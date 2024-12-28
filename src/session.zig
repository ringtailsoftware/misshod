const std = @import("std");
const util = @import("util.zig");
const TRACE = util.trace;
const TRACEDUMP = util.tracedump;
const native_endian = @import("builtin").target.cpu.arch.endian();
const BufferWriter = @import("buffer.zig").BufferWriter;
const BufferReader = @import("buffer.zig").BufferReader;
const Hasher = @import("hasher.zig").Hasher;
const AesCtr = @import("aesctr.zig").AesCtr;
const decodePrivKey = @import("privkey.zig").decodePrivKey;

// SSH packet header, appears before payload
// https://datatracker.ietf.org/doc/html/rfc4253#section-6
const PktHdr = packed struct {
    packet_length: u32,
    padding_length: u8,
};

// Number of bytes used by PktHdr
// https://datatracker.ietf.org/doc/html/rfc4253#section-6
const sizeof_PktHdr = @bitSizeOf(PktHdr) / 8;

// Buffer
const MaxSSHPacket = 4096; // Can be smaller https://datatracker.ietf.org/doc/html/rfc4253#section-5.3
const MaxPayload = (MaxSSHPacket - (sizeof_PktHdr + 255 + mac_algo.key_length));
const MaxIVLen = 20; // number of bytes to generate for IVs
const MaxKeyLen = 64; // number of bytes to generate for keys

// Basic SSH states to move through
const SessionState = enum {
    Init,
    VersionWrite,
    VersionRead,
    VersionReadNextByte,
    KexInitWrite,
    KexInitReadPkt,
    KexInitRead,
    EcdhInit,
    EcdhReply,
    EcdhReplyReadPkt,
    CheckHostKey,
    NewKeysReadReadPkt,
    NewKeysRead,
    NewKeysWrite,
    AuthServReq,
    AuthServRspReadPkt,
    AuthServRsp,
    AuthStart,
    PubkeyAuthReq,
    PubkeyAuthDecodeKeyPasswordless,
    PubkeyAuthDecodeKeyPassword,
    PasswordAuthReq,
    PasswordAuthRspReadPkt,
    PasswordAuthRsp,
    ChannelOpenReq,
    ChannelOpenRspReadPkt,
    ChannelOpenRsp,
    ChannelPtyReq,
    ChannelShellReq,
    ChannelConnected,
    DataRxAdjustWindowReq,
    DataRxReadPkt,
    DataRx,
    ReadPktBody,
    ReadPktBodyEnc,
    Idle,
    Busy,
    End,
    Error,
};

// order in which items must be hashed to produce kex hash, H
// The key exchange hash is built up piecemeal through several states
// Calling check to advance to the next state asserts if it's done in the wrong order
const KexHashOrder = enum { // https://datatracker.ietf.org/doc/html/rfc5656#section-4
    Init,
    V_C, // client's identification string (CR and LF excluded)
    V_S, // server's identification string (CR and LF excluded)
    I_C, // payload of the client's SSH_MSG_KEXINIT
    I_S, // payload of the server's SSH_MSG_KEXINIT
    K_S, // server's public host key
    Q_C, // client's ephemeral public key octet string
    Q_S, // server's ephemeral public key octet string
    K, // shared secret

    // calling myorder = myorder.check(next) will assert if done in the wrong order
    pub fn check(self: *const KexHashOrder, next: KexHashOrder) KexHashOrder {
        std.debug.assert(@intFromEnum(self.*) + 1 == @intFromEnum(next));
        return next;
    }
};

// https://datatracker.ietf.org/doc/html/rfc4250#section-4.1.2
const MsgId = enum(u8) {
    SSH_MSG_DISCONNECT = 1,
    SSH_MSG_UNIMPLEMENTED = 3,
    SSH_MSG_SERVICE_REQUEST = 5,
    SSH_MSG_SERVICE_ACCEPT = 6,
    SSH_MSG_KEXINIT = 20,
    SSH_MSG_NEWKEYS = 21,
    SSH_MSG_KEX_ECDH_INIT = 30,
    SSH_MSG_KEX_ECDH_REPLY = 31,
    SSH_MSG_USERAUTH_REQUEST = 50,
    SSH_MSG_USERAUTH_FAILURE = 51,
    SSH_MSG_USERAUTH_SUCCESS = 52,
    SSH_MSG_USERAUTH_BANNER = 53,
    SSH_MSG_GLOBAL_REQUEST = 80,
    SSH_MSG_CHANNEL_OPEN = 90,
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91,
    SSH_MSG_CHANNEL_WINDOW_ADJUST = 93,
    SSH_MSG_CHANNEL_DATA = 94,
    SSH_MSG_CHANNEL_EXTENDED_DATA = 95,
    SSH_MSG_CHANNEL_EOF = 96,
    SSH_MSG_CHANNEL_REQUEST = 98,
};

// Setup names and functions for the ciphers and algorithms we offer
// Only support a single option for each
// https://datatracker.ietf.org/doc/html/rfc4253#section-4.2
const client_version = "SSH-2.0-SSH_ZS-0.0.1";

const hash_algo = std.crypto.hash.sha2.Sha256;
const hash_algo_name = "hmac-sha2-256";

const kex_algo = std.crypto.dh.X25519;
const kex_algo_name = "curve25519-sha256";

const srv_hostkey_algo = std.crypto.sign.Ed25519;
const srv_hostkey_algo_name = "ssh-ed25519";

const mac_algo = std.crypto.auth.hmac.sha2.HmacSha256;
const mac_algo_name = "hmac-sha2-256";

const enc_algo = std.crypto.core.aes.Aes256;
const enc_algo_name = "aes256-ctr";
const AesCtrT = AesCtr(enc_algo);

pub const SessionEvent = union(enum) {
    None,
    HostKeyValidateReq: ?[]const u8, // blob hostkey
    KeyReq: ?[]const u8, // base64 key data in openssh ascii file format
    KeyReqPassphrase: ?[]const u8, // passphrase for priv key decrypt
    UserReqPassphrase: ?[]const u8, // passphrase for login user auth
    NetReadReq: []u8, // request read of n bytes, slice addr lifetime valid until written to
    NetWriteReq: ?[]u8, // request write of n bytes, slice addr lifetime valid until NetWriteReq rsp received
    SessionRecv: ?[]const u8, // session data being delivered to app (stdout)
    SessionRecvExt: ?[]const u8, // session data being delivered to app (stderr)
    SessionSend: []const u8, // session data sent from app to ssh
    NetDataAvailable: void, // app says there's incoming data on socket
    Connected: void, // tell app they're connected
};

const SessionEventTracked = struct {
    const Self = @This();
    const State = enum {
        Pending,
        WaitRsp,
        Completed, // option != null
    };
    event: SessionEvent = .None,
    state: State = .Pending,
    next_state: SessionState = .Error,
    final_state: ?SessionState = null, // for two phase packet reads

    pub fn pending(event: SessionEvent, next_state: SessionState, final_state: ?SessionState) Self {
        return Self{
            .state = .Pending,
            .event = event,
            .next_state = next_state,
            .final_state = final_state,
        };
    }
};

pub const Session = struct {
    const Self = @This();

    sessionState: SessionState = .Init,
    ecdh_ephem_keypair: kex_algo.KeyPair = undefined,
    // In form U32LenString("ssh-ed25519"), U32LenString(secret)
    hostkey_ks: ?[]u8 = undefined, // K_S, slice of hostkey_ks_buf, allocated
    shared_secret_k: [kex_algo.shared_length]u8 = undefined, // K
    kex_hasher: Hasher(hash_algo) = undefined, // for building H
    kex_hash_order: KexHashOrder = .Init,
    session_id: [hash_algo.digest_length]u8 = undefined,
    c2s_iv: [MaxIVLen]u8 = undefined,
    c2s_key: [MaxKeyLen]u8 = undefined,
    s2c_iv: [MaxIVLen]u8 = undefined,
    s2c_key: [MaxKeyLen]u8 = undefined,
    c2s_mackey: [MaxKeyLen]u8 = undefined,
    s2c_mackey: [MaxKeyLen]u8 = undefined,
    c2s_seq: u32 = 0,
    s2c_seq: u32 = 0,
    c2s_aesctr: AesCtrT = undefined,
    s2c_aesctr: AesCtrT = undefined,
    username: []const u8,
    rand: std.Random = undefined,
    encrypted: bool,

    active_event: ?SessionEventTracked, // event in progress
    event_final_state: ?SessionState, // the state to go to after 2-phase used by RecvPkt

    // these should all be freed/cleared after used
    privkey_blob: [srv_hostkey_algo.SecretKey.encoded_length]u8 = undefined,
    privkey_ascii: ?[]u8 = null, // allocated
    passphrase: ?[]u8 = null, // allocated

    writebuf: [MaxSSHPacket]u8 = undefined, // single packet queued for send
    writebuf_len: usize = 0, // length of valid data in writebuf

    server_version_buf: [256]u8 = undefined,
    server_version: []u8 = &.{},

    pub fn init(rand: std.Random, username: []const u8) !Self {
        return Self{
            .sessionState = .Init,
            .c2s_seq = 0,
            .s2c_seq = 0,
            .username = username,
            .rand = rand,
            .active_event = null,
            .event_final_state = null,
            .encrypted = false,
        };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        if (self.hostkey_ks) |p| {
            allocator.free(p);
        }
        if (self.privkey_ascii) |p| {
            allocator.free(p);
        }
        if (self.passphrase) |p| {
            allocator.free(p);
        }
    }

    fn setSessionState(self: *Self, newState: SessionState) void {
        TRACE(.Debug, "state {any} -> {any}", .{ self.sessionState, newState });
        self.sessionState = newState;
    }

    pub fn isActive(self: *const Self) bool {
        return !(self.sessionState == .End or self.sessionState == .Error);
    }

    pub fn canSend(self: *const Self) bool {
        return self.sessionState == .Idle;
    }

    pub fn getNextEvent(self: *Self) SessionEvent {
        if (self.active_event) |*evt| {
            switch (evt.state) {
                .Pending => {
                    evt.state = .WaitRsp;
                    return evt.event;
                },
                .WaitRsp => {
                    return .None; // no new events until the current one gets handled
                },
                .Completed => {
                    // advance session state
                    if (evt.final_state) |s| {
                        // if there's a final_state, record it - used by recvPkt
                        self.event_final_state = s;
                    } else {
                        self.event_final_state = null;
                    }
                    self.setSessionState(self.active_event.?.next_state);
                    self.active_event = null;
                    return .None;
                },
            }
        } else {
            return .None;
        }
    }

    // can wrap this in function calls if it's easier for caller
    pub fn handleEventRsp(self: *Self, allocator: std.mem.Allocator, event: SessionEvent) !void {
        TRACE(.Debug, "handleEventRsp {any}", .{event});

        if (event == .SessionSend) { // special case, can come in at any time (when .Idle)
            const buf = event.SessionSend;
            if (self.sessionState != .Idle) {
                return error.InvalidStateError;
            }
            if (buf.len > MaxPayload) {
                return error.SendTooBigError;
            }
            // request tx, FIXME need to honour window adjustments from the other side
            var pkt = BufferWriter.init(&self.writebuf, sizeof_PktHdr);
            try pkt.writeU8(@intFromEnum(MsgId.SSH_MSG_CHANNEL_DATA));
            // https://datatracker.ietf.org/doc/html/rfc4250#section-3.3
            try pkt.writeU32(0);
            try pkt.writeU32LenString(buf);
            try self.sendPkt(&pkt, .Idle); // FIXME could ack back with user, or make them watch for .Idle
            return;
        }

        if (event == .NetDataAvailable) { // special case, can come in at any time (when .Idle), ignored at other times
            if (self.sessionState != .Idle) {
                return error.InvalidStateError;
            }
            // request rx
            self.setSessionState(.DataRxAdjustWindowReq); // adjusts window then rx
            return;
        }

        if (self.active_event) |active_event| {
            if (@intFromEnum(active_event.event) == @intFromEnum(event)) {
                // event payload validation
                switch (event) {
                    // messages which can be empty or not
                    .KeyReq, .SessionRecv, .SessionRecvExt, .NetDataAvailable, .Connected => {},
                    // messages expected to be empty
                    .None, .HostKeyValidateReq => {},
                    // non optional payload
                    .NetReadReq, .SessionSend => {},
                    // messages expected to have null payload
                    .NetWriteReq => |arg| if (arg != null) return error.expectedNullEventError,
                    // messages expected to have optional payload
                    inline else => |arg| {
                        if (arg == null) {
                            return error.emptyEventError;
                        }
                    },
                }
                switch (event) {
                    .SessionSend, .NetDataAvailable => {}, // already handled
                    .SessionRecv, .SessionRecvExt, .Connected => {
                        self.active_event.?.state = .Completed;
                    },
                    .NetReadReq => {
                        TRACE(.Debug, "handleEventRsp .NetReadReq", .{});
                        // already updated self.writebuf_len when .NetReadReq was sent
                        // so, self.writebuf now contains rsp
                        self.active_event.?.state = .Completed;
                    },
                    .NetWriteReq => {
                        TRACE(.Debug, "handleEventRsp .NetWriteReq", .{});
                        self.writebuf_len = 0;
                        self.active_event.?.state = .Completed;
                    },
                    .HostKeyValidateReq => {
                        // receiving any response means acceptance, no tagged val
                        self.active_event.?.state = .Completed;
                    },
                    .KeyReq => |keydata_ascii| {
                        std.debug.assert(self.privkey_ascii == null);
                        if (keydata_ascii) |data| {
                            // stash ascii
                            self.privkey_ascii = try allocator.dupe(u8, data);
                        } else {
                            self.privkey_ascii = null;
                        }
                        // cleardown event
                        self.active_event.?.state = .Completed;
                    },
                    .UserReqPassphrase, .KeyReqPassphrase => |passphrase| {
                        // stash passphrase
                        if (self.passphrase != null) { // might already have one from key auth
                            allocator.free(self.passphrase.?);
                        }
                        self.passphrase = try allocator.dupe(u8, passphrase.?);
                        // cleardown event
                        self.active_event.?.state = .Completed;
                    },
                    .None => return error.unsolicitedEventError,
                }
            } else {
                TRACE(.Info, "handleEventRsp wrong event received {any}", .{event});
                return error.unsolicitedEventError;
            }
        } else {
            TRACE(.Info, "handleEventRsp unsolicited event received {any}", .{event});
            return error.unsolicitedEventError;
        }
    }

    // generate session keys from shared secret
    pub fn genKeys(self: *Self, H: [hash_algo.digest_length]u8) !void {
        // https://datatracker.ietf.org/doc/html/rfc4253#section-7.2

        var hasher: Hasher(hash_algo) = undefined;

        // prepare contact(K,H) = K:mpint concat H:raw
        var backing: [4 + kex_algo.shared_length + 1 + hash_algo.digest_length]u8 = undefined; // 4 for len, 1 for possible padding
        var khbuf = BufferWriter.init(&backing, 0);
        try khbuf.writeMpint(&self.shared_secret_k); // K
        try khbuf.writeBytes(&H); // H
        const data_kh = khbuf.payload;

        // c2s_iv
        hasher = Hasher(hash_algo).init();
        hasher.writeBytes(data_kh);
        hasher.writeU8('A'); // "A"
        hasher.writeBytes(&self.session_id); // session_id
        hasher.final(&self.c2s_iv, data_kh);
        TRACEDUMP(.Debug, "c2s_iv", .{}, &self.c2s_iv);

        // s2c_iv
        hasher = Hasher(hash_algo).init();
        hasher.writeBytes(data_kh);
        hasher.writeU8('B'); // "B"
        hasher.writeBytes(&self.session_id); // session_id
        hasher.final(&self.s2c_iv, data_kh);
        TRACEDUMP(.Debug, "s2c_iv", .{}, &self.s2c_iv);

        // c2s_key
        hasher = Hasher(hash_algo).init();
        hasher.writeBytes(data_kh);
        hasher.writeU8('C'); // "C"
        hasher.writeBytes(&self.session_id); // session_id
        hasher.final(&self.c2s_key, data_kh);
        TRACEDUMP(.Debug, "c2s_key", .{}, &self.c2s_key);

        // s2c_key
        hasher = Hasher(hash_algo).init();
        hasher.writeBytes(data_kh);
        hasher.writeU8('D'); // "D"
        hasher.writeBytes(&self.session_id); // session_id
        hasher.final(&self.s2c_key, data_kh);
        TRACEDUMP(.Debug, "s2c_key", .{}, &self.s2c_key);

        // c2s_mackey
        hasher = Hasher(hash_algo).init();
        hasher.writeBytes(data_kh);
        hasher.writeU8('E'); // "E"
        hasher.writeBytes(&self.session_id); // session_id
        hasher.final(&self.c2s_mackey, data_kh);
        TRACEDUMP(.Debug, "c2s_mackey", .{}, &self.c2s_mackey);

        // s2c_mackey
        hasher = Hasher(hash_algo).init();
        hasher.writeBytes(data_kh);
        hasher.writeU8('F'); // "F"
        hasher.writeBytes(&self.session_id); // session_id
        hasher.final(&self.s2c_mackey, data_kh);
        TRACEDUMP(.Debug, "s2c_mackey", .{}, &self.s2c_mackey);

        // setup aesctrs
        self.c2s_aesctr = AesCtrT.init(self.c2s_iv[0..AesCtrT.iv_size].*, self.c2s_key[0..AesCtrT.key_size].*);
        self.s2c_aesctr = AesCtrT.init(self.s2c_iv[0..AesCtrT.iv_size].*, self.s2c_key[0..AesCtrT.key_size].*);
    }

    fn recvPkt(self: *Self, nextState: SessionState) !void {
        std.debug.assert(self.active_event == null);

        if (!self.encrypted) {
            self.writebuf_len = sizeof_PktHdr; // how many bytes we want
            // tell app where to write them
            self.active_event = SessionEventTracked.pending(.{ .NetReadReq = self.writebuf[0..self.writebuf_len] }, .ReadPktBody, nextState);
            self.setSessionState(.Busy);
        } else {
            // https://datatracker.ietf.org/doc/html/rfc4253#section-6
            // read in a block, need first 4 bytes to get len
            self.writebuf_len = AesCtrT.block_size; // how many bytes we want
            // tell app where to write them
            self.active_event = SessionEventTracked.pending(.{ .NetReadReq = self.writebuf[0..self.writebuf_len] }, .ReadPktBodyEnc, nextState);
            self.setSessionState(.Busy);
        }
    }

    fn getRecvBuffer(self: *Self) !BufferReader {
        var hdr: PktHdr = std.mem.bytesAsValue(PktHdr, self.writebuf[0..sizeof_PktHdr]).*;
        if (native_endian != .big) {
            // flip bytes
            std.mem.byteSwapAllFields(PktHdr, &hdr);
        }
        const payload_len = hdr.packet_length - hdr.padding_length - 1;
        const payload = self.writebuf[sizeof_PktHdr .. sizeof_PktHdr + payload_len];

        if (!self.encrypted) {
            return BufferReader.init(payload);
        } else {
            const pkt_len = payload_len + (sizeof_PktHdr) + hdr.padding_length;
            if (pkt_len > AesCtrT.block_size) { // if there's more to be decrypted after first block
                const remaining_pkt_bytes = pkt_len - AesCtrT.block_size;
                var dec: [MaxSSHPacket]u8 = undefined;
                self.s2c_aesctr.encrypt(self.writebuf[AesCtrT.block_size .. AesCtrT.block_size + remaining_pkt_bytes], dec[AesCtrT.block_size .. AesCtrT.block_size + remaining_pkt_bytes]); // use same offset into dec for simplicity

                TRACEDUMP(.Debug, "dec", .{}, dec[AesCtrT.block_size .. AesCtrT.block_size + remaining_pkt_bytes]);
                // copy decrypted back into writebuf
                @memcpy(self.writebuf[AesCtrT.block_size .. AesCtrT.block_size + remaining_pkt_bytes], dec[AesCtrT.block_size .. AesCtrT.block_size + remaining_pkt_bytes]);
                TRACEDUMP(.Debug, "writebuf", .{}, self.writebuf[0..self.writebuf_len]);
            }

            // verify mac
            if (self.writebuf_len < mac_algo.key_length) {
                return error.InvalidPacketSize; // too small to have a mac
            }
            const rxmac = self.writebuf[self.writebuf_len - mac_algo.key_length .. self.writebuf_len]; // at the end
            var calcmac: [mac_algo.key_length]u8 = undefined;
            var m = mac_algo.init(self.s2c_mackey[0..mac_algo.key_length]);
            const seq = std.mem.nativeTo(u32, self.s2c_seq - 1, .big); // seq has already been incremented
            m.update(std.mem.asBytes(&seq));
            m.update(self.writebuf[0 .. self.writebuf_len - mac_algo.key_length]); // plaintext
            m.final(&calcmac);

            TRACEDUMP(.Debug, "rxmac", .{}, rxmac);
            TRACEDUMP(.Debug, "mackey", .{}, self.s2c_mackey[0..mac_algo.key_length]);
            TRACEDUMP(.Debug, "macseq", .{}, std.mem.asBytes(&seq));
            TRACEDUMP(.Debug, "macdata", .{}, self.writebuf[0 .. self.writebuf_len - mac_algo.key_length]);
            TRACEDUMP(.Debug, "calcmac", .{}, std.mem.asBytes(&calcmac));

            if (!std.mem.eql(u8, &calcmac, rxmac)) {
                return error.InvalidMacS2C;
            }

            // remove mac and return buffer containing just plaintext payload
            return BufferReader.init(self.writebuf[sizeof_PktHdr .. self.writebuf_len - mac_algo.key_length]);
        }
    }

    // schedule a packet for sending, increment sent count and apply headers
    // move to nextState once sent
    fn sendPkt(self: *Self, pkt: *BufferWriter, nextState: SessionState) !void {
        if (!self.encrypted) {
            try self.wrapPkt(pkt);
            self.c2s_seq +%= 1;
            self.active_event = SessionEventTracked.pending(.{ .NetWriteReq = pkt.payload }, nextState, null);
            self.setSessionState(.Busy);
        } else {
            // check that pkt is backed by the persistent self.writebuf
            std.debug.assert(@intFromPtr(&pkt.payload_buf[0]) == @intFromPtr(&self.writebuf[0])); // almost certainly bad
            try self.wrapPkt(pkt);
            var out: [MaxSSHPacket]u8 = undefined;

            TRACEDUMP(.Debug, "sendPkt enc:plaintext", .{}, pkt.payload);
            self.c2s_aesctr.encrypt(pkt.payload, out[0..pkt.payload.len]);

            var mac: [mac_algo.key_length]u8 = undefined;
            var m = mac_algo.init(self.c2s_mackey[0..mac_algo.key_length]);
            const seq = std.mem.nativeTo(u32, self.c2s_seq, .big);
            m.update(std.mem.asBytes(&seq));
            m.update(pkt.payload); // plaintext
            m.final(&mac);

            TRACEDUMP(.Debug, "mackey", .{}, self.c2s_mackey[0..mac_algo.key_length]);
            TRACEDUMP(.Debug, "macseq", .{}, std.mem.asBytes(&seq));
            TRACEDUMP(.Debug, "macdata", .{}, pkt.payload);

            // new bufferwriter, to append mac to out
            var out_buffer = BufferWriter.init(&out, pkt.payload.len); // append
            try out_buffer.writeBytes(&mac);

            // everything is now encrypted and in out_buffer with mac, copy back to self.writebuf before sending
            @memcpy(self.writebuf[0..out_buffer.payload.len], out_buffer.payload);
            self.c2s_seq +%= 1;
            self.active_event = SessionEventTracked.pending(.{ .NetWriteReq = self.writebuf[0..out_buffer.payload.len] }, nextState, null);
            self.setSessionState(.Busy);
        }
    }

    // special case as we write direct to stream before entering binary pkt mode
    fn writeProtocolVersion(self: *Self) !void {
        //std.debug.assert(self.keyexch != null);
        std.debug.assert(self.writebuf_len == 0);
        const vers = try std.fmt.bufPrint(&self.writebuf, "{s}\r\n", .{client_version});
        self.writebuf_len = vers.len;
        TRACE(.Debug, "TX: version '{s}'", .{client_version});
        self.kex_hash_order = self.kex_hash_order.check(.V_C);
        self.kex_hasher.writeU32LenString(client_version);
    }

    pub fn advance(self: *Self, allocator: std.mem.Allocator) !void {
        switch (self.sessionState) {
            .Init => {
                self.kex_hasher = Hasher(hash_algo).init(); // for hashing H
                self.setSessionState(.VersionWrite);
            },
            .VersionWrite => {
                try self.writeProtocolVersion(); // to writebuf
                self.active_event = SessionEventTracked.pending(.{ .NetWriteReq = self.writebuf[0..self.writebuf_len] }, .VersionRead, null);
                self.setSessionState(.Busy);
            },
            .VersionRead => {
                self.server_version = &.{}; // no bytes read yet
                // request first byte
                self.writebuf_len = 1; // only one byte a time, need to scan for version string ending with "\r\n"
                self.active_event = SessionEventTracked.pending(.{ .NetReadReq = self.writebuf[0..self.writebuf_len] }, .VersionReadNextByte, null);
                self.setSessionState(.Busy);
            },
            .VersionReadNextByte => {
                if (self.server_version.len >= self.server_version_buf.len) {
                    return error.BadServerVersion;
                } else {
                    self.server_version_buf[self.server_version.len] = self.writebuf[0];
                    self.server_version = self.server_version_buf[0 .. self.server_version.len + 1];

                    if (self.server_version.len >= 2) {
                        if (self.server_version[self.server_version.len - 2] == '\r' and self.server_version[self.server_version.len - 1] == '\n') {
                            // found complete line
                            TRACE(.Debug, "RX: version '{s}'", .{util.chomp(self.server_version)});
                            self.kex_hash_order = self.kex_hash_order.check(.V_S);
                            self.kex_hasher.writeU32LenString(util.chomp(self.server_version));
                            self.setSessionState(.KexInitWrite);
                            return;
                        }
                    }
                    // request another byte
                    self.writebuf_len = 1; // only one byte a time, need to scan for version string ending with "\r\n"
                    self.active_event = SessionEventTracked.pending(.{ .NetReadReq = self.writebuf[0..self.writebuf_len] }, .VersionReadNextByte, null);
                    self.setSessionState(.Busy);
                }
            },
            .ReadPktBody => { // second part of recvPkt() for unencrypted pkts
                std.debug.assert(self.active_event == null);
                std.debug.assert(self.event_final_state != null);
                // copy header
                var hdr: PktHdr = std.mem.bytesAsValue(PktHdr, self.writebuf[0..sizeof_PktHdr]).*;
                if (native_endian != .big) {
                    // flip bytes
                    std.mem.byteSwapAllFields(PktHdr, &hdr);
                }

                // read in payload
                const payload_len = hdr.packet_length - hdr.padding_length - 1;
                std.debug.assert(payload_len <= MaxPayload);

                self.writebuf_len = sizeof_PktHdr + payload_len + hdr.padding_length; // on completion, how much we have
                // tell app where to write them, then progress to event_final_state
                self.active_event = SessionEventTracked.pending(.{ .NetReadReq = self.writebuf[sizeof_PktHdr .. sizeof_PktHdr + payload_len + hdr.padding_length] }, self.event_final_state.?, null);
                self.setSessionState(.Busy);
                self.s2c_seq +%= 1;
            },
            .ReadPktBodyEnc => { // second part of recvPkt() for encrypted pkts
                std.debug.assert(self.active_event == null);
                std.debug.assert(self.event_final_state != null);

                // https://datatracker.ietf.org/doc/html/rfc4253#section-6
                // grab first encrypted block from writebuf
                var firstblock_encbuf: [AesCtrT.block_size]u8 = undefined;
                @memcpy(&firstblock_encbuf, self.writebuf[0..AesCtrT.block_size]);

                // decrypt directly into writebuf
                self.s2c_aesctr.encrypt(&firstblock_encbuf, self.writebuf[0..AesCtrT.block_size]);
                TRACEDUMP(.Debug, "firstblock_dec(in payload)", .{}, self.writebuf[0..AesCtrT.block_size]);

                // read PktHdr from first block
                const pkthdr_size = sizeof_PktHdr;
                var hdr: PktHdr = undefined;
                hdr = std.mem.bytesToValue(PktHdr, self.writebuf[0..pkthdr_size]);
                if (native_endian != .big) {
                    std.mem.byteSwapAllFields(PktHdr, &hdr);
                }
                TRACE(.Debug, "writebuf_len={d} hdr {any}\n", .{ self.writebuf_len, hdr });

                // padding len is such that payload_len + sizeof(hdr) + padding = block size
                const payload_len = hdr.packet_length - (hdr.padding_length + 1);
                if (hdr.padding_length < 4) {
                    return error.InvalidPacketSize;
                }
                const pkt_len = payload_len + (sizeof_PktHdr) + hdr.padding_length;
                // avoid reading obviously bad packet sizes
                if (pkt_len < 8 or pkt_len > MaxSSHPacket) {
                    return error.InvalidPacketSize;
                }

                // calc number of remaining bytes + mac, read from network
                var remaining_pkt_bytes: usize = 0;
                if (pkt_len > AesCtrT.block_size) {
                    remaining_pkt_bytes = pkt_len - AesCtrT.block_size;
                }
                TRACE(.Debug, "About to read {d}\n", .{remaining_pkt_bytes + mac_algo.key_length});

                // tell app where to write them, then progress to event_final_state
                self.active_event = SessionEventTracked.pending(.{ .NetReadReq = self.writebuf[self.writebuf_len .. self.writebuf_len + remaining_pkt_bytes + mac_algo.key_length] }, self.event_final_state.?, null);
                self.writebuf_len += remaining_pkt_bytes + mac_algo.key_length; // on completion, how much we have
                self.setSessionState(.Busy);
                self.s2c_seq +%= 1;
            },

            .KexInitWrite => {
                var pkt = BufferWriter.init(&self.writebuf, sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(MsgId.SSH_MSG_KEXINIT));
                var cookie: [16]u8 = undefined;
                self.rand.bytes(&cookie);
                try pkt.writeBytes(&cookie);

                try pkt.writeU32LenString(kex_algo_name); // kex
                try pkt.writeU32LenString(srv_hostkey_algo_name); // hostkey verification
                try pkt.writeU32LenString(enc_algo_name); // enc c2s
                try pkt.writeU32LenString(enc_algo_name); // enc s2c
                try pkt.writeU32LenString(mac_algo_name); // mac c2s
                try pkt.writeU32LenString(mac_algo_name); // mac s2c
                try pkt.writeU32LenString("none"); // compression c2s
                try pkt.writeU32LenString("none"); // compression s2c
                try pkt.writeU32LenString(""); // lang c2s
                try pkt.writeU32LenString(""); // lang s2c

                const first_kex_packet_follows = false;
                try pkt.writeBoolean(first_kex_packet_follows);
                try pkt.writeU32(0); // reserved

                self.kex_hash_order = self.kex_hash_order.check(.I_C);
                self.kex_hasher.writeU32LenString(pkt.active());

                try self.sendPkt(&pkt, .KexInitReadPkt);
            },
            .KexInitReadPkt => {
                try self.recvPkt(.KexInitRead);
            },
            .KexInitRead => {
                var rdr = try self.getRecvBuffer();

                self.kex_hash_order = self.kex_hash_order.check(.I_S);
                self.kex_hasher.writeU32LenString(rdr.payload);

                const msgid = try rdr.readU8();

                if (msgid == @intFromEnum(MsgId.SSH_MSG_KEXINIT)) {
                    TRACE(.Debug, "SSH_MSG_KEXINIT", .{});
                    // https://datatracker.ietf.org/doc/html/rfc4253#section-7.1
                    // https://datatracker.ietf.org/doc/html/rfc4251#section-5

                    // read server's SSH_MSG_KEXINIT
                    const cookie = try rdr.readBytes(16);
                    TRACEDUMP(.Debug, "cookie", .{}, cookie);

                    const listnames = [_][]const u8{
                        "kex_algorithms",
                        "server_host_key_algorithms",
                        "encryption_algorithms_client_to_server",
                        "encryption_algorithms_server_to_client",
                        "mac_algorithms_client_to_server",
                        "mac_algorithms_server_to_client",
                        "compression_algorithms_client_to_server",
                        "compression_algorithms_server_to_client",
                        "languages_client_to_server",
                        "languages_server_to_client",
                    };

                    for (listnames) |listname| {
                        TRACE(.Debug, "{s}: ", .{listname});
                        var iter = util.NameListTokenizer.init(try rdr.readU32LenString());
                        while (iter.next()) |name| {
                            TRACE(.Debug, "  '{s}' ", .{name});
                        }
                    }

                    const first_kex_packet_follows = try rdr.readBoolean();
                    TRACE(.Debug, "first_kex_packet_follows = {any}\n", .{first_kex_packet_follows});
                    _ = try rdr.readU32(); // reserved, ignore
                    self.setSessionState(.EcdhInit);
                } else {
                    return error.NotKexInitErr;
                }
            },
            .EcdhInit => { // https://datatracker.ietf.org/doc/html/rfc5656#section-4
                var pkt = BufferWriter.init(&self.writebuf, sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(MsgId.SSH_MSG_KEX_ECDH_INIT));

                self.ecdh_ephem_keypair = kex_algo.KeyPair.generate();
                var q_c = self.ecdh_ephem_keypair.public_key;
                try pkt.writeU32LenString(&q_c);

                try self.sendPkt(&pkt, .EcdhReplyReadPkt);
            },
            .EcdhReplyReadPkt => {
                try self.recvPkt(.EcdhReply);
            },
            .EcdhReply => {
                var rdr = try self.getRecvBuffer();
                const msgid = try rdr.readU8();

                if (msgid == @intFromEnum(MsgId.SSH_MSG_KEX_ECDH_REPLY)) {
                    TRACE(.Debug, "SSH_MSG_KEX_ECDH_REPLY", .{});

                    // server's public host key, store so we can ask user to ok it
                    self.hostkey_ks = try allocator.dupe(u8, try rdr.readU32LenString());
                    TRACEDUMP(.Debug, "hostkey_ks", .{}, self.hostkey_ks.?);

                    const srv_pub_ephem = try rdr.readU32LenString();
                    TRACEDUMP(.Debug, "srv_pub_ephem: (len={d})", .{srv_pub_ephem.len}, srv_pub_ephem);

                    // In form U32LenString("ssh-ed25519"), U32LenString(hash)
                    const sig_exch_hash = try rdr.readU32LenString();
                    TRACEDUMP(.Debug, "sig_exch_hash: (len={d})", .{sig_exch_hash.len}, sig_exch_hash);

                    self.kex_hash_order = self.kex_hash_order.check(.K_S);
                    self.kex_hasher.writeU32LenString(self.hostkey_ks.?);

                    self.kex_hash_order = self.kex_hash_order.check(.Q_C);
                    self.kex_hasher.writeU32LenString(&self.ecdh_ephem_keypair.public_key);

                    self.kex_hash_order = self.kex_hash_order.check(.Q_S);
                    self.kex_hasher.writeU32LenString(srv_pub_ephem);

                    // generate shared secret
                    @memcpy(&self.shared_secret_k, &try kex_algo.scalarmult(self.ecdh_ephem_keypair.secret_key, srv_pub_ephem[0..self.ecdh_ephem_keypair.secret_key.len].*));

                    TRACEDUMP(.Debug, "shared secret len={d}", .{self.shared_secret_k.len}, &self.shared_secret_k);

                    self.kex_hash_order = self.kex_hash_order.check(.K);
                    self.kex_hasher.writeMpint(&self.shared_secret_k);

                    // Produce H/session_id/key exchange hash
                    // Both sides now have this
                    var kexhash: [hash_algo.digest_length]u8 = undefined; // session_id, H
                    self.kex_hasher.final(&kexhash, null);
                    TRACEDUMP(.Debug, "kexhash: (len={d})", .{kexhash.len}, &kexhash);

                    @memcpy(&self.session_id, &kexhash); // store as session_id

                    // verify server's signature on the hash
                    var nb = util.NamedBlob.init(self.hostkey_ks.?);
                    const rawpubkey = try nb.getBlob();
                    const pubkey = try srv_hostkey_algo.PublicKey.fromBytes(rawpubkey[0..srv_hostkey_algo.PublicKey.encoded_length].*);

                    nb = util.NamedBlob.init(sig_exch_hash);
                    const rawsig = try nb.getBlob();
                    const sig = srv_hostkey_algo.Signature.fromBytes(rawsig[0..srv_hostkey_algo.Signature.encoded_length].*);

                    try sig.verify(&kexhash, pubkey);

                    // generate keys
                    try self.genKeys(kexhash);

                    self.setSessionState(.CheckHostKey);
                }
            },
            .CheckHostKey => {
                self.active_event = SessionEventTracked.pending(.{ .HostKeyValidateReq = self.hostkey_ks.? }, .NewKeysReadReadPkt, null);

                self.setSessionState(.Busy);
            },
            .NewKeysReadReadPkt => {
                try self.recvPkt(.NewKeysRead);
            },
            .NewKeysRead => {
                // https://datatracker.ietf.org/doc/html/rfc4253#section-7.2
                var rdr = try self.getRecvBuffer();
                const msgid = try rdr.readU8();

                if (msgid == @intFromEnum(MsgId.SSH_MSG_NEWKEYS)) {
                    TRACE(.Debug, "SSH_MSG_NEWKEYS", .{});
                    self.setSessionState(.NewKeysWrite);
                } else {
                    return error.NotNewKeysErr;
                }
            },
            .NewKeysWrite => {
                // https://datatracker.ietf.org/doc/html/rfc4253#section-7.2
                var pkt = BufferWriter.init(&self.writebuf, sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(MsgId.SSH_MSG_NEWKEYS));
                try self.sendPkt(&pkt, .AuthServReq);
            },
            .AuthServReq => {
                self.encrypted = true; // newkeys established, everything now encrypted
                // https://datatracker.ietf.org/doc/html/rfc4253
                var pkt = BufferWriter.init(&self.writebuf, sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(MsgId.SSH_MSG_SERVICE_REQUEST));
                try pkt.writeU32LenString("ssh-userauth");
                try self.sendPkt(&pkt, .AuthServRspReadPkt);
            },
            .AuthServRspReadPkt => {
                try self.recvPkt(.AuthServRsp);
            },
            .AuthServRsp => {
                var rdr = try self.getRecvBuffer();
                const msgid = try rdr.readU8();

                switch (msgid) {
                    @intFromEnum(MsgId.SSH_MSG_SERVICE_ACCEPT) => {
                        TRACE(.Debug, "MsgId.SSH_MSG_SERVICE_ACCEPT", .{});
                        self.setSessionState(.AuthStart);
                    },
                    else => {
                        TRACE(.Info, "got unexpected msgid {d}", .{msgid});
                        // FIXME
                        return error.UnexpectedMessage;
                    },
                }
            },
            .AuthStart => {
                // should always try to get a key, then fall back to password
                std.debug.assert(self.active_event == null);
                self.active_event = SessionEventTracked.pending(.{ .KeyReq = null }, .PubkeyAuthDecodeKeyPasswordless, null);
                self.setSessionState(.Busy);
            },
            .PubkeyAuthDecodeKeyPasswordless => {
                std.debug.assert(self.active_event == null);
                if (self.privkey_ascii) |privkey_ascii| {
                    TRACE(.Debug, "privkey_ascii = {s}\n", .{privkey_ascii});

                    // attempt passwordless
                    decodePrivKey(privkey_ascii, null, &self.privkey_blob) catch |err| {
                        // free privkey_ascii
                        switch (err) {
                            error.InvalidKeyDecrypt => {
                                // need a passphrase to decode key
                                self.active_event = SessionEventTracked.pending(.{ .KeyReqPassphrase = null }, .PubkeyAuthDecodeKeyPassword, null);
                                self.setSessionState(.Busy);
                                return; // drop into idle until we have passphrase
                            },
                            else => {
                                return err;
                            },
                        }
                    };
                    self.setSessionState(.PubkeyAuthReq);
                } else {
                    // no key available
                    // try password auth
                    self.active_event = SessionEventTracked.pending(.{ .UserReqPassphrase = null }, .PasswordAuthReq, null);
                    self.setSessionState(.Busy);
                }
            },
            .PubkeyAuthDecodeKeyPassword => {
                std.debug.assert(self.active_event == null);
                std.debug.assert(self.passphrase != null);

                // attempt decode with passphrase
                // if this fails, drop to password auth
                decodePrivKey(self.privkey_ascii.?, self.passphrase, &self.privkey_blob) catch {
                    self.active_event = SessionEventTracked.pending(.{ .UserReqPassphrase = null }, .PasswordAuthReq, null);
                    self.setSessionState(.Busy);
                    return;
                };
                self.setSessionState(.Busy);
                self.setSessionState(.PubkeyAuthReq);
            },
            .PubkeyAuthReq => {
                // https://datatracker.ietf.org/doc/html/rfc4252#section-7
                var pkt = BufferWriter.init(&self.writebuf, sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(MsgId.SSH_MSG_USERAUTH_REQUEST));
                //https://datatracker.ietf.org/doc/html/rfc4252#section-5.1
                //https://datatracker.ietf.org/doc/html/rfc4252#section-8

                const secretkey = try srv_hostkey_algo.SecretKey.fromBytes(self.privkey_blob);
                const keypair = try srv_hostkey_algo.KeyPair.fromSecretKey(secretkey);

                var backing_pubkey_buf: [256]u8 = undefined;
                var typed_pubkey_buf = BufferWriter.init(&backing_pubkey_buf, 0);
                try typed_pubkey_buf.writeU32LenString(srv_hostkey_algo_name);
                try typed_pubkey_buf.writeU32LenString(&keypair.public_key.bytes);

                try pkt.writeU32LenString(self.username);
                try pkt.writeU32LenString("ssh-connection");
                try pkt.writeU32LenString("publickey");
                try pkt.writeBoolean(true);
                try pkt.writeU32LenString(srv_hostkey_algo_name);
                try pkt.writeU32LenString(typed_pubkey_buf.active());

                var backing_sigbuffer_buf: [512]u8 = undefined;
                var sigbuffer = BufferWriter.init(&backing_sigbuffer_buf, 0);
                try sigbuffer.writeU32LenString(&self.session_id);
                try sigbuffer.writeU8(@intFromEnum(MsgId.SSH_MSG_USERAUTH_REQUEST));
                try sigbuffer.writeU32LenString(self.username);
                try sigbuffer.writeU32LenString("ssh-connection");
                try sigbuffer.writeU32LenString("publickey");
                try sigbuffer.writeBoolean(true);
                try sigbuffer.writeU32LenString(srv_hostkey_algo_name);
                try sigbuffer.writeU32LenString(typed_pubkey_buf.active());

                // gen signature
                const sig = try keypair.sign(sigbuffer.active(), null);
                const sigbytes = sig.toBytes();
                TRACEDUMP(.Debug, "sigbytes", .{}, &sigbytes);

                var backing_typed_sig_buf: [256]u8 = undefined;
                var typed_sig_buf = BufferWriter.init(&backing_typed_sig_buf, 0);
                try typed_sig_buf.writeU32LenString(srv_hostkey_algo_name);
                try typed_sig_buf.writeU32LenString(&sigbytes);
                try pkt.writeU32LenString(typed_sig_buf.active());

                try self.sendPkt(&pkt, .PasswordAuthRspReadPkt);
            },
            .PasswordAuthReq => {
                std.debug.assert(self.passphrase != null);
                var pkt = BufferWriter.init(&self.writebuf, sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(MsgId.SSH_MSG_USERAUTH_REQUEST));
                //https://datatracker.ietf.org/doc/html/rfc4252#section-5.1
                //https://datatracker.ietf.org/doc/html/rfc4252#section-8
                try pkt.writeU32LenString(self.username);
                try pkt.writeU32LenString("ssh-connection");
                try pkt.writeU32LenString("password");
                try pkt.writeBoolean(false);
                try pkt.writeU32LenString(self.passphrase.?);
                try self.sendPkt(&pkt, .PasswordAuthRspReadPkt);
            },
            .PasswordAuthRspReadPkt => {
                try self.recvPkt(.PasswordAuthRsp);
            },
            .PasswordAuthRsp => {
                // all auth attempts complete
                // free/zap allocated auth data as they won't be needed again
                if (self.hostkey_ks) |p| {
                    std.crypto.secureZero(u8, p);
                    allocator.free(p);
                }
                if (self.privkey_ascii) |p| {
                    std.crypto.secureZero(u8, p);
                    allocator.free(p);
                }
                if (self.passphrase) |p| {
                    std.crypto.secureZero(u8, p);
                    allocator.free(p);
                }
                std.crypto.secureZero(u8, &self.privkey_blob);

                var rdr = try self.getRecvBuffer();
                const msgid = try rdr.readU8();

                switch (msgid) {
                    @intFromEnum(MsgId.SSH_MSG_USERAUTH_BANNER) => {
                        TRACE(.Debug, "MsgId.SSH_MSG_USERAUTH_BANNER", .{});

                        const banner = try rdr.readU32LenString();
                        TRACE(.Info, "Server banner '{s}'", .{util.chomp(banner)});
                        const lang = try rdr.readU32LenString();
                        TRACE(.Debug, "Server banner language '{s}'", .{lang});
                        // do another read
                        self.setSessionState(.PasswordAuthRspReadPkt);
                    },
                    @intFromEnum(MsgId.SSH_MSG_USERAUTH_SUCCESS) => {
                        TRACE(.Debug, "MsgId.SSH_MSG_USERAUTH_SUCCESS", .{});
                        self.setSessionState(.ChannelOpenReq);
                    },
                    @intFromEnum(MsgId.SSH_MSG_UNIMPLEMENTED) => {
                        TRACE(.Info, "auth mechanism not supported/implemented", .{});
                        self.setSessionState(.Error);
                    },
                    @intFromEnum(MsgId.SSH_MSG_USERAUTH_FAILURE) => {
                        TRACE(.Info, "auth failure", .{});
                        self.setSessionState(.Error);
                    },
                    else => {
                        TRACE(.Info, "got unexpected msgid {d}", .{msgid});
                        return error.UnexpectedMessage;
                    },
                }
            },
            .ChannelOpenReq => {
                var pkt = BufferWriter.init(&self.writebuf, sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(MsgId.SSH_MSG_CHANNEL_OPEN));
                // https://datatracker.ietf.org/doc/html/rfc4254#section-5.1
                try pkt.writeU32LenString("session"); // https://datatracker.ietf.org/doc/html/rfc4250#section-4.9.1
                try pkt.writeU32(0); // sender channel
                try pkt.writeU32(MaxPayload); // initial window size
                try pkt.writeU32(MaxPayload); // maximum packet size
                try self.sendPkt(&pkt, .ChannelOpenRspReadPkt);
            },
            .ChannelOpenRspReadPkt => {
                try self.recvPkt(.ChannelOpenRsp);
            },
            .ChannelOpenRsp => {
                var rdr = try self.getRecvBuffer();
                const msgid = try rdr.readU8();

                switch (msgid) {
                    @intFromEnum(MsgId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION) => {
                        TRACE(.Debug, "MsgId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION", .{});
                        // uint32    recipient channel
                        // uint32    sender channel
                        // uint32    initial window size
                        // uint32    maximum packet size
                        self.setSessionState(.ChannelPtyReq);
                    },
                    @intFromEnum(MsgId.SSH_MSG_GLOBAL_REQUEST) => {
                        const reqname = try rdr.readU32LenString();
                        const wantreply = try rdr.readBoolean();
                        TRACE(.Debug, "MsgId.SSH_MSG_GLOBAL_REQUEST reqname={s} wantreply={any}", .{ reqname, wantreply });
                        // read again
                        self.setSessionState(.ChannelOpenRspReadPkt);
                    },
                    else => {
                        TRACE(.Info, "got msgid {d}", .{msgid});
                        return error.NotChannelOpenRsp;
                    },
                }
            },
            .ChannelPtyReq => {
                var pkt = BufferWriter.init(&self.writebuf, sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(MsgId.SSH_MSG_CHANNEL_REQUEST));
                // https://datatracker.ietf.org/doc/html/rfc4254#section-6.2
                try pkt.writeU32(0);
                try pkt.writeU32LenString("pty-req");
                try pkt.writeBoolean(false); // want reply
                try pkt.writeU32LenString("xterm-color");
                try pkt.writeU32(80);
                try pkt.writeU32(24);
                try pkt.writeU32(640);
                try pkt.writeU32(480);

                // magic pulled from observing OpenSSH connect
                const termdata = &[_]u8{
                    0x81, 0x00, 0x00, 0x25, 0x80, 0x80, 0x00,
                    0x00, 0x25, 0x80, 0x01, 0x00, 0x00, 0x00,
                    0x03, 0x02, 0x00, 0x00, 0x00, 0x1c, 0x03,
                    0x00, 0x00, 0x00, 0x7f, 0x04, 0x00, 0x00,
                    0x00, 0x15, 0x05, 0x00, 0x00, 0x00, 0x04,
                    0x06, 0x00, 0x00, 0x00, 0xff, 0x07, 0x00,
                    0x00, 0x00, 0xff, 0x08, 0x00, 0x00, 0x00,
                    0x11, 0x09, 0x00, 0x00, 0x00, 0x13, 0x0a,
                    0x00, 0x00, 0x00, 0x1a, 0x0b, 0x00, 0x00,
                    0x00, 0x19, 0x0c, 0x00, 0x00, 0x00, 0x12,
                    0x0d, 0x00, 0x00, 0x00, 0x17, 0x0e, 0x00,
                    0x00, 0x00, 0x16, 0x11, 0x00, 0x00, 0x00,
                    0x14, 0x12, 0x00, 0x00, 0x00, 0x0f, 0x1e,
                    0x00, 0x00, 0x00, 0x01, 0x1f, 0x00, 0x00,
                    0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00,
                    0x21, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00,
                    0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00,
                    0x00, 0x24, 0x00, 0x00, 0x00, 0x01, 0x26,
                    0x00, 0x00, 0x00, 0x01, 0x27, 0x00, 0x00,
                    0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00,
                    0x29, 0x00, 0x00, 0x00, 0x01, 0x2a, 0x00,
                    0x00, 0x00, 0x01, 0x32, 0x00, 0x00, 0x00,
                    0x01, 0x33, 0x00, 0x00, 0x00, 0x01, 0x35,
                    0x00, 0x00, 0x00, 0x01, 0x36, 0x00, 0x00,
                    0x00, 0x01, 0x37, 0x00, 0x00, 0x00, 0x01,
                    0x38, 0x00, 0x00, 0x00, 0x00, 0x39, 0x00,
                    0x00, 0x00, 0x00, 0x3a, 0x00, 0x00, 0x00,
                    0x00, 0x3b, 0x00, 0x00, 0x00, 0x00, 0x3c,
                    0x00, 0x00, 0x00, 0x01, 0x3d, 0x00, 0x00,
                    0x00, 0x01, 0x3e, 0x00, 0x00, 0x00, 0x01,
                    0x46, 0x00, 0x00, 0x00, 0x01, 0x48, 0x00,
                    0x00, 0x00, 0x01, 0x49, 0x00, 0x00, 0x00,
                    0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x4b,
                    0x00, 0x00, 0x00, 0x00, 0x5a, 0x00, 0x00,
                    0x00, 0x01, 0x5b, 0x00, 0x00, 0x00, 0x01,
                    0x5c, 0x00, 0x00, 0x00, 0x00, 0x5d, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                };
                try pkt.writeU32LenString(termdata);

                try self.sendPkt(&pkt, .ChannelShellReq);
            },
            .ChannelShellReq => {
                var pkt = BufferWriter.init(&self.writebuf, sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(MsgId.SSH_MSG_CHANNEL_REQUEST));
                // https://datatracker.ietf.org/doc/html/rfc4254#section-6.2
                try pkt.writeU32(0);
                try pkt.writeU32LenString("shell");
                try pkt.writeBoolean(false); // want reply
                try self.sendPkt(&pkt, .ChannelConnected);
            },

            .ChannelConnected => {
                self.active_event = SessionEventTracked.pending(SessionEvent.Connected, .Idle, null);
                self.setSessionState(.Busy);
            },
            .DataRxAdjustWindowReq => {
                // https://datatracker.ietf.org/doc/html/rfc4254#section-5.2
                var pkt = BufferWriter.init(&self.writebuf, sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(MsgId.SSH_MSG_CHANNEL_WINDOW_ADJUST));
                try pkt.writeU32(0); // channel
                try pkt.writeU32(MaxPayload); // bytes to add
                try self.sendPkt(&pkt, .DataRxReadPkt);
            },
            .DataRxReadPkt => {
                try self.recvPkt(.DataRx);
            },
            .DataRx => {
                var rdr = try self.getRecvBuffer();
                const msgid = try rdr.readU8();

                switch (msgid) {
                    @intFromEnum(MsgId.SSH_MSG_CHANNEL_EXTENDED_DATA) => {
                        TRACE(.Debug, "MsgId.SSH_MSG_CHANNEL_EXTENDED_DATA", .{});
                        const channelnum = try rdr.readU32();
                        const data_type_code = try rdr.readU32();
                        const s = try rdr.readU32LenString();
                        TRACE(.Debug, "got data chan={d} data_type_code={d} '{s}'\n", .{ channelnum, data_type_code, s });
                        // deliver to app, then receive some more, s points to writebuf, so is safe until handled
                        self.active_event = SessionEventTracked.pending(.{ .SessionRecvExt = s }, .Idle, null);
                        self.setSessionState(.Busy);
                    },
                    @intFromEnum(MsgId.SSH_MSG_CHANNEL_DATA) => {
                        TRACE(.Debug, "MsgId.SSH_MSG_CHANNEL_DATA", .{});
                        const channelnum = try rdr.readU32();
                        const s = try rdr.readU32LenString();
                        TRACE(.Debug, "got data chan={d} '{s}'\n", .{ channelnum, s });
                        // deliver to app, then receive some more, s points to writebuf, so is safe until handled
                        self.active_event = SessionEventTracked.pending(.{ .SessionRecv = s }, .Idle, null);
                        self.setSessionState(.Busy);
                    },
                    @intFromEnum(MsgId.SSH_MSG_CHANNEL_EOF) => {
                        self.setSessionState(.End);
                    },
                    @intFromEnum(MsgId.SSH_MSG_CHANNEL_WINDOW_ADJUST) => {
                        // ignore FIXME, and try read again
                        self.setSessionState(.DataRxReadPkt);
                    },
                    else => {
                        TRACE(.Info, "got msgid {d}", .{msgid});
                        return error.UnexpectedMessage;
                    },
                }
            },
            .Idle => {},
            .Busy => {},
            .End => {},
            .Error => {},
        }
    }

    fn wrapPkt(self: *Self, buffer: *BufferWriter) !void {
        // https://datatracker.ietf.org/doc/html/rfc4253#section-6
        // pad such that whole packet (payload + hdr) is multiple of block_size
        const buffer_len = buffer.active().len;
        var padding_length: u8 = @intCast(AesCtrT.block_size - (buffer_len + sizeof_PktHdr) % AesCtrT.block_size);
        if (padding_length < 4) {
            padding_length += @intCast(AesCtrT.block_size);
        }
        // construct header
        var hdr: PktHdr = .{
            .packet_length = @intCast(buffer_len + padding_length + 1),
            .padding_length = @intCast(padding_length),
        };
        // make correct endianness
        if (native_endian != .big) {
            std.mem.byteSwapAllFields(PktHdr, &hdr);
        }
        // insert hdr into hole
        @memcpy(buffer.payload[0..sizeof_PktHdr], util.asPackedBytes(PktHdr, &hdr));

        // append padding, NOTE, will change buffer.payload.len (stored in hdr above)
        var rndbuf: [255]u8 = undefined; // block_size would do
        self.rand.bytes(rndbuf[0..padding_length]);
        _ = try buffer.writeBytes(rndbuf[0..padding_length]);
    }
};
