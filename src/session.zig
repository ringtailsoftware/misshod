const std = @import("std");
const util = @import("util.zig");
const TRACE = util.trace;
const TRACEDUMP = util.tracedump;
const Misshod = @import("misshod.zig").Misshod;
const MisshodError = @import("misshod.zig").MisshodError;
const IoError = @import("misshod.zig").IoError;
const native_endian = @import("builtin").target.cpu.arch.endian();
const BufferWriter = @import("buffer.zig").BufferWriter;
const BufferError = @import("buffer.zig").BufferError;
const BufferReader = @import("buffer.zig").BufferReader;
const Hasher = @import("hasher.zig").Hasher;
const AesCtr = @import("aesctr.zig").AesCtr;
const decodePrivKey = @import("privkey.zig").decodePrivKey;
const PrivKeyError = @import("privkey.zig").PrivKeyError;

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
pub const MaxSSHPacket = 4096; // Can be smaller https://datatracker.ietf.org/doc/html/rfc4253#section-5.3
const MaxPayload = (MaxSSHPacket - (sizeof_PktHdr + 255 + mac_algo.key_length));
const MaxIVLen = 20; // number of bytes to generate for IVs
const MaxKeyLen = 64; // number of bytes to generate for keys

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
        TRACE(.Debug, "KexHashOrder {any} -> {any}", .{ self, next });
        std.debug.assert(@intFromEnum(self.*) + 1 == @intFromEnum(next));
        return next;
    }
};

// Note, the buffers are not used for storage, they're just passed forward to signal to receiver where the data can be found
pub const IoSessionState = union(enum) {
    Init,
    Idle,
    VersionWrite,
    VersionReadLine,
    VersionReadLineChar: []const u8,
    VersionReadLineCompletion: []const u8,
    ReadPktHdr,
    ReadPktBody: []const u8,
    ReadPktCompletion: []const u8,
};

pub const SessionState = enum {
    Init,
    KexInitWrite,
    KexInitRead,
    EcdhInitWrite,
    EcdhReply,
    CheckHostKey,
    CheckHostKeyCompleted,
    NewKeysRead,
    NewKeysWrite,
    AuthServReq,
    AuthServRsp,
    AuthStart,
    GetPrivateKeyCompleted,
    PubkeyAuthDecodeKeyPasswordless,
    PubkeyAuthDecodeKeyPassword,
    PubkeyAuthReq,
    AuthRsp,
    PasswordAuthReq,
    ChannelOpenReq,
    ChannelOpenRsp,
    ChannelPtyReq,
    ChannelShellReq,
    ChannelConnected,
    ChannelData,
    ChannelDataRxAdjustWindow,
    ChannelDataRx,
    ChannelDataTx,
    ChannelDataTxComplete,
};

pub const Session = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    ioSessionState: IoSessionState,
    sessionState: SessionState,

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
    c2s_seq: u32,
    s2c_seq: u32,
    c2s_aesctr: AesCtrT = undefined,
    s2c_aesctr: AesCtrT = undefined,
    username: []const u8,
    rand: std.Random = undefined,
    encrypted: bool,
    channel_write_buf: [64]u8 = undefined, // FIXME size
    channel_write_buf_nbytes: usize,

    privkey_ascii: ?[]u8, // allocated  // FIXME deinit properly and clear
    privkey_passphrase: ?[]u8, //allocated
    auth_passphrase: ?[]u8, //allocated
    privkey_blob: [srv_hostkey_algo.SecretKey.encoded_length]u8 = undefined,

    pub fn init(rand: std.Random, username: []const u8, allocator: std.mem.Allocator) Self {
        return .{
            .ioSessionState = .Init,
            .sessionState = .Init,
            .rand = rand,
            .allocator = allocator,
            .username = username,
            .encrypted = false,
            .c2s_seq = 0,
            .s2c_seq = 0,
            .kex_hasher = Hasher(hash_algo).init(), // for hashing H
            .privkey_ascii = null,
            .privkey_passphrase = null,
            .auth_passphrase = null,
            .channel_write_buf_nbytes = 0,
        };
    }

    pub fn setIoSessionState(self: *Self, newState: IoSessionState) void {
        TRACE(.Debug, "ioSessionState {any} -> {any}", .{ self.ioSessionState, newState });
        self.ioSessionState = newState;
    }

    pub fn setSessionState(self: *Self, newState: SessionState) void {
        TRACE(.Debug, "sessionState {any} -> {any}", .{ self.sessionState, newState });
        self.sessionState = newState;
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

    fn wrapPkt(self: *Self, buffer: *BufferWriter, iobuf: []u8) MisshodError![]const u8 {
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

        if (self.encrypted) {
            var out: [MaxSSHPacket]u8 = undefined;

            TRACEDUMP(.Debug, "sendbuffer enc:plaintext", .{}, buffer.payload);
            self.c2s_aesctr.encrypt(buffer.payload, out[0..buffer.payload.len]);

            var mac: [mac_algo.key_length]u8 = undefined;
            var m = mac_algo.init(self.c2s_mackey[0..mac_algo.key_length]);
            const seq = std.mem.nativeTo(u32, self.c2s_seq, .big);
            m.update(std.mem.asBytes(&seq));
            m.update(buffer.payload); // plaintext
            m.final(&mac);

            TRACEDUMP(.Debug, "mackey", .{}, self.c2s_mackey[0..mac_algo.key_length]);
            TRACEDUMP(.Debug, "macseq", .{}, std.mem.asBytes(&seq));
            TRACEDUMP(.Debug, "macdata", .{}, buffer.payload);

            // new bufferwriter, to append mac to out
            var out_buffer = BufferWriter.init(&out, buffer.payload.len); // append
            try out_buffer.writeBytes(&mac);

            // everything is now encrypted and in out_buffer with mac, copy back to self.writebuf before sending
            @memcpy(iobuf[0..out_buffer.payload.len], out_buffer.payload);

            TRACEDUMP(.Debug, "enc send", .{}, iobuf[0..out_buffer.payload.len]);

            self.c2s_seq +%= 1;
            return iobuf[0..out_buffer.payload.len];
        } else {
            self.c2s_seq +%= 1;
            return iobuf[0..buffer.payload.len];
        }
    }

    pub fn advanceSession(self: *Self, misshod: *Misshod) MisshodError!void {
        switch (self.sessionState) {
            .Init => {
                self.setSessionState(.KexInitWrite);
            },
            .KexInitWrite => {
                var pkt = BufferWriter.init(&misshod.iobuf, sizeof_PktHdr);
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

                misshod.requestWrite(try self.wrapPkt(&pkt, &misshod.iobuf), .Idle);
                self.setSessionState(.KexInitRead);
            },
            .KexInitRead => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .EcdhInitWrite => {
                var pkt = BufferWriter.init(&misshod.iobuf, sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(MsgId.SSH_MSG_KEX_ECDH_INIT));

                self.ecdh_ephem_keypair = kex_algo.KeyPair.generate();
                var q_c = self.ecdh_ephem_keypair.public_key;
                try pkt.writeU32LenString(&q_c);

                misshod.requestWrite(try self.wrapPkt(&pkt, &misshod.iobuf), .Idle);
                self.setSessionState(.EcdhReply);
            },
            .EcdhReply => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .CheckHostKey => {
                misshod.requestEvent(.{ .CheckHostKey = self.hostkey_ks }, .Idle);
                self.setSessionState(.CheckHostKeyCompleted);
            },
            .CheckHostKeyCompleted => {
                self.setSessionState(.NewKeysRead);
                self.setIoSessionState(.ReadPktHdr);
            },
            .NewKeysRead => {
                //std.debug.assert(false);
                // FIXME explain why empty
            },
            .NewKeysWrite => {
                // https://datatracker.ietf.org/doc/html/rfc4253#section-7.2
                var pkt = BufferWriter.init(&misshod.iobuf, sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(MsgId.SSH_MSG_NEWKEYS));
                misshod.requestWrite(try self.wrapPkt(&pkt, &misshod.iobuf), .Idle);
                self.setSessionState(.AuthServReq);
                self.encrypted = true; // have read and written SSH_MSG_NEWKEYS, encrypted from now on
            },
            .AuthServReq => {
                // https://datatracker.ietf.org/doc/html/rfc4253
                var pkt = BufferWriter.init(&misshod.iobuf, sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(MsgId.SSH_MSG_SERVICE_REQUEST));
                try pkt.writeU32LenString("ssh-userauth");
                misshod.requestWrite(try self.wrapPkt(&pkt, &misshod.iobuf), .Idle);
                self.setSessionState(.AuthServRsp);
            },
            .AuthServRsp => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .AuthStart => {
                // if we have no private key yet, ask for one
                // triggers caller to call setPrivateKey(), but they may not
                if (self.privkey_ascii == null) {
                    misshod.requestEvent(.GetPrivateKey, .Idle);
                    self.setSessionState(.GetPrivateKeyCompleted);
                }
            },
            .GetPrivateKeyCompleted => {
                TRACE(.Debug, "self.privkey_ascii = {any}", .{self.privkey_ascii});
                if (self.privkey_ascii != null) {
                    self.setSessionState(.PubkeyAuthDecodeKeyPasswordless);
                } else {
                    misshod.requestEvent(.GetAuthPassphrase, .Idle);
                    self.setSessionState(.PasswordAuthReq);
                }
            },
            .PubkeyAuthDecodeKeyPasswordless => {
                if (self.privkey_ascii) |privkey_ascii| { // have private key
                    // attempt passwordless
                    decodePrivKey(privkey_ascii, null, &self.privkey_blob) catch |err| {
                        // free privkey_ascii
                        switch (err) {
                            PrivKeyError.InvalidKeyDecrypt => {
                                // need a passphrase to decode key
                                misshod.requestEvent(.GetKeyPassphrase, .Idle);
                                self.setSessionState(.PubkeyAuthDecodeKeyPassword);
                                return;
                            },
                            else => {
                                return err;
                            },
                        }
                    };
                    // key decoded ok, so must have been passwordless
                    self.setSessionState(.PubkeyAuthReq);
                } else {
                    // no key available
                    // try password auth
                    misshod.requestEvent(.GetAuthPassphrase, .Idle);
                    self.setSessionState(.PasswordAuthReq);
                }
            },
            .PubkeyAuthReq => {
                // https://datatracker.ietf.org/doc/html/rfc4252#section-7
                var pkt = BufferWriter.init(&misshod.iobuf, sizeof_PktHdr);
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

                misshod.requestWrite(try self.wrapPkt(&pkt, &misshod.iobuf), .Idle);
                self.setSessionState(.AuthRsp);
            },
            .PubkeyAuthDecodeKeyPassword => {
                // attempt decode with passphrase
                // if this fails, drop to password auth
                decodePrivKey(self.privkey_ascii.?, self.privkey_passphrase, &self.privkey_blob) catch {
                    if (self.auth_passphrase == null) {
                        misshod.requestEvent(.GetAuthPassphrase, .Idle);
                    }
                    self.setSessionState(.PasswordAuthReq);
                    return;
                };
                // key decode ok, continue with pubkey
                self.setSessionState(.PubkeyAuthReq);
            },
            .PasswordAuthReq => {
                std.debug.assert(self.auth_passphrase != null);
                var pkt = BufferWriter.init(&misshod.iobuf, sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(MsgId.SSH_MSG_USERAUTH_REQUEST));
                //https://datatracker.ietf.org/doc/html/rfc4252#section-5.1
                //https://datatracker.ietf.org/doc/html/rfc4252#section-8
                try pkt.writeU32LenString(self.username);
                try pkt.writeU32LenString("ssh-connection");
                try pkt.writeU32LenString("password");
                try pkt.writeBoolean(false);
                try pkt.writeU32LenString(self.auth_passphrase.?);
                misshod.requestWrite(try self.wrapPkt(&pkt, &misshod.iobuf), .Idle);
                self.setSessionState(.AuthRsp);
            },
            .AuthRsp => { // for password or pubkey
                self.setIoSessionState(.ReadPktHdr);
            },
            .ChannelOpenReq => {
                var pkt = BufferWriter.init(&misshod.iobuf, sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(MsgId.SSH_MSG_CHANNEL_OPEN));
                // https://datatracker.ietf.org/doc/html/rfc4254#section-5.1
                try pkt.writeU32LenString("session"); // https://datatracker.ietf.org/doc/html/rfc4250#section-4.9.1
                try pkt.writeU32(0); // sender channel
                try pkt.writeU32(MaxPayload); // initial window size
                try pkt.writeU32(MaxPayload); // maximum packet size
                misshod.requestWrite(try self.wrapPkt(&pkt, &misshod.iobuf), .Idle);
                self.setSessionState(.ChannelOpenRsp);
            },
            .ChannelOpenRsp => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .ChannelPtyReq => {
                var pkt = BufferWriter.init(&misshod.iobuf, sizeof_PktHdr);
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

                misshod.requestWrite(try self.wrapPkt(&pkt, &misshod.iobuf), .Idle);
                self.setSessionState(.ChannelShellReq);
            },
            .ChannelShellReq => {
                var pkt = BufferWriter.init(&misshod.iobuf, sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(MsgId.SSH_MSG_CHANNEL_REQUEST));
                // https://datatracker.ietf.org/doc/html/rfc4254#section-6.2
                try pkt.writeU32(0);
                try pkt.writeU32LenString("shell");
                try pkt.writeBoolean(false); // want reply

                misshod.requestWrite(try self.wrapPkt(&pkt, &misshod.iobuf), .Idle);
                self.setSessionState(.ChannelConnected);
            },
            .ChannelConnected => {
                misshod.requestEvent(.Connected, .Idle);
                self.setSessionState(.ChannelData);
            },
            .ChannelData => {
                if (self.channel_write_buf_nbytes > 0) { // something to send
                    self.setSessionState(.ChannelDataTx);
                } else { // wait for incoming
                    self.setSessionState(.ChannelDataRxAdjustWindow);
                }
            },
            .ChannelDataRxAdjustWindow => {
                // https://datatracker.ietf.org/doc/html/rfc4254#section-5.2
                var pkt = BufferWriter.init(&misshod.iobuf, sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(MsgId.SSH_MSG_CHANNEL_WINDOW_ADJUST));
                try pkt.writeU32(0); // channel
                try pkt.writeU32(MaxPayload); // bytes to add
                misshod.requestWrite(try self.wrapPkt(&pkt, &misshod.iobuf), .Idle);
                self.setSessionState(.ChannelDataRx);
            },
            .ChannelDataRx => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .ChannelDataTx => {
                // request tx, FIXME need to honour window adjustments from the other side
                var pkt = BufferWriter.init(&misshod.iobuf, sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(MsgId.SSH_MSG_CHANNEL_DATA));
                // https://datatracker.ietf.org/doc/html/rfc4250#section-3.3
                try pkt.writeU32(0);
                try pkt.writeU32LenString(self.channel_write_buf[0..self.channel_write_buf_nbytes]);
                misshod.requestWrite(try self.wrapPkt(&pkt, &misshod.iobuf), .Idle);
                self.setSessionState(.ChannelDataTxComplete);
            },
            .ChannelDataTxComplete => {
                self.channel_write_buf_nbytes = 0;
                self.setSessionState(.ChannelData);
            },
        }
    }

    pub fn getChannelWriteBuffer(self: *Self) MisshodError![]u8 {
        if (self.channel_write_buf_nbytes > 0) {
            return &.{}; // not able to write
        } else {
            return &self.channel_write_buf;
        }
    }

    pub fn channelWriteComplete(self: *Self, nbytes: usize) MisshodError!void {
        TRACEDUMP(.Debug, "channelWriteComplete nbytes={d} sessionState={any} ioState={any}", .{ nbytes, self.sessionState, self.ioSessionState }, self.channel_write_buf[0..nbytes]);
        if (nbytes > self.channel_write_buf.len) {
            return IoError.tooBig;
        } else {
            self.channel_write_buf_nbytes = nbytes; // will be picked up for send in next .ChannelData -> .ChannelDataTx
        }

        if (self.sessionState == .ChannelDataRx) { // waiting to receive
            if (self.ioSessionState == .ReadPktHdr) { // nothing actually happening
                self.setSessionState(.ChannelDataTx);
                self.setIoSessionState(.Idle);
            }
        }
        // FIXME, if read is idling, cancel it - need to assume main's poll() is going to trip due to character write too though, FIXME

    }

    pub fn setPrivateKey(self: *Self, keydata_ascii: []const u8) MisshodError!void {
        if (self.privkey_ascii) |old| {
            self.allocator.free(old);
            self.privkey_ascii = null;
        }
        std.debug.assert(self.privkey_ascii == null);
        self.privkey_ascii = try self.allocator.dupe(u8, keydata_ascii);
    }

    pub fn setPrivateKeyPassphrase(self: *Self, data: []const u8) MisshodError!void {
        if (self.privkey_passphrase) |old| {
            self.allocator.free(old);
            self.privkey_passphrase = null;
        }
        std.debug.assert(self.privkey_passphrase == null);
        self.privkey_passphrase = try self.allocator.dupe(u8, data);
    }

    pub fn setAuthPassphrase(self: *Self, data: []const u8) MisshodError!void {
        if (self.auth_passphrase) |old| {
            self.allocator.free(old);
            self.auth_passphrase = null;
        }
        std.debug.assert(self.auth_passphrase == null);
        self.auth_passphrase = try self.allocator.dupe(u8, data);
    }

    // special case as we write direct to stream before entering binary pkt mode
    fn writeProtocolVersion(self: *Self, buf: []u8) []const u8 {
        const vers = std.fmt.bufPrint(buf, "{s}\r\n", .{client_version}) catch unreachable;
        TRACE(.Debug, "TX: version '{s}'", .{client_version});
        self.kex_hash_order = self.kex_hash_order.check(.V_C);
        self.kex_hasher.writeU32LenString(client_version);
        return vers;
    }

    fn getRecvBuffer(self: *Self, iobuf: []u8) MisshodError!BufferReader {
        var hdr: PktHdr = std.mem.bytesAsValue(PktHdr, iobuf[0..sizeof_PktHdr]).*;
        if (native_endian != .big) {
            // flip bytes
            std.mem.byteSwapAllFields(PktHdr, &hdr);
        }
        const payload_len = hdr.packet_length - hdr.padding_length - 1;
        const payload = iobuf[sizeof_PktHdr .. sizeof_PktHdr + payload_len];

        if (!self.encrypted) {
            return BufferReader.init(payload);
        } else {
            TRACEDUMP(.Debug, "all buf", .{}, iobuf);
            const pkt_len = payload_len + (sizeof_PktHdr) + hdr.padding_length;
            if (pkt_len > AesCtrT.block_size) { // if there's more to be decrypted after first block
                const remaining_pkt_bytes = pkt_len - AesCtrT.block_size;
                var dec: [MaxSSHPacket]u8 = undefined;
                self.s2c_aesctr.encrypt(iobuf[AesCtrT.block_size .. AesCtrT.block_size + remaining_pkt_bytes], dec[AesCtrT.block_size .. AesCtrT.block_size + remaining_pkt_bytes]); // use same offset into dec for simplicity

                TRACEDUMP(.Debug, "dec", .{}, dec[AesCtrT.block_size .. AesCtrT.block_size + remaining_pkt_bytes]);
                // copy decrypted back into writebuf
                @memcpy(iobuf[AesCtrT.block_size .. AesCtrT.block_size + remaining_pkt_bytes], dec[AesCtrT.block_size .. AesCtrT.block_size + remaining_pkt_bytes]);
                TRACEDUMP(.Debug, "writebuf", .{}, iobuf[0..pkt_len]);
            }

            // verify mac
            if (iobuf.len < mac_algo.key_length) {
                return error.InvalidPacketSize; // too small to have a mac
            }
            const rxmac = iobuf[pkt_len..iobuf.len]; // at the end
            var calcmac: [mac_algo.key_length]u8 = undefined;
            var m = mac_algo.init(self.s2c_mackey[0..mac_algo.key_length]);
            const seq = std.mem.nativeTo(u32, self.s2c_seq - 1, .big); // seq has already been incremented
            m.update(std.mem.asBytes(&seq));
            m.update(iobuf[0 .. iobuf.len - mac_algo.key_length]); // plaintext
            m.final(&calcmac);

            TRACEDUMP(.Debug, "rxmac", .{}, rxmac);
            TRACEDUMP(.Debug, "mackey", .{}, self.s2c_mackey[0..mac_algo.key_length]);
            TRACEDUMP(.Debug, "macseq", .{}, std.mem.asBytes(&seq));
            TRACEDUMP(.Debug, "macdata", .{}, iobuf[0 .. iobuf.len - mac_algo.key_length]);
            TRACEDUMP(.Debug, "calcmac", .{}, std.mem.asBytes(&calcmac));

            if (!std.mem.eql(u8, &calcmac, rxmac)) {
                return IoError.InvalidMacS2C;
            }

            // remove mac and return buffer containing just plaintext payload
            return BufferReader.init(iobuf[sizeof_PktHdr .. iobuf.len - mac_algo.key_length]);
        }
    }

    pub fn handlePacket(self: *Self, buf: []const u8, misshod: *Misshod) MisshodError!void {
        var rdr = try self.getRecvBuffer(misshod.iobuf[0..buf.len]);

        const msgid = try rdr.readU8();

        TRACE(.Debug, "handlePacket msgId={d}", .{msgid});
        TRACEDUMP(.Debug, "handlePacket", .{}, buf);

        switch (msgid) {
            @intFromEnum(MsgId.SSH_MSG_KEXINIT) => {
                TRACE(.Debug, "{any}", .{@as(MsgId, @enumFromInt(msgid))});

                self.kex_hash_order = self.kex_hash_order.check(.I_S);
                self.kex_hasher.writeU32LenString(rdr.payload[(rdr.off - 1)..]); // from before the msgid

                // https://datatracker.ietf.org/doc/html/rfc4253#section-7.1
                // https://datatracker.ietf.org/doc/html/rfc4251#section-5
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

                if (self.sessionState == .KexInitRead) {
                    self.setSessionState(.EcdhInitWrite);
                    self.setIoSessionState(.Idle);
                } else {
                    // go read another packet
                    self.setIoSessionState(.ReadPktHdr);
                }
            },
            @intFromEnum(MsgId.SSH_MSG_KEX_ECDH_REPLY) => {
                if (self.sessionState == .EcdhReply) {
                    TRACE(.Debug, "{any}", .{@as(MsgId, @enumFromInt(msgid))});

                    // server's public host key, store so we can ask user to ok it
                    self.hostkey_ks = try self.allocator.dupe(u8, try rdr.readU32LenString());
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
                    self.setIoSessionState(.Idle);
                } else {
                    return IoError.UnexpectedResponse;
                }
            },
            @intFromEnum(MsgId.SSH_MSG_NEWKEYS) => {
                if (self.sessionState == .NewKeysRead) {
                    self.setSessionState(.NewKeysWrite);
                    self.setIoSessionState(.Idle);
                } else {
                    return IoError.UnexpectedResponse;
                }
            },
            @intFromEnum(MsgId.SSH_MSG_SERVICE_ACCEPT) => {
                if (self.sessionState == .AuthServRsp) {
                    self.setSessionState(.AuthStart);
                    self.setIoSessionState(.Idle);
                } else {
                    return IoError.UnexpectedResponse;
                }
            },
            @intFromEnum(MsgId.SSH_MSG_USERAUTH_BANNER) => {
                TRACE(.Debug, "MsgId.SSH_MSG_USERAUTH_BANNER", .{});
                const banner = try rdr.readU32LenString();
                TRACE(.Info, "Server banner '{s}'", .{util.chomp(banner)});
                const lang = try rdr.readU32LenString();
                TRACE(.Debug, "Server banner language '{s}'", .{lang});
                // do another read
                self.setIoSessionState(.ReadPktHdr);
            },
            @intFromEnum(MsgId.SSH_MSG_USERAUTH_SUCCESS) => {
                // don't care what state we were in, we've been let in
                self.setIoSessionState(.Idle);
                self.setSessionState(.ChannelOpenReq);
            },
            @intFromEnum(MsgId.SSH_MSG_USERAUTH_FAILURE) => {
                misshod.requestEvent(.{ .EndSession = .AuthFailure }, .Idle);
            },
            @intFromEnum(MsgId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION) => {
                // uint32    recipient channel
                // uint32    sender channel
                // uint32    initial window size
                // uint32    maximum packet size
                self.setIoSessionState(.Idle);
                self.setSessionState(.ChannelPtyReq);
            },
            @intFromEnum(MsgId.SSH_MSG_CHANNEL_DATA) => {
                TRACE(.Debug, "MsgId.SSH_MSG_CHANNEL_DATA", .{});
                const channelnum = try rdr.readU32();
                const s = try rdr.readU32LenString();
                TRACE(.Debug, "got data chan={d} '{s}'\n", .{ channelnum, s });

                misshod.requestEvent(.{ .RxData = s }, .Idle);
                self.setSessionState(.ChannelData);
            },
            @intFromEnum(MsgId.SSH_MSG_DISCONNECT), @intFromEnum(MsgId.SSH_MSG_CHANNEL_EOF) => {
                misshod.requestEvent(.{ .EndSession = .Disconnect }, .Idle); // FIXME reason code
            },
            else => {
                // unhandled packet type
                TRACE(.Info, "Unhandled msg id={d}", .{msgid});
                self.setIoSessionState(.ReadPktHdr); // read again
            },
        }
    }

    pub fn advanceIoSession(self: *Self, misshod: *Misshod) MisshodError!void {
        std.debug.assert(misshod.iostate == .Idle); // we only get called once IO completes
        switch (self.ioSessionState) {
            .Idle => {
                TRACE(.Debug, "ioSessionState Idle", .{});
                try self.advanceSession(misshod);
            },
            .Init => {
                self.setIoSessionState(.VersionWrite);
            },
            .VersionWrite => {
                const sl = self.writeProtocolVersion(&misshod.iobuf);
                misshod.requestWrite(sl, .VersionReadLine);
            },
            .VersionReadLine => {
                // read first char
                misshod.requestRead(0, 1, .{ .VersionReadLineChar = misshod.iobuf[0..1] });
            },
            .VersionReadLineChar => |buf| {
                if (buf.len + 1 > misshod.iobuf.len) {
                    return IoError.noEOLFound;
                } else {
                    if (buf.len >= 2) {
                        if (buf[buf.len - 2] == '\r' and buf[buf.len - 1] == '\n') {
                            self.setIoSessionState(.{ .VersionReadLineCompletion = buf });
                            return;
                        }
                    }
                    // read next char
                    misshod.requestRead(buf.len, 1, .{ .VersionReadLineChar = misshod.iobuf[0 .. buf.len + 1] });
                }
            },
            .VersionReadLineCompletion => |buf| {
                self.setIoSessionState(.Idle);
                TRACE(.Debug, "RX: version '{s}'", .{util.chomp(buf)});
                self.kex_hash_order = self.kex_hash_order.check(.V_S);
                self.kex_hasher.writeU32LenString(util.chomp(buf));
            },
            .ReadPktHdr => {
                if (self.encrypted) {
                    misshod.requestRead(0, AesCtrT.block_size, .{ .ReadPktBody = misshod.iobuf[0..AesCtrT.block_size] });
                } else {
                    misshod.requestRead(0, sizeof_PktHdr, .{ .ReadPktBody = misshod.iobuf[0..sizeof_PktHdr] });
                }
            },
            .ReadPktBody => |buf| {
                if (self.encrypted) {
                    // https://datatracker.ietf.org/doc/html/rfc4253#section-6
                    // grab first encrypted block from writebuf
                    var firstblock_encbuf: [AesCtrT.block_size]u8 = undefined;
                    @memcpy(&firstblock_encbuf, buf);

                    // decrypt directly into iobuf
                    self.s2c_aesctr.encrypt(&firstblock_encbuf, misshod.iobuf[0..AesCtrT.block_size]);
                    TRACEDUMP(.Debug, "firstblock_dec(in payload)", .{}, misshod.iobuf[0..AesCtrT.block_size]);

                    // read PktHdr from first block
                    const pkthdr_size = sizeof_PktHdr;
                    var hdr: PktHdr = undefined;
                    hdr = std.mem.bytesToValue(PktHdr, buf[0..pkthdr_size]);
                    if (native_endian != .big) {
                        std.mem.byteSwapAllFields(PktHdr, &hdr);
                    }

                    // padding len is such that payload_len + sizeof(hdr) + padding = block size
                    const payload_len = hdr.packet_length - (hdr.padding_length + 1);
                    if (hdr.padding_length < 4) {
                        return IoError.InvalidPacketSize;
                    }
                    const pkt_len = payload_len + (sizeof_PktHdr) + hdr.padding_length;
                    // avoid reading obviously bad packet sizes
                    if (pkt_len < 8 or pkt_len > MaxSSHPacket) {
                        return IoError.InvalidPacketSize;
                    }

                    // calc number of remaining bytes + mac, read from network
                    var remaining_pkt_bytes: usize = 0;
                    if (pkt_len > AesCtrT.block_size) {
                        remaining_pkt_bytes = pkt_len - AesCtrT.block_size;
                    }
                    TRACE(.Debug, "About to read {d}\n", .{remaining_pkt_bytes + mac_algo.key_length});
                    //
                    misshod.requestRead(buf.len, (remaining_pkt_bytes + mac_algo.key_length), .{ .ReadPktCompletion = misshod.iobuf[0 .. buf.len + remaining_pkt_bytes + mac_algo.key_length] }); // on completion, how much we have

                    self.s2c_seq +%= 1;
                } else {
                    // copy header
                    var hdr: PktHdr = std.mem.bytesAsValue(PktHdr, buf[0..sizeof_PktHdr]).*;
                    if (native_endian != .big) {
                        // flip bytes
                        std.mem.byteSwapAllFields(PktHdr, &hdr);
                    }

                    TRACE(.Debug, ".ReadPktBody hdr={any}", .{hdr});
                    // read in payload
                    const payload_len = hdr.packet_length - hdr.padding_length - 1;
                    std.debug.assert(payload_len <= MaxPayload);

                    misshod.requestRead(buf.len, payload_len + hdr.padding_length, .{ .ReadPktCompletion = misshod.iobuf[0 .. buf.len + payload_len + hdr.padding_length] });
                    self.s2c_seq +%= 1;
                }
            },
            .ReadPktCompletion => |buf| {
                TRACEDUMP(.Debug, ".ReadPktCompletion", .{}, buf);
                try self.handlePacket(buf, misshod);
            },
        }
    }
};
