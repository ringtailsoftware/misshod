const std = @import("std");
const util = @import("util.zig");
const TRACE = util.trace;
const TRACEDUMP = util.tracedump;
const MisshodServer = @import("misshod.zig").MisshodServer;
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
const Protocol = @import("protocol.zig");

pub const SessionState = enum {
    Init,
    KexInitWrite,
    KexInitRead,
    EcdhInitRead,
    EcdhReplyWrite,
    NewKeysRead,
    NewKeysWrite,
    AuthRead,
    AuthRspServReqSuccess,
    CheckUserPasswordAuth,
    UserPasswordAuthDenied,
    UserAuthAccepted,
    AuthPkAllowed,
    Authenticated,
    ChannelOpenConfirmWrite,
    ChannelRspWrite,
    ChannelData,
    ChannelConnected,
    ChannelDataRxAdjustWindow,
    ChannelDataRx,
    ChannelDataTx,
    ChannelDataTxComplete,
};

pub const Session = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    ioSessionState: Protocol.IoSessionState,
    sessionState: SessionState,

    ecdh_ephem_keypair: Protocol.kex_algo.KeyPair = undefined,
    shared_secret_k: [Protocol.kex_algo.shared_length]u8 = undefined, // K
    kex_hasher: Hasher(Protocol.hash_algo) = undefined, // for building H
    kex_hash_order: Protocol.KexHashOrder = .Init,
    session_id: [Protocol.hash_algo.digest_length]u8 = undefined,
    keydata: Protocol.KeyDataBi,
    rand: std.Random = undefined,
    encrypted: bool,
    channel_write_buf: [64]u8 = undefined, // FIXME size
    channel_write_buf_nbytes: usize,

    privkey_ascii: ?[]u8, // allocated  // FIXME deinit properly and clear
    privkey_passphrase: ?[]u8, //allocated
    auth_passphrase: ?[]u8, //allocated

    auth_pubkey_attempted:[Protocol.srv_hostkey_algo.PublicKey.encoded_length]u8 = undefined, // U32LenString with algo name + pubkey
    q_c:[Protocol.srv_hostkey_algo.PublicKey.encoded_length]u8 = undefined,

    // server host key
    privkey_blob: [Protocol.srv_hostkey_algo.SecretKey.encoded_length]u8 = undefined,
    pubkey_blob: [Protocol.srv_hostkey_algo.PublicKey.encoded_length]u8 = undefined,

    chan:u32 = 0,

    pub fn init(rand: std.Random, hostkey_ascii: []const u8, allocator: std.mem.Allocator) !Self {
        var s = Self {
            .ioSessionState = .Init,
            .sessionState = .Init,
            .rand = rand,
            .allocator = allocator,
            .encrypted = false,
            .keydata = Protocol.KeyDataBi.init(),
            .kex_hasher = Hasher(Protocol.hash_algo).init(), // for hashing H
            .privkey_ascii = null,
            .privkey_passphrase = null,
            .auth_passphrase = null,
            .channel_write_buf_nbytes = 0,
        };

        try decodePrivKey(hostkey_ascii, null, &s.privkey_blob, &s.pubkey_blob);

        return s;
    }

    pub fn setIoSessionState(self: *Self, newState: Protocol.IoSessionState) void {
        TRACE(.Debug, "ioSessionState {any} -> {any}", .{ self.ioSessionState, newState });
        self.ioSessionState = newState;
    }

    pub fn setSessionState(self: *Self, newState: SessionState) void {
        TRACE(.Debug, "sessionState {any} -> {any}", .{ self.sessionState, newState });
        self.sessionState = newState;
    }

    pub fn grantAccess(self: *Self, allow:bool) MisshodError!void {
        if (self.sessionState != .CheckUserPasswordAuth) {
            return IoError.UnexpectedResponse;
        } else {
            if (allow) {
                self.setSessionState(.UserAuthAccepted);
            } else {
                self.setSessionState(.UserPasswordAuthDenied);
            }
        }
    }

    pub fn advanceSession(self: *Self, misshod: *MisshodServer) MisshodError!void {
        const outkeys = &self.keydata.s2c;

        switch (self.sessionState) {
            .Init => {
                self.setSessionState(.KexInitRead);
            },
            .KexInitRead => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .KexInitWrite => {
                var pkt = BufferWriter.init(&misshod.iobuf, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_KEXINIT));
                var cookie: [16]u8 = undefined;
                self.rand.bytes(&cookie);
                try pkt.writeBytes(&cookie);

                try pkt.writeU32LenString(Protocol.kex_algo_name); // kex
                try pkt.writeU32LenString(Protocol.srv_hostkey_algo_name); // hostkey verification
                try pkt.writeU32LenString(Protocol.enc_algo_name); // enc c2s
                try pkt.writeU32LenString(Protocol.enc_algo_name); // enc s2c
                try pkt.writeU32LenString(Protocol.mac_algo_name); // mac c2s
                try pkt.writeU32LenString(Protocol.mac_algo_name); // mac s2c
                try pkt.writeU32LenString("none"); // compression c2s
                try pkt.writeU32LenString("none"); // compression s2c
                try pkt.writeU32LenString(""); // lang c2s
                try pkt.writeU32LenString(""); // lang s2c

                const first_kex_packet_follows = false;
                try pkt.writeBoolean(first_kex_packet_follows);
                try pkt.writeU32(0); // reserved

                self.kex_hash_order = self.kex_hash_order.check(.I_S);
                self.kex_hasher.writeU32LenString(pkt.active());

                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf), .Idle);
                self.setSessionState(.EcdhInitRead);
            },
            .EcdhInitRead => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .EcdhReplyWrite => {
                var pkt = BufferWriter.init(&misshod.iobuf, Protocol.sizeof_PktHdr);

                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_KEX_ECDH_REPLY));

                // hostkey_ks
                var backing_buf: [256]u8 = undefined;
                var typed_ks_buf = BufferWriter.init(&backing_buf, 0);
                try typed_ks_buf.writeU32LenString(Protocol.srv_hostkey_algo_name);
                try typed_ks_buf.writeU32LenString(&self.pubkey_blob);

                TRACEDUMP(.Debug, "ks", .{}, typed_ks_buf.payload);
                self.kex_hash_order = self.kex_hash_order.check(.K_S);
                self.kex_hasher.writeU32LenString(typed_ks_buf.payload);
                try pkt.writeU32LenString(typed_ks_buf.payload);

                self.kex_hash_order = self.kex_hash_order.check(.Q_C);
                self.kex_hasher.writeU32LenString(&self.q_c);

                self.ecdh_ephem_keypair = Protocol.kex_algo.KeyPair.generate();
                try pkt.writeU32LenString(&self.ecdh_ephem_keypair.public_key);
                TRACEDUMP(.Debug, "qs", .{}, &self.ecdh_ephem_keypair.public_key);

                self.kex_hash_order = self.kex_hash_order.check(.Q_S);
                self.kex_hasher.writeU32LenString(&self.ecdh_ephem_keypair.public_key);

                // generate shared secret
                @memcpy(&self.shared_secret_k, &try Protocol.kex_algo.scalarmult(self.ecdh_ephem_keypair.secret_key, self.q_c));

                TRACEDUMP(.Debug, "shared secret len={d}", .{self.shared_secret_k.len}, &self.shared_secret_k);

                self.kex_hash_order = self.kex_hash_order.check(.K);
                self.kex_hasher.writeMpint(&self.shared_secret_k);

                // Produce H/session_id/key exchange hash
                // Both sides now have this
                var kexhash: [Protocol.hash_algo.digest_length]u8 = undefined; // session_id, H
                self.kex_hasher.final(&kexhash, null);
                TRACEDUMP(.Debug, "kexhash: (len={d})", .{kexhash.len}, &kexhash);

                @memcpy(&self.session_id, &kexhash); // store as session_id

                const secretkey = try Protocol.srv_hostkey_algo.SecretKey.fromBytes(self.privkey_blob);
                const host_keypair = try Protocol.srv_hostkey_algo.KeyPair.fromSecretKey(secretkey);

                const sig = try host_keypair.sign(&kexhash, null);
                var typed_sig_buf = BufferWriter.init(&backing_buf, 0);
                try typed_sig_buf.writeU32LenString(Protocol.srv_hostkey_algo_name);
                try typed_sig_buf.writeU32LenString(&sig.toBytes());

                try pkt.writeU32LenString(typed_sig_buf.payload);

                // generate keys
                try self.keydata.genKeys(kexhash, self.shared_secret_k, self.session_id);

                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf), .Idle);

                self.setSessionState(.NewKeysWrite);
            },
            .NewKeysWrite => {
                // https://datatracker.ietf.org/doc/html/rfc4253#section-7.2
                var pkt = BufferWriter.init(&misshod.iobuf, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_NEWKEYS));
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf), .Idle);
                self.setSessionState(.NewKeysRead);

            },
            .NewKeysRead => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .AuthRead => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .AuthRspServReqSuccess => {
                var pkt = BufferWriter.init(&misshod.iobuf, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_SERVICE_ACCEPT));
                try pkt.writeU32LenString("ssh-userauth");
                self.setSessionState(.AuthRead);
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf), .Idle);
            },
            .CheckUserPasswordAuth => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .UserPasswordAuthDenied => {
                var pkt = BufferWriter.init(&misshod.iobuf, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_FAILURE));
                try pkt.writeU32LenString("password,publickey");
                try pkt.writeBoolean(false);    // partial success
                self.setSessionState(.AuthRead);
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf), .Idle);
            },
            .UserAuthAccepted => {
                var pkt = BufferWriter.init(&misshod.iobuf, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_SUCCESS));
                self.setSessionState(.Authenticated);
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf), .Idle);
            },
            .AuthPkAllowed => {
                var pkt = BufferWriter.init(&misshod.iobuf, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_PK_OK));
                try pkt.writeU32LenString(Protocol.srv_hostkey_algo_name);

                var backing_pubkey_buf: [256]u8 = undefined;
                var typed_pubkey_buf = BufferWriter.init(&backing_pubkey_buf, 0);
                try typed_pubkey_buf.writeU32LenString(Protocol.srv_hostkey_algo_name);
                try typed_pubkey_buf.writeU32LenString(&self.auth_pubkey_attempted);

                try pkt.writeU32LenString(typed_pubkey_buf.payload);
                self.setSessionState(.AuthRead);
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf), .Idle);
            },
            .Authenticated => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .ChannelOpenConfirmWrite => {
                var pkt = BufferWriter.init(&misshod.iobuf, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION));
                try pkt.writeU32(self.chan);
                try pkt.writeU32(self.chan);
                try pkt.writeU32(256);  // init window size, FIXME
                try pkt.writeU32(256);  // max window size
                self.setSessionState(.ChannelConnected);
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf), .Idle);
            },
            .ChannelRspWrite => {
                //https://datatracker.ietf.org/doc/html/rfc4254#section-5.4
                var pkt = BufferWriter.init(&misshod.iobuf, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_SUCCESS));
                try pkt.writeU32(self.chan);
                self.setSessionState(.ChannelData);
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf), .Idle);
            },
            .ChannelConnected => {
                misshod.requestEvent(.Connected, .Idle);
                self.setSessionState(.ChannelData);
            },
            .ChannelData => {
                if (self.channel_write_buf_nbytes > 0) { // something to send
                    TRACE(.Debug, "ChannelData have data to send len={d}", .{self.channel_write_buf_nbytes});
                    self.setSessionState(.ChannelDataRxAdjustWindow);
                } else { // wait for incoming
                    TRACE(.Debug, "ChannelData reading", .{});
                    self.setSessionState(.ChannelDataRx);
                }
            },
            .ChannelDataRxAdjustWindow => {
                // https://datatracker.ietf.org/doc/html/rfc4254#section-5.2
                var pkt = BufferWriter.init(&misshod.iobuf, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_WINDOW_ADJUST));
                try pkt.writeU32(0); // channel
                try pkt.writeU32(Protocol.MaxPayload); // bytes to add
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf), .Idle);
                self.setSessionState(.ChannelDataTx);
            },
            .ChannelDataRx => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .ChannelDataTx => {
                // request tx, FIXME need to honour window adjustments from the other side
                var pkt = BufferWriter.init(&misshod.iobuf, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_DATA));
                // https://datatracker.ietf.org/doc/html/rfc4250#section-3.3
                try pkt.writeU32(0);    // FIXME chan?
                try pkt.writeU32LenString(self.channel_write_buf[0..self.channel_write_buf_nbytes]);
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf), .Idle);
                self.setSessionState(.ChannelDataTxComplete);
            },
            .ChannelDataTxComplete => {
                self.channel_write_buf_nbytes = 0;
                self.setSessionState(.ChannelData);
            },
        }
    }

    pub fn getChannelWriteBuffer(self: *Self) MisshodError![]u8 {
        if (self.channel_write_buf_nbytes > 0 and self.ioSessionState == .Idle) {
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
            self.setSessionState(.ChannelData);
            self.setIoSessionState(.Idle);
        }
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
    pub fn writeProtocolVersion(self: *Self, buf: []u8) []const u8 {
        const vers = std.fmt.bufPrint(buf, "{s}\r\n", .{Protocol.version}) catch unreachable;
        TRACE(.Debug, "TX: version '{s}'", .{Protocol.version});
        self.kex_hash_order = self.kex_hash_order.check(.V_S);
        self.kex_hasher.writeU32LenString(Protocol.version);
        return vers;
    }

    pub fn handlePacket(self: *Self, buf: []const u8, misshod: *MisshodServer) MisshodError!void {
        var rdr = try misshod.getRecvBuffer(misshod.iobuf[0..buf.len], &self.keydata.c2s);

        const msgid = try rdr.readU8();

        TRACE(.Debug, "handlePacket msgId={d}", .{msgid});
        TRACEDUMP(.Debug, "handlePacket", .{}, buf);

        switch (msgid) {
            @intFromEnum(Protocol.MsgId.SSH_MSG_KEXINIT) => {
                TRACE(.Debug, "{any}", .{@as(Protocol.MsgId, @enumFromInt(msgid))});

                self.kex_hash_order = self.kex_hash_order.check(.I_C);
                self.kex_hasher.writeU32LenString(rdr.payload[(rdr.off - 1)..]); // from before the msgid

                // https://datatracker.ietf.org/doc/html/rfc4253#section-7.1
                // https://datatracker.ietf.org/doc/html/rfc4251#section-5
                const cookie = try rdr.readBytes(16);
                TRACEDUMP(.Debug, "cookie", .{}, cookie);

                const listnames = [_][]const u8{
                    "Protocol.kex_algorithms",
                    "server_host_key_algorithms",
                    "encryption_algorithms_client_to_server",
                    "encryption_algorithms_server_to_client",
                    "Protocol.mac_algorithms_client_to_server",
                    "Protocol.mac_algorithms_server_to_client",
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
                    self.setSessionState(.KexInitWrite);
                    self.setIoSessionState(.Idle);
                } else {
                    // go read another packet
                    self.setIoSessionState(.ReadPktHdr);
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_KEX_ECDH_INIT) => {
                if (self.sessionState == .EcdhInitRead) {
                    const q_c = try rdr.readU32LenString();
                    if (q_c.len != Protocol.srv_hostkey_algo.PublicKey.encoded_length) {
                        // client may have sent a hopeful q_c for wrong algo
                        // go read another packet
                        self.setIoSessionState(.ReadPktHdr);
                        return;
                    }
                    TRACEDUMP(.Debug, "q_c", .{}, q_c);
                    @memcpy(&self.q_c, q_c);

                    self.setSessionState(.EcdhReplyWrite);
                    self.setIoSessionState(.Idle);
                } else {
                    return IoError.UnexpectedResponse;
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_NEWKEYS) => {
                if (self.sessionState == .NewKeysRead) {
                    self.encrypted = true; // have read and written SSH_MSG_NEWKEYS, encrypted from now on
                    self.setSessionState(.AuthRead);
                    self.setIoSessionState(.ReadPktHdr);
                } else {
                    return IoError.UnexpectedResponse;
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_SERVICE_REQUEST) => {
                if (self.sessionState == .AuthRead) {
                    const svcname = try rdr.readU32LenString();
                    if (std.mem.eql(u8, svcname, "ssh-userauth")) {
                        self.setSessionState(.AuthRspServReqSuccess);
                        self.setIoSessionState(.Idle);
                    } else {
                        return IoError.UnimplementedService;
                    }
                } else {
                    return IoError.UnexpectedResponse;  // why is client asking now?
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_REQUEST) => {
                if (self.sessionState == .AuthRead) {
                    //https://datatracker.ietf.org/doc/html/rfc4252#section-5.1
                    //https://datatracker.ietf.org/doc/html/rfc4252#section-8
                    const username = try rdr.readU32LenString();
                    const svcname = try rdr.readU32LenString();
                    const authtyp = try rdr.readU32LenString();

                    TRACE(.Debug, "username={s} svcname={s} authtyp={s}", .{username, svcname, authtyp});
                    if (!std.mem.eql(u8, svcname, "ssh-connection")) {
                        return IoError.UnimplementedService;
                    }

                    if (std.mem.eql(u8, authtyp, "password")) {
                        const b = try rdr.readBoolean();
                        if (b != false) {
                            return IoError.UnexpectedResponse;
                        }
                        const password = try rdr.readU32LenString();
                        self.setSessionState(.CheckUserPasswordAuth);
                        misshod.requestEvent(.{ .UserAuth = .{
                            .username = username,
                            .auth = .{.Password = password},
                        } }, .Idle);
                    } else if (std.mem.eql(u8, authtyp, "publickey")) {
                        const forreal = try rdr.readBoolean();
                        const algoname = try rdr.readU32LenString();
                        const typed_pubkey = try rdr.readU32LenString();

                        TRACE(.Debug, "forreal={any} algoname={s} typed_pubkey len={d}", .{forreal, algoname, typed_pubkey.len});

                        // extract raw pubkey
                        var nb = util.NamedBlob.init(typed_pubkey);
                        const rawpubkey = try nb.getBlob();

                        // stash pubkey for AuthPkAllowed
                        if (rawpubkey.len != Protocol.srv_hostkey_algo.PublicKey.encoded_length) {
                            self.setSessionState(.UserPasswordAuthDenied);
                            self.setIoSessionState(.Idle);
                            return;
                        }
                        @memcpy(&self.auth_pubkey_attempted, rawpubkey);

                        if (!forreal) {
                            self.setSessionState(.AuthPkAllowed);
                            self.setIoSessionState(.Idle);
                        } else {
                            if (!std.mem.eql(u8, algoname, Protocol.srv_hostkey_algo_name)) {
                                self.setSessionState(.UserPasswordAuthDenied);
                                self.setIoSessionState(.Idle);
                                return;
                            }

                            const pubkey = try Protocol.srv_hostkey_algo.PublicKey.fromBytes(rawpubkey[0..Protocol.srv_hostkey_algo.PublicKey.encoded_length].*);
                            const typedsig = try rdr.readU32LenString();

                            // extract raw sig bytes
                            var nbsig = util.NamedBlob.init(typedsig);
                            const rawsig = try nbsig.getBlob();

                            const sig = Protocol.srv_hostkey_algo.Signature.fromBytes(rawsig[0..Protocol.srv_hostkey_algo.Signature.encoded_length].*);

                            var backing_sigbuffer_buf: [512]u8 = undefined;
                            var sigbuffer = BufferWriter.init(&backing_sigbuffer_buf, 0);
                            try sigbuffer.writeU32LenString(&self.session_id);
                            try sigbuffer.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_REQUEST));
                            try sigbuffer.writeU32LenString(username);
                            try sigbuffer.writeU32LenString("ssh-connection");
                            try sigbuffer.writeU32LenString("publickey");
                            try sigbuffer.writeBoolean(true);
                            try sigbuffer.writeU32LenString(Protocol.srv_hostkey_algo_name);
                            try sigbuffer.writeU32LenString(typed_pubkey);

                            TRACEDUMP(.Debug, "typed_pubkey", .{}, typed_pubkey);
                            TRACEDUMP(.Debug, "rawpubkey", .{}, rawpubkey);
                            TRACEDUMP(.Debug, "rawsig", .{}, rawsig);

                            // verify sig, as provided by user
                            sig.verify(sigbuffer.payload, pubkey) catch {
                                TRACE(.Info, "pubkey sig verify failed", .{});
                                self.setSessionState(.UserPasswordAuthDenied);
                                self.setIoSessionState(.Idle);
                                return;
                            };

                            // sig verify ok, confirm with app that this username+pubkey is allowed
                            self.setSessionState(.CheckUserPasswordAuth);
                            misshod.requestEvent(.{ .UserAuth = .{
                                .username = username,
                                .auth = .{.Pubkey = typed_pubkey},
                            } }, .Idle);
                        }
                    } else if (std.mem.eql(u8, authtyp, "none")) {
                        self.setSessionState(.CheckUserPasswordAuth);
                        misshod.requestEvent(.{ .UserAuth = .{
                            .username = username,
                            .auth = null
                        } }, .Idle);
                    } else {
                        return IoError.UnimplementedService;
                    }
                } else {
                    return IoError.UnexpectedResponse;  // why is client asking now?
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN) => {
                // https://datatracker.ietf.org/doc/html/rfc4254#section-5.1

                const chantype = try rdr.readU32LenString();
                self.chan = try rdr.readU32();
                const initwinsz = try rdr.readU32();
                const maxwinsz = try rdr.readU32();
                _ = initwinsz;  // FIXME
                _ = maxwinsz;

                if (!std.mem.eql(u8, chantype, "session")) {
                    return IoError.UnimplementedService;
                }

                self.setSessionState(.ChannelOpenConfirmWrite);
                self.setIoSessionState(.Idle);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_REQUEST) => {
                // https://datatracker.ietf.org/doc/html/rfc4254#section-6.2
                const chan = try rdr.readU32();
                if (chan != self.chan) {
                    std.debug.assert(false);    // FIXME, need to record the channels client is asking for and honour them
                }
                const typ = try rdr.readU32LenString();
                const wantreply = try rdr.readBoolean();
                if (std.mem.eql(u8, typ, "pty-req")) {
                    const term = try rdr.readU32LenString();
                    const cols = try rdr.readU32();
                    const rows = try rdr.readU32();
                    const widthpx = try rdr.readU32();
                    const heightpx = try rdr.readU32();

                    _ = term;
                    _ = cols;
                    _ = rows;
                    _ = widthpx;
                    _ = heightpx;
                } else if (std.mem.eql(u8, typ, "shell")) {
                    // FIXME, any special shell behaviour here
                } else {
                    TRACE(.Debug, "channel req '{s}'", .{typ});
                    if (wantreply) {    // can't do this
                        return IoError.UnimplementedService;
                    }
                }

                if (wantreply) {
                    self.setSessionState(.ChannelRspWrite);
                    self.setIoSessionState(.Idle);
                } else {
                    self.setSessionState(.ChannelData);                
                    self.setIoSessionState(.Idle);
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_DATA) => {
                if (self.sessionState == .ChannelDataRx) {  // only accept data when we're expecting it
                    TRACE(.Debug, "Protocol.MsgId.SSH_MSG_CHANNEL_DATA", .{});
                    const channelnum = try rdr.readU32();
                    const s = try rdr.readU32LenString();
                    TRACE(.Debug, "got data chan={d} '{s}'\n", .{ channelnum, s });

                    misshod.requestEvent(.{ .RxData = s }, .Idle);
                    self.setSessionState(.ChannelData);
                } else {
                    return IoError.UnexpectedResponse;
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_DISCONNECT), @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_EOF) => {
                misshod.requestEvent(.{ .EndSession = .Disconnect }, .Idle); // FIXME reason code
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_WINDOW_ADJUST) => {
                // TBD
                self.setIoSessionState(.ReadPktHdr); // read again
            },
            else => {
                // unhandled packet type
                TRACE(.Info, "Unhandled msg id={d}", .{msgid});
                self.setIoSessionState(.ReadPktHdr); // read again
            },
        }
    }

};
