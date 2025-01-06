const std = @import("std");
const util = @import("util.zig");
const TRACE = util.trace;
const TRACEDUMP = util.tracedump;
const MisshodClient = @import("misshod.zig").MisshodClient;
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
    ioSessionState: Protocol.IoSessionState,
    sessionState: SessionState,

    ecdh_ephem_keypair: Protocol.kex_algo.KeyPair = undefined,
    // In form U32LenString("ssh-ed25519"), U32LenString(secret)
    hostkey_ks: ?[]u8 = undefined, // K_S, slice of hostkey_ks_buf, allocated
    shared_secret_k: [Protocol.kex_algo.shared_length]u8 = undefined, // K
    kex_hasher: Hasher(Protocol.hash_algo) = undefined, // for building H
    kex_hash_order: Protocol.KexHashOrder = .Init,
    session_id: [Protocol.hash_algo.digest_length]u8 = undefined,
    keydata: Protocol.KeyDataBi,
    username: []const u8,
    rand: std.Random = undefined,
    encrypted: bool,
    channel_write_buf: [64]u8 = undefined, // FIXME size
    channel_write_buf_nbytes: usize,

    privkey_ascii: ?[]u8, // allocated  // FIXME deinit properly and clear
    privkey_passphrase: ?[]u8, //allocated
    auth_passphrase: ?[]u8, //allocated
    privkey_blob: [Protocol.srv_hostkey_algo.SecretKey.encoded_length]u8 = undefined,
    pubkey_blob: [Protocol.srv_hostkey_algo.PublicKey.encoded_length]u8 = undefined,

    pub fn init(rand: std.Random, username: []const u8, allocator: std.mem.Allocator) !Self {
        return .{
            .ioSessionState = .Init,
            .sessionState = .Init,
            .rand = rand,
            .allocator = allocator,
            .username = username,
            .encrypted = false,
            .keydata = Protocol.KeyDataBi.init(),
            .kex_hasher = Hasher(Protocol.hash_algo).init(), // for hashing H
            .privkey_ascii = null,
            .privkey_passphrase = null,
            .auth_passphrase = null,
            .channel_write_buf_nbytes = 0,
        };
    }

    pub fn setIoSessionState(self: *Self, newState: Protocol.IoSessionState) void {
        TRACE(.Debug, "ioSessionState {any} -> {any}", .{ self.ioSessionState, newState });
        self.ioSessionState = newState;
    }

    pub fn setSessionState(self: *Self, newState: SessionState) void {
        TRACE(.Debug, "sessionState {any} -> {any}", .{ self.sessionState, newState });
        self.sessionState = newState;
    }


    pub fn advanceSession(self: *Self, misshod: *MisshodClient) MisshodError!void {
        const outkeys = &self.keydata.c2s;

        switch (self.sessionState) {
            .Init => {
                self.setSessionState(.KexInitWrite);
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

                self.kex_hash_order = self.kex_hash_order.check(.I_C);
                self.kex_hasher.writeU32LenString(pkt.active());

                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf), .Idle);
                self.setSessionState(.KexInitRead);
            },
            .KexInitRead => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .EcdhInitWrite => {
                var pkt = BufferWriter.init(&misshod.iobuf, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_KEX_ECDH_INIT));

                self.ecdh_ephem_keypair = Protocol.kex_algo.KeyPair.generate();
                var q_c = self.ecdh_ephem_keypair.public_key;
                try pkt.writeU32LenString(&q_c);

                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf), .Idle);
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
                var pkt = BufferWriter.init(&misshod.iobuf, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_NEWKEYS));
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf), .Idle);
                self.setSessionState(.AuthServReq);
                self.encrypted = true; // have read and written SSH_MSG_NEWKEYS, encrypted from now on
            },
            .AuthServReq => {
                // https://datatracker.ietf.org/doc/html/rfc4253
                var pkt = BufferWriter.init(&misshod.iobuf, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_SERVICE_REQUEST));
                try pkt.writeU32LenString("ssh-userauth");
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf), .Idle);
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
                    decodePrivKey(privkey_ascii, null, &self.privkey_blob, &self.pubkey_blob) catch |err| {
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
                var pkt = BufferWriter.init(&misshod.iobuf, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_REQUEST));
                //https://datatracker.ietf.org/doc/html/rfc4252#section-5.1
                //https://datatracker.ietf.org/doc/html/rfc4252#section-8

                const secretkey = try Protocol.srv_hostkey_algo.SecretKey.fromBytes(self.privkey_blob);
                const keypair = try Protocol.srv_hostkey_algo.KeyPair.fromSecretKey(secretkey);

                var backing_pubkey_buf: [256]u8 = undefined;
                var typed_pubkey_buf = BufferWriter.init(&backing_pubkey_buf, 0);
                try typed_pubkey_buf.writeU32LenString(Protocol.srv_hostkey_algo_name);
                try typed_pubkey_buf.writeU32LenString(&keypair.public_key.bytes);

                try pkt.writeU32LenString(self.username);
                try pkt.writeU32LenString("ssh-connection");
                try pkt.writeU32LenString("publickey");
                try pkt.writeBoolean(true);
                try pkt.writeU32LenString(Protocol.srv_hostkey_algo_name);
                try pkt.writeU32LenString(typed_pubkey_buf.active());

                var backing_sigbuffer_buf: [512]u8 = undefined;
                var sigbuffer = BufferWriter.init(&backing_sigbuffer_buf, 0);
                try sigbuffer.writeU32LenString(&self.session_id);
                try sigbuffer.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_REQUEST));
                try sigbuffer.writeU32LenString(self.username);
                try sigbuffer.writeU32LenString("ssh-connection");
                try sigbuffer.writeU32LenString("publickey");
                try sigbuffer.writeBoolean(true);
                try sigbuffer.writeU32LenString(Protocol.srv_hostkey_algo_name);
                try sigbuffer.writeU32LenString(typed_pubkey_buf.active());

                // gen signature
                const sig = try keypair.sign(sigbuffer.active(), null);
                const sigbytes = sig.toBytes();
                TRACEDUMP(.Debug, "sigbytes", .{}, &sigbytes);

                var backing_typed_sig_buf: [256]u8 = undefined;
                var typed_sig_buf = BufferWriter.init(&backing_typed_sig_buf, 0);
                try typed_sig_buf.writeU32LenString(Protocol.srv_hostkey_algo_name);
                try typed_sig_buf.writeU32LenString(&sigbytes);
                try pkt.writeU32LenString(typed_sig_buf.active());

                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf), .Idle);
                self.setSessionState(.AuthRsp);
            },
            .PubkeyAuthDecodeKeyPassword => {
                // attempt decode with passphrase
                // if this fails, drop to password auth
                decodePrivKey(self.privkey_ascii.?, self.privkey_passphrase, &self.privkey_blob, &self.pubkey_blob) catch {
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
                var pkt = BufferWriter.init(&misshod.iobuf, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_REQUEST));
                //https://datatracker.ietf.org/doc/html/rfc4252#section-5.1
                //https://datatracker.ietf.org/doc/html/rfc4252#section-8
                try pkt.writeU32LenString(self.username);
                try pkt.writeU32LenString("ssh-connection");
                try pkt.writeU32LenString("password");
                try pkt.writeBoolean(false);
                try pkt.writeU32LenString(self.auth_passphrase.?);
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf), .Idle);
                self.setSessionState(.AuthRsp);
            },
            .AuthRsp => { // for password or pubkey
                self.setIoSessionState(.ReadPktHdr);
            },
            .ChannelOpenReq => {
                var pkt = BufferWriter.init(&misshod.iobuf, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN));
                // https://datatracker.ietf.org/doc/html/rfc4254#section-5.1
                try pkt.writeU32LenString("session"); // https://datatracker.ietf.org/doc/html/rfc4250#section-4.9.1
                try pkt.writeU32(0); // sender channel
                try pkt.writeU32(Protocol.MaxPayload); // initial window size
                try pkt.writeU32(Protocol.MaxPayload); // maximum packet size
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf), .Idle);
                self.setSessionState(.ChannelOpenRsp);
            },
            .ChannelOpenRsp => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .ChannelPtyReq => {
                var pkt = BufferWriter.init(&misshod.iobuf, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_REQUEST));
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

                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf), .Idle);
                self.setSessionState(.ChannelShellReq);
            },
            .ChannelShellReq => {
                var pkt = BufferWriter.init(&misshod.iobuf, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_REQUEST));
                // https://datatracker.ietf.org/doc/html/rfc4254#section-6.2
                try pkt.writeU32(0);
                try pkt.writeU32LenString("shell");
                try pkt.writeBoolean(false); // want reply

                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf), .Idle);
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
                var pkt = BufferWriter.init(&misshod.iobuf, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_WINDOW_ADJUST));
                try pkt.writeU32(0); // channel
                try pkt.writeU32(Protocol.MaxPayload); // bytes to add
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf), .Idle);
                self.setSessionState(.ChannelDataRx);
            },
            .ChannelDataRx => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .ChannelDataTx => {
                // request tx, FIXME need to honour window adjustments from the other side
                var pkt = BufferWriter.init(&misshod.iobuf, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_DATA));
                // https://datatracker.ietf.org/doc/html/rfc4250#section-3.3
                try pkt.writeU32(0);
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
    pub fn writeProtocolVersion(self: *Self, buf: []u8) []const u8 {
        const vers = std.fmt.bufPrint(buf, "{s}\r\n", .{Protocol.version}) catch unreachable;
        TRACE(.Debug, "TX: version '{s}'", .{Protocol.version});
        self.kex_hash_order = self.kex_hash_order.check(.V_C);
        self.kex_hasher.writeU32LenString(Protocol.version);
        return vers;
    }

    pub fn handlePacket(self: *Self, buf: []const u8, misshod: *MisshodClient) MisshodError!void {
        var rdr = try misshod.getRecvBuffer(misshod.iobuf[0..buf.len], &self.keydata.s2c);

        const msgid = try rdr.readU8();

        TRACE(.Debug, "handlePacket msgId={d}", .{msgid});
        TRACEDUMP(.Debug, "handlePacket", .{}, buf);

        switch (msgid) {
            @intFromEnum(Protocol.MsgId.SSH_MSG_KEXINIT) => {
                TRACE(.Debug, "{any}", .{@as(Protocol.MsgId, @enumFromInt(msgid))});

                self.kex_hash_order = self.kex_hash_order.check(.I_S);
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
                    self.setSessionState(.EcdhInitWrite);
                    self.setIoSessionState(.Idle);
                } else {
                    // go read another packet
                    self.setIoSessionState(.ReadPktHdr);
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_KEX_ECDH_REPLY) => {
                if (self.sessionState == .EcdhReply) {
                    TRACE(.Debug, "{any}", .{@as(Protocol.MsgId, @enumFromInt(msgid))});

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
                    @memcpy(&self.shared_secret_k, &try Protocol.kex_algo.scalarmult(self.ecdh_ephem_keypair.secret_key, srv_pub_ephem[0..self.ecdh_ephem_keypair.secret_key.len].*));

                    TRACEDUMP(.Debug, "shared secret len={d}", .{self.shared_secret_k.len}, &self.shared_secret_k);

                    self.kex_hash_order = self.kex_hash_order.check(.K);
                    self.kex_hasher.writeMpint(&self.shared_secret_k);

                    // Produce H/session_id/key exchange hash
                    // Both sides now have this
                    var kexhash: [Protocol.hash_algo.digest_length]u8 = undefined; // session_id, H
                    self.kex_hasher.final(&kexhash, null);
                    TRACEDUMP(.Debug, "kexhash: (len={d})", .{kexhash.len}, &kexhash);

                    @memcpy(&self.session_id, &kexhash); // store as session_id

                    // verify server's signature on the hash
                    var nb = util.NamedBlob.init(self.hostkey_ks.?);
                    const rawpubkey = try nb.getBlob();
                    const pubkey = try Protocol.srv_hostkey_algo.PublicKey.fromBytes(rawpubkey[0..Protocol.srv_hostkey_algo.PublicKey.encoded_length].*);

                    nb = util.NamedBlob.init(sig_exch_hash);
                    const rawsig = try nb.getBlob();
                    const sig = Protocol.srv_hostkey_algo.Signature.fromBytes(rawsig[0..Protocol.srv_hostkey_algo.Signature.encoded_length].*);

                    try sig.verify(&kexhash, pubkey);

                    // generate keys
                    try self.keydata.genKeys(kexhash, self.shared_secret_k, self.session_id);

                    self.setSessionState(.CheckHostKey);
                    self.setIoSessionState(.Idle);
                } else {
                    return IoError.UnexpectedResponse;
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_NEWKEYS) => {
                if (self.sessionState == .NewKeysRead) {
                    self.setSessionState(.NewKeysWrite);
                    self.setIoSessionState(.Idle);
                } else {
                    return IoError.UnexpectedResponse;
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_SERVICE_ACCEPT) => {
                if (self.sessionState == .AuthServRsp) {
                    self.setSessionState(.AuthStart);
                    self.setIoSessionState(.Idle);
                } else {
                    return IoError.UnexpectedResponse;
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_BANNER) => {
                TRACE(.Debug, "Protocol.MsgId.SSH_MSG_USERAUTH_BANNER", .{});
                const banner = try rdr.readU32LenString();
                TRACE(.Info, "Server banner '{s}'", .{util.chomp(banner)});
                const lang = try rdr.readU32LenString();
                TRACE(.Debug, "Server banner language '{s}'", .{lang});
                // do another read
                self.setIoSessionState(.ReadPktHdr);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_SUCCESS) => {
                // don't care what state we were in, we've been let in
                self.setIoSessionState(.Idle);
                self.setSessionState(.ChannelOpenReq);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_FAILURE) => {
                misshod.requestEvent(.{ .EndSession = .AuthFailure }, .Idle);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION) => {
                // uint32    recipient channel
                // uint32    sender channel
                // uint32    initial window size
                // uint32    maximum packet size
                self.setIoSessionState(.Idle);
                self.setSessionState(.ChannelPtyReq);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_DATA) => {
                TRACE(.Debug, "Protocol.MsgId.SSH_MSG_CHANNEL_DATA", .{});
                const channelnum = try rdr.readU32();
                const s = try rdr.readU32LenString();
                TRACE(.Debug, "got data chan={d} '{s}'\n", .{ channelnum, s });

                misshod.requestEvent(.{ .RxData = s }, .Idle);
                self.setSessionState(.ChannelData);
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
