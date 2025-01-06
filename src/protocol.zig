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

pub const CommDir = enum {
    ClientToServer,
    ServerToClient,
};

// https://datatracker.ietf.org/doc/html/rfc4250#section-4.1.2
pub const MsgId = enum(u8) {
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
    SSH_MSG_USERAUTH_PK_OK = 60,
    SSH_MSG_GLOBAL_REQUEST = 80,
    SSH_MSG_CHANNEL_OPEN = 90,
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91,
    SSH_MSG_CHANNEL_WINDOW_ADJUST = 93,
    SSH_MSG_CHANNEL_DATA = 94,
    SSH_MSG_CHANNEL_EXTENDED_DATA = 95,
    SSH_MSG_CHANNEL_EOF = 96,
    SSH_MSG_CHANNEL_REQUEST = 98,
    SSH_MSG_CHANNEL_SUCCESS = 99,
};


// SSH packet header, appears before payload
// https://datatracker.ietf.org/doc/html/rfc4253#section-6
pub const PktHdr = packed struct {
    packet_length: u32,
    padding_length: u8,
};

// Number of bytes used by PktHdr
// https://datatracker.ietf.org/doc/html/rfc4253#section-6
pub const sizeof_PktHdr = @bitSizeOf(PktHdr) / 8;

// order in which items must be hashed to produce kex hash, H
// The key exchange hash is built up piecemeal through several states
// Calling check to advance to the next state asserts if it's done in the wrong order
pub const KexHashOrder = enum { // https://datatracker.ietf.org/doc/html/rfc5656#section-4
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

pub const MaxSSHPacket = 4096; // Can be smaller https://datatracker.ietf.org/doc/html/rfc4253#section-5.3
pub const MaxPayload = (MaxSSHPacket - (sizeof_PktHdr + 255 + mac_algo.key_length));
pub const MaxIVLen = 20; // number of bytes to generate for IVs
pub const MaxKeyLen = 64; // number of bytes to generate for keys

// https://datatracker.ietf.org/doc/html/rfc4253#section-4.2
pub const version = "SSH-2.0-SSH_ZS-0.0.1";

pub const hash_algo = std.crypto.hash.sha2.Sha256;
pub const hash_algo_name = "hmac-sha2-256";

pub const kex_algo = std.crypto.dh.X25519;
pub const kex_algo_name = "curve25519-sha256";

pub const srv_hostkey_algo = std.crypto.sign.Ed25519;
pub const srv_hostkey_algo_name = "ssh-ed25519";

pub const mac_algo = std.crypto.auth.hmac.sha2.HmacSha256;
pub const mac_algo_name = "hmac-sha2-256";

pub const enc_algo = std.crypto.core.aes.Aes256;
pub const enc_algo_name = "aes256-ctr";
pub const AesCtrT = AesCtr(enc_algo);

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

pub const KeyDataUni = struct {
    iv: [MaxIVLen]u8 = undefined,
    key: [MaxKeyLen]u8 = undefined,
    mackey: [MaxKeyLen]u8 = undefined,
    seq: u32,
    aesctr: AesCtrT = undefined,
};

pub const KeyDataBi = struct {
    const Self = @This();

    c2s: KeyDataUni,
    s2c: KeyDataUni,

    pub fn init() Self {
        return Self {
            .c2s = .{.seq = 0},
            .s2c = .{.seq = 0},
        };
    }

    // generate session keys from shared secret
    pub fn genKeys(self:* Self, H: [hash_algo.digest_length]u8, shared_secret_k:[kex_algo.shared_length]u8, session_id: [hash_algo.digest_length]u8) !void {

        // https://datatracker.ietf.org/doc/html/rfc4253#section-7.2

        var hasher: Hasher(hash_algo) = undefined;

        // prepare contact(K,H) = K:mpint concat H:raw
        var backing: [4 + kex_algo.shared_length + 1 + hash_algo.digest_length]u8 = undefined; // 4 for len, 1 for possible padding
        var khbuf = BufferWriter.init(&backing, 0);
        try khbuf.writeMpint(&shared_secret_k); // K
        try khbuf.writeBytes(&H); // H
        const data_kh = khbuf.payload;

        // c2s.iv
        hasher = Hasher(hash_algo).init();
        hasher.writeBytes(data_kh);
        hasher.writeU8('A'); // "A"
        hasher.writeBytes(&session_id); // session_id
        hasher.final(&self.c2s.iv, data_kh);
        TRACEDUMP(.Debug, "c2s.iv", .{}, &self.c2s.iv);

        // s2c.iv
        hasher = Hasher(hash_algo).init();
        hasher.writeBytes(data_kh);
        hasher.writeU8('B'); // "B"
        hasher.writeBytes(&session_id); // session_id
        hasher.final(&self.s2c.iv, data_kh);
        TRACEDUMP(.Debug, "s2c.iv", .{}, &self.s2c.iv);

        // c2s.key
        hasher = Hasher(hash_algo).init();
        hasher.writeBytes(data_kh);
        hasher.writeU8('C'); // "C"
        hasher.writeBytes(&session_id); // session_id
        hasher.final(&self.c2s.key, data_kh);
        TRACEDUMP(.Debug, "c2s.key", .{}, &self.c2s.key);

        // s2c.key
        hasher = Hasher(hash_algo).init();
        hasher.writeBytes(data_kh);
        hasher.writeU8('D'); // "D"
        hasher.writeBytes(&session_id); // session_id
        hasher.final(&self.s2c.key, data_kh);
        TRACEDUMP(.Debug, "s2c.key", .{}, &self.s2c.key);

        // c2s.mackey
        hasher = Hasher(hash_algo).init();
        hasher.writeBytes(data_kh);
        hasher.writeU8('E'); // "E"
        hasher.writeBytes(&session_id); // session_id
        hasher.final(&self.c2s.mackey, data_kh);
        TRACEDUMP(.Debug, "c2s.mackey", .{}, &self.c2s.mackey);

        // s2c.mackey
        hasher = Hasher(hash_algo).init();
        hasher.writeBytes(data_kh);
        hasher.writeU8('F'); // "F"
        hasher.writeBytes(&session_id); // session_id
        hasher.final(&self.s2c.mackey, data_kh);
        TRACEDUMP(.Debug, "s2c.mackey", .{}, &self.s2c.mackey);

        // setup aesctrs
        self.c2s.aesctr = AesCtrT.init(self.c2s.iv[0..AesCtrT.iv_size].*, self.c2s.key[0..AesCtrT.key_size].*);
        self.s2c.aesctr = AesCtrT.init(self.s2c.iv[0..AesCtrT.iv_size].*, self.s2c.key[0..AesCtrT.key_size].*);
    }
};

pub fn wrapPkt(rand:*std.Random, encrypted:bool, keysuni:*KeyDataUni, buffer: *BufferWriter, iobuf: []u8) MisshodError![]const u8 {
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
    rand.bytes(rndbuf[0..padding_length]);
    _ = try buffer.writeBytes(rndbuf[0..padding_length]);

    if (encrypted) {
        var out: [MaxSSHPacket]u8 = undefined;

        TRACEDUMP(.Debug, "sendbuffer enc:plaintext", .{}, buffer.payload);
        keysuni.aesctr.encrypt(buffer.payload, out[0..buffer.payload.len]);

        var mac: [mac_algo.key_length]u8 = undefined;
        var m = mac_algo.init(keysuni.mackey[0..mac_algo.key_length]);
        const seq = std.mem.nativeTo(u32, keysuni.seq, .big);
        m.update(std.mem.asBytes(&seq));
        m.update(buffer.payload); // plaintext
        m.final(&mac);

        TRACEDUMP(.Debug, "mackey", .{}, keysuni.mackey[0..mac_algo.key_length]);
        TRACEDUMP(.Debug, "macseq", .{}, std.mem.asBytes(&seq));
        TRACEDUMP(.Debug, "macdata", .{}, buffer.payload);

        // new bufferwriter, to append mac to out
        var out_buffer = BufferWriter.init(&out, buffer.payload.len); // append
        try out_buffer.writeBytes(&mac);

        // everything is now encrypted and in out_buffer with mac, copy back to self.writebuf before sending
        @memcpy(iobuf[0..out_buffer.payload.len], out_buffer.payload);

        TRACEDUMP(.Debug, "enc send", .{}, iobuf[0..out_buffer.payload.len]);

        keysuni.seq +%= 1;
        return iobuf[0..out_buffer.payload.len];
    } else {
        keysuni.seq +%= 1;
        return iobuf[0..buffer.payload.len];
    }
}

