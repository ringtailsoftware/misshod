const std = @import("std");
const crypto = std.crypto;
const aes = std.crypto.core.aes;
const ctr_mode = crypto.core.modes.ctr;

// convenience wrapper, defining block_size, iv_size, key_size
// ensures that the ctr mode counter matches the number of bytes sent
pub fn AesCtr(enc_algo: anytype) type {
    return struct {
        const Self = @This();
        pub const block_size = 16;
        pub const iv_size = 16;
        pub const key_size = enc_algo.key_bits / 8;
        ctx: aes.AesEncryptCtx(enc_algo),
        iv: [iv_size]u8,
        origiv: [iv_size]u8,
        bytecount: u32,

        pub fn init(iv: [iv_size]u8, key: [key_size]u8) Self {
            return Self{
                .ctx = enc_algo.initEnc(key),
                .iv = iv,
                .bytecount = 0,
                .origiv = iv,
            };
        }

        pub fn encrypt(self: *Self, in: []const u8, out: []u8) void {
            std.debug.assert(out.len == in.len); // equal sizes only

            // fixup the counter iv according to the bytecount
            const orig = std.mem.readInt(u128, &self.origiv, .big);
            std.mem.writeInt(u128, &self.iv, (self.bytecount / iv_size) +% std.mem.toNative(u128, orig, .little), .big);
            ctr_mode(aes.AesEncryptCtx(enc_algo), self.ctx, out, in, self.iv, std.builtin.Endian.big);
            self.bytecount +%= @intCast(in.len);
        }
    };
}

const util = @import("util.zig");
const TRACE = util.trace;
const TRACEDUMP = util.tracedump;

const testalgos = .{ aes.Aes128, aes.Aes256 };

test "aesctr-bigblock-twostage" {
    inline for (testalgos) |algo| {
        const AesCtrT = AesCtr(algo);

        const iv: [AesCtrT.iv_size]u8 = .{'I'} ** AesCtrT.iv_size;
        const key: [AesCtrT.key_size]u8 = .{'K'} ** AesCtrT.key_size;
        var aesctx_enc = AesCtrT.init(iv, key);
        const block0_plaintext: [AesCtrT.block_size * 10]u8 = .{'0'} ** (AesCtrT.block_size * 10);
        var block0_ciphertext: [AesCtrT.block_size * 10]u8 = undefined;
        aesctx_enc.encrypt(&block0_plaintext, &block0_ciphertext);

        //        TRACEDUMP(.Debug, "plaintext0", .{}, &block0_plaintext);
        //        TRACEDUMP(.Debug, "ciphertext0", .{}, &block0_ciphertext);

        const block1_plaintext: [AesCtrT.block_size * 10]u8 = .{'1'} ** (AesCtrT.block_size * 10);
        var block1_ciphertext: [AesCtrT.block_size * 10]u8 = undefined;
        aesctx_enc.encrypt(&block1_plaintext, &block1_ciphertext);

        //        TRACEDUMP(.Debug, "plaintext1", .{}, &block1_plaintext);
        //        TRACEDUMP(.Debug, "ciphertext1", .{}, &block1_ciphertext);

        var aesctx_dec = AesCtrT.init(iv, key);
        var block0_recovered_plaintext: [AesCtrT.block_size * 10]u8 = undefined;
        aesctx_dec.encrypt(&block0_ciphertext, &block0_recovered_plaintext);

        //        TRACEDUMP(.Debug, "ciphertext0", .{}, &block0_ciphertext);
        //        TRACEDUMP(.Debug, "recovered plaintext0", .{}, &block0_recovered_plaintext);

        try std.testing.expect(std.mem.eql(u8, &block0_plaintext, &block0_recovered_plaintext));

        var block1_recovered_plaintext: [AesCtrT.block_size * 10]u8 = undefined;
        aesctx_dec.encrypt(&block1_ciphertext, &block1_recovered_plaintext);

        //        TRACEDUMP(.Debug, "ciphertext1", .{}, &block1_ciphertext);
        //        TRACEDUMP(.Debug, "recovered plaintext1", .{}, &block1_recovered_plaintext);

        try std.testing.expect(std.mem.eql(u8, &block1_plaintext, &block1_recovered_plaintext));
    }
}

test "aesctr-doubleblock-twostage" {
    inline for (testalgos) |algo| {
        const AesCtrT = AesCtr(algo);

        const iv: [AesCtrT.iv_size]u8 = .{'I'} ** AesCtrT.iv_size;
        const key: [AesCtrT.key_size]u8 = .{'K'} ** AesCtrT.key_size;
        var aesctx_enc = AesCtrT.init(iv, key);
        const block0_plaintext: [AesCtrT.block_size]u8 = .{'0'} ** AesCtrT.block_size;
        var block0_ciphertext: [AesCtrT.block_size]u8 = undefined;
        aesctx_enc.encrypt(&block0_plaintext, &block0_ciphertext);

        //        TRACEDUMP(.Debug, "plaintext0", .{}, &block0_plaintext);
        //        TRACEDUMP(.Debug, "ciphertext0", .{}, &block0_ciphertext);

        const block1_plaintext: [AesCtrT.block_size]u8 = .{'1'} ** AesCtrT.block_size;
        var block1_ciphertext: [AesCtrT.block_size]u8 = undefined;
        aesctx_enc.encrypt(&block1_plaintext, &block1_ciphertext);

        //        TRACEDUMP(.Debug, "plaintext1", .{}, &block1_plaintext);
        //        TRACEDUMP(.Debug, "ciphertext1", .{}, &block1_ciphertext);

        var aesctx_dec = AesCtrT.init(iv, key);
        var block0_recovered_plaintext: [AesCtrT.block_size]u8 = undefined;
        aesctx_dec.encrypt(&block0_ciphertext, &block0_recovered_plaintext);

        //        TRACEDUMP(.Debug, "ciphertext0", .{}, &block0_ciphertext);
        //        TRACEDUMP(.Debug, "recovered plaintext0", .{}, &block0_recovered_plaintext);

        try std.testing.expect(std.mem.eql(u8, &block0_plaintext, &block0_recovered_plaintext));

        var block1_recovered_plaintext: [AesCtrT.block_size]u8 = undefined;
        aesctx_dec.encrypt(&block1_ciphertext, &block1_recovered_plaintext);

        //        TRACEDUMP(.Debug, "ciphertext1", .{}, &block1_ciphertext);
        //        TRACEDUMP(.Debug, "recovered plaintext1", .{}, &block1_recovered_plaintext);

        try std.testing.expect(std.mem.eql(u8, &block1_plaintext, &block1_recovered_plaintext));
    }
}

test "aesctr-singleblock-normal" {
    inline for (testalgos) |algo| {
        const AesCtrT = AesCtr(algo);

        const iv: [AesCtrT.iv_size]u8 = .{'I'} ** AesCtrT.iv_size;
        const key: [AesCtrT.key_size]u8 = .{'K'} ** AesCtrT.key_size;
        var aesctx_enc = AesCtrT.init(iv, key);
        const block_plaintext: [AesCtrT.block_size]u8 = .{'D'} ** AesCtrT.block_size;
        var block_ciphertext: [AesCtrT.block_size]u8 = undefined;
        aesctx_enc.encrypt(&block_plaintext, &block_ciphertext);

        //    TRACEDUMP(.Debug, "plaintext", .{}, &block_plaintext);
        //    TRACEDUMP(.Debug, "ciphertext", .{}, &block_ciphertext);

        var aesctx_dec = AesCtrT.init(iv, key);
        var block_recovered_plaintext: [AesCtrT.block_size]u8 = undefined;
        aesctx_dec.encrypt(&block_ciphertext, &block_recovered_plaintext);

        //    TRACEDUMP(.Debug, "ciphertext", .{}, &block_ciphertext);
        //    TRACEDUMP(.Debug, "recovered plaintext", .{}, &block_recovered_plaintext);

        try std.testing.expect(std.mem.eql(u8, &block_plaintext, &block_recovered_plaintext));
    }
}

test "aesctr-doubleblock-normal" {
    inline for (testalgos) |algo| {
        const AesCtrT = AesCtr(algo);

        const iv: [AesCtrT.iv_size]u8 = .{'I'} ** AesCtrT.iv_size;
        const key: [AesCtrT.key_size]u8 = .{'K'} ** AesCtrT.key_size;
        var aesctx_enc = AesCtrT.init(iv, key);
        const plaintext: [AesCtrT.block_size * 2]u8 = .{'D'} ** (AesCtrT.block_size * 2);
        var ciphertext: [AesCtrT.block_size * 2]u8 = undefined;
        aesctx_enc.encrypt(&plaintext, &ciphertext);

        //        TRACEDUMP(.Debug, "plaintext", .{}, &plaintext);
        //        TRACEDUMP(.Debug, "ciphertext", .{}, &ciphertext);

        var aesctx_dec = AesCtrT.init(iv, key);
        var recovered_plaintext: [AesCtrT.block_size * 2]u8 = undefined;
        aesctx_dec.encrypt(&ciphertext, &recovered_plaintext);

        //        TRACEDUMP(.Debug, "ciphertext", .{}, &ciphertext);
        //        TRACEDUMP(.Debug, "recovered plaintext", .{}, &recovered_plaintext);

        try std.testing.expect(std.mem.eql(u8, &plaintext, &recovered_plaintext));
    }
}

test "aesctr-singleblock-wrongkey" {
    inline for (testalgos) |algo| {
        const AesCtrT = AesCtr(algo);

        const iv: [AesCtrT.iv_size]u8 = .{'I'} ** AesCtrT.iv_size;
        const key: [AesCtrT.key_size]u8 = .{'K'} ** AesCtrT.key_size;
        var aesctx_enc = AesCtrT.init(iv, key);
        const block_plaintext: [AesCtrT.block_size]u8 = .{'D'} ** AesCtrT.block_size;
        var block_ciphertext: [AesCtrT.block_size]u8 = undefined;

        aesctx_enc.encrypt(&block_plaintext, &block_ciphertext);

        const keywrong: [AesCtrT.key_size]u8 = .{'L'} ** AesCtrT.key_size;
        var aesctx_dec = AesCtrT.init(iv, keywrong);
        var block_recovered_plaintext: [AesCtrT.block_size]u8 = undefined;
        aesctx_dec.encrypt(&block_ciphertext, &block_recovered_plaintext);

        try std.testing.expect(!std.mem.eql(u8, &block_plaintext, &block_recovered_plaintext));
    }
}

test "aesctr-singleblock-wrongiv" {
    inline for (testalgos) |algo| {
        const AesCtrT = AesCtr(algo);

        const iv: [AesCtrT.iv_size]u8 = .{'I'} ** AesCtrT.iv_size;
        const key: [AesCtrT.key_size]u8 = .{'K'} ** AesCtrT.key_size;
        var aesctx_enc = AesCtrT.init(iv, key);
        const block_plaintext: [AesCtrT.block_size]u8 = .{'D'} ** AesCtrT.block_size;
        var block_ciphertext: [AesCtrT.block_size]u8 = undefined;

        aesctx_enc.encrypt(&block_plaintext, &block_ciphertext);

        const ivwrong: [AesCtrT.iv_size]u8 = .{'J'} ** AesCtrT.iv_size;
        var aesctx_dec = AesCtrT.init(ivwrong, key);
        var block_recovered_plaintext: [AesCtrT.block_size]u8 = undefined;
        aesctx_dec.encrypt(&block_ciphertext, &block_recovered_plaintext);

        try std.testing.expect(!std.mem.eql(u8, &block_plaintext, &block_recovered_plaintext));
    }
}
