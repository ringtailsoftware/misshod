const std = @import("std");

const targetEndian: std.builtin.Endian = .big;

// Build hashes by writing ssh types. Updates hash on the fly without storing everything in a Buffer
pub fn Hasher(hash_algo: anytype) type {
    return struct {
        const Self = @This();
        comptime digest_length: usize = hash_algo.digest_length,
        h: hash_algo,
        msg_len: usize = 0,

        pub fn init() Self {
            return Self{
                .h = hash_algo.init(.{}),
                .digest_length = hash_algo.digest_length,
            };
        }

        // if digest is smaller than hash, truncate it
        // if digest if bigger than hash, extend https://datatracker.ietf.org/doc/html/rfc4253#section-7.2
        pub fn final(self: *Self, digest: []u8, extension: ?[]u8) void {
            var tmpdigest: [hash_algo.digest_length]u8 = undefined;
            self.h.final(&tmpdigest);

            if (digest.len == hash_algo.digest_length) { // asked for exact length
                @memcpy(digest, &tmpdigest);
                return;
            } else {
                if (digest.len < hash_algo.digest_length) { // asked for truncation
                    @memcpy(digest, tmpdigest[0..digest.len]);
                } else { // extension required
                    if (extension) |ext| {
                        // copy what we have into digest
                        @memcpy(digest[0..hash_algo.digest_length], &tmpdigest);

                        var remaining_len = digest.len - hash_algo.digest_length;
                        var digest_off: usize = hash_algo.digest_length;

                        outer: while (true) {
                            // create new hash of digest + ext
                            var exthasher = hash_algo.init(.{});
                            exthasher.update(ext);
                            exthasher.update(digest[0..digest_off]);
                            var exthash_digest: [hash_algo.digest_length]u8 = undefined;
                            exthasher.final(&exthash_digest);
                            // write new hash into digest
                            if (remaining_len <= hash_algo.digest_length) {
                                // fill remaining part of digest
                                @memcpy(digest[digest_off .. digest_off + remaining_len], exthash_digest[0..remaining_len]);
                                return;
                            } else {
                                // copy whole of exthash_digest in
                                @memcpy(digest[digest_off .. digest_off + hash_algo.digest_length], &exthash_digest);
                                remaining_len -= hash_algo.digest_length;
                                digest_off += hash_algo.digest_length;
                                continue :outer;
                            }
                        }
                        std.debug.assert(remaining_len == 0);
                        std.debug.assert(digest_off == digest.len);
                    } else {
                        std.debug.assert(false);
                    }
                }
            }
        }

        pub fn writeU8(self: *Self, v: u8) void {
            self.h.update(&[1]u8{v});
            self.msg_len += 1;
        }

        pub fn writeBoolean(self: *Self, v: bool) void {
            self.h.update(&[1]u8{if (v) 1 else 0});
            self.msg_len += 1;
        }

        pub fn writeU32(self: *Self, v: u32) void {
            const net_v = std.mem.nativeTo(u32, v, targetEndian);
            self.h.update(std.mem.asBytes(&net_v));
            self.msg_len += 4;
        }

        pub fn writeBytes(self: *Self, v: []const u8) void {
            self.h.update(v);
            self.msg_len += v.len;
        }

        pub fn writeMpint(self: *Self, v: []const u8) void {
            // if MSB of first byte is set, mpint must be padded
            // https://datatracker.ietf.org/doc/html/rfc4251#section-5
            const pad = v[0] & 0x80 > 0;
            if (pad) {
                self.writeU32(@intCast(v.len + 1));
                self.writeU8(0);
            } else {
                self.writeU32(@intCast(v.len));
            }
            self.writeBytes(v);
        }

        pub fn writeU32LenString(self: *Self, v: []const u8) void {
            self.writeU32(@intCast(v.len));
            self.writeBytes(v);
        }
    };
}

test "hasher" {
    // Generated with sha256 -s <input>
    var hasher = Hasher(std.crypto.hash.sha2.Sha256).init();
    var digest: [hasher.digest_length]u8 = undefined;
    hasher.final(&digest, null);
    try std.testing.expect(std.mem.eql(u8, &std.fmt.bytesToHex(digest, .lower), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));

    hasher = Hasher(std.crypto.hash.sha2.Sha256).init();
    hasher.writeU8('a');
    hasher.final(&digest, null);
    try std.testing.expect(std.mem.eql(u8, &std.fmt.bytesToHex(digest, .lower), "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"));

    hasher = Hasher(std.crypto.hash.sha2.Sha256).init();
    hasher.writeU8('a');
    hasher.writeU8('b');
    hasher.final(&digest, null);
    try std.testing.expect(std.mem.eql(u8, &std.fmt.bytesToHex(digest, .lower), "fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603"));

    hasher = Hasher(std.crypto.hash.sha2.Sha256).init();
    hasher.writeBytes(&[2]u8{ 'a', 'b' });
    hasher.writeU8('c');
    hasher.final(&digest, null);
    try std.testing.expect(std.mem.eql(u8, &std.fmt.bytesToHex(digest, .lower), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}
