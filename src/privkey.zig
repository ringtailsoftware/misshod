const std = @import("std");
const util = @import("util.zig");
const crypto = std.crypto;
const TRACE = util.trace;
const TRACEDUMP = util.tracedump;
const AesCtr = @import("aesctr.zig").AesCtr;
const BufferReader = @import("buffer.zig").BufferReader;
const BufferError = @import("buffer.zig").BufferError;

// cat id_ed25519  | grep -v "^-----" | base64 -d | xxd

const KdfError = crypto.pwhash.KdfError;
const HasherError = crypto.pwhash.HasherError;

pub const PrivKeyError = PrivKeyInternalError || BufferError || std.base64.Error || crypto.pwhash.Error || KdfError || HasherError || std.crypto.errors.EncodingError;

pub const PrivKeyInternalError = error{
    PrivKeyOutofSpace,
    BadPrivKey,
    InvalidKeyDecrypt,
    InvalidInput,
    UnsupportedPrivKey,
};

// This format has only been tested for Ed25519 files
const srv_hostkey_algo = std.crypto.sign.Ed25519;

fn decodeAsciiToBinary(keydata_ascii: []const u8, keydata_bin_buf: []u8) PrivKeyError![]u8 {
    const pre_banner = "-----BEGIN OPENSSH PRIVATE KEY-----";
    const post_banner = "-----END OPENSSH PRIVATE KEY-----";

    var b64_slice_opt: ?[]const u8 = null;
    if (std.ascii.indexOfIgnoreCase(keydata_ascii, pre_banner)) |pre_banner_start| {
        if (std.ascii.indexOfIgnoreCase(keydata_ascii, post_banner)) |post_banner_start| {
            b64_slice_opt = keydata_ascii[pre_banner_start + pre_banner.len .. post_banner_start];
        }
    }
    if (b64_slice_opt) |b64_slice| {
        TRACEDUMP(.Debug, "b64", .{}, b64_slice);
        var decoder = std.base64.Base64DecoderWithIgnore.init(std.base64.standard_alphabet_chars, '=', "\n");
        const decoded_size = try decoder.calcSizeUpperBound(b64_slice.len);
        if (decoded_size > keydata_bin_buf.len) {
            return PrivKeyError.PrivKeyOutofSpace;
        }
        const sz = decoder.decode(keydata_bin_buf, b64_slice) catch return PrivKeyError.BadPrivKey;
        return keydata_bin_buf[0..sz];
    } else {
        return PrivKeyError.BadPrivKey;
    }
}

pub fn decodePrivKey(keydata_ascii: []const u8, passphrase_opt: ?[]const u8, privkey_blob: *[srv_hostkey_algo.SecretKey.encoded_length]u8, pubkey_blob: *[srv_hostkey_algo.PublicKey.encoded_length]u8) PrivKeyError!void {
    var keydata_bin_buf: [1024]u8 = undefined;
    const bin = try decodeAsciiToBinary(keydata_ascii, &keydata_bin_buf);
    TRACEDUMP(.Debug, "raw len={d}", .{bin.len}, bin);

    // http://dnaeon.github.io/openssh-private-key-binary-format/
    const AuthMagic = "openssh-key-v1\x00";
    if (!std.mem.eql(u8, AuthMagic, bin[0..AuthMagic.len])) {
        return PrivKeyError.BadPrivKey; // Not magical enough
    }

    var buffer = BufferReader.init(bin[AuthMagic.len..]);
    const ciphername = try buffer.readU32LenString();

    const kdfname = try buffer.readU32LenString();
    const kdfoptions_section = try buffer.readU32LenString();
    const n_keys = try buffer.readU32();

    if (n_keys != 1) {
        return PrivKeyError.BadPrivKey; // All known files have a single keypair
    }

    TRACE(.Debug, "ciphername={s} kdfname={s} n_keys={d}\n", .{ ciphername, kdfname, n_keys });

    const pubkey = try buffer.readU32LenString();
    TRACEDUMP(.Debug, "pubkey", .{}, pubkey);

    var kbuffer = BufferReader.init(pubkey);
    const pkey_algo = try kbuffer.readU32LenString();
    TRACE(.Debug, "pkey_algo={s}\n", .{pkey_algo});
    const pkey_blob = try kbuffer.readU32LenString();
    TRACEDUMP(.Debug, "pkey_blob", .{}, pkey_blob);

    const enc_section_off = buffer.off + 4 + AuthMagic.len; // current position is before u32 length field, then data blob
    const enc_section = try buffer.readU32LenString();

    if (std.mem.eql(u8, ciphername, "aes256-ctr")) {
        if (std.mem.eql(u8, kdfname, "bcrypt")) {
            if (passphrase_opt) |passphrase| {
                var buffer_kdfopt = BufferReader.init(kdfoptions_section);
                const salt = try buffer_kdfopt.readU32LenString();
                const rounds = try buffer_kdfopt.readU32();
                TRACEDUMP(.Debug, "salt rounds={d}", .{rounds}, salt);
                if (salt.len != 16) {
                    return PrivKeyError.BadPrivKey;
                }

                const enc_algo = crypto.core.aes.Aes256;
                const AesCtrT = AesCtr(enc_algo);
                var hash: [AesCtrT.key_size + AesCtrT.iv_size]u8 = undefined;
                // https://github.com/openssh/openssh-portable/blob/826483d51a9fee60703298bbf839d9ce37943474/sshkey.c#L2880
                // need zig 0.14.0 for this https://github.com/ziglang/zig/pull/22027
                try crypto.pwhash.bcrypt.opensshKdf(passphrase, salt[0..16], &hash, rounds);
                TRACEDUMP(.Debug, "bcrypt hash", .{}, &hash);
                // https://www.thedigitalcatonline.com/blog/2021/06/03/public-key-cryptography-openssh-private-keys/#a-poorly-documented-format-2ea8
                var aesctr = AesCtrT.init(hash[AesCtrT.key_size..].*, hash[0..AesCtrT.key_size].*);
                var dec: [1024]u8 = undefined; // FIXME
                aesctr.encrypt(enc_section, dec[0..enc_section.len]);
                TRACEDUMP(.Debug, "dec", .{}, dec[0..enc_section.len]);
                // copy decrypted area over original encrypted
                @memcpy(keydata_bin_buf[enc_section_off .. enc_section_off + enc_section.len], dec[0..enc_section.len]);
            } else {
                return PrivKeyError.InvalidKeyDecrypt;
            }
        } else {
            return PrivKeyError.UnsupportedPrivKey;
        }
    } else {
        if (!std.mem.eql(u8, ciphername, "none")) {
            return PrivKeyError.UnsupportedPrivKey; // aes256-ctr/none are only options we support
        }
    }

    TRACEDUMP(.Debug, "enc_section", .{}, enc_section);
    var encbuffer = BufferReader.init(enc_section);

    const checkint1 = try encbuffer.readU32();
    const checkint2 = try encbuffer.readU32();

    TRACE(.Debug, "checkint1={d} checkint2={d}\n", .{ checkint1, checkint2 });
    if (checkint1 != checkint2) { // should be same, proving key decryption worked
        return PrivKeyError.InvalidKeyDecrypt;
    }

    TRACE(.Debug, "enc section len = {d}\n", .{enc_section.len});
    TRACE(.Debug, "enc encbuffer local pos={d}\n", .{encbuffer.off});

    const key_algo = try encbuffer.readU32LenString();
    TRACE(.Debug, "key_algo={s}\n", .{key_algo});

    const key_blob_pub = try encbuffer.readU32LenString();
    TRACEDUMP(.Debug, "key_blob_pub", .{}, key_blob_pub);

    @memcpy(pubkey_blob, key_blob_pub);

    const key_blob_prv = try encbuffer.readU32LenString();
    TRACEDUMP(.Debug, "key_blob_prv", .{}, key_blob_prv);

    @memcpy(privkey_blob, key_blob_prv);
}

const testkey_valid = "-----BEGIN OPENSSH PRIVATE KEY-----\n" ++
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n" ++
    "QyNTUxOQAAACDog6jr6QPaMp+fpV6mmzHL3y8JZUWJ17oDr2AVcPd09QAAAJiIu1EaiLtR\n" ++
    "GgAAAAtzc2gtZWQyNTUxOQAAACDog6jr6QPaMp+fpV6mmzHL3y8JZUWJ17oDr2AVcPd09Q\n" ++
    "AAAECmd7pZcmWYhcQO0+7Oj0nfKWUtxISW8PApUuU2mMEo3OiDqOvpA9oyn5+lXqabMcvf\n" ++
    "LwllRYnXugOvYBVw93T1AAAAE3RyakBtdWRkeS5mcml0ei5ib3gBAg==\n" ++
    "-----END OPENSSH PRIVATE KEY-----\n";

const testkey_invalid_bad_preamble = "-----BEGIN sheep PRIVATE KEY-----\n" ++
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n" ++
    "QyNTUxOQAAACDog6jr6QPaMp+fpV6mmzHL3y8JZUWJ17oDr2AVcPd09QAAAJiIu1EaiLtR\n" ++
    "GgAAAAtzc2gtZWQyNTUxOQAAACDog6jr6QPaMp+fpV6mmzHL3y8JZUWJ17oDr2AVcPd09Q\n" ++
    "AAAECmd7pZcmWYhcQO0+7Oj0nfKWUtxISW8PApUuU2mMEo3OiDqOvpA9oyn5+lXqabMcvf\n" ++
    "LwllRYnXugOvYBVw93T1AAAAE3RyakBtdWRkeS5mcml0ei5ib3gBAg==\n" ++
    "-----END OPENSSH PRIVATE KEY-----\n";

const testkey_invalid_missing_footer = "-----BEGIN OPENSSH PRIVATE KEY-----\n" ++
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n" ++
    "QyNTUxOQAAACDog6jr6QPaMp+fpV6mmzHL3y8JZUWJ17oDr2AVcPd09QAAAJiIu1EaiLtR\n" ++
    "GgAAAAtzc2gtZWQyNTUxOQAAACDog6jr6QPaMp+fpV6mmzHL3y8JZUWJ17oDr2AVcPd09Q\n" ++
    "AAAECmd7pZcmWYhcQO0+7Oj0nfKWUtxISW8PApUuU2mMEo3OiDqOvpA9oyn5+lXqabMcvf\n" ++
    "LwllRYnXugOvYBVw93T1AAAAE3RyakBtdWRkeS5mcml0ei5ib3gBAg==\n";

const testkey_invalid_bad_base64 = "-----BEGIN OPENSSH PRIVATE KEY-----\n" ++
    "!3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n" ++
    "QyNTUxOQAAACDog6jr6QPaMp+fpV6mmzHL3y8JZUWJ17oDr2AVcPd09QAAAJiIu1EaiLtR\n" ++
    "GgAAAAtzc2gtZWQyNTUxOQAAACDog6jr6QPaMp+fpV6mmzHL3y8JZUWJ17oDr2AVcPd09Q\n" ++
    "AAAECmd7pZcmWYhcQO0+7Oj0nfKWUtxISW8PApUuU2mMEo3OiDqOvpA9oyn5+lXqabMcvf\n" ++
    "LwllRYnXugOvYBVw93T1AAAAE3RyakBtdWRkeS5mcml0ei5ib3gBAg==\n" ++
    "-----END OPENSSH PRIVATE KEY-----\n";

const testkey_encrypted_valid_passworded = "-----BEGIN OPENSSH PRIVATE KEY-----\n" ++
    "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBbMFVQ8d\n" ++
    "i1La+cBNrgXD80AAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIL0bjghULlZAQmP5\n" ++
    "rM/Q04YVwfpVMDn7UYVuQhD0VoL5AAAAoL2DUXL8F88zDCQ3fctyJwJ25+nOwx5wIVKsYX\n" ++
    "HBoLMzX2IfngLErsk4phzQ0NFUyP1m33LkgJE9xTXCd5NjP9jOZvMt9d9OK85CBanVd40L\n" ++
    "HH5xk/jrsrnfEKK5Jp51xgCLWhCwUNVhxU1WpLGnKU+v04XDLRAfvM3Z7J/D6X2QsjHpVc\n" ++
    "g2ILO29XLBcTFbYRCfxSezVzrkURuId+d3WYQ=\n" ++
    "-----END OPENSSH PRIVATE KEY-----\n";

const testkey_encrypted_valid_password = "secretpassword";

test "decodepriv" {
    var blob: [srv_hostkey_algo.SecretKey.encoded_length]u8 = undefined;
    var pubblob: [srv_hostkey_algo.PublicKey.encoded_length]u8 = undefined;

    try std.testing.expectError(PrivKeyError.BadPrivKey, decodePrivKey(testkey_invalid_bad_preamble, null, &blob, &pubblob));
    try std.testing.expectError(PrivKeyError.BadPrivKey, decodePrivKey(testkey_invalid_missing_footer, null, &blob, &pubblob));
    try std.testing.expectError(PrivKeyError.BadPrivKey, decodePrivKey(testkey_invalid_bad_base64, null, &blob, &pubblob));
    try decodePrivKey(testkey_encrypted_valid_passworded, testkey_encrypted_valid_password, &blob, &pubblob);
    try std.testing.expectError(PrivKeyError.InvalidKeyDecrypt, decodePrivKey(testkey_encrypted_valid_passworded, "notpassword", &blob, &pubblob));
    try std.testing.expect(std.mem.eql(u8, &blob, &[_]u8{ 168, 158, 23, 77, 212, 94, 57, 255, 157, 6, 173, 128, 17, 109, 67, 232, 3, 126, 106, 1, 93, 9, 70, 135, 50, 35, 207, 108, 76, 128, 251, 24, 189, 27, 142, 8, 84, 46, 86, 64, 66, 99, 249, 172, 207, 208, 211, 134, 21, 193, 250, 85, 48, 57, 251, 81, 133, 110, 66, 16, 244, 86, 130, 249 }));
    try decodePrivKey(testkey_valid, null, &blob, &pubblob);
    try std.testing.expect(std.mem.eql(u8, &blob, &[_]u8{ 166, 119, 186, 89, 114, 101, 152, 133, 196, 14, 211, 238, 206, 143, 73, 223, 41, 101, 45, 196, 132, 150, 240, 240, 41, 82, 229, 54, 152, 193, 40, 220, 232, 131, 168, 235, 233, 3, 218, 50, 159, 159, 165, 94, 166, 155, 49, 203, 223, 47, 9, 101, 69, 137, 215, 186, 3, 175, 96, 21, 112, 247, 116, 245 }));
}
