const std = @import("std");

const targetEndian: std.builtin.Endian = .big;

// Buffer representing SSH payloads containing types from https://datatracker.ietf.org/doc/html/rfc4251#section-5
// Values are network order

pub const BufferReader = struct {
    const Self = @This();
    payload: []const u8,
    off: usize,

    pub fn init(payload: []const u8) Self {
        return Self{
            .payload = payload,
            .off = 0,
        };
    }

    pub fn readBoolean(self: *Self) !bool {
        if (self.off + 1 > self.payload.len) {
            return error.ReaderOutOfDataErr;
        } else {
            const v = self.payload[self.off];
            self.off += 1;
            return v != 0;
        }
    }

    pub fn readU8(self: *Self) !u8 {
        if (self.off + 1 > self.payload.len) {
            return error.ReaderOutOfDataErr;
        } else {
            const v = self.payload[self.off];
            self.off += 1;
            return v;
        }
    }

    pub fn skip(self: *Self, n: usize) !void {
        if (self.off + n > self.payload.len) {
            return error.ReaderOutOfDataErr;
        } else {
            self.off += n;
        }
    }

    pub fn readBytes(self: *Self, n: usize) ![]const u8 {
        if (self.off + n > self.payload.len) {
            return error.ReaderOutOfDataErr;
        } else {
            const sl = self.payload[self.off .. self.off + n];
            self.off += n;
            return sl;
        }
    }

    pub fn readU32(self: *Self) !u32 {
        if (self.off + 4 > self.payload.len) {
            return error.ReaderOutOfDataErr;
        } else {
            const v = std.mem.bytesToValue(u32, self.payload[self.off .. self.off + 4]);
            self.off += 4;
            return std.mem.toNative(u32, v, targetEndian);
        }
    }

    pub fn readU32LenString(self: *Self) ![]const u8 {
        const len = try self.readU32();
        return try self.readBytes(len);
    }

    // for walking lists
    pub fn skipU32LenString(self: *Self) !void {
        const len = try self.readU32();
        try self.skip(len);
    }
};

// maxsize: fixed upper size limit
// pre_payload_len: reserved bytes before payload for inserting headers
pub const BufferWriter = struct {
    const Self = @This();
    payload_buf: []u8,
    payload: []u8, // a slice of payload_buf inclusive of pre_payload_len
    off: usize = 0,
    pre_payload_len: usize = 0,

    // get the active part without pre_payload_len
    pub fn active(self: *Self) []u8 {
        return self.payload[self.pre_payload_len..];
    }

    pub fn init(backingbuf: []u8, pre_payload_len: usize) Self {
        var s = Self{
            .off = 0,
            .payload_buf = backingbuf,
            .pre_payload_len = pre_payload_len,
            .payload = &.{},
        };
        _ = s.skip(pre_payload_len) catch 0;
        return s;
    }

    pub fn updateUnderlying(self: *Self) void {
        self.payload = self.payload_buf[0..self.off];
    }

    pub fn discard(self: *Self, n: usize) !void {
        if (self.off < n) {
            return error.WriterOutOfDataErr;
        } else {
            self.off -= n;
            self.updateUnderlying();
        }
    }

    pub fn skip(self: *Self, n: usize) !void {
        if (self.off + n > self.payload_buf.len) {
            return error.WriterOutOfDataErr;
        } else {
            self.off += n;
            self.updateUnderlying();
        }
    }

    pub fn writeBoolean(self: *Self, v: bool) !void {
        if (self.off + 1 > self.payload_buf.len) {
            return error.WriterOutOfDataErr;
        } else {
            self.payload_buf[self.off] = if (v) 1 else 0;
            self.off += 1;
            self.updateUnderlying();
        }
    }

    pub fn writeU8(self: *Self, v: u8) !void {
        if (self.off + 1 > self.payload_buf.len) {
            return error.WriterOutOfDataErr;
        } else {
            self.payload_buf[self.off] = v;
            self.off += 1;
            self.updateUnderlying();
        }
    }

    pub fn writeU32(self: *Self, v: u32) !void {
        if (self.off + 4 > self.payload_buf.len) {
            return error.WriterOutOfDataErr;
        } else {
            const net_v = std.mem.nativeTo(u32, v, targetEndian);
            @memcpy(self.payload_buf[self.off .. self.off + 4], std.mem.asBytes(&net_v));
            self.off += 4;
            self.updateUnderlying();
        }
    }

    pub fn writeBytes(self: *Self, v: []const u8) !void {
        if (self.off + v.len > self.payload_buf.len) {
            return error.WriterOutOfDataErr;
        } else {
            @memcpy(self.payload_buf[self.off .. self.off + v.len], v);
            self.off += v.len;
            self.updateUnderlying();
        }
    }

    pub fn writeMpint(self: *Self, v: []const u8) !void {
        // if MSB of first byte is set, mpint must be padded
        // https://datatracker.ietf.org/doc/html/rfc4251#section-5
        const pad = v[0] & 0x80 > 0;
        if (self.off + v.len + 4 > self.payload_buf.len) {
            return error.WriterOutOfDataErr;
        } else {
            if (pad) {
                try self.writeU32(@intCast(v.len + 1));
            } else {
                try self.writeU32(@intCast(v.len));
            }
            if (pad) {
                try self.writeU8(0);
            }
            try self.writeBytes(v);
        }
    }

    pub fn writeU32LenString(self: *Self, v: []const u8) !void {
        if (self.off + v.len + 4 > self.payload_buf.len) {
            return error.WriterOutOfDataErr;
        } else {
            try self.writeU32(@intCast(v.len));
            try self.writeBytes(v);
        }
    }
};

test "buffer wr overflow" {
    var backing: [123]u8 = undefined;
    var pkt = BufferWriter.init(&backing, 0);
    for (0..backing.len) |_| {
        try pkt.writeU8(0xAA);
    }
    // unable to write anymore
    try std.testing.expectError(error.WriterOutOfDataErr, pkt.writeU8(0xBB));
}

test "buffer-skip" {
    var backing: [4]u8 = undefined;
    var buffer = BufferWriter.init(&backing, 1);
    try std.testing.expect(buffer.active().len == 0);
    // start with 1
    try std.testing.expect(buffer.payload.len == 1);
    // write one byte
    try buffer.writeU8(0x43);
    try std.testing.expect(buffer.payload.len == 2);
    try std.testing.expect(buffer.active().len == 1);
    // directly write underlying buffer
    buffer.payload[0] = 0x42;
    try std.testing.expect(std.mem.eql(u8, buffer.payload, &[_]u8{ 0x42, 0x43 }));
    try std.testing.expect(std.mem.eql(u8, buffer.active(), &[_]u8{0x43}));
}

test "buffer" {
    var backing: [128]u8 = undefined;
    var buffer = BufferWriter.init(&backing, 0);

    // start empty
    try std.testing.expect(buffer.payload.len == 0);
    // write 1 byte
    try buffer.writeU8(0x42);
    // check underlying buf
    try std.testing.expect(buffer.payload.len == 1);
    try std.testing.expect(std.mem.eql(u8, buffer.payload, &[_]u8{0x42}));
    // read back 1 byte
    var rd = BufferReader.init(buffer.active());
    try std.testing.expect(try rd.readU8() == 0x42);
    // no more available to read
    try std.testing.expectError(error.ReaderOutOfDataErr, rd.readU8());

    // write 1 byte
    try buffer.writeU8(0x43);
    // check underlying buf
    try std.testing.expect(buffer.payload.len == 2);
    try std.testing.expect(std.mem.eql(u8, buffer.payload, &[_]u8{ 0x42, 0x43 }));
    // read back 2 bytes
    rd = BufferReader.init(buffer.active());
    try std.testing.expect(try rd.readU8() == 0x42);
    try std.testing.expect(try rd.readU8() == 0x43);
    // no more available to read
    try std.testing.expectError(error.ReaderOutOfDataErr, rd.readU8());

    // write u32
    try buffer.writeU32(0xDEADBEEF);
    // check underlying buf
    try std.testing.expect(buffer.payload.len == 6);
    try std.testing.expect(std.mem.eql(u8, buffer.payload, &[_]u8{ 0x42, 0x43, 0xDE, 0xAD, 0xBE, 0xEF })); // network order
    // read back 2 bytes and u32
    rd = BufferReader.init(buffer.active());
    try std.testing.expect(try rd.readU8() == 0x42);
    try std.testing.expect(try rd.readU8() == 0x43);
    try std.testing.expect(try rd.readU32() == 0xDEADBEEF);
    // no more available to read
    try std.testing.expectError(error.ReaderOutOfDataErr, rd.readU8());

    // write byte buf
    try buffer.writeBytes(&[_]u8{ 'h', 'e', 'l', 'l', 'o' });
    // check underlying buf
    try std.testing.expect(buffer.payload.len == 11);
    try std.testing.expect(std.mem.eql(u8, buffer.payload, &[_]u8{ 0x42, 0x43, 0xDE, 0xAD, 0xBE, 0xEF, 'h', 'e', 'l', 'l', 'o' }));
    // read back 2 bytes, u32, byte buf
    rd = BufferReader.init(buffer.active());
    try std.testing.expect(try rd.readU8() == 0x42);
    try std.testing.expect(try rd.readU8() == 0x43);
    try std.testing.expect(try rd.readU32() == 0xDEADBEEF);
    try std.testing.expect(std.mem.eql(u8, try rd.readBytes(5), &[_]u8{ 'h', 'e', 'l', 'l', 'o' }));
    // no more available to read
    try std.testing.expectError(error.ReaderOutOfDataErr, rd.readU8());

    // write boolean=false
    try buffer.writeBoolean(false);
    // check underlying buf
    try std.testing.expect(buffer.payload.len == 12);
    try std.testing.expect(std.mem.eql(u8, buffer.payload, &[_]u8{ 0x42, 0x43, 0xDE, 0xAD, 0xBE, 0xEF, 'h', 'e', 'l', 'l', 'o', 0 }));
    // read back 2 bytes, u32, byte buf, boolean
    rd = BufferReader.init(buffer.active());
    try std.testing.expect(try rd.readU8() == 0x42);
    try std.testing.expect(try rd.readU8() == 0x43);
    try std.testing.expect(try rd.readU32() == 0xDEADBEEF);
    try std.testing.expect(std.mem.eql(u8, try rd.readBytes(5), &[_]u8{ 'h', 'e', 'l', 'l', 'o' }));
    try std.testing.expect(try rd.readBoolean() == false);
    // no more available to read
    try std.testing.expectError(error.ReaderOutOfDataErr, rd.readU8());

    // write boolean=true
    try buffer.writeBoolean(true);
    // check underlying buf
    try std.testing.expect(buffer.payload.len == 13);
    try std.testing.expect(std.mem.eql(u8, buffer.payload, &[_]u8{ 0x42, 0x43, 0xDE, 0xAD, 0xBE, 0xEF, 'h', 'e', 'l', 'l', 'o', 0, 1 }));
    // read back 2 bytes, u32, byte buf, boolean, boolean
    rd = BufferReader.init(buffer.active());
    try std.testing.expect(try rd.readU8() == 0x42);
    try std.testing.expect(try rd.readU8() == 0x43);
    try std.testing.expect(try rd.readU32() == 0xDEADBEEF);
    try std.testing.expect(std.mem.eql(u8, try rd.readBytes(5), &[_]u8{ 'h', 'e', 'l', 'l', 'o' }));
    try std.testing.expect(try rd.readBoolean() == false);
    try std.testing.expect(try rd.readBoolean() == true);
    // no more available to read
    try std.testing.expectError(error.ReaderOutOfDataErr, rd.readU8());

    // write str
    try buffer.writeU32LenString("MOOF");
    // check underlying buf
    try std.testing.expect(buffer.payload.len == 21);
    try std.testing.expect(std.mem.eql(u8, buffer.payload, &[_]u8{ 0x42, 0x43, 0xDE, 0xAD, 0xBE, 0xEF, 'h', 'e', 'l', 'l', 'o', 0, 1, 0x00, 0x00, 0x00, 0x04, 'M', 'O', 'O', 'F' }));
    // read back 2 bytes, u32, byte buf, boolean, boolean
    rd = BufferReader.init(buffer.active());
    try std.testing.expect(try rd.readU8() == 0x42);
    try std.testing.expect(try rd.readU8() == 0x43);
    try std.testing.expect(try rd.readU32() == 0xDEADBEEF);
    try std.testing.expect(std.mem.eql(u8, try rd.readBytes(5), &[_]u8{ 'h', 'e', 'l', 'l', 'o' }));
    try std.testing.expect(try rd.readBoolean() == false);
    try std.testing.expect(try rd.readBoolean() == true);
    try std.testing.expect(std.mem.eql(u8, try rd.readU32LenString(), &[_]u8{ 'M', 'O', 'O', 'F' }));
    // no more available to read
    try std.testing.expectError(error.ReaderOutOfDataErr, rd.readU8());
}
