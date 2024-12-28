const std = @import("std");
const builtin = @import("builtin");
const BufferReader = @import("buffer.zig").BufferReader;
const BufferWriter = @import("buffer.zig").BufferWriter;

const TraceLevel = enum {
    Info,
    Debug,
};

const trace_level: TraceLevel = .Info;

pub fn trace(level: TraceLevel, comptime fmt: []const u8, args: anytype) void {
    if (builtin.os.tag != .freestanding) {
        if (@intFromEnum(trace_level) >= @intFromEnum(level)) {
            const writer = std.io.getStdErr().writer();
            _ = writer.print(fmt ++ "\n", args) catch 0;
        }
    }
}

pub fn tracedump(level: TraceLevel, comptime fmt: []const u8, args: anytype, data: []const u8) void {
    if (builtin.os.tag != .freestanding) {
        if (@intFromEnum(trace_level) >= @intFromEnum(level)) {
            const writer = std.io.getStdErr().writer();
            _ = writer.print(fmt ++ "\n", args) catch 0;
            _ = dump(writer, data) catch 0;
        }
    }
}

// remove newline from end if present
pub fn chomp(s: []const u8) []const u8 {
    if (s.len < 2) {
        return s;
    }
    var i: usize = s.len;
    while (i >= 2) {
        if ((s[i - 2] == '\r' and s[i - 1] == '\n')) {
            i -= 2;
        } else {
            break;
        }
    }
    return s[0..i];
}

// std.mem.asBytes(), but returning only the bytes needed for a packed struct
pub fn asPackedBytes(T: type, ptr: anytype) []u8 {
    return std.mem.asBytes(ptr)[0 .. @bitSizeOf(T) / 8];
}

// xxd style hexdump
pub fn dump(writer: anytype, data: []const u8) !void {
    const bytes_per_line = 16;
    std.debug.assert(bytes_per_line % 2 == 0);
    var off: usize = 0;

    while (off < data.len) : (off += bytes_per_line) {
        try writer.print("{x:0>8}: ", .{off});
        const bytes_to_show = if (off + bytes_per_line > data.len) data.len - off else bytes_per_line;
        for (0..bytes_per_line) |n| {
            if (n < bytes_to_show) {
                try writer.print("{x:0>2}", .{data[off + n]});
            } else {
                try writer.print("  ", .{});
            }
            if (n % 2 == 1) {
                try writer.print(" ", .{});
            }
        }
        try writer.print(" ", .{});
        for (0..bytes_per_line) |n| {
            if (n < bytes_to_show) {
                try writer.print("{c}", .{if (std.ascii.isPrint(data[off + n])) data[off + n] else '.'});
            }
        }
        try writer.print("\n", .{});
    }
}

// Convencience for splitting comma separated values
pub const NameListTokenizer = struct {
    const Self = @This();
    pub fn init(namelist: []const u8) std.mem.SplitIterator(u8, .sequence) {
        return std.mem.splitSequence(u8, namelist, ",");
    }
};

// server host key comes as two U32LenStrings, name and binary blob
// convenience function to extract these parts in either order
pub const NamedBlob = struct {
    const Self = @This();
    nameblob: []const u8,

    pub fn init(nameblob: []const u8) Self {
        return Self{
            .nameblob = nameblob,
        };
    }

    pub fn getName(self: *Self) ![]const u8 {
        var buffer = BufferReader.init(self.nameblob);
        return try buffer.readU32LenString();
    }

    pub fn getBlob(self: *Self) ![]const u8 {
        var buffer = BufferReader.init(self.nameblob);
        try buffer.skipU32LenString();
        return try buffer.readU32LenString();
    }
};

test "chomp" {
    try std.testing.expect(std.mem.eql(u8, chomp(""), ""));
    try std.testing.expect(std.mem.eql(u8, chomp("\r\n"), ""));
    try std.testing.expect(std.mem.eql(u8, chomp("\r\n\r\n"), ""));
    try std.testing.expect(std.mem.eql(u8, chomp("a"), "a"));
    try std.testing.expect(std.mem.eql(u8, chomp("a\r"), "a\r"));
    try std.testing.expect(std.mem.eql(u8, chomp("a\r\n"), "a"));
    try std.testing.expect(std.mem.eql(u8, chomp("abc"), "abc"));
    try std.testing.expect(std.mem.eql(u8, chomp("abc\n"), "abc\n"));
    try std.testing.expect(std.mem.eql(u8, chomp("abc\r\n"), "abc"));
    try std.testing.expect(std.mem.eql(u8, chomp("\r\nabc\r\n"), "\r\nabc"));
}

test "namedblob" {
    var backing: [128]u8 = undefined;
    var buffer = BufferWriter.init(&backing, 0);
    // write str
    try buffer.writeU32LenString("MOOF");
    try buffer.writeU32LenString("blah");

    var nb = NamedBlob.init(buffer.active());
    try std.testing.expect(std.mem.eql(u8, try nb.getName(), "MOOF"));
    try std.testing.expect(std.mem.eql(u8, try nb.getBlob(), "blah"));
}
