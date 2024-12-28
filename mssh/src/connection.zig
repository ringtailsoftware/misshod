const std = @import("std");
const net = std.net;
const posix = std.posix;
const util = @import("util");

const stdout_writer = std.io.getStdOut().writer();

pub const Connection = struct {
    const Self = @This();
    stream: ?net.Stream = null,

    pub fn connectToHost(allocator: std.mem.Allocator, host: []const u8, port: u16) !Self {
        return Self{
            .stream = try std.net.tcpConnectToHost(allocator, host, port),
        };
    }

    pub fn write(self: *Self, buf: []const u8, timeout: i32) !usize {
        std.debug.assert(timeout > 0);
        // FIXME TBD needs to ensure piecemeal writes happen, fire and forget for now
        if (self.stream) |stream| {
            const count = try stream.write(buf);
            std.debug.assert(count == buf.len);
            return count;
        } else {
            return error.notOpenErr;
        }
    }

    pub fn read(self: *Self, buf: []u8, timeout: i32) ![]u8 {
        const count = try self.readBytes(buf, timeout);
        return buf[0..count];
    }

    pub fn skip(self: *Self, n: usize, timeout: i32) !void {
        // FIXME, do this in a less silly way
        var buf: [1]u8 = undefined;
        for (0..n) |_| {
            const count = try self.readBytes(&buf, timeout);
            std.debug.assert(count == 1);
        }
    }

    // read from buffer and stream if needed, assumes buf.len is the requested read len
    pub fn readBytes(self: *Self, buf: []u8, timeout: i32) !usize {
        std.debug.assert(timeout > 0);
        var total_read: usize = 0;
        const start_time = std.time.milliTimestamp();

        while (total_read != buf.len and start_time < std.time.milliTimestamp() + timeout) {
            const remaining_timeout = timeout - (std.time.milliTimestamp() - start_time);
            if (remaining_timeout <= 0) {
                return total_read;
            }
            //std.debug.print("polling for {d} {d}ms\n", .{buf.len - total_read, remaining_timeout});
            total_read += try self.readPollSingleAttempt(buf[total_read..], @intCast(remaining_timeout));
            //std.debug.print("rd {d}\n", .{total_read});
        }

        return total_read;
    }

    pub fn poll(self: *Self, readable: bool, writable: bool, timeout: i32) !i16 {
        if (self.stream) |stream| {
            var fds = [_]std.posix.pollfd{
                .{
                    .fd = stream.handle,
                    .events = 0,
                    .revents = undefined,
                },
            };

            if (readable) {
                fds[0].events |= std.posix.POLL.IN;
            }
            if (writable) {
                fds[0].events |= std.posix.POLL.OUT;
            }

            const ready = std.posix.poll(&fds, timeout) catch 0;
            if (ready > 0) {
                if (fds[0].revents & std.posix.POLL.HUP > 0) {
                    return error.HangupErr;
                }
                return fds[0].revents;
            } else {
                return 0;
            }
        } else {
            return error.notOpenErr;
        }
    }

    fn readPollSingleAttempt(self: *Self, buf: []u8, timeout: i32) !usize {
        if (self.stream) |stream| {
            var fds = [_]std.posix.pollfd{
                .{
                    .fd = stream.handle,
                    .events = std.posix.POLL.IN,
                    .revents = undefined,
                },
            };
            const ready = std.posix.poll(&fds, timeout) catch 0;
            if (ready > 0) {
                if (fds[0].revents & std.posix.POLL.HUP > 0) {
                    return error.HangupErr;
                }
                if (fds[0].revents == std.posix.POLL.IN) {
                    const count = stream.read(buf) catch 0;
                    if (count > 0) {
                        return count;
                    } else {
                        return error.HangupErr;
                    }
                } else {
                    return 0;
                }
            } else {
                return 0;
            }
        } else {
            return error.notOpenErr;
        }
    }

    pub fn close(self: *Self) void {
        if (self.stream) |stream| {
            stream.close();
            self.stream = null;
        }
    }
};
