const std = @import("std");
const posix = std.posix;
const Misshod = @import("misshod").Misshod;

const user = "testuser";
const password = "password";

pub fn main() !void {
    var buffer: [512]u8 = undefined;   // Not a lot of heap is needed!
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const allocator = fba.allocator();

    const stdin_reader = std.io.getStdIn();
    const stdout_writer = std.io.getStdOut().writer();

    var prng = std.Random.DefaultPrng.init(0xDEADBEEF);

    var misshod = try Misshod.init(prng.random(), user, allocator);
    defer misshod.deinit(allocator);

    var iobuf: [8]u8 = undefined; // could be any size
    var quit = false;

    outer: while (!quit) {
        const ev = try misshod.getNextEvent();
        switch (ev) {
            .Event => |eventCode| {
                switch (eventCode) {
                    .Connected => {
                        std.debug.print("Connected!\n", .{});
                        try misshod.clearEvent(eventCode);
                    },
                    .RxData => |buf| {
                        std.debug.print("{s}", .{buf});
                        try misshod.clearEvent(eventCode);
                    },
                    .EndSession => |reason| {
                        std.debug.print("Session ended: {any}\n", .{reason});
                        quit = true;
                        continue :outer;
                    },
                    .CheckHostKey => {
                        std.debug.print("Auto accepting host key\n", .{});
                        try misshod.clearEvent(eventCode);
                    },
                    .GetPrivateKey => {
                        try misshod.clearEvent(eventCode);
                    },
                    .GetKeyPassphrase => {
                        try misshod.clearEvent(eventCode);
                    },
                    .GetAuthPassphrase => {
                        try misshod.setAuthPassphrase(password);
                        try misshod.clearEvent(eventCode);
                    },
                }
            },
            .ReadyToConsume, .ReadyToProduce => |len| {
                var pollevts: i16 = 0;

                if (ev == .ReadyToConsume) {
                    pollevts |= std.posix.POLL.IN;
                } else {
                    pollevts |= std.posix.POLL.OUT;
                }

                var fds = [_]std.posix.pollfd{
                    .{
                        .fd = stdin_reader.handle,
                        .events = pollevts,
                        .revents = undefined,
                    },
                };

                const ready = std.posix.poll(&fds, 1000) catch 0;
                if (ready > 0) {
                    if (fds[0].revents & std.posix.POLL.IN > 0) { // socket is readable
                        var bytes_to_read = len;
                        if (bytes_to_read > iobuf.len) {
                            bytes_to_read = iobuf.len;
                        }
                        const nbytes = try stdin_reader.read(iobuf[0..bytes_to_read]);
                        //std.debug.assert(nbytes > 0);
                        if (nbytes > 0) {
                            try misshod.write(iobuf[0..nbytes]);
                        }
                    }
                    if (fds[0].revents & std.posix.POLL.OUT > 0) { // socket is writeable
                        const towrite = try misshod.peek(128); // get data it wants to send up to a limit
                        const bytes_written = try stdout_writer.write(towrite);
                        //std.debug.print("bytes_written = {d} towrite={d}\n", .{bytes_written, towrite.len});
                        // socket may not have accepted all of the bytes
                        try misshod.consumed(bytes_written);
                    }
                } else {
                    //std.debug.print("timeout\n", .{});
                }
            },
        }
    }
}
