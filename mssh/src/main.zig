const std = @import("std");
const posix = std.posix;
const Misshod = @import("misshod").Misshod;

// Turn off echo and read a password
fn readPassphrase(password_buf: []u8) ![]u8 {
    const in = std.io.getStdIn();
    var buf = std.io.bufferedReader(in.reader());
    var r = buf.reader();

    if (std.posix.isatty(in.handle)) {
        // disable terminal echo
        var termios = try std.posix.tcgetattr(in.handle);
        termios.lflag.ECHO = false;
        try std.posix.tcsetattr(in.handle, .FLUSH, termios);
        const password = try r.readUntilDelimiterOrEof(password_buf, '\n');
        // re-enable echo
        termios.lflag.ECHO = true;
        try std.posix.tcsetattr(in.handle, .FLUSH, termios);
        try std.io.getStdOut().writer().print("\n", .{});
        return password.?;
    } else {
        const password = try r.readUntilDelimiterOrEof(password_buf, '\n');
        return password.?;
    }
}

var original_termios: ?std.posix.termios = null;

pub fn raw_mode_start() !void {
    const stdin_reader = std.io.getStdIn();
    const handle = stdin_reader.handle;

    if (std.posix.isatty(handle)) {
        var termios = try std.posix.tcgetattr(handle);
        original_termios = termios;

        termios.iflag.BRKINT = false;
        termios.iflag.ICRNL = true;
        termios.iflag.INPCK = false;
        termios.iflag.ISTRIP = false;
        termios.iflag.IXON = false;
        termios.oflag.OPOST = true;
        termios.lflag.ECHO = false;
        termios.lflag.ICANON = false;
        termios.lflag.IEXTEN = false;
        termios.lflag.ISIG = false;
        termios.cflag.CSIZE = .CS8;
        termios.cc[@intFromEnum(std.posix.V.TIME)] = 0;
        termios.cc[@intFromEnum(std.posix.V.MIN)] = 1;

        try std.posix.tcsetattr(handle, .FLUSH, termios);
    }
}

pub fn raw_mode_stop() void {
    const stdout_writer = std.io.getStdOut().writer();

    const stdin_reader = std.io.getStdIn();
    if (original_termios) |termios| {
        std.posix.tcsetattr(stdin_reader.handle, .FLUSH, termios) catch {};
    }
    _ = stdout_writer.print("\n", .{}) catch 0;
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 3) {
        std.debug.print("{s} <username@host> <port> [idfile]\n", .{args[0]});
        std.process.exit(1);
    }

    const user_host = args[1];
    const port = try std.fmt.parseInt(u16, args[2], 10);
    var host_opt: ?[]u8 = null;
    var user_opt: ?[]u8 = null;

    var iter = std.mem.tokenizeSequence(u8, user_host, "@");
    var i: usize = 0;
    while (iter.next()) |item| {
        switch (i) {
            0 => user_opt = try allocator.dupe(u8, item),
            1 => host_opt = try allocator.dupe(u8, item),
            else => {
                std.debug.print("Bad user@host\n", .{});
                std.process.exit(1);
            },
        }
        i += 1;
    }

    if (host_opt) |host| {
        if (user_opt) |user| {
            var stream = std.net.tcpConnectToHost(allocator, host, port) catch |err| {
                switch (err) {
                    posix.ConnectError.ConnectionRefused => std.debug.print("ConnectionRefused\n", .{}),
                    else => std.debug.print("{any}\n", .{err}),
                }
                return;
            };
            defer stream.close();

            // make a reasonable prng
            var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
            try posix.getrandom(&seed);
            var prng = std.Random.DefaultCsprng.init(seed);

            var misshod = try Misshod.init(prng.random(), user, allocator);
            defer misshod.deinit(allocator);

            defer raw_mode_stop();

            var iobuf: [8]u8 = undefined; // could be any size
            var quit = false;
            const stdin_reader = std.io.getStdIn();

            outer: while (!quit) {
                const ev = try misshod.getNextEvent();
                switch (ev) {
                    .Event => |eventCode| {
                        switch (eventCode) {
                            .Connected => {
                                std.debug.print("Connected!\n", .{});
                                try misshod.clearEvent(eventCode);
                                try raw_mode_start();
                            },
                            .RxData => |buf| {
                                const stdout_writer = std.io.getStdOut().writer();
                                try stdout_writer.print("{s}", .{buf});
                                try misshod.clearEvent(eventCode);
                            },
                            .EndSession => |reason| {
                                std.debug.print("Session ended: {any}\n", .{reason});
                                quit = true;
                                continue :outer;
                            },
                            .CheckHostKey => |keydata| {
                                // make a decision about whether to accept host key
                                // a real client could check ~/.ssh/known_hosts
                                var fingerprint_buf: [512]u8 = undefined;
                                std.debug.assert(std.base64.standard.Encoder.calcSize(keydata.?.len) <= fingerprint_buf.len);
                                const fingerprint = std.base64.standard.Encoder.encode(&fingerprint_buf, keydata.?);
                                std.debug.print("Auto accepting host key {s}\n", .{fingerprint});
                                try misshod.clearEvent(eventCode);
                            },
                            .GetPrivateKey => {
                                if (args.len >= 4) { // id file provided
                                    const keydata_ascii = std.fs.cwd().readFileAlloc(allocator, args[3], 1024) catch {
                                        std.debug.print("Failed to open idfile {s}\n", .{args[3]});
                                        std.process.exit(1);
                                    };
                                    try misshod.setPrivateKey(keydata_ascii);
                                    allocator.free(keydata_ascii);
                                }
                                try misshod.clearEvent(eventCode);
                            },
                            .GetKeyPassphrase => {
                                var password_buf: [128]u8 = undefined;
                                std.debug.print("Password for private key decrypt: ", .{});
                                try misshod.setPrivateKeyPassphrase(try readPassphrase(&password_buf));
                                try misshod.clearEvent(eventCode);
                            },
                            .GetAuthPassphrase => {
                                var password_buf: [128]u8 = undefined;
                                std.debug.print("Password for auth: ", .{});
                                try misshod.setAuthPassphrase(try readPassphrase(&password_buf));
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
                                .fd = stream.handle,
                                .events = pollevts,
                                .revents = undefined,
                            },
                            .{
                                .fd = stdin_reader.handle,
                                .events = std.posix.POLL.IN,
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
                                const nbytes = try stream.read(iobuf[0..bytes_to_read]);
                                std.debug.assert(nbytes > 0);
                                // misshod may not get as much as it asked for, but it can req more later
                                //std.debug.print("Can consume {d}\n", .{len});
                                try misshod.write(iobuf[0..nbytes]);
                            }
                            if (fds[0].revents & std.posix.POLL.OUT > 0) { // socket is writeable
                                const towrite = try misshod.peek(4); // get data it wants to send up to a limit
                                const bytes_written = try stream.write(towrite);
                                //std.debug.print("bytes_written = {d} towrite={d}\n", .{bytes_written, towrite.len});
                                // socket may not have accepted all of the bytes
                                try misshod.consumed(bytes_written);
                            }
                            if (fds[1].revents & std.posix.POLL.IN > 0) { // keyboard data in
                                const buf = try misshod.getChannelWriteBuffer();
                                if (buf.len > 0) {
                                    const count = stdin_reader.read(buf) catch 0;
                                    if (count > 0) {
                                        try misshod.channelWriteComplete(count);
                                    }
                                }
                            }
                        } else {
                            //std.debug.print("timeout\n", .{});
                        }
                    },
                }
            }
        } else {
            std.debug.print("Bad/missing user\n", .{});
        }
    } else {
        std.debug.print("Bad/missing user\n", .{});
    }
}
