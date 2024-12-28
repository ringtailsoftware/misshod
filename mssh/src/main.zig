const std = @import("std");
const posix = std.posix;
const Connection = @import("connection.zig").Connection;
const Misshod = @import("misshod");
const Session = Misshod.Session;
const SessionEvent = Misshod.SessionEvent;

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
            var connection = Connection.connectToHost(allocator, host, port) catch |err| {
                switch (err) {
                    posix.ConnectError.ConnectionRefused => std.debug.print("ConnectionRefused\n", .{}),
                    else => std.debug.print("{any}\n", .{err}),
                }
                return;
            };
            defer connection.close();

            // make a reasonable prng
            var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
            try posix.getrandom(&seed);
            var prng = std.Random.DefaultCsprng.init(seed);

            var session = try Session.init(prng.random(), user);
            defer session.deinit(allocator);

            //            try raw_mode_start();
            defer raw_mode_stop();

            outer: while (session.isActive()) {
                if (!session.canSend()) {
                    try session.advance(allocator);
                }

                if (session.canSend()) {
                    const stdin_reader = std.io.getStdIn();

                    var fds = [_]std.posix.pollfd{
                        .{
                            .fd = connection.stream.?.handle,
                            .events = std.posix.POLL.IN, // incoming socket data
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
                        if (fds[0].revents & std.posix.POLL.IN > 0) {
                            // socket data
                            //std.debug.print("NETDATA\n", .{});
                            try session.handleEventRsp(allocator, SessionEvent.NetDataAvailable);
                            continue :outer;
                        }
                        if (fds[1].revents & std.posix.POLL.IN > 0) {
                            // kb data
                            var buf: [128]u8 = undefined;
                            const count = stdin_reader.read(&buf) catch 0;
                            if (count > 0) {
                                try session.handleEventRsp(allocator, SessionEvent{ .SessionSend = buf[0..count] });
                                continue :outer;
                            }
                        }
                    }
                }

                switch (session.getNextEvent()) {
                    .Connected => {
                        //std.debug.print("**** CONNECTED\n", .{});
                        try session.handleEventRsp(allocator, SessionEvent.Connected); // ack
                        try raw_mode_start();
                    },
                    .None, .SessionSend, .NetDataAvailable => {},
                    .SessionRecv => |buf| {
                        std.debug.print("{s}", .{buf.?});
                        try session.handleEventRsp(allocator, SessionEvent{ .SessionRecv = null }); // ack
                    },
                    .SessionRecvExt => |buf| {
                        std.debug.print("{s}", .{buf.?});
                        try session.handleEventRsp(allocator, SessionEvent{ .SessionRecvExt = null }); // ack
                    },
                    .NetReadReq => |buf| {
                        //std.debug.print(".NetReadReq {d}\n", .{buf.len});
                        const x = try connection.read(buf, 2000);
                        std.debug.assert(x.len == buf.len);
                        try session.handleEventRsp(allocator, SessionEvent{ .NetReadReq = buf });
                    },
                    .NetWriteReq => |buf| {
                        //std.debug.print(".NetWriteReq {x}\n", .{buf.?});
                        _ = try connection.write(buf.?, 2000);
                        try session.handleEventRsp(allocator, SessionEvent{ .NetWriteReq = null });
                    },
                    .HostKeyValidateReq => |keydata| {
                        // make a decision about whether to accept host key
                        // a real client could check ~/.ssh/known_hosts
                        var fingerprint_buf: [512]u8 = undefined;
                        std.debug.assert(std.base64.standard.Encoder.calcSize(keydata.?.len) <= fingerprint_buf.len);
                        const fingerprint = std.base64.standard.Encoder.encode(&fingerprint_buf, keydata.?);
                        std.debug.print("Auto accepting host key {s}\n", .{fingerprint});
                        try session.handleEventRsp(allocator, SessionEvent{ .HostKeyValidateReq = null });
                    },
                    .KeyReq => {
                        if (args.len >= 4) { // id file provided
                            const keydata_ascii = std.fs.cwd().readFileAlloc(allocator, args[3], 1024) catch {
                                std.debug.print("Failed to open idfile {s}\n", .{args[3]});
                                std.process.exit(1);
                            };
                            try session.handleEventRsp(allocator, SessionEvent{ .KeyReq = keydata_ascii });
                            allocator.free(keydata_ascii);
                        } else {
                            try session.handleEventRsp(allocator, SessionEvent{ .KeyReq = null });
                        }
                    },
                    .KeyReqPassphrase => {
                        var password_buf: [128]u8 = undefined;
                        std.debug.print("Password private key decrypt: ", .{});
                        try session.handleEventRsp(allocator, SessionEvent{ .KeyReqPassphrase = try readPassphrase(&password_buf) });
                    },
                    .UserReqPassphrase => {
                        var password_buf: [128]u8 = undefined;
                        std.debug.print("Password for {s}@{s}: ", .{ user, host });
                        try session.handleEventRsp(allocator, SessionEvent{ .UserReqPassphrase = try readPassphrase(&password_buf) });
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
