const std = @import("std");
const posix = std.posix;
const MisshodServer = @import("misshod").MisshodServer;

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 3) {
        std.debug.print("{s} <port> <hostkey>\n", .{args[0]});
        std.process.exit(1);
    }

    const hostkey_ascii = std.fs.cwd().readFileAlloc(allocator, args[2], 1024) catch {
        std.debug.print("Failed to open hostkey file {s}\n", .{args[2]});
        std.process.exit(1);
    };
    defer allocator.free(hostkey_ascii);

    const port = try std.fmt.parseInt(u16, args[1], 10);

    const addr = std.net.Address.initIp4(.{0, 0, 0, 0}, port);
    var server = try addr.listen(.{.reuse_port = true});

    std.debug.print("Server listening on port {d}\n", .{port});

    nextclient: while(true) {
        const client = try server.accept();

        var stream = client.stream;
        defer stream.close();

        // make a reasonable prng
        var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
        try posix.getrandom(&seed);
        var prng = std.Random.DefaultCsprng.init(seed);

        var misshod = try MisshodServer.init(prng.random(), hostkey_ascii, allocator);
        defer misshod.deinit(allocator);

        var iobuf: [8]u8 = undefined; // could be any size
        var quit = false;
        const pipe = try std.posix.pipe();
        var pipeInFile:std.fs.File = std.fs.File{.handle = pipe[1]};
        var pipeOutFile:std.fs.File = std.fs.File{.handle = pipe[0]};

        ioloop: while (!quit) {
            const ev = try misshod.getNextEvent();
            switch (ev) {
                .Event => |eventCode| {
                    switch (eventCode) {
                        .Connected => {
                            std.debug.print("Connected!\n", .{});
                            try misshod.clearEvent(eventCode);
                        },
                        .RxData => |rbuf| {
                            const stdout_writer = std.io.getStdOut().writer();
                            try stdout_writer.print("{s}", .{rbuf});

                            _ = try pipeInFile.writer().print("You said '{s}'\r\n", .{rbuf});

                            try misshod.clearEvent(eventCode);
                        },
                        .EndSession => |reason| {
                            std.debug.print("Session ended: {any}\n", .{reason});
                            quit = true;
                            continue :ioloop;
                        },
                        .UserAuth => |credentials| {
                            //std.debug.print("credentials: {any}\n", .{credentials});
                            if (credentials.auth) |auth| {
                                switch(auth) {
                                    .Password => |password| {
                                        // FIXME, some kind of username/password lookup
                                        // for now, rule is password must match username
                                        try misshod.grantAccess(std.mem.eql(u8, credentials.username, password));
                                    },
                                    .Pubkey => |pubkey| {
                                        var fingerprint_buf: [512]u8 = undefined;
                                        std.debug.assert(std.base64.standard.Encoder.calcSize(pubkey.len) <= fingerprint_buf.len);
                                        const fingerprint = std.base64.standard.Encoder.encode(&fingerprint_buf, pubkey);
                                        std.debug.print("FIXME decide whether to allow username={s} pubkey={s}\n", .{credentials.username, fingerprint});

                                        try misshod.grantAccess(true);  // FIXME
                                    },
                                }
                            } else {
                                try misshod.grantAccess(false); // "none"
                            }
                            try misshod.clearEvent(eventCode);
                        },
                        .GetPubkeyForUser => |username| {
                            std.debug.print(".GetPubkeyForUser: {s}\n", .{username});
                            std.debug.assert(false);
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
                            .fd = pipeOutFile.handle,
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
                            if (nbytes > 0) {
                                // misshod may not get as much as it asked for, but it can req more later
                                //std.debug.print("Can consume {d}\n", .{len});
                                try misshod.write(iobuf[0..nbytes]);
                                continue :ioloop;
                            } else {
                                continue :nextclient;
                            }
                        }
                        if (fds[0].revents & std.posix.POLL.OUT > 0) { // socket is writeable
                            const towrite = try misshod.peek(4); // get data it wants to send up to a limit
                            const bytes_written = try stream.write(towrite);
                            //std.debug.print("bytes_written = {d} towrite={d}\n", .{bytes_written, towrite.len});
                            // socket may not have accepted all of the bytes
                            try misshod.consumed(bytes_written);
                            continue :ioloop;
                        }
                        if (fds[1].revents & std.posix.POLL.IN > 0) { // data to be sent (from pipe)
                            const buf = try misshod.getChannelWriteBuffer();
                            if (buf.len > 0) {
                                const count = pipeOutFile.reader().read(buf) catch 0;
                                if (count > 0) {
                                    try misshod.channelWriteComplete(count);
                                    continue :ioloop;
                                }
                            }
                        }
                    } else {
                        //std.debug.print("timeout\n", .{});
                    }
                },
            }
        }
    }
}
