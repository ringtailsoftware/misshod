const std = @import("std");
const util = @import("util.zig");
const TRACE = util.trace;
const TRACEDUMP = util.tracedump;
const ClientSession = @import("client_session.zig").Session;
const ServerSession = @import("server_session.zig").Session;
const BufferError = @import("buffer.zig").BufferError;
const PrivKeyError = @import("privkey.zig").PrivKeyError;
const Protocol = @import("protocol.zig");
const native_endian = @import("builtin").target.cpu.arch.endian();
const BufferReader = @import("buffer.zig").BufferReader;

pub const MisshodError = std.crypto.errors.Error || std.mem.Allocator.Error || BufferError || IoError || PrivKeyError;

pub const IoError = error{
    cannotAcceptWrite,
    notProducing,
    notEnoughData,
    noEOLFound,
    badClearEvent,
    InvalidPacketSize,
    InvalidMac,
    UnexpectedResponse,
    tooBig,
    UnimplementedService,
};

pub const EndSessionReason = enum {
    Disconnect,
    AuthFailure,
};

pub const Role = enum {
    Client,
    Server,
};

fn sessionType(role:Role) type {
    return switch(role) {
        .Client => ClientSession,
        .Server => ServerSession,
    };
}

fn eventCodeType(role:Role) type {
    return switch(role) {
        .Client => MisshodClientEventCodes,
        .Server => MisshodServerEventCodes,
    };
}

pub const MisshodClientEventCodes = union(enum) {
    CheckHostKey: ?[]const u8,
    GetPrivateKey,
    GetKeyPassphrase,
    GetAuthPassphrase,
    EndSession: EndSessionReason,
    Connected,
    RxData: []const u8,
};

pub const UserCredentialsPasswordOrPubkey = union(enum) {
    Password: []const u8,   // "password" auth
    Pubkey: []const u8, // "publickey" auth
};

pub const UserCredentials = struct {
    username: []const u8,
    auth: ?UserCredentialsPasswordOrPubkey, // null for "none" auth
};

pub const MisshodServerEventCodes = union(enum) {
    EndSession: EndSessionReason,
    UserAuth: UserCredentials,
    GetPubkeyForUser: []const u8,
    Connected,
    RxData: []const u8,
};

pub fn MisshodEvent(role:Role) type {
    return union(enum) {
        Event: eventCodeType(role),
        ReadyToConsume: usize,
        ReadyToProduce: usize,
    };
}

// Producing a block, or consuming a block
pub fn IoAction(role:Role) type {
    return union(enum) {
        Producing: usize,
        Consuming: usize,
        Eventing: eventCodeType(role),
    };
}

// An IoAction, followed by state to move Session to on completion
pub fn IoStep(role:Role) type {
    return struct {
        action: IoAction(role),
        next_state: Protocol.IoSessionState,
    };
}

// Either Idle, or Active (Producing or Consuming) with a next IoSessionState on completion
pub fn IoState(role:Role) type {
    return union(enum) {
        Idle,
        Active: IoStep(role),
    };
}


pub const MisshodClient = MisshodImpl(.Client);
pub const MisshodServer = MisshodImpl(.Server);


pub fn MisshodImpl(role: Role) type {
    return struct {
    const Self = @This();

    session: sessionType(role),
    iostate: IoState(role),

    // io strategy, only ever reading or writing, always trying to get a fixed number of bytes
    iobuf: [Protocol.MaxSSHPacket]u8 = undefined, // single shared buf, half duplex
    iobuf_nbytes: usize,
    iobuf_rdwroff: usize,

    pub fn init(rand: std.Random, username: []const u8, allocator: std.mem.Allocator) !Self {
        return Self{
            .session = try sessionType(role).init(rand, username, allocator),
            .iobuf_nbytes = 0, // number of bytes in iobuf
            .iobuf_rdwroff = 0, // rd offset into iobuf
            .iostate = .Idle,
        };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        _ = self;
        _ = allocator;
    }

    // for session use
    pub fn requestWrite(self: *Self, wbuf: []const u8, next_state: Protocol.IoSessionState) void {
        std.debug.assert(self.iostate == .Idle);
        std.debug.assert(&wbuf[0] == &self.iobuf[0]);
        self.iobuf_nbytes = wbuf.len;
        self.iobuf_rdwroff = 0; // all writes start from start of buf
        self.iostate = .{ .Active = .{
            .action = .{ .Producing = wbuf.len },
            .next_state = next_state,
        } };
    }

    // for session use
    pub fn requestRead(self: *Self, offset: usize, nbytes: usize, next_state: Protocol.IoSessionState) void {
        self.iobuf_nbytes = 0;
        self.iobuf_rdwroff = offset;
        self.iostate = .{ .Active = .{
            .action = .{ .Consuming = nbytes },
            .next_state = next_state,
        } };
    }

    // for session use
    // FIXME add event code
    pub fn requestEvent(self: *Self, code: eventCodeType(role), next_state: Protocol.IoSessionState) void {
        self.iobuf_nbytes = 0; // unused
        self.iobuf_rdwroff = 0; // unused
        self.iostate = .{ .Active = .{
            .action = .{ .Eventing = code },
            .next_state = next_state,
        } };
    }

    pub fn grantAccess(self: *Self, allow:bool) MisshodError!void {
        switch(role) {
            .Client => return IoError.UnimplementedService, // FIXME something more tailored
            .Server => return try self.session.grantAccess(allow),
        }
    }

    pub fn clearEvent(self: *Self, clearEventCode: eventCodeType(role)) MisshodError!void {
        TRACE(.Debug, "clearEvent clearEventCode={any}", .{clearEventCode});
        TRACE(.Debug, "clearEvent iostate={any}", .{self.iostate});

        switch (self.iostate) {
            .Active => |iotype| {
                switch (iotype.action) {
                    .Eventing => |eventCode| {
                        if (@intFromEnum(eventCode) == @intFromEnum(clearEventCode)) {
                            // event succesfully cleared
                            self.session.setIoSessionState(iotype.next_state);
                            self.iostate = .Idle;
                            try self.advance();
                            return;
                        }
                    },
                    else => {},
                }
            },
            else => {},
        }

        return IoError.badClearEvent;
    }

    pub fn getNextEvent(self: *Self) MisshodError!MisshodEvent(role) {
        // if eventing, send an event
        switch (self.iostate) {
            .Active => |iotype| {
                switch (iotype.action) {
                    .Eventing => |eventCode| {
                        return MisshodEvent(role){ .Event = eventCode };
                    },
                    else => {},
                }
            },
            else => {},
        }

        // else either .ReadyToConsume ^ .ReadyToProduce
        var can_consume_nbytes: usize = 0;
        var can_produce_nbytes: usize = 0;

        try self.getIoReq(&can_consume_nbytes, &can_produce_nbytes);

        std.debug.assert(!(can_consume_nbytes > 0 and can_produce_nbytes > 0));
        std.debug.assert(can_consume_nbytes > 0 or can_produce_nbytes > 0);

        if (can_consume_nbytes > 0) {
            return MisshodEvent(role){ .ReadyToConsume = can_consume_nbytes };
        } else {
            return MisshodEvent(role){ .ReadyToProduce = can_produce_nbytes };
        }

        unreachable;
    }

    fn getIoReq(self: *Self, can_consume: *usize, can_produce: *usize) MisshodError!void {
        try self.advance();

        switch (self.iostate) {
            .Idle => {
                TRACE(.Debug, "getIoReq Idle", .{});
                can_consume.* = 0;
                can_produce.* = 0;
            },
            .Active => |iotype| {
                switch (iotype.action) {
                    .Consuming => |target_size| {
                        TRACE(.Debug, "getIoReq Consuming target_size={d} iobuf.len={d} iobuf.nbytes={d}", .{ target_size, self.iobuf.len, self.iobuf_nbytes });
                        // reading from caller into iobuf
                        if (target_size > self.iobuf.len - self.iobuf_nbytes) {
                            can_consume.* = self.iobuf.len - self.iobuf_nbytes;
                        } else {
                            can_consume.* = target_size - self.iobuf_nbytes;
                        }
                        can_produce.* = 0;
                    },
                    .Producing => |block_size| {
                        TRACE(.Debug, "getIoReq Producing {d} iobuf_nbytes={d}", .{ block_size, self.iobuf_nbytes });
                        // being read by caller from iobuf
                        can_produce.* = self.iobuf_nbytes; // number of bytes in buffer
                        can_consume.* = 0;
                    },
                    .Eventing => {
                        can_produce.* = 0;
                        can_consume.* = 0;
                    },
                }
            },
        }
    }

    pub fn write(self: *Self, wbuf: []const u8) MisshodError!void {
        TRACE(.Debug, "misshod.write len={d} .iobuf_nbytes={d}", .{ wbuf.len, self.iobuf_nbytes });
        switch (self.iostate) {
            .Active => |iotype| {
                switch (iotype.action) {
                    .Consuming => |target_size| {
                        if (wbuf.len > target_size - self.iobuf_nbytes) {
                            return IoError.cannotAcceptWrite;
                        }

                        @memcpy(self.iobuf[self.iobuf_nbytes + self.iobuf_rdwroff .. self.iobuf_nbytes + wbuf.len + self.iobuf_rdwroff], wbuf);
                        self.iobuf_nbytes += wbuf.len;

                        if (self.iobuf_nbytes == target_size) {
                            // entire block has been written by caller
                            self.session.setIoSessionState(iotype.next_state);
                            self.iostate = .Idle;
                            try self.advance();
                        }
                    },
                    else => {},
                }
            },
            else => return IoError.cannotAcceptWrite,
        }
    }

    pub fn peek(self: *Self, nbytes: usize) MisshodError![]const u8 {
        TRACE(.Debug, "peek nbytes={d} .iobuf_rdwroff={d} .iobuf_nbytes={d}", .{ nbytes, self.iobuf_rdwroff, self.iobuf_nbytes });
        // sanity check
        switch (self.iostate) {
            .Active => |iotype| {
                switch (iotype.action) {
                    .Producing => {}, // ok
                    else => return IoError.notProducing,
                }
            },
            else => return IoError.notProducing,
        }

        const bytes_remaining = self.iobuf_nbytes - self.iobuf_rdwroff;

        if (bytes_remaining < nbytes) {
            return self.iobuf[self.iobuf_rdwroff .. self.iobuf_rdwroff + bytes_remaining];
        } else {
            return self.iobuf[self.iobuf_rdwroff..self.iobuf_nbytes];
        }
    }

    pub fn consumed(self: *Self, nbytes: usize) MisshodError!void {
        TRACE(.Debug, "consumed nbytes={d} iobuf_rdwroff={d} .iobuf_nbytes={d}", .{ nbytes, self.iobuf_rdwroff, self.iobuf_nbytes });

        const bytes_remaining = self.iobuf_nbytes - self.iobuf_rdwroff;

        // sanity check
        switch (self.iostate) {
            .Active => |iotype| {
                switch (iotype.action) {
                    .Producing => {
                        if (nbytes > bytes_remaining) {
                            return IoError.notEnoughData;
                        }
                    },
                    else => return IoError.notProducing,
                }
            },
            else => return IoError.notProducing,
        }

        self.iobuf_rdwroff += nbytes;

        if (self.iobuf_rdwroff == self.iobuf_nbytes) {
            // entire block has been consumed by caller
            switch (self.iostate) {
                .Active => |iotype| {
                    self.session.setIoSessionState(iotype.next_state);
                    self.iostate = .Idle;
                    try self.advance();
                },
                else => unreachable,
            }
        }
    }

    pub fn getRecvBuffer(self: *Self, iobuf: []u8, inkeys: *Protocol.KeyDataUni) MisshodError!BufferReader {

        var hdr: Protocol.PktHdr = std.mem.bytesAsValue(Protocol.PktHdr, iobuf[0..Protocol.sizeof_PktHdr]).*;
        if (native_endian != .big) {
            // flip bytes
            std.mem.byteSwapAllFields(Protocol.PktHdr, &hdr);
        }
        const payload_len = hdr.packet_length - hdr.padding_length - 1;
        const payload = iobuf[Protocol.sizeof_PktHdr .. Protocol.sizeof_PktHdr + payload_len];

        if (!self.session.encrypted) {
            return BufferReader.init(payload);
        } else {
            TRACEDUMP(.Debug, "all buf", .{}, iobuf);
            const pkt_len = payload_len + (Protocol.sizeof_PktHdr) + hdr.padding_length;
            if (pkt_len > Protocol.AesCtrT.block_size) { // if there's more to be decrypted after first block
                const remaining_pkt_bytes = pkt_len - Protocol.AesCtrT.block_size;
                var dec: [Protocol.MaxSSHPacket]u8 = undefined;
                inkeys.aesctr.encrypt(iobuf[Protocol.AesCtrT.block_size .. Protocol.AesCtrT.block_size + remaining_pkt_bytes], dec[Protocol.AesCtrT.block_size .. Protocol.AesCtrT.block_size + remaining_pkt_bytes]); // use same offset into dec for simplicity

                TRACEDUMP(.Debug, "dec", .{}, dec[Protocol.AesCtrT.block_size .. Protocol.AesCtrT.block_size + remaining_pkt_bytes]);
                // copy decrypted back into writebuf
                @memcpy(iobuf[Protocol.AesCtrT.block_size .. Protocol.AesCtrT.block_size + remaining_pkt_bytes], dec[Protocol.AesCtrT.block_size .. Protocol.AesCtrT.block_size + remaining_pkt_bytes]);
                TRACEDUMP(.Debug, "writebuf", .{}, iobuf[0..pkt_len]);
            }

            // verify mac
            if (iobuf.len < Protocol.mac_algo.key_length) {
                return error.InvalidPacketSize; // too small to have a mac
            }
            const rxmac = iobuf[pkt_len..iobuf.len]; // at the end
            var calcmac: [Protocol.mac_algo.key_length]u8 = undefined;
            var m = Protocol.mac_algo.init(inkeys.mackey[0..Protocol.mac_algo.key_length]);
            const seq = std.mem.nativeTo(u32, inkeys.seq - 1, .big); // seq has already been incremented
            m.update(std.mem.asBytes(&seq));
            m.update(iobuf[0 .. iobuf.len - Protocol.mac_algo.key_length]); // plaintext
            m.final(&calcmac);

            TRACEDUMP(.Debug, "rxmac", .{}, rxmac);
            TRACEDUMP(.Debug, "mackey", .{}, inkeys.mackey[0..Protocol.mac_algo.key_length]);
            TRACEDUMP(.Debug, "macseq", .{}, std.mem.asBytes(&seq));
            TRACEDUMP(.Debug, "macdata", .{}, iobuf[0 .. iobuf.len - Protocol.mac_algo.key_length]);
            TRACEDUMP(.Debug, "calcmac", .{}, std.mem.asBytes(&calcmac));

            if (!std.mem.eql(u8, &calcmac, rxmac)) {
                return IoError.InvalidMac;
            }

            // remove mac and return buffer containing just plaintext payload
            return BufferReader.init(iobuf[Protocol.sizeof_PktHdr .. iobuf.len - Protocol.mac_algo.key_length]);
        }
    }


    fn advanceIoSession(self:*Self, inkeys:*Protocol.KeyDataUni) MisshodError!void {
        std.debug.assert(self.iostate == .Idle); // we only get called once IO completes
        switch (self.session.ioSessionState) {
            .Idle => {
                TRACE(.Debug, "ioSessionState Idle", .{});
                try self.session.advanceSession(self);
            },
            .Init => {
                switch(role) {
                    .Client => self.session.setIoSessionState(.VersionWrite),
                    .Server => self.session.setIoSessionState(.VersionReadLine),
                }
            },
            .VersionWrite => {
                const sl = self.session.writeProtocolVersion(&self.iobuf);
                switch(role) {
                    .Client => self.requestWrite(sl, .VersionReadLine),
                    .Server => self.requestWrite(sl, .Idle),
                }
            },
            .VersionReadLine => {
                // read first char
                self.requestRead(0, 1, .{ .VersionReadLineChar = self.iobuf[0..1] });
            },
            .VersionReadLineChar => |buf| {
                if (buf.len + 1 > self.iobuf.len) {
                    return IoError.noEOLFound;
                } else {
                    if (buf.len >= 2) {
                        if (buf[buf.len - 2] == '\r' and buf[buf.len - 1] == '\n') {
                            self.session.setIoSessionState(.{ .VersionReadLineCompletion = buf });
                            return;
                        }
                    }
                    // read next char
                    self.requestRead(buf.len, 1, .{ .VersionReadLineChar = self.iobuf[0 .. buf.len + 1] });
                }
            },
            .VersionReadLineCompletion => |buf| {
                TRACE(.Debug, "RX: version '{s}'", .{util.chomp(buf)});
                switch(role) {
                    .Client => self.session.kex_hash_order = self.session.kex_hash_order.check(.V_S),
                    .Server => self.session.kex_hash_order = self.session.kex_hash_order.check(.V_C)
                }
                self.session.kex_hasher.writeU32LenString(util.chomp(buf));
                switch(role) {
                    .Client => self.session.setIoSessionState(.Idle),
                    .Server => self.session.setIoSessionState(.VersionWrite),
                }
            },
            .ReadPktHdr => {
                if (self.session.encrypted) {
                    self.requestRead(0, Protocol.AesCtrT.block_size, .{ .ReadPktBody = self.iobuf[0..Protocol.AesCtrT.block_size] });
                } else {
                    self.requestRead(0, Protocol.sizeof_PktHdr, .{ .ReadPktBody = self.iobuf[0..Protocol.sizeof_PktHdr] });
                }
            },
            .ReadPktBody => |buf| {
                if (self.session.encrypted) {
                    // https://datatracker.ietf.org/doc/html/rfc4253#section-6
                    // grab first encrypted block from writebuf
                    var firstblock_encbuf: [Protocol.AesCtrT.block_size]u8 = undefined;
                    @memcpy(&firstblock_encbuf, buf);

                    // decrypt directly into iobuf
                    inkeys.aesctr.encrypt(&firstblock_encbuf, self.iobuf[0..Protocol.AesCtrT.block_size]);
                    TRACEDUMP(.Debug, "firstblock_dec(in payload)", .{}, self.iobuf[0..Protocol.AesCtrT.block_size]);

                    // read Protocol.PktHdr from first block
                    const pkthdr_size = Protocol.sizeof_PktHdr;
                    var hdr: Protocol.PktHdr = undefined;
                    hdr = std.mem.bytesToValue(Protocol.PktHdr, buf[0..pkthdr_size]);
                    if (native_endian != .big) {
                        std.mem.byteSwapAllFields(Protocol.PktHdr, &hdr);
                    }

                    // padding len is such that payload_len + sizeof(hdr) + padding = block size
                    const payload_len = hdr.packet_length - (hdr.padding_length + 1);
                    if (hdr.padding_length < 4) {
                        return IoError.InvalidPacketSize;
                    }
                    const pkt_len = payload_len + (Protocol.sizeof_PktHdr) + hdr.padding_length;
                    // avoid reading obviously bad packet sizes
                    if (pkt_len < 8 or pkt_len > Protocol.MaxSSHPacket) {
                        TRACE(.Info, "Bad pkt size {d}\n", .{pkt_len});
                        return IoError.InvalidPacketSize;
                    }

                    // calc number of remaining bytes + mac, read from network
                    var remaining_pkt_bytes: usize = 0;
                    if (pkt_len > Protocol.AesCtrT.block_size) {
                        remaining_pkt_bytes = pkt_len - Protocol.AesCtrT.block_size;
                    }
                    TRACE(.Debug, "About to read {d}\n", .{remaining_pkt_bytes + Protocol.mac_algo.key_length});
                    //
                    self.requestRead(buf.len, (remaining_pkt_bytes + Protocol.mac_algo.key_length), .{ .ReadPktCompletion = self.iobuf[0 .. buf.len + remaining_pkt_bytes + Protocol.mac_algo.key_length] }); // on completion, how much we have

                    inkeys.seq +%= 1;
                } else {
                    // copy header
                    var hdr: Protocol.PktHdr = std.mem.bytesAsValue(Protocol.PktHdr, buf[0..Protocol.sizeof_PktHdr]).*;
                    if (native_endian != .big) {
                        // flip bytes
                        std.mem.byteSwapAllFields(Protocol.PktHdr, &hdr);
                    }

                    TRACE(.Debug, ".ReadPktBody hdr={any}", .{hdr});
                    // read in payload
                    const payload_len = hdr.packet_length - hdr.padding_length - 1;
                    std.debug.assert(payload_len <= Protocol.MaxPayload);

                    self.requestRead(buf.len, payload_len + hdr.padding_length, .{ .ReadPktCompletion = self.iobuf[0 .. buf.len + payload_len + hdr.padding_length] });
                    inkeys.seq +%= 1;
                }
            },
            .ReadPktCompletion => |buf| {
                TRACEDUMP(.Debug, ".ReadPktCompletion", .{}, buf);
                try self.session.handlePacket(buf, self);
            },
        }
    }


    pub fn advance(self: *Self) MisshodError!void {
        while (self.iostate == .Idle) { // only ever in Idle at init time or after event, until everything gets flowing
            switch(role) {
                .Client => try self.advanceIoSession(&self.session.keydata.s2c),
                .Server => try self.advanceIoSession(&self.session.keydata.c2s),
            }
        }
    }

    pub fn setPrivateKey(self: *Self, keydata_ascii: []const u8) MisshodError!void {
        try self.session.setPrivateKey(keydata_ascii);
    }

    pub fn setPrivateKeyPassphrase(self: *Self, data: []const u8) MisshodError!void {
        try self.session.setPrivateKeyPassphrase(data);
    }

    pub fn setAuthPassphrase(self: *Self, data: []const u8) MisshodError!void {
        try self.session.setAuthPassphrase(data);
    }

    pub fn isActive(self: *Self) bool {
        return self.session.isActive();
    }

    pub fn getChannelWriteBuffer(self: *Self) MisshodError![]u8 {
        // only returns a nonzero sized buffer if iosessionstate == .Idle
        return self.session.getChannelWriteBuffer();
    }

    pub fn channelWriteComplete(self: *Self, nbytes: usize) MisshodError!void {
        // assumes that getChannelWriteBuffer() is called then channelWriteComplete()
        self.iostate = .Idle;
        try self.advance();

        try self.session.channelWriteComplete(nbytes);
        self.iostate = .Idle;
        try self.advance();
    }
};
}
