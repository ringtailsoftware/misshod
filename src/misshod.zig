const std = @import("std");
const util = @import("util.zig");
const TRACE = util.trace;
const TRACEDUMP = util.tracedump;
const Session = @import("session.zig").Session;
const IoSessionState = @import("session.zig").IoSessionState;
const BufferError = @import("buffer.zig").BufferError;
const PrivKeyError = @import("privkey.zig").PrivKeyError;

// Buffer
const MaxSSHPacket = @import("session.zig").MaxSSHPacket;

pub const MisshodError = std.crypto.errors.Error || std.mem.Allocator.Error || BufferError || IoError || PrivKeyError;

pub const IoError = error{
    cannotAcceptWrite,
    notProducing,
    notEnoughData,
    noEOLFound,
    badClearEvent,
    InvalidPacketSize,
    InvalidMacS2C,
    UnexpectedResponse,
    tooBig,
};

pub const EndSessionReason = enum {
    Disconnect,
    AuthFailure,
};

pub const MisshodUserEventCodes = union(enum) {
    CheckHostKey: ?[]const u8,
    GetPrivateKey,
    GetKeyPassphrase,
    GetAuthPassphrase,
    EndSession: EndSessionReason,
    Connected,
    RxData: []const u8,
};

pub const MisshodEvent = union(enum) {
    Event: MisshodUserEventCodes,
    ReadyToConsume: usize,
    ReadyToProduce: usize,
};

// Producing a block, or consuming a block
pub const IoAction = union(enum) {
    Producing: usize,
    Consuming: usize,
    Eventing: MisshodUserEventCodes,
};

// An IoAction, followed by state to move Session to on completion
pub const IoStep = struct {
    action: IoAction,
    next_state: IoSessionState,
};

// Either Idle, or Active (Producing or Consuming) with a next IoSessionState on completion
pub const IoState = union(enum) {
    Idle,
    Active: IoStep,
};

pub const Misshod = struct {
    const Self = @This();

    session: Session,
    iostate: IoState,

    // io strategy, only ever reading or writing, always trying to get a fixed number of bytes
    iobuf: [MaxSSHPacket]u8 = undefined, // single shared buf, half duplex
    iobuf_nbytes: usize,
    iobuf_rdwroff: usize,

    pub fn init(rand: std.Random, username: []const u8, allocator: std.mem.Allocator) !Self {
        return Self{
            .session = Session.init(rand, username, allocator),
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
    pub fn requestWrite(self: *Self, wbuf: []const u8, next_state: IoSessionState) void {
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
    pub fn requestRead(self: *Self, offset: usize, nbytes: usize, next_state: IoSessionState) void {
        self.iobuf_nbytes = 0;
        self.iobuf_rdwroff = offset;
        self.iostate = .{ .Active = .{
            .action = .{ .Consuming = nbytes },
            .next_state = next_state,
        } };
    }

    // for session use
    // FIXME add event code
    pub fn requestEvent(self: *Self, code: MisshodUserEventCodes, next_state: IoSessionState) void {
        self.iobuf_nbytes = 0; // unused
        self.iobuf_rdwroff = 0; // unused
        self.iostate = .{ .Active = .{
            .action = .{ .Eventing = code },
            .next_state = next_state,
        } };
    }

    pub fn clearEvent(self: *Self, clearEventCode: MisshodUserEventCodes) MisshodError!void {
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

    pub fn getNextEvent(self: *Self) MisshodError!MisshodEvent {
        // if eventing, send an event
        switch (self.iostate) {
            .Active => |iotype| {
                switch (iotype.action) {
                    .Eventing => |eventCode| {
                        return MisshodEvent{ .Event = eventCode };
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
            return MisshodEvent{ .ReadyToConsume = can_consume_nbytes };
        } else {
            return MisshodEvent{ .ReadyToProduce = can_produce_nbytes };
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

    pub fn advance(self: *Self) MisshodError!void {
        while (self.iostate == .Idle) { // only ever in Idle at init time or after event, until everything gets flowing
            try self.session.advanceIoSession(self);
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
        return self.session.getChannelWriteBuffer();
    }

    pub fn channelWriteComplete(self: *Self, nbytes: usize) MisshodError!void {
        try self.session.channelWriteComplete(nbytes);
        self.iostate = .Idle;
        try self.advance();
    }
};
