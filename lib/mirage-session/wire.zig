//! What the two ends of a session say to each other.
//!
//! Every message is the same length, so a reader takes exactly one message per read and never holds
//! half of one. That matters more than compactness here: a descriptor travels beside the message
//! that hands it over, and a stream socket pairs a descriptor with the bytes of the one send it came
//! with. Messages of one size keep that pairing true without a length to get wrong, and a message is
//! rare enough that the room kept for a name it may not carry costs nothing.

const std = @import("std");
const posix = std.posix;
const sys = posix.system;
const socket = @import("socket.zig");

/// The port a guest's agent opens its first stream to, and the port it opens a stream to when it
/// wants to be connected somewhere. The guest and this side both read them from here, so the two
/// cannot disagree about which is which.
pub const control_port = 1024;
pub const reaching_port = 1025;

pub const header_size = 12;
/// The longest text a message carries: a name to reach, or a directory offered and where it is. Long
/// enough for a whole path under a session directory, because that is what an offer carries.
pub const max_text = 1024;
pub const size = header_size + max_text;

pub const Tag = enum(u8) {
    /// The guest is up and whoever holds the other end may build calls from it.
    up = 1,
    /// The guest has gone. Nothing more will work on this session.
    lost = 2,
    /// Asks for a stream to the guest on a port.
    open = 3,
    /// A stream, with the descriptor for it beside this message.
    opened = 4,
    /// No stream. The reason says why, and the caller may ask again later.
    refused = 5,
    /// Stop the guest and end the session.
    stop = 6,
    /// The guest is trying to reach an address and a port, and nothing has decided yet whether it
    /// may. The value holds the address and the port field holds the port. This is what a guest with
    /// a network of its own produces, because such a guest holds addresses.
    asked = 7,
    /// The answer to one of those. The reason says which way.
    decided = 8,
    /// The guest is reaching for a name and a port. The text holds the name, the port field holds
    /// the port, and the value is the question's own number, which the answer carries back.
    ///
    /// A guest that reaches this way never holds an address, and that is the point of it: the name
    /// is what crosses, so a guest cannot ask for one place and be given another.
    reaching = 9,
    /// The answer. Allowing carries a descriptor already connected where the name led, so this end
    /// resolves nothing and connects to nothing. Refusing carries none and the guest's stream ends.
    reached = 10,
    /// Offer the guest a directory under a name, while it runs. The text holds the name, an equals
    /// sign and the directory, and the reason says whether the guest may change what is in it.
    ///
    /// This exists because the set of directories a guest should see changes between pieces of work,
    /// and the transport cannot add a device to a running machine. What a guest mounts is one
    /// filesystem holding a name for each of these.
    share = 11,
    /// Take one back. The text holds the name. Anything the guest still holds open on it stops
    /// working, which is what a directory offered for one piece of work has to do.
    unshare = 12,
    /// What came of one of those two.
    shared = 13,
    /// An operation a reader has no name for. Never sent.
    _,
};

pub const Reason = enum(u8) {
    none = 0,
    /// The guest is not up, or is up no longer.
    guest_gone = 1,
    /// The guest has opened no stream on that port that nobody holds yet.
    nobody_waiting = 2,
    /// This end has as many streams as it can hold.
    too_many = 3,
    /// This end could not make the pair of descriptors a stream needs.
    no_room = 4,
    /// The guest may reach it.
    allowed = 5,
    /// The guest may not.
    denied = 6,
    /// What the guest is trying: a datagram, or a connection. Said with a question about
    /// somewhere, because what a guest may do with a place can depend on which it is.
    datagram = 7,
    connection = 8,
    /// Whether a directory offered may be changed by the guest.
    writable = 9,
    read_only = 10,
    /// A name nothing can be offered under, or a directory this end will not open.
    bad_name = 11,
    /// Nothing is holding directories for this guest.
    no_shares = 12,
    /// How a guest that has gone came to go, said with `lost`. A harness reports this to whoever
    /// asked for the work, so a build that brought the guest down does not read the same as an
    /// agent that finished.
    powered_off = 13,
    restarted = 14,
    limit_reached = 15,
    faulted = 16,
    /// Whoever holds the session asked for the guest to stop, and it has. Told apart from a limit
    /// because a caller that asked reports work that was cancelled, not work that ran out of room.
    was_asked = 17,
    _,
};

pub const Frame = struct {
    tag: Tag,
    reason: Reason = .none,
    /// A port somewhere else, for a decision about reaching it.
    port: u16 = 0,
    /// A port on the guest for `open`, the guest's address for `up`, an address somewhere else for a
    /// decision, and the question's own number for a name.
    value: u32 = 0,
    /// A name, for a question about somewhere. Points into whatever buffer the message was read
    /// into, so it lasts as long as that does and no longer.
    text: []const u8 = &.{},

    pub fn encode(self: Frame) [size]u8 {
        var bytes: [size]u8 = @splat(0);
        bytes[0] = @intFromEnum(self.tag);
        bytes[1] = @intFromEnum(self.reason);
        std.mem.writeInt(u16, bytes[2..4], self.port, .little);
        std.mem.writeInt(u32, bytes[4..8], self.value, .little);
        // A name longer than the room kept for it is cut rather than refused here. Whoever built
        // the message checked it: a name nobody can hold is a name nothing will answer for.
        const carried = @min(self.text.len, max_text);
        std.mem.writeInt(u16, bytes[8..10], @intCast(carried), .little);
        @memcpy(bytes[header_size..][0..carried], self.text[0..carried]);
        return bytes;
    }

    /// Read a message out of the buffer it arrived in. The text points into that buffer.
    pub fn decode(bytes: *const [size]u8) Frame {
        const carried = @min(std.mem.readInt(u16, bytes[8..10], .little), max_text);
        return .{
            .tag = @enumFromInt(bytes[0]),
            .reason = @enumFromInt(bytes[1]),
            .port = std.mem.readInt(u16, bytes[2..4], .little),
            .value = std.mem.readInt(u32, bytes[4..8], .little),
            .text = bytes[header_size..][0..carried],
        };
    }
};

pub const Error = error{
    /// The other end has gone.
    Ended,
    /// The other end sent something this one has no name for.
    Unreadable,
} || posix.UnexpectedError;

/// Room for one descriptor: the header the kernel wants, then the descriptor, both aligned the way
/// the header is.
const Carry = extern struct {
    head: sys.cmsghdr,
    fd: posix.fd_t,
};

/// The header and one descriptor, with no room for a second. The kernel counts the descriptors from
/// the length in the header, so a length that reaches the padding at the end of the structure says
/// there are two and the second one is whatever was in that memory.
const carried_length = @sizeOf(sys.cmsghdr) + @sizeOf(posix.fd_t);

/// Send one message, and a descriptor with it if there is one. The descriptor stays open on
/// this side: the far end gets one of its own, and closing ours is the caller's to do.
pub fn send(fd: posix.socket_t, frame: Frame, carried: ?posix.fd_t) Error!void {
    const bytes = frame.encode();
    var vector = [1]posix.iovec_const{.{ .base = &bytes, .len = bytes.len }};
    var room: Carry = undefined;

    var head: sys.msghdr_const = .{
        .name = null,
        .namelen = 0,
        .iov = &vector,
        .iovlen = 1,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };
    if (carried) |one| {
        room = .{
            .head = .{
                .len = @intCast(carried_length),
                .level = posix.SOL.SOCKET,
                .type = sys.SCM.RIGHTS,
            },
            .fd = one,
        };
        head.control = &room;
        head.controllen = @intCast(@sizeOf(Carry));
    }

    while (true) {
        const wrote = sys.sendmsg(fd, &head, 0);
        switch (posix.errno(wrote)) {
            .SUCCESS => return,
            .INTR => continue,
            .PIPE, .CONNRESET, .NOTCONN => return Error.Ended,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

/// Take one message into a buffer, and the descriptor it carries if it carries one. Returns null
/// when there is nothing to take yet, so a caller with one thread can ask and carry on.
///
/// The buffer is the caller's because a message may carry a name, and the name in the message this
/// returns points into it. It lasts until the next message is read into the same buffer.
pub fn receive(fd: posix.socket_t, bytes: *[size]u8, carried: *?posix.fd_t) Error!?Frame {
    var vector = [1]posix.iovec{.{ .base = bytes, .len = bytes.len }};
    var room: Carry = undefined;
    room.head = .{ .len = 0, .level = 0, .type = 0 };

    var head: sys.msghdr = .{
        .name = null,
        .namelen = 0,
        .iov = &vector,
        .iovlen = 1,
        .control = &room,
        .controllen = @intCast(@sizeOf(Carry)),
        .flags = 0,
    };

    carried.* = null;
    while (true) {
        const got = sys.recvmsg(fd, &head, 0);
        switch (posix.errno(got)) {
            .SUCCESS => {
                // A read of no bytes on a stream socket is the far end closing.
                if (got == 0) return Error.Ended;
                if (got != size) return Error.Unreadable;
                if (head.controllen >= carried_length and room.head.len >= carried_length and
                    room.head.level == posix.SOL.SOCKET and room.head.type == sys.SCM.RIGHTS)
                {
                    carried.* = room.fd;
                }
                return Frame.decode(bytes);
            },
            .INTR => continue,
            .AGAIN => return null,
            .CONNRESET, .NOTCONN => return Error.Ended,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

test "a frame survives the trip" {
    const one: Frame = .{ .tag = .open, .value = 1024 };
    const bytes = one.encode();
    const back = Frame.decode(&bytes);
    try std.testing.expectEqual(Tag.open, back.tag);
    try std.testing.expectEqual(@as(u32, 1024), back.value);
    try std.testing.expectEqual(Reason.none, back.reason);
}

test "a reason survives the trip" {
    const one: Frame = .{ .tag = .refused, .reason = .nobody_waiting };
    const back = Frame.decode(&one.encode());
    try std.testing.expectEqual(Tag.refused, back.tag);
    try std.testing.expectEqual(Reason.nobody_waiting, back.reason);
}

test "a tag nobody named stays a number" {
    var bytes: [size]u8 = @splat(0);
    bytes[0] = 200;
    const back = Frame.decode(&bytes);
    try std.testing.expect(back.tag != .up);
    try std.testing.expectEqual(@as(u8, 200), @intFromEnum(back.tag));
}

test "a message goes over a socket and a descriptor goes with it" {
    const pair = try socket.pair();
    defer socket.close(pair[0]);
    defer socket.close(pair[1]);

    var carried: ?posix.fd_t = null;
    var room: [size]u8 = undefined;
    // Nothing sent yet, so there is nothing to take.
    try std.testing.expectEqual(@as(?Frame, null), try receive(pair[1], &room, &carried));

    try send(pair[0], .{ .tag = .open, .value = 1024 }, null);
    const plain = (try receive(pair[1], &room, &carried)).?;
    try std.testing.expectEqual(Tag.open, plain.tag);
    try std.testing.expectEqual(@as(u32, 1024), plain.value);
    try std.testing.expectEqual(@as(?posix.fd_t, null), carried);

    // A descriptor with a message. The far end gets one of its own, and bytes written to what was
    // sent arrive on the end this side kept.
    const spare = try socket.pair();
    defer socket.close(spare[0]);
    try send(pair[0], .{ .tag = .opened }, spare[1]);
    socket.close(spare[1]);

    const carrying = (try receive(pair[1], &room, &carried)).?;
    try std.testing.expectEqual(Tag.opened, carrying.tag);
    const theirs = carried orelse return error.NoDescriptorCame;
    defer socket.close(theirs);

    _ = try socket.write(spare[0], "through");
    var came: [16]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 7), try socket.read(theirs, &came));
    try std.testing.expectEqualSlices(u8, "through", came[0..7]);
}

test "an address and a port fit in one message" {
    const one: Frame = .{ .tag = .asked, .port = 443, .value = 0x5db8d822 };
    const back = Frame.decode(&one.encode());
    try std.testing.expectEqual(Tag.asked, back.tag);
    try std.testing.expectEqual(@as(u16, 443), back.port);
    try std.testing.expectEqual(@as(u32, 0x5db8d822), back.value);
}

/// A directory offered to a guest, said as one name and one path.
pub const Sharing = struct {
    name: []const u8,
    at: []const u8,

    /// Split what a `share` message carries. Null when it is not two parts, which is a caller that
    /// meant something this end cannot act on.
    pub fn of(text: []const u8) ?Sharing {
        const split = std.mem.indexOfScalar(u8, text, '=') orelse return null;
        if (split == 0 or split + 1 == text.len) return null;
        return .{ .name = text[0..split], .at = text[split + 1 ..] };
    }

    /// The other way, into a buffer the caller owns.
    pub fn into(self: Sharing, room: []u8) ?[]const u8 {
        if (self.name.len + 1 + self.at.len > room.len) return null;
        @memcpy(room[0..self.name.len], self.name);
        room[self.name.len] = '=';
        @memcpy(room[self.name.len + 1 ..][0..self.at.len], self.at);
        return room[0 .. self.name.len + 1 + self.at.len];
    }
};

test "a directory offered survives being said and read back" {
    var room: [128]u8 = undefined;
    const said = (Sharing{ .name = "store", .at = "/nix/store" }).into(&room).?;
    try std.testing.expectEqualSlices(u8, "store=/nix/store", said);

    const back = Sharing.of(said).?;
    try std.testing.expectEqualSlices(u8, "store", back.name);
    try std.testing.expectEqualSlices(u8, "/nix/store", back.at);
}

test "half of an offer is not an offer" {
    try std.testing.expectEqual(@as(?Sharing, null), Sharing.of("store"));
    try std.testing.expectEqual(@as(?Sharing, null), Sharing.of("=/nix/store"));
    try std.testing.expectEqual(@as(?Sharing, null), Sharing.of("store="));
}
