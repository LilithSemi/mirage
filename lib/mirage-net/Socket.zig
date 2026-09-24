//! A stream socket to a program that carries a guest's traffic off this machine, or that answers its
//! security chip.
//!
//! Whoever starts a guest starts that program, so the usual way in is a descriptor that is already
//! connected: the caller makes a pair, hands one end over, and gives the other to this. Connecting to a
//! path is here as well, because a person at a shell has a path and not a descriptor.
//!
//! Connecting and closing are `std.Io.net`'s work and not this file's. What this file adds is reading
//! and writing that never wait.
//!
//! `std.Io.Reader` and `std.Io.Writer` are the right way to move bytes and the wrong way to move these.
//! Their contract is to wait until there is something, and this runs on the thread the guest runs on,
//! so waiting for a helper with nothing to say stops the guest. That is why the descriptor is used
//! directly here. Once the device model has a thread of its own, waiting becomes correct and this file
//! becomes a `Stream.Reader`.
//!
//! Nothing below names one system. `std.posix.system` is whichever one this is, the syscalls on Linux
//! and the C library elsewhere, and `std.posix.errno` knows how each of them reports a failure.

const std = @import("std");
const system = std.posix.system;

const Socket = @This();

pub const Error = error{
    PathTooLong,
    NotListening,
    /// The helper closed the connection, or it was never open.
    Closed,
    Unexpected,
};

stream: std.Io.net.Stream,

/// Take a descriptor that is already connected. This is the way a harness uses: it made the
/// pair and started the helper on the other end, so no path exists and there is no moment
/// when something else could connect instead.
pub fn adopt(handle: std.posix.fd_t) Error!Socket {
    const self: Socket = .{
        .stream = .{
            .socket = .{
                .handle = handle,
                // A unix socket has no address of its own. The field is here for the ones that do.
                .address = .{ .ip4 = .loopback(0) },
            },
        },
    };
    try self.dontWait();
    return self;
}

/// Connect to a helper that is listening on a path.
pub fn connect(io: std.Io, path: []const u8) Error!Socket {
    const address = std.Io.net.UnixAddress.init(path) catch return Error.PathTooLong;
    const stream = address.connect(io) catch |err| switch (err) {
        // A path with nothing at it. A socket that exists with nobody listening on it is not
        // told apart here, because `std.Io.net` does not name that case yet and it arrives as
        // an unexpected one.
        error.FileNotFound => return Error.NotListening,
        else => return Error.Unexpected,
    };

    const self: Socket = .{ .stream = stream };
    errdefer self.stream.close(io);
    try self.dontWait();
    return self;
}

/// Ask the descriptor not to wait, so a read with nothing behind it answers rather than blocks. Which
/// bit that is differs by system, and `std.posix.O` is what knows.
fn dontWait(self: Socket) Error!void {
    const handle = self.stream.socket.handle;

    const flags = system.fcntl(handle, std.posix.F.GETFL, @as(usize, 0));
    if (std.posix.errno(flags) != .SUCCESS) return Error.Unexpected;

    const asking: std.posix.O = .{ .NONBLOCK = true };
    const wanted = @as(usize, @as(u32, @bitCast(asking))) | @as(usize, @intCast(flags));
    const rc = system.fcntl(handle, std.posix.F.SETFL, wanted);
    if (std.posix.errno(rc) != .SUCCESS) return Error.Unexpected;
}

pub fn close(self: *Socket, io: std.Io) void {
    self.stream.close(io);
    self.* = undefined;
}

/// Read whatever has arrived. Returns how much, which is zero when nothing has.
pub fn read(self: Socket, into: []u8) Error!usize {
    if (into.len == 0) return 0;
    const got = system.read(self.stream.socket.handle, into.ptr, into.len);
    return switch (std.posix.errno(got)) {
        // Zero bytes from a stream means the far end has gone, which is not the same as
        // nothing having arrived. A caller that cannot tell them apart spins on a dead helper.
        .SUCCESS => if (got == 0) Error.Closed else @intCast(got),
        .AGAIN, .INTR => 0,
        .CONNRESET, .PIPE => Error.Closed,
        else => Error.Unexpected,
    };
}

/// Write what will go now. Returns how much went, which is often less than was offered and
/// sometimes none at all.
pub fn write(self: Socket, bytes: []const u8) Error!usize {
    if (bytes.len == 0) return 0;
    const put = system.write(self.stream.socket.handle, bytes.ptr, bytes.len);
    return switch (std.posix.errno(put)) {
        .SUCCESS => @intCast(put),
        // The helper is not keeping up. What is left stays for the next turn.
        .AGAIN, .INTR => 0,
        .CONNRESET, .PIPE => Error.Closed,
        else => Error.Unexpected,
    };
}

/// A connected pair, for a test that wants both ends. Nothing outside a test needs this: a caller
/// with a helper to start makes its own pair and hands one end to it.
fn pair() ?[2]std.posix.fd_t {
    var made: [2]i32 = undefined;
    const rc = system.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &made);
    if (std.posix.errno(rc) != .SUCCESS) return null;
    return made;
}

test "a pair of sockets carries bytes without waiting" {
    const made = pair() orelse return error.SkipZigTest;

    const one = try Socket.adopt(made[0]);
    const two = try Socket.adopt(made[1]);
    defer _ = system.close(made[0]);
    defer _ = system.close(made[1]);

    // Nothing sent yet. A read that waits here would stop the guest for as long as the helper
    // stays quiet, which is most of the time.
    var buffer: [64]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), try two.read(&buffer));

    try std.testing.expectEqual(@as(usize, 5), try one.write("hello"));
    try std.testing.expectEqual(@as(usize, 5), try two.read(&buffer));
    try std.testing.expectEqualSlices(u8, "hello", buffer[0..5]);
}

test "a helper that goes away is reported rather than read as an empty frame" {
    const made = pair() orelse return error.SkipZigTest;

    const two = try Socket.adopt(made[1]);
    defer _ = system.close(made[1]);
    _ = system.close(made[0]);

    var buffer: [64]u8 = undefined;
    try std.testing.expectError(Error.Closed, two.read(&buffer));
}

test "a path longer than a socket address holds is refused" {
    var long: [256]u8 = @splat('x');
    // No `Io` is needed to reach this, because the length is wrong before anything is opened.
    try std.testing.expectError(Error.PathTooLong, Socket.connect(undefined, &long));
}
