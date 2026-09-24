//! The socket calls a session needs, on whichever system this is.
//!
//! `std.posix.system` is the syscalls on Linux and the C library elsewhere, and `std.posix.errno`
//! knows how each of them reports a failure. Nothing below names one system.
//!
//! `std.Io.net` is the right way to open and close sockets and the wrong way for these: its accept
//! and its connect wait, and this end is pumped from the thread the guest runs on, so anything that
//! waits stops the guest.

const std = @import("std");
const system = std.posix.system;
const posix = std.posix;

pub const Error = error{
    PathTooLong,
    /// The path is taken, its directory is not writable, or nothing is listening on it.
    Refused,
    /// The far end has gone.
    Closed,
    Unexpected,
};

pub fn stream() Error!posix.fd_t {
    const rc = system.socket(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    if (posix.errno(rc) != .SUCCESS) return Error.Unexpected;
    const fd: posix.fd_t = @intCast(rc);
    try dontWait(fd);
    return fd;
}

/// A pair of connected descriptors. One end is handed over and the other is kept.
pub fn pair() Error![2]posix.fd_t {
    var made: [2]i32 = undefined;
    const rc = system.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &made);
    if (posix.errno(rc) != .SUCCESS) return Error.Unexpected;
    try dontWait(made[0]);
    try dontWait(made[1]);
    return made;
}

/// Ask a descriptor not to wait. Which bit that is differs by system, and `std.posix.O` knows.
pub fn dontWait(fd: posix.fd_t) Error!void {
    const flags = system.fcntl(fd, posix.F.GETFL, @as(usize, 0));
    if (posix.errno(flags) != .SUCCESS) return Error.Unexpected;

    const asking: posix.O = .{ .NONBLOCK = true };
    const wanted = @as(usize, @as(u32, @bitCast(asking))) | @as(usize, @intCast(flags));
    const rc = system.fcntl(fd, posix.F.SETFL, wanted);
    if (posix.errno(rc) != .SUCCESS) return Error.Unexpected;
}

const Address = struct {
    raw: posix.sockaddr.un,
    len: posix.socklen_t,
};

fn address(path: []const u8) Error!Address {
    var raw: posix.sockaddr.un = .{ .family = posix.AF.UNIX, .path = @splat(0) };
    // One byte is kept for the end of the name.
    if (path.len >= raw.path.len) return Error.PathTooLong;
    @memcpy(raw.path[0..path.len], path);
    return .{ .raw = raw, .len = @intCast(@sizeOf(posix.sockaddr.un)) };
}

/// Bind a path and listen on it. A path left behind by a session that died is not a session, so
/// it goes: a bind onto it would fail and the guest would never come up.
pub fn hold(path: []const u8) Error!posix.fd_t {
    const at = try address(path);
    const fd = try stream();
    errdefer close(fd);

    forget(path);
    if (posix.errno(system.bind(fd, @ptrCast(&at.raw), at.len)) != .SUCCESS) return Error.Refused;
    if (posix.errno(system.listen(fd, 1)) != .SUCCESS) return Error.Refused;
    return fd;
}

/// Take whoever is waiting, or nothing. Never waits.
pub fn take(listener: posix.fd_t) ?posix.fd_t {
    const rc = system.accept(listener, null, null);
    if (posix.errno(rc) != .SUCCESS) return null;
    const fd: posix.fd_t = @intCast(rc);
    dontWait(fd) catch {
        close(fd);
        return null;
    };
    return fd;
}

pub fn reach(path: []const u8) Error!posix.fd_t {
    const at = try address(path);
    const fd = try stream();
    errdefer close(fd);
    if (posix.errno(system.connect(fd, @ptrCast(&at.raw), at.len)) != .SUCCESS) return Error.Refused;
    return fd;
}

pub fn close(fd: posix.fd_t) void {
    _ = system.close(fd);
}

pub fn forget(path: []const u8) void {
    var room: [256]u8 = undefined;
    if (path.len >= room.len) return;
    @memcpy(room[0..path.len], path);
    room[path.len] = 0;
    _ = system.unlink(@ptrCast(&room));
}

/// Read what has arrived. Zero means nothing yet, which is not the same as the far end going.
pub fn read(fd: posix.fd_t, into: []u8) Error!usize {
    if (into.len == 0) return 0;
    const got = system.read(fd, into.ptr, into.len);
    return switch (posix.errno(got)) {
        .SUCCESS => if (got == 0) Error.Closed else @intCast(got),
        .AGAIN, .INTR => 0,
        .CONNRESET, .PIPE => Error.Closed,
        else => Error.Unexpected,
    };
}

pub fn write(fd: posix.fd_t, bytes: []const u8) Error!usize {
    if (bytes.len == 0) return 0;
    const put = system.write(fd, bytes.ptr, bytes.len);
    return switch (posix.errno(put)) {
        .SUCCESS => @intCast(put),
        .AGAIN, .INTR => 0,
        .CONNRESET, .PIPE => Error.Closed,
        else => Error.Unexpected,
    };
}

/// Wait for a descriptor to have something, for as long as this many milliseconds. Used where
/// there is one thing to wait for and nothing else to do, which is starting and stopping.
pub fn waitFor(fd: posix.fd_t, ms: u64) void {
    var one = [1]posix.pollfd{.{ .fd = fd, .events = posix.POLL.IN, .revents = 0 }};
    _ = posix.poll(&one, @intCast(ms)) catch {};
}

pub fn rest(ms: u64) void {
    var none: [0]posix.pollfd = .{};
    _ = posix.poll(&none, @intCast(ms)) catch {};
}

test "a pair carries bytes and says when an end has gone" {
    const made = try pair();
    defer close(made[1]);

    var room: [8]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), try read(made[1], &room));
    try std.testing.expectEqual(@as(usize, 2), try write(made[0], "hi"));
    try std.testing.expectEqual(@as(usize, 2), try read(made[1], &room));

    close(made[0]);
    try std.testing.expectError(Error.Closed, read(made[1], &room));
}

test "a path longer than an address holds is refused before anything opens" {
    var long: [256]u8 = @splat('x');
    try std.testing.expectError(Error.PathTooLong, hold(&long));
}
