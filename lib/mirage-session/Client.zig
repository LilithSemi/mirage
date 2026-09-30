//! The end of a session that asks for streams into the guest.
//!
//! Three calls: start a guest, take a stream to it, stop it. Everything else is a descriptor the
//! caller already knows how to poll. Nothing here starts a thread and nothing here calls back, so a
//! caller with one thread and one poll loop can hold a guest without changing its shape.
//!
//! A guest lives as long as the session does. Whoever starts one keeps this, and whoever only uses
//! one is handed the descriptor and adopts it, so the guest outlives any single call.

const std = @import("std");
const posix = std.posix;
const wire = @import("wire.zig");
const socket = @import("socket.zig");

const Client = @This();

control: posix.socket_t,
/// Only needed to start a guest and to wait for the process when it ends. A session that was
/// adopted has none: the descriptor is all it needs.
io: ?std.Io = null,
/// The process running the guest, when this end started it. A caller that adopted a descriptor
/// has none: the guest belongs to whoever started it.
guest: ?std.process.Child = null,
/// Set once the guest has said it is up, and again when it has gone.
up: bool = false,
gone: bool = false,
/// The guest's address on the channel, as the guest end sees it.
cid: u32 = 0,
/// A message is read into this. A name in a message points here, so it lasts until the next
/// message is read.
said: [wire.size]u8 = undefined,

pub const Error = error{
    /// The session's socket is not there, or nothing is listening on it.
    NoSession,
    /// The guest did not come up in the time it was given. A session that starts this way is
    /// a session that has no sandbox, which is a refusal and not a call that does nothing.
    GuestDidNotBoot,
    /// The guest was up and is not any more.
    GuestGone,
    /// The guest opened no stream on that port that nobody holds yet. Asking again later is
    /// reasonable: the guest may not have got to it.
    NobodyWaiting,
    /// This session is already holding as many streams as it can.
    TooManyStreams,
    /// The other end could not make a stream.
    NoRoom,
    /// The other end said something this one has no name for.
    Unreadable,
    /// A socket call failed in a way no name was given to.
    Unexpected,
    /// Nothing is holding directories for this guest, so none can be offered to it.
    NoShares,
    /// That name or that directory is not one anything can be offered under.
    BadShare,
};

pub const Share = struct {
    name: []const u8,
    at: []const u8,
};

pub const Options = struct {
    /// The program that runs a guest, found the way a shell would find it.
    program: []const u8 = "mirage",
    /// Where the session's socket goes. One path, one guest.
    socket: []const u8,
    kernel: []const u8,
    initrd: ?[]const u8 = null,
    disk: ?[]const u8 = null,
    cmdline: ?[]const u8 = null,
    root_hash: ?[]const u8 = null,
    memory_mb: u64 = 512,
    cpus: u32 = 1,
    /// The port the guest opens its streams to.
    port: u32 = wire.control_port,
    /// A directory on this machine the guest may mount, and the name it mounts it by. Read only,
    /// which is what a harness wants for the tools it gives a guest: nothing the guest does can
    /// change what every other guest will read.
    share: ?Share = null,
    /// Whether the guest is given a network of the host's own. A sandbox that brokers every
    /// connection wants this off, and its broker decides what may be reached.
    network: bool = false,
    /// Where the guest's console goes. A guest that failed to boot says why there and nowhere else, so
    /// a caller that wants to know keeps it. Inheriting is for a program with a terminal: a caller whose
    /// own output is a pipe somebody else reads should give a file instead.
    console: std.process.SpawnOptions.StdIo = .ignore,
    /// How long to wait for the guest to say it is up.
    boot_ms: u64 = 20_000,
};

/// Start a guest and wait for it to say it is up. Returns only once there is a guest to build
/// calls from, or an error saying there is not.
pub fn start(gpa: std.mem.Allocator, io: std.Io, options: Options) (Error || error{OutOfMemory})!Client {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(gpa);

    var memory: [24]u8 = undefined;
    var cpus: [12]u8 = undefined;
    var port: [12]u8 = undefined;

    try argv.appendSlice(gpa, &.{ options.program, "run", "--kernel", options.kernel });
    try argv.appendSlice(gpa, &.{ "--session", options.socket });
    try argv.appendSlice(gpa, &.{ "--vsock", std.fmt.bufPrint(&port, "{d}", .{options.port}) catch unreachable });
    try argv.appendSlice(gpa, &.{ "--memory", std.fmt.bufPrint(&memory, "{d}", .{options.memory_mb}) catch unreachable });
    try argv.appendSlice(gpa, &.{ "--cpus", std.fmt.bufPrint(&cpus, "{d}", .{options.cpus}) catch unreachable });
    if (options.initrd) |path| try argv.appendSlice(gpa, &.{ "--initrd", path });
    if (options.disk) |path| try argv.appendSlice(gpa, &.{ "--disk", path });
    if (options.cmdline) |line| try argv.appendSlice(gpa, &.{ "--cmdline", line });
    if (options.root_hash) |hex| try argv.appendSlice(gpa, &.{ "--root-hash", hex });
    if (options.network) try argv.appendSlice(gpa, &.{ "--nat", "yes" });
    var sharing: [512]u8 = undefined;
    if (options.share) |offered| {
        const said = std.fmt.bufPrint(&sharing, "{s}={s}", .{ offered.name, offered.at }) catch
            return Error.NoSession;
        try argv.appendSlice(gpa, &.{ "--share", said });
    }

    const child = std.process.spawn(io, .{
        .argv = argv.items,
        .stdin = .ignore,
        .stdout = options.console,
        .stderr = options.console,
    }) catch return Error.NoSession;

    var self: Client = .{ .control = -1, .io = io, .guest = child };
    errdefer self.stop();

    // The guest's process binds the socket once it is running, so this waits for the path to
    // appear rather than deciding on the first try that there is no session.
    self.control = reach(options.socket, options.boot_ms) catch return Error.GuestDidNotBoot;
    try self.wait(options.boot_ms);
    return self;
}

/// Take a session somebody else started. The descriptor is connected to the session's socket and
/// says the guest is up: whoever started it waited for that already.
pub fn adopt(control: posix.socket_t) Client {
    return .{ .control = control, .up = true };
}

/// What to poll. Readable means the guest said something about itself, which `take` reads.
pub fn descriptor(self: *const Client) posix.fd_t {
    return self.control;
}

/// A guest reaching for a name. The name is what crosses: the guest never holds an address, and what
/// is handed back for one of these is a descriptor already connected there.
///
/// The name is held here rather than pointed at. Deciding can take as long as it takes, including
/// asking a person, and every message read while that happens would have overwritten a name that
/// only pointed into the buffer it arrived in. What that loses is not a crash but a connection to
/// whatever name landed there next, which nobody approved, so the name is copied and this is a value
/// a caller can hold for as long as it likes.
pub const Reaching = struct {
    said: [wire.max_text]u8 = undefined,
    said_len: usize = 0,
    port: u16 = 0,
    /// The question's own number. Handed back with the answer, and nothing else identifies it: a
    /// guest may reach the same name twice and those are two streams.
    ticket: u32 = 0,

    pub fn name(self: *const Reaching) []const u8 {
        return self.said[0..self.said_len];
    }

    fn of(frame: wire.Frame) Reaching {
        var one: Reaching = .{ .port = frame.port, .ticket = frame.value };
        one.said_len = @min(frame.text.len, one.said.len);
        @memcpy(one.said[0..one.said_len], frame.text[0..one.said_len]);
        return one;
    }
};

/// How the guest came to go.
///
/// Its own names rather than the wire's, because the wire says why anything was refused and only
/// four of those are ways a guest ends. A caller switches on this and has covered every one.
pub const Lost = enum {
    /// The guest powered itself off, which is how work that finished ends.
    powered_off,
    /// The guest asked to be started again. Nothing starts it: a session holds one guest, so this
    /// reaches a caller as a guest that has gone.
    restarted,
    /// Whoever holds the session asked for it, so the work was cancelled rather than finished.
    asked,
    /// A limit whoever started the guest gave it ran out, either the exits or the seconds.
    limit_reached,
    /// The guest or the hypervisor under it failed. What failed is in the runner's own output,
    /// because a byte on a socket cannot carry a fault.
    faulted,
    /// The session went away saying nothing. A runner that was killed looks like this, and so does
    /// one built before it had anything to say.
    unsaid,

    fn of(reason: wire.Reason) Lost {
        return switch (reason) {
            .powered_off => .powered_off,
            .restarted => .restarted,
            .limit_reached => .limit_reached,
            .was_asked => .asked,
            .faulted => .faulted,
            else => .unsaid,
        };
    }
};

/// What a session says about itself and about the guest it holds.
///
/// A value rather than the message it came from, so nothing a caller holds points into a buffer that
/// the next message is read into.
pub const Event = union(enum) {
    /// The guest is up, and this is its address on the channel.
    up: u32,
    /// The guest has gone, and this is how it went. Nothing more will work on this session.
    lost: Lost,
    /// The guest is reaching for a name. Answer with `allow` or `refuse`.
    reaching: Reaching,
    /// Something a session said that a caller of this version has no name for. Never anything that
    /// needs answering: a session says nothing else on its own.
    other: wire.Tag,
};

/// Read what the session said, if it said anything. Returns null when there is nothing to read, so
/// this can be called from a poll loop that woke for something else.
pub fn take(self: *Client) Error!?Event {
    var carried: ?posix.fd_t = null;
    const frame = wire.receive(self.control, &self.said, &carried) catch |err| switch (err) {
        error.Ended => {
            self.gone = true;
            return Event{ .lost = .unsaid };
        },
        error.Unreadable => return Error.Unreadable,
        else => |rest| return rest,
    } orelse return null;
    if (carried) |extra| socket.close(extra);

    switch (frame.tag) {
        .up => {
            self.up = true;
            self.cid = frame.value;
            return Event{ .up = frame.value };
        },
        .lost => {
            self.gone = true;
            return Event{ .lost = .of(frame.reason) };
        },
        .reaching => return Event{ .reaching = .of(frame) },
        else => return Event{ .other = frame.tag },
    }
}

/// Let the guest reach where it asked, through a descriptor that is already connected there.
///
/// Whoever answers decides and connects: this end resolves nothing and opens nothing, so a guest
/// cannot ask for one place and be handed another. The descriptor stays open here as well and
/// closing it is the caller's to do.
pub fn allow(self: *Client, reaching: Reaching, connected: posix.fd_t) Error!void {
    wire.send(self.control, .{
        .tag = .reached,
        .reason = .allowed,
        .port = reaching.port,
        .value = reaching.ticket,
    }, connected) catch |err| switch (err) {
        error.Ended => {
            self.gone = true;
            return Error.GuestGone;
        },
        else => return Error.Unexpected,
    };
}

/// Refuse where the guest asked to reach. The guest's stream ends and it learns nothing else.
pub fn refuse(self: *Client, reaching: Reaching) Error!void {
    try self.say(.{
        .tag = .reached,
        .reason = .denied,
        .port = reaching.port,
        .value = reaching.ticket,
    });
}

/// Offer the guest a directory while it runs, under a name it will see in what it mounted.
///
/// For a caller whose set of directories changes between pieces of work: offer what a piece of work
/// needs before it starts and take it back after. The guest needs no restart and mounts nothing new,
/// because what it mounted holds a name for each of these.
pub fn share(self: *Client, name: []const u8, at: []const u8, writable: bool) Error!void {
    var room: [wire.max_text]u8 = undefined;
    const said = (wire.Sharing{ .name = name, .at = at }).into(&room) orelse return Error.Unreadable;
    try self.say(.{
        .tag = .share,
        .reason = if (writable) .writable else .read_only,
        .text = said,
    });
    return self.hearAboutShare();
}

/// Take one back. Whatever the guest still holds open on it stops working, which is what a directory
/// offered for one piece of work has to do when that work is over.
pub fn unshare(self: *Client, name: []const u8) Error!void {
    try self.say(.{ .tag = .unshare, .text = name });
    return self.hearAboutShare();
}

/// Wait for the answer to an offer or a withdrawal. Everything else that may arrive is held for the
/// caller's own reading, except the guest going, which is the end of all of it.
fn hearAboutShare(self: *Client) Error!void {
    var left: u64 = 5_000;
    while (left > 0) : (left -= 1) {
        var carried: ?posix.fd_t = null;
        const frame = wire.receive(self.control, &self.said, &carried) catch |err| switch (err) {
            error.Ended => {
                self.gone = true;
                return Error.GuestGone;
            },
            error.Unreadable => return Error.Unreadable,
            else => |rest| return rest,
        } orelse {
            socket.waitFor(self.control, 1);
            continue;
        };
        if (carried) |extra| socket.close(extra);

        switch (frame.tag) {
            .shared => return switch (frame.reason) {
                .writable, .read_only, .none => {},
                .no_shares => Error.NoShares,
                else => Error.BadShare,
            },
            .lost => {
                self.gone = true;
                return Error.GuestGone;
            },
            else => {},
        }
    }
    return Error.GuestGone;
}

/// Take a stream to the guest on a port. The result is a descriptor: the caller reads and writes
/// it, polls it beside everything else, and closes it when the call is over.
pub fn channel(self: *Client, port: u32) Error!posix.fd_t {
    if (self.gone) return Error.GuestGone;
    try self.say(.{ .tag = .open, .value = port });

    // The answer is one message, and the only other thing that can arrive is the guest going.
    var left: u64 = 5_000;
    while (left > 0) : (left -= 1) {
        var carried: ?posix.fd_t = null;
        const frame = wire.receive(self.control, &self.said, &carried) catch |err| switch (err) {
            error.Ended => {
                self.gone = true;
                return Error.GuestGone;
            },
            error.Unreadable => return Error.Unreadable,
            else => |rest| return rest,
        } orelse {
            socket.waitFor(self.control, 1);
            continue;
        };

        switch (frame.tag) {
            .opened => return carried orelse Error.Unreadable,
            .refused => {
                if (carried) |extra| socket.close(extra);
                return switch (frame.reason) {
                    .nobody_waiting => Error.NobodyWaiting,
                    .too_many => Error.TooManyStreams,
                    .no_room => Error.NoRoom,
                    else => Error.GuestGone,
                };
            },
            .lost => {
                if (carried) |extra| socket.close(extra);
                self.gone = true;
                return Error.GuestGone;
            },
            else => if (carried) |extra| socket.close(extra),
        }
    }
    return Error.GuestGone;
}

/// Stop the guest and let go of the session. A session that is stopped twice is stopped once.
pub fn stop(self: *Client) void {
    if (self.control >= 0) {
        self.say(.{ .tag = .stop }) catch {};
        // The guest's process holds the other end, so the far end closing is the guest going. A
        // limit belongs here: a guest that will not stop must not hold up whoever asked it to.
        var left: u64 = 3_000;
        while (left > 0 and !closed(self.control)) : (left -= 20) socket.waitFor(self.control, 20);
        socket.close(self.control);
        self.control = -1;
    }
    if (self.guest) |*child| {
        // Whatever is left of it goes now. This waits for the process and takes back what it held,
        // and one that has already stopped is only collected.
        if (self.io) |io| child.kill(io);
        self.guest = null;
    }
    self.gone = true;
}

/// Whether the far end of a socket has gone. Anything still to read is thrown away: this is only
/// asked while stopping, and nothing said then is anybody's to act on.
fn closed(fd: posix.fd_t) bool {
    var byte: [1]u8 = undefined;
    _ = socket.read(fd, &byte) catch return true;
    return false;
}

fn say(self: *Client, frame: wire.Frame) Error!void {
    wire.send(self.control, frame, null) catch |err| switch (err) {
        error.Ended => {
            self.gone = true;
            return Error.GuestGone;
        },
        else => return Error.Unreadable,
    };
}

/// Connect to the session's socket, waiting for it to appear.
fn reach(path: []const u8, ms: u64) Error!posix.socket_t {
    var left = ms;
    while (true) {
        if (socket.reach(path)) |fd| return fd else |_| {}
        if (left == 0) return Error.NoSession;
        const step = @min(left, 20);
        socket.rest(step);
        left -= step;
    }
}

/// Wait for the guest to say it is up.
fn wait(self: *Client, ms: u64) Error!void {
    var left = ms;
    while (left > 0) {
        if (self.take() catch return Error.GuestDidNotBoot) |said| switch (said) {
            .up => return,
            .lost => return Error.GuestDidNotBoot,
            else => continue,
        };
        const step = @min(left, 20);
        socket.waitFor(self.control, step);
        left -= step;
    }
    return Error.GuestDidNotBoot;
}

test "a guest that has gone says how it went" {
    const ends = try socket.pair();
    defer socket.close(ends[0]);
    defer socket.close(ends[1]);

    var mine = Client.adopt(ends[1]);
    try wire.send(ends[0], .{ .tag = .lost, .reason = .limit_reached }, null);
    const said = (try mine.take()).?;
    try std.testing.expectEqual(Lost.limit_reached, said.lost);
}

test "a session that closes without a word still says the guest has gone" {
    const ends = try socket.pair();
    defer socket.close(ends[1]);

    var mine = Client.adopt(ends[1]);
    socket.close(ends[0]);
    const said = (try mine.take()).?;
    try std.testing.expectEqual(Lost.unsaid, said.lost);
}
