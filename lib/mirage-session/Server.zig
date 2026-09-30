//! The end of a session that holds the guest.
//!
//! A session is one guest that stays up as long as whoever asked for it is there. This end lives
//! in the process that runs the guest, and it is pumped from the same loop that serves the guest's
//! devices: it never blocks, never starts a thread, and does nothing between calls. That is what
//! lets the guest's own loop stay the only loop there is.
//!
//! Streams go one way only: the guest opens them and this end hands them out. The transport is
//! built that way, and a stream the guest opened is also proof the guest is alive to open it.

const std = @import("std");
const posix = std.posix;
const wire = @import("wire.zig");
const socket = @import("socket.zig");
const Vsock = @import("mirage-device").virtio.Vsock;

const Server = @This();

/// How many places the guest can be reaching for at once, waiting for somebody to decide.
pub const max_reaching = 8;

/// How many streams one session can hand out at a time. The transport holds a few connections and
/// a stream costs a pair of descriptors, so the limit is small on purpose.
pub const max_streams = 8;
/// Streams the guest has opened that nobody has claimed. A guest may open them before anything
/// asks, which is how a caller gets one without waiting.
pub const max_waiting = 8;

/// A guest reaching for a name. The guest opens a stream, writes the name and the port it wants,
/// and waits. Nothing is read from it as data until somebody has decided, and if the answer is no
/// the stream ends without the guest ever learning an address.
const Reaching = struct {
    used: bool = false,
    handle: Vsock.Handle = undefined,
    /// The question's own number, which the answer carries back. A name is not enough to match on:
    /// a guest may reach the same name twice and the two are different streams.
    ticket: u32 = 0,
    /// What the guest has written so far, up to the end of the line.
    said: [wire.max_text]u8 = undefined,
    said_len: usize = 0,
    /// Set once the question has gone out, so it goes out once.
    told: bool = false,
    /// Where the line ended. Anything the guest wrote after it is for the far end and goes out as
    /// soon as there is one, rather than being dropped for arriving early.
    after: usize = 0,
};

const Stream = struct {
    /// The end of the pair this side kept. The other end went to whoever asked.
    ours: posix.socket_t = -1,
    handle: Vsock.Handle = undefined,
    /// Bytes read from one side that the other side would not take yet.
    to_guest: [4096]u8 = undefined,
    to_guest_len: usize = 0,
    to_caller: [4096]u8 = undefined,
    to_caller_len: usize = 0,
    /// Set when one side has gone, so the other side's last bytes still go out.
    ending: bool = false,

    fn free(self: *const Stream) bool {
        return self.ours < 0;
    }
};

/// Who holds the directories the guest may mount, when anybody does. A session carries the words and
/// knows nothing about files: what a name means to a filesystem is not a session's to decide.
pub const Sharing = struct {
    ctx: *anyopaque,
    /// Offer a directory under a name, or say it could not be. Called while the guest runs.
    offer: *const fn (ctx: *anyopaque, name: []const u8, at: []const u8, writable: bool) bool,
    /// Take one back, closing whatever the guest still holds open on it.
    withdraw: *const fn (ctx: *anyopaque, name: []const u8) void,
};

listener: posix.socket_t,
/// The path the listener is bound to, unlinked when this ends.
path: []const u8,
client: ?posix.socket_t = null,
/// Who holds the guest's directories, for a caller that changes them between pieces of work.
sharing: ?Sharing = null,
/// Set once the guest has opened its first stream, which is what it is up.
guest_up: bool = false,
told_up: bool = false,
/// Set when the far end asked for the guest to stop.
asked_stop: bool = false,
streams: [max_streams]Stream = @splat(.{}),
waiting: [max_waiting]Vsock.Handle = undefined,
waiting_len: usize = 0,
/// Streams asked for and not given, and streams the guest opened with no room to hold them.
/// A session that quietly loses one of these looks like a guest that stopped answering.
turned_away: u64 = 0,
overflowed: u64 = 0,
handed_out: u64 = 0,
/// Directories offered and taken back while the guest ran.
offered_shares: u64 = 0,
withdrawn_shares: u64 = 0,

/// Names the guest is reaching for, and the number of the next question.
reaching: [max_reaching]Reaching = @splat(.{}),
next_ticket: u32 = 1,
reached: u64 = 0,
turned_back: u64 = 0,
/// A message is read into this, and the name in it points here until the next one is read.
said: [wire.size]u8 = undefined,
asked_about: u64 = 0,
allowed: u64 = 0,
denied: u64 = 0,

pub const Error = error{
    /// The path is taken, or its directory is not writable.
    CannotListen,
};

/// Bind a socket for one session. The path is the session's name: whoever starts the guest chooses
/// it and hands it to whoever holds the other end.
pub fn listen(path: []const u8) Error!Server {
    const fd = socket.hold(path) catch return Error.CannotListen;
    return .{ .listener = fd, .path = path };
}

/// Move everything that can move without waiting: take the caller if there is one, answer what it
/// asked, take the streams the guest opened, and carry bytes both ways.
pub fn pump(self: *Server, vsock: *Vsock) void {
    self.take();
    self.collect(vsock);
    self.announce(vsock);
    self.answer(vsock);
    self.hearNames(vsock);
    self.carry(vsock);
}

/// Take the caller, if one is waiting and there is not one already. A session holds one: it names
/// one guest, and two callers sharing a guest could not tell whose stream was whose.
fn take(self: *Server) void {
    if (self.client != null) return;
    const fd = socket.take(self.listener) orelse return;
    self.client = fd;
    self.told_up = false;
}

/// Drop what the guest has closed: waiting streams, and names it gave up reaching for.
///
/// Without this a list comes to hold connections nobody can be handed, and the next one the guest
/// opens is closed instead of kept. A guest that gives up would cost the one after it its place, and
/// the limits would mean something other than what they say.
///
/// A question already asked is the one that needs this. Being told takes it out of the reading loop,
/// so nothing else is left to notice the guest has gone. The test is the connection being gone
/// rather than the guest saying it will write no more, because writing the line and then saying that
/// is a reasonable way to ask.
fn tidy(self: *Server, vsock: *Vsock) void {
    var index: usize = 0;
    while (index < self.waiting_len) {
        if (vsock.port(self.waiting[index]) == null) {
            self.forget(index);
            continue;
        }
        index += 1;
    }
    for (&self.reaching) |*each| {
        if (!each.used) continue;
        if (vsock.port(each.handle) == null) self.giveUp(vsock, each);
    }
}

/// Take the streams the guest opened. The first one means the guest is up.
///
/// A stream to the reaching port is the guest asking to be connected somewhere, and it is held here
/// rather than handed out. Every other stream is the guest's work and goes to whoever asks for one.
fn collect(self: *Server, vsock: *Vsock) void {
    self.tidy(vsock);
    while (vsock.accept()) |handle| {
        self.guest_up = true;
        if (vsock.port(handle) == wire.reaching_port) {
            const free = for (&self.reaching) |*each| {
                if (!each.used) break each;
            } else {
                self.overflowed += 1;
                vsock.close(handle);
                continue;
            };
            free.* = .{ .used = true, .handle = handle, .ticket = self.next_ticket };
            self.next_ticket +%= 1;
            continue;
        }
        if (self.waiting_len == self.waiting.len) {
            self.overflowed += 1;
            vsock.close(handle);
            continue;
        }
        self.waiting[self.waiting_len] = handle;
        self.waiting_len += 1;
    }
}

/// Read what a reaching guest wrote, and ask about it once there is a whole line. The line is a
/// name, a space, and a port: nothing else is read from that stream until it is answered.
fn hearNames(self: *Server, vsock: *Vsock) void {
    for (&self.reaching) |*each| {
        if (!each.used or each.told) continue;

        if (each.said_len < each.said.len) {
            each.said_len += vsock.read(each.handle, each.said[each.said_len..]);
        }
        const line = std.mem.indexOfScalar(u8, each.said[0..each.said_len], '\n') orelse {
            // No line, and none is coming: the guest filled the room kept for one, or said it will
            // send no more. A guest that has said everything and still has a line is answered below,
            // because writing the line and then saying no more is a reasonable thing to do.
            if (each.said_len == each.said.len or vsock.finished(each.handle)) self.giveUp(vsock, each);
            continue;
        };

        const asked_for = each.said[0..line];
        const split = std.mem.lastIndexOfScalar(u8, asked_for, ' ') orelse {
            self.giveUp(vsock, each);
            continue;
        };
        const port = std.fmt.parseInt(u16, asked_for[split + 1 ..], 10) catch {
            self.giveUp(vsock, each);
            continue;
        };
        const name = asked_for[0..split];
        if (name.len == 0) {
            self.giveUp(vsock, each);
            continue;
        }

        const client = self.client orelse continue;
        wire.send(client, .{
            .tag = .reaching,
            .port = port,
            .value = each.ticket,
            .text = name,
        }, null) catch {
            self.drop();
            continue;
        };
        each.told = true;
        each.after = line + 1;
        self.asked_about += 1;
    }
}

/// End a stream the guest was reaching on. The guest learns only that it did not work.
fn giveUp(self: *Server, vsock: *Vsock, each: *Reaching) void {
    vsock.close(each.handle);
    each.* = .{};
    self.turned_back += 1;
}

/// Take the answer about a name. Allowing carries a descriptor already connected where the name
/// led, and from here on the stream and that descriptor are one thing with bytes going both ways.
fn settleName(self: *Server, vsock: *Vsock, frame: wire.Frame, carried: ?posix.fd_t) void {
    const found = for (&self.reaching) |*each| {
        if (each.used and each.ticket == frame.value) break each;
    } else {
        // Nothing is waiting for this. The guest gave up, or the answer came twice.
        if (carried) |extra| socket.close(extra);
        return;
    };

    const connected = carried orelse {
        self.denied += 1;
        self.giveUp(vsock, found);
        return;
    };
    if (frame.reason != .allowed) {
        socket.close(connected);
        self.denied += 1;
        self.giveUp(vsock, found);
        return;
    }

    const slot = self.room() orelse {
        socket.close(connected);
        self.giveUp(vsock, found);
        return;
    };
    socket.dontWait(connected) catch {};
    slot.* = .{ .ours = connected, .handle = found.handle };
    // Whatever the guest wrote after its line was written before it could know the answer. It is
    // for the far end, so it goes out on the first turn rather than being lost.
    const early = found.said[found.after..found.said_len];
    if (early.len > 0) {
        @memcpy(slot.to_caller[0..early.len], early);
        slot.to_caller_len = early.len;
    }
    found.* = .{};
    self.allowed += 1;
    self.reached += 1;
}

fn announce(self: *Server, vsock: *Vsock) void {
    if (self.told_up or !self.guest_up) return;
    const client = self.client orelse return;
    wire.send(client, .{ .tag = .up, .value = @truncate(vsock.guest_cid) }, null) catch {
        self.drop();
        return;
    };
    self.told_up = true;
}

/// Say the guest has gone and how it went, so whoever holds the other end learns it from a message
/// rather than from a call that does nothing. A harness reports the reason to whoever asked for the
/// work, so the reason has to come from the runner: this end cannot see how a guest ended.
pub fn lost(self: *Server, why: wire.Reason) void {
    const client = self.client orelse return;
    wire.send(client, .{ .tag = .lost, .reason = why }, null) catch {};
}

fn answer(self: *Server, vsock: *Vsock) void {
    const client = self.client orelse return;
    var carried: ?posix.fd_t = null;
    while (true) {
        const frame = wire.receive(client, &self.said, &carried) catch {
            self.drop();
            return;
        } orelse return;

        // An answer about a name carries the descriptor to use. Everything else carries none, and
        // one left open would leak.
        if (frame.tag != .reached) {
            if (carried) |extra| socket.close(extra);
            carried = null;
        }

        switch (frame.tag) {
            .open => self.give(vsock, frame.value),
            .reached => self.settleName(vsock, frame, carried),
            .share => self.takeShare(frame),
            .unshare => self.dropShare(frame),
            .stop => {
                self.asked_stop = true;
                return;
            },
            else => {},
        }
    }
}

/// Hand out a stream on a port, or say why not.
fn give(self: *Server, vsock: *Vsock, port: u32) void {
    const client = self.client.?;
    if (!self.guest_up) {
        self.refuse(.guest_gone);
        return;
    }

    const found = self.claim(vsock, port) orelse {
        self.refuse(.nobody_waiting);
        return;
    };
    const slot = self.room() orelse {
        // The stream stays waiting: a caller that asks again after closing one gets it.
        self.keep(found);
        self.refuse(.too_many);
        return;
    };

    const pair = socket.pair() catch {
        self.keep(found);
        self.refuse(.no_room);
        return;
    };

    wire.send(client, .{ .tag = .opened, .value = port }, pair[1]) catch {
        socket.close(pair[0]);
        socket.close(pair[1]);
        self.keep(found);
        self.drop();
        return;
    };
    // The far end has its own now.
    socket.close(pair[1]);

    slot.* = .{ .ours = pair[0], .handle = found };
    self.handed_out += 1;
}

/// Offer a directory to the guest, and say what came of it.
fn takeShare(self: *Server, frame: wire.Frame) void {
    const client = self.client orelse return;
    const holder = self.sharing orelse {
        self.say(client, .{ .tag = .shared, .reason = .no_shares });
        return;
    };
    const said = wire.Sharing.of(frame.text) orelse {
        self.say(client, .{ .tag = .shared, .reason = .bad_name });
        return;
    };
    const writable = frame.reason == .writable;
    if (!holder.offer(holder.ctx, said.name, said.at, writable)) {
        self.say(client, .{ .tag = .shared, .reason = .bad_name });
        return;
    }
    self.offered_shares += 1;
    self.say(client, .{ .tag = .shared, .reason = if (writable) .writable else .read_only });
}

/// Take one back. Nothing can fail here: a name nobody offered is already not offered.
fn dropShare(self: *Server, frame: wire.Frame) void {
    const client = self.client orelse return;
    if (self.sharing) |holder| {
        if (frame.text.len > 0) holder.withdraw(holder.ctx, frame.text);
        self.withdrawn_shares += 1;
    }
    self.say(client, .{ .tag = .shared, .reason = .none });
}

/// Say one thing, and let go of the caller if it has gone.
fn say(self: *Server, client: posix.socket_t, frame: wire.Frame) void {
    wire.send(client, frame, null) catch self.drop();
}

fn refuse(self: *Server, why: wire.Reason) void {
    const client = self.client orelse return;
    self.turned_away += 1;
    wire.send(client, .{ .tag = .refused, .reason = why }, null) catch self.drop();
}

/// Take a waiting stream on a port out of the list. Port zero means any, so a caller that does
/// not care takes whatever the guest opened.
fn claim(self: *Server, vsock: *Vsock, port: u32) ?Vsock.Handle {
    var index: usize = 0;
    while (index < self.waiting_len) {
        const handle = self.waiting[index];
        const on = vsock.port(handle) orelse {
            // The guest closed it while it waited. Forgetting moves the last one into this place,
            // so this place is looked at again rather than stepped over.
            self.forget(index);
            continue;
        };
        if (port != 0 and on != port) {
            index += 1;
            continue;
        }
        self.forget(index);
        return handle;
    }
    return null;
}

fn forget(self: *Server, index: usize) void {
    self.waiting[index] = self.waiting[self.waiting_len - 1];
    self.waiting_len -= 1;
}

fn keep(self: *Server, handle: Vsock.Handle) void {
    if (self.waiting_len == self.waiting.len) {
        self.overflowed += 1;
        return;
    }
    self.waiting[self.waiting_len] = handle;
    self.waiting_len += 1;
}

fn room(self: *Server) ?*Stream {
    for (&self.streams) |*each| if (each.free()) return each;
    return null;
}

/// Carry bytes between the descriptors this end holds and the guest's streams.
fn carry(self: *Server, vsock: *Vsock) void {
    for (&self.streams) |*stream| {
        if (stream.free()) continue;

        // Whatever the caller wrote, on towards the guest.
        if (stream.to_guest_len < stream.to_guest.len) {
            const got = socket.read(stream.ours, stream.to_guest[stream.to_guest_len..]) catch some: {
                stream.ending = true;
                break :some 0;
            };
            stream.to_guest_len += got;
        }
        if (stream.to_guest_len > 0) {
            const took = vsock.write(stream.handle, stream.to_guest[0..stream.to_guest_len]);
            if (took > 0) {
                std.mem.copyForwards(
                    u8,
                    stream.to_guest[0..],
                    stream.to_guest[took..stream.to_guest_len],
                );
                stream.to_guest_len -= took;
            }
        }

        // Whatever the guest wrote, on towards the caller.
        if (stream.to_caller_len < stream.to_caller.len) {
            const got = vsock.read(stream.handle, stream.to_caller[stream.to_caller_len..]);
            stream.to_caller_len += got;
        }
        if (stream.to_caller_len > 0) {
            const wrote = socket.write(stream.ours, stream.to_caller[0..stream.to_caller_len]) catch {
                self.end(vsock, stream);
                continue;
            };
            if (wrote > 0) {
                std.mem.copyForwards(
                    u8,
                    stream.to_caller[0..],
                    stream.to_caller[wrote..stream.to_caller_len],
                );
                stream.to_caller_len -= wrote;
            }
        }

        // A side that has gone ends the stream once the last bytes are through.
        const empty = stream.to_guest_len == 0 and stream.to_caller_len == 0;
        if (empty and (stream.ending or vsock.finished(stream.handle))) self.end(vsock, stream);
    }
}

fn end(self: *Server, vsock: *Vsock, stream: *Stream) void {
    _ = self;
    if (stream.free()) return;
    vsock.close(stream.handle);
    socket.close(stream.ours);
    stream.* = .{};
}

fn drop(self: *Server) void {
    const client = self.client orelse return;
    socket.close(client);
    self.client = null;
    self.told_up = false;
}

pub fn close(self: *Server, vsock: *Vsock) void {
    for (&self.streams) |*stream| self.end(vsock, stream);
    self.drop();
    socket.close(self.listener);
    socket.forget(self.path);
}

/// A transport the guest never touched, so it opens no streams and holds no connections. Enough to
/// drive everything that is not the guest itself. Built in place, because this one holds pointers
/// into itself and a copy leaves them aimed at the copy that has gone.
fn untouched(vsock: *Vsock, ports: []const u32) void {
    vsock.init(3, ports);
}

fn temporary(what: []const u8, into: []u8) []const u8 {
    return std.fmt.bufPrint(into, "/tmp/mirage-session-test-{d}-{s}", .{ std.os.linux.getpid(), what }) catch unreachable;
}

test "a stream asked for before the guest opened one is refused rather than waited for" {
    var name: [96]u8 = undefined;
    const path = temporary("nostream", &name);

    var vsock: Vsock = undefined;
    const ports = [1]u32{1024};
    untouched(&vsock, &ports);
    var held = try Server.listen(path);
    defer held.close(&vsock);

    const mine = try socket.reach(path);
    defer socket.close(mine);

    // The guest has opened nothing, so there is nothing to hand over and nothing to say it is up.
    held.pump(&vsock);
    try wire.send(mine, .{ .tag = .open, .value = 1024 }, null);
    held.pump(&vsock);

    var carried: ?std.posix.fd_t = null;
    var came: [wire.size]u8 = undefined;
    const said = (try wire.receive(mine, &came, &carried)).?;
    try std.testing.expectEqual(wire.Tag.refused, said.tag);
    try std.testing.expectEqual(wire.Reason.guest_gone, said.reason);
    try std.testing.expectEqual(@as(?std.posix.fd_t, null), carried);
}

test "a session that ends takes its path with it" {
    var name: [96]u8 = undefined;
    const path = temporary("gone", &name);

    var vsock: Vsock = undefined;
    const ports = [1]u32{1024};
    untouched(&vsock, &ports);
    var held = try Server.listen(path);
    held.close(&vsock);

    // Nothing is listening there any more, so nothing can join a session that has ended.
    try std.testing.expectError(socket.Error.Refused, socket.reach(path));
}

test "a stream the guest closed while it waited is forgotten, whichever place it held" {
    var name: [96]u8 = undefined;
    const path = temporary("deadwait", &name);

    var vsock: Vsock = undefined;
    const ports = [1]u32{1024};
    untouched(&vsock, &ports);
    var held = try Server.listen(path);
    defer held.close(&vsock);

    const mine = try socket.reach(path);
    defer socket.close(mine);
    held.pump(&vsock);

    // A handle the transport knows nothing about is a stream the guest opened and closed. The first
    // place in the list is the one worth testing: walking off the front of it is how a loop over a
    // shrinking list goes wrong.
    held.guest_up = true;
    held.waiting[0] = .{ .index = 0, .generation = 7 };
    held.waiting_len = 1;

    try wire.send(mine, .{ .tag = .open, .value = 1024 }, null);
    held.pump(&vsock);

    var carried: ?std.posix.fd_t = null;
    var came: [wire.size]u8 = undefined;
    var refused = false;
    var tries: usize = 0;
    while (!refused and tries < 4) : (tries += 1) {
        const said = (try wire.receive(mine, &came, &carried)) orelse continue;
        if (said.tag == .refused) refused = true;
    }
    try std.testing.expect(refused);
    try std.testing.expectEqual(@as(usize, 0), held.waiting_len);
}

test "a waiting stream the guest closed does not cost the next one its place" {
    var name: [96]u8 = undefined;
    const path = temporary("tidywait", &name);

    var vsock: Vsock = undefined;
    const ports = [1]u32{1024};
    untouched(&vsock, &ports);
    var held = try Server.listen(path);
    defer held.close(&vsock);

    // Every place taken by a stream the guest has closed. The transport knows none of these, which
    // is what a handle for a connection that ended looks like.
    for (0..max_waiting) |each| held.waiting[each] = .{ .index = @intCast(each), .generation = 9 };
    held.waiting_len = max_waiting;

    held.tidy(&vsock);
    try std.testing.expectEqual(@as(usize, 0), held.waiting_len);
}

test "a name the guest gave up reaching for stops holding its place" {
    var name: [96]u8 = undefined;
    const path = temporary("tidyreach", &name);

    var vsock: Vsock = undefined;
    const ports = [1]u32{1024};
    untouched(&vsock, &ports);
    var held = try Server.listen(path);
    defer held.close(&vsock);

    // Every place taken by a question already asked. Being told is what took these out of the
    // reading loop, so nothing was left to notice that the guest had gone.
    for (&held.reaching, 0..) |*each, index| {
        each.* = .{ .used = true, .told = true, .handle = .{ .index = @intCast(index), .generation = 5 } };
    }

    held.tidy(&vsock);
    for (&held.reaching) |*each| try std.testing.expect(!each.used);
}
