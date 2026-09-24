//! Directories on this machine, offered to a guest under one mount.
//!
//! A guest mounts this once and sees a directory holding one name per thing offered. That shape is
//! what lets the set change while the guest runs: the transport cannot add a device to a running
//! machine, so a share added for one piece of work and taken away after it has to be a name in a
//! directory rather than a device of its own. Whoever holds the guest adds and withdraws them, and a
//! guest puts them where it wants them with mounts of its own.
//!
//! This is what a guest mounts. It answers the kernel's filesystem messages from real files here,
//! and it answers every request that would change something with a refusal, so a guest cannot write
//! through it however it asks.
//!
//! What a guest may reach is bounded by name rather than by trust. A name with a separator in it, or
//! one that walks upwards, is refused before anything is opened: the kernel never sends those, so a
//! guest that does is a guest trying to leave, and the answer is that there is no such name. What
//! symlinks point at is the kernel's to resolve inside its own mount, not this end's to follow.
//!
//! Files are reached through `std.Io` rather than through this system's own calls, because the calls
//! differ and the answers do not: one system has `fstatat` and another has `statx`, and a filesystem
//! should not know which. What that costs is that a read waits for the disk on the thread that asked,
//! which is the thread the guest runs on, and a store is on local disk.

const std = @import("std");
const wire = @import("wire.zig");

const Export = @This();

/// How many files and directories a guest may have open at once.
pub const max_handles = 64;

/// How large the guest is told its filesystem is, in blocks of the size the protocol reports. A
/// terabyte: large enough that nothing refuses to start, and not so large that a program computing
/// with it overflows.
const room_blocks = (1 << 40) / wire.Statfs.block_size;

/// How many things may be offered at once.
/// The name the guest mounts. One name for the whole filesystem, because what a caller names are the
/// directories inside it.
pub const tag = "mirage";

/// How many things may be offered at once.
pub const max_offers = 32;

/// One directory on this machine, under the name the guest sees it by.
const Offer = struct {
    used: bool = false,
    /// The name in the mounted directory. Owned here.
    name: []u8 = &.{},
    /// Where it really is, as a whole path on this machine. Owned here.
    at: []u8 = &.{},
    /// Whether the guest may change what is in it.
    writable: bool = false,
    /// Changes every time this slot is used for something else. A node the guest still holds from an
    /// offer that was taken back would otherwise resolve into whatever took the slot, which is the one
    /// way a guest could reach a directory nobody offered it.
    generation: u32 = 0,
};

/// One file or directory the guest has been told about, by the path it is at. A path rather than a
/// descriptor because a store holds hundreds of thousands of them and a descriptor for each is a
/// limit this would run into; opening happens per request instead.
const Node = struct {
    /// Which offer it is under, and which use of that slot. The root of the mount belongs to none.
    offer: u32 = 0,
    generation: u32 = 0,
    /// Which use of this slot in the table. A guest held up for a session makes and forgets files for
    /// hours, so slots are used again; the number the guest holds says which use it belongs to, and a
    /// number from an earlier one resolves to nothing rather than to whatever file took the slot.
    own: u32 = 0,
    /// Where it is, under that offer. Empty for the offer's own directory.
    path: []u8,
    /// How many times the kernel has been told about it and not yet forgotten it. At zero the node
    /// may go, which is what keeps the table from growing with every name ever read.
    lookups: u64 = 0,
};

const Handle = struct {
    open: ?std.Io.File = null,
    /// Which offer it is under, so taking that back closes this.
    under: u32 = 0,
    /// Set for a directory, which is read by name rather than by offset.
    directory: bool = false,
    /// Where a directory read has got to, and the walk that got there. A store holds tens of
    /// thousands of names in one directory and the kernel takes them a few at a time, so starting
    /// again for every read would cost the square of that. The walk is kept and carried on.
    walking: ?std.Io.Dir = null,
    walker: ?std.Io.Dir.Iterator = null,
    /// Which name the guest has been handed as far as. The kernel asks for what comes after this.
    at: u64 = 0,
    /// A name taken from the walk that did not fit in the last answer. It is held rather than
    /// dropped, because the walk cannot go back: dropping it would lose a name, and reading the
    /// directory again from the start to find it is what makes a walk cost the square of its size.
    waiting: [256]u8 = undefined,
    waiting_len: usize = 0,
};

gpa: std.mem.Allocator,
io: std.Io,
offers: [max_offers]Offer = @splat(.{}),
nodes: std.ArrayList(Node),
/// Which node a path is, so finding one costs the same whether the export holds ten names or a
/// hundred thousand. A store is the second, and walking one with a search per name costs the square
/// of it: measured at fifty seconds for seventy thousand names before this was a map.
known: std.StringHashMapUnmanaged(u64) = .empty,
/// Slots nobody holds any more, ready to be used again.
free_nodes: std.ArrayList(u32) = .empty,
handles: [max_handles]Handle = @splat(.{}),

/// What the guest asked for and what it was told. A guest whose reads quietly fail looks the same as
/// a guest with an empty filesystem, so the refusals are counted.
looked_up: u64 = 0,
/// Names handed over in a directory read. A guest that reads a directory needs no lookup for what is
/// in it, because the answer carries what a lookup would have said.
named: u64 = 0,
read_bytes: u64 = 0,
refused: u64 = 0,
turned_away: u64 = 0,
/// Files and directories the guest holds open, and has let go of.
held: u64 = 0,
let_go: u64 = 0,
/// Files the guest has finished with, whose slots went back.
let_go_nodes: u64 = 0,
/// Directories offered and taken back.
offered: u64 = 0,
withdrawn: u64 = 0,
/// What the guest changed, where it was allowed to.
written_bytes: u64 = 0,
made: u64 = 0,
taken_away: u64 = 0,
moved: u64 = 0,

/// The number the guest holds for a file: which slot in the table, and which use of that slot. A guest
/// that keeps one past the file being forgotten gets nothing back rather than somebody else's file.
fn nodeIdOf(index: usize, own: u32) u64 {
    return (@as(u64, own) << 32) | @as(u32, @intCast(index));
}

/// The node a number names, or nothing: a slot nobody holds any more, or a number from an earlier use
/// of the slot.
fn nodeAt(self: *Export, nodeid: u64) ?*Node {
    const index: u32 = @truncate(nodeid);
    const own: u32 = @truncate(nodeid >> 32);
    if (index == 0 or index >= self.nodes.items.len) return null;
    const node = &self.nodes.items[index];
    if (node.lookups == 0 or node.own != own) return null;
    return node;
}

pub const Error = error{
    OutOfMemory,
    /// A name nothing can be offered under: one with a separator in it, or one that walks upwards.
    BadName,
    /// A directory named by anything other than its whole path. What a guest is offered is opened
    /// from wherever this process happens to be, so a relative path would mean somewhere else.
    BadPath,
    /// As many things are offered as this can hold.
    NoRoom,
};

pub fn init(gpa: std.mem.Allocator, io: std.Io) Error!Export {
    var nodes: std.ArrayList(Node) = .empty;
    // Nothing is ever at node zero, and node one is the directory the guest mounts. That one is not
    // anywhere on this machine: it holds a name for each thing offered and nothing else.
    try nodes.append(gpa, .{ .path = &.{}, .lookups = 1 });
    try nodes.append(gpa, .{ .path = try gpa.dupe(u8, ""), .lookups = 1 });
    return .{ .gpa = gpa, .io = io, .nodes = nodes };
}

/// Offer a directory under a name. The guest sees the name in the directory it mounted, and what is
/// under it is what is really there.
///
/// Offering the same name again replaces what it points at, because a name is how whoever holds the
/// guest refers to one, and two things under one name would be a name that means either.
pub fn offer(self: *Export, name: []const u8, at: []const u8, writable: bool) Error!void {
    if (!nameIsSafe(name)) return Error.BadName;
    if (at.len == 0 or at[0] != '/') return Error.BadPath;
    if (self.findOffer(name)) |which| {
        const one = &self.offers[which];
        const moved = try self.gpa.dupe(u8, at);
        self.gpa.free(one.at);
        one.at = moved;
        one.writable = writable;
        return;
    }
    const free = for (&self.offers, 0..) |*each, index| {
        if (!each.used) break .{ each, index };
    } else return Error.NoRoom;
    _ = free[1];

    const named = try self.gpa.dupe(u8, name);
    const where = self.gpa.dupe(u8, at) catch |err| {
        self.gpa.free(named);
        return err;
    };
    free[0].* = .{
        .used = true,
        .name = named,
        .at = where,
        .writable = writable,
        .generation = free[0].generation +% 1,
    };
    self.offered += 1;
}

/// Take one back. Anything the guest still holds open on it stops working: a share taken away has to
/// be gone, not gone for the next program to look.
pub fn withdraw(self: *Export, name: []const u8) void {
    const which = self.findOffer(name) orelse return;
    for (&self.handles, 0..) |*each, index| {
        _ = index;
        if (each.under != which) continue;
        if (each.open) |file| file.close(self.io);
        if (each.walking) |one| one.close(self.io);
        each.* = .{};
    }
    // The nodes under it stop resolving, because their offer is not used any more.
    const one = &self.offers[which];
    self.gpa.free(one.name);
    self.gpa.free(one.at);
    // The generation stays with the slot rather than being reset, so a node from this offer resolves
    // to nothing even after the slot is used again.
    one.* = .{ .generation = one.generation };
    self.withdrawn += 1;
}

fn findOffer(self: *Export, name: []const u8) ?u32 {
    for (&self.offers, 0..) |*each, index| {
        if (each.used and std.mem.eql(u8, each.name, name)) return @intCast(index);
    }
    return null;
}

pub fn deinit(self: *Export) void {
    for (&self.offers) |*each| {
        if (!each.used) continue;
        self.gpa.free(each.name);
        self.gpa.free(each.at);
        each.* = .{};
    }
    for (self.nodes.items[1..]) |each| self.gpa.free(each.path);
    self.nodes.deinit(self.gpa);
    self.free_nodes.deinit(self.gpa);
    var keys = self.known.keyIterator();
    while (keys.next()) |key| self.gpa.free(key.*);
    self.known.deinit(self.gpa);
    for (&self.handles) |*each| {
        if (each.open) |file| file.close(self.io);
        each.* = .{};
    }
}

/// Answer one message. Returns how much of `into` the answer fills, which is never zero: a message
/// with nothing to say still carries a header, and a kernel waiting for one that never comes is a
/// guest that stops.
pub fn answer(self: *Export, request: []const u8, into: []u8) usize {
    const head = wire.Header.parse(request) orelse {
        self.refused += 1;
        // Nothing can be answered: without a header there is no number to answer to.
        return 0;
    };
    const body = head.body(request);
    const room = into[wire.Answer.size..];

    return switch (head.op) {
        .init => blk: {
            const asked = wire.Init.parse(body) orelse break :blk self.refuse(into, head, wire.err.invalid);
            if (asked.major != wire.major) break :blk self.refuse(into, head, wire.err.nosys);
            break :blk wire.Answer.write(into, head.unique, 0, wire.Init.writeOut(room, asked));
        },
        .lookup => self.lookup(into, head, body),
        .getattr => self.getattr(into, head),
        .readlink => self.readlink(into, head),
        .open, .opendir => self.open(into, head, body, head.op == .opendir),
        .read => self.read(into, head, body),
        .readdir, .readdirplus => self.readdir(into, head, body),
        .release, .releasedir => self.release(into, head, body),
        .forget => blk: {
            if (wire.Forget.parse(body)) |count| self.forget(head.nodeid, count);
            // A forget is told, not asked: the kernel wants no answer at all.
            break :blk 0;
        },
        .batch_forget => blk: {
            self.batchForget(body);
            break :blk 0;
        },
        .statfs => self.statfs(into, head),
        // Nothing here answers these, and saying so is better than a guest waiting: the kernel asks
        // once, remembers the answer, and stops asking.
        .flush, .access, .syncfs => wire.Answer.write(into, head.unique, 0, 0),
        .getxattr, .listxattr => self.refuse(into, head, wire.err.nosys),
        // Everything that would change something. Allowed under a share whose whole point is that a
        // guest writes to it, and refused the way a read only mount refuses anywhere else.
        .write => self.write(into, head, body),
        .create => self.create(into, head, body),
        .setattr => self.setattr(into, head, body),
        .mkdir => self.makeDirectory(into, head, body),
        .unlink => self.remove(into, head, body, false),
        .rmdir => self.remove(into, head, body, true),
        .rename, .rename2 => self.rename(into, head, body, head.op == .rename2),
        .symlink => self.makeLink(into, head, body),
        .link => self.makeHardLink(into, head, body),
        // Nothing here holds anything back, so there is nothing to push out. Saying so is better
        // than refusing: a program that asks and is refused takes it for a failure to save.
        .fsync, .fsyncdir => wire.Answer.write(into, head.unique, 0, 0),
        .destroy => wire.Answer.write(into, head.unique, 0, 0),
        else => self.refuse(into, head, wire.err.nosys),
    };
}

/// How much room the guest is told there is.
///
/// Not the host's real numbers, and this says so rather than pretending: there is no portable call for
/// them, and the two this would need are a struct per system that nobody would notice was wrong.
/// What is answered instead is a large filesystem, because the alternative is answering zero and a
/// program told there is no room refuses to start.
///
/// What this cannot do is make a full disk look full before it is written to. That is not lost: a
/// write with nowhere to go fails with the error the host gave, which is the same answer a program
/// gets on a real filesystem that filled up while it was working.
fn statfs(self: *Export, into: []u8, head: wire.Header) usize {
    const room = into[wire.Answer.size..];
    // Whichever share the question was about, or the first one offered when it was about the mount
    // itself, which is not anywhere on this machine and has no room of its own.
    var path_room: [4096]u8 = undefined;
    var about: ?[]const u8 = self.pathOf(head.nodeid, null, &path_room);
    if (about == null) {
        for (&self.offers) |*each| {
            if (each.used) {
                about = each.at;
                break;
            }
        }
    }
    const where = about orelse return wire.Answer.write(into, head.unique, 0, wire.Statfs.writeOut(room, 0, 0, 0));

    _ = where;
    return wire.Answer.write(into, head.unique, 0, wire.Statfs.writeOut(
        room,
        room_blocks,
        room_blocks / 2,
        // Files known about, which is a real number, and the same again as room for more.
        self.nodes.items.len * 2,
    ));
}

fn refuse(self: *Export, into: []u8, head: wire.Header, code: i32) usize {
    self.refused += 1;
    return wire.Answer.write(into, head.unique, -code, 0);
}

/// Whether a name is one the kernel would really have sent. Anything else is a guest trying to leave
/// the directory it was given, and there is no such name.
fn nameIsSafe(name: []const u8) bool {
    if (name.len == 0 or name.len > 255) return false;
    if (std.mem.indexOfScalar(u8, name, '/') != null) return false;
    if (std.mem.indexOfScalar(u8, name, 0) != null) return false;
    if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return false;
    return true;
}

/// Where a node really is on this machine, into a buffer the caller owns.
///
/// Null for the directory the guest mounted, which is nowhere on this machine, and for a node whose
/// offer has been taken back: a name that was withdrawn resolves to nothing rather than to whatever
/// took its place in the table.
fn pathOf(self: *Export, nodeid: u64, extra: ?[]const u8, into: []u8) ?[]const u8 {
    if (nodeid == 1) return null;
    const node = (self.nodeAt(nodeid) orelse return null).*;
    if (node.offer >= self.offers.len) return null;
    const offered = self.offers[node.offer];
    if (!offered.used or offered.generation != node.generation) return null;

    var at: usize = 0;
    if (offered.at.len + 2 > into.len) return null;
    @memcpy(into[0..offered.at.len], offered.at);
    at = offered.at.len;
    if (node.path.len > 0) {
        if (at + 1 + node.path.len >= into.len) return null;
        into[at] = '/';
        at += 1;
        @memcpy(into[at..][0..node.path.len], node.path);
        at += node.path.len;
    }
    if (extra) |name| {
        if (at + 1 + name.len >= into.len) return null;
        into[at] = '/';
        at += 1;
        @memcpy(into[at..][0..name.len], name);
        at += name.len;
    }
    return into[0..at];
}

/// Whether the guest may change what is under a node.
fn mayWrite(self: *Export, nodeid: u64) bool {
    if (nodeid == 1) return false;
    const node = (self.nodeAt(nodeid) orelse return false).*;
    if (node.offer >= self.offers.len) return false;
    const offered = self.offers[node.offer];
    return offered.used and offered.generation == node.generation and offered.writable;
}

/// What the directory the guest mounted looks like: a directory holding one name per offer, owned by
/// nobody and changeable by nobody.
fn rootAttr(self: *Export) wire.Attr {
    _ = self;
    return .{ .ino = 1, .mode = 0o040555, .links = 2, .blksize = 4096 };
}

/// What a node is called under its offer, with a name added.
fn joinUnder(self: *Export, nodeid: u64, name: []const u8) Error![]u8 {
    const node = (self.nodeAt(nodeid) orelse return Error.BadName).*;
    if (node.path.len == 0) return self.gpa.dupe(u8, name);
    const room = try self.gpa.alloc(u8, node.path.len + 1 + name.len);
    @memcpy(room[0..node.path.len], node.path);
    room[node.path.len] = '/';
    @memcpy(room[node.path.len + 1 ..], name);
    return room;
}

/// What this machine says about a path, turned into what the kernel wants to hear.
///
/// A symlink is never followed here. What it points at is the kernel's to resolve inside its own
/// mount, and following it on this side is how a guest would be handed something outside the export.
fn attrOf(self: *Export, path: []const u8) ?wire.Attr {
    const about = std.Io.Dir.cwd().statFile(self.io, path, .{ .follow_symlinks = false }) catch return null;

    // The type bits, which the kernel reads to know what it is looking at.
    const kind: u32 = switch (about.kind) {
        .directory => 0o040000,
        .sym_link => 0o120000,
        .file => 0o100000,
        .character_device => 0o020000,
        .block_device => 0o060000,
        .named_pipe => 0o010000,
        .unix_domain_socket => 0o140000,
        else => 0o100000,
    };
    // Everything is read only whatever this machine says: the write bits come off rather than being
    // trusted, so a file writable here is not writable there.
    const allowed: u32 = @intCast(about.permissions.toMode() & 0o777 & ~@as(u32, 0o222));

    return .{
        .ino = @intCast(about.inode),
        .bytes = about.size,
        .blocks = (about.size + 511) / 512,
        .seconds = @intCast(@divTrunc(about.mtime.nanoseconds, std.time.ns_per_s)),
        .mode = kind | allowed,
        .links = @intCast(about.nlink),
    };
}

/// Find a node by the path it is at, or make one. The kernel counts how many times it has been told
/// about a name and says when it has finished with it, which is what `forget` answers.
fn nodeFor(self: *Export, offer_index: u32, path: []u8) Error!u64 {
    // Keyed by the offer and which use of it, as well as by the path: two offers may both hold a
    // name, and a slot used again is not the same directory.
    const generation = self.offers[offer_index].generation;
    var key_room: [4200]u8 = undefined;
    const key = std.fmt.bufPrint(&key_room, "{d}/{d}/{s}", .{ offer_index, generation, path }) catch {
        self.gpa.free(path);
        return Error.OutOfMemory;
    };
    if (self.known.get(key)) |which| {
        if (self.nodeAt(which)) |node| {
            node.lookups += 1;
            self.gpa.free(path);
            return which;
        }
        // The slot was let go and used again, so what the map remembers is not this file any more.
        _ = self.known.remove(key);
    }

    const held_key = self.gpa.dupe(u8, key) catch {
        self.gpa.free(path);
        return Error.OutOfMemory;
    };

    // A slot nobody holds any more, if there is one. Every use of it has its own number, so a guest
    // holding the old one is told there is nothing there.
    if (self.free_nodes.pop()) |index| {
        const node = &self.nodes.items[index];
        node.* = .{
            .offer = offer_index,
            .generation = generation,
            .own = node.own +% 1,
            .path = path,
            .lookups = 1,
        };
        self.known.put(self.gpa, held_key, nodeIdOf(index, node.own)) catch {
            self.gpa.free(held_key);
            return Error.OutOfMemory;
        };
        return nodeIdOf(index, node.own);
    }
    try self.nodes.append(self.gpa, .{
        .offer = offer_index,
        .generation = generation,
        .path = path,
        .lookups = 1,
    });
    const which = nodeIdOf(self.nodes.items.len - 1, 0);
    self.known.put(self.gpa, held_key, which) catch {
        self.gpa.free(held_key);
        // Without the map this node could not be found again, and a second name would make a second
        // node for the same file. Better to have no node at all than two.
        _ = self.nodes.pop();
        return Error.OutOfMemory;
    };
    return which;
}

/// The kernel saying it has finished with a name. The node stays: its number may still be in a
/// directory read the guest has not looked at yet, and a number handed out twice for two different
/// files is the one mistake a filesystem must not make.
fn forget(self: *Export, nodeid: u64, count: u64) void {
    if (nodeid == 1) return;
    const node = self.nodeAt(nodeid) orelse return;
    if (count < node.lookups) {
        node.lookups -= count;
        return;
    }

    // Nobody holds it any more. What it held goes back, and so does its slot: a guest that works for
    // hours makes and forgets files for hours, and a table that only grows is a machine that fills.
    var key_room: [4200]u8 = undefined;
    if (std.fmt.bufPrint(&key_room, "{d}/{d}/{s}", .{ node.offer, node.generation, node.path })) |key| {
        if (self.known.fetchRemove(key)) |gone| self.gpa.free(gone.key);
    } else |_| {}
    self.gpa.free(node.path);
    node.path = &.{};
    node.lookups = 0;
    const index: u32 = @truncate(nodeid);
    self.free_nodes.append(self.gpa, index) catch {
        // No room to remember the slot, so it is simply not used again. Nothing is wrong beyond this
        // table staying larger than it needs to be.
    };
    self.let_go_nodes += 1;
}

fn batchForget(self: *Export, body: []const u8) void {
    if (body.len < 8) return;
    const count = std.mem.readInt(u32, body[0..4], .little);
    var at: usize = 8;
    var left = count;
    while (left > 0 and at + 16 <= body.len) : (left -= 1) {
        const nodeid = std.mem.readInt(u64, body[at..][0..8], .little);
        const times = std.mem.readInt(u64, body[at + 8 ..][0..8], .little);
        self.forget(nodeid, times);
        at += 16;
    }
}

fn lookup(self: *Export, into: []u8, head: wire.Header, body: []const u8) usize {
    const name = std.mem.sliceTo(body, 0);
    if (!nameIsSafe(name)) {
        self.turned_away += 1;
        return self.refuse(into, head, wire.err.noent);
    }

    // In the directory the guest mounted, a name is one of the things offered. Nothing is cached about
    // these, because the set changes while the guest runs and a name the kernel remembered would be a
    // share that outlived being taken back.
    if (head.nodeid == 1) {
        const which = self.findOffer(name) orelse return self.refuse(into, head, wire.err.noent);
        var room: [4096]u8 = undefined;
        const empty = self.gpa.dupe(u8, "") catch return self.refuse(into, head, wire.err.nomem);
        const nodeid = self.nodeFor(which, empty) catch {
            self.gpa.free(empty);
            return self.refuse(into, head, wire.err.nomem);
        };
        const path = self.pathOf(nodeid, null, &room) orelse
            return self.refuse(into, head, wire.err.noent);
        const attr = self.attrOf(path) orelse return self.refuse(into, head, wire.err.noent);
        self.looked_up += 1;
        return wire.Answer.write(into, head.unique, 0, wire.Entry.writeBriefly(
            into[wire.Answer.size..],
            nodeid,
            attr,
        ));
    }

    var room: [4096]u8 = undefined;
    const path = self.pathOf(head.nodeid, name, &room) orelse
        return self.refuse(into, head, wire.err.noent);
    const attr = self.attrOf(path) orelse return self.refuse(into, head, wire.err.noent);

    const node = (self.nodeAt(head.nodeid) orelse return self.refuse(into, head, wire.err.noent)).*;
    const under = self.joinUnder(head.nodeid, name) catch
        return self.refuse(into, head, wire.err.nomem);
    const nodeid = self.nodeFor(node.offer, under) catch {
        self.gpa.free(under);
        return self.refuse(into, head, wire.err.nomem);
    };

    self.looked_up += 1;
    return wire.Answer.write(into, head.unique, 0, wire.Entry.write(into[wire.Answer.size..], nodeid, attr));
}

fn getattr(self: *Export, into: []u8, head: wire.Header) usize {
    if (head.nodeid == 1) {
        return wire.Answer.write(into, head.unique, 0, wire.AttrAnswer.write(into[wire.Answer.size..], self.rootAttr()));
    }
    var room: [4096]u8 = undefined;
    const path = self.pathOf(head.nodeid, null, &room) orelse
        return self.refuse(into, head, wire.err.noent);
    const attr = self.attrOf(path) orelse return self.refuse(into, head, wire.err.noent);
    return wire.Answer.write(into, head.unique, 0, wire.AttrAnswer.write(into[wire.Answer.size..], attr));
}

fn readlink(self: *Export, into: []u8, head: wire.Header) usize {
    var room: [4096]u8 = undefined;
    const path = self.pathOf(head.nodeid, null, &room) orelse
        return self.refuse(into, head, wire.err.noent);

    const answer_room = into[wire.Answer.size..];
    const got = std.Io.Dir.cwd().readLink(self.io, path, answer_room) catch
        return self.refuse(into, head, wire.err.invalid);
    return wire.Answer.write(into, head.unique, 0, got);
}

fn open(self: *Export, into: []u8, head: wire.Header, body: []const u8, directory: bool) usize {
    // The directory the guest mounted is opened without opening anything here: what is in it is the
    // list of offers, which a read below answers from.
    if (head.nodeid == 1) {
        if (!directory) return self.refuse(into, head, wire.err.isdir);
        const slot = for (&self.handles, 0..) |*each, index| {
            if (each.open == null and !each.directory) break .{ each, index };
        } else return self.refuse(into, head, wire.err.nfile);
        slot[0].* = .{ .directory = true };
        self.held += 1;
        return wire.Answer.write(into, head.unique, 0, wire.Open.writeOut(into[wire.Answer.size..], slot[1] + 1));
    }

    // Asking to open for writing is refused here rather than later. The guest's own kernel would
    // allow it, because the guest is root inside itself and root is not stopped by permissions, and
    // the refusal would arrive on the first write instead. Saying so at the open is the same answer
    // a read only mount gives, and a program that checks whether it may write gets a true answer.
    var writing = false;
    if (!directory and body.len >= 4) {
        const wanted = std.mem.readInt(u32, body[0..4], .little);
        writing = wanted & 0o3 != 0;
        if (writing and !self.mayWrite(head.nodeid)) return self.refuse(into, head, wire.err.rofs);
    }

    var room: [4096]u8 = undefined;
    const path = self.pathOf(head.nodeid, null, &room) orelse
        return self.refuse(into, head, wire.err.noent);

    const slot = for (&self.handles, 0..) |*each, index| {
        if (each.open == null) break .{ each, index };
    } else return self.refuse(into, head, wire.err.nfile);

    // A directory is read by name when the read arrives, so nothing is opened for one here beyond
    // saying that it is one. A file is opened read only and stays open until the guest lets go.
    if (directory) {
        const opened = std.Io.Dir.openDirAbsolute(self.io, path, .{ .iterate = true }) catch
            return self.refuse(into, head, wire.err.access);
        slot[0].* = .{ .open = null, .directory = true, .walking = opened };
        slot[0].walker = opened.iterate();
        self.held += 1;
        return wire.Answer.write(into, head.unique, 0, wire.Open.writeOut(into[wire.Answer.size..], slot[1] + 1));
    }

    const file = std.Io.Dir.openFileAbsolute(self.io, path, .{
        .mode = if (writing) .read_write else .read_only,
    }) catch return self.refuse(into, head, wire.err.access);
    slot[0].* = .{
        .open = file,
        .directory = false,
        .under = (self.nodeAt(head.nodeid) orelse return self.refuse(into, head, wire.err.noent)).offer,
    };
    self.held += 1;
    return wire.Answer.write(into, head.unique, 0, wire.Open.writeOut(into[wire.Answer.size..], slot[1] + 1));
}

fn heldAt(self: *Export, handle: u64) ?*Handle {
    if (handle == 0 or handle > self.handles.len) return null;
    const one = &self.handles[@intCast(handle - 1)];
    if (one.open == null and !one.directory) return null;
    return one;
}

fn read(self: *Export, into: []u8, head: wire.Header, body: []const u8) usize {
    const asked = wire.Read.parse(body) orelse return self.refuse(into, head, wire.err.invalid);
    const held = self.heldAt(asked.handle) orelse return self.refuse(into, head, wire.err.badf);
    if (held.directory) return self.refuse(into, head, wire.err.isdir);

    const file = held.open orelse return self.refuse(into, head, wire.err.badf);
    const room = into[wire.Answer.size..];
    const wanted = @min(@as(usize, asked.bytes), room.len);
    // Nothing left to read is not a fault: a read past the end of a file answers no bytes, which is
    // how the guest kernel learns where the end is.
    const got = file.readPositionalAll(self.io, room[0..wanted], asked.offset) catch
        return self.refuse(into, head, wire.err.io);

    self.read_bytes += got;
    return wire.Answer.write(into, head.unique, 0, got);
}

/// Whether a node may be changed, and the refusal to send when it may not.
fn writableOr(self: *Export, into: []u8, head: wire.Header) ?usize {
    if (self.mayWrite(head.nodeid)) return null;
    return self.refuse(into, head, wire.err.rofs);
}

fn write(self: *Export, into: []u8, head: wire.Header, body: []const u8) usize {
    if (self.writableOr(into, head)) |refused| return refused;
    const asked, const bytes = wire.Write.parse(body) orelse
        return self.refuse(into, head, wire.err.invalid);
    const held = self.heldAt(asked.handle) orelse return self.refuse(into, head, wire.err.badf);
    const file = held.open orelse return self.refuse(into, head, wire.err.badf);

    file.writePositionalAll(self.io, bytes, asked.offset) catch
        return self.refuse(into, head, wire.err.io);
    self.written_bytes += bytes.len;
    return wire.Answer.write(into, head.unique, 0, wire.Write.writeOut(into[wire.Answer.size..], bytes.len));
}

fn create(self: *Export, into: []u8, head: wire.Header, body: []const u8) usize {
    if (self.writableOr(into, head)) |refused| return refused;
    const asked = wire.Create.parse(body) orelse return self.refuse(into, head, wire.err.invalid);
    if (!nameIsSafe(asked.name)) {
        self.turned_away += 1;
        return self.refuse(into, head, wire.err.noent);
    }

    var room: [4096]u8 = undefined;
    const path = self.pathOf(head.nodeid, asked.name, &room) orelse
        return self.refuse(into, head, wire.err.noent);

    const slot = for (&self.handles, 0..) |*each, index| {
        if (each.open == null and !each.directory) break .{ each, index };
    } else return self.refuse(into, head, wire.err.nfile);

    // Whether it is truncated is the guest's to say: a program that opens for appending means to
    // keep what is there.
    const truncating = asked.flags & 0o1000 != 0;
    const file = std.Io.Dir.createFileAbsolute(self.io, path, .{
        .read = true,
        .truncate = truncating,
    }) catch return self.refuse(into, head, wire.err.access);
    const attr = self.attrOf(path) orelse {
        file.close(self.io);
        return self.refuse(into, head, wire.err.io);
    };

    const node = (self.nodeAt(head.nodeid) orelse return self.refuse(into, head, wire.err.noent)).*;
    const under = self.joinUnder(head.nodeid, asked.name) catch {
        file.close(self.io);
        return self.refuse(into, head, wire.err.nomem);
    };
    const nodeid = self.nodeFor(node.offer, under) catch {
        self.gpa.free(under);
        file.close(self.io);
        return self.refuse(into, head, wire.err.nomem);
    };

    slot[0].* = .{ .open = file, .under = node.offer };
    self.held += 1;
    self.made += 1;
    return wire.Answer.write(into, head.unique, 0, wire.Create.writeOut(
        into[wire.Answer.size..],
        nodeid,
        attr,
        slot[1] + 1,
    ));
}

/// Change what a file is: its length, or what it may be read and written by. Only those two, because
/// they are the ones a program really depends on and the rest of what a guest could ask to change is
/// about owners this export does not have.
fn setattr(self: *Export, into: []u8, head: wire.Header, body: []const u8) usize {
    if (self.writableOr(into, head)) |refused| return refused;
    const asked = wire.SetAttr.parse(body) orelse return self.refuse(into, head, wire.err.invalid);

    var room: [4096]u8 = undefined;
    const path = self.pathOf(head.nodeid, null, &room) orelse
        return self.refuse(into, head, wire.err.noent);

    if (asked.valid & wire.SetAttr.wants_size != 0) {
        // Through a handle when the guest gave one, because the file may have been taken away by
        // name since it was opened.
        if (self.heldAt(asked.handle)) |held| {
            if (held.open) |file| {
                file.setLength(self.io, asked.size) catch
                    return self.refuse(into, head, wire.err.io);
            }
        } else {
            const file = std.Io.Dir.openFileAbsolute(self.io, path, .{ .mode = .write_only }) catch
                return self.refuse(into, head, wire.err.access);
            defer file.close(self.io);
            file.setLength(self.io, asked.size) catch
                return self.refuse(into, head, wire.err.io);
        }
    }
    // The times. A build system compares them to decide what to rebuild, so keeping the old ones and
    // reporting success is how a cache becomes wrong rather than slow.
    if (asked.valid & (wire.SetAttr.wants_atime | wire.SetAttr.wants_mtime) != 0) {
        const file = std.Io.Dir.openFileAbsolute(self.io, path, .{}) catch
            return self.refuse(into, head, wire.err.access);
        defer file.close(self.io);
        file.setTimestamps(self.io, .{
            .access_timestamp = whenAsked(
                asked.valid & wire.SetAttr.wants_atime != 0,
                asked.valid & wire.SetAttr.atime_is_now != 0,
                asked.atime,
                asked.atime_nanoseconds,
            ),
            .modify_timestamp = whenAsked(
                asked.valid & wire.SetAttr.wants_mtime != 0,
                asked.valid & wire.SetAttr.mtime_is_now != 0,
                asked.mtime,
                asked.mtime_nanoseconds,
            ),
        }) catch return self.refuse(into, head, wire.err.io);
    }
    if (asked.valid & wire.SetAttr.wants_mode != 0) {
        const file = std.Io.Dir.openFileAbsolute(self.io, path, .{}) catch
            return self.refuse(into, head, wire.err.access);
        defer file.close(self.io);
        // Only the bits that say who may read and write, because that is all a mode means here.
        file.setPermissions(self.io, @enumFromInt(asked.mode & 0o777)) catch {};
    }

    const attr = self.attrOf(path) orelse return self.refuse(into, head, wire.err.noent);
    return wire.Answer.write(into, head.unique, 0, wire.AttrAnswer.write(into[wire.Answer.size..], attr));
}

/// What a time should become: left alone, the time now, or the one the guest gave.
fn whenAsked(wanted: bool, now: bool, seconds: i64, nanoseconds: u32) std.Io.File.SetTimestamp {
    if (!wanted) return .unchanged;
    if (now) return .now;
    return .{ .new = .{ .nanoseconds = @as(i96, seconds) * std.time.ns_per_s + nanoseconds } };
}

fn makeDirectory(self: *Export, into: []u8, head: wire.Header, body: []const u8) usize {
    if (self.writableOr(into, head)) |refused| return refused;
    const asked = wire.MakeDirectory.parse(body) orelse return self.refuse(into, head, wire.err.invalid);
    if (!nameIsSafe(asked.name)) {
        self.turned_away += 1;
        return self.refuse(into, head, wire.err.noent);
    }

    var room: [4096]u8 = undefined;
    const path = self.pathOf(head.nodeid, asked.name, &room) orelse
        return self.refuse(into, head, wire.err.noent);
    std.Io.Dir.createDirAbsolute(self.io, path, @enumFromInt(asked.mode & 0o777)) catch |err| switch (err) {
        error.PathAlreadyExists => return self.refuse(into, head, wire.err.exist),
        else => return self.refuse(into, head, wire.err.access),
    };

    const attr = self.attrOf(path) orelse return self.refuse(into, head, wire.err.io);
    const node = (self.nodeAt(head.nodeid) orelse return self.refuse(into, head, wire.err.noent)).*;
    const under = self.joinUnder(head.nodeid, asked.name) catch
        return self.refuse(into, head, wire.err.nomem);
    const nodeid = self.nodeFor(node.offer, under) catch {
        self.gpa.free(under);
        return self.refuse(into, head, wire.err.nomem);
    };
    self.made += 1;
    return wire.Answer.write(into, head.unique, 0, wire.Entry.write(into[wire.Answer.size..], nodeid, attr));
}

fn remove(self: *Export, into: []u8, head: wire.Header, body: []const u8, directory: bool) usize {
    if (self.writableOr(into, head)) |refused| return refused;
    const name = std.mem.sliceTo(body, 0);
    if (!nameIsSafe(name)) {
        self.turned_away += 1;
        return self.refuse(into, head, wire.err.noent);
    }

    var room: [4096]u8 = undefined;
    const path = self.pathOf(head.nodeid, name, &room) orelse
        return self.refuse(into, head, wire.err.noent);
    if (directory) {
        std.Io.Dir.deleteDirAbsolute(self.io, path) catch
            return self.refuse(into, head, wire.err.notdir);
    } else {
        std.Io.Dir.cwd().deleteFile(self.io, path) catch
            return self.refuse(into, head, wire.err.access);
    }
    self.taken_away += 1;
    return wire.Answer.write(into, head.unique, 0, 0);
}

fn rename(self: *Export, into: []u8, head: wire.Header, body: []const u8, wide: bool) usize {
    if (self.writableOr(into, head)) |refused| return refused;
    const asked = wire.Rename.parse(body, wide) orelse return self.refuse(into, head, wire.err.invalid);
    if (!nameIsSafe(asked.from) or !nameIsSafe(asked.to)) {
        self.turned_away += 1;
        return self.refuse(into, head, wire.err.noent);
    }
    // Moving into another directory is only allowed inside the same share: a rename across two of
    // them would be a guest moving a file between things whoever holds the guest offered separately.
    if (!self.mayWrite(asked.into_nodeid)) return self.refuse(into, head, wire.err.rofs);
    const here = (self.nodeAt(head.nodeid) orelse return self.refuse(into, head, wire.err.noent)).*;
    const there = (self.nodeAt(asked.into_nodeid) orelse return self.refuse(into, head, wire.err.noent)).*;
    if (here.offer != there.offer) return self.refuse(into, head, wire.err.invalid);

    var from_room: [4096]u8 = undefined;
    var to_room: [4096]u8 = undefined;
    const from = self.pathOf(head.nodeid, asked.from, &from_room) orelse
        return self.refuse(into, head, wire.err.noent);
    const to = self.pathOf(asked.into_nodeid, asked.to, &to_room) orelse
        return self.refuse(into, head, wire.err.noent);

    std.Io.Dir.renameAbsolute(from, to, self.io) catch
        return self.refuse(into, head, wire.err.access);
    self.moved += 1;
    return wire.Answer.write(into, head.unique, 0, 0);
}

fn makeLink(self: *Export, into: []u8, head: wire.Header, body: []const u8) usize {
    if (self.writableOr(into, head)) |refused| return refused;
    const name = std.mem.sliceTo(body, 0);
    if (body.len < name.len + 2) return self.refuse(into, head, wire.err.invalid);
    const points_at = std.mem.sliceTo(body[name.len + 1 ..], 0);
    if (!nameIsSafe(name) or points_at.len == 0) {
        self.turned_away += 1;
        return self.refuse(into, head, wire.err.noent);
    }

    var room: [4096]u8 = undefined;
    const path = self.pathOf(head.nodeid, name, &room) orelse
        return self.refuse(into, head, wire.err.noent);
    // What it points at is written down as the guest gave it and never resolved here. A link out of
    // the share is the guest's own to follow inside its own mount, where it means nothing.
    std.Io.Dir.symLinkAbsolute(self.io, points_at, path, .{}) catch
        return self.refuse(into, head, wire.err.access);

    const attr = self.attrOf(path) orelse return self.refuse(into, head, wire.err.io);
    const node = (self.nodeAt(head.nodeid) orelse return self.refuse(into, head, wire.err.noent)).*;
    const under = self.joinUnder(head.nodeid, name) catch
        return self.refuse(into, head, wire.err.nomem);
    const nodeid = self.nodeFor(node.offer, under) catch {
        self.gpa.free(under);
        return self.refuse(into, head, wire.err.nomem);
    };
    self.made += 1;
    return wire.Answer.write(into, head.unique, 0, wire.Entry.write(into[wire.Answer.size..], nodeid, attr));
}

/// A second name for a file that is already there. Both names have to be inside the same share: one
/// reaching into another would be a guest joining two things that were offered separately.
fn makeHardLink(self: *Export, into: []u8, head: wire.Header, body: []const u8) usize {
    if (body.len < 8) return self.refuse(into, head, wire.err.invalid);
    const existing = std.mem.readInt(u64, body[0..8], .little);
    const name = std.mem.sliceTo(body[8..], 0);
    if (self.writableOr(into, head)) |refused| return refused;
    if (!nameIsSafe(name)) {
        self.turned_away += 1;
        return self.refuse(into, head, wire.err.noent);
    }
    const from_node = (self.nodeAt(existing) orelse return self.refuse(into, head, wire.err.noent)).*;
    const here = (self.nodeAt(head.nodeid) orelse return self.refuse(into, head, wire.err.noent)).*;
    if (from_node.offer != here.offer or from_node.generation != here.generation) {
        return self.refuse(into, head, wire.err.invalid);
    }

    var from_room: [4096]u8 = undefined;
    var to_room: [4096]u8 = undefined;
    const from = self.pathOf(existing, null, &from_room) orelse
        return self.refuse(into, head, wire.err.noent);
    const to = self.pathOf(head.nodeid, name, &to_room) orelse
        return self.refuse(into, head, wire.err.noent);

    std.Io.Dir.cwd().hardLink(from, .cwd(), to, self.io, .{}) catch |err| switch (err) {
        error.PathAlreadyExists => return self.refuse(into, head, wire.err.exist),
        else => return self.refuse(into, head, wire.err.access),
    };

    const attr = self.attrOf(to) orelse return self.refuse(into, head, wire.err.io);
    const under = self.joinUnder(head.nodeid, name) catch
        return self.refuse(into, head, wire.err.nomem);
    const nodeid = self.nodeFor(here.offer, under) catch {
        self.gpa.free(under);
        return self.refuse(into, head, wire.err.nomem);
    };
    self.made += 1;
    return wire.Answer.write(into, head.unique, 0, wire.Entry.write(into[wire.Answer.size..], nodeid, attr));
}

fn release(self: *Export, into: []u8, head: wire.Header, body: []const u8) usize {
    const handle = wire.Release.parse(body) orelse return self.refuse(into, head, wire.err.invalid);
    if (self.heldAt(handle)) |held| {
        if (held.open) |file| file.close(self.io);
        if (held.walking) |*one| one.close(self.io);
        held.* = .{};
        self.let_go += 1;
    }
    return wire.Answer.write(into, head.unique, 0, 0);
}

/// Every name in the directory the guest mounted, which is one per offer.
fn listOffers(self: *Export, into: []u8, head: wire.Header, asked: wire.Read) usize {
    const answer_room = into[wire.Answer.size..];
    const wanted = @min(@as(usize, asked.bytes), answer_room.len);
    var filled: usize = 0;
    var index: u64 = 0;

    for (&self.offers, 0..) |*each, which| {
        if (!each.used) continue;
        index += 1;
        if (index <= asked.offset) continue;
        if (filled + wire.DirEntry.roomFor(each.name) > wanted) break;

        var room: [4096]u8 = undefined;
        const empty = self.gpa.dupe(u8, "") catch break;
        const nodeid = self.nodeFor(@intCast(which), empty) catch {
            self.gpa.free(empty);
            break;
        };
        const path = self.pathOf(nodeid, null, &room) orelse continue;
        const attr = self.attrOf(path) orelse continue;
        filled += wire.DirEntry.write(answer_room[filled..], nodeid, attr, index, each.name);
        self.named += 1;
    }
    return wire.Answer.write(into, head.unique, 0, filled);
}

/// Read a directory, one answer holding as many names as fit.
///
/// The offset is a place in the listing rather than a byte count, and the kernel hands back the one
/// from the last name it took. Reading from the start each time and skipping is what keeps this end
/// from holding a cursor the guest could get wrong.
fn readdir(self: *Export, into: []u8, head: wire.Header, body: []const u8) usize {
    const asked = wire.Read.parse(body) orelse return self.refuse(into, head, wire.err.invalid);
    const held = self.heldAt(asked.handle) orelse return self.refuse(into, head, wire.err.badf);
    if (!held.directory) return self.refuse(into, head, wire.err.notdir);

    // The directory the guest mounted holds the offers and nothing else. It is short, so one answer
    // holds all of it and there is no walk to carry on.
    if (head.nodeid == 1) return self.listOffers(into, head, asked);

    // A read that asks for something already handed over starts the walk again. The kernel does this
    // when a program rewinds a directory, and only then: reading forwards never comes back here.
    if (asked.offset < held.at) {
        const one = held.walking orelse return self.refuse(into, head, wire.err.badf);
        held.walker = one.iterate();
        held.at = 0;
        held.waiting_len = 0;
    }
    const walker = &(held.walker orelse return self.refuse(into, head, wire.err.badf));

    var room: [4096]u8 = undefined;
    const answer_room = into[wire.Answer.size..];
    const wanted = @min(@as(usize, asked.bytes), answer_room.len);
    var filled: usize = 0;

    while (true) {
        // The name left over from last time, or the next one from the walk.
        if (held.waiting_len == 0) {
            const entry = (walker.next(self.io) catch null) orelse break;
            if (!nameIsSafe(entry.name)) continue;
            const taking = @min(entry.name.len, held.waiting.len);
            @memcpy(held.waiting[0..taking], entry.name[0..taking]);
            held.waiting_len = taking;
        }
        const name = held.waiting[0..held.waiting_len];

        // No room for it: it stays waiting and goes out at the front of the next answer.
        if (filled + wire.DirEntry.roomFor(name) > wanted) break;

        const path = self.pathOf(head.nodeid, name, &room) orelse {
            held.waiting_len = 0;
            continue;
        };
        const attr = self.attrOf(path) orelse {
            held.waiting_len = 0;
            continue;
        };
        const under = self.joinUnder(head.nodeid, name) catch break;
        const nodeid = self.nodeFor(self.nodes.items[@intCast(head.nodeid)].offer, under) catch {
            self.gpa.free(under);
            break;
        };

        // The offset is where the guest has got to, and the next read asks for what comes after it.
        held.at += 1;
        filled += wire.DirEntry.write(answer_room[filled..], nodeid, attr, held.at, name);
        held.waiting_len = 0;
        self.named += 1;
    }
    return wire.Answer.write(into, head.unique, 0, filled);
}

/// Build one message, the way the kernel lays it out.
fn ask(into: []u8, op: wire.Op, nodeid: u64, body: []const u8) []const u8 {
    @memset(into[0..wire.Header.size], 0);
    const total = wire.Header.size + body.len;
    std.mem.writeInt(u32, into[0..4], @intCast(total), .little);
    std.mem.writeInt(u32, into[4..8], @intFromEnum(op), .little);
    std.mem.writeInt(u64, into[8..16], 1, .little);
    std.mem.writeInt(u64, into[16..24], nodeid, .little);
    @memcpy(into[wire.Header.size..][0..body.len], body);
    return into[0..total];
}

/// What an answer refused with, or nothing if it did not refuse.
fn refusalIn(answered: []const u8) ?i32 {
    const code = std.mem.readInt(i32, answered[4..8], .little);
    return if (code == 0) null else -code;
}

/// The node of an offered directory, found the way a guest finds it: by looking its name up in the
/// directory it mounted.
fn nodeOf(offered: *Export, name: []const u8, request: []u8, answered: []u8) !u64 {
    var room: [64]u8 = undefined;
    const asking = std.fmt.bufPrint(&room, "{s}\x00", .{name}) catch unreachable;
    const wrote = offered.answer(ask(request, .lookup, 1, asking), answered);
    if (refusalIn(answered[0..wrote])) |_| return error.NotOffered;
    return std.mem.readInt(u64, answered[wire.Answer.size..][0..8], .little);
}

const Bench = struct {
    io: std.Io,
    threaded: *std.Io.Threaded,
    at: []const u8,
    gpa: std.mem.Allocator,

    fn open(gpa: std.mem.Allocator) !Bench {
        const threaded = try gpa.create(std.Io.Threaded);
        threaded.* = .init(gpa, .{});
        const io = threaded.io();

        var room: [128]u8 = undefined;
        const at = try gpa.dupe(u8, std.fmt.bufPrint(&room, "/tmp/mirage-export-test-{d}", .{std.os.linux.getpid()}) catch unreachable);
        const cwd: std.Io.Dir = .cwd();
        cwd.deleteTree(io, at) catch {};
        try cwd.createDir(io, at, .default_dir);

        var name: [256]u8 = undefined;
        try cwd.writeFile(io, .{
            .sub_path = std.fmt.bufPrint(&name, "{s}/hello", .{at}) catch unreachable,
            .data = "a store path's contents\n",
        });
        try cwd.createDir(io, std.fmt.bufPrint(&name, "{s}/deep", .{at}) catch unreachable, .default_dir);
        try cwd.writeFile(io, .{
            .sub_path = std.fmt.bufPrint(&name, "{s}/deep/inside", .{at}) catch unreachable,
            .data = "deeper\n",
        });
        try cwd.symLink(io, "hello", std.fmt.bufPrint(&name, "{s}/link", .{at}) catch unreachable, .{});

        return .{ .io = io, .threaded = threaded, .at = at, .gpa = gpa };
    }

    fn close(self: *Bench) void {
        std.Io.Dir.cwd().deleteTree(self.io, self.at) catch {};
        self.gpa.free(self.at);
        self.threaded.deinit();
        self.gpa.destroy(self.threaded);
    }
};

test "a guest looks a name up and reads what is there" {
    const gpa = std.testing.allocator;
    var bench = try Bench.open(gpa);
    defer bench.close();

    var offered = try Export.init(gpa, bench.io);
    defer offered.deinit();
    try offered.offer("store", bench.at, false);

    var request: [512]u8 = undefined;
    var answered: [4096]u8 = undefined;

    // The kernel starts by agreeing a version.
    var start: [wire.Init.in_size]u8 = @splat(0);
    std.mem.writeInt(u32, start[0..4], wire.major, .little);
    std.mem.writeInt(u32, start[4..8], 41, .little);
    var wrote = offered.answer(ask(&request, .init, 1, &start), &answered);
    try std.testing.expectEqual(@as(?i32, null), refusalIn(answered[0..wrote]));

    // Then it looks up a name in the root.
    wrote = offered.answer(ask(&request, .lookup, try nodeOf(&offered, "store", &request, &answered), "hello\x00"), &answered);
    try std.testing.expectEqual(@as(?i32, null), refusalIn(answered[0..wrote]));
    const nodeid = std.mem.readInt(u64, answered[wire.Answer.size..][0..8], .little);
    try std.testing.expect(nodeid > 1);

    // The attributes come with it: a file, of the size it really is, with no write bits.
    const attr = answered[wire.Answer.size + 40 ..];
    try std.testing.expectEqual(@as(u64, 24), std.mem.readInt(u64, attr[8..16], .little));
    const mode = std.mem.readInt(u32, attr[60..64], .little);
    try std.testing.expectEqual(@as(u32, 0o100000), mode & 0o170000);
    try std.testing.expectEqual(@as(u32, 0), mode & 0o222);

    // Opening it gives a handle, and reading through that gives the bytes.
    var open_in: [8]u8 = @splat(0);
    wrote = offered.answer(ask(&request, .open, nodeid, &open_in), &answered);
    try std.testing.expectEqual(@as(?i32, null), refusalIn(answered[0..wrote]));
    const handle = std.mem.readInt(u64, answered[wire.Answer.size..][0..8], .little);

    var read_in: [wire.Read.in_size]u8 = @splat(0);
    std.mem.writeInt(u64, read_in[0..8], handle, .little);
    std.mem.writeInt(u64, read_in[8..16], 0, .little);
    std.mem.writeInt(u32, read_in[16..20], 64, .little);
    wrote = offered.answer(ask(&request, .read, nodeid, &read_in), &answered);
    try std.testing.expectEqual(@as(?i32, null), refusalIn(answered[0..wrote]));
    try std.testing.expectEqualSlices(u8, "a store path's contents\n", answered[wire.Answer.size..wrote]);

    // And letting go of it closes what this end held.
    var release_in: [24]u8 = @splat(0);
    std.mem.writeInt(u64, release_in[0..8], handle, .little);
    wrote = offered.answer(ask(&request, .release, nodeid, &release_in), &answered);
    try std.testing.expectEqual(@as(?i32, null), refusalIn(answered[0..wrote]));
    try std.testing.expectEqual(@as(u64, 1), offered.let_go);
}

test "a name that walks out of the export is a name that is not there" {
    const gpa = std.testing.allocator;
    var bench = try Bench.open(gpa);
    defer bench.close();

    var offered = try Export.init(gpa, bench.io);
    defer offered.deinit();
    try offered.offer("store", bench.at, false);

    var request: [512]u8 = undefined;
    var answered: [4096]u8 = undefined;

    // The kernel never sends any of these: it resolves them itself. A guest that sends one is trying
    // to leave the directory it was given, and it is told there is no such name.
    for ([_][]const u8{ "..\x00", ".\x00", "../etc/passwd\x00", "deep/inside\x00", "/etc/passwd\x00" }) |name| {
        const wrote = offered.answer(ask(&request, .lookup, try nodeOf(&offered, "store", &request, &answered), name), &answered);
        try std.testing.expectEqual(@as(?i32, wire.err.noent), refusalIn(answered[0..wrote]));
    }
    try std.testing.expectEqual(@as(u64, 5), offered.turned_away);

    // A name that really is there still works, so the rule is about leaving rather than about names.
    const wrote = offered.answer(ask(&request, .lookup, try nodeOf(&offered, "store", &request, &answered), "deep\x00"), &answered);
    try std.testing.expectEqual(@as(?i32, null), refusalIn(answered[0..wrote]));
}

test "nothing a guest sends can change what is exported" {
    const gpa = std.testing.allocator;
    var bench = try Bench.open(gpa);
    defer bench.close();

    var offered = try Export.init(gpa, bench.io);
    defer offered.deinit();
    try offered.offer("store", bench.at, false);

    var request: [512]u8 = undefined;
    var answered: [4096]u8 = undefined;

    // Every way of changing something is refused the way a read only mount refuses it, so the guest's
    // own kernel reports it as the filesystem being read only rather than as a fault.
    for ([_]wire.Op{ .write, .setattr, .create }) |op| {
        const wrote = offered.answer(ask(&request, op, try nodeOf(&offered, "store", &request, &answered), "x" ** 64), &answered);
        try std.testing.expectEqual(@as(?i32, wire.err.rofs), refusalIn(answered[0..wrote]));
    }

    // The file is still what it was.
    var room: [128]u8 = undefined;
    const said = try std.Io.Dir.cwd().readFileAlloc(
        bench.io,
        std.fmt.bufPrint(&room, "{s}/hello", .{bench.at}) catch unreachable,
        gpa,
        .limited(1024),
    );
    defer gpa.free(said);
    try std.testing.expectEqualSlices(u8, "a store path's contents\n", said);
}

test "a directory read carries every name with what a lookup would have said" {
    const gpa = std.testing.allocator;
    var bench = try Bench.open(gpa);
    defer bench.close();

    var offered = try Export.init(gpa, bench.io);
    defer offered.deinit();
    try offered.offer("store", bench.at, false);

    var request: [512]u8 = undefined;
    var answered: [8192]u8 = undefined;

    const store_node = try nodeOf(&offered, "store", &request, &answered);
    var open_in: [8]u8 = @splat(0);
    var wrote = offered.answer(ask(&request, .opendir, store_node, &open_in), &answered);
    try std.testing.expectEqual(@as(?i32, null), refusalIn(answered[0..wrote]));
    const handle = std.mem.readInt(u64, answered[wire.Answer.size..][0..8], .little);

    var read_in: [wire.Read.in_size]u8 = @splat(0);
    std.mem.writeInt(u64, read_in[0..8], handle, .little);
    std.mem.writeInt(u32, read_in[16..20], 4096, .little);
    wrote = offered.answer(ask(&request, .readdirplus, store_node, &read_in), &answered);
    try std.testing.expectEqual(@as(?i32, null), refusalIn(answered[0..wrote]));

    // Every name the directory holds is in there, and nothing else is.
    const listing = answered[wire.Answer.size..wrote];
    try std.testing.expect(std.mem.indexOf(u8, listing, "hello") != null);
    try std.testing.expect(std.mem.indexOf(u8, listing, "deep") != null);
    try std.testing.expect(std.mem.indexOf(u8, listing, "link") != null);
    try std.testing.expect(std.mem.indexOf(u8, listing, "..") == null);
}

test "a link is handed over rather than followed" {
    const gpa = std.testing.allocator;
    var bench = try Bench.open(gpa);
    defer bench.close();

    var offered = try Export.init(gpa, bench.io);
    defer offered.deinit();
    try offered.offer("store", bench.at, false);

    var request: [512]u8 = undefined;
    var answered: [4096]u8 = undefined;

    var wrote = offered.answer(ask(&request, .lookup, try nodeOf(&offered, "store", &request, &answered), "link\x00"), &answered);
    const nodeid = std.mem.readInt(u64, answered[wire.Answer.size..][0..8], .little);

    // A link, said to be one, rather than the file it points at.
    const mode = std.mem.readInt(u32, answered[wire.Answer.size + 40 + 60 ..][0..4], .little);
    try std.testing.expectEqual(@as(u32, 0o120000), mode & 0o170000);

    // What it points at goes back as text. Resolving it is the guest kernel's, inside its own mount,
    // which is what keeps a link from reaching out of the export.
    wrote = offered.answer(ask(&request, .readlink, nodeid, &.{}), &answered);
    try std.testing.expectEqual(@as(?i32, null), refusalIn(answered[0..wrote]));
    try std.testing.expectEqualSlices(u8, "hello", answered[wire.Answer.size..wrote]);
}

test "opening to write is refused at the open rather than at the write" {
    const gpa = std.testing.allocator;
    var bench = try Bench.open(gpa);
    defer bench.close();

    var offered = try Export.init(gpa, bench.io);
    defer offered.deinit();
    try offered.offer("store", bench.at, false);

    var request: [512]u8 = undefined;
    var answered: [4096]u8 = undefined;

    var wrote = offered.answer(ask(&request, .lookup, try nodeOf(&offered, "store", &request, &answered), "hello\x00"), &answered);
    const nodeid = std.mem.readInt(u64, answered[wire.Answer.size..][0..8], .little);

    // A guest is root inside itself, so its own kernel would let it open this for writing and only
    // the write would fail. The answer to the open is the true one.
    for ([_]u32{ 1, 2 }) |accmode| {
        var open_in: [8]u8 = @splat(0);
        std.mem.writeInt(u32, open_in[0..4], accmode, .little);
        wrote = offered.answer(ask(&request, .open, nodeid, &open_in), &answered);
        try std.testing.expectEqual(@as(?i32, wire.err.rofs), refusalIn(answered[0..wrote]));
    }

    // Reading is still reading.
    var read_only: [8]u8 = @splat(0);
    wrote = offered.answer(ask(&request, .open, nodeid, &read_only), &answered);
    try std.testing.expectEqual(@as(?i32, null), refusalIn(answered[0..wrote]));
}

test "a directory read in small answers hands over every name exactly once" {
    const gpa = std.testing.allocator;
    var bench = try Bench.open(gpa);
    defer bench.close();

    // More names than one small answer can hold, so the reading takes several turns. A walk that
    // started again on each turn would hand some names over twice and cost the square of the size.
    var name: [160]u8 = undefined;
    for (0..40) |index| {
        try std.Io.Dir.cwd().writeFile(bench.io, .{
            .sub_path = try std.fmt.bufPrint(&name, "{s}/path-{d}", .{ bench.at, index }),
            .data = "x",
        });
    }

    var offered = try Export.init(gpa, bench.io);
    defer offered.deinit();
    try offered.offer("store", bench.at, false);

    var request: [512]u8 = undefined;
    var answered: [4096]u8 = undefined;

    const store_node = try nodeOf(&offered, "store", &request, &answered);
    var open_in: [8]u8 = @splat(0);
    var wrote = offered.answer(ask(&request, .opendir, store_node, &open_in), &answered);
    const handle = std.mem.readInt(u64, answered[wire.Answer.size..][0..8], .little);

    // Room for two names at a time, which is what makes this the interesting case.
    var seen: std.StringHashMapUnmanaged(u32) = .empty;
    defer {
        var walk = seen.keyIterator();
        while (walk.next()) |key| gpa.free(key.*);
        seen.deinit(gpa);
    }

    var offset: u64 = 0;
    var turns: usize = 0;
    while (turns < 200) : (turns += 1) {
        var read_in: [wire.Read.in_size]u8 = @splat(0);
        std.mem.writeInt(u64, read_in[0..8], handle, .little);
        std.mem.writeInt(u64, read_in[8..16], offset, .little);
        std.mem.writeInt(u32, read_in[16..20], 400, .little);
        wrote = offered.answer(ask(&request, .readdirplus, store_node, &read_in), &answered);
        try std.testing.expectEqual(@as(?i32, null), refusalIn(answered[0..wrote]));

        const listing = answered[wire.Answer.size..wrote];
        if (listing.len == 0) break;

        // Walk the answer the way the kernel does, taking the offset from the last entry in it.
        var at: usize = 0;
        while (at + wire.Entry.size + wire.DirEntry.header_size <= listing.len) {
            const after = listing[at + wire.Entry.size ..];
            const where = std.mem.readInt(u64, after[8..16], .little);
            const said_len = std.mem.readInt(u32, after[16..20], .little);
            const text = after[wire.DirEntry.header_size..][0..said_len];

            const found = try seen.getOrPut(gpa, text);
            if (found.found_existing) {
                found.value_ptr.* += 1;
            } else {
                found.key_ptr.* = try gpa.dupe(u8, text);
                found.value_ptr.* = 1;
            }
            offset = where;
            at += wire.Entry.size + wire.DirEntry.header_size + std.mem.alignForward(usize, said_len, 8);
        }
    }

    // Forty names, the file, the directory and the link that the bench makes: every one of them once.
    try std.testing.expectEqual(@as(usize, 43), seen.count());
    var counted = seen.valueIterator();
    while (counted.next()) |times| try std.testing.expectEqual(@as(u32, 1), times.*);
    try std.testing.expect(seen.contains("path-39"));
    try std.testing.expect(seen.contains("hello"));
}

test "a guest writes into a share that allows it" {
    const gpa = std.testing.allocator;
    var bench = try Bench.open(gpa);
    defer bench.close();

    var offered = try Export.init(gpa, bench.io);
    defer offered.deinit();
    try offered.offer("work", bench.at, true);

    var request: [1024]u8 = undefined;
    var answered: [4096]u8 = undefined;
    const work = try nodeOf(&offered, "work", &request, &answered);

    // Make a file, write to it, and let it go.
    var create_in: [wire.Create.in_size + 8]u8 = @splat(0);
    std.mem.writeInt(u32, create_in[0..4], 0o101, .little);
    std.mem.writeInt(u32, create_in[4..8], 0o100644, .little);
    @memcpy(create_in[wire.Create.in_size..][0..6], "new\x00\x00\x00");
    var wrote = offered.answer(ask(&request, .create, work, &create_in), &answered);
    try std.testing.expectEqual(@as(?i32, null), refusalIn(answered[0..wrote]));
    const nodeid = std.mem.readInt(u64, answered[wire.Answer.size..][0..8], .little);
    const handle = std.mem.readInt(u64, answered[wire.Answer.size + wire.Entry.size ..][0..8], .little);

    const said = "what the agent wrote\n";
    var write_in: [wire.Write.in_size + said.len]u8 = @splat(0);
    std.mem.writeInt(u64, write_in[0..8], handle, .little);
    std.mem.writeInt(u64, write_in[8..16], 0, .little);
    std.mem.writeInt(u32, write_in[16..20], said.len, .little);
    @memcpy(write_in[wire.Write.in_size..], said);
    wrote = offered.answer(ask(&request, .write, nodeid, &write_in), &answered);
    try std.testing.expectEqual(@as(?i32, null), refusalIn(answered[0..wrote]));
    try std.testing.expectEqual(@as(u32, said.len), std.mem.readInt(u32, answered[wire.Answer.size..][0..4], .little));

    var release_in: [24]u8 = @splat(0);
    std.mem.writeInt(u64, release_in[0..8], handle, .little);
    _ = offered.answer(ask(&request, .release, nodeid, &release_in), &answered);

    // It is really there, on this machine, with those bytes in it.
    var room: [160]u8 = undefined;
    const path = try std.fmt.bufPrint(&room, "{s}/new", .{bench.at});
    const on_disk = try std.Io.Dir.cwd().readFileAlloc(bench.io, path, gpa, .limited(1024));
    defer gpa.free(on_disk);
    try std.testing.expectEqualSlices(u8, said, on_disk);
    try std.testing.expectEqual(@as(u64, said.len), offered.written_bytes);
}

test "a guest makes and unmakes directories and moves names about" {
    const gpa = std.testing.allocator;
    var bench = try Bench.open(gpa);
    defer bench.close();

    var offered = try Export.init(gpa, bench.io);
    defer offered.deinit();
    try offered.offer("work", bench.at, true);

    var request: [1024]u8 = undefined;
    var answered: [4096]u8 = undefined;
    const work = try nodeOf(&offered, "work", &request, &answered);

    var mkdir_in: [wire.MakeDirectory.in_size + 8]u8 = @splat(0);
    std.mem.writeInt(u32, mkdir_in[0..4], 0o755, .little);
    @memcpy(mkdir_in[wire.MakeDirectory.in_size..][0..5], "made\x00");
    var wrote = offered.answer(ask(&request, .mkdir, work, &mkdir_in), &answered);
    try std.testing.expectEqual(@as(?i32, null), refusalIn(answered[0..wrote]));

    // Moved, then taken away.
    var rename_in: [wire.Rename.in_size + 16]u8 = @splat(0);
    std.mem.writeInt(u64, rename_in[0..8], work, .little);
    @memcpy(rename_in[wire.Rename.in_size..][0..11], "made\x00moved\x00");
    wrote = offered.answer(ask(&request, .rename, work, &rename_in), &answered);
    try std.testing.expectEqual(@as(?i32, null), refusalIn(answered[0..wrote]));

    var room: [160]u8 = undefined;
    const moved = try std.fmt.bufPrint(&room, "{s}/moved", .{bench.at});
    const about = try std.Io.Dir.cwd().statFile(bench.io, moved, .{});
    try std.testing.expectEqual(std.Io.File.Kind.directory, about.kind);

    wrote = offered.answer(ask(&request, .rmdir, work, "moved\x00"), &answered);
    try std.testing.expectEqual(@as(?i32, null), refusalIn(answered[0..wrote]));
    try std.testing.expectError(error.FileNotFound, std.Io.Dir.cwd().statFile(bench.io, moved, .{}));
    try std.testing.expectEqual(@as(u64, 1), offered.moved);
    try std.testing.expectEqual(@as(u64, 1), offered.taken_away);
}

test "a share nobody made writable refuses every way of changing it" {
    const gpa = std.testing.allocator;
    var bench = try Bench.open(gpa);
    defer bench.close();

    var offered = try Export.init(gpa, bench.io);
    defer offered.deinit();
    try offered.offer("store", bench.at, false);

    var request: [1024]u8 = undefined;
    var answered: [4096]u8 = undefined;
    const store = try nodeOf(&offered, "store", &request, &answered);

    // Every one of them, and the same answer to each: the one a read only mount gives.
    for ([_]wire.Op{ .write, .create, .setattr, .mkdir, .unlink, .rmdir, .rename, .symlink }) |op| {
        var asking: [128]u8 = @splat(0);
        @memcpy(asking[0..6], "x\x00y\x00z\x00");
        const wrote = offered.answer(ask(&request, op, store, &asking), &answered);
        try std.testing.expectEqual(@as(?i32, wire.err.rofs), refusalIn(answered[0..wrote]));
    }

    // And the directory is as it was.
    var room: [160]u8 = undefined;
    const path = try std.fmt.bufPrint(&room, "{s}/hello", .{bench.at});
    const on_disk = try std.Io.Dir.cwd().readFileAlloc(bench.io, path, gpa, .limited(1024));
    defer gpa.free(on_disk);
    try std.testing.expectEqualSlices(u8, "a store path's contents\n", on_disk);
    try std.testing.expectEqual(@as(u64, 0), offered.written_bytes);
    try std.testing.expectEqual(@as(u64, 0), offered.made);
}

test "two shares are two names, and one being writable says nothing about the other" {
    const gpa = std.testing.allocator;
    var bench = try Bench.open(gpa);
    defer bench.close();

    // A second directory, to offer beside the first.
    var room: [160]u8 = undefined;
    const second = try std.fmt.allocPrint(gpa, "{s}-work", .{bench.at});
    defer gpa.free(second);
    std.Io.Dir.cwd().createDir(bench.io, second, .default_dir) catch {};
    defer std.Io.Dir.cwd().deleteTree(bench.io, second) catch {};

    var offered = try Export.init(gpa, bench.io);
    defer offered.deinit();
    try offered.offer("store", bench.at, false);
    try offered.offer("work", second, true);

    var request: [1024]u8 = undefined;
    var answered: [8192]u8 = undefined;

    // Both names are in the directory the guest mounted, and nothing else is.
    var open_in: [8]u8 = @splat(0);
    var wrote = offered.answer(ask(&request, .opendir, 1, &open_in), &answered);
    const handle = std.mem.readInt(u64, answered[wire.Answer.size..][0..8], .little);
    var read_in: [wire.Read.in_size]u8 = @splat(0);
    std.mem.writeInt(u64, read_in[0..8], handle, .little);
    std.mem.writeInt(u32, read_in[16..20], 4096, .little);
    wrote = offered.answer(ask(&request, .readdirplus, 1, &read_in), &answered);
    const listing = answered[wire.Answer.size..wrote];
    try std.testing.expect(std.mem.indexOf(u8, listing, "store") != null);
    try std.testing.expect(std.mem.indexOf(u8, listing, "work") != null);

    // Making a directory under the writable one works, and under the other one does not.
    var mkdir_in: [wire.MakeDirectory.in_size + 8]u8 = @splat(0);
    std.mem.writeInt(u32, mkdir_in[0..4], 0o755, .little);
    @memcpy(mkdir_in[wire.MakeDirectory.in_size..][0..5], "here\x00");

    const work = try nodeOf(&offered, "work", &request, &answered);
    wrote = offered.answer(ask(&request, .mkdir, work, &mkdir_in), &answered);
    try std.testing.expectEqual(@as(?i32, null), refusalIn(answered[0..wrote]));

    const store = try nodeOf(&offered, "store", &request, &answered);
    wrote = offered.answer(ask(&request, .mkdir, store, &mkdir_in), &answered);
    try std.testing.expectEqual(@as(?i32, wire.err.rofs), refusalIn(answered[0..wrote]));

    // It went where it was allowed and nowhere else.
    const made = try std.fmt.bufPrint(&room, "{s}/here", .{second});
    _ = try std.Io.Dir.cwd().statFile(bench.io, made, .{});
    const not_made = try std.fmt.bufPrint(&room, "{s}/here", .{bench.at});
    try std.testing.expectError(error.FileNotFound, std.Io.Dir.cwd().statFile(bench.io, not_made, .{}));
}

test "a share taken back stops answering, and what the guest held on it stops working" {
    const gpa = std.testing.allocator;
    var bench = try Bench.open(gpa);
    defer bench.close();

    var offered = try Export.init(gpa, bench.io);
    defer offered.deinit();
    try offered.offer("secret", bench.at, false);

    var request: [1024]u8 = undefined;
    var answered: [4096]u8 = undefined;
    const secret = try nodeOf(&offered, "secret", &request, &answered);

    var open_in: [8]u8 = @splat(0);
    var wrote = offered.answer(ask(&request, .lookup, secret, "hello\x00"), &answered);
    const nodeid = std.mem.readInt(u64, answered[wire.Answer.size..][0..8], .little);
    wrote = offered.answer(ask(&request, .open, nodeid, &open_in), &answered);
    const handle = std.mem.readInt(u64, answered[wire.Answer.size..][0..8], .little);

    // Taken back while the guest holds it open. That is the case a per call secret needs: it exists
    // for one program and then does not, whatever that program is still holding.
    offered.withdraw("secret");

    var read_in: [wire.Read.in_size]u8 = @splat(0);
    std.mem.writeInt(u64, read_in[0..8], handle, .little);
    std.mem.writeInt(u32, read_in[16..20], 64, .little);
    wrote = offered.answer(ask(&request, .read, nodeid, &read_in), &answered);
    try std.testing.expectEqual(@as(?i32, wire.err.badf), refusalIn(answered[0..wrote]));

    // The name is gone from the mounted directory as well.
    try std.testing.expectError(error.NotOffered, nodeOf(&offered, "secret", &request, &answered));
    try std.testing.expectEqual(@as(u64, 1), offered.withdrawn);
}

test "a name in the mounted directory is one the guest may not remember" {
    const gpa = std.testing.allocator;
    var bench = try Bench.open(gpa);
    defer bench.close();

    var offered = try Export.init(gpa, bench.io);
    defer offered.deinit();
    try offered.offer("secret", bench.at, false);

    var request: [512]u8 = undefined;
    var answered: [4096]u8 = undefined;

    const wrote = offered.answer(ask(&request, .lookup, 1, "secret\x00"), &answered);
    try std.testing.expectEqual(@as(?i32, null), refusalIn(answered[0..wrote]));

    // How long the guest may believe this, both for the name and for what it says about it. Zero, and
    // it has to stay zero: a name the guest remembered would be a directory that outlived being taken
    // back, and one offered for a single piece of work would still be readable after it.
    const entry = answered[wire.Answer.size..];
    try std.testing.expectEqual(@as(u64, 0), std.mem.readInt(u64, entry[16..24], .little));
    try std.testing.expectEqual(@as(u64, 0), std.mem.readInt(u64, entry[24..32], .little));

    // A name inside one of them is ordinary and may be remembered, because what is in a directory is
    // not what may be taken away underneath the guest.
    const inside = try nodeOf(&offered, "secret", &request, &answered);
    const also = offered.answer(ask(&request, .lookup, inside, "hello\x00"), &answered);
    try std.testing.expectEqual(@as(?i32, null), refusalIn(answered[0..also]));
    const ordinary = answered[wire.Answer.size..];
    try std.testing.expect(std.mem.readInt(u64, ordinary[16..24], .little) > 0);
}

test "a node under a withdrawn name resolves to nothing, not to whatever took its place" {
    const gpa = std.testing.allocator;
    var bench = try Bench.open(gpa);
    defer bench.close();

    var offered = try Export.init(gpa, bench.io);
    defer offered.deinit();
    try offered.offer("secret", bench.at, false);

    var request: [512]u8 = undefined;
    var answered: [4096]u8 = undefined;
    const secret = try nodeOf(&offered, "secret", &request, &answered);
    var wrote = offered.answer(ask(&request, .lookup, secret, "hello\x00"), &answered);
    const nodeid = std.mem.readInt(u64, answered[wire.Answer.size..][0..8], .little);

    // Taken back, and another directory offered afterwards, which takes the same slot.
    offered.withdraw("secret");
    const other = try std.fmt.allocPrint(gpa, "{s}-other", .{bench.at});
    defer gpa.free(other);
    std.Io.Dir.cwd().createDir(bench.io, other, .default_dir) catch {};
    defer std.Io.Dir.cwd().deleteTree(bench.io, other) catch {};
    var name: [256]u8 = undefined;
    try std.Io.Dir.cwd().writeFile(bench.io, .{
        .sub_path = try std.fmt.bufPrint(&name, "{s}/hello", .{other}),
        .data = "somebody else's file\n",
    });
    try offered.offer("other", other, false);

    // The nodeid the guest still holds names nothing. Reading through it must not reach the directory
    // that took the slot, which is the one way a guest could be handed a file nobody offered it.
    wrote = offered.answer(ask(&request, .getattr, nodeid, &.{}), &answered);
    try std.testing.expectEqual(@as(?i32, wire.err.noent), refusalIn(answered[0..wrote]));

    var open_in: [8]u8 = @splat(0);
    wrote = offered.answer(ask(&request, .open, nodeid, &open_in), &answered);
    try std.testing.expectEqual(@as(?i32, wire.err.noent), refusalIn(answered[0..wrote]));
}

test "a time the guest sets is the time the host holds" {
    const gpa = std.testing.allocator;
    var bench = try Bench.open(gpa);
    defer bench.close();

    var offered = try Export.init(gpa, bench.io);
    defer offered.deinit();
    try offered.offer("work", bench.at, true);

    var request: [1024]u8 = undefined;
    var answered: [4096]u8 = undefined;
    const work = try nodeOf(&offered, "work", &request, &answered);
    var wrote = offered.answer(ask(&request, .lookup, work, "hello\x00"), &answered);
    const nodeid = std.mem.readInt(u64, answered[wire.Answer.size..][0..8], .little);

    // A build system decides what to rebuild by comparing these, so a filesystem that keeps the old
    // one and reports success makes a cache that is wrong rather than slow.
    const wanted: i64 = 1_000_000_000;
    var setattr_in: [wire.SetAttr.in_size]u8 = @splat(0);
    std.mem.writeInt(u32, setattr_in[0..4], wire.SetAttr.wants_mtime, .little);
    std.mem.writeInt(i64, setattr_in[40..48], wanted, .little);
    wrote = offered.answer(ask(&request, .setattr, nodeid, &setattr_in), &answered);
    try std.testing.expectEqual(@as(?i32, null), refusalIn(answered[0..wrote]));

    var room: [200]u8 = undefined;
    const about = try std.Io.Dir.cwd().statFile(
        bench.io,
        try std.fmt.bufPrint(&room, "{s}/hello", .{bench.at}),
        .{},
    );
    try std.testing.expectEqual(wanted, @divTrunc(about.mtime.nanoseconds, std.time.ns_per_s));

    // And what the answer said about it matches what the host now holds.
    const attr = answered[wire.Answer.size + 16 ..];
    try std.testing.expectEqual(@as(u64, @bitCast(wanted)), std.mem.readInt(u64, attr[24..32], .little));
}

test "a second name for a file is a second name, not a second copy" {
    const gpa = std.testing.allocator;
    var bench = try Bench.open(gpa);
    defer bench.close();

    var offered = try Export.init(gpa, bench.io);
    defer offered.deinit();
    try offered.offer("work", bench.at, true);

    var request: [1024]u8 = undefined;
    var answered: [4096]u8 = undefined;
    const work = try nodeOf(&offered, "work", &request, &answered);
    var wrote = offered.answer(ask(&request, .lookup, work, "hello\x00"), &answered);
    const nodeid = std.mem.readInt(u64, answered[wire.Answer.size..][0..8], .little);

    // A package manager, a build cache and a version control system all do this rather than copying,
    // so a filesystem without it makes them fall back or fail.
    var link_in: [8 + 8]u8 = @splat(0);
    std.mem.writeInt(u64, link_in[0..8], nodeid, .little);
    @memcpy(link_in[8..][0..7], "also\x00\x00\x00");
    wrote = offered.answer(ask(&request, .link, work, &link_in), &answered);
    try std.testing.expectEqual(@as(?i32, null), refusalIn(answered[0..wrote]));

    // Two names, one file: the same contents and a link count above one.
    var room: [200]u8 = undefined;
    const said = try std.Io.Dir.cwd().readFileAlloc(
        bench.io,
        try std.fmt.bufPrint(&room, "{s}/also", .{bench.at}),
        gpa,
        .limited(1024),
    );
    defer gpa.free(said);
    try std.testing.expectEqualSlices(u8, "a store path's contents\n", said);
    const attr = answered[wire.Answer.size + 40 ..];
    try std.testing.expect(std.mem.readInt(u32, attr[64..68], .little) >= 2);
}

test "a share nobody made writable refuses a second name too" {
    const gpa = std.testing.allocator;
    var bench = try Bench.open(gpa);
    defer bench.close();

    var offered = try Export.init(gpa, bench.io);
    defer offered.deinit();
    try offered.offer("store", bench.at, false);

    var request: [1024]u8 = undefined;
    var answered: [4096]u8 = undefined;
    const store = try nodeOf(&offered, "store", &request, &answered);
    const wrote = offered.answer(ask(&request, .lookup, store, "hello\x00"), &answered);
    const nodeid = std.mem.readInt(u64, answered[wire.Answer.size..][0..8], .little);

    var link_in: [16]u8 = @splat(0);
    std.mem.writeInt(u64, link_in[0..8], nodeid, .little);
    @memcpy(link_in[8..][0..5], "also\x00");
    const refused = offered.answer(ask(&request, .link, store, &link_in), &answered);
    try std.testing.expectEqual(@as(?i32, wire.err.rofs), refusalIn(answered[0..refused]));
    _ = wrote;
}

test "the guest is told there is room to work in" {
    const gpa = std.testing.allocator;
    var bench = try Bench.open(gpa);
    defer bench.close();

    var offered = try Export.init(gpa, bench.io);
    defer offered.deinit();
    try offered.offer("work", bench.at, true);

    var request: [1024]u8 = undefined;
    var answered: [4096]u8 = undefined;
    const wrote = offered.answer(ask(&request, .statfs, 1, &.{}), &answered);
    try std.testing.expectEqual(@as(?i32, null), refusalIn(answered[0..wrote]));

    // Not the host's real numbers, but never zero: a program told there is no room refuses to start
    // rather than trying and being told no, and the second is the answer a guest should get.
    const said = answered[wire.Answer.size..];
    try std.testing.expect(std.mem.readInt(u64, said[0..8], .little) > 0);
    try std.testing.expect(std.mem.readInt(u64, said[8..16], .little) > 0);
    try std.testing.expectEqual(@as(u32, 4096), std.mem.readInt(u32, said[40..44], .little));
}

test "a guest that makes and forgets many files does not grow this without bound" {
    const gpa = std.testing.allocator;
    var bench = try Bench.open(gpa);
    defer bench.close();

    var offered = try Export.init(gpa, bench.io);
    defer offered.deinit();
    try offered.offer("work", bench.at, true);

    var request: [1024]u8 = undefined;
    var answered: [4096]u8 = undefined;
    const work = try nodeOf(&offered, "work", &request, &answered);

    // A build makes temporary files, uses them and takes them away, and a guest held up for a whole
    // session does that for hours. Every distinct name it ever used must not stay here.
    var rounds: usize = 0;
    while (rounds < 400) : (rounds += 1) {
        var name: [64]u8 = undefined;
        const called = try std.fmt.bufPrint(&name, "temp-{d}\x00", .{rounds});

        var create_in: [wire.Create.in_size + 64]u8 = @splat(0);
        std.mem.writeInt(u32, create_in[0..4], 0o101, .little);
        std.mem.writeInt(u32, create_in[4..8], 0o100644, .little);
        @memcpy(create_in[wire.Create.in_size..][0..called.len], called);
        var wrote = offered.answer(ask(&request, .create, work, &create_in), &answered);
        try std.testing.expectEqual(@as(?i32, null), refusalIn(answered[0..wrote]));
        const nodeid = std.mem.readInt(u64, answered[wire.Answer.size..][0..8], .little);
        const handle = std.mem.readInt(u64, answered[wire.Answer.size + wire.Entry.size ..][0..8], .little);

        var release_in: [24]u8 = @splat(0);
        std.mem.writeInt(u64, release_in[0..8], handle, .little);
        _ = offered.answer(ask(&request, .release, nodeid, &release_in), &answered);

        wrote = offered.answer(ask(&request, .unlink, work, called), &answered);
        try std.testing.expectEqual(@as(?i32, null), refusalIn(answered[0..wrote]));

        // The kernel saying it has finished with the name, which is what lets this end let go.
        var forget_in: [8]u8 = @splat(0);
        std.mem.writeInt(u64, forget_in[0..8], 1, .little);
        _ = offered.answer(ask(&request, .forget, nodeid, &forget_in), &answered);
    }

    // Four hundred names, every one of them gone. What is held should be a handful, not four hundred:
    // a guest that works for an hour would otherwise grow this until the machine noticed.
    try std.testing.expect(offered.nodes.items.len < 50);
    try std.testing.expect(offered.known.count() < 50);
}
