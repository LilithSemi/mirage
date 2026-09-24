//! A virtio balloon, which is how a guest's memory grows and shrinks while it runs.
//!
//! The guest is given its whole eventual size in its memory map and the balloon holds
//! everything above what it may use now. Growing is the balloon giving pages back;
//! shrinking is the balloon taking them. One device does both, where adding memory to a
//! running guest would need hot plug support the guest may not have.
//!
//! Whoever started the guest sets a target and tells the guest the configuration changed.
//! The guest then hands pages over on the inflate queue, or asks for them back on the
//! deflate queue, and reports how many it really has. The two counts disagree while it
//! works, and the guest is never obliged to reach the target: a guest under pressure may
//! refuse, which is the point of `DEFLATE_ON_OOM`.
//!
//! Every page number comes from the guest, so one outside the memory it was given is
//! refused rather than handed to the host to release.
//!
//! Releasing host memory is not done here. This module is portable and may not make a
//! syscall, so it records which pages went into the balloon and whoever is above it decides
//! what to do about them.
//!
//! Two things a caller should expect. A guest holds pages the balloon asked for whether or
//! not the host ever gets them back, so the limit is enforced either way. But the balloon
//! counts in 4096 byte pages while a host gives memory up one of **its** pages at a time,
//! and on this architecture those are often 65536 bytes. A guest that hands over scattered
//! single pages then returns almost nothing to the host: measured on an Ampere Altra with a
//! 4K page guest, 139MB given up yielded 4MB back, because 34386 of 34392 runs were shorter
//! than one host page. A guest built with pages the size of the host's does far better.

const std = @import("std");
const testing = @import("mirage-testing");
const Bus = @import("../Bus.zig");
const Mmio = @import("Mmio.zig");
const Queue = @import("Queue.zig");
const Service = @import("../../mirage-device.zig").Service;
const GuestMemory = @import("mirage-memory").GuestMemory;

const Balloon = @This();

/// `VIRTIO_ID_BALLOON`.
const device_id = 5;
/// `VIRTIO_F_VERSION_1`. A modern driver refuses a device that does not offer it.
const feature_version_1: u64 = 1 << 32;
/// `VIRTIO_BALLOON_F_MUST_TELL_HOST`. The guest promises to ask before it uses a page it
/// gave up. Without this promise a host that throws the page away corrupts guest memory,
/// so a caller may only release what it holds when this is offered and accepted.
const feature_must_tell_host: u64 = 1 << 0;
/// `VIRTIO_BALLOON_F_DEFLATE_ON_OOM`. Lets a guest take pages back when it would otherwise
/// kill a process. Without it a balloon can put a guest under pressure it cannot escape.
const feature_deflate_on_oom: u64 = 1 << 2;

/// The balloon counts in 4096 byte pages whatever the guest's own page size is.
pub const page_size = 4096;

pub const queue_inflate = 0;
pub const queue_deflate = 1;
pub const queue_count = 2;

/// How many page numbers one buffer from the driver carries. `VIRTIO_BALLOON_ARRAY_PFNS_MAX`
/// in Linux. The pages in one of those are wherever the guest allocator found them, so in
/// the worst case each one is its own run and none of them join.
pub const batch = 256;

/// How many page ranges are held for the caller at once. At least one whole batch, so a
/// chain is never recorded by halves, and a little more so a caller has room to drain at its
/// own pace. A caller that never drains stops the balloon taking more, which is back
/// pressure rather than an allocation that grows on the guest's say so.
pub const max_pending = batch * 2;

pub const Error = Queue.Error;

/// A run of pages the guest handed over, in guest physical addresses.
pub const Range = struct {
    start: u64,
    len: u64,

    /// The part of this run that a host with pages of `host_page` bytes can actually take
    /// back, or nothing when there is none.
    ///
    /// A host cannot give up less than one of its own pages, so a run has to be trimmed to
    /// whole aligned ones. When the host's pages are larger than the balloon's, which is
    /// the usual case on this architecture, a guest handing over scattered single pages
    /// yields nothing at all. That is a property of the two page sizes and not a fault:
    /// the guest is still held to its limit, the host simply gets none of it back.
    pub fn hostAligned(self: Range, host_page: u64) ?Range {
        const from = std.mem.alignForward(u64, self.start, host_page);
        const to = std.mem.alignBackward(u64, self.start + self.len, host_page);
        if (to <= from) return null;
        return .{ .start = from, .len = to - from };
    }
};

mmio: Mmio,
queues: [queue_count]Queue,
/// The target then what the guest reports, as the configuration space holds them. The
/// first is this side's to write and the second is the guest's.
config: [8]u8,

/// Where the guest's memory starts and ends. A page number outside this is refused, so a
/// guest cannot name host memory it was never given.
ram_base: u64,
ram_size: u64,

/// Ranges the guest has handed over that the caller has not taken yet.
pending: [max_pending]Range,
pending_len: usize,
/// Pages the guest gave back that were refused, and queue entries that made no sense.
refused: u64,
dropped: u64,

/// Initialised in place, never returned by value. The transport points at `queues` and
/// `config` inside this same struct, and a value that is copied leaves those pointers
/// aimed at wherever the old copy used to be.
pub fn init(self: *Balloon, ram_base: u64, ram_size: u64) void {
    self.ram_base = ram_base;
    self.ram_size = ram_size;
    self.pending_len = 0;
    self.refused = 0;
    self.dropped = 0;

    @memset(&self.config, 0);
    self.queues = @splat(.{ .size = 0, .descriptor = 0, .available = 0, .used = 0 });
    self.mmio = .{
        .device_id = device_id,
        .device_features = feature_version_1 | feature_must_tell_host | feature_deflate_on_oom,
        .config = &self.config,
        // The guest owns the second word, where it says how many pages it really has.
        .config_writable_from = 4,
        .queues = &self.queues,
    };
}

pub fn device(self: *Balloon, at: u64) Bus.Device {
    return self.mmio.device(at);
}

/// Hand this to a run loop so it can serve the queues without knowing what kind of device
/// is behind it.
pub fn service(self: *Balloon, intid: u32) Service {
    return .{ .ctx = self, .intid = intid, .poll = Balloon.askPoll };
}

fn askPoll(ctx: *anyopaque, memory: *GuestMemory) Service.Error!bool {
    const self: *Balloon = @ptrCast(@alignCast(ctx));
    _ = try self.serve(memory);
    return self.mmio.interrupt_status != 0;
}

/// How many pages the balloon is asked to hold.
pub fn target(self: *const Balloon) u32 {
    return std.mem.readInt(u32, self.config[0..4], .little);
}

/// How many pages the guest says it has handed over. The guest writes this, so it is what
/// the guest claims and not what this side counted.
pub fn reported(self: *const Balloon) u32 {
    return std.mem.readInt(u32, self.config[4..8], .little);
}

/// Ask the guest to hold this many pages. Raising it takes memory away from the guest and
/// lowering it gives memory back, which is how a guest grows.
///
/// The guest only looks when it is told the configuration changed, so this says so. It is
/// a request: a guest may take its time, and a guest under pressure may refuse.
pub fn setTarget(self: *Balloon, pages: u32) void {
    std.mem.writeInt(u32, self.config[0..4], pages, .little);
    self.mmio.raiseConfig();
}

/// How many bytes of the guest's memory the balloon is asked to hold.
pub fn targetBytes(self: *const Balloon) u64 {
    return @as(u64, self.target()) * page_size;
}

/// Take the ranges the guest has handed over. Returns how many went into `into`. Until
/// these are taken the balloon stops accepting more, so a caller that never drains them
/// does not grow this device.
pub fn take(self: *Balloon, into: []Range) usize {
    const count = @min(into.len, self.pending_len);
    if (count == 0) return 0;

    @memcpy(into[0..count], self.pending[0..count]);
    const left = self.pending_len - count;
    std.mem.copyForwards(Range, self.pending[0..left], self.pending[count..self.pending_len]);
    self.pending_len = left;
    return count;
}

/// Whether the guest agreed to ask before reusing a page it gave up. A caller that throws
/// away what it holds without this corrupts guest memory.
pub fn mayRelease(self: *const Balloon) bool {
    return self.mmio.driver_features & feature_must_tell_host != 0;
}

/// Read both queues. Returns how many chains were served.
pub fn serve(self: *Balloon, memory: *GuestMemory) Error!u32 {
    var served: u32 = 0;
    if (self.mmio.rang(queue_inflate)) {
        self.mmio.served(queue_inflate);
        served += try self.drain(memory, queue_inflate);
    }
    if (self.mmio.rang(queue_deflate)) {
        self.mmio.served(queue_deflate);
        served += try self.drain(memory, queue_deflate);
    }
    if (served > 0) self.mmio.raise();
    return served;
}

/// Read one queue. Both carry the same thing, a list of page numbers; which queue it
/// arrived on says whether the guest is giving pages up or taking them back.
fn drain(self: *Balloon, memory: *GuestMemory, which: usize) Error!u32 {
    const queue = &self.queues[which];
    if (!queue.ready) return 0;

    var served: u32 = 0;
    while (true) {
        // Only start a chain there is room for the whole of. Half a chain recorded is pages
        // the guest believes are held and that this side never hands back.
        if (which == queue_inflate and self.pending.len - self.pending_len < batch) break;

        const head = (try queue.next(memory)) orelse break;
        var chain = queue.walk(head);
        served += 1;

        while (try chain.next(memory)) |segment| {
            var at: u32 = 0;
            while (at + 4 <= segment.len) : (at += 4) {
                var bytes: [4]u8 = undefined;
                try memory.read(segment.addr + at, &bytes);
                const pfn = std.mem.readInt(u32, &bytes, .little);
                if (which == queue_inflate) self.hold(pfn) else self.release(pfn);
            }
        }

        try queue.complete(memory, head, 0);
    }
    return served;
}

/// The guest gave up one page. The page number is the guest's, so it is checked against
/// the memory the guest was actually given.
fn hold(self: *Balloon, pfn: u32) void {
    const address = @as(u64, pfn) * page_size;
    if (address < self.ram_base or address + page_size > self.ram_base + self.ram_size) {
        self.refused += 1;
        return;
    }

    // A guest hands pages over in order more often than not, so a run that carries on from
    // the last one is joined to it rather than taking another slot.
    if (self.pending_len > 0) {
        const last = &self.pending[self.pending_len - 1];
        if (last.start + last.len == address) {
            last.len += page_size;
            return;
        }
    }

    if (self.pending_len == self.pending.len) {
        // Nobody has taken what is already here. Refusing is back pressure; growing this
        // list on the guest's say so is not.
        self.refused += 1;
        return;
    }
    self.pending[self.pending_len] = .{ .start = address, .len = page_size };
    self.pending_len += 1;
}

/// The guest took one page back. Whatever the caller did with it has to be undone before
/// the guest touches it, and the caller is the only one that knows what that was, so this
/// only stops the page being handed over again.
fn release(self: *Balloon, pfn: u32) void {
    const address = @as(u64, pfn) * page_size;
    var index: usize = 0;
    while (index < self.pending_len) : (index += 1) {
        const range = &self.pending[index];
        if (address < range.start or address >= range.start + range.len) continue;

        // The page is in the middle of a run, so the run loses its tail rather than being
        // split. The tail is offered again on the next pass if the guest still wants it
        // held, which is the safe way round: a page the caller never released is a page
        // nothing has to undo.
        range.len = address - range.start;
        if (range.len == 0) {
            const left = self.pending_len - index - 1;
            std.mem.copyForwards(Range, self.pending[index .. index + left], self.pending[index + 1 .. self.pending_len]);
            self.pending_len -= 1;
        }
        return;
    }
}

const test_base = 0x4000_0000;
const test_size = 16 * page_size;

/// A guest with an inflate and a deflate ring, laid out the way a driver lays them out.
const Fixture = struct {
    ram: []u8,
    memory: GuestMemory,
    regions: [1]GuestMemory.Region,
    balloon: Balloon,
    published: [queue_count]u16,
    taken: [queue_count]u16,

    /// Where the rings sit, above the memory the guest is told it has so the two do not
    /// overlap.
    const rings = test_size;
    const size = rings + 0x9000;

    fn ringOf(which: usize, part: usize) u64 {
        // Four pages per queue: descriptor, available, used, and a buffer.
        return test_base + rings + (which * 4 + part) * 0x1000;
    }

    fn init(self: *Fixture, gpa: std.mem.Allocator) !void {
        self.published = @splat(0);
        self.taken = @splat(0);

        self.ram = try gpa.alloc(u8, size);
        @memset(self.ram, 0);
        self.regions = .{.{ .gpa = test_base, .len = size, .backing = .{ .shared = self.ram } }};
        self.memory = .{ .regions = &self.regions };

        // The balloon is told the guest has `test_size`, which is less than the region, so
        // a page number past it is one the guest never had.
        self.balloon.init(test_base, test_size);

        for (0..queue_count) |which| {
            self.balloon.queues[which] = .{
                .size = 1,
                .descriptor = ringOf(which, 0),
                .available = ringOf(which, 1),
                .used = ringOf(which, 2),
                .ready = true,
            };
        }
    }

    fn deinit(self: *Fixture, gpa: std.mem.Allocator) void {
        gpa.free(self.ram);
    }

    fn at(self: *Fixture, address: u64) []u8 {
        return self.ram[@intCast(address - test_base)..];
    }

    /// Put a list of page numbers on one queue and ring its doorbell.
    fn hand(self: *Fixture, which: usize, pages: []const u32) void {
        const buffer = self.at(ringOf(which, 3));
        for (pages, 0..) |pfn, index| {
            std.mem.writeInt(u32, buffer[index * 4 ..][0..4], pfn, .little);
        }

        const entry = self.at(ringOf(which, 0));
        std.mem.writeInt(u64, entry[0..8], ringOf(which, 3), .little);
        std.mem.writeInt(u32, entry[8..12], @intCast(pages.len * 4), .little);
        std.mem.writeInt(u16, entry[12..14], 0, .little);
        std.mem.writeInt(u16, entry[14..16], 0, .little);

        const ring = self.at(ringOf(which, 1));
        self.published[which] += 1;
        std.mem.writeInt(u16, ring[2..4], self.published[which], .little);
        std.mem.writeInt(u16, ring[4..6], 0, .little);

        self.balloon.mmio.notified |= @as(u32, 1) << @intCast(which);
    }

    /// The page number of one page inside the guest's memory.
    fn pageOf(index: u32) u32 {
        return @intCast((test_base / page_size) + index);
    }
};

test "the register file says this is a balloon" {
    const gpa = testing.allocator();
    var fixture: Fixture = undefined;
    try fixture.init(gpa);
    defer fixture.deinit(gpa);

    var devices = [_]Bus.Device{fixture.balloon.device(0x0a00_0400)};
    var bus: Bus = .{ .devices = &devices };

    try testing.expectEqual(@as(u64, device_id), bus.read(0x0a00_0400 + 0x008, .word));
}

test "a target the caller sets is what the guest reads, and the guest is told it moved" {
    const gpa = testing.allocator();
    var fixture: Fixture = undefined;
    try fixture.init(gpa);
    defer fixture.deinit(gpa);

    var devices = [_]Bus.Device{fixture.balloon.device(0x0a00_0400)};
    var bus: Bus = .{ .devices = &devices };

    fixture.balloon.setTarget(4);
    try testing.expectEqual(@as(u64, 4), bus.read(0x0a00_0400 + 0x100, .word));
    try testing.expectEqual(@as(u32, 4), fixture.balloon.target());
    try testing.expectEqual(@as(u64, 4 * page_size), fixture.balloon.targetBytes());

    // The interrupt says the configuration changed and not that a queue was used. A guest
    // told the wrong one looks in the wrong place and never sees the new target.
    try testing.expectEqual(@as(u64, 2), bus.read(0x0a00_0400 + 0x060, .word));
}

test "the guest writes how many pages it really gave and the device reads it back" {
    const gpa = testing.allocator();
    var fixture: Fixture = undefined;
    try fixture.init(gpa);
    defer fixture.deinit(gpa);

    var devices = [_]Bus.Device{fixture.balloon.device(0x0a00_0400)};
    var bus: Bus = .{ .devices = &devices };

    // The second word of the configuration space belongs to the guest.
    bus.write(0x0a00_0400 + 0x104, .word, 3);
    try testing.expectEqual(@as(u32, 3), fixture.balloon.reported());

    // The first word does not. A guest that could write it would be telling this side
    // something this side decided.
    bus.write(0x0a00_0400 + 0x100, .word, 99);
    try testing.expectEqual(@as(u32, 0), fixture.balloon.target());
}

test "pages the guest hands over are held for the caller as one run" {
    const gpa = testing.allocator();
    var fixture: Fixture = undefined;
    try fixture.init(gpa);
    defer fixture.deinit(gpa);

    fixture.balloon.setTarget(3);
    fixture.hand(queue_inflate, &.{ Fixture.pageOf(0), Fixture.pageOf(1), Fixture.pageOf(2) });
    _ = try fixture.balloon.serve(&fixture.memory);

    // Three pages that follow one another, so one run rather than three.
    var ranges: [8]Range = undefined;
    try testing.expectEqual(@as(usize, 1), fixture.balloon.take(&ranges));
    try testing.expectEqual(@as(u64, test_base), ranges[0].start);
    try testing.expectEqual(@as(u64, 3 * page_size), ranges[0].len);

    // Taken once. A caller that is given the same page twice releases it twice.
    try testing.expectEqual(@as(usize, 0), fixture.balloon.take(&ranges));
}

test "pages that do not follow one another are held apart" {
    const gpa = testing.allocator();
    var fixture: Fixture = undefined;
    try fixture.init(gpa);
    defer fixture.deinit(gpa);

    fixture.hand(queue_inflate, &.{ Fixture.pageOf(0), Fixture.pageOf(4) });
    _ = try fixture.balloon.serve(&fixture.memory);

    var ranges: [8]Range = undefined;
    try testing.expectEqual(@as(usize, 2), fixture.balloon.take(&ranges));
    try testing.expectEqual(@as(u64, test_base), ranges[0].start);
    try testing.expectEqual(@as(u64, page_size), ranges[0].len);
    try testing.expectEqual(@as(u64, test_base + 4 * page_size), ranges[1].start);
}

test "a page outside the memory the guest was given is refused" {
    const gpa = testing.allocator();
    var fixture: Fixture = undefined;
    try fixture.init(gpa);
    defer fixture.deinit(gpa);

    // The page number comes from the guest. A device that believes it hands the caller
    // host memory to release that the guest never had.
    fixture.hand(queue_inflate, &.{ 0, Fixture.pageOf(1000), Fixture.pageOf(2) });
    _ = try fixture.balloon.serve(&fixture.memory);

    var ranges: [8]Range = undefined;
    try testing.expectEqual(@as(usize, 1), fixture.balloon.take(&ranges));
    try testing.expectEqual(@as(u64, test_base + 2 * page_size), ranges[0].start);
    try testing.expectEqual(@as(u64, 2), fixture.balloon.refused);
}

test "a page the guest takes back stops being held" {
    const gpa = testing.allocator();
    var fixture: Fixture = undefined;
    try fixture.init(gpa);
    defer fixture.deinit(gpa);

    fixture.hand(queue_inflate, &.{ Fixture.pageOf(0), Fixture.pageOf(1) });
    _ = try fixture.balloon.serve(&fixture.memory);

    // Lowering the target is how a guest grows, and the guest answers on the deflate
    // queue.
    fixture.hand(queue_deflate, &.{Fixture.pageOf(1)});
    _ = try fixture.balloon.serve(&fixture.memory);

    var ranges: [8]Range = undefined;
    try testing.expectEqual(@as(usize, 1), fixture.balloon.take(&ranges));
    try testing.expectEqual(@as(u64, test_base), ranges[0].start);
    try testing.expectEqual(@as(u64, page_size), ranges[0].len);
}

test "a caller that never takes the ranges stops the balloon rather than growing it" {
    const gpa = testing.allocator();
    var fixture: Fixture = undefined;
    try fixture.init(gpa);
    defer fixture.deinit(gpa);

    // Pages that do not follow one another, so each one takes a slot. More of them than
    // the list holds, and nobody takes any.
    var pages: [max_pending + 8]u32 = undefined;
    for (&pages, 0..) |*pfn, index| pfn.* = Fixture.pageOf(@intCast(index * 2));

    // The guest was given sixteen pages, so most of these are outside it and refused for
    // that reason. The point here is that the list stops at its size either way.
    fixture.hand(queue_inflate, &pages);
    _ = try fixture.balloon.serve(&fixture.memory);

    try std.testing.expect(fixture.balloon.pending_len <= max_pending);
    try std.testing.expect(fixture.balloon.refused > 0);
}

test "a queue entry shorter than one page number is served rather than read past" {
    const gpa = testing.allocator();
    var fixture: Fixture = undefined;
    try fixture.init(gpa);
    defer fixture.deinit(gpa);

    // The driver chose this length. A device that reads four bytes anyway reads whatever
    // follows the buffer in guest memory.
    fixture.hand(queue_inflate, &.{});
    const entry = fixture.at(Fixture.ringOf(queue_inflate, 0));
    std.mem.writeInt(u32, entry[8..12], 2, .little);

    try testing.expectEqual(@as(u32, 1), try fixture.balloon.serve(&fixture.memory));
    try testing.expectEqual(@as(usize, 0), fixture.balloon.pending_len);
}

test "the caller may only release pages once the guest promised to ask for them back" {
    const gpa = testing.allocator();
    var fixture: Fixture = undefined;
    try fixture.init(gpa);
    defer fixture.deinit(gpa);

    var devices = [_]Bus.Device{fixture.balloon.device(0x0a00_0400)};
    var bus: Bus = .{ .devices = &devices };

    // Nothing agreed yet, so nothing may be thrown away. A host that discards a page the
    // guest may still reuse without asking corrupts the guest.
    try std.testing.expect(!fixture.balloon.mayRelease());

    // The driver accepts the low feature word, which is where the promise lives.
    bus.write(0x0a00_0400 + 0x024, .word, 0);
    bus.write(0x0a00_0400 + 0x020, .word, 1);
    try std.testing.expect(fixture.balloon.mayRelease());
}

test "only whole aligned pages of the host can be given back" {
    // A host whose pages are the same size as the balloon's takes back everything.
    const one: Range = .{ .start = test_base, .len = page_size };
    const same = one.hostAligned(page_size).?;
    try testing.expectEqual(@as(u64, test_base), same.start);
    try testing.expectEqual(@as(u64, page_size), same.len);

    // A host with larger pages takes back nothing from a run shorter than one of them.
    // This is the usual case on this architecture and it is why a guest handing over
    // scattered single pages returns less than it gave up.
    try std.testing.expect(one.hostAligned(16 * page_size) == null);

    // A run that spans a whole large page gives up that page and keeps the ragged ends.
    const spanning: Range = .{
        .start = test_base + 3 * page_size,
        .len = 40 * page_size,
    };
    const trimmed = spanning.hostAligned(16 * page_size).?;
    try testing.expectEqual(@as(u64, test_base + 16 * page_size), trimmed.start);
    try testing.expectEqual(@as(u64, 16 * page_size), trimmed.len);

    // Aligned at both ends, so nothing is lost to the trim.
    const whole: Range = .{ .start = test_base, .len = 32 * page_size };
    const kept = whole.hostAligned(16 * page_size).?;
    try testing.expectEqual(@as(u64, test_base), kept.start);
    try testing.expectEqual(@as(u64, 32 * page_size), kept.len);
}
