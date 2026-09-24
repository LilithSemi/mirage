//! A split virtqueue, read from guest memory.
//!
//! Every field below is written by the guest, so every field is untrusted. A
//! descriptor index is bounded by the queue size, a chain is bounded by the queue
//! size, and a buffer is borrowed through `GuestMemory` so a bad address is refused
//! rather than followed. A queue that trusts the driver is a queue that reads host
//! memory on request.
//!
//! The rings are little endian on the wire whatever the host is, because the
//! specification says so, so every read names its byte order.

const std = @import("std");
const testing = @import("mirage-testing");
const GuestMemory = @import("mirage-memory").GuestMemory;

const Queue = @This();

/// The descriptor continues into `next`.
pub const flag_next: u16 = 1;
/// The device writes this descriptor, the driver only reads it.
pub const flag_write: u16 = 2;

pub const Descriptor = extern struct {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
};

/// One buffer of a chain, already bounds checked.
pub const Segment = struct {
    addr: u64,
    len: u32,
    writable: bool,
};

pub const Error = error{
    /// The driver named a descriptor outside the queue.
    BadDescriptor,
    /// The chain is longer than the queue holds, so it loops.
    ChainTooLong,
} || GuestMemory.Error;

size: u16,
descriptor: u64,
available: u64,
used: u64,
ready: bool = false,
/// How far into the available ring this device has read.
last_available: u16 = 0,

fn readU16(memory: *const GuestMemory, at: u64) Error!u16 {
    var bytes: [2]u8 = undefined;
    try memory.read(at, &bytes);
    return std.mem.readInt(u16, &bytes, .little);
}

fn writeU16(memory: *GuestMemory, at: u64, value: u16) Error!void {
    var bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &bytes, value, .little);
    try memory.write(at, &bytes);
}

fn writeU32(memory: *GuestMemory, at: u64, value: u32) Error!void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    try memory.write(at, &bytes);
}

pub fn descriptorAt(self: *const Queue, memory: *const GuestMemory, index: u16) Error!Descriptor {
    if (index >= self.size) return Error.BadDescriptor;

    var bytes: [@sizeOf(Descriptor)]u8 = undefined;
    try memory.read(self.descriptor + @as(u64, index) * @sizeOf(Descriptor), &bytes);
    return .{
        .addr = std.mem.readInt(u64, bytes[0..8], .little),
        .len = std.mem.readInt(u32, bytes[8..12], .little),
        .flags = std.mem.readInt(u16, bytes[12..14], .little),
        .next = std.mem.readInt(u16, bytes[14..16], .little),
    };
}

/// The head of the next chain the driver published, or nothing.
pub fn next(self: *Queue, memory: *GuestMemory) Error!?u16 {
    const published = try readU16(memory, self.available + 2);
    if (published == self.last_available) return null;

    const slot = self.last_available % self.size;
    const head = try readU16(memory, self.available + 4 + @as(u64, slot) * 2);
    if (head >= self.size) return Error.BadDescriptor;

    self.last_available +%= 1;
    return head;
}

pub const Walk = struct {
    queue: *const Queue,
    index: u16,
    done: bool,
    steps: u16 = 0,

    pub fn next(self: *Walk, memory: *const GuestMemory) Error!?Segment {
        if (self.done) return null;

        // A chain cannot be longer than the queue, so one that is has a cycle in it.
        if (self.steps >= self.queue.size) return Error.ChainTooLong;
        self.steps += 1;

        const desc = try self.queue.descriptorAt(memory, self.index);
        if (desc.flags & flag_next != 0) {
            self.index = desc.next;
        } else {
            self.done = true;
        }

        return .{
            .addr = desc.addr,
            .len = desc.len,
            .writable = desc.flags & flag_write != 0,
        };
    }
};

pub fn walk(self: *const Queue, head: u16) Walk {
    return .{ .queue = self, .index = head, .done = false };
}

/// Tell the driver the chain is finished, and how much was written into it.
pub fn complete(self: *Queue, memory: *GuestMemory, head: u16, written: u32) Error!void {
    const index = try readU16(memory, self.used + 2);
    const slot = index % self.size;
    const at = self.used + 4 + @as(u64, slot) * 8;

    try writeU32(memory, at, head);
    try writeU32(memory, at + 4, written);
    // The counter moves last, because the driver reads it to decide the entry above
    // is there at all.
    try writeU16(memory, self.used + 2, index +% 1);
}
const base = 0x4000_0000;
const ring_size = 4;

/// A queue laid out in guest memory the way a driver would lay it out.
const Fixture = struct {
    bytes: [4096]u8 = @splat(0),
    regions: [1]GuestMemory.Region = undefined,

    const desc_at = base + 0x000;
    const avail_at = base + 0x100;
    const used_at = base + 0x200;
    const buffer_at = base + 0x300;

    fn memory(self: *Fixture) GuestMemory {
        self.regions = .{.{ .gpa = base, .len = self.bytes.len, .backing = .{ .shared = &self.bytes } }};
        return .{ .regions = &self.regions };
    }

    fn queue(self: *Fixture) Queue {
        _ = self;
        return .{
            .size = ring_size,
            .descriptor = desc_at,
            .available = avail_at,
            .used = used_at,
            .ready = true,
        };
    }

    fn putDescriptor(self: *Fixture, index: u16, desc: Descriptor) void {
        const at = 0x000 + @as(usize, index) * @sizeOf(Descriptor);
        std.mem.writeInt(u64, self.bytes[at..][0..8], desc.addr, .little);
        std.mem.writeInt(u32, self.bytes[at + 8 ..][0..4], desc.len, .little);
        std.mem.writeInt(u16, self.bytes[at + 12 ..][0..2], desc.flags, .little);
        std.mem.writeInt(u16, self.bytes[at + 14 ..][0..2], desc.next, .little);
    }

    /// Publish one head index in the available ring and bump its counter.
    fn publish(self: *Fixture, head: u16, index: u16) void {
        const ring = 0x100 + 4 + @as(usize, index % ring_size) * 2;
        std.mem.writeInt(u16, self.bytes[ring..][0..2], head, .little);
        std.mem.writeInt(u16, self.bytes[0x100 + 2 ..][0..2], index + 1, .little);
    }

    fn usedIndex(self: *const Fixture) u16 {
        return std.mem.readInt(u16, self.bytes[0x200 + 2 ..][0..2], .little);
    }
};

test "a queue with nothing published hands back nothing" {
    var f: Fixture = .{};
    var memory = f.memory();
    var queue = f.queue();

    try testing.expectEqual(@as(?u16, null), try queue.next(&memory));
}

test "a published chain is handed back once and not twice" {
    var f: Fixture = .{};
    f.putDescriptor(0, .{ .addr = Fixture.buffer_at, .len = 16, .flags = 0, .next = 0 });
    f.publish(0, 0);

    var memory = f.memory();
    var queue = f.queue();

    try testing.expectEqual(@as(?u16, 0), try queue.next(&memory));
    try testing.expectEqual(@as(?u16, null), try queue.next(&memory));
}

test "a chain walks through every descriptor the driver linked" {
    var f: Fixture = .{};
    f.putDescriptor(0, .{ .addr = Fixture.buffer_at, .len = 16, .flags = flag_next, .next = 1 });
    f.putDescriptor(1, .{ .addr = Fixture.buffer_at + 16, .len = 32, .flags = flag_next | flag_write, .next = 2 });
    f.putDescriptor(2, .{ .addr = Fixture.buffer_at + 48, .len = 1, .flags = flag_write, .next = 0 });
    f.publish(0, 0);

    var memory = f.memory();
    var queue = f.queue();

    const head = (try queue.next(&memory)).?;
    var chain = queue.walk(head);

    const first = (try chain.next(&memory)).?;
    try testing.expectEqual(@as(u32, 16), first.len);
    try std.testing.expect(!first.writable);

    const second = (try chain.next(&memory)).?;
    try testing.expectEqual(@as(u32, 32), second.len);
    try std.testing.expect(second.writable);

    const third = (try chain.next(&memory)).?;
    try testing.expectEqual(@as(u32, 1), third.len);

    try testing.expectEqual(@as(?Segment, null), try chain.next(&memory));
}

test "a descriptor index past the end of the queue is refused" {
    var f: Fixture = .{};
    f.publish(ring_size + 7, 0);

    var memory = f.memory();
    var queue = f.queue();

    // The driver chose this index. A queue that trusts it reads memory it was never
    // given.
    try testing.expectError(error.BadDescriptor, queue.next(&memory));
}

test "a chain that points at itself is refused rather than followed forever" {
    var f: Fixture = .{};
    f.putDescriptor(0, .{ .addr = Fixture.buffer_at, .len = 8, .flags = flag_next, .next = 1 });
    f.putDescriptor(1, .{ .addr = Fixture.buffer_at, .len = 8, .flags = flag_next, .next = 0 });
    f.publish(0, 0);

    var memory = f.memory();
    var queue = f.queue();
    const head = (try queue.next(&memory)).?;
    var chain = queue.walk(head);

    var seen: usize = 0;
    while (chain.next(&memory) catch |err| {
        try testing.expectEqual(error.ChainTooLong, err);
        return;
    }) |_| {
        seen += 1;
        if (seen > ring_size * 2) return error.TestUnexpectedResult;
    }
    return error.TestUnexpectedResult;
}

test "a completed chain is written to the used ring" {
    var f: Fixture = .{};
    f.putDescriptor(0, .{ .addr = Fixture.buffer_at, .len = 16, .flags = 0, .next = 0 });
    f.publish(0, 0);

    var memory = f.memory();
    var queue = f.queue();

    const head = (try queue.next(&memory)).?;
    try queue.complete(&memory, head, 16);

    try testing.expectEqual(@as(u16, 1), f.usedIndex());
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, f.bytes[0x200 + 4 ..][0..4], .little));
    try testing.expectEqual(@as(u32, 16), std.mem.readInt(u32, f.bytes[0x200 + 8 ..][0..4], .little));
}
