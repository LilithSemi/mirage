//! A virtio block device, backed by bytes the host already holds.
//!
//! A request is a chain of three parts: a header the driver wrote, a data buffer,
//! and one status byte the device writes. The sector number in that header is chosen
//! by the guest, so it is bounds checked against the storage rather than trusted. A
//! device that trusts it reads host memory on request, which is the whole reason the
//! guest is in a box.

const std = @import("std");
const testing = @import("mirage-testing");
const Bus = @import("../Bus.zig");
const Mmio = @import("Mmio.zig");
const Queue = @import("Queue.zig");
const Service = @import("../../mirage-device.zig").Service;
const GuestMemory = @import("mirage-memory").GuestMemory;

const Block = @This();

pub const sector_size = 512;

/// A block device has one queue and everything goes through it.
const request_queue = 0;

/// `VIRTIO_BLK_T_*`.
pub const kind_in = 0;
pub const kind_out = 1;
pub const kind_flush = 4;

/// `VIRTIO_BLK_S_*`.
pub const status_ok: u8 = 0;
pub const status_io_error: u8 = 1;
pub const status_unsupported: u8 = 2;

/// `VIRTIO_ID_BLOCK`.
const device_id = 2;
/// `VIRTIO_F_VERSION_1`. A modern driver refuses a device that does not offer it.
const feature_version_1: u64 = 1 << 32;

const header_size = 16;

pub const Error = Queue.Error;

mmio: Mmio,
/// One queue, for requests. The transport points into this, so a `Block` that is
/// copied by value leaves that pointer aimed at the old copy.
queues: [1]Queue,
storage: []u8,
/// The capacity in sectors, little endian, as the configuration space holds it.
config: [8]u8,

/// Initialised in place, never returned by value. The transport points at `config`
/// inside this same struct, and a value that is copied leaves that pointer aimed at
/// wherever the old copy used to be.
pub fn init(self: *Block, storage: []u8) void {
    self.storage = storage;
    std.mem.writeInt(u64, &self.config, storage.len / sector_size, .little);
    self.queues = .{.{ .size = 0, .descriptor = 0, .available = 0, .used = 0 }};
    self.mmio = .{
        .device_id = device_id,
        .device_features = feature_version_1,
        .config = &self.config,
        .queues = &self.queues,
    };
}

pub fn device(self: *Block, at: u64) Bus.Device {
    return self.mmio.device(at);
}

/// Hand this to a run loop so it can serve the queue without knowing what kind of
/// device is behind it.
pub fn service(self: *Block, intid: u32) Service {
    return .{ .ctx = self, .intid = intid, .poll = Block.askPoll };
}

fn askPoll(ctx: *anyopaque, memory: *GuestMemory) Service.Error!bool {
    const self: *Block = @ptrCast(@alignCast(ctx));
    if (self.mmio.rang(request_queue)) _ = try self.serve(memory);
    return self.mmio.interrupt_status != 0;
}

fn sectors(self: *const Block) u64 {
    return self.storage.len / sector_size;
}

/// Serve everything the driver has published. Returns how many requests finished.
pub fn serve(self: *Block, memory: *GuestMemory) Error!u32 {
    const queue = &self.queues[request_queue];
    if (!queue.ready) return 0;

    var served: u32 = 0;
    while (try queue.next(memory)) |head| {
        var chain = queue.walk(head);

        const request = (try chain.next(memory)) orelse continue;
        if (request.len < header_size) continue;

        var header: [header_size]u8 = undefined;
        try memory.read(request.addr, &header);
        const kind = std.mem.readInt(u32, header[0..4], .little);
        const sector = std.mem.readInt(u64, header[8..16], .little);

        var written: u32 = 0;
        var status = status_ok;

        while (try chain.next(memory)) |segment| {
            // The last writable byte of the chain is the status, not data.
            if (segment.len == 1 and segment.writable) {
                try memory.write(segment.addr, &[_]u8{status});
                written += 1;
                continue;
            }
            const result = self.transfer(memory, kind, sector, segment) catch |err| switch (err) {
                error.OutOfBounds, error.PrivateMemory => blk: {
                    status = status_io_error;
                    break :blk 0;
                },
                else => return err,
            };
            if (result) |count| {
                if (segment.writable) written += count;
            } else {
                status = if (kind == kind_flush) status_ok else status_unsupported;
            }
        }

        try queue.complete(memory, head, written);
        served += 1;
    }

    if (served > 0) self.mmio.raise();
    self.mmio.served(request_queue);
    return served;
}

/// Move one segment between guest memory and storage. Null means the request type is
/// not implemented.
fn transfer(self: *Block, memory: *GuestMemory, kind: u32, sector: u64, segment: Queue.Segment) Error!?u32 {
    if (kind != kind_in and kind != kind_out) return null;

    // Both of these come from the guest, so the sum is checked before it is used.
    const start = std.math.mul(u64, sector, sector_size) catch return Error.OutOfBounds;
    const end = std.math.add(u64, start, segment.len) catch return Error.OutOfBounds;
    if (end > self.storage.len) return Error.OutOfBounds;

    const at: usize = @intCast(start);
    const length: usize = @intCast(segment.len);

    if (kind == kind_in) {
        try memory.write(segment.addr, self.storage[at .. at + length]);
    } else {
        const source = try memory.slice(segment.addr, segment.len);
        @memcpy(self.storage[at .. at + length], source);
    }
    return segment.len;
}
const ram = 0x4000_0000;
const mmio_at = 0x0a00_0000;
const ring = 4;

const desc_at = ram + 0x000;
const avail_at = ram + 0x100;
const used_at = ram + 0x200;
const header_at = ram + 0x300;
const data_at = ram + 0x400;
const status_at = ram + 0x700;

const Harness = struct {
    bytes: [4096]u8 = @splat(0),
    regions: [1]GuestMemory.Region = undefined,

    fn memory(self: *Harness) GuestMemory {
        self.regions = .{.{ .gpa = ram, .len = self.bytes.len, .backing = .{ .shared = &self.bytes } }};
        return .{ .regions = &self.regions };
    }

    fn descriptor(self: *Harness, index: u16, addr: u64, length: u32, flags: u16, next: u16) void {
        const at = @as(usize, index) * 16;
        std.mem.writeInt(u64, self.bytes[at..][0..8], addr, .little);
        std.mem.writeInt(u32, self.bytes[at + 8 ..][0..4], length, .little);
        std.mem.writeInt(u16, self.bytes[at + 12 ..][0..2], flags, .little);
        std.mem.writeInt(u16, self.bytes[at + 14 ..][0..2], next, .little);
    }

    /// A three part request: the header, the data, then the status byte.
    fn request(self: *Harness, kind: u32, sector: u64, length: u32, writable_data: bool) void {
        std.mem.writeInt(u32, self.bytes[0x300..][0..4], kind, .little);
        std.mem.writeInt(u32, self.bytes[0x304..][0..4], 0, .little);
        std.mem.writeInt(u64, self.bytes[0x308..][0..8], sector, .little);

        self.descriptor(0, header_at, 16, Queue.flag_next, 1);
        self.descriptor(1, data_at, length, Queue.flag_next | (if (writable_data) Queue.flag_write else 0), 2);
        self.descriptor(2, status_at, 1, Queue.flag_write, 0);

        std.mem.writeInt(u16, self.bytes[0x104..][0..2], 0, .little);
        std.mem.writeInt(u16, self.bytes[0x102..][0..2], 1, .little);
    }

    fn statusByte(self: *const Harness) u8 {
        return self.bytes[0x700];
    }

    fn attach(self: *Harness, block: *Block) void {
        _ = self;
        block.queues[0] = .{
            .size = ring,
            .descriptor = desc_at,
            .available = avail_at,
            .used = used_at,
            .ready = true,
        };
    }
};

test "capacity is reported in 512 byte sectors" {
    var storage: [2048]u8 = @splat(0);
    var block: Block = undefined;
    block.init(&storage);
    var devices = [_]Bus.Device{block.device(mmio_at)};
    var bus: Bus = .{ .devices = &devices };

    try testing.expectEqual(@as(u64, 4), bus.read(mmio_at + 0x100, .word));
    try testing.expectEqual(@as(u64, 2), bus.read(mmio_at + 0x008, .word));
}

test "a read request copies a sector from storage into the guest" {
    var storage: [1024]u8 = @splat(0);
    @memset(storage[512..1024], 0xab);

    var block: Block = undefined;
    block.init(&storage);
    var h: Harness = .{};
    h.attach(&block);
    h.request(Block.kind_in, 1, 512, true);

    var memory = h.memory();
    try testing.expectEqual(@as(u32, 1), try block.serve(&memory));

    try testing.expectEqual(Block.status_ok, h.statusByte());
    try testing.expectEqual(@as(u8, 0xab), h.bytes[0x400]);
    try testing.expectEqual(@as(u8, 0xab), h.bytes[0x400 + 511]);
}

test "a write request copies the guest buffer into storage" {
    var storage: [1024]u8 = @splat(0);
    var block: Block = undefined;
    block.init(&storage);
    var h: Harness = .{};
    h.attach(&block);
    @memset(h.bytes[0x400..][0..512], 0xcd);
    h.request(Block.kind_out, 0, 512, false);

    var memory = h.memory();
    _ = try block.serve(&memory);

    try testing.expectEqual(Block.status_ok, h.statusByte());
    try testing.expectEqual(@as(u8, 0xcd), storage[0]);
    try testing.expectEqual(@as(u8, 0xcd), storage[511]);
}

test "a sector past the end of storage is an io error and not a read of host memory" {
    var storage: [1024]u8 = @splat(0);
    var block: Block = undefined;
    block.init(&storage);
    var h: Harness = .{};
    h.attach(&block);
    // The guest chooses the sector number.
    h.request(Block.kind_in, 1000, 512, true);

    var memory = h.memory();
    _ = try block.serve(&memory);

    try testing.expectEqual(Block.status_io_error, h.statusByte());
}

test "a request type the device does not implement is refused" {
    var storage: [1024]u8 = @splat(0);
    var block: Block = undefined;
    block.init(&storage);
    var h: Harness = .{};
    h.attach(&block);
    h.request(99, 0, 512, true);

    var memory = h.memory();
    _ = try block.serve(&memory);

    try testing.expectEqual(Block.status_unsupported, h.statusByte());
}

test "a completed request raises the interrupt the driver waits on" {
    var storage: [1024]u8 = @splat(0);
    var block: Block = undefined;
    block.init(&storage);
    var h: Harness = .{};
    h.attach(&block);
    h.request(Block.kind_in, 0, 512, true);

    var memory = h.memory();
    _ = try block.serve(&memory);

    var devices = [_]Bus.Device{block.device(mmio_at)};
    var bus: Bus = .{ .devices = &devices };
    try testing.expectEqual(@as(u64, 1), bus.read(mmio_at + 0x060, .word));
}

test "servicing a queue with nothing published completes nothing" {
    var storage: [1024]u8 = @splat(0);
    var block: Block = undefined;
    block.init(&storage);
    var h: Harness = .{};
    h.attach(&block);

    var memory = h.memory();
    try testing.expectEqual(@as(u32, 0), try block.serve(&memory));
}
