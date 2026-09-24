//! The virtio MMIO transport, version 2.
//!
//! This is the register file a guest driver finds at a fixed address and uses to
//! discover the device, agree a feature set, place its queue, and say when there is
//! work. It holds no policy of its own. What the queue means is the device above it.
//!
//! Every value written here comes from the guest. A queue size larger than the
//! device supports, a status bit out of order, a register that does not exist: all
//! of them are recoverable and none of them assert.

const std = @import("std");
const testing = @import("mirage-testing");
const Bus = @import("../Bus.zig");
const Queue = @import("Queue.zig");

const Mmio = @This();

/// "virt" read as a little endian word.
pub const magic = 0x7472_6976;
/// Version 2 is the one without the legacy layout.
pub const version = 2;
/// The largest ring this device will accept. A driver asks for no more than this.
pub const queue_size_max = 256;

pub const len = 0x200;

const reg = struct {
    const magic_value = 0x000;
    const version_value = 0x004;
    const device_id = 0x008;
    const vendor_id = 0x00c;
    const device_features = 0x010;
    const device_features_sel = 0x014;
    const driver_features = 0x020;
    const driver_features_sel = 0x024;
    const queue_sel = 0x030;
    const queue_num_max = 0x034;
    const queue_num = 0x038;
    const queue_ready = 0x044;
    const queue_notify = 0x050;
    const interrupt_status = 0x060;
    const interrupt_ack = 0x064;
    const status = 0x070;
    const queue_desc_low = 0x080;
    const queue_desc_high = 0x084;
    const queue_driver_low = 0x090;
    const queue_driver_high = 0x094;
    const queue_device_low = 0x0a0;
    const queue_device_high = 0x0a4;
    /// Which shared memory region the driver is asking about, and how long it is. A device with none
    /// answers that every region is missing, which the transport says with a length of all ones.
    const shm_select = 0x0ac;
    const shm_len_low = 0x0b0;
    const shm_len_high = 0x0b4;
    const shm_base_low = 0x0b8;
    const shm_base_high = 0x0bc;
    const config_generation = 0x0fc;
    const config = 0x100;
};

/// Why the interrupt was raised. A driver reads this to know whether to look at a queue or
/// at the configuration space.
const interrupt_used_buffer = 1;
const interrupt_config_changed = 2;

device_id: u32,
device_features: u64,
config: []u8,
/// Where in the configuration space the guest may start writing. A device whose
/// configuration is all its own leaves this null. The balloon does not: the guest reports
/// there how many pages it really gave back, and that field is its to write.
config_writable_from: ?usize = null,

/// The queues this device has. A device with one is given a slice of one, and the
/// selector the driver writes chooses among them.
queues: []Queue,
/// Which queue the queue registers name. The driver chooses it, so every use of it
/// is bounds checked rather than trusted.
queue_sel: u32 = 0,
status: u32 = 0,
interrupt_status: u32 = 0,
device_features_sel: u32 = 0,
driver_features_sel: u32 = 0,
driver_features: u64 = 0,
/// Which queues the driver rang, one bit each, because it can ring more than one
/// before the device looks. The device above clears a bit when it serves that queue.
notified: u32 = 0,

pub fn device(self: *Mmio, at: u64) Bus.Device {
    return .{
        .base = at,
        .len = len,
        .ctx = self,
        .vtable = &.{ .read = Mmio.read, .write = Mmio.write },
    };
}

/// Say a queue was used. The guest sees this in the interrupt status register and
/// the caller still has to deliver the interrupt itself.
pub fn raise(self: *Mmio) void {
    self.interrupt_status |= interrupt_used_buffer;
}

/// Say the configuration space changed. A guest that is never told this never looks, so a
/// device whose configuration the VMM moves has to say so.
pub fn raiseConfig(self: *Mmio) void {
    self.interrupt_status |= interrupt_config_changed;
}

/// The queue the selector names, or nothing when the driver named one that does not
/// exist. A driver is allowed to be wrong, so this is never an assertion.
fn selected(self: *Mmio) ?*Queue {
    if (self.queue_sel >= self.queues.len) return null;
    return &self.queues[self.queue_sel];
}

/// Whether the driver rang this queue since the device last served it.
pub fn rang(self: *const Mmio, index: usize) bool {
    if (index >= 32) return false;
    return self.notified & (@as(u32, 1) << @intCast(index)) != 0;
}

/// Say this queue has been served. What the driver rings next is a new doorbell.
pub fn served(self: *Mmio, index: usize) void {
    if (index >= 32) return;
    self.notified &= ~(@as(u32, 1) << @intCast(index));
}

fn half(value: u64, selector: u32) u32 {
    return if (selector == 0) @truncate(value) else @truncate(value >> 32);
}

fn setHalf(value: u64, selector: u32, half_value: u32) u64 {
    const wide: u64 = half_value;
    return if (selector == 0)
        (value & 0xffff_ffff_0000_0000) | wide
    else
        (value & 0x0000_0000_ffff_ffff) | (wide << 32);
}

fn setLow(value: u64, low: u32) u64 {
    return (value & 0xffff_ffff_0000_0000) | @as(u64, low);
}

fn setHigh(value: u64, high: u32) u64 {
    return (value & 0x0000_0000_ffff_ffff) | (@as(u64, high) << 32);
}

fn read(ctx: *anyopaque, offset: u64, size: Bus.Size) u64 {
    const self: *Mmio = @ptrCast(@alignCast(ctx));

    // The configuration space holds fields of several widths, so this is the one part
    // of the register file where how wide the access is matters. A driver reading a
    // 64 bit field in one go must not get only half of it.
    if (offset >= reg.config) {
        const at = offset - reg.config;
        const width = @intFromEnum(size);
        if (at + width > self.config.len) return 0;
        var value: u64 = 0;
        for (0..width) |index| {
            value |= @as(u64, self.config[@intCast(at + index)]) << @intCast(index * 8);
        }
        return value;
    }

    // Every register below is a word wide, so the size says nothing more.

    return switch (offset) {
        reg.magic_value => magic,
        reg.version_value => version,
        reg.device_id => self.device_id,
        // No shared memory region, ever. A length of zero would be read as a region that exists and
        // is empty, and a driver that asked for one of those reserves nothing and refuses the device:
        // a guest with a filesystem it could have mounted then has none.
        reg.shm_len_low, reg.shm_len_high => 0xffff_ffff,
        reg.shm_base_low, reg.shm_base_high => 0xffff_ffff,
        reg.vendor_id => 0x4d495241,
        reg.device_features => half(self.device_features, self.device_features_sel),
        // Zero says there is no such queue, which is how a driver learns how many
        // this device has.
        reg.queue_num_max => if (self.queue_sel < self.queues.len) queue_size_max else 0,
        reg.queue_ready => @intFromBool(if (self.selected()) |queue| queue.ready else false),
        reg.interrupt_status => self.interrupt_status,
        reg.status => self.status,
        reg.config_generation => 0,
        else => 0,
    };
}

fn write(ctx: *anyopaque, offset: u64, size: Bus.Size, value: u64) void {
    const self: *Mmio = @ptrCast(@alignCast(ctx));
    const word: u32 = @truncate(value);

    // The guest may write the part of the configuration space the device says is its own,
    // and nothing else. A device whose whole configuration is writable lets a guest tell it
    // things it decided itself.
    if (offset >= reg.config) {
        const from = self.config_writable_from orelse return;
        const at = offset - reg.config;
        if (at < from) return;
        const width = @intFromEnum(size);
        if (at + width > self.config.len) return;
        for (0..width) |index| {
            self.config[@intCast(at + index)] = @truncate(value >> @intCast(index * 8));
        }
        return;
    }

    switch (offset) {
        reg.device_features_sel => self.device_features_sel = word,
        reg.driver_features_sel => self.driver_features_sel = word,
        reg.driver_features => self.driver_features = setHalf(self.driver_features, self.driver_features_sel, word),
        reg.queue_sel => self.queue_sel = word,
        reg.queue_num => {
            const queue = self.selected() orelse return;
            // The driver chooses this. A ring larger than the device supports is
            // left unset, so the queue stays unusable rather than walking memory
            // that was never described.
            if (word == 0 or word > queue_size_max) return;
            queue.size = @intCast(word);
        },
        reg.queue_desc_low => if (self.selected()) |queue| {
            queue.descriptor = setLow(queue.descriptor, word);
        },
        reg.queue_desc_high => if (self.selected()) |queue| {
            queue.descriptor = setHigh(queue.descriptor, word);
        },
        reg.queue_driver_low => if (self.selected()) |queue| {
            queue.available = setLow(queue.available, word);
        },
        reg.queue_driver_high => if (self.selected()) |queue| {
            queue.available = setHigh(queue.available, word);
        },
        reg.queue_device_low => if (self.selected()) |queue| {
            queue.used = setLow(queue.used, word);
        },
        reg.queue_device_high => if (self.selected()) |queue| {
            queue.used = setHigh(queue.used, word);
        },
        reg.queue_ready => if (self.selected()) |queue| {
            queue.ready = word != 0;
        },
        // The value is which queue was rung, not the selector. A driver may ring one
        // it never selected, and a number this device has no queue for is ignored.
        reg.queue_notify => if (word < self.queues.len and word < 32) {
            self.notified |= @as(u32, 1) << @intCast(word);
        },
        reg.interrupt_ack => self.interrupt_status &= ~word,
        reg.status => self.status = word,
        else => {},
    }
}

const base = 0x0a00_0000;

const blank: Queue = .{ .size = 0, .descriptor = 0, .available = 0, .used = 0 };

fn fixture(config: []u8, queues: []Queue) Mmio {
    return .{
        .device_id = 2,
        .device_features = 1 << 32,
        .config = config,
        .queues = queues,
    };
}

test "the register file identifies a modern virtio mmio device" {
    var capacity: [8]u8 = @splat(0);
    var queues = [_]Queue{ blank, blank };
    var mmio = fixture(&capacity, &queues);
    var devices = [_]Bus.Device{mmio.device(base)};
    var bus: Bus = .{ .devices = &devices };

    try testing.expectEqual(@as(u64, 0x7472_6976), bus.read(base + 0x000, .word));
    try testing.expectEqual(@as(u64, 2), bus.read(base + 0x004, .word));
    try testing.expectEqual(@as(u64, 2), bus.read(base + 0x008, .word));
}

test "the device offers its features in two halves" {
    var capacity: [8]u8 = @splat(0);
    var queues = [_]Queue{ blank, blank };
    var mmio = fixture(&capacity, &queues);
    var devices = [_]Bus.Device{mmio.device(base)};
    var bus: Bus = .{ .devices = &devices };

    // Selector zero gives the low 32 bits, selector one the high 32.
    bus.write(base + 0x014, .word, 0);
    try testing.expectEqual(@as(u64, 0), bus.read(base + 0x010, .word));
    bus.write(base + 0x014, .word, 1);
    try testing.expectEqual(@as(u64, 1), bus.read(base + 0x010, .word));
}

test "what the driver accepts is what the device records" {
    var capacity: [8]u8 = @splat(0);
    var queues = [_]Queue{ blank, blank };
    var mmio = fixture(&capacity, &queues);
    var devices = [_]Bus.Device{mmio.device(base)};
    var bus: Bus = .{ .devices = &devices };

    bus.write(base + 0x024, .word, 1);
    bus.write(base + 0x020, .word, 1);

    try testing.expectEqual(@as(u64, 1 << 32), mmio.driver_features);
}

test "the queue address the driver writes is the address the queue uses" {
    var capacity: [8]u8 = @splat(0);
    var queues = [_]Queue{ blank, blank };
    var mmio = fixture(&capacity, &queues);
    var devices = [_]Bus.Device{mmio.device(base)};
    var bus: Bus = .{ .devices = &devices };

    bus.write(base + 0x038, .word, 8);
    bus.write(base + 0x080, .word, 0x1000);
    bus.write(base + 0x084, .word, 0);
    bus.write(base + 0x090, .word, 0x2000);
    bus.write(base + 0x094, .word, 0);
    bus.write(base + 0x0a0, .word, 0x3000);
    bus.write(base + 0x0a4, .word, 0);
    bus.write(base + 0x044, .word, 1);

    try testing.expectEqual(@as(u16, 8), queues[0].size);
    try testing.expectEqual(@as(u64, 0x1000), queues[0].descriptor);
    try testing.expectEqual(@as(u64, 0x2000), queues[0].available);
    try testing.expectEqual(@as(u64, 0x3000), queues[0].used);
    try std.testing.expect(queues[0].ready);
}

test "a queue larger than the device supports is refused" {
    var capacity: [8]u8 = @splat(0);
    var queues = [_]Queue{ blank, blank };
    var mmio = fixture(&capacity, &queues);
    var devices = [_]Bus.Device{mmio.device(base)};
    var bus: Bus = .{ .devices = &devices };

    // The driver chooses this. A device that accepts it walks a ring that is not
    // there.
    bus.write(base + 0x038, .word, Mmio.queue_size_max * 2);
    try testing.expectEqual(@as(u16, 0), queues[0].size);
}

test "notifying the queue is remembered until the device services it" {
    var capacity: [8]u8 = @splat(0);
    var queues = [_]Queue{ blank, blank };
    var mmio = fixture(&capacity, &queues);
    var devices = [_]Bus.Device{mmio.device(base)};
    var bus: Bus = .{ .devices = &devices };

    try std.testing.expect(!mmio.rang(0));
    bus.write(base + 0x050, .word, 0);
    try std.testing.expect(mmio.rang(0));

    // The device says it looked, and what the driver rings next is a new doorbell.
    mmio.served(0);
    try std.testing.expect(!mmio.rang(0));
}

test "an interrupt the driver acknowledges is cleared" {
    var capacity: [8]u8 = @splat(0);
    var queues = [_]Queue{ blank, blank };
    var mmio = fixture(&capacity, &queues);
    var devices = [_]Bus.Device{mmio.device(base)};
    var bus: Bus = .{ .devices = &devices };

    mmio.raise();
    try testing.expectEqual(@as(u64, 1), bus.read(base + 0x060, .word));

    bus.write(base + 0x064, .word, 1);
    try testing.expectEqual(@as(u64, 0), bus.read(base + 0x060, .word));
}

test "config space is read through the window above the registers" {
    var capacity: [8]u8 = .{ 0x40, 0, 0, 0, 0, 0, 0, 0 };
    var queues = [_]Queue{ blank, blank };
    var mmio = fixture(&capacity, &queues);
    var devices = [_]Bus.Device{mmio.device(base)};
    var bus: Bus = .{ .devices = &devices };

    try testing.expectEqual(@as(u64, 0x40), bus.read(base + 0x100, .word));
}

test "the selector chooses which queue the registers name" {
    var capacity: [8]u8 = @splat(0);
    var queues = [_]Queue{ blank, blank, blank };
    var mmio = fixture(&capacity, &queues);
    var devices = [_]Bus.Device{mmio.device(base)};
    var bus: Bus = .{ .devices = &devices };

    // A device with three queues is placed one queue at a time, and each one has its
    // own ring. Writing them all to the same place is how a driver's second queue
    // reads the first one's descriptors.
    bus.write(base + 0x030, .word, 0);
    bus.write(base + 0x038, .word, 8);
    bus.write(base + 0x080, .word, 0x1000);

    bus.write(base + 0x030, .word, 2);
    bus.write(base + 0x038, .word, 16);
    bus.write(base + 0x080, .word, 0x9000);

    try testing.expectEqual(@as(u16, 8), queues[0].size);
    try testing.expectEqual(@as(u64, 0x1000), queues[0].descriptor);
    try testing.expectEqual(@as(u16, 16), queues[2].size);
    try testing.expectEqual(@as(u64, 0x9000), queues[2].descriptor);
}

test "a driver that selects a queue the device does not have changes nothing" {
    var capacity: [8]u8 = @splat(0);
    var queues = [_]Queue{ blank, blank };
    var mmio = fixture(&capacity, &queues);
    var devices = [_]Bus.Device{mmio.device(base)};
    var bus: Bus = .{ .devices = &devices };

    // The selector comes from the guest. A device that indexes with it reads and
    // writes past the queues it owns.
    bus.write(base + 0x030, .word, 7);
    bus.write(base + 0x038, .word, 8);
    bus.write(base + 0x080, .word, 0x1000);
    bus.write(base + 0x044, .word, 1);

    // Zero says there is no such queue, which is how a driver counts them.
    try testing.expectEqual(@as(u64, 0), bus.read(base + 0x034, .word));
    try testing.expectEqual(@as(u64, 0), bus.read(base + 0x044, .word));
    for (queues) |queue| {
        try testing.expectEqual(@as(u16, 0), queue.size);
        try std.testing.expect(!queue.ready);
    }
}

test "each queue has its own doorbell" {
    var capacity: [8]u8 = @splat(0);
    var queues = [_]Queue{ blank, blank, blank };
    var mmio = fixture(&capacity, &queues);
    var devices = [_]Bus.Device{mmio.device(base)};
    var bus: Bus = .{ .devices = &devices };

    // A driver can ring two queues before the device looks at either, so one bell
    // must not hide the other.
    bus.write(base + 0x050, .word, 0);
    bus.write(base + 0x050, .word, 2);

    try std.testing.expect(mmio.rang(0));
    try std.testing.expect(!mmio.rang(1));
    try std.testing.expect(mmio.rang(2));

    mmio.served(0);
    try std.testing.expect(!mmio.rang(0));
    try std.testing.expect(mmio.rang(2));

    // A queue this device does not have is ignored rather than remembered.
    bus.write(base + 0x050, .word, 9);
    try std.testing.expect(!mmio.rang(9));
}

test "a configuration field is read at the width the driver asked for" {
    // A little endian field, so the low byte comes first.
    var field = [_]u8{ 0x03, 0, 0, 0, 0, 0, 0, 0 };
    var queues = [_]Queue{blank};
    var mmio = fixture(&field, &queues);
    var devices = [_]Bus.Device{mmio.device(base)};
    var bus: Bus = .{ .devices = &devices };

    std.mem.writeInt(u64, &field, 0x0000_0002_0000_0003, .little);

    // Two words, which is how a driver on this transport usually reads a wide field.
    try testing.expectEqual(@as(u64, 3), bus.read(base + 0x100, .word));
    try testing.expectEqual(@as(u64, 2), bus.read(base + 0x104, .word));

    // And in one go, which must give the whole field rather than half of it.
    try testing.expectEqual(@as(u64, 0x0000_0002_0000_0003), bus.read(base + 0x100, .double));

    // Past the end is zero, not whatever follows the field in this process.
    try testing.expectEqual(@as(u64, 0), bus.read(base + 0x108, .word));
}

test "a device with no shared memory region says so rather than offering an empty one" {
    var config: [8]u8 = @splat(0);
    var queues: [1]Queue = @splat(.{ .size = 0, .descriptor = 0, .available = 0, .used = 0 });
    var mmio: Mmio = .{ .device_id = 26, .device_features = 0, .config = &config, .queues = &queues };

    var devices = [_]Bus.Device{mmio.device(0x0a00_0000)};
    var bus: Bus = .{ .devices = &devices };

    // The driver picks a region and asks how long it is. All ones means there is no such region, and
    // zero would mean one that exists and holds nothing, which a driver refuses the device over.
    bus.write(0x0a00_0000 + 0x0ac, .word, 0);
    try testing.expectEqual(@as(u64, 0xffff_ffff), bus.read(0x0a00_0000 + 0x0b0, .word));
    try testing.expectEqual(@as(u64, 0xffff_ffff), bus.read(0x0a00_0000 + 0x0b4, .word));
}
