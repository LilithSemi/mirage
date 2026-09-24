//! The bus that carries a guest memory access to the device that owns the address.
//!
//! The guest chooses the address, so an access matching no device is a recoverable
//! fault and never an assertion. It is counted, because a guest is allowed to be
//! wrong and a fault that is recovered in silence is a bug that hides itself.

const std = @import("std");
const testing = @import("mirage-testing");

const Bus = @This();

/// The width of one device access, in bytes.
pub const Size = enum(u4) { byte = 1, half = 2, word = 4, double = 8 };

pub const Device = struct {
    base: u64,
    len: u64,
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        read: *const fn (ctx: *anyopaque, offset: u64, size: Size) u64,
        write: *const fn (ctx: *anyopaque, offset: u64, size: Size, value: u64) void,
    };
};

devices: []Device,
unmapped: u64 = 0,

const Found = struct {
    device: *Device,
    offset: u64,
};

fn find(self: *Bus, gpa: u64, size: Size) ?Found {
    // Both the address and the width come from the guest. Unchecked arithmetic wraps
    // and then passes a bounds test it should have failed.
    const end = std.math.add(u64, gpa, @intFromEnum(size)) catch return null;

    for (self.devices) |*owner| {
        if (gpa < owner.base) continue;
        if (end > owner.base + owner.len) continue;
        return .{ .device = owner, .offset = gpa - owner.base };
    }
    return null;
}

pub fn read(self: *Bus, gpa: u64, size: Size) u64 {
    const found = self.find(gpa, size) orelse {
        self.unmapped += 1;
        return 0;
    };
    return found.device.vtable.read(found.device.ctx, found.offset, size);
}

pub fn write(self: *Bus, gpa: u64, size: Size, value: u64) void {
    const found = self.find(gpa, size) orelse {
        self.unmapped += 1;
        return;
    };
    found.device.vtable.write(found.device.ctx, found.offset, size, value);
}

const Counter = struct {
    reads: u32 = 0,
    writes: u32 = 0,
    last_offset: u64 = 0,
    last_value: u64 = 0,

    fn device(self: *Counter, base: u64, len: u64) Device {
        return .{ .base = base, .len = len, .ctx = self, .vtable = &.{
            .read = Counter.read,
            .write = Counter.write,
        } };
    }

    fn read(ctx: *anyopaque, offset: u64, size: Size) u64 {
        _ = size;
        const self: *Counter = @ptrCast(@alignCast(ctx));
        self.reads += 1;
        self.last_offset = offset;
        return 0x55;
    }

    fn write(ctx: *anyopaque, offset: u64, size: Size, value: u64) void {
        _ = size;
        const self: *Counter = @ptrCast(@alignCast(ctx));
        self.writes += 1;
        self.last_offset = offset;
        self.last_value = value;
    }
};

test "a write reaches the device that owns the address, at an offset" {
    var counter: Counter = .{};
    var devices = [_]Device{counter.device(0x0900_0000, 0x1000)};
    var bus: Bus = .{ .devices = &devices };

    bus.write(0x0900_0018, .word, 0xabcd);

    try testing.expectEqual(@as(u32, 1), counter.writes);
    try testing.expectEqual(@as(u64, 0x18), counter.last_offset);
    try testing.expectEqual(@as(u64, 0xabcd), counter.last_value);
}

test "a read reaches the device and returns what it gave" {
    var counter: Counter = .{};
    var devices = [_]Device{counter.device(0x0900_0000, 0x1000)};
    var bus: Bus = .{ .devices = &devices };

    try testing.expectEqual(@as(u64, 0x55), bus.read(0x0900_0004, .word));
    try testing.expectEqual(@as(u64, 4), counter.last_offset);
}

test "an access that matches no device is counted and does not reach one" {
    var counter: Counter = .{};
    var devices = [_]Device{counter.device(0x0900_0000, 0x1000)};
    var bus: Bus = .{ .devices = &devices };

    // The guest picks this address. An access to nothing is a recoverable fault, so
    // it is counted and the guest is allowed to carry on. It is never an assertion.
    bus.write(0x0a00_0000, .word, 1);
    try testing.expectEqual(@as(u64, 0), bus.read(0x0a00_0000, .word));

    try testing.expectEqual(@as(u32, 0), counter.writes);
    try testing.expectEqual(@as(u64, 2), bus.unmapped);
}

test "an access that runs past the end of a device does not reach it" {
    var counter: Counter = .{};
    var devices = [_]Device{counter.device(0x0900_0000, 0x1000)};
    var bus: Bus = .{ .devices = &devices };

    bus.write(0x0900_0ffe, .word, 1);

    try testing.expectEqual(@as(u32, 0), counter.writes);
    try testing.expectEqual(@as(u64, 1), bus.unmapped);
}
