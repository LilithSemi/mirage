//! The firmware configuration device, as firmware built for a QEMU machine expects to find it.
//!
//! Firmware asks this for the things a device tree does not carry: what the machine is called, what
//! tables to use, which files were handed to it. Mirage hands over none of those, so what this
//! answers is the interface itself and an empty set of files.
//!
//! It is here because without it firmware does not boot at all. The library that drives it builds
//! its record of the device only after reading a signature back, and in a release build the
//! assertion that the record exists is compiled away, so firmware reads address zero and takes a
//! data abort before it reaches any of its own code. Answering the signature is what makes the
//! difference between a machine that boots and one that faults.

const std = @import("std");
const Bus = @import("Bus.zig");
const testing = @import("mirage-testing");

const FwCfg = @This();

/// How wide the window is. Eight bytes of data, two of selector, and nothing after them: a window
/// of 0x18 or more is how firmware is told there is a DMA interface as well, and there is not.
pub const window_size = 0x10;

const data_at = 0x00;
const selector_at = 0x08;

/// The items a machine answers. Firmware reads the first to learn the device is there at all, the
/// second to learn what it can do, and the third to find the files, of which there are none.
pub const signature_item: u16 = 0x0000;
pub const revision_item: u16 = 0x0001;
pub const directory_item: u16 = 0x0019;

/// What the first item reads. Firmware compares this against the four characters and gives up on
/// the device if they differ.
const signature = "QEMU";

/// Bit zero is the register interface this has. Bit one would promise the one that moves bytes by
/// itself, which this does not have.
const revision: u32 = 1;

/// Which item is selected, and how far into it the next read starts.
selected: u16 = 0,
offset: usize = 0,

/// Selections of an item this does not have. The guest chooses the number, so an item nobody
/// models is counted rather than refused.
unknown: u64 = 0,

pub fn device(self: *FwCfg, at: u64) Bus.Device {
    return .{
        .base = at,
        .len = window_size,
        .ctx = self,
        .vtable = &.{ .read = FwCfg.read, .write = FwCfg.write },
    };
}

/// How long the selected item is.
fn length(self: *const FwCfg) usize {
    return switch (self.selected) {
        signature_item => signature.len,
        revision_item => @sizeOf(u32),
        // A count of files, and no files. The count is four bytes whichever way it is read,
        // because zero is the same in both.
        directory_item => @sizeOf(u32),
        else => 0,
    };
}

fn byteOf(self: *const FwCfg, index: usize) u8 {
    if (index >= self.length()) return 0;
    return switch (self.selected) {
        signature_item => signature[index],
        revision_item => @truncate(revision >> @intCast(index * 8)),
        else => 0,
    };
}

fn read(ctx: *anyopaque, offset: u64, size: Bus.Size) u64 {
    const self: *FwCfg = @ptrCast(@alignCast(ctx));
    // The selector is write only, and nothing else in the window answers.
    if (offset != data_at) return 0;

    // Each byte of the item in turn, the first one lowest. The device hands bytes over in the
    // order they are in the item and the machine assembles them, so a read of four bytes of the
    // signature is the four characters in the order they are written.
    const bytes: u64 = @backingInt(size);
    var value: u64 = 0;
    for (0..bytes) |taken| {
        const byte: u64 = self.byteOf(self.offset);
        value |= byte << @intCast(taken * 8);
        self.offset += 1;
    }
    return value;
}

fn write(ctx: *anyopaque, offset: u64, size: Bus.Size, value: u64) void {
    const self: *FwCfg = @ptrCast(@alignCast(ctx));
    _ = size;
    if (offset != selector_at) return;

    // Written the other way round, because the register is big endian and everything that drives
    // it swaps the number before the store.
    self.selected = @byteSwap(@as(u16, @truncate(value)));
    self.offset = 0;
    if (self.length() == 0) self.unknown += 1;
}

/// Select an item the way firmware does, with the number swapped.
fn select(one: *Bus.Device, item: u16) void {
    one.vtable.write(one.ctx, selector_at, .half, @byteSwap(item));
}

test "the signature reads as the four characters firmware looks for" {
    var chip: FwCfg = .{};
    var one = chip.device(0x0902_0000);

    select(&one, signature_item);

    // What firmware compares against: the four characters assembled into one word, lowest byte
    // first. A device that handed them over the other way round would be ignored.
    const want: u64 = 'Q' | @as(u64, 'E') << 8 | @as(u64, 'M') << 16 | @as(u64, 'U') << 24;
    try testing.expectEqual(want, one.vtable.read(one.ctx, data_at, .word));
}

test "an item is read from its start every time it is selected" {
    var chip: FwCfg = .{};
    var one = chip.device(0);

    select(&one, signature_item);
    try testing.expectEqual(@as(u64, 'Q'), one.vtable.read(one.ctx, data_at, .byte));
    try testing.expectEqual(@as(u64, 'E'), one.vtable.read(one.ctx, data_at, .byte));

    // Selecting again starts over, which is what lets firmware read an item twice.
    select(&one, signature_item);
    try testing.expectEqual(@as(u64, 'Q'), one.vtable.read(one.ctx, data_at, .byte));
}

test "reading past the end of an item gives zeros rather than the next item" {
    var chip: FwCfg = .{};
    var one = chip.device(0);

    select(&one, signature_item);
    _ = one.vtable.read(one.ctx, data_at, .word);
    try testing.expectEqual(@as(u64, 0), one.vtable.read(one.ctx, data_at, .word));
}

test "the revision says the register interface and not the one that moves bytes itself" {
    var chip: FwCfg = .{};
    var one = chip.device(0);

    select(&one, revision_item);

    // Bit one would say this device can be asked to move bytes on its own. The window is also
    // declared too short for firmware to look for that interface, so the two agree.
    const said = one.vtable.read(one.ctx, data_at, .word);
    try testing.expectEqual(@as(u64, 1), said & 1);
    try testing.expectEqual(@as(u64, 0), said & 2);
    try testing.expectEqual(@as(u64, 0x10), @as(u64, window_size));
}

test "the list of files is empty rather than absent" {
    var chip: FwCfg = .{};
    var one = chip.device(0);

    // A count of zero. Firmware reads the count, looks for nothing, and carries on; an item that
    // answered nothing at all would leave it reading whatever came next.
    select(&one, directory_item);
    try testing.expectEqual(@as(u64, 0), one.vtable.read(one.ctx, data_at, .word));
    try testing.expectEqual(@as(u64, 0), chip.unknown);
}

test "an item nobody models reads zeros and is counted" {
    var chip: FwCfg = .{};
    var one = chip.device(0);

    select(&one, 0x0014);
    try testing.expectEqual(@as(u64, 0), one.vtable.read(one.ctx, data_at, .double));
    try testing.expectEqual(@as(u64, 1), chip.unknown);
}

test "the selector reads as nothing, because it is written and never read" {
    var chip: FwCfg = .{};
    var one = chip.device(0);

    select(&one, signature_item);
    try testing.expectEqual(@as(u64, 0), one.vtable.read(one.ctx, selector_at, .half));

    // And the item it selected is still the one that answers, because reading elsewhere in the
    // window moves nothing on.
    try testing.expectEqual(@as(u64, 'Q'), one.vtable.read(one.ctx, data_at, .byte));
}
