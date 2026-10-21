//! A PCI host bridge the guest reaches through a memory mapped config space.
//!
//! Config space is one window in guest memory. An address inside it names a bus, a device, a
//! function and a register, so a read of the vendor id is an ordinary load and the guest needs no
//! port instructions. That is the arrangement a device tree describes, and it is the simplest one
//! an endpoint can live behind.
//!
//! The guest picks every address and every width, so a request that names no function answers all
//! ones rather than faulting. All ones is how enumeration learns a slot is empty, which makes the
//! usual case and the refusal the same answer.

const std = @import("std");
const Bus = @import("Bus.zig");
const testing = @import("mirage-testing");

const PciHost = @This();

/// How many functions one bridge holds. One bus is thirty two devices of eight functions, and a
/// machine built here has a handful, so the table is small and flat.
pub const max_functions = 8;

/// How many base address registers a function has.
pub const max_regions = 6;

/// Bytes of config space per function, and how much window one bus needs.
pub const function_size = 0x1000;
pub const bus_size = 32 * 8 * function_size;

/// A register a guest reads that names nothing. Enumeration takes this for an empty slot.
const absent: u64 = 0xFFFF_FFFF_FFFF_FFFF;

/// Where a function sits.
pub const Address = struct {
    device: u5,
    function: u3 = 0,
};

/// One addressable region of a function.
///
/// A wide region takes two registers, because the high half of its address lives in the next one.
/// The register after a wide region therefore belongs to it and cannot hold a region of its own.
pub const Region = struct {
    /// Size in bytes, or zero where the function has no such region. A power of two and at least
    /// sixteen, because the sizing protocol cannot describe anything smaller.
    size: u64 = 0,
    /// Whether the address is sixty four bits wide. Firmware may place a wide region above four
    /// gigabytes, which is the only way to give a guest an aperture larger than the low window.
    wide: bool = false,
    /// Whether reads may be prefetched. A frame buffer says yes, a register block says no.
    prefetchable: bool = false,
};

/// What a function reports in its config space. The identity is the caller's to state, and the
/// sizes are what the guest's firmware reads when it asks how much room each region needs.
pub const Function = struct {
    at: Address,
    vendor: u16,
    device: u16,
    class: u8,
    subclass: u8,
    prog_if: u8 = 0,
    revision: u8 = 0,
    subsystem_vendor: u16 = 0,
    subsystem_device: u16 = 0,
    regions: [max_regions]Region = @splat(.{}),
    /// Size of the expansion rom, or zero for none.
    rom_size: u32 = 0,
    /// Whether to report a message signalled interrupt capability.
    ///
    /// The card this was built for advertises one while every interrupt line is tied off, so it can
    /// be enabled and will never fire. Saying so here lets the model carry that, because a model
    /// kinder than the hardware would let a guest enable it, wait, and pass where the real card
    /// hangs.
    msi_capability: bool = false,
};

functions: [max_functions]?Function = @splat(null),
/// What the guest has written that the bridge keeps: the command word, where firmware put each
/// region, and where it put the rom. Held beside the function rather than inside it, so what the
/// caller declared stays separate from what the guest decided.
state: [max_functions]State = @splat(.{}),
/// Reads and writes that named no function. A guest is allowed to be wrong, so these are counted
/// rather than refused loudly.
unclaimed: u64 = 0,

pub const State = struct {
    command: u16 = 0,
    /// One entry per register rather than per region, because a wide region's address arrives in
    /// two writes and the guest may make them in either order.
    bases: [max_regions]u32 = @splat(0),
    rom_base: u32 = 0,
    /// What the guest wrote to the message signalled interrupt control word, kept so a read gives
    /// back what was written. Nothing here ever sends one.
    msi_control: u16 = 0,
};

/// Whether a register holds a region, the high half of one, or nothing.
const Role = union(enum) {
    none,
    low: usize,
    high: usize,
};

fn roleOf(one: Function, index: usize) Role {
    var at: usize = 0;
    while (at < max_regions) : (at += 1) {
        const each = one.regions[at];
        if (each.size == 0) {
            if (at == index) return .none;
            continue;
        }
        if (at == index) return .{ .low = at };
        if (each.wide) {
            if (at + 1 == index) return .{ .high = at };
            at += 1;
        }
    }
    return .none;
}

/// Whether a function's regions fit the registers they claim. A wide region in the last register
/// has nowhere to put its high half, and a region declared in a register another one already took
/// would be read as part of an address.
pub fn describes(one: Function) bool {
    var at: usize = 0;
    while (at < max_regions) : (at += 1) {
        const each = one.regions[at];
        if (each.size == 0) continue;
        if (!std.math.isPowerOfTwo(each.size)) return false;
        if (each.size < 16) return false;
        if (!each.wide and each.size > 0xFFFF_FFFF) return false;
        if (each.wide) {
            if (at + 1 >= max_regions) return false;
            if (one.regions[at + 1].size != 0) return false;
            at += 1;
        }
    }
    return true;
}

/// Offer a function at the address it names. Returns false when the table is full, when something
/// already sits there, or when the regions do not fit the registers.
pub fn add(self: *PciHost, one: Function) bool {
    if (!describes(one)) return false;
    var free: ?usize = null;
    for (self.functions, 0..) |each, index| {
        if (each) |held| {
            if (held.at.device == one.at.device and held.at.function == one.at.function) return false;
        } else if (free == null) free = index;
    }
    const slot = free orelse return false;
    self.functions[slot] = one;
    self.state[slot] = .{};
    return true;
}

/// Where firmware placed a region, or nothing when it has not placed one yet.
pub fn baseOf(self: *const PciHost, slot: usize, region: usize) ?u64 {
    const one = self.functions[slot] orelse return null;
    if (region >= max_regions) return null;
    const each = one.regions[region];
    if (each.size == 0) return null;

    const held = self.state[slot];
    const low: u64 = held.bases[region] & ~@as(u32, kindBits(each));
    const base = if (each.wide) low | (@as(u64, held.bases[region + 1]) << 32) else low;
    if (base == 0) return null;
    return base;
}

/// The window a bridge claims, anchored where the device tree says it is.
pub fn device(self: *PciHost, at: u64) Bus.Device {
    return .{
        .base = at,
        .len = bus_size,
        .ctx = self,
        .vtable = &.{ .read = PciHost.read, .write = PciHost.write },
    };
}

fn slotOf(self: *const PciHost, bus: u8, dev: u5, fun: u3) ?usize {
    if (bus != 0) return null;
    for (self.functions, 0..) |each, index| {
        const held = each orelse continue;
        if (held.at.device == dev and held.at.function == fun) return index;
    }
    return null;
}

fn read(ctx: *anyopaque, offset: u64, size: Bus.Size) u64 {
    const self: *PciHost = @ptrCast(@alignCast(ctx));
    const bytes: u64 = @backingInt(size);

    const bus: u8 = @truncate(offset >> 20);
    const dev: u5 = @truncate(offset >> 15);
    const fun: u3 = @truncate(offset >> 12);
    const reg: u64 = offset & (function_size - 1);

    const slot = self.slotOf(bus, dev, fun) orelse {
        self.unclaimed += 1;
        return absent >> @intCast(64 - bytes * 8);
    };

    // Config space is dword shaped, so a narrower read takes its bytes out of the word that holds
    // them. A read that crosses a word boundary is answered word by word.
    var value: u64 = 0;
    var taken: u64 = 0;
    while (taken < bytes) : (taken += 4) {
        const dword = self.word(slot, (reg + taken) & ~@as(u64, 3));
        const shift = ((reg + taken) & 3) * 8;
        value |= @as(u64, dword >> @intCast(shift)) << @intCast(taken * 8);
    }
    if (bytes == 8) return value;
    return value & ((@as(u64, 1) << @intCast(bytes * 8)) - 1);
}

/// The low bits of a region's register, which say what kind of region it is rather than where it
/// sits. Firmware keeps them and reads them back, so they are part of every answer.
fn kindBits(each: Region) u32 {
    var bits: u32 = 0;
    if (each.wide) bits |= 0b10 << 1;
    if (each.prefetchable) bits |= 1 << 3;
    return bits;
}

/// One dword of a function's config space.
fn word(self: *const PciHost, slot: usize, reg: u64) u32 {
    const one = self.functions[slot].?;
    const held = self.state[slot];

    if (reg >= 0x10 and reg < 0x10 + max_regions * 4) {
        const index = (reg - 0x10) / 4;
        return switch (roleOf(one, index)) {
            .none => 0,
            .low => |owner| held.bases[index] | kindBits(one.regions[owner]),
            .high => held.bases[index],
        };
    }
    if (one.msi_capability and reg >= msi_cap_at and reg < msi_cap_at + 0x10) {
        return self.msiWord(slot, reg - msi_cap_at);
    }

    return switch (reg) {
        0x00 => @as(u32, one.device) << 16 | one.vendor,
        0x04 => @as(u32, status) << 16 | held.command,
        0x08 => @as(u32, one.class) << 24 | @as(u32, one.subclass) << 16 |
            @as(u32, one.prog_if) << 8 | one.revision,
        // Header type zero, no multi function bit, and a cache line size nothing here uses.
        0x0c => 0,
        0x2c => @as(u32, one.subsystem_device) << 16 | one.subsystem_vendor,
        0x30 => held.rom_base,
        0x34 => if (one.msi_capability) msi_cap_at else 0,
        // No interrupt pin, because nothing here raises one.
        0x3c => 0,
        else => 0,
    };
}

/// Where the capability list starts, when there is one. Anywhere above the header and below the
/// first extended register will do, and this leaves the header alone.
const msi_cap_at: u32 = 0x40;

/// The message signalled interrupt capability, which is reported and never honoured. The identifier
/// is five, the next pointer is zero because it is the only one, and the message control word is
/// whatever the guest last wrote.
fn msiWord(self: *const PciHost, slot: usize, within: u64) u32 {
    const held = self.state[slot];
    return switch (within) {
        0x00 => @as(u32, held.msi_control) << 16 | 0x05,
        else => 0,
    };
}

/// The status word every function here reports. Nothing sets an error bit, so it is constant.
const status: u16 = 0;

fn write(ctx: *anyopaque, offset: u64, size: Bus.Size, value: u64) void {
    const self: *PciHost = @ptrCast(@alignCast(ctx));
    _ = size;

    const bus: u8 = @truncate(offset >> 20);
    const dev: u5 = @truncate(offset >> 15);
    const fun: u3 = @truncate(offset >> 12);
    const reg: u64 = offset & (function_size - 1);

    const slot = self.slotOf(bus, dev, fun) orelse {
        self.unclaimed += 1;
        return;
    };

    const one = self.functions[slot].?;
    const held = &self.state[slot];
    const narrow: u32 = @truncate(value);
    const aligned = reg & ~@as(u64, 3);

    if (aligned >= 0x10 and aligned < 0x10 + max_regions * 4) {
        const index = (aligned - 0x10) / 4;
        switch (roleOf(one, index)) {
            .none => {},
            .low => |owner| {
                const each = one.regions[owner];
                const mask: u32 = @truncate(~(each.size - 1));
                held.bases[index] = (narrow & mask) | kindBits(each);
            },
            .high => |owner| {
                const each = one.regions[owner];
                held.bases[index] = narrow & @as(u32, @truncate(~(each.size - 1) >> 32));
            },
        }
        return;
    }
    if (one.msi_capability and aligned == msi_cap_at) {
        held.msi_control = @truncate((narrow >> 16) & msi_control_writable);
        return;
    }

    switch (aligned) {
        // Only the bits a guest is allowed to set. The rest of the word is status, which is read
        // only here.
        0x04 => held.command = @truncate(narrow & command_writable),
        0x30 => {
            if (one.rom_size == 0) return;
            const mask: u32 = @truncate(~(@as(u64, one.rom_size) - 1));
            held.rom_base = (narrow & mask) | (narrow & rom_enable);
        },
        else => {},
    }
}

/// Which command bits a guest may set: memory space, bus master, and interrupt disable.
const command_writable: u32 = 0x0002 | 0x0004 | 0x0400;

/// The rom's only low bit is the enable, which the guest owns.
const rom_enable: u32 = 1;

/// The one bit of the message control word a guest may set here, which is the enable.
const msi_control_writable: u32 = 1;

/// The identity and region sizes of the card this bridge was first built for, taken from the
/// generated hardware rather than chosen here. The two sizing answers below are the values that
/// appear in the generated register transfer level for `chenega_v1_ax7203`, so a change to the
/// arithmetic above has to disagree with real hardware before it can pass.
const glacier: Function = .{
    .at = .{ .device = 1 },
    .vendor = 0x10ee,
    .device = 0x7203,
    .class = 0x03,
    .subclass = 0x80,
    .subsystem_vendor = 0x10ee,
    .subsystem_device = 0x7203,
    .regions = .{ .{ .size = 0x1000 }, .{}, .{}, .{}, .{}, .{} },
    .rom_size = 0x4_0000,
};

fn ecam(dev: u5, fun: u3, reg: u64) u64 {
    return (@as(u64, dev) << 15) | (@as(u64, fun) << 12) | reg;
}

test "a slot with nothing in it reads all ones" {
    var host: PciHost = .{};
    var one = host.device(0);

    // How enumeration learns a slot is empty. Answering zero would read as a real function whose
    // vendor is zero, and firmware would try to configure it.
    try testing.expectEqual(@as(u64, 0xFFFF_FFFF), one.vtable.read(one.ctx, ecam(0, 0, 0x00), .word));
    try testing.expectEqual(@as(u64, 0xFFFF), one.vtable.read(one.ctx, ecam(5, 2, 0x00), .half));
    try testing.expectEqual(@as(u64, 2), host.unclaimed);
}

test "a function reports the identity it was declared with" {
    var host: PciHost = .{};
    try testing.expectEqual(true, host.add(glacier));
    var one = host.device(0);

    try testing.expectEqual(@as(u64, 0x10ee), one.vtable.read(one.ctx, ecam(1, 0, 0x00), .half));
    try testing.expectEqual(@as(u64, 0x7203), one.vtable.read(one.ctx, ecam(1, 0, 0x02), .half));
    // Class, subclass and interface together, which is how a display controller says so.
    try testing.expectEqual(@as(u64, 0x03_80_00), one.vtable.read(one.ctx, ecam(1, 0, 0x09), .word) & 0xFF_FFFF);
    try testing.expectEqual(@as(u64, 0x7203_10ee), one.vtable.read(one.ctx, ecam(1, 0, 0x2c), .word));
}

test "the sizing protocol answers what the real card answers" {
    var host: PciHost = .{};
    try testing.expectEqual(true, host.add(glacier));
    var one = host.device(0);

    // Firmware writes all ones and reads back the bits it may change. These two numbers come from
    // the generated hardware, so the arithmetic is checked against the card and not against itself.
    one.vtable.write(one.ctx, ecam(1, 0, 0x10), .word, 0xFFFF_FFFF);
    try testing.expectEqual(@as(u64, 0xFFFF_F000), one.vtable.read(one.ctx, ecam(1, 0, 0x10), .word));

    one.vtable.write(one.ctx, ecam(1, 0, 0x30), .word, 0xFFFF_FFFF);
    try testing.expectEqual(@as(u64, 0xFFFC_0001), one.vtable.read(one.ctx, ecam(1, 0, 0x30), .word));

    // A region the card does not have stays absent however hard firmware asks.
    one.vtable.write(one.ctx, ecam(1, 0, 0x14), .word, 0xFFFF_FFFF);
    try testing.expectEqual(@as(u64, 0), one.vtable.read(one.ctx, ecam(1, 0, 0x14), .word));
}

test "firmware places a region where it chose to" {
    var host: PciHost = .{};
    try testing.expectEqual(true, host.add(glacier));
    var one = host.device(0);

    one.vtable.write(one.ctx, ecam(1, 0, 0x10), .word, 0x4000_0000);
    try testing.expectEqual(@as(u64, 0x4000_0000), one.vtable.read(one.ctx, ecam(1, 0, 0x10), .word));

    // The low bits belong to the region's kind and stay clear whatever is written over them.
    one.vtable.write(one.ctx, ecam(1, 0, 0x10), .word, 0x4000_0FFF);
    try testing.expectEqual(@as(u64, 0x4000_0000), one.vtable.read(one.ctx, ecam(1, 0, 0x10), .word));
}

test "the command word keeps only the bits a guest may set" {
    var host: PciHost = .{};
    try testing.expectEqual(true, host.add(glacier));
    var one = host.device(0);

    one.vtable.write(one.ctx, ecam(1, 0, 0x04), .word, 0xFFFF_FFFF);
    const back = one.vtable.read(one.ctx, ecam(1, 0, 0x04), .half);
    try testing.expectEqual(@as(u64, 0x0406), back);
    // Status sits in the top half of the same word and no write reaches it.
    try testing.expectEqual(@as(u64, 0), one.vtable.read(one.ctx, ecam(1, 0, 0x06), .half));
}

test "two functions cannot claim one address" {
    var host: PciHost = .{};
    try testing.expectEqual(true, host.add(glacier));
    try testing.expectEqual(false, host.add(glacier));

    var moved = glacier;
    moved.at = .{ .device = 2 };
    try testing.expectEqual(true, host.add(moved));
}

test "a bus this bridge does not have answers nothing" {
    var host: PciHost = .{};
    try testing.expectEqual(true, host.add(glacier));
    var one = host.device(0);

    // The window is one bus wide, so anything above it names no function.
    const second_bus = ecam(1, 0, 0x00) + (1 << 20);
    try testing.expectEqual(@as(u64, 0xFFFF_FFFF), one.vtable.read(one.ctx, second_bus, .word));
    try testing.expectEqual(@as(u64, 1), host.unclaimed);
}

/// A card with a wide aperture beside its register block, which is the shape a frame buffer wants:
/// a small register region, then a large prefetchable one firmware may put above four gigabytes.
const wide_card: Function = .{
    .at = .{ .device = 1 },
    .vendor = 0x10ee,
    .device = 0x7203,
    .class = 0x03,
    .subclass = 0x80,
    .regions = .{
        .{ .size = 0x1000 },
        .{},
        .{ .size = 0x20_0000, .wide = true, .prefetchable = true },
        .{},
        .{},
        .{},
    },
};

test "a wide region says so and claims the register after it" {
    var host: PciHost = .{};
    try testing.expectEqual(true, host.add(wide_card));
    var one = host.device(0);

    // Type bits ten in binary for sixty four, and the prefetchable bit above them. Firmware reads
    // these to learn it has to write two halves and may place them high.
    one.vtable.write(one.ctx, ecam(1, 0, 0x18), .word, 0xFFFF_FFFF);
    try testing.expectEqual(@as(u64, 0xFFE0_000C), one.vtable.read(one.ctx, ecam(1, 0, 0x18), .word));

    // The register after it is the high half, so it sizes as the top of the same region rather
    // than reading as a region of its own.
    one.vtable.write(one.ctx, ecam(1, 0, 0x1c), .word, 0xFFFF_FFFF);
    try testing.expectEqual(@as(u64, 0xFFFF_FFFF), one.vtable.read(one.ctx, ecam(1, 0, 0x1c), .word));
}

test "firmware places a wide region above four gigabytes" {
    var host: PciHost = .{};
    try testing.expectEqual(true, host.add(wide_card));
    var one = host.device(0);

    // Thirty two gigabytes up, which no thirty two bit register could name.
    one.vtable.write(one.ctx, ecam(1, 0, 0x18), .word, 0x0000_0000);
    one.vtable.write(one.ctx, ecam(1, 0, 0x1c), .word, 0x0000_0008);
    try testing.expectEqual(@as(?u64, 0x8_0000_0000), host.baseOf(0, 2));

    // The narrow region beside it is still read with one register.
    one.vtable.write(one.ctx, ecam(1, 0, 0x10), .word, 0x4000_0000);
    try testing.expectEqual(@as(?u64, 0x4000_0000), host.baseOf(0, 0));
}

test "a region that cannot fit its registers is refused" {
    var host: PciHost = .{};

    // A wide region in the last register has nowhere to put its high half.
    var last = wide_card;
    last.regions = @splat(.{});
    last.regions[5] = .{ .size = 0x1000, .wide = true };
    try testing.expectEqual(false, host.add(last));

    // A region in the register a wide one already took would be read as part of an address.
    var overlapping = wide_card;
    overlapping.regions[3] = .{ .size = 0x1000 };
    try testing.expectEqual(false, host.add(overlapping));

    // A size that is not a power of two cannot be described by the sizing protocol at all.
    var odd = wide_card;
    odd.regions[0] = .{ .size = 0x1800 };
    try testing.expectEqual(false, host.add(odd));

    // And a narrow region cannot be larger than the register that holds it.
    var too_big = wide_card;
    too_big.regions[0] = .{ .size = 0x1_0000_0000 };
    try testing.expectEqual(false, host.add(too_big));
}

test "the interrupt capability is reported only when the caller asks for it" {
    var host: PciHost = .{};
    var quiet = wide_card;
    quiet.at = .{ .device = 1 };
    try testing.expectEqual(true, host.add(quiet));

    var loud = wide_card;
    loud.at = .{ .device = 2 };
    loud.msi_capability = true;
    try testing.expectEqual(true, host.add(loud));

    var one = host.device(0);

    // Without it the capability pointer leads nowhere, so a guest walks no list.
    try testing.expectEqual(@as(u64, 0), one.vtable.read(one.ctx, ecam(1, 0, 0x34), .byte));

    // With it the pointer leads to a capability whose identifier is five, and the list ends there.
    try testing.expectEqual(@as(u64, 0x40), one.vtable.read(one.ctx, ecam(2, 0, 0x34), .byte));
    try testing.expectEqual(@as(u64, 0x05), one.vtable.read(one.ctx, ecam(2, 0, 0x40), .byte));
    try testing.expectEqual(@as(u64, 0x00), one.vtable.read(one.ctx, ecam(2, 0, 0x41), .byte));

    // The guest may enable it and read the enable back. Nothing here ever sends one, which is what
    // the real card does today: a capability it advertises and does not honour.
    one.vtable.write(one.ctx, ecam(2, 0, 0x40), .word, 0x0001_0000);
    try testing.expectEqual(@as(u64, 1), one.vtable.read(one.ctx, ecam(2, 0, 0x42), .half));
}
