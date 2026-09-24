//! A GICv2 interrupt controller, emulated in the VMM.
//!
//! KVM emulates a GICv3 inside the kernel, so this exists for the Apple backend,
//! which has no interrupt controller of its own to lend a guest. A GICv2 is the one
//! that can be built here at all: its CPU interface is memory mapped, so every guest
//! access arrives as a data abort. A GICv3 puts that interface in system registers,
//! and on Apple Silicon those neither trap nor exist, so a guest there is told
//! `ID_AA64PFR0_EL1.GIC` is zero and will not drive one.
//!
//! Two memory windows: the distributor decides which interrupts exist and who may
//! see them, and the CPU interface is where a guest acknowledges one and says it has
//! finished with it.
//!
//! Most of this is per CPU, which is what makes a machine with more than one possible.
//! The first 32 interrupts are banked: every CPU has its own copy of whether they are
//! enabled, waiting, and being handled, because a timer belongs to one CPU and a
//! message from one CPU to another belongs to the CPU it was sent to. The rest are
//! shared, held once, and delivered to whichever CPUs a target mask names. The CPU
//! interface is banked entirely: a guest reads its own at the same address.
//!
//! Which CPU is reading is not in a memory access, so `acting` is what says so, and
//! whoever drives the bus sets it before every access. A run loop with a thread per
//! CPU sets it on that CPU's thread while holding the lock that the devices share.
//!
//! Every number below comes from the guest, so every one is bounds checked. A
//! controller that trusts an interrupt number writes outside its own state.

const std = @import("std");
const testing = @import("mirage-testing");
const Bus = @import("Bus.zig");

const Gicv2 = @This();

/// Enough for the 32 that are private to a CPU and 224 shared ones, which is what a
/// machine of this size needs.
pub const interrupts = 256;
const words = interrupts / 32;

/// How many are private to each CPU. The first 16 of those are messages one CPU sends
/// another, and the rest belong to a device that is part of a CPU, such as its timer.
pub const private = 32;
pub const messages = 16;

/// How many CPUs this controller can hold state for. A guest with more than this is one
/// this controller cannot describe, which is better than describing it wrongly.
pub const max_cpus = 8;

/// `1023`, the number a guest reads when it acknowledges and finds nothing waiting.
/// It must not be a real interrupt.
pub const spurious = 1023;

pub const distributor_size = 0x1000;
pub const cpu_size = 0x2000;

const gicd = struct {
    const ctlr = 0x000;
    const typer = 0x004;
    const iidr = 0x008;
    const isenabler = 0x100;
    const icenabler = 0x180;
    const ispendr = 0x200;
    const icpendr = 0x280;
    const isactiver = 0x300;
    const icactiver = 0x380;
    const ipriorityr = 0x400;
    const itargetsr = 0x800;
    const icfgr = 0xc00;
    const sgir = 0xf00;
};

const gicc = struct {
    const ctlr = 0x000;
    const pmr = 0x004;
    const bpr = 0x008;
    const iar = 0x00c;
    const eoir = 0x010;
    const iidr = 0x0fc;
};

/// What each CPU has of its own: the interrupts that belong to it, and its interface.
const Cpu = struct {
    /// The first 32 interrupts, one bit each.
    enabled: u32 = 0,
    pending: u32 = 0,
    active: u32 = 0,
    priority: [private]u8 = @splat(0),

    interface_on: bool = false,
    /// Only a priority higher than this, meaning a smaller number, is delivered.
    mask: u8 = 0,
    /// A shared interrupt this CPU has taken and not finished with. Shared state is held
    /// once, so which CPU is handling one has to be remembered here.
    holding: ?u32 = null,
};

/// How many CPUs the guest has. Everything banked exists this many times.
cpus: u32 = 1,
/// Which CPU is touching the registers. Whoever drives the bus sets this first; a
/// machine with one CPU may leave it alone.
acting: u32 = 0,

banked: [max_cpus]Cpu = @splat(.{}),

/// The shared interrupts, from `private` upwards. Bits below that are unused here and
/// live in `banked` instead, so that a register offset indexes the same word either way.
enabled: [words]u32 = @splat(0),
pending: [words]u32 = @splat(0),
active: [words]u32 = @splat(0),
priority: [interrupts]u8 = @splat(0),
/// Which CPUs each shared interrupt may go to, one bit per CPU. A driver writes these,
/// and one left at zero means a shared interrupt nothing will ever see.
target: [interrupts]u8 = @splat(0),

distributor_on: bool = false,

/// Interrupts refused because the number was out of range, or because a device raised
/// one that belongs to a CPU rather than to the machine. A fault recovered without a
/// trace is a bug that hides itself.
dropped: u64 = 0,

fn setBit(set: *[words]u32, intid: u32, on: bool) void {
    const which = @as(u32, 1) << @intCast(intid % 32);
    if (on) set[intid / 32] |= which else set[intid / 32] &= ~which;
}

fn hasBit(set: *const [words]u32, intid: u32) bool {
    return set[intid / 32] & (@as(u32, 1) << @intCast(intid % 32)) != 0;
}

fn oneBit(word: u32, intid: u32) bool {
    return word & (@as(u32, 1) << @intCast(intid)) != 0;
}

/// Which shared interrupt a CPU has taken and not finished with. For a test to look at, because
/// nothing else can tell whether one was ended by the CPU that owned it.
pub fn holdingFor(self: *const Gicv2, cpu_index: u32) ?u32 {
    if (cpu_index >= max_cpus) return null;
    return self.banked[cpu_index].holding;
}

/// The CPU whose registers an access is about, bounded so a caller that never set
/// `acting` still reads something rather than reading past the state.
fn actingCpu(self: *Gicv2) *Cpu {
    const which = if (self.acting < self.cpus and self.acting < max_cpus) self.acting else 0;
    return &self.banked[which];
}

/// Say a shared interrupt has happened. This is what a device does, and a device belongs
/// to the machine rather than to any one CPU, so anything private is refused here.
pub fn raise(self: *Gicv2, intid: u32) void {
    if (intid >= interrupts or intid < private) {
        self.dropped += 1;
        return;
    }
    setBit(&self.pending, intid, true);
}

pub fn lower(self: *Gicv2, intid: u32) void {
    if (intid >= interrupts or intid < private) {
        self.dropped += 1;
        return;
    }
    setBit(&self.pending, intid, false);
}

/// Say an interrupt belonging to one CPU has happened, which is what a timer does.
pub fn raiseOn(self: *Gicv2, cpu: u32, intid: u32) void {
    if (cpu >= self.cpus or cpu >= max_cpus or intid >= private) {
        self.dropped += 1;
        return;
    }
    self.banked[cpu].pending |= @as(u32, 1) << @intCast(intid);
}

pub fn lowerOn(self: *Gicv2, cpu: u32, intid: u32) void {
    if (cpu >= self.cpus or cpu >= max_cpus or intid >= private) {
        self.dropped += 1;
        return;
    }
    self.banked[cpu].pending &= ~(@as(u32, 1) << @intCast(intid));
}

/// Send a message from one CPU to others, which is how a guest with several of them
/// arranges anything at all: starting one, stopping one, or asking it to reschedule.
fn sendMessage(self: *Gicv2, from: u32, value: u32) void {
    const intid = value & 0xf;
    const filter = (value >> 24) & 0x3;
    const listed: u8 = @truncate((value >> 16) & 0xff);

    for (0..@min(self.cpus, max_cpus)) |index| {
        const which: u32 = @intCast(index);
        const wanted = switch (filter) {
            // The listed CPUs, by bit.
            0 => listed & (@as(u8, 1) << @intCast(which % 8)) != 0,
            // Everyone but the sender.
            1 => which != from,
            // The sender alone.
            2 => which == from,
            else => false,
        };
        if (wanted) self.banked[which].pending |= @as(u32, 1) << @intCast(intid);
    }
}

/// The highest priority interrupt waiting for this CPU, if there is one.
///
/// Equal priorities are broken by number, which is what the specification requires. A
/// CPU already handling one is given nothing else, which is what stops it being entered
/// again before it has finished.
fn highestFor(self: *const Gicv2, cpu: u32) ?u32 {
    if (!self.distributor_on) return null;
    if (cpu >= self.cpus or cpu >= max_cpus) return null;

    const own = &self.banked[cpu];
    if (!own.interface_on) return null;
    if (own.active != 0 or own.holding != null) return null;

    var best: ?u32 = null;
    var best_priority: u8 = 0xff;

    // The ones that belong to this CPU.
    for (0..private) |index| {
        const intid: u32 = @intCast(index);
        if (!oneBit(own.enabled, intid)) continue;
        if (!oneBit(own.pending, intid)) continue;
        if (own.priority[intid] >= own.mask) continue;
        if (own.priority[intid] < best_priority) {
            best = intid;
            best_priority = own.priority[intid];
        }
    }

    // And the shared ones this CPU is named a target of.
    const mine = @as(u8, 1) << @intCast(cpu % 8);
    for (private..interrupts) |index| {
        const intid: u32 = @intCast(index);
        if (!hasBit(&self.enabled, intid)) continue;
        if (!hasBit(&self.pending, intid)) continue;
        if (hasBit(&self.active, intid)) continue;
        if (self.target[intid] & mine == 0) continue;
        if (self.priority[intid] >= own.mask) continue;
        if (self.priority[intid] < best_priority) {
            best = intid;
            best_priority = self.priority[intid];
        }
    }
    return best;
}

/// Whether the controller is asserting the interrupt line into this CPU.
pub fn signalled(self: *const Gicv2, cpu: u32) bool {
    return self.highestFor(cpu) != null;
}

fn askSignalled(ctx: *anyopaque, cpu: u32) bool {
    return cast(ctx).signalled(cpu);
}

fn askRaise(ctx: *anyopaque, intid: u32) void {
    cast(ctx).raise(intid);
}

fn askRaiseOn(ctx: *anyopaque, cpu: u32, intid: u32) void {
    cast(ctx).raiseOn(cpu, intid);
}

fn askLower(ctx: *anyopaque, intid: u32) void {
    cast(ctx).lower(intid);
}

/// Hand this to a run loop so it can drive the interrupt line without knowing what
/// kind of controller is behind it.
/// Say which CPU is touching the registers. The banked part of this controller is per CPU and an
/// access does not say who made it, so whoever runs the CPUs says.
fn askActing(ctx: *anyopaque, cpu: u32) void {
    const self: *Gicv2 = @ptrCast(@alignCast(ctx));
    self.acting = cpu;
}

pub fn controller(self: *Gicv2) @import("../mirage-device.zig").Controller {
    return .{
        .ctx = self,
        .signalled = Gicv2.askSignalled,
        .raise = Gicv2.askRaise,
        .raiseOn = Gicv2.askRaiseOn,
        .lower = Gicv2.askLower,
        .acting = Gicv2.askActing,
    };
}

pub fn devices(self: *Gicv2, distributor_base: u64, cpu_base: u64) [2]Bus.Device {
    return .{
        .{
            .base = distributor_base,
            .len = distributor_size,
            .ctx = self,
            .vtable = &.{ .read = Gicv2.readDistributor, .write = Gicv2.writeDistributor },
        },
        .{
            .base = cpu_base,
            .len = cpu_size,
            .ctx = self,
            .vtable = &.{ .read = Gicv2.readCpu, .write = Gicv2.writeCpu },
        },
    };
}

fn cast(ctx: *anyopaque) *Gicv2 {
    return @ptrCast(@alignCast(ctx));
}

/// Which word of a bitmap register an offset names, or nothing when the offset is
/// not inside that register at all. The check comes before the subtraction, because
/// an offset below the base would wrap.
fn wordAt(offset: u64, base: u64) ?usize {
    if (offset < base or offset >= base + words * 4) return null;
    return @intCast((offset - base) / 4);
}

/// Which byte of a per interrupt register an offset names.
fn byteAt(offset: u64, base: u64) ?u32 {
    if (offset < base or offset >= base + interrupts) return null;
    return @intCast(offset - base);
}

fn readDistributor(ctx: *anyopaque, offset: u64, size: Bus.Size) u64 {
    const self = cast(ctx);
    _ = size;
    const own = self.actingCpu();

    if (byteAt(offset, gicd.ipriorityr)) |intid| {
        // The first 32 are banked, so a CPU reads the priority it set itself.
        return if (intid < private) own.priority[intid] else self.priority[intid];
    }
    if (byteAt(offset, gicd.itargetsr)) |intid| {
        // A private interrupt has no target: it belongs to whoever reads it. A driver reads
        // one of these to learn which bit means itself, so it must read its own bit.
        if (intid < private) return @as(u8, 1) << @intCast(self.acting % 8);
        return self.target[intid];
    }
    if (wordAt(offset, gicd.isenabler)) |index| {
        return if (index == 0) own.enabled else self.enabled[index];
    }
    if (wordAt(offset, gicd.ispendr)) |index| {
        return if (index == 0) own.pending else self.pending[index];
    }
    if (wordAt(offset, gicd.isactiver)) |index| {
        return if (index == 0) own.active else self.active[index];
    }

    return switch (offset) {
        gicd.ctlr => @intFromBool(self.distributor_on),
        // The interrupt count in blocks of 32, one less than the number of blocks, and how
        // many CPUs there are, one less, in the three bits above it.
        gicd.typer => (words - 1) | (@as(u32, @min(self.cpus, max_cpus) - 1) << 5),
        gicd.iidr => 0x0200_043b,
        else => 0,
    };
}

fn writeDistributor(ctx: *anyopaque, offset: u64, size: Bus.Size, value: u64) void {
    const self = cast(ctx);
    _ = size;
    const word: u32 = @truncate(value);
    const own = self.actingCpu();

    if (byteAt(offset, gicd.ipriorityr)) |intid| {
        if (intid < private) own.priority[intid] = @truncate(value) else self.priority[intid] = @truncate(value);
        return;
    }
    if (byteAt(offset, gicd.itargetsr)) |intid| {
        // A private interrupt has no target to set, and a write saying otherwise is ignored
        // rather than being allowed to point one CPU's timer at another.
        if (intid >= private) self.target[intid] = @truncate(value);
        return;
    }

    // A driver sets and clears through separate registers, writing ones for the bits
    // it means, so neither one ever clears a bit the driver did not name.
    if (wordAt(offset, gicd.isenabler)) |index| {
        if (index == 0) own.enabled |= word else self.enabled[index] |= word;
        return;
    }
    if (wordAt(offset, gicd.icenabler)) |index| {
        if (index == 0) own.enabled &= ~word else self.enabled[index] &= ~word;
        return;
    }
    if (wordAt(offset, gicd.ispendr)) |index| {
        if (index == 0) own.pending |= word else self.pending[index] |= word;
        return;
    }
    if (wordAt(offset, gicd.icpendr)) |index| {
        if (index == 0) own.pending &= ~word else self.pending[index] &= ~word;
        return;
    }
    if (wordAt(offset, gicd.icactiver)) |index| {
        if (index == 0) own.active &= ~word else self.active[index] &= ~word;
        return;
    }

    switch (offset) {
        gicd.ctlr => self.distributor_on = word & 1 != 0,
        gicd.sgir => self.sendMessage(self.acting, word),
        else => {},
    }
}

fn readCpu(ctx: *anyopaque, offset: u64, size: Bus.Size) u64 {
    const self = cast(ctx);
    _ = size;
    const which = if (self.acting < self.cpus and self.acting < max_cpus) self.acting else 0;
    const own = &self.banked[which];

    return switch (offset) {
        gicc.ctlr => @intFromBool(own.interface_on),
        gicc.pmr => own.mask,
        // Acknowledging takes the interrupt: it stops being pending and becomes
        // active, and nothing else is delivered to this CPU until it ends it.
        gicc.iar => blk: {
            const found = self.highestFor(which) orelse break :blk spurious;
            if (found < private) {
                own.pending &= ~(@as(u32, 1) << @intCast(found));
                own.active |= @as(u32, 1) << @intCast(found);
            } else {
                setBit(&self.pending, found, false);
                setBit(&self.active, found, true);
                own.holding = found;
            }
            break :blk found;
        },
        gicc.iidr => 0x0002_043b,
        else => 0,
    };
}

fn writeCpu(ctx: *anyopaque, offset: u64, size: Bus.Size, value: u64) void {
    const self = cast(ctx);
    _ = size;
    const which = if (self.acting < self.cpus and self.acting < max_cpus) self.acting else 0;
    const own = &self.banked[which];

    switch (offset) {
        gicc.ctlr => own.interface_on = value & 1 != 0,
        gicc.pmr => own.mask = @truncate(value),
        gicc.eoir => {
            // The guest writes back the whole word it read when it acknowledged. For a message from
            // another CPU that word carries the sender in the three bits above the number, so only the
            // low ten are the number itself. Taking the whole word gives something above every real
            // interrupt, and refusing that leaves the interrupt active for ever: the CPU then takes no
            // further interrupt, and anything waiting on all of them waits for ever.
            const intid: u32 = @as(u32, @truncate(value)) & 0x3ff;
            if (intid >= interrupts) return;
            if (intid < private) {
                own.active &= ~(@as(u32, 1) << @intCast(intid));
                return;
            }
            // A shared one is only finished with by the CPU that took it, or a CPU could end
            // an interrupt another one is still handling.
            if (own.holding == intid) {
                setBit(&self.active, intid, false);
                own.holding = null;
            }
        },
        else => {},
    }
}

const dist = 0x0800_0000;
const cpu_window = 0x0801_0000;

/// Turn the controller on for one CPU, the way a driver does on that CPU: the distributor once, then
/// this CPU's own interface and its priority gate.
fn wake(bus: *Bus, gic: *Gicv2, which: u32) void {
    gic.acting = which;
    bus.write(dist + gicd.ctlr, .word, 1);
    bus.write(cpu_window + gicc.ctlr, .word, 1);
    bus.write(cpu_window + gicc.pmr, .word, 0xff);
}

/// Let one interrupt through to a CPU, from that CPU.
fn allow(bus: *Bus, gic: *Gicv2, which: u32, intid: u32) void {
    gic.acting = which;
    bus.write(dist + gicd.isenabler + (intid / 32) * 4, .word, @as(u32, 1) << @intCast(intid % 32));
    if (intid >= private) bus.write(dist + gicd.itargetsr + intid, .byte, @as(u8, 1) << @intCast(which % 8));
}

test "a private interrupt goes to its own cpu and to no other" {
    var gic: Gicv2 = .{ .cpus = 4 };
    var on_bus = gic.devices(dist, cpu_window);
    var bus: Bus = .{ .devices = &on_bus };

    for (0..4) |which| {
        wake(&bus, &gic, @intCast(which));
        // The virtual timer, which every CPU has one of.
        allow(&bus, &gic, @intCast(which), 27);
    }

    // The timer of the third CPU. Nothing else may see it: a timer belongs to one CPU, and a guest
    // whose CPUs all saw each other's timers would be a guest with no working clock anywhere.
    gic.raiseOn(2, 27);
    try std.testing.expect(!gic.signalled(0));
    try std.testing.expect(!gic.signalled(1));
    try std.testing.expect(gic.signalled(2));
    try std.testing.expect(!gic.signalled(3));

    // And that CPU takes it while the others still see nothing.
    gic.acting = 2;
    try testing.expectEqual(@as(u64, 27), bus.read(cpu_window + gicc.iar, .word));
    try std.testing.expect(!gic.signalled(2));
    try testing.expectEqual(@as(u64, spurious), bus.read(cpu_window + gicc.iar, .word));

    gic.acting = 0;
    try testing.expectEqual(@as(u64, spurious), bus.read(cpu_window + gicc.iar, .word));
}

test "a device raising a private interrupt is refused rather than delivered to nobody" {
    var gic: Gicv2 = .{ .cpus = 2 };

    // A device belongs to the machine, so it has no CPU to raise one for. Refusing is what says so.
    gic.raise(27);
    try testing.expectEqual(@as(u64, 1), gic.dropped);
    try std.testing.expect(!gic.signalled(0));
    try std.testing.expect(!gic.signalled(1));

    // And a CPU that does not exist is refused the same way.
    gic.raiseOn(7, 27);
    try testing.expectEqual(@as(u64, 2), gic.dropped);
}

test "a shared interrupt goes only to the cpus it is aimed at" {
    var gic: Gicv2 = .{ .cpus = 4 };
    var on_bus = gic.devices(dist, cpu_window);
    var bus: Bus = .{ .devices = &on_bus };

    for (0..4) |which| wake(&bus, &gic, @intCast(which));

    // Enabled once, because it is held once, and aimed at the second CPU alone.
    gic.acting = 0;
    bus.write(dist + gicd.isenabler + 4, .word, 1 << 16);
    bus.write(dist + gicd.itargetsr + 48, .byte, 1 << 1);

    gic.raise(48);
    try std.testing.expect(!gic.signalled(0));
    try std.testing.expect(gic.signalled(1));
    try std.testing.expect(!gic.signalled(2));

    // The CPU it was aimed at takes it, and then nobody has it waiting.
    gic.acting = 1;
    try testing.expectEqual(@as(u64, 48), bus.read(cpu_window + gicc.iar, .word));
    try std.testing.expect(!gic.signalled(1));

    // A different CPU cannot finish with it, because it never took it. Letting it would end an
    // interrupt another CPU is still inside.
    gic.acting = 2;
    bus.write(cpu_window + gicc.eoir, .word, 48);
    gic.acting = 1;
    try std.testing.expect(gic.holdingFor(1) != null);

    // The one that took it can.
    bus.write(cpu_window + gicc.eoir, .word, 48);
    try std.testing.expect(gic.holdingFor(1) == null);
}

test "one cpu sends another a message, which is how a guest starts them" {
    var gic: Gicv2 = .{ .cpus = 4 };
    var on_bus = gic.devices(dist, cpu_window);
    var bus: Bus = .{ .devices = &on_bus };

    for (0..4) |which| {
        wake(&bus, &gic, @intCast(which));
        allow(&bus, &gic, @intCast(which), 1);
    }

    // The first CPU sends message one to the third and fourth, by naming them.
    gic.acting = 0;
    bus.write(dist + gicd.sgir, .word, (@as(u32, 0b1100) << 16) | 1);
    try std.testing.expect(!gic.signalled(0));
    try std.testing.expect(!gic.signalled(1));
    try std.testing.expect(gic.signalled(2));
    try std.testing.expect(gic.signalled(3));

    // Everyone but the sender.
    var fresh: Gicv2 = .{ .cpus = 4 };
    var fresh_bus_devices = fresh.devices(dist, cpu_window);
    var fresh_bus: Bus = .{ .devices = &fresh_bus_devices };
    for (0..4) |which| {
        wake(&fresh_bus, &fresh, @intCast(which));
        allow(&fresh_bus, &fresh, @intCast(which), 1);
    }
    fresh.acting = 1;
    fresh_bus.write(dist + gicd.sgir, .word, (@as(u32, 1) << 24) | 1);
    try std.testing.expect(fresh.signalled(0));
    try std.testing.expect(!fresh.signalled(1));
    try std.testing.expect(fresh.signalled(2));
    try std.testing.expect(fresh.signalled(3));
}

test "a cpu reads its own bit from the target register" {
    var gic: Gicv2 = .{ .cpus = 4 };
    var on_bus = gic.devices(dist, cpu_window);
    var bus: Bus = .{ .devices = &on_bus };

    // A driver reads one of the banked target bytes to learn which bit means itself. A controller that
    // answered the same thing to every CPU would have them all believe they were the first.
    for (0..4) |which| {
        gic.acting = @intCast(which);
        try testing.expectEqual(@as(u64, @as(u8, 1) << @intCast(which)), bus.read(dist + gicd.itargetsr + 5, .byte));
    }
}

test "how many cpus the controller says it has" {
    var gic: Gicv2 = .{ .cpus = 4 };
    var on_bus = gic.devices(dist, cpu_window);
    var bus: Bus = .{ .devices = &on_bus };

    // The three bits above the block count say how many CPUs there are, one less. A guest reads this to
    // decide how many interfaces exist.
    const said = bus.read(dist + gicd.typer, .word);
    try testing.expectEqual(@as(u64, 3), (said >> 5) & 0x7);
    try testing.expectEqual(@as(u64, words - 1), said & 0x1f);
}

test "a message is finished with even though the guest writes the sender back too" {
    var gic: Gicv2 = .{ .cpus = 4 };
    var on_bus = gic.devices(dist, cpu_window);
    var bus: Bus = .{ .devices = &on_bus };

    for (0..4) |which| {
        wake(&bus, &gic, @intCast(which));
        allow(&bus, &gic, @intCast(which), 3);
    }

    gic.acting = 0;
    bus.write(dist + gicd.sgir, .word, (@as(u32, 0b0010) << 16) | 3);

    gic.acting = 1;
    try std.testing.expect(gic.signalled(1));
    try testing.expectEqual(@as(u64, 3), bus.read(cpu_window + gicc.iar, .word));
    try std.testing.expect(!gic.signalled(1));

    // A guest writes back the whole word it read, and for a message that word carries the sender above
    // the number. Refusing it because the whole word looks too large leaves the interrupt active, and
    // that CPU then takes nothing else ever: the symptom is a guest that stops the moment it needs every
    // CPU to answer at once, with nothing pending anywhere to explain it.
    bus.write(cpu_window + gicc.eoir, .word, (@as(u32, 2) << 10) | 3);

    // Another message gets through, which is what says the first was really finished with.
    gic.acting = 0;
    bus.write(dist + gicd.sgir, .word, (@as(u32, 0b0010) << 16) | 3);
    gic.acting = 1;
    try std.testing.expect(gic.signalled(1));
}

/// What one CPU holds, for a caller that has to report why a guest stopped. Nothing outside can see
/// these: the state is banked, and a CPU that takes no interrupt looks the same from outside as one with
/// none to take.
pub fn activeFor(self: *const Gicv2, which: u32) u32 {
    if (which >= max_cpus) return 0;
    return self.banked[which].active;
}

pub fn pendingFor(self: *const Gicv2, which: u32) u32 {
    if (which >= max_cpus) return 0;
    return self.banked[which].pending;
}

pub fn enabledFor(self: *const Gicv2, which: u32) u32 {
    if (which >= max_cpus) return 0;
    return self.banked[which].enabled;
}

pub fn interfaceOn(self: *const Gicv2, which: u32) bool {
    if (which >= max_cpus) return false;
    return self.banked[which].interface_on;
}

pub fn maskFor(self: *const Gicv2, which: u32) u8 {
    if (which >= max_cpus) return 0;
    return self.banked[which].mask;
}
