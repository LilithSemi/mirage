//! The device tree Mirage hands a guest.
//!
//! A guest on real hardware is given this by firmware. A guest here has no firmware,
//! so the VMM has to describe the machine it invented: how much memory there is, where
//! the serial port sits, how many CPUs there are, and how to turn them on.
//!
//! The addresses below are the ones an aarch64 Linux guest already expects from a
//! virtual machine, so a stock kernel needs no patching to find them.

const std = @import("std");
const testing = @import("mirage-testing");
const dtree = @import("dtree");

/// Where the GIC v3 lives. The distributor is fixed and each CPU gets a
/// redistributor of its own after it.
pub const gicd_base = 0x0800_0000;
pub const gicd_size = 0x1_0000;
pub const gicr_stride = 0x2_0000;

/// The redistributors sit above every other device rather than just above the distributor, which is
/// where a machine with a handful of CPUs would put them. One per CPU at this stride is a window that
/// grows with the guest, and below the serial port there was room for a hundred and twenty three of
/// them: the hundred and twenty fourth overlapped it, and a guest whose redistributor is also a serial
/// port does not boot and does not say why. Up here the only thing above is memory.
pub const gicr_base = 0x0d00_0000;

/// How many CPUs the redistributors have room for before they would reach memory.
///
/// A limit that follows from the address map rather than one chosen here. It is in the thousands, so
/// nothing will meet it, but a guest that asked for more has to be told rather than left to die in a
/// window that overlaps its own memory.
pub fn cpusThatFit(ram_base: u64) u64 {
    if (ram_base <= gicr_base) return 0;
    return (ram_base - gicr_base) / gicr_stride;
}

/// Where a GICv2 sits instead. The distributor keeps the same address, and the CPU
/// interface takes the space the redistributors would have used.
pub const gicv2_cpu_base = 0x0801_0000;
pub const gicv2_distributor_size = 0x1000;
pub const gicv2_cpu_size = 0x2000;

/// The PL011 wants a clock, and the rate only has to be one both sides agree on.
const clock_phandle = 1;
const clock_hz = 24_000_000;

/// Every interrupt in the tree is resolved against the controller, and a node can
/// only be named by a phandle. Without this the timer finds no interrupt and gives
/// up, and the guest runs with no clock at all.
const gic_phandle = 2;

/// The first cell of an `interrupts` entry. A PPI is private to one CPU, an SPI is
/// shared, and the timer is always a PPI.
const ppi = 1;
const spi = 0;

/// Where the virtio devices sit. Each one gets a window and a shared interrupt of its
/// own, one after the other, which is the layout an arm64 Linux guest already expects.
pub const virtio_base = 0x0a00_0000;
pub const virtio_size = 0x200;
pub const virtio_irq = 16;
pub const virtio_intid = 32 + virtio_irq;

/// The second slot, for the channel between the guest and whoever started it.
pub const vsock_base = virtio_base + virtio_size;
pub const vsock_irq = virtio_irq + 1;
pub const vsock_intid = 32 + vsock_irq;

/// The third slot, for the balloon that decides how much of its memory a guest may use.
pub const balloon_base = vsock_base + virtio_size;
pub const balloon_irq = vsock_irq + 1;
pub const balloon_intid = 32 + balloon_irq;

/// The fourth slot, for the network the guest reaches through a helper.
pub const net_base = balloon_base + virtio_size;
pub const net_irq = balloon_irq + 1;
pub const net_intid = 32 + net_irq;

/// The fifth slot, for a directory on the host that the guest mounts.
pub const fs_base = net_base + virtio_size;
pub const fs_irq = net_irq + 1;
pub const fs_intid = 32 + fs_irq;

/// Where the security chip sits. Not a virtio device: it has a register interface of its own, and it
/// needs no interrupt because a guest waits for its answer by reading the status.
pub const tpm_base = 0x0c00_0000;
pub const tpm_size = 0x5000;

/// Level triggered, active low, for every CPU. This is the encoding an arm64 Linux
/// guest expects for the architected timer.
const timer_flags = 0xf08;
pub const uart_irq = 1;

/// What the controller calls it. The first 32 are private to a CPU, so a shared
/// interrupt numbered 1 in the tree is 33 to the controller.
pub const uart_intid = 32 + uart_irq;

/// Which interrupt controller the machine has. KVM emulates a GICv3 in the kernel.
/// Apple lends the guest nothing, and a GICv3 cannot be built for it, so a guest
/// there is given the GICv2 this VMM writes. See `mirage-device/Gicv2.zig`.
pub const Interrupts = union(enum) {
    gic_v3,
    gic_v2: struct { cpu_base: u64 },
};

pub const Config = struct {
    ram_base: u64,
    ram_size: u64,
    cpus: u32,
    cmdline: []const u8,
    uart_base: u64,
    /// Where the initial filesystem was placed, if there is one. The kernel finds it
    /// through these two properties and nowhere else.
    initrd: ?Range = null,
    controller: Interrupts = .gic_v3,
    /// Entropy for the guest to start its random pool with. Without one a kernel
    /// waits, sometimes for a minute or more, before anything that needs randomness
    /// can run. It has to come from the host, and a guest that is given a
    /// predictable seed has predictable randomness.
    rng_seed: ?[]const u8 = null,
    /// Whether the machine has a block device. A tree that names one the VMM did not
    /// build sends the guest to read an address that answers nothing.
    block_device: bool = true,
    /// Whether the machine has a channel to whoever started the guest.
    vsock: bool = false,
    /// Whether the machine has a balloon, which is what lets the memory the guest may use
    /// change while it runs.
    balloon: bool = false,
    /// Whether the machine has a network device.
    net: bool = false,
    /// Whether the guest is told about a directory it may mount.
    share: bool = false,
    /// Whether the machine has a security chip.
    tpm: bool = false,
    /// Where the list of measurements is, if the guest is given one. It has to be inside memory the
    /// guest knows about, because Linux reads it through the map of ordinary memory.
    log: ?Range = null,
};

pub const Range = struct {
    start: u64,
    end: u64,
};

/// Which CPU a hypervisor knows by this position.
///
/// A CPU is named by its affinity, not by the order it was created in, and the levels are packed one
/// byte apart. Only sixteen fit in the lowest level, because a GICv3 addresses that many directly when
/// one CPU sends another an interrupt, so the seventeenth CPU is the first in the next level. A guest
/// told the wrong number here asks for a CPU nothing has, and is refused.
pub fn affinity(index: u32) u32 {
    return (index & 0xf) |
        (((index >> 4) & 0xff) << 8) |
        (((index >> 12) & 0xff) << 16);
}

/// One virtio mmio window. Every device on this transport is described the same way,
/// so the only difference between two of them is where they sit and what they raise.
fn virtioNode(builder: anytype, name: []u8, at: u64, irq: u32) !void {
    try builder.beginNode(try std.fmt.bufPrint(name, "virtio_mmio@{x}", .{at}));
    try builder.propString("compatible", "virtio,mmio");
    try builder.propCells("reg", &cells(at, virtio_size));
    try builder.propCells("interrupts", &.{ spi, irq, 4 });
    try builder.endNode();
}

fn cells(address: u64, size: u64) [4]u32 {
    return .{
        @truncate(address >> 32),
        @truncate(address),
        @truncate(size >> 32),
        @truncate(size),
    };
}

/// The caller owns the blob.
pub fn build(gpa: std.mem.Allocator, config: Config) ![]u8 {
    var builder: dtree.Builder = .init(gpa);
    defer builder.deinit();

    var name: [64]u8 = undefined;

    // The list of measurements sits in ordinary memory, so the guest has to be told not to use it
    // for anything else. Without this the kernel is free to write over it before the chip driver
    // attaches and copies it.
    if (config.log) |where| try builder.reserve(where.start, where.end - where.start);

    try builder.beginNode("");
    try builder.propU32("#address-cells", 2);
    try builder.propU32("#size-cells", 2);
    try builder.propString("compatible", "linux,dummy-virt");
    try builder.propString("model", "mirage");
    try builder.propU32("interrupt-parent", gic_phandle);

    try builder.beginNode("chosen");
    try builder.propString("bootargs", config.cmdline);
    try builder.propString("stdout-path", try std.fmt.bufPrint(&name, "/pl011@{x}", .{config.uart_base}));
    if (config.initrd) |range| {
        try builder.propU64("linux,initrd-start", range.start);
        try builder.propU64("linux,initrd-end", range.end);
    }
    if (config.rng_seed) |seed| try builder.prop("rng-seed", seed);
    try builder.endNode();

    try builder.beginNode(try std.fmt.bufPrint(&name, "memory@{x}", .{config.ram_base}));
    try builder.propString("device_type", "memory");
    try builder.propCells("reg", &cells(config.ram_base, config.ram_size));
    try builder.endNode();

    try builder.beginNode("cpus");
    try builder.propU32("#address-cells", 1);
    try builder.propU32("#size-cells", 0);
    for (0..config.cpus) |index| {
        const id = affinity(@intCast(index));
        try builder.beginNode(try std.fmt.bufPrint(&name, "cpu@{x}", .{id}));
        try builder.propString("device_type", "cpu");
        try builder.propString("compatible", "arm,armv8");
        // The guest reads this and asks the hypervisor to start that CPU by this number, so it has to
        // be the number the hypervisor knows the CPU by and not the order it was made in. The two
        // agree up to sixteen and part company after.
        try builder.propU32("reg", id);
        // The guest brings its other CPUs up with PSCI, which KVM answers itself.
        try builder.propString("enable-method", "psci");
        try builder.endNode();
    }
    try builder.endNode();

    try builder.beginNode("psci");
    try builder.propString("compatible", "arm,psci-0.2");
    // `hvc`, because the call has to reach the hypervisor and not a secure monitor
    // that does not exist here.
    try builder.propString("method", "hvc");
    try builder.endNode();

    try builder.beginNode("timer");
    try builder.propString("compatible", "arm,armv8-timer");
    try builder.propCells("interrupts", &.{
        ppi, 13, timer_flags, // secure physical
        ppi, 14, timer_flags, // non secure physical
        ppi, 11, timer_flags, // virtual
        ppi, 10, timer_flags, // hypervisor
    });
    try builder.propEmpty("always-on");
    try builder.endNode();

    try builder.beginNode(try std.fmt.bufPrint(&name, "intc@{x}", .{gicd_base}));
    try builder.propU32("#interrupt-cells", 3);
    try builder.propU32("#address-cells", 2);
    try builder.propU32("#size-cells", 2);
    try builder.propEmpty("interrupt-controller");
    switch (config.controller) {
        // A distributor and one redistributor for each CPU, and the CPU interface
        // lives in system registers rather than in memory.
        .gic_v3 => {
            try builder.propString("compatible", "arm,gic-v3");
            // One redistributor per CPU, so the window grows with the guest. A window that ran into
            // memory would leave the guest with two things at one address, so a caller that asked for
            // more CPUs than fit is refused before this is built.
            std.debug.assert(config.cpus <= cpusThatFit(config.ram_base));
            try builder.propCells("reg", &(cells(gicd_base, gicd_size) ++
                cells(gicr_base, gicr_stride * @as(u64, config.cpus))));
        },
        // A distributor and a CPU interface, both in memory, which is what makes
        // this one possible to write in a VMM at all.
        .gic_v2 => |v2| {
            try builder.propString("compatible", "arm,cortex-a15-gic");
            try builder.propCells("reg", &(cells(gicd_base, gicv2_distributor_size) ++
                cells(v2.cpu_base, gicv2_cpu_size)));
        },
    }
    try builder.propU32("phandle", gic_phandle);
    try builder.endNode();

    try builder.beginNode(try std.fmt.bufPrint(&name, "pl011@{x}", .{config.uart_base}));
    try builder.propString("compatible", "arm,pl011\x00arm,primecell");
    try builder.propCells("reg", &cells(config.uart_base, 0x1000));
    try builder.propCells("interrupts", &.{ spi, uart_irq, 4 });
    try builder.propCells("clocks", &.{ clock_phandle, clock_phandle });
    try builder.propString("clock-names", "uartclk\x00apb_pclk");
    try builder.endNode();

    if (config.block_device) try virtioNode(&builder, &name, virtio_base, virtio_irq);
    if (config.vsock) try virtioNode(&builder, &name, vsock_base, vsock_irq);
    if (config.balloon) try virtioNode(&builder, &name, balloon_base, balloon_irq);
    if (config.net) try virtioNode(&builder, &name, net_base, net_irq);
    if (config.share) try virtioNode(&builder, &name, fs_base, fs_irq);

    if (config.tpm) {
        try builder.beginNode(try std.fmt.bufPrint(&name, "tpm@{x}", .{tpm_base}));
        // What Linux's memory mapped driver binds to. A guest told any other name does not attach.
        try builder.propString("compatible", "tcg,tpm-tis-mmio");
        try builder.propCells("reg", &cells(tpm_base, tpm_size));
        // Where the list of measurements is, if there is one. Linux copies it from here when the
        // driver attaches and offers it to the guest, so the guest can fold the list for itself and
        // check the answer against the chip. Both are big endian whatever the guest is, which is what
        // the driver reads them as.
        if (config.log) |where| {
            try builder.propU64("linux,sml-base", where.start);
            try builder.propU32("linux,sml-size", @intCast(where.end - where.start));
        }
        try builder.endNode();
    }

    try builder.beginNode("apb-pclk");
    try builder.propString("compatible", "fixed-clock");
    try builder.propU32("#clock-cells", 0);
    try builder.propU32("clock-frequency", clock_hz);
    try builder.propU32("phandle", clock_phandle);
    try builder.endNode();

    try builder.endNode();
    return builder.finish();
}

const sample: Config = .{
    .ram_base = 0x4000_0000,
    .ram_size = 0x0800_0000,
    .cpus = 2,
    .cmdline = "console=ttyAMA0 earlycon=pl011,0x9000000",
    .uart_base = 0x0900_0000,
};

fn read(gpa: std.mem.Allocator, blob: []const u8) !dtree.Reader {
    _ = gpa;
    return dtree.Reader.initBuffer(blob);
}

test "the tree gives the guest the memory it was configured with" {
    const gpa = testing.allocator();
    const blob = try build(gpa, sample);
    defer gpa.free(blob);

    const tree = try read(gpa, blob);
    defer tree.deinit();

    // Two address cells then two size cells, big endian, as the root declares.
    const reg = try tree.find(&.{ "", "memory@40000000", "reg" });
    try testing.expectEqual(@as(usize, 16), reg.len);
    try testing.expectEqual(sample.ram_base, std.mem.readInt(u64, reg[0..8], .big));
    try testing.expectEqual(sample.ram_size, std.mem.readInt(u64, reg[8..16], .big));
}

test "the command line reaches the guest through chosen" {
    const gpa = testing.allocator();
    const blob = try build(gpa, sample);
    defer gpa.free(blob);

    const tree = try read(gpa, blob);
    defer tree.deinit();

    const args = try tree.find(&.{ "", "chosen", "bootargs" });
    try testing.expectEqualSlices(u8, sample.cmdline, args[0 .. args.len - 1]);
}

test "the serial port is described at the address the bus puts it" {
    const gpa = testing.allocator();
    const blob = try build(gpa, sample);
    defer gpa.free(blob);

    const tree = try read(gpa, blob);
    defer tree.deinit();

    const reg = try tree.find(&.{ "", "pl011@9000000", "reg" });
    try testing.expectEqual(sample.uart_base, std.mem.readInt(u64, reg[0..8], .big));

    const compatible = try tree.find(&.{ "", "pl011@9000000", "compatible" });
    try std.testing.expect(std.mem.indexOf(u8, compatible, "arm,pl011") != null);
}

test "every configured cpu is described" {
    const gpa = testing.allocator();
    const blob = try build(gpa, sample);
    defer gpa.free(blob);

    const tree = try read(gpa, blob);
    defer tree.deinit();

    try testing.expectEqual(@as(u32, 0), try tree.findAs(u32, &.{ "", "cpus", "cpu@0", "reg" }));
    try testing.expectEqual(@as(u32, 1), try tree.findAs(u32, &.{ "", "cpus", "cpu@1", "reg" }));
}

test "psci is described as hvc, which is the call kvm services" {
    const gpa = testing.allocator();
    const blob = try build(gpa, sample);
    defer gpa.free(blob);

    const tree = try read(gpa, blob);
    defer tree.deinit();

    const method = try tree.find(&.{ "", "psci", "method" });
    try testing.expectEqualSlices(u8, "hvc\x00", method);
}

test "the interrupt controller is a gic v3" {
    const gpa = testing.allocator();
    const blob = try build(gpa, sample);
    defer gpa.free(blob);

    const tree = try read(gpa, blob);
    defer tree.deinit();

    const compatible = try tree.find(&.{ "", "intc@8000000", "compatible" });
    try testing.expectEqualSlices(u8, "arm,gic-v3\x00", compatible);
}

test "the tree names an interrupt parent so the timer can find its interrupt" {
    const gpa = testing.allocator();
    const blob = try build(gpa, sample);
    defer gpa.free(blob);

    const tree = try read(gpa, blob);
    defer tree.deinit();

    // Without this the kernel reports "arch_timer: No interrupt available, giving up"
    // and runs with no clock. The parent has to be the controller that declares it.
    const parent = try tree.findAs(u32, &.{ "", "interrupt-parent" });
    const phandle = try tree.findAs(u32, &.{ "", "intc@8000000", "phandle" });
    try testing.expectEqual(parent, phandle);
}

test "the tree describes a virtio device where the bus puts it" {
    const gpa = testing.allocator();
    const blob = try build(gpa, sample);
    defer gpa.free(blob);

    const tree = try read(gpa, blob);
    defer tree.deinit();

    const compatible = try tree.find(&.{ "", "virtio_mmio@a000000", "compatible" });
    try testing.expectEqualSlices(u8, "virtio,mmio\x00", compatible);

    const reg = try tree.find(&.{ "", "virtio_mmio@a000000", "reg" });
    try testing.expectEqual(@as(u64, virtio_base), std.mem.readInt(u64, reg[0..8], .big));

    // A shared interrupt, so the first cell is zero and the second is the number the
    // controller adds 32 to.
    const interrupts = try tree.find(&.{ "", "virtio_mmio@a000000", "interrupts" });
    try testing.expectEqual(@as(u32, spi), std.mem.readInt(u32, interrupts[0..4], .big));
    try testing.expectEqual(@as(u32, virtio_irq), std.mem.readInt(u32, interrupts[4..8], .big));
}

test "an apple machine is described with a memory mapped interrupt controller" {
    const gpa = testing.allocator();
    var apple = sample;
    apple.controller = .{ .gic_v2 = .{ .cpu_base = gicv2_cpu_base } };

    const blob = try build(gpa, apple);
    defer gpa.free(blob);

    const tree = try read(gpa, blob);
    defer tree.deinit();

    // A guest on Apple Silicon is told its CPU interface is zero in
    // ID_AA64PFR0_EL1, so it will not drive a GICv3 whatever the tree claims.
    const compatible = try tree.find(&.{ "", "intc@8000000", "compatible" });
    try testing.expectEqualSlices(u8, "arm,cortex-a15-gic\x00", compatible);

    // Two windows: the distributor, then the CPU interface the guest acknowledges
    // interrupts through.
    const reg = try tree.find(&.{ "", "intc@8000000", "reg" });
    try testing.expectEqual(@as(usize, 32), reg.len);
    try testing.expectEqual(@as(u64, gicd_base), std.mem.readInt(u64, reg[0..8], .big));
    try testing.expectEqual(@as(u64, gicv2_distributor_size), std.mem.readInt(u64, reg[8..16], .big));
    try testing.expectEqual(@as(u64, gicv2_cpu_base), std.mem.readInt(u64, reg[16..24], .big));
    try testing.expectEqual(@as(u64, gicv2_cpu_size), std.mem.readInt(u64, reg[24..32], .big));
}

test "the interrupt parent is named whichever controller the machine has" {
    const gpa = testing.allocator();
    var apple = sample;
    apple.controller = .{ .gic_v2 = .{ .cpu_base = gicv2_cpu_base } };

    const blob = try build(gpa, apple);
    defer gpa.free(blob);

    const tree = try read(gpa, blob);
    defer tree.deinit();

    const parent = try tree.findAs(u32, &.{ "", "interrupt-parent" });
    const phandle = try tree.findAs(u32, &.{ "", "intc@8000000", "phandle" });
    try testing.expectEqual(parent, phandle);
}

test "a seed given to the guest is described where the kernel looks for it" {
    const gpa = testing.allocator();
    var seeded = sample;
    seeded.rng_seed = "0123456789abcdef";

    const blob = try build(gpa, seeded);
    defer gpa.free(blob);

    const tree = try read(gpa, blob);
    defer tree.deinit();

    // Without this a kernel waits for entropy before anything needing randomness can
    // run, which on a quiet machine can be a minute or more.
    const found = try tree.find(&.{ "", "chosen", "rng-seed" });
    try testing.expectEqualSlices(u8, "0123456789abcdef", found);
}

test "a machine given no seed says nothing about one" {
    const gpa = testing.allocator();
    const blob = try build(gpa, sample);
    defer gpa.free(blob);

    const tree = try read(gpa, blob);
    defer tree.deinit();

    try testing.expectError(error.NotFound, tree.find(&.{ "", "chosen", "rng-seed" }));
}

test "a machine with a channel names a second virtio window" {
    const gpa = testing.allocator();
    const blob = try build(gpa, .{
        .ram_base = 0x4000_0000,
        .ram_size = 128 << 20,
        .cpus = 1,
        .cmdline = "console=ttyAMA0",
        .uart_base = 0x0900_0000,
        .vsock = true,
    });
    defer gpa.free(blob);

    const tree = try read(gpa, blob);
    defer tree.deinit();

    // Two windows, and they do not overlap. A guest given one address for two devices
    // drives whichever it probed last.
    const block = try tree.find(&.{ "", "virtio_mmio@a000000", "reg" });
    const channel = try tree.find(&.{ "", "virtio_mmio@a000200", "reg" });
    try testing.expectEqual(@as(u64, virtio_base), std.mem.readInt(u64, block[0..8], .big));
    try testing.expectEqual(@as(u64, vsock_base), std.mem.readInt(u64, channel[0..8], .big));

    // And each one raises its own interrupt, or the guest cannot tell them apart.
    const lines = try tree.find(&.{ "", "virtio_mmio@a000200", "interrupts" });
    try testing.expectEqual(@as(u32, vsock_irq), std.mem.readInt(u32, lines[4..8], .big));
}

test "a machine with a network names a fourth virtio window" {
    const gpa = testing.allocator();
    const blob = try build(gpa, .{
        .ram_base = 0x4000_0000,
        .ram_size = 128 << 20,
        .cpus = 1,
        .cmdline = "console=ttyAMA0",
        .uart_base = 0x0900_0000,
        .net = true,
    });
    defer gpa.free(blob);

    const tree = try read(gpa, blob);
    defer tree.deinit();

    // The window the guest is told to look at, and the interrupt it is told to expect. A tree
    // that names neither leaves the driver with nothing to probe.
    const window = try tree.find(&.{ "", "virtio_mmio@a000600", "reg" });
    try testing.expectEqual(@as(u64, net_base), std.mem.readInt(u64, window[0..8], .big));

    const lines = try tree.find(&.{ "", "virtio_mmio@a000600", "interrupts" });
    try testing.expectEqual(@as(u32, net_irq), std.mem.readInt(u32, lines[4..8], .big));
}

test "a machine with a security chip names where it sits" {
    const gpa = testing.allocator();
    const blob = try build(gpa, .{
        .ram_base = 0x4000_0000,
        .ram_size = 128 << 20,
        .cpus = 1,
        .cmdline = "console=ttyAMA0",
        .uart_base = 0x0900_0000,
        .tpm = true,
    });
    defer gpa.free(blob);

    const tree = try read(gpa, blob);
    defer tree.deinit();

    // The name is what a driver binds to. A guest told anything else does not attach, and then it
    // has a chip it cannot reach.
    const name = try tree.find(&.{ "", "tpm@c000000", "compatible" });
    try testing.expectEqualSlices(u8, "tcg,tpm-tis-mmio\x00", name);

    const window = try tree.find(&.{ "", "tpm@c000000", "reg" });
    try testing.expectEqual(@as(u64, tpm_base), std.mem.readInt(u64, window[0..8], .big));
    try testing.expectEqual(@as(u64, tpm_size), std.mem.readInt(u64, window[8..16], .big));
}

test "a guest is told where the list of measurements is" {
    const gpa = testing.allocator();

    const where: Range = .{ .start = 0x4160_0000, .end = 0x4160_01b6 };
    const blob = try build(gpa, .{
        .ram_base = 0x4000_0000,
        .ram_size = 128 << 20,
        .cpus = 1,
        .cmdline = "console=ttyAMA0",
        .uart_base = 0x0900_0000,
        .tpm = true,
        .log = where,
    });
    defer gpa.free(blob);

    const tree = try read(gpa, blob);
    defer tree.deinit();

    // Linux reads both of these as big endian whatever the guest is, and one is eight bytes while the
    // other is four. A driver given them the wrong way round copies the wrong memory and offers the
    // guest a list of nothing.
    const base = try tree.find(&.{ "", "tpm@c000000", "linux,sml-base" });
    try testing.expectEqual(@as(usize, 8), base.len);
    try testing.expectEqual(where.start, std.mem.readInt(u64, base[0..8], .big));

    const length = try tree.find(&.{ "", "tpm@c000000", "linux,sml-size" });
    try testing.expectEqual(@as(usize, 4), length.len);
    try testing.expectEqual(@as(u32, @intCast(where.end - where.start)), std.mem.readInt(u32, length[0..4], .big));
}

test "a guest without a list is told about none" {
    const gpa = testing.allocator();

    const blob = try build(gpa, .{
        .ram_base = 0x4000_0000,
        .ram_size = 128 << 20,
        .cpus = 1,
        .cmdline = "console=ttyAMA0",
        .uart_base = 0x0900_0000,
        .tpm = true,
    });
    defer gpa.free(blob);

    const tree = try read(gpa, blob);
    defer tree.deinit();

    // A property that is there but empty sends the driver looking at address zero. Leaving it out is
    // what makes the driver fall back rather than read nothing and believe it.
    try testing.expectError(error.NotFound, tree.find(&.{ "", "tpm@c000000", "linux,sml-base" }));
    try testing.expectError(error.NotFound, tree.find(&.{ "", "tpm@c000000", "linux,sml-size" }));
}

test "a cpu is named by its affinity, which stops agreeing with its position at sixteen" {
    // The first sixteen are the same number either way, which is why a mistake here shows up only on
    // a guest with more than sixteen CPUs and looks like the seventeenth being broken.
    try testing.expectEqual(@as(u32, 0), affinity(0));
    try testing.expectEqual(@as(u32, 15), affinity(15));

    // The seventeenth starts the next level rather than continuing this one.
    try testing.expectEqual(@as(u32, 0x100), affinity(16));
    try testing.expectEqual(@as(u32, 0x101), affinity(17));
    try testing.expectEqual(@as(u32, 0x10f), affinity(31));
    try testing.expectEqual(@as(u32, 0x200), affinity(32));

    // And the level above that, which is where a guest with more CPUs than a byte holds goes.
    try testing.expectEqual(@as(u32, 0x1_0000), affinity(4096));

    // Every one is different from every other, which is the only property a guest relies on.
    var seen: [256]u32 = undefined;
    for (0..seen.len) |index| seen[index] = affinity(@intCast(index));
    for (seen, 0..) |value, index| {
        for (seen[index + 1 ..]) |other| try std.testing.expect(value != other);
    }
}

test "the tree names each cpu by the number the hypervisor knows it by" {
    const gpa = testing.allocator();

    const blob = try build(gpa, .{
        .ram_base = 0x4000_0000,
        .ram_size = 128 << 20,
        .cpus = 20,
        .cmdline = "console=ttyAMA0",
        .uart_base = 0x0900_0000,
    });
    defer gpa.free(blob);

    const tree = try read(gpa, blob);
    defer tree.deinit();

    // The seventeenth CPU. A tree that called it 16 would send the guest to ask for a CPU nothing has,
    // and the guest would report that one as having failed to boot.
    const reg = try tree.find(&.{ "", "cpus", "cpu@100", "reg" });
    try testing.expectEqual(@as(u32, 0x100), std.mem.readInt(u32, reg[0..4], .big));

    // And the redistributor window covers every CPU, one stride each.
    const window = try tree.find(&.{ "", "intc@8000000", "reg" });
    try testing.expectEqual(gicr_base, std.mem.readInt(u64, window[16..24], .big));
    try testing.expectEqual(@as(u64, gicr_stride * 20), std.mem.readInt(u64, window[24..32], .big));
}

test "the room for cpus follows from the address map" {
    // Thousands, so nothing meets it. What matters is that it is worked out rather than chosen, and
    // that it says none when there is nowhere to put them.
    try std.testing.expect(cpusThatFit(0x4000_0000) > 1000);
    try testing.expectEqual(@as(u64, 0), cpusThatFit(gicr_base));
    try testing.expectEqual(@as(u64, 0), cpusThatFit(0));
}
