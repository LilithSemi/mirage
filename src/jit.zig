//! `mirage run --jit yes`: boots a raw arm64 kernel (and an optional initramfs) on the AArch64 JIT with a
//! serial port and an interrupt controller, and says exactly where and why it stopped.
//!
//! It needs no hypervisor, so it runs on any host. A kernel that does not boot ends with the
//! instruction, the address and the registers of whatever the JIT could not yet do.
const std = @import("std");
const jit = @import("mirage-jit").aarch64;
const core = @import("mirage-core");
/// The guest is aarch64 whatever this host is.
const Launch = core.Launch.For(arm64);
const device = @import("mirage-device");
const arm64 = @import("mirage-arm64");
const attest = @import("mirage-attest");
const GuestMemory = @import("mirage-memory").GuestMemory;
const Options = @import("Options.zig");

const ram_base = 0x4000_0000;
const uart_base = 0x0900_0000;

const default_cmdline = "console=ttyAMA0 earlycon=pl011,0x9000000 nokaslr loglevel=8";

/// The wall clock, enforced from the run loop's host hook because an exit count
/// says nothing about how long a guest has been spinning.
const Deadline = struct {
    io: std.Io,
    until: i96,
    machine: *jit.Machine,
    exits: u64 = 0,
    /// Set when the guest's stack pointer left everything it could validly point at.
    lost_stack: bool = false,
    /// A program counter to stop at, from `--stop-at`, to look at how the guest got
    /// there. Zero is never a place to stop.
    stop_at: u64 = 0,
    reached: bool = false,

    fn step(ctx: *anyopaque) bool {
        const self: *Deadline = @ptrCast(@alignCast(ctx));
        self.exits += 1;
        if (self.stop_at != 0 and self.machine.cpu.pc == self.stop_at) {
            self.reached = true;
            return false;
        }
        // Reading the clock on every exit would cost more than the exit.
        if (self.exits % 4096 != 0) return true;
        return std.Io.Clock.awake.now(self.io).nanoseconds < self.until;
    }
};

pub fn run(gpa: std.mem.Allocator, io: std.Io, out: *std.Io.Writer, options: Options) !void {
    const w = out;
    // The serial console writes through unbuffered, so guest output appears as the guest produces it.
    var console_out = std.Io.File.stdout().writer(io, &.{});
    const console = &console_out.interface;
    try w.flush();

    if (options.kernel.len == 0) {
        try w.writeAll("a kernel is required\n");
        return;
    }
    if (options.cpus != 1) {
        try w.writeAll("the JIT runs one cpu\n");
        return;
    }
    if (options.disk != null or options.vsock != null or options.nat or options.net != null or options.pci or
        options.tpm != null or options.share_count > 0 or options.session != null or options.save != null or
        options.restore != null or options.firmware != null)
    {
        try w.writeAll("the JIT has a serial port and an interrupt controller so far, and no other device\n");
        return;
    }
    const seconds: u64 = options.seconds orelse 20;
    const cmdline: []const u8 = options.cmdline;
    const ram_size: u64 = options.memory << 20;
    const limit: std.Io.Limit = .limited(1 << 30);

    const kernel = try std.Io.Dir.cwd().readFileAlloc(io, options.kernel, gpa, limit);
    defer gpa.free(kernel);
    const initrd: ?[]const u8 = if (options.initrd) |path| try std.Io.Dir.cwd().readFileAlloc(io, path, gpa, limit) else null;
    defer if (initrd) |bytes| gpa.free(bytes);

    const ram = try gpa.alloc(u8, ram_size);
    defer gpa.free(ram);
    @memset(ram, 0);
    const regions = [_]GuestMemory.Region{.{ .gpa = ram_base, .len = ram.len, .backing = .{ .shared = ram } }};
    var memory: GuestMemory = .{ .regions = &regions };

    var manifest: attest.Manifest = .{};
    defer manifest.deinit(gpa);
    const layout = try Launch.prepare(gpa, &memory, &manifest, .{
        .kernel = kernel,
        .cmdline = cmdline,
        .initrd = initrd,
        .controller = .{ .gic_v2 = .{ .cpu_base = arm64.fdt.gicv2_cpu_base } },
        .block_device = false,
        .ram_base = ram_base,
        .ram_size = ram_size,
        .cpus = 1,
        .uart_base = uart_base,
    });

    var gic: device.Gicv2 = .{ .cpus = 1 };
    const gic_devices = gic.devices(arm64.fdt.gicd_base, arm64.fdt.gicv2_cpu_base);
    var serial: device.Pl011 = .{
        .sink = console,
        .line = .{ .controller = gic.controller(), .intid = arm64.fdt.uart_intid },
    };
    var devices = [_]device.Bus.Device{ serial.device(uart_base), gic_devices[0], gic_devices[1] };
    var bus: device.Bus = .{ .devices = &devices };

    var machine = jit.Machine.init(gpa, &memory);
    defer machine.deinit();
    const hv = machine.backend();
    const id = try hv.addVcpu();
    try Launch.enter(hv, id, layout);
    try w.print("entry {x}, device tree {x}\n", .{ layout.entry, layout.device_tree });
    try w.flush();

    var trace: jit.Machine.Trace = .{};
    machine.trace = &trace;
    var deadline: Deadline = .{
        .stop_at = options.stop_at,
        .io = io,
        .machine = &machine,
        .until = std.Io.Clock.awake.now(io).nanoseconds + @as(i96, seconds) * std.time.ns_per_s,
    };
    const result = Launch.run(hv, id, .{
        .bus = &bus,
        .memory = &memory,
        .controller = gic.controller(),
        .exits = std.math.maxInt(u64),
        .host = .{ .ctx = &deadline, .step = Deadline.step },
    });

    try w.writeAll("\n--- stopped: ");
    if (result) |reason| {
        try w.print("{t}\n", .{reason});
    } else |err| {
        try w.print("error {t}\n", .{err});
    }
    try report(&machine, &memory, w);
    if (deadline.lost_stack or deadline.reached) {
        // Oldest first, ending at the block that ran last.
        try w.writeAll("the stack pointer left memory; the last blocks, oldest first:\n");
        const shown: u64 = @min(trace.count, if (deadline.reached) @as(u64, 120) else @as(u64, 24));
        var index = trace.count - shown;
        while (index < trace.count) : (index += 1) {
            const slot = index % jit.Machine.Trace.capacity;
            try w.print("  pc {x}  sp {x}\n", .{ trace.pcs[slot], trace.sps[slot] });
        }
    }
    try w.print("exits {d}, blocks compiled {d}, unmapped bus accesses {d}\n", .{ deadline.exits, machine.cache.blocks.items.len, bus.unmapped });
}

/// What the guest was doing when it stopped: enough to name the next thing to build.
fn report(machine: *jit.Machine, memory: *GuestMemory, w: *std.Io.Writer) !void {
    const cpu = &machine.cpu;
    if (machine.stalled) |why| {
        try w.print("refused at {x}: {s}\n", .{ machine.stalled_at, why });
    }
    try w.print("pc {x}  sp {x}  el {d}  flags {x}\n", .{ cpu.pc, cpu.sp, cpu.system.el, cpu.flags });
    try w.print("esr {x}  elr {x}  far {x}  spsr {x}  sctlr {x}\n", .{
        cpu.system.esr_el1,  cpu.system.elr_el1,   cpu.system.far_el1,
        cpu.system.spsr_el1, cpu.system.sctlr_el1,
    });
    for (cpu.x, 0..) |value, index| {
        try w.print("x{d:<2} {x:0>16}{s}", .{ index, value, if (index % 4 == 3) "\n" else "  " });
    }
    try w.writeAll("\n");

    const at = if (machine.stalled != null) machine.stalled_at else cpu.pc;
    // The last address an exception was taken for, which is what the guest tripped
    // over first; the address above is only where it was left after that.
    if (cpu.system.far_el1 != 0) {
        try w.print("the last fault was on {x}:\n", .{cpu.system.far_el1});
        try dumpWalk(cpu, memory, cpu.system.far_el1, w);
    }
    // A block is refused as a whole, so `at` is where it starts. Walk forward to
    // the first word the decoder will not take: that is the one to build.
    var probe = at;
    var steps: usize = 0;
    while (steps < 64) : (steps += 1) {
        const physical = jit.Translate.translate(&machine.tlb, cpu, memory, probe, .execute) catch {
            try w.print("the address {x} does not translate\n", .{probe});
            try dumpWalk(cpu, memory, probe, w);
            return;
        };
        var bytes: [4]u8 = undefined;
        memory.read(physical, &bytes) catch return;
        const word = std.mem.readInt(u32, &bytes, .little);
        if (jit.Decode.decode(word)) |instruction| {
            if (machine.stalled == null or instruction.terminates()) {
                try w.print("word at {x} (physical {x}): {x:0>8}\n", .{ probe, physical, word });
                return;
            }
        } else |_| {
            try w.print("first word not decoded, at {x} (physical {x}): {x:0>8}\n", .{ probe, physical, word });
            return;
        }
        probe += 4;
    }
}

/// The tables as the guest built them, read the way the architecture says a walk
/// reads them and not through the code under test, so that a disagreement between
/// the two is visible. Assumes a 4 KiB granule, which is the only one advertised.
fn dumpWalk(cpu: *const jit.Cpu, memory: *GuestMemory, virtual: u64, w: *std.Io.Writer) !void {
    const system = cpu.system;
    try w.print("ttbr0 {x}  ttbr1 {x}  tcr {x}  mair {x}\n", .{ system.ttbr0_el1, system.ttbr1_el1, system.tcr_el1, system.mair_el1 });
    const t0sz: u6 = @truncate(system.tcr_el1);
    const t1sz: u6 = @truncate(system.tcr_el1 >> 16);
    try w.print("t0sz {d}  t1sz {d}  tg0 {d}  tg1 {d}  ips {d}\n", .{
        t0sz,                                     t1sz,
        @as(u2, @truncate(system.tcr_el1 >> 14)), @as(u2, @truncate(system.tcr_el1 >> 30)),
        @as(u3, @truncate(system.tcr_el1 >> 32)),
    });
    const upper = (virtual >> 63) != 0;
    var table = (if (upper) system.ttbr1_el1 else system.ttbr0_el1) & 0x0000_ffff_ffff_f000;
    try w.print("walking {x} from the {s} root at {x}\n", .{ virtual, if (upper) "upper" else "lower", table });
    var level: i32 = 0;
    while (level < 4) : (level += 1) {
        const shift: u6 = @intCast(39 - 9 * level);
        const index = (virtual >> shift) & 0x1ff;
        var word: [8]u8 = undefined;
        memory.read(table + index * 8, &word) catch {
            try w.print("  level {d}: table at {x} is outside memory\n", .{ level, table });
            return;
        };
        const entry = std.mem.readInt(u64, &word, .little);
        try w.print("  level {d}: table {x}  index {d}  entry {x}\n", .{ level, table, index, entry });
        if (entry & 3 != 3 or level == 3) return;
        table = entry & 0x0000_ffff_ffff_f000;
    }
}
