//! The guest interrupt controller, a GIC v3 that KVM emulates in the kernel.
//!
//! An aarch64 Linux guest will not get far without one. The device tree beside this
//! describes a controller at fixed addresses, and this is what actually creates it,
//! so the two have to agree on where it sits.
//!
//! Order matters and the kernel enforces it. Every vCPU has a redistributor of its
//! own, so every vCPU must exist before the controller is initialised. Adding one
//! afterwards is refused.

const std = @import("std");
const testing = @import("mirage-testing");
const Machine = @import("Machine.zig");
const Vm = @import("Vm.zig");
const ioctl = @import("ioctl.zig");
const arm64 = @import("mirage-arm64");
const device = @import("mirage-device");
const linux = std.os.linux;

const Gic = @This();

const nr = struct {
    const create_device = 0xe0;
    const set_device_attr = 0xe1;
};

/// `KVM_DEV_TYPE_ARM_VGIC_V3`, the seventh entry of `enum kvm_device_type`.
const device_type_vgic_v3 = 7;

/// `KVM_DEV_ARM_VGIC_GRP_*` in `asm/kvm.h`.
const group = struct {
    const addr = 0;
    const nr_irqs = 3;
    const ctrl = 4;
};

/// `KVM_VGIC_V3_ADDR_TYPE_*`.
const addr_type = struct {
    const dist = 2;
    const redist = 3;
};

/// The first 32 interrupts are private to a CPU, so a shared one numbered 1 in the
/// device tree is 33 to the controller and 1 to the kernel.
const spi_base = 32;

/// `KVM_DEV_ARM_VGIC_CTRL_INIT`.
const ctrl_init = 0;

/// The specification counts interrupts in blocks of 32, and a controller needs at
/// least 64. This is enough for the serial port and room to grow.
const interrupts = 256;

/// One redistributor is two 64K frames, so each CPU takes this much space.
pub const redistributor_stride = arm64.fdt.gicr_stride;

pub const CreateDevice = extern struct {
    type: u32,
    fd: u32,
    flags: u32,
};

pub const DeviceAttr = extern struct {
    flags: u32,
    group: u32,
    attr: u64,
    addr: u64,
};

pub const Error = ioctl.Error;

fd: std.posix.fd_t,
vm: *Vm,
/// Interrupts the kernel refused. A failed injection is a runtime fault and not a
/// programmer error, so it is counted and the guest carries on. A guest that then
/// waits forever has this number to explain it.
dropped: u64 = 0,
/// Attributes the kernel would not report or would not take when state was carried.
refused_reads: usize = 0,
refused_writes: usize = 0,

fn attribute(self: Gic, attr_group: u32, attr: u64, addr: u64) Error!void {
    const request: DeviceAttr = .{
        .flags = 0,
        .group = attr_group,
        .attr = attr,
        .addr = addr,
    };
    _ = try ioctl.call(
        self.fd,
        comptime ioctl.request(.write, DeviceAttr, nr.set_device_attr),
        @intFromPtr(&request),
    );
}

pub fn create(vm: *Vm, cpus: u32, dist_base: u64, redist_base: u64) Error!Gic {
    var request: CreateDevice = .{ .type = device_type_vgic_v3, .fd = 0, .flags = 0 };
    _ = try ioctl.call(
        vm.fd,
        comptime ioctl.request(.read_write, CreateDevice, nr.create_device),
        @intFromPtr(&request),
    );

    const self: Gic = .{ .fd = @intCast(request.fd), .vm = vm };
    errdefer _ = linux.close(self.fd);

    // Every attribute below is passed by address, so these locals have to outlive
    // the calls that read them.
    var count: u32 = interrupts;
    var distributor_at = dist_base;
    var redistributor_at = redist_base;

    try self.attribute(group.nr_irqs, 0, @intFromPtr(&count));
    try self.attribute(group.addr, addr_type.dist, @intFromPtr(&distributor_at));
    try self.attribute(group.addr, addr_type.redist, @intFromPtr(&redistributor_at));
    _ = cpus;

    // Nothing may be added to the controller after this.
    try self.attribute(group.ctrl, ctrl_init, 0);
    return self;
}

fn cast(ctx: *anyopaque) *Gic {
    return @ptrCast(@alignCast(ctx));
}

/// The kernel drives the line into the vCPU itself, so there is nothing for a run
/// loop to assert.
fn askSignalled(ctx: *anyopaque, cpu: u32) bool {
    _ = ctx;
    _ = cpu;
    return false;
}

fn inject(self: *Gic, intid: u32, level: bool) void {
    // Only a shared interrupt goes in this way. The timer is private to a CPU and
    // the kernel delivers it, so anything below the shared range is not ours.
    if (intid < spi_base) {
        self.dropped += 1;
        return;
    }
    self.vm.setIrq(intid - spi_base, level) catch {
        self.dropped += 1;
    };
}

fn askRaise(ctx: *anyopaque, intid: u32) void {
    cast(ctx).inject(intid, true);
}

/// The kernel delivers a CPU's own interrupts itself here, the timer included, so there is nothing to do.
fn askRaiseOn(ctx: *anyopaque, cpu: u32, intid: u32) void {
    _ = ctx;
    _ = cpu;
    _ = intid;
}

fn askLower(ctx: *anyopaque, intid: u32) void {
    cast(ctx).inject(intid, false);
}

/// Hand this to a run loop so it can send an interrupt without knowing that the
/// controller behind it is in the kernel.
/// Nothing to say: this controller is the kernel's and it knows which CPU asked.
fn askActing(_: *anyopaque, _: u32) void {}

pub fn controller(self: *Gic) device.Controller {
    return .{
        .ctx = self,
        .signalled = Gic.askSignalled,
        .raise = Gic.askRaise,
        .raiseOn = Gic.askRaiseOn,
        .lower = Gic.askLower,
        .acting = Gic.askActing,
    };
}

pub fn deinit(self: *Gic) void {
    _ = linux.close(self.fd);
    self.* = undefined;
}

/// Reading an attribute back out, which is `KVM_GET_DEVICE_ATTR`. Saving state needs it and
/// nothing else here did, which is why it appears beside `set_device_attr` only now.
const get_device_attr = 0xe2;

/// The groups a GICv3's state lives in. The distributor is shared; the redistributor and the CPU
/// interface belong to one CPU each and carry its address in the high half of the attribute.
/// These are the numbers in `asm/kvm.h` and nowhere else. Writing them from memory put every one
/// of them on the wrong group: the distributor's offsets went to the redistributor, the
/// redistributor's to interrupt translation, and the CPU interface's to the maintenance
/// interrupt, which refuses writes once the controller is running and was the `EBUSY` that took
/// an afternoon.
const state_group = struct {
    const dist_regs = 1;
    const redist_regs = 5;
    const cpu_sysregs = 6;
    const line_level = 7;
};

/// `VGIC_LEVEL_INFO_LINE_LEVEL`, and where it sits in the attribute.
const level_line_level = 0;
const level_info_shift = 10;

/// Where one CPU's identity goes in an attribute, for the groups that belong to a CPU.
const mpidr_shift = 32;

/// The registers of the distributor that hold state rather than describe the hardware.
///
/// A register that says what the controller *is* need not be carried, because the controller it
/// moves to is built the same way. A register that says what the guest *did* must be.
const dist = struct {
    const ctlr = 0x0000;
    const statusr = 0x0010;
    const igroupr = 0x0080;
    const isenabler = 0x0100;
    const ispendr = 0x0200;
    const isactiver = 0x0300;
    const ipriorityr = 0x0400;
    const icfgr = 0x0c00;
    const irouter = 0x6000;
};

/// The same for a redistributor. The second page holds the interrupts private to its CPU.
const redist = struct {
    const ctlr = 0x0000;
    const statusr = 0x0010;
    const waker = 0x0014;
    const propbaser = 0x0070;
    const pendbaser = 0x0078;

    /// The private interrupt page sits one 64K frame along.
    const sgi_page = 0x1_0000;
    const igroupr0 = sgi_page + 0x0080;
    const isenabler0 = sgi_page + 0x0100;
    const ispendr0 = sgi_page + 0x0200;
    const isactiver0 = sgi_page + 0x0300;
    const ipriorityr = sgi_page + 0x0400;
    const icfgr = sgi_page + 0x0c00;
};

/// One register of the CPU interface, named the way the architecture names a system register.
fn sysreg(op0: u64, op1: u64, crn: u64, crm: u64, op2: u64) u64 {
    return (op0 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2;
}

/// The CPU interface registers that hold what the guest set. `ICC_SRE_EL1` comes first on the way
/// back in, because the others mean nothing until the guest has said it is using the system
/// register interface.
///
const cpu_interface = [_]u64{
    sysreg(3, 0, 12, 12, 5), // ICC_SRE_EL1
    sysreg(3, 0, 4, 6, 0), // ICC_PMR_EL1
    sysreg(3, 0, 12, 12, 4), // ICC_CTLR_EL1
    sysreg(3, 0, 12, 12, 6), // ICC_IGRPEN0_EL1
    sysreg(3, 0, 12, 12, 7), // ICC_IGRPEN1_EL1
    sysreg(3, 0, 12, 8, 3), // ICC_BPR0_EL1
    sysreg(3, 0, 12, 12, 3), // ICC_BPR1_EL1
    sysreg(3, 0, 12, 8, 4), // ICC_AP0R0_EL1
    sysreg(3, 0, 12, 9, 0), // ICC_AP1R0_EL1
};

/// Read one attribute of this controller.
fn readAttr(self: Gic, attr_group: u32, attr: u64, into: *u64) Error!void {
    const request: DeviceAttr = .{
        .flags = 0,
        .group = attr_group,
        .attr = attr,
        .addr = @intFromPtr(into),
    };
    _ = try ioctl.call(
        self.fd,
        comptime ioctl.request(.write, DeviceAttr, get_device_attr),
        @intFromPtr(&request),
    );
}

/// Write one attribute of this controller.
fn writeAttr(self: Gic, attr_group: u32, attr: u64, from: *const u64) Error!void {
    const request: DeviceAttr = .{
        .flags = 0,
        .group = attr_group,
        .attr = attr,
        .addr = @intFromPtr(from),
    };
    _ = try ioctl.call(
        self.fd,
        comptime ioctl.request(.write, DeviceAttr, nr.set_device_attr),
        @intFromPtr(&request),
    );
}

/// How many words each block of the distributor takes for `interrupts` lines.
const blocks = struct {
    /// One bit per interrupt.
    const per_bit = interrupts / 32;
    /// One byte per interrupt.
    const per_byte = interrupts / 4;
    /// Two bits per interrupt.
    const per_pair = interrupts / 16;
};

/// Everything the guest set in this controller, as bytes a caller can keep and give back.
///
/// Each entry is the group, then the attribute, then the value. The format is this backend's own,
/// like the vCPU's: a controller saved under KVM is not one another hypervisor could be given.
pub const State = struct {
    /// One saved attribute.
    pub const entry_size = @sizeOf(u32) + @sizeOf(u64) + @sizeOf(u64);

    /// How many attributes are carried, which decides how much room `save` needs.
    pub fn count(cpus: usize) usize {
        const distributor = 2 + blocks.per_bit * 4 + blocks.per_byte + blocks.per_pair +
            (interrupts - spi_base);
        const per_cpu = 5 + 4 + 8 + 2 + cpu_interface.len + blocks.per_bit;
        return distributor + per_cpu * cpus;
    }

    pub fn size(cpus: usize) usize {
        return count(cpus) * entry_size;
    }
};

/// Walk every attribute that holds state, calling `each` with the group and the attribute.
fn walk(cpus: usize, context: anytype, comptime each: fn (@TypeOf(context), u32, u64) Error!void) Error!void {
    const d = state_group.dist_regs;
    try each(context, d, dist.statusr);
    for (0..blocks.per_bit) |i| {
        const at: u64 = @intCast(i * 4);
        try each(context, d, dist.igroupr + at);
        try each(context, d, dist.isenabler + at);
        try each(context, d, dist.ispendr + at);
        try each(context, d, dist.isactiver + at);
    }
    for (0..blocks.per_byte) |i| try each(context, d, dist.ipriorityr + @as(u64, @intCast(i * 4)));
    for (0..blocks.per_pair) |i| try each(context, d, dist.icfgr + @as(u64, @intCast(i * 4)));
    // One eight byte entry per shared interrupt, saying which CPU it goes to.
    for (spi_base..interrupts) |line| {
        try each(context, d, dist.irouter + @as(u64, @intCast(line * 8)));
    }

    for (0..cpus) |cpu| {
        // The CPU's own address, which for a single core guest is simply its number.
        const who: u64 = @as(u64, @intCast(cpu)) << mpidr_shift;
        const r = state_group.redist_regs;
        try each(context, r, who | redist.ctlr);
        try each(context, r, who | redist.statusr);
        try each(context, r, who | redist.waker);
        try each(context, r, who | redist.propbaser);
        try each(context, r, who | redist.pendbaser);

        try each(context, r, who | redist.igroupr0);
        try each(context, r, who | redist.isenabler0);
        try each(context, r, who | redist.ispendr0);
        try each(context, r, who | redist.isactiver0);
        for (0..8) |i| try each(context, r, who | (redist.ipriorityr + @as(u64, @intCast(i * 4))));
        for (0..2) |i| try each(context, r, who | (redist.icfgr + @as(u64, @intCast(i * 4))));

        for (cpu_interface) |reg| try each(context, state_group.cpu_sysregs, who | reg);

        // Which level triggered lines were asserted when the guest was stopped. The serial port's
        // interrupt is one of these, so a guest moved with it asserted loses it without this.
        for (0..blocks.per_bit) |i| {
            const line: u64 = @intCast(i * 32);
            try each(context, state_group.line_level, who | (level_line_level << level_info_shift) | line);
        }
    }

    // The distributor's control register goes last, because it is the switch that turns the
    // controller on. Turning it on before its interrupts have been put back is asking it to run
    // with half a configuration.
    try each(context, d, dist.ctlr);
}

const Saver = struct {
    gic: *Gic,
    into: []u8,
    at: usize = 0,
    /// Attributes the kernel would not report. A controller that names a register it will not
    /// read is not a fault in this code, and the count says how many there were.
    refused: usize = 0,

    fn one(self: *Saver, attr_group: u32, attr: u64) Error!void {
        if (self.at + State.entry_size > self.into.len) return Error.TooBig;

        var value: u64 = 0;
        self.gic.readAttr(attr_group, attr, &value) catch {
            self.refused += 1;
            return;
        };

        std.mem.writeInt(u32, self.into[self.at..][0..4], attr_group, .little);
        std.mem.writeInt(u64, self.into[self.at + 4 ..][0..8], attr, .little);
        std.mem.writeInt(u64, self.into[self.at + 12 ..][0..8], value, .little);
        self.at += State.entry_size;
    }
};

/// Write down everything the guest set in this controller. Returns how many bytes it took.
pub fn save(self: *Gic, cpus: usize, into: []u8) Error!usize {
    var saver: Saver = .{ .gic = self, .into = into };
    try walk(cpus, &saver, Saver.one);
    self.refused_reads = saver.refused;
    return saver.at;
}

/// Put it all back. A register the kernel refuses is counted rather than fatal, because a
/// controller names some registers it will not take and refusing to restore at all would mean
/// never restoring anything.
pub fn load(self: *Gic, from: []const u8) Error!usize {
    var at: usize = 0;
    var written: usize = 0;

    while (at + State.entry_size <= from.len) {
        const attr_group = std.mem.readInt(u32, from[at..][0..4], .little);
        const attr = std.mem.readInt(u64, from[at + 4 ..][0..8], .little);
        const value = std.mem.readInt(u64, from[at + 12 ..][0..8], .little);
        at += State.entry_size;

        self.writeAttr(attr_group, attr, &value) catch {
            self.refused_writes += 1;
            continue;
        };
        written += 1;
    }
    return written;
}

fn openMachine() !Machine {
    return Machine.create(testing.allocator(), 2) catch |err| switch (err) {
        error.NoKvm => error.SkipZigTest,
        else => err,
    };
}

test "a gic v3 is created and placed where the device tree says it is" {
    var machine = try openMachine();
    defer machine.deinit();
    const hv = machine.backend();

    // The redistributors are per CPU, so every CPU has to exist before the
    // controller is initialised. Creating one afterwards is refused by the kernel.
    _ = try hv.addVcpu();

    var gic = try Gic.create(&machine.vm, 1, arm64.fdt.gicd_base, arm64.fdt.gicr_base);
    defer gic.deinit();

    try std.testing.expect(gic.fd > 0);
}

test "a guest still reaches the serial port with an interrupt controller present" {
    var machine = try openMachine();
    defer machine.deinit();

    const ram = 0x4000_0000;
    const region = try machine.vm.addMemory(ram, 4 * std.heap.pageSize(), .shared);
    var memory: @import("../../Backend.zig").GuestMemory = .{ .regions = &.{region} };

    const code = [_]u32{
        0xd2a12001, // movz x1, #0x0900, lsl #16
        0x52800d00, // movz w0, #0x68              'h'
        0xb9000020, // str  w0, [x1]
        0x14000000, // b    .
    };
    try memory.write(ram, std.mem.sliceAsBytes(code[0..]));

    const hv = machine.backend();
    const id = try hv.addVcpu();

    var gic = try Gic.create(&machine.vm, 1, arm64.fdt.gicd_base, arm64.fdt.gicr_base);
    defer gic.deinit();

    var buffer: [8]u8 = undefined;
    var sink = std.Io.Writer.fixed(&buffer);
    var serial: @import("mirage-device").Pl011 = .{ .sink = &sink };
    var devices = [_]@import("mirage-device").Device{serial.device(0x0900_0000)};
    var bus: @import("mirage-device").Bus = .{ .devices = &devices };

    try hv.setRegister(id, .pc, ram);
    switch (try hv.run(id)) {
        .mmio_write => |w| bus.write(w.gpa, w.size, w.value),
        else => return error.TestUnexpectedResult,
    }

    try testing.expectEqualSlices(u8, "h", sink.buffered());
}

test "what the guest set in the controller goes out and comes back" {
    var machine = try openMachine();
    defer machine.deinit();

    const hv = machine.backend();
    _ = try hv.addVcpu();

    var gic = try Gic.create(&machine.vm, 1, arm64.fdt.gicd_base, arm64.fdt.gicr_base);
    defer gic.deinit();

    const gpa = testing.allocator();
    const blob = try gpa.alloc(u8, Gic.State.size(1));
    defer gpa.free(blob);

    const used = try gic.save(1, blob);
    try std.testing.expect(used > 0);

    // Everything read back is offered again, and the controller takes it. The ones it refuses are
    // counted rather than fatal, because a controller names registers it will not take.
    const written = try gic.load(blob[0..used]);
    try std.testing.expect(written > 0);
    try testing.expectEqual(used / Gic.State.entry_size, written + gic.refused_writes);
}
