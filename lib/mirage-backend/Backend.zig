//! The hypervisor a vCPU runs on, and the exits it comes back with.
//!
//! KVM hands back a decoded MMIO exit and services PSCI and WFI inside the kernel, so
//! three variants below never occur there. Hypervisor.framework hands back a raw
//! exception and a syndrome register, so that backend decodes the syndrome into this
//! same shape and services PSCI and WFI itself, with its own timer thread. The
//! difference stays here. Nothing above this interface learns which one is under it.

const std = @import("std");
const testing = @import("mirage-testing");

const Backend = @This();

/// Which CPU. Wide enough that the number of CPUs a guest may have is the hypervisor's business and
/// never this type's: a machine with hundreds of them is an ordinary machine now.
pub const VcpuId = u32;

/// An exit reports a device access, so it uses the same width enum the devices do.
/// There is one such enum and `mirage-device` owns it.
pub const Size = @import("mirage-device").Size;

/// The registers the arm64 Linux boot protocol needs before the first instruction.
/// The protocol requires `x1` through `x3` to be zero, so they are named here to be
/// set rather than assumed.
pub const Register = enum { pc, x0, x1, x2, x3 };

pub const GuestMemory = @import("mirage-memory").GuestMemory;

pub const Exit = union(enum) {
    mmio_read: struct { gpa: u64, size: Size, dest: u5 },
    mmio_write: struct { gpa: u64, size: Size, value: u64 },
    psci: struct { function: u32, args: [3]u64 },
    wfi,
    /// The virtual timer came due. Only Apple sends this, because KVM delivers the
    /// timer interrupt itself. Something has to turn it into an interrupt.
    timer,
    /// The guest was still running and a signal took the CPU back. This is how a VMM
    /// reaches a guest that is blocked and making no exits of its own, so it is an exit
    /// like any other and never a fault.
    interrupted,
    shutdown,
    reset,
};

pub const Error = error{
    TooManyVcpus,
    NoSuchVcpu,
    HypervisorFault,
};

pub const VTable = struct {
    /// Assert or release the interrupt line into a vCPU. Apple needs this, because
    /// the controller that drives the line is written by the VMM. KVM does not: its
    /// controller lives in the kernel and drives the line itself.
    setInterrupt: *const fn (ctx: *anyopaque, vcpu: VcpuId, level: bool) Error!void,
    addVcpu: *const fn (ctx: *anyopaque) Error!VcpuId,
    run: *const fn (ctx: *anyopaque, vcpu: VcpuId) Error!Exit,
    /// KVM writes the value into `kvm_run`, and Hypervisor.framework writes a
    /// register and moves the program counter. A caller does neither.
    completeMmioRead: *const fn (ctx: *anyopaque, vcpu: VcpuId, value: u64) Error!void,
    setRegister: *const fn (ctx: *anyopaque, vcpu: VcpuId, reg: Register, value: u64) Error!void,
    /// Read one back. A snapshot needs every register, and a test that has to reach past
    /// this interface to read one is a test that proves less than it looks like it does.
    getRegister: *const fn (ctx: *anyopaque, vcpu: VcpuId, reg: Register) Error!u64,
};

ctx: *anyopaque,
vtable: *const VTable,

pub fn addVcpu(self: Backend) Error!VcpuId {
    return self.vtable.addVcpu(self.ctx);
}

pub fn run(self: Backend, vcpu: VcpuId) Error!Exit {
    return self.vtable.run(self.ctx, vcpu);
}

pub fn completeMmioRead(self: Backend, vcpu: VcpuId, value: u64) Error!void {
    return self.vtable.completeMmioRead(self.ctx, vcpu, value);
}

pub fn setRegister(self: Backend, vcpu: VcpuId, reg: Register, value: u64) Error!void {
    return self.vtable.setRegister(self.ctx, vcpu, reg, value);
}

pub fn getRegister(self: Backend, vcpu: VcpuId, reg: Register) Error!u64 {
    return self.vtable.getRegister(self.ctx, vcpu, reg);
}

pub fn setInterrupt(self: Backend, vcpu: VcpuId, level: bool) Error!void {
    return self.vtable.setInterrupt(self.ctx, vcpu, level);
}

/// A backend with no hypervisor under it, so the run loop above can be tested on a
/// machine that has none, and on a target that has no operating system at all.
pub const Mock = struct {
    pub const max_vcpus = 8;

    script: []const Exit,
    next: usize = 0,
    vcpus: u32 = 0,
    registers: [max_vcpus]std.EnumArray(Register, u64) = @splat(.initFill(0)),
    last_completion: ?u64 = null,
    /// The last level the run loop asked for, so a test can see the line move.
    interrupt: bool = false,

    pub fn init(script: []const Exit) Mock {
        return .{ .script = script };
    }

    pub fn backend(self: *Mock) Backend {
        return .{ .ctx = self, .vtable = &vtable };
    }

    pub fn register(self: *const Mock, vcpu: VcpuId, reg: Register) u64 {
        return self.registers[vcpu].get(reg);
    }

    const vtable: VTable = .{
        .addVcpu = Mock.addVcpu,
        .run = Mock.run,
        .completeMmioRead = Mock.completeMmioRead,
        .setRegister = Mock.setRegister,
        .getRegister = Mock.getRegister,
        .setInterrupt = Mock.setInterrupt,
    };

    fn cast(ctx: *anyopaque) *Mock {
        return @ptrCast(@alignCast(ctx));
    }

    fn addVcpu(ctx: *anyopaque) Error!VcpuId {
        const self = cast(ctx);
        if (self.vcpus >= max_vcpus) return Error.TooManyVcpus;
        defer self.vcpus += 1;
        return self.vcpus;
    }

    fn run(ctx: *anyopaque, vcpu: VcpuId) Error!Exit {
        const self = cast(ctx);
        if (vcpu >= self.vcpus) return Error.NoSuchVcpu;
        if (self.next >= self.script.len) return .shutdown;
        defer self.next += 1;
        return self.script[self.next];
    }

    fn completeMmioRead(ctx: *anyopaque, vcpu: VcpuId, value: u64) Error!void {
        const self = cast(ctx);
        if (vcpu >= self.vcpus) return Error.NoSuchVcpu;
        self.last_completion = value;
    }

    fn setRegister(ctx: *anyopaque, vcpu: VcpuId, reg: Register, value: u64) Error!void {
        const self = cast(ctx);
        if (vcpu >= self.vcpus) return Error.NoSuchVcpu;
        self.registers[vcpu].set(reg, value);
    }

    fn getRegister(ctx: *anyopaque, vcpu: VcpuId, reg: Register) Error!u64 {
        const self = cast(ctx);
        if (vcpu >= self.vcpus) return Error.NoSuchVcpu;
        return self.registers[vcpu].get(reg);
    }

    fn setInterrupt(ctx: *anyopaque, vcpu: VcpuId, level: bool) Error!void {
        const self = cast(ctx);
        if (vcpu >= self.vcpus) return Error.NoSuchVcpu;
        self.interrupt = level;
    }
};

test "a mock backend hands back the exits it was scripted with, in order" {
    var mock: Mock = .init(&.{
        .{ .mmio_write = .{ .gpa = 0x900_0000, .size = .word, .value = 'M' } },
        .{ .mmio_read = .{ .gpa = 0x900_0018, .size = .word, .dest = 0 } },
        .wfi,
    });
    var backend = mock.backend();
    const cpu = try backend.addVcpu();

    try testing.expectEqual(Exit{ .mmio_write = .{ .gpa = 0x900_0000, .size = .word, .value = 'M' } }, try backend.run(cpu));
    try testing.expectEqual(Exit{ .mmio_read = .{ .gpa = 0x900_0018, .size = .word, .dest = 0 } }, try backend.run(cpu));
    try testing.expectEqual(@as(Exit, .wfi), try backend.run(cpu));
}

test "a mock backend that runs out of scripted exits reports shutdown" {
    var mock: Mock = .init(&.{.wfi});
    var backend = mock.backend();
    const cpu = try backend.addVcpu();

    _ = try backend.run(cpu);
    try testing.expectEqual(@as(Exit, .shutdown), try backend.run(cpu));
}

test "completing an mmio read records the value the device produced" {
    var mock: Mock = .init(&.{.{ .mmio_read = .{ .gpa = 0x900_0018, .size = .word, .dest = 3 } }});
    var backend = mock.backend();
    const cpu = try backend.addVcpu();

    _ = try backend.run(cpu);
    try backend.completeMmioRead(cpu, 0x2000_0000);

    try testing.expectEqual(@as(u64, 0x2000_0000), mock.last_completion.?);
}

test "a register set through the interface is the register the backend holds" {
    var mock: Mock = .init(&.{});
    var backend = mock.backend();
    const cpu = try backend.addVcpu();

    try backend.setRegister(cpu, .pc, 0x4008_0000);
    try backend.setRegister(cpu, .x0, 0x4000_0000);

    try testing.expectEqual(@as(u64, 0x4008_0000), mock.register(cpu, .pc));
    try testing.expectEqual(@as(u64, 0x4000_0000), mock.register(cpu, .x0));
}

test "each added vcpu gets its own identifier and its own registers" {
    var mock: Mock = .init(&.{});
    var backend = mock.backend();

    const first = try backend.addVcpu();
    const second = try backend.addVcpu();
    try std.testing.expect(first != second);

    try backend.setRegister(first, .x0, 1);
    try backend.setRegister(second, .x0, 2);
    try testing.expectEqual(@as(u64, 1), mock.register(first, .x0));
    try testing.expectEqual(@as(u64, 2), mock.register(second, .x0));
}

test "a register goes in and comes back out through the interface" {
    // A snapshot has to read every register back, and reading is the half of this
    // interface that was missing. The mock is where the shape is checked; the two real
    // backends are checked on the machines that have them.
    var mock: Mock = .init(&.{.shutdown});
    const hv = mock.backend();
    const id = try hv.addVcpu();

    try hv.setRegister(id, .pc, 0x4008_0000);
    try hv.setRegister(id, .x0, 0xdead_beef);

    try testing.expectEqual(@as(u64, 0x4008_0000), try hv.getRegister(id, .pc));
    try testing.expectEqual(@as(u64, 0xdead_beef), try hv.getRegister(id, .x0));

    // A vCPU nobody made is refused rather than read out of the array behind it.
    try testing.expectError(Error.NoSuchVcpu, hv.getRegister(id + 1, .pc));
}
