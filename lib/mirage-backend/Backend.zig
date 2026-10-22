//! The hypervisor a vCPU runs on, and the exits it comes back with.
//!
//! KVM hands back a decoded MMIO exit and services PSCI and WFI inside the kernel, so
//! three variants below never occur there. Hypervisor.framework hands back a raw
//! exception and a syndrome register, so that backend decodes the syndrome into this
//! same shape and services PSCI and WFI itself, with its own timer thread. The
//! difference stays here. Nothing above this interface learns which one is under it.

const std = @import("std");
const builtin = @import("builtin");
const testing = @import("mirage-testing");

/// What a backend says that no architecture changes: which CPU, how wide an access, and what a guest
/// did to leave. Kept apart so `For` can give each guest the same ones under their usual names.
pub const shared = struct {
    /// Which CPU. Wide enough that the number of CPUs a guest may have is the hypervisor's business and
    /// never this type's: a machine with hundreds of them is an ordinary machine now.
    pub const VcpuId = u32;

    /// An exit reports a device access, so it uses the same width enum the devices do.
    /// There is one such enum and `mirage-device` owns it.
    pub const Size = @import("mirage-device").Size;

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
        /// x86 guest wrote a byte, word, or dword to a port. aarch64 never produces this.
        port_out: struct { port: u16, size: Size, value: u64 },
        /// x86 guest read from a port; complete it with completeMmioRead. aarch64 never produces this.
        port_in: struct { port: u16, size: Size },
    };

    pub const Error = error{
        TooManyVcpus,
        NoSuchVcpu,
        HypervisorFault,
    };
};

/// The registers a guest names belong to that guest's architecture, so a backend is made for the guest
/// it runs and never for the host it happens to be on. `Guest` is an architecture module, such as
/// `mirage-arm64`: it supplies `Register`. A translator running an aarch64 guest on an x86 host and KVM
/// running an aarch64 guest on an arm host are the same `For(arm64)`; one host can serve several.
pub fn For(comptime Guest: type) type {
    return struct {
        const Backend = @This();

        pub const VcpuId = shared.VcpuId;
        pub const Size = shared.Size;
        pub const GuestMemory = shared.GuestMemory;
        pub const Exit = shared.Exit;
        pub const Error = shared.Error;
        pub const Register = Guest.Register;

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
    };
}

test "a mock backend hands back the exits it was scripted with, in order" {
    var mock: For(host).Mock = .init(&.{
        .{ .mmio_write = .{ .gpa = 0x900_0000, .size = .word, .value = 'M' } },
        .{ .mmio_read = .{ .gpa = 0x900_0018, .size = .word, .dest = 0 } },
        .wfi,
    });
    var backend = mock.backend();
    const cpu = try backend.addVcpu();

    try testing.expectEqual(shared.Exit{ .mmio_write = .{ .gpa = 0x900_0000, .size = .word, .value = 'M' } }, try backend.run(cpu));
    try testing.expectEqual(shared.Exit{ .mmio_read = .{ .gpa = 0x900_0018, .size = .word, .dest = 0 } }, try backend.run(cpu));
    try testing.expectEqual(@as(shared.Exit, .wfi), try backend.run(cpu));
}

test "a mock backend that runs out of scripted exits reports shutdown" {
    var mock: For(host).Mock = .init(&.{.wfi});
    var backend = mock.backend();
    const cpu = try backend.addVcpu();

    _ = try backend.run(cpu);
    try testing.expectEqual(@as(shared.Exit, .shutdown), try backend.run(cpu));
}

test "completing an mmio read records the value the device produced" {
    var mock: For(host).Mock = .init(&.{.{ .mmio_read = .{ .gpa = 0x900_0018, .size = .word, .dest = 3 } }});
    var backend = mock.backend();
    const cpu = try backend.addVcpu();

    _ = try backend.run(cpu);
    try backend.completeMmioRead(cpu, 0x2000_0000);

    try testing.expectEqual(@as(u64, 0x2000_0000), mock.last_completion.?);
}

const arm64 = @import("mirage-arm64");
const host = @import("mirage-arch");

/// The two registers these tests exercise, named per guest so the mock proves the same thing for each:
/// the program counter, and one argument register. The mock is built for a guest, not for the host, so
/// an aarch64 guest is checked on an x86 host and the other way round.
fn registers(comptime Guest: type) struct { pc: Guest.Register, arg: Guest.Register } {
    return if (@hasField(Guest.Register, "rip"))
        .{ .pc = .rip, .arg = .rsi }
    else
        .{ .pc = .pc, .arg = .x0 };
}

fn @"a register set through the interface is the register the backend holds"(comptime Guest: type) !void {
    const B = For(Guest);
    const regs = registers(Guest);
    var mock: B.Mock = .init(&.{});
    var backend = mock.backend();
    const cpu = try backend.addVcpu();

    try backend.setRegister(cpu, regs.pc, 0x4008_0000);
    try backend.setRegister(cpu, regs.arg, 0x4000_0000);

    try testing.expectEqual(@as(u64, 0x4008_0000), mock.register(cpu, regs.pc));
    try testing.expectEqual(@as(u64, 0x4000_0000), mock.register(cpu, regs.arg));
}

fn @"each added vcpu gets its own identifier and its own registers"(comptime Guest: type) !void {
    const B = For(Guest);
    const regs = registers(Guest);
    var mock: B.Mock = .init(&.{});
    var backend = mock.backend();

    const first = try backend.addVcpu();
    const second = try backend.addVcpu();
    try std.testing.expect(first != second);

    try backend.setRegister(first, regs.arg, 1);
    try backend.setRegister(second, regs.arg, 2);
    try testing.expectEqual(@as(u64, 1), mock.register(first, regs.arg));
    try testing.expectEqual(@as(u64, 2), mock.register(second, regs.arg));
}

fn @"a mock backend carries a port write and completes a port read"(comptime Guest: type) !void {
    const B = For(Guest);
    var mock: B.Mock = .init(&.{
        .{ .port_out = .{ .port = 0x3f8, .size = .byte, .value = 'M' } },
        .{ .port_in = .{ .port = 0x3f8, .size = .byte } },
    });
    var backend = mock.backend();
    const cpu = try backend.addVcpu();
    try testing.expectEqual(shared.Exit{ .port_out = .{ .port = 0x3f8, .size = .byte, .value = 'M' } }, try backend.run(cpu));
    try testing.expectEqual(shared.Exit{ .port_in = .{ .port = 0x3f8, .size = .byte } }, try backend.run(cpu));
    try backend.completeMmioRead(cpu, 0x5a);
    try testing.expectEqual(@as(?u64, 0x5a), mock.last_completion);
}

fn @"a register goes in and comes back out through the interface"(comptime Guest: type) !void {
    const B = For(Guest);
    const regs = registers(Guest);
    // A snapshot has to read every register back, and reading is the half of this
    // interface that was missing. The mock is where the shape is checked; the two real
    // backends are checked on the machines that have them.
    var mock: B.Mock = .init(&.{.shutdown});
    const hv = mock.backend();
    const id = try hv.addVcpu();

    try hv.setRegister(id, regs.pc, 0x4008_0000);
    try hv.setRegister(id, regs.arg, 0xdead_beef);

    try testing.expectEqual(@as(u64, 0x4008_0000), try hv.getRegister(id, regs.pc));
    try testing.expectEqual(@as(u64, 0xdead_beef), try hv.getRegister(id, regs.arg));

    // A vCPU nobody made is refused rather than read out of the array behind it.
    try testing.expectError(B.Error.NoSuchVcpu, hv.getRegister(id + 1, regs.pc));
}

test "a register set through the interface is the register the backend holds" {
    try @"a register set through the interface is the register the backend holds"(arm64);
    try @"a register set through the interface is the register the backend holds"(host);
}

test "each added vcpu gets its own identifier and its own registers" {
    try @"each added vcpu gets its own identifier and its own registers"(arm64);
    try @"each added vcpu gets its own identifier and its own registers"(host);
}

test "a mock backend carries a port write and completes a port read" {
    try @"a mock backend carries a port write and completes a port read"(arm64);
    try @"a mock backend carries a port write and completes a port read"(host);
}

test "a register goes in and comes back out through the interface" {
    try @"a register goes in and comes back out through the interface"(arm64);
    try @"a register goes in and comes back out through the interface"(host);
}
