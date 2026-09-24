//! Hypervisor.framework behind the `Backend` interface.
//!
//! This is the file that makes Apple one of the two things a run loop can sit on.
//! KVM hands back a decoded access and services PSCI and the wait instructions in
//! the kernel. Apple hands back a raw syndrome and services none of them, so the
//! work KVM does for free is done here instead, and the result is the same `Exit`
//! either way.
//!
//! Advancing the program counter is this backend's job too. KVM moves it past a
//! faulting instruction itself. Apple leaves the guest pointing at the instruction
//! that trapped, so a backend that forgets runs it again forever.

const std = @import("std");
const testing = @import("mirage-testing");
const Backend = @import("../../Backend.zig");
const arm64 = @import("mirage-arm64");
const hv = @import("binding.zig");

const Machine = @This();

pub const max_vcpus = 8;

/// Every exception this backend sees comes from a 32 bit instruction, so stepping
/// over one is always four bytes.
const instruction_size = 4;

/// How long to wait when a guest says it has nothing to do. Apple reports the wait
/// and does not perform it, so a VMM that re enters straight away turns an idle
/// guest into a busy loop: it spends every entry on the same instruction and real
/// time never advances enough for the timer to come due. Sleeping here lets the
/// clock move.
const idle_wait_ns = 200 * 1000;

/// The state a vCPU starts in. `KVM_ARM_VCPU_INIT` sets this on the other backend
/// and Hypervisor.framework sets none of it, so a guest left alone begins at EL0.
/// From there a hypervisor call is undefined rather than a trap, and the guest
/// vectors into a table it has not written yet.
///
/// `M` is `0b0101`, EL1 using its own stack pointer, and `DAIF` is masked because a
/// guest that has not installed a vector table cannot take an interrupt.
const reset_pstate: u64 = 0x3c5;

pub const Error = hv.Error;

const Vcpu = struct {
    id: u64,
    exit: *hv.Exit,
    /// The register a pending read has to be written back into.
    pending: ?u5 = null,
};

api: hv.Api,
/// Room for exactly the CPUs this machine was asked for.
///
/// The framework binds a CPU to the thread that created it, so every CPU after the first is created on
/// its own thread rather than here. That makes `addVcpu` something several threads call at once, which
/// is why there is a lock: it is held only while a slot is taken, never while a guest runs.
vcpus: []Vcpu,
count: u32 = 0,
adding: std.atomic.Mutex = .unlocked,
gpa: std.mem.Allocator,
/// What the framework actually returned, behind the last `HypervisorFault`.
fault: ?hv.Return = null,
/// Exits this backend dealt with itself, which the run loop never saw.
absorbed: u64 = 0,

pub fn create(gpa: std.mem.Allocator, cpus: u32) Error!Machine {
    std.debug.assert(cpus > 0);

    const api = try hv.Api.load();
    if (api.vm_create(null) != hv.success) return Error.NoHypervisor;

    const room = gpa.alloc(Vcpu, cpus) catch {
        _ = api.vm_destroy();
        return Error.NoHypervisor;
    };
    return .{ .api = api, .vcpus = room, .gpa = gpa };
}

pub fn deinit(self: *Machine) void {
    for (self.vcpus[0..self.count]) |each| _ = self.api.vcpu_destroy(each.id);
    self.gpa.free(self.vcpus);
    _ = self.api.vm_destroy();
    self.* = undefined;
}
/// Give the guest a view of memory the host already holds. The host mapping must not
/// be executable: Apple Silicon refuses a page that is writable and executable, and
/// the guest takes its permission from here rather than from the host mapping.
pub fn map(self: *Machine, host: []u8, guest: u64) Error!void {
    const flags = hv.memory_read | hv.memory_write | hv.memory_exec;
    if (self.api.vm_map(host.ptr, guest, host.len, flags) != hv.success) return Error.NoHypervisor;
}

pub fn backend(self: *Machine) Backend {
    return .{ .ctx = self, .vtable = &vtable };
}

const vtable: Backend.VTable = .{
    .addVcpu = Machine.addVcpu,
    .run = Machine.run,
    .completeMmioRead = Machine.completeMmioRead,
    .setRegister = Machine.setRegister,
    .getRegister = Machine.getRegister,
    .setInterrupt = Machine.setInterrupt,
};

fn cast(ctx: *anyopaque) *Machine {
    return @ptrCast(@alignCast(ctx));
}

fn record(self: *Machine, result: hv.Return) Backend.Error {
    self.fault = result;
    return Backend.Error.HypervisorFault;
}

fn cpu(self: *Machine, id: Backend.VcpuId) Backend.Error!*Vcpu {
    if (id >= self.count) return Backend.Error.NoSuchVcpu;
    return &self.vcpus[id];
}

fn register(reg: Backend.Register) hv.Reg {
    return switch (reg) {
        .pc => .pc,
        .x0 => .x0,
        .x1 => .x1,
        .x2 => .x2,
        .x3 => .x3,
    };
}

/// Make a CPU. This must be called on the thread that will run it, because the framework binds the two.
///
/// Its number is set here rather than left to the framework, because the guest asks the power interface
/// to start a CPU by the number the device tree gave it, and the two have to be the same number.
fn addVcpu(ctx: *anyopaque) Backend.Error!Backend.VcpuId {
    const self = cast(ctx);

    var id: u64 = 0;
    var exit: *hv.Exit = undefined;
    const result = self.api.vcpu_create(&id, &exit, null);
    if (result != hv.success) return self.record(result);

    const state = self.api.vcpu_set_reg(id, .cpsr, reset_pstate);
    if (state != hv.success) return self.record(state);

    // Apple traps the debug registers by default and KVM does not. A guest that
    // cannot touch them stops during early CPU setup, at the `msr osdlr_el1, xzr`
    // every arm64 kernel does, with nothing to say about why. Let the guest own its
    // own debug state, the way it owns it under KVM.
    const registers = self.api.vcpu_set_trap_debug_reg_accesses(id, false);
    if (registers != hv.success) return self.record(registers);

    const exceptions = self.api.vcpu_set_trap_debug_exceptions(id, false);
    if (exceptions != hv.success) return self.record(exceptions);

    // Taking a slot is the only part several threads do at once.
    while (!self.adding.tryLock()) std.atomic.spinLoopHint();
    defer self.adding.unlock();

    if (self.count >= self.vcpus.len) {
        _ = self.api.vcpu_destroy(id);
        return Backend.Error.TooManyVcpus;
    }
    const which: Backend.VcpuId = @intCast(self.count);

    // The affinity the tree promised for this position. The bit that says it is a real CPU is set as
    // well, because that is how the architecture says a number here is one.
    const named = arm64.fdt.affinity(which) | (1 << 31);
    const wrote = self.api.vcpu_set_sys_reg(id, .mpidr_el1, named);
    if (wrote != hv.success) {
        _ = self.api.vcpu_destroy(id);
        return self.record(wrote);
    }

    self.vcpus[which] = .{ .id = id, .exit = exit };
    self.count += 1;
    return which;
}

fn advance(self: *Machine, target: *Vcpu) Backend.Error!void {
    var pc: u64 = 0;
    var result = self.api.vcpu_get_reg(target.id, .pc, &pc);
    if (result != hv.success) return self.record(result);

    result = self.api.vcpu_set_reg(target.id, .pc, pc + instruction_size);
    if (result != hv.success) return self.record(result);
}

fn run(ctx: *anyopaque, id: Backend.VcpuId) Backend.Error!Backend.Exit {
    const self = cast(ctx);
    const target = try self.cpu(id);

    // Some exits are the backend's own business and never reach the run loop. A
    // trapped debug register is one: Apple reports it, KVM does not, and a guest
    // that cannot write one stops during early CPU setup.
    while (true) {
        if (try self.step(target)) |exit| return exit;
    }
}

fn step(self: *Machine, target: *Vcpu) Backend.Error!?Backend.Exit {
    const result = self.api.vcpu_run(target.id);
    if (result != hv.success) return self.record(result);

    return switch (target.exit.reason) {
        .exception => self.exception(target),

        // The timer came due. It is masked here so that re entering the guest does
        // not immediately come straight back out with the same timer still due,
        // which would leave the guest no instructions in between. The mask is
        // lifted when the guest next waits, by which time it has handled it.
        .vtimer_activated => {
            const masked = self.api.vcpu_set_vtimer_mask(target.id, true);
            if (masked != hv.success) return self.record(masked);
            return .timer;
        },

        // The host asked this vCPU to come out. Nothing happened, so it reads as a
        // wait and the guest carries on.
        .canceled => .wfi,
        else => Backend.Error.HypervisorFault,
    };
}

fn exception(self: *Machine, target: *Vcpu) Backend.Error!?Backend.Exit {
    const syndrome = target.exit.exception.syndrome;

    switch (arm64.esr.decode(syndrome)) {
        .data_abort => |abort| {
            // Without a syndrome there is no width and no register, and guessing at
            // either corrupts the guest.
            if (!abort.valid) return Backend.Error.HypervisorFault;

            const address = target.exit.exception.physical_address;

            if (!abort.write) {
                // The value arrives later, through `completeMmioRead`, which is also
                // where the program counter moves.
                target.pending = abort.register;
                return .{ .mmio_read = .{
                    .gpa = address,
                    .size = abort.size,
                    .dest = abort.register,
                } };
            }

            var value: u64 = 0;
            // Register 31 is the zero register, not a general one, so a store from
            // it writes zero rather than whatever x31 would have held.
            if (abort.register != 31) {
                const result = self.api.vcpu_get_reg(target.id, @enumFromInt(abort.register), &value);
                if (result != hv.success) return self.record(result);
            }

            try self.advance(target);
            return .{ .mmio_write = .{ .gpa = address, .size = abort.size, .value = value } };
        },
        // The debug and trace space. This machine has no debug hardware, so a write
        // is dropped and a read answers zero, which is what a guest would find on
        // hardware that has none. Anything outside that space is refused rather
        // than guessed at, because ignoring a register a guest needs is worse than
        // stopping.
        .system_register => |reg| {
            if (!reg.debug()) return Backend.Error.HypervisorFault;

            if (!reg.write and reg.transfer != 31) {
                const zeroed = self.api.vcpu_set_reg(target.id, @enumFromInt(reg.transfer), 0);
                if (zeroed != hv.success) return self.record(zeroed);
            }

            self.absorbed += 1;
            try self.advance(target);
            return null;
        },

        .hvc => {
            // PSCI arrives this way. The function is in x0 and the arguments follow.
            var args: [4]u64 = @splat(0);
            for (0..4) |index| {
                const result = self.api.vcpu_get_reg(target.id, @enumFromInt(index), &args[index]);
                if (result != hv.success) return self.record(result);
            }
            // `hvc` already moved the program counter, so it is not advanced here.
            return .{ .psci = .{
                .function = @truncate(args[0]),
                .args = .{ args[1], args[2], args[3] },
            } };
        },
        .wfi, .wfe => {
            // The guest has gone idle, so it has finished with whatever the timer
            // last raised, and the timer can be armed again.
            const unmasked = self.api.vcpu_set_vtimer_mask(target.id, false);
            if (unmasked != hv.success) return self.record(unmasked);

            var wait: std.c.timespec = .{ .sec = 0, .nsec = idle_wait_ns };
            _ = std.c.nanosleep(&wait, null);

            try self.advance(target);
            return .wfi;
        },
        .unhandled => return Backend.Error.HypervisorFault,
    }
}

fn completeMmioRead(ctx: *anyopaque, id: Backend.VcpuId, value: u64) Backend.Error!void {
    const self = cast(ctx);
    const target = try self.cpu(id);
    const into = target.pending orelse return Backend.Error.HypervisorFault;
    target.pending = null;

    if (into != 31) {
        const result = self.api.vcpu_set_reg(target.id, @enumFromInt(into), value);
        if (result != hv.success) return self.record(result);
    }
    return self.advance(target);
}

/// Assert or release the interrupt line. The controller that decides when is
/// written by the VMM here, because Apple lends the guest none of its own.
fn setInterrupt(ctx: *anyopaque, id: Backend.VcpuId, level: bool) Backend.Error!void {
    const self = cast(ctx);
    const target = try self.cpu(id);
    const result = self.api.vcpu_set_pending_interrupt(target.id, .irq, level);
    if (result != hv.success) return self.record(result);
}

fn setRegister(ctx: *anyopaque, id: Backend.VcpuId, reg: Backend.Register, value: u64) Backend.Error!void {
    const self = cast(ctx);
    const target = try self.cpu(id);
    const result = self.api.vcpu_set_reg(target.id, register(reg), value);
    if (result != hv.success) return self.record(result);
}

fn getRegister(ctx: *anyopaque, id: Backend.VcpuId, reg: Backend.Register) Backend.Error!u64 {
    const self = cast(ctx);
    const target = try self.cpu(id);
    var value: u64 = 0;
    const result = self.api.vcpu_get_reg(target.id, register(reg), &value);
    if (result != hv.success) return self.record(result);
    return value;
}
