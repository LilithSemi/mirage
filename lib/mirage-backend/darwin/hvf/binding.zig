//! Hypervisor.framework, reached at run time rather than linked.
//!
//! Apple ships this as a framework, and linking one needs the macOS SDK, which would
//! stop the backend building anywhere but a Mac. Opening the library and looking the
//! symbols up needs neither an SDK nor a line of C, so the whole backend cross
//! compiles from Linux and the no C surface rule holds with no exception.
//!
//! A process calling any of this needs the `com.apple.security.hypervisor`
//! entitlement. An ad hoc signature carries it.

const std = @import("std");
const testing = @import("mirage-testing");

const library = "/System/Library/Frameworks/Hypervisor.framework/Hypervisor";

extern "c" fn dlopen(path: [*:0]const u8, mode: c_int) ?*anyopaque;
extern "c" fn dlsym(handle: ?*anyopaque, name: [*:0]const u8) ?*anyopaque;

/// `RTLD_NOW`. Resolve everything on open, so a missing symbol is found here rather
/// than at the moment a guest needs it.
const resolve_now = 2;

pub const Error = error{
    /// The framework is not on this machine, which means this is not a Mac that can
    /// run a guest.
    NoHypervisor,
    /// The library opened but does not hold what this code expects.
    MissingSymbol,
};

/// `hv_return_t`. Zero is success and everything else is a failure code.
pub const Return = u32;
pub const success: Return = 0;

/// `hv_reg_t`. The general registers come first and in order, so the program counter
/// lands immediately after the last of them.
pub const Reg = enum(u32) {
    x0 = 0,
    x1 = 1,
    x2 = 2,
    x3 = 3,
    /// The frame pointer and the link register, which on this architecture are these two by another
    /// name. A frame record holds the previous one of the first followed by the second.
    x29 = 29,
    x30 = 30,
    pc = 31,
    cpsr = 34,
    _,
};

/// `hv_exit_reason_t`.
pub const ExitReason = enum(u32) {
    canceled = 0,
    exception = 1,
    vtimer_activated = 2,
    unknown = 3,
    _,
};

pub const ExitException = extern struct {
    syndrome: u64,
    virtual_address: u64,
    physical_address: u64,
};

/// `hv_vcpu_exit_t`. The framework writes this and hands the VMM a pointer to it,
/// so the layout has to match or every exit reads as something else.
pub const Exit = extern struct {
    reason: ExitReason,
    exception: ExitException,

    comptime {
        if (@offsetOf(Exit, "exception") != 8) @compileError("the exception follows the reason after padding");
        if (@sizeOf(Exit) != 32) @compileError("hv_vcpu_exit_t is 32 bytes");
    }
};

/// `hv_interrupt_type_t`.
pub const InterruptType = enum(u32) {
    irq = 0,
    fiq = 1,
};

/// `hv_memory_flags_t`.
pub const memory_read: u64 = 1;
pub const memory_write: u64 = 2;
pub const memory_exec: u64 = 4;

/// `hv_sys_reg_t`. Only the ones this VMM touches are named, by the encoding the architecture gives,
/// which is what the framework matches on.
pub const SysReg = enum(u16) {
    /// Which CPU this is, as the guest reads it. A guest asks the power interface to start a CPU by this
    /// number, so it has to be the number the device tree promised for that CPU.
    mpidr_el1 = 0xc005,
    _,
};

pub const Api = struct {
    vm_create: *const fn (config: ?*anyopaque) callconv(.c) Return,
    vm_destroy: *const fn () callconv(.c) Return,
    vm_map: *const fn (host: *anyopaque, guest: u64, size: usize, flags: u64) callconv(.c) Return,
    vm_unmap: *const fn (guest: u64, size: usize) callconv(.c) Return,
    vcpu_create: *const fn (vcpu: *u64, exit: **Exit, config: ?*anyopaque) callconv(.c) Return,
    vcpu_destroy: *const fn (vcpu: u64) callconv(.c) Return,
    vcpu_run: *const fn (vcpu: u64) callconv(.c) Return,
    vcpu_set_reg: *const fn (vcpu: u64, reg: Reg, value: u64) callconv(.c) Return,
    vcpu_get_reg: *const fn (vcpu: u64, reg: Reg, value: *u64) callconv(.c) Return,
    vcpu_set_pending_interrupt: *const fn (vcpu: u64, kind: InterruptType, pending: bool) callconv(.c) Return,
    vcpu_set_vtimer_mask: *const fn (vcpu: u64, masked: bool) callconv(.c) Return,
    vcpu_set_trap_debug_reg_accesses: *const fn (vcpu: u64, trap: bool) callconv(.c) Return,
    vcpu_set_trap_debug_exceptions: *const fn (vcpu: u64, trap: bool) callconv(.c) Return,
    vcpu_set_sys_reg: *const fn (vcpu: u64, reg: SysReg, value: u64) callconv(.c) Return,
    vcpu_get_sys_reg: *const fn (vcpu: u64, reg: SysReg, value: *u64) callconv(.c) Return,

    fn find(handle: ?*anyopaque, comptime T: type, name: [*:0]const u8) Error!T {
        const symbol = dlsym(handle, name) orelse return Error.MissingSymbol;
        // A symbol address carries no alignment of its own, and a function pointer
        // wants one.
        return @ptrCast(@alignCast(symbol));
    }

    pub fn load() Error!Api {
        const handle = dlopen(library, resolve_now) orelse return Error.NoHypervisor;

        var api: Api = undefined;
        inline for (@typeInfo(Api).@"struct".fields) |field| {
            // Every field is named for its symbol with the `hv_` prefix removed, so
            // the two cannot drift apart.
            @field(api, field.name) = try find(handle, field.type, "hv_" ++ field.name);
        }
        return api;
    }
};
