//! Taking an exception and returning from one.
//!
//! Both are here rather than in the translator because both are decisions about
//! where the guest runs next, and a translated block is chosen by the bytes at a
//! program counter it has already seen. Making them traps keeps the vector
//! fetch on the same path as any other instruction fetch, so a vector is
//! translated and executed rather than interpreted.
//!
//! Only the two levels a trimmed `arm64 defconfig` uses are modelled, and only
//! the register bank that matters: there is one set of general registers here,
//! so entering an exception saves the stack pointer for the level being left
//! and loading the one for the level being entered, and there is nothing else
//! to bank. A guest that expects the other levels' banks restored would need
//! real banking, which is what running two levels at once would require.
const std = @import("std");
const Cpu = @import("Cpu.zig");

const Exception = @This();

/// Which of the four vector slots an exception goes to. The sync slot takes
/// every synchronous exception, and the handler tells the rest apart from
/// `ESR_EL1`, which is the split the architecture asks for rather than one made
/// here.
pub const Kind = enum(u2) { sync = 0, irq = 1, fiq = 2, serror = 3 };

/// Why the exception happened, in the two parts `ESR_EL1` keeps: the exception
/// class, which says what sort of thing it was, and the fault status, which
/// says which thing. The handler reads both.
pub const Reason = struct {
    kind: Kind = .sync,
    /// The exception class, at bits 31:26. A data abort from the current level
    /// is `0b100001` and from a lower one `0b100000`; the two differ only in
    /// which level the faulting access was made from.
    ec: u6 = 0,
    /// True when the faulting address was being fetched as an instruction,
    /// which is bit 25 and changes which status codes are legal.
    instruction: bool = false,
    /// The fault status code, in the low bits.
    status: u6 = 0b000100,
};

/// The fault status codes this can report. They are the same for a data and an
/// instruction abort, except that a permission fault on a fetch is `0b001101`.
pub const status = struct {
    pub const translation: u6 = 0b000100;
    pub const permission: u6 = 0b001100;
    pub const permission_fetch: u6 = 0b001101;
};

/// Take an exception. Returns the address of the vector, which is the guest's
/// program counter from then on.
pub fn take(cpu: *Cpu, reason: Reason, fault_address: u64) u64 {
    const from = cpu.system.el;

    // The saved status is where the handler resumes from: flags, masks, level,
    // and the selected stack at EL1.
    const spsr = (@as(u64, cpu.flags) & 0xf000_0000) |
        ((cpu.system.daif & 0xf) << 6) |
        (@as(u64, from & 3) << 2) |
        @as(u64, @intFromBool(cpu.system.spsel));
    cpu.system.spsr_el1 = spsr;

    // The return address is the instruction that raised it, so that a handler
    // which does not change it resumes at the same place and faults again.
    cpu.system.elr_el1 = cpu.pc;
    cpu.system.esr_el1 = (@as(u64, reason.ec) << 26) |
        (@as(u64, @intFromBool(reason.instruction)) << 25) |
        reason.status;
    cpu.system.far_el1 = fault_address;

    // Select the vector using the interrupted PSTATE, before exception entry
    // changes the live selection to SP_EL1.
    const vector_pc = vector(cpu, reason.kind, from);

    // EL1 can be using SP_EL0 (EL1t) or SP_EL1 (EL1h). Save whichever is live,
    // then exceptions at EL1 enter the handler using SP_EL1.
    const live_stack: u8 = if (from == 1 and !cpu.system.spsel) 0 else from & 3;
    cpu.system.sp_el[live_stack] = cpu.sp;
    cpu.system.el = 1;
    cpu.system.spsel = true;
    cpu.sp = cpu.system.sp_el[1];

    // Interrupts are masked on entry. A handler that wants them lowers `DAIF`
    // itself, which is what keeps an exception from re-entering itself.
    cpu.system.daif = 0xf;
    cpu.monitor_valid = false;
    cpu.fault_address = fault_address;

    cpu.pc = vector_pc;
    return cpu.pc;
}

/// The address of the vector for this kind of exception, arrived at from `from`.
///
/// The table is four groups of four slots, and which group an address falls in
/// is what says how it was raised: the first two groups are exceptions taken at
/// EL1, told apart by the stack pointer the configuration selects, and the last
/// two are exceptions taken at EL0, which always arrive with that level's stack
/// pointer. This is the split Linux's own vector table uses.
fn vector(cpu: *const Cpu, kind: Kind, from: u8) u64 {
    const group: u8 = if (from != 1)
        2
    else if (cpu.system.spsel)
        1 // EL1 using SP_EL1 (EL1h)
    else
        0; // EL1 using SP_EL0 (EL1t)
    return cpu.system.vbar_el1 + @as(u64, group) * 0x200 + @as(u64, @backingInt(kind)) * 0x80;
}

/// Return from an exception, resuming where it was taken from. Returns the new
/// program counter.
pub fn eret(cpu: *Cpu) u64 {
    const spsr = cpu.system.spsr_el1;

    // The stack pointer of the level being left is banked before the level
    // changes, or a handler that used the stack would lose what it put there.
    cpu.system.sp_el[cpu.system.el & 3] = cpu.sp;

    // An exception return ends any claim a load-exclusive made before it.
    cpu.monitor_valid = false;
    const to: u8 = @intCast((spsr >> 2) & 3);
    cpu.system.el = to;
    cpu.system.spsel = to == 1 and (spsr & 1) != 0;
    const live_stack: u8 = if (to == 1 and !cpu.system.spsel) 0 else to;
    cpu.sp = cpu.system.sp_el[live_stack];
    // The masks and the condition flags come back together, because a handler
    // that changed them meant to change them for the code it returns to.
    cpu.system.daif = (spsr >> 6) & 0xf;
    cpu.flags = @truncate(spsr & 0xf000_0000);
    cpu.pc = cpu.system.elr_el1;
    return cpu.pc;
}
