//! The registers a VMM names: the ones the arm64 Linux boot protocol wants written before the
//! first instruction, and the two that say why a guest stopped.
//!
//! The protocol wants the device tree address in `x0` and the other three argument registers
//! zeroed, so they are named here to be set rather than assumed. `esr` and `far` are read rather
//! than written: a guest that faults inside itself never leaves, so they are the only account of
//! what it was doing.

pub const Register = enum {
    pc,
    x0,
    x1,
    x2,
    x3,
    /// `ESR_EL1`, the syndrome of the last exception the guest took to itself. It is not cleared
    /// between exceptions, so it reads as the most recent one whenever it is asked.
    esr,
    /// `FAR_EL1`, the address of the last fault, which means something only for the exception
    /// classes that set it.
    far,
};
