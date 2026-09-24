//! The architected timer, as far as a VMM has to care about it.
//!
//! KVM emulates this in the kernel and delivers its interrupt without the VMM ever
//! seeing it. Hypervisor.framework reports that the timer came due as an exit and
//! leaves the interrupt to the VMM, so the number below is what it raises.

const std = @import("std");
const testing = @import("mirage-testing");

/// The virtual timer is private to a CPU, and the first 16 of those are software
/// generated, so its interrupt number is 16 plus its own.
pub const virtual_ppi = 11;
pub const virtual_intid = 16 + virtual_ppi;

test "the virtual timer interrupt is the number a guest device tree names" {
    // The tree says `<1 11 flags>`, a private interrupt numbered 11, and a
    // controller counts that as 27.
    try testing.expectEqual(@as(u32, 27), virtual_intid);
}
