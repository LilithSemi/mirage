//! The memory a guest runs in.
//!
//! No raw slice of guest memory leaves this module. Every borrow goes through
//! `GuestMemory.slice`, which is allowed to refuse. A page the guest never shared has
//! no host mapping under `guest_memfd`, and has none under SEV-SNP either, so a
//! device model that assumes it can address any guest page is a device model that has
//! to be rewritten at tier 3.

pub const GuestMemory = @import("mirage-memory/GuestMemory.zig");

test {
    _ = GuestMemory;
}
