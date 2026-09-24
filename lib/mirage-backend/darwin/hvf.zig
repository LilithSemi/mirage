//! The Apple half of the backend.
//!
//! Hypervisor.framework gives a VMM less than KVM does. There is no interrupt
//! controller, no timer and no PSCI, so those are the VMM's own work here, and a raw
//! exception syndrome arrives where KVM would have sent a decoded access.

pub const binding = @import("hvf/binding.zig");
pub const Machine = @import("hvf/Machine.zig");
