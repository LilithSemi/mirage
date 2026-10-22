//! Turning the words a guest wrote into code this machine runs.
//!
//! A device model holds registers, counters and threads. Compiling the words of a kernel is a
//! compiler's work and does not belong inside a model, so the models carry a seam and whoever
//! fills it lives here. Vulcan does the compiling.
//!
//! Glacier runs RISC-V kernel words for the card model. `aarch64` translates an AArch64 guest and
//! is a Backend for the shared launch loop. Both compile for the host, whatever its architecture.

pub const Glacier = @import("mirage-jit/Glacier.zig");
pub const Cache = @import("mirage-jit/Cache.zig").Cache;
pub const aarch64 = @import("mirage-jit/aarch64.zig");

test {
    _ = Glacier;
    _ = aarch64;
}
