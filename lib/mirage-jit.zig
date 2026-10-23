//! Turning the words a guest wrote into code this machine runs.
//!
//! A device model holds registers, counters and threads. Compiling the words of a kernel is a
//! compiler's work and does not belong inside a model, so the models carry a seam and whoever
//! fills it lives here. Vulcan does the compiling.

pub const Glacier = @import("mirage-jit/Glacier.zig");

test {
    _ = Glacier;
}
