//! Native JIT infrastructure parameterized by a guest instruction set.
//! Only AArch64 has a decoder and Mirage backend today.
pub const Cache = @import("mirage-jit/Cache.zig").Cache;
pub const aarch64 = @import("mirage-jit/aarch64.zig");
