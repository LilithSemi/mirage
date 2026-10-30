//! Compiling one lifted AArch64 block for the machine this program is on.
//!
//! Reading the words is Vulcan's work: `lift.region` turns them into IR. What is left here is
//! giving that IR to the native backend and handing the image back as something a run loop can
//! call.
const std = @import("std");
const ir = @import("vulcan-ir");
const vulcan = @import("vulcan-target");
const native = vulcan.native;
const opt = vulcan.opt;
const lift = vulcan.aarch64_guest.lift;
const Cpu = vulcan.aarch64_guest.Cpu;

pub const Error = std.mem.Allocator.Error || native.Error || lift.Error;

/// A translated straight-line block. It owns its executable image; `run` updates
/// guest registers and returns the next guest PC. Calls are valid only on the host
/// architecture selected by Vulcan's native backend.
pub const Block = struct {
    image: native.JittedModule,

    pub fn deinit(self: *Block) void {
        self.image.deinit();
    }

    pub fn run(self: *const Block, cpu: *Cpu) u64 {
        cpu.trap = .none;
        const entry = self.image.entry(*const fn (*Cpu) callconv(.c) u64, "block") orelse unreachable;
        const next_pc = entry(cpu);
        cpu.pc = next_pc;
        return next_pc;
    }
};

/// Compile little-endian AArch64 instructions at `guest_pc` into native code.
pub fn compile(allocator: std.mem.Allocator, guest_pc: u64, bytes: []const u8) Error!Block {
    return compileIn(allocator, allocator, guest_pc, bytes);
}

/// Like `compile`, but everything the translation needs only while it runs comes
/// from `scratch`, which the caller can reset afterwards, and only what the block
/// keeps for its lifetime comes from `allocator`. A block is a few hundred bytes
/// of that and many kilobytes of the other.
pub fn compileIn(scratch: std.mem.Allocator, allocator: std.mem.Allocator, guest_pc: u64, bytes: []const u8) Error!Block {
    var func = ir.function.Function.init(scratch);
    defer func.deinit();
    try lift.region(&func, guest_pc, bytes);
    // Tuning is only an improvement: a pass that gives up leaves the function it was handed
    // correct, so a failure here costs speed and not the block.
    _ = opt.optimize(scratch, &func) catch false;

    const funcs = [_]native.ModuleFunction{.{ .name = "block", .func = &func }};
    var image = try native.jitModule(scratch, &funcs);
    errdefer image.deinit();
    // The module's own bookkeeping was taken from `scratch`, which is about to be
    // reused, so it moves to the allocator that will free it.
    if (@intFromPtr(scratch.ptr) != @intFromPtr(allocator.ptr)) {
        const symbols = try allocator.dupe(@TypeOf(image.symbols[0]), image.symbols);
        errdefer allocator.free(symbols);
        const data = try allocator.dupe(@TypeOf(image.data[0]), image.data);
        image.symbols = symbols;
        image.data = data;
        image.allocator = allocator;
    }
    return .{ .image = image };
}
