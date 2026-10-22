//! AArch64 guest ISA, state, and Mirage backend for the shared JIT cache.
const std = @import("std");
const GuestMemory = @import("mirage-memory").GuestMemory;
const lowering = @import("aarch64/Compile.zig");
pub const Decode = @import("aarch64/Decode.zig");
pub const Identification = @import("aarch64/Identification.zig");

pub const Cpu = @import("aarch64/Cpu.zig");
pub const Translate = @import("aarch64/Translate.zig");
pub const Tlb = Translate.Tlb;
pub const Exception = @import("aarch64/Exception.zig");
pub const Block = lowering.Block;
pub const Error = lowering.Error || GuestMemory.Error || Translate.Fault;
pub const Cache = @import("Cache.zig").Cache(@This());
pub const Machine = @import("aarch64/Machine.zig");
pub const max_instruction_bytes = 4;

pub fn pc(cpu: *const Cpu) u64 {
    return cpu.pc;
}

/// Fetch one instruction. The program counter is a virtual address like any
/// other, so it goes through the same walk as a load; translating it anywhere
/// else would let the fetch and the data side of a page disagree.
pub fn fetch(
    memory: *GuestMemory,
    cpu: *const Cpu,
    tlb: *Translate.Tlb,
    at: u64,
    into: []u8,
) Error!usize {
    const physical = try Translate.translate(tlb, cpu, memory, at, .execute);
    memory.read(physical, into[0..max_instruction_bytes]) catch |err| switch (err) {
        error.OutOfBounds => return error.TranslationFault,
        error.PrivateMemory => return error.TranslationFault,
    };
    return max_instruction_bytes;
}

pub fn terminates(instruction: []const u8) Error!bool {
    const word = std.mem.readInt(u32, instruction[0..4], .little);
    return (try Decode.decode(word)).terminates();
}

pub fn compile(allocator: std.mem.Allocator, guest_pc: u64, bytes: []const u8) Error!Block {
    return lowering.compile(allocator, guest_pc, bytes);
}
