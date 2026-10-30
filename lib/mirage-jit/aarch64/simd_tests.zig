//! SIMD and floating point instructions, checked against the machine that runs the tests.
//!
//! On an AArch64 host the same word is executed natively and lifted, from the same starting
//! registers, and the two must leave the same registers behind. The architecture is the oracle, so
//! nothing here says what an instruction should do. The starting registers are chosen to hit the
//! places where implementations disagree: zeros of both signs, infinities, NaNs, the edges of the
//! integer ranges, and values that sit just either side of a rounding or a saturation.
//!
//! Elsewhere the lifted code is only checked to run.
const std = @import("std");
const builtin = @import("builtin");
const testing = @import("mirage-testing");
const guest = @import("mirage-jit").aarch64;
const Cpu = guest.Cpu;
const cases = @import("simd_cases.zig").cases;

const native_host = builtin.cpu.arch == .aarch64;

/// The registers a case may touch, laid out for the assembly below to load and store.
const State = extern struct {
    v: [8][2]u64,
    x: [8]u64,
    nzcv: u64,
};

fn runNative(comptime word: u32, state: *State) void {
    const body = std.fmt.comptimePrint("\n.inst 0x{x}\n", .{word});
    asm volatile (
        \\ ldr x9, [%[s], #192]
        \\ msr nzcv, x9
        \\ ldp q0, q1, [%[s], #0]
        \\ ldp q2, q3, [%[s], #32]
        \\ ldp q4, q5, [%[s], #64]
        \\ ldp q6, q7, [%[s], #96]
        \\ ldp x0, x1, [%[s], #128]
        \\ ldp x2, x3, [%[s], #144]
        \\ ldp x4, x5, [%[s], #160]
        \\ ldp x6, x7, [%[s], #176]
        ++ body ++
            \\ stp q0, q1, [%[s], #0]
            \\ stp q2, q3, [%[s], #32]
            \\ stp q4, q5, [%[s], #64]
            \\ stp q6, q7, [%[s], #96]
            \\ stp x0, x1, [%[s], #128]
            \\ stp x2, x3, [%[s], #144]
            \\ stp x4, x5, [%[s], #160]
            \\ stp x6, x7, [%[s], #176]
            \\ mrs x9, nzcv
            \\ str x9, [%[s], #192]
        :
        : [s] "r" (state),
        : .{ .x0 = true, .x1 = true, .x2 = true, .x3 = true, .x4 = true, .x5 = true, .x6 = true, .x7 = true, .x9 = true, .v0 = true, .v1 = true, .v2 = true, .v3 = true, .v4 = true, .v5 = true, .v6 = true, .v7 = true, .memory = true });
}

fn runLifted(word: u32, state: *State) !void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, word, .little);
    // Not the testing allocator: it remembers every allocation it has ever made, and this makes
    // tens of thousands of compilations.
    var block = try guest.compile(std.heap.smp_allocator, 0x1000, &bytes);
    defer block.deinit();
    var cpu: Cpu = .{};
    for (0..8) |i| {
        cpu.v[i] = state.v[i];
        cpu.x[i] = state.x[i];
    }
    cpu.flags = @intCast(state.nzcv & 0xf000_0000);
    _ = block.run(&cpu);
    for (0..8) |i| {
        state.v[i] = cpu.v[i];
        state.x[i] = cpu.x[i];
    }
    state.nzcv = cpu.flags;
}

/// Bit patterns that live at the edges of the single and double formats, and of the integers.
const interesting = [_]u64{
    0,
    1,
    0xffff_ffff_ffff_ffff,
    0x8000_0000_0000_0000,
    0x7fff_ffff_ffff_ffff,
    0x3ff0_0000_0000_0000, // 1.0
    0xbff0_0000_0000_0000, // -1.0
    0x4000_0000_0000_0000, // 2.0
    0x3fe0_0000_0000_0000, // 0.5
    0x4004_0000_0000_0000, // 2.5
    0xc00c_0000_0000_0000, // -3.5
    0x7ff0_0000_0000_0000, // +inf
    0xfff0_0000_0000_0000, // -inf
    0x7ff8_0000_0000_0000, // quiet NaN
    0x7ff4_0000_0000_0000, // signalling NaN
    0x0000_0000_0000_0001, // smallest denormal
    0x000f_ffff_ffff_ffff,
    0x43e0_0000_0000_0000, // 2^63
    0xc3e0_0000_0000_0000, // -2^63
    0x41e0_0000_0000_0000, // 2^31
    0x43f0_0000_0000_0000, // 2^64
    0x3f80_0000_3f80_0000, // 1.0f twice
    0xbf80_0000_4000_0000,
    0x7f80_0000_ff80_0000, // +inf, -inf singles
    0x7fc0_0000_7fa0_0000, // NaNs
    0x4f00_0000_cf00_0000, // 2^31, -2^31 singles
    0x4f80_0000_5f00_0000, // 2^32, 2^63 singles
    0x3f00_0000_bf00_0000,
    0x4020_0000_c020_0000, // 2.5f, -2.5f
    0x0000_0000_8000_0000,
    0x0000_0000_7fff_ffff,
    0x0000_0000_ffff_ffff,
    0x8000_0000_0000_0001,
    0x00ff_00ff_00ff_00ff,
    0x0123_4567_89ab_cdef,
};

fn pick(random: std.Random) u64 {
    if (random.uintLessThan(u8, 4) != 0) return interesting[random.uintLessThan(usize, interesting.len)];
    return random.int(u64);
}

fn fill(random: std.Random, state: *State) void {
    for (&state.v) |*register| register.* = .{ pick(random), pick(random) };
    for (&state.x) |*register| register.* = pick(random);
    state.nzcv = @as(u64, random.uintLessThan(u8, 16)) << 28;
    // Lanes that are the same register twice are the common case in real code, so some starting
    // states make operands equal.
    if (random.boolean()) state.v[2] = state.v[1];
    if (random.uintLessThan(u8, 8) == 0) state.v[0] = state.v[1];
}

fn same(a: State, b: State) bool {
    return std.mem.eql(u8, std.mem.asBytes(&a), std.mem.asBytes(&b));
}

test "SIMD and floating point instructions agree with the machine they run on" {
    if (!native_host) return error.SkipZigTest;
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const random = prng.random();
    var failed: usize = 0;
    inline for (cases) |case| {
        var bad: usize = 0;
        var first: ?struct { before: State, native: State, lifted: State } = null;
        for (0..400) |_| {
            var before: State = undefined;
            fill(random, &before);
            var native = before;
            runNative(case.word, &native);
            var lifted = before;
            runLifted(case.word, &lifted) catch |err| {
                std.debug.print("{s} ({x:0>8}): {t}\n", .{ case.text, case.word, err });
                bad = 1000;
                break;
            };
            if (!same(native, lifted)) {
                bad += 1;
                if (first == null) first = .{ .before = before, .native = native, .lifted = lifted };
            }
        }
        if (bad != 0) {
            failed += 1;
            std.debug.print("DIFFERS {s} ({x:0>8}): {} of 400 starts\n", .{ case.text, case.word, bad });
            if (first) |f| {
                std.debug.print("  inputs: v1 {x:0>16}_{x:0>16} v2 {x:0>16}_{x:0>16} v3 {x:0>16}_{x:0>16} x1 {x:0>16} nzcv {x}\n", .{ f.before.v[1][1], f.before.v[1][0], f.before.v[2][1], f.before.v[2][0], f.before.v[3][1], f.before.v[3][0], f.before.x[1], f.before.nzcv >> 28 });
                for (0..8) |i| {
                    if (!std.mem.eql(u64, &f.native.v[i], &f.lifted.v[i]))
                        std.debug.print("  v{}: before {x:0>16}_{x:0>16} native {x:0>16}_{x:0>16} lifted {x:0>16}_{x:0>16}\n", .{ i, f.before.v[i][1], f.before.v[i][0], f.native.v[i][1], f.native.v[i][0], f.lifted.v[i][1], f.lifted.v[i][0] });
                    if (f.native.x[i] != f.lifted.x[i])
                        std.debug.print("  x{}: before {x:0>16} native {x:0>16} lifted {x:0>16}\n", .{ i, f.before.x[i], f.native.x[i], f.lifted.x[i] });
                }
                if (f.native.nzcv != f.lifted.nzcv)
                    std.debug.print("  nzcv: before {x} native {x} lifted {x}\n", .{ f.before.nzcv >> 28, f.native.nzcv >> 28, f.lifted.nzcv >> 28 });
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 0), failed);
}

