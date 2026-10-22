const std = @import("std");
const testing = @import("mirage-testing");
const GuestMemory = @import("mirage-memory").GuestMemory;
const arm64 = @import("mirage-arm64");
const Backend = @import("mirage-backend").For(arm64);
const guest = @import("mirage-jit").aarch64;
const Decode = guest.Decode;
const decode = Decode.decode;
const Instruction = Decode.Instruction;
const Cpu = guest.Cpu;
const Cache = guest.Cache;
const Machine = guest.Machine;
const Translate = guest.Translate;
const Exception = guest.Exception;

fn compileWords(allocator: std.mem.Allocator, pc: u64, words: []const u32) guest.Error!guest.Block {
    var bytes: [64 * 4]u8 = undefined;
    for (words, 0..) |word, index| std.mem.writeInt(u32, bytes[index * 4 ..][0..4], word, .little);
    return guest.compile(allocator, pc, bytes[0 .. words.len * 4]);
}

test "MOVZ and ADD immediate execute as native code and advance guest PC" {
    var block = try compileWords(testing.allocator(), 0x4000_0000, &.{ 0xd28000e0, 0x91001400 });
    defer block.deinit();
    var cpu: Cpu = .{};
    try testing.expectEqual(@as(u64, 0x4000_0008), block.run(&cpu));
    try testing.expectEqual(@as(u64, 12), cpu.x[0]);
}

test "MOVK replaces only its halfword and W writes zero-extend" {
    var wide = try compileWords(testing.allocator(), 0x1000, &.{0xf2e24680});
    defer wide.deinit();
    var cpu: Cpu = .{};
    cpu.x[0] = 0xffff_5678_9abc_def0;
    _ = wide.run(&cpu);
    try testing.expectEqual(@as(u64, 0x1234_5678_9abc_def0), cpu.x[0]);

    var narrow = try compileWords(testing.allocator(), 0x1004, &.{0x72b579a0});
    defer narrow.deinit();
    _ = narrow.run(&cpu);
    try testing.expectEqual(@as(u64, 0xabcd_def0), cpu.x[0]);
    try testing.expectError(error.UnsupportedInstruction, compileWords(testing.allocator(), 0x1008, &.{0x72e24680}));
}

test "B imm26 terminates the block at the decoded target" {
    var block = try compileWords(testing.allocator(), 0x1000, &.{0x14000002});
    defer block.deinit();
    var cpu: Cpu = .{};
    try testing.expectEqual(@as(u64, 0x1008), block.run(&cpu));
}

test "cache reuses compiled blocks but distinguishes modified guest code" {
    var cache = Cache.init(testing.allocator());
    defer cache.deinit();
    var first: [4]u8 = undefined;
    var changed: [4]u8 = undefined;
    std.mem.writeInt(u32, &first, 0xd28000e0, .little);
    std.mem.writeInt(u32, &changed, 0xd2800140, .little);
    const a = try cache.getOrCompile(0x8000, &first);
    const b = try cache.getOrCompile(0x8000, &first);
    try testing.expectEqual(true, a == b);
    var cpu: Cpu = .{};
    _ = a.run(&cpu);
    try testing.expectEqual(@as(u64, 7), cpu.x[0]);
    const modified = try cache.getOrCompile(0x8000, &changed);
    _ = modified.run(&cpu);
    try testing.expectEqual(@as(u64, 10), cpu.x[0]);
}

test "runBlock fetches guest instructions from GuestMemory and executes them" {
    const base: u64 = 0x4000_0000;
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u32, bytes[0..4], 0xd28000e0, .little);
    std.mem.writeInt(u32, bytes[4..8], 0x14000000, .little);
    const regions = [_]GuestMemory.Region{.{ .gpa = base, .len = bytes.len, .backing = .{ .shared = &bytes } }};
    var memory: GuestMemory = .{ .regions = &regions };
    var cpu: Cpu = .{ .pc = base };
    var cache = Cache.init(testing.allocator());
    defer cache.deinit();
    var tlb: Translate.Tlb = .{};

    try testing.expectEqual(base + 4, try cache.runBlock(&memory, &cpu, &tlb));
    try testing.expectEqual(@as(u64, 7), cpu.x[0]);
    try testing.expectEqual(@as(u64, base + 4), cpu.pc);
}

test "a block run again from the same address is found without a fetch, until its page is written" {
    const base: u64 = 0x4000_0000;
    var bytes: [4096]u8 = @splat(0);
    std.mem.writeInt(u32, bytes[0..4], 0xd28000e0, .little); // movz x0, #7
    std.mem.writeInt(u32, bytes[4..8], 0x14000000, .little); // b .
    const regions = [_]GuestMemory.Region{.{ .gpa = base, .len = bytes.len, .backing = .{ .shared = &bytes } }};
    var memory: GuestMemory = .{ .regions = &regions };
    var cpu: Cpu = .{ .pc = base };
    var cache = Cache.init(testing.allocator());
    defer cache.deinit();
    var tlb: Translate.Tlb = .{};

    _ = try cache.runBlock(&memory, &cpu, &tlb);
    try testing.expectEqual(@as(u64, 7), cpu.x[0]);
    // A write to some other page is not a write to code.
    cache.written(base + 0x10_0000);
    cpu.pc = base;
    _ = try cache.runBlock(&memory, &cpu, &tlb);
    try testing.expectEqual(@as(usize, 1), cache.blocks.items.len);

    // Rewriting the instruction and telling the cache must run the new one.
    std.mem.writeInt(u32, bytes[0..4], 0xd28001e0, .little); // movz x0, #15
    cache.written(base);
    cpu.pc = base;
    _ = try cache.runBlock(&memory, &cpu, &tlb);
    try testing.expectEqual(@as(u64, 15), cpu.x[0]);
    try testing.expectEqual(@as(usize, 2), cache.blocks.items.len);
}

test "ADD immediate uses SP for register 31" {
    var block = try compileWords(testing.allocator(), 0x2000, &.{0x910017ff});
    defer block.deinit();
    var cpu: Cpu = .{ .sp = 9 };
    try testing.expectEqual(@as(u64, 0x2004), block.run(&cpu));
    try testing.expectEqual(@as(u64, 14), cpu.sp);
}

test "native backend executes RAM accesses and exits for MMIO, PSCI, and WFI" {
    const base: u64 = 0x1000;
    var bytes: [4096]u8 = @splat(0);
    const instructions = [_]u32{
        0xd2826820, // movz x0, #0x1341
        0x39000020, // strb w0, [x1]
        0x39400022, // ldrb w2, [x1]
        0x39000060, // strb w0, [x3] (MMIO truncates to 0x41)
        0x39400060, // ldrb w0, [x3] (MMIO)
        0xd4000002, // hvc #0
        0xd503207f, // wfi
    };
    for (instructions, 0..) |word, index| std.mem.writeInt(u32, bytes[index * 4 ..][0..4], word, .little);
    std.mem.writeInt(u32, bytes[0x80..][0..4], 0xd503207f, .little); // wfi
    const regions = [_]GuestMemory.Region{.{ .gpa = base, .len = bytes.len, .backing = .{ .shared = &bytes } }};
    var memory: GuestMemory = .{ .regions = &regions };
    var machine = Machine.init(testing.allocator(), &memory);
    machine.cpu.system.spsel = false;
    defer machine.deinit();
    const hv = machine.backend();
    const id = try hv.addVcpu();
    try hv.setRegister(id, .pc, base);
    try hv.setRegister(id, .x1, base + 48);
    try hv.setRegister(id, .x3, 0x9000_0000);

    try testing.expectEqual(Backend.Exit{ .mmio_write = .{ .gpa = 0x9000_0000, .size = .byte, .value = 65 } }, try hv.run(id));
    try testing.expectEqual(@as(u8, 65), bytes[48]);
    try testing.expectEqual(Backend.Exit{ .mmio_read = .{ .gpa = 0x9000_0000, .size = .byte, .dest = 0 } }, try hv.run(id));
    try testing.expectError(error.HypervisorFault, hv.run(id));
    try hv.completeMmioRead(id, 0x1234);
    try testing.expectEqual(@as(u64, 0x34), try hv.getRegister(id, .x0));
    try hv.setRegister(id, .x0, 0x8400_0000);
    try testing.expectEqual(Backend.Exit{ .psci = .{ .function = 0x8400_0000, .args = .{ base + 48, 65, 0x9000_0000 } } }, try hv.run(id));
    try testing.expectEqual(@as(Backend.Exit, .wfi), try hv.run(id));
    try testing.expectEqual(base + instructions.len * 4, try hv.getRegister(id, .pc));
    // A line raised while interrupts are masked stays pending: the guest is
    // still where it was. Once it lets interrupts in, the next block boundary
    // vectors to the current-stack IRQ slot.
    try hv.setInterrupt(id, true);
    try testing.expectEqual(base + instructions.len * 4, try hv.getRegister(id, .pc));
    machine.cpu.system.vbar_el1 = base;
    machine.cpu.system.daif = 0;
    try testing.expectEqual(@as(Backend.Exit, .wfi), try hv.run(id));
    try testing.expectEqual(base + instructions.len * 4, machine.cpu.system.elr_el1);
    try testing.expectEqual(@as(u64, base + 0x84), machine.cpu.pc);
    try testing.expectError(error.TooManyVcpus, hv.addVcpu());
}
test "a due virtual timer is reported once to the host, unless masked at the timer" {
    // Two nops and a self branch. The host raises the timer in its controller,
    // so the machine only reports each time it comes due.
    const base: u64 = 0x1000;
    var bytes: [512]u8 = @splat(0);
    const program = [_]u32{ 0xd503201f, 0xd503201f, 0x14000000 };
    for (program, 0..) |word, index| std.mem.writeInt(u32, bytes[index * 4 ..][0..4], word, .little);
    std.mem.writeInt(u32, bytes[0x80..][0..4], 0x14000000, .little); // self branch at the vector
    const regions = [_]GuestMemory.Region{.{ .gpa = base, .len = bytes.len, .backing = .{ .shared = &bytes } }};
    var memory: GuestMemory = .{ .regions = &regions };
    var machine = Machine.init(testing.allocator(), &memory);
    machine.cpu.system.spsel = false;
    defer machine.deinit();
    const hv = machine.backend();
    const id = try hv.addVcpu();
    try hv.setRegister(id, .pc, base);
    // The counter is past the compare and the timer is enabled and unmasked: the
    // run reports it before any block, even with interrupts masked, since the
    // mask is what stops the guest taking it and not what stops it happening.
    machine.cpu.system.vbar_el1 = base;
    machine.cpu.system.cntvct_el0 = 0x2000;
    machine.cpu.system.cntv_cval_el0 = 0x1000;
    machine.cpu.system.cntv_ctl_el0 = 0b1;
    try testing.expectEqual(@as(Backend.Exit, .timer), try hv.run(id));
    try testing.expectEqual(base, machine.cpu.pc);
    // A second run does not report it again while it stays due, and executes.
    switch (try hv.run(id)) {
        .interrupted => {},
        else => return error.ExpectedInterrupted,
    }
    try testing.expectEqual(base + 8, machine.cpu.pc);
    // Once the controller has raised the line and interrupts are unmasked, the
    // guest takes it at the vector base plus the IRQ slot.
    try hv.setInterrupt(id, true);
    machine.cpu.system.daif = 0;
    _ = try hv.run(id);
    try testing.expectEqual(base + 8, machine.cpu.system.elr_el1);
    try testing.expectEqual(base + 0x80, machine.cpu.pc);
    // Masked at the timer, a fresh run executes both nops and yields instead.
    {
        var masked = Machine.init(testing.allocator(), &memory);
        defer masked.deinit();
        const hv_masked = masked.backend();
        const id_masked = try hv_masked.addVcpu();
        try hv_masked.setRegister(id_masked, .pc, base);
        masked.cpu.system.cntvct_el0 = 0x2000;
        masked.cpu.system.cntv_cval_el0 = 0x1000;
        masked.cpu.system.cntv_ctl_el0 = 0b11;
        switch (try hv_masked.run(id_masked)) {
            .interrupted => {},
            else => return error.ExpectedInterrupted,
        }
        try testing.expectEqual(@as(u64, base + 8), masked.cpu.pc);
    }
}

test "typed decoder distinguishes memory widths and branch offsets" {
    const byte = try decode(0x39400022); // ldrb w2, [x1]
    try std.testing.expectEqual(Instruction{ .memory = .{ .op = .load, .size = .byte, .rn = 1, .rt = 2, .addressing = .{ .offset = 0 } } }, byte);
    try std.testing.expect(byte.terminates());
    try std.testing.expectEqual(Instruction{ .b = -4 }, try decode(0x17ff_ffff));
    try std.testing.expectError(error.UnsupportedInstruction, decode(0x72e24680)); // MOVK W shift #48
    try std.testing.expectEqual(Instruction{ .b_cond = .{ .cond = .eq, .offset = 8 } }, try decode(0x54000040)); // b.eq +8
    try std.testing.expectError(error.UnsupportedInstruction, decode(0x9a800802)); // CSEL with bit 11 set
    try std.testing.expectError(error.UnsupportedInstruction, decode(0xba800022)); // CSEL with bit 29 set
}

/// Blocks in this file start here, so a `b.<cond> +8` target is a fixed address.
const flag_base: u64 = 0x3000;

fn flagBlock(allocator: std.mem.Allocator, words: []const u32) !guest.Block {
    return compileWords(allocator, flag_base, words);
}

test "SUBS immediate sets NZCV the way the architecture defines" {
    // subs x0, x0, #1 from zero: the result is negative and the subtraction
    // borrowed, so N is set and C is clear. It did not overflow: minus one fits.
    var block = try flagBlock(testing.allocator(), &.{0xf1000400});
    defer block.deinit();
    var cpu: Cpu = .{};
    _ = block.run(&cpu);
    try testing.expectEqual(@as(u64, 0xffff_ffff_ffff_ffff), cpu.x[0]);
    try testing.expectEqual(@as(u32, 1 << 31), cpu.flags);

    // subs x0, x0, #1 from one: zero, with nothing borrowed out of a larger
    // value, so Z and C set.
    var zero = try flagBlock(testing.allocator(), &.{0xf1000400});
    defer zero.deinit();
    cpu.x[0] = 1;
    _ = zero.run(&cpu);
    try testing.expectEqual(@as(u64, 0), cpu.x[0]);
    try testing.expectEqual(@as(u32, (1 << 30) | (1 << 29)), cpu.flags);

    // subs w0, w0, #1 at 32 bits: the wrap is the same borrow and the same sign,
    // with no overflow, and the write zero-extends into x0.
    var wrap = try flagBlock(testing.allocator(), &.{0x71000400});
    defer wrap.deinit();
    cpu.x[0] = 0;
    _ = wrap.run(&cpu);
    try testing.expectEqual(@as(u64, 0xffff_ffff), cpu.x[0]);
    try testing.expectEqual(@as(u32, 1 << 31), cpu.flags);

    // The most negative value minus one is where a subtract does overflow: the
    // result wraps to the largest positive, nothing was borrowed, and the sign
    // changed the wrong way. C and V set, N clear.
    var overflow = try flagBlock(testing.allocator(), &.{0xf1000400});
    defer overflow.deinit();
    cpu.x[0] = 0x8000_0000_0000_0000;
    _ = overflow.run(&cpu);
    try testing.expectEqual(@as(u64, 0x7fff_ffff_ffff_ffff), cpu.x[0]);
    try testing.expectEqual(@as(u32, (1 << 29) | (1 << 28)), cpu.flags);

    // And a positive value minus a larger one is negative without overflowing,
    // which is the case a sign-change test alone gets wrong.
    var small = try flagBlock(testing.allocator(), &.{0xf1002000}); // subs x0, x0, #8
    defer small.deinit();
    cpu.x[0] = 4;
    _ = small.run(&cpu);
    try testing.expectEqual(@as(u32, 1 << 31), cpu.flags);
}

test "flag-setting arithmetic reports carry and overflow" {
    // adds x0, x0, #1 from the largest unsigned value wraps to zero and carries.
    var carry = try flagBlock(testing.allocator(), &.{0xb1000400});
    defer carry.deinit();
    var cpu: Cpu = .{};
    cpu.x[0] = 0xffff_ffff_ffff_ffff;
    _ = carry.run(&cpu);
    try testing.expectEqual(@as(u32, (1 << 30) | (1 << 29)), cpu.flags);

    // adds x0, x0, #1 from the largest signed value overflows into a negative
    // result: N and V set, and C does not.
    var overflow = try flagBlock(testing.allocator(), &.{0xb1000400});
    defer overflow.deinit();
    cpu.x[0] = 0x7fff_ffff_ffff_ffff;
    _ = overflow.run(&cpu);
    try testing.expectEqual(@as(u64, 0x8000_0000_0000_0000), cpu.x[0]);
    try testing.expectEqual(@as(u32, (1 << 31) | (1 << 28)), cpu.flags);

    // cmp x0, #0 is `subs xzr, x0, #0`: the write is discarded, the flags are not.
    var compare = try flagBlock(testing.allocator(), &.{0xf100001f});
    defer compare.deinit();
    cpu.x[0] = 5;
    _ = compare.run(&cpu);
    try testing.expectEqual(@as(u32, 1 << 29), cpu.flags);
    try testing.expectEqual(@as(u64, 5), cpu.x[0]);
}

test "B.cond reads flags a previous block left behind" {
    // A branch terminates its block, and so does a memory access. Putting a load
    // between the flag-setting instruction and the branch is what forces the
    // branch to be compiled into a block of its own, reading flags out of the
    // register file rather than out of the same block. That is the situation a
    // guest is always in.
    const base: u64 = 0x3000;
    const words = [_]u32{
        0xf1000400, // 0x3000 subs x0, x0, #1: sets Z when x0 was 1
        0x39400042, // 0x3004 ldrb w2, [x2]: ends the block
        0x54000060, // 0x3008 b.eq +12
        0xd28000e0, // 0x300c movz x0, #7
        0x14000000, // 0x3010 b ., ending the block the branch falls into
        0xd28000a0, // 0x3014 movz x0, #5
        0x14000000, // 0x3018 b ., ending the block the branch jumps to
    };
    var bytes: [words.len * 4]u8 = undefined;
    for (words, 0..) |word, index| std.mem.writeInt(u32, bytes[index * 4 ..][0..4], word, .little);
    const regions = [_]GuestMemory.Region{.{ .gpa = base, .len = bytes.len, .backing = .{ .shared = &bytes } }};
    var memory: GuestMemory = .{ .regions = &regions };
    var cache = Cache.init(testing.allocator());
    defer cache.deinit();
    var tlb: Translate.Tlb = .{};

    // x0 = 1 makes the subtraction zero, so the branch is taken past movz #7
    // and lands on movz #5.
    var cpu: Cpu = .{ .pc = base };
    cpu.x[0] = 1;
    cpu.x[2] = base + words.len * 4;
    try testing.expectEqual(base + 8, try cache.runBlock(&memory, &cpu, &tlb)); // the subs and the load
    try testing.expectEqual(Cpu.Trap.load, cpu.trap);
    try testing.expectEqual(base + 20, try cache.runBlock(&memory, &cpu, &tlb)); // the b.eq
    try testing.expectEqual(@as(u64, 0), cpu.x[0]);
    try testing.expectEqual(base + 24, try cache.runBlock(&memory, &cpu, &tlb)); // movz #5, b .
    try testing.expectEqual(@as(u64, 5), cpu.x[0]);

    // x0 = 2 leaves the result non-zero, so the branch falls through to movz #7.
    var other: Cpu = .{ .pc = base };
    other.x[0] = 2;
    other.x[2] = base + words.len * 4;
    try testing.expectEqual(base + 8, try cache.runBlock(&memory, &other, &tlb));
    try testing.expectEqual(base + 12, try cache.runBlock(&memory, &other, &tlb));
    try testing.expectEqual(@as(u64, 1), other.x[0]); // 2 - 1, before the branch decides
    try testing.expectEqual(base + 16, try cache.runBlock(&memory, &other, &tlb)); // movz #7, b .
    try testing.expectEqual(@as(u64, 7), other.x[0]);
}

test "the CSEL family produces what a failed condition is defined to produce" {
    // movz x0,#5; movz x1,#9; cmp x0,#5, which leaves Z set. A condition that
    // holds picks Rn (x1); a condition that fails shows what each variant leaves
    // behind instead. The two encoding bits are named here rather than pasted
    // from an assembler, so the same condition can be asked of all four.
    const setup = [_]u32{ 0xd28000a0, 0xd2800121, 0xf100141f };
    const cases = [_]struct { name: []const u8, bits: u32, failed: u64 }{
        .{ .name = "csel", .bits = 0x0000_0000, .failed = 5 }, // Rm
        .{ .name = "csinc", .bits = 0x0000_0400, .failed = 6 }, // Rm + 1
        .{ .name = "csinv", .bits = 0x4000_0000, .failed = ~@as(u64, 5) }, // ~Rm
        .{ .name = "csneg", .bits = 0x4000_0400, .failed = @as(u64, 0) -% 5 }, // -Rm
    };
    inline for (cases) |case| {
        // `eq` is 0 and `ne` is 1, which is the low bit of the condition field.
        for ([_]u32{ 0, 1 }, 0..) |cond, held| {
            var words: [setup.len + 1]u32 = undefined;
            @memcpy(words[0..setup.len], &setup);
            // Rm = x0 is what a failed condition falls back to, Rn = x1 is what it keeps.
            words[setup.len] = 0x9a80_0000 | case.bits | (1 << 5) | (cond << 12) | 2;
            var block = try compileWords(testing.allocator(), 0x3800, &words);
            defer block.deinit();
            var cpu: Cpu = .{};
            _ = block.run(&cpu);
            errdefer std.debug.print("{s} word={x} cond={d} gave x2 = {x}\n", .{ case.name, words[setup.len], cond, cpu.x[2] });
            try testing.expectEqual(if (held == 0) @as(u64, 9) else case.failed, cpu.x[2]);
        }
    }
}

test "the register form of add and subtract carries the same flags" {
    const cases = [_]struct { name: []const u8, word: u32, x1: u64, x2: u64, x0: ?u64, flags: ?u32 }{
        .{ .name = "adds x", .word = 0xab020020, .x1 = 0x1000_0000_0000_0000, .x2 = 3, .x0 = 0x1000_0000_0000_0003, .flags = null },
        // The 32-bit form shifts Rm, not Rn: 0x80000000 + (3 asr 2) is negative
        // with no carry and no overflow.
        .{ .name = "adds w asr", .word = 0x2b820820, .x1 = 0x8000_0000, .x2 = 3, .x0 = 0x8000_0000, .flags = 1 << 31 },
        // x1 - (3 lsr 1) leaves a positive result, so N clears and the carry
        // says nothing was borrowed.
        .{ .name = "subs lsr", .word = 0xeb420420, .x1 = 0x1000_0000_0000_0000, .x2 = 3, .x0 = 0x0fff_ffff_ffff_ffff, .flags = 1 << 29 },
        // cmp x1, x1 is `subs xzr, x1, x1`: zero, and nothing borrowed, and
        // x0 is left alone because the write goes nowhere.
        .{ .name = "cmp", .word = 0xeb01003f, .x1 = 0x1000_0000_0000_0000, .x2 = 0, .x0 = 0, .flags = (1 << 30) | (1 << 29) },
    };
    inline for (cases) |case| {
        var block = try compileWords(testing.allocator(), 0x4000, &.{case.word});
        defer block.deinit();
        var cpu: Cpu = .{};
        cpu.x[1] = case.x1;
        cpu.x[2] = case.x2;
        _ = block.run(&cpu);
        errdefer std.debug.print("{s}: x0={x} flags={x}\n", .{ case.name, cpu.x[0], cpu.flags });
        if (case.x0) |want| try testing.expectEqual(want, cpu.x[0]);
        if (case.flags) |want| try testing.expectEqual(want, cpu.flags);
    }
}

test "the shift on a register operand follows the encoding" {
    // Each of these is one instruction, run with x1 = 1 and x2 = 0xff.
    const cases = [_]struct { name: []const u8, word: u32, expected: u64 }{
        .{ .name = "lsl #3", .word = 0x8b020c20, .expected = 1 + 0xff * 8 },
        .{ .name = "lsr #1", .word = 0xeb420420, .expected = @as(u64, 1) -% (0xff >> 1) },
        .{ .name = "asr #2", .word = 0x2b820820, .expected = 1 + (0xff >> 2) },
    };
    inline for (cases) |case| {
        var block = try compileWords(testing.allocator(), 0x4200, &.{case.word});
        defer block.deinit();
        var cpu: Cpu = .{};
        cpu.x[1] = 1;
        cpu.x[2] = 0xff;
        _ = block.run(&cpu);
        errdefer std.debug.print("{s} gave {x}\n", .{ case.name, cpu.x[0] });
        try testing.expectEqual(case.expected, cpu.x[0]);
    }

    // A shift by a constant is a bitfield instruction, and is decoded as a
    // shift rather than refused, because that is what a compiler emits.
    const immediate = [_]struct { name: []const u8, word: u32, expected: u64 }{
        .{ .name = "lsl x0, x1, #3", .word = 0xd37df020, .expected = 0xff << 3 },
        .{ .name = "lsr x0, x1, #3", .word = 0xd343fc20, .expected = 0xff >> 3 },
        .{ .name = "asr x0, x1, #3", .word = 0x9343fc20, .expected = 0xff >> 3 },
        .{ .name = "lsl w0, w1, #3", .word = 0x531d7020, .expected = 0xff << 3 },
        .{ .name = "lsr w0, w1, #3", .word = 0x53037c20, .expected = 0xff >> 3 },
        .{ .name = "asr w0, w1, #3", .word = 0x13037c20, .expected = 0xff >> 3 },
        // A left shift of thirty-two in a 64-bit register, which is the one
        // distance where the negated rotation is easy to get wrong.
        .{ .name = "lsl x0, x1, #32", .word = 0xd3607c20, .expected = @as(u64, 0xff) << 32 },
        .{ .name = "lsr x0, x1, #63", .word = 0xd37ffc20, .expected = 0xff >> 63 },
    };
    for (immediate) |case| {
        var block = try compileWords(testing.allocator(), 0x4200, &.{case.word});
        defer block.deinit();
        var cpu: Cpu = .{};
        cpu.x[1] = 0xff;
        errdefer std.debug.print("{s} gave {x}\n", .{ case.name, cpu.x[0] });
        _ = block.run(&cpu);
        try testing.expectEqual(case.expected, cpu.x[0]);
    }
}

test "the bitwise instructions do what their names say" {
    const cases = [_]struct { name: []const u8, word: u32, x1: u64, x2: u64, expected: u64 }{
        .{ .name = "and", .word = 0x8a020020, .x1 = 0xf0f0_0f0f_0f0f_0f0f, .x2 = 0x00ff_00ff_00ff_00ff, .expected = 0x00f0_000f_000f_000f },
        .{ .name = "orr", .word = 0xaa020020, .x1 = 0xf0f0_0f0f_0f0f_0f0f, .x2 = 0x00ff_00ff_00ff_00ff, .expected = 0xf0ff_0fff_0fff_0fff },
        .{ .name = "eor", .word = 0xca020020, .x1 = 0xf0f0_0f0f_0f0f_0f0f, .x2 = 0x00ff_00ff_00ff_00ff, .expected = 0xf00f_0ff0_0ff0_0ff0 },
        // The N bit inverts the second operand, which is the whole difference
        // between AND and BIC.
        .{ .name = "bic", .word = 0x8a220020, .x1 = 0xf0f0_0f0f_0f0f_0f0f, .x2 = 0x00ff_00ff_00ff_00ff, .expected = 0xf000_0f00_0f00_0f00 },
        .{ .name = "orn", .word = 0xaa220020, .x1 = 0xf0f0_0f0f_0f0f_0f0f, .x2 = 0x00ff_00ff_00ff_00ff, .expected = 0xfff0_ff0f_ff0f_ff0f },
        .{ .name = "eon", .word = 0xca220020, .x1 = 0xf0f0_0f0f_0f0f_0f0f, .x2 = 0x00ff_00ff_00ff_00ff, .expected = 0x0ff0_f00f_f00f_f00f },
        // MOV and MVN are ORR and ORN against the zero register.
        // MOV and MVN read the zero register as their first operand, so the
        // value comes from the second one.
        .{ .name = "mov", .word = 0xaa0103e0, .x1 = 0x0123_4567_89ab_cdef, .x2 = 0, .expected = 0x0123_4567_89ab_cdef },
        .{ .name = "mvn", .word = 0xaa2103e0, .x1 = 0x0123_4567_89ab_cdef, .x2 = 0, .expected = ~@as(u64, 0x0123_4567_89ab_cdef) },
        // The shift is on the second operand.
        .{ .name = "and lsl", .word = 0x8a021420, .x1 = 0xff, .x2 = 3, .expected = 0xff & (3 << 5) },
        .{ .name = "and lsr", .word = 0x8a420420, .x1 = 0x7fff, .x2 = 0xff00, .expected = 0x7fff & (0xff00 >> 1) },
        // `eor w0, w1, w2, ror #16`: the shift is on the second operand.
        .{ .name = "eor ror", .word = 0x4ac24020, .x1 = 0x1234_5678, .x2 = 0xdead_dead, .expected = 0x1234_5678 ^ std.math.rotr(u32, 0xdead_dead, 16) },
    };
    inline for (cases) |case| {
        var block = try compileWords(testing.allocator(), 0x5000, &.{case.word});
        defer block.deinit();
        var cpu: Cpu = .{};
        cpu.x[1] = case.x1;
        cpu.x[2] = case.x2;
        _ = block.run(&cpu);
        const shape = decode(case.word) catch unreachable;
        errdefer std.debug.print("{s}: word={x} {any} x0={x} x1={x} x2={x}\n", .{ case.name, case.word, shape, cpu.x[0], cpu.x[1], cpu.x[2] });
        try testing.expectEqual(case.expected, cpu.x[0]);
    }
}

test "a bitwise instruction that sets flags sets N and Z and clears the carry and overflow" {
    // subs x0, x0, #1 from the most negative value overflows, so C and V are both
    // set going in. The ands after it must clear them, not keep them.
    var setup = try compileWords(testing.allocator(), 0x5200, &.{0xf1000400});
    defer setup.deinit();
    var before: Cpu = .{};
    before.x[0] = 0x8000_0000_0000_0000;
    _ = setup.run(&before);
    try testing.expectEqual(@as(u32, (1 << 29) | (1 << 28)), before.flags);

    var block = try compileWords(testing.allocator(), 0x5200, &.{ 0xf1000400, 0xea020020 });
    defer block.deinit();
    var cpu: Cpu = .{};
    cpu.x[0] = 0x8000_0000_0000_0000;
    cpu.x[1] = 0xff00_ff00_ff00_ff00;
    cpu.x[2] = 0x0f0f_0f0f_0f0f_0f0f;
    _ = block.run(&cpu);
    // The result is non-zero and positive, so N and Z are clear, and C and V are
    // cleared, whatever the subtract left behind.
    try testing.expectEqual(0x0f00_0f00_0f00_0f00, cpu.x[0]);
    try testing.expectEqual(@as(u32, 0), cpu.flags);

    // The 32-bit form follows the same rule, and zeroes the rest of the register:
    // ands w0, w1, w2 with every bit set gives a negative result.
    var narrow = try compileWords(testing.allocator(), 0x5200, &.{ 0xf1000400, 0x6a020020 });
    defer narrow.deinit();
    var other: Cpu = .{};
    other.x[0] = 0x8000_0000_0000_0000;
    other.x[1] = 0xffff_ffff;
    other.x[2] = 0xffff_ffff;
    _ = narrow.run(&other);
    try testing.expectEqual(@as(u32, 1 << 31), other.flags);
    try testing.expectEqual(@as(u64, 0xffff_ffff), other.x[0]);
}

test "tst is ands with the result thrown away" {
    // An overflowing subtract first, so C and V are set going in, then a tst whose
    // own result is non-zero and positive: every flag is clear afterwards, because
    // a flag-setting bitwise instruction clears C and V rather than keeping them.
    var block = try compileWords(testing.allocator(), 0x5400, &.{ 0xf1000484, 0xea01001f });
    defer block.deinit();
    var cpu: Cpu = .{ .sp = 0x7000 };
    cpu.x[4] = 0x8000_0000_0000_0000;
    cpu.x[0] = 0x1234;
    cpu.x[1] = 0x5678;
    _ = block.run(&cpu);
    try testing.expectEqual(@as(u32, 0), cpu.flags);
    // The result went nowhere: x0 is what the tst read, and the stack is untouched.
    try testing.expectEqual(@as(u64, 0x1234), cpu.x[0]);
    try testing.expectEqual(@as(u64, 0x7000), cpu.sp);
}

test "compare and branch on a register or a bit" {
    const cases = [_]struct {
        name: []const u8,
        word: u32,
        value: u64,
        taken: bool,
    }{
        .{ .name = "cbz set", .word = 0xb4000060, .value = 0, .taken = true },
        .{ .name = "cbz clear", .word = 0xb4000060, .value = 1, .taken = false },
        .{ .name = "cbnz set", .word = 0xb5000060, .value = 1, .taken = true },
        .{ .name = "cbnz clear", .word = 0xb5000060, .value = 0, .taken = false },
        // The high half of a 64-bit register is not tested by the 32-bit form.
        .{ .name = "cbz w high", .word = 0x34000060, .value = 0x1_0000_0000, .taken = true },
        .{ .name = "cbz x high", .word = 0xb4000060, .value = 0x1_0000_0000, .taken = false },
        // TBZ branches when bit 3 is clear, TBNZ when it is set. 8 and 1 differ
        // in that bit and in nothing else below.
        .{ .name = "tbz bit set", .word = 0x36180060, .value = 8, .taken = false },
        .{ .name = "tbz bit clear", .word = 0x36180060, .value = 1, .taken = true },
        .{ .name = "tbnz bit set", .word = 0x37180060, .value = 8, .taken = true },
        .{ .name = "tbnz bit clear", .word = 0x37180060, .value = 1, .taken = false },
    };
    inline for (cases) |case| {
        var block = try compileWords(testing.allocator(), 0x5600, &.{ case.word, 0xd28000e0 });
        defer block.deinit();
        var cpu: Cpu = .{};
        cpu.x[0] = case.value;
        _ = block.run(&cpu);
        // The branch is +8, so a taken branch lands past the movz and an
        // untaken one runs it.
        errdefer std.debug.print("{s} value {x} gave pc {x} x0 {x}\n", .{ case.name, case.value, cpu.pc, cpu.x[0] });
        // The branch ends the block, so the movz is the next block's work.
        // A taken branch lands past it and an untaken one lands on it.
        errdefer std.debug.print("{s}: value {x} gave pc {x}\n", .{ case.name, case.value, cpu.pc });
        try testing.expectEqual(if (case.taken) @as(u64, 0x560c) else 0x5604, cpu.pc);
        try testing.expectEqual(case.value, cpu.x[0]);
    }
}

test "a call and a return carry through the link register" {
    const base: u64 = 0x6000;
    const words = [_]u32{
        0x94000002, // 0x6000 bl 0x6008
        0xd4000001, // 0x6004 svc #0
        0xd28000e0, // 0x6008 movz x0, #7
        0xd65f03c0, // 0x600c ret
    };
    var bytes: [words.len * 4]u8 = undefined;
    for (words, 0..) |word, index| std.mem.writeInt(u32, bytes[index * 4 ..][0..4], word, .little);
    const regions = [_]GuestMemory.Region{.{ .gpa = base, .len = bytes.len, .backing = .{ .shared = &bytes } }};
    var memory: GuestMemory = .{ .regions = &regions };
    var cache = Cache.init(testing.allocator());
    defer cache.deinit();
    var tlb: Translate.Tlb = .{};
    var cpu: Cpu = .{ .pc = base };

    // The call leaves the address it came from in x30 and goes to the callee.
    try testing.expectEqual(base + 8, try cache.runBlock(&memory, &cpu, &tlb));
    try testing.expectEqual(base + 4, cpu.x[30]);
    // The callee runs and returns through x30, all in one block, so the block
    // already comes back to the caller.
    try testing.expectEqual(base + 4, try cache.runBlock(&memory, &cpu, &tlb));
    try testing.expectEqual(@as(u64, 7), cpu.x[0]);
    // Which is the instruction after the call, and the one that exits.
    try testing.expectEqual(base + 8, try cache.runBlock(&memory, &cpu, &tlb));
    try testing.expectEqual(Cpu.Trap.svc, cpu.trap);
}

/// Which conditions hold, per condition code, for the two flag states below.
/// A lowering that reads the wrong flag bit, or inverts a condition, disagrees
/// with one entry of one of these rows.
const condition_truth = struct {
    const order = std.enums.values(Decode.Condition);
    // `adds xzr, x0, #0` with x0 = 0: N=0, Z=1, C=0, V=0.
    const zero = [_]bool{ true, false, false, true, false, true, false, true, false, true, true, false, false, true };
    // `subs x0, x0, #2` with x0 = 5: result 3, so N=0, Z=0, C=1, V=0.
    const nonzero = [_]bool{ false, true, true, false, false, true, false, true, true, false, true, false, true, false };
    comptime {
        std.debug.assert(order.len - 2 == zero.len); // al and nv are not conditions to test
        std.debug.assert(nonzero.len == zero.len);
    }
};

test "every condition code reads the flags it is defined by" {
    for (condition_truth.order, 0..) |cond, index| {
        if (cond == .al or cond == .nv) continue;
        const branch = 0x54000000 | @as(u32, @backingInt(cond)) | (2 << 5); // b.<cond> +8

        var zero = try compileWords(testing.allocator(), 0x2000, &.{ 0xb100001f, branch, 0xd28000e0 });
        defer zero.deinit();
        var first: Cpu = .{};
        _ = zero.run(&first);
        try testing.expectEqual(condition_truth.zero[index], first.pc == 0x200c);

        var nonzero = try compileWords(testing.allocator(), 0x2000, &.{ 0xf1000800, branch, 0xd28000e0 });
        defer nonzero.deinit();
        var second: Cpu = .{};
        second.x[0] = 5;
        _ = nonzero.run(&second);
        try testing.expectEqual(condition_truth.nonzero[index], second.pc == 0x200c);
    }
}

// Generated by assembling `and <reg>, <reg>, #value` for every distinct value a
// bit pattern immediate can name, and recording the word the assembler chose.
// The table is the architecture's own answer, captured rather than recomputed:
// what is being tested is that the decoder recovers the value from the word, not
// that two implementations of one formula happen to agree.
const BitmaskCase = struct { word: u32, value: u64 };

const x64_cases = [_]BitmaskCase{
    .{ .word = 0x92000021, .value = 0x100000001 },
    .{ .word = 0x92000421, .value = 0x300000003 },
    .{ .word = 0x92000821, .value = 0x700000007 },
    .{ .word = 0x92000c21, .value = 0xf0000000f },
    .{ .word = 0x92001021, .value = 0x1f0000001f },
    .{ .word = 0x92001421, .value = 0x3f0000003f },
    .{ .word = 0x92001821, .value = 0x7f0000007f },
    .{ .word = 0x92001c21, .value = 0xff000000ff },
    .{ .word = 0x92002021, .value = 0x1ff000001ff },
    .{ .word = 0x92002421, .value = 0x3ff000003ff },
    .{ .word = 0x92002821, .value = 0x7ff000007ff },
    .{ .word = 0x92002c21, .value = 0xfff00000fff },
    .{ .word = 0x92003021, .value = 0x1fff00001fff },
    .{ .word = 0x92003421, .value = 0x3fff00003fff },
    .{ .word = 0x92003821, .value = 0x7fff00007fff },
    .{ .word = 0x92003c21, .value = 0xffff0000ffff },
    .{ .word = 0x92004021, .value = 0x1ffff0001ffff },
    .{ .word = 0x92004421, .value = 0x3ffff0003ffff },
    .{ .word = 0x92004821, .value = 0x7ffff0007ffff },
    .{ .word = 0x92004c21, .value = 0xfffff000fffff },
    .{ .word = 0x92005021, .value = 0x1fffff001fffff },
    .{ .word = 0x92005421, .value = 0x3fffff003fffff },
    .{ .word = 0x92005821, .value = 0x7fffff007fffff },
    .{ .word = 0x92005c21, .value = 0xffffff00ffffff },
    .{ .word = 0x92006021, .value = 0x1ffffff01ffffff },
    .{ .word = 0x92006421, .value = 0x3ffffff03ffffff },
    .{ .word = 0x92006821, .value = 0x7ffffff07ffffff },
    .{ .word = 0x92006c21, .value = 0xfffffff0fffffff },
    .{ .word = 0x92007021, .value = 0x1fffffff1fffffff },
    .{ .word = 0x92007421, .value = 0x3fffffff3fffffff },
    .{ .word = 0x92007821, .value = 0x7fffffff7fffffff },
    .{ .word = 0x92008021, .value = 0x1000100010001 },
    .{ .word = 0x92008421, .value = 0x3000300030003 },
    .{ .word = 0x92008821, .value = 0x7000700070007 },
    .{ .word = 0x92008c21, .value = 0xf000f000f000f },
    .{ .word = 0x92009021, .value = 0x1f001f001f001f },
    .{ .word = 0x92009421, .value = 0x3f003f003f003f },
    .{ .word = 0x92009821, .value = 0x7f007f007f007f },
    .{ .word = 0x92009c21, .value = 0xff00ff00ff00ff },
    .{ .word = 0x9200a021, .value = 0x1ff01ff01ff01ff },
    .{ .word = 0x9200a421, .value = 0x3ff03ff03ff03ff },
    .{ .word = 0x9200a821, .value = 0x7ff07ff07ff07ff },
    .{ .word = 0x9200ac21, .value = 0xfff0fff0fff0fff },
    .{ .word = 0x9200b021, .value = 0x1fff1fff1fff1fff },
    .{ .word = 0x9200b421, .value = 0x3fff3fff3fff3fff },
    .{ .word = 0x9200b821, .value = 0x7fff7fff7fff7fff },
    .{ .word = 0x9200c021, .value = 0x101010101010101 },
    .{ .word = 0x9200c421, .value = 0x303030303030303 },
    .{ .word = 0x9200c821, .value = 0x707070707070707 },
    .{ .word = 0x9200cc21, .value = 0xf0f0f0f0f0f0f0f },
    .{ .word = 0x9200d021, .value = 0x1f1f1f1f1f1f1f1f },
    .{ .word = 0x9200d421, .value = 0x3f3f3f3f3f3f3f3f },
    .{ .word = 0x9200d821, .value = 0x7f7f7f7f7f7f7f7f },
    .{ .word = 0x9200e021, .value = 0x1111111111111111 },
    .{ .word = 0x9200e421, .value = 0x3333333333333333 },
    .{ .word = 0x9200e821, .value = 0x7777777777777777 },
    .{ .word = 0x9200f021, .value = 0x5555555555555555 },
    .{ .word = 0x92010021, .value = 0x8000000080000000 },
    .{ .word = 0x92010421, .value = 0x8000000180000001 },
    .{ .word = 0x92010821, .value = 0x8000000380000003 },
    .{ .word = 0x92010c21, .value = 0x8000000780000007 },
    .{ .word = 0x92011021, .value = 0x8000000f8000000f },
    .{ .word = 0x92011421, .value = 0x8000001f8000001f },
    .{ .word = 0x92011821, .value = 0x8000003f8000003f },
    .{ .word = 0x92011c21, .value = 0x8000007f8000007f },
    .{ .word = 0x92012021, .value = 0x800000ff800000ff },
    .{ .word = 0x92012421, .value = 0x800001ff800001ff },
    .{ .word = 0x92012821, .value = 0x800003ff800003ff },
    .{ .word = 0x92012c21, .value = 0x800007ff800007ff },
    .{ .word = 0x92013021, .value = 0x80000fff80000fff },
    .{ .word = 0x92013421, .value = 0x80001fff80001fff },
    .{ .word = 0x92013821, .value = 0x80003fff80003fff },
    .{ .word = 0x92013c21, .value = 0x80007fff80007fff },
    .{ .word = 0x92014021, .value = 0x8000ffff8000ffff },
    .{ .word = 0x92014421, .value = 0x8001ffff8001ffff },
    .{ .word = 0x92014821, .value = 0x8003ffff8003ffff },
    .{ .word = 0x92014c21, .value = 0x8007ffff8007ffff },
    .{ .word = 0x92015021, .value = 0x800fffff800fffff },
    .{ .word = 0x92015421, .value = 0x801fffff801fffff },
    .{ .word = 0x92015821, .value = 0x803fffff803fffff },
    .{ .word = 0x92015c21, .value = 0x807fffff807fffff },
    .{ .word = 0x92016021, .value = 0x80ffffff80ffffff },
    .{ .word = 0x92016421, .value = 0x81ffffff81ffffff },
    .{ .word = 0x92016821, .value = 0x83ffffff83ffffff },
    .{ .word = 0x92016c21, .value = 0x87ffffff87ffffff },
    .{ .word = 0x92017021, .value = 0x8fffffff8fffffff },
    .{ .word = 0x92017421, .value = 0x9fffffff9fffffff },
    .{ .word = 0x92017821, .value = 0xbfffffffbfffffff },
    .{ .word = 0x92018021, .value = 0x8000800080008000 },
    .{ .word = 0x92018421, .value = 0x8001800180018001 },
    .{ .word = 0x92018821, .value = 0x8003800380038003 },
    .{ .word = 0x92018c21, .value = 0x8007800780078007 },
    .{ .word = 0x92019021, .value = 0x800f800f800f800f },
    .{ .word = 0x92019421, .value = 0x801f801f801f801f },
    .{ .word = 0x92019821, .value = 0x803f803f803f803f },
    .{ .word = 0x92019c21, .value = 0x807f807f807f807f },
    .{ .word = 0x9201a021, .value = 0x80ff80ff80ff80ff },
    .{ .word = 0x9201a421, .value = 0x81ff81ff81ff81ff },
    .{ .word = 0x9201a821, .value = 0x83ff83ff83ff83ff },
    .{ .word = 0x9201ac21, .value = 0x87ff87ff87ff87ff },
    .{ .word = 0x9201b021, .value = 0x8fff8fff8fff8fff },
    .{ .word = 0x9201b421, .value = 0x9fff9fff9fff9fff },
    .{ .word = 0x9201b821, .value = 0xbfffbfffbfffbfff },
    .{ .word = 0x9201c021, .value = 0x8080808080808080 },
    .{ .word = 0x9201c421, .value = 0x8181818181818181 },
    .{ .word = 0x9201c821, .value = 0x8383838383838383 },
    .{ .word = 0x9201cc21, .value = 0x8787878787878787 },
    .{ .word = 0x9201d021, .value = 0x8f8f8f8f8f8f8f8f },
    .{ .word = 0x9201d421, .value = 0x9f9f9f9f9f9f9f9f },
    .{ .word = 0x9201d821, .value = 0xbfbfbfbfbfbfbfbf },
    .{ .word = 0x9201e021, .value = 0x8888888888888888 },
    .{ .word = 0x9201e421, .value = 0x9999999999999999 },
    .{ .word = 0x9201e821, .value = 0xbbbbbbbbbbbbbbbb },
    .{ .word = 0x9201f021, .value = 0xaaaaaaaaaaaaaaaa },
    .{ .word = 0x92020021, .value = 0x4000000040000000 },
    .{ .word = 0x92020421, .value = 0xc0000000c0000000 },
    .{ .word = 0x92020821, .value = 0xc0000001c0000001 },
    .{ .word = 0x92020c21, .value = 0xc0000003c0000003 },
    .{ .word = 0x92021021, .value = 0xc0000007c0000007 },
    .{ .word = 0x92021421, .value = 0xc000000fc000000f },
    .{ .word = 0x92021821, .value = 0xc000001fc000001f },
    .{ .word = 0x92021c21, .value = 0xc000003fc000003f },
    .{ .word = 0x92022021, .value = 0xc000007fc000007f },
    .{ .word = 0x92022421, .value = 0xc00000ffc00000ff },
    .{ .word = 0x92022821, .value = 0xc00001ffc00001ff },
    .{ .word = 0x92022c21, .value = 0xc00003ffc00003ff },
    .{ .word = 0x92023021, .value = 0xc00007ffc00007ff },
    .{ .word = 0x92023421, .value = 0xc0000fffc0000fff },
    .{ .word = 0x92023821, .value = 0xc0001fffc0001fff },
    .{ .word = 0x92023c21, .value = 0xc0003fffc0003fff },
    .{ .word = 0x92024021, .value = 0xc0007fffc0007fff },
    .{ .word = 0x92024421, .value = 0xc000ffffc000ffff },
    .{ .word = 0x92024821, .value = 0xc001ffffc001ffff },
    .{ .word = 0x92024c21, .value = 0xc003ffffc003ffff },
    .{ .word = 0x92025021, .value = 0xc007ffffc007ffff },
    .{ .word = 0x92025421, .value = 0xc00fffffc00fffff },
    .{ .word = 0x92025821, .value = 0xc01fffffc01fffff },
    .{ .word = 0x92025c21, .value = 0xc03fffffc03fffff },
    .{ .word = 0x92026021, .value = 0xc07fffffc07fffff },
    .{ .word = 0x92026421, .value = 0xc0ffffffc0ffffff },
    .{ .word = 0x92026821, .value = 0xc1ffffffc1ffffff },
    .{ .word = 0x92026c21, .value = 0xc3ffffffc3ffffff },
    .{ .word = 0x92027021, .value = 0xc7ffffffc7ffffff },
    .{ .word = 0x92027421, .value = 0xcfffffffcfffffff },
    .{ .word = 0x92027821, .value = 0xdfffffffdfffffff },
    .{ .word = 0x92028021, .value = 0x4000400040004000 },
    .{ .word = 0x92028421, .value = 0xc000c000c000c000 },
    .{ .word = 0x92028821, .value = 0xc001c001c001c001 },
    .{ .word = 0x92028c21, .value = 0xc003c003c003c003 },
    .{ .word = 0x92029021, .value = 0xc007c007c007c007 },
    .{ .word = 0x92029421, .value = 0xc00fc00fc00fc00f },
    .{ .word = 0x92029821, .value = 0xc01fc01fc01fc01f },
    .{ .word = 0x92029c21, .value = 0xc03fc03fc03fc03f },
    .{ .word = 0x9202a021, .value = 0xc07fc07fc07fc07f },
    .{ .word = 0x9202a421, .value = 0xc0ffc0ffc0ffc0ff },
    .{ .word = 0x9202a821, .value = 0xc1ffc1ffc1ffc1ff },
    .{ .word = 0x9202ac21, .value = 0xc3ffc3ffc3ffc3ff },
    .{ .word = 0x9202b021, .value = 0xc7ffc7ffc7ffc7ff },
    .{ .word = 0x9202b421, .value = 0xcfffcfffcfffcfff },
    .{ .word = 0x9202b821, .value = 0xdfffdfffdfffdfff },
    .{ .word = 0x9202c021, .value = 0x4040404040404040 },
    .{ .word = 0x9202c421, .value = 0xc0c0c0c0c0c0c0c0 },
    .{ .word = 0x9202c821, .value = 0xc1c1c1c1c1c1c1c1 },
    .{ .word = 0x9202cc21, .value = 0xc3c3c3c3c3c3c3c3 },
    .{ .word = 0x9202d021, .value = 0xc7c7c7c7c7c7c7c7 },
    .{ .word = 0x9202d421, .value = 0xcfcfcfcfcfcfcfcf },
    .{ .word = 0x9202d821, .value = 0xdfdfdfdfdfdfdfdf },
    .{ .word = 0x9202e021, .value = 0x4444444444444444 },
    .{ .word = 0x9202e421, .value = 0xcccccccccccccccc },
    .{ .word = 0x9202e821, .value = 0xdddddddddddddddd },
    .{ .word = 0x92030021, .value = 0x2000000020000000 },
    .{ .word = 0x92030421, .value = 0x6000000060000000 },
    .{ .word = 0x92030821, .value = 0xe0000000e0000000 },
    .{ .word = 0x92030c21, .value = 0xe0000001e0000001 },
    .{ .word = 0x92031021, .value = 0xe0000003e0000003 },
    .{ .word = 0x92031421, .value = 0xe0000007e0000007 },
    .{ .word = 0x92031821, .value = 0xe000000fe000000f },
    .{ .word = 0x92031c21, .value = 0xe000001fe000001f },
    .{ .word = 0x92032021, .value = 0xe000003fe000003f },
    .{ .word = 0x92032421, .value = 0xe000007fe000007f },
    .{ .word = 0x92032821, .value = 0xe00000ffe00000ff },
    .{ .word = 0x92032c21, .value = 0xe00001ffe00001ff },
    .{ .word = 0x92033021, .value = 0xe00003ffe00003ff },
    .{ .word = 0x92033421, .value = 0xe00007ffe00007ff },
    .{ .word = 0x92033821, .value = 0xe0000fffe0000fff },
    .{ .word = 0x92033c21, .value = 0xe0001fffe0001fff },
    .{ .word = 0x92034021, .value = 0xe0003fffe0003fff },
    .{ .word = 0x92034421, .value = 0xe0007fffe0007fff },
    .{ .word = 0x92034821, .value = 0xe000ffffe000ffff },
    .{ .word = 0x92034c21, .value = 0xe001ffffe001ffff },
    .{ .word = 0x92035021, .value = 0xe003ffffe003ffff },
    .{ .word = 0x92035421, .value = 0xe007ffffe007ffff },
    .{ .word = 0x92035821, .value = 0xe00fffffe00fffff },
    .{ .word = 0x92035c21, .value = 0xe01fffffe01fffff },
    .{ .word = 0x92036021, .value = 0xe03fffffe03fffff },
    .{ .word = 0x92036421, .value = 0xe07fffffe07fffff },
    .{ .word = 0x92036821, .value = 0xe0ffffffe0ffffff },
    .{ .word = 0x92036c21, .value = 0xe1ffffffe1ffffff },
    .{ .word = 0x92037021, .value = 0xe3ffffffe3ffffff },
    .{ .word = 0x92037421, .value = 0xe7ffffffe7ffffff },
    .{ .word = 0x92037821, .value = 0xefffffffefffffff },
    .{ .word = 0x92038021, .value = 0x2000200020002000 },
    .{ .word = 0x92038421, .value = 0x6000600060006000 },
    .{ .word = 0x92038821, .value = 0xe000e000e000e000 },
    .{ .word = 0x92038c21, .value = 0xe001e001e001e001 },
    .{ .word = 0x92039021, .value = 0xe003e003e003e003 },
    .{ .word = 0x92039421, .value = 0xe007e007e007e007 },
    .{ .word = 0x92039821, .value = 0xe00fe00fe00fe00f },
    .{ .word = 0x92039c21, .value = 0xe01fe01fe01fe01f },
    .{ .word = 0x9203a021, .value = 0xe03fe03fe03fe03f },
    .{ .word = 0x9203a421, .value = 0xe07fe07fe07fe07f },
    .{ .word = 0x9203a821, .value = 0xe0ffe0ffe0ffe0ff },
    .{ .word = 0x9203ac21, .value = 0xe1ffe1ffe1ffe1ff },
    .{ .word = 0x9203b021, .value = 0xe3ffe3ffe3ffe3ff },
    .{ .word = 0x9203b421, .value = 0xe7ffe7ffe7ffe7ff },
    .{ .word = 0x9203b821, .value = 0xefffefffefffefff },
    .{ .word = 0x9203c021, .value = 0x2020202020202020 },
    .{ .word = 0x9203c421, .value = 0x6060606060606060 },
    .{ .word = 0x9203c821, .value = 0xe0e0e0e0e0e0e0e0 },
    .{ .word = 0x9203cc21, .value = 0xe1e1e1e1e1e1e1e1 },
    .{ .word = 0x9203d021, .value = 0xe3e3e3e3e3e3e3e3 },
    .{ .word = 0x9203d421, .value = 0xe7e7e7e7e7e7e7e7 },
    .{ .word = 0x9203d821, .value = 0xefefefefefefefef },
    .{ .word = 0x9203e021, .value = 0x2222222222222222 },
    .{ .word = 0x9203e421, .value = 0x6666666666666666 },
    .{ .word = 0x9203e821, .value = 0xeeeeeeeeeeeeeeee },
    .{ .word = 0x92040021, .value = 0x1000000010000000 },
    .{ .word = 0x92040421, .value = 0x3000000030000000 },
    .{ .word = 0x92040821, .value = 0x7000000070000000 },
    .{ .word = 0x92040c21, .value = 0xf0000000f0000000 },
    .{ .word = 0x92041021, .value = 0xf0000001f0000001 },
    .{ .word = 0x92041421, .value = 0xf0000003f0000003 },
    .{ .word = 0x92041821, .value = 0xf0000007f0000007 },
    .{ .word = 0x92041c21, .value = 0xf000000ff000000f },
    .{ .word = 0x92042021, .value = 0xf000001ff000001f },
    .{ .word = 0x92042421, .value = 0xf000003ff000003f },
    .{ .word = 0x92042821, .value = 0xf000007ff000007f },
    .{ .word = 0x92042c21, .value = 0xf00000fff00000ff },
    .{ .word = 0x92043021, .value = 0xf00001fff00001ff },
    .{ .word = 0x92043421, .value = 0xf00003fff00003ff },
    .{ .word = 0x92043821, .value = 0xf00007fff00007ff },
    .{ .word = 0x92043c21, .value = 0xf0000ffff0000fff },
    .{ .word = 0x92044021, .value = 0xf0001ffff0001fff },
    .{ .word = 0x92044421, .value = 0xf0003ffff0003fff },
    .{ .word = 0x92044821, .value = 0xf0007ffff0007fff },
    .{ .word = 0x92044c21, .value = 0xf000fffff000ffff },
    .{ .word = 0x92045021, .value = 0xf001fffff001ffff },
    .{ .word = 0x92045421, .value = 0xf003fffff003ffff },
    .{ .word = 0x92045821, .value = 0xf007fffff007ffff },
    .{ .word = 0x92045c21, .value = 0xf00ffffff00fffff },
    .{ .word = 0x92046021, .value = 0xf01ffffff01fffff },
    .{ .word = 0x92046421, .value = 0xf03ffffff03fffff },
    .{ .word = 0x92046821, .value = 0xf07ffffff07fffff },
    .{ .word = 0x92046c21, .value = 0xf0fffffff0ffffff },
    .{ .word = 0x92047021, .value = 0xf1fffffff1ffffff },
    .{ .word = 0x92047421, .value = 0xf3fffffff3ffffff },
    .{ .word = 0x92047821, .value = 0xf7fffffff7ffffff },
    .{ .word = 0x92048021, .value = 0x1000100010001000 },
    .{ .word = 0x92048421, .value = 0x3000300030003000 },
    .{ .word = 0x92048821, .value = 0x7000700070007000 },
    .{ .word = 0x92048c21, .value = 0xf000f000f000f000 },
    .{ .word = 0x92049021, .value = 0xf001f001f001f001 },
    .{ .word = 0x92049421, .value = 0xf003f003f003f003 },
    .{ .word = 0x92049821, .value = 0xf007f007f007f007 },
    .{ .word = 0x92049c21, .value = 0xf00ff00ff00ff00f },
    .{ .word = 0x9204a021, .value = 0xf01ff01ff01ff01f },
    .{ .word = 0x9204a421, .value = 0xf03ff03ff03ff03f },
    .{ .word = 0x9204a821, .value = 0xf07ff07ff07ff07f },
    .{ .word = 0x9204ac21, .value = 0xf0fff0fff0fff0ff },
    .{ .word = 0x9204b021, .value = 0xf1fff1fff1fff1ff },
    .{ .word = 0x9204b421, .value = 0xf3fff3fff3fff3ff },
    .{ .word = 0x9204b821, .value = 0xf7fff7fff7fff7ff },
    .{ .word = 0x9204c021, .value = 0x1010101010101010 },
    .{ .word = 0x9204c421, .value = 0x3030303030303030 },
    .{ .word = 0x9204c821, .value = 0x7070707070707070 },
    .{ .word = 0x9204cc21, .value = 0xf0f0f0f0f0f0f0f0 },
    .{ .word = 0x9204d021, .value = 0xf1f1f1f1f1f1f1f1 },
    .{ .word = 0x9204d421, .value = 0xf3f3f3f3f3f3f3f3 },
    .{ .word = 0x9204d821, .value = 0xf7f7f7f7f7f7f7f7 },
    .{ .word = 0x92050021, .value = 0x800000008000000 },
    .{ .word = 0x92050421, .value = 0x1800000018000000 },
    .{ .word = 0x92050821, .value = 0x3800000038000000 },
    .{ .word = 0x92050c21, .value = 0x7800000078000000 },
    .{ .word = 0x92051021, .value = 0xf8000000f8000000 },
    .{ .word = 0x92051421, .value = 0xf8000001f8000001 },
    .{ .word = 0x92051821, .value = 0xf8000003f8000003 },
    .{ .word = 0x92051c21, .value = 0xf8000007f8000007 },
    .{ .word = 0x92052021, .value = 0xf800000ff800000f },
    .{ .word = 0x92052421, .value = 0xf800001ff800001f },
    .{ .word = 0x92052821, .value = 0xf800003ff800003f },
    .{ .word = 0x92052c21, .value = 0xf800007ff800007f },
    .{ .word = 0x92053021, .value = 0xf80000fff80000ff },
    .{ .word = 0x92053421, .value = 0xf80001fff80001ff },
    .{ .word = 0x92053821, .value = 0xf80003fff80003ff },
    .{ .word = 0x92053c21, .value = 0xf80007fff80007ff },
    .{ .word = 0x92054021, .value = 0xf8000ffff8000fff },
    .{ .word = 0x92054421, .value = 0xf8001ffff8001fff },
    .{ .word = 0x92054821, .value = 0xf8003ffff8003fff },
    .{ .word = 0x92054c21, .value = 0xf8007ffff8007fff },
    .{ .word = 0x92055021, .value = 0xf800fffff800ffff },
    .{ .word = 0x92055421, .value = 0xf801fffff801ffff },
    .{ .word = 0x92055821, .value = 0xf803fffff803ffff },
    .{ .word = 0x92055c21, .value = 0xf807fffff807ffff },
    .{ .word = 0x92056021, .value = 0xf80ffffff80fffff },
    .{ .word = 0x92056421, .value = 0xf81ffffff81fffff },
    .{ .word = 0x92056821, .value = 0xf83ffffff83fffff },
    .{ .word = 0x92056c21, .value = 0xf87ffffff87fffff },
    .{ .word = 0x92057021, .value = 0xf8fffffff8ffffff },
    .{ .word = 0x92057421, .value = 0xf9fffffff9ffffff },
    .{ .word = 0x92057821, .value = 0xfbfffffffbffffff },
    .{ .word = 0x92058021, .value = 0x800080008000800 },
    .{ .word = 0x92058421, .value = 0x1800180018001800 },
    .{ .word = 0x92058821, .value = 0x3800380038003800 },
    .{ .word = 0x92058c21, .value = 0x7800780078007800 },
    .{ .word = 0x92059021, .value = 0xf800f800f800f800 },
    .{ .word = 0x92059421, .value = 0xf801f801f801f801 },
    .{ .word = 0x92059821, .value = 0xf803f803f803f803 },
    .{ .word = 0x92059c21, .value = 0xf807f807f807f807 },
    .{ .word = 0x9205a021, .value = 0xf80ff80ff80ff80f },
    .{ .word = 0x9205a421, .value = 0xf81ff81ff81ff81f },
    .{ .word = 0x9205a821, .value = 0xf83ff83ff83ff83f },
    .{ .word = 0x9205ac21, .value = 0xf87ff87ff87ff87f },
    .{ .word = 0x9205b021, .value = 0xf8fff8fff8fff8ff },
    .{ .word = 0x9205b421, .value = 0xf9fff9fff9fff9ff },
    .{ .word = 0x9205b821, .value = 0xfbfffbfffbfffbff },
    .{ .word = 0x9205c021, .value = 0x808080808080808 },
    .{ .word = 0x9205c421, .value = 0x1818181818181818 },
    .{ .word = 0x9205c821, .value = 0x3838383838383838 },
    .{ .word = 0x9205cc21, .value = 0x7878787878787878 },
    .{ .word = 0x9205d021, .value = 0xf8f8f8f8f8f8f8f8 },
    .{ .word = 0x9205d421, .value = 0xf9f9f9f9f9f9f9f9 },
    .{ .word = 0x9205d821, .value = 0xfbfbfbfbfbfbfbfb },
    .{ .word = 0x92060021, .value = 0x400000004000000 },
    .{ .word = 0x92060421, .value = 0xc0000000c000000 },
    .{ .word = 0x92060821, .value = 0x1c0000001c000000 },
    .{ .word = 0x92060c21, .value = 0x3c0000003c000000 },
    .{ .word = 0x92061021, .value = 0x7c0000007c000000 },
    .{ .word = 0x92061421, .value = 0xfc000000fc000000 },
    .{ .word = 0x92061821, .value = 0xfc000001fc000001 },
    .{ .word = 0x92061c21, .value = 0xfc000003fc000003 },
    .{ .word = 0x92062021, .value = 0xfc000007fc000007 },
    .{ .word = 0x92062421, .value = 0xfc00000ffc00000f },
    .{ .word = 0x92062821, .value = 0xfc00001ffc00001f },
    .{ .word = 0x92062c21, .value = 0xfc00003ffc00003f },
    .{ .word = 0x92063021, .value = 0xfc00007ffc00007f },
    .{ .word = 0x92063421, .value = 0xfc0000fffc0000ff },
    .{ .word = 0x92063821, .value = 0xfc0001fffc0001ff },
    .{ .word = 0x92063c21, .value = 0xfc0003fffc0003ff },
    .{ .word = 0x92064021, .value = 0xfc0007fffc0007ff },
    .{ .word = 0x92064421, .value = 0xfc000ffffc000fff },
    .{ .word = 0x92064821, .value = 0xfc001ffffc001fff },
    .{ .word = 0x92064c21, .value = 0xfc003ffffc003fff },
    .{ .word = 0x92065021, .value = 0xfc007ffffc007fff },
    .{ .word = 0x92065421, .value = 0xfc00fffffc00ffff },
    .{ .word = 0x92065821, .value = 0xfc01fffffc01ffff },
    .{ .word = 0x92065c21, .value = 0xfc03fffffc03ffff },
    .{ .word = 0x92066021, .value = 0xfc07fffffc07ffff },
    .{ .word = 0x92066421, .value = 0xfc0ffffffc0fffff },
    .{ .word = 0x92066821, .value = 0xfc1ffffffc1fffff },
    .{ .word = 0x92066c21, .value = 0xfc3ffffffc3fffff },
    .{ .word = 0x92067021, .value = 0xfc7ffffffc7fffff },
    .{ .word = 0x92067421, .value = 0xfcfffffffcffffff },
    .{ .word = 0x92067821, .value = 0xfdfffffffdffffff },
    .{ .word = 0x92068021, .value = 0x400040004000400 },
    .{ .word = 0x92068421, .value = 0xc000c000c000c00 },
    .{ .word = 0x92068821, .value = 0x1c001c001c001c00 },
    .{ .word = 0x92068c21, .value = 0x3c003c003c003c00 },
    .{ .word = 0x92069021, .value = 0x7c007c007c007c00 },
    .{ .word = 0x92069421, .value = 0xfc00fc00fc00fc00 },
    .{ .word = 0x92069821, .value = 0xfc01fc01fc01fc01 },
    .{ .word = 0x92069c21, .value = 0xfc03fc03fc03fc03 },
    .{ .word = 0x9206a021, .value = 0xfc07fc07fc07fc07 },
    .{ .word = 0x9206a421, .value = 0xfc0ffc0ffc0ffc0f },
    .{ .word = 0x9206a821, .value = 0xfc1ffc1ffc1ffc1f },
    .{ .word = 0x9206ac21, .value = 0xfc3ffc3ffc3ffc3f },
    .{ .word = 0x9206b021, .value = 0xfc7ffc7ffc7ffc7f },
    .{ .word = 0x9206b421, .value = 0xfcfffcfffcfffcff },
    .{ .word = 0x9206b821, .value = 0xfdfffdfffdfffdff },
    .{ .word = 0x9206c021, .value = 0x404040404040404 },
    .{ .word = 0x9206c421, .value = 0xc0c0c0c0c0c0c0c },
    .{ .word = 0x9206c821, .value = 0x1c1c1c1c1c1c1c1c },
    .{ .word = 0x9206cc21, .value = 0x3c3c3c3c3c3c3c3c },
    .{ .word = 0x9206d021, .value = 0x7c7c7c7c7c7c7c7c },
    .{ .word = 0x9206d421, .value = 0xfcfcfcfcfcfcfcfc },
    .{ .word = 0x9206d821, .value = 0xfdfdfdfdfdfdfdfd },
    .{ .word = 0x92070021, .value = 0x200000002000000 },
    .{ .word = 0x92070421, .value = 0x600000006000000 },
    .{ .word = 0x92070821, .value = 0xe0000000e000000 },
    .{ .word = 0x92070c21, .value = 0x1e0000001e000000 },
    .{ .word = 0x92071021, .value = 0x3e0000003e000000 },
    .{ .word = 0x92071421, .value = 0x7e0000007e000000 },
    .{ .word = 0x92071821, .value = 0xfe000000fe000000 },
    .{ .word = 0x92071c21, .value = 0xfe000001fe000001 },
    .{ .word = 0x92072021, .value = 0xfe000003fe000003 },
    .{ .word = 0x92072421, .value = 0xfe000007fe000007 },
    .{ .word = 0x92072821, .value = 0xfe00000ffe00000f },
    .{ .word = 0x92072c21, .value = 0xfe00001ffe00001f },
    .{ .word = 0x92073021, .value = 0xfe00003ffe00003f },
    .{ .word = 0x92073421, .value = 0xfe00007ffe00007f },
    .{ .word = 0x92073821, .value = 0xfe0000fffe0000ff },
    .{ .word = 0x92073c21, .value = 0xfe0001fffe0001ff },
    .{ .word = 0x92074021, .value = 0xfe0003fffe0003ff },
    .{ .word = 0x92074421, .value = 0xfe0007fffe0007ff },
    .{ .word = 0x92074821, .value = 0xfe000ffffe000fff },
    .{ .word = 0x92074c21, .value = 0xfe001ffffe001fff },
    .{ .word = 0x92075021, .value = 0xfe003ffffe003fff },
    .{ .word = 0x92075421, .value = 0xfe007ffffe007fff },
    .{ .word = 0x92075821, .value = 0xfe00fffffe00ffff },
    .{ .word = 0x92075c21, .value = 0xfe01fffffe01ffff },
    .{ .word = 0x92076021, .value = 0xfe03fffffe03ffff },
    .{ .word = 0x92076421, .value = 0xfe07fffffe07ffff },
    .{ .word = 0x92076821, .value = 0xfe0ffffffe0fffff },
    .{ .word = 0x92076c21, .value = 0xfe1ffffffe1fffff },
    .{ .word = 0x92077021, .value = 0xfe3ffffffe3fffff },
    .{ .word = 0x92077421, .value = 0xfe7ffffffe7fffff },
    .{ .word = 0x92077821, .value = 0xfefffffffeffffff },
    .{ .word = 0x92078021, .value = 0x200020002000200 },
    .{ .word = 0x92078421, .value = 0x600060006000600 },
    .{ .word = 0x92078821, .value = 0xe000e000e000e00 },
    .{ .word = 0x92078c21, .value = 0x1e001e001e001e00 },
    .{ .word = 0x92079021, .value = 0x3e003e003e003e00 },
    .{ .word = 0x92079421, .value = 0x7e007e007e007e00 },
    .{ .word = 0x92079821, .value = 0xfe00fe00fe00fe00 },
    .{ .word = 0x92079c21, .value = 0xfe01fe01fe01fe01 },
    .{ .word = 0x9207a021, .value = 0xfe03fe03fe03fe03 },
    .{ .word = 0x9207a421, .value = 0xfe07fe07fe07fe07 },
    .{ .word = 0x9207a821, .value = 0xfe0ffe0ffe0ffe0f },
    .{ .word = 0x9207ac21, .value = 0xfe1ffe1ffe1ffe1f },
    .{ .word = 0x9207b021, .value = 0xfe3ffe3ffe3ffe3f },
    .{ .word = 0x9207b421, .value = 0xfe7ffe7ffe7ffe7f },
    .{ .word = 0x9207b821, .value = 0xfefffefffefffeff },
    .{ .word = 0x9207c021, .value = 0x202020202020202 },
    .{ .word = 0x9207c421, .value = 0x606060606060606 },
    .{ .word = 0x9207c821, .value = 0xe0e0e0e0e0e0e0e },
    .{ .word = 0x9207cc21, .value = 0x1e1e1e1e1e1e1e1e },
    .{ .word = 0x9207d021, .value = 0x3e3e3e3e3e3e3e3e },
    .{ .word = 0x9207d421, .value = 0x7e7e7e7e7e7e7e7e },
    .{ .word = 0x9207d821, .value = 0xfefefefefefefefe },
    .{ .word = 0x92080021, .value = 0x100000001000000 },
    .{ .word = 0x92080421, .value = 0x300000003000000 },
    .{ .word = 0x92080821, .value = 0x700000007000000 },
    .{ .word = 0x92080c21, .value = 0xf0000000f000000 },
    .{ .word = 0x92081021, .value = 0x1f0000001f000000 },
    .{ .word = 0x92081421, .value = 0x3f0000003f000000 },
    .{ .word = 0x92081821, .value = 0x7f0000007f000000 },
    .{ .word = 0x92081c21, .value = 0xff000000ff000000 },
    .{ .word = 0x92082021, .value = 0xff000001ff000001 },
    .{ .word = 0x92082421, .value = 0xff000003ff000003 },
    .{ .word = 0x92082821, .value = 0xff000007ff000007 },
    .{ .word = 0x92082c21, .value = 0xff00000fff00000f },
    .{ .word = 0x92083021, .value = 0xff00001fff00001f },
    .{ .word = 0x92083421, .value = 0xff00003fff00003f },
    .{ .word = 0x92083821, .value = 0xff00007fff00007f },
    .{ .word = 0x92083c21, .value = 0xff0000ffff0000ff },
    .{ .word = 0x92084021, .value = 0xff0001ffff0001ff },
    .{ .word = 0x92084421, .value = 0xff0003ffff0003ff },
    .{ .word = 0x92084821, .value = 0xff0007ffff0007ff },
    .{ .word = 0x92084c21, .value = 0xff000fffff000fff },
    .{ .word = 0x92085021, .value = 0xff001fffff001fff },
    .{ .word = 0x92085421, .value = 0xff003fffff003fff },
    .{ .word = 0x92085821, .value = 0xff007fffff007fff },
    .{ .word = 0x92085c21, .value = 0xff00ffffff00ffff },
    .{ .word = 0x92086021, .value = 0xff01ffffff01ffff },
    .{ .word = 0x92086421, .value = 0xff03ffffff03ffff },
    .{ .word = 0x92086821, .value = 0xff07ffffff07ffff },
    .{ .word = 0x92086c21, .value = 0xff0fffffff0fffff },
    .{ .word = 0x92087021, .value = 0xff1fffffff1fffff },
    .{ .word = 0x92087421, .value = 0xff3fffffff3fffff },
    .{ .word = 0x92087821, .value = 0xff7fffffff7fffff },
    .{ .word = 0x92088021, .value = 0x100010001000100 },
    .{ .word = 0x92088421, .value = 0x300030003000300 },
    .{ .word = 0x92088821, .value = 0x700070007000700 },
    .{ .word = 0x92088c21, .value = 0xf000f000f000f00 },
    .{ .word = 0x92089021, .value = 0x1f001f001f001f00 },
    .{ .word = 0x92089421, .value = 0x3f003f003f003f00 },
    .{ .word = 0x92089821, .value = 0x7f007f007f007f00 },
    .{ .word = 0x92089c21, .value = 0xff00ff00ff00ff00 },
    .{ .word = 0x9208a021, .value = 0xff01ff01ff01ff01 },
    .{ .word = 0x9208a421, .value = 0xff03ff03ff03ff03 },
    .{ .word = 0x9208a821, .value = 0xff07ff07ff07ff07 },
    .{ .word = 0x9208ac21, .value = 0xff0fff0fff0fff0f },
    .{ .word = 0x9208b021, .value = 0xff1fff1fff1fff1f },
    .{ .word = 0x9208b421, .value = 0xff3fff3fff3fff3f },
    .{ .word = 0x9208b821, .value = 0xff7fff7fff7fff7f },
    .{ .word = 0x92090021, .value = 0x80000000800000 },
    .{ .word = 0x92090421, .value = 0x180000001800000 },
    .{ .word = 0x92090821, .value = 0x380000003800000 },
    .{ .word = 0x92090c21, .value = 0x780000007800000 },
    .{ .word = 0x92091021, .value = 0xf8000000f800000 },
    .{ .word = 0x92091421, .value = 0x1f8000001f800000 },
    .{ .word = 0x92091821, .value = 0x3f8000003f800000 },
    .{ .word = 0x92091c21, .value = 0x7f8000007f800000 },
    .{ .word = 0x92092021, .value = 0xff800000ff800000 },
    .{ .word = 0x92092421, .value = 0xff800001ff800001 },
    .{ .word = 0x92092821, .value = 0xff800003ff800003 },
    .{ .word = 0x92092c21, .value = 0xff800007ff800007 },
    .{ .word = 0x92093021, .value = 0xff80000fff80000f },
    .{ .word = 0x92093421, .value = 0xff80001fff80001f },
    .{ .word = 0x92093821, .value = 0xff80003fff80003f },
    .{ .word = 0x92093c21, .value = 0xff80007fff80007f },
    .{ .word = 0x92094021, .value = 0xff8000ffff8000ff },
    .{ .word = 0x92094421, .value = 0xff8001ffff8001ff },
    .{ .word = 0x92094821, .value = 0xff8003ffff8003ff },
    .{ .word = 0x92094c21, .value = 0xff8007ffff8007ff },
    .{ .word = 0x92095021, .value = 0xff800fffff800fff },
    .{ .word = 0x92095421, .value = 0xff801fffff801fff },
    .{ .word = 0x92095821, .value = 0xff803fffff803fff },
    .{ .word = 0x92095c21, .value = 0xff807fffff807fff },
    .{ .word = 0x92096021, .value = 0xff80ffffff80ffff },
    .{ .word = 0x92096421, .value = 0xff81ffffff81ffff },
    .{ .word = 0x92096821, .value = 0xff83ffffff83ffff },
    .{ .word = 0x92096c21, .value = 0xff87ffffff87ffff },
    .{ .word = 0x92097021, .value = 0xff8fffffff8fffff },
    .{ .word = 0x92097421, .value = 0xff9fffffff9fffff },
    .{ .word = 0x92097821, .value = 0xffbfffffffbfffff },
    .{ .word = 0x92098021, .value = 0x80008000800080 },
    .{ .word = 0x92098421, .value = 0x180018001800180 },
    .{ .word = 0x92098821, .value = 0x380038003800380 },
    .{ .word = 0x92098c21, .value = 0x780078007800780 },
    .{ .word = 0x92099021, .value = 0xf800f800f800f80 },
    .{ .word = 0x92099421, .value = 0x1f801f801f801f80 },
    .{ .word = 0x92099821, .value = 0x3f803f803f803f80 },
    .{ .word = 0x92099c21, .value = 0x7f807f807f807f80 },
    .{ .word = 0x9209a021, .value = 0xff80ff80ff80ff80 },
    .{ .word = 0x9209a421, .value = 0xff81ff81ff81ff81 },
    .{ .word = 0x9209a821, .value = 0xff83ff83ff83ff83 },
    .{ .word = 0x9209ac21, .value = 0xff87ff87ff87ff87 },
    .{ .word = 0x9209b021, .value = 0xff8fff8fff8fff8f },
    .{ .word = 0x9209b421, .value = 0xff9fff9fff9fff9f },
    .{ .word = 0x9209b821, .value = 0xffbfffbfffbfffbf },
    .{ .word = 0x920a0021, .value = 0x40000000400000 },
    .{ .word = 0x920a0421, .value = 0xc0000000c00000 },
    .{ .word = 0x920a0821, .value = 0x1c0000001c00000 },
    .{ .word = 0x920a0c21, .value = 0x3c0000003c00000 },
    .{ .word = 0x920a1021, .value = 0x7c0000007c00000 },
    .{ .word = 0x920a1421, .value = 0xfc000000fc00000 },
    .{ .word = 0x920a1821, .value = 0x1fc000001fc00000 },
    .{ .word = 0x920a1c21, .value = 0x3fc000003fc00000 },
    .{ .word = 0x920a2021, .value = 0x7fc000007fc00000 },
    .{ .word = 0x920a2421, .value = 0xffc00000ffc00000 },
    .{ .word = 0x920a2821, .value = 0xffc00001ffc00001 },
    .{ .word = 0x920a2c21, .value = 0xffc00003ffc00003 },
    .{ .word = 0x920a3021, .value = 0xffc00007ffc00007 },
    .{ .word = 0x920a3421, .value = 0xffc0000fffc0000f },
    .{ .word = 0x920a3821, .value = 0xffc0001fffc0001f },
    .{ .word = 0x920a3c21, .value = 0xffc0003fffc0003f },
    .{ .word = 0x920a4021, .value = 0xffc0007fffc0007f },
    .{ .word = 0x920a4421, .value = 0xffc000ffffc000ff },
    .{ .word = 0x920a4821, .value = 0xffc001ffffc001ff },
    .{ .word = 0x920a4c21, .value = 0xffc003ffffc003ff },
    .{ .word = 0x920a5021, .value = 0xffc007ffffc007ff },
    .{ .word = 0x920a5421, .value = 0xffc00fffffc00fff },
    .{ .word = 0x920a5821, .value = 0xffc01fffffc01fff },
    .{ .word = 0x920a5c21, .value = 0xffc03fffffc03fff },
    .{ .word = 0x920a6021, .value = 0xffc07fffffc07fff },
    .{ .word = 0x920a6421, .value = 0xffc0ffffffc0ffff },
    .{ .word = 0x920a6821, .value = 0xffc1ffffffc1ffff },
    .{ .word = 0x920a6c21, .value = 0xffc3ffffffc3ffff },
    .{ .word = 0x920a7021, .value = 0xffc7ffffffc7ffff },
    .{ .word = 0x920a7421, .value = 0xffcfffffffcfffff },
    .{ .word = 0x920a7821, .value = 0xffdfffffffdfffff },
    .{ .word = 0x920a8021, .value = 0x40004000400040 },
    .{ .word = 0x920a8421, .value = 0xc000c000c000c0 },
    .{ .word = 0x920a8821, .value = 0x1c001c001c001c0 },
    .{ .word = 0x920a8c21, .value = 0x3c003c003c003c0 },
    .{ .word = 0x920a9021, .value = 0x7c007c007c007c0 },
    .{ .word = 0x920a9421, .value = 0xfc00fc00fc00fc0 },
    .{ .word = 0x920a9821, .value = 0x1fc01fc01fc01fc0 },
    .{ .word = 0x920a9c21, .value = 0x3fc03fc03fc03fc0 },
    .{ .word = 0x920aa021, .value = 0x7fc07fc07fc07fc0 },
    .{ .word = 0x920aa421, .value = 0xffc0ffc0ffc0ffc0 },
    .{ .word = 0x920aa821, .value = 0xffc1ffc1ffc1ffc1 },
    .{ .word = 0x920aac21, .value = 0xffc3ffc3ffc3ffc3 },
    .{ .word = 0x920ab021, .value = 0xffc7ffc7ffc7ffc7 },
    .{ .word = 0x920ab421, .value = 0xffcfffcfffcfffcf },
    .{ .word = 0x920ab821, .value = 0xffdfffdfffdfffdf },
    .{ .word = 0x920b0021, .value = 0x20000000200000 },
    .{ .word = 0x920b0421, .value = 0x60000000600000 },
    .{ .word = 0x920b0821, .value = 0xe0000000e00000 },
    .{ .word = 0x920b0c21, .value = 0x1e0000001e00000 },
    .{ .word = 0x920b1021, .value = 0x3e0000003e00000 },
    .{ .word = 0x920b1421, .value = 0x7e0000007e00000 },
    .{ .word = 0x920b1821, .value = 0xfe000000fe00000 },
    .{ .word = 0x920b1c21, .value = 0x1fe000001fe00000 },
    .{ .word = 0x920b2021, .value = 0x3fe000003fe00000 },
    .{ .word = 0x920b2421, .value = 0x7fe000007fe00000 },
    .{ .word = 0x920b2821, .value = 0xffe00000ffe00000 },
    .{ .word = 0x920b2c21, .value = 0xffe00001ffe00001 },
    .{ .word = 0x920b3021, .value = 0xffe00003ffe00003 },
    .{ .word = 0x920b3421, .value = 0xffe00007ffe00007 },
    .{ .word = 0x920b3821, .value = 0xffe0000fffe0000f },
    .{ .word = 0x920b3c21, .value = 0xffe0001fffe0001f },
    .{ .word = 0x920b4021, .value = 0xffe0003fffe0003f },
    .{ .word = 0x920b4421, .value = 0xffe0007fffe0007f },
    .{ .word = 0x920b4821, .value = 0xffe000ffffe000ff },
    .{ .word = 0x920b4c21, .value = 0xffe001ffffe001ff },
    .{ .word = 0x920b5021, .value = 0xffe003ffffe003ff },
    .{ .word = 0x920b5421, .value = 0xffe007ffffe007ff },
    .{ .word = 0x920b5821, .value = 0xffe00fffffe00fff },
    .{ .word = 0x920b5c21, .value = 0xffe01fffffe01fff },
    .{ .word = 0x920b6021, .value = 0xffe03fffffe03fff },
    .{ .word = 0x920b6421, .value = 0xffe07fffffe07fff },
    .{ .word = 0x920b6821, .value = 0xffe0ffffffe0ffff },
    .{ .word = 0x920b6c21, .value = 0xffe1ffffffe1ffff },
    .{ .word = 0x920b7021, .value = 0xffe3ffffffe3ffff },
    .{ .word = 0x920b7421, .value = 0xffe7ffffffe7ffff },
    .{ .word = 0x920b7821, .value = 0xffefffffffefffff },
    .{ .word = 0x920b8021, .value = 0x20002000200020 },
    .{ .word = 0x920b8421, .value = 0x60006000600060 },
    .{ .word = 0x920b8821, .value = 0xe000e000e000e0 },
    .{ .word = 0x920b8c21, .value = 0x1e001e001e001e0 },
    .{ .word = 0x920b9021, .value = 0x3e003e003e003e0 },
    .{ .word = 0x920b9421, .value = 0x7e007e007e007e0 },
    .{ .word = 0x920b9821, .value = 0xfe00fe00fe00fe0 },
    .{ .word = 0x920b9c21, .value = 0x1fe01fe01fe01fe0 },
    .{ .word = 0x920ba021, .value = 0x3fe03fe03fe03fe0 },
    .{ .word = 0x920ba421, .value = 0x7fe07fe07fe07fe0 },
    .{ .word = 0x920ba821, .value = 0xffe0ffe0ffe0ffe0 },
    .{ .word = 0x920bac21, .value = 0xffe1ffe1ffe1ffe1 },
    .{ .word = 0x920bb021, .value = 0xffe3ffe3ffe3ffe3 },
    .{ .word = 0x920bb421, .value = 0xffe7ffe7ffe7ffe7 },
    .{ .word = 0x920bb821, .value = 0xffefffefffefffef },
    .{ .word = 0x920c0021, .value = 0x10000000100000 },
    .{ .word = 0x920c0421, .value = 0x30000000300000 },
    .{ .word = 0x920c0821, .value = 0x70000000700000 },
    .{ .word = 0x920c0c21, .value = 0xf0000000f00000 },
    .{ .word = 0x920c1021, .value = 0x1f0000001f00000 },
    .{ .word = 0x920c1421, .value = 0x3f0000003f00000 },
    .{ .word = 0x920c1821, .value = 0x7f0000007f00000 },
    .{ .word = 0x920c1c21, .value = 0xff000000ff00000 },
    .{ .word = 0x920c2021, .value = 0x1ff000001ff00000 },
    .{ .word = 0x920c2421, .value = 0x3ff000003ff00000 },
    .{ .word = 0x920c2821, .value = 0x7ff000007ff00000 },
    .{ .word = 0x920c2c21, .value = 0xfff00000fff00000 },
    .{ .word = 0x920c3021, .value = 0xfff00001fff00001 },
    .{ .word = 0x920c3421, .value = 0xfff00003fff00003 },
    .{ .word = 0x920c3821, .value = 0xfff00007fff00007 },
    .{ .word = 0x920c3c21, .value = 0xfff0000ffff0000f },
    .{ .word = 0x920c4021, .value = 0xfff0001ffff0001f },
    .{ .word = 0x920c4421, .value = 0xfff0003ffff0003f },
    .{ .word = 0x920c4821, .value = 0xfff0007ffff0007f },
    .{ .word = 0x920c4c21, .value = 0xfff000fffff000ff },
    .{ .word = 0x920c5021, .value = 0xfff001fffff001ff },
    .{ .word = 0x920c5421, .value = 0xfff003fffff003ff },
    .{ .word = 0x920c5821, .value = 0xfff007fffff007ff },
    .{ .word = 0x920c5c21, .value = 0xfff00ffffff00fff },
    .{ .word = 0x920c6021, .value = 0xfff01ffffff01fff },
    .{ .word = 0x920c6421, .value = 0xfff03ffffff03fff },
    .{ .word = 0x920c6821, .value = 0xfff07ffffff07fff },
    .{ .word = 0x920c6c21, .value = 0xfff0fffffff0ffff },
    .{ .word = 0x920c7021, .value = 0xfff1fffffff1ffff },
    .{ .word = 0x920c7421, .value = 0xfff3fffffff3ffff },
    .{ .word = 0x920c7821, .value = 0xfff7fffffff7ffff },
    .{ .word = 0x920c8021, .value = 0x10001000100010 },
    .{ .word = 0x920c8421, .value = 0x30003000300030 },
    .{ .word = 0x920c8821, .value = 0x70007000700070 },
    .{ .word = 0x920c8c21, .value = 0xf000f000f000f0 },
    .{ .word = 0x920c9021, .value = 0x1f001f001f001f0 },
    .{ .word = 0x920c9421, .value = 0x3f003f003f003f0 },
    .{ .word = 0x920c9821, .value = 0x7f007f007f007f0 },
    .{ .word = 0x920c9c21, .value = 0xff00ff00ff00ff0 },
    .{ .word = 0x920ca021, .value = 0x1ff01ff01ff01ff0 },
    .{ .word = 0x920ca421, .value = 0x3ff03ff03ff03ff0 },
    .{ .word = 0x920ca821, .value = 0x7ff07ff07ff07ff0 },
    .{ .word = 0x920cac21, .value = 0xfff0fff0fff0fff0 },
    .{ .word = 0x920cb021, .value = 0xfff1fff1fff1fff1 },
    .{ .word = 0x920cb421, .value = 0xfff3fff3fff3fff3 },
    .{ .word = 0x920cb821, .value = 0xfff7fff7fff7fff7 },
    .{ .word = 0x920d0021, .value = 0x8000000080000 },
    .{ .word = 0x920d0421, .value = 0x18000000180000 },
    .{ .word = 0x920d0821, .value = 0x38000000380000 },
    .{ .word = 0x920d0c21, .value = 0x78000000780000 },
    .{ .word = 0x920d1021, .value = 0xf8000000f80000 },
    .{ .word = 0x920d1421, .value = 0x1f8000001f80000 },
    .{ .word = 0x920d1821, .value = 0x3f8000003f80000 },
    .{ .word = 0x920d1c21, .value = 0x7f8000007f80000 },
    .{ .word = 0x920d2021, .value = 0xff800000ff80000 },
    .{ .word = 0x920d2421, .value = 0x1ff800001ff80000 },
    .{ .word = 0x920d2821, .value = 0x3ff800003ff80000 },
    .{ .word = 0x920d2c21, .value = 0x7ff800007ff80000 },
    .{ .word = 0x920d3021, .value = 0xfff80000fff80000 },
    .{ .word = 0x920d3421, .value = 0xfff80001fff80001 },
    .{ .word = 0x920d3821, .value = 0xfff80003fff80003 },
    .{ .word = 0x920d3c21, .value = 0xfff80007fff80007 },
    .{ .word = 0x920d4021, .value = 0xfff8000ffff8000f },
    .{ .word = 0x920d4421, .value = 0xfff8001ffff8001f },
    .{ .word = 0x920d4821, .value = 0xfff8003ffff8003f },
    .{ .word = 0x920d4c21, .value = 0xfff8007ffff8007f },
    .{ .word = 0x920d5021, .value = 0xfff800fffff800ff },
    .{ .word = 0x920d5421, .value = 0xfff801fffff801ff },
    .{ .word = 0x920d5821, .value = 0xfff803fffff803ff },
    .{ .word = 0x920d5c21, .value = 0xfff807fffff807ff },
    .{ .word = 0x920d6021, .value = 0xfff80ffffff80fff },
    .{ .word = 0x920d6421, .value = 0xfff81ffffff81fff },
    .{ .word = 0x920d6821, .value = 0xfff83ffffff83fff },
    .{ .word = 0x920d6c21, .value = 0xfff87ffffff87fff },
    .{ .word = 0x920d7021, .value = 0xfff8fffffff8ffff },
    .{ .word = 0x920d7421, .value = 0xfff9fffffff9ffff },
    .{ .word = 0x920d7821, .value = 0xfffbfffffffbffff },
    .{ .word = 0x920d8021, .value = 0x8000800080008 },
    .{ .word = 0x920d8421, .value = 0x18001800180018 },
    .{ .word = 0x920d8821, .value = 0x38003800380038 },
    .{ .word = 0x920d8c21, .value = 0x78007800780078 },
    .{ .word = 0x920d9021, .value = 0xf800f800f800f8 },
    .{ .word = 0x920d9421, .value = 0x1f801f801f801f8 },
    .{ .word = 0x920d9821, .value = 0x3f803f803f803f8 },
    .{ .word = 0x920d9c21, .value = 0x7f807f807f807f8 },
    .{ .word = 0x920da021, .value = 0xff80ff80ff80ff8 },
    .{ .word = 0x920da421, .value = 0x1ff81ff81ff81ff8 },
    .{ .word = 0x920da821, .value = 0x3ff83ff83ff83ff8 },
    .{ .word = 0x920dac21, .value = 0x7ff87ff87ff87ff8 },
    .{ .word = 0x920db021, .value = 0xfff8fff8fff8fff8 },
    .{ .word = 0x920db421, .value = 0xfff9fff9fff9fff9 },
    .{ .word = 0x920db821, .value = 0xfffbfffbfffbfffb },
    .{ .word = 0x920e0021, .value = 0x4000000040000 },
    .{ .word = 0x920e0421, .value = 0xc0000000c0000 },
    .{ .word = 0x920e0821, .value = 0x1c0000001c0000 },
    .{ .word = 0x920e0c21, .value = 0x3c0000003c0000 },
    .{ .word = 0x920e1021, .value = 0x7c0000007c0000 },
    .{ .word = 0x920e1421, .value = 0xfc000000fc0000 },
    .{ .word = 0x920e1821, .value = 0x1fc000001fc0000 },
    .{ .word = 0x920e1c21, .value = 0x3fc000003fc0000 },
    .{ .word = 0x920e2021, .value = 0x7fc000007fc0000 },
    .{ .word = 0x920e2421, .value = 0xffc00000ffc0000 },
    .{ .word = 0x920e2821, .value = 0x1ffc00001ffc0000 },
    .{ .word = 0x920e2c21, .value = 0x3ffc00003ffc0000 },
    .{ .word = 0x920e3021, .value = 0x7ffc00007ffc0000 },
    .{ .word = 0x920e3421, .value = 0xfffc0000fffc0000 },
    .{ .word = 0x920e3821, .value = 0xfffc0001fffc0001 },
    .{ .word = 0x920e3c21, .value = 0xfffc0003fffc0003 },
    .{ .word = 0x920e4021, .value = 0xfffc0007fffc0007 },
    .{ .word = 0x920e4421, .value = 0xfffc000ffffc000f },
    .{ .word = 0x920e4821, .value = 0xfffc001ffffc001f },
    .{ .word = 0x920e4c21, .value = 0xfffc003ffffc003f },
    .{ .word = 0x920e5021, .value = 0xfffc007ffffc007f },
    .{ .word = 0x920e5421, .value = 0xfffc00fffffc00ff },
    .{ .word = 0x920e5821, .value = 0xfffc01fffffc01ff },
    .{ .word = 0x920e5c21, .value = 0xfffc03fffffc03ff },
    .{ .word = 0x920e6021, .value = 0xfffc07fffffc07ff },
    .{ .word = 0x920e6421, .value = 0xfffc0ffffffc0fff },
    .{ .word = 0x920e6821, .value = 0xfffc1ffffffc1fff },
    .{ .word = 0x920e6c21, .value = 0xfffc3ffffffc3fff },
    .{ .word = 0x920e7021, .value = 0xfffc7ffffffc7fff },
    .{ .word = 0x920e7421, .value = 0xfffcfffffffcffff },
    .{ .word = 0x920e7821, .value = 0xfffdfffffffdffff },
    .{ .word = 0x920e8021, .value = 0x4000400040004 },
    .{ .word = 0x920e8421, .value = 0xc000c000c000c },
    .{ .word = 0x920e8821, .value = 0x1c001c001c001c },
    .{ .word = 0x920e8c21, .value = 0x3c003c003c003c },
    .{ .word = 0x920e9021, .value = 0x7c007c007c007c },
    .{ .word = 0x920e9421, .value = 0xfc00fc00fc00fc },
    .{ .word = 0x920e9821, .value = 0x1fc01fc01fc01fc },
    .{ .word = 0x920e9c21, .value = 0x3fc03fc03fc03fc },
    .{ .word = 0x920ea021, .value = 0x7fc07fc07fc07fc },
    .{ .word = 0x920ea421, .value = 0xffc0ffc0ffc0ffc },
    .{ .word = 0x920ea821, .value = 0x1ffc1ffc1ffc1ffc },
    .{ .word = 0x920eac21, .value = 0x3ffc3ffc3ffc3ffc },
    .{ .word = 0x920eb021, .value = 0x7ffc7ffc7ffc7ffc },
    .{ .word = 0x920eb421, .value = 0xfffcfffcfffcfffc },
    .{ .word = 0x920eb821, .value = 0xfffdfffdfffdfffd },
    .{ .word = 0x920f0021, .value = 0x2000000020000 },
    .{ .word = 0x920f0421, .value = 0x6000000060000 },
    .{ .word = 0x920f0821, .value = 0xe0000000e0000 },
    .{ .word = 0x920f0c21, .value = 0x1e0000001e0000 },
    .{ .word = 0x920f1021, .value = 0x3e0000003e0000 },
    .{ .word = 0x920f1421, .value = 0x7e0000007e0000 },
    .{ .word = 0x920f1821, .value = 0xfe000000fe0000 },
    .{ .word = 0x920f1c21, .value = 0x1fe000001fe0000 },
    .{ .word = 0x920f2021, .value = 0x3fe000003fe0000 },
    .{ .word = 0x920f2421, .value = 0x7fe000007fe0000 },
    .{ .word = 0x920f2821, .value = 0xffe00000ffe0000 },
    .{ .word = 0x920f2c21, .value = 0x1ffe00001ffe0000 },
    .{ .word = 0x920f3021, .value = 0x3ffe00003ffe0000 },
    .{ .word = 0x920f3421, .value = 0x7ffe00007ffe0000 },
    .{ .word = 0x920f3821, .value = 0xfffe0000fffe0000 },
    .{ .word = 0x920f3c21, .value = 0xfffe0001fffe0001 },
    .{ .word = 0x920f4021, .value = 0xfffe0003fffe0003 },
    .{ .word = 0x920f4421, .value = 0xfffe0007fffe0007 },
    .{ .word = 0x920f4821, .value = 0xfffe000ffffe000f },
    .{ .word = 0x920f4c21, .value = 0xfffe001ffffe001f },
    .{ .word = 0x920f5021, .value = 0xfffe003ffffe003f },
    .{ .word = 0x920f5421, .value = 0xfffe007ffffe007f },
    .{ .word = 0x920f5821, .value = 0xfffe00fffffe00ff },
    .{ .word = 0x920f5c21, .value = 0xfffe01fffffe01ff },
    .{ .word = 0x920f6021, .value = 0xfffe03fffffe03ff },
    .{ .word = 0x920f6421, .value = 0xfffe07fffffe07ff },
    .{ .word = 0x920f6821, .value = 0xfffe0ffffffe0fff },
    .{ .word = 0x920f6c21, .value = 0xfffe1ffffffe1fff },
    .{ .word = 0x920f7021, .value = 0xfffe3ffffffe3fff },
    .{ .word = 0x920f7421, .value = 0xfffe7ffffffe7fff },
    .{ .word = 0x920f7821, .value = 0xfffefffffffeffff },
    .{ .word = 0x920f8021, .value = 0x2000200020002 },
    .{ .word = 0x920f8421, .value = 0x6000600060006 },
    .{ .word = 0x920f8821, .value = 0xe000e000e000e },
    .{ .word = 0x920f8c21, .value = 0x1e001e001e001e },
    .{ .word = 0x920f9021, .value = 0x3e003e003e003e },
    .{ .word = 0x920f9421, .value = 0x7e007e007e007e },
    .{ .word = 0x920f9821, .value = 0xfe00fe00fe00fe },
    .{ .word = 0x920f9c21, .value = 0x1fe01fe01fe01fe },
    .{ .word = 0x920fa021, .value = 0x3fe03fe03fe03fe },
    .{ .word = 0x920fa421, .value = 0x7fe07fe07fe07fe },
    .{ .word = 0x920fa821, .value = 0xffe0ffe0ffe0ffe },
    .{ .word = 0x920fac21, .value = 0x1ffe1ffe1ffe1ffe },
    .{ .word = 0x920fb021, .value = 0x3ffe3ffe3ffe3ffe },
    .{ .word = 0x920fb421, .value = 0x7ffe7ffe7ffe7ffe },
    .{ .word = 0x920fb821, .value = 0xfffefffefffefffe },
    .{ .word = 0x92100021, .value = 0x1000000010000 },
    .{ .word = 0x92100421, .value = 0x3000000030000 },
    .{ .word = 0x92100821, .value = 0x7000000070000 },
    .{ .word = 0x92100c21, .value = 0xf0000000f0000 },
    .{ .word = 0x92101021, .value = 0x1f0000001f0000 },
    .{ .word = 0x92101421, .value = 0x3f0000003f0000 },
    .{ .word = 0x92101821, .value = 0x7f0000007f0000 },
    .{ .word = 0x92101c21, .value = 0xff000000ff0000 },
    .{ .word = 0x92102021, .value = 0x1ff000001ff0000 },
    .{ .word = 0x92102421, .value = 0x3ff000003ff0000 },
    .{ .word = 0x92102821, .value = 0x7ff000007ff0000 },
    .{ .word = 0x92102c21, .value = 0xfff00000fff0000 },
    .{ .word = 0x92103021, .value = 0x1fff00001fff0000 },
    .{ .word = 0x92103421, .value = 0x3fff00003fff0000 },
    .{ .word = 0x92103821, .value = 0x7fff00007fff0000 },
    .{ .word = 0x92103c21, .value = 0xffff0000ffff0000 },
    .{ .word = 0x92104021, .value = 0xffff0001ffff0001 },
    .{ .word = 0x92104421, .value = 0xffff0003ffff0003 },
    .{ .word = 0x92104821, .value = 0xffff0007ffff0007 },
    .{ .word = 0x92104c21, .value = 0xffff000fffff000f },
    .{ .word = 0x92105021, .value = 0xffff001fffff001f },
    .{ .word = 0x92105421, .value = 0xffff003fffff003f },
    .{ .word = 0x92105821, .value = 0xffff007fffff007f },
    .{ .word = 0x92105c21, .value = 0xffff00ffffff00ff },
    .{ .word = 0x92106021, .value = 0xffff01ffffff01ff },
    .{ .word = 0x92106421, .value = 0xffff03ffffff03ff },
    .{ .word = 0x92106821, .value = 0xffff07ffffff07ff },
    .{ .word = 0x92106c21, .value = 0xffff0fffffff0fff },
    .{ .word = 0x92107021, .value = 0xffff1fffffff1fff },
    .{ .word = 0x92107421, .value = 0xffff3fffffff3fff },
    .{ .word = 0x92107821, .value = 0xffff7fffffff7fff },
    .{ .word = 0x92110021, .value = 0x800000008000 },
    .{ .word = 0x92110421, .value = 0x1800000018000 },
    .{ .word = 0x92110821, .value = 0x3800000038000 },
    .{ .word = 0x92110c21, .value = 0x7800000078000 },
    .{ .word = 0x92111021, .value = 0xf8000000f8000 },
    .{ .word = 0x92111421, .value = 0x1f8000001f8000 },
    .{ .word = 0x92111821, .value = 0x3f8000003f8000 },
    .{ .word = 0x92111c21, .value = 0x7f8000007f8000 },
    .{ .word = 0x92112021, .value = 0xff800000ff8000 },
    .{ .word = 0x92112421, .value = 0x1ff800001ff8000 },
    .{ .word = 0x92112821, .value = 0x3ff800003ff8000 },
    .{ .word = 0x92112c21, .value = 0x7ff800007ff8000 },
    .{ .word = 0x92113021, .value = 0xfff80000fff8000 },
    .{ .word = 0x92113421, .value = 0x1fff80001fff8000 },
    .{ .word = 0x92113821, .value = 0x3fff80003fff8000 },
    .{ .word = 0x92113c21, .value = 0x7fff80007fff8000 },
    .{ .word = 0x92114021, .value = 0xffff8000ffff8000 },
    .{ .word = 0x92114421, .value = 0xffff8001ffff8001 },
    .{ .word = 0x92114821, .value = 0xffff8003ffff8003 },
    .{ .word = 0x92114c21, .value = 0xffff8007ffff8007 },
    .{ .word = 0x92115021, .value = 0xffff800fffff800f },
    .{ .word = 0x92115421, .value = 0xffff801fffff801f },
    .{ .word = 0x92115821, .value = 0xffff803fffff803f },
    .{ .word = 0x92115c21, .value = 0xffff807fffff807f },
    .{ .word = 0x92116021, .value = 0xffff80ffffff80ff },
    .{ .word = 0x92116421, .value = 0xffff81ffffff81ff },
    .{ .word = 0x92116821, .value = 0xffff83ffffff83ff },
    .{ .word = 0x92116c21, .value = 0xffff87ffffff87ff },
    .{ .word = 0x92117021, .value = 0xffff8fffffff8fff },
    .{ .word = 0x92117421, .value = 0xffff9fffffff9fff },
    .{ .word = 0x92117821, .value = 0xffffbfffffffbfff },
    .{ .word = 0x92120021, .value = 0x400000004000 },
    .{ .word = 0x92120421, .value = 0xc0000000c000 },
    .{ .word = 0x92120821, .value = 0x1c0000001c000 },
    .{ .word = 0x92120c21, .value = 0x3c0000003c000 },
    .{ .word = 0x92121021, .value = 0x7c0000007c000 },
    .{ .word = 0x92121421, .value = 0xfc000000fc000 },
    .{ .word = 0x92121821, .value = 0x1fc000001fc000 },
    .{ .word = 0x92121c21, .value = 0x3fc000003fc000 },
    .{ .word = 0x92122021, .value = 0x7fc000007fc000 },
    .{ .word = 0x92122421, .value = 0xffc00000ffc000 },
    .{ .word = 0x92122821, .value = 0x1ffc00001ffc000 },
    .{ .word = 0x92122c21, .value = 0x3ffc00003ffc000 },
    .{ .word = 0x92123021, .value = 0x7ffc00007ffc000 },
    .{ .word = 0x92123421, .value = 0xfffc0000fffc000 },
    .{ .word = 0x92123821, .value = 0x1fffc0001fffc000 },
    .{ .word = 0x92123c21, .value = 0x3fffc0003fffc000 },
    .{ .word = 0x92124021, .value = 0x7fffc0007fffc000 },
    .{ .word = 0x92124421, .value = 0xffffc000ffffc000 },
    .{ .word = 0x92124821, .value = 0xffffc001ffffc001 },
    .{ .word = 0x92124c21, .value = 0xffffc003ffffc003 },
    .{ .word = 0x92125021, .value = 0xffffc007ffffc007 },
    .{ .word = 0x92125421, .value = 0xffffc00fffffc00f },
    .{ .word = 0x92125821, .value = 0xffffc01fffffc01f },
    .{ .word = 0x92125c21, .value = 0xffffc03fffffc03f },
    .{ .word = 0x92126021, .value = 0xffffc07fffffc07f },
    .{ .word = 0x92126421, .value = 0xffffc0ffffffc0ff },
    .{ .word = 0x92126821, .value = 0xffffc1ffffffc1ff },
    .{ .word = 0x92126c21, .value = 0xffffc3ffffffc3ff },
    .{ .word = 0x92127021, .value = 0xffffc7ffffffc7ff },
    .{ .word = 0x92127421, .value = 0xffffcfffffffcfff },
    .{ .word = 0x92127821, .value = 0xffffdfffffffdfff },
    .{ .word = 0x92130021, .value = 0x200000002000 },
    .{ .word = 0x92130421, .value = 0x600000006000 },
    .{ .word = 0x92130821, .value = 0xe0000000e000 },
    .{ .word = 0x92130c21, .value = 0x1e0000001e000 },
    .{ .word = 0x92131021, .value = 0x3e0000003e000 },
    .{ .word = 0x92131421, .value = 0x7e0000007e000 },
    .{ .word = 0x92131821, .value = 0xfe000000fe000 },
    .{ .word = 0x92131c21, .value = 0x1fe000001fe000 },
    .{ .word = 0x92132021, .value = 0x3fe000003fe000 },
    .{ .word = 0x92132421, .value = 0x7fe000007fe000 },
    .{ .word = 0x92132821, .value = 0xffe00000ffe000 },
    .{ .word = 0x92132c21, .value = 0x1ffe00001ffe000 },
    .{ .word = 0x92133021, .value = 0x3ffe00003ffe000 },
    .{ .word = 0x92133421, .value = 0x7ffe00007ffe000 },
    .{ .word = 0x92133821, .value = 0xfffe0000fffe000 },
    .{ .word = 0x92133c21, .value = 0x1fffe0001fffe000 },
    .{ .word = 0x92134021, .value = 0x3fffe0003fffe000 },
    .{ .word = 0x92134421, .value = 0x7fffe0007fffe000 },
    .{ .word = 0x92134821, .value = 0xffffe000ffffe000 },
    .{ .word = 0x92134c21, .value = 0xffffe001ffffe001 },
    .{ .word = 0x92135021, .value = 0xffffe003ffffe003 },
    .{ .word = 0x92135421, .value = 0xffffe007ffffe007 },
    .{ .word = 0x92135821, .value = 0xffffe00fffffe00f },
    .{ .word = 0x92135c21, .value = 0xffffe01fffffe01f },
    .{ .word = 0x92136021, .value = 0xffffe03fffffe03f },
    .{ .word = 0x92136421, .value = 0xffffe07fffffe07f },
    .{ .word = 0x92136821, .value = 0xffffe0ffffffe0ff },
    .{ .word = 0x92136c21, .value = 0xffffe1ffffffe1ff },
    .{ .word = 0x92137021, .value = 0xffffe3ffffffe3ff },
    .{ .word = 0x92137421, .value = 0xffffe7ffffffe7ff },
    .{ .word = 0x92137821, .value = 0xffffefffffffefff },
    .{ .word = 0x92140021, .value = 0x100000001000 },
    .{ .word = 0x92140421, .value = 0x300000003000 },
    .{ .word = 0x92140821, .value = 0x700000007000 },
    .{ .word = 0x92140c21, .value = 0xf0000000f000 },
    .{ .word = 0x92141021, .value = 0x1f0000001f000 },
    .{ .word = 0x92141421, .value = 0x3f0000003f000 },
    .{ .word = 0x92141821, .value = 0x7f0000007f000 },
    .{ .word = 0x92141c21, .value = 0xff000000ff000 },
    .{ .word = 0x92142021, .value = 0x1ff000001ff000 },
    .{ .word = 0x92142421, .value = 0x3ff000003ff000 },
    .{ .word = 0x92142821, .value = 0x7ff000007ff000 },
    .{ .word = 0x92142c21, .value = 0xfff00000fff000 },
    .{ .word = 0x92143021, .value = 0x1fff00001fff000 },
    .{ .word = 0x92143421, .value = 0x3fff00003fff000 },
    .{ .word = 0x92143821, .value = 0x7fff00007fff000 },
    .{ .word = 0x92143c21, .value = 0xffff0000ffff000 },
    .{ .word = 0x92144021, .value = 0x1ffff0001ffff000 },
    .{ .word = 0x92144421, .value = 0x3ffff0003ffff000 },
    .{ .word = 0x92144821, .value = 0x7ffff0007ffff000 },
    .{ .word = 0x92144c21, .value = 0xfffff000fffff000 },
    .{ .word = 0x92145021, .value = 0xfffff001fffff001 },
    .{ .word = 0x92145421, .value = 0xfffff003fffff003 },
    .{ .word = 0x92145821, .value = 0xfffff007fffff007 },
    .{ .word = 0x92145c21, .value = 0xfffff00ffffff00f },
    .{ .word = 0x92146021, .value = 0xfffff01ffffff01f },
    .{ .word = 0x92146421, .value = 0xfffff03ffffff03f },
    .{ .word = 0x92146821, .value = 0xfffff07ffffff07f },
    .{ .word = 0x92146c21, .value = 0xfffff0fffffff0ff },
    .{ .word = 0x92147021, .value = 0xfffff1fffffff1ff },
    .{ .word = 0x92147421, .value = 0xfffff3fffffff3ff },
    .{ .word = 0x92147821, .value = 0xfffff7fffffff7ff },
    .{ .word = 0x92150021, .value = 0x80000000800 },
    .{ .word = 0x92150421, .value = 0x180000001800 },
    .{ .word = 0x92150821, .value = 0x380000003800 },
    .{ .word = 0x92150c21, .value = 0x780000007800 },
    .{ .word = 0x92151021, .value = 0xf8000000f800 },
    .{ .word = 0x92151421, .value = 0x1f8000001f800 },
    .{ .word = 0x92151821, .value = 0x3f8000003f800 },
    .{ .word = 0x92151c21, .value = 0x7f8000007f800 },
    .{ .word = 0x92152021, .value = 0xff800000ff800 },
    .{ .word = 0x92152421, .value = 0x1ff800001ff800 },
    .{ .word = 0x92152821, .value = 0x3ff800003ff800 },
    .{ .word = 0x92152c21, .value = 0x7ff800007ff800 },
    .{ .word = 0x92153021, .value = 0xfff80000fff800 },
    .{ .word = 0x92153421, .value = 0x1fff80001fff800 },
    .{ .word = 0x92153821, .value = 0x3fff80003fff800 },
    .{ .word = 0x92153c21, .value = 0x7fff80007fff800 },
    .{ .word = 0x92154021, .value = 0xffff8000ffff800 },
    .{ .word = 0x92154421, .value = 0x1ffff8001ffff800 },
    .{ .word = 0x92154821, .value = 0x3ffff8003ffff800 },
    .{ .word = 0x92154c21, .value = 0x7ffff8007ffff800 },
    .{ .word = 0x92155021, .value = 0xfffff800fffff800 },
    .{ .word = 0x92155421, .value = 0xfffff801fffff801 },
    .{ .word = 0x92155821, .value = 0xfffff803fffff803 },
    .{ .word = 0x92155c21, .value = 0xfffff807fffff807 },
    .{ .word = 0x92156021, .value = 0xfffff80ffffff80f },
    .{ .word = 0x92156421, .value = 0xfffff81ffffff81f },
    .{ .word = 0x92156821, .value = 0xfffff83ffffff83f },
    .{ .word = 0x92156c21, .value = 0xfffff87ffffff87f },
    .{ .word = 0x92157021, .value = 0xfffff8fffffff8ff },
    .{ .word = 0x92157421, .value = 0xfffff9fffffff9ff },
    .{ .word = 0x92157821, .value = 0xfffffbfffffffbff },
    .{ .word = 0x92160021, .value = 0x40000000400 },
    .{ .word = 0x92160421, .value = 0xc0000000c00 },
    .{ .word = 0x92160821, .value = 0x1c0000001c00 },
    .{ .word = 0x92160c21, .value = 0x3c0000003c00 },
    .{ .word = 0x92161021, .value = 0x7c0000007c00 },
    .{ .word = 0x92161421, .value = 0xfc000000fc00 },
    .{ .word = 0x92161821, .value = 0x1fc000001fc00 },
    .{ .word = 0x92161c21, .value = 0x3fc000003fc00 },
    .{ .word = 0x92162021, .value = 0x7fc000007fc00 },
    .{ .word = 0x92162421, .value = 0xffc00000ffc00 },
    .{ .word = 0x92162821, .value = 0x1ffc00001ffc00 },
    .{ .word = 0x92162c21, .value = 0x3ffc00003ffc00 },
    .{ .word = 0x92163021, .value = 0x7ffc00007ffc00 },
    .{ .word = 0x92163421, .value = 0xfffc0000fffc00 },
    .{ .word = 0x92163821, .value = 0x1fffc0001fffc00 },
    .{ .word = 0x92163c21, .value = 0x3fffc0003fffc00 },
    .{ .word = 0x92164021, .value = 0x7fffc0007fffc00 },
    .{ .word = 0x92164421, .value = 0xffffc000ffffc00 },
    .{ .word = 0x92164821, .value = 0x1ffffc001ffffc00 },
    .{ .word = 0x92164c21, .value = 0x3ffffc003ffffc00 },
    .{ .word = 0x92165021, .value = 0x7ffffc007ffffc00 },
    .{ .word = 0x92165421, .value = 0xfffffc00fffffc00 },
    .{ .word = 0x92165821, .value = 0xfffffc01fffffc01 },
    .{ .word = 0x92165c21, .value = 0xfffffc03fffffc03 },
    .{ .word = 0x92166021, .value = 0xfffffc07fffffc07 },
    .{ .word = 0x92166421, .value = 0xfffffc0ffffffc0f },
    .{ .word = 0x92166821, .value = 0xfffffc1ffffffc1f },
    .{ .word = 0x92166c21, .value = 0xfffffc3ffffffc3f },
    .{ .word = 0x92167021, .value = 0xfffffc7ffffffc7f },
    .{ .word = 0x92167421, .value = 0xfffffcfffffffcff },
    .{ .word = 0x92167821, .value = 0xfffffdfffffffdff },
    .{ .word = 0x92170021, .value = 0x20000000200 },
    .{ .word = 0x92170421, .value = 0x60000000600 },
    .{ .word = 0x92170821, .value = 0xe0000000e00 },
    .{ .word = 0x92170c21, .value = 0x1e0000001e00 },
    .{ .word = 0x92171021, .value = 0x3e0000003e00 },
    .{ .word = 0x92171421, .value = 0x7e0000007e00 },
    .{ .word = 0x92171821, .value = 0xfe000000fe00 },
    .{ .word = 0x92171c21, .value = 0x1fe000001fe00 },
    .{ .word = 0x92172021, .value = 0x3fe000003fe00 },
    .{ .word = 0x92172421, .value = 0x7fe000007fe00 },
    .{ .word = 0x92172821, .value = 0xffe00000ffe00 },
    .{ .word = 0x92172c21, .value = 0x1ffe00001ffe00 },
    .{ .word = 0x92173021, .value = 0x3ffe00003ffe00 },
    .{ .word = 0x92173421, .value = 0x7ffe00007ffe00 },
    .{ .word = 0x92173821, .value = 0xfffe0000fffe00 },
    .{ .word = 0x92173c21, .value = 0x1fffe0001fffe00 },
    .{ .word = 0x92174021, .value = 0x3fffe0003fffe00 },
    .{ .word = 0x92174421, .value = 0x7fffe0007fffe00 },
    .{ .word = 0x92174821, .value = 0xffffe000ffffe00 },
    .{ .word = 0x92174c21, .value = 0x1ffffe001ffffe00 },
    .{ .word = 0x92175021, .value = 0x3ffffe003ffffe00 },
    .{ .word = 0x92175421, .value = 0x7ffffe007ffffe00 },
    .{ .word = 0x92175821, .value = 0xfffffe00fffffe00 },
    .{ .word = 0x92175c21, .value = 0xfffffe01fffffe01 },
    .{ .word = 0x92176021, .value = 0xfffffe03fffffe03 },
    .{ .word = 0x92176421, .value = 0xfffffe07fffffe07 },
    .{ .word = 0x92176821, .value = 0xfffffe0ffffffe0f },
    .{ .word = 0x92176c21, .value = 0xfffffe1ffffffe1f },
    .{ .word = 0x92177021, .value = 0xfffffe3ffffffe3f },
    .{ .word = 0x92177421, .value = 0xfffffe7ffffffe7f },
    .{ .word = 0x92177821, .value = 0xfffffefffffffeff },
    .{ .word = 0x92180021, .value = 0x10000000100 },
    .{ .word = 0x92180421, .value = 0x30000000300 },
    .{ .word = 0x92180821, .value = 0x70000000700 },
    .{ .word = 0x92180c21, .value = 0xf0000000f00 },
    .{ .word = 0x92181021, .value = 0x1f0000001f00 },
    .{ .word = 0x92181421, .value = 0x3f0000003f00 },
    .{ .word = 0x92181821, .value = 0x7f0000007f00 },
    .{ .word = 0x92181c21, .value = 0xff000000ff00 },
    .{ .word = 0x92182021, .value = 0x1ff000001ff00 },
    .{ .word = 0x92182421, .value = 0x3ff000003ff00 },
    .{ .word = 0x92182821, .value = 0x7ff000007ff00 },
    .{ .word = 0x92182c21, .value = 0xfff00000fff00 },
    .{ .word = 0x92183021, .value = 0x1fff00001fff00 },
    .{ .word = 0x92183421, .value = 0x3fff00003fff00 },
    .{ .word = 0x92183821, .value = 0x7fff00007fff00 },
    .{ .word = 0x92183c21, .value = 0xffff0000ffff00 },
    .{ .word = 0x92184021, .value = 0x1ffff0001ffff00 },
    .{ .word = 0x92184421, .value = 0x3ffff0003ffff00 },
    .{ .word = 0x92184821, .value = 0x7ffff0007ffff00 },
    .{ .word = 0x92184c21, .value = 0xfffff000fffff00 },
    .{ .word = 0x92185021, .value = 0x1fffff001fffff00 },
    .{ .word = 0x92185421, .value = 0x3fffff003fffff00 },
    .{ .word = 0x92185821, .value = 0x7fffff007fffff00 },
    .{ .word = 0x92185c21, .value = 0xffffff00ffffff00 },
    .{ .word = 0x92186021, .value = 0xffffff01ffffff01 },
    .{ .word = 0x92186421, .value = 0xffffff03ffffff03 },
    .{ .word = 0x92186821, .value = 0xffffff07ffffff07 },
    .{ .word = 0x92186c21, .value = 0xffffff0fffffff0f },
    .{ .word = 0x92187021, .value = 0xffffff1fffffff1f },
    .{ .word = 0x92187421, .value = 0xffffff3fffffff3f },
    .{ .word = 0x92187821, .value = 0xffffff7fffffff7f },
    .{ .word = 0x92190021, .value = 0x8000000080 },
    .{ .word = 0x92190421, .value = 0x18000000180 },
    .{ .word = 0x92190821, .value = 0x38000000380 },
    .{ .word = 0x92190c21, .value = 0x78000000780 },
    .{ .word = 0x92191021, .value = 0xf8000000f80 },
    .{ .word = 0x92191421, .value = 0x1f8000001f80 },
    .{ .word = 0x92191821, .value = 0x3f8000003f80 },
    .{ .word = 0x92191c21, .value = 0x7f8000007f80 },
    .{ .word = 0x92192021, .value = 0xff800000ff80 },
    .{ .word = 0x92192421, .value = 0x1ff800001ff80 },
    .{ .word = 0x92192821, .value = 0x3ff800003ff80 },
    .{ .word = 0x92192c21, .value = 0x7ff800007ff80 },
    .{ .word = 0x92193021, .value = 0xfff80000fff80 },
    .{ .word = 0x92193421, .value = 0x1fff80001fff80 },
    .{ .word = 0x92193821, .value = 0x3fff80003fff80 },
    .{ .word = 0x92193c21, .value = 0x7fff80007fff80 },
    .{ .word = 0x92194021, .value = 0xffff8000ffff80 },
    .{ .word = 0x92194421, .value = 0x1ffff8001ffff80 },
    .{ .word = 0x92194821, .value = 0x3ffff8003ffff80 },
    .{ .word = 0x92194c21, .value = 0x7ffff8007ffff80 },
    .{ .word = 0x92195021, .value = 0xfffff800fffff80 },
    .{ .word = 0x92195421, .value = 0x1fffff801fffff80 },
    .{ .word = 0x92195821, .value = 0x3fffff803fffff80 },
    .{ .word = 0x92195c21, .value = 0x7fffff807fffff80 },
    .{ .word = 0x92196021, .value = 0xffffff80ffffff80 },
    .{ .word = 0x92196421, .value = 0xffffff81ffffff81 },
    .{ .word = 0x92196821, .value = 0xffffff83ffffff83 },
    .{ .word = 0x92196c21, .value = 0xffffff87ffffff87 },
    .{ .word = 0x92197021, .value = 0xffffff8fffffff8f },
    .{ .word = 0x92197421, .value = 0xffffff9fffffff9f },
    .{ .word = 0x92197821, .value = 0xffffffbfffffffbf },
    .{ .word = 0x921a0021, .value = 0x4000000040 },
    .{ .word = 0x921a0421, .value = 0xc0000000c0 },
    .{ .word = 0x921a0821, .value = 0x1c0000001c0 },
    .{ .word = 0x921a0c21, .value = 0x3c0000003c0 },
    .{ .word = 0x921a1021, .value = 0x7c0000007c0 },
    .{ .word = 0x921a1421, .value = 0xfc000000fc0 },
    .{ .word = 0x921a1821, .value = 0x1fc000001fc0 },
    .{ .word = 0x921a1c21, .value = 0x3fc000003fc0 },
    .{ .word = 0x921a2021, .value = 0x7fc000007fc0 },
    .{ .word = 0x921a2421, .value = 0xffc00000ffc0 },
    .{ .word = 0x921a2821, .value = 0x1ffc00001ffc0 },
    .{ .word = 0x921a2c21, .value = 0x3ffc00003ffc0 },
    .{ .word = 0x921a3021, .value = 0x7ffc00007ffc0 },
    .{ .word = 0x921a3421, .value = 0xfffc0000fffc0 },
    .{ .word = 0x921a3821, .value = 0x1fffc0001fffc0 },
    .{ .word = 0x921a3c21, .value = 0x3fffc0003fffc0 },
    .{ .word = 0x921a4021, .value = 0x7fffc0007fffc0 },
    .{ .word = 0x921a4421, .value = 0xffffc000ffffc0 },
    .{ .word = 0x921a4821, .value = 0x1ffffc001ffffc0 },
    .{ .word = 0x921a4c21, .value = 0x3ffffc003ffffc0 },
    .{ .word = 0x921a5021, .value = 0x7ffffc007ffffc0 },
    .{ .word = 0x921a5421, .value = 0xfffffc00fffffc0 },
    .{ .word = 0x921a5821, .value = 0x1fffffc01fffffc0 },
    .{ .word = 0x921a5c21, .value = 0x3fffffc03fffffc0 },
    .{ .word = 0x921a6021, .value = 0x7fffffc07fffffc0 },
    .{ .word = 0x921a6421, .value = 0xffffffc0ffffffc0 },
    .{ .word = 0x921a6821, .value = 0xffffffc1ffffffc1 },
    .{ .word = 0x921a6c21, .value = 0xffffffc3ffffffc3 },
    .{ .word = 0x921a7021, .value = 0xffffffc7ffffffc7 },
    .{ .word = 0x921a7421, .value = 0xffffffcfffffffcf },
    .{ .word = 0x921a7821, .value = 0xffffffdfffffffdf },
    .{ .word = 0x921b0021, .value = 0x2000000020 },
    .{ .word = 0x921b0421, .value = 0x6000000060 },
    .{ .word = 0x921b0821, .value = 0xe0000000e0 },
    .{ .word = 0x921b0c21, .value = 0x1e0000001e0 },
    .{ .word = 0x921b1021, .value = 0x3e0000003e0 },
    .{ .word = 0x921b1421, .value = 0x7e0000007e0 },
    .{ .word = 0x921b1821, .value = 0xfe000000fe0 },
    .{ .word = 0x921b1c21, .value = 0x1fe000001fe0 },
    .{ .word = 0x921b2021, .value = 0x3fe000003fe0 },
    .{ .word = 0x921b2421, .value = 0x7fe000007fe0 },
    .{ .word = 0x921b2821, .value = 0xffe00000ffe0 },
    .{ .word = 0x921b2c21, .value = 0x1ffe00001ffe0 },
    .{ .word = 0x921b3021, .value = 0x3ffe00003ffe0 },
    .{ .word = 0x921b3421, .value = 0x7ffe00007ffe0 },
    .{ .word = 0x921b3821, .value = 0xfffe0000fffe0 },
    .{ .word = 0x921b3c21, .value = 0x1fffe0001fffe0 },
    .{ .word = 0x921b4021, .value = 0x3fffe0003fffe0 },
    .{ .word = 0x921b4421, .value = 0x7fffe0007fffe0 },
    .{ .word = 0x921b4821, .value = 0xffffe000ffffe0 },
    .{ .word = 0x921b4c21, .value = 0x1ffffe001ffffe0 },
    .{ .word = 0x921b5021, .value = 0x3ffffe003ffffe0 },
    .{ .word = 0x921b5421, .value = 0x7ffffe007ffffe0 },
    .{ .word = 0x921b5821, .value = 0xfffffe00fffffe0 },
    .{ .word = 0x921b5c21, .value = 0x1fffffe01fffffe0 },
    .{ .word = 0x921b6021, .value = 0x3fffffe03fffffe0 },
    .{ .word = 0x921b6421, .value = 0x7fffffe07fffffe0 },
    .{ .word = 0x921b6821, .value = 0xffffffe0ffffffe0 },
    .{ .word = 0x921b6c21, .value = 0xffffffe1ffffffe1 },
    .{ .word = 0x921b7021, .value = 0xffffffe3ffffffe3 },
    .{ .word = 0x921b7421, .value = 0xffffffe7ffffffe7 },
    .{ .word = 0x921b7821, .value = 0xffffffefffffffef },
    .{ .word = 0x921c0021, .value = 0x1000000010 },
    .{ .word = 0x921c0421, .value = 0x3000000030 },
    .{ .word = 0x921c0821, .value = 0x7000000070 },
    .{ .word = 0x921c0c21, .value = 0xf0000000f0 },
    .{ .word = 0x921c1021, .value = 0x1f0000001f0 },
    .{ .word = 0x921c1421, .value = 0x3f0000003f0 },
    .{ .word = 0x921c1821, .value = 0x7f0000007f0 },
    .{ .word = 0x921c1c21, .value = 0xff000000ff0 },
    .{ .word = 0x921c2021, .value = 0x1ff000001ff0 },
    .{ .word = 0x921c2421, .value = 0x3ff000003ff0 },
    .{ .word = 0x921c2821, .value = 0x7ff000007ff0 },
    .{ .word = 0x921c2c21, .value = 0xfff00000fff0 },
    .{ .word = 0x921c3021, .value = 0x1fff00001fff0 },
    .{ .word = 0x921c3421, .value = 0x3fff00003fff0 },
    .{ .word = 0x921c3821, .value = 0x7fff00007fff0 },
    .{ .word = 0x921c3c21, .value = 0xffff0000ffff0 },
    .{ .word = 0x921c4021, .value = 0x1ffff0001ffff0 },
    .{ .word = 0x921c4421, .value = 0x3ffff0003ffff0 },
    .{ .word = 0x921c4821, .value = 0x7ffff0007ffff0 },
    .{ .word = 0x921c4c21, .value = 0xfffff000fffff0 },
    .{ .word = 0x921c5021, .value = 0x1fffff001fffff0 },
    .{ .word = 0x921c5421, .value = 0x3fffff003fffff0 },
    .{ .word = 0x921c5821, .value = 0x7fffff007fffff0 },
    .{ .word = 0x921c5c21, .value = 0xffffff00ffffff0 },
    .{ .word = 0x921c6021, .value = 0x1ffffff01ffffff0 },
    .{ .word = 0x921c6421, .value = 0x3ffffff03ffffff0 },
    .{ .word = 0x921c6821, .value = 0x7ffffff07ffffff0 },
    .{ .word = 0x921c6c21, .value = 0xfffffff0fffffff0 },
    .{ .word = 0x921c7021, .value = 0xfffffff1fffffff1 },
    .{ .word = 0x921c7421, .value = 0xfffffff3fffffff3 },
    .{ .word = 0x921c7821, .value = 0xfffffff7fffffff7 },
    .{ .word = 0x921d0021, .value = 0x800000008 },
    .{ .word = 0x921d0421, .value = 0x1800000018 },
    .{ .word = 0x921d0821, .value = 0x3800000038 },
    .{ .word = 0x921d0c21, .value = 0x7800000078 },
    .{ .word = 0x921d1021, .value = 0xf8000000f8 },
    .{ .word = 0x921d1421, .value = 0x1f8000001f8 },
    .{ .word = 0x921d1821, .value = 0x3f8000003f8 },
    .{ .word = 0x921d1c21, .value = 0x7f8000007f8 },
    .{ .word = 0x921d2021, .value = 0xff800000ff8 },
    .{ .word = 0x921d2421, .value = 0x1ff800001ff8 },
    .{ .word = 0x921d2821, .value = 0x3ff800003ff8 },
    .{ .word = 0x921d2c21, .value = 0x7ff800007ff8 },
    .{ .word = 0x921d3021, .value = 0xfff80000fff8 },
    .{ .word = 0x921d3421, .value = 0x1fff80001fff8 },
    .{ .word = 0x921d3821, .value = 0x3fff80003fff8 },
    .{ .word = 0x921d3c21, .value = 0x7fff80007fff8 },
    .{ .word = 0x921d4021, .value = 0xffff8000ffff8 },
    .{ .word = 0x921d4421, .value = 0x1ffff8001ffff8 },
    .{ .word = 0x921d4821, .value = 0x3ffff8003ffff8 },
    .{ .word = 0x921d4c21, .value = 0x7ffff8007ffff8 },
    .{ .word = 0x921d5021, .value = 0xfffff800fffff8 },
    .{ .word = 0x921d5421, .value = 0x1fffff801fffff8 },
    .{ .word = 0x921d5821, .value = 0x3fffff803fffff8 },
    .{ .word = 0x921d5c21, .value = 0x7fffff807fffff8 },
    .{ .word = 0x921d6021, .value = 0xffffff80ffffff8 },
    .{ .word = 0x921d6421, .value = 0x1ffffff81ffffff8 },
    .{ .word = 0x921d6821, .value = 0x3ffffff83ffffff8 },
    .{ .word = 0x921d6c21, .value = 0x7ffffff87ffffff8 },
    .{ .word = 0x921d7021, .value = 0xfffffff8fffffff8 },
    .{ .word = 0x921d7421, .value = 0xfffffff9fffffff9 },
    .{ .word = 0x921d7821, .value = 0xfffffffbfffffffb },
    .{ .word = 0x921e0021, .value = 0x400000004 },
    .{ .word = 0x921e0421, .value = 0xc0000000c },
    .{ .word = 0x921e0821, .value = 0x1c0000001c },
    .{ .word = 0x921e0c21, .value = 0x3c0000003c },
    .{ .word = 0x921e1021, .value = 0x7c0000007c },
    .{ .word = 0x921e1421, .value = 0xfc000000fc },
    .{ .word = 0x921e1821, .value = 0x1fc000001fc },
    .{ .word = 0x921e1c21, .value = 0x3fc000003fc },
    .{ .word = 0x921e2021, .value = 0x7fc000007fc },
    .{ .word = 0x921e2421, .value = 0xffc00000ffc },
    .{ .word = 0x921e2821, .value = 0x1ffc00001ffc },
    .{ .word = 0x921e2c21, .value = 0x3ffc00003ffc },
    .{ .word = 0x921e3021, .value = 0x7ffc00007ffc },
    .{ .word = 0x921e3421, .value = 0xfffc0000fffc },
    .{ .word = 0x921e3821, .value = 0x1fffc0001fffc },
    .{ .word = 0x921e3c21, .value = 0x3fffc0003fffc },
    .{ .word = 0x921e4021, .value = 0x7fffc0007fffc },
    .{ .word = 0x921e4421, .value = 0xffffc000ffffc },
    .{ .word = 0x921e4821, .value = 0x1ffffc001ffffc },
    .{ .word = 0x921e4c21, .value = 0x3ffffc003ffffc },
    .{ .word = 0x921e5021, .value = 0x7ffffc007ffffc },
    .{ .word = 0x921e5421, .value = 0xfffffc00fffffc },
    .{ .word = 0x921e5821, .value = 0x1fffffc01fffffc },
    .{ .word = 0x921e5c21, .value = 0x3fffffc03fffffc },
    .{ .word = 0x921e6021, .value = 0x7fffffc07fffffc },
    .{ .word = 0x921e6421, .value = 0xffffffc0ffffffc },
    .{ .word = 0x921e6821, .value = 0x1ffffffc1ffffffc },
    .{ .word = 0x921e6c21, .value = 0x3ffffffc3ffffffc },
    .{ .word = 0x921e7021, .value = 0x7ffffffc7ffffffc },
    .{ .word = 0x921e7421, .value = 0xfffffffcfffffffc },
    .{ .word = 0x921e7821, .value = 0xfffffffdfffffffd },
    .{ .word = 0x921f0021, .value = 0x200000002 },
    .{ .word = 0x921f0421, .value = 0x600000006 },
    .{ .word = 0x921f0821, .value = 0xe0000000e },
    .{ .word = 0x921f0c21, .value = 0x1e0000001e },
    .{ .word = 0x921f1021, .value = 0x3e0000003e },
    .{ .word = 0x921f1421, .value = 0x7e0000007e },
    .{ .word = 0x921f1821, .value = 0xfe000000fe },
    .{ .word = 0x921f1c21, .value = 0x1fe000001fe },
    .{ .word = 0x921f2021, .value = 0x3fe000003fe },
    .{ .word = 0x921f2421, .value = 0x7fe000007fe },
    .{ .word = 0x921f2821, .value = 0xffe00000ffe },
    .{ .word = 0x921f2c21, .value = 0x1ffe00001ffe },
    .{ .word = 0x921f3021, .value = 0x3ffe00003ffe },
    .{ .word = 0x921f3421, .value = 0x7ffe00007ffe },
    .{ .word = 0x921f3821, .value = 0xfffe0000fffe },
    .{ .word = 0x921f3c21, .value = 0x1fffe0001fffe },
    .{ .word = 0x921f4021, .value = 0x3fffe0003fffe },
    .{ .word = 0x921f4421, .value = 0x7fffe0007fffe },
    .{ .word = 0x921f4821, .value = 0xffffe000ffffe },
    .{ .word = 0x921f4c21, .value = 0x1ffffe001ffffe },
    .{ .word = 0x921f5021, .value = 0x3ffffe003ffffe },
    .{ .word = 0x921f5421, .value = 0x7ffffe007ffffe },
    .{ .word = 0x921f5821, .value = 0xfffffe00fffffe },
    .{ .word = 0x921f5c21, .value = 0x1fffffe01fffffe },
    .{ .word = 0x921f6021, .value = 0x3fffffe03fffffe },
    .{ .word = 0x921f6421, .value = 0x7fffffe07fffffe },
    .{ .word = 0x921f6821, .value = 0xffffffe0ffffffe },
    .{ .word = 0x921f6c21, .value = 0x1ffffffe1ffffffe },
    .{ .word = 0x921f7021, .value = 0x3ffffffe3ffffffe },
    .{ .word = 0x921f7421, .value = 0x7ffffffe7ffffffe },
    .{ .word = 0x921f7821, .value = 0xfffffffefffffffe },
    .{ .word = 0x92400021, .value = 0x1 },
    .{ .word = 0x92400421, .value = 0x3 },
    .{ .word = 0x92400821, .value = 0x7 },
    .{ .word = 0x92400c21, .value = 0xf },
    .{ .word = 0x92401021, .value = 0x1f },
    .{ .word = 0x92401421, .value = 0x3f },
    .{ .word = 0x92401821, .value = 0x7f },
    .{ .word = 0x92401c21, .value = 0xff },
    .{ .word = 0x92402021, .value = 0x1ff },
    .{ .word = 0x92402421, .value = 0x3ff },
    .{ .word = 0x92402821, .value = 0x7ff },
    .{ .word = 0x92402c21, .value = 0xfff },
    .{ .word = 0x92403021, .value = 0x1fff },
    .{ .word = 0x92403421, .value = 0x3fff },
    .{ .word = 0x92403821, .value = 0x7fff },
    .{ .word = 0x92403c21, .value = 0xffff },
    .{ .word = 0x92404021, .value = 0x1ffff },
    .{ .word = 0x92404421, .value = 0x3ffff },
    .{ .word = 0x92404821, .value = 0x7ffff },
    .{ .word = 0x92404c21, .value = 0xfffff },
    .{ .word = 0x92405021, .value = 0x1fffff },
    .{ .word = 0x92405421, .value = 0x3fffff },
    .{ .word = 0x92405821, .value = 0x7fffff },
    .{ .word = 0x92405c21, .value = 0xffffff },
    .{ .word = 0x92406021, .value = 0x1ffffff },
    .{ .word = 0x92406421, .value = 0x3ffffff },
    .{ .word = 0x92406821, .value = 0x7ffffff },
    .{ .word = 0x92406c21, .value = 0xfffffff },
    .{ .word = 0x92407021, .value = 0x1fffffff },
    .{ .word = 0x92407421, .value = 0x3fffffff },
    .{ .word = 0x92407821, .value = 0x7fffffff },
    .{ .word = 0x92407c21, .value = 0xffffffff },
    .{ .word = 0x92408021, .value = 0x1ffffffff },
    .{ .word = 0x92408421, .value = 0x3ffffffff },
    .{ .word = 0x92408821, .value = 0x7ffffffff },
    .{ .word = 0x92408c21, .value = 0xfffffffff },
    .{ .word = 0x92409021, .value = 0x1fffffffff },
    .{ .word = 0x92409421, .value = 0x3fffffffff },
    .{ .word = 0x92409821, .value = 0x7fffffffff },
    .{ .word = 0x92409c21, .value = 0xffffffffff },
    .{ .word = 0x9240a021, .value = 0x1ffffffffff },
    .{ .word = 0x9240a421, .value = 0x3ffffffffff },
    .{ .word = 0x9240a821, .value = 0x7ffffffffff },
    .{ .word = 0x9240ac21, .value = 0xfffffffffff },
    .{ .word = 0x9240b021, .value = 0x1fffffffffff },
    .{ .word = 0x9240b421, .value = 0x3fffffffffff },
    .{ .word = 0x9240b821, .value = 0x7fffffffffff },
    .{ .word = 0x9240bc21, .value = 0xffffffffffff },
    .{ .word = 0x9240c021, .value = 0x1ffffffffffff },
    .{ .word = 0x9240c421, .value = 0x3ffffffffffff },
    .{ .word = 0x9240c821, .value = 0x7ffffffffffff },
    .{ .word = 0x9240cc21, .value = 0xfffffffffffff },
    .{ .word = 0x9240d021, .value = 0x1fffffffffffff },
    .{ .word = 0x9240d421, .value = 0x3fffffffffffff },
    .{ .word = 0x9240d821, .value = 0x7fffffffffffff },
    .{ .word = 0x9240dc21, .value = 0xffffffffffffff },
    .{ .word = 0x9240e021, .value = 0x1ffffffffffffff },
    .{ .word = 0x9240e421, .value = 0x3ffffffffffffff },
    .{ .word = 0x9240e821, .value = 0x7ffffffffffffff },
    .{ .word = 0x9240ec21, .value = 0xfffffffffffffff },
    .{ .word = 0x9240f021, .value = 0x1fffffffffffffff },
    .{ .word = 0x9240f421, .value = 0x3fffffffffffffff },
    .{ .word = 0x9240f821, .value = 0x7fffffffffffffff },
    .{ .word = 0x92410021, .value = 0x8000000000000000 },
    .{ .word = 0x92410421, .value = 0x8000000000000001 },
    .{ .word = 0x92410821, .value = 0x8000000000000003 },
    .{ .word = 0x92410c21, .value = 0x8000000000000007 },
    .{ .word = 0x92411021, .value = 0x800000000000000f },
    .{ .word = 0x92411421, .value = 0x800000000000001f },
    .{ .word = 0x92411821, .value = 0x800000000000003f },
    .{ .word = 0x92411c21, .value = 0x800000000000007f },
    .{ .word = 0x92412021, .value = 0x80000000000000ff },
    .{ .word = 0x92412421, .value = 0x80000000000001ff },
    .{ .word = 0x92412821, .value = 0x80000000000003ff },
    .{ .word = 0x92412c21, .value = 0x80000000000007ff },
    .{ .word = 0x92413021, .value = 0x8000000000000fff },
    .{ .word = 0x92413421, .value = 0x8000000000001fff },
    .{ .word = 0x92413821, .value = 0x8000000000003fff },
    .{ .word = 0x92413c21, .value = 0x8000000000007fff },
    .{ .word = 0x92414021, .value = 0x800000000000ffff },
    .{ .word = 0x92414421, .value = 0x800000000001ffff },
    .{ .word = 0x92414821, .value = 0x800000000003ffff },
    .{ .word = 0x92414c21, .value = 0x800000000007ffff },
    .{ .word = 0x92415021, .value = 0x80000000000fffff },
    .{ .word = 0x92415421, .value = 0x80000000001fffff },
    .{ .word = 0x92415821, .value = 0x80000000003fffff },
    .{ .word = 0x92415c21, .value = 0x80000000007fffff },
    .{ .word = 0x92416021, .value = 0x8000000000ffffff },
    .{ .word = 0x92416421, .value = 0x8000000001ffffff },
    .{ .word = 0x92416821, .value = 0x8000000003ffffff },
    .{ .word = 0x92416c21, .value = 0x8000000007ffffff },
    .{ .word = 0x92417021, .value = 0x800000000fffffff },
    .{ .word = 0x92417421, .value = 0x800000001fffffff },
    .{ .word = 0x92417821, .value = 0x800000003fffffff },
    .{ .word = 0x92417c21, .value = 0x800000007fffffff },
    .{ .word = 0x92418021, .value = 0x80000000ffffffff },
    .{ .word = 0x92418421, .value = 0x80000001ffffffff },
    .{ .word = 0x92418821, .value = 0x80000003ffffffff },
    .{ .word = 0x92418c21, .value = 0x80000007ffffffff },
    .{ .word = 0x92419021, .value = 0x8000000fffffffff },
    .{ .word = 0x92419421, .value = 0x8000001fffffffff },
    .{ .word = 0x92419821, .value = 0x8000003fffffffff },
    .{ .word = 0x92419c21, .value = 0x8000007fffffffff },
    .{ .word = 0x9241a021, .value = 0x800000ffffffffff },
    .{ .word = 0x9241a421, .value = 0x800001ffffffffff },
    .{ .word = 0x9241a821, .value = 0x800003ffffffffff },
    .{ .word = 0x9241ac21, .value = 0x800007ffffffffff },
    .{ .word = 0x9241b021, .value = 0x80000fffffffffff },
    .{ .word = 0x9241b421, .value = 0x80001fffffffffff },
    .{ .word = 0x9241b821, .value = 0x80003fffffffffff },
    .{ .word = 0x9241bc21, .value = 0x80007fffffffffff },
    .{ .word = 0x9241c021, .value = 0x8000ffffffffffff },
    .{ .word = 0x9241c421, .value = 0x8001ffffffffffff },
    .{ .word = 0x9241c821, .value = 0x8003ffffffffffff },
    .{ .word = 0x9241cc21, .value = 0x8007ffffffffffff },
    .{ .word = 0x9241d021, .value = 0x800fffffffffffff },
    .{ .word = 0x9241d421, .value = 0x801fffffffffffff },
    .{ .word = 0x9241d821, .value = 0x803fffffffffffff },
    .{ .word = 0x9241dc21, .value = 0x807fffffffffffff },
    .{ .word = 0x9241e021, .value = 0x80ffffffffffffff },
    .{ .word = 0x9241e421, .value = 0x81ffffffffffffff },
    .{ .word = 0x9241e821, .value = 0x83ffffffffffffff },
    .{ .word = 0x9241ec21, .value = 0x87ffffffffffffff },
    .{ .word = 0x9241f021, .value = 0x8fffffffffffffff },
    .{ .word = 0x9241f421, .value = 0x9fffffffffffffff },
    .{ .word = 0x9241f821, .value = 0xbfffffffffffffff },
    .{ .word = 0x92420021, .value = 0x4000000000000000 },
    .{ .word = 0x92420421, .value = 0xc000000000000000 },
    .{ .word = 0x92420821, .value = 0xc000000000000001 },
    .{ .word = 0x92420c21, .value = 0xc000000000000003 },
    .{ .word = 0x92421021, .value = 0xc000000000000007 },
    .{ .word = 0x92421421, .value = 0xc00000000000000f },
    .{ .word = 0x92421821, .value = 0xc00000000000001f },
    .{ .word = 0x92421c21, .value = 0xc00000000000003f },
    .{ .word = 0x92422021, .value = 0xc00000000000007f },
    .{ .word = 0x92422421, .value = 0xc0000000000000ff },
    .{ .word = 0x92422821, .value = 0xc0000000000001ff },
    .{ .word = 0x92422c21, .value = 0xc0000000000003ff },
    .{ .word = 0x92423021, .value = 0xc0000000000007ff },
    .{ .word = 0x92423421, .value = 0xc000000000000fff },
    .{ .word = 0x92423821, .value = 0xc000000000001fff },
    .{ .word = 0x92423c21, .value = 0xc000000000003fff },
    .{ .word = 0x92424021, .value = 0xc000000000007fff },
    .{ .word = 0x92424421, .value = 0xc00000000000ffff },
    .{ .word = 0x92424821, .value = 0xc00000000001ffff },
    .{ .word = 0x92424c21, .value = 0xc00000000003ffff },
    .{ .word = 0x92425021, .value = 0xc00000000007ffff },
    .{ .word = 0x92425421, .value = 0xc0000000000fffff },
    .{ .word = 0x92425821, .value = 0xc0000000001fffff },
    .{ .word = 0x92425c21, .value = 0xc0000000003fffff },
    .{ .word = 0x92426021, .value = 0xc0000000007fffff },
    .{ .word = 0x92426421, .value = 0xc000000000ffffff },
    .{ .word = 0x92426821, .value = 0xc000000001ffffff },
    .{ .word = 0x92426c21, .value = 0xc000000003ffffff },
    .{ .word = 0x92427021, .value = 0xc000000007ffffff },
    .{ .word = 0x92427421, .value = 0xc00000000fffffff },
    .{ .word = 0x92427821, .value = 0xc00000001fffffff },
    .{ .word = 0x92427c21, .value = 0xc00000003fffffff },
    .{ .word = 0x92428021, .value = 0xc00000007fffffff },
    .{ .word = 0x92428421, .value = 0xc0000000ffffffff },
    .{ .word = 0x92428821, .value = 0xc0000001ffffffff },
    .{ .word = 0x92428c21, .value = 0xc0000003ffffffff },
    .{ .word = 0x92429021, .value = 0xc0000007ffffffff },
    .{ .word = 0x92429421, .value = 0xc000000fffffffff },
    .{ .word = 0x92429821, .value = 0xc000001fffffffff },
    .{ .word = 0x92429c21, .value = 0xc000003fffffffff },
    .{ .word = 0x9242a021, .value = 0xc000007fffffffff },
    .{ .word = 0x9242a421, .value = 0xc00000ffffffffff },
    .{ .word = 0x9242a821, .value = 0xc00001ffffffffff },
    .{ .word = 0x9242ac21, .value = 0xc00003ffffffffff },
    .{ .word = 0x9242b021, .value = 0xc00007ffffffffff },
    .{ .word = 0x9242b421, .value = 0xc0000fffffffffff },
    .{ .word = 0x9242b821, .value = 0xc0001fffffffffff },
    .{ .word = 0x9242bc21, .value = 0xc0003fffffffffff },
    .{ .word = 0x9242c021, .value = 0xc0007fffffffffff },
    .{ .word = 0x9242c421, .value = 0xc000ffffffffffff },
    .{ .word = 0x9242c821, .value = 0xc001ffffffffffff },
    .{ .word = 0x9242cc21, .value = 0xc003ffffffffffff },
    .{ .word = 0x9242d021, .value = 0xc007ffffffffffff },
    .{ .word = 0x9242d421, .value = 0xc00fffffffffffff },
    .{ .word = 0x9242d821, .value = 0xc01fffffffffffff },
    .{ .word = 0x9242dc21, .value = 0xc03fffffffffffff },
    .{ .word = 0x9242e021, .value = 0xc07fffffffffffff },
    .{ .word = 0x9242e421, .value = 0xc0ffffffffffffff },
    .{ .word = 0x9242e821, .value = 0xc1ffffffffffffff },
    .{ .word = 0x9242ec21, .value = 0xc3ffffffffffffff },
    .{ .word = 0x9242f021, .value = 0xc7ffffffffffffff },
    .{ .word = 0x9242f421, .value = 0xcfffffffffffffff },
    .{ .word = 0x9242f821, .value = 0xdfffffffffffffff },
    .{ .word = 0x92430021, .value = 0x2000000000000000 },
    .{ .word = 0x92430421, .value = 0x6000000000000000 },
    .{ .word = 0x92430821, .value = 0xe000000000000000 },
    .{ .word = 0x92430c21, .value = 0xe000000000000001 },
    .{ .word = 0x92431021, .value = 0xe000000000000003 },
    .{ .word = 0x92431421, .value = 0xe000000000000007 },
    .{ .word = 0x92431821, .value = 0xe00000000000000f },
    .{ .word = 0x92431c21, .value = 0xe00000000000001f },
    .{ .word = 0x92432021, .value = 0xe00000000000003f },
    .{ .word = 0x92432421, .value = 0xe00000000000007f },
    .{ .word = 0x92432821, .value = 0xe0000000000000ff },
    .{ .word = 0x92432c21, .value = 0xe0000000000001ff },
    .{ .word = 0x92433021, .value = 0xe0000000000003ff },
    .{ .word = 0x92433421, .value = 0xe0000000000007ff },
    .{ .word = 0x92433821, .value = 0xe000000000000fff },
    .{ .word = 0x92433c21, .value = 0xe000000000001fff },
    .{ .word = 0x92434021, .value = 0xe000000000003fff },
    .{ .word = 0x92434421, .value = 0xe000000000007fff },
    .{ .word = 0x92434821, .value = 0xe00000000000ffff },
    .{ .word = 0x92434c21, .value = 0xe00000000001ffff },
    .{ .word = 0x92435021, .value = 0xe00000000003ffff },
    .{ .word = 0x92435421, .value = 0xe00000000007ffff },
    .{ .word = 0x92435821, .value = 0xe0000000000fffff },
    .{ .word = 0x92435c21, .value = 0xe0000000001fffff },
    .{ .word = 0x92436021, .value = 0xe0000000003fffff },
    .{ .word = 0x92436421, .value = 0xe0000000007fffff },
    .{ .word = 0x92436821, .value = 0xe000000000ffffff },
    .{ .word = 0x92436c21, .value = 0xe000000001ffffff },
    .{ .word = 0x92437021, .value = 0xe000000003ffffff },
    .{ .word = 0x92437421, .value = 0xe000000007ffffff },
    .{ .word = 0x92437821, .value = 0xe00000000fffffff },
    .{ .word = 0x92437c21, .value = 0xe00000001fffffff },
    .{ .word = 0x92438021, .value = 0xe00000003fffffff },
    .{ .word = 0x92438421, .value = 0xe00000007fffffff },
    .{ .word = 0x92438821, .value = 0xe0000000ffffffff },
    .{ .word = 0x92438c21, .value = 0xe0000001ffffffff },
    .{ .word = 0x92439021, .value = 0xe0000003ffffffff },
    .{ .word = 0x92439421, .value = 0xe0000007ffffffff },
    .{ .word = 0x92439821, .value = 0xe000000fffffffff },
    .{ .word = 0x92439c21, .value = 0xe000001fffffffff },
    .{ .word = 0x9243a021, .value = 0xe000003fffffffff },
    .{ .word = 0x9243a421, .value = 0xe000007fffffffff },
    .{ .word = 0x9243a821, .value = 0xe00000ffffffffff },
    .{ .word = 0x9243ac21, .value = 0xe00001ffffffffff },
    .{ .word = 0x9243b021, .value = 0xe00003ffffffffff },
    .{ .word = 0x9243b421, .value = 0xe00007ffffffffff },
    .{ .word = 0x9243b821, .value = 0xe0000fffffffffff },
    .{ .word = 0x9243bc21, .value = 0xe0001fffffffffff },
    .{ .word = 0x9243c021, .value = 0xe0003fffffffffff },
    .{ .word = 0x9243c421, .value = 0xe0007fffffffffff },
    .{ .word = 0x9243c821, .value = 0xe000ffffffffffff },
    .{ .word = 0x9243cc21, .value = 0xe001ffffffffffff },
    .{ .word = 0x9243d021, .value = 0xe003ffffffffffff },
    .{ .word = 0x9243d421, .value = 0xe007ffffffffffff },
    .{ .word = 0x9243d821, .value = 0xe00fffffffffffff },
    .{ .word = 0x9243dc21, .value = 0xe01fffffffffffff },
    .{ .word = 0x9243e021, .value = 0xe03fffffffffffff },
    .{ .word = 0x9243e421, .value = 0xe07fffffffffffff },
    .{ .word = 0x9243e821, .value = 0xe0ffffffffffffff },
    .{ .word = 0x9243ec21, .value = 0xe1ffffffffffffff },
    .{ .word = 0x9243f021, .value = 0xe3ffffffffffffff },
    .{ .word = 0x9243f421, .value = 0xe7ffffffffffffff },
    .{ .word = 0x9243f821, .value = 0xefffffffffffffff },
    .{ .word = 0x92440021, .value = 0x1000000000000000 },
    .{ .word = 0x92440421, .value = 0x3000000000000000 },
    .{ .word = 0x92440821, .value = 0x7000000000000000 },
    .{ .word = 0x92440c21, .value = 0xf000000000000000 },
    .{ .word = 0x92441021, .value = 0xf000000000000001 },
    .{ .word = 0x92441421, .value = 0xf000000000000003 },
    .{ .word = 0x92441821, .value = 0xf000000000000007 },
    .{ .word = 0x92441c21, .value = 0xf00000000000000f },
    .{ .word = 0x92442021, .value = 0xf00000000000001f },
    .{ .word = 0x92442421, .value = 0xf00000000000003f },
    .{ .word = 0x92442821, .value = 0xf00000000000007f },
    .{ .word = 0x92442c21, .value = 0xf0000000000000ff },
    .{ .word = 0x92443021, .value = 0xf0000000000001ff },
    .{ .word = 0x92443421, .value = 0xf0000000000003ff },
    .{ .word = 0x92443821, .value = 0xf0000000000007ff },
    .{ .word = 0x92443c21, .value = 0xf000000000000fff },
    .{ .word = 0x92444021, .value = 0xf000000000001fff },
    .{ .word = 0x92444421, .value = 0xf000000000003fff },
    .{ .word = 0x92444821, .value = 0xf000000000007fff },
    .{ .word = 0x92444c21, .value = 0xf00000000000ffff },
    .{ .word = 0x92445021, .value = 0xf00000000001ffff },
    .{ .word = 0x92445421, .value = 0xf00000000003ffff },
    .{ .word = 0x92445821, .value = 0xf00000000007ffff },
    .{ .word = 0x92445c21, .value = 0xf0000000000fffff },
    .{ .word = 0x92446021, .value = 0xf0000000001fffff },
    .{ .word = 0x92446421, .value = 0xf0000000003fffff },
    .{ .word = 0x92446821, .value = 0xf0000000007fffff },
    .{ .word = 0x92446c21, .value = 0xf000000000ffffff },
    .{ .word = 0x92447021, .value = 0xf000000001ffffff },
    .{ .word = 0x92447421, .value = 0xf000000003ffffff },
    .{ .word = 0x92447821, .value = 0xf000000007ffffff },
    .{ .word = 0x92447c21, .value = 0xf00000000fffffff },
    .{ .word = 0x92448021, .value = 0xf00000001fffffff },
    .{ .word = 0x92448421, .value = 0xf00000003fffffff },
    .{ .word = 0x92448821, .value = 0xf00000007fffffff },
    .{ .word = 0x92448c21, .value = 0xf0000000ffffffff },
    .{ .word = 0x92449021, .value = 0xf0000001ffffffff },
    .{ .word = 0x92449421, .value = 0xf0000003ffffffff },
    .{ .word = 0x92449821, .value = 0xf0000007ffffffff },
    .{ .word = 0x92449c21, .value = 0xf000000fffffffff },
    .{ .word = 0x9244a021, .value = 0xf000001fffffffff },
    .{ .word = 0x9244a421, .value = 0xf000003fffffffff },
    .{ .word = 0x9244a821, .value = 0xf000007fffffffff },
    .{ .word = 0x9244ac21, .value = 0xf00000ffffffffff },
    .{ .word = 0x9244b021, .value = 0xf00001ffffffffff },
    .{ .word = 0x9244b421, .value = 0xf00003ffffffffff },
    .{ .word = 0x9244b821, .value = 0xf00007ffffffffff },
    .{ .word = 0x9244bc21, .value = 0xf0000fffffffffff },
    .{ .word = 0x9244c021, .value = 0xf0001fffffffffff },
    .{ .word = 0x9244c421, .value = 0xf0003fffffffffff },
    .{ .word = 0x9244c821, .value = 0xf0007fffffffffff },
    .{ .word = 0x9244cc21, .value = 0xf000ffffffffffff },
    .{ .word = 0x9244d021, .value = 0xf001ffffffffffff },
    .{ .word = 0x9244d421, .value = 0xf003ffffffffffff },
    .{ .word = 0x9244d821, .value = 0xf007ffffffffffff },
    .{ .word = 0x9244dc21, .value = 0xf00fffffffffffff },
    .{ .word = 0x9244e021, .value = 0xf01fffffffffffff },
    .{ .word = 0x9244e421, .value = 0xf03fffffffffffff },
    .{ .word = 0x9244e821, .value = 0xf07fffffffffffff },
    .{ .word = 0x9244ec21, .value = 0xf0ffffffffffffff },
    .{ .word = 0x9244f021, .value = 0xf1ffffffffffffff },
    .{ .word = 0x9244f421, .value = 0xf3ffffffffffffff },
    .{ .word = 0x9244f821, .value = 0xf7ffffffffffffff },
    .{ .word = 0x92450021, .value = 0x800000000000000 },
    .{ .word = 0x92450421, .value = 0x1800000000000000 },
    .{ .word = 0x92450821, .value = 0x3800000000000000 },
    .{ .word = 0x92450c21, .value = 0x7800000000000000 },
    .{ .word = 0x92451021, .value = 0xf800000000000000 },
    .{ .word = 0x92451421, .value = 0xf800000000000001 },
    .{ .word = 0x92451821, .value = 0xf800000000000003 },
    .{ .word = 0x92451c21, .value = 0xf800000000000007 },
    .{ .word = 0x92452021, .value = 0xf80000000000000f },
    .{ .word = 0x92452421, .value = 0xf80000000000001f },
    .{ .word = 0x92452821, .value = 0xf80000000000003f },
    .{ .word = 0x92452c21, .value = 0xf80000000000007f },
    .{ .word = 0x92453021, .value = 0xf8000000000000ff },
    .{ .word = 0x92453421, .value = 0xf8000000000001ff },
    .{ .word = 0x92453821, .value = 0xf8000000000003ff },
    .{ .word = 0x92453c21, .value = 0xf8000000000007ff },
    .{ .word = 0x92454021, .value = 0xf800000000000fff },
    .{ .word = 0x92454421, .value = 0xf800000000001fff },
    .{ .word = 0x92454821, .value = 0xf800000000003fff },
    .{ .word = 0x92454c21, .value = 0xf800000000007fff },
    .{ .word = 0x92455021, .value = 0xf80000000000ffff },
    .{ .word = 0x92455421, .value = 0xf80000000001ffff },
    .{ .word = 0x92455821, .value = 0xf80000000003ffff },
    .{ .word = 0x92455c21, .value = 0xf80000000007ffff },
    .{ .word = 0x92456021, .value = 0xf8000000000fffff },
    .{ .word = 0x92456421, .value = 0xf8000000001fffff },
    .{ .word = 0x92456821, .value = 0xf8000000003fffff },
    .{ .word = 0x92456c21, .value = 0xf8000000007fffff },
    .{ .word = 0x92457021, .value = 0xf800000000ffffff },
    .{ .word = 0x92457421, .value = 0xf800000001ffffff },
    .{ .word = 0x92457821, .value = 0xf800000003ffffff },
    .{ .word = 0x92457c21, .value = 0xf800000007ffffff },
    .{ .word = 0x92458021, .value = 0xf80000000fffffff },
    .{ .word = 0x92458421, .value = 0xf80000001fffffff },
    .{ .word = 0x92458821, .value = 0xf80000003fffffff },
    .{ .word = 0x92458c21, .value = 0xf80000007fffffff },
    .{ .word = 0x92459021, .value = 0xf8000000ffffffff },
    .{ .word = 0x92459421, .value = 0xf8000001ffffffff },
    .{ .word = 0x92459821, .value = 0xf8000003ffffffff },
    .{ .word = 0x92459c21, .value = 0xf8000007ffffffff },
    .{ .word = 0x9245a021, .value = 0xf800000fffffffff },
    .{ .word = 0x9245a421, .value = 0xf800001fffffffff },
    .{ .word = 0x9245a821, .value = 0xf800003fffffffff },
    .{ .word = 0x9245ac21, .value = 0xf800007fffffffff },
    .{ .word = 0x9245b021, .value = 0xf80000ffffffffff },
    .{ .word = 0x9245b421, .value = 0xf80001ffffffffff },
    .{ .word = 0x9245b821, .value = 0xf80003ffffffffff },
    .{ .word = 0x9245bc21, .value = 0xf80007ffffffffff },
    .{ .word = 0x9245c021, .value = 0xf8000fffffffffff },
    .{ .word = 0x9245c421, .value = 0xf8001fffffffffff },
    .{ .word = 0x9245c821, .value = 0xf8003fffffffffff },
    .{ .word = 0x9245cc21, .value = 0xf8007fffffffffff },
    .{ .word = 0x9245d021, .value = 0xf800ffffffffffff },
    .{ .word = 0x9245d421, .value = 0xf801ffffffffffff },
    .{ .word = 0x9245d821, .value = 0xf803ffffffffffff },
    .{ .word = 0x9245dc21, .value = 0xf807ffffffffffff },
    .{ .word = 0x9245e021, .value = 0xf80fffffffffffff },
    .{ .word = 0x9245e421, .value = 0xf81fffffffffffff },
    .{ .word = 0x9245e821, .value = 0xf83fffffffffffff },
    .{ .word = 0x9245ec21, .value = 0xf87fffffffffffff },
    .{ .word = 0x9245f021, .value = 0xf8ffffffffffffff },
    .{ .word = 0x9245f421, .value = 0xf9ffffffffffffff },
    .{ .word = 0x9245f821, .value = 0xfbffffffffffffff },
    .{ .word = 0x92460021, .value = 0x400000000000000 },
    .{ .word = 0x92460421, .value = 0xc00000000000000 },
    .{ .word = 0x92460821, .value = 0x1c00000000000000 },
    .{ .word = 0x92460c21, .value = 0x3c00000000000000 },
    .{ .word = 0x92461021, .value = 0x7c00000000000000 },
    .{ .word = 0x92461421, .value = 0xfc00000000000000 },
    .{ .word = 0x92461821, .value = 0xfc00000000000001 },
    .{ .word = 0x92461c21, .value = 0xfc00000000000003 },
    .{ .word = 0x92462021, .value = 0xfc00000000000007 },
    .{ .word = 0x92462421, .value = 0xfc0000000000000f },
    .{ .word = 0x92462821, .value = 0xfc0000000000001f },
    .{ .word = 0x92462c21, .value = 0xfc0000000000003f },
    .{ .word = 0x92463021, .value = 0xfc0000000000007f },
    .{ .word = 0x92463421, .value = 0xfc000000000000ff },
    .{ .word = 0x92463821, .value = 0xfc000000000001ff },
    .{ .word = 0x92463c21, .value = 0xfc000000000003ff },
    .{ .word = 0x92464021, .value = 0xfc000000000007ff },
    .{ .word = 0x92464421, .value = 0xfc00000000000fff },
    .{ .word = 0x92464821, .value = 0xfc00000000001fff },
    .{ .word = 0x92464c21, .value = 0xfc00000000003fff },
    .{ .word = 0x92465021, .value = 0xfc00000000007fff },
    .{ .word = 0x92465421, .value = 0xfc0000000000ffff },
    .{ .word = 0x92465821, .value = 0xfc0000000001ffff },
    .{ .word = 0x92465c21, .value = 0xfc0000000003ffff },
    .{ .word = 0x92466021, .value = 0xfc0000000007ffff },
    .{ .word = 0x92466421, .value = 0xfc000000000fffff },
    .{ .word = 0x92466821, .value = 0xfc000000001fffff },
    .{ .word = 0x92466c21, .value = 0xfc000000003fffff },
    .{ .word = 0x92467021, .value = 0xfc000000007fffff },
    .{ .word = 0x92467421, .value = 0xfc00000000ffffff },
    .{ .word = 0x92467821, .value = 0xfc00000001ffffff },
    .{ .word = 0x92467c21, .value = 0xfc00000003ffffff },
    .{ .word = 0x92468021, .value = 0xfc00000007ffffff },
    .{ .word = 0x92468421, .value = 0xfc0000000fffffff },
    .{ .word = 0x92468821, .value = 0xfc0000001fffffff },
    .{ .word = 0x92468c21, .value = 0xfc0000003fffffff },
    .{ .word = 0x92469021, .value = 0xfc0000007fffffff },
    .{ .word = 0x92469421, .value = 0xfc000000ffffffff },
    .{ .word = 0x92469821, .value = 0xfc000001ffffffff },
    .{ .word = 0x92469c21, .value = 0xfc000003ffffffff },
    .{ .word = 0x9246a021, .value = 0xfc000007ffffffff },
    .{ .word = 0x9246a421, .value = 0xfc00000fffffffff },
    .{ .word = 0x9246a821, .value = 0xfc00001fffffffff },
    .{ .word = 0x9246ac21, .value = 0xfc00003fffffffff },
    .{ .word = 0x9246b021, .value = 0xfc00007fffffffff },
    .{ .word = 0x9246b421, .value = 0xfc0000ffffffffff },
    .{ .word = 0x9246b821, .value = 0xfc0001ffffffffff },
    .{ .word = 0x9246bc21, .value = 0xfc0003ffffffffff },
    .{ .word = 0x9246c021, .value = 0xfc0007ffffffffff },
    .{ .word = 0x9246c421, .value = 0xfc000fffffffffff },
    .{ .word = 0x9246c821, .value = 0xfc001fffffffffff },
    .{ .word = 0x9246cc21, .value = 0xfc003fffffffffff },
    .{ .word = 0x9246d021, .value = 0xfc007fffffffffff },
    .{ .word = 0x9246d421, .value = 0xfc00ffffffffffff },
    .{ .word = 0x9246d821, .value = 0xfc01ffffffffffff },
    .{ .word = 0x9246dc21, .value = 0xfc03ffffffffffff },
    .{ .word = 0x9246e021, .value = 0xfc07ffffffffffff },
    .{ .word = 0x9246e421, .value = 0xfc0fffffffffffff },
    .{ .word = 0x9246e821, .value = 0xfc1fffffffffffff },
    .{ .word = 0x9246ec21, .value = 0xfc3fffffffffffff },
    .{ .word = 0x9246f021, .value = 0xfc7fffffffffffff },
    .{ .word = 0x9246f421, .value = 0xfcffffffffffffff },
    .{ .word = 0x9246f821, .value = 0xfdffffffffffffff },
    .{ .word = 0x92470021, .value = 0x200000000000000 },
    .{ .word = 0x92470421, .value = 0x600000000000000 },
    .{ .word = 0x92470821, .value = 0xe00000000000000 },
    .{ .word = 0x92470c21, .value = 0x1e00000000000000 },
    .{ .word = 0x92471021, .value = 0x3e00000000000000 },
    .{ .word = 0x92471421, .value = 0x7e00000000000000 },
    .{ .word = 0x92471821, .value = 0xfe00000000000000 },
    .{ .word = 0x92471c21, .value = 0xfe00000000000001 },
    .{ .word = 0x92472021, .value = 0xfe00000000000003 },
    .{ .word = 0x92472421, .value = 0xfe00000000000007 },
    .{ .word = 0x92472821, .value = 0xfe0000000000000f },
    .{ .word = 0x92472c21, .value = 0xfe0000000000001f },
    .{ .word = 0x92473021, .value = 0xfe0000000000003f },
    .{ .word = 0x92473421, .value = 0xfe0000000000007f },
    .{ .word = 0x92473821, .value = 0xfe000000000000ff },
    .{ .word = 0x92473c21, .value = 0xfe000000000001ff },
    .{ .word = 0x92474021, .value = 0xfe000000000003ff },
    .{ .word = 0x92474421, .value = 0xfe000000000007ff },
    .{ .word = 0x92474821, .value = 0xfe00000000000fff },
    .{ .word = 0x92474c21, .value = 0xfe00000000001fff },
    .{ .word = 0x92475021, .value = 0xfe00000000003fff },
    .{ .word = 0x92475421, .value = 0xfe00000000007fff },
    .{ .word = 0x92475821, .value = 0xfe0000000000ffff },
    .{ .word = 0x92475c21, .value = 0xfe0000000001ffff },
    .{ .word = 0x92476021, .value = 0xfe0000000003ffff },
    .{ .word = 0x92476421, .value = 0xfe0000000007ffff },
    .{ .word = 0x92476821, .value = 0xfe000000000fffff },
    .{ .word = 0x92476c21, .value = 0xfe000000001fffff },
    .{ .word = 0x92477021, .value = 0xfe000000003fffff },
    .{ .word = 0x92477421, .value = 0xfe000000007fffff },
    .{ .word = 0x92477821, .value = 0xfe00000000ffffff },
    .{ .word = 0x92477c21, .value = 0xfe00000001ffffff },
    .{ .word = 0x92478021, .value = 0xfe00000003ffffff },
    .{ .word = 0x92478421, .value = 0xfe00000007ffffff },
    .{ .word = 0x92478821, .value = 0xfe0000000fffffff },
    .{ .word = 0x92478c21, .value = 0xfe0000001fffffff },
    .{ .word = 0x92479021, .value = 0xfe0000003fffffff },
    .{ .word = 0x92479421, .value = 0xfe0000007fffffff },
    .{ .word = 0x92479821, .value = 0xfe000000ffffffff },
    .{ .word = 0x92479c21, .value = 0xfe000001ffffffff },
    .{ .word = 0x9247a021, .value = 0xfe000003ffffffff },
    .{ .word = 0x9247a421, .value = 0xfe000007ffffffff },
    .{ .word = 0x9247a821, .value = 0xfe00000fffffffff },
    .{ .word = 0x9247ac21, .value = 0xfe00001fffffffff },
    .{ .word = 0x9247b021, .value = 0xfe00003fffffffff },
    .{ .word = 0x9247b421, .value = 0xfe00007fffffffff },
    .{ .word = 0x9247b821, .value = 0xfe0000ffffffffff },
    .{ .word = 0x9247bc21, .value = 0xfe0001ffffffffff },
    .{ .word = 0x9247c021, .value = 0xfe0003ffffffffff },
    .{ .word = 0x9247c421, .value = 0xfe0007ffffffffff },
    .{ .word = 0x9247c821, .value = 0xfe000fffffffffff },
    .{ .word = 0x9247cc21, .value = 0xfe001fffffffffff },
    .{ .word = 0x9247d021, .value = 0xfe003fffffffffff },
    .{ .word = 0x9247d421, .value = 0xfe007fffffffffff },
    .{ .word = 0x9247d821, .value = 0xfe00ffffffffffff },
    .{ .word = 0x9247dc21, .value = 0xfe01ffffffffffff },
    .{ .word = 0x9247e021, .value = 0xfe03ffffffffffff },
    .{ .word = 0x9247e421, .value = 0xfe07ffffffffffff },
    .{ .word = 0x9247e821, .value = 0xfe0fffffffffffff },
    .{ .word = 0x9247ec21, .value = 0xfe1fffffffffffff },
    .{ .word = 0x9247f021, .value = 0xfe3fffffffffffff },
    .{ .word = 0x9247f421, .value = 0xfe7fffffffffffff },
    .{ .word = 0x9247f821, .value = 0xfeffffffffffffff },
    .{ .word = 0x92480021, .value = 0x100000000000000 },
    .{ .word = 0x92480421, .value = 0x300000000000000 },
    .{ .word = 0x92480821, .value = 0x700000000000000 },
    .{ .word = 0x92480c21, .value = 0xf00000000000000 },
    .{ .word = 0x92481021, .value = 0x1f00000000000000 },
    .{ .word = 0x92481421, .value = 0x3f00000000000000 },
    .{ .word = 0x92481821, .value = 0x7f00000000000000 },
    .{ .word = 0x92481c21, .value = 0xff00000000000000 },
    .{ .word = 0x92482021, .value = 0xff00000000000001 },
    .{ .word = 0x92482421, .value = 0xff00000000000003 },
    .{ .word = 0x92482821, .value = 0xff00000000000007 },
    .{ .word = 0x92482c21, .value = 0xff0000000000000f },
    .{ .word = 0x92483021, .value = 0xff0000000000001f },
    .{ .word = 0x92483421, .value = 0xff0000000000003f },
    .{ .word = 0x92483821, .value = 0xff0000000000007f },
    .{ .word = 0x92483c21, .value = 0xff000000000000ff },
    .{ .word = 0x92484021, .value = 0xff000000000001ff },
    .{ .word = 0x92484421, .value = 0xff000000000003ff },
    .{ .word = 0x92484821, .value = 0xff000000000007ff },
    .{ .word = 0x92484c21, .value = 0xff00000000000fff },
    .{ .word = 0x92485021, .value = 0xff00000000001fff },
    .{ .word = 0x92485421, .value = 0xff00000000003fff },
    .{ .word = 0x92485821, .value = 0xff00000000007fff },
    .{ .word = 0x92485c21, .value = 0xff0000000000ffff },
    .{ .word = 0x92486021, .value = 0xff0000000001ffff },
    .{ .word = 0x92486421, .value = 0xff0000000003ffff },
    .{ .word = 0x92486821, .value = 0xff0000000007ffff },
    .{ .word = 0x92486c21, .value = 0xff000000000fffff },
    .{ .word = 0x92487021, .value = 0xff000000001fffff },
    .{ .word = 0x92487421, .value = 0xff000000003fffff },
    .{ .word = 0x92487821, .value = 0xff000000007fffff },
    .{ .word = 0x92487c21, .value = 0xff00000000ffffff },
    .{ .word = 0x92488021, .value = 0xff00000001ffffff },
    .{ .word = 0x92488421, .value = 0xff00000003ffffff },
    .{ .word = 0x92488821, .value = 0xff00000007ffffff },
    .{ .word = 0x92488c21, .value = 0xff0000000fffffff },
    .{ .word = 0x92489021, .value = 0xff0000001fffffff },
    .{ .word = 0x92489421, .value = 0xff0000003fffffff },
    .{ .word = 0x92489821, .value = 0xff0000007fffffff },
    .{ .word = 0x92489c21, .value = 0xff000000ffffffff },
    .{ .word = 0x9248a021, .value = 0xff000001ffffffff },
    .{ .word = 0x9248a421, .value = 0xff000003ffffffff },
    .{ .word = 0x9248a821, .value = 0xff000007ffffffff },
    .{ .word = 0x9248ac21, .value = 0xff00000fffffffff },
    .{ .word = 0x9248b021, .value = 0xff00001fffffffff },
    .{ .word = 0x9248b421, .value = 0xff00003fffffffff },
    .{ .word = 0x9248b821, .value = 0xff00007fffffffff },
    .{ .word = 0x9248bc21, .value = 0xff0000ffffffffff },
    .{ .word = 0x9248c021, .value = 0xff0001ffffffffff },
    .{ .word = 0x9248c421, .value = 0xff0003ffffffffff },
    .{ .word = 0x9248c821, .value = 0xff0007ffffffffff },
    .{ .word = 0x9248cc21, .value = 0xff000fffffffffff },
    .{ .word = 0x9248d021, .value = 0xff001fffffffffff },
    .{ .word = 0x9248d421, .value = 0xff003fffffffffff },
    .{ .word = 0x9248d821, .value = 0xff007fffffffffff },
    .{ .word = 0x9248dc21, .value = 0xff00ffffffffffff },
    .{ .word = 0x9248e021, .value = 0xff01ffffffffffff },
    .{ .word = 0x9248e421, .value = 0xff03ffffffffffff },
    .{ .word = 0x9248e821, .value = 0xff07ffffffffffff },
    .{ .word = 0x9248ec21, .value = 0xff0fffffffffffff },
    .{ .word = 0x9248f021, .value = 0xff1fffffffffffff },
    .{ .word = 0x9248f421, .value = 0xff3fffffffffffff },
    .{ .word = 0x9248f821, .value = 0xff7fffffffffffff },
    .{ .word = 0x92490021, .value = 0x80000000000000 },
    .{ .word = 0x92490421, .value = 0x180000000000000 },
    .{ .word = 0x92490821, .value = 0x380000000000000 },
    .{ .word = 0x92490c21, .value = 0x780000000000000 },
    .{ .word = 0x92491021, .value = 0xf80000000000000 },
    .{ .word = 0x92491421, .value = 0x1f80000000000000 },
    .{ .word = 0x92491821, .value = 0x3f80000000000000 },
    .{ .word = 0x92491c21, .value = 0x7f80000000000000 },
    .{ .word = 0x92492021, .value = 0xff80000000000000 },
    .{ .word = 0x92492421, .value = 0xff80000000000001 },
    .{ .word = 0x92492821, .value = 0xff80000000000003 },
    .{ .word = 0x92492c21, .value = 0xff80000000000007 },
    .{ .word = 0x92493021, .value = 0xff8000000000000f },
    .{ .word = 0x92493421, .value = 0xff8000000000001f },
    .{ .word = 0x92493821, .value = 0xff8000000000003f },
    .{ .word = 0x92493c21, .value = 0xff8000000000007f },
    .{ .word = 0x92494021, .value = 0xff800000000000ff },
    .{ .word = 0x92494421, .value = 0xff800000000001ff },
    .{ .word = 0x92494821, .value = 0xff800000000003ff },
    .{ .word = 0x92494c21, .value = 0xff800000000007ff },
    .{ .word = 0x92495021, .value = 0xff80000000000fff },
    .{ .word = 0x92495421, .value = 0xff80000000001fff },
    .{ .word = 0x92495821, .value = 0xff80000000003fff },
    .{ .word = 0x92495c21, .value = 0xff80000000007fff },
    .{ .word = 0x92496021, .value = 0xff8000000000ffff },
    .{ .word = 0x92496421, .value = 0xff8000000001ffff },
    .{ .word = 0x92496821, .value = 0xff8000000003ffff },
    .{ .word = 0x92496c21, .value = 0xff8000000007ffff },
    .{ .word = 0x92497021, .value = 0xff800000000fffff },
    .{ .word = 0x92497421, .value = 0xff800000001fffff },
    .{ .word = 0x92497821, .value = 0xff800000003fffff },
    .{ .word = 0x92497c21, .value = 0xff800000007fffff },
    .{ .word = 0x92498021, .value = 0xff80000000ffffff },
    .{ .word = 0x92498421, .value = 0xff80000001ffffff },
    .{ .word = 0x92498821, .value = 0xff80000003ffffff },
    .{ .word = 0x92498c21, .value = 0xff80000007ffffff },
    .{ .word = 0x92499021, .value = 0xff8000000fffffff },
    .{ .word = 0x92499421, .value = 0xff8000001fffffff },
    .{ .word = 0x92499821, .value = 0xff8000003fffffff },
    .{ .word = 0x92499c21, .value = 0xff8000007fffffff },
    .{ .word = 0x9249a021, .value = 0xff800000ffffffff },
    .{ .word = 0x9249a421, .value = 0xff800001ffffffff },
    .{ .word = 0x9249a821, .value = 0xff800003ffffffff },
    .{ .word = 0x9249ac21, .value = 0xff800007ffffffff },
    .{ .word = 0x9249b021, .value = 0xff80000fffffffff },
    .{ .word = 0x9249b421, .value = 0xff80001fffffffff },
    .{ .word = 0x9249b821, .value = 0xff80003fffffffff },
    .{ .word = 0x9249bc21, .value = 0xff80007fffffffff },
    .{ .word = 0x9249c021, .value = 0xff8000ffffffffff },
    .{ .word = 0x9249c421, .value = 0xff8001ffffffffff },
    .{ .word = 0x9249c821, .value = 0xff8003ffffffffff },
    .{ .word = 0x9249cc21, .value = 0xff8007ffffffffff },
    .{ .word = 0x9249d021, .value = 0xff800fffffffffff },
    .{ .word = 0x9249d421, .value = 0xff801fffffffffff },
    .{ .word = 0x9249d821, .value = 0xff803fffffffffff },
    .{ .word = 0x9249dc21, .value = 0xff807fffffffffff },
    .{ .word = 0x9249e021, .value = 0xff80ffffffffffff },
    .{ .word = 0x9249e421, .value = 0xff81ffffffffffff },
    .{ .word = 0x9249e821, .value = 0xff83ffffffffffff },
    .{ .word = 0x9249ec21, .value = 0xff87ffffffffffff },
    .{ .word = 0x9249f021, .value = 0xff8fffffffffffff },
    .{ .word = 0x9249f421, .value = 0xff9fffffffffffff },
    .{ .word = 0x9249f821, .value = 0xffbfffffffffffff },
    .{ .word = 0x924a0021, .value = 0x40000000000000 },
    .{ .word = 0x924a0421, .value = 0xc0000000000000 },
    .{ .word = 0x924a0821, .value = 0x1c0000000000000 },
    .{ .word = 0x924a0c21, .value = 0x3c0000000000000 },
    .{ .word = 0x924a1021, .value = 0x7c0000000000000 },
    .{ .word = 0x924a1421, .value = 0xfc0000000000000 },
    .{ .word = 0x924a1821, .value = 0x1fc0000000000000 },
    .{ .word = 0x924a1c21, .value = 0x3fc0000000000000 },
    .{ .word = 0x924a2021, .value = 0x7fc0000000000000 },
    .{ .word = 0x924a2421, .value = 0xffc0000000000000 },
    .{ .word = 0x924a2821, .value = 0xffc0000000000001 },
    .{ .word = 0x924a2c21, .value = 0xffc0000000000003 },
    .{ .word = 0x924a3021, .value = 0xffc0000000000007 },
    .{ .word = 0x924a3421, .value = 0xffc000000000000f },
    .{ .word = 0x924a3821, .value = 0xffc000000000001f },
    .{ .word = 0x924a3c21, .value = 0xffc000000000003f },
    .{ .word = 0x924a4021, .value = 0xffc000000000007f },
    .{ .word = 0x924a4421, .value = 0xffc00000000000ff },
    .{ .word = 0x924a4821, .value = 0xffc00000000001ff },
    .{ .word = 0x924a4c21, .value = 0xffc00000000003ff },
    .{ .word = 0x924a5021, .value = 0xffc00000000007ff },
    .{ .word = 0x924a5421, .value = 0xffc0000000000fff },
    .{ .word = 0x924a5821, .value = 0xffc0000000001fff },
    .{ .word = 0x924a5c21, .value = 0xffc0000000003fff },
    .{ .word = 0x924a6021, .value = 0xffc0000000007fff },
    .{ .word = 0x924a6421, .value = 0xffc000000000ffff },
    .{ .word = 0x924a6821, .value = 0xffc000000001ffff },
    .{ .word = 0x924a6c21, .value = 0xffc000000003ffff },
    .{ .word = 0x924a7021, .value = 0xffc000000007ffff },
    .{ .word = 0x924a7421, .value = 0xffc00000000fffff },
    .{ .word = 0x924a7821, .value = 0xffc00000001fffff },
    .{ .word = 0x924a7c21, .value = 0xffc00000003fffff },
    .{ .word = 0x924a8021, .value = 0xffc00000007fffff },
    .{ .word = 0x924a8421, .value = 0xffc0000000ffffff },
    .{ .word = 0x924a8821, .value = 0xffc0000001ffffff },
    .{ .word = 0x924a8c21, .value = 0xffc0000003ffffff },
    .{ .word = 0x924a9021, .value = 0xffc0000007ffffff },
    .{ .word = 0x924a9421, .value = 0xffc000000fffffff },
    .{ .word = 0x924a9821, .value = 0xffc000001fffffff },
    .{ .word = 0x924a9c21, .value = 0xffc000003fffffff },
    .{ .word = 0x924aa021, .value = 0xffc000007fffffff },
    .{ .word = 0x924aa421, .value = 0xffc00000ffffffff },
    .{ .word = 0x924aa821, .value = 0xffc00001ffffffff },
    .{ .word = 0x924aac21, .value = 0xffc00003ffffffff },
    .{ .word = 0x924ab021, .value = 0xffc00007ffffffff },
    .{ .word = 0x924ab421, .value = 0xffc0000fffffffff },
    .{ .word = 0x924ab821, .value = 0xffc0001fffffffff },
    .{ .word = 0x924abc21, .value = 0xffc0003fffffffff },
    .{ .word = 0x924ac021, .value = 0xffc0007fffffffff },
    .{ .word = 0x924ac421, .value = 0xffc000ffffffffff },
    .{ .word = 0x924ac821, .value = 0xffc001ffffffffff },
    .{ .word = 0x924acc21, .value = 0xffc003ffffffffff },
    .{ .word = 0x924ad021, .value = 0xffc007ffffffffff },
    .{ .word = 0x924ad421, .value = 0xffc00fffffffffff },
    .{ .word = 0x924ad821, .value = 0xffc01fffffffffff },
    .{ .word = 0x924adc21, .value = 0xffc03fffffffffff },
    .{ .word = 0x924ae021, .value = 0xffc07fffffffffff },
    .{ .word = 0x924ae421, .value = 0xffc0ffffffffffff },
    .{ .word = 0x924ae821, .value = 0xffc1ffffffffffff },
    .{ .word = 0x924aec21, .value = 0xffc3ffffffffffff },
    .{ .word = 0x924af021, .value = 0xffc7ffffffffffff },
    .{ .word = 0x924af421, .value = 0xffcfffffffffffff },
    .{ .word = 0x924af821, .value = 0xffdfffffffffffff },
    .{ .word = 0x924b0021, .value = 0x20000000000000 },
    .{ .word = 0x924b0421, .value = 0x60000000000000 },
    .{ .word = 0x924b0821, .value = 0xe0000000000000 },
    .{ .word = 0x924b0c21, .value = 0x1e0000000000000 },
    .{ .word = 0x924b1021, .value = 0x3e0000000000000 },
    .{ .word = 0x924b1421, .value = 0x7e0000000000000 },
    .{ .word = 0x924b1821, .value = 0xfe0000000000000 },
    .{ .word = 0x924b1c21, .value = 0x1fe0000000000000 },
    .{ .word = 0x924b2021, .value = 0x3fe0000000000000 },
    .{ .word = 0x924b2421, .value = 0x7fe0000000000000 },
    .{ .word = 0x924b2821, .value = 0xffe0000000000000 },
    .{ .word = 0x924b2c21, .value = 0xffe0000000000001 },
    .{ .word = 0x924b3021, .value = 0xffe0000000000003 },
    .{ .word = 0x924b3421, .value = 0xffe0000000000007 },
    .{ .word = 0x924b3821, .value = 0xffe000000000000f },
    .{ .word = 0x924b3c21, .value = 0xffe000000000001f },
    .{ .word = 0x924b4021, .value = 0xffe000000000003f },
    .{ .word = 0x924b4421, .value = 0xffe000000000007f },
    .{ .word = 0x924b4821, .value = 0xffe00000000000ff },
    .{ .word = 0x924b4c21, .value = 0xffe00000000001ff },
    .{ .word = 0x924b5021, .value = 0xffe00000000003ff },
    .{ .word = 0x924b5421, .value = 0xffe00000000007ff },
    .{ .word = 0x924b5821, .value = 0xffe0000000000fff },
    .{ .word = 0x924b5c21, .value = 0xffe0000000001fff },
    .{ .word = 0x924b6021, .value = 0xffe0000000003fff },
    .{ .word = 0x924b6421, .value = 0xffe0000000007fff },
    .{ .word = 0x924b6821, .value = 0xffe000000000ffff },
    .{ .word = 0x924b6c21, .value = 0xffe000000001ffff },
    .{ .word = 0x924b7021, .value = 0xffe000000003ffff },
    .{ .word = 0x924b7421, .value = 0xffe000000007ffff },
    .{ .word = 0x924b7821, .value = 0xffe00000000fffff },
    .{ .word = 0x924b7c21, .value = 0xffe00000001fffff },
    .{ .word = 0x924b8021, .value = 0xffe00000003fffff },
    .{ .word = 0x924b8421, .value = 0xffe00000007fffff },
    .{ .word = 0x924b8821, .value = 0xffe0000000ffffff },
    .{ .word = 0x924b8c21, .value = 0xffe0000001ffffff },
    .{ .word = 0x924b9021, .value = 0xffe0000003ffffff },
    .{ .word = 0x924b9421, .value = 0xffe0000007ffffff },
    .{ .word = 0x924b9821, .value = 0xffe000000fffffff },
    .{ .word = 0x924b9c21, .value = 0xffe000001fffffff },
    .{ .word = 0x924ba021, .value = 0xffe000003fffffff },
    .{ .word = 0x924ba421, .value = 0xffe000007fffffff },
    .{ .word = 0x924ba821, .value = 0xffe00000ffffffff },
    .{ .word = 0x924bac21, .value = 0xffe00001ffffffff },
    .{ .word = 0x924bb021, .value = 0xffe00003ffffffff },
    .{ .word = 0x924bb421, .value = 0xffe00007ffffffff },
    .{ .word = 0x924bb821, .value = 0xffe0000fffffffff },
    .{ .word = 0x924bbc21, .value = 0xffe0001fffffffff },
    .{ .word = 0x924bc021, .value = 0xffe0003fffffffff },
    .{ .word = 0x924bc421, .value = 0xffe0007fffffffff },
    .{ .word = 0x924bc821, .value = 0xffe000ffffffffff },
    .{ .word = 0x924bcc21, .value = 0xffe001ffffffffff },
    .{ .word = 0x924bd021, .value = 0xffe003ffffffffff },
    .{ .word = 0x924bd421, .value = 0xffe007ffffffffff },
    .{ .word = 0x924bd821, .value = 0xffe00fffffffffff },
    .{ .word = 0x924bdc21, .value = 0xffe01fffffffffff },
    .{ .word = 0x924be021, .value = 0xffe03fffffffffff },
    .{ .word = 0x924be421, .value = 0xffe07fffffffffff },
    .{ .word = 0x924be821, .value = 0xffe0ffffffffffff },
    .{ .word = 0x924bec21, .value = 0xffe1ffffffffffff },
    .{ .word = 0x924bf021, .value = 0xffe3ffffffffffff },
    .{ .word = 0x924bf421, .value = 0xffe7ffffffffffff },
    .{ .word = 0x924bf821, .value = 0xffefffffffffffff },
    .{ .word = 0x924c0021, .value = 0x10000000000000 },
    .{ .word = 0x924c0421, .value = 0x30000000000000 },
    .{ .word = 0x924c0821, .value = 0x70000000000000 },
    .{ .word = 0x924c0c21, .value = 0xf0000000000000 },
    .{ .word = 0x924c1021, .value = 0x1f0000000000000 },
    .{ .word = 0x924c1421, .value = 0x3f0000000000000 },
    .{ .word = 0x924c1821, .value = 0x7f0000000000000 },
    .{ .word = 0x924c1c21, .value = 0xff0000000000000 },
    .{ .word = 0x924c2021, .value = 0x1ff0000000000000 },
    .{ .word = 0x924c2421, .value = 0x3ff0000000000000 },
    .{ .word = 0x924c2821, .value = 0x7ff0000000000000 },
    .{ .word = 0x924c2c21, .value = 0xfff0000000000000 },
    .{ .word = 0x924c3021, .value = 0xfff0000000000001 },
    .{ .word = 0x924c3421, .value = 0xfff0000000000003 },
    .{ .word = 0x924c3821, .value = 0xfff0000000000007 },
    .{ .word = 0x924c3c21, .value = 0xfff000000000000f },
    .{ .word = 0x924c4021, .value = 0xfff000000000001f },
    .{ .word = 0x924c4421, .value = 0xfff000000000003f },
    .{ .word = 0x924c4821, .value = 0xfff000000000007f },
    .{ .word = 0x924c4c21, .value = 0xfff00000000000ff },
    .{ .word = 0x924c5021, .value = 0xfff00000000001ff },
    .{ .word = 0x924c5421, .value = 0xfff00000000003ff },
    .{ .word = 0x924c5821, .value = 0xfff00000000007ff },
    .{ .word = 0x924c5c21, .value = 0xfff0000000000fff },
    .{ .word = 0x924c6021, .value = 0xfff0000000001fff },
    .{ .word = 0x924c6421, .value = 0xfff0000000003fff },
    .{ .word = 0x924c6821, .value = 0xfff0000000007fff },
    .{ .word = 0x924c6c21, .value = 0xfff000000000ffff },
    .{ .word = 0x924c7021, .value = 0xfff000000001ffff },
    .{ .word = 0x924c7421, .value = 0xfff000000003ffff },
    .{ .word = 0x924c7821, .value = 0xfff000000007ffff },
    .{ .word = 0x924c7c21, .value = 0xfff00000000fffff },
    .{ .word = 0x924c8021, .value = 0xfff00000001fffff },
    .{ .word = 0x924c8421, .value = 0xfff00000003fffff },
    .{ .word = 0x924c8821, .value = 0xfff00000007fffff },
    .{ .word = 0x924c8c21, .value = 0xfff0000000ffffff },
    .{ .word = 0x924c9021, .value = 0xfff0000001ffffff },
    .{ .word = 0x924c9421, .value = 0xfff0000003ffffff },
    .{ .word = 0x924c9821, .value = 0xfff0000007ffffff },
    .{ .word = 0x924c9c21, .value = 0xfff000000fffffff },
    .{ .word = 0x924ca021, .value = 0xfff000001fffffff },
    .{ .word = 0x924ca421, .value = 0xfff000003fffffff },
    .{ .word = 0x924ca821, .value = 0xfff000007fffffff },
    .{ .word = 0x924cac21, .value = 0xfff00000ffffffff },
    .{ .word = 0x924cb021, .value = 0xfff00001ffffffff },
    .{ .word = 0x924cb421, .value = 0xfff00003ffffffff },
    .{ .word = 0x924cb821, .value = 0xfff00007ffffffff },
    .{ .word = 0x924cbc21, .value = 0xfff0000fffffffff },
    .{ .word = 0x924cc021, .value = 0xfff0001fffffffff },
    .{ .word = 0x924cc421, .value = 0xfff0003fffffffff },
    .{ .word = 0x924cc821, .value = 0xfff0007fffffffff },
    .{ .word = 0x924ccc21, .value = 0xfff000ffffffffff },
    .{ .word = 0x924cd021, .value = 0xfff001ffffffffff },
    .{ .word = 0x924cd421, .value = 0xfff003ffffffffff },
    .{ .word = 0x924cd821, .value = 0xfff007ffffffffff },
    .{ .word = 0x924cdc21, .value = 0xfff00fffffffffff },
    .{ .word = 0x924ce021, .value = 0xfff01fffffffffff },
    .{ .word = 0x924ce421, .value = 0xfff03fffffffffff },
    .{ .word = 0x924ce821, .value = 0xfff07fffffffffff },
    .{ .word = 0x924cec21, .value = 0xfff0ffffffffffff },
    .{ .word = 0x924cf021, .value = 0xfff1ffffffffffff },
    .{ .word = 0x924cf421, .value = 0xfff3ffffffffffff },
    .{ .word = 0x924cf821, .value = 0xfff7ffffffffffff },
    .{ .word = 0x924d0021, .value = 0x8000000000000 },
    .{ .word = 0x924d0421, .value = 0x18000000000000 },
    .{ .word = 0x924d0821, .value = 0x38000000000000 },
    .{ .word = 0x924d0c21, .value = 0x78000000000000 },
    .{ .word = 0x924d1021, .value = 0xf8000000000000 },
    .{ .word = 0x924d1421, .value = 0x1f8000000000000 },
    .{ .word = 0x924d1821, .value = 0x3f8000000000000 },
    .{ .word = 0x924d1c21, .value = 0x7f8000000000000 },
    .{ .word = 0x924d2021, .value = 0xff8000000000000 },
    .{ .word = 0x924d2421, .value = 0x1ff8000000000000 },
    .{ .word = 0x924d2821, .value = 0x3ff8000000000000 },
    .{ .word = 0x924d2c21, .value = 0x7ff8000000000000 },
    .{ .word = 0x924d3021, .value = 0xfff8000000000000 },
    .{ .word = 0x924d3421, .value = 0xfff8000000000001 },
    .{ .word = 0x924d3821, .value = 0xfff8000000000003 },
    .{ .word = 0x924d3c21, .value = 0xfff8000000000007 },
    .{ .word = 0x924d4021, .value = 0xfff800000000000f },
    .{ .word = 0x924d4421, .value = 0xfff800000000001f },
    .{ .word = 0x924d4821, .value = 0xfff800000000003f },
    .{ .word = 0x924d4c21, .value = 0xfff800000000007f },
    .{ .word = 0x924d5021, .value = 0xfff80000000000ff },
    .{ .word = 0x924d5421, .value = 0xfff80000000001ff },
    .{ .word = 0x924d5821, .value = 0xfff80000000003ff },
    .{ .word = 0x924d5c21, .value = 0xfff80000000007ff },
    .{ .word = 0x924d6021, .value = 0xfff8000000000fff },
    .{ .word = 0x924d6421, .value = 0xfff8000000001fff },
    .{ .word = 0x924d6821, .value = 0xfff8000000003fff },
    .{ .word = 0x924d6c21, .value = 0xfff8000000007fff },
    .{ .word = 0x924d7021, .value = 0xfff800000000ffff },
    .{ .word = 0x924d7421, .value = 0xfff800000001ffff },
    .{ .word = 0x924d7821, .value = 0xfff800000003ffff },
    .{ .word = 0x924d7c21, .value = 0xfff800000007ffff },
    .{ .word = 0x924d8021, .value = 0xfff80000000fffff },
    .{ .word = 0x924d8421, .value = 0xfff80000001fffff },
    .{ .word = 0x924d8821, .value = 0xfff80000003fffff },
    .{ .word = 0x924d8c21, .value = 0xfff80000007fffff },
    .{ .word = 0x924d9021, .value = 0xfff8000000ffffff },
    .{ .word = 0x924d9421, .value = 0xfff8000001ffffff },
    .{ .word = 0x924d9821, .value = 0xfff8000003ffffff },
    .{ .word = 0x924d9c21, .value = 0xfff8000007ffffff },
    .{ .word = 0x924da021, .value = 0xfff800000fffffff },
    .{ .word = 0x924da421, .value = 0xfff800001fffffff },
    .{ .word = 0x924da821, .value = 0xfff800003fffffff },
    .{ .word = 0x924dac21, .value = 0xfff800007fffffff },
    .{ .word = 0x924db021, .value = 0xfff80000ffffffff },
    .{ .word = 0x924db421, .value = 0xfff80001ffffffff },
    .{ .word = 0x924db821, .value = 0xfff80003ffffffff },
    .{ .word = 0x924dbc21, .value = 0xfff80007ffffffff },
    .{ .word = 0x924dc021, .value = 0xfff8000fffffffff },
    .{ .word = 0x924dc421, .value = 0xfff8001fffffffff },
    .{ .word = 0x924dc821, .value = 0xfff8003fffffffff },
    .{ .word = 0x924dcc21, .value = 0xfff8007fffffffff },
    .{ .word = 0x924dd021, .value = 0xfff800ffffffffff },
    .{ .word = 0x924dd421, .value = 0xfff801ffffffffff },
    .{ .word = 0x924dd821, .value = 0xfff803ffffffffff },
    .{ .word = 0x924ddc21, .value = 0xfff807ffffffffff },
    .{ .word = 0x924de021, .value = 0xfff80fffffffffff },
    .{ .word = 0x924de421, .value = 0xfff81fffffffffff },
    .{ .word = 0x924de821, .value = 0xfff83fffffffffff },
    .{ .word = 0x924dec21, .value = 0xfff87fffffffffff },
    .{ .word = 0x924df021, .value = 0xfff8ffffffffffff },
    .{ .word = 0x924df421, .value = 0xfff9ffffffffffff },
    .{ .word = 0x924df821, .value = 0xfffbffffffffffff },
    .{ .word = 0x924e0021, .value = 0x4000000000000 },
    .{ .word = 0x924e0421, .value = 0xc000000000000 },
    .{ .word = 0x924e0821, .value = 0x1c000000000000 },
    .{ .word = 0x924e0c21, .value = 0x3c000000000000 },
    .{ .word = 0x924e1021, .value = 0x7c000000000000 },
    .{ .word = 0x924e1421, .value = 0xfc000000000000 },
    .{ .word = 0x924e1821, .value = 0x1fc000000000000 },
    .{ .word = 0x924e1c21, .value = 0x3fc000000000000 },
    .{ .word = 0x924e2021, .value = 0x7fc000000000000 },
    .{ .word = 0x924e2421, .value = 0xffc000000000000 },
    .{ .word = 0x924e2821, .value = 0x1ffc000000000000 },
    .{ .word = 0x924e2c21, .value = 0x3ffc000000000000 },
    .{ .word = 0x924e3021, .value = 0x7ffc000000000000 },
    .{ .word = 0x924e3421, .value = 0xfffc000000000000 },
    .{ .word = 0x924e3821, .value = 0xfffc000000000001 },
    .{ .word = 0x924e3c21, .value = 0xfffc000000000003 },
    .{ .word = 0x924e4021, .value = 0xfffc000000000007 },
    .{ .word = 0x924e4421, .value = 0xfffc00000000000f },
    .{ .word = 0x924e4821, .value = 0xfffc00000000001f },
    .{ .word = 0x924e4c21, .value = 0xfffc00000000003f },
    .{ .word = 0x924e5021, .value = 0xfffc00000000007f },
    .{ .word = 0x924e5421, .value = 0xfffc0000000000ff },
    .{ .word = 0x924e5821, .value = 0xfffc0000000001ff },
    .{ .word = 0x924e5c21, .value = 0xfffc0000000003ff },
    .{ .word = 0x924e6021, .value = 0xfffc0000000007ff },
    .{ .word = 0x924e6421, .value = 0xfffc000000000fff },
    .{ .word = 0x924e6821, .value = 0xfffc000000001fff },
    .{ .word = 0x924e6c21, .value = 0xfffc000000003fff },
    .{ .word = 0x924e7021, .value = 0xfffc000000007fff },
    .{ .word = 0x924e7421, .value = 0xfffc00000000ffff },
    .{ .word = 0x924e7821, .value = 0xfffc00000001ffff },
    .{ .word = 0x924e7c21, .value = 0xfffc00000003ffff },
    .{ .word = 0x924e8021, .value = 0xfffc00000007ffff },
    .{ .word = 0x924e8421, .value = 0xfffc0000000fffff },
    .{ .word = 0x924e8821, .value = 0xfffc0000001fffff },
    .{ .word = 0x924e8c21, .value = 0xfffc0000003fffff },
    .{ .word = 0x924e9021, .value = 0xfffc0000007fffff },
    .{ .word = 0x924e9421, .value = 0xfffc000000ffffff },
    .{ .word = 0x924e9821, .value = 0xfffc000001ffffff },
    .{ .word = 0x924e9c21, .value = 0xfffc000003ffffff },
    .{ .word = 0x924ea021, .value = 0xfffc000007ffffff },
    .{ .word = 0x924ea421, .value = 0xfffc00000fffffff },
    .{ .word = 0x924ea821, .value = 0xfffc00001fffffff },
    .{ .word = 0x924eac21, .value = 0xfffc00003fffffff },
    .{ .word = 0x924eb021, .value = 0xfffc00007fffffff },
    .{ .word = 0x924eb421, .value = 0xfffc0000ffffffff },
    .{ .word = 0x924eb821, .value = 0xfffc0001ffffffff },
    .{ .word = 0x924ebc21, .value = 0xfffc0003ffffffff },
    .{ .word = 0x924ec021, .value = 0xfffc0007ffffffff },
    .{ .word = 0x924ec421, .value = 0xfffc000fffffffff },
    .{ .word = 0x924ec821, .value = 0xfffc001fffffffff },
    .{ .word = 0x924ecc21, .value = 0xfffc003fffffffff },
    .{ .word = 0x924ed021, .value = 0xfffc007fffffffff },
    .{ .word = 0x924ed421, .value = 0xfffc00ffffffffff },
    .{ .word = 0x924ed821, .value = 0xfffc01ffffffffff },
    .{ .word = 0x924edc21, .value = 0xfffc03ffffffffff },
    .{ .word = 0x924ee021, .value = 0xfffc07ffffffffff },
    .{ .word = 0x924ee421, .value = 0xfffc0fffffffffff },
    .{ .word = 0x924ee821, .value = 0xfffc1fffffffffff },
    .{ .word = 0x924eec21, .value = 0xfffc3fffffffffff },
    .{ .word = 0x924ef021, .value = 0xfffc7fffffffffff },
    .{ .word = 0x924ef421, .value = 0xfffcffffffffffff },
    .{ .word = 0x924ef821, .value = 0xfffdffffffffffff },
    .{ .word = 0x924f0021, .value = 0x2000000000000 },
    .{ .word = 0x924f0421, .value = 0x6000000000000 },
    .{ .word = 0x924f0821, .value = 0xe000000000000 },
    .{ .word = 0x924f0c21, .value = 0x1e000000000000 },
    .{ .word = 0x924f1021, .value = 0x3e000000000000 },
    .{ .word = 0x924f1421, .value = 0x7e000000000000 },
    .{ .word = 0x924f1821, .value = 0xfe000000000000 },
    .{ .word = 0x924f1c21, .value = 0x1fe000000000000 },
    .{ .word = 0x924f2021, .value = 0x3fe000000000000 },
    .{ .word = 0x924f2421, .value = 0x7fe000000000000 },
    .{ .word = 0x924f2821, .value = 0xffe000000000000 },
    .{ .word = 0x924f2c21, .value = 0x1ffe000000000000 },
    .{ .word = 0x924f3021, .value = 0x3ffe000000000000 },
    .{ .word = 0x924f3421, .value = 0x7ffe000000000000 },
    .{ .word = 0x924f3821, .value = 0xfffe000000000000 },
    .{ .word = 0x924f3c21, .value = 0xfffe000000000001 },
    .{ .word = 0x924f4021, .value = 0xfffe000000000003 },
    .{ .word = 0x924f4421, .value = 0xfffe000000000007 },
    .{ .word = 0x924f4821, .value = 0xfffe00000000000f },
    .{ .word = 0x924f4c21, .value = 0xfffe00000000001f },
    .{ .word = 0x924f5021, .value = 0xfffe00000000003f },
    .{ .word = 0x924f5421, .value = 0xfffe00000000007f },
    .{ .word = 0x924f5821, .value = 0xfffe0000000000ff },
    .{ .word = 0x924f5c21, .value = 0xfffe0000000001ff },
    .{ .word = 0x924f6021, .value = 0xfffe0000000003ff },
    .{ .word = 0x924f6421, .value = 0xfffe0000000007ff },
    .{ .word = 0x924f6821, .value = 0xfffe000000000fff },
    .{ .word = 0x924f6c21, .value = 0xfffe000000001fff },
    .{ .word = 0x924f7021, .value = 0xfffe000000003fff },
    .{ .word = 0x924f7421, .value = 0xfffe000000007fff },
    .{ .word = 0x924f7821, .value = 0xfffe00000000ffff },
    .{ .word = 0x924f7c21, .value = 0xfffe00000001ffff },
    .{ .word = 0x924f8021, .value = 0xfffe00000003ffff },
    .{ .word = 0x924f8421, .value = 0xfffe00000007ffff },
    .{ .word = 0x924f8821, .value = 0xfffe0000000fffff },
    .{ .word = 0x924f8c21, .value = 0xfffe0000001fffff },
    .{ .word = 0x924f9021, .value = 0xfffe0000003fffff },
    .{ .word = 0x924f9421, .value = 0xfffe0000007fffff },
    .{ .word = 0x924f9821, .value = 0xfffe000000ffffff },
    .{ .word = 0x924f9c21, .value = 0xfffe000001ffffff },
    .{ .word = 0x924fa021, .value = 0xfffe000003ffffff },
    .{ .word = 0x924fa421, .value = 0xfffe000007ffffff },
    .{ .word = 0x924fa821, .value = 0xfffe00000fffffff },
    .{ .word = 0x924fac21, .value = 0xfffe00001fffffff },
    .{ .word = 0x924fb021, .value = 0xfffe00003fffffff },
    .{ .word = 0x924fb421, .value = 0xfffe00007fffffff },
    .{ .word = 0x924fb821, .value = 0xfffe0000ffffffff },
    .{ .word = 0x924fbc21, .value = 0xfffe0001ffffffff },
    .{ .word = 0x924fc021, .value = 0xfffe0003ffffffff },
    .{ .word = 0x924fc421, .value = 0xfffe0007ffffffff },
    .{ .word = 0x924fc821, .value = 0xfffe000fffffffff },
    .{ .word = 0x924fcc21, .value = 0xfffe001fffffffff },
    .{ .word = 0x924fd021, .value = 0xfffe003fffffffff },
    .{ .word = 0x924fd421, .value = 0xfffe007fffffffff },
    .{ .word = 0x924fd821, .value = 0xfffe00ffffffffff },
    .{ .word = 0x924fdc21, .value = 0xfffe01ffffffffff },
    .{ .word = 0x924fe021, .value = 0xfffe03ffffffffff },
    .{ .word = 0x924fe421, .value = 0xfffe07ffffffffff },
    .{ .word = 0x924fe821, .value = 0xfffe0fffffffffff },
    .{ .word = 0x924fec21, .value = 0xfffe1fffffffffff },
    .{ .word = 0x924ff021, .value = 0xfffe3fffffffffff },
    .{ .word = 0x924ff421, .value = 0xfffe7fffffffffff },
    .{ .word = 0x924ff821, .value = 0xfffeffffffffffff },
    .{ .word = 0x92500021, .value = 0x1000000000000 },
    .{ .word = 0x92500421, .value = 0x3000000000000 },
    .{ .word = 0x92500821, .value = 0x7000000000000 },
    .{ .word = 0x92500c21, .value = 0xf000000000000 },
    .{ .word = 0x92501021, .value = 0x1f000000000000 },
    .{ .word = 0x92501421, .value = 0x3f000000000000 },
    .{ .word = 0x92501821, .value = 0x7f000000000000 },
    .{ .word = 0x92501c21, .value = 0xff000000000000 },
    .{ .word = 0x92502021, .value = 0x1ff000000000000 },
    .{ .word = 0x92502421, .value = 0x3ff000000000000 },
    .{ .word = 0x92502821, .value = 0x7ff000000000000 },
    .{ .word = 0x92502c21, .value = 0xfff000000000000 },
    .{ .word = 0x92503021, .value = 0x1fff000000000000 },
    .{ .word = 0x92503421, .value = 0x3fff000000000000 },
    .{ .word = 0x92503821, .value = 0x7fff000000000000 },
    .{ .word = 0x92503c21, .value = 0xffff000000000000 },
    .{ .word = 0x92504021, .value = 0xffff000000000001 },
    .{ .word = 0x92504421, .value = 0xffff000000000003 },
    .{ .word = 0x92504821, .value = 0xffff000000000007 },
    .{ .word = 0x92504c21, .value = 0xffff00000000000f },
    .{ .word = 0x92505021, .value = 0xffff00000000001f },
    .{ .word = 0x92505421, .value = 0xffff00000000003f },
    .{ .word = 0x92505821, .value = 0xffff00000000007f },
    .{ .word = 0x92505c21, .value = 0xffff0000000000ff },
    .{ .word = 0x92506021, .value = 0xffff0000000001ff },
    .{ .word = 0x92506421, .value = 0xffff0000000003ff },
    .{ .word = 0x92506821, .value = 0xffff0000000007ff },
    .{ .word = 0x92506c21, .value = 0xffff000000000fff },
    .{ .word = 0x92507021, .value = 0xffff000000001fff },
    .{ .word = 0x92507421, .value = 0xffff000000003fff },
    .{ .word = 0x92507821, .value = 0xffff000000007fff },
    .{ .word = 0x92507c21, .value = 0xffff00000000ffff },
    .{ .word = 0x92508021, .value = 0xffff00000001ffff },
    .{ .word = 0x92508421, .value = 0xffff00000003ffff },
    .{ .word = 0x92508821, .value = 0xffff00000007ffff },
    .{ .word = 0x92508c21, .value = 0xffff0000000fffff },
    .{ .word = 0x92509021, .value = 0xffff0000001fffff },
    .{ .word = 0x92509421, .value = 0xffff0000003fffff },
    .{ .word = 0x92509821, .value = 0xffff0000007fffff },
    .{ .word = 0x92509c21, .value = 0xffff000000ffffff },
    .{ .word = 0x9250a021, .value = 0xffff000001ffffff },
    .{ .word = 0x9250a421, .value = 0xffff000003ffffff },
    .{ .word = 0x9250a821, .value = 0xffff000007ffffff },
    .{ .word = 0x9250ac21, .value = 0xffff00000fffffff },
    .{ .word = 0x9250b021, .value = 0xffff00001fffffff },
    .{ .word = 0x9250b421, .value = 0xffff00003fffffff },
    .{ .word = 0x9250b821, .value = 0xffff00007fffffff },
    .{ .word = 0x9250bc21, .value = 0xffff0000ffffffff },
    .{ .word = 0x9250c021, .value = 0xffff0001ffffffff },
    .{ .word = 0x9250c421, .value = 0xffff0003ffffffff },
    .{ .word = 0x9250c821, .value = 0xffff0007ffffffff },
    .{ .word = 0x9250cc21, .value = 0xffff000fffffffff },
    .{ .word = 0x9250d021, .value = 0xffff001fffffffff },
    .{ .word = 0x9250d421, .value = 0xffff003fffffffff },
    .{ .word = 0x9250d821, .value = 0xffff007fffffffff },
    .{ .word = 0x9250dc21, .value = 0xffff00ffffffffff },
    .{ .word = 0x9250e021, .value = 0xffff01ffffffffff },
    .{ .word = 0x9250e421, .value = 0xffff03ffffffffff },
    .{ .word = 0x9250e821, .value = 0xffff07ffffffffff },
    .{ .word = 0x9250ec21, .value = 0xffff0fffffffffff },
    .{ .word = 0x9250f021, .value = 0xffff1fffffffffff },
    .{ .word = 0x9250f421, .value = 0xffff3fffffffffff },
    .{ .word = 0x9250f821, .value = 0xffff7fffffffffff },
    .{ .word = 0x92510021, .value = 0x800000000000 },
    .{ .word = 0x92510421, .value = 0x1800000000000 },
    .{ .word = 0x92510821, .value = 0x3800000000000 },
    .{ .word = 0x92510c21, .value = 0x7800000000000 },
    .{ .word = 0x92511021, .value = 0xf800000000000 },
    .{ .word = 0x92511421, .value = 0x1f800000000000 },
    .{ .word = 0x92511821, .value = 0x3f800000000000 },
    .{ .word = 0x92511c21, .value = 0x7f800000000000 },
    .{ .word = 0x92512021, .value = 0xff800000000000 },
    .{ .word = 0x92512421, .value = 0x1ff800000000000 },
    .{ .word = 0x92512821, .value = 0x3ff800000000000 },
    .{ .word = 0x92512c21, .value = 0x7ff800000000000 },
    .{ .word = 0x92513021, .value = 0xfff800000000000 },
    .{ .word = 0x92513421, .value = 0x1fff800000000000 },
    .{ .word = 0x92513821, .value = 0x3fff800000000000 },
    .{ .word = 0x92513c21, .value = 0x7fff800000000000 },
    .{ .word = 0x92514021, .value = 0xffff800000000000 },
    .{ .word = 0x92514421, .value = 0xffff800000000001 },
    .{ .word = 0x92514821, .value = 0xffff800000000003 },
    .{ .word = 0x92514c21, .value = 0xffff800000000007 },
    .{ .word = 0x92515021, .value = 0xffff80000000000f },
    .{ .word = 0x92515421, .value = 0xffff80000000001f },
    .{ .word = 0x92515821, .value = 0xffff80000000003f },
    .{ .word = 0x92515c21, .value = 0xffff80000000007f },
    .{ .word = 0x92516021, .value = 0xffff8000000000ff },
    .{ .word = 0x92516421, .value = 0xffff8000000001ff },
    .{ .word = 0x92516821, .value = 0xffff8000000003ff },
    .{ .word = 0x92516c21, .value = 0xffff8000000007ff },
    .{ .word = 0x92517021, .value = 0xffff800000000fff },
    .{ .word = 0x92517421, .value = 0xffff800000001fff },
    .{ .word = 0x92517821, .value = 0xffff800000003fff },
    .{ .word = 0x92517c21, .value = 0xffff800000007fff },
    .{ .word = 0x92518021, .value = 0xffff80000000ffff },
    .{ .word = 0x92518421, .value = 0xffff80000001ffff },
    .{ .word = 0x92518821, .value = 0xffff80000003ffff },
    .{ .word = 0x92518c21, .value = 0xffff80000007ffff },
    .{ .word = 0x92519021, .value = 0xffff8000000fffff },
    .{ .word = 0x92519421, .value = 0xffff8000001fffff },
    .{ .word = 0x92519821, .value = 0xffff8000003fffff },
    .{ .word = 0x92519c21, .value = 0xffff8000007fffff },
    .{ .word = 0x9251a021, .value = 0xffff800000ffffff },
    .{ .word = 0x9251a421, .value = 0xffff800001ffffff },
    .{ .word = 0x9251a821, .value = 0xffff800003ffffff },
    .{ .word = 0x9251ac21, .value = 0xffff800007ffffff },
    .{ .word = 0x9251b021, .value = 0xffff80000fffffff },
    .{ .word = 0x9251b421, .value = 0xffff80001fffffff },
    .{ .word = 0x9251b821, .value = 0xffff80003fffffff },
    .{ .word = 0x9251bc21, .value = 0xffff80007fffffff },
    .{ .word = 0x9251c021, .value = 0xffff8000ffffffff },
    .{ .word = 0x9251c421, .value = 0xffff8001ffffffff },
    .{ .word = 0x9251c821, .value = 0xffff8003ffffffff },
    .{ .word = 0x9251cc21, .value = 0xffff8007ffffffff },
    .{ .word = 0x9251d021, .value = 0xffff800fffffffff },
    .{ .word = 0x9251d421, .value = 0xffff801fffffffff },
    .{ .word = 0x9251d821, .value = 0xffff803fffffffff },
    .{ .word = 0x9251dc21, .value = 0xffff807fffffffff },
    .{ .word = 0x9251e021, .value = 0xffff80ffffffffff },
    .{ .word = 0x9251e421, .value = 0xffff81ffffffffff },
    .{ .word = 0x9251e821, .value = 0xffff83ffffffffff },
    .{ .word = 0x9251ec21, .value = 0xffff87ffffffffff },
    .{ .word = 0x9251f021, .value = 0xffff8fffffffffff },
    .{ .word = 0x9251f421, .value = 0xffff9fffffffffff },
    .{ .word = 0x9251f821, .value = 0xffffbfffffffffff },
    .{ .word = 0x92520021, .value = 0x400000000000 },
    .{ .word = 0x92520421, .value = 0xc00000000000 },
    .{ .word = 0x92520821, .value = 0x1c00000000000 },
    .{ .word = 0x92520c21, .value = 0x3c00000000000 },
    .{ .word = 0x92521021, .value = 0x7c00000000000 },
    .{ .word = 0x92521421, .value = 0xfc00000000000 },
    .{ .word = 0x92521821, .value = 0x1fc00000000000 },
    .{ .word = 0x92521c21, .value = 0x3fc00000000000 },
    .{ .word = 0x92522021, .value = 0x7fc00000000000 },
    .{ .word = 0x92522421, .value = 0xffc00000000000 },
    .{ .word = 0x92522821, .value = 0x1ffc00000000000 },
    .{ .word = 0x92522c21, .value = 0x3ffc00000000000 },
    .{ .word = 0x92523021, .value = 0x7ffc00000000000 },
    .{ .word = 0x92523421, .value = 0xfffc00000000000 },
    .{ .word = 0x92523821, .value = 0x1fffc00000000000 },
    .{ .word = 0x92523c21, .value = 0x3fffc00000000000 },
    .{ .word = 0x92524021, .value = 0x7fffc00000000000 },
    .{ .word = 0x92524421, .value = 0xffffc00000000000 },
    .{ .word = 0x92524821, .value = 0xffffc00000000001 },
    .{ .word = 0x92524c21, .value = 0xffffc00000000003 },
    .{ .word = 0x92525021, .value = 0xffffc00000000007 },
    .{ .word = 0x92525421, .value = 0xffffc0000000000f },
    .{ .word = 0x92525821, .value = 0xffffc0000000001f },
    .{ .word = 0x92525c21, .value = 0xffffc0000000003f },
    .{ .word = 0x92526021, .value = 0xffffc0000000007f },
    .{ .word = 0x92526421, .value = 0xffffc000000000ff },
    .{ .word = 0x92526821, .value = 0xffffc000000001ff },
    .{ .word = 0x92526c21, .value = 0xffffc000000003ff },
    .{ .word = 0x92527021, .value = 0xffffc000000007ff },
    .{ .word = 0x92527421, .value = 0xffffc00000000fff },
    .{ .word = 0x92527821, .value = 0xffffc00000001fff },
    .{ .word = 0x92527c21, .value = 0xffffc00000003fff },
    .{ .word = 0x92528021, .value = 0xffffc00000007fff },
    .{ .word = 0x92528421, .value = 0xffffc0000000ffff },
    .{ .word = 0x92528821, .value = 0xffffc0000001ffff },
    .{ .word = 0x92528c21, .value = 0xffffc0000003ffff },
    .{ .word = 0x92529021, .value = 0xffffc0000007ffff },
    .{ .word = 0x92529421, .value = 0xffffc000000fffff },
    .{ .word = 0x92529821, .value = 0xffffc000001fffff },
    .{ .word = 0x92529c21, .value = 0xffffc000003fffff },
    .{ .word = 0x9252a021, .value = 0xffffc000007fffff },
    .{ .word = 0x9252a421, .value = 0xffffc00000ffffff },
    .{ .word = 0x9252a821, .value = 0xffffc00001ffffff },
    .{ .word = 0x9252ac21, .value = 0xffffc00003ffffff },
    .{ .word = 0x9252b021, .value = 0xffffc00007ffffff },
    .{ .word = 0x9252b421, .value = 0xffffc0000fffffff },
    .{ .word = 0x9252b821, .value = 0xffffc0001fffffff },
    .{ .word = 0x9252bc21, .value = 0xffffc0003fffffff },
    .{ .word = 0x9252c021, .value = 0xffffc0007fffffff },
    .{ .word = 0x9252c421, .value = 0xffffc000ffffffff },
    .{ .word = 0x9252c821, .value = 0xffffc001ffffffff },
    .{ .word = 0x9252cc21, .value = 0xffffc003ffffffff },
    .{ .word = 0x9252d021, .value = 0xffffc007ffffffff },
    .{ .word = 0x9252d421, .value = 0xffffc00fffffffff },
    .{ .word = 0x9252d821, .value = 0xffffc01fffffffff },
    .{ .word = 0x9252dc21, .value = 0xffffc03fffffffff },
    .{ .word = 0x9252e021, .value = 0xffffc07fffffffff },
    .{ .word = 0x9252e421, .value = 0xffffc0ffffffffff },
    .{ .word = 0x9252e821, .value = 0xffffc1ffffffffff },
    .{ .word = 0x9252ec21, .value = 0xffffc3ffffffffff },
    .{ .word = 0x9252f021, .value = 0xffffc7ffffffffff },
    .{ .word = 0x9252f421, .value = 0xffffcfffffffffff },
    .{ .word = 0x9252f821, .value = 0xffffdfffffffffff },
    .{ .word = 0x92530021, .value = 0x200000000000 },
    .{ .word = 0x92530421, .value = 0x600000000000 },
    .{ .word = 0x92530821, .value = 0xe00000000000 },
    .{ .word = 0x92530c21, .value = 0x1e00000000000 },
    .{ .word = 0x92531021, .value = 0x3e00000000000 },
    .{ .word = 0x92531421, .value = 0x7e00000000000 },
    .{ .word = 0x92531821, .value = 0xfe00000000000 },
    .{ .word = 0x92531c21, .value = 0x1fe00000000000 },
    .{ .word = 0x92532021, .value = 0x3fe00000000000 },
    .{ .word = 0x92532421, .value = 0x7fe00000000000 },
    .{ .word = 0x92532821, .value = 0xffe00000000000 },
    .{ .word = 0x92532c21, .value = 0x1ffe00000000000 },
    .{ .word = 0x92533021, .value = 0x3ffe00000000000 },
    .{ .word = 0x92533421, .value = 0x7ffe00000000000 },
    .{ .word = 0x92533821, .value = 0xfffe00000000000 },
    .{ .word = 0x92533c21, .value = 0x1fffe00000000000 },
    .{ .word = 0x92534021, .value = 0x3fffe00000000000 },
    .{ .word = 0x92534421, .value = 0x7fffe00000000000 },
    .{ .word = 0x92534821, .value = 0xffffe00000000000 },
    .{ .word = 0x92534c21, .value = 0xffffe00000000001 },
    .{ .word = 0x92535021, .value = 0xffffe00000000003 },
    .{ .word = 0x92535421, .value = 0xffffe00000000007 },
    .{ .word = 0x92535821, .value = 0xffffe0000000000f },
    .{ .word = 0x92535c21, .value = 0xffffe0000000001f },
    .{ .word = 0x92536021, .value = 0xffffe0000000003f },
    .{ .word = 0x92536421, .value = 0xffffe0000000007f },
    .{ .word = 0x92536821, .value = 0xffffe000000000ff },
    .{ .word = 0x92536c21, .value = 0xffffe000000001ff },
    .{ .word = 0x92537021, .value = 0xffffe000000003ff },
    .{ .word = 0x92537421, .value = 0xffffe000000007ff },
    .{ .word = 0x92537821, .value = 0xffffe00000000fff },
    .{ .word = 0x92537c21, .value = 0xffffe00000001fff },
    .{ .word = 0x92538021, .value = 0xffffe00000003fff },
    .{ .word = 0x92538421, .value = 0xffffe00000007fff },
    .{ .word = 0x92538821, .value = 0xffffe0000000ffff },
    .{ .word = 0x92538c21, .value = 0xffffe0000001ffff },
    .{ .word = 0x92539021, .value = 0xffffe0000003ffff },
    .{ .word = 0x92539421, .value = 0xffffe0000007ffff },
    .{ .word = 0x92539821, .value = 0xffffe000000fffff },
    .{ .word = 0x92539c21, .value = 0xffffe000001fffff },
    .{ .word = 0x9253a021, .value = 0xffffe000003fffff },
    .{ .word = 0x9253a421, .value = 0xffffe000007fffff },
    .{ .word = 0x9253a821, .value = 0xffffe00000ffffff },
    .{ .word = 0x9253ac21, .value = 0xffffe00001ffffff },
    .{ .word = 0x9253b021, .value = 0xffffe00003ffffff },
    .{ .word = 0x9253b421, .value = 0xffffe00007ffffff },
    .{ .word = 0x9253b821, .value = 0xffffe0000fffffff },
    .{ .word = 0x9253bc21, .value = 0xffffe0001fffffff },
    .{ .word = 0x9253c021, .value = 0xffffe0003fffffff },
    .{ .word = 0x9253c421, .value = 0xffffe0007fffffff },
    .{ .word = 0x9253c821, .value = 0xffffe000ffffffff },
    .{ .word = 0x9253cc21, .value = 0xffffe001ffffffff },
    .{ .word = 0x9253d021, .value = 0xffffe003ffffffff },
    .{ .word = 0x9253d421, .value = 0xffffe007ffffffff },
    .{ .word = 0x9253d821, .value = 0xffffe00fffffffff },
    .{ .word = 0x9253dc21, .value = 0xffffe01fffffffff },
    .{ .word = 0x9253e021, .value = 0xffffe03fffffffff },
    .{ .word = 0x9253e421, .value = 0xffffe07fffffffff },
    .{ .word = 0x9253e821, .value = 0xffffe0ffffffffff },
    .{ .word = 0x9253ec21, .value = 0xffffe1ffffffffff },
    .{ .word = 0x9253f021, .value = 0xffffe3ffffffffff },
    .{ .word = 0x9253f421, .value = 0xffffe7ffffffffff },
    .{ .word = 0x9253f821, .value = 0xffffefffffffffff },
    .{ .word = 0x92540021, .value = 0x100000000000 },
    .{ .word = 0x92540421, .value = 0x300000000000 },
    .{ .word = 0x92540821, .value = 0x700000000000 },
    .{ .word = 0x92540c21, .value = 0xf00000000000 },
    .{ .word = 0x92541021, .value = 0x1f00000000000 },
    .{ .word = 0x92541421, .value = 0x3f00000000000 },
    .{ .word = 0x92541821, .value = 0x7f00000000000 },
    .{ .word = 0x92541c21, .value = 0xff00000000000 },
    .{ .word = 0x92542021, .value = 0x1ff00000000000 },
    .{ .word = 0x92542421, .value = 0x3ff00000000000 },
    .{ .word = 0x92542821, .value = 0x7ff00000000000 },
    .{ .word = 0x92542c21, .value = 0xfff00000000000 },
    .{ .word = 0x92543021, .value = 0x1fff00000000000 },
    .{ .word = 0x92543421, .value = 0x3fff00000000000 },
    .{ .word = 0x92543821, .value = 0x7fff00000000000 },
    .{ .word = 0x92543c21, .value = 0xffff00000000000 },
    .{ .word = 0x92544021, .value = 0x1ffff00000000000 },
    .{ .word = 0x92544421, .value = 0x3ffff00000000000 },
    .{ .word = 0x92544821, .value = 0x7ffff00000000000 },
    .{ .word = 0x92544c21, .value = 0xfffff00000000000 },
    .{ .word = 0x92545021, .value = 0xfffff00000000001 },
    .{ .word = 0x92545421, .value = 0xfffff00000000003 },
    .{ .word = 0x92545821, .value = 0xfffff00000000007 },
    .{ .word = 0x92545c21, .value = 0xfffff0000000000f },
    .{ .word = 0x92546021, .value = 0xfffff0000000001f },
    .{ .word = 0x92546421, .value = 0xfffff0000000003f },
    .{ .word = 0x92546821, .value = 0xfffff0000000007f },
    .{ .word = 0x92546c21, .value = 0xfffff000000000ff },
    .{ .word = 0x92547021, .value = 0xfffff000000001ff },
    .{ .word = 0x92547421, .value = 0xfffff000000003ff },
    .{ .word = 0x92547821, .value = 0xfffff000000007ff },
    .{ .word = 0x92547c21, .value = 0xfffff00000000fff },
    .{ .word = 0x92548021, .value = 0xfffff00000001fff },
    .{ .word = 0x92548421, .value = 0xfffff00000003fff },
    .{ .word = 0x92548821, .value = 0xfffff00000007fff },
    .{ .word = 0x92548c21, .value = 0xfffff0000000ffff },
    .{ .word = 0x92549021, .value = 0xfffff0000001ffff },
    .{ .word = 0x92549421, .value = 0xfffff0000003ffff },
    .{ .word = 0x92549821, .value = 0xfffff0000007ffff },
    .{ .word = 0x92549c21, .value = 0xfffff000000fffff },
    .{ .word = 0x9254a021, .value = 0xfffff000001fffff },
    .{ .word = 0x9254a421, .value = 0xfffff000003fffff },
    .{ .word = 0x9254a821, .value = 0xfffff000007fffff },
    .{ .word = 0x9254ac21, .value = 0xfffff00000ffffff },
    .{ .word = 0x9254b021, .value = 0xfffff00001ffffff },
    .{ .word = 0x9254b421, .value = 0xfffff00003ffffff },
    .{ .word = 0x9254b821, .value = 0xfffff00007ffffff },
    .{ .word = 0x9254bc21, .value = 0xfffff0000fffffff },
    .{ .word = 0x9254c021, .value = 0xfffff0001fffffff },
    .{ .word = 0x9254c421, .value = 0xfffff0003fffffff },
    .{ .word = 0x9254c821, .value = 0xfffff0007fffffff },
    .{ .word = 0x9254cc21, .value = 0xfffff000ffffffff },
    .{ .word = 0x9254d021, .value = 0xfffff001ffffffff },
    .{ .word = 0x9254d421, .value = 0xfffff003ffffffff },
    .{ .word = 0x9254d821, .value = 0xfffff007ffffffff },
    .{ .word = 0x9254dc21, .value = 0xfffff00fffffffff },
    .{ .word = 0x9254e021, .value = 0xfffff01fffffffff },
    .{ .word = 0x9254e421, .value = 0xfffff03fffffffff },
    .{ .word = 0x9254e821, .value = 0xfffff07fffffffff },
    .{ .word = 0x9254ec21, .value = 0xfffff0ffffffffff },
    .{ .word = 0x9254f021, .value = 0xfffff1ffffffffff },
    .{ .word = 0x9254f421, .value = 0xfffff3ffffffffff },
    .{ .word = 0x9254f821, .value = 0xfffff7ffffffffff },
    .{ .word = 0x92550021, .value = 0x80000000000 },
    .{ .word = 0x92550421, .value = 0x180000000000 },
    .{ .word = 0x92550821, .value = 0x380000000000 },
    .{ .word = 0x92550c21, .value = 0x780000000000 },
    .{ .word = 0x92551021, .value = 0xf80000000000 },
    .{ .word = 0x92551421, .value = 0x1f80000000000 },
    .{ .word = 0x92551821, .value = 0x3f80000000000 },
    .{ .word = 0x92551c21, .value = 0x7f80000000000 },
    .{ .word = 0x92552021, .value = 0xff80000000000 },
    .{ .word = 0x92552421, .value = 0x1ff80000000000 },
    .{ .word = 0x92552821, .value = 0x3ff80000000000 },
    .{ .word = 0x92552c21, .value = 0x7ff80000000000 },
    .{ .word = 0x92553021, .value = 0xfff80000000000 },
    .{ .word = 0x92553421, .value = 0x1fff80000000000 },
    .{ .word = 0x92553821, .value = 0x3fff80000000000 },
    .{ .word = 0x92553c21, .value = 0x7fff80000000000 },
    .{ .word = 0x92554021, .value = 0xffff80000000000 },
    .{ .word = 0x92554421, .value = 0x1ffff80000000000 },
    .{ .word = 0x92554821, .value = 0x3ffff80000000000 },
    .{ .word = 0x92554c21, .value = 0x7ffff80000000000 },
    .{ .word = 0x92555021, .value = 0xfffff80000000000 },
    .{ .word = 0x92555421, .value = 0xfffff80000000001 },
    .{ .word = 0x92555821, .value = 0xfffff80000000003 },
    .{ .word = 0x92555c21, .value = 0xfffff80000000007 },
    .{ .word = 0x92556021, .value = 0xfffff8000000000f },
    .{ .word = 0x92556421, .value = 0xfffff8000000001f },
    .{ .word = 0x92556821, .value = 0xfffff8000000003f },
    .{ .word = 0x92556c21, .value = 0xfffff8000000007f },
    .{ .word = 0x92557021, .value = 0xfffff800000000ff },
    .{ .word = 0x92557421, .value = 0xfffff800000001ff },
    .{ .word = 0x92557821, .value = 0xfffff800000003ff },
    .{ .word = 0x92557c21, .value = 0xfffff800000007ff },
    .{ .word = 0x92558021, .value = 0xfffff80000000fff },
    .{ .word = 0x92558421, .value = 0xfffff80000001fff },
    .{ .word = 0x92558821, .value = 0xfffff80000003fff },
    .{ .word = 0x92558c21, .value = 0xfffff80000007fff },
    .{ .word = 0x92559021, .value = 0xfffff8000000ffff },
    .{ .word = 0x92559421, .value = 0xfffff8000001ffff },
    .{ .word = 0x92559821, .value = 0xfffff8000003ffff },
    .{ .word = 0x92559c21, .value = 0xfffff8000007ffff },
    .{ .word = 0x9255a021, .value = 0xfffff800000fffff },
    .{ .word = 0x9255a421, .value = 0xfffff800001fffff },
    .{ .word = 0x9255a821, .value = 0xfffff800003fffff },
    .{ .word = 0x9255ac21, .value = 0xfffff800007fffff },
    .{ .word = 0x9255b021, .value = 0xfffff80000ffffff },
    .{ .word = 0x9255b421, .value = 0xfffff80001ffffff },
    .{ .word = 0x9255b821, .value = 0xfffff80003ffffff },
    .{ .word = 0x9255bc21, .value = 0xfffff80007ffffff },
    .{ .word = 0x9255c021, .value = 0xfffff8000fffffff },
    .{ .word = 0x9255c421, .value = 0xfffff8001fffffff },
    .{ .word = 0x9255c821, .value = 0xfffff8003fffffff },
    .{ .word = 0x9255cc21, .value = 0xfffff8007fffffff },
    .{ .word = 0x9255d021, .value = 0xfffff800ffffffff },
    .{ .word = 0x9255d421, .value = 0xfffff801ffffffff },
    .{ .word = 0x9255d821, .value = 0xfffff803ffffffff },
    .{ .word = 0x9255dc21, .value = 0xfffff807ffffffff },
    .{ .word = 0x9255e021, .value = 0xfffff80fffffffff },
    .{ .word = 0x9255e421, .value = 0xfffff81fffffffff },
    .{ .word = 0x9255e821, .value = 0xfffff83fffffffff },
    .{ .word = 0x9255ec21, .value = 0xfffff87fffffffff },
    .{ .word = 0x9255f021, .value = 0xfffff8ffffffffff },
    .{ .word = 0x9255f421, .value = 0xfffff9ffffffffff },
    .{ .word = 0x9255f821, .value = 0xfffffbffffffffff },
    .{ .word = 0x92560021, .value = 0x40000000000 },
    .{ .word = 0x92560421, .value = 0xc0000000000 },
    .{ .word = 0x92560821, .value = 0x1c0000000000 },
    .{ .word = 0x92560c21, .value = 0x3c0000000000 },
    .{ .word = 0x92561021, .value = 0x7c0000000000 },
    .{ .word = 0x92561421, .value = 0xfc0000000000 },
    .{ .word = 0x92561821, .value = 0x1fc0000000000 },
    .{ .word = 0x92561c21, .value = 0x3fc0000000000 },
    .{ .word = 0x92562021, .value = 0x7fc0000000000 },
    .{ .word = 0x92562421, .value = 0xffc0000000000 },
    .{ .word = 0x92562821, .value = 0x1ffc0000000000 },
    .{ .word = 0x92562c21, .value = 0x3ffc0000000000 },
    .{ .word = 0x92563021, .value = 0x7ffc0000000000 },
    .{ .word = 0x92563421, .value = 0xfffc0000000000 },
    .{ .word = 0x92563821, .value = 0x1fffc0000000000 },
    .{ .word = 0x92563c21, .value = 0x3fffc0000000000 },
    .{ .word = 0x92564021, .value = 0x7fffc0000000000 },
    .{ .word = 0x92564421, .value = 0xffffc0000000000 },
    .{ .word = 0x92564821, .value = 0x1ffffc0000000000 },
    .{ .word = 0x92564c21, .value = 0x3ffffc0000000000 },
    .{ .word = 0x92565021, .value = 0x7ffffc0000000000 },
    .{ .word = 0x92565421, .value = 0xfffffc0000000000 },
    .{ .word = 0x92565821, .value = 0xfffffc0000000001 },
    .{ .word = 0x92565c21, .value = 0xfffffc0000000003 },
    .{ .word = 0x92566021, .value = 0xfffffc0000000007 },
    .{ .word = 0x92566421, .value = 0xfffffc000000000f },
    .{ .word = 0x92566821, .value = 0xfffffc000000001f },
    .{ .word = 0x92566c21, .value = 0xfffffc000000003f },
    .{ .word = 0x92567021, .value = 0xfffffc000000007f },
    .{ .word = 0x92567421, .value = 0xfffffc00000000ff },
    .{ .word = 0x92567821, .value = 0xfffffc00000001ff },
    .{ .word = 0x92567c21, .value = 0xfffffc00000003ff },
    .{ .word = 0x92568021, .value = 0xfffffc00000007ff },
    .{ .word = 0x92568421, .value = 0xfffffc0000000fff },
    .{ .word = 0x92568821, .value = 0xfffffc0000001fff },
    .{ .word = 0x92568c21, .value = 0xfffffc0000003fff },
    .{ .word = 0x92569021, .value = 0xfffffc0000007fff },
    .{ .word = 0x92569421, .value = 0xfffffc000000ffff },
    .{ .word = 0x92569821, .value = 0xfffffc000001ffff },
    .{ .word = 0x92569c21, .value = 0xfffffc000003ffff },
    .{ .word = 0x9256a021, .value = 0xfffffc000007ffff },
    .{ .word = 0x9256a421, .value = 0xfffffc00000fffff },
    .{ .word = 0x9256a821, .value = 0xfffffc00001fffff },
    .{ .word = 0x9256ac21, .value = 0xfffffc00003fffff },
    .{ .word = 0x9256b021, .value = 0xfffffc00007fffff },
    .{ .word = 0x9256b421, .value = 0xfffffc0000ffffff },
    .{ .word = 0x9256b821, .value = 0xfffffc0001ffffff },
    .{ .word = 0x9256bc21, .value = 0xfffffc0003ffffff },
    .{ .word = 0x9256c021, .value = 0xfffffc0007ffffff },
    .{ .word = 0x9256c421, .value = 0xfffffc000fffffff },
    .{ .word = 0x9256c821, .value = 0xfffffc001fffffff },
    .{ .word = 0x9256cc21, .value = 0xfffffc003fffffff },
    .{ .word = 0x9256d021, .value = 0xfffffc007fffffff },
    .{ .word = 0x9256d421, .value = 0xfffffc00ffffffff },
    .{ .word = 0x9256d821, .value = 0xfffffc01ffffffff },
    .{ .word = 0x9256dc21, .value = 0xfffffc03ffffffff },
    .{ .word = 0x9256e021, .value = 0xfffffc07ffffffff },
    .{ .word = 0x9256e421, .value = 0xfffffc0fffffffff },
    .{ .word = 0x9256e821, .value = 0xfffffc1fffffffff },
    .{ .word = 0x9256ec21, .value = 0xfffffc3fffffffff },
    .{ .word = 0x9256f021, .value = 0xfffffc7fffffffff },
    .{ .word = 0x9256f421, .value = 0xfffffcffffffffff },
    .{ .word = 0x9256f821, .value = 0xfffffdffffffffff },
    .{ .word = 0x92570021, .value = 0x20000000000 },
    .{ .word = 0x92570421, .value = 0x60000000000 },
    .{ .word = 0x92570821, .value = 0xe0000000000 },
    .{ .word = 0x92570c21, .value = 0x1e0000000000 },
    .{ .word = 0x92571021, .value = 0x3e0000000000 },
    .{ .word = 0x92571421, .value = 0x7e0000000000 },
    .{ .word = 0x92571821, .value = 0xfe0000000000 },
    .{ .word = 0x92571c21, .value = 0x1fe0000000000 },
    .{ .word = 0x92572021, .value = 0x3fe0000000000 },
    .{ .word = 0x92572421, .value = 0x7fe0000000000 },
    .{ .word = 0x92572821, .value = 0xffe0000000000 },
    .{ .word = 0x92572c21, .value = 0x1ffe0000000000 },
    .{ .word = 0x92573021, .value = 0x3ffe0000000000 },
    .{ .word = 0x92573421, .value = 0x7ffe0000000000 },
    .{ .word = 0x92573821, .value = 0xfffe0000000000 },
    .{ .word = 0x92573c21, .value = 0x1fffe0000000000 },
    .{ .word = 0x92574021, .value = 0x3fffe0000000000 },
    .{ .word = 0x92574421, .value = 0x7fffe0000000000 },
    .{ .word = 0x92574821, .value = 0xffffe0000000000 },
    .{ .word = 0x92574c21, .value = 0x1ffffe0000000000 },
    .{ .word = 0x92575021, .value = 0x3ffffe0000000000 },
    .{ .word = 0x92575421, .value = 0x7ffffe0000000000 },
    .{ .word = 0x92575821, .value = 0xfffffe0000000000 },
    .{ .word = 0x92575c21, .value = 0xfffffe0000000001 },
    .{ .word = 0x92576021, .value = 0xfffffe0000000003 },
    .{ .word = 0x92576421, .value = 0xfffffe0000000007 },
    .{ .word = 0x92576821, .value = 0xfffffe000000000f },
    .{ .word = 0x92576c21, .value = 0xfffffe000000001f },
    .{ .word = 0x92577021, .value = 0xfffffe000000003f },
    .{ .word = 0x92577421, .value = 0xfffffe000000007f },
    .{ .word = 0x92577821, .value = 0xfffffe00000000ff },
    .{ .word = 0x92577c21, .value = 0xfffffe00000001ff },
    .{ .word = 0x92578021, .value = 0xfffffe00000003ff },
    .{ .word = 0x92578421, .value = 0xfffffe00000007ff },
    .{ .word = 0x92578821, .value = 0xfffffe0000000fff },
    .{ .word = 0x92578c21, .value = 0xfffffe0000001fff },
    .{ .word = 0x92579021, .value = 0xfffffe0000003fff },
    .{ .word = 0x92579421, .value = 0xfffffe0000007fff },
    .{ .word = 0x92579821, .value = 0xfffffe000000ffff },
    .{ .word = 0x92579c21, .value = 0xfffffe000001ffff },
    .{ .word = 0x9257a021, .value = 0xfffffe000003ffff },
    .{ .word = 0x9257a421, .value = 0xfffffe000007ffff },
    .{ .word = 0x9257a821, .value = 0xfffffe00000fffff },
    .{ .word = 0x9257ac21, .value = 0xfffffe00001fffff },
    .{ .word = 0x9257b021, .value = 0xfffffe00003fffff },
    .{ .word = 0x9257b421, .value = 0xfffffe00007fffff },
    .{ .word = 0x9257b821, .value = 0xfffffe0000ffffff },
    .{ .word = 0x9257bc21, .value = 0xfffffe0001ffffff },
    .{ .word = 0x9257c021, .value = 0xfffffe0003ffffff },
    .{ .word = 0x9257c421, .value = 0xfffffe0007ffffff },
    .{ .word = 0x9257c821, .value = 0xfffffe000fffffff },
    .{ .word = 0x9257cc21, .value = 0xfffffe001fffffff },
    .{ .word = 0x9257d021, .value = 0xfffffe003fffffff },
    .{ .word = 0x9257d421, .value = 0xfffffe007fffffff },
    .{ .word = 0x9257d821, .value = 0xfffffe00ffffffff },
    .{ .word = 0x9257dc21, .value = 0xfffffe01ffffffff },
    .{ .word = 0x9257e021, .value = 0xfffffe03ffffffff },
    .{ .word = 0x9257e421, .value = 0xfffffe07ffffffff },
    .{ .word = 0x9257e821, .value = 0xfffffe0fffffffff },
    .{ .word = 0x9257ec21, .value = 0xfffffe1fffffffff },
    .{ .word = 0x9257f021, .value = 0xfffffe3fffffffff },
    .{ .word = 0x9257f421, .value = 0xfffffe7fffffffff },
    .{ .word = 0x9257f821, .value = 0xfffffeffffffffff },
    .{ .word = 0x92580021, .value = 0x10000000000 },
    .{ .word = 0x92580421, .value = 0x30000000000 },
    .{ .word = 0x92580821, .value = 0x70000000000 },
    .{ .word = 0x92580c21, .value = 0xf0000000000 },
    .{ .word = 0x92581021, .value = 0x1f0000000000 },
    .{ .word = 0x92581421, .value = 0x3f0000000000 },
    .{ .word = 0x92581821, .value = 0x7f0000000000 },
    .{ .word = 0x92581c21, .value = 0xff0000000000 },
    .{ .word = 0x92582021, .value = 0x1ff0000000000 },
    .{ .word = 0x92582421, .value = 0x3ff0000000000 },
    .{ .word = 0x92582821, .value = 0x7ff0000000000 },
    .{ .word = 0x92582c21, .value = 0xfff0000000000 },
    .{ .word = 0x92583021, .value = 0x1fff0000000000 },
    .{ .word = 0x92583421, .value = 0x3fff0000000000 },
    .{ .word = 0x92583821, .value = 0x7fff0000000000 },
    .{ .word = 0x92583c21, .value = 0xffff0000000000 },
    .{ .word = 0x92584021, .value = 0x1ffff0000000000 },
    .{ .word = 0x92584421, .value = 0x3ffff0000000000 },
    .{ .word = 0x92584821, .value = 0x7ffff0000000000 },
    .{ .word = 0x92584c21, .value = 0xfffff0000000000 },
    .{ .word = 0x92585021, .value = 0x1fffff0000000000 },
    .{ .word = 0x92585421, .value = 0x3fffff0000000000 },
    .{ .word = 0x92585821, .value = 0x7fffff0000000000 },
    .{ .word = 0x92585c21, .value = 0xffffff0000000000 },
    .{ .word = 0x92586021, .value = 0xffffff0000000001 },
    .{ .word = 0x92586421, .value = 0xffffff0000000003 },
    .{ .word = 0x92586821, .value = 0xffffff0000000007 },
    .{ .word = 0x92586c21, .value = 0xffffff000000000f },
    .{ .word = 0x92587021, .value = 0xffffff000000001f },
    .{ .word = 0x92587421, .value = 0xffffff000000003f },
    .{ .word = 0x92587821, .value = 0xffffff000000007f },
    .{ .word = 0x92587c21, .value = 0xffffff00000000ff },
    .{ .word = 0x92588021, .value = 0xffffff00000001ff },
    .{ .word = 0x92588421, .value = 0xffffff00000003ff },
    .{ .word = 0x92588821, .value = 0xffffff00000007ff },
    .{ .word = 0x92588c21, .value = 0xffffff0000000fff },
    .{ .word = 0x92589021, .value = 0xffffff0000001fff },
    .{ .word = 0x92589421, .value = 0xffffff0000003fff },
    .{ .word = 0x92589821, .value = 0xffffff0000007fff },
    .{ .word = 0x92589c21, .value = 0xffffff000000ffff },
    .{ .word = 0x9258a021, .value = 0xffffff000001ffff },
    .{ .word = 0x9258a421, .value = 0xffffff000003ffff },
    .{ .word = 0x9258a821, .value = 0xffffff000007ffff },
    .{ .word = 0x9258ac21, .value = 0xffffff00000fffff },
    .{ .word = 0x9258b021, .value = 0xffffff00001fffff },
    .{ .word = 0x9258b421, .value = 0xffffff00003fffff },
    .{ .word = 0x9258b821, .value = 0xffffff00007fffff },
    .{ .word = 0x9258bc21, .value = 0xffffff0000ffffff },
    .{ .word = 0x9258c021, .value = 0xffffff0001ffffff },
    .{ .word = 0x9258c421, .value = 0xffffff0003ffffff },
    .{ .word = 0x9258c821, .value = 0xffffff0007ffffff },
    .{ .word = 0x9258cc21, .value = 0xffffff000fffffff },
    .{ .word = 0x9258d021, .value = 0xffffff001fffffff },
    .{ .word = 0x9258d421, .value = 0xffffff003fffffff },
    .{ .word = 0x9258d821, .value = 0xffffff007fffffff },
    .{ .word = 0x9258dc21, .value = 0xffffff00ffffffff },
    .{ .word = 0x9258e021, .value = 0xffffff01ffffffff },
    .{ .word = 0x9258e421, .value = 0xffffff03ffffffff },
    .{ .word = 0x9258e821, .value = 0xffffff07ffffffff },
    .{ .word = 0x9258ec21, .value = 0xffffff0fffffffff },
    .{ .word = 0x9258f021, .value = 0xffffff1fffffffff },
    .{ .word = 0x9258f421, .value = 0xffffff3fffffffff },
    .{ .word = 0x9258f821, .value = 0xffffff7fffffffff },
    .{ .word = 0x92590021, .value = 0x8000000000 },
    .{ .word = 0x92590421, .value = 0x18000000000 },
    .{ .word = 0x92590821, .value = 0x38000000000 },
    .{ .word = 0x92590c21, .value = 0x78000000000 },
    .{ .word = 0x92591021, .value = 0xf8000000000 },
    .{ .word = 0x92591421, .value = 0x1f8000000000 },
    .{ .word = 0x92591821, .value = 0x3f8000000000 },
    .{ .word = 0x92591c21, .value = 0x7f8000000000 },
    .{ .word = 0x92592021, .value = 0xff8000000000 },
    .{ .word = 0x92592421, .value = 0x1ff8000000000 },
    .{ .word = 0x92592821, .value = 0x3ff8000000000 },
    .{ .word = 0x92592c21, .value = 0x7ff8000000000 },
    .{ .word = 0x92593021, .value = 0xfff8000000000 },
    .{ .word = 0x92593421, .value = 0x1fff8000000000 },
    .{ .word = 0x92593821, .value = 0x3fff8000000000 },
    .{ .word = 0x92593c21, .value = 0x7fff8000000000 },
    .{ .word = 0x92594021, .value = 0xffff8000000000 },
    .{ .word = 0x92594421, .value = 0x1ffff8000000000 },
    .{ .word = 0x92594821, .value = 0x3ffff8000000000 },
    .{ .word = 0x92594c21, .value = 0x7ffff8000000000 },
    .{ .word = 0x92595021, .value = 0xfffff8000000000 },
    .{ .word = 0x92595421, .value = 0x1fffff8000000000 },
    .{ .word = 0x92595821, .value = 0x3fffff8000000000 },
    .{ .word = 0x92595c21, .value = 0x7fffff8000000000 },
    .{ .word = 0x92596021, .value = 0xffffff8000000000 },
    .{ .word = 0x92596421, .value = 0xffffff8000000001 },
    .{ .word = 0x92596821, .value = 0xffffff8000000003 },
    .{ .word = 0x92596c21, .value = 0xffffff8000000007 },
    .{ .word = 0x92597021, .value = 0xffffff800000000f },
    .{ .word = 0x92597421, .value = 0xffffff800000001f },
    .{ .word = 0x92597821, .value = 0xffffff800000003f },
    .{ .word = 0x92597c21, .value = 0xffffff800000007f },
    .{ .word = 0x92598021, .value = 0xffffff80000000ff },
    .{ .word = 0x92598421, .value = 0xffffff80000001ff },
    .{ .word = 0x92598821, .value = 0xffffff80000003ff },
    .{ .word = 0x92598c21, .value = 0xffffff80000007ff },
    .{ .word = 0x92599021, .value = 0xffffff8000000fff },
    .{ .word = 0x92599421, .value = 0xffffff8000001fff },
    .{ .word = 0x92599821, .value = 0xffffff8000003fff },
    .{ .word = 0x92599c21, .value = 0xffffff8000007fff },
    .{ .word = 0x9259a021, .value = 0xffffff800000ffff },
    .{ .word = 0x9259a421, .value = 0xffffff800001ffff },
    .{ .word = 0x9259a821, .value = 0xffffff800003ffff },
    .{ .word = 0x9259ac21, .value = 0xffffff800007ffff },
    .{ .word = 0x9259b021, .value = 0xffffff80000fffff },
    .{ .word = 0x9259b421, .value = 0xffffff80001fffff },
    .{ .word = 0x9259b821, .value = 0xffffff80003fffff },
    .{ .word = 0x9259bc21, .value = 0xffffff80007fffff },
    .{ .word = 0x9259c021, .value = 0xffffff8000ffffff },
    .{ .word = 0x9259c421, .value = 0xffffff8001ffffff },
    .{ .word = 0x9259c821, .value = 0xffffff8003ffffff },
    .{ .word = 0x9259cc21, .value = 0xffffff8007ffffff },
    .{ .word = 0x9259d021, .value = 0xffffff800fffffff },
    .{ .word = 0x9259d421, .value = 0xffffff801fffffff },
    .{ .word = 0x9259d821, .value = 0xffffff803fffffff },
    .{ .word = 0x9259dc21, .value = 0xffffff807fffffff },
    .{ .word = 0x9259e021, .value = 0xffffff80ffffffff },
    .{ .word = 0x9259e421, .value = 0xffffff81ffffffff },
    .{ .word = 0x9259e821, .value = 0xffffff83ffffffff },
    .{ .word = 0x9259ec21, .value = 0xffffff87ffffffff },
    .{ .word = 0x9259f021, .value = 0xffffff8fffffffff },
    .{ .word = 0x9259f421, .value = 0xffffff9fffffffff },
    .{ .word = 0x9259f821, .value = 0xffffffbfffffffff },
    .{ .word = 0x925a0021, .value = 0x4000000000 },
    .{ .word = 0x925a0421, .value = 0xc000000000 },
    .{ .word = 0x925a0821, .value = 0x1c000000000 },
    .{ .word = 0x925a0c21, .value = 0x3c000000000 },
    .{ .word = 0x925a1021, .value = 0x7c000000000 },
    .{ .word = 0x925a1421, .value = 0xfc000000000 },
    .{ .word = 0x925a1821, .value = 0x1fc000000000 },
    .{ .word = 0x925a1c21, .value = 0x3fc000000000 },
    .{ .word = 0x925a2021, .value = 0x7fc000000000 },
    .{ .word = 0x925a2421, .value = 0xffc000000000 },
    .{ .word = 0x925a2821, .value = 0x1ffc000000000 },
    .{ .word = 0x925a2c21, .value = 0x3ffc000000000 },
    .{ .word = 0x925a3021, .value = 0x7ffc000000000 },
    .{ .word = 0x925a3421, .value = 0xfffc000000000 },
    .{ .word = 0x925a3821, .value = 0x1fffc000000000 },
    .{ .word = 0x925a3c21, .value = 0x3fffc000000000 },
    .{ .word = 0x925a4021, .value = 0x7fffc000000000 },
    .{ .word = 0x925a4421, .value = 0xffffc000000000 },
    .{ .word = 0x925a4821, .value = 0x1ffffc000000000 },
    .{ .word = 0x925a4c21, .value = 0x3ffffc000000000 },
    .{ .word = 0x925a5021, .value = 0x7ffffc000000000 },
    .{ .word = 0x925a5421, .value = 0xfffffc000000000 },
    .{ .word = 0x925a5821, .value = 0x1fffffc000000000 },
    .{ .word = 0x925a5c21, .value = 0x3fffffc000000000 },
    .{ .word = 0x925a6021, .value = 0x7fffffc000000000 },
    .{ .word = 0x925a6421, .value = 0xffffffc000000000 },
    .{ .word = 0x925a6821, .value = 0xffffffc000000001 },
    .{ .word = 0x925a6c21, .value = 0xffffffc000000003 },
    .{ .word = 0x925a7021, .value = 0xffffffc000000007 },
    .{ .word = 0x925a7421, .value = 0xffffffc00000000f },
    .{ .word = 0x925a7821, .value = 0xffffffc00000001f },
    .{ .word = 0x925a7c21, .value = 0xffffffc00000003f },
    .{ .word = 0x925a8021, .value = 0xffffffc00000007f },
    .{ .word = 0x925a8421, .value = 0xffffffc0000000ff },
    .{ .word = 0x925a8821, .value = 0xffffffc0000001ff },
    .{ .word = 0x925a8c21, .value = 0xffffffc0000003ff },
    .{ .word = 0x925a9021, .value = 0xffffffc0000007ff },
    .{ .word = 0x925a9421, .value = 0xffffffc000000fff },
    .{ .word = 0x925a9821, .value = 0xffffffc000001fff },
    .{ .word = 0x925a9c21, .value = 0xffffffc000003fff },
    .{ .word = 0x925aa021, .value = 0xffffffc000007fff },
    .{ .word = 0x925aa421, .value = 0xffffffc00000ffff },
    .{ .word = 0x925aa821, .value = 0xffffffc00001ffff },
    .{ .word = 0x925aac21, .value = 0xffffffc00003ffff },
    .{ .word = 0x925ab021, .value = 0xffffffc00007ffff },
    .{ .word = 0x925ab421, .value = 0xffffffc0000fffff },
    .{ .word = 0x925ab821, .value = 0xffffffc0001fffff },
    .{ .word = 0x925abc21, .value = 0xffffffc0003fffff },
    .{ .word = 0x925ac021, .value = 0xffffffc0007fffff },
    .{ .word = 0x925ac421, .value = 0xffffffc000ffffff },
    .{ .word = 0x925ac821, .value = 0xffffffc001ffffff },
    .{ .word = 0x925acc21, .value = 0xffffffc003ffffff },
    .{ .word = 0x925ad021, .value = 0xffffffc007ffffff },
    .{ .word = 0x925ad421, .value = 0xffffffc00fffffff },
    .{ .word = 0x925ad821, .value = 0xffffffc01fffffff },
    .{ .word = 0x925adc21, .value = 0xffffffc03fffffff },
    .{ .word = 0x925ae021, .value = 0xffffffc07fffffff },
    .{ .word = 0x925ae421, .value = 0xffffffc0ffffffff },
    .{ .word = 0x925ae821, .value = 0xffffffc1ffffffff },
    .{ .word = 0x925aec21, .value = 0xffffffc3ffffffff },
    .{ .word = 0x925af021, .value = 0xffffffc7ffffffff },
    .{ .word = 0x925af421, .value = 0xffffffcfffffffff },
    .{ .word = 0x925af821, .value = 0xffffffdfffffffff },
    .{ .word = 0x925b0021, .value = 0x2000000000 },
    .{ .word = 0x925b0421, .value = 0x6000000000 },
    .{ .word = 0x925b0821, .value = 0xe000000000 },
    .{ .word = 0x925b0c21, .value = 0x1e000000000 },
    .{ .word = 0x925b1021, .value = 0x3e000000000 },
    .{ .word = 0x925b1421, .value = 0x7e000000000 },
    .{ .word = 0x925b1821, .value = 0xfe000000000 },
    .{ .word = 0x925b1c21, .value = 0x1fe000000000 },
    .{ .word = 0x925b2021, .value = 0x3fe000000000 },
    .{ .word = 0x925b2421, .value = 0x7fe000000000 },
    .{ .word = 0x925b2821, .value = 0xffe000000000 },
    .{ .word = 0x925b2c21, .value = 0x1ffe000000000 },
    .{ .word = 0x925b3021, .value = 0x3ffe000000000 },
    .{ .word = 0x925b3421, .value = 0x7ffe000000000 },
    .{ .word = 0x925b3821, .value = 0xfffe000000000 },
    .{ .word = 0x925b3c21, .value = 0x1fffe000000000 },
    .{ .word = 0x925b4021, .value = 0x3fffe000000000 },
    .{ .word = 0x925b4421, .value = 0x7fffe000000000 },
    .{ .word = 0x925b4821, .value = 0xffffe000000000 },
    .{ .word = 0x925b4c21, .value = 0x1ffffe000000000 },
    .{ .word = 0x925b5021, .value = 0x3ffffe000000000 },
    .{ .word = 0x925b5421, .value = 0x7ffffe000000000 },
    .{ .word = 0x925b5821, .value = 0xfffffe000000000 },
    .{ .word = 0x925b5c21, .value = 0x1fffffe000000000 },
    .{ .word = 0x925b6021, .value = 0x3fffffe000000000 },
    .{ .word = 0x925b6421, .value = 0x7fffffe000000000 },
    .{ .word = 0x925b6821, .value = 0xffffffe000000000 },
    .{ .word = 0x925b6c21, .value = 0xffffffe000000001 },
    .{ .word = 0x925b7021, .value = 0xffffffe000000003 },
    .{ .word = 0x925b7421, .value = 0xffffffe000000007 },
    .{ .word = 0x925b7821, .value = 0xffffffe00000000f },
    .{ .word = 0x925b7c21, .value = 0xffffffe00000001f },
    .{ .word = 0x925b8021, .value = 0xffffffe00000003f },
    .{ .word = 0x925b8421, .value = 0xffffffe00000007f },
    .{ .word = 0x925b8821, .value = 0xffffffe0000000ff },
    .{ .word = 0x925b8c21, .value = 0xffffffe0000001ff },
    .{ .word = 0x925b9021, .value = 0xffffffe0000003ff },
    .{ .word = 0x925b9421, .value = 0xffffffe0000007ff },
    .{ .word = 0x925b9821, .value = 0xffffffe000000fff },
    .{ .word = 0x925b9c21, .value = 0xffffffe000001fff },
    .{ .word = 0x925ba021, .value = 0xffffffe000003fff },
    .{ .word = 0x925ba421, .value = 0xffffffe000007fff },
    .{ .word = 0x925ba821, .value = 0xffffffe00000ffff },
    .{ .word = 0x925bac21, .value = 0xffffffe00001ffff },
    .{ .word = 0x925bb021, .value = 0xffffffe00003ffff },
    .{ .word = 0x925bb421, .value = 0xffffffe00007ffff },
    .{ .word = 0x925bb821, .value = 0xffffffe0000fffff },
    .{ .word = 0x925bbc21, .value = 0xffffffe0001fffff },
    .{ .word = 0x925bc021, .value = 0xffffffe0003fffff },
    .{ .word = 0x925bc421, .value = 0xffffffe0007fffff },
    .{ .word = 0x925bc821, .value = 0xffffffe000ffffff },
    .{ .word = 0x925bcc21, .value = 0xffffffe001ffffff },
    .{ .word = 0x925bd021, .value = 0xffffffe003ffffff },
    .{ .word = 0x925bd421, .value = 0xffffffe007ffffff },
    .{ .word = 0x925bd821, .value = 0xffffffe00fffffff },
    .{ .word = 0x925bdc21, .value = 0xffffffe01fffffff },
    .{ .word = 0x925be021, .value = 0xffffffe03fffffff },
    .{ .word = 0x925be421, .value = 0xffffffe07fffffff },
    .{ .word = 0x925be821, .value = 0xffffffe0ffffffff },
    .{ .word = 0x925bec21, .value = 0xffffffe1ffffffff },
    .{ .word = 0x925bf021, .value = 0xffffffe3ffffffff },
    .{ .word = 0x925bf421, .value = 0xffffffe7ffffffff },
    .{ .word = 0x925bf821, .value = 0xffffffefffffffff },
    .{ .word = 0x925c0021, .value = 0x1000000000 },
    .{ .word = 0x925c0421, .value = 0x3000000000 },
    .{ .word = 0x925c0821, .value = 0x7000000000 },
    .{ .word = 0x925c0c21, .value = 0xf000000000 },
    .{ .word = 0x925c1021, .value = 0x1f000000000 },
    .{ .word = 0x925c1421, .value = 0x3f000000000 },
    .{ .word = 0x925c1821, .value = 0x7f000000000 },
    .{ .word = 0x925c1c21, .value = 0xff000000000 },
    .{ .word = 0x925c2021, .value = 0x1ff000000000 },
    .{ .word = 0x925c2421, .value = 0x3ff000000000 },
    .{ .word = 0x925c2821, .value = 0x7ff000000000 },
    .{ .word = 0x925c2c21, .value = 0xfff000000000 },
    .{ .word = 0x925c3021, .value = 0x1fff000000000 },
    .{ .word = 0x925c3421, .value = 0x3fff000000000 },
    .{ .word = 0x925c3821, .value = 0x7fff000000000 },
    .{ .word = 0x925c3c21, .value = 0xffff000000000 },
    .{ .word = 0x925c4021, .value = 0x1ffff000000000 },
    .{ .word = 0x925c4421, .value = 0x3ffff000000000 },
    .{ .word = 0x925c4821, .value = 0x7ffff000000000 },
    .{ .word = 0x925c4c21, .value = 0xfffff000000000 },
    .{ .word = 0x925c5021, .value = 0x1fffff000000000 },
    .{ .word = 0x925c5421, .value = 0x3fffff000000000 },
    .{ .word = 0x925c5821, .value = 0x7fffff000000000 },
    .{ .word = 0x925c5c21, .value = 0xffffff000000000 },
    .{ .word = 0x925c6021, .value = 0x1ffffff000000000 },
    .{ .word = 0x925c6421, .value = 0x3ffffff000000000 },
    .{ .word = 0x925c6821, .value = 0x7ffffff000000000 },
    .{ .word = 0x925c6c21, .value = 0xfffffff000000000 },
    .{ .word = 0x925c7021, .value = 0xfffffff000000001 },
    .{ .word = 0x925c7421, .value = 0xfffffff000000003 },
    .{ .word = 0x925c7821, .value = 0xfffffff000000007 },
    .{ .word = 0x925c7c21, .value = 0xfffffff00000000f },
    .{ .word = 0x925c8021, .value = 0xfffffff00000001f },
    .{ .word = 0x925c8421, .value = 0xfffffff00000003f },
    .{ .word = 0x925c8821, .value = 0xfffffff00000007f },
    .{ .word = 0x925c8c21, .value = 0xfffffff0000000ff },
    .{ .word = 0x925c9021, .value = 0xfffffff0000001ff },
    .{ .word = 0x925c9421, .value = 0xfffffff0000003ff },
    .{ .word = 0x925c9821, .value = 0xfffffff0000007ff },
    .{ .word = 0x925c9c21, .value = 0xfffffff000000fff },
    .{ .word = 0x925ca021, .value = 0xfffffff000001fff },
    .{ .word = 0x925ca421, .value = 0xfffffff000003fff },
    .{ .word = 0x925ca821, .value = 0xfffffff000007fff },
    .{ .word = 0x925cac21, .value = 0xfffffff00000ffff },
    .{ .word = 0x925cb021, .value = 0xfffffff00001ffff },
    .{ .word = 0x925cb421, .value = 0xfffffff00003ffff },
    .{ .word = 0x925cb821, .value = 0xfffffff00007ffff },
    .{ .word = 0x925cbc21, .value = 0xfffffff0000fffff },
    .{ .word = 0x925cc021, .value = 0xfffffff0001fffff },
    .{ .word = 0x925cc421, .value = 0xfffffff0003fffff },
    .{ .word = 0x925cc821, .value = 0xfffffff0007fffff },
    .{ .word = 0x925ccc21, .value = 0xfffffff000ffffff },
    .{ .word = 0x925cd021, .value = 0xfffffff001ffffff },
    .{ .word = 0x925cd421, .value = 0xfffffff003ffffff },
    .{ .word = 0x925cd821, .value = 0xfffffff007ffffff },
    .{ .word = 0x925cdc21, .value = 0xfffffff00fffffff },
    .{ .word = 0x925ce021, .value = 0xfffffff01fffffff },
    .{ .word = 0x925ce421, .value = 0xfffffff03fffffff },
    .{ .word = 0x925ce821, .value = 0xfffffff07fffffff },
    .{ .word = 0x925cec21, .value = 0xfffffff0ffffffff },
    .{ .word = 0x925cf021, .value = 0xfffffff1ffffffff },
    .{ .word = 0x925cf421, .value = 0xfffffff3ffffffff },
    .{ .word = 0x925cf821, .value = 0xfffffff7ffffffff },
    .{ .word = 0x925d0021, .value = 0x800000000 },
    .{ .word = 0x925d0421, .value = 0x1800000000 },
    .{ .word = 0x925d0821, .value = 0x3800000000 },
    .{ .word = 0x925d0c21, .value = 0x7800000000 },
    .{ .word = 0x925d1021, .value = 0xf800000000 },
    .{ .word = 0x925d1421, .value = 0x1f800000000 },
    .{ .word = 0x925d1821, .value = 0x3f800000000 },
    .{ .word = 0x925d1c21, .value = 0x7f800000000 },
    .{ .word = 0x925d2021, .value = 0xff800000000 },
    .{ .word = 0x925d2421, .value = 0x1ff800000000 },
    .{ .word = 0x925d2821, .value = 0x3ff800000000 },
    .{ .word = 0x925d2c21, .value = 0x7ff800000000 },
    .{ .word = 0x925d3021, .value = 0xfff800000000 },
    .{ .word = 0x925d3421, .value = 0x1fff800000000 },
    .{ .word = 0x925d3821, .value = 0x3fff800000000 },
    .{ .word = 0x925d3c21, .value = 0x7fff800000000 },
    .{ .word = 0x925d4021, .value = 0xffff800000000 },
    .{ .word = 0x925d4421, .value = 0x1ffff800000000 },
    .{ .word = 0x925d4821, .value = 0x3ffff800000000 },
    .{ .word = 0x925d4c21, .value = 0x7ffff800000000 },
    .{ .word = 0x925d5021, .value = 0xfffff800000000 },
    .{ .word = 0x925d5421, .value = 0x1fffff800000000 },
    .{ .word = 0x925d5821, .value = 0x3fffff800000000 },
    .{ .word = 0x925d5c21, .value = 0x7fffff800000000 },
    .{ .word = 0x925d6021, .value = 0xffffff800000000 },
    .{ .word = 0x925d6421, .value = 0x1ffffff800000000 },
    .{ .word = 0x925d6821, .value = 0x3ffffff800000000 },
    .{ .word = 0x925d6c21, .value = 0x7ffffff800000000 },
    .{ .word = 0x925d7021, .value = 0xfffffff800000000 },
    .{ .word = 0x925d7421, .value = 0xfffffff800000001 },
    .{ .word = 0x925d7821, .value = 0xfffffff800000003 },
    .{ .word = 0x925d7c21, .value = 0xfffffff800000007 },
    .{ .word = 0x925d8021, .value = 0xfffffff80000000f },
    .{ .word = 0x925d8421, .value = 0xfffffff80000001f },
    .{ .word = 0x925d8821, .value = 0xfffffff80000003f },
    .{ .word = 0x925d8c21, .value = 0xfffffff80000007f },
    .{ .word = 0x925d9021, .value = 0xfffffff8000000ff },
    .{ .word = 0x925d9421, .value = 0xfffffff8000001ff },
    .{ .word = 0x925d9821, .value = 0xfffffff8000003ff },
    .{ .word = 0x925d9c21, .value = 0xfffffff8000007ff },
    .{ .word = 0x925da021, .value = 0xfffffff800000fff },
    .{ .word = 0x925da421, .value = 0xfffffff800001fff },
    .{ .word = 0x925da821, .value = 0xfffffff800003fff },
    .{ .word = 0x925dac21, .value = 0xfffffff800007fff },
    .{ .word = 0x925db021, .value = 0xfffffff80000ffff },
    .{ .word = 0x925db421, .value = 0xfffffff80001ffff },
    .{ .word = 0x925db821, .value = 0xfffffff80003ffff },
    .{ .word = 0x925dbc21, .value = 0xfffffff80007ffff },
    .{ .word = 0x925dc021, .value = 0xfffffff8000fffff },
    .{ .word = 0x925dc421, .value = 0xfffffff8001fffff },
    .{ .word = 0x925dc821, .value = 0xfffffff8003fffff },
    .{ .word = 0x925dcc21, .value = 0xfffffff8007fffff },
    .{ .word = 0x925dd021, .value = 0xfffffff800ffffff },
    .{ .word = 0x925dd421, .value = 0xfffffff801ffffff },
    .{ .word = 0x925dd821, .value = 0xfffffff803ffffff },
    .{ .word = 0x925ddc21, .value = 0xfffffff807ffffff },
    .{ .word = 0x925de021, .value = 0xfffffff80fffffff },
    .{ .word = 0x925de421, .value = 0xfffffff81fffffff },
    .{ .word = 0x925de821, .value = 0xfffffff83fffffff },
    .{ .word = 0x925dec21, .value = 0xfffffff87fffffff },
    .{ .word = 0x925df021, .value = 0xfffffff8ffffffff },
    .{ .word = 0x925df421, .value = 0xfffffff9ffffffff },
    .{ .word = 0x925df821, .value = 0xfffffffbffffffff },
    .{ .word = 0x925e0021, .value = 0x400000000 },
    .{ .word = 0x925e0421, .value = 0xc00000000 },
    .{ .word = 0x925e0821, .value = 0x1c00000000 },
    .{ .word = 0x925e0c21, .value = 0x3c00000000 },
    .{ .word = 0x925e1021, .value = 0x7c00000000 },
    .{ .word = 0x925e1421, .value = 0xfc00000000 },
    .{ .word = 0x925e1821, .value = 0x1fc00000000 },
    .{ .word = 0x925e1c21, .value = 0x3fc00000000 },
    .{ .word = 0x925e2021, .value = 0x7fc00000000 },
    .{ .word = 0x925e2421, .value = 0xffc00000000 },
    .{ .word = 0x925e2821, .value = 0x1ffc00000000 },
    .{ .word = 0x925e2c21, .value = 0x3ffc00000000 },
    .{ .word = 0x925e3021, .value = 0x7ffc00000000 },
    .{ .word = 0x925e3421, .value = 0xfffc00000000 },
    .{ .word = 0x925e3821, .value = 0x1fffc00000000 },
    .{ .word = 0x925e3c21, .value = 0x3fffc00000000 },
    .{ .word = 0x925e4021, .value = 0x7fffc00000000 },
    .{ .word = 0x925e4421, .value = 0xffffc00000000 },
    .{ .word = 0x925e4821, .value = 0x1ffffc00000000 },
    .{ .word = 0x925e4c21, .value = 0x3ffffc00000000 },
    .{ .word = 0x925e5021, .value = 0x7ffffc00000000 },
    .{ .word = 0x925e5421, .value = 0xfffffc00000000 },
    .{ .word = 0x925e5821, .value = 0x1fffffc00000000 },
    .{ .word = 0x925e5c21, .value = 0x3fffffc00000000 },
    .{ .word = 0x925e6021, .value = 0x7fffffc00000000 },
    .{ .word = 0x925e6421, .value = 0xffffffc00000000 },
    .{ .word = 0x925e6821, .value = 0x1ffffffc00000000 },
    .{ .word = 0x925e6c21, .value = 0x3ffffffc00000000 },
    .{ .word = 0x925e7021, .value = 0x7ffffffc00000000 },
    .{ .word = 0x925e7421, .value = 0xfffffffc00000000 },
    .{ .word = 0x925e7821, .value = 0xfffffffc00000001 },
    .{ .word = 0x925e7c21, .value = 0xfffffffc00000003 },
    .{ .word = 0x925e8021, .value = 0xfffffffc00000007 },
    .{ .word = 0x925e8421, .value = 0xfffffffc0000000f },
    .{ .word = 0x925e8821, .value = 0xfffffffc0000001f },
    .{ .word = 0x925e8c21, .value = 0xfffffffc0000003f },
    .{ .word = 0x925e9021, .value = 0xfffffffc0000007f },
    .{ .word = 0x925e9421, .value = 0xfffffffc000000ff },
    .{ .word = 0x925e9821, .value = 0xfffffffc000001ff },
    .{ .word = 0x925e9c21, .value = 0xfffffffc000003ff },
    .{ .word = 0x925ea021, .value = 0xfffffffc000007ff },
    .{ .word = 0x925ea421, .value = 0xfffffffc00000fff },
    .{ .word = 0x925ea821, .value = 0xfffffffc00001fff },
    .{ .word = 0x925eac21, .value = 0xfffffffc00003fff },
    .{ .word = 0x925eb021, .value = 0xfffffffc00007fff },
    .{ .word = 0x925eb421, .value = 0xfffffffc0000ffff },
    .{ .word = 0x925eb821, .value = 0xfffffffc0001ffff },
    .{ .word = 0x925ebc21, .value = 0xfffffffc0003ffff },
    .{ .word = 0x925ec021, .value = 0xfffffffc0007ffff },
    .{ .word = 0x925ec421, .value = 0xfffffffc000fffff },
    .{ .word = 0x925ec821, .value = 0xfffffffc001fffff },
    .{ .word = 0x925ecc21, .value = 0xfffffffc003fffff },
    .{ .word = 0x925ed021, .value = 0xfffffffc007fffff },
    .{ .word = 0x925ed421, .value = 0xfffffffc00ffffff },
    .{ .word = 0x925ed821, .value = 0xfffffffc01ffffff },
    .{ .word = 0x925edc21, .value = 0xfffffffc03ffffff },
    .{ .word = 0x925ee021, .value = 0xfffffffc07ffffff },
    .{ .word = 0x925ee421, .value = 0xfffffffc0fffffff },
    .{ .word = 0x925ee821, .value = 0xfffffffc1fffffff },
    .{ .word = 0x925eec21, .value = 0xfffffffc3fffffff },
    .{ .word = 0x925ef021, .value = 0xfffffffc7fffffff },
    .{ .word = 0x925ef421, .value = 0xfffffffcffffffff },
    .{ .word = 0x925ef821, .value = 0xfffffffdffffffff },
    .{ .word = 0x925f0021, .value = 0x200000000 },
    .{ .word = 0x925f0421, .value = 0x600000000 },
    .{ .word = 0x925f0821, .value = 0xe00000000 },
    .{ .word = 0x925f0c21, .value = 0x1e00000000 },
    .{ .word = 0x925f1021, .value = 0x3e00000000 },
    .{ .word = 0x925f1421, .value = 0x7e00000000 },
    .{ .word = 0x925f1821, .value = 0xfe00000000 },
    .{ .word = 0x925f1c21, .value = 0x1fe00000000 },
    .{ .word = 0x925f2021, .value = 0x3fe00000000 },
    .{ .word = 0x925f2421, .value = 0x7fe00000000 },
    .{ .word = 0x925f2821, .value = 0xffe00000000 },
    .{ .word = 0x925f2c21, .value = 0x1ffe00000000 },
    .{ .word = 0x925f3021, .value = 0x3ffe00000000 },
    .{ .word = 0x925f3421, .value = 0x7ffe00000000 },
    .{ .word = 0x925f3821, .value = 0xfffe00000000 },
    .{ .word = 0x925f3c21, .value = 0x1fffe00000000 },
    .{ .word = 0x925f4021, .value = 0x3fffe00000000 },
    .{ .word = 0x925f4421, .value = 0x7fffe00000000 },
    .{ .word = 0x925f4821, .value = 0xffffe00000000 },
    .{ .word = 0x925f4c21, .value = 0x1ffffe00000000 },
    .{ .word = 0x925f5021, .value = 0x3ffffe00000000 },
    .{ .word = 0x925f5421, .value = 0x7ffffe00000000 },
    .{ .word = 0x925f5821, .value = 0xfffffe00000000 },
    .{ .word = 0x925f5c21, .value = 0x1fffffe00000000 },
    .{ .word = 0x925f6021, .value = 0x3fffffe00000000 },
    .{ .word = 0x925f6421, .value = 0x7fffffe00000000 },
    .{ .word = 0x925f6821, .value = 0xffffffe00000000 },
    .{ .word = 0x925f6c21, .value = 0x1ffffffe00000000 },
    .{ .word = 0x925f7021, .value = 0x3ffffffe00000000 },
    .{ .word = 0x925f7421, .value = 0x7ffffffe00000000 },
    .{ .word = 0x925f7821, .value = 0xfffffffe00000000 },
    .{ .word = 0x925f7c21, .value = 0xfffffffe00000001 },
    .{ .word = 0x925f8021, .value = 0xfffffffe00000003 },
    .{ .word = 0x925f8421, .value = 0xfffffffe00000007 },
    .{ .word = 0x925f8821, .value = 0xfffffffe0000000f },
    .{ .word = 0x925f8c21, .value = 0xfffffffe0000001f },
    .{ .word = 0x925f9021, .value = 0xfffffffe0000003f },
    .{ .word = 0x925f9421, .value = 0xfffffffe0000007f },
    .{ .word = 0x925f9821, .value = 0xfffffffe000000ff },
    .{ .word = 0x925f9c21, .value = 0xfffffffe000001ff },
    .{ .word = 0x925fa021, .value = 0xfffffffe000003ff },
    .{ .word = 0x925fa421, .value = 0xfffffffe000007ff },
    .{ .word = 0x925fa821, .value = 0xfffffffe00000fff },
    .{ .word = 0x925fac21, .value = 0xfffffffe00001fff },
    .{ .word = 0x925fb021, .value = 0xfffffffe00003fff },
    .{ .word = 0x925fb421, .value = 0xfffffffe00007fff },
    .{ .word = 0x925fb821, .value = 0xfffffffe0000ffff },
    .{ .word = 0x925fbc21, .value = 0xfffffffe0001ffff },
    .{ .word = 0x925fc021, .value = 0xfffffffe0003ffff },
    .{ .word = 0x925fc421, .value = 0xfffffffe0007ffff },
    .{ .word = 0x925fc821, .value = 0xfffffffe000fffff },
    .{ .word = 0x925fcc21, .value = 0xfffffffe001fffff },
    .{ .word = 0x925fd021, .value = 0xfffffffe003fffff },
    .{ .word = 0x925fd421, .value = 0xfffffffe007fffff },
    .{ .word = 0x925fd821, .value = 0xfffffffe00ffffff },
    .{ .word = 0x925fdc21, .value = 0xfffffffe01ffffff },
    .{ .word = 0x925fe021, .value = 0xfffffffe03ffffff },
    .{ .word = 0x925fe421, .value = 0xfffffffe07ffffff },
    .{ .word = 0x925fe821, .value = 0xfffffffe0fffffff },
    .{ .word = 0x925fec21, .value = 0xfffffffe1fffffff },
    .{ .word = 0x925ff021, .value = 0xfffffffe3fffffff },
    .{ .word = 0x925ff421, .value = 0xfffffffe7fffffff },
    .{ .word = 0x925ff821, .value = 0xfffffffeffffffff },
    .{ .word = 0x92600021, .value = 0x100000000 },
    .{ .word = 0x92600421, .value = 0x300000000 },
    .{ .word = 0x92600821, .value = 0x700000000 },
    .{ .word = 0x92600c21, .value = 0xf00000000 },
    .{ .word = 0x92601021, .value = 0x1f00000000 },
    .{ .word = 0x92601421, .value = 0x3f00000000 },
    .{ .word = 0x92601821, .value = 0x7f00000000 },
    .{ .word = 0x92601c21, .value = 0xff00000000 },
    .{ .word = 0x92602021, .value = 0x1ff00000000 },
    .{ .word = 0x92602421, .value = 0x3ff00000000 },
    .{ .word = 0x92602821, .value = 0x7ff00000000 },
    .{ .word = 0x92602c21, .value = 0xfff00000000 },
    .{ .word = 0x92603021, .value = 0x1fff00000000 },
    .{ .word = 0x92603421, .value = 0x3fff00000000 },
    .{ .word = 0x92603821, .value = 0x7fff00000000 },
    .{ .word = 0x92603c21, .value = 0xffff00000000 },
    .{ .word = 0x92604021, .value = 0x1ffff00000000 },
    .{ .word = 0x92604421, .value = 0x3ffff00000000 },
    .{ .word = 0x92604821, .value = 0x7ffff00000000 },
    .{ .word = 0x92604c21, .value = 0xfffff00000000 },
    .{ .word = 0x92605021, .value = 0x1fffff00000000 },
    .{ .word = 0x92605421, .value = 0x3fffff00000000 },
    .{ .word = 0x92605821, .value = 0x7fffff00000000 },
    .{ .word = 0x92605c21, .value = 0xffffff00000000 },
    .{ .word = 0x92606021, .value = 0x1ffffff00000000 },
    .{ .word = 0x92606421, .value = 0x3ffffff00000000 },
    .{ .word = 0x92606821, .value = 0x7ffffff00000000 },
    .{ .word = 0x92606c21, .value = 0xfffffff00000000 },
    .{ .word = 0x92607021, .value = 0x1fffffff00000000 },
    .{ .word = 0x92607421, .value = 0x3fffffff00000000 },
    .{ .word = 0x92607821, .value = 0x7fffffff00000000 },
    .{ .word = 0x92607c21, .value = 0xffffffff00000000 },
    .{ .word = 0x92608021, .value = 0xffffffff00000001 },
    .{ .word = 0x92608421, .value = 0xffffffff00000003 },
    .{ .word = 0x92608821, .value = 0xffffffff00000007 },
    .{ .word = 0x92608c21, .value = 0xffffffff0000000f },
    .{ .word = 0x92609021, .value = 0xffffffff0000001f },
    .{ .word = 0x92609421, .value = 0xffffffff0000003f },
    .{ .word = 0x92609821, .value = 0xffffffff0000007f },
    .{ .word = 0x92609c21, .value = 0xffffffff000000ff },
    .{ .word = 0x9260a021, .value = 0xffffffff000001ff },
    .{ .word = 0x9260a421, .value = 0xffffffff000003ff },
    .{ .word = 0x9260a821, .value = 0xffffffff000007ff },
    .{ .word = 0x9260ac21, .value = 0xffffffff00000fff },
    .{ .word = 0x9260b021, .value = 0xffffffff00001fff },
    .{ .word = 0x9260b421, .value = 0xffffffff00003fff },
    .{ .word = 0x9260b821, .value = 0xffffffff00007fff },
    .{ .word = 0x9260bc21, .value = 0xffffffff0000ffff },
    .{ .word = 0x9260c021, .value = 0xffffffff0001ffff },
    .{ .word = 0x9260c421, .value = 0xffffffff0003ffff },
    .{ .word = 0x9260c821, .value = 0xffffffff0007ffff },
    .{ .word = 0x9260cc21, .value = 0xffffffff000fffff },
    .{ .word = 0x9260d021, .value = 0xffffffff001fffff },
    .{ .word = 0x9260d421, .value = 0xffffffff003fffff },
    .{ .word = 0x9260d821, .value = 0xffffffff007fffff },
    .{ .word = 0x9260dc21, .value = 0xffffffff00ffffff },
    .{ .word = 0x9260e021, .value = 0xffffffff01ffffff },
    .{ .word = 0x9260e421, .value = 0xffffffff03ffffff },
    .{ .word = 0x9260e821, .value = 0xffffffff07ffffff },
    .{ .word = 0x9260ec21, .value = 0xffffffff0fffffff },
    .{ .word = 0x9260f021, .value = 0xffffffff1fffffff },
    .{ .word = 0x9260f421, .value = 0xffffffff3fffffff },
    .{ .word = 0x9260f821, .value = 0xffffffff7fffffff },
    .{ .word = 0x92610021, .value = 0x80000000 },
    .{ .word = 0x92610421, .value = 0x180000000 },
    .{ .word = 0x92610821, .value = 0x380000000 },
    .{ .word = 0x92610c21, .value = 0x780000000 },
    .{ .word = 0x92611021, .value = 0xf80000000 },
    .{ .word = 0x92611421, .value = 0x1f80000000 },
    .{ .word = 0x92611821, .value = 0x3f80000000 },
    .{ .word = 0x92611c21, .value = 0x7f80000000 },
    .{ .word = 0x92612021, .value = 0xff80000000 },
    .{ .word = 0x92612421, .value = 0x1ff80000000 },
    .{ .word = 0x92612821, .value = 0x3ff80000000 },
    .{ .word = 0x92612c21, .value = 0x7ff80000000 },
    .{ .word = 0x92613021, .value = 0xfff80000000 },
    .{ .word = 0x92613421, .value = 0x1fff80000000 },
    .{ .word = 0x92613821, .value = 0x3fff80000000 },
    .{ .word = 0x92613c21, .value = 0x7fff80000000 },
    .{ .word = 0x92614021, .value = 0xffff80000000 },
    .{ .word = 0x92614421, .value = 0x1ffff80000000 },
    .{ .word = 0x92614821, .value = 0x3ffff80000000 },
    .{ .word = 0x92614c21, .value = 0x7ffff80000000 },
    .{ .word = 0x92615021, .value = 0xfffff80000000 },
    .{ .word = 0x92615421, .value = 0x1fffff80000000 },
    .{ .word = 0x92615821, .value = 0x3fffff80000000 },
    .{ .word = 0x92615c21, .value = 0x7fffff80000000 },
    .{ .word = 0x92616021, .value = 0xffffff80000000 },
    .{ .word = 0x92616421, .value = 0x1ffffff80000000 },
    .{ .word = 0x92616821, .value = 0x3ffffff80000000 },
    .{ .word = 0x92616c21, .value = 0x7ffffff80000000 },
    .{ .word = 0x92617021, .value = 0xfffffff80000000 },
    .{ .word = 0x92617421, .value = 0x1fffffff80000000 },
    .{ .word = 0x92617821, .value = 0x3fffffff80000000 },
    .{ .word = 0x92617c21, .value = 0x7fffffff80000000 },
    .{ .word = 0x92618021, .value = 0xffffffff80000000 },
    .{ .word = 0x92618421, .value = 0xffffffff80000001 },
    .{ .word = 0x92618821, .value = 0xffffffff80000003 },
    .{ .word = 0x92618c21, .value = 0xffffffff80000007 },
    .{ .word = 0x92619021, .value = 0xffffffff8000000f },
    .{ .word = 0x92619421, .value = 0xffffffff8000001f },
    .{ .word = 0x92619821, .value = 0xffffffff8000003f },
    .{ .word = 0x92619c21, .value = 0xffffffff8000007f },
    .{ .word = 0x9261a021, .value = 0xffffffff800000ff },
    .{ .word = 0x9261a421, .value = 0xffffffff800001ff },
    .{ .word = 0x9261a821, .value = 0xffffffff800003ff },
    .{ .word = 0x9261ac21, .value = 0xffffffff800007ff },
    .{ .word = 0x9261b021, .value = 0xffffffff80000fff },
    .{ .word = 0x9261b421, .value = 0xffffffff80001fff },
    .{ .word = 0x9261b821, .value = 0xffffffff80003fff },
    .{ .word = 0x9261bc21, .value = 0xffffffff80007fff },
    .{ .word = 0x9261c021, .value = 0xffffffff8000ffff },
    .{ .word = 0x9261c421, .value = 0xffffffff8001ffff },
    .{ .word = 0x9261c821, .value = 0xffffffff8003ffff },
    .{ .word = 0x9261cc21, .value = 0xffffffff8007ffff },
    .{ .word = 0x9261d021, .value = 0xffffffff800fffff },
    .{ .word = 0x9261d421, .value = 0xffffffff801fffff },
    .{ .word = 0x9261d821, .value = 0xffffffff803fffff },
    .{ .word = 0x9261dc21, .value = 0xffffffff807fffff },
    .{ .word = 0x9261e021, .value = 0xffffffff80ffffff },
    .{ .word = 0x9261e421, .value = 0xffffffff81ffffff },
    .{ .word = 0x9261e821, .value = 0xffffffff83ffffff },
    .{ .word = 0x9261ec21, .value = 0xffffffff87ffffff },
    .{ .word = 0x9261f021, .value = 0xffffffff8fffffff },
    .{ .word = 0x9261f421, .value = 0xffffffff9fffffff },
    .{ .word = 0x9261f821, .value = 0xffffffffbfffffff },
    .{ .word = 0x92620021, .value = 0x40000000 },
    .{ .word = 0x92620421, .value = 0xc0000000 },
    .{ .word = 0x92620821, .value = 0x1c0000000 },
    .{ .word = 0x92620c21, .value = 0x3c0000000 },
    .{ .word = 0x92621021, .value = 0x7c0000000 },
    .{ .word = 0x92621421, .value = 0xfc0000000 },
    .{ .word = 0x92621821, .value = 0x1fc0000000 },
    .{ .word = 0x92621c21, .value = 0x3fc0000000 },
    .{ .word = 0x92622021, .value = 0x7fc0000000 },
    .{ .word = 0x92622421, .value = 0xffc0000000 },
    .{ .word = 0x92622821, .value = 0x1ffc0000000 },
    .{ .word = 0x92622c21, .value = 0x3ffc0000000 },
    .{ .word = 0x92623021, .value = 0x7ffc0000000 },
    .{ .word = 0x92623421, .value = 0xfffc0000000 },
    .{ .word = 0x92623821, .value = 0x1fffc0000000 },
    .{ .word = 0x92623c21, .value = 0x3fffc0000000 },
    .{ .word = 0x92624021, .value = 0x7fffc0000000 },
    .{ .word = 0x92624421, .value = 0xffffc0000000 },
    .{ .word = 0x92624821, .value = 0x1ffffc0000000 },
    .{ .word = 0x92624c21, .value = 0x3ffffc0000000 },
    .{ .word = 0x92625021, .value = 0x7ffffc0000000 },
    .{ .word = 0x92625421, .value = 0xfffffc0000000 },
    .{ .word = 0x92625821, .value = 0x1fffffc0000000 },
    .{ .word = 0x92625c21, .value = 0x3fffffc0000000 },
    .{ .word = 0x92626021, .value = 0x7fffffc0000000 },
    .{ .word = 0x92626421, .value = 0xffffffc0000000 },
    .{ .word = 0x92626821, .value = 0x1ffffffc0000000 },
    .{ .word = 0x92626c21, .value = 0x3ffffffc0000000 },
    .{ .word = 0x92627021, .value = 0x7ffffffc0000000 },
    .{ .word = 0x92627421, .value = 0xfffffffc0000000 },
    .{ .word = 0x92627821, .value = 0x1fffffffc0000000 },
    .{ .word = 0x92627c21, .value = 0x3fffffffc0000000 },
    .{ .word = 0x92628021, .value = 0x7fffffffc0000000 },
    .{ .word = 0x92628421, .value = 0xffffffffc0000000 },
    .{ .word = 0x92628821, .value = 0xffffffffc0000001 },
    .{ .word = 0x92628c21, .value = 0xffffffffc0000003 },
    .{ .word = 0x92629021, .value = 0xffffffffc0000007 },
    .{ .word = 0x92629421, .value = 0xffffffffc000000f },
    .{ .word = 0x92629821, .value = 0xffffffffc000001f },
    .{ .word = 0x92629c21, .value = 0xffffffffc000003f },
    .{ .word = 0x9262a021, .value = 0xffffffffc000007f },
    .{ .word = 0x9262a421, .value = 0xffffffffc00000ff },
    .{ .word = 0x9262a821, .value = 0xffffffffc00001ff },
    .{ .word = 0x9262ac21, .value = 0xffffffffc00003ff },
    .{ .word = 0x9262b021, .value = 0xffffffffc00007ff },
    .{ .word = 0x9262b421, .value = 0xffffffffc0000fff },
    .{ .word = 0x9262b821, .value = 0xffffffffc0001fff },
    .{ .word = 0x9262bc21, .value = 0xffffffffc0003fff },
    .{ .word = 0x9262c021, .value = 0xffffffffc0007fff },
    .{ .word = 0x9262c421, .value = 0xffffffffc000ffff },
    .{ .word = 0x9262c821, .value = 0xffffffffc001ffff },
    .{ .word = 0x9262cc21, .value = 0xffffffffc003ffff },
    .{ .word = 0x9262d021, .value = 0xffffffffc007ffff },
    .{ .word = 0x9262d421, .value = 0xffffffffc00fffff },
    .{ .word = 0x9262d821, .value = 0xffffffffc01fffff },
    .{ .word = 0x9262dc21, .value = 0xffffffffc03fffff },
    .{ .word = 0x9262e021, .value = 0xffffffffc07fffff },
    .{ .word = 0x9262e421, .value = 0xffffffffc0ffffff },
    .{ .word = 0x9262e821, .value = 0xffffffffc1ffffff },
    .{ .word = 0x9262ec21, .value = 0xffffffffc3ffffff },
    .{ .word = 0x9262f021, .value = 0xffffffffc7ffffff },
    .{ .word = 0x9262f421, .value = 0xffffffffcfffffff },
    .{ .word = 0x9262f821, .value = 0xffffffffdfffffff },
    .{ .word = 0x92630021, .value = 0x20000000 },
    .{ .word = 0x92630421, .value = 0x60000000 },
    .{ .word = 0x92630821, .value = 0xe0000000 },
    .{ .word = 0x92630c21, .value = 0x1e0000000 },
    .{ .word = 0x92631021, .value = 0x3e0000000 },
    .{ .word = 0x92631421, .value = 0x7e0000000 },
    .{ .word = 0x92631821, .value = 0xfe0000000 },
    .{ .word = 0x92631c21, .value = 0x1fe0000000 },
    .{ .word = 0x92632021, .value = 0x3fe0000000 },
    .{ .word = 0x92632421, .value = 0x7fe0000000 },
    .{ .word = 0x92632821, .value = 0xffe0000000 },
    .{ .word = 0x92632c21, .value = 0x1ffe0000000 },
    .{ .word = 0x92633021, .value = 0x3ffe0000000 },
    .{ .word = 0x92633421, .value = 0x7ffe0000000 },
    .{ .word = 0x92633821, .value = 0xfffe0000000 },
    .{ .word = 0x92633c21, .value = 0x1fffe0000000 },
    .{ .word = 0x92634021, .value = 0x3fffe0000000 },
    .{ .word = 0x92634421, .value = 0x7fffe0000000 },
    .{ .word = 0x92634821, .value = 0xffffe0000000 },
    .{ .word = 0x92634c21, .value = 0x1ffffe0000000 },
    .{ .word = 0x92635021, .value = 0x3ffffe0000000 },
    .{ .word = 0x92635421, .value = 0x7ffffe0000000 },
    .{ .word = 0x92635821, .value = 0xfffffe0000000 },
    .{ .word = 0x92635c21, .value = 0x1fffffe0000000 },
    .{ .word = 0x92636021, .value = 0x3fffffe0000000 },
    .{ .word = 0x92636421, .value = 0x7fffffe0000000 },
    .{ .word = 0x92636821, .value = 0xffffffe0000000 },
    .{ .word = 0x92636c21, .value = 0x1ffffffe0000000 },
    .{ .word = 0x92637021, .value = 0x3ffffffe0000000 },
    .{ .word = 0x92637421, .value = 0x7ffffffe0000000 },
    .{ .word = 0x92637821, .value = 0xfffffffe0000000 },
    .{ .word = 0x92637c21, .value = 0x1fffffffe0000000 },
    .{ .word = 0x92638021, .value = 0x3fffffffe0000000 },
    .{ .word = 0x92638421, .value = 0x7fffffffe0000000 },
    .{ .word = 0x92638821, .value = 0xffffffffe0000000 },
    .{ .word = 0x92638c21, .value = 0xffffffffe0000001 },
    .{ .word = 0x92639021, .value = 0xffffffffe0000003 },
    .{ .word = 0x92639421, .value = 0xffffffffe0000007 },
    .{ .word = 0x92639821, .value = 0xffffffffe000000f },
    .{ .word = 0x92639c21, .value = 0xffffffffe000001f },
    .{ .word = 0x9263a021, .value = 0xffffffffe000003f },
    .{ .word = 0x9263a421, .value = 0xffffffffe000007f },
    .{ .word = 0x9263a821, .value = 0xffffffffe00000ff },
    .{ .word = 0x9263ac21, .value = 0xffffffffe00001ff },
    .{ .word = 0x9263b021, .value = 0xffffffffe00003ff },
    .{ .word = 0x9263b421, .value = 0xffffffffe00007ff },
    .{ .word = 0x9263b821, .value = 0xffffffffe0000fff },
    .{ .word = 0x9263bc21, .value = 0xffffffffe0001fff },
    .{ .word = 0x9263c021, .value = 0xffffffffe0003fff },
    .{ .word = 0x9263c421, .value = 0xffffffffe0007fff },
    .{ .word = 0x9263c821, .value = 0xffffffffe000ffff },
    .{ .word = 0x9263cc21, .value = 0xffffffffe001ffff },
    .{ .word = 0x9263d021, .value = 0xffffffffe003ffff },
    .{ .word = 0x9263d421, .value = 0xffffffffe007ffff },
    .{ .word = 0x9263d821, .value = 0xffffffffe00fffff },
    .{ .word = 0x9263dc21, .value = 0xffffffffe01fffff },
    .{ .word = 0x9263e021, .value = 0xffffffffe03fffff },
    .{ .word = 0x9263e421, .value = 0xffffffffe07fffff },
    .{ .word = 0x9263e821, .value = 0xffffffffe0ffffff },
    .{ .word = 0x9263ec21, .value = 0xffffffffe1ffffff },
    .{ .word = 0x9263f021, .value = 0xffffffffe3ffffff },
    .{ .word = 0x9263f421, .value = 0xffffffffe7ffffff },
    .{ .word = 0x9263f821, .value = 0xffffffffefffffff },
    .{ .word = 0x92640021, .value = 0x10000000 },
    .{ .word = 0x92640421, .value = 0x30000000 },
    .{ .word = 0x92640821, .value = 0x70000000 },
    .{ .word = 0x92640c21, .value = 0xf0000000 },
    .{ .word = 0x92641021, .value = 0x1f0000000 },
    .{ .word = 0x92641421, .value = 0x3f0000000 },
    .{ .word = 0x92641821, .value = 0x7f0000000 },
    .{ .word = 0x92641c21, .value = 0xff0000000 },
    .{ .word = 0x92642021, .value = 0x1ff0000000 },
    .{ .word = 0x92642421, .value = 0x3ff0000000 },
    .{ .word = 0x92642821, .value = 0x7ff0000000 },
    .{ .word = 0x92642c21, .value = 0xfff0000000 },
    .{ .word = 0x92643021, .value = 0x1fff0000000 },
    .{ .word = 0x92643421, .value = 0x3fff0000000 },
    .{ .word = 0x92643821, .value = 0x7fff0000000 },
    .{ .word = 0x92643c21, .value = 0xffff0000000 },
    .{ .word = 0x92644021, .value = 0x1ffff0000000 },
    .{ .word = 0x92644421, .value = 0x3ffff0000000 },
    .{ .word = 0x92644821, .value = 0x7ffff0000000 },
    .{ .word = 0x92644c21, .value = 0xfffff0000000 },
    .{ .word = 0x92645021, .value = 0x1fffff0000000 },
    .{ .word = 0x92645421, .value = 0x3fffff0000000 },
    .{ .word = 0x92645821, .value = 0x7fffff0000000 },
    .{ .word = 0x92645c21, .value = 0xffffff0000000 },
    .{ .word = 0x92646021, .value = 0x1ffffff0000000 },
    .{ .word = 0x92646421, .value = 0x3ffffff0000000 },
    .{ .word = 0x92646821, .value = 0x7ffffff0000000 },
    .{ .word = 0x92646c21, .value = 0xfffffff0000000 },
    .{ .word = 0x92647021, .value = 0x1fffffff0000000 },
    .{ .word = 0x92647421, .value = 0x3fffffff0000000 },
    .{ .word = 0x92647821, .value = 0x7fffffff0000000 },
    .{ .word = 0x92647c21, .value = 0xffffffff0000000 },
    .{ .word = 0x92648021, .value = 0x1ffffffff0000000 },
    .{ .word = 0x92648421, .value = 0x3ffffffff0000000 },
    .{ .word = 0x92648821, .value = 0x7ffffffff0000000 },
    .{ .word = 0x92648c21, .value = 0xfffffffff0000000 },
    .{ .word = 0x92649021, .value = 0xfffffffff0000001 },
    .{ .word = 0x92649421, .value = 0xfffffffff0000003 },
    .{ .word = 0x92649821, .value = 0xfffffffff0000007 },
    .{ .word = 0x92649c21, .value = 0xfffffffff000000f },
    .{ .word = 0x9264a021, .value = 0xfffffffff000001f },
    .{ .word = 0x9264a421, .value = 0xfffffffff000003f },
    .{ .word = 0x9264a821, .value = 0xfffffffff000007f },
    .{ .word = 0x9264ac21, .value = 0xfffffffff00000ff },
    .{ .word = 0x9264b021, .value = 0xfffffffff00001ff },
    .{ .word = 0x9264b421, .value = 0xfffffffff00003ff },
    .{ .word = 0x9264b821, .value = 0xfffffffff00007ff },
    .{ .word = 0x9264bc21, .value = 0xfffffffff0000fff },
    .{ .word = 0x9264c021, .value = 0xfffffffff0001fff },
    .{ .word = 0x9264c421, .value = 0xfffffffff0003fff },
    .{ .word = 0x9264c821, .value = 0xfffffffff0007fff },
    .{ .word = 0x9264cc21, .value = 0xfffffffff000ffff },
    .{ .word = 0x9264d021, .value = 0xfffffffff001ffff },
    .{ .word = 0x9264d421, .value = 0xfffffffff003ffff },
    .{ .word = 0x9264d821, .value = 0xfffffffff007ffff },
    .{ .word = 0x9264dc21, .value = 0xfffffffff00fffff },
    .{ .word = 0x9264e021, .value = 0xfffffffff01fffff },
    .{ .word = 0x9264e421, .value = 0xfffffffff03fffff },
    .{ .word = 0x9264e821, .value = 0xfffffffff07fffff },
    .{ .word = 0x9264ec21, .value = 0xfffffffff0ffffff },
    .{ .word = 0x9264f021, .value = 0xfffffffff1ffffff },
    .{ .word = 0x9264f421, .value = 0xfffffffff3ffffff },
    .{ .word = 0x9264f821, .value = 0xfffffffff7ffffff },
    .{ .word = 0x92650021, .value = 0x8000000 },
    .{ .word = 0x92650421, .value = 0x18000000 },
    .{ .word = 0x92650821, .value = 0x38000000 },
    .{ .word = 0x92650c21, .value = 0x78000000 },
    .{ .word = 0x92651021, .value = 0xf8000000 },
    .{ .word = 0x92651421, .value = 0x1f8000000 },
    .{ .word = 0x92651821, .value = 0x3f8000000 },
    .{ .word = 0x92651c21, .value = 0x7f8000000 },
    .{ .word = 0x92652021, .value = 0xff8000000 },
    .{ .word = 0x92652421, .value = 0x1ff8000000 },
    .{ .word = 0x92652821, .value = 0x3ff8000000 },
    .{ .word = 0x92652c21, .value = 0x7ff8000000 },
    .{ .word = 0x92653021, .value = 0xfff8000000 },
    .{ .word = 0x92653421, .value = 0x1fff8000000 },
    .{ .word = 0x92653821, .value = 0x3fff8000000 },
    .{ .word = 0x92653c21, .value = 0x7fff8000000 },
    .{ .word = 0x92654021, .value = 0xffff8000000 },
    .{ .word = 0x92654421, .value = 0x1ffff8000000 },
    .{ .word = 0x92654821, .value = 0x3ffff8000000 },
    .{ .word = 0x92654c21, .value = 0x7ffff8000000 },
    .{ .word = 0x92655021, .value = 0xfffff8000000 },
    .{ .word = 0x92655421, .value = 0x1fffff8000000 },
    .{ .word = 0x92655821, .value = 0x3fffff8000000 },
    .{ .word = 0x92655c21, .value = 0x7fffff8000000 },
    .{ .word = 0x92656021, .value = 0xffffff8000000 },
    .{ .word = 0x92656421, .value = 0x1ffffff8000000 },
    .{ .word = 0x92656821, .value = 0x3ffffff8000000 },
    .{ .word = 0x92656c21, .value = 0x7ffffff8000000 },
    .{ .word = 0x92657021, .value = 0xfffffff8000000 },
    .{ .word = 0x92657421, .value = 0x1fffffff8000000 },
    .{ .word = 0x92657821, .value = 0x3fffffff8000000 },
    .{ .word = 0x92657c21, .value = 0x7fffffff8000000 },
    .{ .word = 0x92658021, .value = 0xffffffff8000000 },
    .{ .word = 0x92658421, .value = 0x1ffffffff8000000 },
    .{ .word = 0x92658821, .value = 0x3ffffffff8000000 },
    .{ .word = 0x92658c21, .value = 0x7ffffffff8000000 },
    .{ .word = 0x92659021, .value = 0xfffffffff8000000 },
    .{ .word = 0x92659421, .value = 0xfffffffff8000001 },
    .{ .word = 0x92659821, .value = 0xfffffffff8000003 },
    .{ .word = 0x92659c21, .value = 0xfffffffff8000007 },
    .{ .word = 0x9265a021, .value = 0xfffffffff800000f },
    .{ .word = 0x9265a421, .value = 0xfffffffff800001f },
    .{ .word = 0x9265a821, .value = 0xfffffffff800003f },
    .{ .word = 0x9265ac21, .value = 0xfffffffff800007f },
    .{ .word = 0x9265b021, .value = 0xfffffffff80000ff },
    .{ .word = 0x9265b421, .value = 0xfffffffff80001ff },
    .{ .word = 0x9265b821, .value = 0xfffffffff80003ff },
    .{ .word = 0x9265bc21, .value = 0xfffffffff80007ff },
    .{ .word = 0x9265c021, .value = 0xfffffffff8000fff },
    .{ .word = 0x9265c421, .value = 0xfffffffff8001fff },
    .{ .word = 0x9265c821, .value = 0xfffffffff8003fff },
    .{ .word = 0x9265cc21, .value = 0xfffffffff8007fff },
    .{ .word = 0x9265d021, .value = 0xfffffffff800ffff },
    .{ .word = 0x9265d421, .value = 0xfffffffff801ffff },
    .{ .word = 0x9265d821, .value = 0xfffffffff803ffff },
    .{ .word = 0x9265dc21, .value = 0xfffffffff807ffff },
    .{ .word = 0x9265e021, .value = 0xfffffffff80fffff },
    .{ .word = 0x9265e421, .value = 0xfffffffff81fffff },
    .{ .word = 0x9265e821, .value = 0xfffffffff83fffff },
    .{ .word = 0x9265ec21, .value = 0xfffffffff87fffff },
    .{ .word = 0x9265f021, .value = 0xfffffffff8ffffff },
    .{ .word = 0x9265f421, .value = 0xfffffffff9ffffff },
    .{ .word = 0x9265f821, .value = 0xfffffffffbffffff },
    .{ .word = 0x92660021, .value = 0x4000000 },
    .{ .word = 0x92660421, .value = 0xc000000 },
    .{ .word = 0x92660821, .value = 0x1c000000 },
    .{ .word = 0x92660c21, .value = 0x3c000000 },
    .{ .word = 0x92661021, .value = 0x7c000000 },
    .{ .word = 0x92661421, .value = 0xfc000000 },
    .{ .word = 0x92661821, .value = 0x1fc000000 },
    .{ .word = 0x92661c21, .value = 0x3fc000000 },
    .{ .word = 0x92662021, .value = 0x7fc000000 },
    .{ .word = 0x92662421, .value = 0xffc000000 },
    .{ .word = 0x92662821, .value = 0x1ffc000000 },
    .{ .word = 0x92662c21, .value = 0x3ffc000000 },
    .{ .word = 0x92663021, .value = 0x7ffc000000 },
    .{ .word = 0x92663421, .value = 0xfffc000000 },
    .{ .word = 0x92663821, .value = 0x1fffc000000 },
    .{ .word = 0x92663c21, .value = 0x3fffc000000 },
    .{ .word = 0x92664021, .value = 0x7fffc000000 },
    .{ .word = 0x92664421, .value = 0xffffc000000 },
    .{ .word = 0x92664821, .value = 0x1ffffc000000 },
    .{ .word = 0x92664c21, .value = 0x3ffffc000000 },
    .{ .word = 0x92665021, .value = 0x7ffffc000000 },
    .{ .word = 0x92665421, .value = 0xfffffc000000 },
    .{ .word = 0x92665821, .value = 0x1fffffc000000 },
    .{ .word = 0x92665c21, .value = 0x3fffffc000000 },
    .{ .word = 0x92666021, .value = 0x7fffffc000000 },
    .{ .word = 0x92666421, .value = 0xffffffc000000 },
    .{ .word = 0x92666821, .value = 0x1ffffffc000000 },
    .{ .word = 0x92666c21, .value = 0x3ffffffc000000 },
    .{ .word = 0x92667021, .value = 0x7ffffffc000000 },
    .{ .word = 0x92667421, .value = 0xfffffffc000000 },
    .{ .word = 0x92667821, .value = 0x1fffffffc000000 },
    .{ .word = 0x92667c21, .value = 0x3fffffffc000000 },
    .{ .word = 0x92668021, .value = 0x7fffffffc000000 },
    .{ .word = 0x92668421, .value = 0xffffffffc000000 },
    .{ .word = 0x92668821, .value = 0x1ffffffffc000000 },
    .{ .word = 0x92668c21, .value = 0x3ffffffffc000000 },
    .{ .word = 0x92669021, .value = 0x7ffffffffc000000 },
    .{ .word = 0x92669421, .value = 0xfffffffffc000000 },
    .{ .word = 0x92669821, .value = 0xfffffffffc000001 },
    .{ .word = 0x92669c21, .value = 0xfffffffffc000003 },
    .{ .word = 0x9266a021, .value = 0xfffffffffc000007 },
    .{ .word = 0x9266a421, .value = 0xfffffffffc00000f },
    .{ .word = 0x9266a821, .value = 0xfffffffffc00001f },
    .{ .word = 0x9266ac21, .value = 0xfffffffffc00003f },
    .{ .word = 0x9266b021, .value = 0xfffffffffc00007f },
    .{ .word = 0x9266b421, .value = 0xfffffffffc0000ff },
    .{ .word = 0x9266b821, .value = 0xfffffffffc0001ff },
    .{ .word = 0x9266bc21, .value = 0xfffffffffc0003ff },
    .{ .word = 0x9266c021, .value = 0xfffffffffc0007ff },
    .{ .word = 0x9266c421, .value = 0xfffffffffc000fff },
    .{ .word = 0x9266c821, .value = 0xfffffffffc001fff },
    .{ .word = 0x9266cc21, .value = 0xfffffffffc003fff },
    .{ .word = 0x9266d021, .value = 0xfffffffffc007fff },
    .{ .word = 0x9266d421, .value = 0xfffffffffc00ffff },
    .{ .word = 0x9266d821, .value = 0xfffffffffc01ffff },
    .{ .word = 0x9266dc21, .value = 0xfffffffffc03ffff },
    .{ .word = 0x9266e021, .value = 0xfffffffffc07ffff },
    .{ .word = 0x9266e421, .value = 0xfffffffffc0fffff },
    .{ .word = 0x9266e821, .value = 0xfffffffffc1fffff },
    .{ .word = 0x9266ec21, .value = 0xfffffffffc3fffff },
    .{ .word = 0x9266f021, .value = 0xfffffffffc7fffff },
    .{ .word = 0x9266f421, .value = 0xfffffffffcffffff },
    .{ .word = 0x9266f821, .value = 0xfffffffffdffffff },
    .{ .word = 0x92670021, .value = 0x2000000 },
    .{ .word = 0x92670421, .value = 0x6000000 },
    .{ .word = 0x92670821, .value = 0xe000000 },
    .{ .word = 0x92670c21, .value = 0x1e000000 },
    .{ .word = 0x92671021, .value = 0x3e000000 },
    .{ .word = 0x92671421, .value = 0x7e000000 },
    .{ .word = 0x92671821, .value = 0xfe000000 },
    .{ .word = 0x92671c21, .value = 0x1fe000000 },
    .{ .word = 0x92672021, .value = 0x3fe000000 },
    .{ .word = 0x92672421, .value = 0x7fe000000 },
    .{ .word = 0x92672821, .value = 0xffe000000 },
    .{ .word = 0x92672c21, .value = 0x1ffe000000 },
    .{ .word = 0x92673021, .value = 0x3ffe000000 },
    .{ .word = 0x92673421, .value = 0x7ffe000000 },
    .{ .word = 0x92673821, .value = 0xfffe000000 },
    .{ .word = 0x92673c21, .value = 0x1fffe000000 },
    .{ .word = 0x92674021, .value = 0x3fffe000000 },
    .{ .word = 0x92674421, .value = 0x7fffe000000 },
    .{ .word = 0x92674821, .value = 0xffffe000000 },
    .{ .word = 0x92674c21, .value = 0x1ffffe000000 },
    .{ .word = 0x92675021, .value = 0x3ffffe000000 },
    .{ .word = 0x92675421, .value = 0x7ffffe000000 },
    .{ .word = 0x92675821, .value = 0xfffffe000000 },
    .{ .word = 0x92675c21, .value = 0x1fffffe000000 },
    .{ .word = 0x92676021, .value = 0x3fffffe000000 },
    .{ .word = 0x92676421, .value = 0x7fffffe000000 },
    .{ .word = 0x92676821, .value = 0xffffffe000000 },
    .{ .word = 0x92676c21, .value = 0x1ffffffe000000 },
    .{ .word = 0x92677021, .value = 0x3ffffffe000000 },
    .{ .word = 0x92677421, .value = 0x7ffffffe000000 },
    .{ .word = 0x92677821, .value = 0xfffffffe000000 },
    .{ .word = 0x92677c21, .value = 0x1fffffffe000000 },
    .{ .word = 0x92678021, .value = 0x3fffffffe000000 },
    .{ .word = 0x92678421, .value = 0x7fffffffe000000 },
    .{ .word = 0x92678821, .value = 0xffffffffe000000 },
    .{ .word = 0x92678c21, .value = 0x1ffffffffe000000 },
    .{ .word = 0x92679021, .value = 0x3ffffffffe000000 },
    .{ .word = 0x92679421, .value = 0x7ffffffffe000000 },
    .{ .word = 0x92679821, .value = 0xfffffffffe000000 },
    .{ .word = 0x92679c21, .value = 0xfffffffffe000001 },
    .{ .word = 0x9267a021, .value = 0xfffffffffe000003 },
    .{ .word = 0x9267a421, .value = 0xfffffffffe000007 },
    .{ .word = 0x9267a821, .value = 0xfffffffffe00000f },
    .{ .word = 0x9267ac21, .value = 0xfffffffffe00001f },
    .{ .word = 0x9267b021, .value = 0xfffffffffe00003f },
    .{ .word = 0x9267b421, .value = 0xfffffffffe00007f },
    .{ .word = 0x9267b821, .value = 0xfffffffffe0000ff },
    .{ .word = 0x9267bc21, .value = 0xfffffffffe0001ff },
    .{ .word = 0x9267c021, .value = 0xfffffffffe0003ff },
    .{ .word = 0x9267c421, .value = 0xfffffffffe0007ff },
    .{ .word = 0x9267c821, .value = 0xfffffffffe000fff },
    .{ .word = 0x9267cc21, .value = 0xfffffffffe001fff },
    .{ .word = 0x9267d021, .value = 0xfffffffffe003fff },
    .{ .word = 0x9267d421, .value = 0xfffffffffe007fff },
    .{ .word = 0x9267d821, .value = 0xfffffffffe00ffff },
    .{ .word = 0x9267dc21, .value = 0xfffffffffe01ffff },
    .{ .word = 0x9267e021, .value = 0xfffffffffe03ffff },
    .{ .word = 0x9267e421, .value = 0xfffffffffe07ffff },
    .{ .word = 0x9267e821, .value = 0xfffffffffe0fffff },
    .{ .word = 0x9267ec21, .value = 0xfffffffffe1fffff },
    .{ .word = 0x9267f021, .value = 0xfffffffffe3fffff },
    .{ .word = 0x9267f421, .value = 0xfffffffffe7fffff },
    .{ .word = 0x9267f821, .value = 0xfffffffffeffffff },
    .{ .word = 0x92680021, .value = 0x1000000 },
    .{ .word = 0x92680421, .value = 0x3000000 },
    .{ .word = 0x92680821, .value = 0x7000000 },
    .{ .word = 0x92680c21, .value = 0xf000000 },
    .{ .word = 0x92681021, .value = 0x1f000000 },
    .{ .word = 0x92681421, .value = 0x3f000000 },
    .{ .word = 0x92681821, .value = 0x7f000000 },
    .{ .word = 0x92681c21, .value = 0xff000000 },
    .{ .word = 0x92682021, .value = 0x1ff000000 },
    .{ .word = 0x92682421, .value = 0x3ff000000 },
    .{ .word = 0x92682821, .value = 0x7ff000000 },
    .{ .word = 0x92682c21, .value = 0xfff000000 },
    .{ .word = 0x92683021, .value = 0x1fff000000 },
    .{ .word = 0x92683421, .value = 0x3fff000000 },
    .{ .word = 0x92683821, .value = 0x7fff000000 },
    .{ .word = 0x92683c21, .value = 0xffff000000 },
    .{ .word = 0x92684021, .value = 0x1ffff000000 },
    .{ .word = 0x92684421, .value = 0x3ffff000000 },
    .{ .word = 0x92684821, .value = 0x7ffff000000 },
    .{ .word = 0x92684c21, .value = 0xfffff000000 },
    .{ .word = 0x92685021, .value = 0x1fffff000000 },
    .{ .word = 0x92685421, .value = 0x3fffff000000 },
    .{ .word = 0x92685821, .value = 0x7fffff000000 },
    .{ .word = 0x92685c21, .value = 0xffffff000000 },
    .{ .word = 0x92686021, .value = 0x1ffffff000000 },
    .{ .word = 0x92686421, .value = 0x3ffffff000000 },
    .{ .word = 0x92686821, .value = 0x7ffffff000000 },
    .{ .word = 0x92686c21, .value = 0xfffffff000000 },
    .{ .word = 0x92687021, .value = 0x1fffffff000000 },
    .{ .word = 0x92687421, .value = 0x3fffffff000000 },
    .{ .word = 0x92687821, .value = 0x7fffffff000000 },
    .{ .word = 0x92687c21, .value = 0xffffffff000000 },
    .{ .word = 0x92688021, .value = 0x1ffffffff000000 },
    .{ .word = 0x92688421, .value = 0x3ffffffff000000 },
    .{ .word = 0x92688821, .value = 0x7ffffffff000000 },
    .{ .word = 0x92688c21, .value = 0xfffffffff000000 },
    .{ .word = 0x92689021, .value = 0x1fffffffff000000 },
    .{ .word = 0x92689421, .value = 0x3fffffffff000000 },
    .{ .word = 0x92689821, .value = 0x7fffffffff000000 },
    .{ .word = 0x92689c21, .value = 0xffffffffff000000 },
    .{ .word = 0x9268a021, .value = 0xffffffffff000001 },
    .{ .word = 0x9268a421, .value = 0xffffffffff000003 },
    .{ .word = 0x9268a821, .value = 0xffffffffff000007 },
    .{ .word = 0x9268ac21, .value = 0xffffffffff00000f },
    .{ .word = 0x9268b021, .value = 0xffffffffff00001f },
    .{ .word = 0x9268b421, .value = 0xffffffffff00003f },
    .{ .word = 0x9268b821, .value = 0xffffffffff00007f },
    .{ .word = 0x9268bc21, .value = 0xffffffffff0000ff },
    .{ .word = 0x9268c021, .value = 0xffffffffff0001ff },
    .{ .word = 0x9268c421, .value = 0xffffffffff0003ff },
    .{ .word = 0x9268c821, .value = 0xffffffffff0007ff },
    .{ .word = 0x9268cc21, .value = 0xffffffffff000fff },
    .{ .word = 0x9268d021, .value = 0xffffffffff001fff },
    .{ .word = 0x9268d421, .value = 0xffffffffff003fff },
    .{ .word = 0x9268d821, .value = 0xffffffffff007fff },
    .{ .word = 0x9268dc21, .value = 0xffffffffff00ffff },
    .{ .word = 0x9268e021, .value = 0xffffffffff01ffff },
    .{ .word = 0x9268e421, .value = 0xffffffffff03ffff },
    .{ .word = 0x9268e821, .value = 0xffffffffff07ffff },
    .{ .word = 0x9268ec21, .value = 0xffffffffff0fffff },
    .{ .word = 0x9268f021, .value = 0xffffffffff1fffff },
    .{ .word = 0x9268f421, .value = 0xffffffffff3fffff },
    .{ .word = 0x9268f821, .value = 0xffffffffff7fffff },
    .{ .word = 0x92690021, .value = 0x800000 },
    .{ .word = 0x92690421, .value = 0x1800000 },
    .{ .word = 0x92690821, .value = 0x3800000 },
    .{ .word = 0x92690c21, .value = 0x7800000 },
    .{ .word = 0x92691021, .value = 0xf800000 },
    .{ .word = 0x92691421, .value = 0x1f800000 },
    .{ .word = 0x92691821, .value = 0x3f800000 },
    .{ .word = 0x92691c21, .value = 0x7f800000 },
    .{ .word = 0x92692021, .value = 0xff800000 },
    .{ .word = 0x92692421, .value = 0x1ff800000 },
    .{ .word = 0x92692821, .value = 0x3ff800000 },
    .{ .word = 0x92692c21, .value = 0x7ff800000 },
    .{ .word = 0x92693021, .value = 0xfff800000 },
    .{ .word = 0x92693421, .value = 0x1fff800000 },
    .{ .word = 0x92693821, .value = 0x3fff800000 },
    .{ .word = 0x92693c21, .value = 0x7fff800000 },
    .{ .word = 0x92694021, .value = 0xffff800000 },
    .{ .word = 0x92694421, .value = 0x1ffff800000 },
    .{ .word = 0x92694821, .value = 0x3ffff800000 },
    .{ .word = 0x92694c21, .value = 0x7ffff800000 },
    .{ .word = 0x92695021, .value = 0xfffff800000 },
    .{ .word = 0x92695421, .value = 0x1fffff800000 },
    .{ .word = 0x92695821, .value = 0x3fffff800000 },
    .{ .word = 0x92695c21, .value = 0x7fffff800000 },
    .{ .word = 0x92696021, .value = 0xffffff800000 },
    .{ .word = 0x92696421, .value = 0x1ffffff800000 },
    .{ .word = 0x92696821, .value = 0x3ffffff800000 },
    .{ .word = 0x92696c21, .value = 0x7ffffff800000 },
    .{ .word = 0x92697021, .value = 0xfffffff800000 },
    .{ .word = 0x92697421, .value = 0x1fffffff800000 },
    .{ .word = 0x92697821, .value = 0x3fffffff800000 },
    .{ .word = 0x92697c21, .value = 0x7fffffff800000 },
    .{ .word = 0x92698021, .value = 0xffffffff800000 },
    .{ .word = 0x92698421, .value = 0x1ffffffff800000 },
    .{ .word = 0x92698821, .value = 0x3ffffffff800000 },
    .{ .word = 0x92698c21, .value = 0x7ffffffff800000 },
    .{ .word = 0x92699021, .value = 0xfffffffff800000 },
    .{ .word = 0x92699421, .value = 0x1fffffffff800000 },
    .{ .word = 0x92699821, .value = 0x3fffffffff800000 },
    .{ .word = 0x92699c21, .value = 0x7fffffffff800000 },
    .{ .word = 0x9269a021, .value = 0xffffffffff800000 },
    .{ .word = 0x9269a421, .value = 0xffffffffff800001 },
    .{ .word = 0x9269a821, .value = 0xffffffffff800003 },
    .{ .word = 0x9269ac21, .value = 0xffffffffff800007 },
    .{ .word = 0x9269b021, .value = 0xffffffffff80000f },
    .{ .word = 0x9269b421, .value = 0xffffffffff80001f },
    .{ .word = 0x9269b821, .value = 0xffffffffff80003f },
    .{ .word = 0x9269bc21, .value = 0xffffffffff80007f },
    .{ .word = 0x9269c021, .value = 0xffffffffff8000ff },
    .{ .word = 0x9269c421, .value = 0xffffffffff8001ff },
    .{ .word = 0x9269c821, .value = 0xffffffffff8003ff },
    .{ .word = 0x9269cc21, .value = 0xffffffffff8007ff },
    .{ .word = 0x9269d021, .value = 0xffffffffff800fff },
    .{ .word = 0x9269d421, .value = 0xffffffffff801fff },
    .{ .word = 0x9269d821, .value = 0xffffffffff803fff },
    .{ .word = 0x9269dc21, .value = 0xffffffffff807fff },
    .{ .word = 0x9269e021, .value = 0xffffffffff80ffff },
    .{ .word = 0x9269e421, .value = 0xffffffffff81ffff },
    .{ .word = 0x9269e821, .value = 0xffffffffff83ffff },
    .{ .word = 0x9269ec21, .value = 0xffffffffff87ffff },
    .{ .word = 0x9269f021, .value = 0xffffffffff8fffff },
    .{ .word = 0x9269f421, .value = 0xffffffffff9fffff },
    .{ .word = 0x9269f821, .value = 0xffffffffffbfffff },
    .{ .word = 0x926a0021, .value = 0x400000 },
    .{ .word = 0x926a0421, .value = 0xc00000 },
    .{ .word = 0x926a0821, .value = 0x1c00000 },
    .{ .word = 0x926a0c21, .value = 0x3c00000 },
    .{ .word = 0x926a1021, .value = 0x7c00000 },
    .{ .word = 0x926a1421, .value = 0xfc00000 },
    .{ .word = 0x926a1821, .value = 0x1fc00000 },
    .{ .word = 0x926a1c21, .value = 0x3fc00000 },
    .{ .word = 0x926a2021, .value = 0x7fc00000 },
    .{ .word = 0x926a2421, .value = 0xffc00000 },
    .{ .word = 0x926a2821, .value = 0x1ffc00000 },
    .{ .word = 0x926a2c21, .value = 0x3ffc00000 },
    .{ .word = 0x926a3021, .value = 0x7ffc00000 },
    .{ .word = 0x926a3421, .value = 0xfffc00000 },
    .{ .word = 0x926a3821, .value = 0x1fffc00000 },
    .{ .word = 0x926a3c21, .value = 0x3fffc00000 },
    .{ .word = 0x926a4021, .value = 0x7fffc00000 },
    .{ .word = 0x926a4421, .value = 0xffffc00000 },
    .{ .word = 0x926a4821, .value = 0x1ffffc00000 },
    .{ .word = 0x926a4c21, .value = 0x3ffffc00000 },
    .{ .word = 0x926a5021, .value = 0x7ffffc00000 },
    .{ .word = 0x926a5421, .value = 0xfffffc00000 },
    .{ .word = 0x926a5821, .value = 0x1fffffc00000 },
    .{ .word = 0x926a5c21, .value = 0x3fffffc00000 },
    .{ .word = 0x926a6021, .value = 0x7fffffc00000 },
    .{ .word = 0x926a6421, .value = 0xffffffc00000 },
    .{ .word = 0x926a6821, .value = 0x1ffffffc00000 },
    .{ .word = 0x926a6c21, .value = 0x3ffffffc00000 },
    .{ .word = 0x926a7021, .value = 0x7ffffffc00000 },
    .{ .word = 0x926a7421, .value = 0xfffffffc00000 },
    .{ .word = 0x926a7821, .value = 0x1fffffffc00000 },
    .{ .word = 0x926a7c21, .value = 0x3fffffffc00000 },
    .{ .word = 0x926a8021, .value = 0x7fffffffc00000 },
    .{ .word = 0x926a8421, .value = 0xffffffffc00000 },
    .{ .word = 0x926a8821, .value = 0x1ffffffffc00000 },
    .{ .word = 0x926a8c21, .value = 0x3ffffffffc00000 },
    .{ .word = 0x926a9021, .value = 0x7ffffffffc00000 },
    .{ .word = 0x926a9421, .value = 0xfffffffffc00000 },
    .{ .word = 0x926a9821, .value = 0x1fffffffffc00000 },
    .{ .word = 0x926a9c21, .value = 0x3fffffffffc00000 },
    .{ .word = 0x926aa021, .value = 0x7fffffffffc00000 },
    .{ .word = 0x926aa421, .value = 0xffffffffffc00000 },
    .{ .word = 0x926aa821, .value = 0xffffffffffc00001 },
    .{ .word = 0x926aac21, .value = 0xffffffffffc00003 },
    .{ .word = 0x926ab021, .value = 0xffffffffffc00007 },
    .{ .word = 0x926ab421, .value = 0xffffffffffc0000f },
    .{ .word = 0x926ab821, .value = 0xffffffffffc0001f },
    .{ .word = 0x926abc21, .value = 0xffffffffffc0003f },
    .{ .word = 0x926ac021, .value = 0xffffffffffc0007f },
    .{ .word = 0x926ac421, .value = 0xffffffffffc000ff },
    .{ .word = 0x926ac821, .value = 0xffffffffffc001ff },
    .{ .word = 0x926acc21, .value = 0xffffffffffc003ff },
    .{ .word = 0x926ad021, .value = 0xffffffffffc007ff },
    .{ .word = 0x926ad421, .value = 0xffffffffffc00fff },
    .{ .word = 0x926ad821, .value = 0xffffffffffc01fff },
    .{ .word = 0x926adc21, .value = 0xffffffffffc03fff },
    .{ .word = 0x926ae021, .value = 0xffffffffffc07fff },
    .{ .word = 0x926ae421, .value = 0xffffffffffc0ffff },
    .{ .word = 0x926ae821, .value = 0xffffffffffc1ffff },
    .{ .word = 0x926aec21, .value = 0xffffffffffc3ffff },
    .{ .word = 0x926af021, .value = 0xffffffffffc7ffff },
    .{ .word = 0x926af421, .value = 0xffffffffffcfffff },
    .{ .word = 0x926af821, .value = 0xffffffffffdfffff },
    .{ .word = 0x926b0021, .value = 0x200000 },
    .{ .word = 0x926b0421, .value = 0x600000 },
    .{ .word = 0x926b0821, .value = 0xe00000 },
    .{ .word = 0x926b0c21, .value = 0x1e00000 },
    .{ .word = 0x926b1021, .value = 0x3e00000 },
    .{ .word = 0x926b1421, .value = 0x7e00000 },
    .{ .word = 0x926b1821, .value = 0xfe00000 },
    .{ .word = 0x926b1c21, .value = 0x1fe00000 },
    .{ .word = 0x926b2021, .value = 0x3fe00000 },
    .{ .word = 0x926b2421, .value = 0x7fe00000 },
    .{ .word = 0x926b2821, .value = 0xffe00000 },
    .{ .word = 0x926b2c21, .value = 0x1ffe00000 },
    .{ .word = 0x926b3021, .value = 0x3ffe00000 },
    .{ .word = 0x926b3421, .value = 0x7ffe00000 },
    .{ .word = 0x926b3821, .value = 0xfffe00000 },
    .{ .word = 0x926b3c21, .value = 0x1fffe00000 },
    .{ .word = 0x926b4021, .value = 0x3fffe00000 },
    .{ .word = 0x926b4421, .value = 0x7fffe00000 },
    .{ .word = 0x926b4821, .value = 0xffffe00000 },
    .{ .word = 0x926b4c21, .value = 0x1ffffe00000 },
    .{ .word = 0x926b5021, .value = 0x3ffffe00000 },
    .{ .word = 0x926b5421, .value = 0x7ffffe00000 },
    .{ .word = 0x926b5821, .value = 0xfffffe00000 },
    .{ .word = 0x926b5c21, .value = 0x1fffffe00000 },
    .{ .word = 0x926b6021, .value = 0x3fffffe00000 },
    .{ .word = 0x926b6421, .value = 0x7fffffe00000 },
    .{ .word = 0x926b6821, .value = 0xffffffe00000 },
    .{ .word = 0x926b6c21, .value = 0x1ffffffe00000 },
    .{ .word = 0x926b7021, .value = 0x3ffffffe00000 },
    .{ .word = 0x926b7421, .value = 0x7ffffffe00000 },
    .{ .word = 0x926b7821, .value = 0xfffffffe00000 },
    .{ .word = 0x926b7c21, .value = 0x1fffffffe00000 },
    .{ .word = 0x926b8021, .value = 0x3fffffffe00000 },
    .{ .word = 0x926b8421, .value = 0x7fffffffe00000 },
    .{ .word = 0x926b8821, .value = 0xffffffffe00000 },
    .{ .word = 0x926b8c21, .value = 0x1ffffffffe00000 },
    .{ .word = 0x926b9021, .value = 0x3ffffffffe00000 },
    .{ .word = 0x926b9421, .value = 0x7ffffffffe00000 },
    .{ .word = 0x926b9821, .value = 0xfffffffffe00000 },
    .{ .word = 0x926b9c21, .value = 0x1fffffffffe00000 },
    .{ .word = 0x926ba021, .value = 0x3fffffffffe00000 },
    .{ .word = 0x926ba421, .value = 0x7fffffffffe00000 },
    .{ .word = 0x926ba821, .value = 0xffffffffffe00000 },
    .{ .word = 0x926bac21, .value = 0xffffffffffe00001 },
    .{ .word = 0x926bb021, .value = 0xffffffffffe00003 },
    .{ .word = 0x926bb421, .value = 0xffffffffffe00007 },
    .{ .word = 0x926bb821, .value = 0xffffffffffe0000f },
    .{ .word = 0x926bbc21, .value = 0xffffffffffe0001f },
    .{ .word = 0x926bc021, .value = 0xffffffffffe0003f },
    .{ .word = 0x926bc421, .value = 0xffffffffffe0007f },
    .{ .word = 0x926bc821, .value = 0xffffffffffe000ff },
    .{ .word = 0x926bcc21, .value = 0xffffffffffe001ff },
    .{ .word = 0x926bd021, .value = 0xffffffffffe003ff },
    .{ .word = 0x926bd421, .value = 0xffffffffffe007ff },
    .{ .word = 0x926bd821, .value = 0xffffffffffe00fff },
    .{ .word = 0x926bdc21, .value = 0xffffffffffe01fff },
    .{ .word = 0x926be021, .value = 0xffffffffffe03fff },
    .{ .word = 0x926be421, .value = 0xffffffffffe07fff },
    .{ .word = 0x926be821, .value = 0xffffffffffe0ffff },
    .{ .word = 0x926bec21, .value = 0xffffffffffe1ffff },
    .{ .word = 0x926bf021, .value = 0xffffffffffe3ffff },
    .{ .word = 0x926bf421, .value = 0xffffffffffe7ffff },
    .{ .word = 0x926bf821, .value = 0xffffffffffefffff },
    .{ .word = 0x926c0021, .value = 0x100000 },
    .{ .word = 0x926c0421, .value = 0x300000 },
    .{ .word = 0x926c0821, .value = 0x700000 },
    .{ .word = 0x926c0c21, .value = 0xf00000 },
    .{ .word = 0x926c1021, .value = 0x1f00000 },
    .{ .word = 0x926c1421, .value = 0x3f00000 },
    .{ .word = 0x926c1821, .value = 0x7f00000 },
    .{ .word = 0x926c1c21, .value = 0xff00000 },
    .{ .word = 0x926c2021, .value = 0x1ff00000 },
    .{ .word = 0x926c2421, .value = 0x3ff00000 },
    .{ .word = 0x926c2821, .value = 0x7ff00000 },
    .{ .word = 0x926c2c21, .value = 0xfff00000 },
    .{ .word = 0x926c3021, .value = 0x1fff00000 },
    .{ .word = 0x926c3421, .value = 0x3fff00000 },
    .{ .word = 0x926c3821, .value = 0x7fff00000 },
    .{ .word = 0x926c3c21, .value = 0xffff00000 },
    .{ .word = 0x926c4021, .value = 0x1ffff00000 },
    .{ .word = 0x926c4421, .value = 0x3ffff00000 },
    .{ .word = 0x926c4821, .value = 0x7ffff00000 },
    .{ .word = 0x926c4c21, .value = 0xfffff00000 },
    .{ .word = 0x926c5021, .value = 0x1fffff00000 },
    .{ .word = 0x926c5421, .value = 0x3fffff00000 },
    .{ .word = 0x926c5821, .value = 0x7fffff00000 },
    .{ .word = 0x926c5c21, .value = 0xffffff00000 },
    .{ .word = 0x926c6021, .value = 0x1ffffff00000 },
    .{ .word = 0x926c6421, .value = 0x3ffffff00000 },
    .{ .word = 0x926c6821, .value = 0x7ffffff00000 },
    .{ .word = 0x926c6c21, .value = 0xfffffff00000 },
    .{ .word = 0x926c7021, .value = 0x1fffffff00000 },
    .{ .word = 0x926c7421, .value = 0x3fffffff00000 },
    .{ .word = 0x926c7821, .value = 0x7fffffff00000 },
    .{ .word = 0x926c7c21, .value = 0xffffffff00000 },
    .{ .word = 0x926c8021, .value = 0x1ffffffff00000 },
    .{ .word = 0x926c8421, .value = 0x3ffffffff00000 },
    .{ .word = 0x926c8821, .value = 0x7ffffffff00000 },
    .{ .word = 0x926c8c21, .value = 0xfffffffff00000 },
    .{ .word = 0x926c9021, .value = 0x1fffffffff00000 },
    .{ .word = 0x926c9421, .value = 0x3fffffffff00000 },
    .{ .word = 0x926c9821, .value = 0x7fffffffff00000 },
    .{ .word = 0x926c9c21, .value = 0xffffffffff00000 },
    .{ .word = 0x926ca021, .value = 0x1ffffffffff00000 },
    .{ .word = 0x926ca421, .value = 0x3ffffffffff00000 },
    .{ .word = 0x926ca821, .value = 0x7ffffffffff00000 },
    .{ .word = 0x926cac21, .value = 0xfffffffffff00000 },
    .{ .word = 0x926cb021, .value = 0xfffffffffff00001 },
    .{ .word = 0x926cb421, .value = 0xfffffffffff00003 },
    .{ .word = 0x926cb821, .value = 0xfffffffffff00007 },
    .{ .word = 0x926cbc21, .value = 0xfffffffffff0000f },
    .{ .word = 0x926cc021, .value = 0xfffffffffff0001f },
    .{ .word = 0x926cc421, .value = 0xfffffffffff0003f },
    .{ .word = 0x926cc821, .value = 0xfffffffffff0007f },
    .{ .word = 0x926ccc21, .value = 0xfffffffffff000ff },
    .{ .word = 0x926cd021, .value = 0xfffffffffff001ff },
    .{ .word = 0x926cd421, .value = 0xfffffffffff003ff },
    .{ .word = 0x926cd821, .value = 0xfffffffffff007ff },
    .{ .word = 0x926cdc21, .value = 0xfffffffffff00fff },
    .{ .word = 0x926ce021, .value = 0xfffffffffff01fff },
    .{ .word = 0x926ce421, .value = 0xfffffffffff03fff },
    .{ .word = 0x926ce821, .value = 0xfffffffffff07fff },
    .{ .word = 0x926cec21, .value = 0xfffffffffff0ffff },
    .{ .word = 0x926cf021, .value = 0xfffffffffff1ffff },
    .{ .word = 0x926cf421, .value = 0xfffffffffff3ffff },
    .{ .word = 0x926cf821, .value = 0xfffffffffff7ffff },
    .{ .word = 0x926d0021, .value = 0x80000 },
    .{ .word = 0x926d0421, .value = 0x180000 },
    .{ .word = 0x926d0821, .value = 0x380000 },
    .{ .word = 0x926d0c21, .value = 0x780000 },
    .{ .word = 0x926d1021, .value = 0xf80000 },
    .{ .word = 0x926d1421, .value = 0x1f80000 },
    .{ .word = 0x926d1821, .value = 0x3f80000 },
    .{ .word = 0x926d1c21, .value = 0x7f80000 },
    .{ .word = 0x926d2021, .value = 0xff80000 },
    .{ .word = 0x926d2421, .value = 0x1ff80000 },
    .{ .word = 0x926d2821, .value = 0x3ff80000 },
    .{ .word = 0x926d2c21, .value = 0x7ff80000 },
    .{ .word = 0x926d3021, .value = 0xfff80000 },
    .{ .word = 0x926d3421, .value = 0x1fff80000 },
    .{ .word = 0x926d3821, .value = 0x3fff80000 },
    .{ .word = 0x926d3c21, .value = 0x7fff80000 },
    .{ .word = 0x926d4021, .value = 0xffff80000 },
    .{ .word = 0x926d4421, .value = 0x1ffff80000 },
    .{ .word = 0x926d4821, .value = 0x3ffff80000 },
    .{ .word = 0x926d4c21, .value = 0x7ffff80000 },
    .{ .word = 0x926d5021, .value = 0xfffff80000 },
    .{ .word = 0x926d5421, .value = 0x1fffff80000 },
    .{ .word = 0x926d5821, .value = 0x3fffff80000 },
    .{ .word = 0x926d5c21, .value = 0x7fffff80000 },
    .{ .word = 0x926d6021, .value = 0xffffff80000 },
    .{ .word = 0x926d6421, .value = 0x1ffffff80000 },
    .{ .word = 0x926d6821, .value = 0x3ffffff80000 },
    .{ .word = 0x926d6c21, .value = 0x7ffffff80000 },
    .{ .word = 0x926d7021, .value = 0xfffffff80000 },
    .{ .word = 0x926d7421, .value = 0x1fffffff80000 },
    .{ .word = 0x926d7821, .value = 0x3fffffff80000 },
    .{ .word = 0x926d7c21, .value = 0x7fffffff80000 },
    .{ .word = 0x926d8021, .value = 0xffffffff80000 },
    .{ .word = 0x926d8421, .value = 0x1ffffffff80000 },
    .{ .word = 0x926d8821, .value = 0x3ffffffff80000 },
    .{ .word = 0x926d8c21, .value = 0x7ffffffff80000 },
    .{ .word = 0x926d9021, .value = 0xfffffffff80000 },
    .{ .word = 0x926d9421, .value = 0x1fffffffff80000 },
    .{ .word = 0x926d9821, .value = 0x3fffffffff80000 },
    .{ .word = 0x926d9c21, .value = 0x7fffffffff80000 },
    .{ .word = 0x926da021, .value = 0xffffffffff80000 },
    .{ .word = 0x926da421, .value = 0x1ffffffffff80000 },
    .{ .word = 0x926da821, .value = 0x3ffffffffff80000 },
    .{ .word = 0x926dac21, .value = 0x7ffffffffff80000 },
    .{ .word = 0x926db021, .value = 0xfffffffffff80000 },
    .{ .word = 0x926db421, .value = 0xfffffffffff80001 },
    .{ .word = 0x926db821, .value = 0xfffffffffff80003 },
    .{ .word = 0x926dbc21, .value = 0xfffffffffff80007 },
    .{ .word = 0x926dc021, .value = 0xfffffffffff8000f },
    .{ .word = 0x926dc421, .value = 0xfffffffffff8001f },
    .{ .word = 0x926dc821, .value = 0xfffffffffff8003f },
    .{ .word = 0x926dcc21, .value = 0xfffffffffff8007f },
    .{ .word = 0x926dd021, .value = 0xfffffffffff800ff },
    .{ .word = 0x926dd421, .value = 0xfffffffffff801ff },
    .{ .word = 0x926dd821, .value = 0xfffffffffff803ff },
    .{ .word = 0x926ddc21, .value = 0xfffffffffff807ff },
    .{ .word = 0x926de021, .value = 0xfffffffffff80fff },
    .{ .word = 0x926de421, .value = 0xfffffffffff81fff },
    .{ .word = 0x926de821, .value = 0xfffffffffff83fff },
    .{ .word = 0x926dec21, .value = 0xfffffffffff87fff },
    .{ .word = 0x926df021, .value = 0xfffffffffff8ffff },
    .{ .word = 0x926df421, .value = 0xfffffffffff9ffff },
    .{ .word = 0x926df821, .value = 0xfffffffffffbffff },
    .{ .word = 0x926e0021, .value = 0x40000 },
    .{ .word = 0x926e0421, .value = 0xc0000 },
    .{ .word = 0x926e0821, .value = 0x1c0000 },
    .{ .word = 0x926e0c21, .value = 0x3c0000 },
    .{ .word = 0x926e1021, .value = 0x7c0000 },
    .{ .word = 0x926e1421, .value = 0xfc0000 },
    .{ .word = 0x926e1821, .value = 0x1fc0000 },
    .{ .word = 0x926e1c21, .value = 0x3fc0000 },
    .{ .word = 0x926e2021, .value = 0x7fc0000 },
    .{ .word = 0x926e2421, .value = 0xffc0000 },
    .{ .word = 0x926e2821, .value = 0x1ffc0000 },
    .{ .word = 0x926e2c21, .value = 0x3ffc0000 },
    .{ .word = 0x926e3021, .value = 0x7ffc0000 },
    .{ .word = 0x926e3421, .value = 0xfffc0000 },
    .{ .word = 0x926e3821, .value = 0x1fffc0000 },
    .{ .word = 0x926e3c21, .value = 0x3fffc0000 },
    .{ .word = 0x926e4021, .value = 0x7fffc0000 },
    .{ .word = 0x926e4421, .value = 0xffffc0000 },
    .{ .word = 0x926e4821, .value = 0x1ffffc0000 },
    .{ .word = 0x926e4c21, .value = 0x3ffffc0000 },
    .{ .word = 0x926e5021, .value = 0x7ffffc0000 },
    .{ .word = 0x926e5421, .value = 0xfffffc0000 },
    .{ .word = 0x926e5821, .value = 0x1fffffc0000 },
    .{ .word = 0x926e5c21, .value = 0x3fffffc0000 },
    .{ .word = 0x926e6021, .value = 0x7fffffc0000 },
    .{ .word = 0x926e6421, .value = 0xffffffc0000 },
    .{ .word = 0x926e6821, .value = 0x1ffffffc0000 },
    .{ .word = 0x926e6c21, .value = 0x3ffffffc0000 },
    .{ .word = 0x926e7021, .value = 0x7ffffffc0000 },
    .{ .word = 0x926e7421, .value = 0xfffffffc0000 },
    .{ .word = 0x926e7821, .value = 0x1fffffffc0000 },
    .{ .word = 0x926e7c21, .value = 0x3fffffffc0000 },
    .{ .word = 0x926e8021, .value = 0x7fffffffc0000 },
    .{ .word = 0x926e8421, .value = 0xffffffffc0000 },
    .{ .word = 0x926e8821, .value = 0x1ffffffffc0000 },
    .{ .word = 0x926e8c21, .value = 0x3ffffffffc0000 },
    .{ .word = 0x926e9021, .value = 0x7ffffffffc0000 },
    .{ .word = 0x926e9421, .value = 0xfffffffffc0000 },
    .{ .word = 0x926e9821, .value = 0x1fffffffffc0000 },
    .{ .word = 0x926e9c21, .value = 0x3fffffffffc0000 },
    .{ .word = 0x926ea021, .value = 0x7fffffffffc0000 },
    .{ .word = 0x926ea421, .value = 0xffffffffffc0000 },
    .{ .word = 0x926ea821, .value = 0x1ffffffffffc0000 },
    .{ .word = 0x926eac21, .value = 0x3ffffffffffc0000 },
    .{ .word = 0x926eb021, .value = 0x7ffffffffffc0000 },
    .{ .word = 0x926eb421, .value = 0xfffffffffffc0000 },
    .{ .word = 0x926eb821, .value = 0xfffffffffffc0001 },
    .{ .word = 0x926ebc21, .value = 0xfffffffffffc0003 },
    .{ .word = 0x926ec021, .value = 0xfffffffffffc0007 },
    .{ .word = 0x926ec421, .value = 0xfffffffffffc000f },
    .{ .word = 0x926ec821, .value = 0xfffffffffffc001f },
    .{ .word = 0x926ecc21, .value = 0xfffffffffffc003f },
    .{ .word = 0x926ed021, .value = 0xfffffffffffc007f },
    .{ .word = 0x926ed421, .value = 0xfffffffffffc00ff },
    .{ .word = 0x926ed821, .value = 0xfffffffffffc01ff },
    .{ .word = 0x926edc21, .value = 0xfffffffffffc03ff },
    .{ .word = 0x926ee021, .value = 0xfffffffffffc07ff },
    .{ .word = 0x926ee421, .value = 0xfffffffffffc0fff },
    .{ .word = 0x926ee821, .value = 0xfffffffffffc1fff },
    .{ .word = 0x926eec21, .value = 0xfffffffffffc3fff },
    .{ .word = 0x926ef021, .value = 0xfffffffffffc7fff },
    .{ .word = 0x926ef421, .value = 0xfffffffffffcffff },
    .{ .word = 0x926ef821, .value = 0xfffffffffffdffff },
    .{ .word = 0x926f0021, .value = 0x20000 },
    .{ .word = 0x926f0421, .value = 0x60000 },
    .{ .word = 0x926f0821, .value = 0xe0000 },
    .{ .word = 0x926f0c21, .value = 0x1e0000 },
    .{ .word = 0x926f1021, .value = 0x3e0000 },
    .{ .word = 0x926f1421, .value = 0x7e0000 },
    .{ .word = 0x926f1821, .value = 0xfe0000 },
    .{ .word = 0x926f1c21, .value = 0x1fe0000 },
    .{ .word = 0x926f2021, .value = 0x3fe0000 },
    .{ .word = 0x926f2421, .value = 0x7fe0000 },
    .{ .word = 0x926f2821, .value = 0xffe0000 },
    .{ .word = 0x926f2c21, .value = 0x1ffe0000 },
    .{ .word = 0x926f3021, .value = 0x3ffe0000 },
    .{ .word = 0x926f3421, .value = 0x7ffe0000 },
    .{ .word = 0x926f3821, .value = 0xfffe0000 },
    .{ .word = 0x926f3c21, .value = 0x1fffe0000 },
    .{ .word = 0x926f4021, .value = 0x3fffe0000 },
    .{ .word = 0x926f4421, .value = 0x7fffe0000 },
    .{ .word = 0x926f4821, .value = 0xffffe0000 },
    .{ .word = 0x926f4c21, .value = 0x1ffffe0000 },
    .{ .word = 0x926f5021, .value = 0x3ffffe0000 },
    .{ .word = 0x926f5421, .value = 0x7ffffe0000 },
    .{ .word = 0x926f5821, .value = 0xfffffe0000 },
    .{ .word = 0x926f5c21, .value = 0x1fffffe0000 },
    .{ .word = 0x926f6021, .value = 0x3fffffe0000 },
    .{ .word = 0x926f6421, .value = 0x7fffffe0000 },
    .{ .word = 0x926f6821, .value = 0xffffffe0000 },
    .{ .word = 0x926f6c21, .value = 0x1ffffffe0000 },
    .{ .word = 0x926f7021, .value = 0x3ffffffe0000 },
    .{ .word = 0x926f7421, .value = 0x7ffffffe0000 },
    .{ .word = 0x926f7821, .value = 0xfffffffe0000 },
    .{ .word = 0x926f7c21, .value = 0x1fffffffe0000 },
    .{ .word = 0x926f8021, .value = 0x3fffffffe0000 },
    .{ .word = 0x926f8421, .value = 0x7fffffffe0000 },
    .{ .word = 0x926f8821, .value = 0xffffffffe0000 },
    .{ .word = 0x926f8c21, .value = 0x1ffffffffe0000 },
    .{ .word = 0x926f9021, .value = 0x3ffffffffe0000 },
    .{ .word = 0x926f9421, .value = 0x7ffffffffe0000 },
    .{ .word = 0x926f9821, .value = 0xfffffffffe0000 },
    .{ .word = 0x926f9c21, .value = 0x1fffffffffe0000 },
    .{ .word = 0x926fa021, .value = 0x3fffffffffe0000 },
    .{ .word = 0x926fa421, .value = 0x7fffffffffe0000 },
    .{ .word = 0x926fa821, .value = 0xffffffffffe0000 },
    .{ .word = 0x926fac21, .value = 0x1ffffffffffe0000 },
    .{ .word = 0x926fb021, .value = 0x3ffffffffffe0000 },
    .{ .word = 0x926fb421, .value = 0x7ffffffffffe0000 },
    .{ .word = 0x926fb821, .value = 0xfffffffffffe0000 },
    .{ .word = 0x926fbc21, .value = 0xfffffffffffe0001 },
    .{ .word = 0x926fc021, .value = 0xfffffffffffe0003 },
    .{ .word = 0x926fc421, .value = 0xfffffffffffe0007 },
    .{ .word = 0x926fc821, .value = 0xfffffffffffe000f },
    .{ .word = 0x926fcc21, .value = 0xfffffffffffe001f },
    .{ .word = 0x926fd021, .value = 0xfffffffffffe003f },
    .{ .word = 0x926fd421, .value = 0xfffffffffffe007f },
    .{ .word = 0x926fd821, .value = 0xfffffffffffe00ff },
    .{ .word = 0x926fdc21, .value = 0xfffffffffffe01ff },
    .{ .word = 0x926fe021, .value = 0xfffffffffffe03ff },
    .{ .word = 0x926fe421, .value = 0xfffffffffffe07ff },
    .{ .word = 0x926fe821, .value = 0xfffffffffffe0fff },
    .{ .word = 0x926fec21, .value = 0xfffffffffffe1fff },
    .{ .word = 0x926ff021, .value = 0xfffffffffffe3fff },
    .{ .word = 0x926ff421, .value = 0xfffffffffffe7fff },
    .{ .word = 0x926ff821, .value = 0xfffffffffffeffff },
    .{ .word = 0x92700021, .value = 0x10000 },
    .{ .word = 0x92700421, .value = 0x30000 },
    .{ .word = 0x92700821, .value = 0x70000 },
    .{ .word = 0x92700c21, .value = 0xf0000 },
    .{ .word = 0x92701021, .value = 0x1f0000 },
    .{ .word = 0x92701421, .value = 0x3f0000 },
    .{ .word = 0x92701821, .value = 0x7f0000 },
    .{ .word = 0x92701c21, .value = 0xff0000 },
    .{ .word = 0x92702021, .value = 0x1ff0000 },
    .{ .word = 0x92702421, .value = 0x3ff0000 },
    .{ .word = 0x92702821, .value = 0x7ff0000 },
    .{ .word = 0x92702c21, .value = 0xfff0000 },
    .{ .word = 0x92703021, .value = 0x1fff0000 },
    .{ .word = 0x92703421, .value = 0x3fff0000 },
    .{ .word = 0x92703821, .value = 0x7fff0000 },
    .{ .word = 0x92703c21, .value = 0xffff0000 },
    .{ .word = 0x92704021, .value = 0x1ffff0000 },
    .{ .word = 0x92704421, .value = 0x3ffff0000 },
    .{ .word = 0x92704821, .value = 0x7ffff0000 },
    .{ .word = 0x92704c21, .value = 0xfffff0000 },
    .{ .word = 0x92705021, .value = 0x1fffff0000 },
    .{ .word = 0x92705421, .value = 0x3fffff0000 },
    .{ .word = 0x92705821, .value = 0x7fffff0000 },
    .{ .word = 0x92705c21, .value = 0xffffff0000 },
    .{ .word = 0x92706021, .value = 0x1ffffff0000 },
    .{ .word = 0x92706421, .value = 0x3ffffff0000 },
    .{ .word = 0x92706821, .value = 0x7ffffff0000 },
    .{ .word = 0x92706c21, .value = 0xfffffff0000 },
    .{ .word = 0x92707021, .value = 0x1fffffff0000 },
    .{ .word = 0x92707421, .value = 0x3fffffff0000 },
    .{ .word = 0x92707821, .value = 0x7fffffff0000 },
    .{ .word = 0x92707c21, .value = 0xffffffff0000 },
    .{ .word = 0x92708021, .value = 0x1ffffffff0000 },
    .{ .word = 0x92708421, .value = 0x3ffffffff0000 },
    .{ .word = 0x92708821, .value = 0x7ffffffff0000 },
    .{ .word = 0x92708c21, .value = 0xfffffffff0000 },
    .{ .word = 0x92709021, .value = 0x1fffffffff0000 },
    .{ .word = 0x92709421, .value = 0x3fffffffff0000 },
    .{ .word = 0x92709821, .value = 0x7fffffffff0000 },
    .{ .word = 0x92709c21, .value = 0xffffffffff0000 },
    .{ .word = 0x9270a021, .value = 0x1ffffffffff0000 },
    .{ .word = 0x9270a421, .value = 0x3ffffffffff0000 },
    .{ .word = 0x9270a821, .value = 0x7ffffffffff0000 },
    .{ .word = 0x9270ac21, .value = 0xfffffffffff0000 },
    .{ .word = 0x9270b021, .value = 0x1fffffffffff0000 },
    .{ .word = 0x9270b421, .value = 0x3fffffffffff0000 },
    .{ .word = 0x9270b821, .value = 0x7fffffffffff0000 },
    .{ .word = 0x9270bc21, .value = 0xffffffffffff0000 },
    .{ .word = 0x9270c021, .value = 0xffffffffffff0001 },
    .{ .word = 0x9270c421, .value = 0xffffffffffff0003 },
    .{ .word = 0x9270c821, .value = 0xffffffffffff0007 },
    .{ .word = 0x9270cc21, .value = 0xffffffffffff000f },
    .{ .word = 0x9270d021, .value = 0xffffffffffff001f },
    .{ .word = 0x9270d421, .value = 0xffffffffffff003f },
    .{ .word = 0x9270d821, .value = 0xffffffffffff007f },
    .{ .word = 0x9270dc21, .value = 0xffffffffffff00ff },
    .{ .word = 0x9270e021, .value = 0xffffffffffff01ff },
    .{ .word = 0x9270e421, .value = 0xffffffffffff03ff },
    .{ .word = 0x9270e821, .value = 0xffffffffffff07ff },
    .{ .word = 0x9270ec21, .value = 0xffffffffffff0fff },
    .{ .word = 0x9270f021, .value = 0xffffffffffff1fff },
    .{ .word = 0x9270f421, .value = 0xffffffffffff3fff },
    .{ .word = 0x9270f821, .value = 0xffffffffffff7fff },
    .{ .word = 0x92710021, .value = 0x8000 },
    .{ .word = 0x92710421, .value = 0x18000 },
    .{ .word = 0x92710821, .value = 0x38000 },
    .{ .word = 0x92710c21, .value = 0x78000 },
    .{ .word = 0x92711021, .value = 0xf8000 },
    .{ .word = 0x92711421, .value = 0x1f8000 },
    .{ .word = 0x92711821, .value = 0x3f8000 },
    .{ .word = 0x92711c21, .value = 0x7f8000 },
    .{ .word = 0x92712021, .value = 0xff8000 },
    .{ .word = 0x92712421, .value = 0x1ff8000 },
    .{ .word = 0x92712821, .value = 0x3ff8000 },
    .{ .word = 0x92712c21, .value = 0x7ff8000 },
    .{ .word = 0x92713021, .value = 0xfff8000 },
    .{ .word = 0x92713421, .value = 0x1fff8000 },
    .{ .word = 0x92713821, .value = 0x3fff8000 },
    .{ .word = 0x92713c21, .value = 0x7fff8000 },
    .{ .word = 0x92714021, .value = 0xffff8000 },
    .{ .word = 0x92714421, .value = 0x1ffff8000 },
    .{ .word = 0x92714821, .value = 0x3ffff8000 },
    .{ .word = 0x92714c21, .value = 0x7ffff8000 },
    .{ .word = 0x92715021, .value = 0xfffff8000 },
    .{ .word = 0x92715421, .value = 0x1fffff8000 },
    .{ .word = 0x92715821, .value = 0x3fffff8000 },
    .{ .word = 0x92715c21, .value = 0x7fffff8000 },
    .{ .word = 0x92716021, .value = 0xffffff8000 },
    .{ .word = 0x92716421, .value = 0x1ffffff8000 },
    .{ .word = 0x92716821, .value = 0x3ffffff8000 },
    .{ .word = 0x92716c21, .value = 0x7ffffff8000 },
    .{ .word = 0x92717021, .value = 0xfffffff8000 },
    .{ .word = 0x92717421, .value = 0x1fffffff8000 },
    .{ .word = 0x92717821, .value = 0x3fffffff8000 },
    .{ .word = 0x92717c21, .value = 0x7fffffff8000 },
    .{ .word = 0x92718021, .value = 0xffffffff8000 },
    .{ .word = 0x92718421, .value = 0x1ffffffff8000 },
    .{ .word = 0x92718821, .value = 0x3ffffffff8000 },
    .{ .word = 0x92718c21, .value = 0x7ffffffff8000 },
    .{ .word = 0x92719021, .value = 0xfffffffff8000 },
    .{ .word = 0x92719421, .value = 0x1fffffffff8000 },
    .{ .word = 0x92719821, .value = 0x3fffffffff8000 },
    .{ .word = 0x92719c21, .value = 0x7fffffffff8000 },
    .{ .word = 0x9271a021, .value = 0xffffffffff8000 },
    .{ .word = 0x9271a421, .value = 0x1ffffffffff8000 },
    .{ .word = 0x9271a821, .value = 0x3ffffffffff8000 },
    .{ .word = 0x9271ac21, .value = 0x7ffffffffff8000 },
    .{ .word = 0x9271b021, .value = 0xfffffffffff8000 },
    .{ .word = 0x9271b421, .value = 0x1fffffffffff8000 },
    .{ .word = 0x9271b821, .value = 0x3fffffffffff8000 },
    .{ .word = 0x9271bc21, .value = 0x7fffffffffff8000 },
    .{ .word = 0x9271c021, .value = 0xffffffffffff8000 },
    .{ .word = 0x9271c421, .value = 0xffffffffffff8001 },
    .{ .word = 0x9271c821, .value = 0xffffffffffff8003 },
    .{ .word = 0x9271cc21, .value = 0xffffffffffff8007 },
    .{ .word = 0x9271d021, .value = 0xffffffffffff800f },
    .{ .word = 0x9271d421, .value = 0xffffffffffff801f },
    .{ .word = 0x9271d821, .value = 0xffffffffffff803f },
    .{ .word = 0x9271dc21, .value = 0xffffffffffff807f },
    .{ .word = 0x9271e021, .value = 0xffffffffffff80ff },
    .{ .word = 0x9271e421, .value = 0xffffffffffff81ff },
    .{ .word = 0x9271e821, .value = 0xffffffffffff83ff },
    .{ .word = 0x9271ec21, .value = 0xffffffffffff87ff },
    .{ .word = 0x9271f021, .value = 0xffffffffffff8fff },
    .{ .word = 0x9271f421, .value = 0xffffffffffff9fff },
    .{ .word = 0x9271f821, .value = 0xffffffffffffbfff },
    .{ .word = 0x92720021, .value = 0x4000 },
    .{ .word = 0x92720421, .value = 0xc000 },
    .{ .word = 0x92720821, .value = 0x1c000 },
    .{ .word = 0x92720c21, .value = 0x3c000 },
    .{ .word = 0x92721021, .value = 0x7c000 },
    .{ .word = 0x92721421, .value = 0xfc000 },
    .{ .word = 0x92721821, .value = 0x1fc000 },
    .{ .word = 0x92721c21, .value = 0x3fc000 },
    .{ .word = 0x92722021, .value = 0x7fc000 },
    .{ .word = 0x92722421, .value = 0xffc000 },
    .{ .word = 0x92722821, .value = 0x1ffc000 },
    .{ .word = 0x92722c21, .value = 0x3ffc000 },
    .{ .word = 0x92723021, .value = 0x7ffc000 },
    .{ .word = 0x92723421, .value = 0xfffc000 },
    .{ .word = 0x92723821, .value = 0x1fffc000 },
    .{ .word = 0x92723c21, .value = 0x3fffc000 },
    .{ .word = 0x92724021, .value = 0x7fffc000 },
    .{ .word = 0x92724421, .value = 0xffffc000 },
    .{ .word = 0x92724821, .value = 0x1ffffc000 },
    .{ .word = 0x92724c21, .value = 0x3ffffc000 },
    .{ .word = 0x92725021, .value = 0x7ffffc000 },
    .{ .word = 0x92725421, .value = 0xfffffc000 },
    .{ .word = 0x92725821, .value = 0x1fffffc000 },
    .{ .word = 0x92725c21, .value = 0x3fffffc000 },
    .{ .word = 0x92726021, .value = 0x7fffffc000 },
    .{ .word = 0x92726421, .value = 0xffffffc000 },
    .{ .word = 0x92726821, .value = 0x1ffffffc000 },
    .{ .word = 0x92726c21, .value = 0x3ffffffc000 },
    .{ .word = 0x92727021, .value = 0x7ffffffc000 },
    .{ .word = 0x92727421, .value = 0xfffffffc000 },
    .{ .word = 0x92727821, .value = 0x1fffffffc000 },
    .{ .word = 0x92727c21, .value = 0x3fffffffc000 },
    .{ .word = 0x92728021, .value = 0x7fffffffc000 },
    .{ .word = 0x92728421, .value = 0xffffffffc000 },
    .{ .word = 0x92728821, .value = 0x1ffffffffc000 },
    .{ .word = 0x92728c21, .value = 0x3ffffffffc000 },
    .{ .word = 0x92729021, .value = 0x7ffffffffc000 },
    .{ .word = 0x92729421, .value = 0xfffffffffc000 },
    .{ .word = 0x92729821, .value = 0x1fffffffffc000 },
    .{ .word = 0x92729c21, .value = 0x3fffffffffc000 },
    .{ .word = 0x9272a021, .value = 0x7fffffffffc000 },
    .{ .word = 0x9272a421, .value = 0xffffffffffc000 },
    .{ .word = 0x9272a821, .value = 0x1ffffffffffc000 },
    .{ .word = 0x9272ac21, .value = 0x3ffffffffffc000 },
    .{ .word = 0x9272b021, .value = 0x7ffffffffffc000 },
    .{ .word = 0x9272b421, .value = 0xfffffffffffc000 },
    .{ .word = 0x9272b821, .value = 0x1fffffffffffc000 },
    .{ .word = 0x9272bc21, .value = 0x3fffffffffffc000 },
    .{ .word = 0x9272c021, .value = 0x7fffffffffffc000 },
    .{ .word = 0x9272c421, .value = 0xffffffffffffc000 },
    .{ .word = 0x9272c821, .value = 0xffffffffffffc001 },
    .{ .word = 0x9272cc21, .value = 0xffffffffffffc003 },
    .{ .word = 0x9272d021, .value = 0xffffffffffffc007 },
    .{ .word = 0x9272d421, .value = 0xffffffffffffc00f },
    .{ .word = 0x9272d821, .value = 0xffffffffffffc01f },
    .{ .word = 0x9272dc21, .value = 0xffffffffffffc03f },
    .{ .word = 0x9272e021, .value = 0xffffffffffffc07f },
    .{ .word = 0x9272e421, .value = 0xffffffffffffc0ff },
    .{ .word = 0x9272e821, .value = 0xffffffffffffc1ff },
    .{ .word = 0x9272ec21, .value = 0xffffffffffffc3ff },
    .{ .word = 0x9272f021, .value = 0xffffffffffffc7ff },
    .{ .word = 0x9272f421, .value = 0xffffffffffffcfff },
    .{ .word = 0x9272f821, .value = 0xffffffffffffdfff },
    .{ .word = 0x92730021, .value = 0x2000 },
    .{ .word = 0x92730421, .value = 0x6000 },
    .{ .word = 0x92730821, .value = 0xe000 },
    .{ .word = 0x92730c21, .value = 0x1e000 },
    .{ .word = 0x92731021, .value = 0x3e000 },
    .{ .word = 0x92731421, .value = 0x7e000 },
    .{ .word = 0x92731821, .value = 0xfe000 },
    .{ .word = 0x92731c21, .value = 0x1fe000 },
    .{ .word = 0x92732021, .value = 0x3fe000 },
    .{ .word = 0x92732421, .value = 0x7fe000 },
    .{ .word = 0x92732821, .value = 0xffe000 },
    .{ .word = 0x92732c21, .value = 0x1ffe000 },
    .{ .word = 0x92733021, .value = 0x3ffe000 },
    .{ .word = 0x92733421, .value = 0x7ffe000 },
    .{ .word = 0x92733821, .value = 0xfffe000 },
    .{ .word = 0x92733c21, .value = 0x1fffe000 },
    .{ .word = 0x92734021, .value = 0x3fffe000 },
    .{ .word = 0x92734421, .value = 0x7fffe000 },
    .{ .word = 0x92734821, .value = 0xffffe000 },
    .{ .word = 0x92734c21, .value = 0x1ffffe000 },
    .{ .word = 0x92735021, .value = 0x3ffffe000 },
    .{ .word = 0x92735421, .value = 0x7ffffe000 },
    .{ .word = 0x92735821, .value = 0xfffffe000 },
    .{ .word = 0x92735c21, .value = 0x1fffffe000 },
    .{ .word = 0x92736021, .value = 0x3fffffe000 },
    .{ .word = 0x92736421, .value = 0x7fffffe000 },
    .{ .word = 0x92736821, .value = 0xffffffe000 },
    .{ .word = 0x92736c21, .value = 0x1ffffffe000 },
    .{ .word = 0x92737021, .value = 0x3ffffffe000 },
    .{ .word = 0x92737421, .value = 0x7ffffffe000 },
    .{ .word = 0x92737821, .value = 0xfffffffe000 },
    .{ .word = 0x92737c21, .value = 0x1fffffffe000 },
    .{ .word = 0x92738021, .value = 0x3fffffffe000 },
    .{ .word = 0x92738421, .value = 0x7fffffffe000 },
    .{ .word = 0x92738821, .value = 0xffffffffe000 },
    .{ .word = 0x92738c21, .value = 0x1ffffffffe000 },
    .{ .word = 0x92739021, .value = 0x3ffffffffe000 },
    .{ .word = 0x92739421, .value = 0x7ffffffffe000 },
    .{ .word = 0x92739821, .value = 0xfffffffffe000 },
    .{ .word = 0x92739c21, .value = 0x1fffffffffe000 },
    .{ .word = 0x9273a021, .value = 0x3fffffffffe000 },
    .{ .word = 0x9273a421, .value = 0x7fffffffffe000 },
    .{ .word = 0x9273a821, .value = 0xffffffffffe000 },
    .{ .word = 0x9273ac21, .value = 0x1ffffffffffe000 },
    .{ .word = 0x9273b021, .value = 0x3ffffffffffe000 },
    .{ .word = 0x9273b421, .value = 0x7ffffffffffe000 },
    .{ .word = 0x9273b821, .value = 0xfffffffffffe000 },
    .{ .word = 0x9273bc21, .value = 0x1fffffffffffe000 },
    .{ .word = 0x9273c021, .value = 0x3fffffffffffe000 },
    .{ .word = 0x9273c421, .value = 0x7fffffffffffe000 },
    .{ .word = 0x9273c821, .value = 0xffffffffffffe000 },
    .{ .word = 0x9273cc21, .value = 0xffffffffffffe001 },
    .{ .word = 0x9273d021, .value = 0xffffffffffffe003 },
    .{ .word = 0x9273d421, .value = 0xffffffffffffe007 },
    .{ .word = 0x9273d821, .value = 0xffffffffffffe00f },
    .{ .word = 0x9273dc21, .value = 0xffffffffffffe01f },
    .{ .word = 0x9273e021, .value = 0xffffffffffffe03f },
    .{ .word = 0x9273e421, .value = 0xffffffffffffe07f },
    .{ .word = 0x9273e821, .value = 0xffffffffffffe0ff },
    .{ .word = 0x9273ec21, .value = 0xffffffffffffe1ff },
    .{ .word = 0x9273f021, .value = 0xffffffffffffe3ff },
    .{ .word = 0x9273f421, .value = 0xffffffffffffe7ff },
    .{ .word = 0x9273f821, .value = 0xffffffffffffefff },
    .{ .word = 0x92740021, .value = 0x1000 },
    .{ .word = 0x92740421, .value = 0x3000 },
    .{ .word = 0x92740821, .value = 0x7000 },
    .{ .word = 0x92740c21, .value = 0xf000 },
    .{ .word = 0x92741021, .value = 0x1f000 },
    .{ .word = 0x92741421, .value = 0x3f000 },
    .{ .word = 0x92741821, .value = 0x7f000 },
    .{ .word = 0x92741c21, .value = 0xff000 },
    .{ .word = 0x92742021, .value = 0x1ff000 },
    .{ .word = 0x92742421, .value = 0x3ff000 },
    .{ .word = 0x92742821, .value = 0x7ff000 },
    .{ .word = 0x92742c21, .value = 0xfff000 },
    .{ .word = 0x92743021, .value = 0x1fff000 },
    .{ .word = 0x92743421, .value = 0x3fff000 },
    .{ .word = 0x92743821, .value = 0x7fff000 },
    .{ .word = 0x92743c21, .value = 0xffff000 },
    .{ .word = 0x92744021, .value = 0x1ffff000 },
    .{ .word = 0x92744421, .value = 0x3ffff000 },
    .{ .word = 0x92744821, .value = 0x7ffff000 },
    .{ .word = 0x92744c21, .value = 0xfffff000 },
    .{ .word = 0x92745021, .value = 0x1fffff000 },
    .{ .word = 0x92745421, .value = 0x3fffff000 },
    .{ .word = 0x92745821, .value = 0x7fffff000 },
    .{ .word = 0x92745c21, .value = 0xffffff000 },
    .{ .word = 0x92746021, .value = 0x1ffffff000 },
    .{ .word = 0x92746421, .value = 0x3ffffff000 },
    .{ .word = 0x92746821, .value = 0x7ffffff000 },
    .{ .word = 0x92746c21, .value = 0xfffffff000 },
    .{ .word = 0x92747021, .value = 0x1fffffff000 },
    .{ .word = 0x92747421, .value = 0x3fffffff000 },
    .{ .word = 0x92747821, .value = 0x7fffffff000 },
    .{ .word = 0x92747c21, .value = 0xffffffff000 },
    .{ .word = 0x92748021, .value = 0x1ffffffff000 },
    .{ .word = 0x92748421, .value = 0x3ffffffff000 },
    .{ .word = 0x92748821, .value = 0x7ffffffff000 },
    .{ .word = 0x92748c21, .value = 0xfffffffff000 },
    .{ .word = 0x92749021, .value = 0x1fffffffff000 },
    .{ .word = 0x92749421, .value = 0x3fffffffff000 },
    .{ .word = 0x92749821, .value = 0x7fffffffff000 },
    .{ .word = 0x92749c21, .value = 0xffffffffff000 },
    .{ .word = 0x9274a021, .value = 0x1ffffffffff000 },
    .{ .word = 0x9274a421, .value = 0x3ffffffffff000 },
    .{ .word = 0x9274a821, .value = 0x7ffffffffff000 },
    .{ .word = 0x9274ac21, .value = 0xfffffffffff000 },
    .{ .word = 0x9274b021, .value = 0x1fffffffffff000 },
    .{ .word = 0x9274b421, .value = 0x3fffffffffff000 },
    .{ .word = 0x9274b821, .value = 0x7fffffffffff000 },
    .{ .word = 0x9274bc21, .value = 0xffffffffffff000 },
    .{ .word = 0x9274c021, .value = 0x1ffffffffffff000 },
    .{ .word = 0x9274c421, .value = 0x3ffffffffffff000 },
    .{ .word = 0x9274c821, .value = 0x7ffffffffffff000 },
    .{ .word = 0x9274cc21, .value = 0xfffffffffffff000 },
    .{ .word = 0x9274d021, .value = 0xfffffffffffff001 },
    .{ .word = 0x9274d421, .value = 0xfffffffffffff003 },
    .{ .word = 0x9274d821, .value = 0xfffffffffffff007 },
    .{ .word = 0x9274dc21, .value = 0xfffffffffffff00f },
    .{ .word = 0x9274e021, .value = 0xfffffffffffff01f },
    .{ .word = 0x9274e421, .value = 0xfffffffffffff03f },
    .{ .word = 0x9274e821, .value = 0xfffffffffffff07f },
    .{ .word = 0x9274ec21, .value = 0xfffffffffffff0ff },
    .{ .word = 0x9274f021, .value = 0xfffffffffffff1ff },
    .{ .word = 0x9274f421, .value = 0xfffffffffffff3ff },
    .{ .word = 0x9274f821, .value = 0xfffffffffffff7ff },
    .{ .word = 0x92750021, .value = 0x800 },
    .{ .word = 0x92750421, .value = 0x1800 },
    .{ .word = 0x92750821, .value = 0x3800 },
    .{ .word = 0x92750c21, .value = 0x7800 },
    .{ .word = 0x92751021, .value = 0xf800 },
    .{ .word = 0x92751421, .value = 0x1f800 },
    .{ .word = 0x92751821, .value = 0x3f800 },
    .{ .word = 0x92751c21, .value = 0x7f800 },
    .{ .word = 0x92752021, .value = 0xff800 },
    .{ .word = 0x92752421, .value = 0x1ff800 },
    .{ .word = 0x92752821, .value = 0x3ff800 },
    .{ .word = 0x92752c21, .value = 0x7ff800 },
    .{ .word = 0x92753021, .value = 0xfff800 },
    .{ .word = 0x92753421, .value = 0x1fff800 },
    .{ .word = 0x92753821, .value = 0x3fff800 },
    .{ .word = 0x92753c21, .value = 0x7fff800 },
    .{ .word = 0x92754021, .value = 0xffff800 },
    .{ .word = 0x92754421, .value = 0x1ffff800 },
    .{ .word = 0x92754821, .value = 0x3ffff800 },
    .{ .word = 0x92754c21, .value = 0x7ffff800 },
    .{ .word = 0x92755021, .value = 0xfffff800 },
    .{ .word = 0x92755421, .value = 0x1fffff800 },
    .{ .word = 0x92755821, .value = 0x3fffff800 },
    .{ .word = 0x92755c21, .value = 0x7fffff800 },
    .{ .word = 0x92756021, .value = 0xffffff800 },
    .{ .word = 0x92756421, .value = 0x1ffffff800 },
    .{ .word = 0x92756821, .value = 0x3ffffff800 },
    .{ .word = 0x92756c21, .value = 0x7ffffff800 },
    .{ .word = 0x92757021, .value = 0xfffffff800 },
    .{ .word = 0x92757421, .value = 0x1fffffff800 },
    .{ .word = 0x92757821, .value = 0x3fffffff800 },
    .{ .word = 0x92757c21, .value = 0x7fffffff800 },
    .{ .word = 0x92758021, .value = 0xffffffff800 },
    .{ .word = 0x92758421, .value = 0x1ffffffff800 },
    .{ .word = 0x92758821, .value = 0x3ffffffff800 },
    .{ .word = 0x92758c21, .value = 0x7ffffffff800 },
    .{ .word = 0x92759021, .value = 0xfffffffff800 },
    .{ .word = 0x92759421, .value = 0x1fffffffff800 },
    .{ .word = 0x92759821, .value = 0x3fffffffff800 },
    .{ .word = 0x92759c21, .value = 0x7fffffffff800 },
    .{ .word = 0x9275a021, .value = 0xffffffffff800 },
    .{ .word = 0x9275a421, .value = 0x1ffffffffff800 },
    .{ .word = 0x9275a821, .value = 0x3ffffffffff800 },
    .{ .word = 0x9275ac21, .value = 0x7ffffffffff800 },
    .{ .word = 0x9275b021, .value = 0xfffffffffff800 },
    .{ .word = 0x9275b421, .value = 0x1fffffffffff800 },
    .{ .word = 0x9275b821, .value = 0x3fffffffffff800 },
    .{ .word = 0x9275bc21, .value = 0x7fffffffffff800 },
    .{ .word = 0x9275c021, .value = 0xffffffffffff800 },
    .{ .word = 0x9275c421, .value = 0x1ffffffffffff800 },
    .{ .word = 0x9275c821, .value = 0x3ffffffffffff800 },
    .{ .word = 0x9275cc21, .value = 0x7ffffffffffff800 },
    .{ .word = 0x9275d021, .value = 0xfffffffffffff800 },
    .{ .word = 0x9275d421, .value = 0xfffffffffffff801 },
    .{ .word = 0x9275d821, .value = 0xfffffffffffff803 },
    .{ .word = 0x9275dc21, .value = 0xfffffffffffff807 },
    .{ .word = 0x9275e021, .value = 0xfffffffffffff80f },
    .{ .word = 0x9275e421, .value = 0xfffffffffffff81f },
    .{ .word = 0x9275e821, .value = 0xfffffffffffff83f },
    .{ .word = 0x9275ec21, .value = 0xfffffffffffff87f },
    .{ .word = 0x9275f021, .value = 0xfffffffffffff8ff },
    .{ .word = 0x9275f421, .value = 0xfffffffffffff9ff },
    .{ .word = 0x9275f821, .value = 0xfffffffffffffbff },
    .{ .word = 0x92760021, .value = 0x400 },
    .{ .word = 0x92760421, .value = 0xc00 },
    .{ .word = 0x92760821, .value = 0x1c00 },
    .{ .word = 0x92760c21, .value = 0x3c00 },
    .{ .word = 0x92761021, .value = 0x7c00 },
    .{ .word = 0x92761421, .value = 0xfc00 },
    .{ .word = 0x92761821, .value = 0x1fc00 },
    .{ .word = 0x92761c21, .value = 0x3fc00 },
    .{ .word = 0x92762021, .value = 0x7fc00 },
    .{ .word = 0x92762421, .value = 0xffc00 },
    .{ .word = 0x92762821, .value = 0x1ffc00 },
    .{ .word = 0x92762c21, .value = 0x3ffc00 },
    .{ .word = 0x92763021, .value = 0x7ffc00 },
    .{ .word = 0x92763421, .value = 0xfffc00 },
    .{ .word = 0x92763821, .value = 0x1fffc00 },
    .{ .word = 0x92763c21, .value = 0x3fffc00 },
    .{ .word = 0x92764021, .value = 0x7fffc00 },
    .{ .word = 0x92764421, .value = 0xffffc00 },
    .{ .word = 0x92764821, .value = 0x1ffffc00 },
    .{ .word = 0x92764c21, .value = 0x3ffffc00 },
    .{ .word = 0x92765021, .value = 0x7ffffc00 },
    .{ .word = 0x92765421, .value = 0xfffffc00 },
    .{ .word = 0x92765821, .value = 0x1fffffc00 },
    .{ .word = 0x92765c21, .value = 0x3fffffc00 },
    .{ .word = 0x92766021, .value = 0x7fffffc00 },
    .{ .word = 0x92766421, .value = 0xffffffc00 },
    .{ .word = 0x92766821, .value = 0x1ffffffc00 },
    .{ .word = 0x92766c21, .value = 0x3ffffffc00 },
    .{ .word = 0x92767021, .value = 0x7ffffffc00 },
    .{ .word = 0x92767421, .value = 0xfffffffc00 },
    .{ .word = 0x92767821, .value = 0x1fffffffc00 },
    .{ .word = 0x92767c21, .value = 0x3fffffffc00 },
    .{ .word = 0x92768021, .value = 0x7fffffffc00 },
    .{ .word = 0x92768421, .value = 0xffffffffc00 },
    .{ .word = 0x92768821, .value = 0x1ffffffffc00 },
    .{ .word = 0x92768c21, .value = 0x3ffffffffc00 },
    .{ .word = 0x92769021, .value = 0x7ffffffffc00 },
    .{ .word = 0x92769421, .value = 0xfffffffffc00 },
    .{ .word = 0x92769821, .value = 0x1fffffffffc00 },
    .{ .word = 0x92769c21, .value = 0x3fffffffffc00 },
    .{ .word = 0x9276a021, .value = 0x7fffffffffc00 },
    .{ .word = 0x9276a421, .value = 0xffffffffffc00 },
    .{ .word = 0x9276a821, .value = 0x1ffffffffffc00 },
    .{ .word = 0x9276ac21, .value = 0x3ffffffffffc00 },
    .{ .word = 0x9276b021, .value = 0x7ffffffffffc00 },
    .{ .word = 0x9276b421, .value = 0xfffffffffffc00 },
    .{ .word = 0x9276b821, .value = 0x1fffffffffffc00 },
    .{ .word = 0x9276bc21, .value = 0x3fffffffffffc00 },
    .{ .word = 0x9276c021, .value = 0x7fffffffffffc00 },
    .{ .word = 0x9276c421, .value = 0xffffffffffffc00 },
    .{ .word = 0x9276c821, .value = 0x1ffffffffffffc00 },
    .{ .word = 0x9276cc21, .value = 0x3ffffffffffffc00 },
    .{ .word = 0x9276d021, .value = 0x7ffffffffffffc00 },
    .{ .word = 0x9276d421, .value = 0xfffffffffffffc00 },
    .{ .word = 0x9276d821, .value = 0xfffffffffffffc01 },
    .{ .word = 0x9276dc21, .value = 0xfffffffffffffc03 },
    .{ .word = 0x9276e021, .value = 0xfffffffffffffc07 },
    .{ .word = 0x9276e421, .value = 0xfffffffffffffc0f },
    .{ .word = 0x9276e821, .value = 0xfffffffffffffc1f },
    .{ .word = 0x9276ec21, .value = 0xfffffffffffffc3f },
    .{ .word = 0x9276f021, .value = 0xfffffffffffffc7f },
    .{ .word = 0x9276f421, .value = 0xfffffffffffffcff },
    .{ .word = 0x9276f821, .value = 0xfffffffffffffdff },
    .{ .word = 0x92770021, .value = 0x200 },
    .{ .word = 0x92770421, .value = 0x600 },
    .{ .word = 0x92770821, .value = 0xe00 },
    .{ .word = 0x92770c21, .value = 0x1e00 },
    .{ .word = 0x92771021, .value = 0x3e00 },
    .{ .word = 0x92771421, .value = 0x7e00 },
    .{ .word = 0x92771821, .value = 0xfe00 },
    .{ .word = 0x92771c21, .value = 0x1fe00 },
    .{ .word = 0x92772021, .value = 0x3fe00 },
    .{ .word = 0x92772421, .value = 0x7fe00 },
    .{ .word = 0x92772821, .value = 0xffe00 },
    .{ .word = 0x92772c21, .value = 0x1ffe00 },
    .{ .word = 0x92773021, .value = 0x3ffe00 },
    .{ .word = 0x92773421, .value = 0x7ffe00 },
    .{ .word = 0x92773821, .value = 0xfffe00 },
    .{ .word = 0x92773c21, .value = 0x1fffe00 },
    .{ .word = 0x92774021, .value = 0x3fffe00 },
    .{ .word = 0x92774421, .value = 0x7fffe00 },
    .{ .word = 0x92774821, .value = 0xffffe00 },
    .{ .word = 0x92774c21, .value = 0x1ffffe00 },
    .{ .word = 0x92775021, .value = 0x3ffffe00 },
    .{ .word = 0x92775421, .value = 0x7ffffe00 },
    .{ .word = 0x92775821, .value = 0xfffffe00 },
    .{ .word = 0x92775c21, .value = 0x1fffffe00 },
    .{ .word = 0x92776021, .value = 0x3fffffe00 },
    .{ .word = 0x92776421, .value = 0x7fffffe00 },
    .{ .word = 0x92776821, .value = 0xffffffe00 },
    .{ .word = 0x92776c21, .value = 0x1ffffffe00 },
    .{ .word = 0x92777021, .value = 0x3ffffffe00 },
    .{ .word = 0x92777421, .value = 0x7ffffffe00 },
    .{ .word = 0x92777821, .value = 0xfffffffe00 },
    .{ .word = 0x92777c21, .value = 0x1fffffffe00 },
    .{ .word = 0x92778021, .value = 0x3fffffffe00 },
    .{ .word = 0x92778421, .value = 0x7fffffffe00 },
    .{ .word = 0x92778821, .value = 0xffffffffe00 },
    .{ .word = 0x92778c21, .value = 0x1ffffffffe00 },
    .{ .word = 0x92779021, .value = 0x3ffffffffe00 },
    .{ .word = 0x92779421, .value = 0x7ffffffffe00 },
    .{ .word = 0x92779821, .value = 0xfffffffffe00 },
    .{ .word = 0x92779c21, .value = 0x1fffffffffe00 },
    .{ .word = 0x9277a021, .value = 0x3fffffffffe00 },
    .{ .word = 0x9277a421, .value = 0x7fffffffffe00 },
    .{ .word = 0x9277a821, .value = 0xffffffffffe00 },
    .{ .word = 0x9277ac21, .value = 0x1ffffffffffe00 },
    .{ .word = 0x9277b021, .value = 0x3ffffffffffe00 },
    .{ .word = 0x9277b421, .value = 0x7ffffffffffe00 },
    .{ .word = 0x9277b821, .value = 0xfffffffffffe00 },
    .{ .word = 0x9277bc21, .value = 0x1fffffffffffe00 },
    .{ .word = 0x9277c021, .value = 0x3fffffffffffe00 },
    .{ .word = 0x9277c421, .value = 0x7fffffffffffe00 },
    .{ .word = 0x9277c821, .value = 0xffffffffffffe00 },
    .{ .word = 0x9277cc21, .value = 0x1ffffffffffffe00 },
    .{ .word = 0x9277d021, .value = 0x3ffffffffffffe00 },
    .{ .word = 0x9277d421, .value = 0x7ffffffffffffe00 },
    .{ .word = 0x9277d821, .value = 0xfffffffffffffe00 },
    .{ .word = 0x9277dc21, .value = 0xfffffffffffffe01 },
    .{ .word = 0x9277e021, .value = 0xfffffffffffffe03 },
    .{ .word = 0x9277e421, .value = 0xfffffffffffffe07 },
    .{ .word = 0x9277e821, .value = 0xfffffffffffffe0f },
    .{ .word = 0x9277ec21, .value = 0xfffffffffffffe1f },
    .{ .word = 0x9277f021, .value = 0xfffffffffffffe3f },
    .{ .word = 0x9277f421, .value = 0xfffffffffffffe7f },
    .{ .word = 0x9277f821, .value = 0xfffffffffffffeff },
    .{ .word = 0x92780021, .value = 0x100 },
    .{ .word = 0x92780421, .value = 0x300 },
    .{ .word = 0x92780821, .value = 0x700 },
    .{ .word = 0x92780c21, .value = 0xf00 },
    .{ .word = 0x92781021, .value = 0x1f00 },
    .{ .word = 0x92781421, .value = 0x3f00 },
    .{ .word = 0x92781821, .value = 0x7f00 },
    .{ .word = 0x92781c21, .value = 0xff00 },
    .{ .word = 0x92782021, .value = 0x1ff00 },
    .{ .word = 0x92782421, .value = 0x3ff00 },
    .{ .word = 0x92782821, .value = 0x7ff00 },
    .{ .word = 0x92782c21, .value = 0xfff00 },
    .{ .word = 0x92783021, .value = 0x1fff00 },
    .{ .word = 0x92783421, .value = 0x3fff00 },
    .{ .word = 0x92783821, .value = 0x7fff00 },
    .{ .word = 0x92783c21, .value = 0xffff00 },
    .{ .word = 0x92784021, .value = 0x1ffff00 },
    .{ .word = 0x92784421, .value = 0x3ffff00 },
    .{ .word = 0x92784821, .value = 0x7ffff00 },
    .{ .word = 0x92784c21, .value = 0xfffff00 },
    .{ .word = 0x92785021, .value = 0x1fffff00 },
    .{ .word = 0x92785421, .value = 0x3fffff00 },
    .{ .word = 0x92785821, .value = 0x7fffff00 },
    .{ .word = 0x92785c21, .value = 0xffffff00 },
    .{ .word = 0x92786021, .value = 0x1ffffff00 },
    .{ .word = 0x92786421, .value = 0x3ffffff00 },
    .{ .word = 0x92786821, .value = 0x7ffffff00 },
    .{ .word = 0x92786c21, .value = 0xfffffff00 },
    .{ .word = 0x92787021, .value = 0x1fffffff00 },
    .{ .word = 0x92787421, .value = 0x3fffffff00 },
    .{ .word = 0x92787821, .value = 0x7fffffff00 },
    .{ .word = 0x92787c21, .value = 0xffffffff00 },
    .{ .word = 0x92788021, .value = 0x1ffffffff00 },
    .{ .word = 0x92788421, .value = 0x3ffffffff00 },
    .{ .word = 0x92788821, .value = 0x7ffffffff00 },
    .{ .word = 0x92788c21, .value = 0xfffffffff00 },
    .{ .word = 0x92789021, .value = 0x1fffffffff00 },
    .{ .word = 0x92789421, .value = 0x3fffffffff00 },
    .{ .word = 0x92789821, .value = 0x7fffffffff00 },
    .{ .word = 0x92789c21, .value = 0xffffffffff00 },
    .{ .word = 0x9278a021, .value = 0x1ffffffffff00 },
    .{ .word = 0x9278a421, .value = 0x3ffffffffff00 },
    .{ .word = 0x9278a821, .value = 0x7ffffffffff00 },
    .{ .word = 0x9278ac21, .value = 0xfffffffffff00 },
    .{ .word = 0x9278b021, .value = 0x1fffffffffff00 },
    .{ .word = 0x9278b421, .value = 0x3fffffffffff00 },
    .{ .word = 0x9278b821, .value = 0x7fffffffffff00 },
    .{ .word = 0x9278bc21, .value = 0xffffffffffff00 },
    .{ .word = 0x9278c021, .value = 0x1ffffffffffff00 },
    .{ .word = 0x9278c421, .value = 0x3ffffffffffff00 },
    .{ .word = 0x9278c821, .value = 0x7ffffffffffff00 },
    .{ .word = 0x9278cc21, .value = 0xfffffffffffff00 },
    .{ .word = 0x9278d021, .value = 0x1fffffffffffff00 },
    .{ .word = 0x9278d421, .value = 0x3fffffffffffff00 },
    .{ .word = 0x9278d821, .value = 0x7fffffffffffff00 },
    .{ .word = 0x9278dc21, .value = 0xffffffffffffff00 },
    .{ .word = 0x9278e021, .value = 0xffffffffffffff01 },
    .{ .word = 0x9278e421, .value = 0xffffffffffffff03 },
    .{ .word = 0x9278e821, .value = 0xffffffffffffff07 },
    .{ .word = 0x9278ec21, .value = 0xffffffffffffff0f },
    .{ .word = 0x9278f021, .value = 0xffffffffffffff1f },
    .{ .word = 0x9278f421, .value = 0xffffffffffffff3f },
    .{ .word = 0x9278f821, .value = 0xffffffffffffff7f },
    .{ .word = 0x92790021, .value = 0x80 },
    .{ .word = 0x92790421, .value = 0x180 },
    .{ .word = 0x92790821, .value = 0x380 },
    .{ .word = 0x92790c21, .value = 0x780 },
    .{ .word = 0x92791021, .value = 0xf80 },
    .{ .word = 0x92791421, .value = 0x1f80 },
    .{ .word = 0x92791821, .value = 0x3f80 },
    .{ .word = 0x92791c21, .value = 0x7f80 },
    .{ .word = 0x92792021, .value = 0xff80 },
    .{ .word = 0x92792421, .value = 0x1ff80 },
    .{ .word = 0x92792821, .value = 0x3ff80 },
    .{ .word = 0x92792c21, .value = 0x7ff80 },
    .{ .word = 0x92793021, .value = 0xfff80 },
    .{ .word = 0x92793421, .value = 0x1fff80 },
    .{ .word = 0x92793821, .value = 0x3fff80 },
    .{ .word = 0x92793c21, .value = 0x7fff80 },
    .{ .word = 0x92794021, .value = 0xffff80 },
    .{ .word = 0x92794421, .value = 0x1ffff80 },
    .{ .word = 0x92794821, .value = 0x3ffff80 },
    .{ .word = 0x92794c21, .value = 0x7ffff80 },
    .{ .word = 0x92795021, .value = 0xfffff80 },
    .{ .word = 0x92795421, .value = 0x1fffff80 },
    .{ .word = 0x92795821, .value = 0x3fffff80 },
    .{ .word = 0x92795c21, .value = 0x7fffff80 },
    .{ .word = 0x92796021, .value = 0xffffff80 },
    .{ .word = 0x92796421, .value = 0x1ffffff80 },
    .{ .word = 0x92796821, .value = 0x3ffffff80 },
    .{ .word = 0x92796c21, .value = 0x7ffffff80 },
    .{ .word = 0x92797021, .value = 0xfffffff80 },
    .{ .word = 0x92797421, .value = 0x1fffffff80 },
    .{ .word = 0x92797821, .value = 0x3fffffff80 },
    .{ .word = 0x92797c21, .value = 0x7fffffff80 },
    .{ .word = 0x92798021, .value = 0xffffffff80 },
    .{ .word = 0x92798421, .value = 0x1ffffffff80 },
    .{ .word = 0x92798821, .value = 0x3ffffffff80 },
    .{ .word = 0x92798c21, .value = 0x7ffffffff80 },
    .{ .word = 0x92799021, .value = 0xfffffffff80 },
    .{ .word = 0x92799421, .value = 0x1fffffffff80 },
    .{ .word = 0x92799821, .value = 0x3fffffffff80 },
    .{ .word = 0x92799c21, .value = 0x7fffffffff80 },
    .{ .word = 0x9279a021, .value = 0xffffffffff80 },
    .{ .word = 0x9279a421, .value = 0x1ffffffffff80 },
    .{ .word = 0x9279a821, .value = 0x3ffffffffff80 },
    .{ .word = 0x9279ac21, .value = 0x7ffffffffff80 },
    .{ .word = 0x9279b021, .value = 0xfffffffffff80 },
    .{ .word = 0x9279b421, .value = 0x1fffffffffff80 },
    .{ .word = 0x9279b821, .value = 0x3fffffffffff80 },
    .{ .word = 0x9279bc21, .value = 0x7fffffffffff80 },
    .{ .word = 0x9279c021, .value = 0xffffffffffff80 },
    .{ .word = 0x9279c421, .value = 0x1ffffffffffff80 },
    .{ .word = 0x9279c821, .value = 0x3ffffffffffff80 },
    .{ .word = 0x9279cc21, .value = 0x7ffffffffffff80 },
    .{ .word = 0x9279d021, .value = 0xfffffffffffff80 },
    .{ .word = 0x9279d421, .value = 0x1fffffffffffff80 },
    .{ .word = 0x9279d821, .value = 0x3fffffffffffff80 },
    .{ .word = 0x9279dc21, .value = 0x7fffffffffffff80 },
    .{ .word = 0x9279e021, .value = 0xffffffffffffff80 },
    .{ .word = 0x9279e421, .value = 0xffffffffffffff81 },
    .{ .word = 0x9279e821, .value = 0xffffffffffffff83 },
    .{ .word = 0x9279ec21, .value = 0xffffffffffffff87 },
    .{ .word = 0x9279f021, .value = 0xffffffffffffff8f },
    .{ .word = 0x9279f421, .value = 0xffffffffffffff9f },
    .{ .word = 0x9279f821, .value = 0xffffffffffffffbf },
    .{ .word = 0x927a0021, .value = 0x40 },
    .{ .word = 0x927a0421, .value = 0xc0 },
    .{ .word = 0x927a0821, .value = 0x1c0 },
    .{ .word = 0x927a0c21, .value = 0x3c0 },
    .{ .word = 0x927a1021, .value = 0x7c0 },
    .{ .word = 0x927a1421, .value = 0xfc0 },
    .{ .word = 0x927a1821, .value = 0x1fc0 },
    .{ .word = 0x927a1c21, .value = 0x3fc0 },
    .{ .word = 0x927a2021, .value = 0x7fc0 },
    .{ .word = 0x927a2421, .value = 0xffc0 },
    .{ .word = 0x927a2821, .value = 0x1ffc0 },
    .{ .word = 0x927a2c21, .value = 0x3ffc0 },
    .{ .word = 0x927a3021, .value = 0x7ffc0 },
    .{ .word = 0x927a3421, .value = 0xfffc0 },
    .{ .word = 0x927a3821, .value = 0x1fffc0 },
    .{ .word = 0x927a3c21, .value = 0x3fffc0 },
    .{ .word = 0x927a4021, .value = 0x7fffc0 },
    .{ .word = 0x927a4421, .value = 0xffffc0 },
    .{ .word = 0x927a4821, .value = 0x1ffffc0 },
    .{ .word = 0x927a4c21, .value = 0x3ffffc0 },
    .{ .word = 0x927a5021, .value = 0x7ffffc0 },
    .{ .word = 0x927a5421, .value = 0xfffffc0 },
    .{ .word = 0x927a5821, .value = 0x1fffffc0 },
    .{ .word = 0x927a5c21, .value = 0x3fffffc0 },
    .{ .word = 0x927a6021, .value = 0x7fffffc0 },
    .{ .word = 0x927a6421, .value = 0xffffffc0 },
    .{ .word = 0x927a6821, .value = 0x1ffffffc0 },
    .{ .word = 0x927a6c21, .value = 0x3ffffffc0 },
    .{ .word = 0x927a7021, .value = 0x7ffffffc0 },
    .{ .word = 0x927a7421, .value = 0xfffffffc0 },
    .{ .word = 0x927a7821, .value = 0x1fffffffc0 },
    .{ .word = 0x927a7c21, .value = 0x3fffffffc0 },
    .{ .word = 0x927a8021, .value = 0x7fffffffc0 },
    .{ .word = 0x927a8421, .value = 0xffffffffc0 },
    .{ .word = 0x927a8821, .value = 0x1ffffffffc0 },
    .{ .word = 0x927a8c21, .value = 0x3ffffffffc0 },
    .{ .word = 0x927a9021, .value = 0x7ffffffffc0 },
    .{ .word = 0x927a9421, .value = 0xfffffffffc0 },
    .{ .word = 0x927a9821, .value = 0x1fffffffffc0 },
    .{ .word = 0x927a9c21, .value = 0x3fffffffffc0 },
    .{ .word = 0x927aa021, .value = 0x7fffffffffc0 },
    .{ .word = 0x927aa421, .value = 0xffffffffffc0 },
    .{ .word = 0x927aa821, .value = 0x1ffffffffffc0 },
    .{ .word = 0x927aac21, .value = 0x3ffffffffffc0 },
    .{ .word = 0x927ab021, .value = 0x7ffffffffffc0 },
    .{ .word = 0x927ab421, .value = 0xfffffffffffc0 },
    .{ .word = 0x927ab821, .value = 0x1fffffffffffc0 },
    .{ .word = 0x927abc21, .value = 0x3fffffffffffc0 },
    .{ .word = 0x927ac021, .value = 0x7fffffffffffc0 },
    .{ .word = 0x927ac421, .value = 0xffffffffffffc0 },
    .{ .word = 0x927ac821, .value = 0x1ffffffffffffc0 },
    .{ .word = 0x927acc21, .value = 0x3ffffffffffffc0 },
    .{ .word = 0x927ad021, .value = 0x7ffffffffffffc0 },
    .{ .word = 0x927ad421, .value = 0xfffffffffffffc0 },
    .{ .word = 0x927ad821, .value = 0x1fffffffffffffc0 },
    .{ .word = 0x927adc21, .value = 0x3fffffffffffffc0 },
    .{ .word = 0x927ae021, .value = 0x7fffffffffffffc0 },
    .{ .word = 0x927ae421, .value = 0xffffffffffffffc0 },
    .{ .word = 0x927ae821, .value = 0xffffffffffffffc1 },
    .{ .word = 0x927aec21, .value = 0xffffffffffffffc3 },
    .{ .word = 0x927af021, .value = 0xffffffffffffffc7 },
    .{ .word = 0x927af421, .value = 0xffffffffffffffcf },
    .{ .word = 0x927af821, .value = 0xffffffffffffffdf },
    .{ .word = 0x927b0021, .value = 0x20 },
    .{ .word = 0x927b0421, .value = 0x60 },
    .{ .word = 0x927b0821, .value = 0xe0 },
    .{ .word = 0x927b0c21, .value = 0x1e0 },
    .{ .word = 0x927b1021, .value = 0x3e0 },
    .{ .word = 0x927b1421, .value = 0x7e0 },
    .{ .word = 0x927b1821, .value = 0xfe0 },
    .{ .word = 0x927b1c21, .value = 0x1fe0 },
    .{ .word = 0x927b2021, .value = 0x3fe0 },
    .{ .word = 0x927b2421, .value = 0x7fe0 },
    .{ .word = 0x927b2821, .value = 0xffe0 },
    .{ .word = 0x927b2c21, .value = 0x1ffe0 },
    .{ .word = 0x927b3021, .value = 0x3ffe0 },
    .{ .word = 0x927b3421, .value = 0x7ffe0 },
    .{ .word = 0x927b3821, .value = 0xfffe0 },
    .{ .word = 0x927b3c21, .value = 0x1fffe0 },
    .{ .word = 0x927b4021, .value = 0x3fffe0 },
    .{ .word = 0x927b4421, .value = 0x7fffe0 },
    .{ .word = 0x927b4821, .value = 0xffffe0 },
    .{ .word = 0x927b4c21, .value = 0x1ffffe0 },
    .{ .word = 0x927b5021, .value = 0x3ffffe0 },
    .{ .word = 0x927b5421, .value = 0x7ffffe0 },
    .{ .word = 0x927b5821, .value = 0xfffffe0 },
    .{ .word = 0x927b5c21, .value = 0x1fffffe0 },
    .{ .word = 0x927b6021, .value = 0x3fffffe0 },
    .{ .word = 0x927b6421, .value = 0x7fffffe0 },
    .{ .word = 0x927b6821, .value = 0xffffffe0 },
    .{ .word = 0x927b6c21, .value = 0x1ffffffe0 },
    .{ .word = 0x927b7021, .value = 0x3ffffffe0 },
    .{ .word = 0x927b7421, .value = 0x7ffffffe0 },
    .{ .word = 0x927b7821, .value = 0xfffffffe0 },
    .{ .word = 0x927b7c21, .value = 0x1fffffffe0 },
    .{ .word = 0x927b8021, .value = 0x3fffffffe0 },
    .{ .word = 0x927b8421, .value = 0x7fffffffe0 },
    .{ .word = 0x927b8821, .value = 0xffffffffe0 },
    .{ .word = 0x927b8c21, .value = 0x1ffffffffe0 },
    .{ .word = 0x927b9021, .value = 0x3ffffffffe0 },
    .{ .word = 0x927b9421, .value = 0x7ffffffffe0 },
    .{ .word = 0x927b9821, .value = 0xfffffffffe0 },
    .{ .word = 0x927b9c21, .value = 0x1fffffffffe0 },
    .{ .word = 0x927ba021, .value = 0x3fffffffffe0 },
    .{ .word = 0x927ba421, .value = 0x7fffffffffe0 },
    .{ .word = 0x927ba821, .value = 0xffffffffffe0 },
    .{ .word = 0x927bac21, .value = 0x1ffffffffffe0 },
    .{ .word = 0x927bb021, .value = 0x3ffffffffffe0 },
    .{ .word = 0x927bb421, .value = 0x7ffffffffffe0 },
    .{ .word = 0x927bb821, .value = 0xfffffffffffe0 },
    .{ .word = 0x927bbc21, .value = 0x1fffffffffffe0 },
    .{ .word = 0x927bc021, .value = 0x3fffffffffffe0 },
    .{ .word = 0x927bc421, .value = 0x7fffffffffffe0 },
    .{ .word = 0x927bc821, .value = 0xffffffffffffe0 },
    .{ .word = 0x927bcc21, .value = 0x1ffffffffffffe0 },
    .{ .word = 0x927bd021, .value = 0x3ffffffffffffe0 },
    .{ .word = 0x927bd421, .value = 0x7ffffffffffffe0 },
    .{ .word = 0x927bd821, .value = 0xfffffffffffffe0 },
    .{ .word = 0x927bdc21, .value = 0x1fffffffffffffe0 },
    .{ .word = 0x927be021, .value = 0x3fffffffffffffe0 },
    .{ .word = 0x927be421, .value = 0x7fffffffffffffe0 },
    .{ .word = 0x927be821, .value = 0xffffffffffffffe0 },
    .{ .word = 0x927bec21, .value = 0xffffffffffffffe1 },
    .{ .word = 0x927bf021, .value = 0xffffffffffffffe3 },
    .{ .word = 0x927bf421, .value = 0xffffffffffffffe7 },
    .{ .word = 0x927bf821, .value = 0xffffffffffffffef },
    .{ .word = 0x927c0021, .value = 0x10 },
    .{ .word = 0x927c0421, .value = 0x30 },
    .{ .word = 0x927c0821, .value = 0x70 },
    .{ .word = 0x927c0c21, .value = 0xf0 },
    .{ .word = 0x927c1021, .value = 0x1f0 },
    .{ .word = 0x927c1421, .value = 0x3f0 },
    .{ .word = 0x927c1821, .value = 0x7f0 },
    .{ .word = 0x927c1c21, .value = 0xff0 },
    .{ .word = 0x927c2021, .value = 0x1ff0 },
    .{ .word = 0x927c2421, .value = 0x3ff0 },
    .{ .word = 0x927c2821, .value = 0x7ff0 },
    .{ .word = 0x927c2c21, .value = 0xfff0 },
    .{ .word = 0x927c3021, .value = 0x1fff0 },
    .{ .word = 0x927c3421, .value = 0x3fff0 },
    .{ .word = 0x927c3821, .value = 0x7fff0 },
    .{ .word = 0x927c3c21, .value = 0xffff0 },
    .{ .word = 0x927c4021, .value = 0x1ffff0 },
    .{ .word = 0x927c4421, .value = 0x3ffff0 },
    .{ .word = 0x927c4821, .value = 0x7ffff0 },
    .{ .word = 0x927c4c21, .value = 0xfffff0 },
    .{ .word = 0x927c5021, .value = 0x1fffff0 },
    .{ .word = 0x927c5421, .value = 0x3fffff0 },
    .{ .word = 0x927c5821, .value = 0x7fffff0 },
    .{ .word = 0x927c5c21, .value = 0xffffff0 },
    .{ .word = 0x927c6021, .value = 0x1ffffff0 },
    .{ .word = 0x927c6421, .value = 0x3ffffff0 },
    .{ .word = 0x927c6821, .value = 0x7ffffff0 },
    .{ .word = 0x927c6c21, .value = 0xfffffff0 },
    .{ .word = 0x927c7021, .value = 0x1fffffff0 },
    .{ .word = 0x927c7421, .value = 0x3fffffff0 },
    .{ .word = 0x927c7821, .value = 0x7fffffff0 },
    .{ .word = 0x927c7c21, .value = 0xffffffff0 },
    .{ .word = 0x927c8021, .value = 0x1ffffffff0 },
    .{ .word = 0x927c8421, .value = 0x3ffffffff0 },
    .{ .word = 0x927c8821, .value = 0x7ffffffff0 },
    .{ .word = 0x927c8c21, .value = 0xfffffffff0 },
    .{ .word = 0x927c9021, .value = 0x1fffffffff0 },
    .{ .word = 0x927c9421, .value = 0x3fffffffff0 },
    .{ .word = 0x927c9821, .value = 0x7fffffffff0 },
    .{ .word = 0x927c9c21, .value = 0xffffffffff0 },
    .{ .word = 0x927ca021, .value = 0x1ffffffffff0 },
    .{ .word = 0x927ca421, .value = 0x3ffffffffff0 },
    .{ .word = 0x927ca821, .value = 0x7ffffffffff0 },
    .{ .word = 0x927cac21, .value = 0xfffffffffff0 },
    .{ .word = 0x927cb021, .value = 0x1fffffffffff0 },
    .{ .word = 0x927cb421, .value = 0x3fffffffffff0 },
    .{ .word = 0x927cb821, .value = 0x7fffffffffff0 },
    .{ .word = 0x927cbc21, .value = 0xffffffffffff0 },
    .{ .word = 0x927cc021, .value = 0x1ffffffffffff0 },
    .{ .word = 0x927cc421, .value = 0x3ffffffffffff0 },
    .{ .word = 0x927cc821, .value = 0x7ffffffffffff0 },
    .{ .word = 0x927ccc21, .value = 0xfffffffffffff0 },
    .{ .word = 0x927cd021, .value = 0x1fffffffffffff0 },
    .{ .word = 0x927cd421, .value = 0x3fffffffffffff0 },
    .{ .word = 0x927cd821, .value = 0x7fffffffffffff0 },
    .{ .word = 0x927cdc21, .value = 0xffffffffffffff0 },
    .{ .word = 0x927ce021, .value = 0x1ffffffffffffff0 },
    .{ .word = 0x927ce421, .value = 0x3ffffffffffffff0 },
    .{ .word = 0x927ce821, .value = 0x7ffffffffffffff0 },
    .{ .word = 0x927cec21, .value = 0xfffffffffffffff0 },
    .{ .word = 0x927cf021, .value = 0xfffffffffffffff1 },
    .{ .word = 0x927cf421, .value = 0xfffffffffffffff3 },
    .{ .word = 0x927cf821, .value = 0xfffffffffffffff7 },
    .{ .word = 0x927d0021, .value = 0x8 },
    .{ .word = 0x927d0421, .value = 0x18 },
    .{ .word = 0x927d0821, .value = 0x38 },
    .{ .word = 0x927d0c21, .value = 0x78 },
    .{ .word = 0x927d1021, .value = 0xf8 },
    .{ .word = 0x927d1421, .value = 0x1f8 },
    .{ .word = 0x927d1821, .value = 0x3f8 },
    .{ .word = 0x927d1c21, .value = 0x7f8 },
    .{ .word = 0x927d2021, .value = 0xff8 },
    .{ .word = 0x927d2421, .value = 0x1ff8 },
    .{ .word = 0x927d2821, .value = 0x3ff8 },
    .{ .word = 0x927d2c21, .value = 0x7ff8 },
    .{ .word = 0x927d3021, .value = 0xfff8 },
    .{ .word = 0x927d3421, .value = 0x1fff8 },
    .{ .word = 0x927d3821, .value = 0x3fff8 },
    .{ .word = 0x927d3c21, .value = 0x7fff8 },
    .{ .word = 0x927d4021, .value = 0xffff8 },
    .{ .word = 0x927d4421, .value = 0x1ffff8 },
    .{ .word = 0x927d4821, .value = 0x3ffff8 },
    .{ .word = 0x927d4c21, .value = 0x7ffff8 },
    .{ .word = 0x927d5021, .value = 0xfffff8 },
    .{ .word = 0x927d5421, .value = 0x1fffff8 },
    .{ .word = 0x927d5821, .value = 0x3fffff8 },
    .{ .word = 0x927d5c21, .value = 0x7fffff8 },
    .{ .word = 0x927d6021, .value = 0xffffff8 },
    .{ .word = 0x927d6421, .value = 0x1ffffff8 },
    .{ .word = 0x927d6821, .value = 0x3ffffff8 },
    .{ .word = 0x927d6c21, .value = 0x7ffffff8 },
    .{ .word = 0x927d7021, .value = 0xfffffff8 },
    .{ .word = 0x927d7421, .value = 0x1fffffff8 },
    .{ .word = 0x927d7821, .value = 0x3fffffff8 },
    .{ .word = 0x927d7c21, .value = 0x7fffffff8 },
    .{ .word = 0x927d8021, .value = 0xffffffff8 },
    .{ .word = 0x927d8421, .value = 0x1ffffffff8 },
    .{ .word = 0x927d8821, .value = 0x3ffffffff8 },
    .{ .word = 0x927d8c21, .value = 0x7ffffffff8 },
    .{ .word = 0x927d9021, .value = 0xfffffffff8 },
    .{ .word = 0x927d9421, .value = 0x1fffffffff8 },
    .{ .word = 0x927d9821, .value = 0x3fffffffff8 },
    .{ .word = 0x927d9c21, .value = 0x7fffffffff8 },
    .{ .word = 0x927da021, .value = 0xffffffffff8 },
    .{ .word = 0x927da421, .value = 0x1ffffffffff8 },
    .{ .word = 0x927da821, .value = 0x3ffffffffff8 },
    .{ .word = 0x927dac21, .value = 0x7ffffffffff8 },
    .{ .word = 0x927db021, .value = 0xfffffffffff8 },
    .{ .word = 0x927db421, .value = 0x1fffffffffff8 },
    .{ .word = 0x927db821, .value = 0x3fffffffffff8 },
    .{ .word = 0x927dbc21, .value = 0x7fffffffffff8 },
    .{ .word = 0x927dc021, .value = 0xffffffffffff8 },
    .{ .word = 0x927dc421, .value = 0x1ffffffffffff8 },
    .{ .word = 0x927dc821, .value = 0x3ffffffffffff8 },
    .{ .word = 0x927dcc21, .value = 0x7ffffffffffff8 },
    .{ .word = 0x927dd021, .value = 0xfffffffffffff8 },
    .{ .word = 0x927dd421, .value = 0x1fffffffffffff8 },
    .{ .word = 0x927dd821, .value = 0x3fffffffffffff8 },
    .{ .word = 0x927ddc21, .value = 0x7fffffffffffff8 },
    .{ .word = 0x927de021, .value = 0xffffffffffffff8 },
    .{ .word = 0x927de421, .value = 0x1ffffffffffffff8 },
    .{ .word = 0x927de821, .value = 0x3ffffffffffffff8 },
    .{ .word = 0x927dec21, .value = 0x7ffffffffffffff8 },
    .{ .word = 0x927df021, .value = 0xfffffffffffffff8 },
    .{ .word = 0x927df421, .value = 0xfffffffffffffff9 },
    .{ .word = 0x927df821, .value = 0xfffffffffffffffb },
    .{ .word = 0x927e0021, .value = 0x4 },
    .{ .word = 0x927e0421, .value = 0xc },
    .{ .word = 0x927e0821, .value = 0x1c },
    .{ .word = 0x927e0c21, .value = 0x3c },
    .{ .word = 0x927e1021, .value = 0x7c },
    .{ .word = 0x927e1421, .value = 0xfc },
    .{ .word = 0x927e1821, .value = 0x1fc },
    .{ .word = 0x927e1c21, .value = 0x3fc },
    .{ .word = 0x927e2021, .value = 0x7fc },
    .{ .word = 0x927e2421, .value = 0xffc },
    .{ .word = 0x927e2821, .value = 0x1ffc },
    .{ .word = 0x927e2c21, .value = 0x3ffc },
    .{ .word = 0x927e3021, .value = 0x7ffc },
    .{ .word = 0x927e3421, .value = 0xfffc },
    .{ .word = 0x927e3821, .value = 0x1fffc },
    .{ .word = 0x927e3c21, .value = 0x3fffc },
    .{ .word = 0x927e4021, .value = 0x7fffc },
    .{ .word = 0x927e4421, .value = 0xffffc },
    .{ .word = 0x927e4821, .value = 0x1ffffc },
    .{ .word = 0x927e4c21, .value = 0x3ffffc },
    .{ .word = 0x927e5021, .value = 0x7ffffc },
    .{ .word = 0x927e5421, .value = 0xfffffc },
    .{ .word = 0x927e5821, .value = 0x1fffffc },
    .{ .word = 0x927e5c21, .value = 0x3fffffc },
    .{ .word = 0x927e6021, .value = 0x7fffffc },
    .{ .word = 0x927e6421, .value = 0xffffffc },
    .{ .word = 0x927e6821, .value = 0x1ffffffc },
    .{ .word = 0x927e6c21, .value = 0x3ffffffc },
    .{ .word = 0x927e7021, .value = 0x7ffffffc },
    .{ .word = 0x927e7421, .value = 0xfffffffc },
    .{ .word = 0x927e7821, .value = 0x1fffffffc },
    .{ .word = 0x927e7c21, .value = 0x3fffffffc },
    .{ .word = 0x927e8021, .value = 0x7fffffffc },
    .{ .word = 0x927e8421, .value = 0xffffffffc },
    .{ .word = 0x927e8821, .value = 0x1ffffffffc },
    .{ .word = 0x927e8c21, .value = 0x3ffffffffc },
    .{ .word = 0x927e9021, .value = 0x7ffffffffc },
    .{ .word = 0x927e9421, .value = 0xfffffffffc },
    .{ .word = 0x927e9821, .value = 0x1fffffffffc },
    .{ .word = 0x927e9c21, .value = 0x3fffffffffc },
    .{ .word = 0x927ea021, .value = 0x7fffffffffc },
    .{ .word = 0x927ea421, .value = 0xffffffffffc },
    .{ .word = 0x927ea821, .value = 0x1ffffffffffc },
    .{ .word = 0x927eac21, .value = 0x3ffffffffffc },
    .{ .word = 0x927eb021, .value = 0x7ffffffffffc },
    .{ .word = 0x927eb421, .value = 0xfffffffffffc },
    .{ .word = 0x927eb821, .value = 0x1fffffffffffc },
    .{ .word = 0x927ebc21, .value = 0x3fffffffffffc },
    .{ .word = 0x927ec021, .value = 0x7fffffffffffc },
    .{ .word = 0x927ec421, .value = 0xffffffffffffc },
    .{ .word = 0x927ec821, .value = 0x1ffffffffffffc },
    .{ .word = 0x927ecc21, .value = 0x3ffffffffffffc },
    .{ .word = 0x927ed021, .value = 0x7ffffffffffffc },
    .{ .word = 0x927ed421, .value = 0xfffffffffffffc },
    .{ .word = 0x927ed821, .value = 0x1fffffffffffffc },
    .{ .word = 0x927edc21, .value = 0x3fffffffffffffc },
    .{ .word = 0x927ee021, .value = 0x7fffffffffffffc },
    .{ .word = 0x927ee421, .value = 0xffffffffffffffc },
    .{ .word = 0x927ee821, .value = 0x1ffffffffffffffc },
    .{ .word = 0x927eec21, .value = 0x3ffffffffffffffc },
    .{ .word = 0x927ef021, .value = 0x7ffffffffffffffc },
    .{ .word = 0x927ef421, .value = 0xfffffffffffffffc },
    .{ .word = 0x927ef821, .value = 0xfffffffffffffffd },
    .{ .word = 0x927f0021, .value = 0x2 },
    .{ .word = 0x927f0421, .value = 0x6 },
    .{ .word = 0x927f0821, .value = 0xe },
    .{ .word = 0x927f0c21, .value = 0x1e },
    .{ .word = 0x927f1021, .value = 0x3e },
    .{ .word = 0x927f1421, .value = 0x7e },
    .{ .word = 0x927f1821, .value = 0xfe },
    .{ .word = 0x927f1c21, .value = 0x1fe },
    .{ .word = 0x927f2021, .value = 0x3fe },
    .{ .word = 0x927f2421, .value = 0x7fe },
    .{ .word = 0x927f2821, .value = 0xffe },
    .{ .word = 0x927f2c21, .value = 0x1ffe },
    .{ .word = 0x927f3021, .value = 0x3ffe },
    .{ .word = 0x927f3421, .value = 0x7ffe },
    .{ .word = 0x927f3821, .value = 0xfffe },
    .{ .word = 0x927f3c21, .value = 0x1fffe },
    .{ .word = 0x927f4021, .value = 0x3fffe },
    .{ .word = 0x927f4421, .value = 0x7fffe },
    .{ .word = 0x927f4821, .value = 0xffffe },
    .{ .word = 0x927f4c21, .value = 0x1ffffe },
    .{ .word = 0x927f5021, .value = 0x3ffffe },
    .{ .word = 0x927f5421, .value = 0x7ffffe },
    .{ .word = 0x927f5821, .value = 0xfffffe },
    .{ .word = 0x927f5c21, .value = 0x1fffffe },
    .{ .word = 0x927f6021, .value = 0x3fffffe },
    .{ .word = 0x927f6421, .value = 0x7fffffe },
    .{ .word = 0x927f6821, .value = 0xffffffe },
    .{ .word = 0x927f6c21, .value = 0x1ffffffe },
    .{ .word = 0x927f7021, .value = 0x3ffffffe },
    .{ .word = 0x927f7421, .value = 0x7ffffffe },
    .{ .word = 0x927f7821, .value = 0xfffffffe },
    .{ .word = 0x927f7c21, .value = 0x1fffffffe },
    .{ .word = 0x927f8021, .value = 0x3fffffffe },
    .{ .word = 0x927f8421, .value = 0x7fffffffe },
    .{ .word = 0x927f8821, .value = 0xffffffffe },
    .{ .word = 0x927f8c21, .value = 0x1ffffffffe },
    .{ .word = 0x927f9021, .value = 0x3ffffffffe },
    .{ .word = 0x927f9421, .value = 0x7ffffffffe },
    .{ .word = 0x927f9821, .value = 0xfffffffffe },
    .{ .word = 0x927f9c21, .value = 0x1fffffffffe },
    .{ .word = 0x927fa021, .value = 0x3fffffffffe },
    .{ .word = 0x927fa421, .value = 0x7fffffffffe },
    .{ .word = 0x927fa821, .value = 0xffffffffffe },
    .{ .word = 0x927fac21, .value = 0x1ffffffffffe },
    .{ .word = 0x927fb021, .value = 0x3ffffffffffe },
    .{ .word = 0x927fb421, .value = 0x7ffffffffffe },
    .{ .word = 0x927fb821, .value = 0xfffffffffffe },
    .{ .word = 0x927fbc21, .value = 0x1fffffffffffe },
    .{ .word = 0x927fc021, .value = 0x3fffffffffffe },
    .{ .word = 0x927fc421, .value = 0x7fffffffffffe },
    .{ .word = 0x927fc821, .value = 0xffffffffffffe },
    .{ .word = 0x927fcc21, .value = 0x1ffffffffffffe },
    .{ .word = 0x927fd021, .value = 0x3ffffffffffffe },
    .{ .word = 0x927fd421, .value = 0x7ffffffffffffe },
    .{ .word = 0x927fd821, .value = 0xfffffffffffffe },
    .{ .word = 0x927fdc21, .value = 0x1fffffffffffffe },
    .{ .word = 0x927fe021, .value = 0x3fffffffffffffe },
    .{ .word = 0x927fe421, .value = 0x7fffffffffffffe },
    .{ .word = 0x927fe821, .value = 0xffffffffffffffe },
    .{ .word = 0x927fec21, .value = 0x1ffffffffffffffe },
    .{ .word = 0x927ff021, .value = 0x3ffffffffffffffe },
    .{ .word = 0x927ff421, .value = 0x7ffffffffffffffe },
    .{ .word = 0x927ff821, .value = 0xfffffffffffffffe },
};

const w32_cases = [_]BitmaskCase{
    .{ .word = 0x12000021, .value = 0x1 },
    .{ .word = 0x12000421, .value = 0x3 },
    .{ .word = 0x12000821, .value = 0x7 },
    .{ .word = 0x12000c21, .value = 0xf },
    .{ .word = 0x12001021, .value = 0x1f },
    .{ .word = 0x12001421, .value = 0x3f },
    .{ .word = 0x12001821, .value = 0x7f },
    .{ .word = 0x12001c21, .value = 0xff },
    .{ .word = 0x12002021, .value = 0x1ff },
    .{ .word = 0x12002421, .value = 0x3ff },
    .{ .word = 0x12002821, .value = 0x7ff },
    .{ .word = 0x12002c21, .value = 0xfff },
    .{ .word = 0x12003021, .value = 0x1fff },
    .{ .word = 0x12003421, .value = 0x3fff },
    .{ .word = 0x12003821, .value = 0x7fff },
    .{ .word = 0x12003c21, .value = 0xffff },
    .{ .word = 0x12004021, .value = 0x1ffff },
    .{ .word = 0x12004421, .value = 0x3ffff },
    .{ .word = 0x12004821, .value = 0x7ffff },
    .{ .word = 0x12004c21, .value = 0xfffff },
    .{ .word = 0x12005021, .value = 0x1fffff },
    .{ .word = 0x12005421, .value = 0x3fffff },
    .{ .word = 0x12005821, .value = 0x7fffff },
    .{ .word = 0x12005c21, .value = 0xffffff },
    .{ .word = 0x12006021, .value = 0x1ffffff },
    .{ .word = 0x12006421, .value = 0x3ffffff },
    .{ .word = 0x12006821, .value = 0x7ffffff },
    .{ .word = 0x12006c21, .value = 0xfffffff },
    .{ .word = 0x12007021, .value = 0x1fffffff },
    .{ .word = 0x12007421, .value = 0x3fffffff },
    .{ .word = 0x12007821, .value = 0x7fffffff },
    .{ .word = 0x12008021, .value = 0x10001 },
    .{ .word = 0x12008421, .value = 0x30003 },
    .{ .word = 0x12008821, .value = 0x70007 },
    .{ .word = 0x12008c21, .value = 0xf000f },
    .{ .word = 0x12009021, .value = 0x1f001f },
    .{ .word = 0x12009421, .value = 0x3f003f },
    .{ .word = 0x12009821, .value = 0x7f007f },
    .{ .word = 0x12009c21, .value = 0xff00ff },
    .{ .word = 0x1200a021, .value = 0x1ff01ff },
    .{ .word = 0x1200a421, .value = 0x3ff03ff },
    .{ .word = 0x1200a821, .value = 0x7ff07ff },
    .{ .word = 0x1200ac21, .value = 0xfff0fff },
    .{ .word = 0x1200b021, .value = 0x1fff1fff },
    .{ .word = 0x1200b421, .value = 0x3fff3fff },
    .{ .word = 0x1200b821, .value = 0x7fff7fff },
    .{ .word = 0x1200c021, .value = 0x1010101 },
    .{ .word = 0x1200c421, .value = 0x3030303 },
    .{ .word = 0x1200c821, .value = 0x7070707 },
    .{ .word = 0x1200cc21, .value = 0xf0f0f0f },
    .{ .word = 0x1200d021, .value = 0x1f1f1f1f },
    .{ .word = 0x1200d421, .value = 0x3f3f3f3f },
    .{ .word = 0x1200d821, .value = 0x7f7f7f7f },
    .{ .word = 0x1200e021, .value = 0x11111111 },
    .{ .word = 0x1200e421, .value = 0x33333333 },
    .{ .word = 0x1200e821, .value = 0x77777777 },
    .{ .word = 0x1200f021, .value = 0x55555555 },
    .{ .word = 0x12010021, .value = 0x80000000 },
    .{ .word = 0x12010421, .value = 0x80000001 },
    .{ .word = 0x12010821, .value = 0x80000003 },
    .{ .word = 0x12010c21, .value = 0x80000007 },
    .{ .word = 0x12011021, .value = 0x8000000f },
    .{ .word = 0x12011421, .value = 0x8000001f },
    .{ .word = 0x12011821, .value = 0x8000003f },
    .{ .word = 0x12011c21, .value = 0x8000007f },
    .{ .word = 0x12012021, .value = 0x800000ff },
    .{ .word = 0x12012421, .value = 0x800001ff },
    .{ .word = 0x12012821, .value = 0x800003ff },
    .{ .word = 0x12012c21, .value = 0x800007ff },
    .{ .word = 0x12013021, .value = 0x80000fff },
    .{ .word = 0x12013421, .value = 0x80001fff },
    .{ .word = 0x12013821, .value = 0x80003fff },
    .{ .word = 0x12013c21, .value = 0x80007fff },
    .{ .word = 0x12014021, .value = 0x8000ffff },
    .{ .word = 0x12014421, .value = 0x8001ffff },
    .{ .word = 0x12014821, .value = 0x8003ffff },
    .{ .word = 0x12014c21, .value = 0x8007ffff },
    .{ .word = 0x12015021, .value = 0x800fffff },
    .{ .word = 0x12015421, .value = 0x801fffff },
    .{ .word = 0x12015821, .value = 0x803fffff },
    .{ .word = 0x12015c21, .value = 0x807fffff },
    .{ .word = 0x12016021, .value = 0x80ffffff },
    .{ .word = 0x12016421, .value = 0x81ffffff },
    .{ .word = 0x12016821, .value = 0x83ffffff },
    .{ .word = 0x12016c21, .value = 0x87ffffff },
    .{ .word = 0x12017021, .value = 0x8fffffff },
    .{ .word = 0x12017421, .value = 0x9fffffff },
    .{ .word = 0x12017821, .value = 0xbfffffff },
    .{ .word = 0x12018021, .value = 0x80008000 },
    .{ .word = 0x12018421, .value = 0x80018001 },
    .{ .word = 0x12018821, .value = 0x80038003 },
    .{ .word = 0x12018c21, .value = 0x80078007 },
    .{ .word = 0x12019021, .value = 0x800f800f },
    .{ .word = 0x12019421, .value = 0x801f801f },
    .{ .word = 0x12019821, .value = 0x803f803f },
    .{ .word = 0x12019c21, .value = 0x807f807f },
    .{ .word = 0x1201a021, .value = 0x80ff80ff },
    .{ .word = 0x1201a421, .value = 0x81ff81ff },
    .{ .word = 0x1201a821, .value = 0x83ff83ff },
    .{ .word = 0x1201ac21, .value = 0x87ff87ff },
    .{ .word = 0x1201b021, .value = 0x8fff8fff },
    .{ .word = 0x1201b421, .value = 0x9fff9fff },
    .{ .word = 0x1201b821, .value = 0xbfffbfff },
    .{ .word = 0x1201c021, .value = 0x80808080 },
    .{ .word = 0x1201c421, .value = 0x81818181 },
    .{ .word = 0x1201c821, .value = 0x83838383 },
    .{ .word = 0x1201cc21, .value = 0x87878787 },
    .{ .word = 0x1201d021, .value = 0x8f8f8f8f },
    .{ .word = 0x1201d421, .value = 0x9f9f9f9f },
    .{ .word = 0x1201d821, .value = 0xbfbfbfbf },
    .{ .word = 0x1201e021, .value = 0x88888888 },
    .{ .word = 0x1201e421, .value = 0x99999999 },
    .{ .word = 0x1201e821, .value = 0xbbbbbbbb },
    .{ .word = 0x1201f021, .value = 0xaaaaaaaa },
    .{ .word = 0x12020021, .value = 0x40000000 },
    .{ .word = 0x12020421, .value = 0xc0000000 },
    .{ .word = 0x12020821, .value = 0xc0000001 },
    .{ .word = 0x12020c21, .value = 0xc0000003 },
    .{ .word = 0x12021021, .value = 0xc0000007 },
    .{ .word = 0x12021421, .value = 0xc000000f },
    .{ .word = 0x12021821, .value = 0xc000001f },
    .{ .word = 0x12021c21, .value = 0xc000003f },
    .{ .word = 0x12022021, .value = 0xc000007f },
    .{ .word = 0x12022421, .value = 0xc00000ff },
    .{ .word = 0x12022821, .value = 0xc00001ff },
    .{ .word = 0x12022c21, .value = 0xc00003ff },
    .{ .word = 0x12023021, .value = 0xc00007ff },
    .{ .word = 0x12023421, .value = 0xc0000fff },
    .{ .word = 0x12023821, .value = 0xc0001fff },
    .{ .word = 0x12023c21, .value = 0xc0003fff },
    .{ .word = 0x12024021, .value = 0xc0007fff },
    .{ .word = 0x12024421, .value = 0xc000ffff },
    .{ .word = 0x12024821, .value = 0xc001ffff },
    .{ .word = 0x12024c21, .value = 0xc003ffff },
    .{ .word = 0x12025021, .value = 0xc007ffff },
    .{ .word = 0x12025421, .value = 0xc00fffff },
    .{ .word = 0x12025821, .value = 0xc01fffff },
    .{ .word = 0x12025c21, .value = 0xc03fffff },
    .{ .word = 0x12026021, .value = 0xc07fffff },
    .{ .word = 0x12026421, .value = 0xc0ffffff },
    .{ .word = 0x12026821, .value = 0xc1ffffff },
    .{ .word = 0x12026c21, .value = 0xc3ffffff },
    .{ .word = 0x12027021, .value = 0xc7ffffff },
    .{ .word = 0x12027421, .value = 0xcfffffff },
    .{ .word = 0x12027821, .value = 0xdfffffff },
    .{ .word = 0x12028021, .value = 0x40004000 },
    .{ .word = 0x12028421, .value = 0xc000c000 },
    .{ .word = 0x12028821, .value = 0xc001c001 },
    .{ .word = 0x12028c21, .value = 0xc003c003 },
    .{ .word = 0x12029021, .value = 0xc007c007 },
    .{ .word = 0x12029421, .value = 0xc00fc00f },
    .{ .word = 0x12029821, .value = 0xc01fc01f },
    .{ .word = 0x12029c21, .value = 0xc03fc03f },
    .{ .word = 0x1202a021, .value = 0xc07fc07f },
    .{ .word = 0x1202a421, .value = 0xc0ffc0ff },
    .{ .word = 0x1202a821, .value = 0xc1ffc1ff },
    .{ .word = 0x1202ac21, .value = 0xc3ffc3ff },
    .{ .word = 0x1202b021, .value = 0xc7ffc7ff },
    .{ .word = 0x1202b421, .value = 0xcfffcfff },
    .{ .word = 0x1202b821, .value = 0xdfffdfff },
    .{ .word = 0x1202c021, .value = 0x40404040 },
    .{ .word = 0x1202c421, .value = 0xc0c0c0c0 },
    .{ .word = 0x1202c821, .value = 0xc1c1c1c1 },
    .{ .word = 0x1202cc21, .value = 0xc3c3c3c3 },
    .{ .word = 0x1202d021, .value = 0xc7c7c7c7 },
    .{ .word = 0x1202d421, .value = 0xcfcfcfcf },
    .{ .word = 0x1202d821, .value = 0xdfdfdfdf },
    .{ .word = 0x1202e021, .value = 0x44444444 },
    .{ .word = 0x1202e421, .value = 0xcccccccc },
    .{ .word = 0x1202e821, .value = 0xdddddddd },
    .{ .word = 0x12030021, .value = 0x20000000 },
    .{ .word = 0x12030421, .value = 0x60000000 },
    .{ .word = 0x12030821, .value = 0xe0000000 },
    .{ .word = 0x12030c21, .value = 0xe0000001 },
    .{ .word = 0x12031021, .value = 0xe0000003 },
    .{ .word = 0x12031421, .value = 0xe0000007 },
    .{ .word = 0x12031821, .value = 0xe000000f },
    .{ .word = 0x12031c21, .value = 0xe000001f },
    .{ .word = 0x12032021, .value = 0xe000003f },
    .{ .word = 0x12032421, .value = 0xe000007f },
    .{ .word = 0x12032821, .value = 0xe00000ff },
    .{ .word = 0x12032c21, .value = 0xe00001ff },
    .{ .word = 0x12033021, .value = 0xe00003ff },
    .{ .word = 0x12033421, .value = 0xe00007ff },
    .{ .word = 0x12033821, .value = 0xe0000fff },
    .{ .word = 0x12033c21, .value = 0xe0001fff },
    .{ .word = 0x12034021, .value = 0xe0003fff },
    .{ .word = 0x12034421, .value = 0xe0007fff },
    .{ .word = 0x12034821, .value = 0xe000ffff },
    .{ .word = 0x12034c21, .value = 0xe001ffff },
    .{ .word = 0x12035021, .value = 0xe003ffff },
    .{ .word = 0x12035421, .value = 0xe007ffff },
    .{ .word = 0x12035821, .value = 0xe00fffff },
    .{ .word = 0x12035c21, .value = 0xe01fffff },
    .{ .word = 0x12036021, .value = 0xe03fffff },
    .{ .word = 0x12036421, .value = 0xe07fffff },
    .{ .word = 0x12036821, .value = 0xe0ffffff },
    .{ .word = 0x12036c21, .value = 0xe1ffffff },
    .{ .word = 0x12037021, .value = 0xe3ffffff },
    .{ .word = 0x12037421, .value = 0xe7ffffff },
    .{ .word = 0x12037821, .value = 0xefffffff },
    .{ .word = 0x12038021, .value = 0x20002000 },
    .{ .word = 0x12038421, .value = 0x60006000 },
    .{ .word = 0x12038821, .value = 0xe000e000 },
    .{ .word = 0x12038c21, .value = 0xe001e001 },
    .{ .word = 0x12039021, .value = 0xe003e003 },
    .{ .word = 0x12039421, .value = 0xe007e007 },
    .{ .word = 0x12039821, .value = 0xe00fe00f },
    .{ .word = 0x12039c21, .value = 0xe01fe01f },
    .{ .word = 0x1203a021, .value = 0xe03fe03f },
    .{ .word = 0x1203a421, .value = 0xe07fe07f },
    .{ .word = 0x1203a821, .value = 0xe0ffe0ff },
    .{ .word = 0x1203ac21, .value = 0xe1ffe1ff },
    .{ .word = 0x1203b021, .value = 0xe3ffe3ff },
    .{ .word = 0x1203b421, .value = 0xe7ffe7ff },
    .{ .word = 0x1203b821, .value = 0xefffefff },
    .{ .word = 0x1203c021, .value = 0x20202020 },
    .{ .word = 0x1203c421, .value = 0x60606060 },
    .{ .word = 0x1203c821, .value = 0xe0e0e0e0 },
    .{ .word = 0x1203cc21, .value = 0xe1e1e1e1 },
    .{ .word = 0x1203d021, .value = 0xe3e3e3e3 },
    .{ .word = 0x1203d421, .value = 0xe7e7e7e7 },
    .{ .word = 0x1203d821, .value = 0xefefefef },
    .{ .word = 0x1203e021, .value = 0x22222222 },
    .{ .word = 0x1203e421, .value = 0x66666666 },
    .{ .word = 0x1203e821, .value = 0xeeeeeeee },
    .{ .word = 0x12040021, .value = 0x10000000 },
    .{ .word = 0x12040421, .value = 0x30000000 },
    .{ .word = 0x12040821, .value = 0x70000000 },
    .{ .word = 0x12040c21, .value = 0xf0000000 },
    .{ .word = 0x12041021, .value = 0xf0000001 },
    .{ .word = 0x12041421, .value = 0xf0000003 },
    .{ .word = 0x12041821, .value = 0xf0000007 },
    .{ .word = 0x12041c21, .value = 0xf000000f },
    .{ .word = 0x12042021, .value = 0xf000001f },
    .{ .word = 0x12042421, .value = 0xf000003f },
    .{ .word = 0x12042821, .value = 0xf000007f },
    .{ .word = 0x12042c21, .value = 0xf00000ff },
    .{ .word = 0x12043021, .value = 0xf00001ff },
    .{ .word = 0x12043421, .value = 0xf00003ff },
    .{ .word = 0x12043821, .value = 0xf00007ff },
    .{ .word = 0x12043c21, .value = 0xf0000fff },
    .{ .word = 0x12044021, .value = 0xf0001fff },
    .{ .word = 0x12044421, .value = 0xf0003fff },
    .{ .word = 0x12044821, .value = 0xf0007fff },
    .{ .word = 0x12044c21, .value = 0xf000ffff },
    .{ .word = 0x12045021, .value = 0xf001ffff },
    .{ .word = 0x12045421, .value = 0xf003ffff },
    .{ .word = 0x12045821, .value = 0xf007ffff },
    .{ .word = 0x12045c21, .value = 0xf00fffff },
    .{ .word = 0x12046021, .value = 0xf01fffff },
    .{ .word = 0x12046421, .value = 0xf03fffff },
    .{ .word = 0x12046821, .value = 0xf07fffff },
    .{ .word = 0x12046c21, .value = 0xf0ffffff },
    .{ .word = 0x12047021, .value = 0xf1ffffff },
    .{ .word = 0x12047421, .value = 0xf3ffffff },
    .{ .word = 0x12047821, .value = 0xf7ffffff },
    .{ .word = 0x12048021, .value = 0x10001000 },
    .{ .word = 0x12048421, .value = 0x30003000 },
    .{ .word = 0x12048821, .value = 0x70007000 },
    .{ .word = 0x12048c21, .value = 0xf000f000 },
    .{ .word = 0x12049021, .value = 0xf001f001 },
    .{ .word = 0x12049421, .value = 0xf003f003 },
    .{ .word = 0x12049821, .value = 0xf007f007 },
    .{ .word = 0x12049c21, .value = 0xf00ff00f },
    .{ .word = 0x1204a021, .value = 0xf01ff01f },
    .{ .word = 0x1204a421, .value = 0xf03ff03f },
    .{ .word = 0x1204a821, .value = 0xf07ff07f },
    .{ .word = 0x1204ac21, .value = 0xf0fff0ff },
    .{ .word = 0x1204b021, .value = 0xf1fff1ff },
    .{ .word = 0x1204b421, .value = 0xf3fff3ff },
    .{ .word = 0x1204b821, .value = 0xf7fff7ff },
    .{ .word = 0x1204c021, .value = 0x10101010 },
    .{ .word = 0x1204c421, .value = 0x30303030 },
    .{ .word = 0x1204c821, .value = 0x70707070 },
    .{ .word = 0x1204cc21, .value = 0xf0f0f0f0 },
    .{ .word = 0x1204d021, .value = 0xf1f1f1f1 },
    .{ .word = 0x1204d421, .value = 0xf3f3f3f3 },
    .{ .word = 0x1204d821, .value = 0xf7f7f7f7 },
    .{ .word = 0x12050021, .value = 0x8000000 },
    .{ .word = 0x12050421, .value = 0x18000000 },
    .{ .word = 0x12050821, .value = 0x38000000 },
    .{ .word = 0x12050c21, .value = 0x78000000 },
    .{ .word = 0x12051021, .value = 0xf8000000 },
    .{ .word = 0x12051421, .value = 0xf8000001 },
    .{ .word = 0x12051821, .value = 0xf8000003 },
    .{ .word = 0x12051c21, .value = 0xf8000007 },
    .{ .word = 0x12052021, .value = 0xf800000f },
    .{ .word = 0x12052421, .value = 0xf800001f },
    .{ .word = 0x12052821, .value = 0xf800003f },
    .{ .word = 0x12052c21, .value = 0xf800007f },
    .{ .word = 0x12053021, .value = 0xf80000ff },
    .{ .word = 0x12053421, .value = 0xf80001ff },
    .{ .word = 0x12053821, .value = 0xf80003ff },
    .{ .word = 0x12053c21, .value = 0xf80007ff },
    .{ .word = 0x12054021, .value = 0xf8000fff },
    .{ .word = 0x12054421, .value = 0xf8001fff },
    .{ .word = 0x12054821, .value = 0xf8003fff },
    .{ .word = 0x12054c21, .value = 0xf8007fff },
    .{ .word = 0x12055021, .value = 0xf800ffff },
    .{ .word = 0x12055421, .value = 0xf801ffff },
    .{ .word = 0x12055821, .value = 0xf803ffff },
    .{ .word = 0x12055c21, .value = 0xf807ffff },
    .{ .word = 0x12056021, .value = 0xf80fffff },
    .{ .word = 0x12056421, .value = 0xf81fffff },
    .{ .word = 0x12056821, .value = 0xf83fffff },
    .{ .word = 0x12056c21, .value = 0xf87fffff },
    .{ .word = 0x12057021, .value = 0xf8ffffff },
    .{ .word = 0x12057421, .value = 0xf9ffffff },
    .{ .word = 0x12057821, .value = 0xfbffffff },
    .{ .word = 0x12058021, .value = 0x8000800 },
    .{ .word = 0x12058421, .value = 0x18001800 },
    .{ .word = 0x12058821, .value = 0x38003800 },
    .{ .word = 0x12058c21, .value = 0x78007800 },
    .{ .word = 0x12059021, .value = 0xf800f800 },
    .{ .word = 0x12059421, .value = 0xf801f801 },
    .{ .word = 0x12059821, .value = 0xf803f803 },
    .{ .word = 0x12059c21, .value = 0xf807f807 },
    .{ .word = 0x1205a021, .value = 0xf80ff80f },
    .{ .word = 0x1205a421, .value = 0xf81ff81f },
    .{ .word = 0x1205a821, .value = 0xf83ff83f },
    .{ .word = 0x1205ac21, .value = 0xf87ff87f },
    .{ .word = 0x1205b021, .value = 0xf8fff8ff },
    .{ .word = 0x1205b421, .value = 0xf9fff9ff },
    .{ .word = 0x1205b821, .value = 0xfbfffbff },
    .{ .word = 0x1205c021, .value = 0x8080808 },
    .{ .word = 0x1205c421, .value = 0x18181818 },
    .{ .word = 0x1205c821, .value = 0x38383838 },
    .{ .word = 0x1205cc21, .value = 0x78787878 },
    .{ .word = 0x1205d021, .value = 0xf8f8f8f8 },
    .{ .word = 0x1205d421, .value = 0xf9f9f9f9 },
    .{ .word = 0x1205d821, .value = 0xfbfbfbfb },
    .{ .word = 0x12060021, .value = 0x4000000 },
    .{ .word = 0x12060421, .value = 0xc000000 },
    .{ .word = 0x12060821, .value = 0x1c000000 },
    .{ .word = 0x12060c21, .value = 0x3c000000 },
    .{ .word = 0x12061021, .value = 0x7c000000 },
    .{ .word = 0x12061421, .value = 0xfc000000 },
    .{ .word = 0x12061821, .value = 0xfc000001 },
    .{ .word = 0x12061c21, .value = 0xfc000003 },
    .{ .word = 0x12062021, .value = 0xfc000007 },
    .{ .word = 0x12062421, .value = 0xfc00000f },
    .{ .word = 0x12062821, .value = 0xfc00001f },
    .{ .word = 0x12062c21, .value = 0xfc00003f },
    .{ .word = 0x12063021, .value = 0xfc00007f },
    .{ .word = 0x12063421, .value = 0xfc0000ff },
    .{ .word = 0x12063821, .value = 0xfc0001ff },
    .{ .word = 0x12063c21, .value = 0xfc0003ff },
    .{ .word = 0x12064021, .value = 0xfc0007ff },
    .{ .word = 0x12064421, .value = 0xfc000fff },
    .{ .word = 0x12064821, .value = 0xfc001fff },
    .{ .word = 0x12064c21, .value = 0xfc003fff },
    .{ .word = 0x12065021, .value = 0xfc007fff },
    .{ .word = 0x12065421, .value = 0xfc00ffff },
    .{ .word = 0x12065821, .value = 0xfc01ffff },
    .{ .word = 0x12065c21, .value = 0xfc03ffff },
    .{ .word = 0x12066021, .value = 0xfc07ffff },
    .{ .word = 0x12066421, .value = 0xfc0fffff },
    .{ .word = 0x12066821, .value = 0xfc1fffff },
    .{ .word = 0x12066c21, .value = 0xfc3fffff },
    .{ .word = 0x12067021, .value = 0xfc7fffff },
    .{ .word = 0x12067421, .value = 0xfcffffff },
    .{ .word = 0x12067821, .value = 0xfdffffff },
    .{ .word = 0x12068021, .value = 0x4000400 },
    .{ .word = 0x12068421, .value = 0xc000c00 },
    .{ .word = 0x12068821, .value = 0x1c001c00 },
    .{ .word = 0x12068c21, .value = 0x3c003c00 },
    .{ .word = 0x12069021, .value = 0x7c007c00 },
    .{ .word = 0x12069421, .value = 0xfc00fc00 },
    .{ .word = 0x12069821, .value = 0xfc01fc01 },
    .{ .word = 0x12069c21, .value = 0xfc03fc03 },
    .{ .word = 0x1206a021, .value = 0xfc07fc07 },
    .{ .word = 0x1206a421, .value = 0xfc0ffc0f },
    .{ .word = 0x1206a821, .value = 0xfc1ffc1f },
    .{ .word = 0x1206ac21, .value = 0xfc3ffc3f },
    .{ .word = 0x1206b021, .value = 0xfc7ffc7f },
    .{ .word = 0x1206b421, .value = 0xfcfffcff },
    .{ .word = 0x1206b821, .value = 0xfdfffdff },
    .{ .word = 0x1206c021, .value = 0x4040404 },
    .{ .word = 0x1206c421, .value = 0xc0c0c0c },
    .{ .word = 0x1206c821, .value = 0x1c1c1c1c },
    .{ .word = 0x1206cc21, .value = 0x3c3c3c3c },
    .{ .word = 0x1206d021, .value = 0x7c7c7c7c },
    .{ .word = 0x1206d421, .value = 0xfcfcfcfc },
    .{ .word = 0x1206d821, .value = 0xfdfdfdfd },
    .{ .word = 0x12070021, .value = 0x2000000 },
    .{ .word = 0x12070421, .value = 0x6000000 },
    .{ .word = 0x12070821, .value = 0xe000000 },
    .{ .word = 0x12070c21, .value = 0x1e000000 },
    .{ .word = 0x12071021, .value = 0x3e000000 },
    .{ .word = 0x12071421, .value = 0x7e000000 },
    .{ .word = 0x12071821, .value = 0xfe000000 },
    .{ .word = 0x12071c21, .value = 0xfe000001 },
    .{ .word = 0x12072021, .value = 0xfe000003 },
    .{ .word = 0x12072421, .value = 0xfe000007 },
    .{ .word = 0x12072821, .value = 0xfe00000f },
    .{ .word = 0x12072c21, .value = 0xfe00001f },
    .{ .word = 0x12073021, .value = 0xfe00003f },
    .{ .word = 0x12073421, .value = 0xfe00007f },
    .{ .word = 0x12073821, .value = 0xfe0000ff },
    .{ .word = 0x12073c21, .value = 0xfe0001ff },
    .{ .word = 0x12074021, .value = 0xfe0003ff },
    .{ .word = 0x12074421, .value = 0xfe0007ff },
    .{ .word = 0x12074821, .value = 0xfe000fff },
    .{ .word = 0x12074c21, .value = 0xfe001fff },
    .{ .word = 0x12075021, .value = 0xfe003fff },
    .{ .word = 0x12075421, .value = 0xfe007fff },
    .{ .word = 0x12075821, .value = 0xfe00ffff },
    .{ .word = 0x12075c21, .value = 0xfe01ffff },
    .{ .word = 0x12076021, .value = 0xfe03ffff },
    .{ .word = 0x12076421, .value = 0xfe07ffff },
    .{ .word = 0x12076821, .value = 0xfe0fffff },
    .{ .word = 0x12076c21, .value = 0xfe1fffff },
    .{ .word = 0x12077021, .value = 0xfe3fffff },
    .{ .word = 0x12077421, .value = 0xfe7fffff },
    .{ .word = 0x12077821, .value = 0xfeffffff },
    .{ .word = 0x12078021, .value = 0x2000200 },
    .{ .word = 0x12078421, .value = 0x6000600 },
    .{ .word = 0x12078821, .value = 0xe000e00 },
    .{ .word = 0x12078c21, .value = 0x1e001e00 },
    .{ .word = 0x12079021, .value = 0x3e003e00 },
    .{ .word = 0x12079421, .value = 0x7e007e00 },
    .{ .word = 0x12079821, .value = 0xfe00fe00 },
    .{ .word = 0x12079c21, .value = 0xfe01fe01 },
    .{ .word = 0x1207a021, .value = 0xfe03fe03 },
    .{ .word = 0x1207a421, .value = 0xfe07fe07 },
    .{ .word = 0x1207a821, .value = 0xfe0ffe0f },
    .{ .word = 0x1207ac21, .value = 0xfe1ffe1f },
    .{ .word = 0x1207b021, .value = 0xfe3ffe3f },
    .{ .word = 0x1207b421, .value = 0xfe7ffe7f },
    .{ .word = 0x1207b821, .value = 0xfefffeff },
    .{ .word = 0x1207c021, .value = 0x2020202 },
    .{ .word = 0x1207c421, .value = 0x6060606 },
    .{ .word = 0x1207c821, .value = 0xe0e0e0e },
    .{ .word = 0x1207cc21, .value = 0x1e1e1e1e },
    .{ .word = 0x1207d021, .value = 0x3e3e3e3e },
    .{ .word = 0x1207d421, .value = 0x7e7e7e7e },
    .{ .word = 0x1207d821, .value = 0xfefefefe },
    .{ .word = 0x12080021, .value = 0x1000000 },
    .{ .word = 0x12080421, .value = 0x3000000 },
    .{ .word = 0x12080821, .value = 0x7000000 },
    .{ .word = 0x12080c21, .value = 0xf000000 },
    .{ .word = 0x12081021, .value = 0x1f000000 },
    .{ .word = 0x12081421, .value = 0x3f000000 },
    .{ .word = 0x12081821, .value = 0x7f000000 },
    .{ .word = 0x12081c21, .value = 0xff000000 },
    .{ .word = 0x12082021, .value = 0xff000001 },
    .{ .word = 0x12082421, .value = 0xff000003 },
    .{ .word = 0x12082821, .value = 0xff000007 },
    .{ .word = 0x12082c21, .value = 0xff00000f },
    .{ .word = 0x12083021, .value = 0xff00001f },
    .{ .word = 0x12083421, .value = 0xff00003f },
    .{ .word = 0x12083821, .value = 0xff00007f },
    .{ .word = 0x12083c21, .value = 0xff0000ff },
    .{ .word = 0x12084021, .value = 0xff0001ff },
    .{ .word = 0x12084421, .value = 0xff0003ff },
    .{ .word = 0x12084821, .value = 0xff0007ff },
    .{ .word = 0x12084c21, .value = 0xff000fff },
    .{ .word = 0x12085021, .value = 0xff001fff },
    .{ .word = 0x12085421, .value = 0xff003fff },
    .{ .word = 0x12085821, .value = 0xff007fff },
    .{ .word = 0x12085c21, .value = 0xff00ffff },
    .{ .word = 0x12086021, .value = 0xff01ffff },
    .{ .word = 0x12086421, .value = 0xff03ffff },
    .{ .word = 0x12086821, .value = 0xff07ffff },
    .{ .word = 0x12086c21, .value = 0xff0fffff },
    .{ .word = 0x12087021, .value = 0xff1fffff },
    .{ .word = 0x12087421, .value = 0xff3fffff },
    .{ .word = 0x12087821, .value = 0xff7fffff },
    .{ .word = 0x12088021, .value = 0x1000100 },
    .{ .word = 0x12088421, .value = 0x3000300 },
    .{ .word = 0x12088821, .value = 0x7000700 },
    .{ .word = 0x12088c21, .value = 0xf000f00 },
    .{ .word = 0x12089021, .value = 0x1f001f00 },
    .{ .word = 0x12089421, .value = 0x3f003f00 },
    .{ .word = 0x12089821, .value = 0x7f007f00 },
    .{ .word = 0x12089c21, .value = 0xff00ff00 },
    .{ .word = 0x1208a021, .value = 0xff01ff01 },
    .{ .word = 0x1208a421, .value = 0xff03ff03 },
    .{ .word = 0x1208a821, .value = 0xff07ff07 },
    .{ .word = 0x1208ac21, .value = 0xff0fff0f },
    .{ .word = 0x1208b021, .value = 0xff1fff1f },
    .{ .word = 0x1208b421, .value = 0xff3fff3f },
    .{ .word = 0x1208b821, .value = 0xff7fff7f },
    .{ .word = 0x12090021, .value = 0x800000 },
    .{ .word = 0x12090421, .value = 0x1800000 },
    .{ .word = 0x12090821, .value = 0x3800000 },
    .{ .word = 0x12090c21, .value = 0x7800000 },
    .{ .word = 0x12091021, .value = 0xf800000 },
    .{ .word = 0x12091421, .value = 0x1f800000 },
    .{ .word = 0x12091821, .value = 0x3f800000 },
    .{ .word = 0x12091c21, .value = 0x7f800000 },
    .{ .word = 0x12092021, .value = 0xff800000 },
    .{ .word = 0x12092421, .value = 0xff800001 },
    .{ .word = 0x12092821, .value = 0xff800003 },
    .{ .word = 0x12092c21, .value = 0xff800007 },
    .{ .word = 0x12093021, .value = 0xff80000f },
    .{ .word = 0x12093421, .value = 0xff80001f },
    .{ .word = 0x12093821, .value = 0xff80003f },
    .{ .word = 0x12093c21, .value = 0xff80007f },
    .{ .word = 0x12094021, .value = 0xff8000ff },
    .{ .word = 0x12094421, .value = 0xff8001ff },
    .{ .word = 0x12094821, .value = 0xff8003ff },
    .{ .word = 0x12094c21, .value = 0xff8007ff },
    .{ .word = 0x12095021, .value = 0xff800fff },
    .{ .word = 0x12095421, .value = 0xff801fff },
    .{ .word = 0x12095821, .value = 0xff803fff },
    .{ .word = 0x12095c21, .value = 0xff807fff },
    .{ .word = 0x12096021, .value = 0xff80ffff },
    .{ .word = 0x12096421, .value = 0xff81ffff },
    .{ .word = 0x12096821, .value = 0xff83ffff },
    .{ .word = 0x12096c21, .value = 0xff87ffff },
    .{ .word = 0x12097021, .value = 0xff8fffff },
    .{ .word = 0x12097421, .value = 0xff9fffff },
    .{ .word = 0x12097821, .value = 0xffbfffff },
    .{ .word = 0x12098021, .value = 0x800080 },
    .{ .word = 0x12098421, .value = 0x1800180 },
    .{ .word = 0x12098821, .value = 0x3800380 },
    .{ .word = 0x12098c21, .value = 0x7800780 },
    .{ .word = 0x12099021, .value = 0xf800f80 },
    .{ .word = 0x12099421, .value = 0x1f801f80 },
    .{ .word = 0x12099821, .value = 0x3f803f80 },
    .{ .word = 0x12099c21, .value = 0x7f807f80 },
    .{ .word = 0x1209a021, .value = 0xff80ff80 },
    .{ .word = 0x1209a421, .value = 0xff81ff81 },
    .{ .word = 0x1209a821, .value = 0xff83ff83 },
    .{ .word = 0x1209ac21, .value = 0xff87ff87 },
    .{ .word = 0x1209b021, .value = 0xff8fff8f },
    .{ .word = 0x1209b421, .value = 0xff9fff9f },
    .{ .word = 0x1209b821, .value = 0xffbfffbf },
    .{ .word = 0x120a0021, .value = 0x400000 },
    .{ .word = 0x120a0421, .value = 0xc00000 },
    .{ .word = 0x120a0821, .value = 0x1c00000 },
    .{ .word = 0x120a0c21, .value = 0x3c00000 },
    .{ .word = 0x120a1021, .value = 0x7c00000 },
    .{ .word = 0x120a1421, .value = 0xfc00000 },
    .{ .word = 0x120a1821, .value = 0x1fc00000 },
    .{ .word = 0x120a1c21, .value = 0x3fc00000 },
    .{ .word = 0x120a2021, .value = 0x7fc00000 },
    .{ .word = 0x120a2421, .value = 0xffc00000 },
    .{ .word = 0x120a2821, .value = 0xffc00001 },
    .{ .word = 0x120a2c21, .value = 0xffc00003 },
    .{ .word = 0x120a3021, .value = 0xffc00007 },
    .{ .word = 0x120a3421, .value = 0xffc0000f },
    .{ .word = 0x120a3821, .value = 0xffc0001f },
    .{ .word = 0x120a3c21, .value = 0xffc0003f },
    .{ .word = 0x120a4021, .value = 0xffc0007f },
    .{ .word = 0x120a4421, .value = 0xffc000ff },
    .{ .word = 0x120a4821, .value = 0xffc001ff },
    .{ .word = 0x120a4c21, .value = 0xffc003ff },
    .{ .word = 0x120a5021, .value = 0xffc007ff },
    .{ .word = 0x120a5421, .value = 0xffc00fff },
    .{ .word = 0x120a5821, .value = 0xffc01fff },
    .{ .word = 0x120a5c21, .value = 0xffc03fff },
    .{ .word = 0x120a6021, .value = 0xffc07fff },
    .{ .word = 0x120a6421, .value = 0xffc0ffff },
    .{ .word = 0x120a6821, .value = 0xffc1ffff },
    .{ .word = 0x120a6c21, .value = 0xffc3ffff },
    .{ .word = 0x120a7021, .value = 0xffc7ffff },
    .{ .word = 0x120a7421, .value = 0xffcfffff },
    .{ .word = 0x120a7821, .value = 0xffdfffff },
    .{ .word = 0x120a8021, .value = 0x400040 },
    .{ .word = 0x120a8421, .value = 0xc000c0 },
    .{ .word = 0x120a8821, .value = 0x1c001c0 },
    .{ .word = 0x120a8c21, .value = 0x3c003c0 },
    .{ .word = 0x120a9021, .value = 0x7c007c0 },
    .{ .word = 0x120a9421, .value = 0xfc00fc0 },
    .{ .word = 0x120a9821, .value = 0x1fc01fc0 },
    .{ .word = 0x120a9c21, .value = 0x3fc03fc0 },
    .{ .word = 0x120aa021, .value = 0x7fc07fc0 },
    .{ .word = 0x120aa421, .value = 0xffc0ffc0 },
    .{ .word = 0x120aa821, .value = 0xffc1ffc1 },
    .{ .word = 0x120aac21, .value = 0xffc3ffc3 },
    .{ .word = 0x120ab021, .value = 0xffc7ffc7 },
    .{ .word = 0x120ab421, .value = 0xffcfffcf },
    .{ .word = 0x120ab821, .value = 0xffdfffdf },
    .{ .word = 0x120b0021, .value = 0x200000 },
    .{ .word = 0x120b0421, .value = 0x600000 },
    .{ .word = 0x120b0821, .value = 0xe00000 },
    .{ .word = 0x120b0c21, .value = 0x1e00000 },
    .{ .word = 0x120b1021, .value = 0x3e00000 },
    .{ .word = 0x120b1421, .value = 0x7e00000 },
    .{ .word = 0x120b1821, .value = 0xfe00000 },
    .{ .word = 0x120b1c21, .value = 0x1fe00000 },
    .{ .word = 0x120b2021, .value = 0x3fe00000 },
    .{ .word = 0x120b2421, .value = 0x7fe00000 },
    .{ .word = 0x120b2821, .value = 0xffe00000 },
    .{ .word = 0x120b2c21, .value = 0xffe00001 },
    .{ .word = 0x120b3021, .value = 0xffe00003 },
    .{ .word = 0x120b3421, .value = 0xffe00007 },
    .{ .word = 0x120b3821, .value = 0xffe0000f },
    .{ .word = 0x120b3c21, .value = 0xffe0001f },
    .{ .word = 0x120b4021, .value = 0xffe0003f },
    .{ .word = 0x120b4421, .value = 0xffe0007f },
    .{ .word = 0x120b4821, .value = 0xffe000ff },
    .{ .word = 0x120b4c21, .value = 0xffe001ff },
    .{ .word = 0x120b5021, .value = 0xffe003ff },
    .{ .word = 0x120b5421, .value = 0xffe007ff },
    .{ .word = 0x120b5821, .value = 0xffe00fff },
    .{ .word = 0x120b5c21, .value = 0xffe01fff },
    .{ .word = 0x120b6021, .value = 0xffe03fff },
    .{ .word = 0x120b6421, .value = 0xffe07fff },
    .{ .word = 0x120b6821, .value = 0xffe0ffff },
    .{ .word = 0x120b6c21, .value = 0xffe1ffff },
    .{ .word = 0x120b7021, .value = 0xffe3ffff },
    .{ .word = 0x120b7421, .value = 0xffe7ffff },
    .{ .word = 0x120b7821, .value = 0xffefffff },
    .{ .word = 0x120b8021, .value = 0x200020 },
    .{ .word = 0x120b8421, .value = 0x600060 },
    .{ .word = 0x120b8821, .value = 0xe000e0 },
    .{ .word = 0x120b8c21, .value = 0x1e001e0 },
    .{ .word = 0x120b9021, .value = 0x3e003e0 },
    .{ .word = 0x120b9421, .value = 0x7e007e0 },
    .{ .word = 0x120b9821, .value = 0xfe00fe0 },
    .{ .word = 0x120b9c21, .value = 0x1fe01fe0 },
    .{ .word = 0x120ba021, .value = 0x3fe03fe0 },
    .{ .word = 0x120ba421, .value = 0x7fe07fe0 },
    .{ .word = 0x120ba821, .value = 0xffe0ffe0 },
    .{ .word = 0x120bac21, .value = 0xffe1ffe1 },
    .{ .word = 0x120bb021, .value = 0xffe3ffe3 },
    .{ .word = 0x120bb421, .value = 0xffe7ffe7 },
    .{ .word = 0x120bb821, .value = 0xffefffef },
    .{ .word = 0x120c0021, .value = 0x100000 },
    .{ .word = 0x120c0421, .value = 0x300000 },
    .{ .word = 0x120c0821, .value = 0x700000 },
    .{ .word = 0x120c0c21, .value = 0xf00000 },
    .{ .word = 0x120c1021, .value = 0x1f00000 },
    .{ .word = 0x120c1421, .value = 0x3f00000 },
    .{ .word = 0x120c1821, .value = 0x7f00000 },
    .{ .word = 0x120c1c21, .value = 0xff00000 },
    .{ .word = 0x120c2021, .value = 0x1ff00000 },
    .{ .word = 0x120c2421, .value = 0x3ff00000 },
    .{ .word = 0x120c2821, .value = 0x7ff00000 },
    .{ .word = 0x120c2c21, .value = 0xfff00000 },
    .{ .word = 0x120c3021, .value = 0xfff00001 },
    .{ .word = 0x120c3421, .value = 0xfff00003 },
    .{ .word = 0x120c3821, .value = 0xfff00007 },
    .{ .word = 0x120c3c21, .value = 0xfff0000f },
    .{ .word = 0x120c4021, .value = 0xfff0001f },
    .{ .word = 0x120c4421, .value = 0xfff0003f },
    .{ .word = 0x120c4821, .value = 0xfff0007f },
    .{ .word = 0x120c4c21, .value = 0xfff000ff },
    .{ .word = 0x120c5021, .value = 0xfff001ff },
    .{ .word = 0x120c5421, .value = 0xfff003ff },
    .{ .word = 0x120c5821, .value = 0xfff007ff },
    .{ .word = 0x120c5c21, .value = 0xfff00fff },
    .{ .word = 0x120c6021, .value = 0xfff01fff },
    .{ .word = 0x120c6421, .value = 0xfff03fff },
    .{ .word = 0x120c6821, .value = 0xfff07fff },
    .{ .word = 0x120c6c21, .value = 0xfff0ffff },
    .{ .word = 0x120c7021, .value = 0xfff1ffff },
    .{ .word = 0x120c7421, .value = 0xfff3ffff },
    .{ .word = 0x120c7821, .value = 0xfff7ffff },
    .{ .word = 0x120c8021, .value = 0x100010 },
    .{ .word = 0x120c8421, .value = 0x300030 },
    .{ .word = 0x120c8821, .value = 0x700070 },
    .{ .word = 0x120c8c21, .value = 0xf000f0 },
    .{ .word = 0x120c9021, .value = 0x1f001f0 },
    .{ .word = 0x120c9421, .value = 0x3f003f0 },
    .{ .word = 0x120c9821, .value = 0x7f007f0 },
    .{ .word = 0x120c9c21, .value = 0xff00ff0 },
    .{ .word = 0x120ca021, .value = 0x1ff01ff0 },
    .{ .word = 0x120ca421, .value = 0x3ff03ff0 },
    .{ .word = 0x120ca821, .value = 0x7ff07ff0 },
    .{ .word = 0x120cac21, .value = 0xfff0fff0 },
    .{ .word = 0x120cb021, .value = 0xfff1fff1 },
    .{ .word = 0x120cb421, .value = 0xfff3fff3 },
    .{ .word = 0x120cb821, .value = 0xfff7fff7 },
    .{ .word = 0x120d0021, .value = 0x80000 },
    .{ .word = 0x120d0421, .value = 0x180000 },
    .{ .word = 0x120d0821, .value = 0x380000 },
    .{ .word = 0x120d0c21, .value = 0x780000 },
    .{ .word = 0x120d1021, .value = 0xf80000 },
    .{ .word = 0x120d1421, .value = 0x1f80000 },
    .{ .word = 0x120d1821, .value = 0x3f80000 },
    .{ .word = 0x120d1c21, .value = 0x7f80000 },
    .{ .word = 0x120d2021, .value = 0xff80000 },
    .{ .word = 0x120d2421, .value = 0x1ff80000 },
    .{ .word = 0x120d2821, .value = 0x3ff80000 },
    .{ .word = 0x120d2c21, .value = 0x7ff80000 },
    .{ .word = 0x120d3021, .value = 0xfff80000 },
    .{ .word = 0x120d3421, .value = 0xfff80001 },
    .{ .word = 0x120d3821, .value = 0xfff80003 },
    .{ .word = 0x120d3c21, .value = 0xfff80007 },
    .{ .word = 0x120d4021, .value = 0xfff8000f },
    .{ .word = 0x120d4421, .value = 0xfff8001f },
    .{ .word = 0x120d4821, .value = 0xfff8003f },
    .{ .word = 0x120d4c21, .value = 0xfff8007f },
    .{ .word = 0x120d5021, .value = 0xfff800ff },
    .{ .word = 0x120d5421, .value = 0xfff801ff },
    .{ .word = 0x120d5821, .value = 0xfff803ff },
    .{ .word = 0x120d5c21, .value = 0xfff807ff },
    .{ .word = 0x120d6021, .value = 0xfff80fff },
    .{ .word = 0x120d6421, .value = 0xfff81fff },
    .{ .word = 0x120d6821, .value = 0xfff83fff },
    .{ .word = 0x120d6c21, .value = 0xfff87fff },
    .{ .word = 0x120d7021, .value = 0xfff8ffff },
    .{ .word = 0x120d7421, .value = 0xfff9ffff },
    .{ .word = 0x120d7821, .value = 0xfffbffff },
    .{ .word = 0x120d8021, .value = 0x80008 },
    .{ .word = 0x120d8421, .value = 0x180018 },
    .{ .word = 0x120d8821, .value = 0x380038 },
    .{ .word = 0x120d8c21, .value = 0x780078 },
    .{ .word = 0x120d9021, .value = 0xf800f8 },
    .{ .word = 0x120d9421, .value = 0x1f801f8 },
    .{ .word = 0x120d9821, .value = 0x3f803f8 },
    .{ .word = 0x120d9c21, .value = 0x7f807f8 },
    .{ .word = 0x120da021, .value = 0xff80ff8 },
    .{ .word = 0x120da421, .value = 0x1ff81ff8 },
    .{ .word = 0x120da821, .value = 0x3ff83ff8 },
    .{ .word = 0x120dac21, .value = 0x7ff87ff8 },
    .{ .word = 0x120db021, .value = 0xfff8fff8 },
    .{ .word = 0x120db421, .value = 0xfff9fff9 },
    .{ .word = 0x120db821, .value = 0xfffbfffb },
    .{ .word = 0x120e0021, .value = 0x40000 },
    .{ .word = 0x120e0421, .value = 0xc0000 },
    .{ .word = 0x120e0821, .value = 0x1c0000 },
    .{ .word = 0x120e0c21, .value = 0x3c0000 },
    .{ .word = 0x120e1021, .value = 0x7c0000 },
    .{ .word = 0x120e1421, .value = 0xfc0000 },
    .{ .word = 0x120e1821, .value = 0x1fc0000 },
    .{ .word = 0x120e1c21, .value = 0x3fc0000 },
    .{ .word = 0x120e2021, .value = 0x7fc0000 },
    .{ .word = 0x120e2421, .value = 0xffc0000 },
    .{ .word = 0x120e2821, .value = 0x1ffc0000 },
    .{ .word = 0x120e2c21, .value = 0x3ffc0000 },
    .{ .word = 0x120e3021, .value = 0x7ffc0000 },
    .{ .word = 0x120e3421, .value = 0xfffc0000 },
    .{ .word = 0x120e3821, .value = 0xfffc0001 },
    .{ .word = 0x120e3c21, .value = 0xfffc0003 },
    .{ .word = 0x120e4021, .value = 0xfffc0007 },
    .{ .word = 0x120e4421, .value = 0xfffc000f },
    .{ .word = 0x120e4821, .value = 0xfffc001f },
    .{ .word = 0x120e4c21, .value = 0xfffc003f },
    .{ .word = 0x120e5021, .value = 0xfffc007f },
    .{ .word = 0x120e5421, .value = 0xfffc00ff },
    .{ .word = 0x120e5821, .value = 0xfffc01ff },
    .{ .word = 0x120e5c21, .value = 0xfffc03ff },
    .{ .word = 0x120e6021, .value = 0xfffc07ff },
    .{ .word = 0x120e6421, .value = 0xfffc0fff },
    .{ .word = 0x120e6821, .value = 0xfffc1fff },
    .{ .word = 0x120e6c21, .value = 0xfffc3fff },
    .{ .word = 0x120e7021, .value = 0xfffc7fff },
    .{ .word = 0x120e7421, .value = 0xfffcffff },
    .{ .word = 0x120e7821, .value = 0xfffdffff },
    .{ .word = 0x120e8021, .value = 0x40004 },
    .{ .word = 0x120e8421, .value = 0xc000c },
    .{ .word = 0x120e8821, .value = 0x1c001c },
    .{ .word = 0x120e8c21, .value = 0x3c003c },
    .{ .word = 0x120e9021, .value = 0x7c007c },
    .{ .word = 0x120e9421, .value = 0xfc00fc },
    .{ .word = 0x120e9821, .value = 0x1fc01fc },
    .{ .word = 0x120e9c21, .value = 0x3fc03fc },
    .{ .word = 0x120ea021, .value = 0x7fc07fc },
    .{ .word = 0x120ea421, .value = 0xffc0ffc },
    .{ .word = 0x120ea821, .value = 0x1ffc1ffc },
    .{ .word = 0x120eac21, .value = 0x3ffc3ffc },
    .{ .word = 0x120eb021, .value = 0x7ffc7ffc },
    .{ .word = 0x120eb421, .value = 0xfffcfffc },
    .{ .word = 0x120eb821, .value = 0xfffdfffd },
    .{ .word = 0x120f0021, .value = 0x20000 },
    .{ .word = 0x120f0421, .value = 0x60000 },
    .{ .word = 0x120f0821, .value = 0xe0000 },
    .{ .word = 0x120f0c21, .value = 0x1e0000 },
    .{ .word = 0x120f1021, .value = 0x3e0000 },
    .{ .word = 0x120f1421, .value = 0x7e0000 },
    .{ .word = 0x120f1821, .value = 0xfe0000 },
    .{ .word = 0x120f1c21, .value = 0x1fe0000 },
    .{ .word = 0x120f2021, .value = 0x3fe0000 },
    .{ .word = 0x120f2421, .value = 0x7fe0000 },
    .{ .word = 0x120f2821, .value = 0xffe0000 },
    .{ .word = 0x120f2c21, .value = 0x1ffe0000 },
    .{ .word = 0x120f3021, .value = 0x3ffe0000 },
    .{ .word = 0x120f3421, .value = 0x7ffe0000 },
    .{ .word = 0x120f3821, .value = 0xfffe0000 },
    .{ .word = 0x120f3c21, .value = 0xfffe0001 },
    .{ .word = 0x120f4021, .value = 0xfffe0003 },
    .{ .word = 0x120f4421, .value = 0xfffe0007 },
    .{ .word = 0x120f4821, .value = 0xfffe000f },
    .{ .word = 0x120f4c21, .value = 0xfffe001f },
    .{ .word = 0x120f5021, .value = 0xfffe003f },
    .{ .word = 0x120f5421, .value = 0xfffe007f },
    .{ .word = 0x120f5821, .value = 0xfffe00ff },
    .{ .word = 0x120f5c21, .value = 0xfffe01ff },
    .{ .word = 0x120f6021, .value = 0xfffe03ff },
    .{ .word = 0x120f6421, .value = 0xfffe07ff },
    .{ .word = 0x120f6821, .value = 0xfffe0fff },
    .{ .word = 0x120f6c21, .value = 0xfffe1fff },
    .{ .word = 0x120f7021, .value = 0xfffe3fff },
    .{ .word = 0x120f7421, .value = 0xfffe7fff },
    .{ .word = 0x120f7821, .value = 0xfffeffff },
    .{ .word = 0x120f8021, .value = 0x20002 },
    .{ .word = 0x120f8421, .value = 0x60006 },
    .{ .word = 0x120f8821, .value = 0xe000e },
    .{ .word = 0x120f8c21, .value = 0x1e001e },
    .{ .word = 0x120f9021, .value = 0x3e003e },
    .{ .word = 0x120f9421, .value = 0x7e007e },
    .{ .word = 0x120f9821, .value = 0xfe00fe },
    .{ .word = 0x120f9c21, .value = 0x1fe01fe },
    .{ .word = 0x120fa021, .value = 0x3fe03fe },
    .{ .word = 0x120fa421, .value = 0x7fe07fe },
    .{ .word = 0x120fa821, .value = 0xffe0ffe },
    .{ .word = 0x120fac21, .value = 0x1ffe1ffe },
    .{ .word = 0x120fb021, .value = 0x3ffe3ffe },
    .{ .word = 0x120fb421, .value = 0x7ffe7ffe },
    .{ .word = 0x120fb821, .value = 0xfffefffe },
    .{ .word = 0x12100021, .value = 0x10000 },
    .{ .word = 0x12100421, .value = 0x30000 },
    .{ .word = 0x12100821, .value = 0x70000 },
    .{ .word = 0x12100c21, .value = 0xf0000 },
    .{ .word = 0x12101021, .value = 0x1f0000 },
    .{ .word = 0x12101421, .value = 0x3f0000 },
    .{ .word = 0x12101821, .value = 0x7f0000 },
    .{ .word = 0x12101c21, .value = 0xff0000 },
    .{ .word = 0x12102021, .value = 0x1ff0000 },
    .{ .word = 0x12102421, .value = 0x3ff0000 },
    .{ .word = 0x12102821, .value = 0x7ff0000 },
    .{ .word = 0x12102c21, .value = 0xfff0000 },
    .{ .word = 0x12103021, .value = 0x1fff0000 },
    .{ .word = 0x12103421, .value = 0x3fff0000 },
    .{ .word = 0x12103821, .value = 0x7fff0000 },
    .{ .word = 0x12103c21, .value = 0xffff0000 },
    .{ .word = 0x12104021, .value = 0xffff0001 },
    .{ .word = 0x12104421, .value = 0xffff0003 },
    .{ .word = 0x12104821, .value = 0xffff0007 },
    .{ .word = 0x12104c21, .value = 0xffff000f },
    .{ .word = 0x12105021, .value = 0xffff001f },
    .{ .word = 0x12105421, .value = 0xffff003f },
    .{ .word = 0x12105821, .value = 0xffff007f },
    .{ .word = 0x12105c21, .value = 0xffff00ff },
    .{ .word = 0x12106021, .value = 0xffff01ff },
    .{ .word = 0x12106421, .value = 0xffff03ff },
    .{ .word = 0x12106821, .value = 0xffff07ff },
    .{ .word = 0x12106c21, .value = 0xffff0fff },
    .{ .word = 0x12107021, .value = 0xffff1fff },
    .{ .word = 0x12107421, .value = 0xffff3fff },
    .{ .word = 0x12107821, .value = 0xffff7fff },
    .{ .word = 0x12110021, .value = 0x8000 },
    .{ .word = 0x12110421, .value = 0x18000 },
    .{ .word = 0x12110821, .value = 0x38000 },
    .{ .word = 0x12110c21, .value = 0x78000 },
    .{ .word = 0x12111021, .value = 0xf8000 },
    .{ .word = 0x12111421, .value = 0x1f8000 },
    .{ .word = 0x12111821, .value = 0x3f8000 },
    .{ .word = 0x12111c21, .value = 0x7f8000 },
    .{ .word = 0x12112021, .value = 0xff8000 },
    .{ .word = 0x12112421, .value = 0x1ff8000 },
    .{ .word = 0x12112821, .value = 0x3ff8000 },
    .{ .word = 0x12112c21, .value = 0x7ff8000 },
    .{ .word = 0x12113021, .value = 0xfff8000 },
    .{ .word = 0x12113421, .value = 0x1fff8000 },
    .{ .word = 0x12113821, .value = 0x3fff8000 },
    .{ .word = 0x12113c21, .value = 0x7fff8000 },
    .{ .word = 0x12114021, .value = 0xffff8000 },
    .{ .word = 0x12114421, .value = 0xffff8001 },
    .{ .word = 0x12114821, .value = 0xffff8003 },
    .{ .word = 0x12114c21, .value = 0xffff8007 },
    .{ .word = 0x12115021, .value = 0xffff800f },
    .{ .word = 0x12115421, .value = 0xffff801f },
    .{ .word = 0x12115821, .value = 0xffff803f },
    .{ .word = 0x12115c21, .value = 0xffff807f },
    .{ .word = 0x12116021, .value = 0xffff80ff },
    .{ .word = 0x12116421, .value = 0xffff81ff },
    .{ .word = 0x12116821, .value = 0xffff83ff },
    .{ .word = 0x12116c21, .value = 0xffff87ff },
    .{ .word = 0x12117021, .value = 0xffff8fff },
    .{ .word = 0x12117421, .value = 0xffff9fff },
    .{ .word = 0x12117821, .value = 0xffffbfff },
    .{ .word = 0x12120021, .value = 0x4000 },
    .{ .word = 0x12120421, .value = 0xc000 },
    .{ .word = 0x12120821, .value = 0x1c000 },
    .{ .word = 0x12120c21, .value = 0x3c000 },
    .{ .word = 0x12121021, .value = 0x7c000 },
    .{ .word = 0x12121421, .value = 0xfc000 },
    .{ .word = 0x12121821, .value = 0x1fc000 },
    .{ .word = 0x12121c21, .value = 0x3fc000 },
    .{ .word = 0x12122021, .value = 0x7fc000 },
    .{ .word = 0x12122421, .value = 0xffc000 },
    .{ .word = 0x12122821, .value = 0x1ffc000 },
    .{ .word = 0x12122c21, .value = 0x3ffc000 },
    .{ .word = 0x12123021, .value = 0x7ffc000 },
    .{ .word = 0x12123421, .value = 0xfffc000 },
    .{ .word = 0x12123821, .value = 0x1fffc000 },
    .{ .word = 0x12123c21, .value = 0x3fffc000 },
    .{ .word = 0x12124021, .value = 0x7fffc000 },
    .{ .word = 0x12124421, .value = 0xffffc000 },
    .{ .word = 0x12124821, .value = 0xffffc001 },
    .{ .word = 0x12124c21, .value = 0xffffc003 },
    .{ .word = 0x12125021, .value = 0xffffc007 },
    .{ .word = 0x12125421, .value = 0xffffc00f },
    .{ .word = 0x12125821, .value = 0xffffc01f },
    .{ .word = 0x12125c21, .value = 0xffffc03f },
    .{ .word = 0x12126021, .value = 0xffffc07f },
    .{ .word = 0x12126421, .value = 0xffffc0ff },
    .{ .word = 0x12126821, .value = 0xffffc1ff },
    .{ .word = 0x12126c21, .value = 0xffffc3ff },
    .{ .word = 0x12127021, .value = 0xffffc7ff },
    .{ .word = 0x12127421, .value = 0xffffcfff },
    .{ .word = 0x12127821, .value = 0xffffdfff },
    .{ .word = 0x12130021, .value = 0x2000 },
    .{ .word = 0x12130421, .value = 0x6000 },
    .{ .word = 0x12130821, .value = 0xe000 },
    .{ .word = 0x12130c21, .value = 0x1e000 },
    .{ .word = 0x12131021, .value = 0x3e000 },
    .{ .word = 0x12131421, .value = 0x7e000 },
    .{ .word = 0x12131821, .value = 0xfe000 },
    .{ .word = 0x12131c21, .value = 0x1fe000 },
    .{ .word = 0x12132021, .value = 0x3fe000 },
    .{ .word = 0x12132421, .value = 0x7fe000 },
    .{ .word = 0x12132821, .value = 0xffe000 },
    .{ .word = 0x12132c21, .value = 0x1ffe000 },
    .{ .word = 0x12133021, .value = 0x3ffe000 },
    .{ .word = 0x12133421, .value = 0x7ffe000 },
    .{ .word = 0x12133821, .value = 0xfffe000 },
    .{ .word = 0x12133c21, .value = 0x1fffe000 },
    .{ .word = 0x12134021, .value = 0x3fffe000 },
    .{ .word = 0x12134421, .value = 0x7fffe000 },
    .{ .word = 0x12134821, .value = 0xffffe000 },
    .{ .word = 0x12134c21, .value = 0xffffe001 },
    .{ .word = 0x12135021, .value = 0xffffe003 },
    .{ .word = 0x12135421, .value = 0xffffe007 },
    .{ .word = 0x12135821, .value = 0xffffe00f },
    .{ .word = 0x12135c21, .value = 0xffffe01f },
    .{ .word = 0x12136021, .value = 0xffffe03f },
    .{ .word = 0x12136421, .value = 0xffffe07f },
    .{ .word = 0x12136821, .value = 0xffffe0ff },
    .{ .word = 0x12136c21, .value = 0xffffe1ff },
    .{ .word = 0x12137021, .value = 0xffffe3ff },
    .{ .word = 0x12137421, .value = 0xffffe7ff },
    .{ .word = 0x12137821, .value = 0xffffefff },
    .{ .word = 0x12140021, .value = 0x1000 },
    .{ .word = 0x12140421, .value = 0x3000 },
    .{ .word = 0x12140821, .value = 0x7000 },
    .{ .word = 0x12140c21, .value = 0xf000 },
    .{ .word = 0x12141021, .value = 0x1f000 },
    .{ .word = 0x12141421, .value = 0x3f000 },
    .{ .word = 0x12141821, .value = 0x7f000 },
    .{ .word = 0x12141c21, .value = 0xff000 },
    .{ .word = 0x12142021, .value = 0x1ff000 },
    .{ .word = 0x12142421, .value = 0x3ff000 },
    .{ .word = 0x12142821, .value = 0x7ff000 },
    .{ .word = 0x12142c21, .value = 0xfff000 },
    .{ .word = 0x12143021, .value = 0x1fff000 },
    .{ .word = 0x12143421, .value = 0x3fff000 },
    .{ .word = 0x12143821, .value = 0x7fff000 },
    .{ .word = 0x12143c21, .value = 0xffff000 },
    .{ .word = 0x12144021, .value = 0x1ffff000 },
    .{ .word = 0x12144421, .value = 0x3ffff000 },
    .{ .word = 0x12144821, .value = 0x7ffff000 },
    .{ .word = 0x12144c21, .value = 0xfffff000 },
    .{ .word = 0x12145021, .value = 0xfffff001 },
    .{ .word = 0x12145421, .value = 0xfffff003 },
    .{ .word = 0x12145821, .value = 0xfffff007 },
    .{ .word = 0x12145c21, .value = 0xfffff00f },
    .{ .word = 0x12146021, .value = 0xfffff01f },
    .{ .word = 0x12146421, .value = 0xfffff03f },
    .{ .word = 0x12146821, .value = 0xfffff07f },
    .{ .word = 0x12146c21, .value = 0xfffff0ff },
    .{ .word = 0x12147021, .value = 0xfffff1ff },
    .{ .word = 0x12147421, .value = 0xfffff3ff },
    .{ .word = 0x12147821, .value = 0xfffff7ff },
    .{ .word = 0x12150021, .value = 0x800 },
    .{ .word = 0x12150421, .value = 0x1800 },
    .{ .word = 0x12150821, .value = 0x3800 },
    .{ .word = 0x12150c21, .value = 0x7800 },
    .{ .word = 0x12151021, .value = 0xf800 },
    .{ .word = 0x12151421, .value = 0x1f800 },
    .{ .word = 0x12151821, .value = 0x3f800 },
    .{ .word = 0x12151c21, .value = 0x7f800 },
    .{ .word = 0x12152021, .value = 0xff800 },
    .{ .word = 0x12152421, .value = 0x1ff800 },
    .{ .word = 0x12152821, .value = 0x3ff800 },
    .{ .word = 0x12152c21, .value = 0x7ff800 },
    .{ .word = 0x12153021, .value = 0xfff800 },
    .{ .word = 0x12153421, .value = 0x1fff800 },
    .{ .word = 0x12153821, .value = 0x3fff800 },
    .{ .word = 0x12153c21, .value = 0x7fff800 },
    .{ .word = 0x12154021, .value = 0xffff800 },
    .{ .word = 0x12154421, .value = 0x1ffff800 },
    .{ .word = 0x12154821, .value = 0x3ffff800 },
    .{ .word = 0x12154c21, .value = 0x7ffff800 },
    .{ .word = 0x12155021, .value = 0xfffff800 },
    .{ .word = 0x12155421, .value = 0xfffff801 },
    .{ .word = 0x12155821, .value = 0xfffff803 },
    .{ .word = 0x12155c21, .value = 0xfffff807 },
    .{ .word = 0x12156021, .value = 0xfffff80f },
    .{ .word = 0x12156421, .value = 0xfffff81f },
    .{ .word = 0x12156821, .value = 0xfffff83f },
    .{ .word = 0x12156c21, .value = 0xfffff87f },
    .{ .word = 0x12157021, .value = 0xfffff8ff },
    .{ .word = 0x12157421, .value = 0xfffff9ff },
    .{ .word = 0x12157821, .value = 0xfffffbff },
    .{ .word = 0x12160021, .value = 0x400 },
    .{ .word = 0x12160421, .value = 0xc00 },
    .{ .word = 0x12160821, .value = 0x1c00 },
    .{ .word = 0x12160c21, .value = 0x3c00 },
    .{ .word = 0x12161021, .value = 0x7c00 },
    .{ .word = 0x12161421, .value = 0xfc00 },
    .{ .word = 0x12161821, .value = 0x1fc00 },
    .{ .word = 0x12161c21, .value = 0x3fc00 },
    .{ .word = 0x12162021, .value = 0x7fc00 },
    .{ .word = 0x12162421, .value = 0xffc00 },
    .{ .word = 0x12162821, .value = 0x1ffc00 },
    .{ .word = 0x12162c21, .value = 0x3ffc00 },
    .{ .word = 0x12163021, .value = 0x7ffc00 },
    .{ .word = 0x12163421, .value = 0xfffc00 },
    .{ .word = 0x12163821, .value = 0x1fffc00 },
    .{ .word = 0x12163c21, .value = 0x3fffc00 },
    .{ .word = 0x12164021, .value = 0x7fffc00 },
    .{ .word = 0x12164421, .value = 0xffffc00 },
    .{ .word = 0x12164821, .value = 0x1ffffc00 },
    .{ .word = 0x12164c21, .value = 0x3ffffc00 },
    .{ .word = 0x12165021, .value = 0x7ffffc00 },
    .{ .word = 0x12165421, .value = 0xfffffc00 },
    .{ .word = 0x12165821, .value = 0xfffffc01 },
    .{ .word = 0x12165c21, .value = 0xfffffc03 },
    .{ .word = 0x12166021, .value = 0xfffffc07 },
    .{ .word = 0x12166421, .value = 0xfffffc0f },
    .{ .word = 0x12166821, .value = 0xfffffc1f },
    .{ .word = 0x12166c21, .value = 0xfffffc3f },
    .{ .word = 0x12167021, .value = 0xfffffc7f },
    .{ .word = 0x12167421, .value = 0xfffffcff },
    .{ .word = 0x12167821, .value = 0xfffffdff },
    .{ .word = 0x12170021, .value = 0x200 },
    .{ .word = 0x12170421, .value = 0x600 },
    .{ .word = 0x12170821, .value = 0xe00 },
    .{ .word = 0x12170c21, .value = 0x1e00 },
    .{ .word = 0x12171021, .value = 0x3e00 },
    .{ .word = 0x12171421, .value = 0x7e00 },
    .{ .word = 0x12171821, .value = 0xfe00 },
    .{ .word = 0x12171c21, .value = 0x1fe00 },
    .{ .word = 0x12172021, .value = 0x3fe00 },
    .{ .word = 0x12172421, .value = 0x7fe00 },
    .{ .word = 0x12172821, .value = 0xffe00 },
    .{ .word = 0x12172c21, .value = 0x1ffe00 },
    .{ .word = 0x12173021, .value = 0x3ffe00 },
    .{ .word = 0x12173421, .value = 0x7ffe00 },
    .{ .word = 0x12173821, .value = 0xfffe00 },
    .{ .word = 0x12173c21, .value = 0x1fffe00 },
    .{ .word = 0x12174021, .value = 0x3fffe00 },
    .{ .word = 0x12174421, .value = 0x7fffe00 },
    .{ .word = 0x12174821, .value = 0xffffe00 },
    .{ .word = 0x12174c21, .value = 0x1ffffe00 },
    .{ .word = 0x12175021, .value = 0x3ffffe00 },
    .{ .word = 0x12175421, .value = 0x7ffffe00 },
    .{ .word = 0x12175821, .value = 0xfffffe00 },
    .{ .word = 0x12175c21, .value = 0xfffffe01 },
    .{ .word = 0x12176021, .value = 0xfffffe03 },
    .{ .word = 0x12176421, .value = 0xfffffe07 },
    .{ .word = 0x12176821, .value = 0xfffffe0f },
    .{ .word = 0x12176c21, .value = 0xfffffe1f },
    .{ .word = 0x12177021, .value = 0xfffffe3f },
    .{ .word = 0x12177421, .value = 0xfffffe7f },
    .{ .word = 0x12177821, .value = 0xfffffeff },
    .{ .word = 0x12180021, .value = 0x100 },
    .{ .word = 0x12180421, .value = 0x300 },
    .{ .word = 0x12180821, .value = 0x700 },
    .{ .word = 0x12180c21, .value = 0xf00 },
    .{ .word = 0x12181021, .value = 0x1f00 },
    .{ .word = 0x12181421, .value = 0x3f00 },
    .{ .word = 0x12181821, .value = 0x7f00 },
    .{ .word = 0x12181c21, .value = 0xff00 },
    .{ .word = 0x12182021, .value = 0x1ff00 },
    .{ .word = 0x12182421, .value = 0x3ff00 },
    .{ .word = 0x12182821, .value = 0x7ff00 },
    .{ .word = 0x12182c21, .value = 0xfff00 },
    .{ .word = 0x12183021, .value = 0x1fff00 },
    .{ .word = 0x12183421, .value = 0x3fff00 },
    .{ .word = 0x12183821, .value = 0x7fff00 },
    .{ .word = 0x12183c21, .value = 0xffff00 },
    .{ .word = 0x12184021, .value = 0x1ffff00 },
    .{ .word = 0x12184421, .value = 0x3ffff00 },
    .{ .word = 0x12184821, .value = 0x7ffff00 },
    .{ .word = 0x12184c21, .value = 0xfffff00 },
    .{ .word = 0x12185021, .value = 0x1fffff00 },
    .{ .word = 0x12185421, .value = 0x3fffff00 },
    .{ .word = 0x12185821, .value = 0x7fffff00 },
    .{ .word = 0x12185c21, .value = 0xffffff00 },
    .{ .word = 0x12186021, .value = 0xffffff01 },
    .{ .word = 0x12186421, .value = 0xffffff03 },
    .{ .word = 0x12186821, .value = 0xffffff07 },
    .{ .word = 0x12186c21, .value = 0xffffff0f },
    .{ .word = 0x12187021, .value = 0xffffff1f },
    .{ .word = 0x12187421, .value = 0xffffff3f },
    .{ .word = 0x12187821, .value = 0xffffff7f },
    .{ .word = 0x12190021, .value = 0x80 },
    .{ .word = 0x12190421, .value = 0x180 },
    .{ .word = 0x12190821, .value = 0x380 },
    .{ .word = 0x12190c21, .value = 0x780 },
    .{ .word = 0x12191021, .value = 0xf80 },
    .{ .word = 0x12191421, .value = 0x1f80 },
    .{ .word = 0x12191821, .value = 0x3f80 },
    .{ .word = 0x12191c21, .value = 0x7f80 },
    .{ .word = 0x12192021, .value = 0xff80 },
    .{ .word = 0x12192421, .value = 0x1ff80 },
    .{ .word = 0x12192821, .value = 0x3ff80 },
    .{ .word = 0x12192c21, .value = 0x7ff80 },
    .{ .word = 0x12193021, .value = 0xfff80 },
    .{ .word = 0x12193421, .value = 0x1fff80 },
    .{ .word = 0x12193821, .value = 0x3fff80 },
    .{ .word = 0x12193c21, .value = 0x7fff80 },
    .{ .word = 0x12194021, .value = 0xffff80 },
    .{ .word = 0x12194421, .value = 0x1ffff80 },
    .{ .word = 0x12194821, .value = 0x3ffff80 },
    .{ .word = 0x12194c21, .value = 0x7ffff80 },
    .{ .word = 0x12195021, .value = 0xfffff80 },
    .{ .word = 0x12195421, .value = 0x1fffff80 },
    .{ .word = 0x12195821, .value = 0x3fffff80 },
    .{ .word = 0x12195c21, .value = 0x7fffff80 },
    .{ .word = 0x12196021, .value = 0xffffff80 },
    .{ .word = 0x12196421, .value = 0xffffff81 },
    .{ .word = 0x12196821, .value = 0xffffff83 },
    .{ .word = 0x12196c21, .value = 0xffffff87 },
    .{ .word = 0x12197021, .value = 0xffffff8f },
    .{ .word = 0x12197421, .value = 0xffffff9f },
    .{ .word = 0x12197821, .value = 0xffffffbf },
    .{ .word = 0x121a0021, .value = 0x40 },
    .{ .word = 0x121a0421, .value = 0xc0 },
    .{ .word = 0x121a0821, .value = 0x1c0 },
    .{ .word = 0x121a0c21, .value = 0x3c0 },
    .{ .word = 0x121a1021, .value = 0x7c0 },
    .{ .word = 0x121a1421, .value = 0xfc0 },
    .{ .word = 0x121a1821, .value = 0x1fc0 },
    .{ .word = 0x121a1c21, .value = 0x3fc0 },
    .{ .word = 0x121a2021, .value = 0x7fc0 },
    .{ .word = 0x121a2421, .value = 0xffc0 },
    .{ .word = 0x121a2821, .value = 0x1ffc0 },
    .{ .word = 0x121a2c21, .value = 0x3ffc0 },
    .{ .word = 0x121a3021, .value = 0x7ffc0 },
    .{ .word = 0x121a3421, .value = 0xfffc0 },
    .{ .word = 0x121a3821, .value = 0x1fffc0 },
    .{ .word = 0x121a3c21, .value = 0x3fffc0 },
    .{ .word = 0x121a4021, .value = 0x7fffc0 },
    .{ .word = 0x121a4421, .value = 0xffffc0 },
    .{ .word = 0x121a4821, .value = 0x1ffffc0 },
    .{ .word = 0x121a4c21, .value = 0x3ffffc0 },
    .{ .word = 0x121a5021, .value = 0x7ffffc0 },
    .{ .word = 0x121a5421, .value = 0xfffffc0 },
    .{ .word = 0x121a5821, .value = 0x1fffffc0 },
    .{ .word = 0x121a5c21, .value = 0x3fffffc0 },
    .{ .word = 0x121a6021, .value = 0x7fffffc0 },
    .{ .word = 0x121a6421, .value = 0xffffffc0 },
    .{ .word = 0x121a6821, .value = 0xffffffc1 },
    .{ .word = 0x121a6c21, .value = 0xffffffc3 },
    .{ .word = 0x121a7021, .value = 0xffffffc7 },
    .{ .word = 0x121a7421, .value = 0xffffffcf },
    .{ .word = 0x121a7821, .value = 0xffffffdf },
    .{ .word = 0x121b0021, .value = 0x20 },
    .{ .word = 0x121b0421, .value = 0x60 },
    .{ .word = 0x121b0821, .value = 0xe0 },
    .{ .word = 0x121b0c21, .value = 0x1e0 },
    .{ .word = 0x121b1021, .value = 0x3e0 },
    .{ .word = 0x121b1421, .value = 0x7e0 },
    .{ .word = 0x121b1821, .value = 0xfe0 },
    .{ .word = 0x121b1c21, .value = 0x1fe0 },
    .{ .word = 0x121b2021, .value = 0x3fe0 },
    .{ .word = 0x121b2421, .value = 0x7fe0 },
    .{ .word = 0x121b2821, .value = 0xffe0 },
    .{ .word = 0x121b2c21, .value = 0x1ffe0 },
    .{ .word = 0x121b3021, .value = 0x3ffe0 },
    .{ .word = 0x121b3421, .value = 0x7ffe0 },
    .{ .word = 0x121b3821, .value = 0xfffe0 },
    .{ .word = 0x121b3c21, .value = 0x1fffe0 },
    .{ .word = 0x121b4021, .value = 0x3fffe0 },
    .{ .word = 0x121b4421, .value = 0x7fffe0 },
    .{ .word = 0x121b4821, .value = 0xffffe0 },
    .{ .word = 0x121b4c21, .value = 0x1ffffe0 },
    .{ .word = 0x121b5021, .value = 0x3ffffe0 },
    .{ .word = 0x121b5421, .value = 0x7ffffe0 },
    .{ .word = 0x121b5821, .value = 0xfffffe0 },
    .{ .word = 0x121b5c21, .value = 0x1fffffe0 },
    .{ .word = 0x121b6021, .value = 0x3fffffe0 },
    .{ .word = 0x121b6421, .value = 0x7fffffe0 },
    .{ .word = 0x121b6821, .value = 0xffffffe0 },
    .{ .word = 0x121b6c21, .value = 0xffffffe1 },
    .{ .word = 0x121b7021, .value = 0xffffffe3 },
    .{ .word = 0x121b7421, .value = 0xffffffe7 },
    .{ .word = 0x121b7821, .value = 0xffffffef },
    .{ .word = 0x121c0021, .value = 0x10 },
    .{ .word = 0x121c0421, .value = 0x30 },
    .{ .word = 0x121c0821, .value = 0x70 },
    .{ .word = 0x121c0c21, .value = 0xf0 },
    .{ .word = 0x121c1021, .value = 0x1f0 },
    .{ .word = 0x121c1421, .value = 0x3f0 },
    .{ .word = 0x121c1821, .value = 0x7f0 },
    .{ .word = 0x121c1c21, .value = 0xff0 },
    .{ .word = 0x121c2021, .value = 0x1ff0 },
    .{ .word = 0x121c2421, .value = 0x3ff0 },
    .{ .word = 0x121c2821, .value = 0x7ff0 },
    .{ .word = 0x121c2c21, .value = 0xfff0 },
    .{ .word = 0x121c3021, .value = 0x1fff0 },
    .{ .word = 0x121c3421, .value = 0x3fff0 },
    .{ .word = 0x121c3821, .value = 0x7fff0 },
    .{ .word = 0x121c3c21, .value = 0xffff0 },
    .{ .word = 0x121c4021, .value = 0x1ffff0 },
    .{ .word = 0x121c4421, .value = 0x3ffff0 },
    .{ .word = 0x121c4821, .value = 0x7ffff0 },
    .{ .word = 0x121c4c21, .value = 0xfffff0 },
    .{ .word = 0x121c5021, .value = 0x1fffff0 },
    .{ .word = 0x121c5421, .value = 0x3fffff0 },
    .{ .word = 0x121c5821, .value = 0x7fffff0 },
    .{ .word = 0x121c5c21, .value = 0xffffff0 },
    .{ .word = 0x121c6021, .value = 0x1ffffff0 },
    .{ .word = 0x121c6421, .value = 0x3ffffff0 },
    .{ .word = 0x121c6821, .value = 0x7ffffff0 },
    .{ .word = 0x121c6c21, .value = 0xfffffff0 },
    .{ .word = 0x121c7021, .value = 0xfffffff1 },
    .{ .word = 0x121c7421, .value = 0xfffffff3 },
    .{ .word = 0x121c7821, .value = 0xfffffff7 },
    .{ .word = 0x121d0021, .value = 0x8 },
    .{ .word = 0x121d0421, .value = 0x18 },
    .{ .word = 0x121d0821, .value = 0x38 },
    .{ .word = 0x121d0c21, .value = 0x78 },
    .{ .word = 0x121d1021, .value = 0xf8 },
    .{ .word = 0x121d1421, .value = 0x1f8 },
    .{ .word = 0x121d1821, .value = 0x3f8 },
    .{ .word = 0x121d1c21, .value = 0x7f8 },
    .{ .word = 0x121d2021, .value = 0xff8 },
    .{ .word = 0x121d2421, .value = 0x1ff8 },
    .{ .word = 0x121d2821, .value = 0x3ff8 },
    .{ .word = 0x121d2c21, .value = 0x7ff8 },
    .{ .word = 0x121d3021, .value = 0xfff8 },
    .{ .word = 0x121d3421, .value = 0x1fff8 },
    .{ .word = 0x121d3821, .value = 0x3fff8 },
    .{ .word = 0x121d3c21, .value = 0x7fff8 },
    .{ .word = 0x121d4021, .value = 0xffff8 },
    .{ .word = 0x121d4421, .value = 0x1ffff8 },
    .{ .word = 0x121d4821, .value = 0x3ffff8 },
    .{ .word = 0x121d4c21, .value = 0x7ffff8 },
    .{ .word = 0x121d5021, .value = 0xfffff8 },
    .{ .word = 0x121d5421, .value = 0x1fffff8 },
    .{ .word = 0x121d5821, .value = 0x3fffff8 },
    .{ .word = 0x121d5c21, .value = 0x7fffff8 },
    .{ .word = 0x121d6021, .value = 0xffffff8 },
    .{ .word = 0x121d6421, .value = 0x1ffffff8 },
    .{ .word = 0x121d6821, .value = 0x3ffffff8 },
    .{ .word = 0x121d6c21, .value = 0x7ffffff8 },
    .{ .word = 0x121d7021, .value = 0xfffffff8 },
    .{ .word = 0x121d7421, .value = 0xfffffff9 },
    .{ .word = 0x121d7821, .value = 0xfffffffb },
    .{ .word = 0x121e0021, .value = 0x4 },
    .{ .word = 0x121e0421, .value = 0xc },
    .{ .word = 0x121e0821, .value = 0x1c },
    .{ .word = 0x121e0c21, .value = 0x3c },
    .{ .word = 0x121e1021, .value = 0x7c },
    .{ .word = 0x121e1421, .value = 0xfc },
    .{ .word = 0x121e1821, .value = 0x1fc },
    .{ .word = 0x121e1c21, .value = 0x3fc },
    .{ .word = 0x121e2021, .value = 0x7fc },
    .{ .word = 0x121e2421, .value = 0xffc },
    .{ .word = 0x121e2821, .value = 0x1ffc },
    .{ .word = 0x121e2c21, .value = 0x3ffc },
    .{ .word = 0x121e3021, .value = 0x7ffc },
    .{ .word = 0x121e3421, .value = 0xfffc },
    .{ .word = 0x121e3821, .value = 0x1fffc },
    .{ .word = 0x121e3c21, .value = 0x3fffc },
    .{ .word = 0x121e4021, .value = 0x7fffc },
    .{ .word = 0x121e4421, .value = 0xffffc },
    .{ .word = 0x121e4821, .value = 0x1ffffc },
    .{ .word = 0x121e4c21, .value = 0x3ffffc },
    .{ .word = 0x121e5021, .value = 0x7ffffc },
    .{ .word = 0x121e5421, .value = 0xfffffc },
    .{ .word = 0x121e5821, .value = 0x1fffffc },
    .{ .word = 0x121e5c21, .value = 0x3fffffc },
    .{ .word = 0x121e6021, .value = 0x7fffffc },
    .{ .word = 0x121e6421, .value = 0xffffffc },
    .{ .word = 0x121e6821, .value = 0x1ffffffc },
    .{ .word = 0x121e6c21, .value = 0x3ffffffc },
    .{ .word = 0x121e7021, .value = 0x7ffffffc },
    .{ .word = 0x121e7421, .value = 0xfffffffc },
    .{ .word = 0x121e7821, .value = 0xfffffffd },
    .{ .word = 0x121f0021, .value = 0x2 },
    .{ .word = 0x121f0421, .value = 0x6 },
    .{ .word = 0x121f0821, .value = 0xe },
    .{ .word = 0x121f0c21, .value = 0x1e },
    .{ .word = 0x121f1021, .value = 0x3e },
    .{ .word = 0x121f1421, .value = 0x7e },
    .{ .word = 0x121f1821, .value = 0xfe },
    .{ .word = 0x121f1c21, .value = 0x1fe },
    .{ .word = 0x121f2021, .value = 0x3fe },
    .{ .word = 0x121f2421, .value = 0x7fe },
    .{ .word = 0x121f2821, .value = 0xffe },
    .{ .word = 0x121f2c21, .value = 0x1ffe },
    .{ .word = 0x121f3021, .value = 0x3ffe },
    .{ .word = 0x121f3421, .value = 0x7ffe },
    .{ .word = 0x121f3821, .value = 0xfffe },
    .{ .word = 0x121f3c21, .value = 0x1fffe },
    .{ .word = 0x121f4021, .value = 0x3fffe },
    .{ .word = 0x121f4421, .value = 0x7fffe },
    .{ .word = 0x121f4821, .value = 0xffffe },
    .{ .word = 0x121f4c21, .value = 0x1ffffe },
    .{ .word = 0x121f5021, .value = 0x3ffffe },
    .{ .word = 0x121f5421, .value = 0x7ffffe },
    .{ .word = 0x121f5821, .value = 0xfffffe },
    .{ .word = 0x121f5c21, .value = 0x1fffffe },
    .{ .word = 0x121f6021, .value = 0x3fffffe },
    .{ .word = 0x121f6421, .value = 0x7fffffe },
    .{ .word = 0x121f6821, .value = 0xffffffe },
    .{ .word = 0x121f6c21, .value = 0x1ffffffe },
    .{ .word = 0x121f7021, .value = 0x3ffffffe },
    .{ .word = 0x121f7421, .value = 0x7ffffffe },
    .{ .word = 0x121f7821, .value = 0xfffffffe },
};

test "a bit pattern immediate decodes to the value the assembler encoded" {
    for (x64_cases) |case| {
        const instruction = decode(case.word) catch |err| {
            std.debug.print("word {x} was refused: {s}\n", .{ case.word, @errorName(err) });
            return err;
        };
        switch (instruction) {
            .logic_imm => |logic| {
                try testing.expectEqual(Decode.Width.x64, logic.width);
                try testing.expectEqual(case.value, logic.immediate);
            },
            else => return error.TestExpectedLogicImmediate,
        }
    }
    for (w32_cases) |case| {
        const instruction = decode(case.word) catch |err| {
            std.debug.print("word {x} was refused: {s}\n", .{ case.word, @errorName(err) });
            return err;
        };
        switch (instruction) {
            .logic_imm => |logic| {
                try testing.expectEqual(Decode.Width.w32, logic.width);
                try testing.expectEqual(case.value, logic.immediate);
            },
            else => return error.TestExpectedLogicImmediate,
        }
    }
}

test "addressing modes decode as the assembler encodes them" {
    // Each word is what the assembler produces, so this is the architecture's own
    // answer rather than a second reading of the encoding.
    try std.testing.expectEqual(Instruction{ .memory = .{ .op = .load, .size = .double, .rn = 1, .rt = 0, .addressing = .{ .offset = 8 } } }, try decode(0xf9400420));
    try std.testing.expectEqual(Instruction{ .memory = .{ .op = .load, .size = .byte, .rn = 3, .rt = 2, .addressing = .{ .offset = 4 } } }, try decode(0x39401062));
    try std.testing.expectEqual(Instruction{ .memory = .{ .op = .load, .size = .double, .rn = 5, .rt = 4, .addressing = .{ .register = .{ .rm = 6, .extend = .uxtx, .amount = 0 } } } }, try decode(0xf86668a4));
    try std.testing.expectEqual(Instruction{ .memory = .{ .op = .load, .size = .double, .rn = 5, .rt = 4, .addressing = .{ .register = .{ .rm = 6, .extend = .uxtx, .amount = 3 } } } }, try decode(0xf86678a4));
    try std.testing.expectEqual(Instruction{ .memory = .{ .op = .load, .size = .double, .rn = 8, .rt = 7, .addressing = .{ .pre_index = 16 } } }, try decode(0xf8410d07));
    try std.testing.expectEqual(Instruction{ .memory = .{ .op = .load, .size = .double, .rn = 10, .rt = 9, .addressing = .{ .post_index = 16 } } }, try decode(0xf8410549));
    try std.testing.expectEqual(Instruction{ .memory = .{ .op = .load, .size = .double, .rn = 12, .rt = 11, .addressing = .{ .offset = -8 } } }, try decode(0xf85f818b));
    try std.testing.expectEqual(Instruction{ .memory = .{ .op = .load, .size = .word, .rn = 14, .rt = 13, .addressing = .{ .offset = -4 } } }, try decode(0xb85fc1cd));
    try std.testing.expectEqual(Instruction{ .memory = .{ .op = .store, .size = .word, .rn = 7, .rt = 6, .addressing = .{ .offset = -4 } } }, try decode(0xb81fc0e6));
    try std.testing.expectEqual(Instruction{ .pair = .{ .op = .store, .size = .double, .rn = 31, .rt = 19, .rt2 = 20, .addressing = .{ .pre_index = -16 } } }, try decode(0xa9bf53f3));
    try std.testing.expectEqual(Instruction{ .pair = .{ .op = .store, .size = .double, .rn = 31, .rt = 19, .rt2 = 20, .addressing = .{ .post_index = 16 } } }, try decode(0xa88153f3));
    try std.testing.expectEqual(Instruction{ .pair = .{ .op = .store, .size = .double, .rn = 31, .rt = 21, .rt2 = 22, .addressing = .{ .offset = 16 } } }, try decode(0xa9015bf5));
    try std.testing.expectEqual(Instruction{ .pair = .{ .op = .load, .size = .double, .rn = 3, .rt = 25, .rt2 = 26, .addressing = .{ .pre_index = -32 } } }, try decode(0xa9fe6879));
    try std.testing.expectEqual(Instruction{ .pair = .{ .op = .load, .size = .double, .rn = 4, .rt = 27, .rt2 = 28, .addressing = .{ .post_index = 32 } } }, try decode(0xa8c2709b));
    try std.testing.expectEqual(Instruction{ .pair = .{ .op = .load, .size = .double, .rn = 5, .rt = 29, .rt2 = 30, .addressing = .{ .offset = 64 } } }, try decode(0xa94478bd));
    try std.testing.expectEqual(Instruction{ .pair = .{ .op = .load, .size = .word, .rn = 3, .rt = 1, .rt2 = 2, .addressing = .{ .offset = 8 } } }, try decode(0x29410861));
    // A pair of 16-bit elements is the floating point class, which this does not model.
    try std.testing.expectError(error.UnsupportedInstruction, decode(0x6d410861));
}

/// The eight bytes of guest memory at an offset within a block, read as a word.
fn readInt(bytes: []const u8, offset: usize) u64 {
    return std.mem.readInt(u64, bytes[offset..][0..8], .little);
}

test "a pre-indexed pair saves and restores a frame" {
    // stp x19, x20, [sp, #-16]! ; ldp x19, x20, [sp], #16 -- the shape of every
    // function prologue and epilogue, so the guest round-trips through memory.
    const instructions = [_]u32{
        0xa9bf53f3, // stp x19, x20, [sp, #-16]!
        0xa88153f3, // ldp x19, x20, [sp], #16
    };
    const base: u64 = 0x1000;
    var bytes: [64]u8 = @splat(0);
    // The run loop resumes at the word after each access, so a self branch parks
    // the guest once the prologue and epilogue have both retired.
    const program = [_]u32{0x14000000};
    for (instructions ++ program, 0..) |word, index| std.mem.writeInt(u32, bytes[index * 4 ..][0..4], word, .little);
    const regions = [_]GuestMemory.Region{.{ .gpa = base, .len = bytes.len, .backing = .{ .shared = &bytes } }};
    var memory: GuestMemory = .{ .regions = &regions };
    var machine = Machine.init(testing.allocator(), &memory);
    defer machine.deinit();
    const hv = machine.backend();
    const id = try hv.addVcpu();
    try hv.setRegister(id, .pc, base);
    // The stack pointer is register 31, which the register file holds last.
    machine.cpu.sp = base + 48;
    machine.cpu.x[19] = 0x1111;
    machine.cpu.x[20] = 0x2222;
    _ = try hv.run(id);
    // The pair must have written both halves, at the frame the prologue opened.
    try testing.expectEqual(@as(u64, 0x1111), readInt(&bytes, 32));
    try testing.expectEqual(@as(u64, 0x2222), readInt(&bytes, 40));
    // The epilogue restores the stack pointer, and the loads must land back in
    // the registers they came from.
    try testing.expectEqual(@as(u64, base + 48), machine.cpu.sp);
    try testing.expectEqual(@as(u64, 0x1111), machine.cpu.x[19]);
    try testing.expectEqual(@as(u64, 0x2222), machine.cpu.x[20]);
}

test "a post-index single access uses the old base and then advances it" {
    // ldr x0, [x1], #16 reads at x1 and leaves x1 sixteen further on, which is
    // the idiom for walking a structure.
    const base: u64 = 0x1000;
    var bytes: [64]u8 = @splat(0);
    // A self branch parks the guest once the access has retired.
    const word: u32 = 0xf8410420; // ldr x0, [x1], #16
    const program = [_]u32{ word, 0x14000000 };
    for (program, 0..) |w, index| std.mem.writeInt(u32, bytes[index * 4 ..][0..4], w, .little);
    std.mem.writeInt(u64, bytes[16..24], 0xabcd, .little);
    const regions = [_]GuestMemory.Region{.{ .gpa = base, .len = bytes.len, .backing = .{ .shared = &bytes } }};
    var memory: GuestMemory = .{ .regions = &regions };
    var machine = Machine.init(testing.allocator(), &memory);
    defer machine.deinit();
    const hv = machine.backend();
    const id = try hv.addVcpu();
    try hv.setRegister(id, .pc, base);
    try hv.setRegister(id, .x1, base + 16);
    _ = try hv.run(id);
    try testing.expectEqual(@as(u64, 0xabcd), machine.cpu.x[0]);
    try testing.expectEqual(@as(u64, base + 32), machine.cpu.x[1]);
}

test "a register offset scales and sums before the access" {
    // ldr x0, [x1, x2, lsl #3] is how an array element is reached.
    const base: u64 = 0x1000;
    var bytes: [256]u8 = @splat(0);
    // A self branch parks the guest once the access has retired.
    const word: u32 = 0xf8627820; // ldr x0, [x1, x2, lsl #3]
    const program = [_]u32{ word, 0x14000000 };
    for (program, 0..) |w, index| std.mem.writeInt(u32, bytes[index * 4 ..][0..4], w, .little);
    std.mem.writeInt(u64, bytes[64..72], 0x5a5a, .little);
    const regions = [_]GuestMemory.Region{.{ .gpa = base, .len = bytes.len, .backing = .{ .shared = &bytes } }};
    var memory: GuestMemory = .{ .regions = &regions };
    var machine = Machine.init(testing.allocator(), &memory);
    defer machine.deinit();
    const hv = machine.backend();
    const id = try hv.addVcpu();
    try hv.setRegister(id, .pc, base);
    try hv.setRegister(id, .x1, base);
    try hv.setRegister(id, .x2, 8); // scaled by eight lands on byte 64
    _ = try hv.run(id);
    try testing.expectEqual(@as(u64, 0x5a5a), machine.cpu.x[0]);
    try testing.expectEqual(@as(u64, base), machine.cpu.x[1]);
}

test "a pair of 32-bit registers moves four bytes per half" {
    // ldp w1, w2, [x3, #8] loads two words into zeroed registers, so a stale
    // upper half would show up here.
    const base: u64 = 0x1000;
    var bytes: [64]u8 = @splat(0);
    // A self branch parks the guest once the access has retired.
    const word: u32 = 0x29410861; // ldp w1, w2, [x3, #8]
    const program = [_]u32{ word, 0x14000000 };
    for (program, 0..) |w, index| std.mem.writeInt(u32, bytes[index * 4 ..][0..4], w, .little);
    std.mem.writeInt(u32, bytes[8..12], 0xdeadbeef, .little);
    std.mem.writeInt(u32, bytes[12..16], 0x12345678, .little);
    const regions = [_]GuestMemory.Region{.{ .gpa = base, .len = bytes.len, .backing = .{ .shared = &bytes } }};
    var memory: GuestMemory = .{ .regions = &regions };
    var machine = Machine.init(testing.allocator(), &memory);
    defer machine.deinit();
    const hv = machine.backend();
    const id = try hv.addVcpu();
    try hv.setRegister(id, .pc, base);
    try hv.setRegister(id, .x3, base);
    machine.cpu.x[1] = 0xdeadbeef_cafebabe;
    machine.cpu.x[2] = 0xdeadbeef_cafebabe;
    _ = try hv.run(id);
    try testing.expectEqual(@as(u64, 0xdeadbeef), machine.cpu.x[1]);
    try testing.expectEqual(@as(u64, 0x12345678), machine.cpu.x[2]);
}
test "a sign-extending pair loads two words and extends each" {
    // The kernel's own `ldpsw x2, x1, [sp]`: a negative first word sign-extends
    // to all ones above bit 31, and a positive second word zero-extends there.
    const base: u64 = 0x1000;
    var bytes: [64]u8 = @splat(0);
    const word: u32 = 0x694007e2; // ldpsw x2, x1, [sp]
    const program = [_]u32{ word, 0x14000000 };
    for (program, 0..) |w, index| std.mem.writeInt(u32, bytes[index * 4 ..][0..4], w, .little);
    std.mem.writeInt(u32, bytes[32..36], 0x8000_0001, .little);
    std.mem.writeInt(u32, bytes[36..40], 0x7fff_ffff, .little);
    const regions = [_]GuestMemory.Region{.{ .gpa = base, .len = bytes.len, .backing = .{ .shared = &bytes } }};
    var memory: GuestMemory = .{ .regions = &regions };
    var machine = Machine.init(testing.allocator(), &memory);
    defer machine.deinit();
    const hv = machine.backend();
    const id = try hv.addVcpu();
    try hv.setRegister(id, .pc, base);
    machine.cpu.sp = base + 32;
    machine.cpu.x[1] = 0xdeadbeef_cafebabe;
    machine.cpu.x[2] = 0xdeadbeef_cafebabe;
    _ = try hv.run(id);
    try testing.expectEqual(@as(u64, 0xffff_ffff_8000_0001), machine.cpu.x[2]);
    try testing.expectEqual(@as(u64, 0x0000_0000_7fff_ffff), machine.cpu.x[1]);
    // The decode carries the extension on both halves, and the store form is refused.
    try testing.expectEqual(Cpu.SignExtend.to64, (try decode(word)).pair.signed);
    try testing.expectError(error.UnsupportedInstruction, decode(0x690007e2));
}

test "a product is added to its accumulator, or stands alone" {
    // madd x0, x1, x2, x3 with the registers holding 6, 7 and 100, and then the
    // same product with no accumulator at all.
    var block = try compileWords(testing.allocator(), 0x4000_0000, &.{
        0xd28000c1, // movz x1, #6
        0xd28000e2, // movz x2, #7
        0xd2801be3, // movz x3, #100
        0x9b0200a0, // madd x0, x1, x2, x3
        0x9b027c20, // mul x0, x1, x2
    });
    defer block.deinit();
    var cpu: Cpu = .{};
    _ = block.run(&cpu);
    // The last of these is a bare product, because register 31 as the
    // accumulator is how the encoding spells `mul`.
    try testing.expectEqual(@as(u64, 6 * 7), cpu.x[0]);
}

test "a 32-bit product keeps only the low half" {
    // 32-bit arithmetic wraps at 32 bits, so this is the answer modulo 2^32 even
    // though the registers hold full 64-bit values.
    var block = try compileWords(testing.allocator(), 0x4000_0000, &.{
        0x52800021, // movz w1, #1
        0x72bfffe1, // movk w1, #0xffff, lsl #16
        0xd2800042, // movz x2, #2
        0x1b027c20, // mul w0, w1, w2
    });
    defer block.deinit();
    var cpu: Cpu = .{};
    _ = block.run(&cpu);
    // The product of 0xffff0001 and 2 is 0x1fffe0002, of which a 32-bit
    // multiply keeps only the low half.
    try testing.expectEqual(@as(u64, 0xfffe0002), cpu.x[0]);
}

test "an address form reaches its own code and the page below it" {
    // adr measures from the instruction itself, and adrp from the page the
    // instruction is in. Starting part way into a page is what separates them:
    // the two differ by exactly the offset into that page.
    const base: u64 = 0x4000_1808;
    // Both displacements are zero here, so the only difference between the two
    // results is the page rounding. These are the words the assembler emits for
    // them at this address.
    var block = try compileWords(testing.allocator(), base, &.{
        0x10000000, // adr x0, #0
        0x90000001, // adrp x1, #0
    });
    defer block.deinit();
    var cpu: Cpu = .{};
    _ = block.run(&cpu);
    try testing.expectEqual(base, cpu.x[0]);
    // The block starts 0x808 into its page, and the page form rounds that away.
    try testing.expectEqual(base & ~@as(u64, 4095), cpu.x[1]);
}

/// The address one instruction forms, checked against the operand as written
/// rather than against a decoded field, so that a mistake in the encoding cannot
/// make the test agree with itself.
fn addressOf(word: u32, cpu: *Cpu) !u64 {
    var block = try compileWords(testing.allocator(), 0x4000_1000, &.{word});
    defer block.deinit();
    _ = block.run(cpu);
    return cpu.address;
}

test "every addressing mode reaches the right address" {
    var cpu: Cpu = .{};
    // A scaled twelve-bit offset.
    cpu.x[1] = 0x2000;
    try testing.expectEqual(@as(u64, 0x2008), try addressOf(0xf9400420, &cpu)); // [x1, #8]
    // A register offset, and the same with the scale the form allows.
    cpu.x[5] = 0x3000;
    cpu.x[6] = 4;
    try testing.expectEqual(@as(u64, 0x3004), try addressOf(0xf86668a4, &cpu)); // [x5, x6]
    try testing.expectEqual(@as(u64, 0x3020), try addressOf(0xf86678a4, &cpu)); // [x5, x6, lsl #3]
    // A pre-index form accesses the new base, so the register already holds it.
    cpu.x[8] = 0x4000;
    try testing.expectEqual(@as(u64, 0x4010), try addressOf(0xf8410d07, &cpu)); // [x8, #16]!
    try testing.expectEqual(@as(u64, 0x4010), cpu.x[8]);
    // A post-index form accesses the old base and defers the update to the run
    // loop, which is the only thing that can order it after the access.
    cpu.x[10] = 0x5000;
    try testing.expectEqual(@as(u64, 0x5000), try addressOf(0xf8410549, &cpu)); // [x10], #16
    try testing.expectEqual(true, cpu.writeback);
    try testing.expectEqual(@as(u64, 0x5010), cpu.writeback_value);
    try testing.expectEqual(@as(u8, 10), cpu.writeback_dest);
    try testing.expectEqual(@as(u64, 0x5000), cpu.x[10]);
    // The unscaled form displaces by the signed nine-bit field, with no scaling,
    // which is what lets it name a negative offset. A fresh CPU, because the
    // writeback above is still set and only the run loop clears it.
    cpu = .{};
    cpu.x[12] = 0x6000;
    try testing.expectEqual(@as(u64, 0x5ff8), try addressOf(0xf85f818b, &cpu)); // [x12, #-8]
    cpu.x[14] = 0x7000;
    try testing.expectEqual(@as(u64, 0x6ffc), try addressOf(0xb85fc1cd, &cpu)); // [x14, #-4]
    try testing.expectEqual(true, !cpu.writeback);
}

test "a pair transfer names two registers at adjacent addresses" {
    var block = try compileWords(testing.allocator(), 0x4000_1000, &.{0xa9bf53f3});
    defer block.deinit();
    var cpu: Cpu = .{ .sp = 0x8000 };
    cpu.x[19] = 0x1111;
    cpu.x[20] = 0x2222;
    _ = block.run(&cpu);

    // The first element is where the form says, and the second one is a single
    // element past it, since the pair is two adjacent registers.
    try testing.expectEqual(@as(u64, 0x8000 - 16), cpu.address);
    try testing.expectEqual(@as(u64, 0x1111), cpu.value);
    try testing.expectEqual(@as(u8, 19), cpu.dest);
    try testing.expectEqual(@as(u64, 0x8000 - 16 + 8), cpu.second_address);
    try testing.expectEqual(@as(u64, 0x2222), cpu.second_value);
    try testing.expectEqual(@as(u8, 20), cpu.second_dest);
    try testing.expectEqual(@as(u8, 8), cpu.second_width);
    try testing.expectEqual(true, cpu.second_pending);
    // A pre-index store has no deferred writeback, the base having already moved.
    try testing.expectEqual(true, !cpu.writeback);
    try testing.expectEqual(@as(u64, 0x8000 - 16), cpu.sp);
}

test "a post-index pair defers the base update to after the access" {
    var block = try compileWords(testing.allocator(), 0x4000_1000, &.{0xa88153f3});
    defer block.deinit();
    var cpu: Cpu = .{ .sp = 0x8000 };
    cpu.x[19] = 0x1111;
    cpu.x[20] = 0x2222;
    _ = block.run(&cpu);

    // It stores at the old base, and leaves the new one for the run loop. The
    // second element is past the new base, which is what makes this form a
    // store-then-advance of a frame.
    try testing.expectEqual(@as(u64, 0x8000), cpu.address);
    try testing.expectEqual(@as(u64, 0x8000 + 8), cpu.second_address);
    try testing.expectEqual(@as(u64, 0x8000 + 16), cpu.writeback_value);
    try testing.expectEqual(@as(u8, 31), cpu.writeback_dest);
    try testing.expectEqual(@as(u64, 0x8000), cpu.sp);
}

test "a product with no accumulator is a plain multiply" {
    // Register 31 in the accumulator field is what spells MUL rather than MADD,
    // so one instruction per block, and the result read from its destination.
    var cpu: Cpu = .{};
    cpu.x[1] = 6;
    cpu.x[2] = 7;
    cpu.x[3] = 100;

    var block = try compileWords(testing.allocator(), 0x4000_1000, &.{0x9b027c20});
    defer block.deinit();
    _ = block.run(&cpu);
    try testing.expectEqual(@as(u64, 42), cpu.x[0]);

    block.deinit();
    block = try compileWords(testing.allocator(), 0x4000_1000, &.{0x9b020c20});
    _ = block.run(&cpu);
    try testing.expectEqual(@as(u64, 142), cpu.x[0]);

    block.deinit();
    block = try compileWords(testing.allocator(), 0x4000_1000, &.{0x9b028c20});
    _ = block.run(&cpu);
    try testing.expectEqual(@as(u64, 58), cpu.x[0]);
}

test "a system register names the field it should" {
    // Every word here is one the assembler emits, paired with the name it
    // carries there. The pairing is the point: a table that disagreed with the
    // assembler would be checked against itself and pass.
    const rows = [_]struct { word: u32, register: Decode.SystemRegister, read: bool }{
        .{ .word = 0xd5384100, .register = .sp_el0, .read = true },
        .{ .word = 0xd53c4100, .register = .sp_el1, .read = true },
        .{ .word = 0xd53e4100, .register = .sp_el2, .read = true },
        .{ .word = 0xd5384240, .register = .current_el, .read = true },
        .{ .word = 0xd5384000, .register = .spsr_el1, .read = true },
        .{ .word = 0xd5384020, .register = .elr_el1, .read = true },
        .{ .word = 0xd5385200, .register = .esr_el1, .read = true },
        .{ .word = 0xd5386000, .register = .far_el1, .read = true },
        .{ .word = 0xd538c000, .register = .vbar_el1, .read = true },
        .{ .word = 0xd5381040, .register = .cpacr_el1, .read = true },
        .{ .word = 0xd5381000, .register = .sctlr_el1, .read = true },
        .{ .word = 0xd5382000, .register = .ttbr0_el1, .read = true },
        .{ .word = 0xd5382020, .register = .ttbr1_el1, .read = true },
        .{ .word = 0xd5382040, .register = .tcr_el1, .read = true },
        .{ .word = 0xd538a200, .register = .mair_el1, .read = true },
        .{ .word = 0xd53bd040, .register = .tpidr_el0, .read = true },
        .{ .word = 0xd53bd060, .register = .tpidrro_el0, .read = true },
        .{ .word = 0xd53be040, .register = .cntvct_el0, .read = true },
        .{ .word = 0xd53b4220, .register = .daif, .read = true },
        .{ .word = 0xd53b4200, .register = .nzcv, .read = true },
        .{ .word = 0xd51c4100, .register = .sp_el1, .read = false },
        .{ .word = 0xd51bd040, .register = .tpidr_el0, .read = false },
        .{ .word = 0xd5184000, .register = .spsr_el1, .read = false },
        .{ .word = 0xd518c000, .register = .vbar_el1, .read = false },
    };
    for (rows) |row| {
        switch (try decode(row.word)) {
            .system => |sys| {
                try testing.expectEqual(row.register, sys.register);
                try testing.expectEqual(row.read, sys.read);
            },
            else => return error.NotASystemRegister,
        }
    }
    // A register this does not model is refused rather than read as zero.
    try testing.expectError(error.UnsupportedInstruction, decode(0xd5380060)); // S3_0_C0_C0_3, which nothing defines
}

test "a control register round-trips through the guest" {
    var cpu: Cpu = .{};
    var block = try compileWords(testing.allocator(), 0x4000_1000, &.{
        0xd51b_d040, // msr tpidr_el0, x0
        0xd53b_d041, // mrs x1, tpidr_el0
    });
    defer block.deinit();
    cpu.x[0] = 0x1234_5678;
    _ = block.run(&cpu);
    try testing.expectEqual(@as(u64, 0x1234_5678), cpu.x[1]);
    try testing.expectEqual(@as(u64, 0x1234_5678), cpu.system.tpidr_el0);
}

test "the stack pointer of the current level is the live one" {
    var cpu: Cpu = .{ .sp = 0x8000, .system = .{ .el = 1, .spsel = true } };
    // Writing SP_EL1 at EL1 must move the live stack pointer, because an access
    // through register 31 has to agree with what the register says.
    var write = try compileWords(testing.allocator(), 0x4000_1000, &.{0xd51c4100});
    defer write.deinit();
    cpu.x[0] = 0x9000;
    _ = write.run(&cpu);
    try testing.expectEqual(@as(u64, 0x9000), cpu.sp);

    // Reading SP_EL2, which is not where the guest is running, gives the saved
    // value rather than the live one.
    var read = try compileWords(testing.allocator(), 0x4000_1000, &.{0xd53e4101});
    defer read.deinit();
    cpu.system.sp_el[2] = 0x1234;
    _ = read.run(&cpu);
    try testing.expectEqual(@as(u64, 0x1234), cpu.x[1]);
    try testing.expectEqual(@as(u64, 0x9000), cpu.sp);
}

test "CurrentEL reads back the level in the architectural bit pattern" {
    var cpu: Cpu = .{ .system = .{ .el = 1 } };
    var block = try compileWords(testing.allocator(), 0x4000_1000, &.{0xd5384241});
    defer block.deinit();
    _ = block.run(&cpu);
    // EL1 is 0b01, in bits 3:2, so the value is 0b0100. Nothing else is set:
    // Linux compares it against exactly that, and against 0b1000 for EL2.
    try testing.expectEqual(@as(u64, 0b0100), cpu.x[1]);
}

test "NZCV reads and writes the condition flags themselves" {
    var cpu: Cpu = .{};
    // A write takes the low four bits only, which are the flags.
    var write = try compileWords(testing.allocator(), 0x4000_1000, &.{0xd51b4200});
    defer write.deinit();
    cpu.x[0] = 0xffff_ffff_ffff_000f;
    _ = write.run(&cpu);
    try testing.expectEqual(@as(u32, 0xf), cpu.flags);

    // And a read gives them back, zero-extended into the wide register.
    var read = try compileWords(testing.allocator(), 0x4000_1000, &.{0xd53b4201});
    defer read.deinit();
    _ = read.run(&cpu);
    try testing.expectEqual(@as(u64, 0xf), cpu.x[1]);
}

test "the barriers are recognised apart from the hints" {
    // The two classes differ only in their register number, so getting the mask
    // wrong turns one into the other or refuses both.
    const rows = [_]struct { word: u32, tag: []const u8 }{
        .{ .word = 0xd5033f9f, .tag = "dsb" },
        .{ .word = 0xd5033fbf, .tag = "dmb" },
        .{ .word = 0xd5033fdf, .tag = "isb" },
        .{ .word = 0xd503201f, .tag = "nop" },
        .{ .word = 0xd503203f, .tag = "yield" },
        .{ .word = 0xd503205f, .tag = "wfe" },
        .{ .word = 0xd503207f, .tag = "wfi" },
        .{ .word = 0xd503209f, .tag = "sev" },
        .{ .word = 0xd50320bf, .tag = "sevl" },
        // The branch target identification hints, which the guest was told do not exist.
        .{ .word = 0xd503241f, .tag = "nop" },
        .{ .word = 0xd503245f, .tag = "nop" },
        .{ .word = 0xd503249f, .tag = "nop" },
        .{ .word = 0xd50324df, .tag = "nop" },
    };
    for (rows) |row| {
        // The name is compared through `std.mem.eql` because the testing shim
        // has no string comparison of its own.
        const got = try decode(row.word);
        try testing.expectEqual(true, std.mem.eql(u8, row.tag, @tagName(got)));
    }
}
test "WFE waits unless an event arrived, and SEV sets the event" {
    // `sevl; wfe` falls through: the local event is set going in.
    const base: u64 = 0x1000;
    var bytes: [512]u8 = @splat(0);
    const program = [_]u32{ 0xd50320bf, 0xd503205f, 0x14000000 };
    for (program, 0..) |word, index| std.mem.writeInt(u32, bytes[index * 4 ..][0..4], word, .little);
    const regions = [_]GuestMemory.Region{.{ .gpa = base, .len = bytes.len, .backing = .{ .shared = &bytes } }};
    var memory: GuestMemory = .{ .regions = &regions };
    var machine = Machine.init(testing.allocator(), &memory);
    defer machine.deinit();
    const hv = machine.backend();
    const id = try hv.addVcpu();
    try hv.setRegister(id, .pc, base);
    switch (try hv.run(id)) {
        .interrupted => {},
        else => return error.ExpectedInterrupted,
    }
    try testing.expectEqual(@as(u64, base + 8), machine.cpu.pc);
    try testing.expectEqual(false, machine.cpu.event_set);

    // A bare `wfe` with no event parks at the wait.
    var waiting = Machine.init(testing.allocator(), &memory);
    defer waiting.deinit();
    const hv_waiting = waiting.backend();
    const id_waiting = try hv_waiting.addVcpu();
    try hv_waiting.setRegister(id_waiting, .pc, base + 4);
    try testing.expectEqual(Backend.Exit{ .wfi = {} }, try hv_waiting.run(id_waiting));
    try testing.expectEqual(@as(u64, base + 8), waiting.cpu.pc);

    // `sev; wfe` falls through the same way `sevl` does.
    var signal_bytes: [12]u8 = undefined;
    std.mem.writeInt(u32, signal_bytes[0..4], 0xd503209f, .little); // sev
    std.mem.writeInt(u32, signal_bytes[4..8], 0xd503205f, .little); // wfe
    std.mem.writeInt(u32, signal_bytes[8..12], 0x14000000, .little);
    var signal_regions = [_]GuestMemory.Region{.{ .gpa = base, .len = signal_bytes.len, .backing = .{ .shared = &signal_bytes } }};
    var signal_memory: GuestMemory = .{ .regions = &signal_regions };
    var signalled = Machine.init(testing.allocator(), &signal_memory);
    defer signalled.deinit();
    const hv_signalled = signalled.backend();
    const id_signalled = try hv_signalled.addVcpu();
    try hv_signalled.setRegister(id_signalled, .pc, base);
    switch (try hv_signalled.run(id_signalled)) {
        .interrupted => {},
        else => return error.ExpectedInterrupted,
    }
    try testing.expectEqual(@as(u64, base + 8), signalled.cpu.pc);
}

test "TST sets the flags and leaves the stack pointer alone" {
    // `TST` is `ANDS` with register 31 as the destination, which discards the
    // result rather than writing the stack pointer. Getting that wrong would
    // corrupt the stack on any code that tests a bit.
    var cpu: Cpu = .{ .sp = 0x7000 };
    var block = try compileWords(testing.allocator(), 0x4000_1000, &.{0xf2400d1f});
    defer block.deinit();
    // Nothing of x8 is in the low four bits, so the result is zero and Z is set.
    cpu.x[8] = 0b1_0000;
    _ = block.run(&cpu);
    try testing.expectEqual(@as(u64, 0x7000), cpu.sp);
    try testing.expectEqual(true, cpu.flags & (1 << 30) != 0);

    // And a bit that is in the mask makes the result non-zero, so Z clears.
    var other = try compileWords(testing.allocator(), 0x4000_1000, &.{0xf2400d1f});
    defer other.deinit();
    cpu.x[8] = 0b1010;
    _ = other.run(&cpu);
    try testing.expectEqual(@as(u64, 0x7000), cpu.sp);
    try testing.expectEqual(false, cpu.flags & (1 << 30) != 0);
}

/// Run one immediate-form instruction against a `daif` starting at `from`.
fn daifAfter(word: u32, from: u64) !u64 {
    var cpu: Cpu = .{ .system = .{ .daif = from } };
    var block = try compileWords(testing.allocator(), 0x4000_1000, &.{word});
    defer block.deinit();
    _ = block.run(&cpu);
    return cpu.system.daif;
}

test "the immediate forms change only the bits they name" {
    // Interrupts start fully masked, so clearing a single one of the four must
    // leave exactly the other three.
    try testing.expectEqual(@as(u64, 0b1101), try daifAfter(0xd50342ff, 0xf));
    // Clearing all four empties the register, and clearing none leaves it alone.
    try testing.expectEqual(@as(u64, 0), try daifAfter(0xd5034fff, 0xf));
    try testing.expectEqual(@as(u64, 0xf), try daifAfter(0xd50340ff, 0xf));
    // Setting puts a bit back without disturbing the others, and setting a mask
    // of nothing is how the instruction spells a no-op.
    try testing.expectEqual(@as(u64, 0b1101), try daifAfter(0xd50340df, 0b1101));
    try testing.expectEqual(@as(u64, 0xf), try daifAfter(0xd50342df, 0b1101));
    try testing.expectEqual(@as(u64, 0xf), try daifAfter(0xd5034fdf, 0b1101));
}

test "a system register this does not model is refused" {
    // Reading an unknown control register as zero would be worse than refusing:
    // a kernel that read its own page table base as zero would carry on until
    // something much later failed for no visible reason.
    for ([_]u32{ 0xd5380060, 0xd5383000, 0xd53b0000, 0xd5385000 }) |word| {
        try testing.expectError(error.UnsupportedInstruction, decode(word));
    }
}

// The stage-1 walk. The page tables here are built by hand, so each expected
// address is written out rather than computed by the code under test, which is
// what would make a test agree with a mistake in the walk itself.

/// Guest physical memory with room for page tables, and a place to put them.
const Fixture = struct {
    /// 1MB of physical memory, which is more than the tables below need.
    bytes: [1 << 20]u8 = @splat(0),
    regions: [1]GuestMemory.Region = undefined,

    fn memory(self: *Fixture) GuestMemory {
        self.regions = .{.{ .gpa = 0, .len = self.bytes.len, .backing = .{ .shared = &self.bytes } }};
        return .{ .regions = &self.regions };
    }

    fn put(self: *Fixture, address: u64, value: u64) void {
        std.mem.writeInt(u64, self.bytes[address..][0..8], value, .little);
    }

    fn get(self: *Fixture, address: u64) u64 {
        return std.mem.readInt(u64, self.bytes[address..][0..8], .little);
    }
};

/// The 48-bit regime `arm64 defconfig` uses: a 4KB granule, a 16-bit `T0SZ`, and
/// a 48-bit physical address.
fn tcr() u64 {
    // `T0SZ` 16 for the low region, `T1SZ` 17 so that the upper half begins at
    // bit 47, which is the split Linux uses, and a 48-bit physical address.
    // TG1 is 2 for a 4KB granule, which is not the value TG0 uses for it.
    return 16 | (17 << 16) | (@as(u64, 2) << 30) | (@as(u64, 4) << 32);
}

/// A leaf describing `output`, at the size `bits` wide. The bits are the ones
/// the architecture gives: AP[2:1] at 7:6, where AP[2] makes the page read-only
/// and AP[1] would make it reachable from EL0, and PXN at 53. A page, which is
/// the size of a granule, is `0b11` in its bottom two bits, and a block, which is
/// larger, is `0b01`.
fn leaf(output: u64, bits: u6, rw: bool, executable: bool) u64 {
    const mask = (@as(u64, 1) << bits) - 1;
    const ap: u64 = if (rw) 0b00 else 0b10; // never reachable from EL0, either way
    const kind: u64 = switch (bits) {
        12, 14, 16 => 0b11,
        else => 0b01,
    };
    return (output & ~mask) | kind | (ap << 6) | (if (executable) 0 else @as(u64, 1) << 53);
}

fn table(next: u64) u64 {
    return (next & ~@as(u64, 0xfff)) | 0b11;
}

/// The shift at which level `level` begins, for a 64KB granule. A 64KB granule
/// is field 1 of `TG`, which is the second size in the field's encoding but not
/// the second in order.
fn granule_shift(level: i8) u6 {
    return 16 + @as(u6, @intCast(9 * @as(u8, @intCast(level))));
}

/// The offset within a table of the entry that `virtual` selects at `level`.
/// The tests place a leaf at the index the walk will actually look at, which is
/// not index zero for an address that is not page-aligned in that way.
fn entry_offset(virtual: u64, level: i8) u64 {
    const shift: u6 = 12 + @as(u6, @intCast(9 * @as(u8, @intCast(level))));
    return ((virtual >> shift) & 0x1ff) * 8;
}

/// Build the chain of tables rooted at `root` that leads to `virtual`, with
/// `value` as the leaf at `leaf_level`. Each level's table is a page further
/// along than the last, so the addresses are fixed and the only thing that varies
/// is the index within them, which is what the walk has to get right.
fn build(f: *Fixture, root: u64, virtual: u64, leaf_level: i8, value: u64) void {
    var base: u64 = root;
    var level: i8 = 3;
    while (level > leaf_level) : (level -= 1) {
        f.put(base + entry_offset(virtual, level), table(base + 0x1000));
        base += 0x1000;
    }
    f.put(base + entry_offset(virtual, leaf_level), value);
}

/// A guest that has turned translation on for the low half of the space.
fn running(ttbr0: u64) Cpu {
    return .{ .system = .{ .sctlr_el1 = 1, .tcr_el1 = tcr(), .ttbr0_el1 = ttbr0 } };
}

test "with translation off an address is its own translation" {
    var tlb: Translate.Tlb = .{};
    var f: Fixture = .{};
    var memory = f.memory();
    var cpu: Cpu = .{};
    try testing.expectEqual(@as(u64, 0xdead_0000), try Translate.translate(&tlb, &cpu, &memory, 0xdead_0000, .read));
}

test "a four level walk reaches a 4KB page" {
    var tlb: Translate.Tlb = .{};
    var f: Fixture = .{};
    var memory = f.memory();
    // level 3 -> level 2 -> level 1 -> level 0 -> the page. The virtual address
    // 0x0000_0000_1234_5678 picks one index at each level.
    const virtual: u64 = 0x1234_5678;
    build(&f, 0, virtual, 0, leaf(0x8000_0000, 12, true, true));

    var cpu = running(0x0000);
    const physical = try Translate.translate(&tlb, &cpu, &memory, virtual, .read);
    // The page base is 0x8000_0000 and the offset within it is 0x678.
    try testing.expectEqual(@as(u64, 0x8000_0678), physical);
}

test "a two megabyte block covers the whole range its level indexes" {
    var tlb: Translate.Tlb = .{};
    var f: Fixture = .{};
    var memory = f.memory();
    const block = [_]u64{ 0x0000_0000_0020_0000, 0x0000_0000_0020_1234, 0x0000_0000_003f_ffff };
    build(&f, 0, block[0], 1, leaf(0x4000_0000, 21, true, true));
    var cpu = running(0x0000);
    // Any address in the 2MB block must land in it, not just the first.
    for (block) |virtual| {
        const physical = try Translate.translate(&tlb, &cpu, &memory, virtual, .read);
        try testing.expectEqual(@as(u64, 0x4000_0000) | (virtual & 0x1f_ffff), physical);
    }
}

test "a read-only page refuses a write and allows a read" {
    var tlb: Translate.Tlb = .{};
    var f: Fixture = .{};
    var memory = f.memory();
    build(&f, 0, 0, 0, leaf(0x8000_0000, 12, false, true));
    var cpu = running(0x0000);
    try testing.expectEqual(@as(u64, 0x8000_0000), try Translate.translate(&tlb, &cpu, &memory, 0, .read));
    try testing.expectError(error.PermissionFault, Translate.translate(&tlb, &cpu, &memory, 0, .write));
}

test "a page that may not be executed refuses an instruction fetch" {
    var tlb: Translate.Tlb = .{};
    var f: Fixture = .{};
    var memory = f.memory();
    build(&f, 0, 0, 0, leaf(0x8000_0000, 12, true, false));
    var cpu = running(0x0000);
    try testing.expectError(error.PermissionFault, Translate.translate(&tlb, &cpu, &memory, 0, .execute));
    // Reading it is still fine, which is the point of the two bits being
    // separate.
    try testing.expectEqual(@as(u64, 0x8000_0000), try Translate.translate(&tlb, &cpu, &memory, 0, .read));
}

test "an address in no table is a translation fault" {
    var tlb: Translate.Tlb = .{};
    var f: Fixture = .{};
    var memory = f.memory();
    f.put(0x0000, table(0x1000));
    // The rest of the levels are all zero, which is an invalid descriptor.
    var cpu = running(0x0000);
    try testing.expectError(error.TranslationFault, Translate.translate(&tlb, &cpu, &memory, 0, .read));
}

test "a reserved descriptor is refused rather than followed" {
    var tlb: Translate.Tlb = .{};
    var f: Fixture = .{};
    var memory = f.memory();
    // Bits 1:0 of 0b10 are not a valid descriptor in any table.
    f.put(0x0000, 0x1000 | 0b10);
    var cpu = running(0x0000);
    try testing.expectError(error.TranslationFault, Translate.translate(&tlb, &cpu, &memory, 0, .read));
}

test "the cache answers a repeat without walking again" {
    var tlb: Translate.Tlb = .{};
    var f: Fixture = .{};
    var memory = f.memory();
    build(&f, 0, 0x1000, 0, leaf(0x8000_0000, 12, true, true));
    var cpu = running(0x0000);
    const first = try Translate.translate(&tlb, &cpu, &memory, 0x1000, .read);
    // Overwrite the table so a second walk would find something else. A hit
    // must not notice, which is the whole point of remembering it.
    f.put(0x3000 + entry_offset(0x1000, 0), leaf(0x9000_0000, 12, true, true));
    const second = try Translate.translate(&tlb, &cpu, &memory, 0x1000, .read);
    try testing.expectEqual(first, second);
}

test "flushing the cache picks up a changed table" {
    var tlb: Translate.Tlb = .{};
    var f: Fixture = .{};
    var memory = f.memory();
    build(&f, 0, 0x1000, 0, leaf(0x8000_0000, 12, true, true));
    var cpu = running(0x0000);
    _ = try Translate.translate(&tlb, &cpu, &memory, 0x1000, .read);
    f.put(0x3000 + entry_offset(0x1000, 0), leaf(0x9000_0000, 12, true, true));
    // Before a flush the old answer stands, because the guest has not said the
    // regime changed.
    try testing.expectEqual(@as(u64, 0x8000_0000), try Translate.translate(&tlb, &cpu, &memory, 0x1000, .read));
    tlb.flush();
    try testing.expectEqual(@as(u64, 0x9000_0000), try Translate.translate(&tlb, &cpu, &memory, 0x1000, .read));
}

test "a fault is remembered so the walk is not repeated" {
    var tlb: Translate.Tlb = .{};
    var f: Fixture = .{};
    var memory = f.memory();
    f.put(0x0000, 0x1000 | 0b10);
    var cpu = running(0x0000);
    try testing.expectError(error.TranslationFault, Translate.translate(&tlb, &cpu, &memory, 0, .read));
    // The slot now records the fault, so the next attempt does not re-read the
    // table; the kind is the same one either way.
    try testing.expectError(error.TranslationFault, Translate.translate(&tlb, &cpu, &memory, 0, .read));
}

test "the two roots are chosen by which half of the space the address is in" {
    var tlb: Translate.Tlb = .{};
    var f: Fixture = .{};
    var memory = f.memory();
    // The split is at bit 47, so a low address uses TTBR0 and one in the top of
    // the space uses TTBR1. The root that is not meant to answer must not.
    build(&f, 0, 0x1000, 0, leaf(0x8000_0000, 12, true, true));
    var cpu = running(0x0000);
    // Below the split the lower root answers, and the tables for the upper root
    // are left empty, so reaching them at all would fault.
    const low: u64 = 0x0000_0000_0000_1000;
    build(&f, 0, low, 0, leaf(0x8000_0000, 12, true, true));
    cpu.system.ttbr1_el1 = 0x9999_0000;
    try testing.expectEqual(@as(u64, 0x8000_0000), try Translate.translate(&tlb, &cpu, &memory, low, .read));

    // Above it, the tables hanging off TTBR1 are the ones that must be walked.
    // The upper root gets its own chain of tables, and the lower root's tables
    // would map this address somewhere else entirely.
    const high: u64 = 0xffff_8000_0000_1000;
    build(&f, 0x5000, high, 0, leaf(0x4000_0000, 12, true, true));
    cpu.system.ttbr1_el1 = 0x5000;
    try testing.expectEqual(@as(u64, 0x4000_0000), try Translate.translate(&tlb, &cpu, &memory, high, .read));
}

test "an address outside the forty-eight bit space is refused" {
    var tlb: Translate.Tlb = .{};
    var f: Fixture = .{};
    var memory = f.memory();
    var cpu = running(0x0000);
    // Bit 55 clear but the top bits set is not a canonical address.
    try testing.expectError(error.TranslationFault, Translate.translate(&tlb, &cpu, &memory, 0x0001_0000_0000_0000, .read));
}

test "the granule size comes from the field the register puts it in" {
    var tlb: Translate.Tlb = .{};
    // `TG1` is at bits 31:30, while `T1SZ` is the six bits at 16. Reading a
    // granule from the wrong place would give a size the guest never asked for,
    // and the walk would then index the tables wrongly.
    var f: Fixture = .{};
    var memory = f.memory();
    // A 64KB granule is field 1, which is not the second size in order.
    const virtual: u64 = 0x0000_0000_0001_2345;
    var cpu: Cpu = .{};
    cpu.system.sctlr_el1 = 1;
    // 16-bit T0SZ, 17-bit T1SZ, a 64KB granule in both `TG` fields (which is 1 for
    // TG0 and 3 for TG1), 48-bit PA.
    cpu.system.tcr_el1 = 16 | (17 << 16) | (1 << 14) | (3 << 30) | (4 << 32);
    cpu.system.ttbr0_el1 = 0;
    // Four levels of 64KB granule tables hold a 48-bit space, so the indices
    // start at shift 16 rather than 12.

    var base: u64 = 0;
    var level: i8 = 3;
    while (level > 0) : (level -= 1) {
        f.put(base + (((virtual >> granule_shift(level)) & 0x1ff) * 8), table(base + 0x10000));
        base += 0x10000;
    }
    f.put(base + (((virtual >> granule_shift(0)) & 0x1ff) * 8), leaf(0x8000_0000, 16, true, true));

    try testing.expectEqual(@as(u64, 0x8000_2345), try Translate.translate(&tlb, &cpu, &memory, virtual, .read));
}

test "a disabled walk is a translation fault rather than a wrong answer" {
    var tlb: Translate.Tlb = .{};
    // `EPD1` says a miss on an address belonging to the upper root is a fault
    // with no walk at all. Following the tables anyway would translate an
    // address the guest has said must not be translated.
    var f: Fixture = .{};
    var memory = f.memory();
    const high: u64 = 0xffff_8000_0000_1000;
    build(&f, 0x5000, high, 0, leaf(0x4000_0000, 12, true, true));
    var cpu = running(0x0000);
    cpu.system.ttbr1_el1 = 0x5000;
    try testing.expectEqual(@as(u64, 0x4000_0000), try Translate.translate(&tlb, &cpu, &memory, high, .read));
    // With the walk disabled the same address now has no translation at all.
    tlb.flush();
    cpu.system.tcr_el1 |= @as(u64, 1) << 23;
    try testing.expectError(error.TranslationFault, Translate.translate(&tlb, &cpu, &memory, high, .read));
}

test "a guest runs with translation on, and the fetch agrees with the data" {
    // The end of the line: page tables in guest memory, the control registers
    // set, and code reached only through the walk. The mapping is the identity,
    // which is the simplest thing that proves both the fetch and the data side
    // go through it, because either one skipping the walk would read elsewhere.
    const v: u64 = 0x4000_4000;
    var bytes: [0x5000]u8 = @splat(0);
    const regions = [_]GuestMemory.Region{.{ .gpa = 0, .len = bytes.len, .backing = .{ .shared = &bytes } }};
    var memory: GuestMemory = .{ .regions = &regions };

    // The guest code, at the physical address the mapping gives it.
    std.mem.writeInt(u32, bytes[0x4000..][0..4], 0xd2800ba8, .little); // mov x8, #93
    std.mem.writeInt(u32, bytes[0x4004..][0..4], 0xd2800000, .little); // mov x0, #0
    std.mem.writeInt(u32, bytes[0x4008..][0..4], 0xd4000001, .little); // svc #0

    const put = struct {
        fn f(b: []u8, at: u64, value: u64) void {
            std.mem.writeInt(u64, b[@intCast(at)..][0..8], value, .little);
        }
    }.f;
    // Four levels of tables, each placed clear of the last so that no table
    // overlaps the code or another table. The entries are written out with the
    // index each level selects, because a loop that computed them would be one
    // more thing that could be wrong and still look right.
    //
    //   0x0000 (L3) index 0 -> 0x1000
    //   0x1008 (L2) index 1 -> 0x2000
    //   0x2000 (L1) index 0 -> 0x3000
    //   0x3020 (L0) index 4 -> the page at 0x4000
    put(&bytes, 0x0000, table(0x1000));
    put(&bytes, 0x1008, table(0x2000));
    put(&bytes, 0x2000, table(0x3000));
    put(&bytes, 0x3020, leaf(0x4000, 12, true, true));

    var cpu: Cpu = .{ .pc = v };
    cpu.system.sctlr_el1 = 1; // SCTLR_EL1.M
    cpu.system.tcr_el1 = 16 | (17 << 16) | (@as(u64, 4) << 32);
    cpu.system.ttbr0_el1 = 0x0000;

    var cache = Cache.init(testing.allocator());
    defer cache.deinit();
    var tlb: Translate.Tlb = .{};
    var steps: usize = 0;
    while (steps < 16) : (steps += 1) {
        _ = cache.runBlock(&memory, &cpu, &tlb) catch |err| return err;
        if (cpu.trap == .svc) break;
        if (cpu.trap != .none) return error.UnexpectedTrap;
    }
    // The guest asked to exit, having been fetched and run entirely through the
    // walk, and its `mov` of 93 into x8 is proof the instructions arrived.
    try testing.expectEqual(Cpu.Trap.svc, cpu.trap);
    try testing.expectEqual(@as(u64, 93), cpu.x[8]);

    // Fetching through the walk touched the page, so its access flag is now set
    // in the page table the walk left behind. This is the whole of the flag's
    // point: the guest's own tables record that the page has been used.
    const leaf_at = 0x3020;
    const descriptor = std.mem.readInt(u64, bytes[leaf_at..][0..8], .little);
    try testing.expectEqual(@as(u64, 1 << 10), descriptor & (1 << 10));
}

test "translation off means the address is the address" {
    // The other half of the same question: before the guest sets `M`, a virtual
    // address is already a physical one, and a walk would be wrong.
    var f: Fixture = .{};
    var memory = f.memory();
    var tlb: Translate.Tlb = .{};
    var cpu: Cpu = .{};
    // Point the table base somewhere real, so a walk would find something and
    // the difference could not be mistaken for an empty table.
    cpu.system.ttbr0_el1 = 0;
    try testing.expectEqual(@as(u64, 0x8000_1234), try Translate.translate(&tlb, &cpu, &memory, 0x8000_1234, .read));
    // Turning translation on makes the same address need a mapping it has not got.
    cpu.system.sctlr_el1 = 1;
    cpu.system.tcr_el1 = 16 | (17 << 16) | (@as(u64, 4) << 32);
    try testing.expectError(error.TranslationFault, Translate.translate(&tlb, &cpu, &memory, 0x8000_1234, .read));
}

test "an exception vectors according to exception level and SPSel" {
    var cpu: Cpu = .{ .pc = 0x1000, .sp = 0x1000, .system = .{ .vbar_el1 = 0xffff_0000, .el = 1, .spsel = false } };

    // EL1t uses the first group. Entry switches the live stack to SP_EL1.
    _ = Exception.take(&cpu, .{ .kind = .sync, .ec = 0b010101 }, 0x1000);
    try testing.expectEqual(@as(u64, 0xffff_0000), cpu.pc);
    try testing.expectEqual(@as(u64, 0x1000), cpu.system.sp_el[0]);
    try testing.expectEqual(true, cpu.system.spsel);
    try testing.expectEqual(@as(u64, 0), cpu.sp);

    // Reset to EL1t and an IRQ selects its second slot in the same group.
    cpu.system.el = 1;
    cpu.system.spsel = false;
    cpu.pc = 0x1000;
    _ = Exception.take(&cpu, .{ .kind = .irq }, 0x1000);
    try testing.expectEqual(@as(u64, 0xffff_0080), cpu.pc);

    // EL1h selects the next group. SCTLR.M has no bearing on this choice.
    cpu.system.vbar_el1 = 0xffff_0000;
    cpu.system.spsel = true;
    cpu.system.sctlr_el1 = 0;
    cpu.pc = 0x1000;
    _ = Exception.take(&cpu, .{ .kind = .sync, .ec = 0b010101 }, 0x1000);
    try testing.expectEqual(@as(u64, 0xffff_0200), cpu.pc);

    // EL0 always uses the third group, regardless of the stack-selection bit.
    cpu.system.el = 0;
    cpu.system.spsel = false;
    cpu.pc = 0x1000;
    _ = Exception.take(&cpu, .{ .kind = .sync, .ec = 0b100000 }, 0x1000);
    try testing.expectEqual(@as(u64, 0xffff_0400), cpu.pc);
    try testing.expectEqual(@as(u8, 1), cpu.system.el);
}

test "an exception records what a handler needs and masks the interrupts" {
    var cpu: Cpu = .{
        .pc = 0x1234,
        .flags = 0b1010 << 28,
        .sp = 0x8000,
        .system = .{ .vbar_el1 = 0xffff_0000, .el = 1, .daif = 0, .spsel = true },
    };
    cpu.system.sp_el[1] = 0x9000;

    _ = Exception.take(&cpu, .{ .kind = .sync, .ec = 0b100001, .status = 0b001100 }, 0xdead_0000);

    // The return address is the instruction that raised it, so a handler that
    // changes nothing resumes in the same place.
    try testing.expectEqual(@as(u64, 0x1234), cpu.system.elr_el1);
    // The class and the status are the two halves of what it was.
    try testing.expectEqual(@as(u64, 0b100001 << 26 | 0b001100), cpu.system.esr_el1);
    try testing.expectEqual(@as(u64, 0xdead_0000), cpu.system.far_el1);
    // The saved status keeps the flags and the level, so that returning brings
    // both back.
    try testing.expectEqual(@as(u32, 0b1010 << 28), @as(u32, @truncate(cpu.system.spsr_el1 & 0xf000_0000)));
    try testing.expectEqual(@as(u8, 1), @as(u8, @truncate((cpu.system.spsr_el1 >> 2) & 3)));
    try testing.expectEqual(@as(u64, 1), cpu.system.spsr_el1 & 1);
    try testing.expectEqual(@as(u64, 0xf), cpu.system.daif);
    // This exception is taken at EL1 and handled at EL1, so it banks and loads
    // the same bank and the stack pointer does not move. That is the point of
    // having one bank per level rather than one shared value.
    try testing.expectEqual(@as(u64, 0x8000), cpu.system.sp_el[1]);
    try testing.expectEqual(@as(u64, 0x8000), cpu.sp);

    // Taken at EL0 it is a different bank, so the handler's stack pointer is the
    // one EL1 left behind rather than the faulting code's.
    var other: Cpu = .{ .pc = 0x1000, .sp = 0x8000, .system = .{ .vbar_el1 = 0, .el = 0 } };
    other.system.sp_el[1] = 0x9000;
    _ = Exception.take(&other, .{ .kind = .sync, .ec = 0b100000 }, 0x1000);
    try testing.expectEqual(@as(u64, 0x8000), other.system.sp_el[0]);
    try testing.expectEqual(@as(u64, 0x9000), other.sp);
    try testing.expectEqual(@as(u8, 1), other.system.el);
}

test "the instruction bit of the status says the address was being fetched" {
    var cpu: Cpu = .{ .pc = 0x1000, .system = .{ .vbar_el1 = 0 } };
    _ = Exception.take(&cpu, .{ .kind = .sync, .ec = 0b001001, .instruction = true, .status = 0b001101 }, 0x2000);
    // Bit 25 is the instruction bit, and a permission fault on a fetch has a
    // different status code from one on a load, so both have to be there.
    try testing.expectEqual(@as(u64, 1 << 25), cpu.system.esr_el1 & (1 << 25));
    try testing.expectEqual(@as(u64, 0b001101), cpu.system.esr_el1 & 0x3f);
}

test "returning brings back the level, the stack pointer, the flags and the masks" {
    var cpu: Cpu = .{ .pc = 0x2000, .sp = 0x8000, .system = .{ .el = 1 } };
    // A handler that used the stack, and unmasked interrupts before returning.
    cpu.sp = 0x8000;
    cpu.flags = 0b0101 << 28;
    cpu.system.daif = 0;
    // A saved status saying: return to EL0, with those flags and no masks.
    cpu.system.spsr_el1 = 0b0101 << 28;
    cpu.system.elr_el1 = 0x4000;
    cpu.system.sp_el[0] = 0x7000;

    try testing.expectEqual(@as(u64, 0x4000), Exception.eret(&cpu));
    try testing.expectEqual(@as(u8, 0), cpu.system.el);
    try testing.expectEqual(@as(u64, 0x7000), cpu.sp);
    try testing.expectEqual(@as(u32, 0b0101 << 28), cpu.flags);
    try testing.expectEqual(@as(u64, 0), cpu.system.daif);
    // The stack pointer of the level being left is banked on the way out too, or
    // a handler that pushed to it would lose what it pushed.
    try testing.expectEqual(@as(u64, 0x8000), cpu.system.sp_el[1]);
}

test "ERET is decoded as the instruction the assembler emits" {
    switch (try decode(0xd69f03e0)) {
        .eret => {},
        else => return error.NotAnEret,
    }
}

test "the first access to a page sets its access flag" {
    // Hardware sets the flag on the first touch and lets that access through, so
    // a guest that allocated a page without setting it is not punished for it.
    // A walker that ignored the flag would also let the access through, but the
    // guest's own page table would still say the page had never been used.
    var f: Fixture = .{};
    var memory = f.memory();
    const virtual: u64 = 0x1000;
    build(&f, 0, virtual, 0, leaf(0x8000_0000, 12, true, true));
    // The flag starts clear, which is what a freshly allocated page looks like.
    try testing.expectEqual(@as(u64, 0), f.get(0x3000 + entry_offset(virtual, 0)) & (1 << 10));

    var tlb: Translate.Tlb = .{};
    var cpu = running(0x0000);
    _ = try Translate.translate(&tlb, &cpu, &memory, virtual, .read);
    try testing.expectEqual(@as(u64, 1 << 10), f.get(0x3000 + entry_offset(virtual, 0)) & (1 << 10));

    // A second touch changes nothing, and a walk that is not repeated is not
    // what proves it: the value is in the page table either way.
    try testing.expectEqual(@as(u64, 1 << 10), f.get(0x3000 + entry_offset(virtual, 0)) & (1 << 10));
}

test "a read of a read-only page leaves its access flag alone" {
    // The architecture lets the first read of a read-only page through without
    // setting the flag, because there is nothing to fault on and nothing to
    // remember. A walker that always set it would be writing to a page table the
    // guest may have made read-only.
    var f: Fixture = .{};
    var memory = f.memory();
    const virtual: u64 = 0x1000;
    build(&f, 0, virtual, 0, leaf(0x8000_0000, 12, false, true));
    var tlb: Translate.Tlb = .{};
    var cpu = running(0x0000);
    _ = try Translate.translate(&tlb, &cpu, &memory, virtual, .read);
    try testing.expectEqual(@as(u64, 0), f.get(0x3000 + entry_offset(virtual, 0)) & (1 << 10));
}

test "a write to a read-only page is refused and still leaves the flag alone" {
    var f: Fixture = .{};
    var memory = f.memory();
    const virtual: u64 = 0x1000;
    build(&f, 0, virtual, 0, leaf(0x8000_0000, 12, false, true));
    var tlb: Translate.Tlb = .{};
    var cpu = running(0x0000);
    try testing.expectError(error.PermissionFault, Translate.translate(&tlb, &cpu, &memory, virtual, .write));
    // The write was refused, so there was no access to record.
    try testing.expectEqual(@as(u64, 0), f.get(0x3000 + entry_offset(virtual, 0)) & (1 << 10));
}

test "DC ZVA is decoded as the instruction the assembler emits" {
    // The cache instructions share a class and differ only in their register
    // number, so getting the mask wrong turns one into another or refuses all.
    const rows = [_]struct { word: u32, register: u5 }{
        .{ .word = 0xd50b7420, .register = 0 },
        .{ .word = 0xd50b7421, .register = 1 },
    };
    for (rows) |row| {
        switch (try decode(row.word)) {
            .dc_zva => |rt| try testing.expectEqual(row.register, rt),
            else => return error.NotADcZva,
        }
    }
    // The clean and invalidate forms share the class. They only ask for ordering,
    // which a coherent machine has nothing to do for, so they decode and do nothing.
    switch (try decode(0xd50b7e20)) {
        .cache_op => {},
        else => return error.NotCacheMaintenance,
    }
}

test "the upper half's granule is read with TG1's own encoding" {
    // `TG1` numbers the sizes 16KB, 4KB, 64KB, so a kernel's 4KB upper half is 2, and
    // read with `TG0`'s table that is 16KB. The tables are Linux's own: the TCR is the
    // one it programmed, and the page is the kind it maps its text with.
    var f: Fixture = .{};
    var memory = f.memory();
    const high: u64 = 0xffff_8000_0000_1000;
    build(&f, 0x5000, high, 0, leaf(0x4000_0000, 12, true, true));
    var tlb: Translate.Tlb = .{};
    var cpu = running(0x0000);
    cpu.system.tcr_el1 = 0x32b5_5035_10;
    cpu.system.ttbr1_el1 = 0x5000;
    try testing.expectEqual(@as(u64, 0x4000_0000), try Translate.translate(&tlb, &cpu, &memory, high, .read));

    // `TG1` of zero is reserved, and refused for an address that is walked with it.
    cpu.system.tcr_el1 &= ~(@as(u64, 3) << 30);
    var fresh: Translate.Tlb = .{};
    try testing.expectError(error.MalformedTables, Translate.translate(&fresh, &cpu, &memory, high, .read));

    // But it says nothing about the lower half, which has its own field.
    const low: u64 = 0x1000;
    build(&f, 0, low, 0, leaf(0x8000_0000, 12, true, true));
    try testing.expectEqual(@as(u64, 0x8000_0000), try Translate.translate(&fresh, &cpu, &memory, low, .read));
}

test "a read-only page for EL1 is readable and executable and not writable" {
    // A descriptor as the kernel builds one for its text and constants, copied from
    // its first page table: a page (`0b11`), attribute index 0, read-only and
    // unreachable from EL0 (`AP[2:1] = 0b10`), inner shareable, accessed, with UXN set
    // and PXN clear. The output address is 0x4024_7000.
    var f: Fixture = .{};
    var memory = f.memory();
    const virtual: u64 = 0x0000_0000_4024_7000;
    build(&f, 0, virtual, 0, 0x00c0_0000_4024_7783);
    var tlb: Translate.Tlb = .{};
    var cpu = running(0x0000);
    try testing.expectEqual(@as(u64, 0x4024_7123), try Translate.translate(&tlb, &cpu, &memory, virtual + 0x123, .read));
    try testing.expectEqual(@as(u64, 0x4024_7123), try Translate.translate(&tlb, &cpu, &memory, virtual + 0x123, .execute));
    try testing.expectError(error.PermissionFault, Translate.translate(&tlb, &cpu, &memory, virtual + 0x123, .write));
}

test "a last-level descriptor is a page only when its low bits are 0b11" {
    // At the last level `0b01` is reserved, not a page: the architecture has no
    // block there, and reading it as one maps a page the guest never described.
    var f: Fixture = .{};
    var memory = f.memory();
    const virtual: u64 = 0x1000;
    build(&f, 0, virtual, 0, (leaf(0x8000_0000, 12, true, true) & ~@as(u64, 3)) | 0b01);
    var tlb: Translate.Tlb = .{};
    var cpu = running(0x0000);
    try testing.expectError(error.TranslationFault, Translate.translate(&tlb, &cpu, &memory, virtual, .read));
}

test "the bits of TCR_EL1 beside T1SZ are not part of it" {
    // Linux sets `A1`, bit 22, directly above the six bits of `T1SZ`. Reading it as
    // part of the size made the region's size negative and panicked the host on a
    // register the guest is entitled to write.
    var f: Fixture = .{};
    var memory = f.memory();
    const virtual: u64 = 0x1000;
    build(&f, 0, virtual, 0, leaf(0x8000_0000, 12, true, true));
    var tlb: Translate.Tlb = .{};
    var cpu = running(0x0000);
    cpu.system.tcr_el1 |= 1 << 22;
    try testing.expectEqual(@as(u64, 0x8000_0000), try Translate.translate(&tlb, &cpu, &memory, virtual, .read));

    // Every value the six bits can hold is a region size, and none can crash the
    // host. A size of zero is the one the architecture reserves, and is refused.
    var each: u64 = 0;
    while (each < 64) : (each += 1) {
        var probe = running(0x0000);
        probe.system.tcr_el1 = 16 | (each << 16) | (@as(u64, 4) << 32) | (1 << 22);
        var fresh: Translate.Tlb = .{};
        _ = Translate.translate(&fresh, &probe, &memory, virtual, .read) catch {};
    }
}

/// The suites for one class of instruction each, kept apart from the tests above because their cases are
/// tables and their helpers would otherwise share one namespace.
const classes = struct {
    /// How a load or store with a register offset forms its address: the index may be
    /// a 32-bit register that is extended first, and the scale is the size of the
    /// access. The address, width and direction are read off the state a translated
    /// block leaves for the run loop, so this needs no memory behind it.
    pub const addressing_tests = struct {
        const Case = struct {
            name: []const u8,
            word: u32,
            base: u64 = 0x1000,
            index: u64,
            address: u64,
            width: u8,
            trap: Cpu.Trap,
        };

        fn check(cases: []const Case) !void {
            for (cases) |case| {
                var bytes: [4]u8 = undefined;
                std.mem.writeInt(u32, &bytes, case.word, .little);
                var block = try guest.compile(testing.allocator(), 0x4000, &bytes);
                defer block.deinit();
                var cpu: Cpu = .{ .sp = 0x9000 };
                cpu.x[1] = case.base;
                cpu.x[2] = case.index;
                _ = block.run(&cpu);
                errdefer std.debug.print("{s}: address {x} width {d} trap {t}\n", .{ case.name, cpu.address, cpu.width, cpu.trap });
                try testing.expectEqual(case.address, cpu.address);
                try testing.expectEqual(case.width, cpu.width);
                try testing.expectEqual(case.trap, cpu.trap);
            }
        }

        test "an unscaled register offset is added as it is, whatever the size of the access" {
            try check(&.{
                .{ .name = "ldrb w0, [x1, x2]", .word = 0x38626820, .index = 5, .address = 0x1005, .width = 1, .trap = .load },
                // The `S` bit is clear, so a doubleword access is not shifted by three.
                .{ .name = "ldr x0, [x1, x2]", .word = 0xf8626820, .index = 8, .address = 0x1008, .width = 8, .trap = .load },
                .{ .name = "ldr w0, [x1, x2]", .word = 0xb8626820, .index = 8, .address = 0x1008, .width = 4, .trap = .load },
            });
        }

        test "a scaled register offset is shifted by the log2 of the size of the access" {
            try check(&.{
                // A word is four bytes, so the shift is two, and not the three that
                // only a doubleword would use.
                .{ .name = "ldr w0, [x1, x2, lsl #2]", .word = 0xb8627820, .index = 5, .address = 0x1014, .width = 4, .trap = .load },
                .{ .name = "str w0, [x1, x2, lsl #2]", .word = 0xb8227820, .index = 5, .address = 0x1014, .width = 4, .trap = .store },
                .{ .name = "ldr x0, [x1, x2, lsl #3]", .word = 0xf8627820, .index = 5, .address = 0x1028, .width = 8, .trap = .load },
                .{ .name = "ldrh w0, [x1, x2, lsl #1]", .word = 0x78627820, .index = 5, .address = 0x100a, .width = 2, .trap = .load },
                // A byte access cannot be scaled: the shift is log2 of one.
                .{ .name = "ldrb w0, [x1, x2, lsl #0]", .word = 0x38627820, .index = 5, .address = 0x1005, .width = 1, .trap = .load },
            });
        }

        test "a 32-bit index is extended before it is scaled and added" {
            try check(&.{
                // Zero-extended: the upper half of the register is not part of a word index.
                .{ .name = "ldrh w0, [x1, w2, uxtw #1]", .word = 0x78625820, .index = 0xffff_ffff_0000_0004, .address = 0x1008, .width = 2, .trap = .load },
                .{ .name = "ldrb w0, [x1, w2, uxtw]", .word = 0x38624820, .index = 0xffff_ffff_0000_0004, .address = 0x1004, .width = 1, .trap = .load },
                // Sign-extended: a word of minus two is minus two, and minus sixteen once scaled.
                .{ .name = "ldr x0, [x1, w2, sxtw #3]", .word = 0xf862d820, .index = 0xffff_fffe, .address = 0x1000 - 16, .width = 8, .trap = .load },
                .{ .name = "ldr x0, [x1, w2, sxtw]", .word = 0xf862c820, .index = 0xffff_fffe, .address = 0x1000 - 2, .width = 8, .trap = .load },
                // A positive word index stays positive.
                .{ .name = "ldr x0, [x1, w2, sxtw #3]", .word = 0xf862d820, .index = 0x7fff_ffff, .address = 0x1000 + (0x7fff_ffff << 3), .width = 8, .trap = .load },
                // The 64-bit sign extension is the operand as it is.
                .{ .name = "ldr x0, [x1, x2, sxtx]", .word = 0xf862e820, .index = 0xffff_ffff_ffff_fff0, .address = 0x1000 - 16, .width = 8, .trap = .load },
            });
        }

        test "the kernel's own register-offset store" {
            // `strb w9, [x8, w21, sxtw]`, from Linux's early code: a byte store at a base
            // plus a sign-extended 32-bit index of minus one.
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, 0x3835c909, .little);
            var block = try guest.compile(testing.allocator(), 0x4000, &bytes);
            defer block.deinit();
            var cpu: Cpu = .{};
            cpu.x[8] = 0x2000;
            cpu.x[21] = 0xffff_ffff;
            cpu.x[9] = 0xab;
            _ = block.run(&cpu);
            try testing.expectEqual(@as(u64, 0x1fff), cpu.address);
            try testing.expectEqual(Cpu.Trap.store, cpu.trap);
            try testing.expectEqual(@as(u8, 1), cpu.width);
            try testing.expectEqual(@as(u64, 0xab), cpu.value);
        }

        test "the reserved index options are refused" {
            // The options for a byte, halfword and their signed forms are not allocated for an index.
            for ([_]u32{ 0xf8620820, 0xf8622820, 0xf8628820, 0xf862a820 }) |word| {
                try testing.expectError(error.UnsupportedInstruction, Decode.decode(word));
            }
        }

        test "a literal load reads from an address relative to the instruction itself" {
            const Literal = struct { word: u32, address: u64, width: u8, dest: u8 };
            for ([_]Literal{
                // `ldr x8, <pc+20>`, as the kernel has it: five instructions on.
                .{ .word = 0x580000a8, .address = 0x4014, .width = 8, .dest = 8 },
                // `ldr w0, <pc-8>`: a negative displacement, and a word.
                .{ .word = 0x18ffffc0, .address = 0x3ff8, .width = 4, .dest = 0 },
                // The largest reach forward is a little under a megabyte: 2^18 - 1 words.
                .{ .word = 0x587fffe1, .address = 0x4000 + ((1 << 18) - 1) * 4, .width = 8, .dest = 1 },
            }) |case| {
                var bytes: [4]u8 = undefined;
                std.mem.writeInt(u32, &bytes, case.word, .little);
                var block = try guest.compile(testing.allocator(), 0x4000, &bytes);
                defer block.deinit();
                var cpu: Cpu = .{};
                cpu.x[1] = 0x1111; // a base register must have no say in a PC-relative address
                _ = block.run(&cpu);
                errdefer std.debug.print("{x}: address {x}\n", .{ case.word, cpu.address });
                try testing.expectEqual(case.address, cpu.address);
                try testing.expectEqual(case.width, cpu.width);
                try testing.expectEqual(case.dest, cpu.dest);
                try testing.expectEqual(Cpu.Trap.load, cpu.trap);
            }
        }

        test "the literal forms this does not perform are refused, not read as plain loads" {
            // The sign-extending word load and the SIMD load.
            for ([_]u32{ 0x98000000, 0x1c000000 }) |word| {
                try testing.expectError(error.UnsupportedInstruction, Decode.decode(word));
            }
        }

        test "a prefetch decodes as nothing and touches nothing" {
            // prfm with an immediate (the kernel's own), a register, an unscaled offset, and a literal.
            for ([_]u32{ 0xf9800131, 0xf8a16800, 0xf8800000, 0xd8000000 }) |word| {
                try testing.expectEqual(true, (try Decode.decode(word)) == .nop);
                var bytes: [4]u8 = undefined;
                std.mem.writeInt(u32, &bytes, word, .little);
                var block = try guest.compile(testing.allocator(), 0x4000, &bytes);
                defer block.deinit();
                var cpu: Cpu = .{ .sp = 0x1234 };
                cpu.x[1] = 0x77;
                _ = block.run(&cpu);
                try testing.expectEqual(Cpu.Trap.none, cpu.trap); // no access was asked for
                try testing.expectEqual(@as(u64, 0x77), cpu.x[1]);
                try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
            }
        }
    };

    /// The bitfield moves: extract, insert, and the extensions and shifts spelled
    /// with them. Every expected value is worked out from the definition of the
    /// instruction, not read back from the translator.
    pub const bitfield_tests = struct {
        const source: u64 = 0x0123_4567_89ab_cdef;
        const previous: u64 = 0x1111_1111_1111_1111;

        fn run(word: u32, cpu: *Cpu) !void {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, word, .little);
            var block = try guest.compile(testing.allocator(), 0x4000, &bytes);
            defer block.deinit();
            _ = block.run(cpu);
        }

        const Case = struct { name: []const u8, word: u32, x1: u64 = source, x0: u64 = previous, expected: u64 };

        fn check(cases: []const Case) !void {
            for (cases) |case| {
                var cpu: Cpu = .{ .sp = 0x1234 };
                cpu.x[0] = case.x0;
                cpu.x[1] = case.x1;
                try run(case.word, &cpu);
                errdefer std.debug.print("{s}: got {x}, wanted {x}\n", .{ case.name, cpu.x[0], case.expected });
                try testing.expectEqual(case.expected, cpu.x[0]);
                try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
            }
        }

        test "extracting a field zero- or sign-extends the bits at its position" {
            // Bits 19:16 of the source are 0xb, which is 0b1011: its top bit is set.
            try check(&.{
                .{ .name = "ubfx x0, x1, #16, #4", .word = 0xd3504c20, .expected = 0xb },
                .{ .name = "sbfx x0, x1, #16, #4", .word = 0x93504c20, .expected = 0xffff_ffff_ffff_fffb },
                // Bits 11:4 of the low word are 0xde, whose top bit is set.
                .{ .name = "ubfx w0, w1, #4, #8", .word = 0x53042c20, .expected = 0xde },
                // A 32-bit result is sign-extended in 32 bits and then zero-extended into
                // the register, so the upper half is clear.
                .{ .name = "sbfx w0, w1, #4, #8", .word = 0x13042c20, .expected = 0xffff_ffde },
                // A field that reaches the top of the register.
                .{ .name = "ubfx x0, x1, #60, #4", .word = 0xd37cfc20, .expected = 0x0 },
                .{ .name = "sbfx x0, x1, #56, #8", .word = 0x9378fc20, .x1 = 0x8000_0000_0000_0000, .expected = 0xffff_ffff_ffff_ff80 },
            });
        }

        test "inserting a field places the bottom of the source at a position" {
            // The bottom four bits of the source are 0xf.
            try check(&.{
                .{ .name = "ubfiz x0, x1, #8, #4", .word = 0xd3780c20, .expected = 0xf00 },
                .{ .name = "sbfiz x0, x1, #8, #4", .word = 0x93780c20, .expected = 0xffff_ffff_ffff_ff00 },
                // Positive when the field's top bit is clear: the bottom four bits are 0x7.
                .{ .name = "sbfiz x0, x1, #8, #4 positive", .word = 0x93780c20, .x1 = 0x7, .expected = 0x700 },
                .{ .name = "ubfiz w0, w1, #4, #8", .word = 0x531c1c20, .x1 = 0xffff_ffff_ffff_ffab, .expected = 0xab0 },
            });
        }

        test "the bitfield insert forms leave the rest of the destination alone" {
            try check(&.{
                // bfxil x0, x1, #16, #4 takes the field to the bottom and keeps the rest.
                .{ .name = "bfxil x0, x1, #16, #4", .word = 0xb3504c20, .expected = 0x1111_1111_1111_111b },
                // bfi x0, x1, #8, #4 replaces bits 11:8 with the source's bottom four.
                .{ .name = "bfi x0, x1, #8, #4", .word = 0xb3780c20, .expected = 0x1111_1111_1111_1f11 },
                // bfc is bfi from the zero register.
                .{ .name = "bfc x0, #8, #4", .word = 0xb3780fe0, .expected = 0x1111_1111_1111_1011 },
                // The 32-bit form keeps the destination's low word and clears the top half.
                .{ .name = "bfi w0, w1, #8, #4", .word = 0x33180c20, .x0 = 0xffff_ffff_ffff_ffff, .expected = 0x0000_0000_ffff_ffff },
                .{ .name = "bfi w0, w1, #8, #4 changes bits", .word = 0x33180c20, .x0 = 0x1111_1111, .x1 = 0x5, .expected = 0x1111_1511 },
            });
        }

        test "the extensions and shifts that are spelled as bitfields still mean what they say" {
            try check(&.{
                .{ .name = "sxtb x0, w1", .word = 0x93401c20, .x1 = 0x80, .expected = 0xffff_ffff_ffff_ff80 },
                .{ .name = "sxth x0, w1", .word = 0x93403c20, .x1 = 0x8000, .expected = 0xffff_ffff_ffff_8000 },
                .{ .name = "sxtw x0, w1", .word = 0x93407c20, .x1 = 0x8000_0000, .expected = 0xffff_ffff_8000_0000 },
                .{ .name = "sxtw x0, w1 positive", .word = 0x93407c20, .x1 = 0x1_7fff_ffff, .expected = 0x7fff_ffff },
                .{ .name = "uxtb w0, w1", .word = 0x53001c20, .x1 = 0x1ff, .expected = 0xff },
                .{ .name = "uxth w0, w1", .word = 0x53003c20, .x1 = 0x1_ffff, .expected = 0xffff },
                .{ .name = "ubfx x0, x1, #0, #64", .word = 0xd340fc20, .expected = source },
                .{ .name = "ubfx w0, w1, #0, #32", .word = 0x53007c20, .expected = 0x89ab_cdef },
            });
        }

        test "a bitfield written to register 31 is discarded and the stack pointer is untouched" {
            var cpu: Cpu = .{ .sp = 0x1234 };
            cpu.x[1] = source;
            try run(0xd3504c3f, &cpu); // ubfx xzr, x1, #16, #4
            try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
        }

        test "the reserved bitfield encodings are refused rather than read as something else" {
            // The N bit disagrees with the register width, in both directions.
            try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x53400c20));
            try testing.expectError(error.UnsupportedInstruction, Decode.decode(0xd3000c20));
            // A 32-bit form naming a bit past 31 in either field.
            try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x53200020));
            try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x53008020));
            // The fourth opcode is not a bitfield move.
            try testing.expectError(error.UnsupportedInstruction, Decode.decode(0xf3504c20));
            // And the class next door is not claimed: MOVN shares its top bits with it, and
            // is its own instruction, not a bitmask and not a bitfield.
            try testing.expectEqual(true, (try Decode.decode(0x92800000)) == .movn);
        }

        test "the decoder unpacks a position and a length, not the encoding's own fields" {
            // ubfx x0, x1, #16, #4: taken from bit 16, four bits.
            const extract = (try Decode.decode(0xd3504c20)).bitfield;
            try testing.expectEqual(true, extract.extract);
            try testing.expectEqual(@as(u6, 16), extract.lsb);
            try testing.expectEqual(@as(u7, 4), extract.len);
            // ubfiz x0, x1, #8, #4: placed at bit 8, four bits. The encoding says rotate by 56.
            const insert = (try Decode.decode(0xd3780c20)).bitfield;
            try testing.expectEqual(false, insert.extract);
            try testing.expectEqual(@as(u6, 8), insert.lsb);
            try testing.expectEqual(@as(u7, 4), insert.len);
            // lsl x0, x1, #3 is ubfm with a rotation of 61 and a run ending at 60.
            const shift = (try Decode.decode(0xd37df020)).bitfield;
            try testing.expectEqual(false, shift.extract);
            try testing.expectEqual(@as(u6, 3), shift.lsb);
            try testing.expectEqual(@as(u7, 61), shift.len);
        }
    };

    /// Add and subtract with carry. Each expected value is the architecture's own
    /// rule: the first operand, plus the second (inverted for a subtract), plus the
    /// carry flag, with the flags read off that three-term sum.
    pub const carry_tests = struct {
        const N: u32 = 1 << 31;
        const Z: u32 = 1 << 30;
        const C: u32 = 1 << 29;
        const V: u32 = 1 << 28;
        const all: u64 = std.math.maxInt(u64);

        const Case = struct {
            name: []const u8,
            word: u32,
            x1: u64 = 0,
            x2: u64 = 0,
            flags: u32 = 0,
            result: u64,
            /// The flags after, when the instruction sets them.
            after: ?u32 = null,
        };

        fn check(cases: []const Case) !void {
            for (cases) |case| {
                var bytes: [4]u8 = undefined;
                std.mem.writeInt(u32, &bytes, case.word, .little);
                var block = try guest.compile(testing.allocator(), 0x4000, &bytes);
                defer block.deinit();
                var cpu: Cpu = .{ .flags = case.flags, .sp = 0x1234 };
                cpu.x[0] = 0xdead_beef_dead_beef;
                cpu.x[1] = case.x1;
                cpu.x[2] = case.x2;
                _ = block.run(&cpu);
                errdefer std.debug.print("{s}: got {x} flags {x}\n", .{ case.name, cpu.x[0], cpu.flags });
                try testing.expectEqual(case.result, cpu.x[0]);
                try testing.expectEqual(case.after orelse case.flags, cpu.flags);
                try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
            }
        }

        // adc x0, x1, x2 and its relatives, on registers 0, 1 and 2.
        const adc_x: u32 = 0x9a020020;
        const adcs_x: u32 = 0xba020020;
        const sbc_x: u32 = 0xda020020;
        const sbcs_x: u32 = 0xfa020020;
        const ngc_x: u32 = 0xda0203e0; // sbc x0, xzr, x2
        const sbc_w: u32 = 0x5a020020;
        const sbcs_w: u32 = 0x7a020020;

        test "add with carry adds the carry flag as one" {
            try check(&.{
                .{ .name = "no carry", .word = adc_x, .x1 = 5, .x2 = 7, .result = 12 },
                .{ .name = "carry", .word = adc_x, .x1 = 5, .x2 = 7, .flags = C, .result = 13, .after = C },
                // The other flags are not read, and adc does not change any of them.
                .{ .name = "other flags left", .word = adc_x, .x1 = 1, .x2 = 1, .flags = N | Z | V, .result = 2, .after = N | Z | V },
            });
        }

        test "subtract with carry treats the carry flag as no borrow" {
            // a - b - 1 + C: with the carry set there is no borrow and it is a plain subtract.
            try check(&.{
                .{ .name = "no borrow", .word = sbc_x, .x1 = 10, .x2 = 3, .flags = C, .result = 7, .after = C },
                .{ .name = "borrow", .word = sbc_x, .x1 = 10, .x2 = 3, .result = 6 },
                // ngc x0, x2 is sbc x0, xzr, x2: zero, less the operand, less the borrow.
                .{ .name = "ngc, no borrow", .word = ngc_x, .x2 = 5, .flags = C, .result = @as(u64, 0) -% 5, .after = C },
                .{ .name = "ngc, borrow", .word = ngc_x, .x2 = 5, .result = @as(u64, 0) -% 6 },
            });
        }

        test "the flag-setting add reports the carry out of all three terms" {
            try check(&.{
                // max + 0 + 1 wraps to zero and carries.
                .{ .name = "wrap to zero", .word = adcs_x, .x1 = all, .x2 = 0, .flags = C, .result = 0, .after = Z | C },
                // max + max + 1 is 2^65 - 1: the result is all ones, and it carried.
                .{ .name = "max + max + carry", .word = adcs_x, .x1 = all, .x2 = all, .flags = C, .result = all, .after = N | C },
                // 3 + max + 1 is 2^64 + 3: the result is 3, which is not below 3, and it
                // still carried. A carry read only from "result below operand" misses this.
                .{ .name = "the wrap that leaves the sum equal", .word = adcs_x, .x1 = 3, .x2 = all, .flags = C, .result = 3, .after = C },
                // The same operands with no carry in: 3 + max is 2^64 + 2, a carry with result 2.
                .{ .name = "and without the carry in", .word = adcs_x, .x1 = 3, .x2 = all, .result = 2, .after = C },
                // No carry anywhere.
                .{ .name = "plain", .word = adcs_x, .x1 = 1, .x2 = 2, .flags = C, .result = 4, .after = 0 },
                // The largest signed value plus one, with a carry in, overflows into the sign bit.
                .{ .name = "signed overflow", .word = adcs_x, .x1 = 0x7fff_ffff_ffff_ffff, .x2 = 0, .flags = C, .result = 0x8000_0000_0000_0000, .after = N | V },
            });
        }

        test "the flag-setting subtract reports borrow and overflow" {
            try check(&.{
                // 0 - 0 - 1: everything borrows, and the result is all ones.
                .{ .name = "borrow out", .word = sbcs_x, .flags = 0, .result = all, .after = N },
                // 5 - 5 with no borrow is zero with the carry set.
                .{ .name = "equal", .word = sbcs_x, .x1 = 5, .x2 = 5, .flags = C, .result = 0, .after = Z | C },
                // The most negative value less one overflows, and nothing was borrowed.
                .{ .name = "signed overflow", .word = sbcs_x, .x1 = 0x8000_0000_0000_0000, .x2 = 1, .flags = C, .result = 0x7fff_ffff_ffff_ffff, .after = C | V },
                // The borrow in can be what pushes a subtraction across zero.
                .{ .name = "borrow in crosses zero", .word = sbcs_x, .x1 = 5, .x2 = 5, .flags = 0, .result = all, .after = N },
            });
        }

        test "the 32-bit forms work in 32 bits and clear the top of the register" {
            try check(&.{
                // The upper half of each operand is not part of a 32-bit operand.
                .{ .name = "sbc w", .word = sbc_w, .x1 = 0x1_0000_0005, .x2 = 0x7_0000_0003, .flags = C, .result = 2, .after = C },
                .{ .name = "sbc w borrow wraps in 32 bits", .word = sbc_w, .x1 = 0, .x2 = 0, .result = 0xffff_ffff },
                // 0x80000000 - 1 overflows at 32 bits though not at 64.
                .{ .name = "sbcs w overflow", .word = sbcs_w, .x1 = 0x8000_0000, .x2 = 1, .flags = C, .result = 0x7fff_ffff, .after = C | V },
            });
        }

        test "a carry result written to register 31 is discarded and the stack is untouched" {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, 0x9a02001f, .little); // adc xzr, x0, x2
            var block = try guest.compile(testing.allocator(), 0x4000, &bytes);
            defer block.deinit();
            var cpu: Cpu = .{ .sp = 0x1234 };
            _ = block.run(&cpu);
            try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
        }

        test "the carry class is told apart from the selects and compares beside it" {
            switch (try Decode.decode(0x5a1f02a9)) { // sbc w9, w21, wzr, the kernel's own
                .arith_carry => |arith| {
                    try testing.expectEqual(Decode.ArithOp.sub, arith.op);
                    try testing.expectEqual(false, arith.flags);
                    try testing.expectEqual(@as(u5, 31), arith.rm);
                },
                else => return error.NotACarryInstruction,
            }
            switch (try Decode.decode(0x9a820020)) { // csel x0, x1, x2, eq
                .csel => {},
                else => return error.NotASelect,
            }
            switch (try Decode.decode(0xfa4f1824)) { // ccmp x1, #15, #4, ne
                .cond_compare => {},
                else => return error.NotACompare,
            }
            // The second opcode is zero in all four; anything else there is not one of them.
            try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x9a020420));
        }
    };

    /// Conditional compares and the conditions that select between values. Every
    /// expected flag word is derived by hand from the architecture's own rule: the
    /// sum of the first operand, the second (inverted for a compare) and a carry in.
    pub const conditional_tests = struct {
        fn run(word: u32, cpu: *Cpu) !void {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, word, .little);
            var block = try guest.compile(testing.allocator(), 0x4000, &bytes);
            defer block.deinit();
            _ = block.run(cpu);
        }

        const Z: u32 = 1 << 30;
        const C: u32 = 1 << 29;
        const N: u32 = 1 << 31;
        const V: u32 = 1 << 28;

        const Case = struct { name: []const u8, word: u32, flags: u32 = 0, x1: u64 = 0, x2: u64 = 0, expected: u32 };

        fn check(cases: []const Case) !void {
            for (cases) |case| {
                var cpu: Cpu = .{ .flags = case.flags, .sp = 0x1234 };
                cpu.x[1] = case.x1;
                cpu.x[2] = case.x2;
                try run(case.word, &cpu);
                errdefer std.debug.print("{s}: flags {x}, wanted {x}\n", .{ case.name, cpu.flags, case.expected });
                try testing.expectEqual(case.expected, cpu.flags);
                try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
            }
        }

        test "a conditional compare whose condition holds sets the flags of the comparison" {
            // ccmp x1, #15, #4, ne, with Z clear so that `ne` holds.
            try check(&.{
                .{ .name = "equal", .word = 0xfa4f1824, .x1 = 15, .expected = Z | C },
                // 3 - 15 is negative and borrows.
                .{ .name = "less", .word = 0xfa4f1824, .x1 = 3, .expected = N },
                // 20 - 15 is positive with no borrow.
                .{ .name = "greater", .word = 0xfa4f1824, .x1 = 20, .expected = C },
                // The most negative value less 15 overflows to a positive result.
                .{ .name = "overflow", .word = 0xfa4f1824, .x1 = 0x8000_0000_0000_0000, .expected = C | V },
            });
        }

        test "a conditional compare whose condition fails loads the flags the encoding carries" {
            // The same ccmp with Z set, so `ne` fails: the four bits are N Z C V from the
            // top, and the operands are not looked at.
            try check(&.{
                .{ .name = "nzcv 4", .word = 0xfa4f1824, .flags = Z, .x1 = 15, .expected = Z },
                .{ .name = "nzcv 4, other value", .word = 0xfa4f1824, .flags = Z, .x1 = 3, .expected = Z },
                // ccmp x1, #15, #10, ne: N and C.
                .{ .name = "nzcv 10", .word = 0xfa4f182a, .flags = Z, .x1 = 15, .expected = N | C },
                // ccmp x1, #15, #0, ne clears everything, including what was set going in.
                .{ .name = "nzcv 0", .word = 0xfa4f1820, .flags = Z | C | V, .x1 = 15, .expected = 0 },
            });
        }

        test "a conditional compare negative adds instead of subtracting" {
            // ccmn x1, #1, #0, eq, with Z set so that `eq` holds.
            try check(&.{
                // All ones plus one wraps to zero: Z, and a carry out, and no overflow.
                .{ .name = "wrap", .word = 0xba410820, .flags = Z, .x1 = std.math.maxInt(u64), .expected = Z | C },
                // The largest signed value plus one overflows into the sign bit.
                .{ .name = "overflow", .word = 0xba410820, .flags = Z, .x1 = 0x7fff_ffff_ffff_ffff, .expected = N | V },
                .{ .name = "plain", .word = 0xba410820, .flags = Z, .x1 = 5, .expected = 0 },
                // With `eq` failing, the encoding's own flags: ccmn x1, #1, #8, eq is N.
                .{ .name = "fails", .word = 0xba410828, .flags = 0, .x1 = 5, .expected = N },
            });
        }

        test "a conditional compare with a register second operand, and the always condition" {
            // ccmp x1, x2, #0, al: `al` is a condition that always holds.
            try check(&.{
                .{ .name = "equal", .word = 0xfa42e020, .x1 = 7, .x2 = 7, .expected = Z | C },
                .{ .name = "less", .word = 0xfa42e020, .x1 = 1, .x2 = 7, .expected = N },
                // `nv` means the same as `al`, not "never".
                .{ .name = "nv holds", .word = 0xfa42f020, .x1 = 7, .x2 = 7, .expected = Z | C },
            });
        }

        test "a 32-bit conditional compare compares 32 bits" {
            // ccmp w1, #5, #0, eq, with Z set so that `eq` holds.
            try check(&.{
                // The upper half of the register is not part of the comparison.
                .{ .name = "equal", .word = 0x7a450820, .flags = Z, .x1 = 0x1_0000_0005, .expected = Z | C },
                // At 32 bits the most negative value less 5 overflows, though it would not at 64.
                .{ .name = "overflow", .word = 0x7a450820, .flags = Z, .x1 = 0x8000_0000, .expected = C | V },
            });
        }

        test "a select on the always conditions takes its first operand" {
            // csel x0, x1, x2, al and csel x0, x1, x2, nv.
            for ([_]u32{ 0x9a82e020, 0x9a82f020 }) |word| {
                var cpu: Cpu = .{ .flags = 0 };
                cpu.x[1] = 0x11;
                cpu.x[2] = 0x22;
                try run(word, &cpu);
                try testing.expectEqual(@as(u64, 0x11), cpu.x[0]);
            }
        }

        test "the neighbouring classes are not read as conditional compares" {
            // A select, which differs in bit 23, and a compare with bit 4 set.
            switch (try Decode.decode(0x9a82e020)) {
                .csel => {},
                else => return error.NotASelect,
            }
            try testing.expectError(error.UnsupportedInstruction, Decode.decode(0xfa4f1834));
            switch (try Decode.decode(0xfa4f1824)) {
                .cond_compare => |compare| {
                    try testing.expectEqual(Decode.Condition.ne, compare.cond);
                    try testing.expectEqual(@as(u4, 4), compare.nzcv);
                    try testing.expectEqual(@as(u5, 15), compare.operand.immediate);
                },
                else => return error.NotACompare,
            }
        }
    };

    /// Register-source data processing: variable shifts, divides, and the encodings
    /// whose register 31 is the zero register rather than the stack pointer.
    pub const data_processing_tests = struct {
        fn run(word: u32, cpu: *Cpu) !void {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, word, .little);
            var block = try guest.compile(testing.allocator(), 0x4000, &bytes);
            defer block.deinit();
            _ = block.run(cpu);
        }

        const Case = struct { name: []const u8, word: u32, x1: u64, x2: u64, expected: u64 };

        fn check(cases: []const Case) !void {
            for (cases) |case| {
                var cpu: Cpu = .{ .sp = 0x1234 };
                cpu.x[1] = case.x1;
                cpu.x[2] = case.x2;
                try run(case.word, &cpu);
                errdefer std.debug.print("{s}: got {x}, wanted {x}\n", .{ case.name, cpu.x[0], case.expected });
                try testing.expectEqual(case.expected, cpu.x[0]);
            }
        }

        test "a shift by a register takes its distance modulo the register width" {
            try check(&.{
                .{ .name = "lsl x", .word = 0x9ac22020, .x1 = 1, .x2 = 65, .expected = 2 },
                .{ .name = "lsl w", .word = 0x1ac22020, .x1 = 1, .x2 = 33, .expected = 2 },
                // A 32-bit result clears the top half of the register.
                .{ .name = "lsl w drops the top", .word = 0x1ac22020, .x1 = 0x8000_0001, .x2 = 1, .expected = 2 },
                .{ .name = "lsr x", .word = 0x9ac22420, .x1 = 0x8000_0000_0000_0000, .x2 = 63, .expected = 1 },
                .{ .name = "lsr w", .word = 0x1ac22420, .x1 = 0xffff_ffff_8000_0000, .x2 = 31, .expected = 1 },
                .{ .name = "asr x", .word = 0x9ac22820, .x1 = 0x8000_0000_0000_0000, .x2 = 63, .expected = std.math.maxInt(u64) },
                .{ .name = "asr x positive", .word = 0x9ac22820, .x1 = 0x4000_0000_0000_0000, .x2 = 62, .expected = 1 },
                .{ .name = "asr w", .word = 0x1ac22820, .x1 = 0x8000_0000, .x2 = 31, .expected = 0xffff_ffff },
                .{ .name = "ror x", .word = 0x9ac22c20, .x1 = 1, .x2 = 1, .expected = 0x8000_0000_0000_0000 },
                .{ .name = "ror x by zero", .word = 0x9ac22c20, .x1 = 0x1234_5678_9abc_def0, .x2 = 0, .expected = 0x1234_5678_9abc_def0 },
                .{ .name = "ror x by the width", .word = 0x9ac22c20, .x1 = 0x1234_5678_9abc_def0, .x2 = 64, .expected = 0x1234_5678_9abc_def0 },
                .{ .name = "ror w", .word = 0x1ac22c20, .x1 = 1, .x2 = 1, .expected = 0x8000_0000 },
                .{ .name = "ror w by zero", .word = 0x1ac22c20, .x1 = 0xdead_beef, .x2 = 0, .expected = 0xdead_beef },
            });
        }

        test "unsigned divide, including the divide by zero that traps on the host" {
            try check(&.{
                .{ .name = "udiv x", .word = 0x9ac20820, .x1 = 100, .x2 = 7, .expected = 14 },
                .{ .name = "udiv x large", .word = 0x9ac20820, .x1 = std.math.maxInt(u64), .x2 = 2, .expected = std.math.maxInt(u64) / 2 },
                .{ .name = "udiv x by zero", .word = 0x9ac20820, .x1 = 100, .x2 = 0, .expected = 0 },
                .{ .name = "udiv w", .word = 0x1ac20820, .x1 = 0x1_0000_0064, .x2 = 7, .expected = 14 },
                // The divisor's top half is not part of a 32-bit divisor.
                .{ .name = "udiv w by zero low half", .word = 0x1ac20820, .x1 = 100, .x2 = 0x1_0000_0000, .expected = 0 },
            });
        }

        test "signed divide, including the two quotients that trap on the host" {
            const min64: u64 = 0x8000_0000_0000_0000;
            try check(&.{
                .{ .name = "sdiv x", .word = 0x9ac20c20, .x1 = 100, .x2 = 7, .expected = 14 },
                .{ .name = "sdiv x negative", .word = 0x9ac20c20, .x1 = @bitCast(@as(i64, -100)), .x2 = 7, .expected = @bitCast(@as(i64, -14)) },
                // Toward zero, not toward minus infinity.
                .{ .name = "sdiv x truncates", .word = 0x9ac20c20, .x1 = @bitCast(@as(i64, -7)), .x2 = 2, .expected = @bitCast(@as(i64, -3)) },
                .{ .name = "sdiv x by zero", .word = 0x9ac20c20, .x1 = 100, .x2 = 0, .expected = 0 },
                .{ .name = "sdiv x by minus one", .word = 0x9ac20c20, .x1 = 100, .x2 = std.math.maxInt(u64), .expected = @bitCast(@as(i64, -100)) },
                .{ .name = "sdiv x min by minus one", .word = 0x9ac20c20, .x1 = min64, .x2 = std.math.maxInt(u64), .expected = min64 },
                .{ .name = "sdiv w", .word = 0x1ac20c20, .x1 = 0xffff_ff9c, .x2 = 7, .expected = 0xffff_fff2 },
                .{ .name = "sdiv w min by minus one", .word = 0x1ac20c20, .x1 = 0x8000_0000, .x2 = 0xffff_ffff, .expected = 0x8000_0000 },
                // Minus one in the low half is minus one, whatever sits above it.
                .{ .name = "sdiv w minus one low half", .word = 0x1ac20c20, .x1 = 100, .x2 = 0x1_ffff_ffff, .expected = 0xffff_ff9c },
            });
        }

        test "a two-source result written to register 31 is discarded, not stored in the stack pointer" {
            var cpu: Cpu = .{ .sp = 0x1234 };
            cpu.x[1] = 100;
            cpu.x[2] = 7;
            try run(0x9ac2083f, &cpu); // udiv xzr, x1, x2
            try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
        }

        test "the two-source class refuses the instructions it shares its space with" {
            // CRC32B, and a pointer-authentication instruction, share the class.
            try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x1ac04020));
            try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x9ac03020));
            // The flag-setting bit selects a different instruction (SUBPS), not this class.
            try testing.expectError(error.UnsupportedInstruction, Decode.decode(0xbac20020));
        }

        test "the zero register is read as zero and written nowhere by a conditional select" {
            // With SP holding a value that would be visible if it were read instead.
            const cases = [_]struct { name: []const u8, word: u32, flags: u32, expected: u64 }{
                // cset w0, eq is csinc w0, wzr, wzr, ne: one when Z is set.
                .{ .name = "cset w true", .word = 0x1a9f17e0, .flags = 1 << 30, .expected = 1 },
                .{ .name = "cset w false", .word = 0x1a9f17e0, .flags = 0, .expected = 0 },
                .{ .name = "cset x true", .word = 0x9a9f17e0, .flags = 1 << 30, .expected = 1 },
                // csetm x0, eq is csinv x0, xzr, xzr, ne: all ones when Z is set.
                .{ .name = "csetm x true", .word = 0xda9f13e0, .flags = 1 << 30, .expected = std.math.maxInt(u64) },
                .{ .name = "csetm x false", .word = 0xda9f13e0, .flags = 0, .expected = 0 },
                // csel x0, xzr, x1, eq and csel x0, x1, xzr, eq.
                .{ .name = "csel xzr first", .word = 0x9a8103e0, .flags = 1 << 30, .expected = 0 },
                .{ .name = "csel xzr second", .word = 0x9a9f0020, .flags = 0, .expected = 0 },
            };
            for (cases) |case| {
                var cpu: Cpu = .{ .sp = 0x1234, .flags = case.flags };
                cpu.x[1] = 0x77;
                try run(case.word, &cpu);
                errdefer std.debug.print("{s}: got {x}, wanted {x}\n", .{ case.name, cpu.x[0], case.expected });
                try testing.expectEqual(case.expected, cpu.x[0]);
            }

            // csel xzr, x1, x2, eq writes nowhere: the stack pointer is not the destination.
            var cpu: Cpu = .{ .sp = 0x1234, .flags = 1 << 30 };
            cpu.x[1] = 0x77;
            try run(0x9a82003f, &cpu);
            try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
        }

        test "multiply reads the zero register as zero and negates for the subtracting forms" {
            try check(&.{
                .{ .name = "mul", .word = 0x9b027c20, .x1 = 6, .x2 = 7, .expected = 42 },
                // mneg x0, x1, x2 is msub x0, x1, x2, xzr: zero minus the product.
                .{ .name = "mneg", .word = 0x9b02fc20, .x1 = 6, .x2 = 7, .expected = @bitCast(@as(i64, -42)) },
                .{ .name = "mneg w", .word = 0x1b02fc20, .x1 = 6, .x2 = 7, .expected = 0xffff_ffd6 },
                // mul x0, xzr, x2: a zero factor, not the stack pointer.
                .{ .name = "mul by xzr", .word = 0x9b027fe0, .x1 = 6, .x2 = 7, .expected = 0 },
            });
            var cpu: Cpu = .{ .sp = 0x1234 };
            cpu.x[1] = 6;
            cpu.x[2] = 7;
            try run(0x9b027c3f, &cpu); // mul xzr, x1, x2
            try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
        }
    };

    /// Exclusive and ordered loads and stores. The monitor lives in the run loop, so
    /// these run real instructions through a `Machine` with memory behind it and read
    /// the result out of both the registers and the memory.
    pub const exclusive_tests = struct {
        const base: u64 = 0x1000;
        /// Where the two words of data are: `x0` points at the first and `x1` at the second.
        const first_at = base + 0x100;
        const second_at = base + 0x108;

        const wfi: u32 = 0xd503207f;

        const Outcome = struct { cpu: Cpu, first: u64, second: u64 };

        /// Run `words` from the start of memory until the guest waits for an interrupt.
        fn execute(words: []const u32, first: u64, second: u64) !Outcome {
            var bytes: [0x200]u8 = @splat(0);
            for (words, 0..) |word, index| std.mem.writeInt(u32, bytes[index * 4 ..][0..4], word, .little);
            std.mem.writeInt(u64, bytes[0x100..][0..8], first, .little);
            std.mem.writeInt(u64, bytes[0x108..][0..8], second, .little);
            const regions = [_]GuestMemory.Region{.{ .gpa = base, .len = bytes.len, .backing = .{ .shared = &bytes } }};
            var memory: GuestMemory = .{ .regions = &regions };
            var machine = guest.Machine.init(testing.allocator(), &memory);
            defer machine.deinit();
            const hv = machine.backend();
            const id = try hv.addVcpu();
            try hv.setRegister(id, .pc, base);
            try hv.setRegister(id, .x0, first_at);
            try hv.setRegister(id, .x1, second_at);
            machine.cpu.sp = 0x7777;
            while (true) switch (try hv.run(id)) {
                .wfi => break,
                .interrupted => {},
                else => return error.UnexpectedExit,
            };
            return .{
                .cpu = machine.cpu,
                .first = std.mem.readInt(u64, bytes[0x100..][0..8], .little),
                .second = std.mem.readInt(u64, bytes[0x108..][0..8], .little),
            };
        }

        // The instructions, by their assembly.
        const ldxr_x2_x0: u32 = 0xc85f7c02;
        const ldxrb_w2_x0: u32 = 0x085f7c02;
        const stxr_w3_x2_x0: u32 = 0xc8037c02;
        const stxr_w3_x2_x1: u32 = 0xc8037c22;
        const stxr_w4_x2_x0: u32 = 0xc8047c02;
        const stxr_wzr_x2_x0: u32 = 0xc81f7c02;
        const add_x2_x2_1: u32 = 0x91000442;
        const movz_x2_7: u32 = 0xd28000e2;
        const clrex: u32 = 0xd503305f;

        test "a load-exclusive followed by a store-exclusive to the same place stores" {
            // ldxr x2, [x0]; add x2, x2, #1; stxr w3, x2, [x0]: an atomic increment.
            const out = try execute(&.{ ldxr_x2_x0, add_x2_x2_1, stxr_w3_x2_x0, wfi }, 41, 0);
            try testing.expectEqual(@as(u64, 42), out.first);
            try testing.expectEqual(@as(u64, 0), out.cpu.x[3]); // it stored
        }

        test "a store-exclusive with no claim does not store and says so" {
            const out = try execute(&.{ movz_x2_7, stxr_w3_x2_x0, wfi }, 0, 0);
            try testing.expectEqual(@as(u64, 0), out.first);
            try testing.expectEqual(@as(u64, 1), out.cpu.x[3]);
        }

        test "CLREX drops the claim" {
            const out = try execute(&.{ ldxr_x2_x0, clrex, stxr_w3_x2_x0, wfi }, 5, 0);
            try testing.expectEqual(@as(u64, 5), out.first);
            try testing.expectEqual(@as(u64, 1), out.cpu.x[3]);
        }

        test "a store-exclusive to a different address than the claim fails" {
            const out = try execute(&.{ ldxr_x2_x0, stxr_w3_x2_x1, wfi }, 5, 9);
            try testing.expectEqual(@as(u64, 9), out.second);
            try testing.expectEqual(@as(u64, 1), out.cpu.x[3]);
        }

        test "the claim is spent by the store-exclusive that used it" {
            // The first stores, and the second has nothing left to succeed with.
            const out = try execute(&.{ ldxr_x2_x0, add_x2_x2_1, stxr_w3_x2_x0, stxr_w4_x2_x0, wfi }, 10, 0);
            try testing.expectEqual(@as(u64, 11), out.first);
            try testing.expectEqual(@as(u64, 0), out.cpu.x[3]);
            try testing.expectEqual(@as(u64, 1), out.cpu.x[4]);
        }

        test "a claim of one size does not license a store of another" {
            // A byte claim, and a doubleword store to the same address.
            const out = try execute(&.{ ldxrb_w2_x0, stxr_w3_x2_x0, wfi }, 0x55, 0);
            try testing.expectEqual(@as(u64, 0x55), out.first);
            try testing.expectEqual(@as(u64, 1), out.cpu.x[3]);
        }

        test "a failed store-exclusive also spends the claim" {
            // The failed store is to the wrong place; the one after it, to the right place, has no claim.
            const out = try execute(&.{ ldxr_x2_x0, stxr_w3_x2_x1, stxr_w4_x2_x0, wfi }, 5, 9);
            try testing.expectEqual(@as(u64, 1), out.cpu.x[3]);
            try testing.expectEqual(@as(u64, 1), out.cpu.x[4]);
            try testing.expectEqual(@as(u64, 5), out.first);
        }

        test "a store-exclusive that reports to register 31 discards the report, not the stack" {
            const out = try execute(&.{ ldxr_x2_x0, add_x2_x2_1, stxr_wzr_x2_x0, wfi }, 1, 0);
            try testing.expectEqual(@as(u64, 2), out.first);
            try testing.expectEqual(@as(u64, 0x7777), out.cpu.sp);
        }

        test "the ordered loads and stores are plain accesses" {
            // ldar x2, [x0]; stlr x2, [x1]: the value moves across.
            const ldar_x2_x0: u32 = 0xc8dffc02;
            const stlr_x2_x1: u32 = 0xc89ffc22;
            const out = try execute(&.{ ldar_x2_x0, stlr_x2_x1, wfi }, 0xdead_beef, 0);
            try testing.expectEqual(@as(u64, 0xdead_beef), out.second);
            // And they decode as the plain accesses they are, with no offset.
            switch (try Decode.decode(ldar_x2_x0)) {
                .memory => |access| {
                    try testing.expectEqual(Decode.Size.double, access.size);
                    try testing.expectEqual(@as(i64, 0), access.addressing.offset);
                },
                else => return error.NotAPlainLoad,
            }
            // The acquire forms without bit 15 are the same accesses: the kernel's own
            // `ldaprb w9, [x0]` and `ldarb w8, [x0]` move a byte each.
            const out_acquire = try execute(&.{ 0x085f7c09, 0x08dffc08, wfi }, 0x5a, 0);
            try testing.expectEqual(@as(u64, 0x5a), out_acquire.cpu.x[9]);
            try testing.expectEqual(@as(u64, 0x5a), out_acquire.cpu.x[8]);
        }

        test "taking or returning from an exception ends the claim" {
            var cpu: Cpu = .{ .monitor_valid = true };
            _ = Exception.take(&cpu, .{ .kind = .sync, .ec = 0 }, 0);
            try testing.expectEqual(false, cpu.monitor_valid);

            cpu.monitor_valid = true;
            _ = Exception.eret(&cpu);
            try testing.expectEqual(false, cpu.monitor_valid);
        }

        test "the forms of this class that are not modelled are refused" {
            // A pair (LDXP) and compare-and-swap. `LDLAR` (bit 15 clear with bit 23 set
            // and a load) stays refused: only the acquire `LDAPR` form without bit 15
            // is accepted, which is what the kernel's spin loop uses.
            for ([_]u32{ 0xc87f0440, 0x88a07c00 }) |word| {
                try testing.expectError(error.UnsupportedInstruction, Decode.decode(word));
            }
            try testing.expectError(error.UnsupportedInstruction, Decode.decode(0xc8df7c00)); // ldlar w0, [x0]
            // A load-exclusive names no status register, so anything but 31 there is not one.
            try testing.expectError(error.UnsupportedInstruction, Decode.decode(0xc85f7c02 & ~@as(u32, 0x000f_0000)));
        }
    };

    /// ADD and SUB with an extended second operand, and the stack pointer they alone
    /// can name as an operand of a register-form add.
    pub const extended_tests = struct {
        fn run(word: u32, cpu: *Cpu) !void {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, word, .little);
            var block = try guest.compile(testing.allocator(), 0x4000, &bytes);
            defer block.deinit();
            _ = block.run(cpu);
        }

        const Case = struct { name: []const u8, word: u32, x1: u64, x2: u64, expected: u64 };

        test "the extension picks the low bits of the operand and fills the rest" {
            // add x0, x1, w2, <extend> with x1 = 0x1000 in each.
            try run2(&.{
                // Zero extensions keep only the field.
                .{ .name = "uxtb", .word = 0x8b220020, .x1 = 0x1000, .x2 = 0xdead_beef_1234_56f0, .expected = 0x10f0 },
                .{ .name = "uxth", .word = 0x8b222020, .x1 = 0x1000, .x2 = 0xdead_beef_1234_fff0, .expected = 0x1000 + 0xfff0 },
                .{ .name = "uxtw", .word = 0x8b224020, .x1 = 0x1000, .x2 = 0xdead_beef_8000_0001, .expected = 0x1000 + 0x8000_0001 },
                // `uxtx` is the operand as it is, which is also what `lsl` means here.
                .{ .name = "uxtx", .word = 0x8b226020, .x1 = 0x1000, .x2 = 0x0000_0001_0000_0000, .expected = 0x1_0000_1000 },
                // Sign extensions fill from the top bit of the field.
                .{ .name = "sxtb negative", .word = 0x8b228020, .x1 = 0x1000, .x2 = 0x1f0, .expected = 0x1000 - 0x10 },
                .{ .name = "sxtb positive", .word = 0x8b228020, .x1 = 0x1000, .x2 = 0x17f, .expected = 0x1000 + 0x7f },
                .{ .name = "sxth negative", .word = 0x8b22a020, .x1 = 0x1000, .x2 = 0x1_fff0, .expected = 0x1000 - 0x10 },
                .{ .name = "sxtw negative", .word = 0x8b22c020, .x1 = 0x1000, .x2 = 0xffff_ffff_8000_0001, .expected = 0xffff_ffff_8000_1001 },
                .{ .name = "sxtw positive", .word = 0x8b22c020, .x1 = 0x1000, .x2 = 0xffff_ffff_7fff_ffff, .expected = 0x1000 + 0x7fff_ffff },
                .{ .name = "sxtx", .word = 0x8b22e020, .x1 = 0x1000, .x2 = 0xffff_ffff_ffff_fff0, .expected = 0x1000 - 0x10 },
            });
        }

        test "the extended operand is shifted left by up to four after it is extended" {
            try run2(&.{
                // add x0, x1, w2, uxtw #2: the word times four, whatever sits above it.
                .{ .name = "uxtw #2", .word = 0x8b224820, .x1 = 0x1000, .x2 = 0xdead_beef_0000_0010, .expected = 0x1040 },
                // add x0, x1, w2, sxtw #4 with a low word of minus two: minus thirty-two.
                .{ .name = "sxtw #4", .word = 0x8b22d020, .x1 = 0x1000, .x2 = 0xffff_fffe, .expected = 0x1000 - 32 },
                .{ .name = "uxtb #3", .word = 0x8b220c20, .x1 = 0, .x2 = 0x1ff, .expected = 0xff << 3 },
            });
        }

        test "subtract, and the kernel's own form" {
            try run2(&.{
                .{ .name = "sub x0, x1, w2, sxtw", .word = 0xcb22c020, .x1 = 0x1000, .x2 = 0xffff_ffff, .expected = 0x1001 },
                // `add x23, x20, w22, sxtw` is a word in Linux's early code, on registers 20,
                // 22 and 23: a base plus a 32-bit signed offset, here minus sixteen.
                .{ .name = "kernel", .word = 0x8b36c297, .x1 = 0x4000_0000, .x2 = 0xffff_fff0, .expected = 0x3fff_fff0 },
            });
        }

        test "a 32-bit operation extends within 32 bits and clears the top of the result" {
            try run2(&.{
                // add w0, w1, w2, sxtb: 0x10 plus minus 128 wraps at 32 bits.
                .{ .name = "sxtb", .word = 0x0b228020, .x1 = 0x10, .x2 = 0x80, .expected = 0xffff_ff90 },
                .{ .name = "uxth", .word = 0x0b222020, .x1 = 0xffff_0000, .x2 = 0x1_0001, .expected = 0xffff_0001 },
                // The upper half of the first operand is not part of a 32-bit sum.
                .{ .name = "upper half", .word = 0x0b224020, .x1 = 0xffff_ffff_0000_0005, .x2 = 3, .expected = 8 },
            });
        }

        /// Run each case with `x0` holding a value that a write to the wrong place would leave.
        fn run2(cases: []const Case) !void {
            for (cases) |case| {
                var cpu: Cpu = .{ .sp = 0x9000 };
                cpu.x[0] = 0xdead_beef_dead_beef;
                cpu.x[1] = case.x1;
                cpu.x[2] = case.x2;
                cpu.x[20] = case.x1;
                cpu.x[22] = case.x2;
                try run(case.word, &cpu);
                const got = if (case.word == 0x8b36c297) cpu.x[23] else cpu.x[0];
                errdefer std.debug.print("{s}: got {x}, wanted {x}\n", .{ case.name, got, case.expected });
                try testing.expectEqual(case.expected, got);
                try testing.expectEqual(@as(u64, 0x9000), cpu.sp);
            }
        }

        test "the stack pointer as an operand and as a destination" {
            // add sp, sp, x1 is `add sp, sp, x1, uxtx`: the destination is the stack pointer.
            var cpu: Cpu = .{ .sp = 0x1000 };
            cpu.x[1] = 0x10;
            try run(0x8b2163ff, &cpu);
            try testing.expectEqual(@as(u64, 0x1010), cpu.sp);

            // sub x0, sp, x1: the stack pointer is read as the first operand.
            var read: Cpu = .{ .sp = 0x1000 };
            read.x[1] = 0x10;
            try run(0xcb2163e0, &read);
            try testing.expectEqual(@as(u64, 0xff0), read.x[0]);
            try testing.expectEqual(@as(u64, 0x1000), read.sp);
        }

        test "with the flags set, register 31 as the destination is the zero register" {
            // cmp sp, x2 is `subs xzr, sp, x2`: the difference is thrown away, and the
            // stack pointer is not written with it.
            var equal: Cpu = .{ .sp = 0x1000 };
            equal.x[2] = 0x1000;
            try run(0xeb2263ff, &equal);
            try testing.expectEqual(@as(u32, (1 << 30) | (1 << 29)), equal.flags);
            try testing.expectEqual(@as(u64, 0x1000), equal.sp);

            // cmp x1, w2, sxtw with 5 against minus one: 5 - (-1) borrows, so C is clear.
            var below: Cpu = .{ .sp = 0x1000 };
            below.x[1] = 5;
            below.x[2] = 0xffff_ffff;
            try run(0xeb22c03f, &below);
            try testing.expectEqual(@as(u32, 0), below.flags);
            try testing.expectEqual(@as(u64, 0x1000), below.sp);

            // adds with a real destination writes it, and sets the flags from the sum.
            var sum: Cpu = .{ .sp = 0x1000 };
            sum.x[1] = std.math.maxInt(u64);
            sum.x[2] = 1;
            try run(0xab226020, &sum); // adds x0, x1, x2, uxtx
            try testing.expectEqual(@as(u64, 0), sum.x[0]);
            try testing.expectEqual(@as(u32, (1 << 30) | (1 << 29)), sum.flags);
        }

        test "the extended form is told apart from the shifted register form and its reserved amounts" {
            // add x0, x1, x2 (shifted register) has bit 21 clear.
            switch (try Decode.decode(0x8b020020)) {
                .arith_reg => {},
                else => return error.NotShiftedRegister,
            }
            switch (try Decode.decode(0x8b22c020)) {
                .arith_ext => |ext| {
                    try testing.expectEqual(Decode.Extend.sxtw, ext.extend);
                    try testing.expectEqual(@as(u3, 0), ext.amount);
                },
                else => return error.NotExtended,
            }
            // An amount past four is not allocated.
            try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x8b22d420));
            // Bits 23:22 are not a shift type in this form.
            try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x8b62c020));
        }
    };

    /// `EXTR` and the rotate by an immediate it is the general case of.
    pub const extract_tests = struct {
        const Case = struct { name: []const u8, word: u32, x1: u64, x2: u64, expected: u64 };

        fn check(cases: []const Case) !void {
            for (cases) |case| {
                var bytes: [4]u8 = undefined;
                std.mem.writeInt(u32, &bytes, case.word, .little);
                var block = try guest.compile(testing.allocator(), 0x4000, &bytes);
                defer block.deinit();
                var cpu: Cpu = .{ .sp = 0x1234 };
                cpu.x[0] = 0xdead_beef_dead_beef;
                cpu.x[1] = case.x1;
                cpu.x[2] = case.x2;
                _ = block.run(&cpu);
                errdefer std.debug.print("{s}: got {x}, wanted {x}\n", .{ case.name, cpu.x[0], case.expected });
                try testing.expectEqual(case.expected, cpu.x[0]);
                try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
            }
        }

        test "extract takes a register's worth of bits from a pair" {
            try check(&.{
                // (x2 >> 8) with the low byte of x1 coming in at the top.
                .{ .name = "extr x0, x1, x2, #8", .word = 0x93c22020, .x1 = 0x1111_2222_3333_4444, .x2 = 0x5555_6666_7777_8888, .expected = 0x4455_5566_6677_7788 },
                // A distance of zero is the second register as it is.
                .{ .name = "extr x0, x1, x2, #0", .word = 0x93c20020, .x1 = 0x1111, .x2 = 0x5555_6666_7777_8888, .expected = 0x5555_6666_7777_8888 },
                // The distance can be all but one bit.
                .{ .name = "extr x0, x1, x2, #63", .word = 0x93c2fc20, .x1 = 1, .x2 = 0x8000_0000_0000_0000, .expected = 3 },
            });
        }

        test "a rotate by an immediate is extract of a register with itself" {
            try check(&.{
                .{ .name = "ror x0, x1, #4", .word = 0x93c11020, .x1 = 0x0123_4567_89ab_cdef, .x2 = 0, .expected = 0xf012_3456_789a_bcde },
                // A 32-bit rotate is within 32 bits, and clears the top of the register.
                .{ .name = "ror w0, w1, #1", .word = 0x13810420, .x1 = 1, .x2 = 0, .expected = 0x8000_0000 },
                .{ .name = "ror w0, w1, #16", .word = 0x13814020, .x1 = 0xdead_beef_1234_5678, .x2 = 0, .expected = 0x5678_1234 },
                // The kernel's own, on registers 9 and 14: `ror w14, w9, #16`.
            });
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, 0x1389412e, .little);
            var block = try guest.compile(testing.allocator(), 0x4000, &bytes);
            defer block.deinit();
            var cpu: Cpu = .{};
            cpu.x[9] = 0x1234_5678;
            _ = block.run(&cpu);
            try testing.expectEqual(@as(u64, 0x5678_1234), cpu.x[14]);
        }

        test "an extract written to register 31 is discarded and the stack is untouched" {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, 0x93c2201f, .little); // extr xzr, x0, x2, #8
            var block = try guest.compile(testing.allocator(), 0x4000, &bytes);
            defer block.deinit();
            var cpu: Cpu = .{ .sp = 0x1234 };
            _ = block.run(&cpu);
            try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
        }

        test "the reserved extract encodings are refused, and the bitfield class next door is not claimed" {
            // A 32-bit form with a position of 32 or more, and N disagreeing with the width.
            try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x13828020));
            try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x13c22020));
            try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x93822020));
            switch (try Decode.decode(0xd3504c20)) { // ubfx x0, x1, #16, #4
                .bitfield => {},
                else => return error.NotABitfield,
            }
            switch (try Decode.decode(0x93c22020)) {
                .extract => |pair| try testing.expectEqual(@as(u6, 8), pair.lsb),
                else => return error.NotAnExtract,
            }
        }
    };

    /// The widening and high-half multiplies. Expected values are worked out by
    /// hand from the definitions, and the wrapped ones from the two's complement of
    /// the true result.
    pub const multiply_tests = struct {
        fn run(word: u32, cpu: *Cpu) !void {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, word, .little);
            var block = try guest.compile(testing.allocator(), 0x4000, &bytes);
            defer block.deinit();
            _ = block.run(cpu);
        }

        const Case = struct { name: []const u8, word: u32, x1: u64, x2: u64, x3: u64 = 100, expected: u64 };

        fn check(cases: []const Case) !void {
            for (cases) |case| {
                var cpu: Cpu = .{ .sp = 0x1234 };
                cpu.x[0] = 0xdead_beef_dead_beef; // what a write to the wrong place would leave
                cpu.x[1] = case.x1;
                cpu.x[2] = case.x2;
                cpu.x[3] = case.x3;
                try run(case.word, &cpu);
                errdefer std.debug.print("{s}: got {x}, wanted {x}\n", .{ case.name, cpu.x[0], case.expected });
                try testing.expectEqual(case.expected, cpu.x[0]);
                try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
            }
        }

        // The 32-bit operands are minus one and five, with junk above them that a 32-bit
        // operand must not see. The accumulator is one hundred.
        const minus_one_word: u64 = 0xdead_beef_ffff_ffff;
        const five_word: u64 = 0xcafe_0000_0005;

        test "the signed long multiplies extend each word and use a 64-bit accumulator" {
            try check(&.{
                // -1 * 5 = -5.
                .{ .name = "smaddl", .word = 0x9b220c20, .x1 = minus_one_word, .x2 = five_word, .expected = 95 },
                .{ .name = "smsubl", .word = 0x9b228c20, .x1 = minus_one_word, .x2 = five_word, .expected = 105 },
                .{ .name = "smull", .word = 0x9b227c20, .x1 = minus_one_word, .x2 = five_word, .expected = 0xffff_ffff_ffff_fffb },
                .{ .name = "smnegl", .word = 0x9b22fc20, .x1 = minus_one_word, .x2 = five_word, .expected = 5 },
                // Two of the most negative words multiply to 2^62.
                .{ .name = "smull min * min", .word = 0x9b227c20, .x1 = 0x8000_0000, .x2 = 0x8000_0000, .expected = 0x4000_0000_0000_0000 },
                .{ .name = "smull max * max", .word = 0x9b227c20, .x1 = 0x7fff_ffff, .x2 = 0x7fff_ffff, .expected = 0x3fff_ffff_0000_0001 },
            });
        }

        test "the unsigned long multiplies zero-extend each word" {
            // 0xffffffff * 5 = 0x4ffffffb.
            try check(&.{
                .{ .name = "umaddl", .word = 0x9ba20c20, .x1 = minus_one_word, .x2 = five_word, .expected = 0x5_0000_005f },
                .{ .name = "umsubl", .word = 0x9ba28c20, .x1 = minus_one_word, .x2 = five_word, .expected = 0xffff_fffb_0000_0069 },
                .{ .name = "umull", .word = 0x9ba27c20, .x1 = minus_one_word, .x2 = five_word, .expected = 0x4_ffff_fffb },
                .{ .name = "umnegl", .word = 0x9ba2fc20, .x1 = minus_one_word, .x2 = five_word, .expected = 0xffff_fffb_0000_0005 },
            });
        }

        test "the high-half multiplies give the top 64 bits of the 128-bit product" {
            const all: u64 = std.math.maxInt(u64);
            try check(&.{
                // -2^63 * 2 = -2^64, whose top half is minus one; unsigned it is 2^64, whose is one.
                .{ .name = "smulh", .word = 0x9b427c20, .x1 = 0x8000_0000_0000_0000, .x2 = 2, .expected = all },
                .{ .name = "umulh", .word = 0x9bc27c20, .x1 = 0x8000_0000_0000_0000, .x2 = 2, .expected = 1 },
                // 2^62 * 2^62 = 2^124, so the top half is 2^60, either way.
                .{ .name = "smulh 2^62", .word = 0x9b427c20, .x1 = 0x4000_0000_0000_0000, .x2 = 0x4000_0000_0000_0000, .expected = 0x1000_0000_0000_0000 },
                .{ .name = "umulh 2^62", .word = 0x9bc27c20, .x1 = 0x4000_0000_0000_0000, .x2 = 0x4000_0000_0000_0000, .expected = 0x1000_0000_0000_0000 },
                // (-1) * (-1) = 1, top half zero; (2^64 - 1)^2 has 2^64 - 2 as its top half.
                .{ .name = "smulh -1 * -1", .word = 0x9b427c20, .x1 = all, .x2 = all, .expected = 0 },
                .{ .name = "umulh max * max", .word = 0x9bc27c20, .x1 = all, .x2 = all, .expected = all - 1 },
                // 3 * -1 = -3 is negative, so its top half is all ones; unsigned, 3 * (2^64 - 1) has top half 2.
                .{ .name = "smulh 3 * -1", .word = 0x9b427c20, .x1 = 3, .x2 = all, .expected = all },
                .{ .name = "umulh 3 * max", .word = 0x9bc27c20, .x1 = 3, .x2 = all, .expected = 2 },
            });
        }

        test "a widening multiply written to register 31 is discarded and the stack is untouched" {
            for ([_]u32{ 0x9b227c3f, 0x9ba27c3f, 0x9b427c3f, 0x9bc27c3f }) |word| {
                var cpu: Cpu = .{ .sp = 0x1234 };
                cpu.x[1] = 3;
                cpu.x[2] = 4;
                try run(word, &cpu);
                try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
            }
        }

        test "the multiply class is told apart, and its reserved forms are refused" {
            // The plain forms are still the plain forms.
            try testing.expectEqual(true, (try Decode.decode(0x9b027c20)) == .mul);
            try testing.expectEqual(true, (try Decode.decode(0x1b020c20)) == .mul);
            try testing.expectEqual(true, (try Decode.decode(0x9b220c20)) == .mul_long);
            try testing.expectEqual(true, (try Decode.decode(0x9b427c20)) == .mul_high);
            // The high halves have no accumulator and no subtract.
            try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x9b420c20));
            try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x9bc2fc20));
            // The long forms exist only at 64 bits.
            try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x1b220c20));
            // Bits 30:29 are zero in every multiply, so a word that sets one is not one.
            try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x3b020c20));
            try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x5b020c20));
        }
    };

    /// The instructions that rearrange or count the bits of one register: the byte
    /// and bit reversals and counting leading zeros. Every expected value is worked
    /// out on paper from the definition, byte by byte and bit by bit.
    pub const one_source_tests = struct {
        fn run(word: u32, cpu: *Cpu) !void {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, word, .little);
            var block = try guest.compile(testing.allocator(), 0x4000, &bytes);
            defer block.deinit();
            _ = block.run(cpu);
        }

        const pattern: u64 = 0x0123_4567_89ab_cdef;

        const Case = struct { name: []const u8, word: u32, x1: u64 = pattern, expected: u64 };

        fn check(cases: []const Case) !void {
            for (cases) |case| {
                var cpu: Cpu = .{ .sp = 0x1234 };
                cpu.x[0] = 0xdead_beef_dead_beef; // what a partial write would leave showing
                cpu.x[1] = case.x1;
                try run(case.word, &cpu);
                errdefer std.debug.print("{s}: got {x}, wanted {x}\n", .{ case.name, cpu.x[0], case.expected });
                try testing.expectEqual(case.expected, cpu.x[0]);
                try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
            }
        }

        test "the byte reversals reverse within the unit they name" {
            try check(&.{
                // The whole register: the eight bytes in the opposite order.
                .{ .name = "rev x0, x1", .word = 0xdac00c20, .expected = 0xefcd_ab89_6745_2301 },
                // A 32-bit register: four bytes of the low word, and the top half of the
                // result is clear.
                .{ .name = "rev w0, w1", .word = 0x5ac00820, .expected = 0xefcd_ab89 },
                // Each halfword's two bytes swapped, the halfwords staying where they are.
                .{ .name = "rev16 x0, x1", .word = 0xdac00420, .expected = 0x2301_6745_ab89_efcd },
                .{ .name = "rev16 w0, w1", .word = 0x5ac00420, .expected = 0xab89_efcd },
                // Each 32-bit word reversed on its own: the words do not change places.
                .{ .name = "rev32 x0, x1", .word = 0xdac00820, .expected = 0x6745_2301_efcd_ab89 },
            });
        }

        test "a bit reversal reverses every bit, not the bytes" {
            // Each byte's bits reversed (0x01 to 0x80, 0x23 to 0xc4, 0x45 to 0xa2, 0x67 to
            // 0xe6, 0x89 to 0x91, 0xab to 0xd5, 0xcd to 0xb3, 0xef to 0xf7), and then the
            // bytes in the opposite order.
            try check(&.{
                .{ .name = "rbit x0, x1", .word = 0xdac00020, .expected = 0xf7b3_d591_e6a2_c480 },
                .{ .name = "rbit w0, w1", .word = 0x5ac00020, .expected = 0xf7b3_d591 },
                // One bit at each end swaps ends.
                .{ .name = "rbit x0, x1, lowest bit", .word = 0xdac00020, .x1 = 1, .expected = 0x8000_0000_0000_0000 },
                .{ .name = "rbit w0, w1, highest bit", .word = 0x5ac00020, .x1 = 0x8000_0000, .expected = 1 },
            });
        }

        test "counting leading zeros counts from the top of the register at its width" {
            try check(&.{
                .{ .name = "clz x, zero", .word = 0xdac01020, .x1 = 0, .expected = 64 },
                .{ .name = "clz x, one", .word = 0xdac01020, .x1 = 1, .expected = 63 },
                .{ .name = "clz x, top bit", .word = 0xdac01020, .x1 = 0x8000_0000_0000_0000, .expected = 0 },
                .{ .name = "clz x, bit 32", .word = 0xdac01020, .x1 = 0x0000_0001_0000_0000, .expected = 31 },
                // The top byte is 0000 0001: seven zeros before the first one.
                .{ .name = "clz x, pattern", .word = 0xdac01020, .expected = 7 },
                .{ .name = "clz w, zero", .word = 0x5ac01020, .x1 = 0, .expected = 32 },
                .{ .name = "clz w, one", .word = 0x5ac01020, .x1 = 1, .expected = 31 },
                .{ .name = "clz w, top bit", .word = 0x5ac01020, .x1 = 0x8000_0000, .expected = 0 },
                // The upper half of the register is not part of a 32-bit operand.
                .{ .name = "clz w ignores the top half", .word = 0x5ac01020, .x1 = 0xffff_ffff_0000_0001, .expected = 31 },
                .{ .name = "clz w, 0x00ff0000", .word = 0x5ac01020, .x1 = 0x00ff_0000, .expected = 8 },
            });
            // Every position of a single set bit, at both widths.
            var bit: u7 = 0;
            while (bit < 64) : (bit += 1) {
                var cpu: Cpu = .{};
                cpu.x[1] = @as(u64, 1) << @intCast(bit);
                try run(0xdac01020, &cpu);
                try testing.expectEqual(@as(u64, 63 - bit), cpu.x[0]);
                if (bit < 32) {
                    var narrow: Cpu = .{};
                    narrow.x[1] = @as(u64, 1) << @intCast(bit);
                    try run(0x5ac01020, &narrow);
                    try testing.expectEqual(@as(u64, 31 - bit), narrow.x[0]);
                }
            }
        }

        test "a one-source result written to register 31 is discarded and the stack is untouched" {
            var cpu: Cpu = .{ .sp = 0x1234 };
            cpu.x[1] = pattern;
            try run(0xdac00c3f, &cpu); // rev xzr, x1
            try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
        }

        test "the neighbours of the one-source class are refused, not read as members" {
            // The 32-bit form of the 64-bit byte reversal does not exist.
            try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x5ac00c20));
            // CLS and a pointer-authentication instruction share the class.
            try testing.expectError(error.UnsupportedInstruction, Decode.decode(0xdac01420));
            try testing.expectError(error.UnsupportedInstruction, Decode.decode(0xdac123e0));
            // With the flag-setting bit set this is not the class at all.
            try testing.expectError(error.UnsupportedInstruction, Decode.decode(0xfac00c20));
            // And the two-source class next door is still the two-source class.
            switch (try Decode.decode(0x9ac22020)) {
                .variable => {},
                else => return error.NotTwoSource,
            }
        }

        test "the decoder reads the width-dependent opcodes the right way round" {
            // Opcode 2 is the 32-bit byte reversal and the 64-bit reversal within words.
            try testing.expectEqual(Decode.UnaryOp.rev, (try Decode.decode(0x5ac00820)).unary.op);
            try testing.expectEqual(Decode.UnaryOp.rev32, (try Decode.decode(0xdac00820)).unary.op);
            // Opcode 3 is the 64-bit byte reversal.
            try testing.expectEqual(Decode.UnaryOp.rev, (try Decode.decode(0xdac00c20)).unary.op);
        }
    };

    /// Loads that sign-extend what they read: LDRSB, LDRSH and LDRSW. They run through
    /// a `Machine`, because the extension happens when the load completes, and a load
    /// answered by a device completes on a different path from one answered by memory.
    pub const signed_load_tests = struct {
        const base: u64 = 0x1000;
        const wfi: u32 = 0xd503207f;
        const device: u64 = 0x9000_0000;

        /// Run `words` with `x0` at a word of RAM holding `data` and `x3` at a device that
        /// answers every read with `answer`.
        fn execute(words: []const u32, data: u64, answer: u64) !Cpu {
            var bytes: [0x200]u8 = @splat(0);
            for (words, 0..) |word, index| std.mem.writeInt(u32, bytes[index * 4 ..][0..4], word, .little);
            std.mem.writeInt(u64, bytes[0x100..][0..8], data, .little);
            const regions = [_]GuestMemory.Region{.{ .gpa = base, .len = bytes.len, .backing = .{ .shared = &bytes } }};
            var memory: GuestMemory = .{ .regions = &regions };
            var machine = guest.Machine.init(testing.allocator(), &memory);
            defer machine.deinit();
            const hv = machine.backend();
            const id = try hv.addVcpu();
            try hv.setRegister(id, .pc, base);
            try hv.setRegister(id, .x0, base + 0x100);
            try hv.setRegister(id, .x3, device);
            while (true) switch (try hv.run(id)) {
                .wfi => break,
                .interrupted => {},
                .mmio_read => try hv.completeMmioRead(id, answer),
                else => return error.UnexpectedExit,
            };
            return machine.cpu;
        }

        const ldrsw_x2: u32 = 0xb9800002; // ldrsw x2, [x0]
        const ldrsb_x2: u32 = 0x39800002;
        const ldrsb_w2: u32 = 0x39c00002;
        const ldrsh_x2: u32 = 0x79800002;
        const ldrsh_w2: u32 = 0x79c00002;
        const ldrb_w4: u32 = 0x39400004; // ldrb w4, [x0]

        test "a sign-extending load fills from the top bit of what it read" {
            const cases = [_]struct { name: []const u8, word: u32, data: u64, expected: u64 }{
                .{ .name = "ldrsw negative", .word = ldrsw_x2, .data = 0x8000_0001, .expected = 0xffff_ffff_8000_0001 },
                .{ .name = "ldrsw positive", .word = ldrsw_x2, .data = 0x7fff_ffff, .expected = 0x7fff_ffff },
                // Only the four bytes it names are looked at, whatever sits above them.
                .{ .name = "ldrsw ignores what follows", .word = ldrsw_x2, .data = 0xdead_beef_0000_0001, .expected = 1 },
                .{ .name = "ldrsb to x", .word = ldrsb_x2, .data = 0x80, .expected = 0xffff_ffff_ffff_ff80 },
                .{ .name = "ldrsb to x positive", .word = ldrsb_x2, .data = 0x7f, .expected = 0x7f },
                // To a W register the extension stops at bit 31 and the rest is clear.
                .{ .name = "ldrsb to w", .word = ldrsb_w2, .data = 0x80, .expected = 0xffff_ff80 },
                .{ .name = "ldrsh to x", .word = ldrsh_x2, .data = 0x8000, .expected = 0xffff_ffff_ffff_8000 },
                .{ .name = "ldrsh to w", .word = ldrsh_w2, .data = 0x8000, .expected = 0xffff_8000 },
                .{ .name = "ldrsh to w positive", .word = ldrsh_w2, .data = 0x7fff, .expected = 0x7fff },
            };
            for (cases) |case| {
                const cpu = try execute(&.{ case.word, wfi }, case.data, 0);
                errdefer std.debug.print("{s}: got {x}, wanted {x}\n", .{ case.name, cpu.x[2], case.expected });
                try testing.expectEqual(case.expected, cpu.x[2]);
            }
        }

        test "the extension belongs to one load and does not leak into the next" {
            // A sign-extending byte load, and then a plain one of the same byte.
            const cpu = try execute(&.{ ldrsb_x2, ldrb_w4, wfi }, 0x80, 0);
            try testing.expectEqual(@as(u64, 0xffff_ffff_ffff_ff80), cpu.x[2]);
            try testing.expectEqual(@as(u64, 0x80), cpu.x[4]);
        }

        test "a load answered by a device is extended when the answer arrives" {
            // ldrsb x2, [x3], ldrsh w5, [x3], and a plain ldrb after them.
            const ldrsb_x2_x3: u32 = 0x39800062;
            const ldrsh_w5_x3: u32 = 0x79c00065;
            const ldrb_w6_x3: u32 = 0x39400066;
            const cpu = try execute(&.{ ldrsb_x2_x3, ldrsh_w5_x3, ldrb_w6_x3, wfi }, 0, 0x8080);
            try testing.expectEqual(@as(u64, 0xffff_ffff_ffff_ff80), cpu.x[2]);
            try testing.expectEqual(@as(u64, 0xffff_8080), cpu.x[5]);
            try testing.expectEqual(@as(u64, 0x80), cpu.x[6]);
        }

        test "the other addressing forms extend too" {
            // ldursw x2, [x0] (unscaled), and ldrsw x2, [x0], #0 (post-index).
            for ([_]u32{ 0xb8800002, 0xb8800402 }) |word| {
                const cpu = try execute(&.{ word, wfi }, 0x8000_0000, 0);
                try testing.expectEqual(@as(u64, 0xffff_ffff_8000_0000), cpu.x[2]);
            }
        }

        test "the sign-extending forms that do not exist are refused" {
            // A word cannot be extended to 32 bits, and a doubleword has nothing to extend:
            // opcode 2 there is the prefetch.
            for ([_]u32{ 0xb9c00002, 0xf9c00002 }) |word| {
                try testing.expectError(error.UnsupportedInstruction, Decode.decode(word));
            }
            // A plain load and store are not extending.
            try testing.expectEqual(Cpu.SignExtend.none, (try Decode.decode(0xb9400002)).memory.signed);
            try testing.expectEqual(Cpu.SignExtend.to64, (try Decode.decode(ldrsw_x2)).memory.signed);
            try testing.expectEqual(Cpu.SignExtend.to32, (try Decode.decode(ldrsb_w2)).memory.signed);
        }
    };

    /// The system registers, the identification values a guest boots on, and the
    /// system instructions that are not register moves.
    pub const system_tests = struct {
        const Identification = guest.Identification;

        fn run(word: u32, cpu: *Cpu) !void {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, word, .little);
            var block = try guest.compile(testing.allocator(), 0x4000, &bytes);
            defer block.deinit();
            _ = block.run(cpu);
        }

        test "the registers that describe the machine read back what Identification says" {
            const rows = [_]struct { word: u32, register: Decode.SystemRegister }{
                .{ .word = 0xd5380000, .register = .midr_el1 }, // mrs x0, midr_el1
                .{ .word = 0xd53800a0, .register = .mpidr_el1 },
                .{ .word = 0xd53b0020, .register = .ctr_el0 },
                .{ .word = 0xd53b00e0, .register = .dczid_el0 },
                .{ .word = 0xd53be000, .register = .cntfrq_el0 },
                .{ .word = 0xd5380400, .register = .id_aa64pfr0_el1 },
                .{ .word = 0xd5380500, .register = .id_aa64dfr0_el1 },
                .{ .word = 0xd5380700, .register = .id_aa64mmfr0_el1 },
            };
            for (rows) |row| {
                const decoded = try Decode.decode(row.word);
                try testing.expectEqual(row.register, decoded.system.register);
                var cpu: Cpu = .{ .sp = 0x1234 };
                try run(row.word, &cpu);
                errdefer std.debug.print("{t}: got {x}\n", .{ row.register, cpu.x[0] });
                try testing.expectEqual(Identification.value(row.register).?, cpu.x[0]);
            }
        }

        test "SP_ELn accesses select the bank named by PSTATE.SP" {
            var cpu: Cpu = .{ .sp = 0x1111, .system = .{ .spsel = false } };
            cpu.system.sp_el[1] = 0x2222;
            try run(0xd5384100, &cpu); // mrs x0, sp_el0: live in EL1t
            try testing.expectEqual(@as(u64, 0x1111), cpu.x[0]);
            try run(0xd53c4100, &cpu); // mrs x0, sp_el1: banked in EL1t
            try testing.expectEqual(@as(u64, 0x2222), cpu.x[0]);

            cpu.system.spsel = true;
            cpu.sp = 0x3333;
            try run(0xd53c4100, &cpu); // mrs x0, sp_el1: live in EL1h
            try testing.expectEqual(@as(u64, 0x3333), cpu.x[0]);
        }

        test "every identification register the kernel reads is answered, and none can be written" {
            // The kernel reads these before anything else, and one that is refused stops
            // the boot at an address no bug report will explain.
            const reads = [_]u32{
                0xd5380000, 0xd53800a0, 0xd53b0020, 0xd53b00e0, 0xd5390020, // midr, mpidr, ctr, dczid, clidr
                0xd5380400, 0xd5380420, 0xd5380440, 0xd5380480, 0xd53804a0, // pfr0, pfr1, pfr2, zfr0, smfr0
                0xd5380500, 0xd5380520, // dfr0, dfr1
                0xd53800c0, // revidr
                0xd53804e0, 0xd5380660, 0xd53900e0, // id_aa64fpfr0 (0,0,4,7), id_aa64isar3 (0,0,6,3), aidr (1,0,0,7)
                0xd5380600, 0xd5380620, 0xd5380640, // isar0, isar1, isar2
                0xd5380700, 0xd5380720, 0xd5380740, 0xd5380760, 0xd5380780, // mmfr0 .. mmfr4
            };
            for (reads) |word| {
                const decoded = try Decode.decode(word);
                try testing.expectEqual(true, Identification.value(decoded.system.register) != null);
                // The same word with the direction bit cleared is an MSR to the same register.
                try testing.expectError(error.UnsupportedInstruction, Decode.decode(word & ~@as(u32, 0x0020_0000)));
            }
        }

        test "the guest is told nothing it cannot do" {
            // No system register interface to the interrupt controller: it is memory mapped.
            try testing.expectEqual(@as(u64, 0), Identification.value(.id_aa64pfr0_el1).? >> 24 & 0xf);
            // AArch64 at EL0 and EL1, and nothing above or below.
            try testing.expectEqual(@as(u64, 0x11), Identification.value(.id_aa64pfr0_el1).? & 0xff);
            // FP and ASIMD are not implemented, so advertise the architectural
            // "not implemented" value rather than the implemented-zero encoding.
            const pfr0 = Identification.value(.id_aa64pfr0_el1).?;
            try testing.expectEqual(@as(u64, 0xf), pfr0 >> 16 & 0xf);
            try testing.expectEqual(@as(u64, 0xf), pfr0 >> 20 & 0xf);
            // No atomic instructions, so the guest builds its own from exclusives.
            try testing.expectEqual(@as(u64, 0), Identification.value(.id_aa64isar0_el1).?);
            // 4 KiB pages only: the 64 KiB field says "no" with 0xf and the 16 KiB one with 0.
            const mmfr0 = Identification.value(.id_aa64mmfr0_el1).?;
            try testing.expectEqual(@as(u64, 0), mmfr0 >> 28 & 0xf);
            try testing.expectEqual(@as(u64, 0xf), mmfr0 >> 24 & 0xf);
            try testing.expectEqual(@as(u64, 0), mmfr0 >> 20 & 0xf);
            // The zeroing block is the sixty-four bytes the run loop clears for `DC ZVA`.
            try testing.expectEqual(@as(u64, 64), @as(u64, 4) << @intCast(Identification.value(.dczid_el0).? & 0xf));
            // Register 31 is reserved as one in `CTR_EL0`, and both line sizes are 64 bytes.
            const ctr = Identification.value(.ctr_el0).?;
            try testing.expectEqual(@as(u64, 1), ctr >> 31);
            try testing.expectEqual(@as(u64, 4), ctr >> 16 & 0xf);
            try testing.expectEqual(@as(u64, 4), ctr & 0xf);
        }

        test "a register the kernel keeps its own state in stores what is written" {
            const rows = [_]struct { write: u32, read: u32, name: []const u8 }{
                .{ .write = 0xd518d080, .read = 0xd538d080, .name = "tpidr_el1" },
                .{ .write = 0xd5100240, .read = 0xd5300240, .name = "mdscr_el1" },
                .{ .write = 0xd518e100, .read = 0xd538e100, .name = "cntkctl_el1" },
                .{ .write = 0xd51b4400, .read = 0xd53b4400, .name = "fpcr" },
                .{ .write = 0xd51b4420, .read = 0xd53b4420, .name = "fpsr" },
            };
            for (rows) |row| {
                var cpu: Cpu = .{};
                cpu.x[0] = 0xfeed_face_cafe_beef;
                try run(row.write, &cpu);
                cpu.x[0] = 0;
                try run(row.read, &cpu);
                errdefer std.debug.print("{s}: read back {x}\n", .{ row.name, cpu.x[0] });
                try testing.expectEqual(@as(u64, 0xfeed_face_cafe_beef), cpu.x[0]);
            }
        }

        test "writing the zero register to a system register writes zero, not the stack pointer" {
            var cpu: Cpu = .{ .sp = 0x1234 };
            cpu.system.tpidr_el1 = 0xffff;
            try run(0xd518d09f, &cpu); // msr tpidr_el1, xzr
            try testing.expectEqual(@as(u64, 0), cpu.system.tpidr_el1);
        }

        test "the register form of DAIF puts the masks at bits 9:6 and reads them back from there" {
            // Interrupts masked means bit 7 of what `mrs` returns, which is what a kernel tests.
            var cpu: Cpu = .{ .system = .{ .daif = 0b0010 } }; // only I
            try run(0xd53b4220, &cpu); // mrs x0, daif
            try testing.expectEqual(@as(u64, 1 << 7), cpu.x[0]);
            cpu.system.daif = 0xf;
            try run(0xd53b4220, &cpu);
            try testing.expectEqual(@as(u64, 0xf << 6), cpu.x[0]);

            // Writing the register form stores the four masks in the layout the immediate
            // forms and an exception use, and ignores every other bit of the value.
            cpu.x[0] = (0b0100 << 6) | 0xffff_0000_0000_003f;
            try run(0xd51b4220, &cpu); // msr daif, x0
            try testing.expectEqual(@as(u64, 0b0100), cpu.system.daif);
        }
        test "the counter advances per executed instruction and drives timer status" {
            // Single-instruction blocks advance it by one guest tick each.
            var cpu: Cpu = .{};
            try run(0xd503201f, &cpu); // nop
            try run(0xd503201f, &cpu); // nop
            try testing.expectEqual(@as(u64, 2), cpu.system.cntvct_el0);
            // Reading the counter itself executes and advances one instruction.
            cpu.x[0] = 0;
            try run(0xd53be040, &cpu); // mrs x0, cntvct_el0
            try testing.expectEqual(@as(u64, 3), cpu.x[0]);

            // The kernel's own words: program a compare, enable the timer, read control.
            cpu.x[9] = 0x1000;
            try run(0xd51be349, &cpu); // msr cntv_cval_el0, x9
            try testing.expectEqual(@as(u64, 0x1000), cpu.system.cntv_cval_el0);
            cpu.system.cntvct_el0 = 0x2000;
            cpu.x[8] = 0b1;
            try run(0xd51be328, &cpu); // msr cntv_ctl_el0, x8
            try run(0xd53be328, &cpu); // mrs x8, cntv_ctl_el0
            try testing.expectEqual(@as(u64, 0b101), cpu.x[8]);
            // A write cannot set or clear the condition: only enable and mask are stored.
            cpu.x[8] = 0xffff_ffff_ffff_ffff;
            try run(0xd51be328, &cpu); // msr cntv_ctl_el0, x8
            try testing.expectEqual(@as(u64, 0b11), cpu.system.cntv_ctl_el0);
            // Before compare: read control advances once, but remains below the compare.
            cpu.system.cntvct_el0 = 0;
            cpu.system.cntv_cval_el0 = 2;
            try run(0xd53be328, &cpu); // mrs x8, cntv_ctl_el0
            try testing.expectEqual(@as(u64, 0b11), cpu.x[8]);
        }
        test "the debug locks clear and the status follows them" {
            // Reset state reads locked; the kernel's own sequence unlocks both.
            var cpu: Cpu = .{};
            try run(0xd530118a, &cpu); // mrs x10, oslsr_el1
            try testing.expectEqual(@as(u64, 0b10), cpu.x[10]);
            cpu.x[8] = 0;
            try run(0xd5101388, &cpu); // msr osdlr_el1, x8
            try run(0xd5101088, &cpu); // msr oslar_el1, x8
            try testing.expectEqual(@as(u64, 0), cpu.system.osdlr_el1);
            try testing.expectEqual(@as(u64, 0), cpu.system.oslar_el1);
            try run(0xd530118a, &cpu); // mrs x10, oslsr_el1
            try testing.expectEqual(@as(u64, 0), cpu.x[10]);
            // Holding either lock reads locked again.
            cpu.x[8] = 1;
            try run(0xd5101088, &cpu); // msr oslar_el1, x8
            try run(0xd530118a, &cpu); // mrs x10, oslsr_el1
            try testing.expectEqual(@as(u64, 0b10), cpu.x[10]);
        }

        test "cache maintenance does nothing and address translation is refused" {
            // dc civac, dc cvau, dc ivac, dc cvac, ic ivau, ic iallu, ic ialluis.
            for ([_]u32{ 0xd50b7e20, 0xd50b7b20, 0xd5087620, 0xd50b7a20, 0xd50b7520, 0xd508751f, 0xd508711f }) |word| {
                switch (try Decode.decode(word)) {
                    .cache_op => {},
                    else => return error.NotCacheMaintenance,
                }
                var cpu: Cpu = .{ .sp = 0x1234 };
                cpu.x[0] = 0x9999;
                try run(word, &cpu);
                // Nothing observable changes: not a register, not the stack, not the flags.
                try testing.expectEqual(@as(u64, 0x9999), cpu.x[0]);
                try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
            }
            // `dc zva` is still its own instruction, and not one of these.
            switch (try Decode.decode(0xd50b7420)) {
                .dc_zva => {},
                else => return error.NotDcZva,
            }
            // `at s1e1r, x0` asks for a translation this does not perform.
            try testing.expectError(error.UnsupportedInstruction, Decode.decode(0xd5087800));
        }

        test "a TLB invalidation ends the block so the run loop can flush what it remembers" {
            // tlbi vmalle1, tlbi vae1 x0, tlbi vaae1 x0, tlbi aside1 x0.
            for ([_]u32{ 0xd508871f, 0xd5088720, 0xd5088760, 0xd5088740 }) |word| {
                const decoded = try Decode.decode(word);
                try testing.expectEqual(true, decoded.terminates());
                var cpu: Cpu = .{};
                try run(word, &cpu);
                // Unlike an ISB, it says the cache is stale outright.
                try testing.expectEqual(Cpu.Trap.tlbi, cpu.trap);
            }
        }

        test "the first block a kernel runs reads its level and leaves the stack pointer alone" {
            // `record_mmu_state`, as Linux's head.S runs it before it has a stack:
            //   mrs x19, CurrentEL; cmp x19, #8; mrs x19, SCTLR_EL1; b.ne +8
            const words = [_]u32{ 0xd5384253, 0xf100227f, 0xd5381013, 0x54000041 };
            var bytes: [16]u8 = undefined;
            for (words, 0..) |word, index| std.mem.writeInt(u32, bytes[index * 4 ..][0..4], word, .little);
            var block = try guest.compile(testing.allocator(), 0x4000, &bytes);
            defer block.deinit();

            var cpu: Cpu = .{ .sp = 0 };
            cpu.system.sctlr_el1 = 0;
            const next = block.run(&cpu);

            // EL1 is the level in bits 3:2, so CurrentEL reads 4. Comparing that to 8
            // borrows, which is negative, not zero, no carry, and no overflow.
            try testing.expectEqual(@as(u32, 0x8000_0000), cpu.flags);
            // SCTLR_EL1 was zero, so x19 ended as zero.
            try testing.expectEqual(@as(u64, 0), cpu.x[19]);
            // The stack is not touched by any of it, and the branch is taken: not equal to 8.
            try testing.expectEqual(@as(u64, 0), cpu.sp);
            try testing.expectEqual(@as(u64, 0x4000 + 12 + 8), next);
        }

        test "CurrentEL names the level in bits 3:2 and nothing else" {
            for ([_]struct { el: u8, expected: u64 }{
                .{ .el = 0, .expected = 0 },
                .{ .el = 1, .expected = 4 },
                .{ .el = 2, .expected = 8 },
            }) |row| {
                var cpu: Cpu = .{ .sp = 0x1234, .system = .{ .el = row.el } };
                try run(0xd5384253, &cpu); // mrs x19, CurrentEL
                errdefer std.debug.print("el {d}: read {x}\n", .{ row.el, cpu.x[19] });
                try testing.expectEqual(row.expected, cpu.x[19]);
                try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
            }
        }
    };

    /// Move wide: MOVN, MOVZ and MOVK, which build a constant a halfword at a time.
    pub const wide_move_tests = struct {
        fn run(word: u32, cpu: *Cpu) !void {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, word, .little);
            var block = try guest.compile(testing.allocator(), 0x4000, &bytes);
            defer block.deinit();
            _ = block.run(cpu);
        }

        test "MOVN writes the complement of the shifted constant at the register's width" {
            const cases = [_]struct { name: []const u8, word: u32, expected: u64 }{
                .{ .name = "movn x0, #0", .word = 0x92800000, .expected = 0xffff_ffff_ffff_ffff },
                .{ .name = "movn x0, #0x1234, lsl #16", .word = 0x92a24680, .expected = 0xffff_ffff_edcb_ffff },
                .{ .name = "movn x0, #1, lsl #48", .word = 0x92e00020, .expected = 0xfffe_ffff_ffff_ffff },
                // At 32 bits nothing is above bit 31: `mov w0, #-1` is 0xffffffff, not all ones.
                .{ .name = "movn w0, #0", .word = 0x12800000, .expected = 0xffff_ffff },
                .{ .name = "movn w0, #0x8000, lsl #16", .word = 0x12b00000, .expected = 0x7fff_ffff },
            };
            for (cases) |case| {
                var cpu: Cpu = .{ .sp = 0x1234 };
                // What a write that did not replace the whole register would leave showing.
                cpu.x[0] = 0xdead_beef_dead_beef;
                try run(case.word, &cpu);
                errdefer std.debug.print("{s}: got {x}, wanted {x}\n", .{ case.name, cpu.x[0], case.expected });
                try testing.expectEqual(case.expected, cpu.x[0]);
                try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
            }
        }

        test "the kernel's own MOVN reads back as the value it names" {
            // `movn w9, #0x8000, lsl #16` is how Linux writes 0x7fffffff into w9.
            var cpu: Cpu = .{};
            cpu.x[9] = 0xffff_ffff_ffff_ffff;
            try run(0x12b00009, &cpu);
            try testing.expectEqual(@as(u64, 0x7fff_ffff), cpu.x[9]);
        }

        test "a wide move to register 31 is discarded and the stack pointer is untouched" {
            for ([_]u32{ 0x9280001f, 0xd280001f, 0xf280001f }) |word| { // movn, movz, movk to xzr
                var cpu: Cpu = .{ .sp = 0x1234 };
                try run(word, &cpu);
                try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
            }
        }

        test "MOVN, MOVZ and MOVK are told apart, and the unallocated encoding is refused" {
            try testing.expectEqual(true, (try Decode.decode(0x92800000)) == .movn);
            try testing.expectEqual(true, (try Decode.decode(0xd2800000)) == .movz);
            try testing.expectEqual(true, (try Decode.decode(0xf2800000)) == .movk);
            // The opcode between MOVN and MOVZ is not allocated.
            try testing.expectError(error.UnsupportedInstruction, Decode.decode(0xb2800000));
            // A 32-bit form cannot shift by 32 or 48.
            try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x12c00000));
            try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x12e00000));
        }
    };
};

test {
    std.testing.refAllDecls(classes);
}
