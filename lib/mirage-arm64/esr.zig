//! Taking apart an exception syndrome.
//!
//! KVM decodes a memory access that left the guest and reports where it went, how
//! wide it was and whether it was a write. Hypervisor.framework does not. It hands
//! back the raw syndrome register and leaves the reading of it to the VMM, so this
//! is the whole difference between the two backends.
//!
//! Field positions are from the Arm Architecture Reference Manual, `ESR_EL2`. They
//! are named here rather than written as shifts at the use site, because a syndrome
//! read one bit out decodes as a plausible access to the wrong address.

const std = @import("std");
const testing = @import("mirage-testing");
const Size = @import("mirage-device").Size;

/// `EC`, the exception class, in the top six bits.
pub const class_wf = 0x01;
pub const class_hvc = 0x16;
pub const class_instruction_abort = 0x20;
pub const class_data_abort = 0x24;
/// A system register the hypervisor was asked to see.
pub const class_system_register = 0x18;

pub const DataAbort = struct {
    /// `ISV`. The hardware sets this when it could decode the access. Without it the
    /// width and the register below mean nothing, and the access cannot be served.
    valid: bool,
    write: bool,
    size: Size,
    /// `SRT`, the register the value came from or goes to.
    register: u5,
    /// `SSE`. A narrow load that has to be widened with its sign.
    sign_extend: bool,
    /// `SF`. The destination is the full 64 bit register.
    sixty_four: bool,
};

/// A trapped `msr` or `mrs`. The five fields name the register the way the
/// instruction encoding does, and together they identify exactly one.
pub const SystemRegister = struct {
    op0: u2,
    op1: u3,
    crn: u4,
    crm: u4,
    op2: u3,
    /// The register the value comes from or goes to. 31 is the zero register.
    transfer: u5,
    write: bool,

    /// The debug and trace space. A machine with no debug hardware can ignore a
    /// write here and answer a read with zero.
    pub fn debug(self: SystemRegister) bool {
        return self.op0 == 2;
    }
};

pub const Exception = union(enum) {
    data_abort: DataAbort,
    system_register: SystemRegister,
    /// The number the guest passed to `hvc`, which is how it asks for PSCI.
    hvc: u16,
    wfi,
    wfe,
    /// An exception class this code does not handle. Reported rather than guessed
    /// at, because guessing runs the guest forward over an access that never
    /// happened.
    unhandled: u6,
};

pub fn class(esr: u64) u6 {
    return @truncate(esr >> 26);
}

pub fn decode(esr: u64) Exception {
    return switch (class(esr)) {
        class_data_abort => .{ .data_abort = .{
            .valid = esr & (1 << 24) != 0,
            .write = esr & (1 << 6) != 0,
            .size = switch (@as(u2, @truncate(esr >> 22))) {
                0 => .byte,
                1 => .half,
                2 => .word,
                3 => .double,
            },
            .register = @truncate(esr >> 16),
            .sign_extend = esr & (1 << 21) != 0,
            .sixty_four = esr & (1 << 15) != 0,
        } },
        class_system_register => .{
            .system_register = .{
                .op0 = @truncate(esr >> 20),
                .op2 = @truncate(esr >> 17),
                .op1 = @truncate(esr >> 14),
                .crn = @truncate(esr >> 10),
                .transfer = @truncate(esr >> 5),
                .crm = @truncate(esr >> 1),
                // The lowest bit says which way the value went, and a read is one.
                .write = esr & 1 == 0,
            },
        },
        class_hvc => .{ .hvc = @truncate(esr) },
        // One class covers both, and the lowest bit of the syndrome separates them.
        class_wf => if (esr & 1 == 0) .wfi else .wfe,
        else => |found| .{ .unhandled = found },
    };
}
/// Build a data abort syndrome the way the hardware would, so a test says what it
/// means rather than carrying a magic number.
fn dataAbort(args: struct {
    size: u2,
    register: u5,
    write: bool,
    valid: bool = true,
    sign_extend: bool = false,
    sixty_four: bool = false,
}) u64 {
    return (@as(u64, class_data_abort) << 26) |
        (1 << 25) |
        (@as(u64, @intFromBool(args.valid)) << 24) |
        (@as(u64, args.size) << 22) |
        (@as(u64, @intFromBool(args.sign_extend)) << 21) |
        (@as(u64, args.register) << 16) |
        (@as(u64, @intFromBool(args.sixty_four)) << 15) |
        (@as(u64, @intFromBool(args.write)) << 6) |
        // Translation fault at level 0, which is what an access to memory the guest
        // was never given looks like.
        0x04;
}

test "a word sized store decodes as a write of that width from that register" {
    const abort = decode(dataAbort(.{ .size = 2, .register = 3, .write = true }));

    try testing.expectEqual(Size.word, abort.data_abort.size);
    try testing.expectEqual(@as(u5, 3), abort.data_abort.register);
    try std.testing.expect(abort.data_abort.write);
}

test "every access width the field can hold decodes to a size" {
    const widths = [_]struct { encoded: u2, size: Size }{
        .{ .encoded = 0, .size = .byte },
        .{ .encoded = 1, .size = .half },
        .{ .encoded = 2, .size = .word },
        .{ .encoded = 3, .size = .double },
    };
    for (widths) |each| {
        const abort = decode(dataAbort(.{ .size = each.encoded, .register = 0, .write = false }));
        try testing.expectEqual(each.size, abort.data_abort.size);
    }
}

test "a load decodes as a read" {
    const abort = decode(dataAbort(.{ .size = 3, .register = 31, .write = false }));

    try std.testing.expect(!abort.data_abort.write);
    try testing.expectEqual(@as(u5, 31), abort.data_abort.register);
}

test "a sign extending load says so, because the value has to be widened" {
    const abort = decode(dataAbort(.{ .size = 0, .register = 1, .write = false, .sign_extend = true }));
    try std.testing.expect(abort.data_abort.sign_extend);
}

test "an abort with no instruction syndrome cannot be serviced" {
    // The hardware sets this when it could not decode the access, which happens for
    // an instruction Mirage cannot emulate. Guessing at the width would corrupt the
    // guest, so the caller has to be told.
    const abort = decode(dataAbort(.{ .size = 2, .register = 0, .write = true, .valid = false }));
    try std.testing.expect(!abort.data_abort.valid);
}

test "a hypervisor call carries the number the guest passed" {
    const esr = (@as(u64, class_hvc) << 26) | (1 << 25) | 0x1234;
    try testing.expectEqual(@as(u16, 0x1234), decode(esr).hvc);
}

test "a wait for interrupt is recognised, because kvm hides it and apple does not" {
    const esr = (@as(u64, class_wf) << 26) | (1 << 25);
    try testing.expectEqual(@as(Exception, .wfi), decode(esr));
}

test "a wait for event is not a wait for interrupt" {
    // Bit 0 of the syndrome separates them.
    const esr = (@as(u64, class_wf) << 26) | (1 << 25) | 1;
    try testing.expectEqual(@as(Exception, .wfe), decode(esr));
}

test "an exception class this code does not handle is reported, not guessed at" {
    const esr = (@as(u64, 0x3f) << 26) | (1 << 25);
    try testing.expectEqual(@as(u6, 0x3f), decode(esr).unhandled);
}

test "a real trapped system register from apple silicon decodes to the right one" {
    // Captured on 2026-09-25 from a Linux guest under Hypervisor.framework, during
    // `__cpu_setup`, which every arm64 kernel runs. Apple traps this and KVM does
    // not, so the guest stopped here with nothing to say about why.
    const abort = decode(0x622807e6).system_register;

    // `OSDLR_EL1` is op0 2, op1 0, CRn 1, CRm 3, op2 4.
    try testing.expectEqual(@as(u2, 2), abort.op0);
    try testing.expectEqual(@as(u3, 0), abort.op1);
    try testing.expectEqual(@as(u4, 1), abort.crn);
    try testing.expectEqual(@as(u4, 3), abort.crm);
    try testing.expectEqual(@as(u3, 4), abort.op2);

    // `msr osdlr_el1, xzr`, so a write from the zero register.
    try std.testing.expect(abort.write);
    try testing.expectEqual(@as(u5, 31), abort.transfer);
    try std.testing.expect(abort.debug());
}

test "a read of a system register is told apart from a write" {
    // The same register, read instead of written, which is the lowest bit.
    const read = decode(0x622807e7).system_register;
    try std.testing.expect(!read.write);
}

test "a register outside the debug space is not treated as one" {
    // op0 3 is the ordinary system register space, where ignoring a write would
    // lose something the guest needs.
    const other = decode((@as(u64, class_system_register) << 26) | (1 << 25) | (3 << 20)).system_register;
    try testing.expectEqual(@as(u2, 3), other.op0);
    try std.testing.expect(!other.debug());
}
