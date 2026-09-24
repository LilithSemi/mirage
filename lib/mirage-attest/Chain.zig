//! The register value a manifest produces, and the commands that put it there.
//!
//! A register on a security chip cannot be set, only extended: its value is the hash of its old
//! value and the new digest. So a register that was extended with each measurement in order holds
//! the whole ordered history, and nothing can rewrite an earlier link without changing the value.
//! That is what makes a chain.
//!
//! Mirage loads the kernel, the initial filesystem, the command line and the tree, so Mirage is what
//! extends the register for them, the same way firmware does for the stages it loads. The guest can
//! then read the register, say what it believes its own history is, and be checked against what this
//! side measured.
//!
//! SHA-384 throughout, to match the manifest. A chip with a SHA-384 bank holds these directly, so
//! nothing is truncated on the way in.

const std = @import("std");
const testing = @import("mirage-testing");
const Manifest = @import("Manifest.zig");
const Sha384 = std.crypto.hash.sha2.Sha384;

/// How long a register in this bank is.
pub const length = Sha384.digest_length;

/// `TPM_ALG_SHA384`, which says which bank a command means. The number next to it is SHA-512, and a
/// chip told the wrong one waits for a digest of another length and refuses the command as short.
pub const algorithm = 0x000c;

/// What a register holds before anything is folded into it.
pub const zero: [length]u8 = @splat(0);

/// Command codes, and the session handle that means the authorization is an empty password.
const cc_pcr_extend = 0x0000_0182;
const cc_pcr_read = 0x0000_017e;
const st_no_sessions = 0x8001;
const st_sessions = 0x8002;
const rs_password = 0x4000_0009;

/// A command and an answer both begin with a tag, their own length, then a code.
const header_size = 10;

pub const extend_size = header_size + 4 + 4 + 9 + 4 + 2 + length;
pub const read_size = header_size + 4 + 2 + 1 + 3;

/// Fold one digest in. This is the rule the chip follows, so a caller can work out what a register
/// must hold without asking anything.
pub fn extend(value: [length]u8, digest: [length]u8) [length]u8 {
    var hash: Sha384 = .init(.{});
    hash.update(&value);
    hash.update(&digest);
    var out: [length]u8 = undefined;
    hash.final(&out);
    return out;
}

/// What a register holds after every entry of the manifest is folded into it, in order. The order is
/// part of the value, so a manifest whose entries were measured in another order gives another
/// register.
pub fn of(manifest: *const Manifest) [length]u8 {
    var value = zero;
    for (manifest.entries.items) |entry| value = extend(value, entry.digest);
    return value;
}

/// The bytes of a command that folds one digest into a register.
pub fn extendCommand(into: *[extend_size]u8, register: u32, digest: [length]u8) []const u8 {
    std.mem.writeInt(u16, into[0..2], st_sessions, .big);
    std.mem.writeInt(u32, into[2..6], extend_size, .big);
    std.mem.writeInt(u32, into[6..10], cc_pcr_extend, .big);
    std.mem.writeInt(u32, into[10..14], register, .big);
    // The authorization is one empty password, which is nine bytes of session.
    std.mem.writeInt(u32, into[14..18], 9, .big);
    std.mem.writeInt(u32, into[18..22], rs_password, .big);
    std.mem.writeInt(u16, into[22..24], 0, .big);
    into[24] = 0;
    std.mem.writeInt(u16, into[25..27], 0, .big);
    // One digest, in this bank.
    std.mem.writeInt(u32, into[27..31], 1, .big);
    std.mem.writeInt(u16, into[31..33], algorithm, .big);
    @memcpy(into[33..extend_size], &digest);
    return into[0..extend_size];
}

/// The bytes of a command that reads one register of this bank.
pub fn readCommand(into: *[read_size]u8, register: u32) []const u8 {
    std.mem.writeInt(u16, into[0..2], st_no_sessions, .big);
    std.mem.writeInt(u32, into[2..6], read_size, .big);
    std.mem.writeInt(u32, into[6..10], cc_pcr_read, .big);
    // One selection, of one bank, over three bytes of register numbers.
    std.mem.writeInt(u32, into[10..14], 1, .big);
    std.mem.writeInt(u16, into[14..16], algorithm, .big);
    into[16] = 3;
    into[17] = 0;
    into[18] = 0;
    into[19] = 0;
    // A register is one bit, counting from the lowest of the first byte.
    if (register < 24) into[17 + register / 8] = @as(u8, 1) << @intCast(register % 8);
    return into[0..read_size];
}

/// The register an answer carries, or nothing when the answer is not one this understands.
///
/// Every length in here was chosen by whatever sent the answer, so each one is checked against what
/// really arrived before it is used.
pub fn digestOf(answer: []const u8) ?[length]u8 {
    if (answer.len < header_size) return null;
    // A code other than zero means the chip refused, and a refusal carries no register.
    if (std.mem.readInt(u32, answer[6..10], .big) != 0) return null;

    var at: usize = header_size + 4; // past the counter that says how often registers changed
    if (answer.len < at + 4) return null;
    const selections = std.mem.readInt(u32, answer[at..][0..4], .big);
    at += 4;

    // The selections come back before the values, and each one is as long as it says.
    for (0..selections) |_| {
        if (selections > 8) return null;
        if (answer.len < at + 3) return null;
        const chosen = answer[at + 2];
        at += 3 + chosen;
        if (answer.len < at) return null;
    }

    if (answer.len < at + 4) return null;
    const values = std.mem.readInt(u32, answer[at..][0..4], .big);
    at += 4;
    // One register was asked for, so one value comes back. More than one means this is the answer to
    // a question somebody else asked.
    if (values != 1) return null;

    if (answer.len < at + 2) return null;
    const size = std.mem.readInt(u16, answer[at..][0..2], .big);
    at += 2;
    if (size != length) return null;
    if (answer.len < at + length) return null;

    var out: [length]u8 = undefined;
    @memcpy(&out, answer[at..][0..length]);
    return out;
}

/// Sends commands to a chip and waits for each answer.
///
/// This runs before the guest does, which is what makes waiting allowed here: nothing else needs the
/// thread yet. Once a guest is running, `mirage-device`'s relay is what carries its commands, and
/// that one never waits. `Transport` is anything with `read` and `write`.
///
/// Every wait is bounded. A chip that stopped answering must not stop a launch forever.
pub fn Session(comptime Transport: type) type {
    return struct {
        const Self = @This();

        transport: *Transport,
        /// Why the chip last refused, which is the only thing that says what it disliked. Zero until
        /// one refuses.
        refusal: u32 = 0,
        /// How many turns to give an answer. Whatever answers a chip is a program on this machine
        /// and answers in microseconds, so this is far more than enough and still not forever.
        patience: usize = 1 << 22,

        pub const Error = error{ NoAnswer, Refused, Unsendable, Disagreed, NotFresh };

        /// Send one command and give back its answer.
        pub fn ask(self: *Self, command: []const u8, into: []u8) Error![]const u8 {
            var sent: usize = 0;
            var turns: usize = 0;
            while (sent < command.len) {
                if (turns >= self.patience) return error.Unsendable;
                turns += 1;
                sent += self.transport.write(command[sent..]) catch return error.Unsendable;
            }

            var held: usize = 0;
            turns = 0;
            while (true) {
                if (turns >= self.patience) return error.NoAnswer;
                turns += 1;
                if (held == into.len) return error.NoAnswer;

                held += self.transport.read(into[held..]) catch return error.NoAnswer;
                if (held < header_size) continue;

                // An answer says how long it is, so there is no guessing about where it ends.
                const declared = std.mem.readInt(u32, into[2..6], .big);
                if (declared > into.len) return error.NoAnswer;
                if (held < declared) continue;

                const code = std.mem.readInt(u32, into[6..10], .big);
                if (code != 0) {
                    self.refusal = code;
                    return error.Refused;
                }
                return into[0..declared];
            }
        }

        /// Fold every entry of the manifest into one register, in the order it was measured, and give
        /// back what the register then holds.
        ///
        /// The register has to be empty first. A register only means something against where it
        /// started, and a guest that reads a register and a list of measurements folds the list from
        /// nothing, so a chip that was already used would make the two disagree for a reason that has
        /// nothing to do with either. Whoever starts a guest gives it a chip of its own.
        ///
        /// The register is read again at the end and checked against the fold. The chip and this side
        /// follow the same rule, so a disagreement means one of them is not the thing it claims.
        pub fn measure(self: *Self, manifest: *const Manifest, register: u32) Error![length]u8 {
            var value = try self.read(register);
            if (!std.mem.eql(u8, &value, &zero)) return error.NotFresh;

            var answer: [512]u8 = undefined;
            for (manifest.entries.items) |entry| {
                var command: [extend_size]u8 = undefined;
                _ = try self.ask(extendCommand(&command, register, entry.digest), &answer);
                value = extend(value, entry.digest);
            }

            const holds = try self.read(register);
            if (!std.mem.eql(u8, &holds, &value)) return error.Disagreed;
            return value;
        }

        /// Read one register back.
        pub fn read(self: *Self, register: u32) Error![length]u8 {
            var command: [read_size]u8 = undefined;
            var answer: [512]u8 = undefined;
            const got = try self.ask(readCommand(&command, register), &answer);
            return digestOf(got) orelse error.Refused;
        }
    };
}

test "a register holds the whole ordered history" {
    const gpa = testing.allocator();

    var forward: Manifest = .{};
    defer forward.deinit(gpa);
    try forward.add(gpa, .kernel, "kernel bytes");
    try forward.add(gpa, .initrd, "initrd bytes");

    var backward: Manifest = .{};
    defer backward.deinit(gpa);
    try backward.add(gpa, .initrd, "initrd bytes");
    try backward.add(gpa, .kernel, "kernel bytes");

    // Two manifests with the same entries in another order leave the register different, which is
    // what stops a link being moved without anybody seeing.
    try std.testing.expect(!std.mem.eql(u8, &of(&forward), &of(&backward)));

    // And the value is the fold, not the manifest's own root. The two answer different questions.
    var by_hand = zero;
    for (forward.entries.items) |entry| by_hand = extend(by_hand, entry.digest);
    try testing.expectEqualSlices(u8, &by_hand, &of(&forward));
    try std.testing.expect(!std.mem.eql(u8, &forward.root(), &of(&forward)));
}

test "an empty manifest leaves the register untouched" {
    var manifest: Manifest = .{};
    try testing.expectEqualSlices(u8, &zero, &of(&manifest));
}

test "the extend command says what it is and how long it is" {
    var digest: [length]u8 = @splat(0xab);
    var bytes: [extend_size]u8 = undefined;
    const command = extendCommand(&bytes, 4, digest);

    try testing.expectEqual(@as(usize, extend_size), command.len);
    try testing.expectEqual(@as(u32, extend_size), std.mem.readInt(u32, command[2..6], .big));
    try testing.expectEqual(@as(u32, cc_pcr_extend), std.mem.readInt(u32, command[6..10], .big));
    try testing.expectEqual(@as(u32, 4), std.mem.readInt(u32, command[10..14], .big));
    try testing.expectEqual(@as(u16, algorithm), std.mem.readInt(u16, command[31..33], .big));
    try testing.expectEqualSlices(u8, &digest, command[33..]);
}

test "the read command asks for the register it was given" {
    var bytes: [read_size]u8 = undefined;

    // Register zero is the lowest bit of the first byte, and register nine the first bit of the
    // second, because that is how a chip counts them.
    _ = readCommand(&bytes, 0);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x00, 0x00 }, bytes[17..20]);
    _ = readCommand(&bytes, 9);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x02, 0x00 }, bytes[17..20]);

    // A register this bank does not have asks for none rather than writing outside the command.
    _ = readCommand(&bytes, 99);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x00, 0x00 }, bytes[17..20]);
}

/// An answer holding one register of this bank, built the way a chip builds it.
fn answerBytes(into: []u8, digest: [length]u8) []const u8 {
    const total = 28 + length;
    std.mem.writeInt(u16, into[0..2], st_no_sessions, .big);
    std.mem.writeInt(u32, into[2..6], @intCast(total), .big);
    std.mem.writeInt(u32, into[6..10], 0, .big);
    std.mem.writeInt(u32, into[10..14], 1, .big); // the counter
    std.mem.writeInt(u32, into[14..18], 1, .big); // one selection
    std.mem.writeInt(u16, into[18..20], algorithm, .big);
    into[20] = 1; // one byte of register numbers
    into[21] = 1; // register zero
    std.mem.writeInt(u32, into[22..26], 1, .big); // one value
    std.mem.writeInt(u16, into[26..28], length, .big);
    @memcpy(into[28..total], &digest);
    return into[0..total];
}

test "a register is read out of an answer" {
    const digest: [length]u8 = @splat(0x5a);
    var bytes: [256]u8 = undefined;
    const answer = answerBytes(&bytes, digest);

    const got = digestOf(answer) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, &digest, &got);
}

test "an answer that is wrong in any way carries no register" {
    const digest: [length]u8 = @splat(0x5a);
    var bytes: [256]u8 = undefined;
    const answer = answerBytes(&bytes, digest);

    // Nothing, and less than a header.
    try std.testing.expect(digestOf(&.{}) == null);
    try std.testing.expect(digestOf(answer[0..9]) == null);

    // Cut short anywhere. Every length in an answer is chosen by whatever sent it, so a short
    // answer must be refused rather than read past its end.
    for (header_size..answer.len) |cut| {
        try std.testing.expect(digestOf(answer[0..cut]) == null);
    }

    // A refusal, which carries nothing whatever else it holds.
    var refused: [256]u8 = undefined;
    @memcpy(refused[0..answer.len], answer);
    std.mem.writeInt(u32, refused[6..10], 0x0000_0101, .big);
    try std.testing.expect(digestOf(refused[0..answer.len]) == null);

    // A digest of another length is a digest from another bank.
    var other: [256]u8 = undefined;
    @memcpy(other[0..answer.len], answer);
    std.mem.writeInt(u16, other[26..28], 32, .big);
    try std.testing.expect(digestOf(other[0..answer.len]) == null);

    // And an answer holding more than one register answers a question nobody here asked.
    var many: [256]u8 = undefined;
    @memcpy(many[0..answer.len], answer);
    std.mem.writeInt(u32, many[22..26], 2, .big);
    try std.testing.expect(digestOf(many[0..answer.len]) == null);
}

/// A chip that folds digests into one register the way a real one does, and answers a read with
/// what it holds. Enough to check the commands this file builds are the commands it means.
const Pretend = struct {
    register: [length]u8 = zero,
    extends: usize = 0,
    /// How many bytes to give per read, because a socket gives what it has and no more.
    per_read: usize = 7,

    out: [256]u8 = undefined,
    out_len: usize = 0,
    out_at: usize = 0,

    fn write(self: *Pretend, bytes: []const u8) !usize {
        const code = std.mem.readInt(u32, bytes[6..10], .big);
        if (code == cc_pcr_extend) {
            var digest: [length]u8 = undefined;
            @memcpy(&digest, bytes[33..][0..length]);
            self.register = extend(self.register, digest);
            self.extends += 1;

            std.mem.writeInt(u16, self.out[0..2], st_sessions, .big);
            std.mem.writeInt(u32, self.out[2..6], header_size, .big);
            std.mem.writeInt(u32, self.out[6..10], 0, .big);
            self.out_len = header_size;
        } else {
            self.out_len = answerBytes(&self.out, self.register).len;
        }
        self.out_at = 0;
        return bytes.len;
    }

    fn read(self: *Pretend, into: []u8) !usize {
        const left = self.out_len - self.out_at;
        const moving = @min(@min(left, self.per_read), into.len);
        @memcpy(into[0..moving], self.out[self.out_at..][0..moving]);
        self.out_at += moving;
        return moving;
    }
};

test "measuring a manifest leaves the register where the fold says" {
    const gpa = testing.allocator();

    var manifest: Manifest = .{};
    defer manifest.deinit(gpa);
    try manifest.add(gpa, .kernel, "kernel bytes");
    try manifest.add(gpa, .initrd, "initrd bytes");
    try manifest.add(gpa, .cmdline, "console=ttyAMA0");

    var chip: Pretend = .{};
    var session: Session(Pretend) = .{ .transport = &chip };
    const folded = try session.measure(&manifest, 0);

    // One command per entry, plus the read before and the read after. The register holds what a
    // caller can work out on its own, which is the whole point: a verifier never has to ask the chip
    // what it should hold.
    try testing.expectEqual(@as(usize, 3), chip.extends);
    try testing.expectEqualSlices(u8, &of(&manifest), &chip.register);
    try testing.expectEqualSlices(u8, &of(&manifest), &folded);

    // And reading it back over the same transport gives the same value.
    const read_back = try session.read(0);
    try testing.expectEqualSlices(u8, &of(&manifest), &read_back);
}

test "a chip that never answers stops rather than waiting forever" {
    const Silent = struct {
        fn write(_: *@This(), bytes: []const u8) !usize {
            return bytes.len;
        }
        fn read(_: *@This(), _: []u8) !usize {
            return 0;
        }
    };

    var chip: Silent = .{};
    var session: Session(Silent) = .{ .transport = &chip, .patience = 16 };
    try testing.expectError(error.NoAnswer, session.read(0));
}

test "a refusal is told apart from an answer" {
    const Refusing = struct {
        fn write(_: *@This(), bytes: []const u8) !usize {
            return bytes.len;
        }
        fn read(_: *@This(), into: []u8) !usize {
            std.mem.writeInt(u16, into[0..2], st_no_sessions, .big);
            std.mem.writeInt(u32, into[2..6], header_size, .big);
            std.mem.writeInt(u32, into[6..10], 0x0000_0184, .big);
            return header_size;
        }
    };

    var chip: Refusing = .{};
    var session: Session(Refusing) = .{ .transport = &chip, .patience = 16 };
    try testing.expectError(error.Refused, session.read(0));
}

test "the bank number and the digest length are one choice" {
    // A chip works out how long a digest is from the algorithm alone, so a bank number that does not
    // match the length gets the command refused as short. The numbers either side are SHA-256 at 32
    // bytes and SHA-512 at 64, and picking one of those by mistake is not visible in any answer a
    // pretend chip gives: only a real one knows.
    try testing.expectEqual(@as(u16, 0x000c), algorithm);
    try testing.expectEqual(@as(usize, 48), length);
}

test "a chip that does not hold what the rule says is caught" {
    const gpa = testing.allocator();

    var manifest: Manifest = .{};
    defer manifest.deinit(gpa);
    try manifest.add(gpa, .kernel, "kernel bytes");

    // A chip that takes the commands but keeps something else. Nothing in the answers says so, which
    // is why the register is read back and checked rather than assumed.
    const Lying = struct {
        took: bool = false,
        out: [256]u8 = undefined,
        out_len: usize = 0,
        out_at: usize = 0,

        pub fn write(self: *@This(), bytes: []const u8) !usize {
            if (std.mem.readInt(u32, bytes[6..10], .big) == cc_pcr_extend) {
                self.took = true;
                std.mem.writeInt(u16, self.out[0..2], st_sessions, .big);
                std.mem.writeInt(u32, self.out[2..6], header_size, .big);
                std.mem.writeInt(u32, self.out[6..10], 0, .big);
                self.out_len = header_size;
            } else {
                // Empty until something is folded in, then a value that is not the fold.
                self.out_len = answerBytes(&self.out, if (self.took) @as([length]u8, @splat(0x11)) else zero).len;
            }
            self.out_at = 0;
            return bytes.len;
        }

        pub fn read(self: *@This(), into: []u8) !usize {
            const moving = @min(self.out_len - self.out_at, into.len);
            @memcpy(into[0..moving], self.out[self.out_at..][0..moving]);
            self.out_at += moving;
            return moving;
        }
    };

    var chip: Lying = .{};
    var session: Session(Lying) = .{ .transport = &chip, .patience = 64 };
    try testing.expectError(error.Disagreed, session.measure(&manifest, 0));
}

test "a chip that was already used is refused" {
    const gpa = testing.allocator();

    var manifest: Manifest = .{};
    defer manifest.deinit(gpa);
    try manifest.add(gpa, .kernel, "kernel bytes");

    // Something folded a digest in before this launch. A guest folds a list of measurements from
    // nothing, so a register that did not start from nothing makes the two disagree for a reason
    // neither of them can see.
    var chip: Pretend = .{ .register = @splat(0x77) };
    var session: Session(Pretend) = .{ .transport = &chip, .patience = 64 };
    try testing.expectError(error.NotFresh, session.measure(&manifest, 0));
    try testing.expectEqual(@as(usize, 0), chip.extends);
}
