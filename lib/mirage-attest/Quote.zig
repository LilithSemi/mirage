//! A signed statement from the chip about what its registers hold.
//!
//! A register and a list of measurements are enough for a guest to know what started it, and enough
//! for whoever started it to check. They are not enough for anybody else: both reach a third party
//! through the machine that is being asked about, and that machine could say anything. A quote is the
//! chip signing the register values itself, with a key the chip will not give up, over a number the
//! asker chose. Then the answer is worth something to somebody who trusts the chip and nothing else.
//!
//! The key here is an ordinary primary key in the owner hierarchy: the same template gives the same
//! key every time, so it does not have to be kept anywhere. It is restricted and signing only, which
//! is what lets the chip sign its own registers with it and stops it signing anything else.
//!
//! What this does not do is say the chip is real. A verifier that cares has to know the key some other
//! way, which for a chip a host provides means the host has to vouch for it. That is a limit of a chip
//! in software and not of this code: the same commands over a chip in hardware carry a key with a
//! certificate behind it.

const std = @import("std");
const testing = @import("mirage-testing");
const Chain = @import("Chain.zig");
const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// Command codes.
const cc_create_primary = 0x0000_0131;
const cc_flush_context = 0x0000_0165;
const cc_quote = 0x0000_0158;

const st_sessions = 0x8002;
const rs_password = 0x4000_0009;
/// `TPM_RH_OWNER`, the hierarchy a key that nobody has to keep belongs in.
const rh_owner = 0x4000_0001;

const alg_sha256 = 0x000b;
const alg_null = 0x0010;
const alg_ecdsa = 0x0018;
const alg_ecc = 0x0023;
const curve_p256 = 0x0003;

/// What a quote begins with, and what says it is one. A verifier that does not check this can be given
/// any signed thing at all and read it as a quote.
pub const magic = 0xff54_4347;
/// `TPM_ST_ATTEST_QUOTE`.
pub const attest_quote = 0x8018;

const header_size = 10;

/// How long a number an asker chooses may be. It only has to be long enough not to be guessed, and a
/// chip has a limit of its own on how much it will carry.
pub const max_nonce = 64;

pub const Error = error{
    /// The chip answered something this does not understand, or answered short.
    Unreadable,
    /// The chip signed, but not over the register this asked about, or not over the number given.
    Wrong,
    /// The signature does not belong to the key.
    Unsigned,
};

/// A key the chip holds, and the public half a verifier needs.
pub const Key = struct {
    /// Where the chip is holding it. It goes away when the chip is told to let go.
    handle: u32,
    /// The point, as one uncompressed point, which is the form the standard library reads.
    point: [65]u8,

    pub fn publicKey(self: Key) !Ecdsa.PublicKey {
        return Ecdsa.PublicKey.fromSec1(&self.point);
    }
};

/// What a quote said, once it has been checked.
pub const Checked = struct {
    /// What the register held when the chip signed. A caller compares this with what it expects.
    register: [Chain.length]u8,
};

/// The bytes of a command that makes the signing key.
///
/// Every field here is part of what the key is: the same template gives the same key on the same chip,
/// and a different template gives a different one. So this is written out rather than built from
/// options, because an option nobody sets is a key nobody can make again.
pub fn createCommand(into: *[create_size]u8) []const u8 {
    var at: usize = 0;
    std.mem.writeInt(u16, into[0..2], st_sessions, .big);
    std.mem.writeInt(u32, into[2..6], create_size, .big);
    std.mem.writeInt(u32, into[6..10], cc_create_primary, .big);
    at = header_size;

    std.mem.writeInt(u32, into[at..][0..4], rh_owner, .big);
    at += 4;

    // One empty password.
    std.mem.writeInt(u32, into[at..][0..4], 9, .big);
    std.mem.writeInt(u32, into[at + 4 ..][0..4], rs_password, .big);
    std.mem.writeInt(u16, into[at + 8 ..][0..2], 0, .big);
    into[at + 10] = 0;
    std.mem.writeInt(u16, into[at + 11 ..][0..2], 0, .big);
    at += 13;

    // Nothing sensitive of the caller's goes in: the chip makes the secret half itself.
    std.mem.writeInt(u16, into[at..][0..2], 4, .big);
    std.mem.writeInt(u16, into[at + 2 ..][0..2], 0, .big);
    std.mem.writeInt(u16, into[at + 4 ..][0..2], 0, .big);
    at += 6;

    // The template, behind its own length.
    std.mem.writeInt(u16, into[at..][0..2], template_size, .big);
    at += 2;
    std.mem.writeInt(u16, into[at..][0..2], alg_ecc, .big);
    std.mem.writeInt(u16, into[at + 2 ..][0..2], alg_sha256, .big);
    std.mem.writeInt(u32, into[at + 4 ..][0..4], attributes, .big);
    std.mem.writeInt(u16, into[at + 8 ..][0..2], 0, .big); // no policy, so the password is the whole of it
    std.mem.writeInt(u16, into[at + 10 ..][0..2], alg_null, .big); // it encrypts nothing
    std.mem.writeInt(u16, into[at + 12 ..][0..2], alg_ecdsa, .big);
    std.mem.writeInt(u16, into[at + 14 ..][0..2], alg_sha256, .big);
    std.mem.writeInt(u16, into[at + 16 ..][0..2], curve_p256, .big);
    std.mem.writeInt(u16, into[at + 18 ..][0..2], alg_null, .big); // it derives nothing
    std.mem.writeInt(u16, into[at + 20 ..][0..2], 0, .big); // the point comes from the chip
    std.mem.writeInt(u16, into[at + 22 ..][0..2], 0, .big);
    at += template_size;

    std.mem.writeInt(u16, into[at..][0..2], 0, .big); // nothing outside goes into what it is
    std.mem.writeInt(u32, into[at + 2 ..][0..4], 0, .big); // and no register does either
    at += 6;

    std.debug.assert(at == create_size);
    return into[0..create_size];
}

/// Restricted, signing, and made by the chip: the three that matter. Restricted is what lets it sign
/// the chip's own registers, and without it a quote is a signature over anything at all.
const attributes = (1 << 1) | // fixed to this chip
    (1 << 4) | // fixed to this hierarchy
    (1 << 5) | // the chip made the secret half
    (1 << 6) | // a password is enough to use it
    (1 << 16) | // restricted
    (1 << 18); // signing

const template_size = 2 + 2 + 4 + 2 + 2 + 2 + 2 + 2 + 2 + 2 + 2;
pub const create_size = header_size + 4 + 13 + 6 + 2 + template_size + 6;

/// The bytes of a command asking the chip to sign what one register holds, over a number the asker
/// chose. Without that number an old quote could be kept and shown again.
pub fn quoteCommand(into: []u8, key: u32, register: u32, nonce: []const u8) []const u8 {
    std.debug.assert(nonce.len <= max_nonce);
    const total = header_size + 4 + 13 + (2 + nonce.len) + 2 + 4 + 2 + 1 + 3;
    std.debug.assert(into.len >= total);

    std.mem.writeInt(u16, into[0..2], st_sessions, .big);
    std.mem.writeInt(u32, into[2..6], @intCast(total), .big);
    std.mem.writeInt(u32, into[6..10], cc_quote, .big);
    var at: usize = header_size;

    std.mem.writeInt(u32, into[at..][0..4], key, .big);
    at += 4;

    std.mem.writeInt(u32, into[at..][0..4], 9, .big);
    std.mem.writeInt(u32, into[at + 4 ..][0..4], rs_password, .big);
    std.mem.writeInt(u16, into[at + 8 ..][0..2], 0, .big);
    into[at + 10] = 0;
    std.mem.writeInt(u16, into[at + 11 ..][0..2], 0, .big);
    at += 13;

    std.mem.writeInt(u16, into[at..][0..2], @intCast(nonce.len), .big);
    @memcpy(into[at + 2 ..][0..nonce.len], nonce);
    at += 2 + nonce.len;

    // The key says how it signs, so nothing here has to.
    std.mem.writeInt(u16, into[at..][0..2], alg_null, .big);
    at += 2;

    std.mem.writeInt(u32, into[at..][0..4], 1, .big);
    std.mem.writeInt(u16, into[at + 4 ..][0..2], Chain.algorithm, .big);
    into[at + 6] = 3;
    into[at + 7] = 0;
    into[at + 8] = 0;
    into[at + 9] = 0;
    if (register < 24) into[at + 7 + register / 8] = @as(u8, 1) << @intCast(register % 8);
    at += 10;

    std.debug.assert(at == total);
    return into[0..total];
}

/// The bytes of a command telling the chip to let go of a key.
pub fn flushCommand(into: *[header_size + 4]u8, key: u32) []const u8 {
    std.mem.writeInt(u16, into[0..2], 0x8001, .big);
    std.mem.writeInt(u32, into[2..6], header_size + 4, .big);
    std.mem.writeInt(u32, into[6..10], cc_flush_context, .big);
    std.mem.writeInt(u32, into[10..14], key, .big);
    return into[0 .. header_size + 4];
}

/// Reads a run of bytes that says its own length first.
const Walk = struct {
    bytes: []const u8,
    at: usize = 0,

    fn take(self: *Walk, count: usize) Error![]const u8 {
        if (self.at + count > self.bytes.len) return Error.Unreadable;
        defer self.at += count;
        return self.bytes[self.at..][0..count];
    }

    fn u8At(self: *Walk) Error!u8 {
        return (try self.take(1))[0];
    }

    fn u16At(self: *Walk) Error!u16 {
        return std.mem.readInt(u16, (try self.take(2))[0..2], .big);
    }

    fn u32At(self: *Walk) Error!u32 {
        return std.mem.readInt(u32, (try self.take(4))[0..4], .big);
    }

    /// A run behind its own two byte length, which is how the chip writes anything of a size it
    /// chooses.
    fn sized(self: *Walk) Error![]const u8 {
        return self.take(try self.u16At());
    }

    /// A run behind a one byte length. Which registers were chosen is written this way and nothing
    /// else here is.
    fn short(self: *Walk) Error![]const u8 {
        return self.take(try self.u8At());
    }
};

/// The key out of an answer to the command that makes one.
pub fn keyOf(answer: []const u8) Error!Key {
    var walk: Walk = .{ .bytes = answer, .at = header_size };
    const handle = try walk.u32At();
    _ = try walk.u32At(); // how long the parameters are, which is not needed to walk them

    const public = try walk.sized();
    var inside: Walk = .{ .bytes = public };
    if (try inside.u16At() != alg_ecc) return Error.Unreadable;
    _ = try inside.u16At(); // the name algorithm
    _ = try inside.u32At(); // the attributes
    _ = try inside.sized(); // the policy
    _ = try inside.u16At(); // what it encrypts with
    _ = try inside.u16At(); // how it signs
    _ = try inside.u16At(); // and with which hash
    _ = try inside.u16At(); // the curve
    _ = try inside.u16At(); // what it derives with

    // The point, as two numbers of the curve's own width. A chip may drop leading zeroes, so each half
    // is placed at the end of its own room rather than at the start.
    const x = try inside.sized();
    const y = try inside.sized();
    if (x.len > 32 or y.len > 32) return Error.Unreadable;

    var key: Key = .{ .handle = handle, .point = @splat(0) };
    key.point[0] = 4; // uncompressed
    @memcpy(key.point[1 + (32 - x.len) ..][0..x.len], x);
    @memcpy(key.point[33 + (32 - y.len) ..][0..y.len], y);
    return key;
}

/// Check a quote and give back what the register held.
///
/// Four things have to hold, and every one of them matters. The signature has to belong to the key, or
/// anybody could write the rest. The statement has to say it is a quote, or a signature over something
/// else entirely could be read as one. The number in it has to be the one that was asked for, or an
/// old quote could be kept and shown again. And the digest in it has to be the digest of the register
/// being claimed, which is the only thing that ties the signature to the value.
pub fn check(answer: []const u8, key: Key, nonce: []const u8, register: [Chain.length]u8) Error!Checked {
    var walk: Walk = .{ .bytes = answer, .at = header_size };
    _ = try walk.u32At(); // how long the parameters are

    const quoted = try walk.sized();

    if (try walk.u16At() != alg_ecdsa) return Error.Unreadable;
    if (try walk.u16At() != alg_sha256) return Error.Unreadable;
    const r = try walk.sized();
    const s = try walk.sized();
    if (r.len > 32 or s.len > 32) return Error.Unreadable;

    var raw: [64]u8 = @splat(0);
    @memcpy(raw[32 - r.len ..][0..r.len], r);
    @memcpy(raw[64 - s.len ..][0..s.len], s);

    const public = key.publicKey() catch return Error.Unsigned;
    const signature: Ecdsa.Signature = .fromBytes(raw);
    signature.verify(quoted, public) catch return Error.Unsigned;

    // Only now is the statement worth reading, because only now is it known to come from the key.
    var inside: Walk = .{ .bytes = quoted };
    if (try inside.u32At() != magic) return Error.Wrong;
    if (try inside.u16At() != attest_quote) return Error.Wrong;
    _ = try inside.sized(); // which key signed, by name

    const given = try inside.sized();
    if (!std.mem.eql(u8, given, nonce)) return Error.Wrong;

    _ = try inside.take(17); // the chip's clock and how often it has been restarted
    _ = try inside.take(8); // and what it runs

    // Which registers were quoted, which has to be the one being claimed and no other.
    if (try inside.u32At() != 1) return Error.Wrong;
    if (try inside.u16At() != Chain.algorithm) return Error.Wrong;
    _ = try inside.short();

    const digest = try inside.sized();
    if (digest.len != Sha256.digest_length) return Error.Wrong;

    // The chip hashes the register values it quoted. One register was asked for, so the digest is of
    // that one value, and this is what ties the signature to it.
    var expected: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(&register, &expected, .{});
    if (!std.mem.eql(u8, digest, &expected)) return Error.Wrong;

    return .{ .register = register };
}

/// What a caller is left with after asking for a quote.
pub const Taken = struct {
    /// The public half, which is what a verifier needs and all it needs.
    key: Key,
    /// What the register held, as the chip said it and as it was checked.
    checked: Checked,
    /// The statement and its signature, as they came from the chip. A caller that wants somebody else
    /// to check this rather than take its word passes these on.
    answer: []const u8,
};

/// Make the key, ask for a quote of one register, let the key go, and check the answer.
///
/// The key goes away afterwards because the chip has room for only a few at once, and this one can be
/// made again from the same template whenever it is wanted. `session` is anything that can `ask`,
/// which in practice is `Chain.Session`.
pub fn take(session: anytype, into: []u8, register: u32, nonce: []const u8, holds: [Chain.length]u8) !Taken {
    var command: [create_size]u8 = undefined;
    var scratch: [1024]u8 = undefined;
    const key = try keyOf(try session.ask(createCommand(&command), &scratch));

    var asking: [header_size + 32 + max_nonce]u8 = undefined;
    const answer = try session.ask(quoteCommand(&asking, key.handle, register, nonce), into);

    // Letting go is not allowed to lose the quote, so it happens before the quote is read and its
    // answer is thrown away. A chip that will not let go is still a chip that gave a good quote.
    var goodbye: [header_size + 4]u8 = undefined;
    var ignored: [64]u8 = undefined;
    _ = session.ask(flushCommand(&goodbye, key.handle), &ignored) catch {};

    return .{ .key = key, .checked = try check(answer, key, nonce, holds), .answer = answer };
}

/// Build a quote the way a chip builds one, and sign it. Everything a real chip does that matters
/// here, so the checks can be tried against a statement that is right and against ones that are wrong
/// in one way each.
const Pretend = struct {
    pair: Ecdsa.KeyPair,

    /// From a fixed seed, so a test that fails fails the same way twice.
    fn init(seed: u8) Pretend {
        return .{ .pair = Ecdsa.KeyPair.generateDeterministic(@splat(seed)) catch unreachable };
    }

    fn key(self: Pretend) Key {
        var out: Key = .{ .handle = 0x8000_0000, .point = @splat(0) };
        out.point = self.pair.public_key.toUncompressedSec1();
        return out;
    }

    /// The statement, before it is signed.
    fn statement(into: []u8, nonce: []const u8, register: [Chain.length]u8, said_magic: u32, said_type: u16) []const u8 {
        var at: usize = 0;
        std.mem.writeInt(u32, into[at..][0..4], said_magic, .big);
        std.mem.writeInt(u16, into[at + 4 ..][0..2], said_type, .big);
        at += 6;
        std.mem.writeInt(u16, into[at..][0..2], 4, .big); // the name of whoever signed
        @memcpy(into[at + 2 ..][0..4], "name");
        at += 6;
        std.mem.writeInt(u16, into[at..][0..2], @intCast(nonce.len), .big);
        @memcpy(into[at + 2 ..][0..nonce.len], nonce);
        at += 2 + nonce.len;
        @memset(into[at..][0..25], 0); // the clock and what the chip runs
        at += 25;
        std.mem.writeInt(u32, into[at..][0..4], 1, .big);
        std.mem.writeInt(u16, into[at + 4 ..][0..2], Chain.algorithm, .big);
        into[at + 6] = 3;
        into[at + 7] = 1;
        into[at + 8] = 0;
        into[at + 9] = 0;
        at += 10;

        var digest: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(&register, &digest, .{});
        std.mem.writeInt(u16, into[at..][0..2], Sha256.digest_length, .big);
        @memcpy(into[at + 2 ..][0..digest.len], &digest);
        at += 2 + digest.len;
        return into[0..at];
    }

    /// The answer the chip gives: the statement, then the signature over it.
    fn answer(self: Pretend, into: []u8, said: []const u8) ![]const u8 {
        const signature = try self.pair.sign(said, null);
        const raw = signature.toBytes();

        var at: usize = 0;
        std.mem.writeInt(u16, into[0..2], st_sessions, .big);
        std.mem.writeInt(u32, into[2..6], 0, .big);
        std.mem.writeInt(u32, into[6..10], 0, .big);
        at = header_size;
        std.mem.writeInt(u32, into[at..][0..4], 0, .big); // how long the parameters are
        at += 4;
        std.mem.writeInt(u16, into[at..][0..2], @intCast(said.len), .big);
        @memcpy(into[at + 2 ..][0..said.len], said);
        at += 2 + said.len;
        std.mem.writeInt(u16, into[at..][0..2], alg_ecdsa, .big);
        std.mem.writeInt(u16, into[at + 2 ..][0..2], alg_sha256, .big);
        at += 4;
        std.mem.writeInt(u16, into[at..][0..2], 32, .big);
        @memcpy(into[at + 2 ..][0..32], raw[0..32]);
        at += 34;
        std.mem.writeInt(u16, into[at..][0..2], 32, .big);
        @memcpy(into[at + 2 ..][0..32], raw[32..64]);
        at += 34;
        return into[0..at];
    }
};

test "a quote says what one register held" {
    const chip: Pretend = .init(1);
    const register: [Chain.length]u8 = @splat(0x5a);
    const nonce = "a number the asker chose";

    var said: [256]u8 = undefined;
    var bytes: [512]u8 = undefined;
    const answer = try chip.answer(&bytes, Pretend.statement(&said, nonce, register, magic, attest_quote));

    const checked = try check(answer, chip.key(), nonce, register);
    try testing.expectEqualSlices(u8, &register, &checked.register);
}

test "a quote is refused when any one thing about it is wrong" {
    const chip: Pretend = .init(1);
    const register: [Chain.length]u8 = @splat(0x5a);
    const nonce = "a number the asker chose";

    var said: [256]u8 = undefined;
    var bytes: [512]u8 = undefined;
    const good = Pretend.statement(&said, nonce, register, magic, attest_quote);
    const answer = try chip.answer(&bytes, good);

    // Another register. This is the one that matters most: without it a quote of any register at all
    // could be shown as a quote of this one.
    var other = register;
    other[0] ^= 1;
    try testing.expectError(Error.Wrong, check(answer, chip.key(), nonce, other));

    // Another number, which is how an old quote would be shown again.
    try testing.expectError(Error.Wrong, check(answer, chip.key(), "another number", register));

    // Another key. The statement is untouched and still refused, because it is the signature that
    // makes any of it worth reading.
    const stranger: Pretend = .init(2);
    try testing.expectError(Error.Unsigned, check(answer, stranger.key(), nonce, register));

    // One bit of the signature.
    var bent: [512]u8 = undefined;
    @memcpy(bent[0..answer.len], answer);
    bent[answer.len - 1] ^= 1;
    try testing.expectError(Error.Unsigned, check(bent[0..answer.len], chip.key(), nonce, register));

    // One bit of the statement, which the signature no longer covers.
    var moved: [512]u8 = undefined;
    @memcpy(moved[0..answer.len], answer);
    moved[header_size + 6 + 4] ^= 1;
    try testing.expectError(Error.Unsigned, check(moved[0..answer.len], chip.key(), nonce, register));
}

test "a signed thing that is not a quote is refused" {
    const chip: Pretend = .init(1);
    const register: [Chain.length]u8 = @splat(0x5a);
    const nonce = "a number the asker chose";

    var said: [256]u8 = undefined;
    var bytes: [512]u8 = undefined;

    // Properly signed by the right key, and not a quote. A verifier that reads the value without
    // checking what kind of statement it is can be handed anything the key ever signed.
    const wrong_magic = try chip.answer(&bytes, Pretend.statement(&said, nonce, register, 0xdead_beef, attest_quote));
    try testing.expectError(Error.Wrong, check(wrong_magic, chip.key(), nonce, register));

    var more: [512]u8 = undefined;
    const wrong_type = try chip.answer(&more, Pretend.statement(&said, nonce, register, magic, 0x8017));
    try testing.expectError(Error.Wrong, check(wrong_type, chip.key(), nonce, register));
}

test "an answer that ends early is refused rather than read past" {
    const chip: Pretend = .init(1);
    const register: [Chain.length]u8 = @splat(0x5a);
    const nonce = "a number";

    var said: [256]u8 = undefined;
    var bytes: [512]u8 = undefined;
    const answer = try chip.answer(&bytes, Pretend.statement(&said, nonce, register, magic, attest_quote));

    // Every length in an answer was chosen by whatever sent it, so a short answer has to be refused
    // at whatever point it runs out.
    for (0..answer.len) |cut| {
        try std.testing.expect(std.meta.isError(check(answer[0..cut], chip.key(), nonce, register)));
    }
}

test "a key is read out of the answer that made it" {
    const chip: Pretend = .init(1);
    const point = chip.pair.public_key.toUncompressedSec1();

    // The answer a chip gives, with the two halves of the point at their full width.
    var bytes: [256]u8 = undefined;
    var at: usize = 0;
    std.mem.writeInt(u16, bytes[0..2], st_sessions, .big);
    std.mem.writeInt(u32, bytes[2..6], 0, .big);
    std.mem.writeInt(u32, bytes[6..10], 0, .big);
    at = header_size;
    std.mem.writeInt(u32, bytes[at..][0..4], 0x8000_0001, .big);
    std.mem.writeInt(u32, bytes[at + 4 ..][0..4], 0, .big);
    at += 8;

    const inside = template_size + 2 + 32 + 2 + 32 - 4;
    std.mem.writeInt(u16, bytes[at..][0..2], inside, .big);
    at += 2;
    std.mem.writeInt(u16, bytes[at..][0..2], alg_ecc, .big);
    std.mem.writeInt(u16, bytes[at + 2 ..][0..2], alg_sha256, .big);
    std.mem.writeInt(u32, bytes[at + 4 ..][0..4], attributes, .big);
    std.mem.writeInt(u16, bytes[at + 8 ..][0..2], 0, .big);
    std.mem.writeInt(u16, bytes[at + 10 ..][0..2], alg_null, .big);
    std.mem.writeInt(u16, bytes[at + 12 ..][0..2], alg_ecdsa, .big);
    std.mem.writeInt(u16, bytes[at + 14 ..][0..2], alg_sha256, .big);
    std.mem.writeInt(u16, bytes[at + 16 ..][0..2], curve_p256, .big);
    std.mem.writeInt(u16, bytes[at + 18 ..][0..2], alg_null, .big);
    at += 20;
    std.mem.writeInt(u16, bytes[at..][0..2], 32, .big);
    @memcpy(bytes[at + 2 ..][0..32], point[1..33]);
    at += 34;
    std.mem.writeInt(u16, bytes[at..][0..2], 32, .big);
    @memcpy(bytes[at + 2 ..][0..32], point[33..65]);
    at += 34;

    const key = try keyOf(bytes[0..at]);
    try testing.expectEqual(@as(u32, 0x8000_0001), key.handle);
    try testing.expectEqualSlices(u8, &point, &key.point);

    // And it is a key the standard library will take, which is the only test that matters about it.
    _ = try key.publicKey();
}
