//! The list of measurements, in the form a guest already knows how to read.
//!
//! A register anchors a chain but does not say what is in it: the value is one hash and nothing can
//! be recovered from it. The log is the other half. It names each measurement in the order it went
//! in, so a guest can fold the log for itself and check the answer against the register. A log that
//! folds to the register is a log nothing has changed, because changing an entry changes the fold.
//!
//! The layout is the Trusted Computing Group's, the one with a digest per bank rather than one
//! SHA-1 digest, because that is what a chip with a SHA-384 bank needs and what Linux reads from
//! `binary_bios_measurements`. The first event is the odd one out: it is in the old layout and
//! carries the list of banks, which is how a reader learns how long the digests after it are.

const std = @import("std");
const testing = @import("mirage-testing");
const Chain = @import("Chain.zig");
const Manifest = @import("Manifest.zig");

/// `EV_NO_ACTION`, which a reader is told to skip rather than fold. The first event says what the
/// banks are and is not a measurement, so it must not go into a register.
pub const no_action = 0x0000_0003;

/// `EV_IPL`, which is what whatever loads a guest uses for the things it loaded.
pub const ipl = 0x0000_000d;

/// The signature the first event carries, sixteen bytes including its own end.
const spec_signature = "Spec ID Event03\x00";

/// How long the first event is: the old layout, with a SHA-1 sized digest of zeroes.
const header_digest = 20;
const header_event = 4 + 4 + header_digest + 4;
/// `TCG_EfiSpecIdEvent` for one bank: the signature, the platform, three version bytes and the size
/// of an address, then one bank, then no vendor bytes.
const spec_event = 16 + 4 + 1 + 1 + 1 + 1 + 4 + (2 + 2) + 1;

/// How long one measurement is: the register, the type, one bank's digest, and a name.
fn eventSize(name_len: usize) usize {
    return 4 + 4 + (4 + 2 + Chain.length) + 4 + name_len;
}

/// How many bytes a log for this manifest takes.
pub fn size(manifest: *const Manifest) usize {
    var total: usize = header_event + spec_event;
    for (manifest.entries.items) |entry| total += eventSize(@tagName(entry.tag).len);
    return total;
}

/// How many bytes a log takes for these measurements. Only the names go into the length, never the
/// digests, so this is answerable before anything has been measured. Whoever hands a guest a log has
/// to know how long it will be before it can say where it is.
pub fn sizeFor(tags: []const Manifest.Tag) usize {
    var total: usize = header_event + spec_event;
    for (tags) |tag| total += eventSize(@tagName(tag).len);
    return total;
}

/// Write the log. The buffer must be at least `size` long, which is a caller's job to work out
/// beforehand, because a log written in part is a log that folds to nothing.
pub fn write(into: []u8, manifest: *const Manifest, register: u32) []u8 {
    std.debug.assert(into.len >= size(manifest));
    var at: usize = 0;

    // The first event, in the old layout. Its digest is zeroes because there is nothing to measure
    // about a list of banks.
    std.mem.writeInt(u32, into[at..][0..4], 0, .little);
    std.mem.writeInt(u32, into[at + 4 ..][0..4], no_action, .little);
    @memset(into[at + 8 ..][0..header_digest], 0);
    std.mem.writeInt(u32, into[at + 8 + header_digest ..][0..4], spec_event, .little);
    at += header_event;

    @memcpy(into[at..][0..16], spec_signature);
    std.mem.writeInt(u32, into[at + 16 ..][0..4], 0, .little); // the platform, which is not one of the named ones
    // Four single bytes, not two pairs: the profile's minor and major, its errata, and how wide an
    // address is on this machine, counted as two for sixty four bits rather than in bytes.
    into[at + 20] = 0;
    into[at + 21] = 2;
    into[at + 22] = 0;
    into[at + 23] = 2;
    std.mem.writeInt(u32, into[at + 24 ..][0..4], 1, .little); // one bank
    std.mem.writeInt(u16, into[at + 28 ..][0..2], Chain.algorithm, .little);
    std.mem.writeInt(u16, into[at + 30 ..][0..2], Chain.length, .little);
    into[at + 32] = 0; // no vendor bytes
    at += spec_event;

    // Then one event per measurement, in the order it was measured. The order is the chain.
    for (manifest.entries.items) |entry| {
        const name = @tagName(entry.tag);
        std.mem.writeInt(u32, into[at..][0..4], register, .little);
        std.mem.writeInt(u32, into[at + 4 ..][0..4], ipl, .little);
        std.mem.writeInt(u32, into[at + 8 ..][0..4], 1, .little); // one digest
        std.mem.writeInt(u16, into[at + 12 ..][0..2], Chain.algorithm, .little);
        @memcpy(into[at + 14 ..][0..Chain.length], &entry.digest);
        std.mem.writeInt(u32, into[at + 14 + Chain.length ..][0..4], @intCast(name.len), .little);
        @memcpy(into[at + 18 + Chain.length ..][0..name.len], name);
        at += eventSize(name.len);
    }

    return into[0..at];
}

/// Walks a log and gives back each measurement in it.
///
/// Every length in a log was written by whoever wrote the log, so each one is checked against what is
/// really there. A guest reads a log this side wrote, and a guest that trusted the lengths in it
/// would read past the end of a log that was cut short.
pub const Reader = struct {
    bytes: []const u8,
    at: usize = 0,
    /// Set when the log ran out in the middle of an event. A log that ends early is not a log whose
    /// last entry can be believed.
    ragged: bool = false,

    pub const Entry = struct {
        register: u32,
        kind: u32,
        digest: [Chain.length]u8,
        name: []const u8,
    };

    /// Read past the first event, which carries the banks rather than a measurement.
    pub fn init(bytes: []const u8) Reader {
        var self: Reader = .{ .bytes = bytes };
        if (bytes.len < header_event) {
            self.at = bytes.len;
            self.ragged = bytes.len != 0;
            return self;
        }
        const declared = std.mem.readInt(u32, bytes[8 + header_digest ..][0..4], .little);
        const past = header_event + @as(usize, declared);
        if (past > bytes.len) {
            self.at = bytes.len;
            self.ragged = true;
            return self;
        }
        self.at = past;
        return self;
    }

    pub fn next(self: *Reader) ?Entry {
        if (self.at >= self.bytes.len) return null;
        const left = self.bytes[self.at..];

        // The fixed part: the register, the type and how many digests follow.
        if (left.len < 12) {
            self.ragged = true;
            self.at = self.bytes.len;
            return null;
        }
        const register = std.mem.readInt(u32, left[0..4], .little);
        const kind = std.mem.readInt(u32, left[4..8], .little);
        const digests = std.mem.readInt(u32, left[8..12], .little);

        // Each digest says its bank, and only the one this understands is taken. The others are
        // skipped, which needs their lengths, and a bank this does not know has no length to skip.
        var walked: usize = 12;
        var found: ?[Chain.length]u8 = null;
        for (0..digests) |_| {
            if (digests > 8) {
                self.ragged = true;
                self.at = self.bytes.len;
                return null;
            }
            if (left.len < walked + 2) {
                self.ragged = true;
                self.at = self.bytes.len;
                return null;
            }
            const bank = std.mem.readInt(u16, left[walked..][0..2], .little);
            const wide = bankLength(bank) orelse {
                self.ragged = true;
                self.at = self.bytes.len;
                return null;
            };
            if (left.len < walked + 2 + wide) {
                self.ragged = true;
                self.at = self.bytes.len;
                return null;
            }
            if (bank == Chain.algorithm and found == null) {
                var digest: [Chain.length]u8 = undefined;
                @memcpy(&digest, left[walked + 2 ..][0..Chain.length]);
                found = digest;
            }
            walked += 2 + wide;
        }

        if (left.len < walked + 4) {
            self.ragged = true;
            self.at = self.bytes.len;
            return null;
        }
        const name_len = std.mem.readInt(u32, left[walked..][0..4], .little);
        walked += 4;
        if (left.len < walked + name_len) {
            self.ragged = true;
            self.at = self.bytes.len;
            return null;
        }
        const name = left[walked..][0..name_len];
        walked += name_len;

        self.at += walked;
        const digest = found orelse return self.next();
        return .{ .register = register, .kind = kind, .digest = digest, .name = name };
    }
};

/// How long a digest in one bank is, or nothing for a bank this does not know. A log may name banks
/// this side never wrote, and a reader has to walk past them without guessing their size.
fn bankLength(bank: u16) ?usize {
    return switch (bank) {
        0x0004 => 20, // sha1
        0x000b => 32, // sha256
        0x000c => 48, // sha384
        0x000d => 64, // sha512
        else => null,
    };
}

/// Fold a log into a register, skipping what a reader is told to skip. This is what a guest does to
/// check the log against the chip, and what this side does to know what the chip must hold.
pub fn fold(bytes: []const u8, register: u32) [Chain.length]u8 {
    var value = Chain.zero;
    var reader: Reader = .init(bytes);
    while (reader.next()) |entry| {
        if (entry.register != register) continue;
        if (entry.kind == no_action) continue;
        value = Chain.extend(value, entry.digest);
    }
    return value;
}

test "a log folds to the same register the manifest does" {
    const gpa = testing.allocator();

    var manifest: Manifest = .{};
    defer manifest.deinit(gpa);
    try manifest.add(gpa, .kernel, "kernel bytes");
    try manifest.add(gpa, .initrd, "initrd bytes");
    try manifest.add(gpa, .cmdline, "console=ttyAMA0");

    const bytes = try gpa.alloc(u8, size(&manifest));
    defer gpa.free(bytes);
    const log = write(bytes, &manifest, 0);

    // The log takes exactly what it said it would, and folds to what the chain says. That second
    // part is what lets a guest check a log it was handed: a changed entry gives another fold.
    try testing.expectEqual(size(&manifest), log.len);
    try testing.expectEqualSlices(u8, &Chain.of(&manifest), &fold(log, 0));
}

test "a log names each measurement in the order it was measured" {
    const gpa = testing.allocator();

    var manifest: Manifest = .{};
    defer manifest.deinit(gpa);
    try manifest.add(gpa, .kernel, "kernel bytes");
    try manifest.add(gpa, .device_tree, "tree bytes");

    const bytes = try gpa.alloc(u8, size(&manifest));
    defer gpa.free(bytes);
    const log = write(bytes, &manifest, 0);

    var reader: Reader = .init(log);
    const first = reader.next() orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, "kernel", first.name);
    try testing.expectEqual(@as(u32, ipl), first.kind);
    try testing.expectEqualSlices(u8, &manifest.entries.items[0].digest, &first.digest);

    const second = reader.next() orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, "device_tree", second.name);

    try std.testing.expect(reader.next() == null);
    try std.testing.expect(!reader.ragged);
}

test "changing one entry of a log changes what it folds to" {
    const gpa = testing.allocator();

    var manifest: Manifest = .{};
    defer manifest.deinit(gpa);
    try manifest.add(gpa, .kernel, "kernel bytes");
    try manifest.add(gpa, .initrd, "initrd bytes");

    const bytes = try gpa.alloc(u8, size(&manifest));
    defer gpa.free(bytes);
    const log = write(bytes, &manifest, 0);
    const before = fold(log, 0);

    // One bit of one digest. A log is only worth reading because this cannot be hidden.
    log[header_event + spec_event + 14] ^= 1;
    try std.testing.expect(!std.mem.eql(u8, &before, &fold(log, 0)));
}

test "a log that was cut short anywhere is read as ragged and never past its end" {
    const gpa = testing.allocator();

    var manifest: Manifest = .{};
    defer manifest.deinit(gpa);
    try manifest.add(gpa, .kernel, "kernel bytes");
    try manifest.add(gpa, .initrd, "initrd bytes");

    const bytes = try gpa.alloc(u8, size(&manifest));
    defer gpa.free(bytes);
    const log = write(bytes, &manifest, 0);

    for (1..log.len) |cut| {
        var reader: Reader = .init(log[0..cut]);
        var seen: usize = 0;
        while (reader.next()) |_| seen += 1;
        // Either it read whole entries and stopped, or it says the log ended in the middle of one.
        try std.testing.expect(seen < 2 or !reader.ragged);
    }
}

test "a log holding a bank this side does not write is walked past" {
    const gpa = testing.allocator();

    var manifest: Manifest = .{};
    defer manifest.deinit(gpa);
    try manifest.add(gpa, .kernel, "kernel bytes");

    // Two digests in one event, the first from another bank. A log written by firmware holds every
    // bank the chip has, so a reader that could not skip one would read nothing at all.
    const name = "kernel";
    const total = header_event + spec_event + 4 + 4 + 4 + (2 + 32) + (2 + Chain.length) + 4 + name.len;
    const bytes = try gpa.alloc(u8, total);
    defer gpa.free(bytes);

    _ = write(bytes, &manifest, 0);
    var at: usize = header_event + spec_event;
    std.mem.writeInt(u32, bytes[at + 8 ..][0..4], 2, .little);
    std.mem.writeInt(u16, bytes[at + 12 ..][0..2], 0x000b, .little);
    @memset(bytes[at + 14 ..][0..32], 0xee);
    at += 14 + 32;
    std.mem.writeInt(u16, bytes[at..][0..2], Chain.algorithm, .little);
    @memcpy(bytes[at + 2 ..][0..Chain.length], &manifest.entries.items[0].digest);
    at += 2 + Chain.length;
    std.mem.writeInt(u32, bytes[at..][0..4], name.len, .little);
    @memcpy(bytes[at + 4 ..][0..name.len], name);

    var reader: Reader = .init(bytes);
    const entry = reader.next() orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, &manifest.entries.items[0].digest, &entry.digest);
    try testing.expectEqualSlices(u8, "kernel", entry.name);
    try std.testing.expect(!reader.ragged);
    try testing.expectEqualSlices(u8, &Chain.of(&manifest), &fold(bytes, 0));
}
