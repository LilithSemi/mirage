//! The ordered list of everything measured into a guest before it starts.
//!
//! The manifest is not one opaque hash. It is a list of tagged digests, because a
//! verifier must see which input produced which digest. Each tier derives its own
//! proof from the same list. A TPM quote extends `root`. SEV-SNP derives the value
//! the AMD PSP reports on its own.
//!
//! SHA-384 because SEV-SNP uses SHA-384. Choosing anything else here would force a
//! second digest tree at tier 3.

const std = @import("std");
const testing = @import("mirage-testing");
const Allocator = std.mem.Allocator;
const Sha384 = std.crypto.hash.sha2.Sha384;

const Manifest = @This();

pub const digest_length = Sha384.digest_length;

pub const Tag = enum(u16) {
    kernel = 1,
    initrd = 2,
    cmdline = 3,
    device_tree = 4,
    memory_region = 5,
    device_config = 6,
    vcpu_count = 7,
    rootfs_verity = 8,
    /// Firmware, which is the first link in a chain: it measures what it loads, and that measures
    /// what it loads. Nothing inside a guest can vouch for the thing that started it, so this side
    /// measures this one.
    firmware = 9,
};

pub const Entry = struct {
    tag: Tag,
    digest: [digest_length]u8,
};

pub const Error = error{Sealed};

entries: std.ArrayList(Entry) = .empty,
sealed: bool = false,

pub fn deinit(self: *Manifest, gpa: Allocator) void {
    self.entries.deinit(gpa);
    self.* = undefined;
}

/// Measure one input. The order of calls is part of the measurement, so a caller
/// that loads inputs in a different order gets a different root.
pub fn add(self: *Manifest, gpa: Allocator, tag: Tag, bytes: []const u8) (Allocator.Error || Error)!void {
    if (self.sealed) return error.Sealed;

    var entry: Entry = .{ .tag = tag, .digest = undefined };
    Sha384.hash(bytes, &entry.digest, .{});
    try self.entries.append(gpa, entry);
}

/// No further input can be measured. The guest is about to run. A write to guest
/// memory after this point is a programmer error, not a recoverable fault.
pub fn seal(self: *Manifest) void {
    self.sealed = true;
}

pub fn root(self: *const Manifest) [digest_length]u8 {
    var hash: Sha384 = .init(.{});
    for (self.entries.items) |entry| {
        hash.update(&std.mem.toBytes(std.mem.nativeToLittle(u16, @intFromEnum(entry.tag))));
        hash.update(&entry.digest);
    }
    var out: [digest_length]u8 = undefined;
    hash.final(&out);
    return out;
}

test "the root changes when two entries swap order" {
    const gpa = testing.allocator();

    var forward: Manifest = .{};
    defer forward.deinit(gpa);
    try forward.add(gpa, .kernel, "kernel bytes");
    try forward.add(gpa, .initrd, "initrd bytes");

    var backward: Manifest = .{};
    defer backward.deinit(gpa);
    try backward.add(gpa, .initrd, "initrd bytes");
    try backward.add(gpa, .kernel, "kernel bytes");

    try std.testing.expect(!std.mem.eql(u8, &forward.root(), &backward.root()));
}

test "the tag is part of the measurement" {
    const gpa = testing.allocator();

    var as_kernel: Manifest = .{};
    defer as_kernel.deinit(gpa);
    try as_kernel.add(gpa, .kernel, "same bytes");

    var as_initrd: Manifest = .{};
    defer as_initrd.deinit(gpa);
    try as_initrd.add(gpa, .initrd, "same bytes");

    try std.testing.expect(!std.mem.eql(u8, &as_kernel.root(), &as_initrd.root()));
}

test "a sealed manifest refuses another entry" {
    const gpa = testing.allocator();

    var manifest: Manifest = .{};
    defer manifest.deinit(gpa);
    try manifest.add(gpa, .kernel, "kernel bytes");

    const before = manifest.root();
    manifest.seal();

    try testing.expectError(error.Sealed, manifest.add(gpa, .initrd, "initrd bytes"));
    try testing.expectEqualSlices(u8, &before, &manifest.root());
}
