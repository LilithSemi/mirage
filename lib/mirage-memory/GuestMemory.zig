//! The guest's physical address space, and who is allowed to touch it.
//!
//! A region is either shared, which means the VMM holds a mapping of it, or private,
//! which means it does not. Private is not a policy this module enforces on itself.
//! It is a fact about the host: `guest_memfd` without `GUEST_MEMFD_FLAG_MMAP` gives
//! the VMM no mapping to hold, and SEV-SNP gives it ciphertext. Either way `slice`
//! has nothing to hand back, so it refuses.
//!
//! Callers must handle that refusal. A device model that assumes every guest page is
//! addressable works today and has to be rewritten at tier 3.
//!
//! On aarch64 the split between the two is fixed before launch, because this kernel
//! has no `KVM_CAP_MEMORY_ATTRIBUTES` and a guest cannot move a page between them
//! while it runs. On x86 it becomes dynamic. The interface does not change.

const std = @import("std");
const testing = @import("mirage-testing");

const GuestMemory = @This();

pub const Error = error{ OutOfBounds, PrivateMemory };

pub const Backing = union(enum) {
    /// The VMM holds a mapping of these bytes.
    shared: []u8,
    /// The VMM holds no mapping. Only the guest and the hypervisor reach these bytes.
    private,
};

pub const Region = struct {
    gpa: u64,
    len: u64,
    backing: Backing,
};

regions: []const Region,

const Found = struct {
    region: *const Region,
    offset: usize,
};

fn find(self: *const GuestMemory, gpa: u64, len: u64) Error!Found {
    // The guest chooses the address and the length. Unchecked arithmetic here wraps
    // and then passes a bounds test that it should have failed.
    const end = std.math.add(u64, gpa, len) catch return Error.OutOfBounds;

    for (self.regions) |*region| {
        if (gpa < region.gpa) continue;
        if (end > region.gpa + region.len) continue;
        return .{ .region = region, .offset = @intCast(gpa - region.gpa) };
    }
    return Error.OutOfBounds;
}

/// Borrow guest memory directly. This fails for a private region, which the VMM
/// cannot map. The caller handles the failure and does not assume a mapping.
pub fn slice(self: *GuestMemory, gpa: u64, len: u64) Error![]u8 {
    const found = try self.find(gpa, len);
    return switch (found.region.backing) {
        .shared => |bytes| bytes[found.offset..][0..@intCast(len)],
        .private => Error.PrivateMemory,
    };
}

pub fn read(self: *const GuestMemory, gpa: u64, out: []u8) Error!void {
    const found = try self.find(gpa, out.len);
    switch (found.region.backing) {
        .shared => |bytes| @memcpy(out, bytes[found.offset..][0..out.len]),
        .private => return Error.PrivateMemory,
    }
}

pub fn write(self: *GuestMemory, gpa: u64, in: []const u8) Error!void {
    const found = try self.find(gpa, in.len);
    switch (found.region.backing) {
        .shared => |bytes| @memcpy(bytes[found.offset..][0..in.len], in),
        .private => return Error.PrivateMemory,
    }
}

const shared_base = 0x4000_0000;
const private_base = 0x8000_0000;

/// Owns its own storage, because a `GuestMemory` borrows the regions it is given and
/// a region literal in a return statement would not outlive the call.
const Fixture = struct {
    bytes: [64]u8 = @splat(0),
    regions: [2]Region = undefined,

    fn memory(self: *Fixture) GuestMemory {
        self.regions = .{
            .{ .gpa = shared_base, .len = self.bytes.len, .backing = .{ .shared = &self.bytes } },
            .{ .gpa = private_base, .len = 0x1000, .backing = .private },
        };
        return .{ .regions = &self.regions };
    }
};

test "a read returns what a write put at that address" {
    var f: Fixture = .{};
    var memory = f.memory();

    try memory.write(shared_base + 0x10, "mirage");

    var out: [6]u8 = undefined;
    try memory.read(shared_base + 0x10, &out);
    try testing.expectEqualSlices(u8, "mirage", &out);
}

test "an address in no region is out of bounds" {
    var f: Fixture = .{};
    var memory = f.memory();

    var out: [4]u8 = undefined;
    try testing.expectError(error.OutOfBounds, memory.read(0x1000, &out));
}

test "a read that runs past the end of a region is out of bounds" {
    var f: Fixture = .{};
    var memory = f.memory();

    var out: [8]u8 = undefined;
    try testing.expectError(error.OutOfBounds, memory.read(shared_base + 60, &out));
}

test "a length that overflows the address is out of bounds" {
    var f: Fixture = .{};
    var memory = f.memory();

    try testing.expectError(error.OutOfBounds, memory.slice(shared_base, std.math.maxInt(u64)));
}

test "private memory refuses to be borrowed" {
    var f: Fixture = .{};
    var memory = f.memory();

    try testing.expectError(error.PrivateMemory, memory.slice(private_base, 8));
}

test "private memory refuses to be read or written" {
    var f: Fixture = .{};
    var memory = f.memory();

    var out: [8]u8 = undefined;
    try testing.expectError(error.PrivateMemory, memory.read(private_base, &out));
    try testing.expectError(error.PrivateMemory, memory.write(private_base, "nope"));
}

test "a borrowed slice aliases the region, so a write through it is visible" {
    var f: Fixture = .{};
    var memory = f.memory();

    const window = try memory.slice(shared_base + 4, 4);
    @memcpy(window, "zigs");

    var out: [4]u8 = undefined;
    try memory.read(shared_base + 4, &out);
    try testing.expectEqualSlices(u8, "zigs", &out);
}
