//! What this host's KVM can actually do.
//!
//! The tier table in the design rests on one claim: that guest memory created
//! without `GUEST_MEMFD_FLAG_MMAP` cannot be mapped by the VMM process. The flag is
//! opt in by the kernel ABI, but an ABI that permits a refusal is not proof that this
//! kernel refuses. This module asks the running kernel and reports what it answered.
//!
//! Every field here is something the kernel was asked, never something assumed.

const std = @import("std");
const ioctl = @import("ioctl.zig");
const linux = std.os.linux;

const nr = struct {
    const get_api_version = 0x00;
    const create_vm = 0x01;
    const check_extension = 0x03;
    const create_guest_memfd = 0xd4;
    const set_user_memory_region2 = 0x49;
};

/// `KVM_CAP_*` in `linux/kvm.h`.
pub const Cap = enum(u32) {
    user_memory2 = 231,
    memory_attributes = 233,
    guest_memfd = 234,
    guest_memfd_flags = 244,
};

/// `GUEST_MEMFD_FLAG_MMAP`. Leaving it clear is what asks for memory the VMM cannot
/// map. Setting it gives the ordinary mappable memory a non confidential guest uses.
const flag_mmap: u64 = 1 << 0;

/// The version this code was written against. `KVM_GET_API_VERSION` has returned 12
/// since Linux 2.6.22 and a different value means a kernel this code does not know.
pub const expected_api_version = 12;

pub const Error = error{NoKvm} || ioctl.Error || std.posix.MMapError;

pub const Report = struct {
    api_version: u32,
    user_memory2: bool,
    memory_attributes: bool,
    guest_memfd: bool,
    guest_memfd_flags: u64,
    private_refuses_mapping: bool,
    shared_allows_mapping: bool,
    /// Whether an unmappable `guest_memfd` is accepted as the backing of a memory
    /// slot. This, and not the refusal above, is the question tier 1 turns on. A
    /// memfd the VMM cannot map is worth nothing if it cannot hold guest RAM.
    private_backs_memory: bool,

    /// The strongest tier this host reaches. Tier 1 needs guest RAM the VMM has no
    /// mapping of, which needs both a refusal and a memory slot that accepts it.
    pub fn tier(self: Report) u8 {
        if (self.guest_memfd and self.private_refuses_mapping and self.private_backs_memory) return 1;
        return 0;
    }
};

fn extension(fd: std.posix.fd_t, cap: Cap) ioctl.Error!usize {
    return ioctl.call(fd, comptime ioctl.request(.none, void, nr.check_extension), @intFromEnum(cap));
}

/// Create guest memory of one page with these flags, and report the file descriptor.
fn guestMemfd(vm: std.posix.fd_t, flags: u64) Error!std.posix.fd_t {
    var args: ioctl.CreateGuestMemfd = .{ .size = std.heap.pageSize(), .flags = flags, .reserved = @splat(0) };
    const raw = try ioctl.call(
        vm,
        comptime ioctl.request(.read_write, ioctl.CreateGuestMemfd, nr.create_guest_memfd),
        @intFromPtr(&args),
    );
    return @intCast(raw);
}

/// Ask whether this kernel accepts such a `guest_memfd` as the memory of a guest.
fn backsMemory(vm: std.posix.fd_t, flags: u64) Error!bool {
    const memfd = try guestMemfd(vm, flags);
    defer _ = linux.close(memfd);

    var region: ioctl.UserspaceMemoryRegion2 = .{
        .slot = 0,
        .flags = 1 << 2,
        .guest_phys_addr = 0x4000_0000,
        .memory_size = std.heap.pageSize(),
        .userspace_addr = 0,
        .guest_memfd_offset = 0,
        .guest_memfd = @intCast(memfd),
        .pad1 = 0,
        .pad2 = @splat(0),
    };
    _ = ioctl.call(
        vm,
        comptime ioctl.request(.write, ioctl.UserspaceMemoryRegion2, nr.set_user_memory_region2),
        @intFromPtr(&region),
    ) catch |err| switch (err) {
        error.InvalidArgument => return false,
        else => return err,
    };
    return true;
}

/// Create guest memory of one page and report whether the VMM may map it.
fn mappable(vm: std.posix.fd_t, flags: u64) Error!bool {
    const size = std.heap.pageSize();

    var args: ioctl.CreateGuestMemfd = .{ .size = size, .flags = flags, .reserved = @splat(0) };
    const raw = try ioctl.call(
        vm,
        comptime ioctl.request(.read_write, ioctl.CreateGuestMemfd, nr.create_guest_memfd),
        @intFromPtr(&args),
    );

    const memfd: std.posix.fd_t = @intCast(raw);
    defer _ = linux.close(memfd);

    const mapped = std.posix.mmap(
        null,
        size,
        .{ .READ = true, .WRITE = true },
        .{ .TYPE = .SHARED },
        memfd,
        0,
    ) catch return false;
    std.posix.munmap(mapped);
    return true;
}

pub fn host() Error!Report {
    const opened = linux.open("/dev/kvm", .{ .ACCMODE = .RDWR, .CLOEXEC = true }, 0);
    if (std.posix.errno(opened) != .SUCCESS) return Error.NoKvm;
    const fd: std.posix.fd_t = @intCast(opened);
    defer _ = linux.close(fd);

    const api = try ioctl.call(fd, comptime ioctl.request(.none, void, nr.get_api_version), 0);

    var report: Report = .{
        .api_version = @intCast(api),
        .user_memory2 = try extension(fd, .user_memory2) != 0,
        .memory_attributes = try extension(fd, .memory_attributes) != 0,
        .guest_memfd = try extension(fd, .guest_memfd) != 0,
        .guest_memfd_flags = try extension(fd, .guest_memfd_flags),
        .private_refuses_mapping = false,
        .shared_allows_mapping = false,
        .private_backs_memory = false,
    };

    if (!report.guest_memfd) return report;

    const raw_vm = try ioctl.call(fd, comptime ioctl.request(.none, void, nr.create_vm), 0);
    const vm: std.posix.fd_t = @intCast(raw_vm);
    defer _ = linux.close(vm);

    report.private_refuses_mapping = !try mappable(vm, 0);
    report.shared_allows_mapping = mappable(vm, flag_mmap) catch false;
    report.private_backs_memory = backsMemory(vm, 0) catch false;

    return report;
}

test "the kvm api version is the one this code was written against" {
    const report = host() catch |err| switch (err) {
        error.NoKvm => return error.SkipZigTest,
        else => return err,
    };
    try std.testing.expect(report.api_version == 12);
}

test "guest memory without the mmap flag cannot be mapped by the vmm" {
    const report = host() catch |err| switch (err) {
        error.NoKvm => return error.SkipZigTest,
        else => return err,
    };
    if (!report.guest_memfd) return error.SkipZigTest;

    try std.testing.expect(report.private_refuses_mapping);
}

test "a guest_memfd the vmm cannot map also cannot hold guest memory here" {
    const report = host() catch |err| switch (err) {
        error.NoKvm => return error.SkipZigTest,
        else => return err,
    };
    if (!report.guest_memfd) return error.SkipZigTest;

    // Measured on aarch64, Linux 6.18.52, 2026-09-24. KVM refuses a memory slot
    // backed by a `guest_memfd` made without `GUEST_MEMFD_FLAG_MMAP`, with EINVAL,
    // whatever `userspace_addr` holds. Without `KVM_CAP_MEMORY_ATTRIBUTES` there is
    // no way to fault a private page, so the kernel demands the mappable flag. A
    // refusal to map therefore buys nothing on its own, and tier 1 needs x86 with
    // SEV-SNP, or pKVM.
    //
    // A kernel that gains memory attributes should make this pass through the skip
    // above. If it fails instead, the tier table gained a row. Update the table,
    // do not delete the test.
    if (report.memory_attributes) return error.SkipZigTest;

    try std.testing.expect(!report.private_backs_memory);
    try std.testing.expectEqual(@as(u8, 0), report.tier());
}

test "guest memory asked to be mappable can be mapped" {
    const report = host() catch |err| switch (err) {
        error.NoKvm => return error.SkipZigTest,
        else => return err,
    };
    if (!report.guest_memfd) return error.SkipZigTest;

    // The control. Without it, a refusal above proves only that the flag is
    // unsupported, not that it means anything.
    try std.testing.expect(report.shared_allows_mapping);
}
