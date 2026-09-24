//! KVM ioctl numbers, derived rather than written down.
//!
//! aarch64 uses the generic ioctl encoding: the direction, then the size of the
//! argument, then the driver letter, then the number. Deriving each number from the
//! Zig struct means a struct whose layout drifts from the kernel header cannot reach
//! the kernel. A number copied by hand would still look right.

const std = @import("std");
const testing = @import("mirage-testing");

/// The letter KVM registers, `KVMIO` in `linux/kvm.h`.
const driver = 0xAE;

const nr_bits = 8;
const type_bits = 8;
const size_bits = 14;

const size_mask = (1 << size_bits) - 1;
const type_shift = nr_bits;
const size_shift = nr_bits + type_bits;
const dir_shift = nr_bits + type_bits + size_bits;

pub const Dir = enum(u2) {
    none = 0,
    write = 1,
    read = 2,
    read_write = 3,
};

pub fn request(comptime dir: Dir, comptime T: type, comptime nr: u8) u32 {
    const size = if (T == void) 0 else @sizeOf(T);
    comptime {
        if (size > size_mask) @compileError("ioctl argument is too large for the size field");
    }
    return (@as(u32, @intFromEnum(dir)) << dir_shift) |
        (@as(u32, size) << size_shift) |
        (@as(u32, driver) << type_shift) |
        @as(u32, nr);
}

pub const Error = error{
    PermissionDenied,
    InvalidFileDescriptor,
    BadAddress,
    InvalidArgument,
    NotSupported,
    Interrupted,
    /// The kernel wanted more room than was offered, and said how much it needs.
    TooBig,
    OutOfMemory,
    Busy,
} || std.posix.UnexpectedError;

/// Every ioctl is I/O and is never assumed to succeed.
pub fn call(fd: std.posix.fd_t, req: u32, arg: usize) Error!usize {
    const rc = std.os.linux.ioctl(fd, req, arg);
    return switch (std.posix.errno(rc)) {
        .SUCCESS => rc,
        .PERM, .ACCES => Error.PermissionDenied,
        .BADF => Error.InvalidFileDescriptor,
        .FAULT => Error.BadAddress,
        .INVAL => Error.InvalidArgument,
        .NOSYS, .NOTTY, .OPNOTSUPP => Error.NotSupported,
        .INTR => Error.Interrupted,
        .@"2BIG" => Error.TooBig,
        .NOMEM => Error.OutOfMemory,
        .BUSY => Error.Busy,
        else => |e| std.posix.unexpectedErrno(e),
    };
}

pub const CreateGuestMemfd = extern struct {
    size: u64,
    flags: u64,
    reserved: [6]u64,
};

pub const UserspaceMemoryRegion2 = extern struct {
    slot: u32,
    flags: u32,
    guest_phys_addr: u64,
    memory_size: u64,
    userspace_addr: u64,
    guest_memfd_offset: u64,
    guest_memfd: u32,
    pad1: u32,
    pad2: [14]u64,
};

test "an argument free request encodes to its documented number" {
    try testing.expectEqual(@as(u32, 0xAE00), request(.none, void, 0x00));
    try testing.expectEqual(@as(u32, 0xAE01), request(.none, void, 0x01));
    try testing.expectEqual(@as(u32, 0xAE80), request(.none, void, 0x80));
}

test "a request carries the size of its argument struct" {
    try testing.expectEqual(@as(u32, 0xC040AED4), request(.read_write, CreateGuestMemfd, 0xd4));
    try testing.expectEqual(@as(u32, 0x40A0AE49), request(.write, UserspaceMemoryRegion2, 0x49));
}

test "the argument structs match the sizes the kernel headers give" {
    try testing.expectEqual(@as(usize, 64), @sizeOf(CreateGuestMemfd));
    try testing.expectEqual(@as(usize, 160), @sizeOf(UserspaceMemoryRegion2));
}
