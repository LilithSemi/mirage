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
    /// The vCPU was not runnable yet, so KVM_RUN handed it back. An application
    /// processor that has not had its startup signal reports this until it does.
    WouldBlock,
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
        .AGAIN => Error.WouldBlock,
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

/// `KVM_MEMORY_ENCRYPT_OP` envelope, 24 bytes. `data` is a userspace pointer to the
/// sub-command struct; `error` is the firmware error out-param.
pub const KvmSevCmd = extern struct {
    id: u32,
    pad0: u32 = 0,
    data: u64,
    @"error": u32 = 0,
    /// The LAUNCH commands issue through a /dev/sev file descriptor the caller opens and passes here.
    /// INIT2 brokers the platform in the kernel and leaves this zero.
    sev_fd: u32 = 0,

    comptime {
        std.debug.assert(@sizeOf(KvmSevCmd) == 24);
    }
};

/// `kvm_sev_init` for `KVM_SEV_INIT2`. Pass all-zero for plain SEV.
pub const KvmSevInit = extern struct {
    vmsa_features: u64,
    flags: u32,
    ghcb_version: u16,
    pad1: u16,
    pad2: [8]u32,

    comptime {
        std.debug.assert(@sizeOf(KvmSevInit) == 48);
    }
};

/// `kvm_sev_launch_start` for `KVM_SEV_LAUNCH_START`.
pub const KvmSevLaunchStart = extern struct {
    handle: u32,
    policy: u32,
    dh_uaddr: u64,
    dh_len: u32,
    pad0: u32 = 0,
    session_uaddr: u64,
    session_len: u32,
    pad1: u32 = 0,

    comptime {
        std.debug.assert(@sizeOf(KvmSevLaunchStart) == 40);
    }
};

/// `kvm_sev_launch_update_data` for `KVM_SEV_LAUNCH_UPDATE_DATA`.
pub const KvmSevLaunchUpdateData = extern struct {
    uaddr: u64,
    len: u32,
    pad0: u32 = 0,

    comptime {
        std.debug.assert(@sizeOf(KvmSevLaunchUpdateData) == 16);
    }
};

/// `kvm_sev_launch_measure` for `KVM_SEV_LAUNCH_MEASURE`.
pub const KvmSevLaunchMeasure = extern struct {
    uaddr: u64,
    len: u32,
    pad0: u32 = 0,

    comptime {
        std.debug.assert(@sizeOf(KvmSevLaunchMeasure) == 16);
    }
};

/// `kvm_sev_launch_secret` for `KVM_SEV_LAUNCH_SECRET`.
pub const KvmSevLaunchSecret = extern struct {
    hdr_uaddr: u64,
    hdr_len: u32,
    pad0: u32 = 0,
    guest_uaddr: u64,
    guest_len: u32,
    pad1: u32 = 0,
    trans_uaddr: u64,
    trans_len: u32,
    pad2: u32 = 0,

    comptime {
        std.debug.assert(@sizeOf(KvmSevLaunchSecret) == 48);
    }
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
