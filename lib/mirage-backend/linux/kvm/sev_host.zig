//! /dev/sev user-space command layer.
//!
//! The KVM VM-fd handles encrypted launch (INIT2, START, UPDATE, MEASURE, FINISH).
//! The platform's own PDH public key and firmware version come from a separate ioctl
//! on /dev/sev. This file issues those two commands. The fd is root-only; callers
//! that get null from `Vm.openSev()` skip the work.

const std = @import("std");
const linux = std.os.linux;
const Vm = @import("Vm.zig");

// SEV_ISSUE_CMD = _IOWR('S', 0x0, struct sev_issue_cmd)
// dir=3 (read+write) <<30 | size=16 <<16 | type=0x53 ('S') <<8 | nr=0
pub const issue_cmd_request: u32 = (3 << 30) | (16 << 16) | (0x53 << 8) | 0;

pub const Cmd = enum(u32) {
    platform_status = 1,
    pdh_cert_export = 5,
};

/// `struct sev_issue_cmd` __packed, 16 bytes.
pub const SevIssueCmd = extern struct {
    cmd: u32,
    data: u64 align(1),
    err: u32,

    comptime {
        std.debug.assert(@sizeOf(SevIssueCmd) == 16);
    }
};

/// `struct sev_user_data_status` __packed, 12 bytes.
const PlatformStatus = extern struct {
    api_major: u8,
    api_minor: u8,
    state: u8,
    flags: u32 align(1),
    build: u8,
    guest_count: u32 align(1),

    comptime {
        std.debug.assert(@sizeOf(PlatformStatus) == 12);
    }
};

/// `struct sev_user_data_pdh_cert_export` __packed, 24 bytes.
const PdhCertExport = extern struct {
    pdh_cert_address: u64,
    pdh_cert_len: u32,
    cert_chain_address: u64 align(1),
    cert_chain_len: u32 align(1),

    comptime {
        std.debug.assert(@sizeOf(PdhCertExport) == 24);
    }
};

pub const Error = error{
    SevFirmwareError,
    PdhBufTooSmall,
    ChainBufTooSmall,
} || std.posix.UnexpectedError || error{
    PermissionDenied,
    InvalidFileDescriptor,
    BadAddress,
    InvalidArgument,
};

fn issueCmd(sev_fd: std.posix.fd_t, cmd: Cmd, data: u64) Error!void {
    var envelope: SevIssueCmd = .{ .cmd = @backingInt(cmd), .data = data, .err = 0 };
    const rc = linux.ioctl(sev_fd, issue_cmd_request, @intFromPtr(&envelope));
    if (envelope.err != 0) return Error.SevFirmwareError;
    return switch (std.posix.errno(rc)) {
        .SUCCESS => {},
        .PERM, .ACCES => Error.PermissionDenied,
        .BADF => Error.InvalidFileDescriptor,
        .FAULT => Error.BadAddress,
        .INVAL => Error.InvalidArgument,
        .IO => Error.SevFirmwareError,
        else => |e| std.posix.unexpectedErrno(e),
    };
}

pub const PlatformInfo = struct {
    api_major: u8,
    api_minor: u8,
    build: u8,
    state: u8,
};

pub fn platformStatus(sev_fd: std.posix.fd_t) Error!PlatformInfo {
    var status: PlatformStatus = std.mem.zeroes(PlatformStatus);
    try issueCmd(sev_fd, .platform_status, @intFromPtr(&status));
    return .{
        .api_major = status.api_major,
        .api_minor = status.api_minor,
        .build = status.build,
        .state = status.state,
    };
}

pub const PdhResult = struct {
    pdh: []u8,
    chain: []u8,
};

pub fn pdhCertExport(sev_fd: std.posix.fd_t, pdh_buf: []u8, chain_buf: []u8) Error!PdhResult {
    // Length probe: pass zero addresses to get the required sizes back.
    var args: PdhCertExport = .{
        .pdh_cert_address = 0,
        .pdh_cert_len = 0,
        .cert_chain_address = 0,
        .cert_chain_len = 0,
    };
    issueCmd(sev_fd, .pdh_cert_export, @intFromPtr(&args)) catch |err| switch (err) {
        error.SevFirmwareError => {},
        else => return err,
    };
    const pdh_len = args.pdh_cert_len;
    const chain_len = args.cert_chain_len;

    if (pdh_len > pdh_buf.len) return Error.PdhBufTooSmall;
    if (chain_len > chain_buf.len) return Error.ChainBufTooSmall;

    args = .{
        .pdh_cert_address = @intFromPtr(pdh_buf.ptr),
        .pdh_cert_len = pdh_len,
        .cert_chain_address = @intFromPtr(chain_buf.ptr),
        .cert_chain_len = chain_len,
    };
    try issueCmd(sev_fd, .pdh_cert_export, @intFromPtr(&args));
    return .{ .pdh = pdh_buf[0..pdh_len], .chain = chain_buf[0..chain_len] };
}

test "a /dev/sev platform status reports an api version" {
    const sev_fd = Vm.openSev() orelse return error.SkipZigTest;
    defer _ = linux.close(sev_fd);
    const info = try platformStatus(sev_fd);
    try std.testing.expect(info.api_major > 0);
}
