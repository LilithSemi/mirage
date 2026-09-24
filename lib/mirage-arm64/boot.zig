//! The aarch64 Linux boot protocol, as far as a VMM needs it.
//!
//! An `Image` begins with a 64 byte header. The VMM reads it to learn where the
//! kernel wants to sit and what it was built for, then places the image, puts the
//! device tree address in `x0`, zeroes `x1` through `x3`, and enters at the start of
//! the image with the MMU off.
//!
//! Every field is little endian on disk, whatever the host is, so each one is read
//! with an explicit byte order rather than copied over the struct.

const std = @import("std");
const testing = @import("mirage-testing");

/// "ARM\x64" read as a little endian word, at offset 56.
pub const magic: u32 = 0x644d5241;

/// The protocol places an image at a 2MB aligned base.
pub const alignment = 2 * 1024 * 1024;

/// Bits 2 and 1 of the flags. Every value of a `u2` is named, so reading one can
/// never fail.
pub const PageSize = enum(u2) {
    unspecified = 0,
    @"4k" = 1,
    @"16k" = 2,
    @"64k" = 3,
};

pub const Header = extern struct {
    code0: u32,
    code1: u32,
    text_offset: u64,
    image_size: u64,
    flags: u64,
    res2: u64,
    res3: u64,
    res4: u64,
    magic: u32,
    res5: u32,

    comptime {
        if (@sizeOf(Header) != 64) @compileError("the aarch64 Image header is 64 bytes");
    }

    /// Bit 0 clear. A big endian kernel needs a big endian host and this is not one.
    pub fn littleEndian(self: Header) bool {
        return self.flags & 1 == 0;
    }

    pub fn pageSize(self: Header) PageSize {
        return @enumFromInt(@as(u2, @truncate(self.flags >> 1)));
    }

    /// Bit 3. A kernel that sets it sits at any 2MB aligned address. One that does
    /// not wants a base near the start of usable memory.
    pub fn placeAnywhere(self: Header) bool {
        return self.flags & (1 << 3) != 0;
    }
};

pub const Error = error{
    TooSmall,
    NotAnImage,
    BigEndianKernel,
};

pub fn parse(image: []const u8) Error!Header {
    if (image.len < @sizeOf(Header)) return Error.TooSmall;
    const bytes: *const [@sizeOf(Header)]u8 = image[0..@sizeOf(Header)];

    const header: Header = .{
        .code0 = std.mem.readInt(u32, bytes[0..4], .little),
        .code1 = std.mem.readInt(u32, bytes[4..8], .little),
        .text_offset = std.mem.readInt(u64, bytes[8..16], .little),
        .image_size = std.mem.readInt(u64, bytes[16..24], .little),
        .flags = std.mem.readInt(u64, bytes[24..32], .little),
        .res2 = 0,
        .res3 = 0,
        .res4 = 0,
        .magic = std.mem.readInt(u32, bytes[56..60], .little),
        .res5 = std.mem.readInt(u32, bytes[60..64], .little),
    };

    if (header.magic != magic) return Error.NotAnImage;
    if (!header.littleEndian()) return Error.BigEndianKernel;
    return header;
}

/// Where the image goes in guest physical memory.
pub fn loadAddress(ram_base: u64, header: Header) u64 {
    return std.mem.alignForward(u64, ram_base, alignment) + header.text_offset;
}

/// The first 64 bytes of the aarch64 Linux kernel this machine booted, taken from
/// `/run/current-system/kernel` on 2026-09-24. Real bytes, embedded rather than read,
/// because a test that opens a file cannot build for a target that has no files.
const real_kernel_header = [_]u8{
    0x4d, 0x5a, 0x40, 0xfa, 0x27, 0x04, 0xc6, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0x52, 0x4d, 0x64, 0x40, 0x00, 0x00, 0x00,
};

test "a real kernel image is recognised" {
    const header = try parse(&real_kernel_header);
    try testing.expectEqual(magic, header.magic);
}

test "the real kernel is little endian and asks for 64K pages" {
    const header = try parse(&real_kernel_header);

    try std.testing.expect(header.littleEndian());
    // This machine reports a host page size of 65536, and the kernel it booted says
    // the same thing here. The two agree, which is why a memory slot sized for a 4K
    // host is refused.
    try testing.expectEqual(PageSize.@"64k", header.pageSize());
}

test "the real kernel may be placed anywhere, at no offset" {
    const header = try parse(&real_kernel_header);

    try std.testing.expect(header.placeAnywhere());
    try testing.expectEqual(@as(u64, 0), header.text_offset);
    try testing.expectEqual(@as(u64, 0x0400_0000), header.image_size);
}

test "a buffer too short to hold a header is refused" {
    try testing.expectError(error.TooSmall, parse(real_kernel_header[0..32]));
}

test "a buffer without the magic is refused" {
    var bad = real_kernel_header;
    bad[56] = 0;
    try testing.expectError(error.NotAnImage, parse(&bad));
}

test "a big endian kernel is refused rather than booted sideways" {
    var big = real_kernel_header;
    big[24] |= 1;
    try testing.expectError(error.BigEndianKernel, parse(&big));
}

test "the load address is the text offset above a 2MB aligned base" {
    const header = try parse(&real_kernel_header);
    try testing.expectEqual(@as(u64, 0x4000_0000), loadAddress(0x4000_0000, header));

    // A base that is not 2MB aligned is rounded up, because the protocol requires it.
    var offset = header;
    offset.text_offset = 0x8_0000;
    try testing.expectEqual(@as(u64, 0x4020_0000 + 0x8_0000), loadAddress(0x4000_1000, offset));
}
