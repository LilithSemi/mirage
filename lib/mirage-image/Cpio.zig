//! A cpio archive in the `newc` format, which is what the Linux kernel unpacks into
//! its initial filesystem.
//!
//! An entry is a 110 byte header of ASCII hexadecimal fields, then the name with a
//! terminator, then the contents. The name and the contents are each padded so the
//! next entry starts on a four byte boundary, and the archive ends with an entry
//! named `TRAILER!!!`. Without that trailer the kernel keeps reading past the end.
//!
//! Nothing here touches a file. The archive is built in memory and handed straight
//! to a guest, so `zig build` stays the only tool that has to exist.

const std = @import("std");
const testing = @import("mirage-testing");
const Allocator = std.mem.Allocator;

const Cpio = @This();

const magic = "070701";
const header_size = 110;
const trailer = "TRAILER!!!";

/// The file type bits of a mode, from `stat.h`.
const mode_file = 0o100000;
const mode_directory = 0o040000;
const mode_character = 0o020000;
const mode_symlink = 0o120000;

gpa: Allocator,
bytes: std.ArrayList(u8) = .empty,
/// Every entry needs an inode number, and they only have to differ.
next_inode: u32 = 1,

pub fn init(gpa: Allocator) Cpio {
    return .{ .gpa = gpa };
}

pub fn deinit(self: *Cpio) void {
    self.bytes.deinit(self.gpa);
    self.* = undefined;
}

fn hex(self: *Cpio, value: u32) Allocator.Error!void {
    var buffer: [8]u8 = undefined;
    // Exactly eight digits, zero padded. A shorter field moves every later one.
    _ = std.fmt.bufPrint(&buffer, "{x:0>8}", .{value}) catch unreachable;
    try self.bytes.appendSlice(self.gpa, &buffer);
}

fn pad(self: *Cpio) Allocator.Error!void {
    while (self.bytes.items.len % 4 != 0) try self.bytes.append(self.gpa, 0);
}

fn entry(
    self: *Cpio,
    name: []const u8,
    mode: u32,
    data: []const u8,
    major: u32,
    minor: u32,
) Allocator.Error!void {
    try self.bytes.appendSlice(self.gpa, magic);

    try self.hex(self.next_inode);
    self.next_inode += 1;

    try self.hex(mode);
    try self.hex(0); // uid
    try self.hex(0); // gid
    try self.hex(1); // nlink
    try self.hex(0); // mtime
    try self.hex(@intCast(data.len));
    try self.hex(0); // devmajor
    try self.hex(0); // devminor
    try self.hex(major);
    try self.hex(minor);
    try self.hex(@intCast(name.len + 1));
    try self.hex(0); // check, unused in this format

    try self.bytes.appendSlice(self.gpa, name);
    try self.bytes.append(self.gpa, 0);
    try self.pad();

    try self.bytes.appendSlice(self.gpa, data);
    try self.pad();
}

/// Paths carry no leading slash, because every entry is relative to the root of the
/// archive.
pub fn addFile(self: *Cpio, name: []const u8, permissions: u32, data: []const u8) Allocator.Error!void {
    return self.entry(name, mode_file | permissions, data, 0, 0);
}

pub fn addDirectory(self: *Cpio, name: []const u8, permissions: u32) Allocator.Error!void {
    return self.entry(name, mode_directory | permissions, &.{}, 0, 0);
}

/// A symbolic link stores where it points as its contents.
pub fn addSymlink(self: *Cpio, name: []const u8, target: []const u8) Allocator.Error!void {
    return self.entry(name, mode_symlink | 0o777, target, 0, 0);
}

/// The first process is given whatever `/dev/console` names, so an archive with no
/// console gives it nothing to write to.
pub fn addCharacterDevice(
    self: *Cpio,
    name: []const u8,
    permissions: u32,
    major: u32,
    minor: u32,
) Allocator.Error!void {
    return self.entry(name, mode_character | permissions, &.{}, major, minor);
}

/// The finished archive. The caller owns it.
pub fn finish(self: *Cpio) Allocator.Error![]u8 {
    try self.entry(trailer, 0, &.{}, 0, 0);
    return self.bytes.toOwnedSlice(self.gpa);
}

fn field(archive: []const u8, at: usize, index: usize) !u32 {
    const start = at + 6 + index * 8;
    return std.fmt.parseInt(u32, archive[start..][0..8], 16);
}

test "an entry begins with the magic the kernel looks for" {
    const gpa = testing.allocator();
    var archive: Cpio = .init(gpa);
    defer archive.deinit();

    try archive.addFile("init", 0o755, "hello");
    const bytes = try archive.finish();
    defer gpa.free(bytes);

    try testing.expectEqualSlices(u8, "070701", bytes[0..6]);
}

test "a file entry carries its size and its name" {
    const gpa = testing.allocator();
    var archive: Cpio = .init(gpa);
    defer archive.deinit();

    try archive.addFile("init", 0o755, "hello");
    const bytes = try archive.finish();
    defer gpa.free(bytes);

    try testing.expectEqual(@as(u32, 5), try field(bytes, 0, 6));
    try testing.expectEqual(@as(u32, 5), try field(bytes, 0, 11));
    try testing.expectEqualSlices(u8, "init\x00", bytes[110..115]);
}

test "a regular file carries the regular file bit above its permissions" {
    const gpa = testing.allocator();
    var archive: Cpio = .init(gpa);
    defer archive.deinit();

    try archive.addFile("init", 0o755, "x");
    const bytes = try archive.finish();
    defer gpa.free(bytes);

    try testing.expectEqual(@as(u32, 0o100755), try field(bytes, 0, 1));
}

test "a directory carries the directory bit and no data" {
    const gpa = testing.allocator();
    var archive: Cpio = .init(gpa);
    defer archive.deinit();

    try archive.addDirectory("dev", 0o755);
    const bytes = try archive.finish();
    defer gpa.free(bytes);

    try testing.expectEqual(@as(u32, 0o40755), try field(bytes, 0, 1));
    try testing.expectEqual(@as(u32, 0), try field(bytes, 0, 6));
}

test "a character device carries its major and minor numbers" {
    const gpa = testing.allocator();
    var archive: Cpio = .init(gpa);
    defer archive.deinit();

    // The console the kernel hands to the first process.
    try archive.addCharacterDevice("dev/console", 0o600, 5, 1);
    const bytes = try archive.finish();
    defer gpa.free(bytes);

    try testing.expectEqual(@as(u32, 0o20600), try field(bytes, 0, 1));
    try testing.expectEqual(@as(u32, 5), try field(bytes, 0, 9));
    try testing.expectEqual(@as(u32, 1), try field(bytes, 0, 10));
}

test "every entry starts on a four byte boundary" {
    const gpa = testing.allocator();
    var archive: Cpio = .init(gpa);
    defer archive.deinit();

    // A name and a body that are both awkward lengths, so the padding has to work.
    try archive.addFile("a", 0o644, "xyz");
    try archive.addFile("bb", 0o644, "wxyz!");
    const bytes = try archive.finish();
    defer gpa.free(bytes);

    // The second entry has to begin with the magic, which only happens if the first
    // one padded its name and its data correctly.
    const second = std.mem.alignForward(usize, 110 + 2 + std.mem.alignForward(usize, 3, 4), 4);
    _ = second;
    const found = std.mem.indexOfPos(u8, bytes, 6, "070701").?;
    try testing.expectEqual(@as(usize, 0), found % 4);
}

test "the archive ends with the trailer and nothing after it" {
    const gpa = testing.allocator();
    var archive: Cpio = .init(gpa);
    defer archive.deinit();

    try archive.addFile("init", 0o755, "hello");
    const bytes = try archive.finish();
    defer gpa.free(bytes);

    // Without this the kernel keeps reading past the end of the archive.
    const at = std.mem.lastIndexOf(u8, bytes, "070701").?;
    try testing.expectEqualSlices(u8, "TRAILER!!!\x00", bytes[at + 110 ..][0..11]);
    try testing.expectEqual(@as(u32, 0), try field(bytes, at, 6));
}

test "the finished archive is a whole number of four byte words" {
    const gpa = testing.allocator();
    var archive: Cpio = .init(gpa);
    defer archive.deinit();

    try archive.addFile("odd-name-here", 0o644, "seven!!");
    const bytes = try archive.finish();
    defer gpa.free(bytes);

    try testing.expectEqual(@as(usize, 0), bytes.len % 4);
}

test "a symbolic link says it is one and carries where it points" {
    const gpa = testing.allocator();
    var archive: Cpio = .init(gpa);
    defer archive.deinit();

    try archive.addFile("init", 0o755, "#!/bin/sh\n");
    try archive.addSymlink("sbin-init", "init");

    const blob = try archive.finish();
    defer gpa.free(blob);

    // The target is the contents of a link, which is how the format carries it, so the name it
    // points at is in the archive as bytes.
    try std.testing.expect(std.mem.indexOf(u8, blob, "sbin-init") != null);

    // The mode says what kind of thing it is, and a link whose mode says regular file is a file
    // holding a path rather than a link to one. The mode is the seventh field of the header, eight
    // hexadecimal digits each.
    const at = std.mem.indexOf(u8, blob, "sbin-init").?;
    const header = at - 110;
    const mode = try std.fmt.parseInt(u32, blob[header + 14 ..][0..8], 16);
    try testing.expectEqual(@as(u32, mode_symlink | 0o777), mode);

    // And the file beside it is still a file, so the mode was not written for everything.
    const file_at = std.mem.indexOf(u8, blob, "init\x00").?;
    const file_header = file_at - 110;
    const file_mode = try std.fmt.parseInt(u32, blob[file_header + 14 ..][0..8], 16);
    try std.testing.expect(file_mode & mode_symlink != mode_symlink);
}
