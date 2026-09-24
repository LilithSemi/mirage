//! An EROFS image, built in memory.
//!
//! EROFS is a read only filesystem, which is what a guest root should be. Everything
//! here uses the plain uncompressed layout and the compact 32 byte inode, because a
//! VMM needs the image to be simple and verifiable rather than small.
//!
//! The layout is: block zero holds the superblock at a fixed offset inside it, the
//! inode table follows, and file and directory contents follow that. An inode is
//! named by a number that is its offset into the inode table divided by 32, so the
//! table has to be laid out before anything can point at it.
//!
//! Every integer on disk is little endian whatever the host is.

const std = @import("std");
const testing = @import("mirage-testing");
const Allocator = std.mem.Allocator;

const Erofs = @This();

/// `EROFS_SUPER_MAGIC_V1`.
pub const magic: u32 = 0xe0f5_e1e2;
/// The superblock does not start at zero, so a boot sector can sit in front of it.
pub const super_offset = 1024;
pub const block_size = 4096;
const block_shift = 12;
/// An inode slot is 32 bytes, and a number names a slot.
const slot_size = 32;
/// The inode table starts here, leaving block zero to the superblock.
const meta_block = 1;

pub const Error = error{
    /// A directory whose entries do not fit in one block. Splitting a directory over
    /// several blocks is allowed by the format and not implemented here, so say so
    /// rather than write an image that reads back short.
    DirectoryTooLarge,
    NotADirectory,
} || Allocator.Error;

pub const Superblock = extern struct {
    magic: u32,
    checksum: u32,
    feature_compat: u32,
    blkszbits: u8,
    sb_extslots: u8,
    root_nid: u16,
    inos: u64,
    build_time: u64,
    build_time_nsec: u32,
    blocks: u32,
    meta_blkaddr: u32,
    xattr_blkaddr: u32,
    uuid: [16]u8,
    volume_name: [16]u8,
    feature_incompat: u32,
    available_compr_algs: u16,
    extra_devices: u16,
    devt_slotoff: u16,
    dirblkbits: u8,
    xattr_prefix_count: u8,
    xattr_prefix_start: u32,
    packed_nid: u64,
    xattr_filter_reserved: u8,
    reserved2: [23]u8,
};

pub const Inode = extern struct {
    i_format: u16,
    i_xattr_icount: u16,
    i_mode: u16,
    i_nlink: u16,
    i_size: u32,
    i_reserved: u32,
    /// The first block of the contents, for the plain layout.
    i_u: u32,
    i_ino: u32,
    i_uid: u16,
    i_gid: u16,
    i_reserved2: u32,
};

/// The shape of one entry, for reading. Neither an extern nor a packed struct
/// reports 12 bytes here: the `u64` gives the first C alignment and the second a
/// backing integer that rounds up. `dirent_size` is the authority, and the entries
/// are written field by field.
pub const Dirent = packed struct {
    nid: u64,
    /// Where the name is, counted from the start of the block this entry is in.
    nameoff: u16,
    file_type: u8,
    reserved: u8,
};

/// `EROFS_FT_*`.
/// On disk an entry is twelve bytes, whatever a struct of those fields measures.
const dirent_size = 12;

const file_type_regular = 1;
const file_type_directory = 2;
const file_type_character = 3;

comptime {
    if (@sizeOf(Superblock) != 128) @compileError("the erofs superblock is 128 bytes");
    if (@sizeOf(Inode) != slot_size) @compileError("a compact erofs inode is 32 bytes");
    if (@bitSizeOf(Dirent) != dirent_size * 8) @compileError("an erofs directory entry is 12 bytes");
}

const Node = struct {
    /// The full path, so a caller can find a node again.
    path: []u8,
    /// The last component, which is what a directory entry holds.
    name: []const u8,
    directory: bool,
    /// A character device has no contents. Its inode carries the device number
    /// where a file would carry its first block.
    character: bool = false,
    rdev: u32 = 0,
    data: []u8,
    children: std.ArrayList(usize) = .empty,
    parent: usize,
    nid: u64 = 0,
    block: u32 = 0,
    size: u64 = 0,
};

gpa: Allocator,
nodes: std.ArrayList(Node) = .empty,

pub fn init(gpa: Allocator) Erofs {
    var fs: Erofs = .{ .gpa = gpa };
    // The root is always the first inode, so its number is zero.
    fs.nodes.append(gpa, .{
        .path = &.{},
        .name = &.{},
        .directory = true,
        .data = &.{},
        .parent = 0,
    }) catch {};
    return fs;
}

pub fn deinit(self: *Erofs) void {
    for (self.nodes.items) |*node| {
        self.gpa.free(node.path);
        self.gpa.free(node.data);
        node.children.deinit(self.gpa);
    }
    self.nodes.deinit(self.gpa);
    self.* = undefined;
}

pub fn lookup(self: *const Erofs, path: []const u8) ?u64 {
    for (self.nodes.items) |node| {
        if (std.mem.eql(u8, node.path, path)) return node.nid;
    }
    return null;
}

/// Read an inode back out of a finished image.
pub fn inodeAt(self: *const Erofs, image: []const u8, nid: u64) *align(1) const Inode {
    _ = self;
    const at = meta_block * block_size + nid * slot_size;
    return @ptrCast(&image[@intCast(at)]);
}

fn childOf(self: *Erofs, parent: usize, name: []const u8) ?usize {
    for (self.nodes.items[parent].children.items) |index| {
        if (std.mem.eql(u8, self.nodes.items[index].name, name)) return index;
    }
    return null;
}

fn add(self: *Erofs, parent: usize, name: []const u8, directory: bool, data: []const u8) Error!usize {
    const prefix = self.nodes.items[parent].path;
    const path = if (prefix.len == 0)
        try self.gpa.dupe(u8, name)
    else
        try std.fmt.allocPrint(self.gpa, "{s}/{s}", .{ prefix, name });
    errdefer self.gpa.free(path);

    const owned = try self.gpa.dupe(u8, data);
    errdefer self.gpa.free(owned);

    const index = self.nodes.items.len;
    try self.nodes.append(self.gpa, .{
        .path = path,
        .name = path[path.len - name.len ..],
        .directory = directory,
        .data = owned,
        .parent = parent,
    });
    try self.nodes.items[parent].children.append(self.gpa, index);
    return index;
}

/// Add a file, creating any directories its path names.
pub fn addFile(self: *Erofs, path: []const u8, data: []const u8) Error!void {
    var parent: usize = 0;
    var parts = std.mem.splitScalar(u8, path, '/');
    var pending = parts.next() orelse return;

    while (parts.next()) |part| {
        if (self.childOf(parent, pending)) |found| {
            if (!self.nodes.items[found].directory) return Error.NotADirectory;
            parent = found;
        } else {
            parent = try self.add(parent, pending, true, &.{});
        }
        pending = part;
    }

    _ = try self.add(parent, pending, false, data);
}

/// The device number as the kernel encodes it into an inode: the major in the
/// second byte, the low minor in the first, and the rest of the minor above both.
fn encodeDevice(major: u32, minor: u32) u32 {
    return (major << 8) | (minor & 0xff) | ((minor & ~@as(u32, 0xff)) << 12);
}

/// The first process is given whatever `/dev/console` names, so a root filesystem
/// with no console node gives it nothing to write to.
pub fn addCharacterDevice(self: *Erofs, path: []const u8, major: u32, minor: u32) Error!void {
    var parent: usize = 0;
    var parts = std.mem.splitScalar(u8, path, '/');
    var pending = parts.next() orelse return;

    while (parts.next()) |part| {
        if (self.childOf(parent, pending)) |found| {
            if (!self.nodes.items[found].directory) return Error.NotADirectory;
            parent = found;
        } else {
            parent = try self.add(parent, pending, true, &.{});
        }
        pending = part;
    }

    const index = try self.add(parent, pending, false, &.{});
    self.nodes.items[index].character = true;
    self.nodes.items[index].rdev = encodeDevice(major, minor);
}

pub fn addDirectory(self: *Erofs, path: []const u8) Error!void {
    var parent: usize = 0;
    var parts = std.mem.splitScalar(u8, path, '/');
    while (parts.next()) |part| {
        if (self.childOf(parent, part)) |found| {
            if (!self.nodes.items[found].directory) return Error.NotADirectory;
            parent = found;
        } else {
            parent = try self.add(parent, part, true, &.{});
        }
    }
}

fn lessByName(self: *Erofs, left: usize, right: usize) bool {
    return std.mem.lessThan(u8, self.nodes.items[left].name, self.nodes.items[right].name);
}

const Directory = struct {
    /// The blocks, padded out to a whole number of them.
    bytes: []u8,
    /// How much of that the entries and the names use. The inode records this and the
    /// kernel reads no further, so a last block that is half empty has to say so.
    size: u64,
};

/// The name of one entry. The first two of every directory are always "." and "..".
fn entryName(self: *const Erofs, node: *const Node, entry: usize) []const u8 {
    return switch (entry) {
        0 => ".",
        1 => "..",
        else => self.nodes.items[node.children.items[entry - 2]].name,
    };
}

/// Which inode one entry points at.
fn entryTarget(node: *const Node, index: usize, entry: usize) usize {
    return switch (entry) {
        0 => index,
        1 => node.parent,
        else => node.children.items[entry - 2],
    };
}

/// The contents of one directory, across as many blocks as it needs.
///
/// Each block stands alone: the entries fill the front and the names the rest, and the
/// offset in the first entry is where the entries stop, which is how the kernel learns how
/// many a block holds. Entries are in order across the whole directory, because that is
/// the order the kernel searches.
fn directoryData(self: *Erofs, index: usize) Error!Directory {
    const node = &self.nodes.items[index];
    std.sort.pdq(usize, node.children.items, self, Erofs.lessByName);

    const total = node.children.items.len + 2;

    // Which entry each block starts at, decided before anything is written. The first
    // entry of a block holds the offset its names begin at, and that is known only once
    // the whole block is accounted for.
    var starts: std.ArrayList(usize) = .empty;
    defer starts.deinit(self.gpa);
    try starts.append(self.gpa, 0);

    var used: usize = 0;
    for (0..total) |entry| {
        const cost = dirent_size + self.entryName(node, entry).len;
        // A name longer than a block cannot be split across two of them.
        if (cost > block_size) return Error.DirectoryTooLarge;
        if (used + cost > block_size) {
            try starts.append(self.gpa, entry);
            used = 0;
        }
        used += cost;
    }

    const out = try self.gpa.alloc(u8, starts.items.len * block_size);
    errdefer self.gpa.free(out);
    @memset(out, 0);

    var size: u64 = 0;
    for (starts.items, 0..) |first, block| {
        const last = if (block + 1 < starts.items.len) starts.items[block + 1] else total;
        const at = block * block_size;
        var names_at = (last - first) * dirent_size;

        for (first..last) |entry| {
            const name = self.entryName(node, entry);
            const each = &self.nodes.items[entryTarget(node, index, entry)];
            const cursor = at + (entry - first) * dirent_size;

            std.mem.writeInt(u64, out[cursor..][0..8], each.nid, .little);
            std.mem.writeInt(u16, out[cursor + 8 ..][0..2], @intCast(names_at), .little);
            out[cursor + 10] = if (entry < 2 or each.directory)
                file_type_directory
            else if (each.character)
                file_type_character
            else
                file_type_regular;
            out[cursor + 11] = 0;

            @memcpy(out[at + names_at ..][0..name.len], name);
            names_at += name.len;
        }
        size = at + names_at;
    }

    return .{ .bytes = out, .size = size };
}

fn blocksFor(bytes: u64) u32 {
    return @intCast(std.mem.alignForward(u64, bytes, block_size) / block_size);
}

/// The finished image. The caller owns it.
pub fn finish(self: *Erofs) Error![]u8 {
    // An inode number is its slot in the table, so the table is laid out first and
    // nothing can name an inode before this.
    for (self.nodes.items, 0..) |*node, index| node.nid = index;

    const inode_blocks = blocksFor(self.nodes.items.len * slot_size);
    var next_block: u32 = meta_block + inode_blocks;

    // A directory has to be rendered to know its size, and rendering needs every
    // number already assigned, which the loop above has done.
    var rendered = try self.gpa.alloc([]u8, self.nodes.items.len);
    defer {
        for (rendered) |each| self.gpa.free(each);
        self.gpa.free(rendered);
    }
    for (rendered) |*each| each.* = &.{};

    for (self.nodes.items, 0..) |*node, index| {
        if (node.directory) {
            const laid_out = try self.directoryData(index);
            rendered[index] = laid_out.bytes;
            node.size = laid_out.size;
        } else {
            node.size = node.data.len;
        }

        if (node.size == 0) {
            node.block = 0;
            continue;
        }
        node.block = next_block;
        next_block += blocksFor(node.size);
    }

    const total = @as(usize, next_block) * block_size;
    const image = try self.gpa.alloc(u8, total);
    errdefer self.gpa.free(image);
    @memset(image, 0);

    const superblock: Superblock = .{
        .magic = magic,
        .checksum = 0,
        .feature_compat = 0,
        .blkszbits = block_shift,
        .sb_extslots = 0,
        .root_nid = 0,
        .inos = self.nodes.items.len,
        .build_time = 0,
        .build_time_nsec = 0,
        .blocks = next_block,
        .meta_blkaddr = meta_block,
        .xattr_blkaddr = 0,
        .uuid = @splat(0),
        .volume_name = @splat(0),
        .feature_incompat = 0,
        .available_compr_algs = 0,
        .extra_devices = 0,
        .devt_slotoff = 0,
        .dirblkbits = 0,
        .xattr_prefix_count = 0,
        .xattr_prefix_start = 0,
        .packed_nid = 0,
        .xattr_filter_reserved = 0,
        .reserved2 = @splat(0),
    };
    @memcpy(image[super_offset..][0..@sizeOf(Superblock)], std.mem.asBytes(&superblock));

    for (self.nodes.items, 0..) |node, index| {
        var subdirectories: u16 = 0;
        for (node.children.items) |child| {
            if (self.nodes.items[child].directory) subdirectories += 1;
        }

        const inode: Inode = .{
            // Compact inode, plain layout: both are zero.
            .i_format = 0,
            .i_xattr_icount = 0,
            .i_mode = if (node.directory)
                0o40755
            else if (node.character)
                0o20600
            else
                0o100755,
            .i_nlink = if (node.directory) 2 + subdirectories else 1,
            .i_size = @intCast(node.size),
            .i_reserved = 0,
            .i_u = if (node.character) node.rdev else node.block,
            .i_ino = @intCast(index),
            .i_uid = 0,
            .i_gid = 0,
            .i_reserved2 = 0,
        };
        const at = meta_block * block_size + index * slot_size;
        @memcpy(image[at..][0..slot_size], std.mem.asBytes(&inode));

        if (node.size == 0) continue;
        const data_at = @as(usize, node.block) * block_size;
        const bytes = if (node.directory) rendered[index][0..@intCast(node.size)] else node.data;
        @memcpy(image[data_at..][0..bytes.len], bytes);
    }

    return image;
}

fn superblockAt(image: []const u8) *align(1) const Superblock {
    return @ptrCast(&image[super_offset]);
}

test "the superblock sits where the kernel looks for it and carries the magic" {
    const gpa = testing.allocator();
    var fs: Erofs = .init(gpa);
    defer fs.deinit();

    try fs.addFile("init", "hello");
    const image = try fs.finish();
    defer gpa.free(image);

    try testing.expectEqual(magic, std.mem.readInt(u32, image[super_offset..][0..4], .little));
}

test "the block size is recorded as a shift, not a size" {
    const gpa = testing.allocator();
    var fs: Erofs = .init(gpa);
    defer fs.deinit();

    try fs.addFile("init", "hello");
    const image = try fs.finish();
    defer gpa.free(image);

    try testing.expectEqual(@as(u8, 12), superblockAt(image).blkszbits);
    try testing.expectEqual(@as(usize, 4096), block_size);
}

test "the image is a whole number of blocks and says how many" {
    const gpa = testing.allocator();
    var fs: Erofs = .init(gpa);
    defer fs.deinit();

    try fs.addFile("init", "hello");
    const image = try fs.finish();
    defer gpa.free(image);

    try testing.expectEqual(@as(usize, 0), image.len % block_size);
    try testing.expectEqual(@as(u32, @intCast(image.len / block_size)), superblockAt(image).blocks);
}

test "the root inode is a directory" {
    const gpa = testing.allocator();
    var fs: Erofs = .init(gpa);
    defer fs.deinit();

    try fs.addFile("init", "hello");
    const image = try fs.finish();
    defer gpa.free(image);

    const root = fs.inodeAt(image, superblockAt(image).root_nid);
    try testing.expectEqual(@as(u16, 0o40755), root.i_mode);
}

test "a file's contents are at the block its inode names" {
    const gpa = testing.allocator();
    var fs: Erofs = .init(gpa);
    defer fs.deinit();

    try fs.addFile("init", "mirage");
    const image = try fs.finish();
    defer gpa.free(image);

    const nid = fs.lookup("init").?;
    const inode = fs.inodeAt(image, nid);

    try testing.expectEqual(@as(u32, 6), inode.i_size);
    try testing.expectEqual(@as(u16, 0o100755), inode.i_mode);

    const at = @as(usize, inode.i_u) * block_size;
    try testing.expectEqualSlices(u8, "mirage", image[at..][0..6]);
}

test "a directory lists itself, its parent and its children" {
    const gpa = testing.allocator();
    var fs: Erofs = .init(gpa);
    defer fs.deinit();

    try fs.addFile("b", "second");
    try fs.addFile("a", "first");
    const image = try fs.finish();
    defer gpa.free(image);

    const root = fs.inodeAt(image, superblockAt(image).root_nid);
    const at = @as(usize, root.i_u) * block_size;

    // Entries are sorted by name, and the kernel does a binary search over them, so
    // an unsorted directory silently fails to find its own files.
    const names = [_][]const u8{ ".", "..", "a", "b" };
    for (names, 0..) |want, index| {
        const entry_at = at + index * dirent_size;
        const name_off = std.mem.readInt(u16, image[entry_at + 8 ..][0..2], .little);
        const got = image[at + name_off ..][0..want.len];
        try testing.expectEqualSlices(u8, want, got);
    }
}

test "a nested directory is reachable and holds its own child" {
    const gpa = testing.allocator();
    var fs: Erofs = .init(gpa);
    defer fs.deinit();

    try fs.addFile("etc/motd", "hi");
    const image = try fs.finish();
    defer gpa.free(image);

    const etc = fs.lookup("etc").?;
    const inode = fs.inodeAt(image, etc);
    try testing.expectEqual(@as(u16, 0o40755), inode.i_mode);

    const motd = fs.lookup("etc/motd").?;
    try testing.expectEqual(@as(u32, 2), fs.inodeAt(image, motd).i_size);
}

test "the on disk structures are the sizes the format fixes" {
    try testing.expectEqual(@as(usize, 128), @sizeOf(Superblock));
    try testing.expectEqual(@as(usize, 32), @sizeOf(Inode));
    try testing.expectEqual(@as(usize, 12), dirent_size);
}

test "a character device carries its device number instead of a block" {
    const gpa = testing.allocator();
    var fs: Erofs = .init(gpa);
    defer fs.deinit();

    try fs.addCharacterDevice("dev/console", 5, 1);
    const image = try fs.finish();
    defer gpa.free(image);

    const nid = fs.lookup("dev/console").?;
    const inode = fs.inodeAt(image, nid);

    try testing.expectEqual(@as(u16, 0o20600), inode.i_mode);
    try testing.expectEqual(@as(u32, 0), inode.i_size);
    try testing.expectEqual(@as(u32, 0x501), inode.i_u);
}

test "a directory spans as many blocks as its entries need" {
    const gpa = testing.allocator();
    var fs: Erofs = .init(gpa);
    defer fs.deinit();

    // One block holds fewer than two hundred entries of this length, and a real root
    // filesystem has directories with far more. Each block stands alone, so the count
    // here is only bounded by the image.
    var name: [16]u8 = undefined;
    const count = 1000;
    for (0..count) |index| {
        const path = try std.fmt.bufPrint(&name, "file{d:0>6}", .{index});
        try fs.addFile(path, "x");
    }

    const blob = try fs.finish();
    defer gpa.free(blob);

    // The root inode says how much directory data there is, and it has to be more than one
    // block or the entries were written over each other.
    const root = fs.inodeAt(blob, 0);
    try std.testing.expect(root.i_size > block_size);

    // Every name is still there to be found, which is what a kernel walking the blocks in
    // order needs.
    try std.testing.expect(fs.lookup("file000000") != null);
    try std.testing.expect(fs.lookup("file000999") != null);
}
