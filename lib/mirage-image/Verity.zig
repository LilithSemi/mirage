//! A dm-verity hash tree over a read only image.
//!
//! The tree turns one short hash into a claim about every block of a disk. The kernel is
//! given the root hash, and it hashes each block as it reads it and walks up the tree to
//! the root. A block that was changed after the tree was built fails the read.
//!
//! This is what carries integrity past the launch. Mirage measures what it loads into
//! guest memory, but a root filesystem is read block by block long after the guest
//! starts, so measuring it once at the start proves nothing about the twentieth read.
//! The root hash goes on the kernel command line, the command line is measured, and the
//! root hash covers every block. That closes the gap.
//!
//! Version 1 of the on disk format, SHA-256, which is what the kernel and
//! `veritysetup` default to.

const std = @import("std");
const testing = @import("mirage-testing");

const Verity = @This();

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const digest_size = Sha256.digest_length;

/// Both the data and the hash blocks. The kernel is told these separately and they may
/// differ, but one size for both is what every tool defaults to and it keeps the
/// arithmetic here in one place.
pub const block_size = 4096;

/// How many hashes go in one hash block. The rest of the block is zero and is hashed
/// along with the hashes, so a partly used block still hashes to one value.
pub const hashes_per_block = block_size / digest_size;

/// The deepest tree this builds. Each level covers 128 times what the one below it
/// covers, so eight of them cover 128 to the eighth blocks. That is more bytes than an
/// address holds, which is why going past this is an assertion and not an error.
pub const max_levels = 8;

pub const Error = error{
    /// A salt longer than the kernel accepts.
    SaltTooLong,
    /// The image does not stop on a block boundary. A tail shorter than a block is a
    /// block the kernel never reads, so covering it would claim something about bytes
    /// nobody checks and would disagree with every other tool. The caller pads.
    NotBlockAligned,
} || std.mem.Allocator.Error;

/// The kernel takes the salt as hexadecimal on the command line and caps it here.
pub const max_salt = 32;

pub const Tree = struct {
    /// The hash blocks, in the order the kernel reads them. The highest level comes
    /// first and level zero last.
    blocks: []u8,
    /// What the kernel is told to expect. The whole integrity claim is this value.
    root: [digest_size]u8,
    /// How many blocks of the image the tree covers.
    data_blocks: u64,
    /// How many levels the tree has, not counting the root hash itself.
    levels: usize,

    pub fn deinit(self: *Tree, gpa: std.mem.Allocator) void {
        gpa.free(self.blocks);
        self.* = undefined;
    }
};

/// One block hashed the way version 1 of the format hashes it: the salt, then the whole
/// block including whatever padding it has.
fn hashBlock(salt: []const u8, block: []const u8) [digest_size]u8 {
    var hash: Sha256 = .init(.{});
    hash.update(salt);
    hash.update(block);
    return hash.finalResult();
}

/// Build the tree over `data`, which has to be a whole number of blocks.
pub fn build(gpa: std.mem.Allocator, data: []const u8, salt: []const u8) Error!Tree {
    if (salt.len > max_salt) return Error.SaltTooLong;
    if (data.len % block_size != 0) return Error.NotBlockAligned;

    // A tree over nothing has no level and no root to speak of. One block is the
    // smallest thing with an answer.
    const covered = @max(data.len / block_size, 1);

    // How many blocks each level takes, counted from level zero up. The level that
    // takes one block is the last, and its hash is the root.
    var level_blocks: [max_levels]u64 = @splat(0);
    var levels: usize = 0;
    var below = covered;
    while (true) {
        std.debug.assert(levels < max_levels);
        const blocks = (below + hashes_per_block - 1) / hashes_per_block;
        level_blocks[levels] = blocks;
        levels += 1;
        if (blocks == 1) break;
        below = blocks;
    }

    var total: u64 = 0;
    for (level_blocks[0..levels]) |blocks| total += blocks;

    const bytes = try gpa.alloc(u8, @intCast(total * block_size));
    errdefer gpa.free(bytes);
    @memset(bytes, 0);

    // Where each level sits. The highest level goes first, so a reader walking down
    // from the root moves forward through the device.
    var level_at: [max_levels]u64 = @splat(0);
    var at: u64 = 0;
    var level = levels;
    while (level > 0) {
        level -= 1;
        level_at[level] = at;
        at += level_blocks[level];
    }

    // Level zero hashes the image itself. Every level above hashes the level below it,
    // which is already in the buffer by the time it is read.
    for (0..levels) |index| {
        const out = bytes[@intCast(level_at[index] * block_size)..][0..@intCast(level_blocks[index] * block_size)];
        const count: u64 = if (index == 0) covered else level_blocks[index - 1];

        for (0..@intCast(count)) |slot| {
            const digest = if (index == 0)
                hashBlock(salt, blockOf(data, slot))
            else
                hashBlock(salt, bytes[@intCast((level_at[index - 1] + slot) * block_size)..][0..block_size]);
            @memcpy(out[slot * digest_size ..][0..digest_size], &digest);
        }
    }

    // The root is the hash of the one block at the top, and it is never stored.
    const top = bytes[@intCast(level_at[levels - 1] * block_size)..][0..block_size];
    return .{
        .blocks = bytes,
        .root = hashBlock(salt, top),
        .data_blocks = covered,
        .levels = levels,
    };
}

/// One block of the image. An empty image still has one block and it reads as zeroes.
fn blockOf(data: []const u8, index: usize) []const u8 {
    const start = index * block_size;
    if (start >= data.len) return &zeroes;
    return data[start..][0..block_size];
}

const zeroes: [block_size]u8 = @splat(0);

/// Write the root hash as the kernel wants to read it, lower case hexadecimal.
pub fn formatDigest(digest: [digest_size]u8, out: *[digest_size * 2]u8) void {
    const alphabet = "0123456789abcdef";
    for (digest, 0..) |byte, index| {
        out[index * 2] = alphabet[byte >> 4];
        out[index * 2 + 1] = alphabet[byte & 0xf];
    }
}

test "a tree over one block is one level and its root is the hash of that block" {
    const gpa = testing.allocator();
    var data: [block_size]u8 = @splat('a');

    var tree = try build(gpa, &data, "");
    defer tree.deinit(gpa);

    try testing.expectEqual(@as(usize, 1), tree.levels);
    try testing.expectEqual(@as(u64, 1), tree.data_blocks);
    try testing.expectEqual(@as(usize, block_size), tree.blocks.len);

    // The one hash block holds the hash of the data block, and the root is the hash of
    // that whole block including its padding.
    const expected = hashBlock("", &data);
    try testing.expectEqualSlices(u8, &expected, tree.blocks[0..digest_size]);
    try testing.expectEqualSlices(u8, &hashBlock("", tree.blocks[0..block_size]), &tree.root);
}

test "a tree deep enough to need two levels puts the top level first" {
    const gpa = testing.allocator();

    // One more block than a single hash block holds, so level zero needs two blocks and
    // a level above them appears.
    const blocks = hashes_per_block + 1;
    const data = try gpa.alloc(u8, blocks * block_size);
    defer gpa.free(data);
    for (data, 0..) |*byte, index| byte.* = @truncate(index);

    var tree = try build(gpa, data, "");
    defer tree.deinit(gpa);

    try testing.expectEqual(@as(usize, 2), tree.levels);
    // Two blocks for level zero and one above them.
    try testing.expectEqual(@as(usize, 3 * block_size), tree.blocks.len);

    // The first block is the top level, and it holds the hashes of the two level zero
    // blocks that follow it.
    const first = hashBlock("", tree.blocks[block_size..][0..block_size]);
    const second = hashBlock("", tree.blocks[2 * block_size ..][0..block_size]);
    try testing.expectEqualSlices(u8, &first, tree.blocks[0..digest_size]);
    try testing.expectEqualSlices(u8, &second, tree.blocks[digest_size..][0..digest_size]);
}

test "changing one byte of the image changes the root" {
    const gpa = testing.allocator();
    const data = try gpa.alloc(u8, 4 * block_size);
    defer gpa.free(data);
    @memset(data, 0);

    var before = try build(gpa, data, "salt");
    defer before.deinit(gpa);

    // The last byte of the last block, which is the furthest thing from the root.
    data[data.len - 1] = 1;
    var after = try build(gpa, data, "salt");
    defer after.deinit(gpa);

    try std.testing.expect(!std.mem.eql(u8, &before.root, &after.root));
}

test "the same image with a different salt has a different root" {
    const gpa = testing.allocator();
    var data: [block_size]u8 = @splat(0);

    var plain = try build(gpa, &data, "");
    defer plain.deinit(gpa);
    var salted = try build(gpa, &data, "\x01\x02\x03\x04");
    defer salted.deinit(gpa);

    try std.testing.expect(!std.mem.eql(u8, &plain.root, &salted.root));
}

test "an image that stops inside a block is refused" {
    const gpa = testing.allocator();
    const data = try gpa.alloc(u8, block_size + 7);
    defer gpa.free(data);
    @memset(data, 'z');

    // Covering a tail shorter than a block would claim something about bytes the kernel
    // never reads, and would disagree with every other tool that builds one of these.
    try testing.expectError(Error.NotBlockAligned, build(gpa, data, ""));
}

test "the root hash is written the way a kernel command line reads it" {
    var digest: [digest_size]u8 = @splat(0);
    digest[0] = 0xde;
    digest[1] = 0xad;
    digest[31] = 0x0f;

    var out: [digest_size * 2]u8 = undefined;
    formatDigest(digest, &out);

    try testing.expectEqualSlices(u8, "dead", out[0..4]);
    try testing.expectEqualSlices(u8, "0f", out[62..64]);
}

test "the deepest tree this builds covers more than any image can hold" {
    // Each level covers 128 times the one below it, so the depth limit is reached only by
    // an image larger than an address. This is why that limit is an assertion.
    var covers: u128 = 1;
    for (0..max_levels) |_| covers *= hashes_per_block;
    try std.testing.expect(covers * block_size > std.math.maxInt(u64));
}

test "the tree matches what veritysetup builds for the same image" {
    const gpa = testing.allocator();

    // Two blocks whose bytes count up and wrap, which is easy to say and hard to get
    // right by accident. The answers below came from `veritysetup 2.8.7` on the same
    // image, so this test says the tree is the one the kernel expects and not merely
    // one this file agrees with itself about.
    const data = try gpa.alloc(u8, 2 * block_size);
    defer gpa.free(data);
    for (data, 0..) |*byte, index| byte.* = @truncate(index);

    var plain = try build(gpa, data, "");
    defer plain.deinit(gpa);
    var hex: [digest_size * 2]u8 = undefined;
    formatDigest(plain.root, &hex);
    try testing.expectEqualSlices(
        u8,
        "9b26777bc07dbde4a7cea1b79a1117788aadb54d2d0d79958c9f9811e7fdd0fb",
        &hex,
    );

    var salted = try build(gpa, data, "\x00\x11\x22\x33");
    defer salted.deinit(gpa);
    formatDigest(salted.root, &hex);
    try testing.expectEqualSlices(
        u8,
        "d6b497a53db69cbae1c1cf163f3acccf00a2e342ed141fbe522da90cdddc353b",
        &hex,
    );

    // Two data blocks fit in one hash block, so there is one level and one block.
    try testing.expectEqual(@as(usize, 1), salted.levels);
    try testing.expectEqual(@as(usize, block_size), salted.blocks.len);
}

/// The header at the start of the hash area, so an image carries its own parameters.
///
/// The root hash is deliberately not in here. It is the trust anchor, and an anchor an
/// attacker can rewrite alongside the thing it anchors is no anchor at all. It comes
/// from somewhere the image cannot reach.
pub const Superblock = extern struct {
    signature: [8]u8,
    version: u32 align(1),
    hash_type: u32 align(1),
    uuid: [16]u8,
    algorithm: [32]u8,
    data_block_size: u32 align(1),
    hash_block_size: u32 align(1),
    data_blocks: u64 align(1),
    salt_size: u16 align(1),
    reserved1: [6]u8,
    salt: [256]u8,
    reserved2: [168]u8,

    /// What the kernel looks for at the start of the hash area.
    pub const magic = "verity\x00\x00";

    /// Version 1 of the header, and the one hash layout the kernel has.
    pub const format_version = 1;
    pub const hash_type_regular = 1;

    comptime {
        std.debug.assert(@sizeOf(Superblock) == 512);
        std.debug.assert(@offsetOf(Superblock, "data_block_size") == 64);
        std.debug.assert(@offsetOf(Superblock, "data_blocks") == 72);
        std.debug.assert(@offsetOf(Superblock, "salt") == 88);
    }

    pub const ParseError = error{
        /// The hash area does not start with a header.
        NotVerity,
        /// A header this code has no layout for.
        UnknownVersion,
        /// A digest or a block size this code does not build.
        Unsupported,
    };

    pub fn init(tree: Tree, salt: []const u8, uuid: [16]u8) Superblock {
        var self: Superblock = std.mem.zeroes(Superblock);
        @memcpy(&self.signature, magic);
        self.version = format_version;
        self.hash_type = hash_type_regular;
        self.uuid = uuid;
        @memcpy(self.algorithm[0..6], "sha256");
        self.data_block_size = block_size;
        self.hash_block_size = block_size;
        self.data_blocks = tree.data_blocks;
        self.salt_size = @intCast(salt.len);
        @memcpy(self.salt[0..salt.len], salt);
        return self;
    }

    /// Read a header that came off a disk. Every field in it was written by whoever made
    /// the image, so each one is checked rather than believed.
    pub fn parse(bytes: *const [512]u8) ParseError!Superblock {
        const self: Superblock = @bitCast(bytes.*);
        if (!std.mem.eql(u8, &self.signature, magic)) return ParseError.NotVerity;
        if (self.version != format_version) return ParseError.UnknownVersion;
        if (self.hash_type != hash_type_regular) return ParseError.Unsupported;
        if (!std.mem.eql(u8, self.algorithm[0..7], "sha256\x00")) return ParseError.Unsupported;
        if (self.data_block_size != block_size) return ParseError.Unsupported;
        if (self.hash_block_size != block_size) return ParseError.Unsupported;
        if (self.salt_size > max_salt) return ParseError.Unsupported;
        return self;
    }
};

test "the header this writes is the header veritysetup writes" {
    const gpa = testing.allocator();

    // Six blocks and an eight byte salt, which is what `veritysetup 2.8.7` was given to
    // produce the bytes checked below.
    const data = try gpa.alloc(u8, 6 * block_size);
    defer gpa.free(data);
    @memset(data, 0);

    var tree = try build(gpa, data, "\xb1\x20\x90\x35\x6b\x21\x89\x54");
    defer tree.deinit(gpa);

    const uuid = [16]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    const header: Superblock = .init(tree, "\xb1\x20\x90\x35\x6b\x21\x89\x54", uuid);
    const bytes: [512]u8 = @bitCast(header);

    const expected = [_]u8{
        'v',  'e',  'r',  'i',  't',  'y',  0,    0,
        1,    0,    0,    0,    1,    0,    0,    0,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        's',  'h',  'a',  '2',  '5',  '6',
    };
    try testing.expectEqualSlices(u8, &expected, bytes[0..expected.len]);

    // Both block sizes, then the block count, then the salt with its length.
    try testing.expectEqual(@as(u32, 4096), std.mem.readInt(u32, bytes[64..68], .little));
    try testing.expectEqual(@as(u32, 4096), std.mem.readInt(u32, bytes[68..72], .little));
    try testing.expectEqual(@as(u64, 6), std.mem.readInt(u64, bytes[72..80], .little));
    try testing.expectEqual(@as(u16, 8), std.mem.readInt(u16, bytes[80..82], .little));
    try testing.expectEqualSlices(u8, "\xb1\x20\x90\x35\x6b\x21\x89\x54", bytes[88..96]);
}

test "a header goes out and comes back the same" {
    const gpa = testing.allocator();
    const data = try gpa.alloc(u8, 3 * block_size);
    defer gpa.free(data);
    @memset(data, 'q');

    var tree = try build(gpa, data, "pepper");
    defer tree.deinit(gpa);

    const header: Superblock = .init(tree, "pepper", @splat(7));
    const bytes: [512]u8 = @bitCast(header);
    const back = try Superblock.parse(&bytes);

    try testing.expectEqual(@as(u64, 3), back.data_blocks);
    try testing.expectEqual(@as(u16, 6), back.salt_size);
    try testing.expectEqualSlices(u8, "pepper", back.salt[0..back.salt_size]);
}

test "a hash area that is not a header is refused rather than read" {
    // Every field of this came from whoever made the image, so believing the magic is
    // believing a stranger about how to read the rest.
    var bytes: [512]u8 = @splat(0);
    try testing.expectError(Superblock.ParseError.NotVerity, Superblock.parse(&bytes));

    @memcpy(bytes[0..8], Superblock.magic);
    std.mem.writeInt(u32, bytes[8..12], 9, .little);
    try testing.expectError(Superblock.ParseError.UnknownVersion, Superblock.parse(&bytes));

    std.mem.writeInt(u32, bytes[8..12], 1, .little);
    std.mem.writeInt(u32, bytes[12..16], 1, .little);
    @memcpy(bytes[32..38], "sha512");
    try testing.expectError(Superblock.ParseError.Unsupported, Superblock.parse(&bytes));

    // A salt longer than this code holds would be read into a buffer that cannot take it.
    @memcpy(bytes[32..39], "sha256\x00");
    std.mem.writeInt(u32, bytes[64..68], block_size, .little);
    std.mem.writeInt(u32, bytes[68..72], block_size, .little);
    std.mem.writeInt(u16, bytes[80..82], 255, .little);
    try testing.expectError(Superblock.ParseError.Unsupported, Superblock.parse(&bytes));
}
