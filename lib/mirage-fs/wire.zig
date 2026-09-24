//! The messages a filesystem in userspace answers, as the kernel lays them out.
//!
//! This is the same protocol a FUSE server on the host speaks, carried over a virtio queue instead of
//! `/dev/fuse`. Nothing here knows about queues or about files: it is the shape of the bytes and
//! nothing else, so it can be read and written without a guest and without a filesystem.
//!
//! Every number is little endian, which is what the kernel writes and what every machine this runs
//! on reads natively. The structures are laid out by hand rather than as `extern struct` because the
//! wire has no padding to guess at and a mistake would be a field silently read from the wrong place.

const std = @import("std");

/// What the kernel asks for. Only the ones a read only export answers are named; anything else is a
/// number this end refuses rather than guesses at.
pub const Op = enum(u32) {
    lookup = 1,
    forget = 2,
    getattr = 3,
    setattr = 4,
    readlink = 5,
    open = 14,
    read = 15,
    write = 16,
    mkdir = 9,
    unlink = 10,
    rmdir = 11,
    rename = 12,
    symlink = 6,
    /// A second name for a file that is already there, which tools that share files between
    /// directories make rather than copying: a package manager, a build cache, a version control
    /// system keeping one copy of an object.
    link = 13,
    fsync = 20,
    fsyncdir = 30,
    rename2 = 45,
    statfs = 17,
    release = 18,
    getxattr = 22,
    listxattr = 23,
    flush = 25,
    init = 26,
    opendir = 27,
    readdir = 28,
    releasedir = 29,
    access = 34,
    create = 35,
    interrupt = 36,
    destroy = 38,
    batch_forget = 42,
    readdirplus = 44,
    syncfs = 50,
    _,
};

/// The version this end speaks. Seven is the only major there has ever been; the minor says which
/// fields the kernel may expect back, and a server that names a lower one gets the older shape.
pub const major = 7;
pub const minor = 31;

/// The most one read or write may carry. The kernel asks for no more than this once it is told.
pub const max_transfer = 128 * 1024;

pub const Header = struct {
    pub const size = 40;

    /// How long the whole message is, this header included.
    len: u32,
    op: Op,
    /// What the answer has to carry back, so the kernel can match them.
    unique: u64,
    /// Which file or directory this is about. One is the root.
    nodeid: u64,
    uid: u32,
    gid: u32,
    pid: u32,

    pub fn parse(bytes: []const u8) ?Header {
        if (bytes.len < size) return null;
        const said = std.mem.readInt(u32, bytes[0..4], .little);
        // A message shorter than its own header, or one claiming to be longer than what arrived, is
        // not a message. Both would have this end reading somebody else's memory.
        if (said < size or said > bytes.len) return null;
        return .{
            .len = said,
            .op = @enumFromInt(std.mem.readInt(u32, bytes[4..8], .little)),
            .unique = std.mem.readInt(u64, bytes[8..16], .little),
            .nodeid = std.mem.readInt(u64, bytes[16..24], .little),
            .uid = std.mem.readInt(u32, bytes[24..28], .little),
            .gid = std.mem.readInt(u32, bytes[28..32], .little),
            .pid = std.mem.readInt(u32, bytes[32..36], .little),
        };
    }

    /// What came after the header, which is the operation's own arguments.
    pub fn body(self: Header, bytes: []const u8) []const u8 {
        return bytes[size..self.len];
    }
};

/// What goes back. An answer with a refusal in it carries nothing else, which is the rule the kernel
/// reads it by.
pub const Answer = struct {
    pub const size = 16;

    pub fn write(into: []u8, unique: u64, refusal: i32, payload_len: usize) usize {
        const total = size + payload_len;
        std.debug.assert(into.len >= total);
        std.mem.writeInt(u32, into[0..4], @intCast(total), .little);
        std.mem.writeInt(i32, into[4..8], refusal, .little);
        std.mem.writeInt(u64, into[8..16], unique, .little);
        return total;
    }
};

/// Errors as the kernel numbers them. A refusal is the negative of one of these.
pub const err = struct {
    pub const perm: i32 = 1;
    pub const noent: i32 = 2;
    pub const io: i32 = 5;
    pub const badf: i32 = 9;
    pub const nomem: i32 = 12;
    pub const access: i32 = 13;
    pub const exist: i32 = 17;
    pub const notdir: i32 = 20;
    pub const isdir: i32 = 21;
    pub const invalid: i32 = 22;
    pub const nfile: i32 = 23;
    pub const rofs: i32 = 30;
    pub const range: i32 = 34;
    pub const nametoolong: i32 = 36;
    pub const nosys: i32 = 38;
    pub const nodata: i32 = 61;
};

pub const Init = struct {
    pub const in_size = 16;
    pub const out_size = 64;

    major: u32,
    minor: u32,
    max_readahead: u32,
    flags: u32,

    pub fn parse(body: []const u8) ?Init {
        if (body.len < in_size) return null;
        return .{
            .major = std.mem.readInt(u32, body[0..4], .little),
            .minor = std.mem.readInt(u32, body[4..8], .little),
            .max_readahead = std.mem.readInt(u32, body[8..12], .little),
            .flags = std.mem.readInt(u32, body[12..16], .little),
        };
    }

    /// What this end can do. Only the things a read only export really does are claimed: a server
    /// that claims more is a server the kernel will ask for it.
    pub const flag = struct {
        /// The kernel may send `readdirplus`, which is a directory read that carries what a lookup
        /// of each name would have said. It saves a message per name and a store has many names.
        pub const do_readdirplus: u32 = 1 << 13;
        /// Bigger writes than one page. Claimed because it also governs how much a read may ask for.
        pub const big_writes: u32 = 1 << 5;
    };

    pub fn writeOut(into: []u8, theirs: Init) usize {
        @memset(into[0..out_size], 0);
        std.mem.writeInt(u32, into[0..4], major, .little);
        // Never more than the kernel asked for: it reads the fields its own version knows about.
        std.mem.writeInt(u32, into[4..8], @min(minor, theirs.minor), .little);
        std.mem.writeInt(u32, into[8..12], theirs.max_readahead, .little);
        std.mem.writeInt(u32, into[12..16], flag.do_readdirplus | flag.big_writes, .little);
        // How many requests the kernel may have in flight, and when it should hold back.
        std.mem.writeInt(u16, into[16..18], 12, .little);
        std.mem.writeInt(u16, into[18..20], 10, .little);
        std.mem.writeInt(u32, into[20..24], max_transfer, .little);
        // The finest time this filesystem records, in nanoseconds. A whole second: the times come
        // from whatever the host holds and nothing here depends on them.
        std.mem.writeInt(u32, into[24..28], std.time.ns_per_s, .little);
        std.mem.writeInt(u16, into[28..30], @intCast(max_transfer / std.heap.page_size_min), .little);
        return out_size;
    }
};

/// What a file or a directory is, as the kernel wants to hear it.
pub const Attr = struct {
    pub const size = 88;

    ino: u64 = 0,
    bytes: u64 = 0,
    blocks: u64 = 0,
    seconds: i64 = 0,
    mode: u32 = 0,
    links: u32 = 1,
    uid: u32 = 0,
    gid: u32 = 0,
    blksize: u32 = 4096,

    pub fn write(self: Attr, into: []u8) usize {
        @memset(into[0..size], 0);
        std.mem.writeInt(u64, into[0..8], self.ino, .little);
        std.mem.writeInt(u64, into[8..16], self.bytes, .little);
        std.mem.writeInt(u64, into[16..24], self.blocks, .little);
        // Accessed, changed and created, all the one time this end keeps.
        const when: u64 = @bitCast(self.seconds);
        std.mem.writeInt(u64, into[24..32], when, .little);
        std.mem.writeInt(u64, into[32..40], when, .little);
        std.mem.writeInt(u64, into[40..48], when, .little);
        std.mem.writeInt(u32, into[60..64], self.mode, .little);
        std.mem.writeInt(u32, into[64..68], self.links, .little);
        std.mem.writeInt(u32, into[68..72], self.uid, .little);
        std.mem.writeInt(u32, into[72..76], self.gid, .little);
        std.mem.writeInt(u32, into[84..88], self.blksize, .little);
        return size;
    }
};

/// How long the kernel may believe an answer for. A read only export never changes, so both are
/// long: every second of this is a message that does not have to be asked.
pub const valid_seconds: u64 = 3600;

pub const Entry = struct {
    pub const size = 40 + Attr.size;

    /// The same entry, but which the kernel is asked not to remember. A name in the directory a guest
    /// mounted is one of the things offered to it, and that set changes while the guest runs: a
    /// remembered name would be a share that outlived being taken back.
    pub fn writeBriefly(into: []u8, nodeid: u64, attr: Attr) usize {
        const wrote = write(into, nodeid, attr);
        std.mem.writeInt(u64, into[16..24], 0, .little);
        std.mem.writeInt(u64, into[24..32], 0, .little);
        return wrote;
    }

    pub fn write(into: []u8, nodeid: u64, attr: Attr) usize {
        @memset(into[0..40], 0);
        std.mem.writeInt(u64, into[0..8], nodeid, .little);
        // The generation, which tells a reused number apart from the one it was. Nothing here reuses
        // a number, so it stays zero.
        std.mem.writeInt(u64, into[8..16], 0, .little);
        std.mem.writeInt(u64, into[16..24], valid_seconds, .little);
        std.mem.writeInt(u64, into[24..32], valid_seconds, .little);
        _ = attr.write(into[40..]);
        return size;
    }
};

pub const AttrAnswer = struct {
    pub const size = 16 + Attr.size;

    pub fn write(into: []u8, attr: Attr) usize {
        @memset(into[0..16], 0);
        std.mem.writeInt(u64, into[0..8], valid_seconds, .little);
        _ = attr.write(into[16..]);
        return size;
    }
};

pub const Open = struct {
    pub const out_size = 16;

    pub fn writeOut(into: []u8, handle: u64) usize {
        @memset(into[0..out_size], 0);
        std.mem.writeInt(u64, into[0..8], handle, .little);
        return out_size;
    }
};

pub const Read = struct {
    pub const in_size = 40;

    handle: u64,
    offset: u64,
    bytes: u32,

    pub fn parse(body: []const u8) ?Read {
        if (body.len < 24) return null;
        return .{
            .handle = std.mem.readInt(u64, body[0..8], .little),
            .offset = std.mem.readInt(u64, body[8..16], .little),
            .bytes = std.mem.readInt(u32, body[16..20], .little),
        };
    }
};

pub const Release = struct {
    pub fn parse(body: []const u8) ?u64 {
        if (body.len < 8) return null;
        return std.mem.readInt(u64, body[0..8], .little);
    }
};

pub const Forget = struct {
    pub fn parse(body: []const u8) ?u64 {
        if (body.len < 8) return null;
        return std.mem.readInt(u64, body[0..8], .little);
    }
};

/// One name in a directory, with what a lookup of it would have said in front. The kernel asked for
/// this shape by claiming `do_readdirplus`, and it saves a message for every name in the directory.
pub const DirEntry = struct {
    pub const header_size = 24;

    /// How much room one name needs, padded the way the kernel steps through them.
    pub fn roomFor(name: []const u8) usize {
        return Entry.size + header_size + std.mem.alignForward(usize, name.len, 8);
    }

    pub fn write(into: []u8, nodeid: u64, attr: Attr, offset: u64, name: []const u8) usize {
        var at = Entry.write(into, nodeid, attr);
        std.mem.writeInt(u64, into[at..][0..8], attr.ino, .little);
        std.mem.writeInt(u64, into[at + 8 ..][0..8], offset, .little);
        std.mem.writeInt(u32, into[at + 16 ..][0..4], @intCast(name.len), .little);
        // The kind, which is the file mode's top bits shifted down the way `DT_*` numbers them.
        std.mem.writeInt(u32, into[at + 20 ..][0..4], (attr.mode & 0o170000) >> 12, .little);
        at += header_size;
        @memcpy(into[at..][0..name.len], name);
        const padded = std.mem.alignForward(usize, name.len, 8);
        @memset(into[at + name.len ..][0 .. padded - name.len], 0);
        return at + padded;
    }
};

pub const Statfs = struct {
    pub const out_size = 80;
    pub const block_size = 4096;

    /// How big the filesystem is and how much of it is left, in blocks of `block_size`.
    ///
    /// Room that is really there matters: a program told there is none refuses to start, and one told
    /// there is plenty when there is none fails in the middle of its work instead.
    pub fn writeOut(into: []u8, blocks: u64, free: u64, files: u64) usize {
        @memset(into[0..out_size], 0);
        std.mem.writeInt(u64, into[0..8], blocks, .little);
        std.mem.writeInt(u64, into[8..16], free, .little);
        std.mem.writeInt(u64, into[16..24], free, .little);
        std.mem.writeInt(u64, into[24..32], files, .little);
        std.mem.writeInt(u64, into[32..40], files, .little);
        std.mem.writeInt(u32, into[40..44], block_size, .little);
        std.mem.writeInt(u32, into[44..48], 255, .little);
        std.mem.writeInt(u32, into[48..52], block_size, .little);
        return out_size;
    }
};

test "a header shorter than itself is not a message" {
    var bytes: [64]u8 = @splat(0);
    try std.testing.expectEqual(@as(?Header, null), Header.parse(bytes[0..8]));

    // Says it is twenty bytes long, which is less than a header.
    std.mem.writeInt(u32, bytes[0..4], 20, .little);
    try std.testing.expectEqual(@as(?Header, null), Header.parse(&bytes));

    // Says it is longer than what arrived, which would read somebody else's memory.
    std.mem.writeInt(u32, bytes[0..4], 4096, .little);
    try std.testing.expectEqual(@as(?Header, null), Header.parse(&bytes));
}

test "a header says what it is about" {
    var bytes: [Header.size + 8]u8 = @splat(0);
    std.mem.writeInt(u32, bytes[0..4], bytes.len, .little);
    std.mem.writeInt(u32, bytes[4..8], @intFromEnum(Op.lookup), .little);
    std.mem.writeInt(u64, bytes[8..16], 0x1234, .little);
    std.mem.writeInt(u64, bytes[16..24], 1, .little);

    const head = Header.parse(&bytes).?;
    try std.testing.expectEqual(Op.lookup, head.op);
    try std.testing.expectEqual(@as(u64, 0x1234), head.unique);
    try std.testing.expectEqual(@as(u64, 1), head.nodeid);
    try std.testing.expectEqual(@as(usize, 8), head.body(&bytes).len);
}

test "an operation nobody named stays a number" {
    var bytes: [Header.size]u8 = @splat(0);
    std.mem.writeInt(u32, bytes[0..4], bytes.len, .little);
    std.mem.writeInt(u32, bytes[4..8], 9999, .little);
    const head = Header.parse(&bytes).?;
    try std.testing.expect(head.op != .lookup);
    try std.testing.expectEqual(@as(u32, 9999), @intFromEnum(head.op));
}

test "an answer carries its own length and the number it answers" {
    var into: [64]u8 = undefined;
    const wrote = Answer.write(&into, 0x99, 0, 8);
    try std.testing.expectEqual(@as(usize, 24), wrote);
    try std.testing.expectEqual(@as(u32, 24), std.mem.readInt(u32, into[0..4], .little));
    try std.testing.expectEqual(@as(i32, 0), std.mem.readInt(i32, into[4..8], .little));
    try std.testing.expectEqual(@as(u64, 0x99), std.mem.readInt(u64, into[8..16], .little));
}

test "a directory entry is padded the way the kernel steps through them" {
    var into: [512]u8 = undefined;
    const attr: Attr = .{ .ino = 7, .mode = 0o040755 };
    const wrote = DirEntry.write(&into, 7, attr, 1, "abc");
    try std.testing.expectEqual(DirEntry.roomFor("abc"), wrote);
    // Eight bytes for a name of three, so the next entry starts aligned.
    try std.testing.expectEqual(Entry.size + DirEntry.header_size + 8, wrote);
    try std.testing.expectEqualSlices(u8, "abc", into[Entry.size + DirEntry.header_size ..][0..3]);
    // A directory, said the way `DT_DIR` numbers it.
    try std.testing.expectEqual(@as(u32, 4), std.mem.readInt(u32, into[Entry.size + 20 ..][0..4], .little));
}

test "what this end says it can do is what it really does" {
    var into: [Init.out_size]u8 = undefined;
    const theirs: Init = .{ .major = 7, .minor = 41, .max_readahead = 131072, .flags = 0xffff_ffff };
    _ = Init.writeOut(&into, theirs);
    try std.testing.expectEqual(@as(u32, 7), std.mem.readInt(u32, into[0..4], .little));
    // Never more than this end knows, whatever the kernel offered.
    try std.testing.expectEqual(@as(u32, minor), std.mem.readInt(u32, into[4..8], .little));
    const said = std.mem.readInt(u32, into[12..16], .little);
    try std.testing.expectEqual(Init.flag.do_readdirplus | Init.flag.big_writes, said);
}

pub const Write = struct {
    pub const in_size = 40;

    handle: u64,
    offset: u64,
    bytes: u32,

    /// What the guest wants written, which follows the arguments in the same message.
    pub fn parse(body: []const u8) ?struct { Write, []const u8 } {
        if (body.len < in_size) return null;
        const said: Write = .{
            .handle = std.mem.readInt(u64, body[0..8], .little),
            .offset = std.mem.readInt(u64, body[8..16], .little),
            .bytes = std.mem.readInt(u32, body[16..20], .little),
        };
        const rest = body[in_size..];
        if (rest.len < said.bytes) return null;
        return .{ said, rest[0..said.bytes] };
    }

    pub fn writeOut(into: []u8, wrote: usize) usize {
        @memset(into[0..8], 0);
        std.mem.writeInt(u32, into[0..4], @intCast(wrote), .little);
        return 8;
    }
};

pub const Create = struct {
    pub const in_size = 16;

    flags: u32,
    mode: u32,
    name: []const u8,

    pub fn parse(body: []const u8) ?Create {
        if (body.len < in_size + 1) return null;
        return .{
            .flags = std.mem.readInt(u32, body[0..4], .little),
            .mode = std.mem.readInt(u32, body[4..8], .little),
            .name = std.mem.sliceTo(body[in_size..], 0),
        };
    }

    /// What a creation answers: what the name is now, and the handle for it.
    pub fn writeOut(into: []u8, nodeid: u64, attr: Attr, handle: u64) usize {
        const wrote = Entry.write(into, nodeid, attr);
        return wrote + Open.writeOut(into[wrote..], handle);
    }
};

pub const MakeDirectory = struct {
    pub const in_size = 8;

    mode: u32,
    name: []const u8,

    pub fn parse(body: []const u8) ?MakeDirectory {
        if (body.len < in_size + 1) return null;
        return .{
            .mode = std.mem.readInt(u32, body[0..4], .little),
            .name = std.mem.sliceTo(body[in_size..], 0),
        };
    }
};

pub const Rename = struct {
    pub const in_size = 8;

    /// The directory the name is moving to, which may be the one it is in.
    into_nodeid: u64,
    from: []const u8,
    to: []const u8,

    /// `rename2` says the same thing with flags in front of the names, which are ignored: this end
    /// does no exchanging and no refusing to replace.
    pub fn parse(body: []const u8, wide: bool) ?Rename {
        const head_size: usize = if (wide) 16 else in_size;
        if (body.len < head_size + 2) return null;
        const from = std.mem.sliceTo(body[head_size..], 0);
        const rest = body[head_size + from.len + 1 ..];
        if (rest.len == 0) return null;
        return .{
            .into_nodeid = std.mem.readInt(u64, body[0..8], .little),
            .from = from,
            .to = std.mem.sliceTo(rest, 0),
        };
    }
};

/// What a `setattr` is allowed to change, as the kernel numbers the bits.
pub const SetAttr = struct {
    pub const in_size = 88;

    pub const wants_mode: u32 = 1 << 0;
    pub const wants_size: u32 = 1 << 3;
    /// The times, which a build system really depends on: it decides what to rebuild by comparing
    /// them. A filesystem that quietly keeps the old ones makes a cache that is wrong rather than
    /// slow, so these are answered rather than ignored.
    pub const wants_atime: u32 = 1 << 4;
    pub const wants_mtime: u32 = 1 << 5;
    /// Set to whatever the time is now, rather than to a time the caller gave.
    pub const atime_is_now: u32 = 1 << 7;
    pub const mtime_is_now: u32 = 1 << 8;

    valid: u32,
    handle: u64,
    size: u64,
    mode: u32,
    /// Seconds and nanoseconds since the epoch, for each of the two times.
    atime: i64,
    atime_nanoseconds: u32,
    mtime: i64,
    mtime_nanoseconds: u32,

    pub fn parse(body: []const u8) ?SetAttr {
        if (body.len < in_size) return null;
        return .{
            .valid = std.mem.readInt(u32, body[0..4], .little),
            .handle = std.mem.readInt(u64, body[8..16], .little),
            .size = std.mem.readInt(u64, body[16..24], .little),
            .mode = std.mem.readInt(u32, body[68..72], .little),
            .atime = std.mem.readInt(i64, body[32..40], .little),
            .atime_nanoseconds = std.mem.readInt(u32, body[56..60], .little),
            .mtime = std.mem.readInt(i64, body[40..48], .little),
            .mtime_nanoseconds = std.mem.readInt(u32, body[60..64], .little),
        };
    }
};

test "a write says where it goes and carries what goes there" {
    var body: [Write.in_size + 5]u8 = @splat(0);
    std.mem.writeInt(u64, body[0..8], 7, .little);
    std.mem.writeInt(u64, body[8..16], 1024, .little);
    std.mem.writeInt(u32, body[16..20], 5, .little);
    @memcpy(body[Write.in_size..][0..5], "hello");

    const said, const bytes = Write.parse(&body).?;
    try std.testing.expectEqual(@as(u64, 7), said.handle);
    try std.testing.expectEqual(@as(u64, 1024), said.offset);
    try std.testing.expectEqualSlices(u8, "hello", bytes);

    // A message claiming more bytes than arrived is not a write: it would read past what came.
    std.mem.writeInt(u32, body[16..20], 4096, .little);
    try std.testing.expectEqual(@as(?struct { Write, []const u8 }, null), Write.parse(&body));
}

test "a rename names both ends" {
    var body: [Rename.in_size + 8]u8 = @splat(0);
    std.mem.writeInt(u64, body[0..8], 1, .little);
    @memcpy(body[Rename.in_size..][0..8], "old\x00new\x00");

    const said = Rename.parse(&body, false).?;
    try std.testing.expectEqualSlices(u8, "old", said.from);
    try std.testing.expectEqualSlices(u8, "new", said.to);
    try std.testing.expectEqual(@as(u64, 1), said.into_nodeid);
}
