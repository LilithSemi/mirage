//! What a caller types, and the work that needs no hypervisor under it.

const std = @import("std");
const backend = @import("mirage-backend");
const core = @import("mirage-core");
const arm64 = @import("mirage-arm64");
const device = @import("mirage-device");
const image = @import("mirage-image");
const netmod = @import("mirage-net");
const sessionmod = @import("mirage-session");
const Options = @import("Options.zig");
const GuestMemory = @import("mirage-memory").GuestMemory;
const attest = @import("mirage-attest");
const Manifest = attest.Manifest;
const usage = Options.usage;
const builtin = @import("builtin");
const runner = switch (builtin.os.tag) {
    .linux => @import("linux.zig"),
    .macos => @import("darwin.zig"),
    else => @compileError("no hypervisor is known on this system"),
};

/// A kernel and an initial filesystem are large but not unbounded. Refusing early
/// is better than an allocator failing somewhere deeper.
const file_limit: std.Io.Limit = .limited(1 << 30);

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    var out_buffer: [4096]u8 = undefined;
    var out = std.Io.File.stdout().writer(io, &out_buffer);
    defer out.interface.flush() catch {};

    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2) {
        try out.interface.writeAll(usage);
        return;
    }

    const command = args[1];
    if (std.mem.eql(u8, command, "probe")) return runner.probe(&out.interface);
    if (std.mem.eql(u8, command, "run")) return runner.run(gpa, io, &out.interface, args[2..]);
    if (std.mem.eql(u8, command, "pack")) return pack(gpa, io, &out.interface, args[2..]);
    if (std.mem.eql(u8, command, "seal")) return seal(gpa, io, &out.interface, args[2..]);

    try out.interface.print("unknown command: {s}\n\n", .{command});
    try out.interface.writeAll(usage);
}

/// Build an initial filesystem from a directory. Every file in it becomes a file at
/// the top of the archive, plus the console device node, because the kernel gives the
/// first process whatever `/dev/console` names.
fn pack(gpa: std.mem.Allocator, io: std.Io, out: *std.Io.Writer, args: []const [:0]const u8) !void {
    if (args.len != 2) {
        try out.writeAll("pack needs a directory and an output path\n\n");
        try out.writeAll(usage);
        return;
    }

    var archive: image.Cpio = .init(gpa);
    defer archive.deinit();

    try archive.addDirectory("dev", 0o755);
    try archive.addCharacterDevice("dev/console", 0o600, 5, 1);

    var source = try std.Io.Dir.cwd().openDir(io, args[0], .{ .iterate = true });
    defer source.close(io);

    var walker = try source.walk(gpa);
    defer walker.deinit();

    var count: usize = 0;
    while (try walker.next(io)) |entry| {
        switch (entry.kind) {
            // A directory has to go in before anything inside it, and the walk hands
            // them out in that order.
            .directory => try archive.addDirectory(entry.path, 0o755),
            .file => {
                const bytes = try entry.dir.readFileAlloc(io, entry.basename, gpa, file_limit);
                defer gpa.free(bytes);
                // Everything is executable, because an archive like this holds programs.
                try archive.addFile(entry.path, 0o755, bytes);
                count += 1;
            },
            // A symbolic link, a socket, a device node the caller made: none of them
            // carry over, and skipping in silence would hide that.
            else => try out.print("skipped {s}, it is a {t}\n", .{ entry.path, entry.kind }),
        }
    }

    const blob = try archive.finish();
    defer gpa.free(blob);

    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = args[1], .data = blob });
    try out.print("packed {d} files into {s}, {d} bytes\n", .{ count, args[1], blob.len });
}

/// Build a read only root filesystem from a directory, with a hash tree over it, and say
/// what to tell the kernel.
///
/// The tree goes on the same disk right after the filesystem, so a guest needs one
/// device. The root hash reaches the guest on the command line, and the command line is
/// measured, which is what makes every block of the disk part of the launch rather than
/// only the bytes loaded into memory at the start.
fn seal(gpa: std.mem.Allocator, io: std.Io, out: *std.Io.Writer, args: []const [:0]const u8) !void {
    if (args.len != 2) {
        try out.writeAll("seal needs a directory and an output path\n\n");
        try out.writeAll(usage);
        return;
    }

    var filesystem: image.Erofs = .init(gpa);
    defer filesystem.deinit();

    try filesystem.addDirectory("dev");
    try filesystem.addCharacterDevice("dev/console", 5, 1);

    var source = try std.Io.Dir.cwd().openDir(io, args[0], .{ .iterate = true });
    defer source.close(io);

    var walker = try source.walk(gpa);
    defer walker.deinit();

    var count: usize = 0;
    while (try walker.next(io)) |entry| {
        switch (entry.kind) {
            // A directory has to go in before anything inside it, and the walk hands
            // them out in that order.
            .directory => try filesystem.addDirectory(entry.path),
            .file => {
                const bytes = try entry.dir.readFileAlloc(io, entry.basename, gpa, file_limit);
                defer gpa.free(bytes);
                try filesystem.addFile(entry.path, bytes);
                count += 1;
            },
            // A symbolic link, a socket, a device node the caller made: none of them
            // carry over, and skipping in silence would hide that.
            else => try out.print("skipped {s}, it is a {t}\n", .{ entry.path, entry.kind }),
        }
    }

    const rootfs = try filesystem.finish();
    defer gpa.free(rootfs);

    // A salt separates one tree from another. It is not a secret, and it is taken from
    // this machine so two seals of the same directory do not share a tree.
    var salt: [8]u8 = undefined;
    try io.randomSecure(&salt);

    var tree = try image.Verity.build(gpa, rootfs, &salt);
    defer tree.deinit(gpa);

    // The filesystem, then a header saying how the tree was built, then the tree. The
    // header means a runner needs only the root hash from outside the image, and the
    // root hash is the one thing that has to come from outside.
    var uuid: [16]u8 = undefined;
    try io.randomSecure(&uuid);
    const header: image.Verity.Superblock = .init(tree, &salt, uuid);

    const block = image.Verity.block_size;
    const sealed = try gpa.alloc(u8, rootfs.len + block + tree.blocks.len);
    defer gpa.free(sealed);
    @memset(sealed, 0);
    @memcpy(sealed[0..rootfs.len], rootfs);
    @memcpy(sealed[rootfs.len..][0..512], &@as([512]u8, @bitCast(header)));
    @memcpy(sealed[rootfs.len + block ..], tree.blocks);

    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = args[1], .data = sealed });

    var digest: [image.Verity.digest_size * 2]u8 = undefined;
    image.Verity.formatDigest(tree.root, &digest);
    var salt_hex: [16]u8 = undefined;
    for (salt, 0..) |byte, index| {
        const alphabet = "0123456789abcdef";
        salt_hex[index * 2] = alphabet[byte >> 4];
        salt_hex[index * 2 + 1] = alphabet[byte & 0xf];
    }

    try out.print(
        \\sealed {d} files into {s}, {d} bytes
        \\
        \\root hash {s}
        \\
        \\the command line the guest needs, which is measured with everything else:
        \\
        \\  --cmdline 'console=ttyAMA0 ro init=/init root=/dev/dm-0 rootfstype=erofs rootwait dm-mod.create="root,,,ro,0 {d} verity 1 /dev/vda /dev/vda {d} {d} {d} {d} sha256 {s} {s}"'
        \\
    , .{
        count,
        args[1],
        sealed.len,
        digest,
        tree.data_blocks * (image.Verity.block_size / 512),
        image.Verity.block_size,
        image.Verity.block_size,
        tree.data_blocks,
        // The header takes the first hash block, so the tree itself starts after it.
        tree.data_blocks + 1,
        digest,
        salt_hex,
    });
}
