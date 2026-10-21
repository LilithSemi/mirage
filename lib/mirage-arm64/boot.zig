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
const fdt = @import("fdt.zig");
const GuestMemory = @import("mirage-memory").GuestMemory;
const attest = @import("mirage-attest");
const Manifest = attest.Manifest;

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
        return @fromBackingInt(@intCast(@as(u2, @truncate(self.flags >> 1))));
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

/// What is being started.
///
/// A Linux kernel carries a header saying where it wants to be and is entered there. Firmware
/// carries nothing: it is placed where it was built to run, entered there, and finds the device tree
/// by looking where the machines it was built for put one, which is the start of memory.
pub const Kind = union(enum) {
    linux,
    firmware: struct {
        /// Where the firmware was built to run. Its own reset vector is the first thing in it.
        at: u64,
        /// How much room to leave for it, which is its own size rounded up by whoever mapped it.
        len: u64,
    },
};

/// A span of guest memory the kernel is told about, such as the initial filesystem or the list of
/// measurements.
pub const Range = struct {
    start: u64,
    end: u64,
};

pub const Config = struct {
    /// What `kernel` holds. Firmware and a kernel are placed differently and told different things.
    kind: Kind = .linux,
    kernel: []const u8,
    /// An initial filesystem, unpacked by the kernel into its root. Without one the
    /// kernel looks for a disk to mount instead.
    initrd: ?[]const u8 = null,
    cmdline: []const u8,
    /// Which interrupt controller the guest is told it has.
    controller: fdt.Interrupts = .gic_v3,
    /// Entropy the guest starts its random pool with. Measured like every other
    /// input, so a verifier can see that one was given and what it was. A caller
    /// that wants unpredictable randomness inside the guest must take this from the
    /// host and not from anything a guest could guess.
    rng_seed: ?[]const u8 = null,
    /// The root of the hash tree over the guest's root filesystem, if it has one.
    ///
    /// This reaches the guest on the command line, which is measured, so the property holds without
    /// it. Measuring it here as well gives a verifier the one value it cares about by name, rather
    /// than asking it to find the value inside a string it has to parse.
    rootfs_verity: ?[]const u8 = null,
    /// Whether the guest is told it has a block device.
    block_device: bool = true,
    /// Whether the guest is told it has a channel to whoever started it.
    vsock: bool = false,
    /// Whether the guest is told it has a balloon.
    balloon: bool = false,
    /// Whether the guest is told it has a network device.
    net: bool = false,
    /// Whether the guest is told about a directory on the host it may mount.
    share: bool = false,
    /// Whether the guest is told it has a security chip.
    tpm: bool = false,
    /// Whether the guest is told it has a pci host bridge.
    pci: bool = false,
    ram_base: u64,
    ram_size: u64,
    cpus: u32,
    uart_base: u64,
};

pub const Layout = struct {
    /// Where the guest starts, and what `pc` is set to.
    entry: u64,
    /// Where the device tree sits, and what `x0` is set to.
    device_tree: u64,
    /// Where the initial filesystem was placed, if there was one.
    initrd: ?Range = null,
    /// Where the list of measurements was placed, if the guest was given one.
    log: ?Range = null,
};

/// Put a guest at its entry point the way the arm64 Linux boot protocol asks.
///
/// The protocol wants the device tree address in `x0` and the other three argument registers zeroed.
/// x86 has to set long mode and a full segment state here, so the boot entry is the seam both
/// architectures meet; arm's needs only the few general registers. The vCPU is passed in rather than
/// imported, so this stays below the backend.
pub fn enter(vcpu: anytype, layout: Layout) !void {
    try vcpu.setRegister(.pc, layout.entry);
    try vcpu.setRegister(.x0, layout.device_tree);
    try vcpu.setRegister(.x1, 0);
    try vcpu.setRegister(.x2, 0);
    try vcpu.setRegister(.x3, 0);
}

pub const PrepareError = error{
    NoRoom,
    /// A device tree node name longer than the buffer that formats it.
    NoSpaceLeft,
    /// The device tree was left with a node open. This is a bug in `mirage-arm64`.
    Unbalanced,
} || std.mem.Allocator.Error || GuestMemory.Error || Manifest.Error || Error;

/// Which register a launch is folded into, and the one the list of measurements names. A register the
/// guest can add to says nothing about what started it, so nothing inside the guest writes this one.
const launch_register = 0;

/// The device tree goes above the kernel image, far enough not to collide with it and
/// near enough for the kernel to reach it early.
const tree_alignment = 2 * 1024 * 1024;

/// Place the guest in memory, measuring every input on the way in, and say where it starts and where
/// it finds the device tree.
///
/// Loading and measuring are one pass on purpose. Nothing reaches guest memory without being hashed
/// on the way in, and the manifest seals before the first instruction.
pub fn prepare(
    gpa: std.mem.Allocator,
    memory: *GuestMemory,
    manifest: *Manifest,
    config: Config,
) PrepareError!Layout {
    if (config.kind == .firmware) return prepareFirmware(gpa, memory, manifest, config);

    const header = try parse(config.kernel);
    const entry = loadAddress(config.ram_base, header);

    const occupied = @max(header.image_size, config.kernel.len);

    // The initial filesystem goes above the kernel and the device tree goes above
    // that, because the tree has to name where the filesystem starts and ends.
    var initrd: ?fdt.Range = null;
    var above = entry + occupied;
    if (config.initrd) |bytes| {
        const at = std.mem.alignForward(u64, above, tree_alignment);
        initrd = .{ .start = at, .end = at + bytes.len };
        above = at + bytes.len;
    }
    const tree_at = std.mem.alignForward(u64, above, tree_alignment);

    var room: [8]Manifest.Tag = undefined;
    const measuring = measuredTags(config, &room);

    var settings: fdt.Config = .{
        .ram_base = config.ram_base,
        .ram_size = config.ram_size,
        .cpus = config.cpus,
        .cmdline = config.cmdline,
        .uart_base = config.uart_base,
        .initrd = initrd,
        .controller = config.controller,
        .rng_seed = config.rng_seed,
        .block_device = config.block_device,
        .vsock = config.vsock,
        .balloon = config.balloon,
        .net = config.net,
        .share = config.share,
        .tpm = config.tpm,
        .pci = config.pci,
    };

    // A guest with a chip is given the list of measurements to go with it, because a register says
    // that two launches differ and never what either of them was.
    //
    // The tree has to name where the list is, and the list holds the tree's own measurement, so
    // neither can be built first. The way out is that the tree's length does not depend on either
    // number in it, because both are written as a fixed width. So the tree is built once to learn its
    // length, the list is placed above it, and the tree is built again with the answer.
    var log: ?fdt.Range = null;
    if (config.tpm) {
        const first = try fdt.build(gpa, settings);
        const provisional = first.len;
        gpa.free(first);

        const log_at = std.mem.alignForward(u64, tree_at + provisional, tree_alignment);
        log = .{ .start = log_at, .end = log_at + attest.Log.sizeFor(measuring) };
        settings.log = log;
    }

    const blob = try fdt.build(gpa, settings);
    defer gpa.free(blob);

    const end = config.ram_base + config.ram_size;
    if (entry + occupied > end) return PrepareError.NoRoom;
    if (tree_at + blob.len > end) return PrepareError.NoRoom;
    if (log) |where| {
        if (where.end > end) return PrepareError.NoRoom;
        // The two builds gave different lengths, which would leave the list somewhere the guest was
        // never told about. Both numbers in the tree are a fixed width, so this cannot happen.
        std.debug.assert(tree_at + blob.len <= where.start);
    }

    // Nothing above here has touched the manifest, so a launch refused for want of room leaves it
    // as it was.
    for (measuring) |tag| try manifest.add(gpa, tag, switch (tag) {
        .kernel => config.kernel,
        .initrd => config.initrd.?,
        .device_config => config.rng_seed.?,
        .rootfs_verity => config.rootfs_verity.?,
        .cmdline => config.cmdline,
        .device_tree => blob,
        else => unreachable,
    });

    try memory.write(entry, config.kernel);
    if (config.initrd) |bytes| try memory.write(initrd.?.start, bytes);
    try memory.write(tree_at, blob);

    manifest.seal();

    // Last of all, because the list holds the measurement of the tree that names it.
    if (log) |where| {
        const bytes = try gpa.alloc(u8, where.end - where.start);
        defer gpa.free(bytes);
        const written = attest.Log.write(bytes, manifest, launch_register);
        std.debug.assert(written.len == bytes.len);
        try memory.write(where.start, written);
    }

    return .{
        .entry = entry,
        .device_tree = tree_at,
        .initrd = rangeOf(initrd),
        .log = rangeOf(log),
    };
}

/// A device tree range as a launch range. The two hold the same two numbers; they are separate types
/// only so a caller that does not name the device tree need not name `fdt`.
fn rangeOf(range: ?fdt.Range) ?Range {
    const one = range orelse return null;
    return .{ .start = one.start, .end = one.end };
}

/// What a launch measures, in the order it measures it.
///
/// One list, used twice: to work out how long the list of measurements will be before anything has
/// been measured, and then to measure. Two lists would disagree the first time somebody adds to one.
fn measuredTags(config: Config, into: *[8]Manifest.Tag) []const Manifest.Tag {
    var count: usize = 0;
    into[count] = .kernel;
    count += 1;
    if (config.initrd != null) {
        into[count] = .initrd;
        count += 1;
    }
    if (config.rng_seed != null) {
        into[count] = .device_config;
        count += 1;
    }
    if (config.rootfs_verity != null) {
        into[count] = .rootfs_verity;
        count += 1;
    }
    into[count] = .cmdline;
    count += 1;
    // The tree is last because it names where everything else is.
    into[count] = .device_tree;
    count += 1;
    return into[0..count];
}

/// Place firmware and the device tree it will look for.
///
/// Firmware is the first link in a chain of measurements: it measures what it loads, that measures
/// what it loads, and so on. This side measures the firmware itself, because nothing inside the
/// guest can vouch for the thing that started it.
///
/// The tree goes at the start of memory because that is where the machines this firmware is built
/// for put one, and the firmware looks there rather than being told.
fn prepareFirmware(
    gpa: std.mem.Allocator,
    memory: *GuestMemory,
    manifest: *Manifest,
    config: Config,
) PrepareError!Layout {
    const where = config.kind.firmware;
    if (config.kernel.len > where.len) return PrepareError.NoRoom;

    var settings: fdt.Config = .{
        .ram_base = config.ram_base,
        .ram_size = config.ram_size,
        .cpus = config.cpus,
        .cmdline = config.cmdline,
        .uart_base = config.uart_base,
        .controller = config.controller,
        .rng_seed = config.rng_seed,
        .block_device = config.block_device,
        .vsock = config.vsock,
        .balloon = config.balloon,
        .net = config.net,
        .share = config.share,
        .tpm = config.tpm,
        .pci = config.pci,
        // Firmware reads this device before it reaches any of its own code, so a machine that
        // starts firmware has one and a machine that starts a kernel does not.
        .fw_cfg = true,
    };

    // What this launch measures, in order. One list, so what goes into the length and what goes into
    // the manifest cannot disagree.
    var room: [4]Manifest.Tag = undefined;
    var count: usize = 0;
    room[count] = .firmware;
    count += 1;
    if (config.rng_seed != null) {
        room[count] = .device_config;
        count += 1;
    }
    room[count] = .device_tree;
    count += 1;
    const measuring = room[0..count];

    // Firmware gets the same list a kernel does, for the same reason, and it is the one that most
    // needs it: firmware measures what it loads next, so the list it is handed is the beginning of a
    // chain it goes on to extend. Two builds of the tree for the same reason as above.
    var log: ?fdt.Range = null;
    if (config.tpm) {
        const first = try fdt.build(gpa, settings);
        const provisional = first.len;
        gpa.free(first);

        const log_at = std.mem.alignForward(u64, config.ram_base + provisional, tree_alignment);
        log = .{ .start = log_at, .end = log_at + attest.Log.sizeFor(measuring) };
        settings.log = log;
    }

    const blob = try fdt.build(gpa, settings);
    defer gpa.free(blob);

    if (blob.len > config.ram_size) return PrepareError.NoRoom;
    if (log) |place| {
        if (place.end > config.ram_base + config.ram_size) return PrepareError.NoRoom;
        std.debug.assert(config.ram_base + blob.len <= place.start);
    }

    for (measuring) |tag| try manifest.add(gpa, tag, switch (tag) {
        .firmware => config.kernel,
        .device_config => config.rng_seed.?,
        .device_tree => blob,
        else => unreachable,
    });

    try memory.write(where.at, config.kernel);
    try memory.write(config.ram_base, blob);

    manifest.seal();

    if (log) |place| {
        const bytes = try gpa.alloc(u8, place.end - place.start);
        defer gpa.free(bytes);
        const written = attest.Log.write(bytes, manifest, launch_register);
        std.debug.assert(written.len == bytes.len);
        try memory.write(place.start, written);
    }

    return .{ .entry = where.at, .device_tree = config.ram_base, .log = rangeOf(log) };
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

const test_ram_base = 0x4000_0000;

/// A kernel image that is only a header. Enough for the loader, which never executes
/// what it places.
fn fakeKernel(buffer: []u8) []u8 {
    @memset(buffer, 0);
    std.mem.writeInt(u32, buffer[56..60], 0x644d5241, .little);
    std.mem.writeInt(u64, buffer[16..24], 0x10_0000, .little);
    std.mem.writeInt(u64, buffer[24..32], 0x0e, .little);
    return buffer;
}

fn fixture(gpa: std.mem.Allocator, ram: []u8, kernel: []const u8) !struct { Layout, Manifest } {
    var regions = [_]GuestMemory.Region{
        .{ .gpa = test_ram_base, .len = ram.len, .backing = .{ .shared = ram } },
    };
    var memory: GuestMemory = .{ .regions = &regions };
    var manifest: Manifest = .{};

    const layout = try prepare(gpa, &memory, &manifest, .{
        .kernel = kernel,
        .cmdline = "console=ttyAMA0",
        .ram_base = test_ram_base,
        .ram_size = ram.len,
        .cpus = 1,
        .uart_base = 0x0900_0000,
    });
    return .{ layout, manifest };
}

test "preparing a launch measures every input before the guest can run" {
    const gpa = testing.allocator();
    var image: [64]u8 = undefined;
    const ram = try gpa.alloc(u8, 8 << 20);
    defer gpa.free(ram);

    const result = try fixture(gpa, ram, fakeKernel(&image));
    var manifest = result[1];
    defer manifest.deinit(gpa);

    // The kernel, the command line and the device tree, each one tagged.
    try testing.expectEqual(@as(usize, 3), manifest.entries.items.len);
    try testing.expectEqual(Manifest.Tag.kernel, manifest.entries.items[0].tag);
    try testing.expectEqual(Manifest.Tag.cmdline, manifest.entries.items[1].tag);
    try testing.expectEqual(Manifest.Tag.device_tree, manifest.entries.items[2].tag);
}

test "the manifest is sealed by the time the guest can run" {
    const gpa = testing.allocator();
    var image: [64]u8 = undefined;
    const ram = try gpa.alloc(u8, 8 << 20);
    defer gpa.free(ram);

    const result = try fixture(gpa, ram, fakeKernel(&image));
    var manifest = result[1];
    defer manifest.deinit(gpa);

    // Measure then launch is worth nothing if anything can still be measured after.
    try std.testing.expect(manifest.sealed);
    try testing.expectError(error.Sealed, manifest.add(gpa, .initrd, "late"));
}

test "the kernel is placed where its header asks and the tree sits above it" {
    const gpa = testing.allocator();
    var image: [64]u8 = undefined;
    const ram = try gpa.alloc(u8, 8 << 20);
    defer gpa.free(ram);

    const result = try fixture(gpa, ram, fakeKernel(&image));
    var manifest = result[1];
    defer manifest.deinit(gpa);
    const layout = result[0];

    try testing.expectEqual(@as(u64, test_ram_base), layout.entry);
    try std.testing.expect(layout.device_tree > layout.entry);
    try std.testing.expect(layout.device_tree % 8 == 0);
}

test "a kernel that does not fit in the memory given is refused" {
    const gpa = testing.allocator();
    var image: [64]u8 = undefined;
    _ = fakeKernel(&image);
    // Claim a 64MB image, then offer 1MB of memory.
    std.mem.writeInt(u64, image[16..24], 0x0400_0000, .little);

    const ram = try gpa.alloc(u8, 1 << 20);
    defer gpa.free(ram);

    try testing.expectError(error.NoRoom, fixture(gpa, ram, &image));
}

test "a launch that names a different root filesystem measures differently" {
    // The whole reason a hash tree root goes on the command line is that the command
    // line is measured. If the measurement did not move when the root hash moved, a
    // verifier could not tell one root filesystem from another and the tree would prove
    // nothing about which disk the guest was given.
    const gpa = testing.allocator();
    var picture: [64]u8 = undefined;
    const ram = try gpa.alloc(u8, 8 << 20);
    defer gpa.free(ram);

    const first = try measure(gpa, ram, fakeKernel(&picture), "root=/dev/dm-0 verity_root=aa11");
    const second = try measure(gpa, ram, fakeKernel(&picture), "root=/dev/dm-0 verity_root=aa12");

    try std.testing.expect(!std.mem.eql(u8, &first, &second));
}

fn measure(gpa: std.mem.Allocator, ram: []u8, kernel: []const u8, cmdline: []const u8) ![48]u8 {
    var regions = [_]GuestMemory.Region{
        .{ .gpa = test_ram_base, .len = ram.len, .backing = .{ .shared = ram } },
    };
    var memory: GuestMemory = .{ .regions = &regions };
    var manifest: Manifest = .{};
    defer manifest.deinit(gpa);

    _ = try prepare(gpa, &memory, &manifest, .{
        .kernel = kernel,
        .cmdline = cmdline,
        .ram_base = test_ram_base,
        .ram_size = ram.len,
        .cpus = 1,
        .uart_base = 0x0900_0000,
    });
    return manifest.root();
}

test "firmware is placed where it was built to run and measured as firmware" {
    const gpa = testing.allocator();
    const ram = try gpa.alloc(u8, 8 << 20);
    defer gpa.free(ram);
    const flash = try gpa.alloc(u8, 1 << 20);
    defer gpa.free(flash);

    // Firmware lives below the guest's memory, in its own window, the way a machine's read only
    // memory does.
    const flash_at = 0x1000_0000;
    var regions = [_]GuestMemory.Region{
        .{ .gpa = flash_at, .len = flash.len, .backing = .{ .shared = flash } },
        .{ .gpa = test_ram_base, .len = ram.len, .backing = .{ .shared = ram } },
    };
    var memory: GuestMemory = .{ .regions = &regions };
    var manifest: Manifest = .{};
    defer manifest.deinit(gpa);

    // Sixteen copies of a four byte pattern. `@splat` fills with one value, so the pattern is the
    // value and the result is flattened.
    const pattern: [16][4]u8 = @splat(.{ 0x11, 0x22, 0x33, 0x44 });
    const image: [64]u8 = @bitCast(pattern);
    const layout = try prepare(gpa, &memory, &manifest, .{
        .kind = .{ .firmware = .{ .at = flash_at, .len = flash.len } },
        .kernel = &image,
        .cmdline = "",
        .ram_base = test_ram_base,
        .ram_size = ram.len,
        .cpus = 1,
        .uart_base = 0x0900_0000,
    });

    // Entered at its own first instruction, not at an address taken from a header it does not have.
    try testing.expectEqual(@as(u64, flash_at), layout.entry);
    try testing.expectEqualSlices(u8, &image, flash[0..image.len]);

    // The tree goes at the start of memory, because firmware looks there rather than being told.
    try testing.expectEqual(@as(u64, test_ram_base), layout.device_tree);
    try std.testing.expect(std.mem.readInt(u32, ram[0..4], .big) == 0xd00dfeed);

    // And the first thing measured says it is firmware. A verifier told this was a kernel would be
    // looking for the wrong thing at the start of the chain.
    try testing.expectEqual(Manifest.Tag.firmware, manifest.entries.items[0].tag);
    try std.testing.expect(manifest.sealed);
}

test "firmware larger than the window it was given is refused" {
    const gpa = testing.allocator();
    const ram = try gpa.alloc(u8, 8 << 20);
    defer gpa.free(ram);

    var regions = [_]GuestMemory.Region{
        .{ .gpa = test_ram_base, .len = ram.len, .backing = .{ .shared = ram } },
    };
    var memory: GuestMemory = .{ .regions = &regions };
    var manifest: Manifest = .{};
    defer manifest.deinit(gpa);

    // A window smaller than the image. Writing it anyway would run past the end of what was mapped.
    const image: [128]u8 = @splat(0xaa);
    try testing.expectError(PrepareError.NoRoom, prepare(gpa, &memory, &manifest, .{
        .kind = .{ .firmware = .{ .at = 0x1000_0000, .len = 64 } },
        .kernel = &image,
        .cmdline = "",
        .ram_base = test_ram_base,
        .ram_size = ram.len,
        .cpus = 1,
        .uart_base = 0x0900_0000,
    }));
}
