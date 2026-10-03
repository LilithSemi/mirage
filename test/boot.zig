//! Boots a real Linux kernel under KVM and reads what it says.
//!
//! This test is Linux only and lives outside `lib/` because it opens a file, and a
//! portable module may not. It maps the kernel this machine booted, puts it in a
//! guest, and reads the serial port.

const std = @import("std");
const core = @import("mirage-core");
const backend = @import("mirage-backend");
const device = @import("mirage-device");
const arm64 = @import("mirage-arm64");
const GuestMemory = @import("mirage-memory").GuestMemory;
const attest = @import("mirage-attest");
const Manifest = attest.Manifest;
const image = @import("mirage-image");
const netmod = @import("mirage-net");
const fsmod = @import("mirage-fs");
const linux = std.os.linux;

/// The guest userspace, built for aarch64 by the same `zig build` as the VMM.
const guest_init = @embedFile("guest-init");

/// What the shared directory holds, and what the guest has to read back out of it.
const shared_contents = "a store path from the host\n";

/// Hand a filesystem message to the export. The device carries bytes and answers nothing itself.
fn answerShare(ctx: *anyopaque, request: []const u8, into: []u8) usize {
    const one: *fsmod.Export = @ptrCast(@alignCast(ctx));
    return one.answer(request, into);
}

/// Whether the guest mounts a read only filesystem from the disk, or is unpacked
/// into memory from an archive.
const erofs_root = std.mem.eql(u8, options.rootfs, "erofs");

/// Whether the guest is given a channel back to this process. It needs a kernel with
/// `AF_VSOCK` built in, which the kernel this machine booted does not have.
const channel_on = options.vsock;

/// Whether the root filesystem is checked block by block as the guest reads it. It needs
/// a kernel with the verity target and the command line device builder built in.
const verity_root = options.verity;

/// Whether the guest is given a balloon and asked to hold half of its memory.
const balloon_on = options.balloon;

/// Where the helper that carries the guest's traffic is listening, or nothing for a guest with
/// no network. A helper has to be running for this, so it is not on by default.
const net_socket = options.net_socket;
const net_on = net_socket.len > 0;

/// Whether the guest is given a network of this VMM's own rather than a helper. Needs nothing running
/// beside this test, which is what lets it be a gate that always runs.
const nat_on = options.nat;

/// Whether the guest is offered a directory on this machine to mount. Needs a kernel with the
/// filesystem driver built in, so it is a gate of its own rather than part of every boot.
const share_on = options.share;

/// Where a program answering the chip commands is listening, or nothing for a guest with no chip.
const chip_socket = options.chip_socket;
const chip_on = chip_socket.len > 0;

/// Where the launch is folded in. A register the guest can add to says nothing about what started
/// it, so this one is written before the guest runs and never from inside.
const launch_register = 0;

/// How many CPUs the guest is given. The guest brings up every one after the first itself.
const cpus: u32 = options.cpus;

/// The address the guest answers to, and the one it gives itself. Fixed so the launch is
/// reproducible, and locally administered so it cannot collide with a real card.
const guest_mac = [6]u8{ 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 };

/// Whether one byte of the root filesystem is changed after the tree is built over it. A
/// check that is never seen to refuse is a check nobody has tested.
const tampered = options.tampered;

/// Fixed so the launch is reproducible. A salt here separates one tree from another and
/// is not a secret.
const verity_salt = "\x6d\x69\x72\x61\x67\x65\x00\x01";
const verity_salt_hex = "6d69726167650001";

/// What the log says when the root came through the verity target. The kernel picks the device
/// number for the mapped device when it is built, so the number is not what tells the two apart:
/// the root is named as the mapped device on the command line, and only the verity target can
/// produce it.
const verity_device = "device-mapper: verity: sha256 using";

const options = @import("boot-options");

const ram_base = 0x4000_0000;
const ram_size = 512 << 20;
const uart_base = 0x0900_0000;

/// The guest address and the port both sides agreed on. The guest program has the same
/// two numbers, and a channel where one side disagrees is a channel nobody answers.
const guest_cid = 3;
const host_port = 1024;

/// A guest that boots prints far more than this, and one that dies prints less. The
/// cap is here so a kernel that spins does not hang the suite.
const max_exits = 2_000_000;

/// A vCPU that is waiting for an interrupt blocks inside `KVM_RUN`, and no loop in
/// this process gets to run while it does. A signal with no `SA_RESTART` is how a
/// VMM takes a vCPU back: the blocked ioctl returns `EINTR`. Real VMMs do the same
/// thing to stop a guest.
fn onAlarm(_: linux.SIG) callconv(.c) void {}

/// Take the CPU back every `interval_ms`. Without this the loop below runs only when the
/// guest exits of its own accord, and a guest waiting on the channel exits for nothing.
fn armTicks(interval_ms: isize) void {
    const act: linux.Sigaction = .{
        .handler = .{ .handler = onAlarm },
        .mask = std.mem.zeroes(linux.sigset_t),
        .flags = 0,
    };
    _ = linux.sigaction(.ALRM, &act, null);

    // This syscall takes `struct itimerval`, whose second field is **microseconds**. The
    // standard library hands it an `itimerspec` and calls that field `nsec`, so the value
    // here is in microseconds despite the name. A nanosecond count lands far out of range
    // and the kernel refuses the call, leaving no timer armed and nothing to say so.
    const every: linux.timespec = .{
        .sec = @divTrunc(interval_ms, 1000),
        .nsec = @rem(interval_ms, 1000) * std.time.us_per_ms,
    };
    const spec: linux.itimerspec = .{ .it_interval = every, .it_value = every };
    _ = linux.setitimer(@intFromEnum(linux.ITIMER.REAL), &spec, null);
}

/// The lock the CPUs of one guest share. A spin lock, because it is held only long enough to serve
/// one device access.
var held: std.atomic.Mutex = .unlocked;

fn take(_: *anyopaque) void {
    while (!held.tryLock()) std.atomic.spinLoopHint();
}

fn release(_: *anyopaque) void {
    held.unlock();
}

/// Held while this test touches anything a second CPU could be touching. A guest with one CPU has
/// nothing to race with, so the lock is skipped rather than taken and released for nothing.
fn hold() void {
    if (cpus > 1) take(undefined);
}

fn drop() void {
    if (cpus > 1) release(undefined);
}

/// One of the CPUs the guest brings up itself. It waits inside the hypervisor until the guest asks
/// for it, and what it returns is not reported: the first CPU is the one that says how the run ended.
fn driveCpu(hv: backend.Backend, id: backend.Backend.VcpuId, driving: core.Launch.Run) void {
    _ = core.Launch.run(hv, id, driving) catch {};
}

/// The first name server this machine uses. A guest looking a name up through an address that answers
/// nothing looks exactly like a network that does not work, so this is read rather than guessed.
fn hostResolver(gpa: std.mem.Allocator) netmod.Ip4 {
    const fallback: netmod.Ip4 = .{ 1, 1, 1, 1 };

    var path: [64:0]u8 = @splat(0);
    @memcpy(path[0.."/etc/resolv.conf".len], "/etc/resolv.conf");
    const opened = linux.open(&path, .{ .ACCMODE = .RDONLY }, 0);
    if (std.posix.errno(opened) != .SUCCESS) return fallback;
    const fd: std.posix.fd_t = @intCast(opened);
    defer _ = linux.close(fd);

    const text = gpa.alloc(u8, 64 << 10) catch return fallback;
    defer gpa.free(text);
    const got = linux.read(fd, text.ptr, text.len);
    if (std.posix.errno(got) != .SUCCESS) return fallback;

    var lines = std.mem.splitScalar(u8, text[0..got], '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (!std.mem.startsWith(u8, trimmed, "nameserver")) continue;

        var parts = std.mem.splitScalar(u8, std.mem.trim(u8, trimmed["nameserver".len..], " \t"), '.');
        var address: netmod.Ip4 = undefined;
        var count: usize = 0;
        while (parts.next()) |part| : (count += 1) {
            if (count >= address.len) return fallback;
            address[count] = std.fmt.parseInt(u8, part, 10) catch return fallback;
        }
        if (count == address.len) return address;
    }
    return fallback;
}

/// The port the guest tries to reach on the gateway, which is this machine's own loopback.
const stream_port = 18080;

/// Listen where the guest will reach, and answer once. Nothing about this leaves the machine: the guest
/// addresses the gateway, the translation sends that to this machine's loopback, and this is what is
/// there. So the gate needs no network and no helper.
const Listener = struct {
    handle: std.posix.fd_t = -1,
    carried: std.posix.fd_t = -1,
    heard: usize = 0,
    answered: bool = false,

    fn open() ?Listener {
        const raw = linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0);
        if (std.posix.errno(raw) != .SUCCESS) return null;
        const handle: std.posix.fd_t = @intCast(raw);

        // Asked to be reusable, because a gate run twice in a row would otherwise find its own last
        // address still held.
        var yes: u32 = 1;
        _ = linux.setsockopt(handle, linux.SOL.SOCKET, linux.SO.REUSEADDR, @ptrCast(&yes), @sizeOf(u32));

        var address: linux.sockaddr.in = .{
            .family = linux.AF.INET,
            .port = std.mem.nativeToBig(u16, stream_port),
            .addr = 0x0100007f,
            .zero = @splat(0),
        };
        if (std.posix.errno(linux.bind(handle, @ptrCast(&address), @sizeOf(linux.sockaddr.in))) != .SUCCESS) {
            _ = linux.close(handle);
            return null;
        }
        if (std.posix.errno(linux.listen(handle, 1)) != .SUCCESS) {
            _ = linux.close(handle);
            return null;
        }
        dontWait(handle);
        return .{ .handle = handle };
    }

    fn deinit(self: *Listener) void {
        if (self.carried >= 0) _ = linux.close(self.carried);
        if (self.handle >= 0) _ = linux.close(self.handle);
        self.* = .{};
    }

    /// Take a connection if one is waiting, read what it says, and answer once. Nothing here waits.
    fn turn(self: *Listener) void {
        if (self.carried < 0) {
            const taken = linux.accept4(self.handle, null, null, 0);
            if (std.posix.errno(taken) != .SUCCESS) return;
            self.carried = @intCast(taken);
            dontWait(self.carried);
        }

        var buffer: [256]u8 = undefined;
        const got = linux.read(self.carried, &buffer, buffer.len);
        if (std.posix.errno(got) == .SUCCESS and got > 0) self.heard += got;

        if (self.heard > 0 and !self.answered) {
            const answer = "the host heard your stream\n";
            _ = linux.write(self.carried, answer.ptr, answer.len);
            self.answered = true;
        }
    }

    fn dontWait(handle: std.posix.fd_t) void {
        const flags = linux.fcntl(handle, linux.F.GETFL, 0);
        if (std.posix.errno(flags) != .SUCCESS) return;
        _ = linux.fcntl(handle, linux.F.SETFL, flags | @as(usize, 1 << 11));
    }
};

fn nowMs() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), 1_000_000);
}

fn mapKernel() !?[]align(std.heap.page_size_min) u8 {
    var path: [256:0]u8 = @splat(0);
    if (options.kernel_path.len >= path.len) return null;
    @memcpy(path[0..options.kernel_path.len], options.kernel_path);

    const opened = linux.open(&path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (std.posix.errno(opened) != .SUCCESS) return null;
    const fd: std.posix.fd_t = @intCast(opened);
    defer _ = linux.close(fd);

    const end = linux.lseek(fd, 0, 2);
    if (std.posix.errno(end) != .SUCCESS) return null;

    return try std.posix.mmap(null, @intCast(end), .{ .READ = true }, .{ .TYPE = .PRIVATE }, fd, 0);
}

test "a real linux kernel boots far enough to speak" {
    const gpa = std.testing.allocator;

    const kernel = (try mapKernel()) orelse return error.SkipZigTest;
    defer std.posix.munmap(kernel);

    var machine = backend.kvm.Machine.create(gpa, cpus) catch |err| switch (err) {
        error.NoKvm => return error.SkipZigTest,
        else => return err,
    };
    defer machine.deinit();

    const region = try machine.vm.addMemory(ram_base, ram_size, .shared);
    var regions = [_]GuestMemory.Region{region};
    var memory: GuestMemory = .{ .regions = &regions };

    const hv = machine.backend();
    // Every CPU has to exist before the controller is initialised, because the controller holds one
    // piece of state per CPU and is sized when it is made.
    const ids = try gpa.alloc(backend.Backend.VcpuId, cpus);
    defer gpa.free(ids);
    for (ids) |*each| each.* = try hv.addVcpu();
    const id = ids[0];

    var gic = try backend.kvm.Gic.create(&machine.vm, cpus, arm64.fdt.gicd_base, arm64.fdt.gicr_base);
    defer gic.deinit();

    var manifest: Manifest = .{};
    defer manifest.deinit(gpa);

    // Either the guest is unpacked into memory from an archive, or it is mounted
    // from a read only filesystem on the disk. A console device node either way,
    // because the kernel gives the first process whatever `/dev/console` names.
    var archive: image.Cpio = .init(gpa);
    defer archive.deinit();
    var filesystem: image.Erofs = .init(gpa);
    defer filesystem.deinit();

    // Both of these are handed over by their builder, so neither is freed by the
    // builder going out of scope.
    var initrd: ?[]const u8 = null;
    defer if (initrd) |bytes| gpa.free(bytes);
    var disk: []u8 = &.{};
    defer gpa.free(disk);

    // The root hash of the filesystem, and the command line that carries it. Both are
    // empty unless the root is checked.
    var verity_cmdline: [512]u8 = undefined;
    var cmdline: []const u8 = "";

    if (erofs_root) {
        try filesystem.addCharacterDevice("dev/console", 5, 1);
        try filesystem.addFile("init", guest_init);
        const rootfs = try filesystem.finish();

        if (!verity_root) {
            disk = rootfs;
        } else {
            defer gpa.free(rootfs);

            // The filesystem, a header saying how the tree was built, then the tree. All
            // on one disk, which is the same layout `mirage seal` writes.
            var tree = try image.Verity.build(gpa, rootfs, verity_salt);
            defer tree.deinit(gpa);

            const header: image.Verity.Superblock = .init(tree, verity_salt, @splat(0x5a));
            const block = image.Verity.block_size;

            disk = try gpa.alloc(u8, rootfs.len + block + tree.blocks.len);
            @memset(disk, 0);
            @memcpy(disk[0..rootfs.len], rootfs);
            @memcpy(disk[rootfs.len..][0..512], &@as([512]u8, @bitCast(header)));
            @memcpy(disk[rootfs.len + block ..], tree.blocks);

            // Change one byte of the filesystem superblock after the tree was built over
            // it. The tree and the root hash still describe what the filesystem used to
            // be, so a kernel that checks its reads cannot mount this at all. The
            // superblock and not some later block, because a block nothing reads until
            // after the first process has run proves nothing about the mount.
            if (tampered) disk[1024] ^= 0xff;

            var digest: [image.Verity.digest_size * 2]u8 = undefined;
            image.Verity.formatDigest(tree.root, &digest);

            // The root hash reaches the guest on the command line, and the command line
            // is measured. That is what makes every block of the disk part of the
            // launch rather than only the bytes loaded into memory at the start.
            cmdline = try std.fmt.bufPrint(&verity_cmdline, "console=ttyAMA0 ro init=/init root=/dev/dm-0 rootfstype=erofs rootwait " ++
                "dm-mod.create=\"root,,,ro,0 {d} verity 1 /dev/vda /dev/vda {d} {d} {d} {d} sha256 {s} {s}\"", .{
                tree.data_blocks * (image.Verity.block_size / 512),
                image.Verity.block_size,
                image.Verity.block_size,
                tree.data_blocks,
                // The header takes the first hash block, so the tree starts after it.
                tree.data_blocks + 1,
                digest,
                verity_salt_hex,
            });
        }
    } else {
        try archive.addDirectory("dev", 0o755);
        try archive.addCharacterDevice("dev/console", 0o600, 5, 1);
        try archive.addFile("init", 0o755, guest_init);
        initrd = try archive.finish();

        // A blank disk, so the driver still has something to probe.
        disk = try gpa.alloc(u8, 1 << 20);
        @memset(disk, 0);
    }

    const layout = try core.Launch.prepare(gpa, &memory, &manifest, .{
        .kernel = kernel,
        .initrd = initrd,
        .rng_seed = "mirage test seed, not for real use",
        // A real root filesystem makes the kernel look for `/sbin/init` and its
        // siblings. Only an unpacked archive gets `/init` for free.
        .cmdline = if (cmdline.len > 0)
            cmdline
        else if (erofs_root)
            "console=ttyAMA0 earlycon=pl011,0x9000000 root=/dev/vda rootfstype=erofs ro init=/init"
        else
            "console=ttyAMA0 earlycon=pl011,0x9000000 nokaslr",
        .ram_base = ram_base,
        .ram_size = ram_size,
        .cpus = cpus,
        .uart_base = uart_base,
        .vsock = channel_on,
        .balloon = balloon_on,
        .net = net_on or nat_on,
        .tpm = chip_on,
        .share = share_on,
    });

    var block: device.virtio.Block = undefined;
    block.init(disk);

    // The channel back to this process. The guest connects to the port, says something
    // and reads the answer, which is the whole of what a harness needs to drive it.
    var ports = [_]u32{host_port};
    var channel: device.virtio.Vsock = undefined;
    channel.init(guest_cid, &ports);

    var balloon: device.virtio.Balloon = undefined;
    balloon.init(ram_base, ram_size);
    // Half of what the guest was told it has. A target it can plainly reach, so a guest that
    // hands over nothing has a driver that never looked rather than a driver that tried.
    if (balloon_on) balloon.setTarget(ram_size / 2 / device.virtio.Balloon.page_size);

    const output = try gpa.alloc(u8, 64 << 10);
    defer gpa.free(output);
    var sink = std.Io.Writer.fixed(output);
    var serial: device.Pl011 = .{ .sink = &sink };

    // A tree that names a device the guest cannot reach sends it to read nothing, so each
    // one goes on the bus only when the guest was told about it. The serial port and the
    // disk are always there.
    // Connecting to the helper is the one thing here that needs an `Io`. A test has none of
    // its own, so one is made and thrown away with the connection.
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var card: device.virtio.Net = undefined;
    var relay: netmod.Relay = .{};
    var socket: ?netmod.Socket = null;
    if (net_on) {
        card.init(guest_mac);
        socket = netmod.Socket.connect(io, net_socket) catch |err| {
            std.debug.print("\nno network helper at {s}: {t}\n", .{ net_socket, err });
            return error.SkipZigTest;
        };
    }
    defer if (socket) |*open| open.close(io);

    // A network of this test's own, translating for a guest with no helper. The resolver is this
    // machine's, read the same way the command line reads it.
    var nat: netmod.Nat = .{
        .guest_ip = .{ 10, 0, 2, 15 },
        .guest_mac = guest_mac,
        .gateway_ip = .{ 10, 0, 2, 2 },
        .gateway_mac = .{ 0x52, 0x54, 0x00, 0x12, 0x34, 0x57 },
        .resolver = hostResolver(gpa),
    };
    defer nat.deinit();
    if (nat_on) card.init(guest_mac);

    // Something for the guest to reach through the gateway, on this machine's own loopback.
    var listener: ?Listener = if (nat_on) Listener.open() else null;
    defer if (listener) |*each| each.deinit();
    if (nat_on and listener == null) std.debug.print("\ncannot listen on port {d}, so the stream is not checked\n", .{stream_port});

    // The chip needs something that understands its commands. `swtpm` is the usual one, and a gate
    // with a path but nothing listening is a gate that would pass without proving anything.
    var chip: device.Tpm = .{};
    var chip_relay: device.Tpm.Relay(netmod.Socket) = .{};
    var chip_link: ?netmod.Socket = null;
    if (chip_on) {
        chip_link = netmod.Socket.connect(io, chip_socket) catch |err| {
            std.debug.print("\nnothing answers the chip at {s}: {t}\n", .{ chip_socket, err });
            return error.SkipZigTest;
        };
    }
    defer if (chip_link) |*open| open.close(io);

    // A directory for the guest to mount, with something in it worth reading. Made here so the gate
    // needs nothing prepared beside itself, and taken away afterwards.
    var offering: ?[]const u8 = null;
    defer if (offering) |at| {
        std.Io.Dir.cwd().deleteTree(io, at) catch {};
        gpa.free(at);
    };
    var offered: ?fsmod.Export = null;
    defer if (offered) |*one| one.deinit();
    var shared_fs: device.virtio.Fs = undefined;
    const share_asked = if (share_on) try gpa.alloc(u8, device.virtio.Fs.buffer_size) else @as([]u8, &.{});
    defer if (share_on) gpa.free(share_asked);
    const share_answered = if (share_on) try gpa.alloc(u8, device.virtio.Fs.buffer_size) else @as([]u8, &.{});
    defer if (share_on) gpa.free(share_answered);
    if (share_on) {
        var room: [96]u8 = undefined;
        const at = try gpa.dupe(u8, try std.fmt.bufPrint(&room, "/tmp/mirage-share-{d}", .{std.os.linux.getpid()}));
        offering = at;
        std.Io.Dir.cwd().deleteTree(io, at) catch {};
        try std.Io.Dir.cwd().createDir(io, at, .default_dir);
        var name: [160]u8 = undefined;
        try std.Io.Dir.cwd().createDir(io, try std.fmt.bufPrint(&name, "{s}/store", .{at}), .default_dir);
        try std.Io.Dir.cwd().createDir(io, try std.fmt.bufPrint(&name, "{s}/work", .{at}), .default_dir);
        try std.Io.Dir.cwd().writeFile(io, .{
            .sub_path = try std.fmt.bufPrint(&name, "{s}/store/hello", .{at}),
            .data = shared_contents,
        });

        // One to read and one to work in, which is the shape a harness gives a guest: its tools where
        // nothing may change them, and a place where everything may.
        offered = try fsmod.Export.init(gpa, io);
        try offered.?.offer("store", try std.fmt.bufPrint(&name, "{s}/store", .{at}), false);
        try offered.?.offer("work", try std.fmt.bufPrint(&name, "{s}/work", .{at}), true);
        shared_fs.init(fsmod.Export.tag, .{ .ctx = &offered.?, .answer = answerShare }, share_asked, share_answered);
    }

    var devices: [7]device.Device = undefined;
    var services: [5]device.Service = undefined;
    devices[0] = serial.device(uart_base);
    devices[1] = block.device(arm64.fdt.virtio_base);
    services[0] = block.service(arm64.fdt.virtio_intid);
    var on_bus: usize = 2;
    var serviced: usize = 1;
    if (channel_on) {
        devices[on_bus] = channel.device(arm64.fdt.vsock_base);
        services[serviced] = channel.service(arm64.fdt.vsock_intid);
        on_bus += 1;
        serviced += 1;
    }
    if (balloon_on) {
        devices[on_bus] = balloon.device(arm64.fdt.balloon_base);
        services[serviced] = balloon.service(arm64.fdt.balloon_intid);
        on_bus += 1;
        serviced += 1;
    }
    if (net_on or nat_on) {
        devices[on_bus] = card.device(arm64.fdt.net_base);
        services[serviced] = card.service(arm64.fdt.net_intid);
        on_bus += 1;
        serviced += 1;
    }
    if (share_on) {
        devices[on_bus] = shared_fs.device(arm64.fdt.fs_base);
        services[serviced] = shared_fs.service(arm64.fdt.fs_intid);
        on_bus += 1;
        serviced += 1;
    }
    if (chip_on) {
        // The chip answers reads and writes only, so it goes on the bus and needs no service.
        devices[on_bus] = chip.device(arm64.fdt.tpm_base);
        on_bus += 1;
    }
    var bus: device.Bus = .{ .devices = devices[0..on_bus] };

    // Fold the launch into the chip before the guest runs, the way firmware does for the stages it
    // loads. The guest then reads that register and says what it believes started it, and this side
    // checks it against arithmetic of its own rather than believing it.
    var expected_chain: ?[attest.Chain.length]u8 = null;
    if (chip_link) |*link| {
        var session: attest.Chain.Session(netmod.Socket) = .{ .transport = link };
        expected_chain = session.measure(&manifest, launch_register) catch |err| {
            std.debug.print("\nthe chip would not take the launch: {t}, code {x}\n", .{ err, session.refusal });
            return error.SkipZigTest;
        };

        // And the chip's own signed word for it. Every other part of this reaches a reader through
        // this process, which could say anything: a quote is the one part that does not. The number
        // it covers is chosen here, so an old quote cannot be shown again in place of this one.
        var room: [1024]u8 = undefined;
        const nonce = "the number this test chose";
        const taken = attest.Quote.take(&session, &room, launch_register, nonce, expected_chain.?) catch |err| {
            std.debug.print("\nthe chip would not quote: {t}, code {x}\n", .{ err, session.refusal });
            return error.SkipZigTest;
        };

        // Checking it again against a register the chip never held has to fail, or the check above
        // proves nothing: a check that passes for every value is not a check.
        var other = expected_chain.?;
        other[0] ^= 1;
        try std.testing.expectError(
            attest.Quote.Error.Wrong,
            attest.Quote.check(taken.answer, taken.key, nonce, other),
        );
        try std.testing.expectError(
            attest.Quote.Error.Wrong,
            attest.Quote.check(taken.answer, taken.key, "a number nobody asked", expected_chain.?),
        );
    }

    try core.Launch.enter(hv, id, layout);

    // The CPUs the guest brings up itself, each on a thread of its own and sharing everything behind
    // the one lock. They are detached because a CPU waiting inside the hypervisor comes out when the
    // guest says so, not when this test would like it to.
    for (ids[1..]) |each| {
        const thread = try std.Thread.spawn(.{}, driveCpu, .{ hv, each, core.Launch.Run{
            .bus = &bus,
            .memory = &memory,
            .controller = gic.controller(),
            .exits = max_exits,
            .guard = .{ .ctx = undefined, .lock = take, .unlock = release },
        } });
        thread.detach();
    }

    // A guest that is waiting on a timer nobody built will sit in `KVM_RUN` forever,
    // so the loop is bounded by the clock as well as by the exit count.
    const deadline = nowMs() + 5_000;
    armTicks(10);

    var exits: usize = 0;
    var reported: usize = 0;
    var stopped: ?backend.Backend.Exit = null;

    // What the guest said over the channel, and whether it has been answered.
    var open: ?device.virtio.Vsock.Handle = null;
    var heard: [256]u8 = undefined;
    var heard_len: usize = 0;
    var answered = false;

    // What the guest handed over through the balloon. Taking them is what stops the device
    // refusing more, so a test that never drains measures its own back pressure.
    var handed_over: u64 = 0;

    // Frames each way, which is what says the network really carried something.
    var frames_out: u64 = 0;
    var frames_in: u64 = 0;
    while (exits < max_exits) : (exits += 1) {
        if (exits % 4096 == 0) {
            if (nowMs() > deadline) {
                std.debug.print("\n=== deadline after {d} exits ===\n", .{exits});
                break;
            }
            const have = sink.buffered();
            if (have.len > reported) {
                std.debug.print("{s}", .{have[reported..]});
                reported = have.len;
            }
        }
        const exit = hv.run(id) catch |err| {
            std.debug.print("\nrun failed after {d} exits: {t}, kvm said {?}\n", .{ exits, err, machine.fault });
            break;
        };

        // Everything from here to the end of the turn touches what the CPUs share, so it is all done
        // holding the lock. Entering the guest above is the one thing that must not be.
        hold();
        defer drop();

        switch (exit) {
            .mmio_write => |w| bus.write(w.gpa, w.size, w.value),
            .mmio_read => |r| try hv.completeMmioRead(id, bus.read(r.gpa, r.size)),
            // The guest was taken back so this loop could run. Serving the devices below
            // is the whole reason for it.
            .interrupted => {},
            else => {
                stopped = exit;
                break;
            },
        }

        // Answer the guest on the channel, before the devices are served, so the answer
        // goes out on this pass. A harness would do something with what it reads.
        if (channel_on and open == null) open = channel.accept();
        if (open) |handle| {
            const got = channel.read(handle, heard[heard_len..]);
            heard_len += got;
            if (got > 0 and !answered) {
                _ = channel.write(handle, "the host heard you\n");
                answered = true;
            }
        }

        // The driver rings a doorbell to say there is work, and the doorbell is an
        // mmio write that is over by the time this loop sees it.
        try core.Launch.poll(services[0..serviced], &memory, gic.controller());

        // Carry a command out to whatever answers it and the answer back. One turn moves what it
        // can, because neither side waits on the other.
        if (chip_link) |*link| chip_relay.carry(&chip, link);

        if (balloon_on) {
            var ranges: [64]device.virtio.Balloon.Range = undefined;
            while (true) {
                const got = balloon.take(&ranges);
                if (got == 0) break;
                for (ranges[0..got]) |range| handed_over += range.len;
            }
        }

        // Move frames between the guest and the helper. Neither side waits, so what has
        // arrived is taken and what will go is written, and the rest waits for the next turn.
        if (socket) |helper| {
            if (relay.room() > 0) {
                const got = helper.read(relay.reading()) catch 0;
                relay.arrived(got);
            }
            while (relay.next()) |frame| {
                const went = card.send(&memory, frame) catch break;
                if (!went) break;
                relay.taken();
                frames_in += 1;
            }

            var frame: [device.virtio.Net.max_frame]u8 = undefined;
            while (card.receive(&memory, &frame) catch null) |length| {
                if (!relay.send(frame[0..length])) break;
                frames_out += 1;
            }
            if (relay.writing().len > 0) {
                const put = helper.write(relay.writing()) catch 0;
                relay.wrote(put);
            }
        }

        // The same two directions as the helper above, with a translator in place of the socket.
        if (nat_on) {
            if (listener) |*each| each.turn();

            var asked: [device.virtio.Net.max_frame]u8 = undefined;
            var answer: [device.virtio.Net.max_frame]u8 = undefined;
            while (card.receive(&memory, &asked) catch null) |length| {
                frames_out += 1;
                if (nat.fromGuest(asked[0..length], &answer)) |reply| {
                    if (card.send(&memory, reply) catch false) frames_in += 1;
                }
            }
            if (nat.poll(&answer)) |reply| {
                if (card.send(&memory, reply) catch false) frames_in += 1;
            }
        }

        if (sink.buffered().len + 512 > output.len) break;
    }

    std.debug.print(
        "\n=== exits {d}, stopped {?}, unmapped {d}, dropped {d} ===\n{s}\n=== end ===\n",
        .{ exits, stopped, bus.unmapped, serial.dropped, sink.buffered() },
    );

    const log = sink.buffered();

    // The device tree Mirage built is the machine the guest believes it is on.
    try std.testing.expect(std.mem.indexOf(u8, log, "Machine model: mirage") != null);

    if (cpus > 1) {
        // The guest brought up every CPU it was told it had. Each one was asked for through the power
        // interface, started by the hypervisor, and ran on a thread of its own from then on. A guest
        // told about CPUs it cannot start says so and carries on with one, which is why the count
        // matters and not merely that the word appears.
        var wanted: [64]u8 = undefined;
        try std.testing.expect(std.mem.indexOf(u8, log, try std.fmt.bufPrint(
            &wanted,
            "SMP: Total of {d} processors activated",
            .{cpus},
        )) != null);

        // And each one by name, because a total is printed from what the guest meant to bring up.
        for (1..cpus) |which| {
            try std.testing.expect(std.mem.indexOf(u8, log, try std.fmt.bufPrint(
                &wanted,
                "CPU{d}: Booted secondary processor",
                .{which},
            )) != null);
        }
    }

    // The timer reached the guest through the interrupt controller. Without the
    // interrupt parent in the tree this reads "No interrupt available, giving up"
    // and every timestamp stays at zero.
    try std.testing.expect(std.mem.indexOf(u8, log, "Switched to clocksource arch_sys_counter") != null);

    // The virtio block driver found the device, agreed a feature set, set up a queue and
    // read the capacity out of the configuration space. A damaged root does not stop the
    // driver finding the disk it is on.
    try std.testing.expect(std.mem.indexOf(u8, log, "[vda]") != null);

    if (!tampered) {
        // The guest reached userspace and the first process ran.
        try std.testing.expect(std.mem.indexOf(u8, log, "mirage guest is alive") != null);

        // That process asked the kernel to power the machine off, which becomes a PSCI
        // call and leaves the guest as a system event. A guest that merely went quiet
        // would leave this null.
        try std.testing.expect(stopped != null);
        try std.testing.expectEqual(backend.Backend.Exit.shutdown, stopped.?);
    }

    if (erofs_root and !tampered) {
        // The root came off the disk, through the filesystem this repository writes.
        try std.testing.expect(std.mem.indexOf(u8, log, "VFS: Mounted root (erofs filesystem)") != null);
    }

    if (verity_root and !tampered) {
        // The root came through the verity target and not straight off the disk. A tree the
        // kernel could not verify leaves the guest with no root at all, so a guest that
        // reached userspace read every block of its root and checked each one.
        try std.testing.expect(std.mem.indexOf(u8, log, "mirage guest is alive") != null);
        try std.testing.expect(std.mem.indexOf(u8, log, verity_device) != null);
        try std.testing.expect(std.mem.indexOf(u8, log, "Mounted root (erofs filesystem)") != null);
    }

    if (share_on) {
        // The driver found the device by the name it was given, mounted it, and read a file out of
        // it. Nothing in this guest ever held those bytes: they came from a directory on the host,
        // one message at a time.
        try std.testing.expect(std.mem.indexOf(u8, log, "discovered new tag: mirage") != null);
        try std.testing.expect(std.mem.indexOf(u8, log, "share: mounted") != null);
        try std.testing.expect(std.mem.indexOf(u8, log, "share said: a store path from the host") != null);
        // And it could not open the same file to write, which is the host refusing rather than the
        // mount options saying so.
        try std.testing.expect(std.mem.indexOf(u8, log, "share: writing refused") != null);
        // The export saw the work: a name looked up and bytes read.
        // A directory read carries what a lookup would have said, so the guest needed no lookups at
        // all: the names it was handed are the work.
        try std.testing.expect(offered.?.named > 0);
        try std.testing.expect(offered.?.read_bytes >= shared_contents.len);
        try std.testing.expectEqual(@as(u64, 0), offered.?.turned_away);

        // What the export refused, printed rather than asserted on, because a guest that reports its
        // own library's name for a number leaves nothing to work from.
        var refusal_room: [fsmod.Export.Refusals.room]fsmod.Export.Refusals.Refusal = undefined;
        std.debug.print("export refused {d} times, nodes let go {d}, table {d}\n", .{
            offered.?.last_refusals.count,
            offered.?.let_go_nodes,
            offered.?.nodes.items.len,
        });
        for (offered.?.last_refusals.held(&refusal_room)) |each| {
            std.debug.print("  refused {t} with {d} at {d}\n", .{ each.op, each.code, each.at });
        }

        // And it wrote into the share that allows it, which this side can see because the bytes went
        // to a real file rather than into a copy.
        try std.testing.expect(std.mem.indexOf(u8, log, "share: wrote a file") != null);
        try std.testing.expect(std.mem.indexOf(u8, log, "share: made a directory") != null);
        // The three a toolchain needs beyond reading and writing bytes. A second name for a file is
        // how a package manager and a build cache avoid copying; a time it chose is how a build system
        // decides what to rebuild; and room reported as none is a program that refuses to start.
        try std.testing.expect(std.mem.indexOf(u8, log, "share: linked a file") != null);
        try std.testing.expect(std.mem.indexOf(u8, log, "share: set a time") != null);
        try std.testing.expect(std.mem.indexOf(u8, log, "share: there is room") != null);
        // Committing work the way a build system does: write into a temporary directory, move it into
        // place, and keep using what is in it. A guest whose numbers go stale across the move is told
        // the work it just committed is not there, which broke every zig build in a guest.
        try std.testing.expect(std.mem.indexOf(u8, log, "commit: moved into place") != null);
        try std.testing.expect(std.mem.indexOf(u8, log, "commit said: the result of the build") != null);
        try std.testing.expect(std.mem.indexOf(u8, log, "commit: what it held still answers") != null);
        var room: [200]u8 = undefined;
        const written = try std.Io.Dir.cwd().readFileAlloc(
            io,
            try std.fmt.bufPrint(&room, "{s}/work/made-inside", .{offering.?}),
            gpa,
            .limited(1024),
        );
        defer gpa.free(written);
        try std.testing.expectEqualSlices(u8, "written by the guest\n", written);
        const made = try std.Io.Dir.cwd().statFile(io, try std.fmt.bufPrint(&room, "{s}/work/made-dir", .{offering.?}), .{});
        try std.testing.expectEqual(std.Io.File.Kind.directory, made.kind);
        try std.testing.expect(offered.?.written_bytes > 0);
        // Nothing got into the one that does not allow it.
        try std.testing.expectError(error.FileNotFound, std.Io.Dir.cwd().statFile(
            io,
            try std.fmt.bufPrint(&room, "{s}/store/made-inside", .{offering.?}),
            .{},
        ));
    }

    if (balloon_on) {
        // The driver found the device, read the target, and handed pages over. A guest that
        // gives nothing has a driver that never looked.
        try std.testing.expect(handed_over > 0);
        try std.testing.expect(balloon.reported() > 0);

        // Every page it named was inside the memory it was given, and none was refused for
        // want of somewhere to record it.
        try std.testing.expectEqual(@as(u64, 0), balloon.refused);

        // The target is what was asked for, not what arrived. A guest is never obliged to
        // reach it and this one is powered off long before it could.
        try std.testing.expect(balloon.targetBytes() == ram_size / 2);
    }

    if (net_on) {
        // The driver set both queues up, which is what says it probed. A network driver says
        // nothing in the log when it is happy, so the log cannot be asked.
        try std.testing.expect(card.ready());

        // Frames went both ways, so the device, the framing and the helper all carried them.
        try std.testing.expect(frames_out > 0);
        try std.testing.expect(frames_in > 0);

        // And the guest reached something real. A name answered means a packet left this
        // machine, was translated, and the answer came back through all of it.
        try std.testing.expect(std.mem.indexOf(u8, log, "network: eth0 is up") != null);
        try std.testing.expect(std.mem.indexOf(u8, log, "network: the name was answered") != null);

        try std.testing.expectEqual(@as(u64, 0), card.dropped);
        try std.testing.expectEqual(@as(u64, 0), relay.refused);
    }

    if (nat_on) {
        // A connection, not only a datagram. The guest opened one to the gateway, which reaches this
        // machine itself, said something, and read the answer. That is what a coding session rests on:
        // nothing clones a repository over datagrams.
        try std.testing.expect(std.mem.indexOf(u8, log, "stream: connected") != null);
        try std.testing.expect(std.mem.indexOf(u8, log, "stream said: the host heard your stream") != null);
        try std.testing.expect(nat.streams_opened > 0);

        // And the far end really received what the guest sent, rather than the guest being told so by
        // something that made it up.
        const at_far_end = if (listener) |each| each.heard else 0;
        try std.testing.expect(at_far_end > 0);

        // Nothing was reset and nothing went unread along the way.
        try std.testing.expectEqual(@as(u64, 0), nat.streams_refused);
        try std.testing.expectEqual(@as(u64, 0), nat.unknown);
        // The guest reached a name server through a network this VMM is, with nothing else running
        // beside this test. Frames went both ways and the answer came back, which is the whole path:
        // the card, the translation, a socket of this process's own, and back again.
        try std.testing.expect(std.mem.indexOf(u8, log, "network: eth0 is up") != null);
        try std.testing.expect(std.mem.indexOf(u8, log, "network: the name was answered") != null);

        try std.testing.expect(frames_out > 0);
        try std.testing.expect(frames_in > 0);
        try std.testing.expect(nat.sent > 0);
        try std.testing.expect(nat.received > 0);

        // Nothing was refused for want of room, and nothing the guest sent went unread. A guest whose
        // traffic disappears in silence looks the same as one with no network at all.
        try std.testing.expectEqual(@as(u64, 0), nat.no_room);
        try std.testing.expectEqual(@as(u64, 0), card.dropped);
    }

    if (chip_on) {
        // The driver attached, which means it read the identifiers and believed them.
        try std.testing.expect(std.mem.indexOf(u8, log, "2.0 TPM (device-id 0x1") != null);

        // And the guest folded a digest into a register of its own and read back what the extend
        // rule says it must hold. That proves the chip kept state between two commands that both went
        // through this transport, and did real work on it: a chip that only echoed would answer both
        // reads alike, and one that hashed something else would not match the rule.
        try std.testing.expect(std.mem.indexOf(u8, log, "chip: extending a register gives what the rule says") != null);

        // Nothing was refused and the far end stayed. Either one would mean the guest got an answer
        // that came from somewhere other than the program answering its commands.
        try std.testing.expect(!chip_relay.gone);
        try std.testing.expectEqual(@as(u64, 0), chip.refused);
        try std.testing.expect(chip_relay.answered > 0);

        // The guest read the launch register and said what it holds. This side folded the launch in
        // and knows what it has to hold, so the two are compared. A guest that could make this agree
        // without reading the chip would be a guest that did not need the chip.
        const expected = expected_chain orelse return error.TestUnexpectedResult;
        const label = "chain ";
        const at = std.mem.indexOf(u8, heard[0..heard_len], label) orelse
            std.mem.indexOf(u8, log, label) orelse return error.TestUnexpectedResult;
        const said = if (std.mem.indexOf(u8, heard[0..heard_len], label) != null)
            heard[at + label.len ..]
        else
            log[at + label.len ..];
        try std.testing.expect(said.len >= attest.Chain.length * 2);

        var told: [attest.Chain.length]u8 = undefined;
        _ = try std.fmt.hexToBytes(&told, said[0 .. attest.Chain.length * 2]);
        try std.testing.expectEqualSlices(u8, &expected, &told);

        // And the guest built its own account of what started it. The kernel handed it the list of
        // measurements this side left in memory, it named each one, and the list folded to the
        // register the chip holds. A changed entry folds to something else, so a list that folds is
        // a list nothing has touched, and the guest can say what it is running rather than be told.
        try std.testing.expect(std.mem.indexOf(u8, log, "account: the list folds to the register") != null);
        try std.testing.expect(std.mem.indexOf(u8, log, "measured kernel") != null);
        try std.testing.expect(std.mem.indexOf(u8, log, "measured device_tree") != null);
    }

    if (tampered) {
        // The superblock was changed after the tree was built over it, so the kernel names
        // the block that failed, refuses to mount, and never reaches userspace. A check
        // that is never seen to refuse is a check nobody has tested.
        try std.testing.expect(std.mem.indexOf(u8, log, "data block 0 is corrupted") != null);
        try std.testing.expect(std.mem.indexOf(u8, log, "Unable to mount root fs") != null);
        try std.testing.expect(std.mem.indexOf(u8, log, "mirage guest is alive") == null);
        try std.testing.expect(std.mem.indexOf(u8, log, "Mounted root (erofs filesystem)") == null);
    }

    try std.testing.expectEqual(@as(u64, 0), bus.unmapped);
    try std.testing.expectEqual(@as(u64, 0), serial.dropped);
}
