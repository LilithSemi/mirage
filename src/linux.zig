//! Running a guest on Linux, where the hypervisor is the kernel's own.

const std = @import("std");
const backend = @import("mirage-backend");
const core = @import("mirage-core");
const arm64 = @import("mirage-arm64");
const device = @import("mirage-device");
const image = @import("mirage-image");
const netmod = @import("mirage-net");
const sessionmod = @import("mirage-session");
const fsmod = @import("mirage-fs");
const Options = @import("Options.zig");
const GuestMemory = @import("mirage-memory").GuestMemory;
const attest = @import("mirage-attest");
const Manifest = attest.Manifest;
const host = @import("host.zig");
const answerFs = host.answerFs;
const Host = host.Host;
const Attached = host.Attached;
const Shared = host.Shared;
const ram_base = host.ram_base;
const uart_base = host.uart_base;
const guest_cid = host.guest_cid;
const guest_mac = host.guest_mac;
const driveCpu = host.driveCpu;
const hostResolver = host.hostResolver;
const usage = Options.usage;

/// Where the launch is folded in. A register the guest can add to says nothing about what started
/// it, so this one is written before the guest runs and never from inside.
const launch_register = 0;

/// Where firmware is placed. A machine like this one has its read only memory at the bottom of the
/// address space, and firmware built for one starts there.
const firmware_base = 0x0;

/// A kernel and an initial filesystem are large but not unbounded. Refusing early
/// is better than an allocator failing somewhere deeper.
const file_limit: std.Io.Limit = .limited(1 << 30);

/// A snapshot is guest memory and a little more, so it is larger than a kernel but not unbounded.
const snapshot_limit: std.Io.Limit = .limited(16 << 30);

pub fn probe(out: *std.Io.Writer) !void {
    if (@import("builtin").os.tag != .linux) {
        try out.writeAll("probe only knows how to ask a Linux kernel\n");
        return;
    }

    const report = backend.kvm.probe.host() catch |err| {
        try out.print("cannot reach a hypervisor: {t}\n", .{err});
        return;
    };

    try out.print(
        \\kvm api version      {d}
        \\user memory 2        {}
        \\memory attributes    {}
        \\guest memfd          {}
        \\guest memfd flags    0b{b}
        \\private refuses map  {}
        \\shared allows map    {}
        \\private backs memory {}
        \\
        \\tier                 {d}
        \\
    , .{
        report.api_version,
        report.user_memory2,
        report.memory_attributes,
        report.guest_memfd,
        report.guest_memfd_flags,
        report.private_refuses_mapping,
        report.shared_allows_mapping,
        report.private_backs_memory,
        report.tier(),
    });

    // Say what the number means. A tier is a claim about what this machine can
    // prove, and a number with no claim attached invites the wrong one.
    try out.writeAll(switch (report.tier()) {
        0 => "\nguest memory is readable by this process, so a compromised VMM reads the guest\n",
        else => "\nguest memory is not mapped by this process\n",
    });
}

/// The end of the channel that belongs to this process. It prints what the guest sends
/// and tells it the bytes arrived, which is enough to see that the channel works.
/// What this machine has free right now, from what the kernel reports. Null when the answer
/// cannot be had, and the caller then uses what the guest started with rather than guessing.
///
/// This is not a promise. It is what was free when the guest started, and the host can still
/// refuse a page later.
fn machineMemory(io: std.Io) ?u64 {
    var buffer: [4096]u8 = undefined;
    const text = std.Io.Dir.cwd().readFile(io, "/proc/meminfo", &buffer) catch return null;

    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const wanted = "MemAvailable:";
        if (!std.mem.startsWith(u8, line, wanted)) continue;

        // The value is in kilobytes with spaces before it and a unit after.
        var fields = std.mem.tokenizeScalar(u8, line[wanted.len..], ' ');
        const number = fields.next() orelse return null;
        const kilobytes = std.fmt.parseInt(u64, number, 10) catch return null;
        return kilobytes * 1024;
    }
    return null;
}

/// A vCPU that is waiting for an interrupt blocks inside `KVM_RUN`, and nothing in this
/// process runs while it does, so a device holding bytes for the guest cannot deliver them
/// or raise the interrupt that would wake it. A signal with no `SA_RESTART` takes the CPU
/// back: the blocked call returns and the loop gets its turn.
///
/// This is polling, and a device thread is the real answer. Polling is what a VMM with one
/// thread can do, and it is enough for a channel that carries a line at a time.
fn onAlarm(_: std.os.linux.SIG) callconv(.c) void {}

/// Install the handler that lets a signal take a CPU back out of the hypervisor, and start the timer
/// that does it repeatedly.
///
/// The handler goes in whether or not the timer is armed, because stopping the other CPUs at the end of
/// a run uses the same signal: a CPU sitting inside the hypervisor comes out only when something
/// interrupts it, and with no handler installed that signal would end the process instead.
fn armTicks(milliseconds: isize) void {
    const act: std.os.linux.Sigaction = .{
        .handler = .{ .handler = onAlarm },
        .mask = std.mem.zeroes(std.os.linux.sigset_t),
        .flags = 0,
    };
    _ = std.os.linux.sigaction(.ALRM, &act, null);

    if (milliseconds <= 0) return;

    // This syscall takes `struct itimerval`, whose second field is **microseconds**. The
    // standard library hands it an `itimerspec` and calls that field `nsec`, so the value
    // here is in microseconds despite the name. A nanosecond count lands far out of range
    // and the kernel refuses the call, leaving no timer armed and nothing to say so.
    const every: std.os.linux.timespec = .{
        .sec = @divTrunc(milliseconds, 1000),
        .nsec = @rem(milliseconds, 1000) * std.time.us_per_ms,
    };
    const spec: std.os.linux.itimerspec = .{ .it_interval = every, .it_value = every };
    _ = std.os.linux.setitimer(@intFromEnum(std.os.linux.ITIMER.REAL), &spec, null);
}

/// Bring every other CPU out of the hypervisor and wait for it to stop.
///
/// A CPU waiting inside the hypervisor holds that CPU's lock, so nothing can read its registers until
/// it comes out: a snapshot taken without this waits forever on the first CPU it tries to save. The
/// signal is what brings it out, the flag is what stops it going back in, and joining is what makes
/// sure it is out before anything reads it.
fn stopOthers(threads: []const std.Thread, end: *Host) void {
    end.stopping.store(true, .release);

    const pid: i32 = @intCast(std.os.linux.getpid());
    for (threads) |each| {
        _ = std.os.linux.tgkill(pid, @intCast(each.getHandle()), std.os.linux.SIG.ALRM);
    }
    for (threads) |each| each.join();
}

/// Write everything a stopped guest holds to a file.
fn saveTo(
    gpa: std.mem.Allocator,
    io: std.Io,
    out: *std.Io.Writer,
    path: []const u8,
    machine: *backend.kvm.Machine,
    gic: *backend.kvm.Gic,
    memory: *GuestMemory,
    ram_size: u64,
    ids_of: []const backend.Backend.VcpuId,
    block: ?*device.virtio.Block,
) !void {
    // Every CPU, not only the first. Each one's registers take the same room, because they all came
    // from one hypervisor on one host, so the sets go one after another and the count says where each
    // begins. A machine saved with only its first CPU comes back missing most of itself.
    const first = &machine.vcpus[ids_of[0]];
    const count = try first.registerCount();
    const ids = try gpa.alloc(u64, @intCast(count + 1));
    defer gpa.free(ids);

    const each_cpu = try backend.kvm.Vcpu.State.size(first, ids);
    const registers = try gpa.alloc(u8, each_cpu * ids_of.len);
    defer gpa.free(registers);

    const running = try gpa.alloc(u8, ids_of.len);
    defer gpa.free(running);

    var written: usize = 0;
    for (ids_of, 0..) |which, index| {
        const cpu = &machine.vcpus[which];
        const took = try cpu.save(try cpu.registerList(ids), registers[index * each_cpu ..]);
        // Every CPU has to take the same room or nothing can find the second one's registers.
        if (took != each_cpu) return error.RegisterSizeDiffered;
        written += took;

        // And whether it was running, which is in none of its registers. A CPU the guest had not
        // started yet would otherwise come back runnable and begin from wherever its registers point.
        running[index] = @intFromBool(try cpu.runState() == backend.kvm.Vcpu.runnable);
    }

    const controller = try gpa.alloc(u8, backend.kvm.Gic.State.size(@intCast(ids_of.len)));
    defer gpa.free(controller);
    const controller_bytes = try gic.save(@intCast(ids_of.len), controller);

    var queues: [core.Snapshot.max_queues]core.Snapshot.QueueState = undefined;
    var queue_count: usize = 0;
    if (block) |each| {
        queues[queue_count] = .of(each.queues[0]);
        queue_count += 1;
    }

    const parts: core.Snapshot.Parts = .{
        .ram_base = ram_base,
        .memory = try memory.slice(ram_base, ram_size),
        .registers = registers[0..written],
        .cpus = @intCast(ids_of.len),
        .running = running,
        .controller = controller[0..controller_bytes],
        .queues = queues[0..queue_count],
    };

    const bytes = try gpa.alloc(u8, core.Snapshot.size(parts));
    defer gpa.free(bytes);
    const used = try core.Snapshot.write(parts, bytes);

    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = bytes[0..used] });
    try out.print("wrote {d}MB of snapshot to {s}\n", .{ used / (1024 * 1024), path });
}

pub fn run(gpa: std.mem.Allocator, io: std.Io, out: *std.Io.Writer, args: []const [:0]const u8) !void {
    if (@import("builtin").os.tag != .linux) {
        try out.writeAll("run only knows how to use KVM so far\n");
        return;
    }

    const options = Options.parse(args) catch |err| {
        try out.print("bad arguments: {t}\n\n", .{err});
        try out.writeAll(usage);
        return;
    };
    if (try options.complain(out, arm64.fdt.cpusThatFit(ram_base))) return;

    // A harness starts a guest for every session, so where the time goes before the guest
    // runs matters as much as how fast the guest boots.
    const began = std.Io.Clock.awake.now(io).nanoseconds;
    var read_at: i96 = began;
    var ready_at: i96 = began;

    const cwd: std.Io.Dir = .cwd();

    // A guest being resumed brings its own memory, so there is no kernel to read and nothing to
    // place. Everything below that would have been placed is skipped as well.
    const kernel: []u8 = if (options.firmware) |path|
        try cwd.readFileAlloc(io, path, gpa, file_limit)
    else if (options.restore == null)
        try cwd.readFileAlloc(io, options.kernel, gpa, file_limit)
    else
        &.{};
    defer if (kernel.len > 0) gpa.free(kernel);
    read_at = std.Io.Clock.awake.now(io).nanoseconds;

    const initrd = if (options.restore != null) null else if (options.initrd) |path|
        try cwd.readFileAlloc(io, path, gpa, file_limit)
    else
        null;
    defer if (initrd) |bytes| gpa.free(bytes);

    const disk = if (options.disk) |path|
        try cwd.readFileAlloc(io, path, gpa, file_limit)
    else
        null;
    defer if (disk) |bytes| gpa.free(bytes);

    var machine = backend.kvm.Machine.create(gpa, options.cpus) catch |err| switch (err) {
        // How many CPUs a guest may have is the kernel's answer, so a refusal is reported as the
        // machine's and not as a limit of this program.
        error.TooManyVcpus => {
            try out.print("this machine will not give a guest {d} cpus\n", .{options.cpus});
            return;
        },
        else => return err,
    };
    defer machine.deinit();

    const starts_with = options.memory * 1024 * 1024;

    // A guest that may grow is told its whole eventual size, and the balloon holds
    // everything above what it starts with. A limit below what it starts with is the caller
    // contradicting itself, so the larger of the two wins and the balloon holds nothing.
    const ram_size = if (options.limit) |limit| @max(starts_with, switch (limit) {
        .megabytes => |count| count * 1024 * 1024,
        .machine => machineMemory(io) orelse starts_with,
    }) else starts_with;

    if (options.limit != null) {
        try out.print("guest starts with {d}MB and may grow to {d}MB\n", .{
            starts_with / (1024 * 1024),
            ram_size / (1024 * 1024),
        });
    }

    const region = try machine.vm.addMemory(ram_base, ram_size, .shared);

    // Firmware runs from the bottom of the address space, where a machine like this one has its
    // read only memory, so it needs a window of its own below the guest's memory.
    const firmware_room = @max(std.mem.alignForward(u64, kernel.len, 64 * 1024), options.firmware_room);
    const firmware_region = if (options.firmware != null)
        try machine.vm.addMemory(options.firmware_at, firmware_room, .shared)
    else
        null;

    var regions: [2]GuestMemory.Region = undefined;
    regions[0] = region;
    var region_count: usize = 1;
    if (firmware_region) |each| {
        regions[region_count] = each;
        region_count += 1;
    }
    var memory: GuestMemory = .{ .regions = regions[0..region_count] };

    const hv = machine.backend();

    // Every CPU has to exist before the controller is initialised, because the controller is sized to
    // hold one piece of state per CPU and that size is fixed when it is made.
    const ids = try gpa.alloc(backend.Backend.VcpuId, options.cpus);
    defer gpa.free(ids);
    for (ids) |*each| each.* = try hv.addVcpu();
    const id = ids[0];

    var gic = try backend.kvm.Gic.create(&machine.vm, options.cpus, arm64.fdt.gicd_base, arm64.fdt.gicr_base);
    defer gic.deinit();

    var manifest: Manifest = .{};
    defer manifest.deinit(gpa);

    // Entropy for the guest, taken from this machine rather than made up. Without
    // it a kernel waits, sometimes for a minute, before anything needing randomness
    // can run. A guest given a predictable seed has predictable randomness, so this
    // asks for the secure source and refuses rather than falling back.
    var seed: [32]u8 = undefined;
    try io.randomSecure(&seed);

    // A guest being resumed was launched once already. Nothing is measured here, because nothing
    // is being placed: the memory and the registers say where it had got to.
    const resuming: ?[]u8 = if (options.restore) |path|
        try cwd.readFileAlloc(io, path, gpa, snapshot_limit)
    else
        null;
    defer if (resuming) |bytes| gpa.free(bytes);

    var restored_queues: [core.Snapshot.max_queues]core.Snapshot.QueueState = undefined;
    const came_back: ?core.Snapshot.Parts = if (resuming) |bytes|
        core.Snapshot.parse(bytes, &restored_queues) catch |err| {
            try out.print("that is not a snapshot this can read: {t}\n", .{err});
            return;
        }
    else
        null;

    if (came_back) |parts| {
        if (parts.memory.len > ram_size) {
            try out.print("the snapshot holds {d}MB of memory and this guest has {d}MB\n", .{
                parts.memory.len / (1024 * 1024),
                ram_size / (1024 * 1024),
            });
            return;
        }
        @memcpy((try memory.slice(ram_base, parts.memory.len))[0..parts.memory.len], parts.memory);

        // A machine has to come back with the CPUs it went away with. One with fewer would leave a
        // CPU's registers unread, and one with more would start a CPU from nothing.
        if (parts.cpus != options.cpus) {
            try out.print("the snapshot holds {d} cpus and this guest was given {d}\n", .{
                parts.cpus,
                options.cpus,
            });
            return;
        }

        var put: usize = 0;
        for (ids, 0..) |which, index| {
            const cpu = &machine.vcpus[which];
            const restored = try cpu.load(parts.registersFor(@intCast(index)));
            put += restored.written;

            // Whether it was running, which is in none of its registers. The first CPU is always
            // running; a later one the guest had never started has to come back stopped, or it would
            // begin from wherever its registers point.
            try cpu.setRunState(if (parts.wasRunning(@intCast(index)))
                backend.kvm.Vcpu.runnable
            else
                backend.kvm.Vcpu.stopped);
        }

        const attributes = try gic.load(parts.controller);
        try out.print("resumed {d} registers across {d} cpus and {d} controller attributes from {s}\n", .{
            put,
            parts.cpus,
            attributes,
            options.restore.?,
        });
    }

    const layout = if (came_back != null) core.Launch.Layout{
        .entry = 0,
        .device_tree = 0,
    } else try core.Launch.prepare(gpa, &memory, &manifest, .{
        .kind = if (options.firmware != null)
            .{ .firmware = .{ .at = options.firmware_at, .len = firmware_room } }
        else
            .linux,
        .kernel = kernel,
        .initrd = initrd,
        .cmdline = options.cmdline,
        .ram_base = ram_base,
        .ram_size = ram_size,
        .cpus = options.cpus,
        .uart_base = uart_base,
        .rng_seed = &seed,
        .rootfs_verity = options.root_hash,
        .block_device = disk != null,
        .vsock = options.vsock != null,
        .balloon = options.limit != null,
        .net = options.net != null or options.nat,
        .tpm = options.tpm != null,
        .share = options.share_count > 0,
    });

    ready_at = std.Io.Clock.awake.now(io).nanoseconds;

    if (came_back == null) {
        const root = manifest.root();
        try out.print("launch measured, root {x}\n", .{root[0..8]});

        // The root says two launches differ. It does not say what they are, and a verifier needs
        // that, so the parts are available on request in the order they went in. The order is part
        // of the measurement: the same parts hashed in another order give another root.
        if (options.show_manifest) {
            for (manifest.entries.items, 0..) |entry, index| {
                try out.print("  {d}. {t} {x}\n", .{ index + 1, entry.tag, entry.digest });
            }
            try out.print("  root {x}\n", .{root});
        }
    }
    try out.flush();

    var serial: device.Pl011 = .{ .sink = out };

    var block: device.virtio.Block = undefined;
    if (disk) |bytes| block.init(bytes);

    // A session listens on a second port as well, the one a guest opens a stream to when it wants to
    // be connected somewhere. A guest with no session never opens it and is not told it is there.
    var ports: [2]u32 = undefined;
    var channel: device.virtio.Vsock = undefined;
    if (options.vsock) |listen| {
        ports[0] = listen;
        ports[1] = sessionmod.wire.reaching_port;
        channel.init(guest_cid, ports[0..if (options.session != null) 2 else 1]);
    }

    // The socket this guest is held up by. It is bound before the guest runs, so whoever starts
    // one can connect as soon as the process exists rather than guessing when it is ready.
    const held: ?*sessionmod.Server = if (options.session) |path| room: {
        const one = try gpa.create(sessionmod.Server);
        one.* = sessionmod.Server.listen(path) catch {
            try out.print("cannot hold a session at {s}\n", .{path});
            return;
        };
        break :room one;
    } else null;
    defer if (held) |one| gpa.destroy(one);

    // The balloon holds everything the guest was told about but may not use yet, so it
    // starts inflated by the difference. The guest only reads the target when its driver
    // probes, so the kernel sees the whole range first and gives it up afterwards. That
    // makes the starting size a target and not a wall.
    var balloon: device.virtio.Balloon = undefined;
    if (options.limit != null) {
        balloon.init(ram_base, ram_size);
        balloon.setTarget(@intCast((ram_size - starts_with) / device.virtio.Balloon.page_size));
    }

    // The network. The helper on the other end does the addressing and the translating, because
    // an unprivileged process cannot hand a frame to a kernel interface.
    var card: device.virtio.Net = undefined;
    var socket: ?netmod.Socket = null;
    var relay: netmod.Relay = .{};
    if (options.net) |helper| {
        card.init(guest_mac);
        socket = switch (helper) {
            .path => |path| netmod.Socket.connect(io, path) catch |err| {
                try out.print("cannot reach the network helper at {s}: {t}\n", .{ path, err });
                return;
            },
            .fd => |number| netmod.Socket.adopt(number) catch |err| {
                try out.print("cannot use descriptor {d} for the network: {t}\n", .{ number, err });
                return;
            },
        };
    }

    // A network of this VMM's own, when the caller asked for one instead of a helper. The guest is told
    // it holds one address and that a gateway sits beside it, and this translates between the two.
    var nat: netmod.Nat = .{
        .guest_ip = .{ 10, 0, 2, 15 },
        .guest_mac = guest_mac,
        .gateway_ip = .{ 10, 0, 2, 2 },
        .gateway_mac = .{ 0x52, 0x54, 0x00, 0x12, 0x34, 0x57 },
        .resolver = hostResolver(io, gpa),
    };
    defer nat.deinit();
    if (options.nat) card.init(guest_mac);
    defer if (socket) |*open| open.close(io);

    // The security chip. Whatever answers its commands is another program, started by whoever
    // started the guest, exactly as the network helper is.
    // A directory on this machine the guest may mount. What answers the guest's filesystem messages
    // is an export that refuses everything that would change anything, and the device below only
    // carries the messages to it.
    // One filesystem holding every directory offered, each under its own name. One device rather than
    // one per directory, because the transport cannot add a device to a running machine and the set a
    // guest is given has to be able to change while it runs.
    const sharing = options.share_count > 0;
    var offered: ?fsmod.Export = if (sharing)
        fsmod.Export.init(gpa, io) catch {
            try out.writeAll("no room to offer a directory\n");
            return;
        }
    else
        null;
    defer if (offered) |*one| one.deinit();
    if (offered) |*one| {
        for (options.shares[0..options.share_count]) |each| {
            one.offer(each.name, each.at, each.writable) catch {
                try out.print("cannot offer {s}\n", .{each.name});
                return;
            };
        }
    }

    // The room the filesystem device carries one message and one answer in. Owned here rather than
    // by the device, because nothing in the device model allocates.
    const share_asked = if (sharing) try gpa.alloc(u8, device.virtio.Fs.buffer_size) else @as([]u8, &.{});
    defer if (sharing) gpa.free(share_asked);
    const share_answered = if (sharing) try gpa.alloc(u8, device.virtio.Fs.buffer_size) else @as([]u8, &.{});
    defer if (sharing) gpa.free(share_answered);

    var shared_fs: device.virtio.Fs = undefined;
    if (sharing) {
        shared_fs.init(fsmod.Export.tag, .{ .ctx = &offered.?, .answer = answerFs }, share_asked, share_answered);
    }

    var chip: device.Tpm = .{};
    var chip_socket: ?netmod.Socket = null;
    if (options.tpm) |path| {
        chip_socket = netmod.Socket.connect(io, path) catch |err| {
            try out.print("cannot reach the security chip at {s}: {t}\n", .{ path, err });
            return;
        };
    }
    defer if (chip_socket) |*open| open.close(io);

    var attached: Attached = .{};
    attached.add(serial.device(uart_base));
    if (sharing) {
        attached.addServed(shared_fs.device(arm64.fdt.fs_base), shared_fs.service(arm64.fdt.fs_intid));
    }
    if (options.tpm != null) attached.add(chip.device(arm64.fdt.tpm_base));
    if (disk != null) {
        attached.addServed(block.device(arm64.fdt.virtio_base), block.service(arm64.fdt.virtio_intid));
    }
    if (options.vsock != null) {
        attached.addServed(channel.device(arm64.fdt.vsock_base), channel.service(arm64.fdt.vsock_intid));
    }
    if (options.limit != null) {
        attached.addServed(balloon.device(arm64.fdt.balloon_base), balloon.service(arm64.fdt.balloon_intid));
    }
    if (options.net != null or options.nat) {
        attached.addServed(card.device(arm64.fdt.net_base), card.service(arm64.fdt.net_intid));
    }
    var bus = attached.bus();

    if (came_back) |parts| {
        // Where each device had got to in its rings, which nothing in guest memory records. The
        // order is the order they were attached, so a resume with different devices puts one
        // device's place into another's rings.
        var which: usize = 0;
        if (disk != null and which < parts.queues.len) {
            parts.queues[which].into(&block.queues[0]);
            which += 1;
        }
    } else {
        // Only a guest that is starting needs putting at its entry point. A resumed one is
        // already wherever it stopped.
        try core.Launch.enter(hv, id, layout);
    }

    // Fold the launch into the chip before the guest runs, the way firmware does for the stages it
    // loads. After this the register holds the whole launch, so the guest can read it and say what it
    // believes started it, and this side can check that against arithmetic of its own.
    var expected_chain: ?[attest.Chain.length]u8 = null;
    if (came_back == null) {
        if (chip_socket) |*link| {
            var session: attest.Chain.Session(netmod.Socket) = .{ .transport = link };
            expected_chain = session.measure(&manifest, launch_register) catch |err| {
                try out.print("the chip would not take the launch: {t}, code {x}\n", .{ err, session.refusal });
                try out.flush();
                return;
            };
            try out.print("launch folded into register {d}, which now holds {x}\n", .{
                launch_register,
                expected_chain.?[0..8],
            });
            // Where the guest will find the list of measurements. A register says two launches differ
            // and never what either was, so the guest is given the list as well and can fold it.
            if (layout.log) |where| {
                try out.print("measurements listed at {x} over {d} bytes\n", .{
                    where.start,
                    where.end - where.start,
                });
            }

            // The chip's own signed word for what the register holds. Everything above reaches a third
            // party through this process, which could say anything, so a quote is what makes the
            // answer worth something to somebody who trusts the chip and not this.
            //
            // The number the quote covers has to be one the asker chose, and nothing here is being
            // asked by anybody, so the seed this launch was given stands in: it is different every
            // run. A caller proving this to somebody else asks them for a number and uses theirs.
            var room: [1024]u8 = undefined;
            const taken = attest.Quote.take(
                &session,
                &room,
                launch_register,
                &seed,
                expected_chain.?,
            ) catch |err| {
                try out.print("the chip would not quote the register: {t}, code {x}\n", .{ err, session.refusal });
                try out.flush();
                return;
            };
            try out.print("the chip signed it with key {x}, over {d} bytes\n", .{
                taken.key.point[1..9],
                taken.answer.len,
            });
        }
    }

    // Without this the loop below only runs when the guest exits of its own accord, and a
    // guest waiting on the channel exits for nothing.
    if (options.tick_ms > 0) armTicks(@intCast(options.tick_ms));

    // A clock is read every exit, which is far more often than a second, so the deadline
    // is worked out once and compared rather than recomputed.
    // What a session may change about the guest's directories while it runs. A caller whose set of
    // them differs from one piece of work to the next offers and withdraws rather than restarting.
    if (held) |one| {
        if (offered) |*holding| {
            one.sharing = .{
                .ctx = holding,
                .offer = host.offerShare,
                .withdraw = host.withdrawShare,
            };
        }
    }

    var end: Host = .{
        .io = io,
        .deadline = if (options.seconds) |limit|
            std.Io.Clock.awake.now(io).nanoseconds + @as(i96, limit) * std.time.ns_per_s
        else
            null,
        .vsock = if (options.vsock != null) &channel else null,
        .session = held,
        .balloon = if (options.limit != null) &balloon else null,
        .memory = &memory,
        .card = if (options.net != null or options.nat) &card else null,
        .nat = if (options.nat) &nat else null,
        .socket = socket,
        .relay = &relay,
        .chip = if (options.tpm != null) &chip else null,
        .chip_socket = chip_socket,
        .expected_chain = expected_chain,
        .out = out,
    };

    // What every CPU is given. A machine with one CPU gets no lock, because there is nothing for it to
    // race with and a lock nobody contends for still costs something on every exit.
    var shared: Shared = .{};
    const driving: core.Launch.Run = .{
        .bus = &bus,
        .memory = &memory,
        .controller = gic.controller(),
        .services = attached.served(),
        .exits = options.exits,
        .host = end.launchHost(),
        .guard = if (options.cpus > 1) shared.guard() else null,
    };

    // The other CPUs run on threads of their own. Each waits inside the hypervisor until the guest asks
    // for it, and the handles are kept rather than detached: a CPU inside the hypervisor holds its own
    // lock, so reading its registers for a snapshot means bringing it out first, and that needs the
    // thread. The first CPU is the one whose answer is the machine's, and when it stops the run is over.
    const threads = try gpa.alloc(std.Thread, options.cpus - 1);
    defer gpa.free(threads);
    var started: usize = 0;
    for (ids[1..], 0..) |each, index| {
        threads[index] = std.Thread.spawn(.{}, driveCpu, .{ hv, each, driving }) catch |err| {
            try out.print("cannot start cpu {d}: {t}\n", .{ each, err });
            return;
        };
        started += 1;
    }

    const reason = core.Launch.run(hv, id, driving) catch |err| stopped: {
        try out.flush();
        // Running out of exits is how a caller stops a guest on purpose, which is what taking a
        // snapshot needs. It is not a fault, so the run carries on to the writing below.
        if (err == error.ExitsExhausted) {
            try out.print("\nthe guest used all {d} exits it was given\n", .{options.exits});
            break :stopped core.Launch.Reason.stopped;
        }
        try out.print("\nthe guest stopped badly: {t}, kvm said {?}\n", .{ err, machine.fault });
        // Every other CPU stops here too. A fault is not a reason to return while another CPU is
        // still inside the hypervisor holding pointers into this frame.
        stopOthers(threads[0..started], &end);
        // A caller waiting on this session hears the fault. Without this it learns only that the
        // socket closed, which reads the same as a guest that finished its work.
        if (held) |one| {
            one.lost(.faulted);
            one.close(&channel);
        }
        return;
    };

    // Every other CPU comes out of the hypervisor and stops before anything reads its state. Nothing
    // below this point is safe while another CPU is still running the guest.
    stopOthers(threads[0..started], &end);

    // Whoever holds the session learns the guest has gone from a message, so a call already in
    // flight fails rather than waiting for a guest that is not there.
    if (held) |one| {
        one.lost(if (one.asked_stop) .was_asked else host.endingOf(reason));
        one.close(&channel);
    }

    const stopped_at = std.Io.Clock.awake.now(io).nanoseconds;
    try out.flush();

    // Write down everything the guest holds, so it can be started again from here. A guest that
    // has powered off has nothing worth keeping, but saying so is the caller's business and not
    // this one's: it asked for a snapshot and it gets one.
    if (options.save) |path| {
        saveTo(gpa, io, out, path, &machine, &gic, &memory, ram_size, ids, if (disk != null) &block else null) catch |err| {
            try out.print("could not write the snapshot: {t}\n", .{err});
        };
    }
    // The build mode is here because it is worth more than any of the numbers beside it. Measuring
    // a `Debug` binary says the launch costs fifteen times what it really does, because that is how
    // much slower the digest is without optimisation.
    try out.print("\ntook {d}ms to read {d}MB of kernel, {d}ms to measure and place it, {d}ms running, built {t}\n", .{
        @divTrunc(read_at - began, std.time.ns_per_ms),
        kernel.len / (1024 * 1024),
        @divTrunc(ready_at - read_at, std.time.ns_per_ms),
        @divTrunc(stopped_at - ready_at, std.time.ns_per_ms),
        @import("builtin").mode,
    });

    if (end.timed_out) {
        // `stopped` says the loop ended, not why. A guest that ran out of time and one
        // that was asked to stop look the same from inside the loop.
        try out.print("\nthe guest ran out of time after {?d} seconds\n", .{options.seconds});
    } else {
        try out.print("\nthe guest stopped: {t}\n", .{reason});
    }

    // A device that asked for an interrupt the kernel refused is why a guest waits
    // forever, so say so rather than leaving it to be guessed at.
    if (offered) |one| {
        try out.print("shares: {d} offered, {d} names handed over, {d}MB read, {d} refused\n", .{
            options.share_count,
            one.named + one.looked_up,
            one.read_bytes / (1024 * 1024),
            one.refused,
        });
        if (one.turned_away != 0) {
            try out.print("{d} names would have left a shared directory\n", .{one.turned_away});
        }
        // What the guest finished with. A guest held up for a session makes and forgets files for hours,
        // and a number here that stays at zero while it works means this side is holding all of them.
        if (one.let_go_nodes != 0) {
            try out.print("share: {d} files the guest finished with\n", .{one.let_go_nodes});
        }
    }
    if (gic.dropped != 0) try out.print("{d} interrupts were dropped\n", .{gic.dropped});
    if (bus.unmapped != 0) try out.print("{d} guest accesses matched no device\n", .{bus.unmapped});
    if (options.net != null or options.nat) {
        // Whether the driver set the queues up says whether it probed at all, which a log line
        // does not: a network driver says nothing when it finds a device it is happy with.
        try out.print("network: driver ready {}, {d} frames from the guest, {d} to it\n", .{
            card.ready(),
            end.frames_out,
            end.frames_in,
        });
        if (end.helper_gone) try out.writeAll("the network helper went away\n");
        if (card.dropped != 0) try out.print("{d} frames were dropped\n", .{card.dropped});
        if (relay.refused != 0) try out.print("{d} times the helper sent something unreadable\n", .{relay.refused});
    }
    if (options.nat) {
        // What the built in network carried, and what it could not. A guest whose traffic vanishes in
        // silence looks the same as a guest with no network, so the refusals are named.
        try out.print("nat: {d} datagrams out, {d} back, {d} in flight\n", .{ nat.sent, nat.received, nat.inFlight() });
        if (nat.streams_opened != 0) try out.print("nat: {d} connections carried\n", .{nat.streams_opened});
        if (nat.streams_refused != 0) try out.print("{d} connections were reset\n", .{nat.streams_refused});
        if (nat.unknown != 0) try out.print("{d} frames were not understood\n", .{nat.unknown});
        if (nat.no_room != 0) try out.print("{d} times the table was full\n", .{nat.no_room});
    }
    if (options.tpm != null) {
        try out.print("security chip answered {d} commands\n", .{end.chip_relay.answered});
        if (end.chain_agreed) |agreed| {
            // The guest read the register and said what it holds. This side folded the launch in and
            // knows what it has to hold, so the two are compared rather than one being believed.
            if (agreed) {
                try out.writeAll("the guest agrees about what started it\n");
            } else {
                try out.writeAll("the guest disagrees about what started it\n");
            }
        }
        if (end.chip_relay.gone) try out.writeAll("whatever answers the chip went away\n");
        if (chip.refused != 0) try out.print("{d} chip requests were refused\n", .{chip.refused});
    }
    if (held) |one| {
        try out.print("session: {d} streams handed out, {d} asked for and not given\n", .{
            one.handed_out,
            one.turned_away,
        });
        if (one.overflowed != 0) try out.print("{d} streams the guest opened had nowhere to go\n", .{one.overflowed});
        if (one.asked_about != 0 or one.turned_back != 0) {
            try out.print("session: asked about {d} names, {d} allowed, {d} refused, {d} it never asked for\n", .{
                one.asked_about,
                one.allowed,
                one.denied,
                one.turned_back,
            });
        }
    }
    if (options.vsock != null and channel.refused != 0) {
        try out.print("{d} channel connections were refused\n", .{channel.refused});
    }
    if (options.limit != null) {
        // What the guest says it gave up, which is what it really did rather than what it
        // was asked for. A guest that refused says so here by reporting less.
        try out.print("balloon asked for {d}MB and the guest gave {d}MB\n", .{
            balloon.targetBytes() / (1024 * 1024),
            @as(u64, balloon.reported()) * device.virtio.Balloon.page_size / (1024 * 1024),
        });
        try out.print("{d}MB was handed back over {d} runs of pages\n", .{ end.released / (1024 * 1024), end.ranges_seen });
        if (end.unmapped != 0) try out.print("{d} runs were not mapped here\n", .{end.unmapped});
        if (end.unadvised != 0) try out.print("{d} runs the kernel would not take back\n", .{end.unadvised});
        if (end.too_small != 0) {
            try out.print("{d} runs were shorter than one {d}K page of this machine\n", .{
                end.too_small,
                std.heap.pageSize() / 1024,
            });
        }
        if (balloon.refused != 0) try out.print("{d} balloon pages were refused\n", .{balloon.refused});
    }
}
