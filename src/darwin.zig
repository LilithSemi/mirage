//! Running a guest on macOS, where the hypervisor is Apple's.
//!
//! What differs from the Linux side is not the guest and not the devices: it is that this hypervisor
//! holds almost nothing. There is no interrupt controller in it, so the guest gets one built here;
//! there is no power interface in it, so the CPUs the guest starts are started here; and a CPU
//! belongs to the thread that made it, so every CPU runs on a thread of its own from the moment it
//! exists rather than being handed out by whoever asks.
//!
//! Everything else is the same code the other runner uses, because a guest cannot tell which
//! hypervisor is under it and nothing above the hypervisor should be able to either.

const std = @import("std");
const backend = @import("mirage-backend");
const core = @import("mirage-core");
const arm64 = @import("mirage-arm64");
const device = @import("mirage-device");
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
const hostResolver = host.hostResolver;
const usage = Options.usage;

/// The register the launch is folded into, the same one the other runner uses. A verifier that reads
/// a quote must not have to know which machine took it.
const launch_register = 0;

/// A kernel and an initial filesystem are large but not unbounded.
const file_limit: std.Io.Limit = .limited(1 << 30);

pub fn probe(out: *std.Io.Writer) !void {
    // Whether the framework is there and will give this process a machine. There is nothing to ask
    // it beyond that: what it can do is fixed by the release of macOS and not reported.
    const loaded = backend.hvf.binding.Api.load();
    try out.print(
        \\hypervisor available {}
        \\cpus a guest may have {d}
        \\interrupt controller  in this process
        \\tier                  0
        \\
    , .{ loaded != error.MissingSymbol, backend.hvf.Machine.max_vcpus });

    // What the number means, in the same words the other runner uses. A tier is a claim about what
    // this machine can hold back from a guest, and this hypervisor maps every page it is given.
    try out.writeAll(
        \\
        \\A guest here is separated by this hypervisor and by nothing else. Its memory is mapped
        \\by this process, so whoever runs this can read it.
        \\
    );
}

/// What a CPU other than the first is waiting for. The guest puts an address in it through the power
/// interface, and until then the CPU must not run: there is nothing where it would begin.
const Waiting = struct {
    wanted: std.atomic.Value(bool) = .init(false),
    entry: u64 = 0,
    context: u64 = 0,
};

/// One per CPU this machine may have. Fixed because the interrupt controller built here holds one
/// piece of state per CPU and is sized once.
var waiting: [device.Gicv2.max_cpus]Waiting = @splat(.{});

/// Everything a CPU other than the first is given. One value rather than a closure, because a thread
/// takes one argument and because nothing here is per CPU except which CPU it is.
const Secondary = struct {
    machine: *backend.hvf.Machine,
    driving: core.Launch.Run,
    end: *Host,
};

/// A CPU the guest starts itself.
///
/// It makes its own CPU, because this hypervisor binds one to the thread that created it, and then
/// waits until the guest asks for it. After that it is an ordinary CPU running the ordinary loop.
fn driveSecondary(given: Secondary) void {
    const hv = given.machine.backend();
    const id = hv.addVcpu() catch return;
    if (id >= device.Gicv2.max_cpus) return;

    while (!waiting[id].wanted.load(.acquire)) {
        if (given.end.stopping.load(.acquire)) return;
        std.Thread.yield() catch {};
    }
    if (given.end.stopping.load(.acquire)) return;

    // Where the guest said to begin, and what it said to begin with. The rest of the registers are
    // the guest's own business and the power interface says they are zero.
    hv.setRegister(id, .pc, waiting[id].entry) catch return;
    hv.setRegister(id, .x0, waiting[id].context) catch return;
    hv.setRegister(id, .x1, 0) catch return;
    hv.setRegister(id, .x2, 0) catch return;
    hv.setRegister(id, .x3, 0) catch return;

    _ = core.Launch.run(hv, id, given.driving) catch return;
}

/// Who the guest asks to start another CPU. The guest names one by the number the device tree gave
/// it, so that number is turned back into which CPU it is: a number naming no CPU is refused,
/// because a guest told a CPU started that never did waits for it forever.
const Power = struct {
    cpus: u32,
    made: *const u32,

    fn start(ctx: *anyopaque, target: u64, entry: u64, context: u64) bool {
        const self: *Power = @ptrCast(@alignCast(ctx));
        for (0..@min(self.cpus, device.Gicv2.max_cpus)) |index| {
            if (arm64.fdt.affinity(@intCast(index)) != target) continue;
            // The first CPU is running already, and one whose thread never made its CPU cannot run.
            if (index == 0 or index >= self.made.*) return false;
            if (waiting[index].wanted.load(.acquire)) return false;

            waiting[index].entry = entry;
            waiting[index].context = context;
            waiting[index].wanted.store(true, .release);
            return true;
        }
        return false;
    }

    fn power(self: *Power) core.Launch.Power {
        return .{ .ctx = self, .start = Power.start };
    }
};

/// A guest that spins inside itself makes no exits, so a loop that reads the clock between exits
/// never reads it. A signal is the only thing that brings a CPU out of this hypervisor then.
fn onAlarm(_: std.c.SIG) callconv(.c) void {}

fn armDeadline(seconds: u64) void {
    var action: std.c.Sigaction = .{
        .handler = .{ .handler = onAlarm },
        .mask = std.mem.zeroes(std.c.sigset_t),
        .flags = 0,
    };
    _ = std.c.sigaction(std.c.SIG.ALRM, &action, null);
    _ = std.c.alarm(@intCast(@min(seconds, std.math.maxInt(c_uint))));
}

pub fn run(gpa: std.mem.Allocator, io: std.Io, out: *std.Io.Writer, args: []const [:0]const u8) !void {
    if (args.len == 0) {
        try out.writeAll(usage);
        return;
    }

    const options = Options.parse(args) catch |err| {
        try out.print("bad arguments: {t}\n\n", .{err});
        try out.writeAll(usage);
        return;
    };
    if (try options.complain(out, arm64.fdt.cpusThatFit(ram_base))) return;
    if (options.restore != null or options.save != null) {
        try out.writeAll("moving a guest is not written for this hypervisor yet\n");
        return;
    }
    if (options.firmware != null) {
        try out.writeAll("starting firmware is not written for this hypervisor yet\n");
        return;
    }
    if (options.cpus > device.Gicv2.max_cpus) {
        try out.print("a guest here gets a version 2 controller, which has no interface past {d} cpus\n", .{
            device.Gicv2.max_cpus,
        });
        return;
    }

    const began = std.Io.Clock.awake.now(io).nanoseconds;
    const cwd: std.Io.Dir = .cwd();

    const kernel = try cwd.readFileAlloc(io, options.kernel, gpa, file_limit);
    defer gpa.free(kernel);
    const read_at = std.Io.Clock.awake.now(io).nanoseconds;

    const initrd = if (options.initrd) |path| try cwd.readFileAlloc(io, path, gpa, file_limit) else null;
    defer if (initrd) |bytes| gpa.free(bytes);
    const disk = if (options.disk) |path| try cwd.readFileAlloc(io, path, gpa, file_limit) else null;
    defer if (disk) |bytes| gpa.free(bytes);

    var machine = backend.hvf.Machine.create(gpa, options.cpus) catch |err| {
        // Either the framework is not there, or this process was not signed to be allowed a guest.
        try out.print("no hypervisor: {t}\n", .{err});
        return;
    };
    defer machine.deinit();

    // Guest memory is this process's memory. There is nothing here like a descriptor the hypervisor
    // can hold on its own, which is what tier 1 would need, so a guest here is separated by the
    // hypervisor and by nothing else.
    const ram_size = options.memory * 1024 * 1024;
    const pages = std.posix.mmap(
        null,
        ram_size,
        .{ .READ = true, .WRITE = true },
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    ) catch |err| {
        try out.print("cannot set aside {d}MB for the guest: {t}\n", .{ ram_size / (1024 * 1024), err });
        return;
    };
    defer std.posix.munmap(pages);

    machine.map(pages, ram_base) catch |err| {
        try out.print("this hypervisor will not take that memory: {t}\n", .{err});
        return;
    };

    var regions = [_]GuestMemory.Region{
        .{ .gpa = ram_base, .len = ram_size, .backing = .{ .shared = pages } },
    };
    var memory: GuestMemory = .{ .regions = &regions };

    var manifest: Manifest = .{};
    defer manifest.deinit(gpa);

    var seed: [32]u8 = undefined;
    try io.randomSecure(&seed);

    const layout = try core.Launch.prepare(gpa, &memory, &manifest, .{
        .kernel = kernel,
        .initrd = initrd,
        .cmdline = options.cmdline,
        .ram_base = ram_base,
        .ram_size = ram_size,
        .cpus = options.cpus,
        .uart_base = uart_base,
        // Built in this process, and the guest is told where both halves of it are.
        .controller = .{ .gic_v2 = .{ .cpu_base = arm64.fdt.gicv2_cpu_base } },
        .rng_seed = &seed,
        .rootfs_verity = options.root_hash,
        .block_device = disk != null,
        .vsock = options.vsock != null,
        .net = options.nat,
        .tpm = options.tpm != null,
        .share = options.share_count > 0,
    });
    const ready_at = std.Io.Clock.awake.now(io).nanoseconds;

    const root = manifest.root();
    try out.print("launch measured, root {x}\n", .{root[0..8]});
    if (options.show_manifest) {
        for (manifest.entries.items, 0..) |entry, index| {
            try out.print("  {d}. {t} {x}\n", .{ index + 1, entry.tag, entry.digest });
        }
        try out.print("  root {x}\n", .{root});
    }
    try out.flush();

    var gic: device.Gicv2 = .{ .cpus = options.cpus };
    const controller_devices = gic.devices(arm64.fdt.gicd_base, arm64.fdt.gicv2_cpu_base);

    var serial: device.Pl011 = .{
        .sink = out,
        // The real driver waits to be told there is room to send. Without a line to report on,
        // output stops the moment the early console hands over.
        .line = .{ .controller = gic.controller(), .intid = arm64.fdt.uart_intid },
    };

    var block: device.virtio.Block = undefined;
    if (disk) |bytes| block.init(bytes);

    var ports: [2]u32 = undefined;
    var channel: device.virtio.Vsock = undefined;
    if (options.vsock) |listen| {
        ports[0] = listen;
        ports[1] = sessionmod.wire.reaching_port;
        channel.init(guest_cid, ports[0..if (options.session != null) 2 else 1]);
    }

    const held: ?*sessionmod.Server = if (options.session) |path| room: {
        const one = try gpa.create(sessionmod.Server);
        one.* = sessionmod.Server.listen(path) catch {
            try out.print("cannot hold a session at {s}\n", .{path});
            return;
        };
        break :room one;
    } else null;
    defer if (held) |one| gpa.destroy(one);

    // A network of this VMM's own. There is no helper to start on a Mac, so this is the only way a
    // guest here reaches anything, and a guest with a session reaches by name instead.
    var card: device.virtio.Net = undefined;
    // Nothing here reads this: a Mac has no helper to relay frames to, so the field is given something
    // real rather than a pointer nobody may follow.
    var relay: netmod.Relay = .{};
    var nat: netmod.Nat = .{
        .guest_ip = .{ 10, 0, 2, 15 },
        .guest_mac = guest_mac,
        .gateway_ip = .{ 10, 0, 2, 2 },
        .gateway_mac = .{ 0x52, 0x54, 0x00, 0x12, 0x34, 0x57 },
        .resolver = hostResolver(io, gpa),
    };
    defer nat.deinit();
    if (options.nat) card.init(guest_mac);

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
    attached.add(controller_devices[0]);
    attached.add(controller_devices[1]);
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
    if (options.nat) {
        attached.addServed(card.device(arm64.fdt.net_base), card.service(arm64.fdt.net_intid));
    }
    var bus = attached.bus();

    const hv = machine.backend();
    const id = hv.addVcpu() catch |err| {
        try out.print("cannot make a cpu: {t}\n", .{err});
        return;
    };
    try core.Launch.enter(hv, id, layout);

    var expected_chain: ?[attest.Chain.length]u8 = null;
    if (chip_socket) |*link| {
        var folding: attest.Chain.Session(netmod.Socket) = .{ .transport = link };
        expected_chain = folding.measure(&manifest, launch_register) catch |err| {
            try out.print("the chip would not take the launch: {t}, code {x}\n", .{ err, folding.refusal });
            return;
        };
        try out.print("launch folded into register {d}, which now holds {x}\n", .{
            launch_register,
            expected_chain.?[0..8],
        });
    }

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
        .memory = &memory,
        .card = if (options.nat) &card else null,
        .nat = if (options.nat) &nat else null,
        .relay = &relay,
        .chip = if (options.tpm != null) &chip else null,
        .chip_socket = chip_socket,
        .expected_chain = expected_chain,
        .out = out,
    };

    var made: u32 = 1;
    var power: Power = .{ .cpus = options.cpus, .made = &made };

    // One lock for everything shared, held whenever a CPU is outside the hypervisor. A machine with
    // one CPU has nothing to race with and is given none.
    var shared: Shared = .{};
    const driving: core.Launch.Run = .{
        .bus = &bus,
        .memory = &memory,
        .controller = gic.controller(),
        .services = attached.served(),
        .exits = options.exits,
        .host = end.launchHost(),
        .power = power.power(),
        .guard = if (options.cpus > 1) shared.guard() else null,
    };

    // The other CPUs, each on a thread that makes its own and then waits for the guest to start it.
    const threads = try gpa.alloc(std.Thread, options.cpus - 1);
    defer gpa.free(threads);
    var started: usize = 0;
    while (started < threads.len) : (started += 1) {
        threads[started] = std.Thread.spawn(.{}, driveSecondary, .{Secondary{
            .machine = &machine,
            .driving = driving,
            .end = &end,
        }}) catch break;
    }
    // How many CPUs really exist. The power interface refuses a CPU whose thread never made one,
    // because a guest told a CPU started that never did waits for it forever.
    made = @intCast(1 + started);

    if (options.seconds) |limit| armDeadline(limit);

    const reason = core.Launch.run(hv, id, driving) catch |err| {
        try out.flush();
        if (err == error.ExitsExhausted) {
            try out.print("\nthe guest used all {d} exits it was given\n", .{options.exits});
            return;
        }
        try out.print("\nthe guest stopped badly: {t}, the framework said {?}\n", .{ err, machine.fault });
        return;
    };

    // Every other CPU leaves its loop before anything else happens. A CPU inside the hypervisor is
    // one whose registers cannot be read and whose devices are still being served.
    end.stopping.store(true, .release);
    for (threads[0..started]) |each| each.join();

    if (held) |one| {
        one.lost();
        one.close(&channel);
    }

    const stopped_at = std.Io.Clock.awake.now(io).nanoseconds;
    try out.flush();

    try out.print("\ntook {d}ms to read {d}MB of kernel, {d}ms to measure and place it, {d}ms running, built {t}\n", .{
        @divTrunc(read_at - began, std.time.ns_per_ms),
        kernel.len / (1024 * 1024),
        @divTrunc(ready_at - read_at, std.time.ns_per_ms),
        @divTrunc(stopped_at - ready_at, std.time.ns_per_ms),
        @import("builtin").mode,
    });
    if (end.timed_out) {
        try out.print("\nthe guest ran out of time after {?d} seconds\n", .{options.seconds});
    } else {
        try out.print("\nthe guest stopped: {t}\n", .{reason});
    }
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
    if (options.nat) {
        try out.print("nat: {d} datagrams out, {d} back, {d} in flight\n", .{ nat.sent, nat.received, nat.inFlight() });
        if (nat.streams_opened != 0) try out.print("nat: {d} connections carried\n", .{nat.streams_opened});
    }
    if (held) |one| {
        try out.print("session: {d} streams handed out, {d} asked for and not given\n", .{
            one.handed_out,
            one.turned_away,
        });
        if (one.asked_about != 0 or one.turned_back != 0) {
            try out.print("session: asked about {d} names, {d} allowed, {d} refused, {d} it never asked for\n", .{
                one.asked_about,
                one.allowed,
                one.denied,
                one.turned_back,
            });
        }
    }
    if (options.tpm != null) {
        try out.print("security chip answered {d} commands\n", .{end.chip_relay.answered});
        if (end.chain_agreed) |agreed| {
            if (agreed) {
                try out.writeAll("the guest agrees about what started it\n");
            } else {
                try out.writeAll("the guest disagrees about what started it\n");
            }
        }
    }
}
