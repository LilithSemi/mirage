//! Running a guest on Linux, where the hypervisor is the kernel's own.

const std = @import("std");
const backend = @import("mirage-backend");
const core = @import("mirage-core");
const arch = @import("mirage-arch");
const device = @import("mirage-device");
const image = @import("mirage-image");
const netmod = @import("mirage-net");
const sessionmod = @import("mirage-session");
const fsmod = @import("mirage-fs");
const Options = @import("Options.zig");
const Trace = @import("Trace.zig");
const Screendump = @import("Screendump.zig");
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

/// Where a guest that never came back was, and what it last faulted on.
///
/// A guest that faults inside itself never leaves the hypervisor: the exception is taken to its own
/// handler, and if that handler spins then the only account of it is in the registers. The syndrome
/// is not cleared between exceptions, so it reads as the last one whether or not that is why the
/// guest stopped, which is why this says "last" rather than "the".
fn sayWhereItWas(say: *std.Io.Writer, hv: backend.Backend, id: backend.Backend.VcpuId) !void {
    if (@import("builtin").cpu.arch != .aarch64) return;

    const pc = hv.getRegister(id, .pc) catch return;
    const esr = hv.getRegister(id, .esr) catch return;
    const far = hv.getRegister(id, .far) catch return;
    if (esr == 0) {
        try say.print("cpu 0 was at {x}, having taken no exception\n", .{pc});
        return;
    }

    try say.print("cpu 0 was at {x}, last exception class {x} syndrome {x} at {x}\n", .{
        pc,
        arch.esr.class(esr),
        esr,
        far,
    });
}

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
    _ = std.os.linux.setitimer(@backingInt(std.os.linux.ITIMER.REAL), &spec, null);
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
    gic: *backend.platform.Controller,
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

    const controller = try gpa.alloc(u8, backend.platform.Controller.State.size(@intCast(ids_of.len)));
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
    // What the guest says is the whole of the first stream, so a caller may keep it or pipe it
    // somewhere and get the guest and nothing else. The second carries faults: a guest that would
    // not start, a device that answered nothing, a run that ended without doing what it was run
    // to do. A run that works says nothing on it, and what a run counted belongs in a trace rather
    // than in either stream.
    var said_room: [4096]u8 = undefined;
    var said_file = std.Io.File.stderr().writer(io, &said_room);
    const say = &said_file.interface;
    defer say.flush() catch {};

    if (@import("builtin").os.tag != .linux) {
        try say.writeAll("run only knows how to use KVM so far\n");
        return;
    }

    const options = Options.parse(args) catch |err| {
        try say.print("bad arguments: {t}\n\n", .{err});
        try say.writeAll(usage);
        return;
    };
    if (try options.complain(say, arch.platform.cpusThatFit(ram_base))) return;
    if (options.pci and arch.platform.pci == null) {
        try say.writeAll("a pci bridge on this architecture is not described to a guest yet\n");
        return;
    }
    // Where firmware put each region lives in the bridge and not in a snapshot, so a guest that
    // came back would believe its card is somewhere the bridge no longer answers.
    if (options.pci and (options.save != null or options.restore != null)) {
        try say.writeAll("a bridge is not in a snapshot, so a guest with one cannot be moved yet\n");
        return;
    }

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

    const create_machine = if (comptime @import("builtin").cpu.arch == .x86_64)
        if (options.sev_es)
            backend.kvm.Machine.createSevEs(gpa, options.cpus)
        else if (options.sev)
            backend.kvm.Machine.createSev(gpa, options.cpus)
        else
            backend.kvm.Machine.create(gpa, options.cpus)
    else
        backend.kvm.Machine.create(gpa, options.cpus);
    var machine = create_machine catch |err| switch (err) {
        // How many CPUs a guest may have is the kernel's answer, so a refusal is reported as the
        // machine's and not as a limit of this program.
        error.TooManyVcpus => {
            try say.print("this machine will not give a guest {d} cpus\n", .{options.cpus});
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
        try say.print("guest starts with {d}MB and may grow to {d}MB\n", .{
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

    // Where firmware keeps its variables: a second bank of flash, directly above the image. Not
    // memory: firmware erases and programs it by writing commands to it and waiting for a status
    // register to answer, and memory that took those commands as data would leave it reading its
    // own command back forever.
    const vars = if (options.firmware_vars) |path|
        try cwd.readFileAlloc(io, path, gpa, file_limit)
    else
        null;
    defer if (vars) |bytes| gpa.free(bytes);

    const vars_at = options.firmware_at + firmware_room;
    // As much of the store as firmware keeps anything in. It holds three regions there, a quarter
    // of a megabyte each, and reads nothing above them: a bank declared as large as the file is
    // sixty four megabytes of window that nobody reads and every read of which leaves the guest.
    const vars_room = if (vars) |bytes| @min(std.mem.alignForward(u64, bytes.len, 64 * 1024), 1024 * 1024) else 0;

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

    var gic = try backend.platform.createController(&machine.vm, options.cpus);
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
            try say.print("that is not a snapshot this can read: {t}\n", .{err});
            return;
        }
    else
        null;

    if (came_back) |parts| {
        if (parts.memory.len > ram_size) {
            try say.print("the snapshot holds {d}MB of memory and this guest has {d}MB\n", .{
                parts.memory.len / (1024 * 1024),
                ram_size / (1024 * 1024),
            });
            return;
        }
        @memcpy((try memory.slice(ram_base, parts.memory.len))[0..parts.memory.len], parts.memory);

        // A machine has to come back with the CPUs it went away with. One with fewer would leave a
        // CPU's registers unread, and one with more would start a CPU from nothing.
        if (parts.cpus != options.cpus) {
            try say.print("the snapshot holds {d} cpus and this guest was given {d}\n", .{
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
        try say.print("resumed {d} registers across {d} cpus and {d} controller attributes from {s}\n", .{
            put,
            parts.cpus,
            attributes,
            options.restore.?,
        });
    }

    var launch_config: core.Launch.Config = .{
        .vars = if (vars != null) .{ .start = vars_at, .end = vars_at + vars_room } else null,
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
        .pci = options.pci,
        .share = options.share_count > 0,
    };

    // The LAUNCH commands issue through this /dev/sev fd, held open from start through finish.
    var sev_dev: ?std.posix.fd_t = null;
    defer if (sev_dev) |fd| {
        _ = std.os.linux.close(fd);
    };
    var sev_measure_buf: [256]u8 = undefined;

    if (comptime @import("builtin").cpu.arch == .x86_64) {
        if (came_back == null and options.sev) {
            sev_dev = backend.kvm.Vm.openSev() orelse {
                try say.print("sev needs /dev/sev, which this user cannot open\n", .{});
                return error.SevUnavailable;
            };
            launch_config.sev_c_bit = arch.platform.hostCBit();
            const policy = if (options.sev_es) options.sev_policy | 0x4 else options.sev_policy;
            try machine.vm.launchStart(policy, sev_dev.?);
        }
    }

    const layout = if (came_back != null) core.Launch.Layout{
        .entry = 0,
        .device_tree = 0,
    } else try core.Launch.prepare(gpa, &memory, &manifest, launch_config);

    if (comptime @import("builtin").cpu.arch == .x86_64) {
        if (came_back == null and options.sev) {
            if (options.sev_es) {
                try machine.sevUpdateData(region);
            } else {
                if (try machine.sevSeal(region, &sev_measure_buf)) |got| {
                    try say.print("sev launch sealed, measurement {d} bytes\n", .{got.len});
                }
            }
        }
    }

    // The root says two launches differ. It does not say what they are, and a verifier needs that,
    // so the parts go out in the order they went in, which is part of the measurement: the same
    // parts hashed in another order give another root. Printed only when it was asked for, and on
    // the guest's stream because it is the answer to the asking rather than a fault.
    if (came_back == null and options.show_manifest) {
        for (manifest.entries.items, 0..) |entry, index| {
            try out.print("  {d}. {t} {x}\n", .{ index + 1, entry.tag, entry.digest });
        }
        try out.print("  root {x}\n", .{manifest.root()});
    }
    try out.flush();
    try say.flush();

    // The serial port. Where it sits and how the guest reaches it is the architecture's: a memory
    // mapped PL011 on arm, an I/O port 16550 on x86. The run loop is given a port bus only when the
    // serial is on one, because a bus with nothing on it still answers an access that matched nothing.
    const Serial = if (arch.platform.serial_is_port) device.Uart16550 else device.Pl011;
    // What the guest has to print for the run to be over, where a caller named one. A test that
    // knows what a working guest says waits for that rather than for a clock.
    var serial: Serial = .{ .sink = out, .watch = options.stop_on orelse &.{} };

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
            try say.print("cannot hold a session at {s}\n", .{path});
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
                try say.print("cannot reach the network helper at {s}: {t}\n", .{ path, err });
                return;
            },
            .fd => |number| netmod.Socket.adopt(number) catch |err| {
                try say.print("cannot use descriptor {d} for the network: {t}\n", .{ number, err });
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
            try say.writeAll("no room to offer a directory\n");
            return;
        }
    else
        null;
    defer if (offered) |*one| one.deinit();
    if (offered) |*one| {
        for (options.shares[0..options.share_count]) |each| {
            one.offer(each.name, each.at, each.writable) catch {
                try say.print("cannot offer {s}\n", .{each.name});
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
            try say.print("cannot reach the security chip at {s}: {t}\n", .{ path, err });
            return;
        };
    }
    defer if (chip_socket) |*open| open.close(io);

    const platform = arch.platform;
    var attached: Attached = .{};

    // The serial port goes on whichever bus the architecture reaches it through. On x86 it is an I/O
    // port with its own bus; on arm it is one more memory mapped device beside the rest.
    var port_devices: [1]device.Bus.Device = undefined;
    var port_bus: ?device.Bus = null;
    if (arch.platform.serial_is_port) {
        port_devices[0] = serial.device(platform.serial.addr);
        port_bus = .{ .devices = &port_devices };
    } else {
        attached.add(serial.device(platform.serial.addr));
    }

    if (sharing) {
        attached.addServed(shared_fs.device(platform.fs.addr), shared_fs.service(platform.fs.intid));
    }
    if (options.tpm != null) attached.add(chip.device(platform.tpm.addr));

    // Firmware reads this before it reaches any of its own code. A guest booting a kernel is told
    // of no such device and is given none.
    var settings: device.FwCfg = .{};
    if (options.firmware != null) attached.add(settings.device(platform.fw_cfg.addr));

    var store: device.NorFlash = .{ .store = if (vars) |bytes| bytes else &.{} };
    if (vars != null) attached.add(store.device(vars_at, vars_room));
    // Config space says where a region is and the windows are the regions, so all three belong to
    // one bridge. They are separate devices on the bus because they are separate spaces.
    var bridge: device.PciHost = .{};
    var bridge_memory: device.PciHost.Window = .{
        .host = &bridge,
        .at = if (platform.pci) |each| each.memory.at else 0,
    };
    var bridge_memory64: device.PciHost.Window = .{
        .host = &bridge,
        .at = if (platform.pci) |each| each.memory64.at else 0,
    };
    // The card's own memory. A region of the fabric rather than of the guest: the engine carries
    // words between the two, and the window lets the guest reach this much of it directly.
    // The card the caller asked for, if they asked for one. A name and its settings, read where
    // the device is made rather than turned into fields of its own.
    const wanted = options.asked("glacier-pci");
    const wanted_rom = if (wanted) |each| each.romFile() else null;

    const fabric = if (wanted != null)
        try gpa.alloc(u8, device.Glacier.prototype_fabric_size)
    else
        @as([]u8, &.{});
    defer if (wanted != null) gpa.free(fabric);
    if (wanted != null) @memset(fabric, 0);

    const option_rom: []const u8 = if (wanted_rom) |path|
        try cwd.readFileAlloc(io, path, gpa, file_limit)
    else
        &.{};
    defer if (wanted_rom != null) gpa.free(@constCast(option_rom));

    // Where what the devices did is written down, for a caller testing a driver. Opened before the
    // guest runs so a device can be told about it as it is made.
    var trace_file: ?std.Io.File = null;
    var trace_room: [4096]u8 = undefined;
    var trace_out: std.Io.File.Writer = undefined;
    var trace: ?Trace = null;
    if (options.trace) |path| {
        trace_file = try cwd.createFile(io, path, .{});
        trace_out = trace_file.?.writer(io, &trace_room);
        trace = .{ .out = &trace_out.interface };
        // What the guest says goes in the same file as what the devices did, so one reader has
        // the whole account of a run rather than two halves of it.
        serial.echo = trace.?.echo();
    }
    defer if (trace_file) |each| each.close(io);

    var gpu: device.Glacier = .{
        .memory = &memory,
        .watching = if (trace != null) trace.?.watcher() else null,
        .fabric = fabric,
        .fabric_at = device.Glacier.prototype_window_at,
        .aperture = .{
            .at = device.Glacier.prototype_window_at,
            .len = device.Glacier.prototype_window_size,
        },
        .display = device.Glacier.prototype_display,
        .display_at = device.Glacier.prototype_display_at,
        .rom = option_rom,
    };
    // A window that does not cover every row of the frame buffer is a card firmware refuses. The
    // numbers are this runner's, not the guest's, so this is a mistake here or nowhere.
    if (wanted != null) std.debug.assert(gpu.covers());

    if (options.pci) {
        if (platform.pci) |each| {
            attached.add(bridge.device(each.ecam));
            attached.add(bridge_memory.device(each.memory.len));
            attached.add(bridge_memory64.device(each.memory64.len));
        }
    }
    if (wanted != null) {
        // The slot is the bridge's to hold and firmware's to configure. A table that is full or a
        // card that describes regions the registers cannot hold is this runner being wrong.
        std.debug.assert(bridge.add(gpu.function(.{ .device = 1 })));
    }
    if (disk != null) {
        attached.addServed(block.device(platform.virtio.addr), block.service(platform.virtio.intid));
    }
    if (options.vsock != null) {
        attached.addServed(channel.device(platform.vsock.addr), channel.service(platform.vsock.intid));
    }
    if (options.limit != null) {
        attached.addServed(balloon.device(platform.balloon.addr), balloon.service(platform.balloon.intid));
    }
    if (options.net != null or options.nat) {
        attached.addServed(card.device(platform.net.addr), card.service(platform.net.intid));
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
        // already wherever it stopped. The boot entry is the architecture's own seam and takes the
        // concrete vCPU, because x86 reaches long mode through the full segment and control state a
        // `KVM_SET_SREGS` holds, which the abstract backend does not expose.
        try arch.boot.enter(&machine.vcpus[id], layout);

        if (comptime @import("builtin").cpu.arch == .x86_64) {
            if (options.sev_es) {
                try machine.vm.launchUpdateVmsa();
                if (try machine.sevMeasureFinish(&sev_measure_buf)) |got| {
                    try say.print("sev-es launch sealed, measurement {d} bytes\n", .{got.len});
                }
            }
        }
    }

    // Fold the launch into the chip before the guest runs, the way firmware does for the stages it
    // loads. After this the register holds the whole launch, so the guest can read it and say what it
    // believes started it, and this side can check that against arithmetic of its own.
    var expected_chain: ?[attest.Chain.length]u8 = null;
    if (came_back == null) {
        if (chip_socket) |*link| {
            var session: attest.Chain.Session(netmod.Socket) = .{ .transport = link };
            expected_chain = session.measure(&manifest, launch_register) catch |err| {
                try say.print("the chip would not take the launch: {t}, code {x}\n", .{ err, session.refusal });
                try out.flush();
                try say.flush();
                return;
            };
            try say.print("launch folded into register {d}, which now holds {x}\n", .{
                launch_register,
                expected_chain.?[0..8],
            });
            // Where the guest will find the list of measurements. A register says two launches differ
            // and never what either was, so the guest is given the list as well and can fold it.
            if (layout.log) |where| {
                try say.print("measurements listed at {x} over {d} bytes\n", .{
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
                try say.print("the chip would not quote the register: {t}, code {x}\n", .{ err, session.refusal });
                try out.flush();
                try say.flush();
                return;
            };
            try say.print("the chip signed it with key {x}, over {d} bytes\n", .{
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

    // Pictures of the screen, where a caller asked for them. The directory has to be there
    // already: making one for a mistyped path is how a typo becomes a surprise directory.
    var screens: ?Screendump = null;
    if (wanted) |each| {
        if (each.get("screendump")) |at| {
            const into = cwd.openDir(io, at, .{}) catch {
                try say.print("there is no directory at {s} to put pictures in\n", .{at});
                return;
            };
            screens = .{
                .into = into,
                .card = &gpu,
                .io = io,
                .every = @as(i96, @intCast(try each.screendumpMs())) * std.time.ns_per_ms,
            };
        }
    }

    var end: Host = .{
        .io = io,
        .heard = if (options.stop_on != null) &serial.said else null,
        .screens = if (screens != null) &screens.? else null,
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
        .controller = backend.platform.controllerLine(&gic),
        .services = attached.served(),
        .exits = options.exits,
        .host = end.launchHost(),
        .guard = if (options.cpus > 1) shared.guard() else null,
        .ports = if (port_bus) |*one| one else null,
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
            try say.print("cannot start cpu {d}: {t}\n", .{ each, err });
            return;
        };
        started += 1;
    }

    const reason = core.Launch.run(hv, id, driving) catch |err| stopped: {
        try out.flush();
        try say.flush();
        // Running out of exits is how a caller stops a guest on purpose, which is what taking a
        // snapshot needs. It is not a fault, so the run carries on to the writing below.
        if (err == error.ExitsExhausted) {
            try say.print("the guest used all {d} exits it was given\n", .{options.exits});
            break :stopped core.Launch.Reason.stopped;
        }
        try say.print("the guest stopped badly: {t}, kvm said {?}\n", .{ err, machine.fault });
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

    try out.flush();
    try say.flush();

    // Write down everything the guest holds, so it can be started again from here. A guest that
    // has powered off has nothing worth keeping, but saying so is the caller's business and not
    // this one's: it asked for a snapshot and it gets one.
    if (options.save) |path| {
        saveTo(gpa, io, say, path, &machine, &gic, &memory, ram_size, ids, if (disk != null) &block else null) catch |err| {
            try say.print("could not write the snapshot: {t}\n", .{err});
        };
    }
    if (end.said_it) {
        // Nothing to say: the guest did what it was waited on to do, and the answer to that is
        // the exit code rather than a line of text.
    } else if (end.timed_out) {
        // `stopped` says the loop ended, not why. A guest that ran out of time and one
        // that was asked to stop look the same from inside the loop.
        try say.print("the guest ran out of time after {?d} seconds\n", .{options.seconds});
        try sayWhereItWas(say, hv, ids[0]);
    } else if (reason != .shutdown) {
        // A guest that powered itself off did what it was asked to. Anything else ended for a
        // reason worth saying.
        try say.print("the guest stopped: {t}\n", .{reason});
    }

    // The last thing on the screen, which is the thing somebody wants to see, and the last line
    // of the trace, which is where a test reads what happened.
    if (screens) |*each| each.take();
    if (trace) |*each| {
        each.lastWord();
        each.summary(&bridge, &gpu);
    }

    // Nothing is said about a bus that worked. What each device did is counted in the trace, which
    // is where whoever cares reads it, and a caller who asked for a trace or for pictures knows
    // where they asked for them to go. Only what went wrong is worth a line here.
    if (options.pci and wanted != null) {
        if (gpu.outside != 0) {
            try say.print("glacier: {d} bytes were painted outside the frame buffer\n", .{gpu.outside});
        }
        if (gpu.strayed != 0) {
            try say.print("glacier: {d} accesses named fabric the card does not have\n", .{gpu.strayed});
        }
    }
    if (bridge.unanswered != 0) {
        try say.print("pci: {d} accesses reached a region with nobody to answer them\n", .{bridge.unanswered});
    }
    if (screens) |each| {
        if (each.lost != 0) try say.print("glacier: {d} pictures could not be written\n", .{each.lost});
    }
    if (trace) |each| {
        if (each.lost != 0) try say.print("trace: {d} lines could not be written\n", .{each.lost});
    }

    // A device that asked for an interrupt the kernel refused is why a guest waits
    // forever, so say so rather than leaving it to be guessed at.
    if (offered) |one| {
        try say.print("shares: {d} offered, {d} names handed over, {d}MB read, {d} refused\n", .{
            options.share_count,
            one.named + one.looked_up,
            one.read_bytes / (1024 * 1024),
            one.refused,
        });
        if (one.turned_away != 0) {
            try say.print("{d} names would have left a shared directory\n", .{one.turned_away});
        }
        // What was refused, the last few. A guest reports whatever its own library made of the
        // number, and a library with no name for one says only that it was unexpected.
        if (one.last_refusals.count != 0) {
            var room: [fsmod.Export.Refusals.room]fsmod.Export.Refusals.Refusal = undefined;
            for (one.last_refusals.held(&room)) |each| {
                try say.print("share: refused {t} with {d} at {d}\n", .{ each.op, each.code, each.at });
            }
        }
        // What the guest finished with. A guest held up for a session makes and forgets files for hours,
        // and a number here that stays at zero while it works means this side is holding all of them.
        if (one.let_go_nodes != 0) {
            try say.print("share: {d} files the guest finished with\n", .{one.let_go_nodes});
        }
    }
    if (gic.dropped != 0) try say.print("{d} interrupts were dropped\n", .{gic.dropped});
    if (bus.unmapped != 0) try say.print("{d} guest accesses matched no device\n", .{bus.unmapped});
    if (options.net != null or options.nat) {
        // Whether the driver set the queues up says whether it probed at all, which a log line
        // does not: a network driver says nothing when it finds a device it is happy with.
        try say.print("network: driver ready {}, {d} frames from the guest, {d} to it\n", .{
            card.ready(),
            end.frames_out,
            end.frames_in,
        });
        if (end.helper_gone) try say.writeAll("the network helper went away\n");
        if (card.dropped != 0) try say.print("{d} frames were dropped\n", .{card.dropped});
        if (relay.refused != 0) try say.print("{d} times the helper sent something unreadable\n", .{relay.refused});
    }
    if (options.nat) {
        // What the built in network carried, and what it could not. A guest whose traffic vanishes in
        // silence looks the same as a guest with no network, so the refusals are named.
        try say.print("nat: {d} datagrams out, {d} back, {d} in flight\n", .{ nat.sent, nat.received, nat.inFlight() });
        if (nat.streams_opened != 0) try say.print("nat: {d} connections carried\n", .{nat.streams_opened});
        if (nat.streams_refused != 0) try say.print("{d} connections were reset\n", .{nat.streams_refused});
        if (nat.unknown != 0) try say.print("{d} frames were not understood\n", .{nat.unknown});
        if (nat.no_room != 0) try say.print("{d} times the table was full\n", .{nat.no_room});
    }
    if (options.tpm != null) {
        try say.print("security chip answered {d} commands\n", .{end.chip_relay.answered});
        if (end.chain_agreed) |agreed| {
            // The guest read the register and said what it holds. This side folded the launch in and
            // knows what it has to hold, so the two are compared rather than one being believed.
            if (agreed) {
                try say.writeAll("the guest agrees about what started it\n");
            } else {
                try say.writeAll("the guest disagrees about what started it\n");
            }
        }
        if (end.chip_relay.gone) try say.writeAll("whatever answers the chip went away\n");
        if (chip.refused != 0) try say.print("{d} chip requests were refused\n", .{chip.refused});
    }
    if (held) |one| {
        try say.print("session: {d} streams handed out, {d} asked for and not given\n", .{
            one.handed_out,
            one.turned_away,
        });
        if (one.overflowed != 0) try say.print("{d} streams the guest opened had nowhere to go\n", .{one.overflowed});
        if (one.asked_about != 0 or one.turned_back != 0) {
            try say.print("session: asked about {d} names, {d} allowed, {d} refused, {d} it never asked for\n", .{
                one.asked_about,
                one.allowed,
                one.denied,
                one.turned_back,
            });
        }
    }
    if (options.vsock != null and channel.refused != 0) {
        try say.print("{d} channel connections were refused\n", .{channel.refused});
    }
    if (options.limit != null) {
        // What the guest says it gave up, which is what it really did rather than what it
        // was asked for. A guest that refused says so here by reporting less.
        try say.print("balloon asked for {d}MB and the guest gave {d}MB\n", .{
            balloon.targetBytes() / (1024 * 1024),
            @as(u64, balloon.reported()) * device.virtio.Balloon.page_size / (1024 * 1024),
        });
        try say.print("{d}MB was handed back over {d} runs of pages\n", .{ end.released / (1024 * 1024), end.ranges_seen });
        if (end.unmapped != 0) try say.print("{d} runs were not mapped here\n", .{end.unmapped});
        if (end.unadvised != 0) try say.print("{d} runs the kernel would not take back\n", .{end.unadvised});
        if (end.too_small != 0) {
            try say.print("{d} runs were shorter than one {d}K page of this machine\n", .{
                end.too_small,
                std.heap.pageSize() / 1024,
            });
        }
        if (balloon.refused != 0) try say.print("{d} balloon pages were refused\n", .{balloon.refused});
    }

    // A caller that named something to wait for and never heard it has a guest that did not do
    // what it was run to do. Said plainly and answered with a failure, because the one asking is
    // a test and a test that passes when the guest never spoke is worse than no test.
    //
    // Leaving this way rather than returning an error: the run is over, everything worth writing
    // has been written, and an error here would arrive wrapped in a stack trace of this program
    // rather than as the plain answer a caller wants.
    if (options.stop_on) |text| {
        if (!end.said_it) {
            try say.print("the guest never said {s}\n", .{text});
            try out.flush();
            try say.flush();
            std.process.exit(1);
        }
    }
}
