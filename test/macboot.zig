//! Boots a real Linux kernel under Hypervisor.framework.
//!
//! The same launch path, the same run loop and the same device tree builder as the
//! KVM side, with the interrupt controller this VMM writes rather than one the
//! kernel lends it. Cross compiled on Linux, signed and run on a Mac.

const std = @import("std");
const backend = @import("mirage-backend");
const core = @import("mirage-core");
const arm64 = @import("mirage-arm64");
const device = @import("mirage-device");
const image = @import("mirage-image");
const netmod = @import("mirage-net");

/// Where a program answering the chip commands is listening, or nothing for a guest with no chip.
const chip_on = options.chip_socket.len > 0;

/// How many CPUs the guest is given. Every one after the first waits inside its own thread until the
/// guest asks the power interface to start it.
const cpus: u32 = options.cpus;

comptime {
    if (cpus < 1 or cpus > device.Gicv2.max_cpus) @compileError("this guest gets a version 2 controller, which has no interface past eight cpus");
}
const GuestMemory = @import("mirage-memory").GuestMemory;
const Manifest = @import("mirage-attest").Manifest;
const options = @import("boot-options");

const guest_init = @embedFile("guest-init");

const ram = 0x4000_0000;
const ram_size = 512 << 20;
const uart = 0x0900_0000;

/// The guest address and the port both sides agreed on. The guest program has the same two numbers,
/// and a channel where one side disagrees is a channel nobody answers.
const guest_cid = 3;

/// The address the guest answers to on the network. Fixed so the launch is reproducible, and locally
/// administered so it cannot collide with a real card.
const guest_mac = [6]u8{ 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 };
const host_port = 1024;

fn say(comptime fmt: []const u8, args: anytype) void {
    var buffer: [1024]u8 = undefined;
    const line = std.fmt.bufPrint(&buffer, fmt ++ "\n", args) catch return;
    _ = std.c.write(1, line.ptr, line.len);
}

/// Write a slice straight out. `say` formats into a fixed buffer and gives up when
/// the text does not fit, which silently swallowed the whole guest log once.
fn emit(bytes: []const u8) void {
    if (bytes.len == 0) return;
    _ = std.c.write(1, bytes.ptr, bytes.len);
}

/// How long to let a run go on for. A guest that has stopped getting anywhere would otherwise sit
/// here until somebody notices, and a run that reports after a minute is worth far more than one that
/// has to be killed.
const run_seconds = 90;

/// The first name server this Mac uses. A guest looking a name up through an address that answers
/// nothing looks exactly like a network that does not work, so this is read rather than guessed.
fn hostResolver() netmod.Ip4 {
    const fallback: netmod.Ip4 = .{ 1, 1, 1, 1 };

    var path: [64:0]u8 = @splat(0);
    @memcpy(path[0.."/etc/resolv.conf".len], "/etc/resolv.conf");
    const fd = std.c.open(&path, .{ .ACCMODE = .RDONLY });
    if (fd < 0) return fallback;
    defer _ = std.c.close(fd);

    var text: [8192]u8 = undefined;
    const got = std.c.read(fd, &text, text.len);
    if (got <= 0) return fallback;

    var lines = std.mem.splitScalar(u8, text[0..@intCast(got)], '\n');
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

/// Listen where the guest will reach, and answer once. Nothing leaves the machine: the guest addresses
/// the gateway, the translation sends that to this machine's loopback, and this is what is there.
const Listener = struct {
    handle: std.c.fd_t = -1,
    carried: std.c.fd_t = -1,
    heard: usize = 0,
    answered: bool = false,

    fn open() ?Listener {
        const handle = std.c.socket(std.c.AF.INET, std.c.SOCK.STREAM, 0);
        if (handle < 0) return null;

        var yes: u32 = 1;
        _ = std.c.setsockopt(handle, std.c.SOL.SOCKET, std.c.SO.REUSEADDR, @ptrCast(&yes), @sizeOf(u32));

        var address: std.c.sockaddr.in = .{
            .port = std.mem.nativeToBig(u16, stream_port),
            .addr = 0x0100007f,
        };
        if (std.c.bind(handle, @ptrCast(&address), @sizeOf(std.c.sockaddr.in)) != 0) {
            _ = std.c.close(handle);
            return null;
        }
        if (std.c.listen(handle, 1) != 0) {
            _ = std.c.close(handle);
            return null;
        }
        dontWait(handle);
        return .{ .handle = handle };
    }

    fn deinit(self: *Listener) void {
        if (self.carried >= 0) _ = std.c.close(self.carried);
        if (self.handle >= 0) _ = std.c.close(self.handle);
        self.* = .{};
    }

    /// Take a connection if one waits, read it, and answer once. Nothing here waits.
    fn turn(self: *Listener) void {
        if (self.carried < 0) {
            const taken = std.c.accept(self.handle, null, null);
            if (taken < 0) return;
            self.carried = taken;
            dontWait(self.carried);
        }

        var buffer: [256]u8 = undefined;
        const got = std.c.read(self.carried, &buffer, buffer.len);
        if (got > 0) self.heard += @intCast(got);

        if (self.heard > 0 and !self.answered) {
            const answer = "the host heard your stream\n";
            _ = std.c.write(self.carried, answer.ptr, answer.len);
            self.answered = true;
        }
    }

    fn dontWait(handle: std.c.fd_t) void {
        const flags = std.c.fcntl(handle, std.posix.F.GETFL, @as(usize, 0));
        if (flags < 0) return;
        const asking: std.posix.O = .{ .NONBLOCK = true };
        _ = std.c.fcntl(handle, std.posix.F.SETFL, @as(usize, @intCast(flags)) | @as(usize, @as(u32, @bitCast(asking))));
    }
};

/// The lock every CPU of the guest takes before touching anything they share, and the flag that ends
/// the run. A spin lock, because it is held only long enough to serve one access.
var held: std.atomic.Mutex = .unlocked;
var stopping = std.atomic.Value(bool).init(false);

fn hold() void {
    if (cpus > 1) while (!held.tryLock()) std.atomic.spinLoopHint();
}

fn drop() void {
    if (cpus > 1) held.unlock();
}

/// What a CPU needs to know once the guest asks for it to be started, and whether it has been asked.
///
/// Every CPU but the first begins stopped. The guest starts one through the power interface, naming
/// where it should begin, and this is how that reaches the thread that is waiting.
const Waiting = struct {
    wanted: std.atomic.Value(bool) = .init(false),
    entry: u64 = 0,
    context: u64 = 0,
};

var waiting: [device.Gicv2.max_cpus]Waiting = @splat(.{});

/// Everything a CPU other than the first is given.
const Shared = struct {
    machine: *backend.hvf.Machine,
    bus: *device.Bus,
    gic: *device.Gicv2,
    /// How many exits each CPU made, so a test can see that one really ran.
    exits: []u64,
};

/// One of the CPUs the guest starts itself.
///
/// The framework binds a CPU to the thread that created it, so this makes its own rather than being
/// handed one. Then it waits: a CPU the guest has not started yet must not run, because the guest has
/// put nothing where it would begin.
fn driveSecondary(shared: Shared) void {
    const hv = shared.machine.backend();
    const id = hv.addVcpu() catch return;
    if (id >= device.Gicv2.max_cpus) return;

    while (!waiting[id].wanted.load(.acquire)) {
        if (stopping.load(.acquire)) return;
        std.Thread.yield() catch {};
    }
    if (stopping.load(.acquire)) return;

    hv.setRegister(id, .pc, waiting[id].entry) catch return;
    hv.setRegister(id, .x0, waiting[id].context) catch return;
    hv.setRegister(id, .x1, 0) catch return;
    hv.setRegister(id, .x2, 0) catch return;
    hv.setRegister(id, .x3, 0) catch return;

    while (!stopping.load(.acquire)) {
        hold();
        const line = shared.gic.signalled(id);
        drop();
        hv.setInterrupt(id, line) catch break;

        const exit = hv.run(id) catch break;
        shared.exits[id] += 1;

        hold();
        defer drop();
        // Which CPU is touching the registers. The controller banks most of itself per CPU and a memory
        // access does not say who made it.
        shared.gic.acting = id;

        switch (exit) {
            .mmio_write => |w| shared.bus.write(w.gpa, w.size, w.value),
            .mmio_read => |r| hv.completeMmioRead(id, shared.bus.read(r.gpa, r.size)) catch break,
            // This CPU's own timer, which belongs to it and to no other.
            .timer => shared.gic.raiseOn(id, arm64.timer.virtual_intid),
            .psci => |call| switch (arm64.psci.handle(.{ .function = call.function, .args = call.args })) {
                .value => |value| hv.setRegister(id, .x0, value) catch break,
                // A CPU turning itself off stops being a CPU that runs. The machine carries on.
                .power_off, .reset => return,
                .start_cpu => |wanted| startCpu(shared.machine, wanted.target, wanted.entry, wanted.context, id),
            },
            else => {},
        }
    }
}

/// Start the CPU the guest named, and say whether it could be.
///
/// The guest names it by the number the device tree gave it, so that number is turned back into which
/// CPU it is. A number naming no CPU is refused, because a guest told a CPU started that never did
/// waits for it forever.
fn startCpu(machine: *backend.hvf.Machine, target: u64, entry: u64, context: u64, asker: backend.Backend.VcpuId) void {
    const hv = machine.backend();
    for (0..@min(cpus, device.Gicv2.max_cpus)) |index| {
        if (arm64.fdt.affinity(@intCast(index)) != target) continue;
        if (index == 0 or index >= machine.count) break;

        waiting[index].entry = entry;
        waiting[index].context = context;
        waiting[index].wanted.store(true, .release);
        hv.setRegister(asker, .x0, arm64.psci.success) catch {};
        return;
    }
    hv.setRegister(asker, .x0, arm64.psci.not_supported) catch {};
}
/// A guest that never stops would spin here forever. A signal with no restart flag brings a CPU out of
/// the hypervisor the same way it brings one out of KVM.
fn onAlarm(_: std.c.SIG) callconv(.c) void {}

/// A guest spinning on a lock of its own makes no exits at all, so a loop that checks the clock between
/// exits never gets to check it. A signal is the only thing that brings a CPU out of the hypervisor
/// then, which is why this exists as well as the clock.
fn armDeadline(seconds: u32) void {
    var action: std.c.Sigaction = .{
        .handler = .{ .handler = onAlarm },
        .mask = std.mem.zeroes(std.c.sigset_t),
        .flags = 0,
    };
    _ = std.c.sigaction(std.c.SIG.ALRM, &action, null);
    _ = std.c.alarm(seconds);
}

fn nowMs() i64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), 1_000_000);
}

fn mapFile(path: []const u8) ?[]align(std.heap.page_size_min) u8 {
    var buffer: [512:0]u8 = @splat(0);
    if (path.len >= buffer.len) return null;
    @memcpy(buffer[0..path.len], path);

    const fd = std.c.open(&buffer, .{ .ACCMODE = .RDONLY });
    if (fd < 0) return null;
    defer _ = std.c.close(fd);

    const end = std.c.lseek(fd, 0, 2);
    if (end <= 0) return null;

    return std.posix.mmap(null, @intCast(end), .{ .READ = true }, .{ .TYPE = .PRIVATE }, fd, 0) catch null;
}

/// Where a kernel built without address randomisation puts itself. Every address inside the image is
/// this far above where the image was really loaded, which is what makes one subtraction enough to
/// read the stack without walking any page tables.
const kernel_virtual_base = 0xffff_8000_8000_0000;

/// Say where the guest is waiting, and who called it there.
///
/// A frame record on this architecture is the previous frame pointer followed by the return address,
/// so the chain is a list that can be read straight out of memory. Only addresses inside the kernel
/// image can be turned into physical ones by one subtraction, and an early boot stack is inside it.
/// Anything outside stops the walk rather than being guessed at, because a wrong frame is worse than
/// no frame.
fn whereWaiting(machine: anytype, id: backend.Backend.VcpuId, memory: *GuestMemory, entry: u64) void {
    var pc: u64 = 0;
    var fp: u64 = 0;
    var lr: u64 = 0;
    _ = machine.api.vcpu_get_reg(machine.vcpus[id].id, .pc, &pc);
    _ = machine.api.vcpu_get_reg(machine.vcpus[id].id, .x29, &fp);
    _ = machine.api.vcpu_get_reg(machine.vcpus[id].id, .x30, &lr);

    say("\nwaiting at 0x{x}, called from 0x{x}, frame 0x{x}", .{ pc, lr, fp });

    var frame = fp;
    var depth: usize = 0;
    while (depth < 16) : (depth += 1) {
        if (frame < kernel_virtual_base) break;
        const at = frame - kernel_virtual_base + entry;

        var record: [16]u8 = undefined;
        memory.read(at, &record) catch break;

        const next = std.mem.readInt(u64, record[0..8], .little);
        const returns = std.mem.readInt(u64, record[8..16], .little);
        if (returns == 0) break;
        say("  frame {d}: returns to 0x{x}", .{ depth, returns });

        // A chain that does not climb is a chain that has been read wrongly.
        if (next <= frame) break;
        frame = next;
    }
}

pub fn main() void {
    var arena: std.heap.DebugAllocator(.{}) = .init;
    const gpa = arena.allocator();

    const kernel = mapFile(options.kernel_path) orelse {
        say("cannot open {s}", .{options.kernel_path});
        std.process.exit(1);
    };
    say("kernel {s}, {d} bytes", .{ options.kernel_path, kernel.len });

    var machine = backend.hvf.Machine.create(gpa, cpus) catch |err| {
        say("no hypervisor: {t}", .{err});
        std.process.exit(1);
    };
    defer machine.deinit();

    const host = std.posix.mmap(
        null,
        ram_size,
        .{ .READ = true, .WRITE = true },
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    ) catch |err| {
        say("cannot allocate guest memory: {t}", .{err});
        std.process.exit(1);
    };
    machine.map(host, ram) catch |err| {
        say("cannot map guest memory: {t}", .{err});
        std.process.exit(1);
    };

    var regions = [_]GuestMemory.Region{
        .{ .gpa = ram, .len = ram_size, .backing = .{ .shared = host } },
    };
    var memory: GuestMemory = .{ .regions = &regions };

    var archive: image.Cpio = .init(gpa);
    defer archive.deinit();
    archive.addDirectory("dev", 0o755) catch unreachable;
    archive.addCharacterDevice("dev/console", 0o600, 5, 1) catch unreachable;
    archive.addFile("init", 0o755, guest_init) catch unreachable;
    const initrd = archive.finish() catch unreachable;
    defer gpa.free(initrd);

    var manifest: Manifest = .{};
    defer manifest.deinit(gpa);

    const layout = core.Launch.prepare(gpa, &memory, &manifest, .{
        .kernel = kernel,
        .initrd = initrd,
        // The early console and the real one, with the handover between them. That handover used to
        // be where a guest on this backend stopped, and it is not a fault in this port: the same
        // Mirage boots through it with one kernel and stops at it with another. A kernel built from
        // nixpkgs 7.2.7 stops at `bootconsole [pl11] disabled` and idles about three thousand times
        // a second forever, with nothing pending, nothing active, the port masked by the guest
        // itself, and timer interrupts arriving and being acknowledged throughout. So it waits on
        // something this side does not owe it.
        .cmdline = "console=ttyAMA0 earlycon=pl011,0x9000000",
        .ram_base = ram,
        .ram_size = ram_size,
        .cpus = cpus,
        .uart_base = uart,
        .controller = .{ .gic_v2 = .{ .cpu_base = arm64.fdt.gicv2_cpu_base } },
        // A fixed seed, because this is a test and a reproducible one is wanted
        // here. A real launch must take this from the host entropy source.
        .rng_seed = "mirage test seed, not for real use",
        // No disk on this backend yet, so the guest is not told about one. A tree that
        // names a device the VMM did not build sends the guest to read nothing.
        .block_device = true,
        // A channel back to whoever started the guest. The tree has to name it or the guest never
        // looks for it.
        .vsock = true,
        .net = true,
        .tpm = chip_on,
    }) catch |err| {
        say("cannot prepare the launch: {t}", .{err});
        std.process.exit(1);
    };

    var gic: device.Gicv2 = .{ .cpus = @min(cpus, device.Gicv2.max_cpus) };
    const interrupt_devices = gic.devices(arm64.fdt.gicd_base, arm64.fdt.gicv2_cpu_base);

    const output = gpa.alloc(u8, 4 << 20) catch unreachable;
    defer gpa.free(output);
    var sink = std.Io.Writer.fixed(output);
    var serial: device.Pl011 = .{
        .sink = &sink,
        // The real driver waits to be told there is room to send. Without a line to
        // report on, output stops the moment the early console hands over.
        .line = .{ .controller = gic.controller(), .intid = arm64.fdt.uart_intid },
    };

    // A chip only when something is there to answer it. Its driver waits out its own timeouts when
    // nothing does, which stalls the boot for minutes, so a guest with no program behind the socket is
    // given no chip at all.
    var chip: device.Tpm = .{};
    var chip_relay: device.Tpm.Relay(netmod.Socket) = .{};
    var chip_side: ?netmod.Socket = if (chip_on) netmod.Socket.connect(undefined, options.chip_socket) catch |err| blk: {
        say("nothing answers the chip at {s}: {t}", .{ options.chip_socket, err });
        break :blk null;
    } else null;

    // A network of this VMM's own. There is no passt on a Mac, so this is what gives a guest here a
    // route off the machine: the card's frames are translated and carried by sockets this process opens.
    var nat: netmod.Nat = .{
        .guest_ip = .{ 10, 0, 2, 15 },
        .guest_mac = guest_mac,
        .gateway_ip = .{ 10, 0, 2, 2 },
        .gateway_mac = .{ 0x52, 0x54, 0x00, 0x12, 0x34, 0x57 },
        .resolver = hostResolver(),
    };
    defer nat.deinit();

    // Something for the guest to reach through the gateway, on this machine's own loopback.
    var listener = Listener.open();
    defer if (listener) |*each| each.deinit();

    var card: device.virtio.Net = undefined;
    card.init(guest_mac);

    // A disk as well, built in memory like the archive. The guest is not asked to mount it: the
    // kernel reading its capacity through the queue is what proves the device works, and it says so
    // by naming `vda`. A harness gives a guest its root this way, so the path has to be real here too.
    var filesystem: image.Erofs = .init(gpa);
    defer filesystem.deinit();
    filesystem.addDirectory("dev") catch unreachable;
    filesystem.addCharacterDevice("dev/console", 5, 1) catch unreachable;
    filesystem.addFile("init", guest_init) catch unreachable;
    const disk = filesystem.finish() catch unreachable;
    defer gpa.free(disk);

    var block: device.virtio.Block = undefined;
    block.init(disk);

    // The channel back to this process. A harness talks to a guest through this and through nothing
    // else, so a guest on this backend without one is a guest nothing can reach. The device is the
    // same one the KVM side uses: it needs no system facility of its own, only guest memory and a
    // line to the controller.
    var ports = [_]u32{host_port};
    var channel: device.virtio.Vsock = undefined;
    channel.init(guest_cid, &ports);

    var devices = [_]device.Device{
        serial.device(uart),
        interrupt_devices[0],
        interrupt_devices[1],
        channel.device(arm64.fdt.vsock_base),
        block.device(arm64.fdt.virtio_base),
        card.device(arm64.fdt.net_base),
        chip.device(arm64.fdt.tpm_base),
    };
    var bus: device.Bus = .{ .devices = &devices };

    // Work that happens between exits rather than inside one. A doorbell is an mmio write that is
    // over by the time this loop sees it, so the queue is served here.
    var services = [_]device.Service{
        channel.service(arm64.fdt.vsock_intid),
        block.service(arm64.fdt.virtio_intid),
        card.service(arm64.fdt.net_intid),
    };

    const hv = machine.backend();
    const id = hv.addVcpu() catch unreachable;
    core.Launch.enter(hv, id, layout) catch unreachable;

    // The CPUs the guest starts itself, each on a thread of its own. Each makes its own CPU, because the
    // framework binds one to the thread that created it, and then waits until the guest asks for it.
    var cpu_exits = [_]u64{0} ** device.Gicv2.max_cpus;
    const shared: Shared = .{ .machine = &machine, .bus = &bus, .gic = &gic, .exits = &cpu_exits };
    var threads: [device.Gicv2.max_cpus]std.Thread = undefined;
    var started: usize = 0;
    while (started + 1 < cpus and started + 1 < device.Gicv2.max_cpus) : (started += 1) {
        threads[started] = std.Thread.spawn(.{}, driveSecondary, .{shared}) catch break;
    }

    // The loop is driven here rather than by `Launch.run` so it can count what the
    // guest did and where it was. A guest that goes quiet on this backend is the
    // thing being looked for, and the shared loop reports none of it.
    const controller = gic.controller();
    var exits: usize = 0;
    var reported: usize = 0;
    var stopped: ?backend.Backend.Exit = null;
    var waits: usize = 0;

    // What the guest said over the channel, and whether it has been answered.
    var open: ?device.virtio.Vsock.Handle = null;
    var heard: [256]u8 = undefined;
    var heard_len: usize = 0;
    var answered = false;

    // Frames each way, and how many questions about who holds an address were answered.
    var frames_in: u64 = 0;
    var frames_out: u64 = 0;
    // How long the guest has gone without saying anything while idling, and whether it has been
    // asked where it is. Asking once is enough and asking every time would bury the answer.
    var said_at: usize = 0;
    var quiet: usize = 0;
    var dumped = false;
    var timers: usize = 0;
    var raised: usize = 0;
    var acknowledged: usize = 0;
    // Where the guest was when it was doing something other than waiting. The idle
    // loop tells nothing, so those are skipped.
    var busy_pc: [6]u64 = @splat(0);
    var busy_at: usize = 0;
    // Which registers of the serial port the guest touches, and how often. A driver
    // that is waiting is waiting on one of these.
    var uart_reads: [64]u32 = @splat(0);
    var uart_writes: [64]u32 = @splat(0);

    // A signal as well as a clock, because a guest spinning inside itself makes no exits to check on.
    armDeadline(run_seconds);
    const deadline = nowMs() + run_seconds * 1000;
    while (exits < 20_000_000) : (exits += 1) {
        // A guest that has stopped getting anywhere is bounded by the clock as well as by how many times
        // it has idled. Checked every turn rather than every few thousand, because a CPU that has stopped
        // making exits would never reach a check that waits for more of them.
        if (nowMs() > deadline) {
            say("\ngave up after {d} seconds, at {d} exits and {d} idles", .{ run_seconds, exits, waits });
            break;
        }

        // Anything the guest has said since the last turn. Often, because output that is still in the
        // buffer when a guest wedges is output nobody ever sees.
        {
            const have = sink.buffered();
            if (have.len > reported) {
                emit(have[reported..]);
                reported = have.len;
            }
        }

        hold();
        const line = controller.signalled(controller.ctx, id);
        drop();
        if (line) raised += 1;
        hv.setInterrupt(id, line) catch unreachable;

        const exit = hv.run(id) catch |err| {
            const raw = machine.vcpus[id].exit;
            say("\nrun failed after {d} exits: {t}, framework returned {?}", .{ exits, err, machine.fault });
            say("  reason {d}, class 0x{x}, syndrome 0x{x}, address 0x{x}", .{
                @intFromEnum(raw.reason),
                arm64.esr.class(raw.exception.syndrome),
                raw.exception.syndrome,
                raw.exception.physical_address,
            });
            break;
        };

        if (exit != .wfi and exits % 977 == 0) {
            var here: u64 = 0;
            _ = machine.api.vcpu_get_reg(machine.vcpus[id].id, .pc, &here);
            busy_pc[busy_at % busy_pc.len] = here;
            busy_at += 1;
        }

        hold();
        defer drop();
        // Which CPU is touching the registers. The controller banks most of itself per CPU, and a memory
        // access does not say who made it.
        gic.acting = id;

        switch (exit) {
            .mmio_write => |w| {
                if (w.gpa >= uart and w.gpa < uart + 0x100) uart_writes[@intCast((w.gpa - uart) / 4)] += 1;
                bus.write(w.gpa, w.size, w.value);
            },
            .mmio_read => |r| {
                if (r.gpa >= uart and r.gpa < uart + 0x100) uart_reads[@intCast((r.gpa - uart) / 4)] += 1;
                // A read of the acknowledge register is the guest taking an
                // interrupt, which is the thing this whole path exists for.
                if (r.gpa == arm64.fdt.gicv2_cpu_base + 0x0c) acknowledged += 1;
                hv.completeMmioRead(id, bus.read(r.gpa, r.size)) catch unreachable;
            },
            .timer => {
                timers += 1;
                // This CPU's own timer. Every CPU has one, so raising it for the machine raises it for nobody.
                controller.raiseOn(controller.ctx, id, arm64.timer.virtual_intid);
            },
            .wfi => {
                waits += 1;

                // A guest that has stopped saying anything and keeps idling is the thing being looked
                // for, and where it is waiting is the one fact that has been missing. The program
                // counter alone is sampled only on exits that are not idles, so it never catches
                // this. Ask once, when the output has stood still long enough that it is not merely
                // slow.
                if (sink.buffered().len != said_at) {
                    said_at = sink.buffered().len;
                    quiet = 0;
                } else quiet += 1;

                if (quiet == 200_000 and !dumped) {
                    dumped = true;
                    whereWaiting(&machine, id, &memory, layout.entry);
                }

                // An idle guest with nothing to wake it will sit here forever, so
                // the wait is bounded and reported rather than spun on.
                if (waits > 8_000_000) {
                    say("\nthe guest waited {d} times with nothing to wake it", .{waits});
                    break;
                }
            },
            .psci => |call| switch (arm64.psci.handle(.{ .function = call.function, .args = call.args })) {
                .value => |value| hv.setRegister(id, .x0, value) catch unreachable,
                // Record what it means rather than how it arrived, which is what
                // `Launch.run` does with the same call.
                .power_off => {
                    stopped = .shutdown;
                    break;
                },
                .reset => {
                    stopped = .reset;
                    break;
                },
                .start_cpu => |wanted| startCpu(&machine, wanted.target, wanted.entry, wanted.context, id),
            },
            else => {
                stopped = exit;
                break;
            },
        }

        // Answer the guest on the channel before the devices are served, so the answer goes out on
        // this pass rather than waiting for the next exit.
        if (open == null) open = channel.accept();
        if (open) |handle| {
            const got = channel.read(handle, heard[heard_len..]);
            heard_len += got;
            if (got > 0 and !answered) {
                _ = channel.write(handle, "the host heard you\n");
                answered = true;
            }
        }

        // The driver rings a doorbell to say there is work, and the doorbell is an mmio write that is
        // over by the time this loop sees it, so the queue is served here.

        // Carry the chip's commands out to the far end and its answers back. Neither side waits.
        if (chip_side) |*link| chip_relay.carry(&chip, link);

        if (listener) |*each| each.turn();

        // Frames between the card and the translator, both ways. Nothing else is running beside this
        // test: the frames are carried by sockets this process opened.
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

        core.Launch.poll(&services, &memory, controller) catch |err| {
            say("a device refused the guest: {t}", .{err});
            break;
        };
    }
    // Where the guest stopped, and what it was sitting on. Only interesting when
    // something went wrong, and it interleaves with the guest log otherwise.
    if (stopped == null) {
        var pc: u64 = 0;
        _ = machine.api.vcpu_get_reg(machine.vcpus[id].id, .pc, &pc);
        say("\nstopped making progress at pc 0x{x}", .{pc});
        if (pc >= ram and pc + 32 < ram + ram_size) {
            const at: usize = @intCast(pc - ram - 16);
            for (0..8) |i| {
                const word = std.mem.readInt(u32, host[at + i * 4 ..][0..4], .little);
                say("  0x{x}: 0x{x:0>8}{s}", .{ ram + at + i * 4, word, if (i == 4) "   <- here" else "" });
            }
        }
    }

    emit(sink.buffered()[reported..]);
    say("=== exits {d}, waits {d}, timers {d}, line raised {d}, acknowledged {d}, absorbed {d}, stopped {?}, unmapped {d} ===", .{
        exits, waits, timers, raised, acknowledged, machine.absorbed, stopped, bus.unmapped,
    });
    say("serial: {d} bytes written, {d} dropped", .{ sink.buffered().len, serial.dropped });

    // Which registers of the serial port the guest touched. Noise on a good run,
    // and the first thing worth seeing on a bad one.
    if (stopped == null) {
        for (uart_reads, 0..) |count, index| {
            if (count > 0) say("  uart read  0x{x:0>3}: {d}", .{ index * 4, count });
        }
        for (uart_writes, 0..) |count, index| {
            if (count > 0) say("  uart write 0x{x:0>3}: {d}", .{ index * 4, count });
        }
    }

    // Every other CPU leaves its loop before anything below reads what the controller holds. A CPU still
    // running would be changing it while it is read.
    stopping.store(true, .release);
    for (threads[0..started]) |each| each.detach();

    // What the controller holds, per CPU for the banked part and once for the shared part. An interrupt
    // that was taken and never ended holds one CPU's line down for good: nothing else reaches it, it
    // waits for something that cannot arrive, and its pending bits read as empty the whole time. That
    // looks the same from outside as a CPU waiting on something else, so it has to be told apart by
    // looking.
    say("gic: distributor {}, shared enabled 0x{x}, pending 0x{x}, active 0x{x}, dropped {d}", .{
        gic.distributor_on,
        gic.enabled[1],
        gic.pending[1],
        gic.active[1],
        gic.dropped,
    });
    for (0..cpus) |which| {
        const own: u32 = @intCast(which);
        say("gic: cpu {d} signalling {}, holding {?}, exits {d}", .{
            own,
            gic.signalled(own),
            gic.holdingFor(own),
            cpu_exits[which],
        });
    }
    say("serial mask 0x{x}", .{serial.imsc});
    if (stopped == null) {
        for (busy_pc, 0..) |each, index| {
            if (each != 0) say("busy pc {d}: 0x{x}", .{ index, each });
        }
    }

    const log = sink.buffered();
    var failed = false;

    for ([_][]const u8{
        // The machine is the one this repository described.
        "Machine model: mirage",
        // The interrupt controller this repository writes was driven by the guest.
        "Root IRQ handler: gic_handle_irq",
        // The serial port this repository writes carried the console.
        "ttyAMA0 at MMIO 0x9000000",
        // The guest reached its first process, out of the archive built in memory.
        "Run /init as init proc",
        // And that process ran and said so.
        "mirage guest is alive",
        // And the channel carried a line each way. A harness talks to a guest through this, so a
        // guest that boots but cannot be spoken to is not much use.
        "channel said: the host heard you",
        // The kernel found the disk and read its capacity through the queue, which is the whole path
        // a root filesystem arrives on.
        "[vda]",
        // And a name was looked up through the network this VMM provides.
        "network: the name was answered",
        // And a connection was carried, which is what a coding session rests on.
        "stream said: the host heard your stream",
        // And a connection was carried, which is what a coding session rests on.
        "stream said: the host heard your stream",
    }) |want| {
        if (std.mem.indexOf(u8, log, want) == null) {
            say("missing from the guest log: {s}", .{want});
            failed = true;
        }
    }

    // The guest asked to stop, and the run loop honoured it.
    if (stopped == null or stopped.? != .shutdown) {
        say("the guest did not ask to power off, it stopped with {?}", .{stopped});
        failed = true;
    }

    // The guest reached a name server through a network this VMM is, on a Mac, with nothing else
    // running. That is the whole path: the card, the translation, a socket this system opened, back
    // through the controller and into the guest.
    say("net: {d} frames out, {d} in, {d} datagrams carried, {d} back, {d} in flight", .{
        frames_out,
        frames_in,
        nat.sent,
        nat.received,
        nat.inFlight(),
    });
    if (frames_out == 0) {
        say("nothing left the card", .{});
        failed = true;
    }
    if (frames_in == 0) {
        say("nothing reached the card", .{});
        failed = true;
    }
    if (nat.streams_opened == 0) {
        say("no connection was carried", .{});
        failed = true;
    }
    if (nat.streams_refused != 0) {
        say("{d} connections were reset", .{nat.streams_refused});
        failed = true;
    }
    if (nat.sent == 0 or nat.received == 0) {
        say("no datagram was carried either way", .{});
        failed = true;
    }
    if (nat.no_room != 0) {
        say("{d} translations were refused for want of room", .{nat.no_room});
        failed = true;
    }

    if (chip_on) {
        // The chip's driver attached and its commands reached whatever answers them.
        say("chip: {d} commands relayed, {d} refused, gone {}", .{
            chip_relay.answered,
            chip.refused,
            chip_relay.gone,
        });
        if (std.mem.indexOf(u8, log, "2.0 TPM (device-id 0x1") == null) {
            say("the chip driver did not attach", .{});
            failed = true;
        }
        if (chip_relay.answered == 0) {
            say("no chip command was answered", .{});
            failed = true;
        }
    }

    if (failed) std.process.exit(1);
    say("ok, linux booted to userspace under hypervisor framework", .{});
}
