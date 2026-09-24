//! Stops a running guest, writes down everything it holds, puts it into a machine that has
//! never run, and lets it carry on.
//!
//! This is the whole of snapshot and resume in one test, because the parts only mean something
//! together: registers without memory resume into nothing, and memory without registers resumes
//! into whatever the new vCPU happened to start with.
//!
//! What this test is for is finding out what is still missing. A guest that carries on to
//! userspace after being moved says the state that was carried was enough. A guest that stops
//! says which part was not.
//!
//! **It found something, and then it found the fix.** Before the interrupt controller's state was
//! carried, a guest moved after about twelve thousand exits would stop dead at
//! `bootconsole [pl11] disabled`, where the serial driver stops polling the port and starts
//! waiting for its interrupt. Carrying the controller as well fixed it, and this test is what
//! said so. Measured on the Altra, a guest now moves at any point from three thousand to thirty
//! thousand exits, which is most of its boot.
//!
//! The default is past the console handover on purpose, because that is where it used to fail.

const std = @import("std");
const core = @import("mirage-core");
const backend = @import("mirage-backend");
const device = @import("mirage-device");
const arm64 = @import("mirage-arm64");
const GuestMemory = @import("mirage-memory").GuestMemory;
const Manifest = @import("mirage-attest").Manifest;
const image = @import("mirage-image");
const linux = std.os.linux;

const options = @import("boot-options");
const guest_init = @embedFile("guest-init");

const ram_base = 0x4000_0000;
/// Smaller than the boot test uses, because this one copies all of it twice.
const ram_size = 128 << 20;
const uart_base = 0x0900_0000;

/// Where the guest is stopped and moved. Far enough in that the kernel is running and has
/// touched its devices, and early enough that it has not finished.
const move_after = options.move_after;

fn onAlarm(_: linux.SIG) callconv(.c) void {}

fn armTicks(interval_ms: isize) void {
    const act: linux.Sigaction = .{
        .handler = .{ .handler = onAlarm },
        .mask = std.mem.zeroes(linux.sigset_t),
        .flags = 0,
    };
    _ = linux.sigaction(.ALRM, &act, null);
    // Microseconds, whatever the field is called. See the comment in `test/boot.zig`.
    const every: linux.timespec = .{ .sec = 0, .nsec = interval_ms * std.time.us_per_ms };
    const spec: linux.itimerspec = .{ .it_interval = every, .it_value = every };
    _ = linux.setitimer(@intFromEnum(linux.ITIMER.REAL), &spec, null);
}

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

/// Everything one guest holds. The device state is here by value because every device in this
/// repository is a plain struct whose only outside reference is a guest physical address, and
/// those mean the same thing in the machine it moves to.
const Snapshot = struct {
    /// Every register of the vCPU, as the backend writes them.
    registers: []u8,
    /// All of guest memory.
    memory: []u8,
    /// What the guest set in the interrupt controller.
    controller: []u8,
    /// The serial port, and the disk's queue.
    serial: device.Pl011,
    block: device.virtio.Block,
};

/// One guest, and the machine it runs on.
const Running = struct {
    machine: backend.kvm.Machine,
    gic: backend.kvm.Gic,
    regions: [1]GuestMemory.Region,
    memory: GuestMemory,
    vcpu: backend.Backend.VcpuId,

    fn start(self: *Running) !void {
        self.machine = backend.kvm.Machine.create(std.testing.allocator, 1) catch |err| switch (err) {
            error.NoKvm => return error.SkipZigTest,
            else => return err,
        };

        const region = try self.machine.vm.addMemory(ram_base, ram_size, .shared);
        self.regions = .{region};
        self.memory = .{ .regions = &self.regions };

        const hv = self.machine.backend();
        self.vcpu = try hv.addVcpu();

        // Every vCPU has to exist before the controller is initialised, in the machine a guest
        // moves to exactly as in the one it came from.
        self.gic = try backend.kvm.Gic.create(
            &self.machine.vm,
            1,
            arm64.fdt.gicd_base,
            arm64.fdt.gicr_base,
        );
    }

    fn stop(self: *Running) void {
        self.gic.deinit();
        self.machine.deinit();
    }
};

/// Run until the exit budget is spent or the guest stops. Returns what stopped it.
fn runFor(
    place: *Running,
    bus: *device.Bus,
    services: []const device.Service,
    budget: usize,
    sink: *std.Io.Writer,
    deadline: i64,
) !?backend.Backend.Exit {
    const hv = place.machine.backend();
    var exits: usize = 0;
    while (exits < budget) : (exits += 1) {
        if (exits % 2048 == 0 and nowMs() > deadline) break;

        const what = hv.run(place.vcpu) catch |err| {
            std.debug.print("\nrun failed after {d} exits: {t}, kvm said {?}\n", .{
                exits,
                err,
                place.machine.fault,
            });
            return error.GuestFaulted;
        };
        switch (what) {
            .mmio_write => |w| bus.write(w.gpa, w.size, w.value),
            .mmio_read => |r| try hv.completeMmioRead(place.vcpu, bus.read(r.gpa, r.size)),
            .interrupted => {},
            else => return what,
        }
        try core.Launch.poll(services, &place.memory, place.gic.controller());
        if (sink.buffered().len + 512 > sink.buffer.len) break;
    }
    return null;
}

test "a guest carries on in a machine it did not start in" {
    const gpa = std.testing.allocator;

    const kernel = (try mapKernel()) orelse return error.SkipZigTest;
    defer std.posix.munmap(kernel);

    var first: Running = undefined;
    try first.start();
    // Stopped by hand rather than by defer, because it has to go before the second one starts.
    var first_open = true;
    defer if (first_open) first.stop();

    var manifest: Manifest = .{};
    defer manifest.deinit(gpa);

    var archive: image.Cpio = .init(gpa);
    defer archive.deinit();
    try archive.addDirectory("dev", 0o755);
    try archive.addCharacterDevice("dev/console", 0o600, 5, 1);
    try archive.addFile("init", 0o755, guest_init);
    const initrd = try archive.finish();
    defer gpa.free(initrd);

    const disk = try gpa.alloc(u8, 1 << 20);
    defer gpa.free(disk);
    @memset(disk, 0);

    const layout = try core.Launch.prepare(gpa, &first.memory, &manifest, .{
        .kernel = kernel,
        .initrd = initrd,
        .rng_seed = "mirage snapshot seed, not for real use",
        .cmdline = "console=ttyAMA0 earlycon=pl011,0x9000000",
        .ram_base = ram_base,
        .ram_size = ram_size,
        .cpus = 1,
        .uart_base = uart_base,
    });

    // One log for both halves of the run, so what the guest said before and after the move reads
    // as one boot.
    const output = try gpa.alloc(u8, 64 << 10);
    defer gpa.free(output);
    var sink = std.Io.Writer.fixed(output);

    var serial: device.Pl011 = .{ .sink = &sink };
    var block: device.virtio.Block = undefined;
    block.init(disk);

    var devices = [_]device.Device{
        serial.device(uart_base),
        block.device(arm64.fdt.virtio_base),
    };
    var bus: device.Bus = .{ .devices = &devices };
    var services = [_]device.Service{block.service(arm64.fdt.virtio_intid)};

    try core.Launch.enter(first.machine.backend(), first.vcpu, layout);
    armTicks(10);

    // Run far enough that the kernel is up and has touched its devices.
    const before = try runFor(&first, &bus, &services, move_after, &sink, nowMs() + 10_000);
    if (before) |early| {
        std.debug.print("\nthe guest stopped before it could be moved: {t}\n", .{early});
        return error.StoppedTooEarly;
    }
    const said_before = sink.buffered().len;
    try std.testing.expect(said_before > 0);

    // Write down everything it holds.
    var taken: Snapshot = .{
        .registers = undefined,
        .controller = undefined,
        .memory = undefined,
        .serial = serial,
        .block = block,
    };

    const cpu = &first.machine.vcpus[first.vcpu];
    const count = try cpu.registerCount();
    const ids_buffer = try gpa.alloc(u64, @intCast(count + 1));
    defer gpa.free(ids_buffer);
    const ids = try cpu.registerList(ids_buffer);

    taken.registers = try gpa.alloc(u8, try backend.kvm.Vcpu.State.size(cpu, ids_buffer));
    defer gpa.free(taken.registers);
    const written = try cpu.save(try cpu.registerList(ids_buffer), taken.registers);
    try std.testing.expectEqual(taken.registers.len, written);

    taken.memory = try gpa.alloc(u8, ram_size);
    defer gpa.free(taken.memory);
    @memcpy(taken.memory, try first.memory.slice(ram_base, ram_size));

    // The interrupt controller. Without this a guest that has programmed it waits for an
    // interrupt that can no longer arrive, which is what moving late used to look like.
    taken.controller = try gpa.alloc(u8, backend.kvm.Gic.State.size(1));
    defer gpa.free(taken.controller);
    const controller_bytes = try first.gic.save(1, taken.controller);
    const refused_reads = first.gic.refused_reads;

    // Everything above goes through the snapshot format rather than being handed over directly,
    // so what a caller would write to a file is what is put back below.
    const queue_state = [_]core.Snapshot.QueueState{.of(block.queues[0])};
    // One CPU here, and its run state, because a snapshot carries both. A guest with several of them is
    // driven from threads, which is the command line's work rather than this test's.
    const running = [_]u8{@intFromBool(try first.machine.vcpus[first.vcpu].runState() == backend.kvm.Vcpu.runnable)};
    try std.testing.expect(running[0] == 1);

    const parts: core.Snapshot.Parts = .{
        .ram_base = ram_base,
        .memory = taken.memory,
        .registers = taken.registers[0..written],
        .cpus = 1,
        .running = &running,
        .controller = taken.controller[0..controller_bytes],
        .queues = &queue_state,
    };
    const file = try gpa.alloc(u8, core.Snapshot.size(parts));
    defer gpa.free(file);
    const file_bytes = try core.Snapshot.write(parts, file);

    // The machine it came from goes away entirely, so nothing below can be carried by accident.
    first.stop();
    first_open = false;

    var second: Running = undefined;
    try second.start();
    defer second.stop();

    // Read it back the way a caller would read it out of a file, so a header this code wrote and
    // cannot read again would be caught here rather than by whoever tried to resume next week.
    var back_queues: [core.Snapshot.max_queues]core.Snapshot.QueueState = undefined;
    const read_back = try core.Snapshot.parse(file[0..file_bytes], &back_queues);
    try std.testing.expectEqual(@as(u64, ram_base), read_back.ram_base);

    @memcpy(try second.memory.slice(ram_base, ram_size), read_back.memory);

    const moved = &second.machine.vcpus[second.vcpu];
    const restored = try moved.load(read_back.registers);
    try std.testing.expectEqual(ids.len, restored.written + restored.refused);

    const put_back = try second.gic.load(read_back.controller);
    try std.testing.expect(put_back > 0);

    // The devices come back by value. Their queues are guest physical addresses, which mean the
    // same thing in this machine as in the last one.
    serial = taken.serial;
    serial.sink = &sink;
    block = taken.block;
    // Where the device had reached in its ring, which nothing in guest memory records.
    read_back.queues[0].into(&block.queues[0]);
    devices[0] = serial.device(uart_base);
    devices[1] = block.device(arm64.fdt.virtio_base);
    services[0] = block.service(arm64.fdt.virtio_intid);

    // And on it goes, in a machine that has never run.
    const after = try runFor(&second, &bus, &services, 4_000_000, &sink, nowMs() + 15_000);

    const log = sink.buffered();
    std.debug.print(
        "\n=== {d} bytes before the move, {d} after, {d} registers and {d} controller attributes " ++
            "put back, {d} reads and {d} writes refused, stopped {?t} ===\n{s}\n=== end ===\n",
        .{
            said_before,
            log.len - said_before,
            restored.written,
            put_back,
            refused_reads,
            second.gic.refused_writes,
            after,
            log,
        },
    );

    // It said something new, so the vCPU really ran in the machine it was moved to.
    try std.testing.expect(log.len > said_before);

    // And it got all the way to userspace and asked to stop, which is what says the state that
    // was carried was enough.
    try std.testing.expect(std.mem.indexOf(u8, log, "mirage guest is alive") != null);
    try std.testing.expect(after != null);
    try std.testing.expectEqual(backend.Backend.Exit.shutdown, after.?);
}
