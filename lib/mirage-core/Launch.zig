//! Placing a guest in memory, and dispatching what it does once it runs.
//!
//! Loading and measuring are one pass on purpose. Nothing reaches guest memory
//! without being hashed on the way in, and the manifest seals before the first
//! instruction. Measure then launch is worth nothing if anything can be measured, or
//! written, afterwards.
//!
//! This module names neither a hypervisor nor an operating system. It is given memory
//! that is already mapped and a `Backend` that is already open.

const std = @import("std");
const testing = @import("mirage-testing");
const Backend = @import("mirage-backend").Backend;
const GuestMemory = @import("mirage-memory").GuestMemory;
const attest = @import("mirage-attest");
const Manifest = attest.Manifest;
const arm64 = @import("mirage-arm64");
const device = @import("mirage-device");

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

pub const Config = struct {
    /// What `kernel` holds. Firmware and a kernel are placed differently and told different things.
    kind: Kind = .linux,
    kernel: []const u8,
    /// An initial filesystem, unpacked by the kernel into its root. Without one the
    /// kernel looks for a disk to mount instead.
    initrd: ?[]const u8 = null,
    cmdline: []const u8,
    /// Which interrupt controller the guest is told it has.
    controller: arm64.fdt.Interrupts = .gic_v3,
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
    initrd: ?arm64.fdt.Range = null,
    /// Where the list of measurements was placed, if the guest was given one.
    log: ?arm64.fdt.Range = null,
};

pub const Error = error{
    NoRoom,
    /// A device tree node name longer than the buffer that formats it.
    NoSpaceLeft,
    /// The device tree was left with a node open. This is a bug in `mirage-arm64`.
    Unbalanced,
} || std.mem.Allocator.Error || GuestMemory.Error || Manifest.Error || arm64.boot.Error;

/// Which register a launch is folded into, and the one the list of measurements names. A register the
/// guest can add to says nothing about what started it, so nothing inside the guest writes this one.
pub const launch_register = 0;

/// The device tree goes above the kernel image, far enough not to collide with it and
/// near enough for the kernel to reach it early.
const tree_alignment = 2 * 1024 * 1024;

pub fn prepare(
    gpa: std.mem.Allocator,
    memory: *GuestMemory,
    manifest: *Manifest,
    config: Config,
) Error!Layout {
    if (config.kind == .firmware) return prepareFirmware(gpa, memory, manifest, config);

    const header = try arm64.boot.parse(config.kernel);
    const entry = arm64.boot.loadAddress(config.ram_base, header);

    const occupied = @max(header.image_size, config.kernel.len);

    // The initial filesystem goes above the kernel and the device tree goes above
    // that, because the tree has to name where the filesystem starts and ends.
    var initrd: ?arm64.fdt.Range = null;
    var above = entry + occupied;
    if (config.initrd) |bytes| {
        const at = std.mem.alignForward(u64, above, tree_alignment);
        initrd = .{ .start = at, .end = at + bytes.len };
        above = at + bytes.len;
    }
    const tree_at = std.mem.alignForward(u64, above, tree_alignment);

    var room: [8]Manifest.Tag = undefined;
    const measuring = measuredTags(config, &room);

    var settings: arm64.fdt.Config = .{
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
    };

    // A guest with a chip is given the list of measurements to go with it, because a register says
    // that two launches differ and never what either of them was.
    //
    // The tree has to name where the list is, and the list holds the tree's own measurement, so
    // neither can be built first. The way out is that the tree's length does not depend on either
    // number in it, because both are written as a fixed width. So the tree is built once to learn its
    // length, the list is placed above it, and the tree is built again with the answer.
    var log: ?arm64.fdt.Range = null;
    if (config.tpm) {
        const first = try arm64.fdt.build(gpa, settings);
        const provisional = first.len;
        gpa.free(first);

        const log_at = std.mem.alignForward(u64, tree_at + provisional, tree_alignment);
        log = .{ .start = log_at, .end = log_at + attest.Log.sizeFor(measuring) };
        settings.log = log;
    }

    const blob = try arm64.fdt.build(gpa, settings);
    defer gpa.free(blob);

    const end = config.ram_base + config.ram_size;
    if (entry + occupied > end) return Error.NoRoom;
    if (tree_at + blob.len > end) return Error.NoRoom;
    if (log) |where| {
        if (where.end > end) return Error.NoRoom;
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

    return .{ .entry = entry, .device_tree = tree_at, .initrd = initrd, .log = log };
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
) Error!Layout {
    const where = config.kind.firmware;
    if (config.kernel.len > where.len) return Error.NoRoom;

    var settings: arm64.fdt.Config = .{
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
    var log: ?arm64.fdt.Range = null;
    if (config.tpm) {
        const first = try arm64.fdt.build(gpa, settings);
        const provisional = first.len;
        gpa.free(first);

        const log_at = std.mem.alignForward(u64, config.ram_base + provisional, tree_alignment);
        log = .{ .start = log_at, .end = log_at + attest.Log.sizeFor(measuring) };
        settings.log = log;
    }

    const blob = try arm64.fdt.build(gpa, settings);
    defer gpa.free(blob);

    if (blob.len > config.ram_size) return Error.NoRoom;
    if (log) |place| {
        if (place.end > config.ram_base + config.ram_size) return Error.NoRoom;
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

    return .{ .entry = where.at, .device_tree = config.ram_base, .log = log };
}

/// Put the guest at its entry point. The protocol wants the device tree address in
/// `x0` and the other three argument registers zeroed.
pub fn enter(hv: Backend, vcpu: Backend.VcpuId, layout: Layout) Backend.Error!void {
    try hv.setRegister(vcpu, .pc, layout.entry);
    try hv.setRegister(vcpu, .x0, layout.device_tree);
    try hv.setRegister(vcpu, .x1, 0);
    try hv.setRegister(vcpu, .x2, 0);
    try hv.setRegister(vcpu, .x3, 0);
}

pub const Reason = enum {
    shutdown,
    reset,
    /// Whoever started the guest asked for the loop to end. A deadline that ran out and
    /// an operator who pressed a key both arrive this way.
    stopped,
};

/// What a run needs beyond the hypervisor itself.
pub const Run = struct {
    bus: *device.Bus,
    /// Guest memory, so a device with a queue can reach what the driver published.
    /// Only needed when there are services.
    memory: ?*GuestMemory = null,
    controller: ?device.Controller = null,
    /// Devices with work that happens between exits.
    services: []const device.Service = &.{},
    /// Give up after this many exits. A guest that spins is a guest that never comes
    /// back, and a caller that cannot stop is one that has to be killed.
    exits: u64 = 1 << 32,
    /// Work that belongs to whoever started the guest, run after every exit and before
    /// the devices are served. A channel has two ends and this module owns neither.
    host: ?Host = null,
    /// Who starts the other CPUs. Left out by a caller whose hypervisor starts them itself, and then
    /// a guest that asks is told the call is not supported, which is honest: nothing here can.
    power: ?Power = null,
    /// Something to hold while anything shared is touched, for a machine whose CPUs run at the same
    /// time. A machine with one CPU passes none: there is nothing to race with, and a lock nobody
    /// contends for still costs something on every exit.
    guard: ?Guard = null,
};

/// What a caller with more than one CPU hands over so they can share their devices.
///
/// This module does not start the threads and does not know what a thread is: a machine may run its
/// CPUs one per thread, or take turns, or be firmware with no threads at all. So the lock comes from
/// whoever runs them, and all this does is hold it at the right moments.
///
/// One lock for everything shared is coarse on purpose. A guest spends its time running instructions
/// rather than leaving, so it is taken rarely, and a lock for each device would let two CPUs be inside
/// one device's queues at once, which no device here is written for.
pub const Guard = struct {
    ctx: *anyopaque,
    lock: *const fn (ctx: *anyopaque) void,
    unlock: *const fn (ctx: *anyopaque) void,
};

/// Who starts the other CPUs, for a hypervisor that does not do it itself.
///
/// The guest asks through the power interface, and on a backend whose hypervisor answers that in the
/// kernel this is never reached. Where it is reached, starting a CPU means putting an address in its
/// program counter and letting it run, and whoever runs the CPUs is the only one who can: this
/// module does not know what a thread is.
pub const Power = struct {
    ctx: *anyopaque,
    /// Returns whether the CPU is now running. A target this machine does not have, or one that is
    /// running already, is answered no and the guest is told so.
    start: *const fn (ctx: *anyopaque, target: u64, entry: u64, context: u64) bool,
};

pub const Host = struct {
    ctx: *anyopaque,
    /// Returns whether the guest should carry on. A clock belongs to whoever started the
    /// guest, not to this module, so a deadline is enforced from here and not from an
    /// exit count that means nothing in seconds.
    step: *const fn (ctx: *anyopaque) bool,
};

pub const RunError = Backend.Error || device.Service.Error || error{
    /// The guest used every exit it was given. Either it is spinning, or the caller
    /// asked for fewer exits than a boot takes.
    ExitsExhausted,
};

/// Run until the guest stops, it exhausts its budget, or a device finds the guest has
/// published something impossible.
pub fn run(hv: Backend, vcpu: Backend.VcpuId, options: Run) RunError!Reason {
    // A service reaches guest memory, so asking for one without memory is a mistake
    // in the caller rather than something the guest can cause.
    std.debug.assert(options.services.len == 0 or options.memory != null);

    var left = options.exits;
    while (left > 0) : (left -= 1) {
        // The line is set before the guest is entered, so it sees the state the
        // controller is in rather than the state it was in an exit ago. A backend
        // whose controller lives in the kernel ignores this.
        if (options.controller) |each| {
            take(options);
            const signalled = each.signalled(each.ctx, vcpu);
            release(options);
            try hv.setInterrupt(vcpu, signalled);
        }

        // Entering the guest is the one thing that must not be done holding anything: it does not
        // come back until the guest leaves, and a CPU waiting inside the hypervisor holding the lock
        // would stop every other CPU getting at a device.
        switch (try hv.run(vcpu)) {
            .mmio_write => |write| {
                take(options);
                defer release(options);
                acting(options, vcpu);
                options.bus.write(write.gpa, write.size, write.value);
            },
            .mmio_read => |read| {
                take(options);
                acting(options, vcpu);
                const value = options.bus.read(read.gpa, read.size);
                release(options);
                try hv.completeMmioRead(vcpu, value);
            },
            .shutdown => return .shutdown,
            .reset => return .reset,

            // KVM answers these in the kernel and never sends one. Apple answers
            // none of them, so they are answered here and the guest cannot tell
            // which hypervisor it is on.
            .psci => |call| switch (arm64.psci.handle(.{ .function = call.function, .args = call.args })) {
                .value => |value| try hv.setRegister(vcpu, .x0, value),
                .power_off => return .shutdown,
                .reset => return .reset,
                // Starting a CPU belongs to whoever runs them. A caller that gave nobody to ask
                // answers no, which is honest: a guest told no runs on the CPU it has.
                .start_cpu => |asked| {
                    const answer = if (options.power) |who| once: {
                        take(options);
                        defer release(options);
                        break :once who.start(who.ctx, asked.target, asked.entry, asked.context);
                    } else false;
                    try hv.setRegister(vcpu, .x0, if (answer) arm64.psci.success else arm64.psci.not_supported);
                },
            },

            // Only Apple sends this. The program counter has already moved past
            // the instruction, so the guest carries on around its idle loop and
            // makes progress whenever an interrupt arrives.
            .wfi => {},

            // Only Apple sends this too, because KVM delivers the timer interrupt
            // itself. Here the VMM has to.
            .timer => if (options.controller) |each| {
                take(options);
                defer release(options);
                // The timer belongs to this CPU and to no other, so it is raised for this one.
                each.raiseOn(each.ctx, vcpu, arm64.timer.virtual_intid);
            },

            // The guest was taken back so this loop could run. Serving the devices and
            // giving the host its turn is the whole point, and both happen below.
            .interrupted => {},
        }

        // The host gets its turn before the devices are served, so anything it hands to
        // a device goes out on this pass rather than waiting for the next exit.
        take(options);
        defer release(options);
        if (options.host) |each| {
            if (!each.step(each.ctx)) return .stopped;
        }
        if (options.memory) |memory| try poll(options.services, memory, options.controller);
    }
    return RunError.ExitsExhausted;
}

/// Say which CPU is about to touch a device, for a controller that banks part of itself per CPU.
/// Held under the same lock as the access it belongs to, or another CPU could say so in between.
fn acting(options: Run, vcpu: Backend.VcpuId) void {
    const each = options.controller orelse return;
    each.acting(each.ctx, vcpu);
}

fn take(options: Run) void {
    if (options.guard) |each| each.lock(each.ctx);
}

fn release(options: Run) void {
    if (options.guard) |each| each.unlock(each.ctx);
}

/// Serve every device that has work waiting and move its interrupt line to match.
/// Written once because a run loop that drives its own exits still needs this step,
/// and two copies of it drift.
pub fn poll(
    services: []const device.Service,
    memory: *GuestMemory,
    controller: ?device.Controller,
) device.Service.Error!void {
    for (services) |each| {
        const asserted = try each.poll(each.ctx, memory);
        const line = controller orelse continue;
        if (asserted) line.raise(line.ctx, each.intid) else line.lower(line.ctx, each.intid);
    }
}
const ram_base = 0x4000_0000;

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
        .{ .gpa = ram_base, .len = ram.len, .backing = .{ .shared = ram } },
    };
    var memory: GuestMemory = .{ .regions = &regions };
    var manifest: Manifest = .{};

    const layout = try prepare(gpa, &memory, &manifest, .{
        .kernel = kernel,
        .cmdline = "console=ttyAMA0",
        .ram_base = ram_base,
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

    try testing.expectEqual(@as(u64, ram_base), layout.entry);
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

test "the run loop carries an mmio write to the bus and stops on shutdown" {
    var mock: Backend.Mock = .init(&.{
        .{ .mmio_write = .{ .gpa = 0x0900_0000, .size = .byte, .value = 'k' } },
        .shutdown,
    });
    const hv = mock.backend();
    const id = try hv.addVcpu();

    var buffer: [8]u8 = undefined;
    var sink = std.Io.Writer.fixed(&buffer);
    var serial: device.Pl011 = .{ .sink = &sink };
    var devices = [_]device.Device{serial.device(0x0900_0000)};
    var bus: device.Bus = .{ .devices = &devices };

    try testing.expectEqual(Reason.shutdown, try run(hv, id, .{ .bus = &bus }));
    try testing.expectEqualSlices(u8, "k", sink.buffered());
}

test "the run loop answers an mmio read with what the device gave" {
    var mock: Backend.Mock = .init(&.{
        .{ .mmio_read = .{ .gpa = 0x0900_0018, .size = .word, .dest = 0 } },
        .shutdown,
    });
    const hv = mock.backend();
    const id = try hv.addVcpu();

    var buffer: [8]u8 = undefined;
    var sink = std.Io.Writer.fixed(&buffer);
    var serial: device.Pl011 = .{ .sink = &sink };
    var devices = [_]device.Device{serial.device(0x0900_0000)};
    var bus: device.Bus = .{ .devices = &devices };

    _ = try run(hv, id, .{ .bus = &bus });
    // The flag register says the transmitter is empty and nothing has arrived.
    try testing.expectEqual(@as(u64, (1 << 7) | (1 << 4)), mock.last_completion.?);
}

test "a guest asking to power off stops the loop" {
    var mock: Backend.Mock = .init(&.{
        .{ .psci = .{ .function = arm64.psci.function.system_off, .args = @splat(0) } },
    });
    const hv = mock.backend();
    const id = try hv.addVcpu();

    var devices = [_]device.Device{};
    var bus: device.Bus = .{ .devices = &devices };

    try testing.expectEqual(Reason.shutdown, try run(hv, id, .{ .bus = &bus }));
}

test "a guest asking for the psci version is answered and carries on" {
    var mock: Backend.Mock = .init(&.{
        .{ .psci = .{ .function = arm64.psci.function.version, .args = @splat(0) } },
        .shutdown,
    });
    const hv = mock.backend();
    const id = try hv.addVcpu();

    var devices = [_]device.Device{};
    var bus: device.Bus = .{ .devices = &devices };

    _ = try run(hv, id, .{ .bus = &bus });

    // The answer goes back in x0, which is where the guest looks for it.
    try testing.expectEqual(arm64.psci.version_number, mock.register(id, .x0));
}

test "a guest asking to start a second cpu is told no rather than ignored" {
    var mock: Backend.Mock = .init(&.{
        .{ .psci = .{ .function = arm64.psci.function.cpu_on, .args = .{ 1, 0x4008_0000, 0 } } },
        .shutdown,
    });
    const hv = mock.backend();
    const id = try hv.addVcpu();

    var devices = [_]device.Device{};
    var bus: device.Bus = .{ .devices = &devices };

    _ = try run(hv, id, .{ .bus = &bus });
    try testing.expectEqual(arm64.psci.not_supported, mock.register(id, .x0));
}

test "the interrupt line follows what the controller says" {
    var gic: device.Gicv2 = .{};
    var on_bus = gic.devices(0x0800_0000, 0x0801_0000);
    var bus: device.Bus = .{ .devices = &on_bus };

    // Turn the controller on and let one interrupt through, the way a driver does.
    bus.write(0x0800_0000, .word, 1);
    bus.write(0x0801_0000, .word, 1);
    bus.write(0x0801_0004, .word, 0xff);
    bus.write(0x0800_0100 + 4, .word, 1 << 16);
    // Which CPU it may go to. A driver writes this, and an interrupt with no target reaches nobody.
    bus.write(0x0800_0800 + 48, .byte, 1);
    gic.raise(48);

    var mock: Backend.Mock = .init(&.{.shutdown});
    const hv = mock.backend();
    const id = try hv.addVcpu();

    _ = try run(hv, id, .{ .bus = &bus, .controller = gic.controller() });

    // The guest was entered with the line raised, because the controller had an
    // interrupt waiting before the first instruction.
    try std.testing.expect(mock.interrupt);
}

test "the interrupt line is released when the controller has nothing waiting" {
    var gic: device.Gicv2 = .{};
    var on_bus = gic.devices(0x0800_0000, 0x0801_0000);
    var bus: device.Bus = .{ .devices = &on_bus };

    var mock: Backend.Mock = .init(&.{.shutdown});
    mock.interrupt = true;
    const hv = mock.backend();
    const id = try hv.addVcpu();

    _ = try run(hv, id, .{ .bus = &bus, .controller = gic.controller() });
    try std.testing.expect(!mock.interrupt);
}

test "a timer exit becomes the timer interrupt in the controller" {
    var gic: device.Gicv2 = .{};
    var on_bus = gic.devices(0x0800_0000, 0x0801_0000);
    var bus: device.Bus = .{ .devices = &on_bus };

    bus.write(0x0800_0000, .word, 1);
    bus.write(0x0801_0000, .word, 1);
    bus.write(0x0801_0004, .word, 0xff);
    // Enable the timer interrupt, which is private to this CPU and numbered 27.
    bus.write(0x0800_0100, .word, @as(u64, 1) << arm64.timer.virtual_intid);

    var mock: Backend.Mock = .init(&.{ .timer, .shutdown });
    const hv = mock.backend();
    const id = try hv.addVcpu();

    _ = try run(hv, id, .{ .bus = &bus, .controller = gic.controller() });

    // Raised by the loop, then acknowledged here to prove it really arrived.
    try testing.expectEqual(@as(u64, arm64.timer.virtual_intid), bus.read(0x0801_000c, .word));
}

test "waiting for an interrupt does not end the run" {
    // A guest that goes idle is not a guest that has stopped. Ending the loop here
    // would kill every kernel that reaches its idle loop, which is all of them.
    var mock: Backend.Mock = .init(&.{ .wfi, .wfi, .shutdown });
    const hv = mock.backend();
    const id = try hv.addVcpu();

    var devices = [_]device.Device{};
    var bus: device.Bus = .{ .devices = &devices };

    try testing.expectEqual(Reason.shutdown, try run(hv, id, .{ .bus = &bus }));
}

test "a guest that never stops runs out of the exits it was given" {
    // The script never reaches a shutdown, so the only way out is the budget. A run
    // loop without one has to be killed from outside, which is how a stray guest is
    // left behind.
    var mock: Backend.Mock = .init(&.{ .wfi, .wfi, .wfi, .wfi });
    const hv = mock.backend();
    const id = try hv.addVcpu();

    var devices = [_]device.Device{};
    var bus: device.Bus = .{ .devices = &devices };

    try testing.expectError(error.ExitsExhausted, run(hv, id, .{ .bus = &bus, .exits = 2 }));
}

test "a service moves the interrupt line to match what the device has outstanding" {
    var storage: [device.virtio.Block.sector_size]u8 = @splat(0);
    var block: device.virtio.Block = undefined;
    block.init(&storage);

    var gic: device.Gicv2 = .{};
    var on_bus = gic.devices(0x0800_0000, 0x0801_0000);
    var bus: device.Bus = .{ .devices = &on_bus };

    // Turn the controller on and let the virtio interrupt through, the way a driver
    // does. It is number 48, because a shared interrupt 16 in the tree is 32 higher
    // to the controller.
    bus.write(0x0800_0000, .word, 1);
    bus.write(0x0801_0000, .word, 1);
    bus.write(0x0801_0004, .word, 0xff);
    bus.write(0x0800_0100 + 4, .word, 1 << 16);
    // Which CPU it may go to. A driver writes this, and an interrupt with no target reaches nobody.
    bus.write(0x0800_0800 + 48, .byte, 1);

    var ram: [4096]u8 = @splat(0);
    var regions = [_]GuestMemory.Region{
        .{ .gpa = ram_base, .len = ram.len, .backing = .{ .shared = &ram } },
    };
    var memory: GuestMemory = .{ .regions = &regions };
    var services = [_]device.Service{block.service(arm64.fdt.virtio_intid)};

    // The device published nothing, so the line has to be released rather than left
    // wherever it was. A level that is never lowered interrupts the guest forever.
    gic.raise(arm64.fdt.virtio_intid);
    try poll(&services, &memory, gic.controller());
    try std.testing.expect(!gic.signalled(0));

    // Now the device has something outstanding.
    block.mmio.raise();
    try poll(&services, &memory, gic.controller());
    try std.testing.expect(gic.signalled(0));
}

test "the host gets a turn after every exit" {
    // A device that carries a channel is useless if the other end never runs. This is
    // where the other end runs.
    var mock: Backend.Mock = .init(&.{ .wfi, .wfi, .shutdown });
    const hv = mock.backend();
    const id = try hv.addVcpu();

    var devices = [_]device.Device{};
    var bus: device.Bus = .{ .devices = &devices };

    var turns: usize = 0;
    const Counter = struct {
        fn step(ctx: *anyopaque) bool {
            const count: *usize = @ptrCast(@alignCast(ctx));
            count.* += 1;
            return true;
        }
    };

    _ = try run(hv, id, .{
        .bus = &bus,
        .host = .{ .ctx = &turns, .step = Counter.step },
    });

    // Two exits before the shutdown, and the shutdown returns without another turn.
    try testing.expectEqual(@as(usize, 2), turns);
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
        .{ .gpa = ram_base, .len = ram.len, .backing = .{ .shared = ram } },
    };
    var memory: GuestMemory = .{ .regions = &regions };
    var manifest: Manifest = .{};
    defer manifest.deinit(gpa);

    _ = try prepare(gpa, &memory, &manifest, .{
        .kernel = kernel,
        .cmdline = cmdline,
        .ram_base = ram_base,
        .ram_size = ram.len,
        .cpus = 1,
        .uart_base = 0x0900_0000,
    });
    return manifest.root();
}

test "a host that says to stop ends the run without the guest asking" {
    // A guest that has wedged never asks to stop, and an exit count says nothing about
    // how long it has been wedged for. Whoever started it holds the clock.
    var mock: Backend.Mock = .init(&.{ .wfi, .wfi, .wfi, .shutdown });
    const hv = mock.backend();
    const id = try hv.addVcpu();

    var devices = [_]device.Device{};
    var bus: device.Bus = .{ .devices = &devices };

    var left: usize = 2;
    const Deadline = struct {
        fn step(ctx: *anyopaque) bool {
            const count: *usize = @ptrCast(@alignCast(ctx));
            if (count.* == 0) return false;
            count.* -= 1;
            return true;
        }
    };

    const reason = try run(hv, id, .{
        .bus = &bus,
        .host = .{ .ctx = &left, .step = Deadline.step },
    });
    try testing.expectEqual(Reason.stopped, reason);
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
        .{ .gpa = ram_base, .len = ram.len, .backing = .{ .shared = ram } },
    };
    var memory: GuestMemory = .{ .regions = &regions };
    var manifest: Manifest = .{};
    defer manifest.deinit(gpa);

    const image = [_]u8{ 0x11, 0x22, 0x33, 0x44 } ** 16;
    const layout = try prepare(gpa, &memory, &manifest, .{
        .kind = .{ .firmware = .{ .at = flash_at, .len = flash.len } },
        .kernel = &image,
        .cmdline = "",
        .ram_base = ram_base,
        .ram_size = ram.len,
        .cpus = 1,
        .uart_base = 0x0900_0000,
    });

    // Entered at its own first instruction, not at an address taken from a header it does not have.
    try testing.expectEqual(@as(u64, flash_at), layout.entry);
    try testing.expectEqualSlices(u8, &image, flash[0..image.len]);

    // The tree goes at the start of memory, because firmware looks there rather than being told.
    try testing.expectEqual(@as(u64, ram_base), layout.device_tree);
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
        .{ .gpa = ram_base, .len = ram.len, .backing = .{ .shared = ram } },
    };
    var memory: GuestMemory = .{ .regions = &regions };
    var manifest: Manifest = .{};
    defer manifest.deinit(gpa);

    // A window smaller than the image. Writing it anyway would run past the end of what was mapped.
    const image = [_]u8{0xaa} ** 128;
    try testing.expectError(Error.NoRoom, prepare(gpa, &memory, &manifest, .{
        .kind = .{ .firmware = .{ .at = 0x1000_0000, .len = 64 } },
        .kernel = &image,
        .cmdline = "",
        .ram_base = ram_base,
        .ram_size = ram.len,
        .cpus = 1,
        .uart_base = 0x0900_0000,
    }));
}
