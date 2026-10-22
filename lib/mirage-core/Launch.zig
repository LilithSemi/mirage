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
const backend_lib = @import("mirage-backend");
const Backend = backend_lib.Backend;
const GuestMemory = @import("mirage-memory").GuestMemory;
const attest = @import("mirage-attest");
const Manifest = attest.Manifest;
const arm64 = @import("mirage-arm64");
const arch = @import("mirage-arch");
const device = @import("mirage-device");

/// Launching a guest of the architecture `Guest`, a module such as `mirage-arm64`. What a guest is
/// told, where it is placed, how it is entered and how its power calls are answered are properties of
/// that architecture, and none of them is a property of the host: a translator runs a guest the host
/// is not. The names below this one are the same for every guest.
pub fn For(comptime Guest: type) type {
    return struct {
        const Of = @This();
        const B = backend_lib.For(Guest);

        /// What is being started, named in the terms of the architecture this is built for. A Linux kernel
        /// is placed where its header asks; firmware is placed where it was built to run.
        pub const Kind = Guest.boot.Kind;

        /// The launch request. Its fields are the architecture's own, because what a guest is told it has and
        /// where it sits are properties of the machine. The runner fills the ones that matter to it; the rest
        /// take their defaults.
        pub const Config = Guest.boot.Config;

        /// Where the guest starts and where it finds what it was told about. An architecture reads these back
        /// out when it enters the guest, so neither this module nor the runner names what they mean.
        pub const Layout = Guest.boot.Layout;

        pub const Error = Guest.boot.PrepareError;

        /// Place the guest in memory and measure every input on the way in, the way the architecture under
        /// this build asks. Loading and measuring are one pass on purpose: nothing reaches guest memory
        /// without being hashed, and the manifest seals before the first instruction.
        pub fn prepare(
            gpa: std.mem.Allocator,
            memory: *GuestMemory,
            manifest: *Manifest,
            config: Of.Config,
        ) Of.Error!Of.Layout {
            return Guest.boot.prepare(gpa, memory, manifest, config);
        }

        /// Put the guest at its entry point, the way the architecture under this build asks.
        pub fn enter(hv: B, vcpu: B.VcpuId, layout: Of.Layout) B.Error!void {
            try Guest.enter(hv, vcpu, layout);
        }

        pub const RunError = B.Error || device.Service.Error || error{
            /// The guest used every exit it was given. Either it is spinning, or the caller
            /// asked for fewer exits than a boot takes.
            ExitsExhausted,
        };

        /// Run until the guest stops, it exhausts its budget, or a device finds the guest has
        /// published something impossible.
        pub fn run(hv: B, vcpu: B.VcpuId, options: Run) Of.RunError!Reason {
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
                    // which hypervisor it is on. Only an architecture with a power interface
                    // reaches these; the x86 hypervisor never emits one.
                    .psci => |call| if (comptime Guest.has_power) switch (Guest.psci.handle(.{ .function = call.function, .args = call.args })) {
                        .value => |value| try hv.setRegister(vcpu, Guest.psci_result, value),
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
                            try hv.setRegister(vcpu, Guest.psci_result, if (answer) Guest.psci.success else Guest.psci.not_supported);
                        },
                    } else unreachable,

                    // Only Apple sends this. The program counter has already moved past
                    // the instruction, so the guest carries on around its idle loop and
                    // makes progress whenever an interrupt arrives.
                    .wfi => {},

                    // Only Apple sends this too, because KVM delivers the timer interrupt
                    // itself. Here the VMM has to.
                    .timer => if (comptime Guest.has_power) {
                        if (options.controller) |each| {
                            take(options);
                            defer release(options);
                            // The timer belongs to this CPU and to no other, so it is raised for this one.
                            each.raiseOn(each.ctx, vcpu, Guest.timer.virtual_intid);
                        }
                    } else unreachable,

                    // The guest was taken back so this loop could run. Serving the devices and
                    // giving the host its turn is the whole point, and both happen below.
                    .interrupted => {},

                    // Port exits reach a port bus when one is present. Without one the exit is
                    // unexpected: aarch64 never produces port exits, and x86 before a serial is
                    // attached has nothing to route to.
                    .port_out => |w| if (options.ports) |ports| {
                        take(options);
                        defer release(options);
                        acting(options, vcpu);
                        ports.write(w.port, w.size, w.value);
                        if (options.shutdown) |flag| if (flag.*) return .shutdown;
                    } else return B.Error.HypervisorFault,
                    .port_in => |r| if (options.ports) |ports| {
                        take(options);
                        acting(options, vcpu);
                        const value = ports.read(r.port, r.size);
                        release(options);
                        try hv.completeMmioRead(vcpu, value);
                    } else return B.Error.HypervisorFault,
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
            return Of.RunError.ExitsExhausted;
        }
    };
}

/// The guest this build's hypervisor runs. A hardware hypervisor can only run a guest of its own
/// architecture, so the runners that name no guest get this one.
const host = For(arch);
pub const Kind = host.Kind;
pub const Config = host.Config;
pub const Layout = host.Layout;
pub const Error = host.Error;
pub const prepare = host.prepare;
pub const enter = host.enter;
pub const RunError = host.RunError;
pub const run = host.run;

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
    /// Port-mapped devices, for an x86 guest that writes to I/O ports rather than memory.
    /// aarch64 never produces port exits, so leaving this null is correct there and on x86
    /// before a serial device is attached.
    ports: ?*device.Bus = null,
    /// Set by a port device to signal a clean poweroff. The run loop checks this after
    /// every port write and returns `Reason.shutdown` when it is true. It is consulted
    /// only on the port_out path, so it is meaningful only when `ports` is also set;
    /// aarch64 never produces port exits, so leaving this null is correct there.
    shutdown: ?*bool = null,
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

/// Say which CPU is about to touch a device, for a controller that banks part of itself per CPU.
/// Held under the same lock as the access it belongs to, or another CPU could say so in between.
fn acting(options: Run, vcpu: backend_lib.shared.VcpuId) void {
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
// Where a guest's memory starts, for the run loop tests below. Placing and measuring a launch is the
// architecture's own, and the tests that prove it live beside it; what remains here is the run loop.
const ram_base = 0x4000_0000;

// The aarch64 guest, whatever this host is: the power interface and its timer are that guest's, and a
// test of them should not depend on which machine runs it.
const arm64_launch = For(arm64);
const arm64_backend = backend_lib.For(arm64);

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
    // The power interface is arm's, so this runs the aarch64 guest whatever the host is.
    {
        var mock: arm64_backend.Mock = .init(&.{
            .{ .psci = .{ .function = arm64.psci.function.system_off, .args = @splat(0) } },
        });
        const hv = mock.backend();
        const id = try hv.addVcpu();

        var devices = [_]device.Device{};
        var bus: device.Bus = .{ .devices = &devices };

        try testing.expectEqual(Reason.shutdown, try arm64_launch.run(hv, id, .{ .bus = &bus }));
    }
}

test "a guest asking for the psci version is answered and carries on" {
    {
        var mock: arm64_backend.Mock = .init(&.{
            .{ .psci = .{ .function = arm64.psci.function.version, .args = @splat(0) } },
            .shutdown,
        });
        const hv = mock.backend();
        const id = try hv.addVcpu();

        var devices = [_]device.Device{};
        var bus: device.Bus = .{ .devices = &devices };

        _ = try arm64_launch.run(hv, id, .{ .bus = &bus });

        // The answer goes back in x0, which is where the guest looks for it.
        try testing.expectEqual(arm64.psci.version_number, mock.register(id, .x0));
    }
}

test "a guest asking to start a second cpu is told no rather than ignored" {
    {
        var mock: arm64_backend.Mock = .init(&.{
            .{ .psci = .{ .function = arm64.psci.function.cpu_on, .args = .{ 1, 0x4008_0000, 0 } } },
            .shutdown,
        });
        const hv = mock.backend();
        const id = try hv.addVcpu();

        var devices = [_]device.Device{};
        var bus: device.Bus = .{ .devices = &devices };

        _ = try arm64_launch.run(hv, id, .{ .bus = &bus });
        try testing.expectEqual(arm64.psci.not_supported, mock.register(id, .x0));
    }
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
    // Only an architecture with its timer in the VMM reaches this exit, so this runs the aarch64 guest.
    var gic: device.Gicv2 = .{};
    var on_bus = gic.devices(0x0800_0000, 0x0801_0000);
    var bus: device.Bus = .{ .devices = &on_bus };

    bus.write(0x0800_0000, .word, 1);
    bus.write(0x0801_0000, .word, 1);
    bus.write(0x0801_0004, .word, 0xff);
    // Enable the timer interrupt, which is private to this CPU and numbered 27.
    bus.write(0x0800_0100, .word, @as(u64, 1) << arm64.timer.virtual_intid);

    var mock: arm64_backend.Mock = .init(&.{ .timer, .shutdown });
    const hv = mock.backend();
    const id = try hv.addVcpu();

    _ = try arm64_launch.run(hv, id, .{ .bus = &bus, .controller = gic.controller() });

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

test "a guest port write reaches a device on the port bus" {
    var buf: [8]u8 = undefined;
    var sink = std.Io.Writer.fixed(&buf);
    var uart: device.Uart16550 = .{ .sink = &sink };
    var pdevs = [_]device.Bus.Device{uart.device(0x3f8)};
    var ports: device.Bus = .{ .devices = &pdevs };
    var mock: Backend.Mock = .init(&.{
        .{ .port_out = .{ .port = 0x3f8, .size = .byte, .value = 'h' } },
        .shutdown,
    });
    const hv = mock.backend();
    const id = try hv.addVcpu();

    var devices = [_]device.Device{};
    var bus: device.Bus = .{ .devices = &devices };

    try testing.expectEqual(Reason.shutdown, try run(hv, id, .{ .bus = &bus, .ports = &ports }));
    try testing.expectEqualSlices(u8, "h", sink.buffered());
}

test "a guest acpi poweroff write ends the run through the shutdown flag" {
    // The x86 ACPI sleep port and the S5 sleep value, inlined so core needs no acpi dep.
    const sleep_port = 0x600;
    const s5_write: u8 = (5 << 2) | (1 << 5);

    var shutdown: device.AcpiShutdown = .{ .slp_typ = 5 };
    var pdevs = [_]device.Bus.Device{shutdown.device(sleep_port)};
    var ports: device.Bus = .{ .devices = &pdevs };
    var mock: Backend.Mock = .init(&.{
        .{ .port_out = .{ .port = sleep_port, .size = .byte, .value = s5_write } },
    });
    const hv = mock.backend();
    const id = try hv.addVcpu();

    var devices = [_]device.Device{};
    var bus: device.Bus = .{ .devices = &devices };

    const reason = try run(hv, id, .{ .bus = &bus, .ports = &ports, .shutdown = &shutdown.requested });
    // Reaching `.shutdown` means the device decoded the S5 write and the flag turned the run.
    try testing.expectEqual(Reason.shutdown, reason);
    try testing.expectEqual(true, shutdown.requested);
}

test "a port write with no port bus faults" {
    // Without a port bus the exit is unexpected and the caller must decide what to do.
    // aarch64 never reaches this arm; on x86 the caller omits ports until a serial is wired.
    var mock: Backend.Mock = .init(&.{
        .{ .port_out = .{ .port = 0x3f8, .size = .byte, .value = 'h' } },
    });
    const hv = mock.backend();
    const id = try hv.addVcpu();

    var devices = [_]device.Device{};
    var bus: device.Bus = .{ .devices = &devices };

    try testing.expectError(error.HypervisorFault, run(hv, id, .{ .bus = &bus }));
}
