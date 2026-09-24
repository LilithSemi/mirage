//! Drives Hypervisor.framework through the `Backend` interface, with the same bus
//! and the same serial port the KVM side uses.
//!
//! The point is parity. If this passes and the KVM tests pass, the interface really
//! does hide which hypervisor is underneath, rather than merely claiming to.
//!
//! A program rather than a test block, because it is cross compiled on Linux, copied
//! to a Mac and signed before it can run.

const std = @import("std");
const backend = @import("mirage-backend");
const arm64 = @import("mirage-arm64");
const device = @import("mirage-device");
const core = @import("mirage-core");

const ram = 0x4000_0000;
const uart = 0x0900_0000;
const ram_size = 1 << 20;

var failures: u32 = 0;

fn say(comptime fmt: []const u8, args: anytype) void {
    var buffer: [512]u8 = undefined;
    const line = std.fmt.bufPrint(&buffer, fmt ++ "\n", args) catch return;
    _ = std.c.write(1, line.ptr, line.len);
}

fn check(ok: bool, comptime what: []const u8, args: anytype) void {
    if (ok) say("  ok   " ++ what, args) else {
        failures += 1;
        say("  FAIL " ++ what, args);
    }
}

pub fn main() void {
    var machine = backend.hvf.Machine.create(std.heap.smp_allocator, 1) catch |err| {
        say("cannot reach the hypervisor: {t}", .{err});
        std.process.exit(1);
    };
    defer machine.deinit();
    say("Hypervisor.framework open, virtual machine created", .{});

    // No execute on the host mapping. Apple Silicon refuses a page that is writable
    // and executable, and the guest takes its permission from the map call.
    const memory = std.posix.mmap(
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

    machine.map(memory, ram) catch |err| {
        say("cannot map guest memory: {t}", .{err});
        std.process.exit(1);
    };

    // Store a byte to the serial port, read its flag register back, then ask PSCI
    // for its version. Three exits of three different kinds.
    const code = [_]u32{
        0xd2a12001, // movz x1, #0x0900, lsl #16   x1 = the uart
        0x528009a0, // movz w0, #0x4d              'M'
        0xb9000020, // str  w0, [x1]               a write that leaves the guest
        0xb9401822, // ldr  w2, [x1, #0x18]        a read of the flag register
        0xd2b08000, // movz x0, #0x8400, lsl #16   PSCI_VERSION
        0xd4000002, // hvc  #0                     a call that leaves the guest
        0xd2b08000, // movz x0, #0x8400, lsl #16
        0xf2800100, // movk x0, #0x0008            PSCI_SYSTEM_OFF
        0xd4000002, // hvc  #0                     the guest asks to stop
        0x14000000, // b    .                      never reached
    };
    @memcpy(memory[0..@sizeOf(@TypeOf(code))], std.mem.sliceAsBytes(code[0..]));

    var buffer: [16]u8 = undefined;
    var sink = std.Io.Writer.fixed(&buffer);
    var serial: device.Pl011 = .{ .sink = &sink };
    var devices = [_]device.Device{serial.device(uart)};
    var bus: device.Bus = .{ .devices = &devices };

    const hv = machine.backend();
    const id = hv.addVcpu() catch |err| {
        say("cannot add a vcpu: {t}", .{err});
        std.process.exit(1);
    };
    hv.setRegister(id, .pc, ram) catch unreachable;

    // Apple lends the guest no interrupt controller, so the VMM drives the line
    // itself. Raising and releasing it must at least be accepted.
    check(if (hv.setInterrupt(id, true)) |_| true else |_| false, "the interrupt line was raised", .{});
    check(if (hv.setInterrupt(id, false)) |_| true else |_| false, "the interrupt line was released", .{});

    // The store.
    switch (hv.run(id) catch |err| fatal(err, machine)) {
        .mmio_write => |write| {
            check(write.gpa == uart, "the store went to the serial port", .{});
            check(write.size == .word, "it was a word", .{});
            bus.write(write.gpa, write.size, write.value);
        },
        else => |other| check(false, "expected a store, got {t}", .{other}),
    }
    check(std.mem.eql(u8, sink.buffered(), "M"), "the serial port received it", .{});

    // The load.
    switch (hv.run(id) catch |err| fatal(err, machine)) {
        .mmio_read => |read| {
            check(read.gpa == uart + 0x18, "the load came from the flag register", .{});
            check(read.dest == 2, "it wanted x2, got x{d}", .{read.dest});
            hv.completeMmioRead(id, bus.read(read.gpa, read.size)) catch unreachable;
        },
        else => |other| check(false, "expected a load, got {t}", .{other}),
    }

    // The call.
    const outcome = hv.run(id) catch |err| {
        const raw = machine.vcpus[id].exit;
        say("third exit: reason {d}, syndrome 0x{x}, class 0x{x}, address 0x{x}", .{
            @intFromEnum(raw.reason),
            raw.exception.syndrome,
            arm64.esr.class(raw.exception.syndrome),
            raw.exception.physical_address,
        });
        fatal(err, machine);
    };
    switch (outcome) {
        .psci => |call| check(call.function == 0x8400_0000, "psci asked for its version, got 0x{x}", .{call.function}),
        else => |other| check(false, "expected a psci call, got {t}", .{other}),
    }

    // The flag register says the transmitter is empty and nothing has arrived, and
    // that value had to be written back into the guest register for the guest to
    // carry on to the call above.
    const loaded = hv.getRegister(id, .x2) catch |err| fatal(err, machine);
    check(loaded == (1 << 7) | (1 << 4), "the guest got the flags back, 0x{x}", .{loaded});

    // Hand the rest to the run loop, which is the same loop the KVM side uses. The
    // guest asks to power off, and nothing here knows which hypervisor answered it.
    // The program is a handful of instructions, so the budget is small. This runs on
    // a machine other people share and a spinning guest must not outlive the test.
    hv.setRegister(id, .x0, arm64.psci.version_number) catch unreachable;
    const reason = core.Launch.run(hv, id, .{ .bus = &bus, .exits = 64 }) catch |err| fatal(err, machine);
    check(reason == .shutdown, "the run loop stopped because the guest asked to, got {t}", .{reason});

    say("{d} failures", .{failures});
    std.process.exit(if (failures == 0) 0 else 1);
}

fn fatal(err: anyerror, machine: backend.hvf.Machine) noreturn {
    say("run failed: {t}, the framework returned {?}", .{ err, machine.fault });
    std.process.exit(1);
}
