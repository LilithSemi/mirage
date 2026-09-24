//! A KVM virtual machine behind the `Backend` interface.
//!
//! `Vm` and `Vcpu` know KVM. This file is what makes them one of the two things a
//! run loop can sit on, so that nothing above here ever names KVM. The
//! Hypervisor.framework backend gets a file of exactly this shape, and the loop above
//! does not change when it arrives.
//!
//! The interface is deliberately narrow, so a KVM errno arrives at a caller as
//! `HypervisorFault`. The errno is kept in `fault` rather than discarded, because a
//! fault that is recovered without a trace is a bug that hides itself.

const std = @import("std");
const testing = @import("mirage-testing");
const Backend = @import("../../Backend.zig");
const Vm = @import("Vm.zig");
const Vcpu = @import("Vcpu.zig");
const device = @import("mirage-device");

const Machine = @This();

pub const Error = Vm.Error || std.mem.Allocator.Error || error{
    /// More CPUs than this host will give a guest. What the limit is comes from the kernel, so this
    /// says the machine refused and not that some number written here was exceeded.
    TooManyVcpus,
};

vm: Vm,
/// Room for exactly the CPUs this machine was asked for. Allocated rather than a fixed array, because
/// how many a guest wants belongs to whoever starts it and how many it may have belongs to the kernel.
/// Neither is a number this file should invent.
vcpus: []Vcpu,
count: u32 = 0,
gpa: std.mem.Allocator,
/// What KVM actually said, behind the last `HypervisorFault`.
fault: ?anyerror = null,

/// Make a machine with room for `cpus` of them. The kernel is asked whether it allows that many before
/// anything is allocated, so a caller asking for too many is told so rather than finding out on the
/// CPU that fails.
pub fn create(gpa: std.mem.Allocator, cpus: u32) Error!Machine {
    std.debug.assert(cpus > 0);

    var vm = try Vm.create();
    errdefer vm.deinit();

    if (cpus > vm.maxVcpus()) return Error.TooManyVcpus;

    return .{ .vm = vm, .vcpus = try gpa.alloc(Vcpu, cpus), .gpa = gpa };
}

pub fn deinit(self: *Machine) void {
    for (self.vcpus[0..self.count]) |*each| each.deinit();
    self.gpa.free(self.vcpus);
    self.vm.deinit();
    self.* = undefined;
}

pub fn backend(self: *Machine) Backend {
    return .{ .ctx = self, .vtable = &vtable };
}

const vtable: Backend.VTable = .{
    .addVcpu = Machine.addVcpu,
    .run = Machine.run,
    .completeMmioRead = Machine.completeMmioRead,
    .setRegister = Machine.setRegister,
    .getRegister = Machine.getRegister,
    .setInterrupt = Machine.setInterrupt,
};

fn cast(ctx: *anyopaque) *Machine {
    return @ptrCast(@alignCast(ctx));
}

fn record(self: *Machine, err: anyerror) Backend.Error {
    self.fault = err;
    return Backend.Error.HypervisorFault;
}

fn cpu(self: *Machine, id: Backend.VcpuId) Backend.Error!*Vcpu {
    if (id >= self.count) return Backend.Error.NoSuchVcpu;
    return &self.vcpus[id];
}

fn addVcpu(ctx: *anyopaque) Backend.Error!Backend.VcpuId {
    const self = cast(ctx);
    // The room was asked for when the machine was made, so asking past it is a caller that did not say
    // how many CPUs it wanted.
    if (self.count >= self.vcpus.len) return Backend.Error.TooManyVcpus;

    self.vcpus[self.count] = Vcpu.create(&self.vm, self.count) catch |err| return self.record(err);
    defer self.count += 1;
    return self.count;
}

fn run(ctx: *anyopaque, id: Backend.VcpuId) Backend.Error!Backend.Exit {
    const self = cast(ctx);
    const target = try self.cpu(id);
    return target.run() catch |err| self.record(err);
}

fn completeMmioRead(ctx: *anyopaque, id: Backend.VcpuId, value: u64) Backend.Error!void {
    const self = cast(ctx);
    const target = try self.cpu(id);
    return target.completeMmioRead(value) catch |err| self.record(err);
}

fn setRegister(ctx: *anyopaque, id: Backend.VcpuId, reg: Backend.Register, value: u64) Backend.Error!void {
    const self = cast(ctx);
    const target = try self.cpu(id);
    return target.setRegister(reg, value) catch |err| self.record(err);
}

fn getRegister(ctx: *anyopaque, id: Backend.VcpuId, reg: Backend.Register) Backend.Error!u64 {
    const self = cast(ctx);
    const target = try self.cpu(id);
    return target.getRegister(reg) catch |err| self.record(err);
}

/// Nothing to do. The GIC lives in the kernel here and drives the line itself, and a
/// device raises an interrupt through `Vm.setIrq` rather than through this.
fn setInterrupt(ctx: *anyopaque, id: Backend.VcpuId, level: bool) Backend.Error!void {
    const self = cast(ctx);
    _ = try self.cpu(id);
    _ = level;
}

const ram = 0x4000_0000;
const uart = 0x0900_0000;

fn open() !Machine {
    return openWith(2);
}

fn openWith(cpus: u32) !Machine {
    return Machine.create(testing.allocator(), cpus) catch |err| switch (err) {
        error.NoKvm => error.SkipZigTest,
        else => err,
    };
}

test "a machine gives each vcpu its own identifier through the interface" {
    var machine = try open();
    defer machine.deinit();
    const hv = machine.backend();

    const first = try hv.addVcpu();
    const second = try hv.addVcpu();

    try std.testing.expect(first != second);
}

test "asking for more vcpus than the machine was made with is refused by name" {
    var machine = try openWith(3);
    defer machine.deinit();
    const hv = machine.backend();

    for (0..3) |_| _ = try hv.addVcpu();
    try testing.expectError(error.TooManyVcpus, hv.addVcpu());
}

test "a machine will not be made with more cpus than this host allows" {
    var machine = try openWith(1);
    defer machine.deinit();

    // What the limit is comes from the kernel, so this asks and then asks for one past it. Nothing here
    // knows the number, which is the point: one written here would be wrong on some other host.
    const most = machine.vm.maxVcpus();
    try std.testing.expect(most >= 1);
    try testing.expectError(error.TooManyVcpus, Machine.create(testing.allocator(), most + 1));
}

test "running a vcpu that was never added is refused by name" {
    var machine = try open();
    defer machine.deinit();
    const hv = machine.backend();

    try testing.expectError(error.NoSuchVcpu, hv.run(3));
}

test "a guest prints through the backend interface, not through kvm directly" {
    var machine = try open();
    defer machine.deinit();

    const region = try machine.vm.addMemory(ram, 4 * std.heap.pageSize(), .shared);
    var memory: Backend.GuestMemory = .{ .regions = &.{region} };

    const code = [_]u32{
        0xd2a12001, // movz x1, #0x0900, lsl #16
        0x52800d00, // movz w0, #0x68              'h'
        0xb9000020, // str  w0, [x1]
        0x52800d20, // movz w0, #0x69              'i'
        0xb9000020, // str  w0, [x1]
        0x14000000, // b    .
    };
    try memory.write(ram, std.mem.sliceAsBytes(code[0..]));

    var buffer: [16]u8 = undefined;
    var sink = std.Io.Writer.fixed(&buffer);
    var serial: device.Pl011 = .{ .sink = &sink };
    var devices = [_]device.Device{serial.device(uart)};
    var bus: device.Bus = .{ .devices = &devices };

    const hv = machine.backend();
    const id = try hv.addVcpu();
    try hv.setRegister(id, .pc, ram);

    for (0..2) |_| {
        switch (try hv.run(id)) {
            .mmio_write => |w| bus.write(w.gpa, w.size, w.value),
            else => return error.TestUnexpectedResult,
        }
    }

    try testing.expectEqualSlices(u8, "hi", sink.buffered());
}
