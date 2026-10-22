const std = @import("std");
const jit = @import("mirage-jit");
const arm64 = @import("mirage-arm64");
const launch = @import("mirage-core").Launch;
const Launch = launch.For(arm64);
const device = @import("mirage-device");
const GuestMemory = @import("mirage-memory").GuestMemory;

const Peripheral = struct {
    written: ?u64 = null,
    reads: usize = 0,
    fn read(ctx: *anyopaque, _: u64, _: device.Size) u64 {
        const self: *Peripheral = @ptrCast(@alignCast(ctx));
        self.reads += 1;
        return 0x42;
    }
    fn write(ctx: *anyopaque, _: u64, _: device.Size, value: u64) void {
        const self: *Peripheral = @ptrCast(@alignCast(ctx));
        self.written = value;
    }
    const vtable: device.Bus.Device.VTable = .{ .read = read, .write = write };
};

const Host = struct {
    exits: usize = 0,
    fn step(ctx: *anyopaque) bool {
        const self: *Host = @ptrCast(@alignCast(ctx));
        self.exits += 1;
        return self.exits < 4;
    }
};

test "Launch dispatches translated guest MMIO, PSCI and WFI" {
    const base: u64 = 0x1000;
    const words = [_]u32{
        0xd2800820, // movz x0, #65
        0x39000020, // strb w0, [x1]
        0x39400022, // ldrb w2, [x1]
        0xd2b08000, // movz x0, #0x8400, lsl #16 (PSCI_VERSION)
        0xd4000002, // hvc #0
        0xd503207f, // wfi
    };
    var bytes: [words.len * 4]u8 = undefined;
    for (words, 0..) |word, index| std.mem.writeInt(u32, bytes[index * 4 ..][0..4], word, .little);
    const regions = [_]GuestMemory.Region{.{ .gpa = base, .len = bytes.len, .backing = .{ .shared = &bytes } }};
    var memory: GuestMemory = .{ .regions = &regions };
    var machine = jit.aarch64.Machine.init(std.testing.allocator, &memory);
    defer machine.deinit();
    const hv = machine.backend();
    const id = try hv.addVcpu();
    try hv.setRegister(id, .pc, base);
    try hv.setRegister(id, .x1, 0x9000_0000);

    var peripheral: Peripheral = .{};
    var devices = [_]device.Bus.Device{.{ .base = 0x9000_0000, .len = 0x1000, .ctx = &peripheral, .vtable = &Peripheral.vtable }};
    var bus: device.Bus = .{ .devices = &devices };
    var host: Host = .{};
    const reason = try Launch.run(hv, id, .{
        .bus = &bus,
        .exits = 5,
        .host = .{ .ctx = &host, .step = Host.step },
    });
    try std.testing.expectEqual(launch.Reason.stopped, reason);
    try std.testing.expectEqual(@as(?u64, 65), peripheral.written);
    try std.testing.expectEqual(@as(usize, 1), peripheral.reads);
    try std.testing.expectEqual(@as(u64, 0x42), machine.cpu.x[2]);
    try std.testing.expectEqual(@as(u64, 2), try hv.getRegister(id, .x0));
    try std.testing.expectEqual(base + words.len * 4, try hv.getRegister(id, .pc));
    try std.testing.expectEqual(@as(usize, 4), host.exits);
}
