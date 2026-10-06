//! Put a guest at its entry point the way the arm64 Linux boot protocol asks.
//!
//! The protocol wants the device tree address in `x0` and the other three argument
//! registers zeroed. The hypervisor and the layout are passed in rather than imported,
//! so this stays below the backend that names this architecture. Only the layout's entry
//! and device tree addresses are read.

const boot = @import("boot.zig");
const testing = @import("mirage-testing");

pub fn enter(hv: anytype, vcpu: anytype, layout: anytype) !void {
    const Shim = struct {
        hv: @TypeOf(hv),
        vcpu: @TypeOf(vcpu),

        pub fn setRegister(self: @This(), reg: anytype, val: u64) !void {
            try self.hv.setRegister(self.vcpu, reg, val);
        }
    };
    try boot.enter(Shim{ .hv = hv, .vcpu = vcpu }, layout);
}

test "enter instantiates through the boot path" {
    // The shim's setRegister must be reachable from boot.enter, which lives in another file. A
    // non-pub method compiles until something instantiates enter, so this test is what keeps the
    // generic entry path (core.Launch.enter -> arch.enter) building for an arm64 guest.
    const Recorder = struct {
        count: *usize,
        pub fn setRegister(self: @This(), vcpu: u32, reg: anytype, val: u64) !void {
            _ = vcpu;
            _ = reg;
            _ = val;
            self.count.* += 1;
        }
    };
    var count: usize = 0;
    try enter(Recorder{ .count = &count }, @as(u32, 0), boot.Layout{ .entry = 0x1000, .device_tree = 0x2000 });
    // boot.enter writes pc, x0, x1, x2, x3.
    try testing.expectEqual(@as(usize, 5), count);
}
