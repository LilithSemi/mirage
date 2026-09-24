//! The power interface a guest uses to stop, restart, or start another CPU.
//!
//! KVM answers these inside the kernel, so this backend never sees them there.
//! Hypervisor.framework answers none of them, and a guest whose power off goes
//! unanswered simply stops saying anything, which looks exactly like a hang. So the
//! VMM answers them, and it answers them the same way on both.
//!
//! Numbers are from the Arm Power State Coordination Interface. A call arrives in
//! `x0` with its arguments in `x1` onwards, and the result goes back in `x0`.

const std = @import("std");
const testing = @import("mirage-testing");

pub const function = struct {
    pub const version = 0x8400_0000;
    pub const cpu_suspend_32 = 0x8400_0001;
    pub const cpu_off = 0x8400_0002;
    pub const cpu_on_32 = 0x8400_0003;
    pub const migrate_info_type = 0x8400_0006;
    pub const system_off = 0x8400_0008;
    pub const system_reset = 0x8400_0009;
    pub const features = 0x8400_000a;
    pub const cpu_on = 0xc400_0003;
    pub const cpu_suspend = 0xc400_0001;
};

/// `PSCI_RET_NOT_SUPPORTED`, which is minus one in two's complement.
pub const not_supported: u64 = @bitCast(@as(i64, -1));
pub const success: u64 = 0;

/// Version 0.2, major in the high half and minor in the low. The device tree says
/// `arm,psci-0.2`, and the two have to agree.
pub const version_number: u64 = 0x0000_0002;

/// There is no trusted operating system here, so there is nothing to migrate.
const migrate_not_required: u64 = 2;

pub const Call = struct {
    function: u32,
    args: [3]u64,
};

pub const Outcome = union(enum) {
    /// Put this in `x0` and let the guest carry on.
    value: u64,
    power_off,
    reset,
    /// The guest wants another CPU running from `entry`, with `context` in `x0`.
    start_cpu: struct {
        target: u64,
        entry: u64,
        context: u64,
    },
};

/// Whether a call is one this code answers. `PSCI_FEATURES` reports the same set,
/// so the two cannot disagree about what exists.
fn implemented(which: u32) bool {
    return switch (which) {
        function.version,
        function.system_off,
        function.system_reset,
        function.features,
        function.migrate_info_type,
        function.cpu_on,
        function.cpu_on_32,
        function.cpu_off,
        => true,
        else => false,
    };
}

pub fn handle(call: Call) Outcome {
    return switch (call.function) {
        function.version => .{ .value = version_number },
        function.system_off => .power_off,
        function.system_reset => .reset,
        function.migrate_info_type => .{ .value = migrate_not_required },

        function.features => .{
            .value = if (implemented(@truncate(call.args[0]))) success else not_supported,
        },

        // The same call in its 32 and its 64 bit form. A guest may use either.
        function.cpu_on, function.cpu_on_32 => .{ .start_cpu = .{
            .target = call.args[0],
            .entry = call.args[1],
            .context = call.args[2],
        } },

        // A CPU turning itself off never returns, so the caller decides what that
        // means for the machine.
        function.cpu_off => .{ .value = success },

        // Refused rather than answered with success. A guest that reads success from
        // a call that did nothing carries on as though it happened.
        else => .{ .value = not_supported },
    };
}

test "the version reported is the one the device tree promises" {
    // The tree says `arm,psci-0.2`, so anything else here is a lie the guest will
    // believe. Major in the high half, minor in the low.
    const outcome = handle(.{ .function = function.version, .args = @splat(0) });
    try testing.expectEqual(@as(u64, 0x0000_0002), outcome.value);
}

test "system off asks the machine to stop rather than returning to the guest" {
    const outcome = handle(.{ .function = function.system_off, .args = @splat(0) });
    try testing.expectEqual(@as(Outcome, .power_off), outcome);
}

test "system reset asks the machine to start again" {
    const outcome = handle(.{ .function = function.system_reset, .args = @splat(0) });
    try testing.expectEqual(@as(Outcome, .reset), outcome);
}

test "turning a cpu on carries the entry point and the context back" {
    const outcome = handle(.{
        .function = function.cpu_on,
        .args = .{ 1, 0x4008_0000, 0xdead },
    });
    try testing.expectEqual(@as(u64, 1), outcome.start_cpu.target);
    try testing.expectEqual(@as(u64, 0x4008_0000), outcome.start_cpu.entry);
    try testing.expectEqual(@as(u64, 0xdead), outcome.start_cpu.context);
}

test "a function this code does not implement is refused, not silently accepted" {
    // A guest that reads success from a call that did nothing carries on as though
    // it happened, which is worse than being told no.
    const outcome = handle(.{ .function = 0x8400_00ff, .args = @splat(0) });
    try testing.expectEqual(not_supported, outcome.value);
}

test "asking about a supported function says so, and an unknown one does not" {
    const supported = handle(.{ .function = function.features, .args = .{ function.system_off, 0, 0 } });
    try testing.expectEqual(@as(u64, 0), supported.value);

    const unknown = handle(.{ .function = function.features, .args = .{ 0x8400_00ff, 0, 0 } });
    try testing.expectEqual(not_supported, unknown.value);
}

test "there is no trusted operating system to migrate" {
    const outcome = handle(.{ .function = function.migrate_info_type, .args = @splat(0) });
    try testing.expectEqual(@as(u64, 2), outcome.value);
}

test "both the 32 and the 64 bit forms of a call are answered" {
    // A guest may use either, and the only difference is one bit of the number.
    const wide = handle(.{ .function = function.cpu_on, .args = .{ 1, 2, 3 } });
    const narrow = handle(.{ .function = function.cpu_on_32, .args = .{ 1, 2, 3 } });
    try testing.expectEqual(wide.start_cpu.entry, narrow.start_cpu.entry);
}
