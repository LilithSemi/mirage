//! The settings written after a device's name, as `name,key=value,key`.
//!
//! The same shape Glacier writes a board in, so `windowsize=32M` means here what it means in the
//! hardware's own `devices.nix`. A device reads a setting where it needs one, so a setting this
//! program does not know still parses.

const std = @import("std");
const testing = @import("mirage-testing");

pub const Error = error{BadNumber};

/// What a setting says, or nothing where it was not given. A setting written with no value reads
/// as `yes`, which is how a device takes one that is only on or off.
pub fn get(text: []const u8, key: []const u8) ?[]const u8 {
    var rest = text;
    while (rest.len != 0) {
        const end = std.mem.indexOfScalar(u8, rest, ',') orelse rest.len;
        const one = rest[0..end];
        rest = if (end == rest.len) &.{} else rest[end + 1 ..];

        const split = std.mem.indexOfScalar(u8, one, '=') orelse {
            if (std.mem.eql(u8, one, key)) return "yes";
            continue;
        };
        if (std.mem.eql(u8, one[0..split], key)) return one[split + 1 ..];
    }
    return null;
}

/// Whether a setting is on. A setting nobody gave stays as it was. `no`, `off`, `false` and `0`
/// turn it off, and anything else turns it on.
pub fn flag(text: []const u8, key: []const u8, unless: bool) bool {
    const said = get(text, key) orelse return unless;
    for ([_][]const u8{ "no", "off", "false", "0" }) |each| {
        if (std.mem.eql(u8, said, each)) return false;
    }
    return true;
}

/// A number a setting says: decimal, hex behind `0x`, and the size suffixes a board is written
/// with. `256K`, `32M` and `1G` are powers of two, the way memory is counted and not the way a
/// disk is sold.
pub fn number(said: []const u8) Error!u64 {
    if (said.len == 0) return error.BadNumber;

    var digits = said;
    var scale: u64 = 1;
    switch (said[said.len - 1]) {
        'K', 'k' => scale = 1024,
        'M', 'm' => scale = 1024 * 1024,
        'G', 'g' => scale = 1024 * 1024 * 1024,
        else => {},
    }
    if (scale != 1) digits = said[0 .. said.len - 1];
    if (digits.len == 0) return error.BadNumber;

    const base: u8 = if (digits.len > 2 and digits[0] == '0' and (digits[1] == 'x' or digits[1] == 'X')) 16 else 10;
    if (base == 16) digits = digits[2..];

    const value = std.fmt.parseInt(u64, digits, base) catch return error.BadNumber;
    return std.math.mul(u64, value, scale) catch error.BadNumber;
}

/// A number a setting says, or what the device was built with where it says nothing.
pub fn numberOr(text: []const u8, key: []const u8, unless: u64) Error!u64 {
    return number(get(text, key) orelse return unless);
}

test "a setting is read by name, and one with no value is simply on" {
    const text = "romfile=/tmp/a.rom,quiet,windowsize=32M";

    try testing.expectEqualSlices(u8, "/tmp/a.rom", get(text, "romfile").?);
    try testing.expectEqualSlices(u8, "yes", get(text, "quiet").?);
    try testing.expectEqual(@as(?[]const u8, null), get(text, "window"));
}

test "a size is counted the way memory is counted" {
    try testing.expectEqual(@as(u64, 32 * 1024 * 1024), try number("32M"));
    try testing.expectEqual(@as(u64, 256 * 1024), try number("256K"));
    try testing.expectEqual(@as(u64, 1024 * 1024 * 1024), try number("1G"));
    try testing.expectEqual(@as(u64, 0x8000_0000), try number("0x80000000"));
    try testing.expectEqual(@as(u64, 1024), try number("1024"));

    // A suffix with nothing in front of it names no number, and neither does a word.
    try testing.expectError(error.BadNumber, number("M"));
    try testing.expectError(error.BadNumber, number("large"));
    try testing.expectError(error.BadNumber, number(""));
}

test "a flag stays as the device was built where nobody gave it" {
    try std.testing.expect(flag("perf=yes", "perf", false));
    try std.testing.expect(!flag("perf=no", "perf", true));
    try std.testing.expect(!flag("perf=0", "perf", true));
    try std.testing.expect(flag("wide", "wide", false));
    try std.testing.expect(flag("", "perf", true));
    try std.testing.expect(!flag("", "perf", false));
}
