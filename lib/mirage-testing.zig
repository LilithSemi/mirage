//! Test support for a target with no operating system.
//!
//! Mirage builds its tests for a freestanding target, because that build is the only
//! check that a portable module did not reach for an operating system. An object file
//! is not a check. Zig does not analyse the body of a function that nothing calls, so
//! a module that opens a file compiles clean as an object for a target that has no
//! files.
//!
//! `std.testing` cannot go there. Its allocator reaches the page allocator and its
//! failure reports reach `std.Io.Threaded`, and a freestanding target has neither. So
//! a portable module's tests use this module instead of `std.testing`. Where there is
//! an operating system every function below hands over to `std.testing`, so a failure
//! still reports what it always did.
//!
//! `std.testing.expect` is not here because it already builds for a freestanding
//! target. Only the functions that format a failure message need a replacement.

const builtin = @import("builtin");
const std = @import("std");

const freestanding = builtin.os.tag == .freestanding;

var buffer: [if (freestanding) 8 << 20 else 0]u8 = undefined;
var fixed: std.heap.FixedBufferAllocator = .init(&buffer);

pub const Error = error{TestFailed};

/// Leak detection where there is an operating system, a fixed buffer where there is
/// not. The freestanding build never runs a test. Only its analysis has value.
pub fn allocator() std.mem.Allocator {
    return if (freestanding) fixed.allocator() else std.testing.allocator;
}

pub fn expectEqual(expected: anytype, actual: anytype) !void {
    if (freestanding) {
        // Zig has no `==` for a struct or a union, and `std.meta.eql` wants both
        // sides to be one type. `std.testing` coerces to the type of the actual
        // value, so do the same, except where that value is a comptime number and
        // has no runtime type to coerce to.
        const Common = if (@TypeOf(actual) == comptime_int or @TypeOf(actual) == comptime_float)
            @TypeOf(expected)
        else
            @TypeOf(actual);

        const want: Common = expected;
        const got: Common = actual;
        return if (std.meta.eql(want, got)) {} else Error.TestFailed;
    }
    return std.testing.expectEqual(expected, actual);
}

pub fn expectEqualSlices(comptime T: type, expected: []const T, actual: []const T) !void {
    if (freestanding) return if (std.mem.eql(T, expected, actual)) {} else Error.TestFailed;
    return std.testing.expectEqualSlices(T, expected, actual);
}

pub fn expectError(expected: anyerror, actual: anytype) !void {
    if (freestanding) {
        if (actual) |_| return Error.TestFailed else |got| {
            return if (got == expected) {} else Error.TestFailed;
        }
    }
    return std.testing.expectError(expected, actual);
}
