//! Everything a stopped guest holds, as bytes, so a caller can put it in a file or a socket.
//!
//! This does no reading or writing of its own. It says what the bytes are and reads them back,
//! which is what lets it be tested without a filesystem and built for a target with none.
//!
//! What is here is state and not provenance. When a snapshot was taken, whether it may be
//! trusted and what it is allowed to be resumed as are for whoever keeps it.
//!
//! The parts that came from a hypervisor are carried as opaque runs of bytes, because only that
//! hypervisor knows what they mean. A snapshot taken under KVM is not one Apple could be given.
//! The parts Mirage owns are written field by field, because a struct written as raw bytes is a
//! struct that stops loading the day the compiler lays it out differently, and because some of
//! those structs hold host pointers that must never reach a file.

const std = @import("std");
const testing = @import("mirage-testing");
const device = @import("mirage-device");

/// What every snapshot starts with, so a reader can tell one from any other run of bytes.
pub const magic = "mirage snapshot\x00";

/// The layout below. A reader refuses a version it does not know rather than reading the fields
/// in the wrong places.
pub const version = 2;

pub const Error = error{
    /// The bytes do not begin with a snapshot.
    NotASnapshot,
    /// A snapshot this code has no layout for.
    UnknownVersion,
    /// The header describes more than the bytes hold.
    Truncated,
    /// More devices, or more CPUs, than this snapshot holds room for.
    TooManyDevices,
};

/// How many device queues one snapshot carries. A guest with more devices than this is one this
/// format cannot hold, which is better than holding some of it.
pub const max_queues = 16;

/// Where one device left off in its rings. The addresses are guest physical, so they mean the same
/// thing in the machine the guest moves to; `last_available` is the device's own place in the
/// ring, which nothing else in guest memory records.
pub const QueueState = struct {
    size: u16,
    ready: bool,
    last_available: u16,
    descriptor: u64,
    available: u64,
    used: u64,

    pub const bytes = 2 + 1 + 2 + 8 + 8 + 8;

    pub fn write(self: QueueState, out: *[bytes]u8) void {
        std.mem.writeInt(u16, out[0..2], self.size, .little);
        out[2] = @intFromBool(self.ready);
        std.mem.writeInt(u16, out[3..5], self.last_available, .little);
        std.mem.writeInt(u64, out[5..13], self.descriptor, .little);
        std.mem.writeInt(u64, out[13..21], self.available, .little);
        std.mem.writeInt(u64, out[21..29], self.used, .little);
    }

    pub fn parse(from: *const [bytes]u8) QueueState {
        return .{
            .size = std.mem.readInt(u16, from[0..2], .little),
            .ready = from[2] != 0,
            .last_available = std.mem.readInt(u16, from[3..5], .little),
            .descriptor = std.mem.readInt(u64, from[5..13], .little),
            .available = std.mem.readInt(u64, from[13..21], .little),
            .used = std.mem.readInt(u64, from[21..29], .little),
        };
    }

    /// Take the state out of a live queue.
    pub fn of(queue: device.virtio.Queue) QueueState {
        return .{
            .size = queue.size,
            .ready = queue.ready,
            .last_available = queue.last_available,
            .descriptor = queue.descriptor,
            .available = queue.available,
            .used = queue.used,
        };
    }

    /// Put it back into one.
    pub fn into(self: QueueState, queue: *device.virtio.Queue) void {
        queue.size = self.size;
        queue.ready = self.ready;
        queue.last_available = self.last_available;
        queue.descriptor = self.descriptor;
        queue.available = self.available;
        queue.used = self.used;
    }
};

/// What a snapshot is made of. The three runs of bytes are not read by this module.
pub const Parts = struct {
    /// Where the guest's memory starts, and the memory itself.
    ram_base: u64,
    memory: []const u8,
    /// Every register of every CPU, as the backend writes them, one CPU after another. Each CPU's set
    /// is the same length, because they came from one hypervisor on one host.
    registers: []const u8,
    /// How many CPUs are in `registers`. A guest with several of them that came back with only the
    /// first would be a guest missing most of itself.
    cpus: u32,
    /// Whether each CPU was running, one byte each, zero for stopped. Not one of its registers, and a
    /// CPU brought back runnable that the guest had never started would begin running from wherever its
    /// registers happen to point.
    running: []const u8,
    /// What the guest set in the interrupt controller, as the backend writes it.
    controller: []const u8,
    /// Where each device left off, in the order the caller attached them.
    queues: []const QueueState,

    /// The registers of one CPU out of the run of them.
    pub fn registersFor(self: Parts, which: u32) []const u8 {
        std.debug.assert(which < self.cpus);
        const each = self.registers.len / self.cpus;
        return self.registers[which * each ..][0..each];
    }

    /// Whether that CPU was running when the snapshot was taken.
    pub fn wasRunning(self: Parts, which: u32) bool {
        std.debug.assert(which < self.cpus);
        return self.running[which] != 0;
    }
};

/// The fixed part at the front: the magic, the version, and the length of everything behind it.
pub const header_size = magic.len + 4 + 8 + 8 + 8 + 8 + 4 + 4;

/// How many CPUs one snapshot carries. A machine with more than this is one this format cannot hold,
/// which is better than holding some of it.
pub const max_cpus = 1024;

/// How many bytes `write` needs for these parts.
pub fn size(parts: Parts) usize {
    return header_size + parts.queues.len * QueueState.bytes + parts.cpus +
        parts.registers.len + parts.controller.len + parts.memory.len;
}
/// Write the whole snapshot into `out`. Returns how many bytes it took.
///
/// The memory goes last because it is almost all of it, so a reader that only wants to know what
/// a snapshot is need not read past the front of it.
pub fn write(parts: Parts, out: []u8) Error!usize {
    if (parts.queues.len > max_queues) return Error.TooManyDevices;
    if (parts.cpus == 0 or parts.cpus > max_cpus) return Error.TooManyDevices;
    // One run state per CPU, and the registers divide evenly between them. Either being wrong means a
    // caller built these parts from two different machines.
    if (parts.running.len != parts.cpus) return Error.TooManyDevices;
    if (parts.registers.len % parts.cpus != 0) return Error.TooManyDevices;

    const total = size(parts);
    if (out.len < total) return Error.Truncated;

    @memcpy(out[0..magic.len], magic);
    var at = magic.len;
    std.mem.writeInt(u32, out[at..][0..4], version, .little);
    at += 4;
    std.mem.writeInt(u64, out[at..][0..8], parts.ram_base, .little);
    at += 8;
    std.mem.writeInt(u64, out[at..][0..8], parts.memory.len, .little);
    at += 8;
    std.mem.writeInt(u64, out[at..][0..8], parts.registers.len, .little);
    at += 8;
    std.mem.writeInt(u64, out[at..][0..8], parts.controller.len, .little);
    at += 8;
    std.mem.writeInt(u32, out[at..][0..4], @intCast(parts.queues.len), .little);
    at += 4;
    std.mem.writeInt(u32, out[at..][0..4], parts.cpus, .little);
    at += 4;

    for (parts.queues) |each| {
        each.write(out[at..][0..QueueState.bytes]);
        at += QueueState.bytes;
    }

    @memcpy(out[at..][0..parts.running.len], parts.running);
    at += parts.running.len;

    @memcpy(out[at..][0..parts.registers.len], parts.registers);
    at += parts.registers.len;
    @memcpy(out[at..][0..parts.controller.len], parts.controller);
    at += parts.controller.len;
    @memcpy(out[at..][0..parts.memory.len], parts.memory);
    at += parts.memory.len;

    return at;
}

/// What a snapshot's bytes say, pointing into them. Every length in the header was written by
/// whoever made the snapshot, so each one is checked against what really arrived.
pub fn parse(bytes: []const u8, queues: *[max_queues]QueueState) Error!Parts {
    if (bytes.len < header_size) return Error.Truncated;
    if (!std.mem.eql(u8, bytes[0..magic.len], magic)) return Error.NotASnapshot;

    var at = magic.len;
    if (std.mem.readInt(u32, bytes[at..][0..4], .little) != version) return Error.UnknownVersion;
    at += 4;
    const ram_base = std.mem.readInt(u64, bytes[at..][0..8], .little);
    at += 8;
    const memory_len = std.mem.readInt(u64, bytes[at..][0..8], .little);
    at += 8;
    const registers_len = std.mem.readInt(u64, bytes[at..][0..8], .little);
    at += 8;
    const controller_len = std.mem.readInt(u64, bytes[at..][0..8], .little);
    at += 8;
    const queue_count = std.mem.readInt(u32, bytes[at..][0..4], .little);
    at += 4;
    const cpu_count = std.mem.readInt(u32, bytes[at..][0..4], .little);
    at += 4;

    if (queue_count > max_queues) return Error.TooManyDevices;
    if (cpu_count == 0 or cpu_count > max_cpus) return Error.TooManyDevices;
    // The registers have to divide evenly between the CPUs, because each one's set is the same length.
    // A count that does not divide them is a header that disagrees with its own body.
    if (registers_len % cpu_count != 0) return Error.Truncated;

    // Every length is checked against what is left before any of it is used, and the sum is
    // checked too, because three lengths that each fit can still not fit together.
    const wanted = std.math.add(u64, memory_len, registers_len) catch return Error.Truncated;
    const all = std.math.add(u64, wanted, controller_len) catch return Error.Truncated;
    const with_queues = all + @as(u64, queue_count) * QueueState.bytes + cpu_count;
    if (with_queues > bytes.len - header_size) return Error.Truncated;

    for (0..queue_count) |index| {
        queues[index] = QueueState.parse(bytes[at..][0..QueueState.bytes]);
        at += QueueState.bytes;
    }

    const running = bytes[at..][0..cpu_count];
    at += cpu_count;

    const registers = bytes[at..][0..@intCast(registers_len)];
    at += @intCast(registers_len);
    const controller = bytes[at..][0..@intCast(controller_len)];
    at += @intCast(controller_len);
    const memory = bytes[at..][0..@intCast(memory_len)];

    return .{
        .ram_base = ram_base,
        .memory = memory,
        .registers = registers,
        .cpus = cpu_count,
        .running = running,
        .controller = controller,
        .queues = queues[0..queue_count],
    };
}

test "a snapshot goes out and comes back the same" {
    const gpa = testing.allocator();

    const memory = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const registers = [_]u8{ 0xaa, 0xbb, 0xcc };
    const controller = [_]u8{ 0x11, 0x22 };
    const queues = [_]QueueState{
        .{ .size = 256, .ready = true, .last_available = 42, .descriptor = 0x4000_1000, .available = 0x4000_2000, .used = 0x4000_3000 },
        .{ .size = 0, .ready = false, .last_available = 0, .descriptor = 0, .available = 0, .used = 0 },
    };

    const parts: Parts = .{
        .ram_base = 0x4000_0000,
        .memory = &memory,
        .registers = &registers,
        .cpus = 1,
        .running = &[_]u8{1},
        .controller = &controller,
        .queues = &queues,
    };

    const out = try gpa.alloc(u8, size(parts));
    defer gpa.free(out);
    const used = try write(parts, out);
    try testing.expectEqual(out.len, used);

    var back_queues: [max_queues]QueueState = undefined;
    const back = try parse(out[0..used], &back_queues);

    try testing.expectEqual(@as(u64, 0x4000_0000), back.ram_base);
    try testing.expectEqualSlices(u8, &memory, back.memory);
    try testing.expectEqualSlices(u8, &registers, back.registers);
    try testing.expectEqualSlices(u8, &controller, back.controller);
    try testing.expectEqual(@as(usize, 2), back.queues.len);

    // The place a device had reached in its ring is the field nothing else records, so losing it
    // would have the device read entries it has already served.
    try testing.expectEqual(@as(u16, 42), back.queues[0].last_available);
    try testing.expectEqual(@as(u16, 256), back.queues[0].size);
    try std.testing.expect(back.queues[0].ready);
    try testing.expectEqual(@as(u64, 0x4000_2000), back.queues[0].available);
    try std.testing.expect(!back.queues[1].ready);
}

test "bytes that are not a snapshot are refused" {
    var queues: [max_queues]QueueState = undefined;

    var nothing: [header_size]u8 = @splat(0);
    try testing.expectError(Error.NotASnapshot, parse(&nothing, &queues));

    // Too short to hold even the header.
    try testing.expectError(Error.Truncated, parse(nothing[0 .. header_size - 1], &queues));

    // The right magic and a version this code has no layout for. Reading the fields anyway would
    // put every length in the wrong place.
    @memcpy(nothing[0..magic.len], magic);
    std.mem.writeInt(u32, nothing[magic.len..][0..4], 99, .little);
    try testing.expectError(Error.UnknownVersion, parse(&nothing, &queues));
}

test "a header that claims more than arrived is refused" {
    const gpa = testing.allocator();
    var queues: [max_queues]QueueState = undefined;

    const memory = [_]u8{ 1, 2, 3, 4 };
    const parts: Parts = .{
        .ram_base = 0,
        .memory = &memory,
        .registers = &.{},
        .cpus = 1,
        .running = &[_]u8{1},
        .controller = &.{},
        .queues = &.{},
    };
    const out = try gpa.alloc(u8, size(parts));
    defer gpa.free(out);
    _ = try write(parts, out);

    // The memory length says far more than the file holds. A reader that trusts it hands out a
    // slice past the end of what it was given.
    std.mem.writeInt(u64, out[magic.len + 4 + 8 ..][0..8], 1 << 40, .little);
    try testing.expectError(Error.Truncated, parse(out, &queues));

    // And a length that overflows when the three are added together.
    std.mem.writeInt(u64, out[magic.len + 4 + 8 ..][0..8], std.math.maxInt(u64), .little);
    std.mem.writeInt(u64, out[magic.len + 4 + 16 ..][0..8], 8, .little);
    try testing.expectError(Error.Truncated, parse(out, &queues));
}

test "more devices than this format holds is refused rather than partly held" {
    const gpa = testing.allocator();
    const many = try gpa.alloc(QueueState, max_queues + 1);
    defer gpa.free(many);
    @memset(many, .{ .size = 0, .ready = false, .last_available = 0, .descriptor = 0, .available = 0, .used = 0 });

    const parts: Parts = .{
        .ram_base = 0,
        .memory = &.{},
        .registers = &.{},
        .cpus = 1,
        .running = &[_]u8{1},
        .controller = &.{},
        .queues = many,
    };
    var out: [4096]u8 = undefined;
    try testing.expectError(Error.TooManyDevices, write(parts, &out));
}

test "a queue's state survives being taken out of one and put into another" {
    const from: device.virtio.Queue = .{
        .size = 128,
        .descriptor = 0x4100_0000,
        .available = 0x4100_1000,
        .used = 0x4100_2000,
        .ready = true,
        .last_available = 7,
    };
    const saved: QueueState = .of(from);

    var to: device.virtio.Queue = .{ .size = 0, .descriptor = 0, .available = 0, .used = 0 };
    saved.into(&to);

    try testing.expectEqual(from.size, to.size);
    try testing.expectEqual(from.descriptor, to.descriptor);
    try testing.expectEqual(from.available, to.available);
    try testing.expectEqual(from.used, to.used);
    try testing.expectEqual(from.ready, to.ready);
    try testing.expectEqual(from.last_available, to.last_available);
}

test "a snapshot of several cpus keeps each one apart" {
    const gpa = testing.allocator();

    // Three CPUs, four register bytes each, and the middle one stopped. A machine with several CPUs
    // that came back with only the first would be a machine missing most of itself.
    const registers = [_]u8{ 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3 };
    const running = [_]u8{ 1, 0, 1 };

    const parts: Parts = .{
        .ram_base = 0x4000_0000,
        .memory = &.{},
        .registers = &registers,
        .cpus = 3,
        .running = &running,
        .controller = &.{},
        .queues = &.{},
    };

    const out = try gpa.alloc(u8, size(parts));
    defer gpa.free(out);
    _ = try write(parts, out);

    var queues: [max_queues]QueueState = undefined;
    const back = try parse(out, &queues);

    try testing.expectEqual(@as(u32, 3), back.cpus);
    try testing.expectEqualSlices(u8, &.{ 1, 1, 1, 1 }, back.registersFor(0));
    try testing.expectEqualSlices(u8, &.{ 2, 2, 2, 2 }, back.registersFor(1));
    try testing.expectEqualSlices(u8, &.{ 3, 3, 3, 3 }, back.registersFor(2));

    // And which of them was running, which is not in any register.
    try std.testing.expect(back.wasRunning(0));
    try std.testing.expect(!back.wasRunning(1));
    try std.testing.expect(back.wasRunning(2));
}

test "a snapshot whose cpus do not divide its registers is refused" {
    const gpa = testing.allocator();

    // Five bytes across two CPUs. Each CPU's set is the same length, so this is a header that
    // disagrees with its own body, and reading it would give one CPU another's registers.
    const registers = [_]u8{ 1, 2, 3, 4, 5 };
    const parts: Parts = .{
        .ram_base = 0,
        .memory = &.{},
        .registers = &registers,
        .cpus = 2,
        .running = &[_]u8{ 1, 1 },
        .controller = &.{},
        .queues = &.{},
    };

    var out: [512]u8 = undefined;
    try testing.expectError(Error.TooManyDevices, write(parts, &out));

    // And the same disagreement is refused on the way back in, whoever wrote it.
    const honest: Parts = .{
        .ram_base = 0,
        .memory = &.{},
        .registers = &[_]u8{ 1, 2, 3, 4 },
        .cpus = 2,
        .running = &[_]u8{ 1, 1 },
        .controller = &.{},
        .queues = &.{},
    };
    const bytes = try gpa.alloc(u8, size(honest));
    defer gpa.free(bytes);
    _ = try write(honest, bytes);

    // Say three CPUs where four register bytes were written.
    std.mem.writeInt(u32, bytes[magic.len + 4 + 8 + 8 + 8 + 8 + 4 ..][0..4], 3, .little);
    var queues: [max_queues]QueueState = undefined;
    try testing.expectError(Error.Truncated, parse(bytes, &queues));
}

test "a snapshot with no cpus at all is refused" {
    const parts: Parts = .{
        .ram_base = 0,
        .memory = &.{},
        .registers = &.{},
        .cpus = 0,
        .running = &.{},
        .controller = &.{},
        .queues = &.{},
    };
    var out: [512]u8 = undefined;
    try testing.expectError(Error.TooManyDevices, write(parts, &out));
}
