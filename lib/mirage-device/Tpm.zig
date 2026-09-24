//! The register interface a guest talks to a security chip through.
//!
//! This carries commands and answers and understands neither. What a command means is for whatever
//! is above this, which in practice hands it to a program that implements the commands, the same way
//! the network hands frames to a helper. A chip's command set is large; its transport is not.
//!
//! Why a guest wants one: firmware that measures each stage of a boot has to put those measurements
//! somewhere the guest cannot quietly rewrite, and then let the guest ask for them back in a form
//! it can show to somebody else. That is what this is for.
//!
//! The layout is the one in the Trusted Computing Group's interface specification, the version with
//! registers in memory rather than on a bus of its own, because that is the one a device tree can
//! describe and Linux's `tcg,tpm-tis-mmio` driver binds to.
//!
//! Every write comes from the guest. A length longer than the buffer, a command sent while another
//! is in flight, a register that does not exist: each one is refused and none of them assert.

const std = @import("std");
const testing = @import("mirage-testing");
const Bus = @import("Bus.zig");

const Tpm = @This();

/// How much address space the interface takes. Five localities of one page each.
pub const len = 0x5000;

/// The largest command or answer carried. The specification's own minimum for a chip that can do
/// anything useful, and more than any measurement command needs.
pub const max_command = 4096;

/// Commands and answers both begin with a tag, then their own length, then a code. The length is
/// what says where a command ends, so it is read from there rather than from how much arrived.
pub const header_size = 10;

const reg = struct {
    const access = 0x000;
    const int_enable = 0x008;
    const int_vector = 0x00c;
    const int_status = 0x010;
    const interface_capability = 0x014;
    const status = 0x018;
    const burst_count = 0x019;
    const data_fifo = 0x024;
    const interface_id = 0x030;
    const extended_fifo = 0x080;
    const vendor = 0xf00;
    const revision = 0xf04;
};

/// `TPM_ACCESS`.
const access_establishment = 1 << 0;
const access_request_use = 1 << 1;
const access_pending_request = 1 << 2;
const access_seize = 1 << 3;
const access_been_seized = 1 << 4;
const access_active_locality = 1 << 5;
const access_valid = 1 << 7;

/// `TPM_STS`.
const status_response_retry = 1 << 1;
const status_self_test_done = 1 << 2;
const status_expect = 1 << 3;
const status_data_available = 1 << 4;
const status_go = 1 << 5;
const status_command_ready = 1 << 6;
const status_valid = 1 << 7;

/// What this chip says it is. A driver reads these to decide it has found something it can talk to,
/// and a driver that reads nothing recognisable does not attach.
const vendor_id = 0x0001_15d1;
const revision_id = 0x01;

/// What the interface can do: it takes a whole command in one burst and needs no interrupt.
const capability = 0x3000_0000 | (1 << 9) | (1 << 8) | (1 << 4);

pub const Phase = enum {
    /// Nothing in flight. The guest may start writing a command.
    idle,
    /// The guest is writing a command and has not said it is finished.
    receiving,
    /// A whole command is here and whatever is above this has not answered it yet.
    asking,
    /// An answer is here and the guest has not finished reading it.
    answering,
};

/// Which locality the guest claimed, or none.
locality: ?u8 = null,
phase: Phase = .idle,

/// The command being written, or the answer being read.
buffer: [max_command]u8 = undefined,
length: usize = 0,
/// How far the guest has read into an answer.
read_at: usize = 0,

/// Commands that ran past the buffer, answers offered when nothing was asked, and writes to a
/// locality that was never claimed. A guest is allowed to be wrong and a fault recovered in silence
/// is a bug that hides itself.
refused: u64 = 0,

/// Carries commands between a chip and whatever answers them.
///
/// The chip understands no command, so something else has to. That something is usually another
/// program on the far end of a socket, and this moves whole commands to it and whole answers back.
/// `Transport` is anything with `read` and `write` that do not wait, because this runs on the thread
/// the guest runs on: a transport that waited would stop the guest until the far end replied.
pub fn Relay(comptime Transport: type) type {
    return struct {
        const Self = @This();

        buffer: [max_command]u8 = undefined,
        /// How much of an answer arrived. An answer can come in pieces and only a whole one is
        /// given to the guest.
        held: usize = 0,
        /// Whether the command in flight already went out. A command goes in one piece.
        sent: bool = false,

        answered: u64 = 0,
        /// The far end closed or failed. A chip whose helper went away answers nothing more, and a
        /// guest waiting on it finds out by waiting, which is what a real chip that died looks like.
        gone: bool = false,

        /// Move whatever can move. Call it often; it does nothing when there is nothing in flight.
        pub fn carry(self: *Self, chip: *Tpm, transport: *Transport) void {
            if (self.gone) return;

            const waiting = chip.asked() orelse {
                // Nothing in flight, so the next command starts from the beginning.
                self.sent = false;
                self.held = 0;
                return;
            };

            if (!self.sent) {
                // A transport that took less than the whole command would leave the far end waiting
                // for a rest it never sees, so this is tried again rather than half sent.
                const moved = transport.write(waiting) catch {
                    self.gone = true;
                    return;
                };
                if (moved != waiting.len) return;
                self.sent = true;
            }

            const got = transport.read(self.buffer[self.held..]) catch {
                self.gone = true;
                return;
            };
            self.held += got;

            // An answer says how long it is, so there is no guessing about where it ends.
            const declared = declaredLength(self.buffer[0..self.held]) orelse return;
            if (self.held < declared) return;

            if (chip.answer(self.buffer[0..declared])) self.answered += 1;
            self.sent = false;
            self.held = 0;
        }
    };
}

pub fn device(self: *Tpm, at: u64) Bus.Device {
    return .{
        .base = at,
        .len = len,
        .ctx = self,
        .vtable = &.{ .read = Tpm.read, .write = Tpm.write },
    };
}

/// The command the guest is waiting for an answer to, or nothing.
pub fn asked(self: *const Tpm) ?[]const u8 {
    if (self.phase != .asking) return null;
    return self.buffer[0..self.length];
}

/// Give the guest its answer. Refused when nothing was asked, because an answer to nothing is an
/// answer the guest would read as the reply to whatever it sends next.
pub fn answer(self: *Tpm, bytes: []const u8) bool {
    if (self.phase != .asking) {
        self.refused += 1;
        return false;
    }
    if (bytes.len > self.buffer.len or bytes.len < header_size) {
        self.refused += 1;
        return false;
    }

    @memcpy(self.buffer[0..bytes.len], bytes);
    self.length = bytes.len;
    self.read_at = 0;
    self.phase = .answering;
    return true;
}

/// How long a command or an answer says it is. Both carry it in the same place.
pub fn declaredLength(bytes: []const u8) ?u32 {
    if (bytes.len < 6) return null;
    return std.mem.readInt(u32, bytes[2..6], .big);
}

/// Whether the chip still needs more of the command the guest is writing. A command says its own
/// length, so this is that length against how much arrived, and not how much room is left.
fn wantsMore(self: *const Tpm) bool {
    const declared = declaredLength(self.buffer[0..self.length]) orelse return true;
    return self.length < declared;
}

fn statusByte(self: *const Tpm) u8 {
    var value: u8 = status_valid | status_self_test_done;
    switch (self.phase) {
        .idle => value |= status_command_ready,
        // A driver writes a whole command and then reads this to check the chip agrees it is whole.
        // One that still asks for more is a chip the driver will not tell to go: Linux reports
        // `TPM_STS_DATA_EXPECT should be unset` and starts the command again.
        .receiving => if (self.wantsMore()) {
            value |= status_expect;
        },
        // The command is with whoever answers it. Neither ready for another nor holding an answer.
        .asking => {},
        .answering => value |= status_data_available,
    }
    return value;
}

/// How many bytes the guest may move in one go. A driver reads this and believes it, so it is the
/// room that is really there.
fn burst(self: *const Tpm) u16 {
    return switch (self.phase) {
        .idle, .receiving => @intCast(self.buffer.len - self.length),
        .answering => @intCast(self.length - self.read_at),
        .asking => 0,
    };
}

fn read(ctx: *anyopaque, offset: u64, size: Bus.Size) u64 {
    const self: *Tpm = @ptrCast(@alignCast(ctx));
    // Every locality answers the same, and which one is claimed is held once rather than per page.
    const at = offset % 0x1000;

    return switch (at) {
        reg.access => blk: {
            var value: u8 = access_valid | access_establishment;
            if (self.locality != null) value |= access_active_locality;
            break :blk value;
        },
        reg.status => blk: {
            // A driver often reads the status and the burst count as one word, so the count sits
            // where the specification puts it: in the two bytes above the status.
            const status: u32 = self.statusByte();
            if (@intFromEnum(size) >= 4) break :blk status | (@as(u32, self.burst()) << 8);
            break :blk status;
        },
        reg.burst_count => self.burst() & 0xff,
        reg.burst_count + 1 => self.burst() >> 8,
        reg.interface_capability => capability,
        reg.data_fifo, reg.extended_fifo => self.take(@intFromEnum(size)),
        reg.vendor => vendor_id,
        reg.revision => revision_id,
        reg.int_enable, reg.int_status, reg.int_vector => 0,
        // The identifier register says this is the memory mapped interface and nothing else.
        reg.interface_id => 0,
        else => 0,
    };
}

/// Read up to `width` bytes of the answer out of the data register.
fn take(self: *Tpm, width: usize) u64 {
    if (self.phase != .answering) {
        self.refused += 1;
        return 0xff;
    }

    var value: u64 = 0;
    var moved: usize = 0;
    while (moved < width and self.read_at < self.length) : (moved += 1) {
        value |= @as(u64, self.buffer[self.read_at]) << @intCast(moved * 8);
        self.read_at += 1;
    }
    // The whole answer has been read, so the chip is ready for another command.
    if (self.read_at == self.length) {
        self.phase = .idle;
        self.length = 0;
        self.read_at = 0;
    }
    return value;
}

fn write(ctx: *anyopaque, offset: u64, size: Bus.Size, value: u64) void {
    const self: *Tpm = @ptrCast(@alignCast(ctx));
    const at = offset % 0x1000;
    const which: u8 = @intCast(offset / 0x1000);

    switch (at) {
        reg.access => {
            const byte: u8 = @truncate(value);
            if (byte & access_request_use != 0 or byte & access_seize != 0) self.locality = which;
            // Giving up a locality abandons whatever was in flight, which is what a driver that
            // has given up expects.
            if (byte & access_active_locality != 0) {
                self.locality = null;
                self.phase = .idle;
                self.length = 0;
                self.read_at = 0;
            }
        },
        reg.status => self.command(@truncate(value)),
        reg.data_fifo, reg.extended_fifo => self.put(value, @intFromEnum(size)),
        else => {},
    }
}

/// A write to the status register is an instruction rather than a value.
fn command(self: *Tpm, value: u32) void {
    if (value & status_command_ready != 0) {
        // Ready for a command, which also throws away a half written one.
        self.phase = .idle;
        self.length = 0;
        self.read_at = 0;
    }
    if (value & status_response_retry != 0 and self.phase == .answering) {
        self.read_at = 0;
    }
    if (value & status_go != 0 and self.phase == .receiving) {
        // The guest says the command is whole. Believe the length it wrote only so far as what
        // really arrived, because the two are chosen separately.
        const declared = declaredLength(self.buffer[0..self.length]) orelse {
            self.refused += 1;
            self.phase = .idle;
            self.length = 0;
            return;
        };
        if (declared != self.length) {
            self.refused += 1;
            self.phase = .idle;
            self.length = 0;
            return;
        }
        self.phase = .asking;
    }
}

/// Write up to `width` bytes of a command into the data register.
fn put(self: *Tpm, value: u64, width: usize) void {
    if (self.locality == null) {
        self.refused += 1;
        return;
    }
    if (self.phase == .idle) self.phase = .receiving;
    if (self.phase != .receiving) {
        self.refused += 1;
        return;
    }

    var moved: usize = 0;
    while (moved < width) : (moved += 1) {
        if (self.length == self.buffer.len) {
            // A command longer than this chip holds. Refusing keeps the rest out of memory that is
            // not the buffer.
            self.refused += 1;
            return;
        }
        self.buffer[self.length] = @truncate(value >> @intCast(moved * 8));
        self.length += 1;
    }
}

const base = 0x0c00_0000;

/// A command with a correct header, which is the only thing this device looks at.
fn commandBytes(into: []u8, code: u32, payload: []const u8) []u8 {
    const total = header_size + payload.len;
    std.mem.writeInt(u16, into[0..2], 0x8001, .big);
    std.mem.writeInt(u32, into[2..6], @intCast(total), .big);
    std.mem.writeInt(u32, into[6..10], code, .big);
    @memcpy(into[header_size..total], payload);
    return into[0..total];
}

fn claim(bus: *Bus) void {
    bus.write(base + reg.access, .byte, access_request_use);
}

fn send(bus: *Bus, bytes: []const u8) void {
    for (bytes) |byte| bus.write(base + reg.data_fifo, .byte, byte);
    bus.write(base + reg.status, .word, status_go);
}

test "a driver reads something it recognises" {
    var tpm: Tpm = .{};
    var devices = [_]Bus.Device{tpm.device(base)};
    var bus: Bus = .{ .devices = &devices };

    // A driver that reads nothing recognisable here does not attach, so these two are what decide
    // whether the guest has a chip at all.
    try testing.expectEqual(@as(u64, vendor_id), bus.read(base + reg.vendor, .word));
    try testing.expectEqual(@as(u64, revision_id), bus.read(base + reg.revision, .byte));

    // Before anything is claimed the interface says it is valid and nobody holds it.
    const access = bus.read(base + reg.access, .byte);
    try std.testing.expect(access & access_valid != 0);
    try std.testing.expect(access & access_active_locality == 0);
}

test "claiming a locality is what lets a command be written" {
    var tpm: Tpm = .{};
    var devices = [_]Bus.Device{tpm.device(base)};
    var bus: Bus = .{ .devices = &devices };

    // Writing without claiming is refused. A chip that takes it would be taking commands from a
    // guest that has not said which locality it speaks for.
    bus.write(base + reg.data_fifo, .byte, 0x80);
    try testing.expectEqual(@as(u64, 1), tpm.refused);
    try testing.expectEqual(Phase.idle, tpm.phase);

    claim(&bus);
    try std.testing.expect(bus.read(base + reg.access, .byte) & access_active_locality != 0);

    bus.write(base + reg.data_fifo, .byte, 0x80);
    try testing.expectEqual(Phase.receiving, tpm.phase);
}

test "a command goes in and comes out whole" {
    var tpm: Tpm = .{};
    var devices = [_]Bus.Device{tpm.device(base)};
    var bus: Bus = .{ .devices = &devices };

    claim(&bus);

    var scratch: [64]u8 = undefined;
    const sent = commandBytes(&scratch, 0x0000_0181, "measure me");
    send(&bus, sent);

    // The whole command is here and the chip is waiting for somebody to answer it.
    try testing.expectEqual(Phase.asking, tpm.phase);
    const asked_for = tpm.asked() orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, sent, asked_for);

    // And the status says neither ready nor holding an answer, because it is neither.
    const status = bus.read(base + reg.status, .byte);
    try std.testing.expect(status & status_command_ready == 0);
    try std.testing.expect(status & status_data_available == 0);
}

test "an answer comes back a byte at a time and leaves the chip ready" {
    var tpm: Tpm = .{};
    var devices = [_]Bus.Device{tpm.device(base)};
    var bus: Bus = .{ .devices = &devices };

    claim(&bus);
    var scratch: [64]u8 = undefined;
    send(&bus, commandBytes(&scratch, 0x0000_0181, "ask"));

    var reply: [64]u8 = undefined;
    const given = commandBytes(&reply, 0x0000_0000, "the answer");
    try std.testing.expect(tpm.answer(given));

    // The guest is told there is something to read, and how much it may take.
    try std.testing.expect(bus.read(base + reg.status, .byte) & status_data_available != 0);
    try testing.expectEqual(@as(u64, given.len), bus.read(base + reg.burst_count, .half));

    var got: [64]u8 = undefined;
    for (0..given.len) |index| got[index] = @truncate(bus.read(base + reg.data_fifo, .byte));
    try testing.expectEqualSlices(u8, given, got[0..given.len]);

    // The whole answer is read, so the chip is ready for another command rather than still holding
    // the last one.
    try testing.expectEqual(Phase.idle, tpm.phase);
    try std.testing.expect(bus.read(base + reg.status, .byte) & status_command_ready != 0);
}

test "a command whose length disagrees with what arrived is refused" {
    var tpm: Tpm = .{};
    var devices = [_]Bus.Device{tpm.device(base)};
    var bus: Bus = .{ .devices = &devices };

    claim(&bus);

    // The header says thirty bytes and ten arrive. A chip that answers this answers a command it
    // was never given the whole of.
    var scratch: [64]u8 = @splat(0);
    std.mem.writeInt(u16, scratch[0..2], 0x8001, .big);
    std.mem.writeInt(u32, scratch[2..6], 30, .big);
    send(&bus, scratch[0..header_size]);

    try testing.expectEqual(Phase.idle, tpm.phase);
    try std.testing.expect(tpm.asked() == null);
    try testing.expectEqual(@as(u64, 1), tpm.refused);
}

test "a command longer than the chip holds stops at the end of the buffer" {
    var tpm: Tpm = .{};
    var devices = [_]Bus.Device{tpm.device(base)};
    var bus: Bus = .{ .devices = &devices };

    claim(&bus);

    // The guest chooses how much it writes. A chip that keeps taking it writes past its own buffer.
    for (0..max_command + 64) |_| bus.write(base + reg.data_fifo, .byte, 0x5a);

    try testing.expectEqual(@as(usize, max_command), tpm.length);
    try std.testing.expect(tpm.refused > 0);
}

test "an answer offered when nothing was asked is refused" {
    var tpm: Tpm = .{};

    // Otherwise the guest reads it as the reply to whatever it sends next.
    var reply: [64]u8 = undefined;
    try std.testing.expect(!tpm.answer(commandBytes(&reply, 0, "unasked")));
    try testing.expectEqual(@as(u64, 1), tpm.refused);
    try testing.expectEqual(Phase.idle, tpm.phase);
}

test "asking to be ready throws away a half written command" {
    var tpm: Tpm = .{};
    var devices = [_]Bus.Device{tpm.device(base)};
    var bus: Bus = .{ .devices = &devices };

    claim(&bus);
    bus.write(base + reg.data_fifo, .byte, 0x80);
    bus.write(base + reg.data_fifo, .byte, 0x01);
    try testing.expectEqual(Phase.receiving, tpm.phase);

    // A driver that has given up says it is ready again, and what it had written must not become
    // the front of the next command.
    bus.write(base + reg.status, .word, status_command_ready);
    try testing.expectEqual(Phase.idle, tpm.phase);
    try testing.expectEqual(@as(usize, 0), tpm.length);
}

test "a driver that asks again reads the answer from the start" {
    var tpm: Tpm = .{};
    var devices = [_]Bus.Device{tpm.device(base)};
    var bus: Bus = .{ .devices = &devices };

    claim(&bus);
    var scratch: [64]u8 = undefined;
    send(&bus, commandBytes(&scratch, 0x0000_0181, "ask"));

    var reply: [64]u8 = undefined;
    const given = commandBytes(&reply, 0, "read me twice");
    try std.testing.expect(tpm.answer(given));

    const first = bus.read(base + reg.data_fifo, .byte);
    _ = bus.read(base + reg.data_fifo, .byte);

    bus.write(base + reg.status, .word, status_response_retry);
    try testing.expectEqual(first, bus.read(base + reg.data_fifo, .byte));
}

test "giving up a locality abandons what was in flight" {
    var tpm: Tpm = .{};
    var devices = [_]Bus.Device{tpm.device(base)};
    var bus: Bus = .{ .devices = &devices };

    claim(&bus);
    var scratch: [64]u8 = undefined;
    send(&bus, commandBytes(&scratch, 0x0000_0181, "ask"));
    try testing.expectEqual(Phase.asking, tpm.phase);

    // A driver that hands the chip back has stopped waiting, so holding its command would have the
    // next claimant read somebody else's answer.
    bus.write(base + reg.access, .byte, access_active_locality);
    try testing.expectEqual(Phase.idle, tpm.phase);
    try std.testing.expect(tpm.asked() == null);
    try std.testing.expect(bus.read(base + reg.access, .byte) & access_active_locality == 0);
}

test "the chip asks for more only while more is really coming" {
    var tpm: Tpm = .{};
    var devices = [_]Bus.Device{tpm.device(base)};
    var bus: Bus = .{ .devices = &devices };

    claim(&bus);

    var scratch: [64]u8 = undefined;
    const sent = commandBytes(&scratch, 0x0000_0181, "measure me");

    // Linux writes a command up to its last byte, checks the chip says it wants more, writes that
    // last byte, then checks the chip has stopped asking. A chip that asks for more after the whole
    // command arrived never gets told to go.
    for (sent[0 .. sent.len - 1]) |byte| {
        bus.write(base + reg.data_fifo, .byte, byte);
        try std.testing.expect(bus.read(base + reg.status, .byte) & status_expect != 0);
    }

    bus.write(base + reg.data_fifo, .byte, sent[sent.len - 1]);
    try std.testing.expect(bus.read(base + reg.status, .byte) & status_expect == 0);

    // Nothing was refused: the chip took every byte and only its answer about wanting more changed.
    try testing.expectEqual(@as(u64, 0), tpm.refused);
    try testing.expectEqual(Phase.receiving, tpm.phase);
}

/// A transport that answers every command with the same fixed answer, and does it a few bytes at a
/// time, because a socket does that too.
const Trickle = struct {
    answer: []const u8,
    out: usize = 0,
    /// How much of an answer to give per read. One byte proves the relay waits for the rest.
    per_read: usize = 1,
    taken: usize = 0,

    fn write(self: *Trickle, bytes: []const u8) !usize {
        self.taken += 1;
        self.out = 0;
        return bytes.len;
    }

    fn read(self: *Trickle, into: []u8) !usize {
        const left = self.answer.len - self.out;
        const moving = @min(@min(left, self.per_read), into.len);
        @memcpy(into[0..moving], self.answer[self.out..][0..moving]);
        self.out += moving;
        return moving;
    }
};

test "the relay gives the guest an answer only once all of it arrived" {
    var tpm: Tpm = .{};
    var devices = [_]Bus.Device{tpm.device(base)};
    var bus: Bus = .{ .devices = &devices };

    var scratch: [64]u8 = undefined;
    const reply = commandBytes(&scratch, 0, "here you are");

    var transport: Trickle = .{ .answer = reply };
    var relay: Relay(Trickle) = .{};

    // Nothing in flight, so nothing moves and nothing is sent.
    relay.carry(&tpm, &transport);
    try testing.expectEqual(@as(usize, 0), transport.taken);

    claim(&bus);
    var out: [64]u8 = undefined;
    send(&bus, commandBytes(&out, 0x0000_0181, "measure me"));
    try testing.expectEqual(Phase.asking, tpm.phase);

    // One byte per turn. The guest holds nothing until the last byte of the answer arrives, because
    // half an answer read as a whole one is a guest that believes something the chip never said.
    for (0..reply.len - 1) |_| {
        relay.carry(&tpm, &transport);
        try testing.expectEqual(Phase.asking, tpm.phase);
    }
    relay.carry(&tpm, &transport);

    try testing.expectEqual(Phase.answering, tpm.phase);
    try testing.expectEqual(@as(u64, 1), relay.answered);
    try testing.expectEqual(@as(usize, 1), transport.taken);
    try std.testing.expect(!relay.gone);

    // The answer the guest reads is the one the far end gave.
    for (reply) |byte| {
        try testing.expectEqual(@as(u64, byte), bus.read(base + reg.data_fifo, .byte));
    }
    try testing.expectEqual(Phase.idle, tpm.phase);

    // And the chip is ready for another, which the relay starts from the beginning.
    relay.carry(&tpm, &transport);
    try std.testing.expect(!relay.sent);
    try testing.expectEqual(@as(usize, 0), relay.held);
}

test "a transport that fails leaves the chip quiet rather than answering wrongly" {
    const Broken = struct {
        fn write(_: *@This(), _: []const u8) !usize {
            return error.ConnectionResetByPeer;
        }
        fn read(_: *@This(), _: []u8) !usize {
            return 0;
        }
    };

    var tpm: Tpm = .{};
    var devices = [_]Bus.Device{tpm.device(base)};
    var bus: Bus = .{ .devices = &devices };

    claim(&bus);
    var out: [64]u8 = undefined;
    send(&bus, commandBytes(&out, 0x0000_0181, "measure me"));

    var transport: Broken = .{};
    var relay: Relay(Broken) = .{};
    relay.carry(&tpm, &transport);

    try std.testing.expect(relay.gone);
    try testing.expectEqual(@as(u64, 0), relay.answered);
    // The guest is left waiting, which is what a chip that died looks like from inside.
    try testing.expectEqual(Phase.asking, tpm.phase);

    // And it stays that way rather than trying again forever.
    relay.carry(&tpm, &transport);
    try testing.expectEqual(Phase.asking, tpm.phase);
}
