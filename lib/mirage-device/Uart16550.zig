//! A 16550 UART, enough of one for an x86 guest to print through both the kernel's polled
//! console and the interrupt-driven tty the first process writes to.
//!
//! The kernel's early console polls the line status and writes a byte at a time. The full
//! driver the first process reaches instead writes a byte, enables the transmit interrupt,
//! and waits for it before writing the next. So the transmit holding register carries the
//! bytes, the line status says the transmitter is free, and the port raises an interrupt
//! whenever the transmit interrupt is enabled, because the transmitter is never busy.

const std = @import("std");
const testing = @import("mirage-testing");
const Bus = @import("Bus.zig");
const Service = @import("../mirage-device.zig").Service;
const GuestMemory = @import("mirage-memory").GuestMemory;

const Uart16550 = @This();

pub const len = 8;

/// The registers this port exposes, by offset from the base port address.
const reg = struct {
    /// Transmit holding register (write) / receive buffer register (read).
    const thr = 0;
    /// Interrupt enable register.
    const ier = 1;
    /// Interrupt identification / FIFO control.
    const iir_fcr = 2;
    /// Line control register. Accepted and ignored.
    const lcr = 3;
    /// Modem control register. Accepted and ignored.
    const mcr = 4;
    /// Line status register. Reports the transmitter always ready.
    const lsr = 5;
    /// Modem status register. Accepted and ignored.
    const msr = 6;
    /// Scratch register.
    const scr = 7;
};

/// THRE (bit 5) and TEMT (bit 6): the transmitter holds nothing and has nothing in
/// flight. A guest polls the line status before writing, so a port that never reports
/// itself ready leaves the guest spinning forever.
const lsr_ready: u64 = 0x60;

/// `UART_IER_THRI`: the guest wants an interrupt when the transmitter is free.
const ier_thri: u8 = 0x02;

/// `UART_IIR_THRI`: the identification register's code for a transmitter-empty interrupt.
const iir_thri: u8 = 0x02;

/// `UART_IIR_NO_INT`: the low bit set means nothing is pending.
const iir_none: u8 = 0x01;

sink: *std.Io.Writer,
/// Something to watch the guest say, and whether it has said it yet. A caller testing a guest
/// runs it until it prints a thing it knows rather than until a clock runs out, which is the
/// difference between a test that takes a second and one that takes a minute.
watch: []const u8 = &.{},
said: bool = false,
/// The last bytes the guest said, as many as the thing being watched for is long. Compared whole
/// each time rather than carried as a position: a match that can begin again inside itself is
/// easy to get wrong that way, and `aab` really is inside `aaab`.
recent: [max_watch]u8 = @splat(0),
heard: usize = 0,
/// Bytes the sink would not take. A byte lost in silence is a bug that hides itself.
dropped: u64 = 0,
/// What the guest asked to be interrupted for. The transmitter is never busy, so the
/// transmit bit is the whole of what matters here.
ier: u8 = 0,
/// Set in the scratch register, read back unchanged. The driver's probe writes a byte here
/// and reads it to decide the port exists, so a port that forgets it looks absent.
scratch: u8 = 0,

pub fn device(self: *Uart16550, port: u64) Bus.Device {
    return .{
        .base = port,
        .len = len,
        .ctx = self,
        .vtable = &.{ .read = Uart16550.read, .write = Uart16550.write },
    };
}

/// Whether the port has an interrupt to raise. The transmitter is always free, so the only
/// question is whether the guest asked to hear about it. The run loop reads this and moves
/// the port's interrupt line to match.
pub fn signalling(self: *const Uart16550) bool {
    return self.ier & ier_thri != 0;
}

/// An adapter for the run loop's poll path. The loop raises GSI `intid` when the
/// poll returns true, and lowers it when false.
pub fn service(self: *Uart16550, intid: u32) Service {
    return .{ .ctx = self, .intid = intid, .poll = Uart16550.poll };
}

fn poll(ctx: *anyopaque, memory: *GuestMemory) Service.Error!bool {
    _ = memory;
    const self: *Uart16550 = @ptrCast(@alignCast(ctx));
    return self.signalling();
}

fn read(ctx: *anyopaque, offset: u64, size: Bus.Size) u64 {
    _ = size;
    const self: *Uart16550 = @ptrCast(@alignCast(ctx));
    return switch (offset) {
        reg.lsr => lsr_ready,
        reg.ier => self.ier,
        // The one interrupt this port raises is the transmitter going free. Reading the
        // identification register is how the driver's handler learns what to service and
        // clears it; the transmitter is free again at once, so the next read says so too.
        reg.iir_fcr => if (self.signalling()) iir_thri else iir_none,
        reg.scr => self.scratch,
        // RBR (offset 0) returns 0: this port carries no input.
        reg.thr, reg.lcr, reg.mcr, reg.msr => 0,
        else => 0,
    };
}

/// The longest thing that can be watched for. A caller asking for more is refused where the ask
/// is made rather than left with a guest that never stops.
pub const max_watch = 64;

/// Take one byte of what the guest said and see whether it has now said the thing being watched
/// for. The match runs over the stream rather than over a line, so the thing may be split across
/// however many writes the guest made.
fn hear(self: *@This(), byte: u8) void {
    if (self.watch.len == 0 or self.said) return;
    if (self.watch.len > self.recent.len) return;

    const wanted = self.watch.len;
    if (self.heard < wanted) {
        self.recent[self.heard] = byte;
        self.heard += 1;
    } else {
        std.mem.copyForwards(u8, self.recent[0 .. wanted - 1], self.recent[1..wanted]);
        self.recent[wanted - 1] = byte;
    }

    if (self.heard == wanted and std.mem.eql(u8, self.recent[0..wanted], self.watch)) self.said = true;
}

fn write(ctx: *anyopaque, offset: u64, size: Bus.Size, value: u64) void {
    _ = size;
    const self: *Uart16550 = @ptrCast(@alignCast(ctx));
    switch (offset) {
        reg.thr => {
            self.hear(@truncate(value));
            self.sink.writeByte(@truncate(value)) catch {
                self.dropped += 1;
            };
        },
        reg.ier => self.ier = @truncate(value),
        reg.scr => self.scratch = @truncate(value),
        // IIR/FCR, LCR, MCR, MSR: accepted and ignored.
        reg.iir_fcr, reg.lcr, reg.mcr, reg.msr => {},
        else => {},
    }
}

test "a byte written to the 16550 transmit register reaches the sink" {
    var buf: [16]u8 = undefined;
    var sink = std.Io.Writer.fixed(&buf);
    var uart: Uart16550 = .{ .sink = &sink };
    var devices = [_]Bus.Device{uart.device(0x3f8)};
    var bus: Bus = .{ .devices = &devices };
    bus.write(0x3f8, .byte, 'M');
    try testing.expectEqualSlices(u8, "M", sink.buffered());
}

test "the line status register reports the transmitter ready" {
    // read 0x3f8+5 -> 0x60 (THRE|TEMT) so the guest never spins
    var buf: [16]u8 = undefined;
    var sink = std.Io.Writer.fixed(&buf);
    var uart: Uart16550 = .{ .sink = &sink };
    var devices = [_]Bus.Device{uart.device(0x3f8)};
    var bus: Bus = .{ .devices = &devices };
    try testing.expectEqual(@as(u64, 0x60), bus.read(0x3f8 + 5, .byte));
}

test "the uart service reports the transmit interrupt" {
    var buf: [16]u8 = undefined;
    var sink = std.Io.Writer.fixed(&buf);
    var uart: Uart16550 = .{ .sink = &sink };
    var devices = [_]Bus.Device{uart.device(0x3f8)};
    var bus: Bus = .{ .devices = &devices };

    var regions: [0]GuestMemory.Region = .{};
    var mem: GuestMemory = .{ .regions = &regions };

    var s = uart.service(4);
    try std.testing.expect(!(try s.poll(s.ctx, &mem)));

    bus.write(0x3f8 + 1, .byte, ier_thri);
    try std.testing.expect(try s.poll(s.ctx, &mem));
}
