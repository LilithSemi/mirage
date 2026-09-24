//! A PL011 serial port, enough of one for a guest to print.
//!
//! This is the device an aarch64 Linux guest reaches with `earlycon=pl011`, so it is
//! the first thing a guest says anything through. Only two registers matter for
//! output: the data register the guest writes a byte to, and the flag register it
//! polls first.

const std = @import("std");
const testing = @import("mirage-testing");
const Bus = @import("Bus.zig");
const Gicv2 = @import("Gicv2.zig");

const Pl011 = @This();

pub const len = 0x1000;

const reg = struct {
    const dr = 0x000;
    const fr = 0x018;
    /// Which interrupts the driver wants to be told about.
    const ibrd = 0x024;
    const fbrd = 0x028;
    const lcr_h = 0x02c;
    const cr = 0x030;
    const ifls = 0x034;
    const imsc = 0x038;
    /// What has happened, before and after the mask is applied.
    const ris = 0x03c;
    const mis = 0x040;
    /// Writing here says the driver has dealt with an interrupt.
    const icr = 0x044;
    /// The PrimeCell identification registers. The AMBA bus driver reads these to
    /// work out what the peripheral is, and binds no driver when they read as zero.
    /// The early console skips the check, which is why a guest can print through
    /// this device long before `ttyAMA0` exists.
    const periph_id0 = 0xfe0;
    const cell_id3 = 0xffc;
};

/// `UARTPeriphID0` through `UARTPCellID3`, from the PL011 manual. The bus reads the
/// four peripheral bytes as one word and matches it against the driver, and the four
/// cell bytes are the constant every PrimeCell carries.
const identification = [_]u32{ 0x11, 0x10, 0x14, 0x00, 0x0d, 0xf0, 0x05, 0xb1 };

/// `TXFE`, the transmitter holds nothing, and `RXFE`, nothing has arrived. A guest
/// polls the flag register before it writes, so a transmitter that never reports
/// itself empty leaves the guest spinning in its own loop forever.
const fr_txfe: u64 = 1 << 7;
const fr_rxfe: u64 = 1 << 4;

/// The transmit interrupt. This port never fills, so there is always room and the
/// raw status always has this bit set. What decides whether the guest sees it is
/// whether the driver asked.
const interrupt_tx: u32 = 1 << 5;

/// Registers this port keeps but does not act on: the baud divisors, the line
/// control and the control register itself. A driver reads one, changes a bit and
/// writes it back, so a port that answers zero hands back a value the driver never
/// chose and undoes its own configuration.
const kept = [_]u64{ reg.ibrd, reg.fbrd, reg.lcr_h, reg.cr, reg.ifls };

sink: *std.Io.Writer,
/// Where to say an interrupt has happened, and which one. A port with nowhere to
/// report is still usable by a driver that polls, which is what an early console
/// does.
line: ?Line = null,
imsc: u32 = 0,
/// What was written to each of `kept`, in the same order.
held: [kept.len]u32 = @splat(0),
/// Bytes the sink would not take. Guest output lost in silence is worse than guest
/// output lost loudly.
dropped: u64 = 0,

pub const Line = struct {
    controller: @import("../mirage-device.zig").Controller,
    intid: u32,
};

/// The raw status. Room to transmit is the only thing this port ever reports.
fn status(self: *const Pl011) u32 {
    _ = self;
    return interrupt_tx;
}

/// Tell the controller whether this port is asking for attention. The interrupt is
/// a level, so it has to be released as well as raised.
fn refresh(self: *Pl011) void {
    const each = self.line orelse return;
    if (self.status() & self.imsc != 0) {
        each.controller.raise(each.controller.ctx, each.intid);
    } else {
        each.controller.lower(each.controller.ctx, each.intid);
    }
}

pub fn device(self: *Pl011, base: u64) Bus.Device {
    return .{
        .base = base,
        .len = len,
        .ctx = self,
        .vtable = &.{ .read = Pl011.read, .write = Pl011.write },
    };
}

fn read(ctx: *anyopaque, offset: u64, size: Bus.Size) u64 {
    _ = size;
    const self: *Pl011 = @ptrCast(@alignCast(ctx));

    if (offset >= reg.periph_id0 and offset <= reg.cell_id3) {
        const index = (offset - reg.periph_id0) / 4;
        return identification[@intCast(index)];
    }

    inline for (kept, 0..) |each, index| {
        if (offset == each) return self.held[index];
    }

    return switch (offset) {
        reg.fr => fr_txfe | fr_rxfe,
        reg.imsc => self.imsc,
        reg.ris => self.status(),
        reg.mis => self.status() & self.imsc,
        else => 0,
    };
}

fn write(ctx: *anyopaque, offset: u64, size: Bus.Size, value: u64) void {
    _ = size;
    const self: *Pl011 = @ptrCast(@alignCast(ctx));
    inline for (kept, 0..) |each, index| {
        if (offset == each) {
            self.held[index] = @truncate(value);
            return;
        }
    }

    switch (offset) {
        reg.dr => self.sink.writeByte(@truncate(value)) catch {
            self.dropped += 1;
        },
        reg.imsc => {
            self.imsc = @truncate(value);
            self.refresh();
        },
        // There is nothing to clear: the only thing reported is room to transmit,
        // and writing a byte does not use it up. The line is refreshed anyway, so a
        // driver that masks through this register is still obeyed.
        reg.icr => self.refresh(),
        else => {},
    }
}

test "the data register writes its byte to the sink" {
    var buffer: [16]u8 = undefined;
    var sink = std.Io.Writer.fixed(&buffer);
    var uart: Pl011 = .{ .sink = &sink };
    var devices = [_]Bus.Device{uart.device(0x0900_0000)};
    var bus: Bus = .{ .devices = &devices };

    bus.write(0x0900_0000, .byte, 'h');
    bus.write(0x0900_0000, .byte, 'i');

    try testing.expectEqualSlices(u8, "hi", sink.buffered());
}

test "the flag register reports the transmitter empty and nothing received" {
    var buffer: [16]u8 = undefined;
    var sink = std.Io.Writer.fixed(&buffer);
    var uart: Pl011 = .{ .sink = &sink };
    var devices = [_]Bus.Device{uart.device(0x0900_0000)};
    var bus: Bus = .{ .devices = &devices };

    // A guest polls this before it writes. Reporting the transmitter busy forever
    // hangs the guest in its own loop.
    const flags = bus.read(0x0900_0018, .word);
    try std.testing.expect(flags & (1 << 7) != 0);
    try std.testing.expect(flags & (1 << 4) != 0);
    try std.testing.expect(flags & (1 << 5) == 0);
}

test "a byte that cannot be written is counted rather than lost in silence" {
    var buffer: [2]u8 = undefined;
    var sink = std.Io.Writer.fixed(&buffer);
    var uart: Pl011 = .{ .sink = &sink };
    var devices = [_]Bus.Device{uart.device(0x0900_0000)};
    var bus: Bus = .{ .devices = &devices };

    bus.write(0x0900_0000, .byte, 'a');
    bus.write(0x0900_0000, .byte, 'b');
    bus.write(0x0900_0000, .byte, 'c');

    try testing.expectEqual(@as(u64, 1), uart.dropped);
}

test "the primecell identification registers name this device to the bus" {
    var buffer: [16]u8 = undefined;
    var sink = std.Io.Writer.fixed(&buffer);
    var uart: Pl011 = .{ .sink = &sink };
    var devices = [_]Bus.Device{uart.device(0x0900_0000)};
    var bus: Bus = .{ .devices = &devices };

    // The bus reads four bytes and joins them into the peripheral number. Masked the
    // way the driver masks it, this has to be the PL011.
    var periph: u32 = 0;
    for (0..4) |i| {
        const byte: u32 = @intCast(bus.read(0x0900_0000 + 0xfe0 + i * 4, .word));
        periph |= byte << @intCast(i * 8);
    }
    try testing.expectEqual(@as(u32, 0x0004_1011), periph & 0x000f_ffff);

    // Every PrimeCell carries the same cell number, and a zero here binds nothing.
    var cell: u32 = 0;
    for (0..4) |i| {
        const byte: u32 = @intCast(bus.read(0x0900_0000 + 0xff0 + i * 4, .word));
        cell |= byte << @intCast(i * 8);
    }
    try testing.expectEqual(@as(u32, 0xb105_f00d), cell);
}

test "the masked status is the raw status with the mask applied" {
    var buffer: [16]u8 = undefined;
    var sink = std.Io.Writer.fixed(&buffer);
    var uart: Pl011 = .{ .sink = &sink };
    var devices = [_]Bus.Device{uart.device(0x0900_0000)};
    var bus: Bus = .{ .devices = &devices };

    // Room to transmit is always there, so the raw status always says so.
    try testing.expectEqual(@as(u64, 1 << 5), bus.read(0x0900_003c, .word));
    // Nothing is masked in yet, so the driver is told nothing.
    try testing.expectEqual(@as(u64, 0), bus.read(0x0900_0040, .word));

    bus.write(0x0900_0038, .word, 1 << 5);
    try testing.expectEqual(@as(u64, 1 << 5), bus.read(0x0900_0040, .word));
}

test "asking for the transmit interrupt raises the line" {
    var controller: Gicv2 = .{};
    const on_bus = controller.devices(0x0800_0000, 0x0801_0000);

    var buffer: [16]u8 = undefined;
    var sink = std.Io.Writer.fixed(&buffer);
    var uart: Pl011 = .{
        .sink = &sink,
        .line = .{ .controller = controller.controller(), .intid = 33 },
    };
    var devices = [_]Bus.Device{ uart.device(0x0900_0000), on_bus[0], on_bus[1] };
    var bus: Bus = .{ .devices = &devices };

    bus.write(0x0800_0000, .word, 1);
    bus.write(0x0801_0000, .word, 1);
    bus.write(0x0801_0004, .word, 0xff);
    bus.write(0x0800_0100 + 4, .word, 1 << 1);
    // Which CPU the shared interrupt may go to. A driver writes this and one left empty is a shared
    // interrupt nothing ever sees, so a test that skips it is testing the wrong thing.
    bus.write(0x0800_0800 + 33, .byte, 1);

    try std.testing.expect(!controller.signalled(0));
    bus.write(0x0900_0038, .word, 1 << 5);
    try std.testing.expect(controller.signalled(0));
}

test "masking the transmit interrupt again releases the line" {
    var controller: Gicv2 = .{};
    const on_bus = controller.devices(0x0800_0000, 0x0801_0000);

    var buffer: [16]u8 = undefined;
    var sink = std.Io.Writer.fixed(&buffer);
    var uart: Pl011 = .{
        .sink = &sink,
        .line = .{ .controller = controller.controller(), .intid = 33 },
    };
    var devices = [_]Bus.Device{ uart.device(0x0900_0000), on_bus[0], on_bus[1] };
    var bus: Bus = .{ .devices = &devices };

    bus.write(0x0800_0000, .word, 1);
    bus.write(0x0801_0000, .word, 1);
    bus.write(0x0801_0004, .word, 0xff);
    bus.write(0x0800_0100 + 4, .word, 1 << 1);
    // Which CPU the shared interrupt may go to. A driver writes this and one left empty is a shared
    // interrupt nothing ever sees, so a test that skips it is testing the wrong thing.
    bus.write(0x0800_0800 + 33, .byte, 1);

    bus.write(0x0900_0038, .word, 1 << 5);
    try std.testing.expect(controller.signalled(0));

    // A driver masks this once it has nothing more to send. A port that keeps the
    // line up interrupts the guest forever.
    bus.write(0x0900_0038, .word, 0);
    try std.testing.expect(!controller.signalled(0));
}

test "a port with nowhere to report is still usable by a driver that polls" {
    var buffer: [16]u8 = undefined;
    var sink = std.Io.Writer.fixed(&buffer);
    var uart: Pl011 = .{ .sink = &sink };
    var devices = [_]Bus.Device{uart.device(0x0900_0000)};
    var bus: Bus = .{ .devices = &devices };

    // An early console never asks for an interrupt, and must not need one.
    bus.write(0x0900_0038, .word, 1 << 5);
    bus.write(0x0900_0000, .byte, 'p');
    try testing.expectEqualSlices(u8, "p", sink.buffered());
}

test "a register the port keeps reads back as it was written" {
    var buffer: [16]u8 = undefined;
    var sink = std.Io.Writer.fixed(&buffer);
    var uart: Pl011 = .{ .sink = &sink };
    var devices = [_]Bus.Device{uart.device(0x0900_0000)};
    var bus: Bus = .{ .devices = &devices };

    // The driver reads the control register, sets the bits it wants and writes it
    // back. A port that answers zero gives it a value it never chose, and the write
    // back then undoes whatever was configured before.
    bus.write(0x0900_0030, .word, 0x0301);
    try testing.expectEqual(@as(u64, 0x0301), bus.read(0x0900_0030, .word));

    bus.write(0x0900_002c, .word, 0x70);
    try testing.expectEqual(@as(u64, 0x70), bus.read(0x0900_002c, .word));
}
