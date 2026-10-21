//! What the guest did, written for another program to read.
//!
//! One line of JSON per thing that happened, then one more at the end holding every count. A test
//! that wants the whole story walks the lines; a test that wants an answer reads the last one. A
//! line is complete when it is written, so a run that was killed still leaves a usable file.

const std = @import("std");
const device = @import("mirage-device");

const Trace = @This();

/// What this writes into. Flushed as each line is finished, because a trace of a guest that hung
/// is exactly the trace somebody wants to read.
out: *std.Io.Writer,
/// Lines written, which is what says a trace was produced at all.
lines: u64 = 0,
/// Lines that could not be written. A trace is something a caller asked for and not something a
/// guest needs, so a failure here is counted and the guest carries on.
lost: u64 = 0,
/// What the guest said, as whole lines. Held until the end of a line because a line is the unit a
/// reader of a log cares about, and written as it is finished so a run that was killed keeps
/// whatever the guest had already said.
said: [line_room]u8 = @splat(0),
saying: usize = 0,

pub fn watcher(self: *Trace) device.Glacier.Watcher {
    return .{ .ctx = self, .saw = Trace.saw };
}

fn saw(ctx: *anyopaque, what: device.Glacier.Event) void {
    const self: *Trace = @ptrCast(@alignCast(ctx));
    switch (what) {
        .transfer => |one| self.line(
            \\{{"event":"transfer","to_host":{},"host":{d},"local":{d},"words":{d},"moved":{d},"error":{d}}}
        , .{
            one.to_host,
            one.host,
            one.local,
            one.words,
            one.moved,
            @backingInt(one.failure),
        }),
        .mode => |one| self.line(
            \\{{"event":"mode","display":{d},"value":{d}}}
        , .{ one.display, one.value }),
    }
}

fn line(self: *Trace, comptime shape: []const u8, args: anytype) void {
    self.out.print(shape ++ "\n", args) catch {
        self.lost += 1;
        return;
    };
    self.out.flush() catch {
        self.lost += 1;
        return;
    };
    self.lines += 1;
}

/// Everything counted, as one line at the end. The names are the ones the counters have, so a
/// reader of this file and a reader of the code are reading the same words.
pub fn summary(self: *Trace, bridge: *const device.PciHost, gpu: *const device.Glacier) void {
    self.line(
        \\{{"event":"summary","rom_reads":{d},"unclaimed":{d},"unanswered":{d},"registers_at":{d},"aperture_at":{d},"aperture_reads":{d},"transfers":{d},"table_reads":{d},"table_found":{d},"mode_selects":{d},"painted_by_engine":{d},"painted_through_window":{d},"outside":{d},"strayed":{d}}}
    , .{
        bridge.rom_reads,
        bridge.unclaimed,
        bridge.unanswered,
        bridge.baseOf(0, 0) orelse 0,
        bridge.baseOf(0, device.Glacier.window_region) orelse 0,
        bridge.state[0].base_reads[device.Glacier.window_region],
        gpu.transfers,
        gpu.table_reads,
        gpu.table_found,
        gpu.mode_selects,
        gpu.painted,
        gpu.painted_through_window,
        gpu.outside,
        gpu.strayed,
    });
}

/// The longest line kept whole. Firmware draws with escape sequences and a screen's worth of them
/// arrives without a newline, so a line that never ends is written out rather than lost.
const line_room = 512;

pub fn echo(self: *Trace) device.Pl011.Echo {
    return .{ .ctx = self, .byte = Trace.heard };
}

fn heard(ctx: *anyopaque, said: u8) void {
    const self: *Trace = @ptrCast(@alignCast(ctx));
    if (said == '\n') {
        self.sayLine();
        return;
    }

    if (self.saying == self.said.len) self.sayLine();
    self.said[self.saying] = said;
    self.saying += 1;
}

/// Write what has been said so far as one line of the file, and begin again. A carriage return at
/// the end is dropped, because a console that moves the cursor back is not saying anything.
fn sayLine(self: *Trace) void {
    var text: []const u8 = self.said[0..self.saying];
    self.saying = 0;
    if (text.len != 0 and text[text.len - 1] == '\r') text = text[0 .. text.len - 1];
    if (text.len == 0) return;

    self.out.writeAll("{\"event\":\"serial\",\"text\":\"") catch {
        self.lost += 1;
        return;
    };
    self.quoted(text);
    self.line("\"}}", .{});
}

/// The text of a line, with everything json cannot carry written as an escape. Firmware paints
/// with escape sequences, so most of what a console says is not printable.
fn quoted(self: *Trace, text: []const u8) void {
    for (text) |byte| {
        const written = switch (byte) {
            '"' => self.out.writeAll("\\\""),
            '\\' => self.out.writeAll("\\\\"),
            '\t' => self.out.writeAll("\\t"),
            '\r' => self.out.writeAll("\\r"),
            0x00...0x08, 0x0b, 0x0c, 0x0e...0x1f, 0x7f => self.out.print("\\u{x:0>4}", .{byte}),
            else => self.out.writeByte(byte),
        };
        written catch {
            self.lost += 1;
            return;
        };
    }
}

/// Whatever the guest said last and never finished. Called when the run is over, so a last line
/// with no newline after it is not lost.
pub fn lastWord(self: *Trace) void {
    self.sayLine();
}
