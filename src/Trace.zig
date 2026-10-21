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
        \\{{"event":"summary","rom_reads":{d},"unclaimed":{d},"unanswered":{d},"registers_at":{d},"aperture_at":{d},"aperture_reads":{d},"transfers":{d},"table_reads":{d},"table_found":{d},"mode_selects":{d},"painted":{d},"outside":{d},"strayed":{d}}}
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
        gpu.outside,
        gpu.strayed,
    });
}
