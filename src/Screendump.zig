//! Pictures of what a guest painted, written as files for somebody else to look at.
//!
//! A frame now and then rather than every frame: nothing here is driving a screen, so the only
//! reason to take a picture is to see what was on it, and a run of a few seconds with a picture a
//! second is enough to see a console fill. Written as PPM because it is the format with the least
//! between the bytes of the screen and the bytes of the file.

const std = @import("std");
const device = @import("mirage-device");

const Screendump = @This();

/// The directory the pictures go in. It has to exist: making a caller's directories for them is
/// how a mistyped path becomes a surprise directory rather than an error.
into: std.Io.Dir,
card: *const device.Glacier,
io: std.Io,
/// How long between pictures, and when the last one was taken.
every: i96,
taken_at: i96 = 0,

/// Pictures written, which is what names them, and pictures that could not be.
taken: u64 = 0,
lost: u64 = 0,

/// Take one now if enough time has passed since the last. Called from the loop that runs the
/// guest, so this must do nothing at all most of the times it is called.
pub fn maybe(self: *Screendump) void {
    const now = std.Io.Clock.awake.now(self.io).nanoseconds;
    if (self.taken != 0 and now - self.taken_at < self.every) return;
    self.taken_at = now;
    self.take();
}

/// Take one whatever the clock says. The end of a run calls this, because the last thing on the
/// screen is the thing somebody wants to see.
pub fn take(self: *Screendump) void {
    const shown = self.card.display orelse return;
    const pixels = self.card.screen() orelse return;

    var name: [32]u8 = undefined;
    const called = std.fmt.bufPrint(&name, "frame-{d:0>4}.ppm", .{self.taken}) catch unreachable;

    const file = self.into.createFile(self.io, called, .{}) catch {
        self.lost += 1;
        return;
    };
    defer file.close(self.io);

    var room: [8192]u8 = undefined;
    var writer = file.writer(self.io, &room);
    self.write(&writer.interface, shown, pixels) catch {
        self.lost += 1;
        return;
    };
    self.taken += 1;
}

fn write(
    self: *Screendump,
    out: *std.Io.Writer,
    shown: device.Glacier.Display,
    pixels: []const u8,
) !void {
    _ = self;
    try out.print("P6\n{d} {d}\n255\n", .{ shown.width, shown.height });

    // Four bytes a pixel, blue lowest, then green, then red, then whatever the format keeps for
    // itself. A row is as long as the pitch and the pixels in it are only the width, so the rest
    // of the row is padding that no picture holds.
    var row: u32 = 0;
    while (row < shown.height) : (row += 1) {
        const begins = @as(usize, row) * shown.pitch;
        var column: u32 = 0;
        while (column < shown.width) : (column += 1) {
            const at = begins + @as(usize, column) * 4;
            if (at + 4 > pixels.len) return;
            try out.writeAll(&.{ pixels[at + 2], pixels[at + 1], pixels[at] });
        }
    }
    try out.flush();
}
