//! Images handed to a guest at launch.
//!
//! A guest with no firmware and no disk still needs something to run. These build
//! that something in memory, so `zig build` stays the only tool in the pipeline and
//! no archiver or filesystem builder has to exist on the machine.

pub const Cpio = @import("mirage-image/Cpio.zig");
pub const Erofs = @import("mirage-image/Erofs.zig");
pub const Verity = @import("mirage-image/Verity.zig");

test {
    _ = Cpio;
    _ = Erofs;
    _ = Verity;
}
