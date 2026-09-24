//! A directory on this machine that a guest may read.
//!
//! The protocol is the kernel's own filesystem in userspace protocol, which a guest reaches through a
//! virtio queue rather than through a descriptor. Splitting it this way means the answers can be
//! tested against real files with no guest and no queues in the way.

pub const wire = @import("mirage-fs/wire.zig");
pub const Export = @import("mirage-fs/Export.zig");

test {
    _ = wire;
    _ = Export;
}
