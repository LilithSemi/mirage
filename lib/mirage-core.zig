//! Starting a guest, and keeping it running.
//!
//! Nothing here names a hypervisor or an operating system. A caller gives this module
//! guest memory that is already mapped and a `Backend` that is already open, and this
//! decides what goes where, measures it on the way in, and dispatches what comes back.

pub const Launch = @import("mirage-core/Launch.zig");
pub const Snapshot = @import("mirage-core/Snapshot.zig");

test {
    _ = Launch;
    _ = Snapshot;
}
