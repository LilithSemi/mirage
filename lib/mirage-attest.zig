//! What Mirage proves about a guest before the guest runs.
//!
//! This module holds no root of trust of its own. The TPM is passed in, because the
//! root is `/dev/tpm0` on Linux and the UEFI TCG protocol on firmware. Keeping the
//! manifest free of both is what lets this module compile for a freestanding target.

pub const Chain = @import("mirage-attest/Chain.zig");
pub const Log = @import("mirage-attest/Log.zig");
pub const Manifest = @import("mirage-attest/Manifest.zig");
pub const Quote = @import("mirage-attest/Quote.zig");

test {
    _ = Chain;
    _ = Log;
    _ = Manifest;
    _ = Quote;
}
