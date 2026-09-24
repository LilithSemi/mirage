//! One guest that stays up as long as whoever asked for it is there.
//!
//! A session is two ends of a socket. `Server` lives in the process that runs the guest and is
//! pumped from the loop that already serves the guest's devices. `Client` is what a program holds
//! to reach that guest: it starts one, takes streams into it, and stops it.
//!
//! Nothing here starts a thread on the caller's side and nothing calls back. What a caller holds is
//! a descriptor, so a program that already polls keeps its own shape.

pub const wire = @import("mirage-session/wire.zig");
pub const Client = @import("mirage-session/Client.zig");
pub const Server = @import("mirage-session/Server.zig");
pub const socket = @import("mirage-session/socket.zig");

test {
    @import("std").testing.refAllDecls(@This());
    _ = wire;
}
