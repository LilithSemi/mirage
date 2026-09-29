//! The devices a guest can see, and the bus that carries an access to one.
//!
//! A device access comes from the guest, so an address that matches no device is a
//! recoverable fault. It is counted and the guest continues. It is never an
//! assertion, because a guest is allowed to be wrong.

const GuestMemory = @import("mirage-memory").GuestMemory;

pub const Bus = @import("mirage-device/Bus.zig");
pub const Device = Bus.Device;
pub const Size = Bus.Size;

/// Something that decides whether the interrupt line into a guest is asserted. The
/// run loop asks after every exit and never learns which controller answered.
pub const Controller = struct {
    ctx: *anyopaque,
    /// Whether the line into one CPU is asserted. Which CPU matters: a timer belongs to one of them, and
    /// so does a message another CPU sent it.
    signalled: *const fn (ctx: *anyopaque, cpu: u32) bool,
    /// Say an interrupt has happened. The run loop uses this for the timer, which
    /// on some backends arrives as an exit rather than as an interrupt.
    raise: *const fn (ctx: *anyopaque, intid: u32) void,
    /// Say an interrupt belonging to one CPU has happened. A timer is one of these: every CPU has its
    /// own, so raising it for the machine rather than for a CPU would be raising it for nobody.
    raiseOn: *const fn (ctx: *anyopaque, cpu: u32, intid: u32) void,
    /// Say it has stopped. A device whose interrupt is a level rather than a pulse
    /// has to release it, or the guest is interrupted forever.
    lower: *const fn (ctx: *anyopaque, intid: u32) void,
    /// Which CPU is about to touch a device. A controller that banks part of itself per CPU cannot
    /// tell from an access who made it, and a run loop is the only thing that knows. A controller the
    /// hypervisor holds ignores this.
    acting: *const fn (ctx: *anyopaque, cpu: u32) void,
};

/// A device with work that happens between guest exits rather than inside an access.
/// A queue is rung by a doorbell write, and by the time a run loop sees that write the
/// driver is already waiting for the answer.
/// Whoever answers a filesystem message. A device carries the bytes and answers nothing itself: what
/// a guest may read is not a device model's to decide.
pub const Answering = struct {
    ctx: *anyopaque,
    /// Answer one message into the room offered, and say how much of it was filled. Zero means there
    /// is nothing to send back, which is what a message that wants no answer gets.
    answer: *const fn (ctx: *anyopaque, request: []const u8, into: []u8) usize,
};

pub const Service = struct {
    ctx: *anyopaque,
    /// The interrupt this device sends, as the controller numbers it.
    intid: u32,
    /// Serve what the guest published and say whether the interrupt is now asserted.
    /// The interrupt is a level, so a device with nothing outstanding says false and
    /// the line is released.
    poll: *const fn (ctx: *anyopaque, memory: *GuestMemory) Error!bool,

    /// What a device can find wrong with what the guest published. Each one is the
    /// guest being wrong, so a caller recovers rather than asserting.
    pub const Error = virtio.Queue.Error;
};

pub const Gicv2 = @import("mirage-device/Gicv2.zig");
pub const Pl011 = @import("mirage-device/Pl011.zig");
pub const Tpm = @import("mirage-device/Tpm.zig");
pub const virtio = struct {
    pub const Queue = @import("mirage-device/virtio/Queue.zig");
    pub const Mmio = @import("mirage-device/virtio/Mmio.zig");
    pub const Block = @import("mirage-device/virtio/Block.zig");
    pub const Fs = @import("mirage-device/virtio/Fs.zig");
    pub const Vsock = @import("mirage-device/virtio/Vsock.zig");
    pub const Balloon = @import("mirage-device/virtio/Balloon.zig");
    pub const Net = @import("mirage-device/virtio/Net.zig");
};

test {
    _ = Bus;
    _ = Gicv2;
    _ = Pl011;
    _ = Tpm;
    _ = virtio.Queue;
    _ = virtio.Mmio;
    _ = virtio.Block;
    _ = virtio.Fs;
    _ = virtio.Vsock;
    _ = virtio.Balloon;
    _ = virtio.Net;
}
