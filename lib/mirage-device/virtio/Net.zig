//! A virtio network device, which carries ethernet frames between a guest and whatever is
//! above this.
//!
//! This moves frames and nothing else. What a frame means, where it should go, and what
//! answer comes back are decided above, because an unprivileged VMM cannot hand a frame to
//! a kernel interface and has to speak the protocols itself.
//!
//! Every length and every descriptor comes from the guest. A frame longer than the buffer
//! it arrived in, a receive buffer too small for a header, a queue that is not ready: each
//! one is refused and none of them assert.
//!
//! The header in front of every frame is either ten or twelve bytes depending on what the
//! driver accepted, so its size is asked for rather than assumed. Getting it wrong shifts
//! every frame by two bytes, which reads as a malformed packet rather than as an error.

const std = @import("std");
const testing = @import("mirage-testing");
const Bus = @import("../Bus.zig");
const Mmio = @import("Mmio.zig");
const Queue = @import("Queue.zig");
const Service = @import("../../mirage-device.zig").Service;
const GuestMemory = @import("mirage-memory").GuestMemory;

const Net = @This();

/// `VIRTIO_ID_NET`.
const device_id = 1;

/// `VIRTIO_F_VERSION_1`. A modern driver refuses a device that does not offer it.
const feature_version_1: u64 = 1 << 32;
/// `VIRTIO_NET_F_MAC`. The device has an address of its own and the guest uses it rather
/// than making one up.
const feature_mac: u64 = 1 << 5;
/// `VIRTIO_NET_F_STATUS`. Lets the device say the link is up. A guest without this assumes
/// it always is.
const feature_status: u64 = 1 << 16;
/// `VIRTIO_NET_F_MRG_RXBUF`. The receive header carries a buffer count. Offering this makes
/// the header size twelve either way, which is worth more than the merging it allows.
const feature_merge_rxbuf: u64 = 1 << 15;
/// `VIRTIO_NET_F_MTU`. The largest frame this device will carry.
const feature_mtu: u64 = 1 << 25;

/// `VIRTIO_NET_S_LINK_UP`.
const status_link_up: u16 = 1;

/// The largest frame carried, not counting the header in front of it. The usual ethernet
/// limit, because a guest that is told more sends more than the other side will take.
pub const mtu = 1500;

/// One frame plus the room ethernet needs around it.
pub const max_frame = mtu + 14;

pub const queue_rx = 0;
pub const queue_tx = 1;
pub const queue_count = 2;

/// `struct virtio_net_hdr` without the buffer count, which is what a driver that refused
/// merging expects.
pub const header_plain = 10;
/// With the buffer count, which is what a driver that accepted merging expects.
pub const header_merged = 12;

pub const Error = Queue.Error;

mmio: Mmio,
queues: [queue_count]Queue,
/// The address, then the link status, then how many queue pairs, then the largest frame.
/// This is `struct virtio_net_config` as far as this device fills it in.
config: [12]u8,

/// Frames the guest sent that were longer than this device carries, and descriptors that
/// made no sense. A guest is allowed to be wrong and a fault recovered in silence is a bug
/// that hides itself.
dropped: u64,
/// Frames this side wanted to give the guest when the driver had left no buffer for one.
/// A caller seeing this rise is sending faster than the guest is reading.
undelivered: u64,

/// Initialised in place, never returned by value. The transport points at `queues` and
/// `config` inside this same struct, and a value that is copied leaves those pointers
/// aimed at wherever the old copy used to be.
pub fn init(self: *Net, mac: [6]u8) void {
    self.dropped = 0;
    self.undelivered = 0;

    @memset(&self.config, 0);
    @memcpy(self.config[0..6], &mac);
    std.mem.writeInt(u16, self.config[6..8], status_link_up, .little);
    std.mem.writeInt(u16, self.config[8..10], 1, .little);
    std.mem.writeInt(u16, self.config[10..12], mtu, .little);

    self.queues = @splat(.{ .size = 0, .descriptor = 0, .available = 0, .used = 0 });
    self.mmio = .{
        .device_id = device_id,
        .device_features = feature_version_1 | feature_mac | feature_status |
            feature_merge_rxbuf | feature_mtu,
        .config = &self.config,
        .queues = &self.queues,
    };
}

pub fn device(self: *Net, at: u64) Bus.Device {
    return self.mmio.device(at);
}

/// The address the guest was given, which is the one it will send to.
pub fn address(self: *const Net) [6]u8 {
    return self.config[0..6].*;
}

/// How many bytes sit in front of every frame. The driver decides this by what it accepts,
/// so it is read from what was negotiated rather than fixed.
pub fn headerSize(self: *const Net) usize {
    return if (self.mmio.driver_features & feature_merge_rxbuf != 0)
        header_merged
    else
        header_plain;
}

/// Whether the guest has set up both queues. Nothing can move until it has.
pub fn ready(self: *const Net) bool {
    return self.queues[queue_rx].ready and self.queues[queue_tx].ready;
}

/// Take the next frame the guest sent, into `into`. Returns how long it is, or null when
/// the guest has sent nothing.
///
/// A frame longer than `into` is dropped rather than truncated, because half a frame read
/// as a whole one is worse than no frame at all.
pub fn receive(self: *Net, memory: *GuestMemory, into: []u8) Error!?usize {
    const tx = &self.queues[queue_tx];
    if (!tx.ready) return null;

    while (try tx.next(memory)) |head| {
        var chain = tx.walk(head);
        const header = self.headerSize();

        var length: usize = 0;
        var skipped: usize = 0;
        var overran = false;

        while (try chain.next(memory)) |segment| {
            var at: usize = 0;

            // The header comes first and is not part of the frame. It can be in its own
            // descriptor or share one with the start of the frame.
            if (skipped < header) {
                const take = @min(@as(usize, segment.len), header - skipped);
                skipped += take;
                at = take;
            }

            const rest = segment.len - at;
            if (rest == 0) continue;
            if (length + rest > into.len) {
                overran = true;
                continue;
            }
            try memory.read(segment.addr + at, into[length .. length + rest]);
            length += rest;
        }

        try tx.complete(memory, head, 0);
        self.mmio.raise();

        if (overran or skipped < header) {
            self.dropped += 1;
            continue;
        }
        if (length == 0) continue;
        return length;
    }
    return null;
}

/// Give the guest one frame. Returns whether it went, which is false when the driver has
/// left no buffer to put it in.
pub fn send(self: *Net, memory: *GuestMemory, frame: []const u8) Error!bool {
    const rx = &self.queues[queue_rx];
    if (!rx.ready) {
        self.undelivered += 1;
        return false;
    }
    if (frame.len > max_frame) {
        self.dropped += 1;
        return false;
    }

    const header = self.headerSize();
    const head = (try rx.next(memory)) orelse {
        self.undelivered += 1;
        return false;
    };
    var chain = rx.walk(head);

    // The header and the frame are written across whatever descriptors the driver left,
    // because a driver may offer one buffer or several.
    var written: usize = 0;
    var wanted: usize = header + frame.len;
    var bytes: [header_merged]u8 = @splat(0);
    // One buffer holds the whole frame, which is what the count says.
    std.mem.writeInt(u16, bytes[10..12], 1, .little);

    while (written < wanted) {
        const segment = (try chain.next(memory)) orelse break;
        if (!segment.writable) break;

        const room = @min(@as(usize, segment.len), wanted - written);
        var at: usize = 0;

        // The header first, then the frame behind it.
        if (written < header) {
            const take = @min(room, header - written);
            try memory.write(segment.addr, bytes[written .. written + take]);
            written += take;
            at = take;
        }

        const more = room - at;
        if (more > 0) {
            const from = written - header;
            try memory.write(segment.addr + at, frame[from .. from + more]);
            written += more;
        }
    }

    if (written < wanted) {
        // The driver's buffer was too small for the frame. Giving it back empty is honest;
        // giving it back part full would have the guest read a frame that never arrived.
        wanted = 0;
        self.dropped += 1;
    }

    try rx.complete(memory, head, @intCast(wanted));
    self.mmio.raise();
    return wanted > 0;
}

/// Hand this to a run loop so the guest is told when a queue was used. This device carries
/// nothing on its own: something above has to take frames out and put frames in.
pub fn service(self: *Net, intid: u32) Service {
    return .{ .ctx = self, .intid = intid, .poll = Net.askPoll };
}

fn askPoll(ctx: *anyopaque, memory: *GuestMemory) Service.Error!bool {
    const self: *Net = @ptrCast(@alignCast(ctx));
    _ = memory;
    // The doorbell is cleared here because whatever is above this reads the queue on every
    // pass anyway. Leaving it set would say there is work long after it was done.
    self.mmio.served(queue_tx);
    return self.mmio.interrupt_status != 0;
}

const test_base = 0x4000_0000;
const test_mac = [6]u8{ 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 };

/// A guest with a transmit and a receive ring, laid out the way a driver lays them out.
const Fixture = struct {
    ram: []u8,
    memory: GuestMemory,
    regions: [1]GuestMemory.Region,
    net: Net,
    published: [queue_count]u16,
    taken: [queue_count]u16,

    const size = 0x20000;

    /// Four pages per queue: descriptor, available, used, and a buffer.
    fn ringOf(which: usize, part: usize) u64 {
        return test_base + 0x1000 + (which * 4 + part) * 0x1000;
    }

    fn init(self: *Fixture, gpa: std.mem.Allocator, merged: bool) !void {
        self.published = @splat(0);
        self.taken = @splat(0);

        self.ram = try gpa.alloc(u8, size);
        @memset(self.ram, 0);
        self.regions = .{.{ .gpa = test_base, .len = size, .backing = .{ .shared = self.ram } }};
        self.memory = .{ .regions = &self.regions };

        self.net.init(test_mac);
        // What the driver accepted is what decides the header size, so a test that wants one
        // or the other says so here.
        if (merged) self.net.mmio.driver_features = feature_merge_rxbuf;

        for (0..queue_count) |which| {
            self.net.queues[which] = .{
                .size = 1,
                .descriptor = ringOf(which, 0),
                .available = ringOf(which, 1),
                .used = ringOf(which, 2),
                .ready = true,
            };
        }
    }

    fn deinit(self: *Fixture, gpa: std.mem.Allocator) void {
        gpa.free(self.ram);
    }

    fn at(self: *Fixture, addr: u64) []u8 {
        return self.ram[@intCast(addr - test_base)..];
    }

    fn descriptor(self: *Fixture, which: usize, addr: u64, len: u32, writable: bool) void {
        const entry = self.at(ringOf(which, 0));
        std.mem.writeInt(u64, entry[0..8], addr, .little);
        std.mem.writeInt(u32, entry[8..12], len, .little);
        std.mem.writeInt(u16, entry[12..14], if (writable) 2 else 0, .little);
        std.mem.writeInt(u16, entry[14..16], 0, .little);
    }

    fn publish(self: *Fixture, which: usize) void {
        const ring = self.at(ringOf(which, 1));
        self.published[which] += 1;
        std.mem.writeInt(u16, ring[2..4], self.published[which], .little);
        std.mem.writeInt(u16, ring[4..6], 0, .little);
    }

    /// Put a frame on the transmit ring, with the header the driver would put there.
    fn sendFrame(self: *Fixture, frame: []const u8) void {
        const header = self.net.headerSize();
        const buffer = self.at(ringOf(queue_tx, 3));
        @memset(buffer[0..header], 0);
        @memcpy(buffer[header..][0..frame.len], frame);

        self.descriptor(queue_tx, ringOf(queue_tx, 3), @intCast(header + frame.len), false);
        self.publish(queue_tx);
    }

    /// Offer one empty buffer on the receive ring.
    fn offer(self: *Fixture, len: u32) void {
        self.descriptor(queue_rx, ringOf(queue_rx, 3), len, true);
        self.publish(queue_rx);
    }

    /// Read back the frame the device put on the receive ring, without its header.
    fn received(self: *Fixture) ?[]const u8 {
        const used = self.at(ringOf(queue_rx, 2));
        const count = std.mem.readInt(u16, used[2..4], .little);
        if (count == self.taken[queue_rx]) return null;
        self.taken[queue_rx] += 1;

        const written = std.mem.readInt(u32, used[8..12], .little);
        const header = self.net.headerSize();
        if (written <= header) return null;
        return self.at(ringOf(queue_rx, 3))[header..written];
    }
};

test "the register file says this is a network device and gives the address" {
    const gpa = testing.allocator();
    var fixture: Fixture = undefined;
    try fixture.init(gpa, true);
    defer fixture.deinit(gpa);

    var devices = [_]Bus.Device{fixture.net.device(0x0a00_0600)};
    var bus: Bus = .{ .devices = &devices };

    try testing.expectEqual(@as(u64, device_id), bus.read(0x0a00_0600 + 0x008, .word));

    // The address is six bytes and the guest reads them where they lie. A guest that reads
    // the wrong ones answers to an address nothing sends to.
    try testing.expectEqual(@as(u64, 0x52), bus.read(0x0a00_0600 + 0x100, .byte));
    try testing.expectEqual(@as(u64, 0x56), bus.read(0x0a00_0600 + 0x105, .byte));
    try testing.expectEqualSlices(u8, &test_mac, &fixture.net.address());

    // The link is up and the largest frame is the usual one.
    try testing.expectEqual(@as(u64, status_link_up), bus.read(0x0a00_0600 + 0x106, .half));
    try testing.expectEqual(@as(u64, mtu), bus.read(0x0a00_0600 + 0x10a, .half));
}

test "the header is as long as what the driver accepted and not what it might have" {
    const gpa = testing.allocator();
    var plain: Fixture = undefined;
    try plain.init(gpa, false);
    defer plain.deinit(gpa);
    try testing.expectEqual(@as(usize, header_plain), plain.net.headerSize());

    var merged: Fixture = undefined;
    try merged.init(gpa, true);
    defer merged.deinit(gpa);
    try testing.expectEqual(@as(usize, header_merged), merged.net.headerSize());
}

test "a frame the guest sends comes back whole" {
    const gpa = testing.allocator();
    var fixture: Fixture = undefined;
    try fixture.init(gpa, true);
    defer fixture.deinit(gpa);

    const frame = "the quick brown fox jumps over the lazy dog";
    fixture.sendFrame(frame);

    var into: [max_frame]u8 = undefined;
    const length = (try fixture.net.receive(&fixture.memory, &into)) orelse
        return error.TestUnexpectedResult;

    try testing.expectEqualSlices(u8, frame, into[0..length]);
    try testing.expectEqual(@as(u64, 0), fixture.net.dropped);

    // Read once. The queue is empty behind it.
    try std.testing.expect((try fixture.net.receive(&fixture.memory, &into)) == null);
}

test "a frame the same guest is given comes back whole" {
    const gpa = testing.allocator();
    var fixture: Fixture = undefined;
    try fixture.init(gpa, true);
    defer fixture.deinit(gpa);

    fixture.offer(header_merged + 64);
    const frame = "an answer from the other side";
    try std.testing.expect(try fixture.net.send(&fixture.memory, frame));

    const got = fixture.received() orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, frame, got);
}

test "a frame is refused when the driver left no buffer for it" {
    const gpa = testing.allocator();
    var fixture: Fixture = undefined;
    try fixture.init(gpa, true);
    defer fixture.deinit(gpa);

    // Nothing offered, so there is nowhere to put it. Saying so lets a caller keep the
    // frame and offer it again rather than losing it in silence.
    try std.testing.expect(!try fixture.net.send(&fixture.memory, "nowhere to go"));
    try testing.expectEqual(@as(u64, 1), fixture.net.undelivered);
}

test "a buffer too small for the frame is given back empty rather than half full" {
    const gpa = testing.allocator();
    var fixture: Fixture = undefined;
    try fixture.init(gpa, true);
    defer fixture.deinit(gpa);

    // The driver chose this size. A device that writes what fits has the guest read a frame
    // that was never sent.
    fixture.offer(header_merged + 4);
    try std.testing.expect(!try fixture.net.send(&fixture.memory, "far longer than four bytes"));
    try testing.expectEqual(@as(u64, 1), fixture.net.dropped);
    try std.testing.expect(fixture.received() == null);
}

test "a frame longer than this device carries is dropped rather than cut short" {
    const gpa = testing.allocator();
    var fixture: Fixture = undefined;
    try fixture.init(gpa, true);
    defer fixture.deinit(gpa);

    // The length comes from the guest. Half a frame read as a whole one is worse than no
    // frame at all, so this is dropped and counted.
    const long = try gpa.alloc(u8, 64);
    defer gpa.free(long);
    @memset(long, 'x');
    fixture.sendFrame(long);

    var into: [16]u8 = undefined;
    try std.testing.expect((try fixture.net.receive(&fixture.memory, &into)) == null);
    try testing.expectEqual(@as(u64, 1), fixture.net.dropped);
}

test "a transmit buffer with no room for a header is dropped" {
    const gpa = testing.allocator();
    var fixture: Fixture = undefined;
    try fixture.init(gpa, true);
    defer fixture.deinit(gpa);

    // Shorter than the header, so there is no frame behind it to read. A device that reads
    // one anyway reads whatever follows the buffer in guest memory.
    fixture.sendFrame(&.{});
    fixture.descriptor(queue_tx, Fixture.ringOf(queue_tx, 3), 4, false);

    var into: [max_frame]u8 = undefined;
    try std.testing.expect((try fixture.net.receive(&fixture.memory, &into)) == null);
    try testing.expectEqual(@as(u64, 1), fixture.net.dropped);
}

test "nothing moves until the guest has set up both queues" {
    const gpa = testing.allocator();
    var fixture: Fixture = undefined;
    try fixture.init(gpa, true);
    defer fixture.deinit(gpa);

    try std.testing.expect(fixture.net.ready());
    fixture.net.queues[queue_rx].ready = false;
    try std.testing.expect(!fixture.net.ready());
}
