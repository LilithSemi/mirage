//! A virtio vsock device, the channel between a guest and whatever started it.
//!
//! A guest opens a connection to a port, bytes go both ways, and one side closes it.
//! There is no address to route and no name to resolve, so this is the channel to give
//! a guest that must be reachable but must not be on a network.
//!
//! Every field of every packet comes from the guest. A port nobody listens on, a
//! connection that does not exist, a length longer than the buffer it came in, more
//! bytes than the credit allows: each one is the guest being wrong, so each one is
//! refused and none of them assert.
//!
//! A caller that drives one thread reaches this device only when the guest exits. A guest
//! blocked on a read exits for nothing, so the caller has to take the CPU back itself: a
//! repeating signal makes the blocked call return and the loop gets its turn. That is
//! polling, and a device thread with an event file descriptor is the answer that is not.
//!
//! The counters here wrap. The specification accounts for credit in modular
//! arithmetic, so every difference between two of them uses wrapping subtraction. A
//! checked subtraction is the wrong tool and would refuse a correct guest.

const std = @import("std");
const testing = @import("mirage-testing");
const Bus = @import("../Bus.zig");
const Mmio = @import("Mmio.zig");
const Queue = @import("Queue.zig");
const Service = @import("../../mirage-device.zig").Service;
const GuestMemory = @import("mirage-memory").GuestMemory;

const Vsock = @This();

/// `VIRTIO_ID_VSOCK`.
const device_id = 19;
/// `VIRTIO_F_VERSION_1`. A modern driver refuses a device that does not offer it.
const feature_version_1: u64 = 1 << 32;

/// `struct virtio_vsock_hdr`, the fixed part of every packet.
pub const header_size = 44;

/// `VMADDR_CID_HOST`. Whoever started the guest is always at this address.
pub const cid_host = 2;

/// The lowest address a guest may have. Below this the numbers are reserved.
pub const cid_first_guest = 3;

/// `VIRTIO_VSOCK_TYPE_STREAM`. A stream is bytes in order with no message boundary.
pub const type_stream = 1;

/// Which queue is which. The driver puts empty buffers on the first for the device to
/// fill, and full ones on the second for the device to read.
pub const queue_rx = 0;
pub const queue_tx = 1;
pub const queue_event = 2;
pub const queue_count = 3;

/// How much each connection holds in each direction. The receive half of this is what
/// the guest is told it may send, so a guest that respects its credit never overruns.
pub const buffer_size = 4096;

/// How many connections can be open at once. A guest that asks for more is refused,
/// because a device that grows on request is a device a guest can exhaust.
pub const max_connections = 16;

pub const Error = Queue.Error;

pub const Op = enum(u16) {
    invalid = 0,
    request = 1,
    response = 2,
    reset = 3,
    shutdown = 4,
    rw = 5,
    credit_update = 6,
    credit_request = 7,
    _,
};

/// `VIRTIO_VSOCK_SHUTDOWN_*`. A guest says which half it has finished with.
pub const shutdown_receive = 1;
pub const shutdown_send = 2;

pub const Packet = struct {
    src_cid: u64,
    dst_cid: u64,
    src_port: u32,
    dst_port: u32,
    len: u32 = 0,
    kind: u16 = type_stream,
    op: Op,
    flags: u32 = 0,
    /// How large the sender's receive buffer is, in total.
    buf_alloc: u32 = 0,
    /// How many bytes the sender has taken out of that buffer since the start.
    fwd_cnt: u32 = 0,

    pub fn decode(bytes: *const [header_size]u8) Packet {
        return .{
            .src_cid = std.mem.readInt(u64, bytes[0..8], .little),
            .dst_cid = std.mem.readInt(u64, bytes[8..16], .little),
            .src_port = std.mem.readInt(u32, bytes[16..20], .little),
            .dst_port = std.mem.readInt(u32, bytes[20..24], .little),
            .len = std.mem.readInt(u32, bytes[24..28], .little),
            .kind = std.mem.readInt(u16, bytes[28..30], .little),
            // The operation comes from the guest, so one this device has no name for
            // stays a number rather than becoming an invalid enum.
            .op = @enumFromInt(std.mem.readInt(u16, bytes[30..32], .little)),
            .flags = std.mem.readInt(u32, bytes[32..36], .little),
            .buf_alloc = std.mem.readInt(u32, bytes[36..40], .little),
            .fwd_cnt = std.mem.readInt(u32, bytes[40..44], .little),
        };
    }

    pub fn encode(self: Packet, bytes: *[header_size]u8) void {
        std.mem.writeInt(u64, bytes[0..8], self.src_cid, .little);
        std.mem.writeInt(u64, bytes[8..16], self.dst_cid, .little);
        std.mem.writeInt(u32, bytes[16..20], self.src_port, .little);
        std.mem.writeInt(u32, bytes[20..24], self.dst_port, .little);
        std.mem.writeInt(u32, bytes[24..28], self.len, .little);
        std.mem.writeInt(u16, bytes[28..30], self.kind, .little);
        std.mem.writeInt(u16, bytes[30..32], @intFromEnum(self.op), .little);
        std.mem.writeInt(u32, bytes[32..36], self.flags, .little);
        std.mem.writeInt(u32, bytes[36..40], self.buf_alloc, .little);
        std.mem.writeInt(u32, bytes[40..44], self.fwd_cnt, .little);
    }
};

/// A connection the host holds. The generation changes every time the slot is reused,
/// so a handle kept past the end of its connection resolves to nothing rather than to
/// whichever guest took the slot next.
pub const Handle = struct { index: u8, generation: u16 };

const Connection = struct {
    state: enum {
        free,
        /// Established. Bytes may go both ways.
        open,
        /// A reset is owed. The slot is free once it goes out.
        resetting,
    } = .free,
    generation: u16 = 0,
    /// True until the host has been told this connection exists.
    announced: bool = false,

    guest_cid: u64 = 0,
    guest_port: u32 = 0,
    host_port: u32 = 0,

    /// The response to the guest's request has not gone out yet.
    owes_response: bool = false,
    /// The guest is waiting to hear that this side took bytes out of its buffer.
    owes_credit: bool = false,
    /// The guest said it will send no more.
    guest_finished: bool = false,

    /// What the guest said about its own receive buffer in the last header it sent.
    peer_buf_alloc: u32 = 0,
    peer_fwd_cnt: u32 = 0,
    /// Bytes this side has sent to the guest, and bytes it has handed to the host.
    /// Both wrap, and every difference between them is a wrapping subtraction.
    tx_cnt: u32 = 0,
    fwd_cnt: u32 = 0,

    /// Bytes from the guest the host has not taken, and bytes for the guest that have
    /// not gone out.
    inbox: [buffer_size]u8 = undefined,
    inbox_len: usize = 0,
    outbox: [buffer_size]u8 = undefined,
    outbox_len: usize = 0,

    fn free(self: *Connection) void {
        self.state = .free;
        self.generation +%= 1;
        self.announced = false;
        self.owes_response = false;
        self.owes_credit = false;
        self.guest_finished = false;
        self.inbox_len = 0;
        self.outbox_len = 0;
        self.tx_cnt = 0;
        self.fwd_cnt = 0;
        self.peer_buf_alloc = 0;
        self.peer_fwd_cnt = 0;
    }

    /// How many bytes the guest still has room for. The guest publishes the size of
    /// its buffer and how much it has consumed, and the difference from what this side
    /// has sent is what is left.
    fn credit(self: *const Connection) u32 {
        const outstanding = self.tx_cnt -% self.peer_fwd_cnt;
        if (outstanding >= self.peer_buf_alloc) return 0;
        return self.peer_buf_alloc - outstanding;
    }
};

mmio: Mmio,
queues: [queue_count]Queue,
/// The guest's own address, as the configuration space holds it.
config: [8]u8,
guest_cid: u64,
/// Host ports something is listening on. A request to any other is refused, which is
/// what a guest sees when nothing listens.
listening: []const u32,
connections: [max_connections]Connection,
/// Connections refused because nothing listened or because every slot was in use, and
/// packets dropped because they made no sense. A guest is allowed to be wrong, and a
/// fault recovered in silence is a bug that hides itself.
refused: u64 = 0,
dropped: u64 = 0,

/// Initialised in place, never returned by value. The transport points at `queues` and
/// `config` inside this same struct, and a value that is copied leaves those pointers
/// aimed at wherever the old copy used to be.
pub fn init(self: *Vsock, guest_cid: u64, listening: []const u32) void {
    self.guest_cid = guest_cid;
    self.listening = listening;
    self.connections = @splat(.{});
    self.refused = 0;
    self.dropped = 0;

    std.mem.writeInt(u64, &self.config, guest_cid, .little);
    self.queues = @splat(.{ .size = 0, .descriptor = 0, .available = 0, .used = 0 });
    self.mmio = .{
        .device_id = device_id,
        .device_features = feature_version_1,
        .config = &self.config,
        .queues = &self.queues,
    };
}

pub fn device(self: *Vsock, at: u64) Bus.Device {
    return self.mmio.device(at);
}

/// Hand this to a run loop so it can carry the channel without knowing what kind of
/// device is behind it.
pub fn service(self: *Vsock, intid: u32) Service {
    return .{ .ctx = self, .intid = intid, .poll = Vsock.askPoll };
}

fn askPoll(ctx: *anyopaque, memory: *GuestMemory) Service.Error!bool {
    const self: *Vsock = @ptrCast(@alignCast(ctx));
    _ = try self.serve(memory);
    return self.mmio.interrupt_status != 0;
}

/// Read what the guest sent and send what is waiting for it. Returns how many packets
/// moved in total.
///
/// This runs on every pass and not only on a doorbell, because the host can put bytes
/// in an outbox at any time and nothing rings a bell for that.
pub fn serve(self: *Vsock, memory: *GuestMemory) Error!u32 {
    var moved: u32 = 0;
    if (self.mmio.rang(queue_tx)) {
        self.mmio.served(queue_tx);
        moved += try self.drain(memory);
    }
    moved += try self.fill(memory);
    if (moved > 0) self.mmio.raise();
    return moved;
}

/// Read every packet the driver published on the transmit queue.
fn drain(self: *Vsock, memory: *GuestMemory) Error!u32 {
    const tx = &self.queues[queue_tx];
    if (!tx.ready) return 0;

    var count: u32 = 0;
    while (try tx.next(memory)) |head| {
        var chain = tx.walk(head);
        count += 1;

        const segment = (try chain.next(memory)) orelse {
            self.dropped += 1;
            try tx.complete(memory, head, 0);
            continue;
        };
        if (segment.len < header_size) {
            self.dropped += 1;
            try tx.complete(memory, head, 0);
            continue;
        }

        var bytes: [header_size]u8 = undefined;
        try memory.read(segment.addr, &bytes);
        const packet = Packet.decode(&bytes);

        // The length in the header and the size of the chain are chosen separately by
        // the guest, so the smaller of the two is what can really be there.
        const in_first = segment.len - header_size;
        var payload: [buffer_size]u8 = undefined;
        var length: usize = @min(packet.len, @min(in_first, payload.len));
        if (length > 0) try memory.read(segment.addr + header_size, payload[0..length]);

        // A driver may split the header and the payload across the chain. Take what
        // the rest of it holds, up to what the header claimed.
        while (length < @min(packet.len, payload.len)) {
            const more = (try chain.next(memory)) orelse break;
            const want = @min(@as(usize, more.len), @min(packet.len, payload.len) - length);
            if (want == 0) break;
            try memory.read(more.addr, payload[length .. length + want]);
            length += want;
        }

        self.receive(packet, payload[0..length]);
        try tx.complete(memory, head, 0);
    }
    return count;
}

/// Act on one packet from the guest.
fn receive(self: *Vsock, packet: Packet, payload: []const u8) void {
    // A guest that claims to be somebody else, or addresses somebody else, is not
    // talking to this device.
    if (packet.src_cid != self.guest_cid or packet.dst_cid != cid_host) {
        self.dropped += 1;
        return;
    }
    if (packet.kind != type_stream) {
        self.dropped += 1;
        return;
    }

    if (packet.op == .request) {
        self.open(packet);
        return;
    }

    const connection = self.find(packet.src_port, packet.dst_port) orelse {
        // Nothing here knows this connection, and it was never opened, so there is
        // nothing to tell the guest that it has not already been told.
        self.dropped += 1;
        return;
    };

    // Every packet carries the guest's credit, whatever else it says.
    connection.peer_buf_alloc = packet.buf_alloc;
    connection.peer_fwd_cnt = packet.fwd_cnt;

    switch (packet.op) {
        .rw => {
            // The guest was told how much room there is. Anything past it is refused
            // rather than written somewhere else.
            const room = connection.inbox.len - connection.inbox_len;
            const taken = @min(payload.len, room);
            if (taken < payload.len) self.dropped += 1;
            @memcpy(connection.inbox[connection.inbox_len..][0..taken], payload[0..taken]);
            connection.inbox_len += taken;
        },
        .credit_request => connection.owes_credit = true,
        .credit_update => {},
        .shutdown => {
            if (packet.flags & shutdown_send != 0) connection.guest_finished = true;
            // The guest has finished with both halves, so the connection is over.
            if (packet.flags & shutdown_receive != 0) connection.state = .resetting;
        },
        .reset => connection.free(),
        else => self.dropped += 1,
    }
}

/// Answer a request to connect. A port nobody listens on and a device with no slot left
/// are both refused.
///
/// A refusal takes a slot, because the guest has to be told and the reset needs
/// somewhere to wait. The slot goes back on the pass that sends it, so a guest hammering
/// a closed port holds the table for one pass and no longer.
fn open(self: *Vsock, packet: Packet) void {
    // Already open, so this is a repeat and the guest is told what it was told before.
    if (self.find(packet.src_port, packet.dst_port)) |existing| {
        existing.owes_response = true;
        return;
    }

    var listens = false;
    for (self.listening) |listener| {
        if (listener == packet.dst_port) listens = true;
    }

    const slot = self.spare() orelse {
        self.refused += 1;
        return;
    };

    slot.* = .{
        .generation = slot.generation,
        .guest_cid = packet.src_cid,
        .guest_port = packet.src_port,
        .host_port = packet.dst_port,
        .peer_buf_alloc = packet.buf_alloc,
        .peer_fwd_cnt = packet.fwd_cnt,
    };

    if (!listens) {
        self.refused += 1;
        slot.state = .resetting;
        return;
    }

    slot.state = .open;
    slot.owes_response = true;
}

fn find(self: *Vsock, guest_port: u32, host_port: u32) ?*Connection {
    for (&self.connections) |*connection| {
        if (connection.state == .free) continue;
        if (connection.guest_port != guest_port) continue;
        if (connection.host_port != host_port) continue;
        return connection;
    }
    return null;
}

fn spare(self: *Vsock) ?*Connection {
    for (&self.connections) |*connection| {
        if (connection.state == .free) return connection;
    }
    return null;
}

/// What one attempt to send achieved.
const Emitted = enum {
    /// Nothing was owed, or the driver left no buffer to send it in.
    nothing,
    /// A buffer came back carrying nothing useful. The used ring moved, so the guest has
    /// to be told, but asking again on this pass would take every buffer it posted.
    wasted,
    /// A packet went out.
    packet,
};

/// Send everything that is owed, for as long as the driver leaves buffers to send it in.
fn fill(self: *Vsock, memory: *GuestMemory) Error!u32 {
    const rx = &self.queues[queue_rx];
    if (!rx.ready) return 0;

    var sent: u32 = 0;
    // Every connection gets a turn before any of them gets a second, so one that is busy
    // cannot starve the rest.
    var progress = true;
    while (progress) {
        progress = false;
        for (&self.connections) |*connection| {
            switch (try self.emit(memory, connection)) {
                .nothing => {},
                .wasted => sent += 1,
                .packet => {
                    sent += 1;
                    progress = true;
                },
            }
        }
    }
    return sent;
}

/// Send one packet for this connection, if it owes one and the driver left a buffer to
/// put it in.
fn emit(self: *Vsock, memory: *GuestMemory, connection: *Connection) Error!Emitted {
    // What to send is decided before a buffer is taken, because a buffer taken and
    // not used is one the driver never gets back.
    var op: Op = .invalid;
    var payload: usize = 0;

    switch (connection.state) {
        .free => return .nothing,
        .resetting => op = .reset,
        .open => {
            const allowed = @min(connection.outbox_len, connection.credit());
            if (connection.owes_response) {
                op = .response;
            } else if (allowed > 0) {
                op = .rw;
                payload = allowed;
            } else if (connection.owes_credit) {
                op = .credit_update;
            } else return .nothing;
        },
    }

    const rx = &self.queues[queue_rx];
    const head = (try rx.next(memory)) orelse return .nothing;
    var chain = rx.walk(head);

    const segment = (try chain.next(memory)) orelse {
        self.dropped += 1;
        try rx.complete(memory, head, 0);
        return .wasted;
    };
    if (!segment.writable or segment.len < header_size) {
        self.dropped += 1;
        try rx.complete(memory, head, 0);
        return .wasted;
    }

    // The driver chose the size of this buffer, so the payload is trimmed to what it
    // really holds rather than to what was wanted.
    const room = segment.len - header_size;
    payload = @min(payload, room);

    // A buffer with room for the header and nothing else cannot carry data, so this one
    // is given back and no more are asked for on this pass.
    if (op == .rw and payload == 0) {
        self.dropped += 1;
        try rx.complete(memory, head, 0);
        return .wasted;
    }

    var bytes: [header_size]u8 = undefined;
    const outgoing: Packet = .{
        .src_cid = cid_host,
        .dst_cid = connection.guest_cid,
        .src_port = connection.host_port,
        .dst_port = connection.guest_port,
        .len = @intCast(payload),
        .op = op,
        .buf_alloc = buffer_size,
        .fwd_cnt = connection.fwd_cnt,
    };
    outgoing.encode(&bytes);
    try memory.write(segment.addr, &bytes);
    if (payload > 0) try memory.write(segment.addr + header_size, connection.outbox[0..payload]);

    try rx.complete(memory, head, @intCast(header_size + payload));

    switch (op) {
        .reset => connection.free(),
        .response => connection.owes_response = false,
        .credit_update => connection.owes_credit = false,
        .rw => {
            connection.tx_cnt +%= @intCast(payload);
            const left = connection.outbox_len - payload;
            std.mem.copyForwards(u8, connection.outbox[0..left], connection.outbox[payload..connection.outbox_len]);
            connection.outbox_len = left;
        },
        else => {},
    }
    return .packet;
}

/// A connection the guest opened that the host has not been told about yet.
pub fn accept(self: *Vsock) ?Handle {
    for (&self.connections, 0..) |*connection, index| {
        if (connection.state != .open or connection.announced) continue;
        connection.announced = true;
        return .{ .index = @intCast(index), .generation = connection.generation };
    }
    return null;
}

/// Which host port this connection arrived on, so a host listening on several can tell
/// them apart.
pub fn port(self: *Vsock, handle: Handle) ?u32 {
    const connection = self.resolve(handle) orelse return null;
    return connection.host_port;
}

fn resolve(self: *Vsock, handle: Handle) ?*Connection {
    if (handle.index >= self.connections.len) return null;
    const connection = &self.connections[handle.index];
    if (connection.state == .free) return null;
    // The slot was reused, so this handle names a connection that has ended.
    if (connection.generation != handle.generation) return null;
    return connection;
}

/// Take what the guest sent. Returns how many bytes went into the buffer.
pub fn read(self: *Vsock, handle: Handle, buffer: []u8) usize {
    const connection = self.resolve(handle) orelse return 0;
    const taken = @min(buffer.len, connection.inbox_len);
    if (taken == 0) return 0;

    @memcpy(buffer[0..taken], connection.inbox[0..taken]);
    const left = connection.inbox_len - taken;
    std.mem.copyForwards(u8, connection.inbox[0..left], connection.inbox[taken..connection.inbox_len]);
    connection.inbox_len = left;

    // Room opened up, and the guest only learns that from a credit update.
    connection.fwd_cnt +%= @intCast(taken);
    connection.owes_credit = true;
    return taken;
}

/// Give the guest bytes. Returns how many were taken, which is fewer than offered when
/// the outbox is full. The caller keeps the rest and offers it again.
pub fn write(self: *Vsock, handle: Handle, bytes: []const u8) usize {
    const connection = self.resolve(handle) orelse return 0;
    const room = connection.outbox.len - connection.outbox_len;
    const taken = @min(bytes.len, room);
    @memcpy(connection.outbox[connection.outbox_len..][0..taken], bytes[0..taken]);
    connection.outbox_len += taken;
    return taken;
}

/// How many bytes the guest sent that the host has not read.
pub fn available(self: *Vsock, handle: Handle) usize {
    const connection = self.resolve(handle) orelse return 0;
    return connection.inbox_len;
}

/// Whether the guest said it will send no more. Bytes already in the inbox are still
/// there to be read.
pub fn finished(self: *Vsock, handle: Handle) bool {
    const connection = self.resolve(handle) orelse return true;
    return connection.guest_finished;
}

/// End the connection. Anything still in the outbox is lost, because a reset is what
/// the guest is told and a reset carries nothing.
pub fn close(self: *Vsock, handle: Handle) void {
    const connection = self.resolve(handle) orelse return;
    connection.state = .resetting;
}

const ram_base = 0x4000_0000;
const test_cid = 3;
const test_host_port = 1024;
const test_guest_port = 50_000;

/// A guest with a transmit and a receive ring, laid out in memory the way a driver
/// lays them out. One descriptor each, which is enough to carry one packet.
const Fixture = struct {
    ram: []u8,
    memory: GuestMemory,
    regions: [1]GuestMemory.Region,
    vsock: Vsock,
    ports: [1]u32,
    tx_published: u16 = 0,
    rx_published: u16 = 0,
    rx_taken: u16 = 0,

    /// Where each ring sits. Every address is page aligned because a real driver
    /// allocates whole pages.
    const tx_descriptor = ram_base + 0x1000;
    const tx_available = ram_base + 0x2000;
    const tx_used = ram_base + 0x3000;
    const tx_buffer = ram_base + 0x4000;
    const rx_descriptor = ram_base + 0x5000;
    const rx_available = ram_base + 0x6000;
    const rx_used = ram_base + 0x7000;
    const rx_buffer = ram_base + 0x8000;
    const size = 0x10000;

    fn init(self: *Fixture, gpa: std.mem.Allocator) !void {
        // Set here and not by a field default, because this is built in place from
        // undefined memory and a default never runs for that.
        self.tx_published = 0;
        self.rx_published = 0;
        self.rx_taken = 0;

        self.ram = try gpa.alloc(u8, size);
        @memset(self.ram, 0);
        self.regions = .{.{ .gpa = ram_base, .len = size, .backing = .{ .shared = self.ram } }};
        self.memory = .{ .regions = &self.regions };

        self.ports = .{test_host_port};
        self.vsock.init(test_cid, &self.ports);

        self.vsock.queues[queue_tx] = .{
            .size = 1,
            .descriptor = tx_descriptor,
            .available = tx_available,
            .used = tx_used,
            .ready = true,
        };
        self.vsock.queues[queue_rx] = .{
            .size = 1,
            .descriptor = rx_descriptor,
            .available = rx_available,
            .used = rx_used,
            .ready = true,
        };
    }

    fn deinit(self: *Fixture, gpa: std.mem.Allocator) void {
        gpa.free(self.ram);
    }

    fn at(self: *Fixture, address: u64) []u8 {
        return self.ram[@intCast(address - ram_base)..];
    }

    /// Write a descriptor, one per ring, because each ring here holds one.
    fn descriptor(self: *Fixture, table: u64, address: u64, length: u32, writable: bool) void {
        const entry = self.at(table);
        std.mem.writeInt(u64, entry[0..8], address, .little);
        std.mem.writeInt(u32, entry[8..12], length, .little);
        std.mem.writeInt(u16, entry[12..14], if (writable) 2 else 0, .little);
        std.mem.writeInt(u16, entry[14..16], 0, .little);
    }

    /// Publish the one descriptor of a ring, the way a driver does when it has work.
    fn publish(self: *Fixture, ring: u64, count: u16) void {
        const entry = self.at(ring);
        std.mem.writeInt(u16, entry[2..4], count, .little);
        std.mem.writeInt(u16, entry[4..6], 0, .little);
    }

    /// Put one packet on the transmit ring and ring the doorbell.
    fn send(self: *Fixture, packet: Packet, payload: []const u8) !void {
        var header: [header_size]u8 = undefined;
        var outgoing = packet;
        outgoing.len = @intCast(payload.len);
        outgoing.encode(&header);

        const buffer = self.at(tx_buffer);
        @memcpy(buffer[0..header_size], &header);
        @memcpy(buffer[header_size..][0..payload.len], payload);

        self.descriptor(tx_descriptor, tx_buffer, @intCast(header_size + payload.len), false);
        self.publish(tx_available, self.tx_published + 1);
        self.tx_published += 1;
        self.vsock.mmio.notified |= 1 << queue_tx;
    }

    /// Offer one empty buffer on the receive ring for the device to fill.
    fn offer(self: *Fixture, length: u32) void {
        self.descriptor(rx_descriptor, rx_buffer, length, true);
        self.publish(rx_available, self.rx_published + 1);
        self.rx_published += 1;
    }

    /// Read back whatever the device put on the receive ring.
    fn received(self: *Fixture) ?struct { Packet, []const u8 } {
        const used = self.at(rx_used);
        const count = std.mem.readInt(u16, used[2..4], .little);
        if (count == self.rx_taken) return null;
        self.rx_taken += 1;

        const written = std.mem.readInt(u32, used[8..12], .little);
        if (written < header_size) return null;

        const buffer = self.at(rx_buffer);
        const packet = Packet.decode(buffer[0..header_size]);
        return .{ packet, buffer[header_size..written] };
    }
};

fn request() Packet {
    return .{
        .src_cid = test_cid,
        .dst_cid = cid_host,
        .src_port = test_guest_port,
        .dst_port = test_host_port,
        .op = .request,
        .buf_alloc = 8192,
        .fwd_cnt = 0,
    };
}

test "the header a guest writes is the header this device reads" {
    const original: Packet = .{
        .src_cid = 3,
        .dst_cid = 2,
        .src_port = 1,
        .dst_port = 1024,
        .len = 7,
        .op = .rw,
        .flags = 3,
        .buf_alloc = 262144,
        .fwd_cnt = 99,
    };

    var bytes: [header_size]u8 = undefined;
    original.encode(&bytes);
    const back = Packet.decode(&bytes);

    try testing.expectEqual(original.src_cid, back.src_cid);
    try testing.expectEqual(original.dst_cid, back.dst_cid);
    try testing.expectEqual(original.src_port, back.src_port);
    try testing.expectEqual(original.dst_port, back.dst_port);
    try testing.expectEqual(original.len, back.len);
    try testing.expectEqual(Op.rw, back.op);
    try testing.expectEqual(original.flags, back.flags);
    try testing.expectEqual(original.buf_alloc, back.buf_alloc);
    try testing.expectEqual(original.fwd_cnt, back.fwd_cnt);
    try testing.expectEqual(@as(u16, type_stream), back.kind);
}

test "a guest connecting to a listening port is answered and the host is told" {
    const gpa = testing.allocator();
    var fixture: Fixture = undefined;
    try fixture.init(gpa);
    defer fixture.deinit(gpa);

    try fixture.send(request(), &.{});
    fixture.offer(header_size);
    _ = try fixture.vsock.serve(&fixture.memory);

    const answer = fixture.received() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(Op.response, answer[0].op);
    try testing.expectEqual(@as(u64, cid_host), answer[0].src_cid);
    try testing.expectEqual(@as(u32, test_guest_port), answer[0].dst_port);

    const handle = fixture.vsock.accept() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(?u32, test_host_port), fixture.vsock.port(handle));

    // Told once. A host that is told twice opens the same connection twice.
    try std.testing.expect(fixture.vsock.accept() == null);
}

test "a guest connecting to a port nobody listens on is reset" {
    const gpa = testing.allocator();
    var fixture: Fixture = undefined;
    try fixture.init(gpa);
    defer fixture.deinit(gpa);

    var packet = request();
    packet.dst_port = 9;
    try fixture.send(packet, &.{});
    fixture.offer(header_size);
    _ = try fixture.vsock.serve(&fixture.memory);

    const answer = fixture.received() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(Op.reset, answer[0].op);
    try testing.expectEqual(@as(u64, 1), fixture.vsock.refused);

    // The slot went back, so a guest cannot use refused connections to fill the table.
    try std.testing.expect(fixture.vsock.accept() == null);
    try testing.expectEqual(@as(usize, 0), fixture.vsock.connections[0].inbox_len);
    try std.testing.expect(fixture.vsock.connections[0].state == .free);
}

test "bytes the guest sends reach the host in order" {
    const gpa = testing.allocator();
    var fixture: Fixture = undefined;
    try fixture.init(gpa);
    defer fixture.deinit(gpa);

    try fixture.send(request(), &.{});
    fixture.offer(header_size);
    _ = try fixture.vsock.serve(&fixture.memory);
    _ = fixture.received();
    const handle = fixture.vsock.accept() orelse return error.TestUnexpectedResult;

    var packet = request();
    packet.op = .rw;
    try fixture.send(packet, "hello");
    _ = try fixture.vsock.serve(&fixture.memory);

    try testing.expectEqual(@as(usize, 5), fixture.vsock.available(handle));

    var buffer: [16]u8 = undefined;
    try testing.expectEqual(@as(usize, 5), fixture.vsock.read(handle, &buffer));
    try testing.expectEqualSlices(u8, "hello", buffer[0..5]);

    // Read once. The bytes are gone from the connection.
    try testing.expectEqual(@as(usize, 0), fixture.vsock.read(handle, &buffer));
}

test "bytes the host writes reach the guest" {
    const gpa = testing.allocator();
    var fixture: Fixture = undefined;
    try fixture.init(gpa);
    defer fixture.deinit(gpa);

    try fixture.send(request(), &.{});
    fixture.offer(header_size);
    _ = try fixture.vsock.serve(&fixture.memory);
    _ = fixture.received();
    const handle = fixture.vsock.accept() orelse return error.TestUnexpectedResult;

    try testing.expectEqual(@as(usize, 6), fixture.vsock.write(handle, "mirage"));

    fixture.offer(header_size + 64);
    _ = try fixture.vsock.serve(&fixture.memory);

    const answer = fixture.received() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(Op.rw, answer[0].op);
    try testing.expectEqual(@as(u32, 6), answer[0].len);
    try testing.expectEqualSlices(u8, "mirage", answer[1]);
}

test "a guest with no credit left is not sent more than it asked for" {
    const gpa = testing.allocator();
    var fixture: Fixture = undefined;
    try fixture.init(gpa);
    defer fixture.deinit(gpa);

    // The guest says its receive buffer holds four bytes.
    var opening = request();
    opening.buf_alloc = 4;
    try fixture.send(opening, &.{});
    fixture.offer(header_size);
    _ = try fixture.vsock.serve(&fixture.memory);
    _ = fixture.received();
    const handle = fixture.vsock.accept() orelse return error.TestUnexpectedResult;

    _ = fixture.vsock.write(handle, "abcdefgh");
    fixture.offer(header_size + 64);
    _ = try fixture.vsock.serve(&fixture.memory);

    const first = fixture.received() orelse return error.TestUnexpectedResult;
    // Four bytes, because that is the whole of the guest's buffer and it has consumed
    // none of it. A device that sends eight overruns the driver.
    try testing.expectEqualSlices(u8, "abcd", first[1]);

    // Nothing more goes out while the guest holds all four.
    fixture.offer(header_size + 64);
    _ = try fixture.vsock.serve(&fixture.memory);
    try std.testing.expect(fixture.received() == null);

    // The guest says it consumed them, so the rest may go.
    var update = request();
    update.op = .credit_update;
    update.buf_alloc = 4;
    update.fwd_cnt = 4;
    try fixture.send(update, &.{});
    fixture.offer(header_size + 64);
    _ = try fixture.vsock.serve(&fixture.memory);

    const second = fixture.received() orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, "efgh", second[1]);
}

test "reading from the host tells the guest there is room again" {
    const gpa = testing.allocator();
    var fixture: Fixture = undefined;
    try fixture.init(gpa);
    defer fixture.deinit(gpa);

    try fixture.send(request(), &.{});
    fixture.offer(header_size);
    _ = try fixture.vsock.serve(&fixture.memory);
    _ = fixture.received();
    const handle = fixture.vsock.accept() orelse return error.TestUnexpectedResult;

    var packet = request();
    packet.op = .rw;
    try fixture.send(packet, "four");
    _ = try fixture.vsock.serve(&fixture.memory);

    var buffer: [8]u8 = undefined;
    _ = fixture.vsock.read(handle, &buffer);

    fixture.offer(header_size);
    _ = try fixture.vsock.serve(&fixture.memory);

    const answer = fixture.received() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(Op.credit_update, answer[0].op);
    // The count is what this side has taken out, which is what the guest subtracts
    // from to work out how much room is left.
    try testing.expectEqual(@as(u32, 4), answer[0].fwd_cnt);
    try testing.expectEqual(@as(u32, buffer_size), answer[0].buf_alloc);
}

test "a guest that sends more than the room it was given loses the excess and not the rest" {
    const gpa = testing.allocator();
    var fixture: Fixture = undefined;
    try fixture.init(gpa);
    defer fixture.deinit(gpa);

    try fixture.send(request(), &.{});
    fixture.offer(header_size);
    _ = try fixture.vsock.serve(&fixture.memory);
    _ = fixture.received();
    const handle = fixture.vsock.accept() orelse return error.TestUnexpectedResult;

    // The guest was told the buffer holds `buffer_size`. This claims to send more, and
    // a device that believes it writes past the end of the connection.
    var packet = request();
    packet.op = .rw;
    const payload = try gpa.alloc(u8, buffer_size);
    defer gpa.free(payload);
    @memset(payload, 'x');
    try fixture.send(packet, payload);
    _ = try fixture.vsock.serve(&fixture.memory);

    try fixture.send(packet, payload);
    _ = try fixture.vsock.serve(&fixture.memory);

    try testing.expectEqual(@as(usize, buffer_size), fixture.vsock.available(handle));
    try std.testing.expect(fixture.vsock.dropped > 0);
}

test "a packet claiming to come from somebody else is dropped" {
    const gpa = testing.allocator();
    var fixture: Fixture = undefined;
    try fixture.init(gpa);
    defer fixture.deinit(gpa);

    var packet = request();
    packet.src_cid = test_cid + 1;
    try fixture.send(packet, &.{});
    fixture.offer(header_size);
    _ = try fixture.vsock.serve(&fixture.memory);

    try std.testing.expect(fixture.received() == null);
    try testing.expectEqual(@as(u64, 1), fixture.vsock.dropped);
}

test "a packet for a connection that does not exist is dropped and allocates nothing" {
    const gpa = testing.allocator();
    var fixture: Fixture = undefined;
    try fixture.init(gpa);
    defer fixture.deinit(gpa);

    var packet = request();
    packet.op = .rw;
    try fixture.send(packet, "nobody is listening on this connection");
    _ = try fixture.vsock.serve(&fixture.memory);

    try testing.expectEqual(@as(u64, 1), fixture.vsock.dropped);
    for (fixture.vsock.connections) |connection| {
        try std.testing.expect(connection.state == .free);
    }
}

test "an operation this device has no name for is dropped rather than guessed at" {
    const gpa = testing.allocator();
    var fixture: Fixture = undefined;
    try fixture.init(gpa);
    defer fixture.deinit(gpa);

    try fixture.send(request(), &.{});
    fixture.offer(header_size);
    _ = try fixture.vsock.serve(&fixture.memory);
    _ = fixture.received();

    var packet = request();
    packet.op = @enumFromInt(0x4141);
    try fixture.send(packet, &.{});
    _ = try fixture.vsock.serve(&fixture.memory);

    try testing.expectEqual(@as(u64, 1), fixture.vsock.dropped);
}

test "a guest that shuts down both halves ends the connection" {
    const gpa = testing.allocator();
    var fixture: Fixture = undefined;
    try fixture.init(gpa);
    defer fixture.deinit(gpa);

    try fixture.send(request(), &.{});
    fixture.offer(header_size);
    _ = try fixture.vsock.serve(&fixture.memory);
    _ = fixture.received();
    const handle = fixture.vsock.accept() orelse return error.TestUnexpectedResult;

    var packet = request();
    packet.op = .shutdown;
    packet.flags = shutdown_receive | shutdown_send;
    try fixture.send(packet, &.{});
    fixture.offer(header_size);
    _ = try fixture.vsock.serve(&fixture.memory);

    const answer = fixture.received() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(Op.reset, answer[0].op);

    // The handle names a connection that has ended, so it reads nothing rather than
    // reading whatever takes the slot next.
    var buffer: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), fixture.vsock.read(handle, &buffer));
    try testing.expectEqual(@as(usize, 0), fixture.vsock.write(handle, "gone"));
    try std.testing.expect(fixture.vsock.port(handle) == null);
}

test "a guest that finishes sending leaves what it already sent to be read" {
    const gpa = testing.allocator();
    var fixture: Fixture = undefined;
    try fixture.init(gpa);
    defer fixture.deinit(gpa);

    try fixture.send(request(), &.{});
    fixture.offer(header_size);
    _ = try fixture.vsock.serve(&fixture.memory);
    _ = fixture.received();
    const handle = fixture.vsock.accept() orelse return error.TestUnexpectedResult;

    var data = request();
    data.op = .rw;
    try fixture.send(data, "last");
    _ = try fixture.vsock.serve(&fixture.memory);

    var packet = request();
    packet.op = .shutdown;
    packet.flags = shutdown_send;
    try fixture.send(packet, &.{});
    _ = try fixture.vsock.serve(&fixture.memory);

    try std.testing.expect(fixture.vsock.finished(handle));

    var buffer: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 4), fixture.vsock.read(handle, &buffer));
    try testing.expectEqualSlices(u8, "last", buffer[0..4]);
}

test "a handle kept past the end of its connection names nothing" {
    const gpa = testing.allocator();
    var fixture: Fixture = undefined;
    try fixture.init(gpa);
    defer fixture.deinit(gpa);

    try fixture.send(request(), &.{});
    fixture.offer(header_size);
    _ = try fixture.vsock.serve(&fixture.memory);
    _ = fixture.received();
    const first = fixture.vsock.accept() orelse return error.TestUnexpectedResult;

    fixture.vsock.close(first);
    fixture.offer(header_size);
    _ = try fixture.vsock.serve(&fixture.memory);

    // A second guest connection takes the same slot. The old handle must not reach it,
    // because that would hand one session's bytes to another.
    var again = request();
    again.src_port = test_guest_port + 1;
    try fixture.send(again, &.{});
    fixture.offer(header_size);
    _ = try fixture.vsock.serve(&fixture.memory);
    _ = fixture.received();

    const second = fixture.vsock.accept() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u8, first.index), second.index);
    try std.testing.expect(first.generation != second.generation);
    try testing.expectEqual(@as(usize, 0), fixture.vsock.write(first, "wrong session"));
    try testing.expectEqual(@as(usize, 4), fixture.vsock.write(second, "fine"));
}

test "a device with no slot left refuses rather than growing" {
    const gpa = testing.allocator();
    var fixture: Fixture = undefined;
    try fixture.init(gpa);
    defer fixture.deinit(gpa);

    // One more than the table holds. A device that grows on request is one a guest can
    // exhaust.
    for (0..max_connections + 1) |index| {
        var packet = request();
        packet.src_port = test_guest_port + @as(u32, @intCast(index));
        try fixture.send(packet, &.{});
        fixture.offer(header_size);
        _ = try fixture.vsock.serve(&fixture.memory);
        _ = fixture.received();
    }

    try testing.expectEqual(@as(u64, 1), fixture.vsock.refused);
    var established: usize = 0;
    for (fixture.vsock.connections) |connection| {
        if (connection.state == .open) established += 1;
    }
    try testing.expectEqual(@as(usize, max_connections), established);
}

test "the device says which address the guest has" {
    const gpa = testing.allocator();
    var fixture: Fixture = undefined;
    try fixture.init(gpa);
    defer fixture.deinit(gpa);

    var devices = [_]Bus.Device{fixture.vsock.device(0x0a00_0000)};
    var bus: Bus = .{ .devices = &devices };

    // The driver reads its own address out of the configuration space, and a guest
    // that does not know its address cannot name itself in a packet.
    try testing.expectEqual(@as(u64, test_cid), bus.read(0x0a00_0000 + 0x100, .word));
    try testing.expectEqual(@as(u64, device_id), bus.read(0x0a00_0000 + 0x008, .word));
}

test "a buffer too small to carry data does not make the device ask for another" {
    const gpa = testing.allocator();
    var fixture: Fixture = undefined;
    try fixture.init(gpa);
    defer fixture.deinit(gpa);

    try fixture.send(request(), &.{});
    fixture.offer(header_size);
    _ = try fixture.vsock.serve(&fixture.memory);
    _ = fixture.received();
    const handle = fixture.vsock.accept() orelse return error.TestUnexpectedResult;

    _ = fixture.vsock.write(handle, "waiting to go out");

    // The driver offers room for a header and nothing else. A device that sends an empty
    // data packet here takes the buffer, moves nothing, and asks for another, which never
    // finishes. The buffer has to come back and the pass has to stop.
    fixture.offer(header_size);
    const moved = try fixture.vsock.serve(&fixture.memory);
    try testing.expectEqual(@as(u32, 1), moved);
    try std.testing.expect(fixture.vsock.dropped > 0);

    // The bytes are still waiting, so a buffer that can hold them still gets them.
    fixture.offer(header_size + 64);
    _ = try fixture.vsock.serve(&fixture.memory);
    _ = fixture.received();
    const answer = fixture.received() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(Op.rw, answer[0].op);
    try testing.expectEqualSlices(u8, "waiting to go out", answer[1]);
}
