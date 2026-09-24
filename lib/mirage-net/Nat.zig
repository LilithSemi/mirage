//! A network for a guest that has no helper to give it one.
//!
//! On Linux a caller starts `passt` and hands the socket over, which is the right thing: it is a
//! program that already does this well. There is no passt on a Mac, so a guest there had a card and
//! nowhere for its frames to go. This is what fills that gap.
//!
//! What it does is translate. The guest has one address of its own and believes there is a gateway next
//! to it. A datagram the guest sends is carried by a socket this process opens, and what comes back on
//! that socket is written as a frame addressed to the guest. Nothing is bridged and no privilege is
//! needed: every packet leaves as ordinary traffic from this process.
//!
//! What it does not do yet is carry a stream. A guest opening a connection is refused and counted, and
//! that is the next piece of work. Datagrams are enough for a guest to look a name up, which is what
//! everything else waits on.
//!
//! Nothing here trusts a guest. Every length is checked against what arrived, a table of translations
//! is bounded, and a packet this does not understand is counted rather than guessed at.

const std = @import("std");
const net = @import("../mirage-net.zig");
const system = std.posix.system;

const Nat = @This();

/// How many translations may be in flight. A guest that asks for more is refused rather than being
/// given a table that grows until the process runs out of memory.
pub const max_flows = 64;

/// How many connections may be open at once. A guest that asks for more is refused, which it reads as a
/// connection that would not open rather than as a network that has gone.
pub const max_streams = 64;

/// How long a translation is kept without being used, in turns of `poll`. A guest that looks up one
/// name and never speaks again would otherwise hold a socket forever.
pub const idle_turns = 20_000;

/// The port a guest looks names up on.
pub const dns_port = 53;

pub const Error = error{
    /// A frame longer than the buffer offered for the answer.
    NoRoom,
};

/// How much of one direction of a connection is held while the other end is not ready for it. A guest
/// that will not take what arrived, or a card with no room, keeps it here rather than losing it.
pub const stream_buffer = 32 * 1024;

/// The largest segment this network tells a guest to send. A frame holds fifteen hundred bytes, and a
/// packet and a segment header take forty of them.
pub const max_segment = 1460;

/// One connection, terminated here and carried by a socket of this process's own.
///
/// This is not a general stream implementation and does not try to be. A guest talks to it over a link
/// that loses nothing, so there is no retransmission and no congestion control: what is acknowledged is
/// what has been handed to the socket, and what the guest is sent is held until the guest acknowledges
/// it. That is the whole of it, and it is correct because the link is this process.
const Stream = struct {
    /// Where a connection is in its life. A guest may open and close one, and either end may reset it.
    const State = enum {
        /// Nothing here.
        free,
        /// The guest asked to open one and the socket is still connecting.
        opening,
        /// Both ends are open and data moves.
        open,
        /// The guest said it has no more to send.
        guest_done,
        /// The far end said it has no more to send.
        remote_done,
        /// Both said so, or somebody reset it. Kept only long enough to answer anything still arriving.
        closing,
    };

    state: State = .free,
    guest_port: u16 = 0,
    remote: net.Ip4 = @splat(0),
    /// Where the guest believes it is talking to, which differs from where this really connected when
    /// the guest addressed the gateway. Traffic to the gateway reaches this machine itself, the way a
    /// helper on Linux maps it, so something listening here can be reached without a network at all.
    seen: net.Ip4 = @splat(0),
    remote_port: u16 = 0,
    handle: std.posix.fd_t = -1,

    /// What the guest will send next, which is what this end acknowledges.
    guest_next: u32 = 0,
    /// What this end will send next, and how much of that the guest has acknowledged.
    our_next: u32 = 0,
    our_acknowledged: u32 = 0,
    /// How much the guest says it can take.
    guest_window: u16 = 0,

    /// Bytes read from the socket and not yet acknowledged by the guest. The front of this is
    /// `our_acknowledged`, so what has been acknowledged is dropped and the rest may be sent again.
    held: [stream_buffer]u8 = undefined,
    held_len: usize = 0,

    /// Turns since anything moved, so a connection nobody is using is let go.
    quiet: u32 = 0,
    /// Set once the far end has closed and everything it sent has been given to the guest.
    finish_sent: bool = false,
};

/// One translation: a guest's datagram source, where it was addressed, and the socket carrying it.
const Flow = struct {
    used: bool = false,
    guest_port: u16 = 0,
    /// Where this really goes, and below it where the guest believes it goes. The two differ when the
    /// guest addresses the gateway itself, which is what it does to look a name up: the gateway is an
    /// address this VMM invented, so the traffic goes to a resolver that exists and the answer has to
    /// come back from the address the guest wrote, or it is not read as an answer at all.
    remote: net.Ip4 = @splat(0),
    seen: net.Ip4 = @splat(0),
    remote_port: u16 = 0,
    handle: std.posix.fd_t = -1,
    /// Turns since anything moved on it.
    quiet: u32 = 0,
};

/// Who says whether the guest may reach somewhere.
///
/// A network with none of these carries whatever the guest asks for. A network with one opens
/// nothing without a decision, and a decision is for one address and one port.
///
/// An answer that has not come yet is not a refusal. The guest sends a connection again when
/// nothing answers, and asks a name again as well, so holding the first one costs a retry rather
/// than the connection. That is what lets the decision come from another program without anything
/// here waiting for it.
pub const Broker = struct {
    ctx: *anyopaque,
    asks: *const fn (ctx: *anyopaque, remote: net.Ip4, port: u16, datagram: bool) Answer,
};

pub const Answer = enum { allowed, refused, waiting };

/// What the guest was told it is, and what it was told is next to it.
guest_ip: net.Ip4,
guest_mac: net.Mac,
gateway_ip: net.Ip4,
gateway_mac: net.Mac,

/// A name server that really exists, for a guest looking a name up through the gateway. Whoever starts
/// a guest knows what this machine uses and this module does not, so it is given rather than found.
resolver: net.Ip4 = .{ 1, 1, 1, 1 },

flows: [max_flows]Flow = @splat(.{}),

/// Whoever decides what the guest may reach, if anybody does.
broker: ?Broker = null,

/// Connections in flight. Separate from the datagram table because a connection holds far more state
/// and lives far longer.
streams: [max_streams]Stream = @splat(.{}),

/// Frames the guest sent that this did not understand, and connections it asked for that cannot be
/// carried yet. Counted rather than ignored, because a guest whose traffic disappears in silence looks
/// like a guest with a broken network.
unknown: u64 = 0,
streams_refused: u64 = 0,
streams_opened: u64 = 0,
/// Translations that could not be made because the table was full.
no_room: u64 = 0,
/// What the decisions came to. A guest that cannot reach anything and a guest nobody answered for
/// look the same from inside, so both are counted.
brokered: u64 = 0,
refused_by_policy: u64 = 0,
waiting_on_policy: u64 = 0,
sent: u64 = 0,
received: u64 = 0,

pub fn deinit(self: *Nat) void {
    for (&self.flows) |*each| {
        if (each.used) _ = system.close(each.handle);
        each.* = .{};
    }
    for (&self.streams) |*open| self.close(open);
}

/// Take a frame from the guest, and give back the frame to hand it in answer, if there is one.
///
/// A question about who holds an address is answered here and now. A datagram is carried by a socket
/// and its answer arrives later, through `poll`.
pub fn fromGuest(self: *Nat, frame: []const u8, into: []u8) ?[]const u8 {
    const outer = net.Ethernet.parse(frame) catch {
        self.unknown += 1;
        return null;
    };

    switch (outer.kind) {
        .arp => return self.answerArp(frame, into),
        .ip4 => {},
        else => {
            self.unknown += 1;
            return null;
        },
    }

    const packet = net.Ethernet.payload(frame) catch {
        self.unknown += 1;
        return null;
    };
    if (!net.Ip4Header.valid(packet)) {
        self.unknown += 1;
        return null;
    }
    const header = net.Ip4Header.parse(packet) catch {
        self.unknown += 1;
        return null;
    };
    const body = packet[header.header_size..][0..header.payload_size];

    switch (header.protocol) {
        .udp => {
            self.carry(header, body);
            return null;
        },
        // Only a ping to the gateway is answered. Reaching anything further needs a socket this
        // process may not open without privilege, so it is refused rather than half done.
        .icmp => return self.answerPing(header, body, into),
        .tcp => return self.carryStream(header, body, into),
        else => {
            self.unknown += 1;
            return null;
        },
    }
}

/// Say who holds the gateway address, and nothing else. A guest asks this before it sends anything, so
/// without an answer nothing it cares about ever leaves.
fn answerArp(self: *Nat, frame: []const u8, into: []u8) ?[]const u8 {
    const body = net.Ethernet.payload(frame) catch {
        self.unknown += 1;
        return null;
    };
    const asked = net.Arp.parse(body) catch {
        self.unknown += 1;
        return null;
    };
    if (asked.operation != .request) {
        self.unknown += 1;
        return null;
    }
    if (!std.mem.eql(u8, &asked.target_ip, &self.gateway_ip)) {
        self.unknown += 1;
        return null;
    }

    const header: net.Ethernet = .{
        .destination = asked.sender_mac,
        .source = self.gateway_mac,
        .kind = .arp,
    };
    const at = header.write(into) catch return null;
    const answer: net.Arp = .{
        .operation = .reply,
        .sender_mac = self.gateway_mac,
        .sender_ip = self.gateway_ip,
        .target_mac = asked.sender_mac,
        .target_ip = asked.sender_ip,
    };
    const end = answer.write(into[at..]) catch return null;
    return into[0 .. at + end];
}

/// Answer a ping to the gateway, so a guest can tell the network is there.
fn answerPing(self: *Nat, header: net.Ip4Header, body: []const u8, into: []u8) ?[]const u8 {
    if (!std.mem.eql(u8, &header.destination, &self.gateway_ip)) {
        self.unknown += 1;
        return null;
    }
    const asked = net.Icmp.parse(body) catch {
        self.unknown += 1;
        return null;
    };
    if (asked.kind != net.Icmp.echo_request) {
        self.unknown += 1;
        return null;
    }

    var scratch: [net.Ip4Header.min_size + 1500]u8 = undefined;
    const answer: net.Icmp = .{
        .kind = net.Icmp.echo_reply,
        .identifier = asked.identifier,
        .sequence = asked.sequence,
        .payload_size = asked.payload_size,
    };
    const inner = answer.write(body[net.Icmp.size..], &scratch) catch return null;
    return self.toGuest(.icmp, scratch[0..inner], into);
}

/// Wrap a payload as a packet from the gateway to the guest, in a frame addressed to it.
fn toGuest(self: *Nat, protocol: net.Protocol, body: []const u8, into: []u8) ?[]const u8 {
    const outer: net.Ethernet = .{
        .destination = self.guest_mac,
        .source = self.gateway_mac,
        .kind = .ip4,
    };
    const at = outer.write(into) catch return null;

    const header: net.Ip4Header = .{
        .source = self.gateway_ip,
        .destination = self.guest_ip,
        .protocol = protocol,
        .header_size = net.Ip4Header.min_size,
        .payload_size = body.len,
        .identification = 0,
        .time_to_live = 64,
    };
    const written = header.write(into[at..]) catch return null;
    if (into.len < at + written + body.len) return null;
    @memcpy(into[at + written ..][0..body.len], body);
    return into[0 .. at + written + body.len];
}

/// Carry a datagram out through a socket of this process's own.
fn carry(self: *Nat, header: net.Ip4Header, body: []const u8) void {
    const datagram = net.Udp.parse(body) catch {
        self.unknown += 1;
        return;
    };
    const payload = net.Udp.payload(body) catch {
        self.unknown += 1;
        return;
    };

    // A guest looking a name up sends it to the gateway, which is an address this VMM invented and
    // nothing answers. So that one goes to a resolver that exists, while the answer still comes back
    // wearing the address the guest wrote.
    const asking_gateway = std.mem.eql(u8, &header.destination, &self.gateway_ip);
    const really = if (asking_gateway and datagram.destination == dns_port)
        self.resolver
    else if (asking_gateway) {
        // Anything else addressed to the gateway has nothing behind it.
        self.unknown += 1;
        return;
    } else header.destination;

    const flow = self.flowFor(datagram.source, really, header.destination, datagram.destination) orelse {
        self.no_room += 1;
        return;
    };

    const put = system.write(flow.handle, payload.ptr, payload.len);
    if (std.posix.errno(put) == .SUCCESS) {
        self.sent += 1;
        flow.quiet = 0;
    }
}

/// The translation for this datagram, making one if there is none.
fn flowFor(self: *Nat, guest_port: u16, remote: net.Ip4, seen: net.Ip4, remote_port: u16) ?*Flow {
    for (&self.flows) |*each| {
        if (!each.used) continue;
        if (each.guest_port == guest_port and each.remote_port == remote_port and
            std.mem.eql(u8, &each.remote, &remote)) return each;
    }

    switch (self.ask(remote, remote_port, true)) {
        .allowed => {},
        // A datagram is sent again as well, by whatever asked for a name or sent it.
        .refused, .waiting => return null,
    }

    const free = for (&self.flows) |*each| {
        if (!each.used) break each;
    } else return null;

    // One socket per translation, connected so what comes back needs no address of its own, and asked
    // not to wait because this runs on the thread the guest runs on.
    const raw = system.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
    if (std.posix.errno(raw) != .SUCCESS) return null;
    const handle: std.posix.fd_t = @intCast(raw);

    var address: std.posix.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, remote_port),
        .addr = @bitCast(remote),
    };
    const joined = system.connect(handle, @ptrCast(&address), @sizeOf(std.posix.sockaddr.in));
    if (std.posix.errno(joined) != .SUCCESS) {
        _ = system.close(handle);
        return null;
    }

    const flags = system.fcntl(handle, std.posix.F.GETFL, @as(usize, 0));
    if (std.posix.errno(flags) == .SUCCESS) {
        const asking: std.posix.O = .{ .NONBLOCK = true };
        const wanted = @as(usize, @as(u32, @bitCast(asking))) | @as(usize, @intCast(flags));
        _ = system.fcntl(handle, std.posix.F.SETFL, wanted);
    }

    free.* = .{
        .used = true,
        .guest_port = guest_port,
        .remote = remote,
        .seen = seen,
        .remote_port = remote_port,
        .handle = handle,
        .quiet = 0,
    };
    return free;
}

/// Ask whoever decides, and count what they said. A network with nobody to ask allows everything:
/// whoever started the guest chose that by giving no broker.
fn ask(self: *Nat, remote: net.Ip4, port: u16, datagram: bool) Answer {
    const who = self.broker orelse return .allowed;
    const answer = who.asks(who.ctx, remote, port, datagram);
    switch (answer) {
        .allowed => self.brokered += 1,
        .refused => self.refused_by_policy += 1,
        .waiting => self.waiting_on_policy += 1,
    }
    return answer;
}

/// Move one answer waiting on a socket back to the guest, if there is one.
///
/// One per call, because a caller has one buffer and a frame each turn is what the card takes. A
/// translation nothing has used for a long time is let go here as well.
pub fn poll(self: *Nat, into: []u8) ?[]const u8 {
    // Connections first, because one carries far more than a datagram, and a guest waiting on one is
    // waiting on everything it asked for.
    if (self.pollStreams(into)) |frame| return frame;

    for (&self.flows) |*each| {
        if (!each.used) continue;

        var payload: [1472]u8 = undefined;
        const got = system.read(each.handle, &payload, payload.len);
        if (std.posix.errno(got) != .SUCCESS or got == 0) {
            each.quiet += 1;
            if (each.quiet > idle_turns) {
                _ = system.close(each.handle);
                each.* = .{};
            }
            continue;
        }
        each.quiet = 0;
        self.received += 1;

        var scratch: [1500]u8 = undefined;
        const datagram: net.Udp = .{
            .source = each.remote_port,
            .destination = each.guest_port,
            .payload_size = @intCast(got),
        };
        // The addresses the guest will see, which are what its checksum is taken over.
        const inner = datagram.write(each.seen, self.guest_ip, payload[0..@intCast(got)], &scratch) catch continue;

        // A datagram comes back from where it was addressed, not from the gateway, so the packet says
        // so: a guest that saw the gateway's address here would drop it as an answer to nothing.
        const outer: net.Ethernet = .{
            .destination = self.guest_mac,
            .source = self.gateway_mac,
            .kind = .ip4,
        };
        const at = outer.write(into) catch continue;
        const header: net.Ip4Header = .{
            .source = each.seen,
            .destination = self.guest_ip,
            .protocol = .udp,
            .header_size = net.Ip4Header.min_size,
            .payload_size = inner,
            .identification = 0,
            .time_to_live = 64,
        };
        const written = header.write(into[at..]) catch continue;
        if (into.len < at + written + inner) continue;
        @memcpy(into[at + written ..][0..inner], scratch[0..inner]);
        return into[0 .. at + written + inner];
    }
    return null;
}

/// Take a segment from the guest.
///
/// Every branch here either answers now or arranges for an answer later. A segment for a connection
/// nobody opened is reset, because a guest left waiting for an answer that will never come is worse than
/// a guest told no.
fn carryStream(self: *Nat, header: net.Ip4Header, body: []const u8, into: []u8) ?[]const u8 {
    const segment = net.Tcp.parse(body) catch {
        self.unknown += 1;
        return null;
    };
    const payload = net.Tcp.payload(body) catch {
        self.unknown += 1;
        return null;
    };

    const found = self.streamFor(segment.source, header.destination, segment.destination);

    // A connection this end knows nothing about. Opening is the only thing a guest may do with one.
    if (found == null) {
        if (!segment.flags.syn) return self.resetTo(segment, header.destination, into);
        return self.openStream(segment, header.destination, into);
    }

    const stream = found.?;
    stream.quiet = 0;
    stream.guest_window = segment.window;

    if (segment.flags.reset) {
        self.close(stream);
        return null;
    }

    // What the guest has acknowledged is no longer held. Anything past what was sent is a guest
    // acknowledging something nobody sent, so it is ignored rather than trusted.
    if (segment.flags.ack) {
        const moved = segment.acknowledgement -% stream.our_acknowledged;
        const outstanding = stream.our_next -% stream.our_acknowledged;
        if (moved <= outstanding) {
            stream.our_acknowledged = segment.acknowledgement;
            if (moved > 0 and moved <= stream.held_len) {
                std.mem.copyForwards(u8, stream.held[0 .. stream.held_len - moved], stream.held[moved..stream.held_len]);
                stream.held_len -= moved;
            }
        }
    }

    if (stream.state == .opening) {
        // The guest acknowledged the opening, so both ends are open now.
        if (segment.flags.ack) stream.state = .open;
    }

    // Data, but only what comes next. A link that loses nothing never delivers a gap, so anything out
    // of order is a guest sending again and is acknowledged without being handed over twice.
    if (payload.len > 0 and segment.sequence == stream.guest_next) {
        const put = system.write(stream.handle, payload.ptr, payload.len);
        if (std.posix.errno(put) == .SUCCESS) {
            stream.guest_next +%= @intCast(put);
            self.sent += @intCast(put);
        }
    }

    if (segment.flags.fin and segment.sequence == stream.guest_next) {
        stream.guest_next +%= 1;
        // Nothing more is coming from the guest, so the socket is told the same.
        _ = system.shutdown(stream.handle, 1);
        stream.state = if (stream.state == .remote_done) .closing else .guest_done;
    }

    // Anything that moved the guest's side forward is acknowledged, and any waiting data goes with it.
    return self.sendStream(stream, into);
}

/// Open a connection for the guest, and answer whether it opened.
fn openStream(self: *Nat, segment: net.Tcp, remote: net.Ip4, into: []u8) ?[]const u8 {
    switch (self.ask(remote, segment.destination, false)) {
        .allowed => {},
        .refused => return self.resetTo(segment, remote, into),
        // Nothing goes back at all. The guest sends this again, and by then there is an answer.
        .waiting => return null,
    }

    const free = for (&self.streams) |*each| {
        if (each.state == .free) break each;
    } else {
        self.no_room += 1;
        return self.resetTo(segment, remote, into);
    };

    const raw = system.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0);
    if (std.posix.errno(raw) != .SUCCESS) return self.resetTo(segment, remote, into);
    const handle: std.posix.fd_t = @intCast(raw);

    // Asked not to wait before connecting, so a far end that is slow or absent does not stop the guest.
    const flags = system.fcntl(handle, std.posix.F.GETFL, @as(usize, 0));
    if (std.posix.errno(flags) == .SUCCESS) {
        const asking: std.posix.O = .{ .NONBLOCK = true };
        const wanted = @as(usize, @as(u32, @bitCast(asking))) | @as(usize, @intCast(flags));
        _ = system.fcntl(handle, std.posix.F.SETFL, wanted);
    }

    // A guest addressing the gateway is addressing this machine. Connecting to its loopback is what makes
    // that true, and is what a helper on Linux does by default, so something listening here is reachable
    // by a guest whose only network is this.
    const towards: net.Ip4 = if (std.mem.eql(u8, &remote, &self.gateway_ip)) .{ 127, 0, 0, 1 } else remote;

    var address: std.posix.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, segment.destination),
        .addr = @bitCast(towards),
    };
    const joined = system.connect(handle, @ptrCast(&address), @sizeOf(std.posix.sockaddr.in));
    switch (std.posix.errno(joined)) {
        // Connected at once, or still going. Either is fine: the answer to the guest waits until the
        // socket says it is writable, which `pollStreams` finds out.
        .SUCCESS, .INPROGRESS, .ALREADY => {},
        else => {
            _ = system.close(handle);
            return self.resetTo(segment, remote, into);
        },
    }

    free.* = .{
        .state = .opening,
        .guest_port = segment.source,
        .seen = remote,
        .remote = towards,
        .remote_port = segment.destination,
        .handle = handle,
        // The guest's opening segment counts as one, so the next thing it sends is one past it.
        .guest_next = segment.sequence +% 1,
        .our_next = 1,
        .our_acknowledged = 1,
        .guest_window = segment.window,
    };
    self.streams_opened += 1;
    return null;
}

/// Tell the guest a connection is not there. A guest that gets this stops waiting, which is the point.
fn resetTo(self: *Nat, segment: net.Tcp, remote: net.Ip4, into: []u8) ?[]const u8 {
    self.streams_refused += 1;

    var scratch: [net.Tcp.min_size]u8 = undefined;
    const answer: net.Tcp = .{
        .source = segment.destination,
        .destination = segment.source,
        .sequence = segment.acknowledgement,
        // What the guest sent counts as one if it was an opening, so the reset points past it.
        .acknowledgement = segment.sequence +% (if (segment.flags.syn) @as(u32, 1) else 0),
        .flags = .{ .reset = true, .ack = true },
        .window = 0,
        .header_size = net.Tcp.min_size,
        .payload_size = 0,
    };
    const inner = answer.write(remote, self.guest_ip, &.{}, &scratch) catch return null;
    return self.wrap(.tcp, remote, scratch[0..inner], into);
}

/// Send the guest whatever this end owes it: the opening answer, data, an acknowledgement, or the close.
fn sendStream(self: *Nat, stream: *Stream, into: []u8) ?[]const u8 {
    var scratch: [net.Tcp.min_size + max_segment]u8 = undefined;

    var flags: net.Tcp.Flags = .{ .ack = true };
    var body: []const u8 = &.{};

    if (stream.state == .opening) {
        // Nothing to say until the socket has connected, which `pollStreams` watches for.
        return null;
    }

    // Unacknowledged data, as much as the guest says it can take and a segment holds.
    const outstanding = stream.our_next -% stream.our_acknowledged;
    if (stream.held_len > outstanding) {
        const waiting = stream.held[outstanding..stream.held_len];
        const room = @min(@min(waiting.len, max_segment), stream.guest_window);
        if (room > 0) {
            body = waiting[0..room];
            flags.push = true;
        }
    }

    // The far end has closed and everything it sent has been given over, so say so once.
    if ((stream.state == .remote_done or stream.state == .closing) and
        body.len == 0 and stream.held_len == (stream.our_next -% stream.our_acknowledged) and
        !stream.finish_sent)
    {
        flags.fin = true;
        stream.finish_sent = true;
    }

    const answer: net.Tcp = .{
        .source = stream.remote_port,
        .destination = stream.guest_port,
        .sequence = stream.our_next,
        .acknowledgement = stream.guest_next,
        .flags = flags,
        .window = stream_buffer - @as(u16, @intCast(@min(stream.held_len, stream_buffer - 1))),
        .header_size = net.Tcp.min_size,
        .payload_size = body.len,
    };
    const inner = answer.write(stream.seen, self.guest_ip, body, &scratch) catch return null;

    stream.our_next +%= @intCast(body.len);
    if (flags.fin) stream.our_next +%= 1;
    return self.wrap(.tcp, stream.seen, scratch[0..inner], into);
}

/// Move one connection along: finish opening it, or read what the far end sent.
fn pollStreams(self: *Nat, into: []u8) ?[]const u8 {
    for (&self.streams) |*each| {
        if (each.state == .free) continue;

        if (each.state == .opening) {
            // Writable means connected, and an error means it never will be. Asking for the error is
            // what tells the two apart without waiting.
            var problem: i32 = 0;
            var width: u32 = @sizeOf(i32);
            const asked = system.getsockopt(each.handle, std.posix.SOL.SOCKET, std.posix.SO.ERROR, @ptrCast(&problem), &width);
            if (std.posix.errno(asked) != .SUCCESS) continue;
            if (problem != 0) {
                // It will not open. The guest is told, and told once.
                const answer = self.resetFor(each, into);
                self.close(each);
                return answer;
            }

            var probe: [1]u8 = undefined;
            const peek = system.recvfrom(each.handle, &probe, probe.len, std.posix.MSG.PEEK | std.posix.MSG.DONTWAIT, null, null);
            switch (std.posix.errno(peek)) {
                // Nothing to read yet is what a fresh connection looks like, and so is data waiting.
                .SUCCESS, .AGAIN => {},
                else => continue,
            }

            each.state = .open;
            each.quiet = 0;
            return self.acceptedFor(each, into);
        }

        // Read what the far end sent, into whatever room is left.
        if (each.held_len < stream_buffer) {
            const got = system.read(each.handle, each.held[each.held_len..].ptr, stream_buffer - each.held_len);
            switch (std.posix.errno(got)) {
                .SUCCESS => {
                    if (got == 0) {
                        // The far end has no more to send.
                        if (each.state == .open) each.state = .remote_done;
                        if (each.state == .guest_done) each.state = .closing;
                    } else {
                        each.held_len += @intCast(got);
                        self.received += @intCast(got);
                        each.quiet = 0;
                    }
                },
                .AGAIN => {},
                else => {
                    const answer = self.resetFor(each, into);
                    self.close(each);
                    return answer;
                },
            }
        }

        // Anything to hand over, or a close to pass on.
        const outstanding = each.our_next -% each.our_acknowledged;
        const waiting = each.held_len > outstanding;
        const closing = (each.state == .remote_done or each.state == .closing) and !each.finish_sent;
        if (waiting or closing) return self.sendStream(each, into);

        // Nothing moved. A connection nobody is using is let go, once both ends are done with it.
        each.quiet += 1;
        if (each.state == .closing and each.finish_sent and each.held_len == 0) {
            self.close(each);
        } else if (each.quiet > idle_turns * 10) {
            self.close(each);
        }
    }
    return null;
}

/// Tell the guest a connection it had is gone.
fn resetFor(self: *Nat, stream: *Stream, into: []u8) ?[]const u8 {
    var scratch: [net.Tcp.min_size]u8 = undefined;
    const answer: net.Tcp = .{
        .source = stream.remote_port,
        .destination = stream.guest_port,
        .sequence = stream.our_next,
        .acknowledgement = stream.guest_next,
        .flags = .{ .reset = true, .ack = true },
        .window = 0,
        .header_size = net.Tcp.min_size,
        .payload_size = 0,
    };
    const inner = answer.write(stream.seen, self.guest_ip, &.{}, &scratch) catch return null;
    return self.wrap(.tcp, stream.seen, scratch[0..inner], into);
}

/// Tell the guest its connection is open.
fn acceptedFor(self: *Nat, stream: *Stream, into: []u8) ?[]const u8 {
    var scratch: [net.Tcp.min_size]u8 = undefined;
    const answer: net.Tcp = .{
        .source = stream.remote_port,
        .destination = stream.guest_port,
        // The opening answer carries the sequence before the first byte, and counts as one itself.
        .sequence = stream.our_next -% 1,
        .acknowledgement = stream.guest_next,
        .flags = .{ .syn = true, .ack = true },
        .window = stream_buffer,
        .header_size = net.Tcp.min_size,
        .payload_size = 0,
    };
    const inner = answer.write(stream.seen, self.guest_ip, &.{}, &scratch) catch return null;
    return self.wrap(.tcp, stream.seen, scratch[0..inner], into);
}

/// The connection for this segment, or nothing if there is none.
fn streamFor(self: *Nat, guest_port: u16, addressed: net.Ip4, remote_port: u16) ?*Stream {
    for (&self.streams) |*each| {
        if (each.state == .free) continue;
        // Matched on the address the guest wrote, not the one this really connected to. The two differ
        // when the guest addressed the gateway, and matching on the wrong one loses the connection the
        // moment the guest answers: its own handshake would find nothing and be reset.
        if (each.guest_port == guest_port and each.remote_port == remote_port and
            std.mem.eql(u8, &each.seen, &addressed)) return each;
    }
    return null;
}

fn close(self: *Nat, stream: *Stream) void {
    _ = self;
    if (stream.state != .free) _ = system.close(stream.handle);
    stream.* = .{};
}

/// Wrap a payload as a packet from one address to the guest, in a frame addressed to it.
fn wrap(self: *Nat, protocol: net.Protocol, from: net.Ip4, body: []const u8, into: []u8) ?[]const u8 {
    const outer: net.Ethernet = .{
        .destination = self.guest_mac,
        .source = self.gateway_mac,
        .kind = .ip4,
    };
    const at = outer.write(into) catch return null;

    const header: net.Ip4Header = .{
        .source = from,
        .destination = self.guest_ip,
        .protocol = protocol,
        .header_size = net.Ip4Header.min_size,
        .payload_size = body.len,
        .identification = 0,
        .time_to_live = 64,
    };
    const written = header.write(into[at..]) catch return null;
    if (into.len < at + written + body.len) return null;
    @memcpy(into[at + written ..][0..body.len], body);
    return into[0 .. at + written + body.len];
}

/// How many translations are in flight.
pub fn inFlight(self: *const Nat) usize {
    var count: usize = 0;
    for (self.flows) |each| {
        if (each.used) count += 1;
    }
    return count;
}

const testing = @import("mirage-testing");

fn fixture() Nat {
    return .{
        .guest_ip = .{ 10, 0, 2, 15 },
        .guest_mac = .{ 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 },
        .gateway_ip = .{ 10, 0, 2, 2 },
        .gateway_mac = .{ 0x52, 0x54, 0x00, 0x12, 0x34, 0x57 },
    };
}

/// A question about who holds an address, as a guest sends one.
fn askArp(target: net.Ip4, into: []u8) []const u8 {
    const outer: net.Ethernet = .{
        .destination = net.broadcast,
        .source = .{ 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 },
        .kind = .arp,
    };
    const at = outer.write(into) catch unreachable;
    const asking: net.Arp = .{
        .operation = .request,
        .sender_mac = .{ 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 },
        .sender_ip = .{ 10, 0, 2, 15 },
        .target_mac = net.unknown,
        .target_ip = target,
    };
    const end = asking.write(into[at..]) catch unreachable;
    return into[0 .. at + end];
}

test "who holds the gateway address is answered, and nothing else is" {
    var nat = fixture();
    defer nat.deinit();

    var asked: [64]u8 = undefined;
    var answer: [64]u8 = undefined;

    const reply = nat.fromGuest(askArp(.{ 10, 0, 2, 2 }, &asked), &answer) orelse
        return error.TestUnexpectedResult;

    const outer = try net.Ethernet.parse(reply);
    try testing.expectEqualSlices(u8, &nat.guest_mac, &outer.destination);
    try testing.expectEqualSlices(u8, &nat.gateway_mac, &outer.source);

    const body = try net.Ethernet.payload(reply);
    const said = try net.Arp.parse(body);
    try testing.expectEqual(net.Arp.Operation.reply, said.operation);
    try testing.expectEqualSlices(u8, &nat.gateway_ip, &said.sender_ip);
    try testing.expectEqualSlices(u8, &nat.gateway_mac, &said.sender_mac);

    // An address this network does not hold is not answered for. Answering would tell the guest to send
    // traffic here that nothing would carry.
    try std.testing.expect(nat.fromGuest(askArp(.{ 10, 0, 2, 99 }, &asked), &answer) == null);
    try testing.expectEqual(@as(u64, 1), nat.unknown);
}

test "a ping to the gateway comes back and one to anywhere else does not" {
    var nat = fixture();
    defer nat.deinit();

    var frame: [128]u8 = undefined;
    var answer: [128]u8 = undefined;

    const request: net.Icmp = .{ .kind = net.Icmp.echo_request, .identifier = 0x1234, .sequence = 7, .payload_size = 4 };
    var inner: [64]u8 = undefined;
    const body = request.write(&.{ 'p', 'i', 'n', 'g' }, &inner) catch unreachable;

    const outer: net.Ethernet = .{ .destination = nat.gateway_mac, .source = nat.guest_mac, .kind = .ip4 };
    const at = outer.write(&frame) catch unreachable;
    const header: net.Ip4Header = .{
        .source = nat.guest_ip,
        .destination = nat.gateway_ip,
        .protocol = .icmp,
        .header_size = net.Ip4Header.min_size,
        .payload_size = body,
        .identification = 1,
        .time_to_live = 64,
    };
    const wrote = header.write(frame[at..]) catch unreachable;
    @memcpy(frame[at + wrote ..][0..body], inner[0..body]);

    const reply = nat.fromGuest(frame[0 .. at + wrote + body], &answer) orelse
        return error.TestUnexpectedResult;

    const packet = try net.Ethernet.payload(reply);
    try std.testing.expect(net.Ip4Header.valid(packet));
    const came = try net.Ip4Header.parse(packet);
    try testing.expectEqual(net.Protocol.icmp, came.protocol);
    try testing.expectEqualSlices(u8, &nat.gateway_ip, &came.source);

    const said = try net.Icmp.parse(packet[came.header_size..]);
    try testing.expectEqual(@as(u8, net.Icmp.echo_reply), said.kind);
    // The identifier and the sequence come back as they went, which is how a guest matches an answer
    // to the question it asked.
    try testing.expectEqual(@as(u16, 0x1234), said.identifier);
    try testing.expectEqual(@as(u16, 7), said.sequence);

    // A ping meant for somewhere else needs a socket this process may not open, so it is counted
    // rather than answered as though it had arrived.
    std.mem.writeInt(u32, frame[at + 16 ..][0..4], 0x08080808, .big);
    const fixed = net.Ip4Header.parse(frame[at..]) catch unreachable;
    _ = fixed;
    var again: [128]u8 = undefined;
    const patched: net.Ip4Header = .{
        .source = nat.guest_ip,
        .destination = .{ 8, 8, 8, 8 },
        .protocol = .icmp,
        .header_size = net.Ip4Header.min_size,
        .payload_size = body,
        .identification = 1,
        .time_to_live = 64,
    };
    const rewrote = patched.write(frame[at..]) catch unreachable;
    @memcpy(frame[at + rewrote ..][0..body], inner[0..body]);
    try std.testing.expect(nat.fromGuest(frame[0 .. at + rewrote + body], &again) == null);
}

/// Build a frame carrying a segment from the guest, as a guest sends one.
fn guestSegment(nat: *const Nat, to: net.Ip4, segment: net.Tcp, body: []const u8, into: []u8) []const u8 {
    var inner: [1600]u8 = undefined;
    const carried = segment.write(nat.guest_ip, to, body, &inner) catch unreachable;

    const outer: net.Ethernet = .{ .destination = nat.gateway_mac, .source = nat.guest_mac, .kind = .ip4 };
    const at = outer.write(into) catch unreachable;
    const header: net.Ip4Header = .{
        .source = nat.guest_ip,
        .destination = to,
        .protocol = .tcp,
        .header_size = net.Ip4Header.min_size,
        .payload_size = carried,
        .identification = 1,
        .time_to_live = 64,
    };
    const wrote = header.write(into[at..]) catch unreachable;
    @memcpy(into[at + wrote ..][0..carried], inner[0..carried]);
    return into[0 .. at + wrote + carried];
}

/// The segment inside a frame this network produced.
fn segmentOf(frame: []const u8) !net.Tcp {
    const packet = try net.Ethernet.payload(frame);
    try std.testing.expect(net.Ip4Header.valid(packet));
    const header = try net.Ip4Header.parse(packet);
    try testing.expectEqual(net.Protocol.tcp, header.protocol);
    return net.Tcp.parse(packet[header.header_size..]);
}

test "a segment for a connection nobody opened is reset rather than ignored" {
    var nat = fixture();
    defer nat.deinit();

    var frame: [256]u8 = undefined;
    var answer: [256]u8 = undefined;

    // Data with no connection behind it. A guest left waiting for an answer that will never come is
    // worse off than one told there is nothing there.
    const sent: net.Tcp = .{
        .source = 40000,
        .destination = 80,
        .sequence = 100,
        .acknowledgement = 0,
        .flags = .{ .ack = true },
        .window = 64240,
        .header_size = net.Tcp.min_size,
        .payload_size = 0,
    };
    const reply = nat.fromGuest(guestSegment(&nat, .{ 8, 8, 8, 8 }, sent, &.{}, &frame), &answer) orelse
        return error.TestUnexpectedResult;

    const said = try segmentOf(reply);
    try std.testing.expect(said.flags.reset);
    try testing.expectEqual(@as(u64, 1), nat.streams_refused);
    try testing.expectEqual(@as(u64, 0), nat.unknown);
}

test "a segment whose header is shorter than a header is not read as one" {
    var nat = fixture();
    defer nat.deinit();

    var frame: [256]u8 = undefined;
    const outer: net.Ethernet = .{ .destination = nat.gateway_mac, .source = nat.guest_mac, .kind = .ip4 };
    const at = outer.write(&frame) catch unreachable;
    const header: net.Ip4Header = .{
        .source = nat.guest_ip,
        .destination = .{ 8, 8, 8, 8 },
        .protocol = .tcp,
        .header_size = net.Ip4Header.min_size,
        .payload_size = net.Tcp.min_size,
        .identification = 1,
        .time_to_live = 64,
    };
    const wrote = header.write(frame[at..]) catch unreachable;
    @memset(frame[at + wrote ..][0..net.Tcp.min_size], 0);

    var answer: [256]u8 = undefined;
    try std.testing.expect(nat.fromGuest(frame[0 .. at + wrote + net.Tcp.min_size], &answer) == null);

    // Counted as not understood rather than as a connection, because a header saying it is zero words
    // long is not a segment at all.
    try testing.expectEqual(@as(u64, 1), nat.unknown);
    try testing.expectEqual(@as(u64, 0), nat.streams_refused);
}

test "a guest opens a connection, sends, is answered, and closes it" {
    var nat = fixture();
    defer nat.deinit();

    // Something for the guest to talk to: a socket on this machine that takes one connection and echoes
    // what it is given. Nothing about this test needs a guest, only the frames one would send.
    const listener: std.posix.fd_t = @intCast(system.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0));
    if (listener < 0) return error.SkipZigTest;
    defer _ = system.close(listener);

    var address: std.posix.sockaddr.in = .{ .port = 0, .addr = 0x0100007f };
    if (std.posix.errno(system.bind(listener, @ptrCast(&address), @sizeOf(std.posix.sockaddr.in))) != .SUCCESS) {
        return error.SkipZigTest;
    }
    var width: u32 = @sizeOf(std.posix.sockaddr.in);
    if (std.posix.errno(system.getsockname(listener, @ptrCast(&address), &width)) != .SUCCESS) {
        return error.SkipZigTest;
    }
    if (std.posix.errno(system.listen(listener, 1)) != .SUCCESS) return error.SkipZigTest;

    const port = std.mem.bigToNative(u16, address.port);
    const remote: net.Ip4 = .{ 127, 0, 0, 1 };

    var frame: [2048]u8 = undefined;
    var answer: [2048]u8 = undefined;

    // The guest asks to open one. Nothing comes back at once, because the socket is still connecting.
    const opening: net.Tcp = .{
        .source = 40000,
        .destination = port,
        .sequence = 1000,
        .acknowledgement = 0,
        .flags = .{ .syn = true },
        .window = 64240,
        .header_size = net.Tcp.min_size,
        .payload_size = 0,
    };
    try std.testing.expect(nat.fromGuest(guestSegment(&nat, remote, opening, &.{}, &frame), &answer) == null);
    try testing.expectEqual(@as(u64, 1), nat.streams_opened);

    // Turning the handle until it says the connection is open.
    const accepted: net.Tcp = blk: {
        for (0..1000) |_| {
            if (nat.poll(&answer)) |reply| {
                const said = try segmentOf(reply);
                if (said.flags.syn and said.flags.ack) break :blk said;
            }
        }
        return error.TestUnexpectedResult;
    };
    // The answer points at the byte after the guest's opening, which is how the guest knows it was heard.
    try testing.expectEqual(@as(u32, 1001), accepted.acknowledgement);

    const carried: std.posix.fd_t = @intCast(system.accept(listener, null, null));
    if (carried < 0) return error.SkipZigTest;
    defer _ = system.close(carried);

    // The guest finishes opening and sends something.
    const hello = "hello over a stream";
    const sending: net.Tcp = .{
        .source = 40000,
        .destination = port,
        .sequence = 1001,
        .acknowledgement = accepted.sequence +% 1,
        .flags = .{ .ack = true, .push = true },
        .window = 64240,
        .header_size = net.Tcp.min_size,
        .payload_size = hello.len,
    };
    _ = nat.fromGuest(guestSegment(&nat, remote, sending, hello, &frame), &answer);

    var heard: [64]u8 = undefined;
    const got = system.read(carried, &heard, heard.len);
    try testing.expectEqual(@as(usize, hello.len), @as(usize, @intCast(got)));
    try testing.expectEqualSlices(u8, hello, heard[0..hello.len]);

    // The far end answers, and the guest is given it.
    const back = "and back again";
    _ = system.write(carried, back.ptr, back.len);

    const delivered: net.Tcp = blk: {
        for (0..1000) |_| {
            if (nat.poll(&answer)) |reply| {
                const said = try segmentOf(reply);
                if (said.payload_size > 0) {
                    const packet = try net.Ethernet.payload(reply);
                    const outer = try net.Ip4Header.parse(packet);
                    const body = try net.Tcp.payload(packet[outer.header_size..]);
                    try testing.expectEqualSlices(u8, back, body);
                    break :blk said;
                }
            }
        }
        return error.TestUnexpectedResult;
    };
    // It is acknowledged up to everything the guest sent, and no further.
    try testing.expectEqual(@as(u32, 1001 + hello.len), delivered.acknowledgement);

    // The guest says it has no more to send, and the far end sees the connection end.
    const finishing: net.Tcp = .{
        .source = 40000,
        .destination = port,
        .sequence = 1001 + hello.len,
        .acknowledgement = delivered.sequence +% @as(u32, @intCast(delivered.payload_size)),
        .flags = .{ .ack = true, .fin = true },
        .window = 64240,
        .header_size = net.Tcp.min_size,
        .payload_size = 0,
    };
    _ = nat.fromGuest(guestSegment(&nat, remote, finishing, &.{}, &frame), &answer);

    const ended = system.read(carried, &heard, heard.len);
    try testing.expectEqual(@as(usize, 0), @as(usize, @intCast(ended)));

    // Nothing was refused and nothing went unread along the way.
    try testing.expectEqual(@as(u64, 0), nat.streams_refused);
    try testing.expectEqual(@as(u64, 0), nat.no_room);
    try testing.expectEqual(@as(u64, 0), nat.unknown);
}

test "a frame that is not a packet at all is counted rather than guessed at" {
    var nat = fixture();
    defer nat.deinit();

    var answer: [64]u8 = undefined;
    // Shorter than a frame header.
    try std.testing.expect(nat.fromGuest(&.{ 1, 2, 3 }, &answer) == null);

    // A kind this network does not carry.
    var frame: [64]u8 = undefined;
    const outer: net.Ethernet = .{ .destination = nat.gateway_mac, .source = nat.guest_mac, .kind = .ip6 };
    const at = outer.write(&frame) catch unreachable;
    try std.testing.expect(nat.fromGuest(frame[0..at], &answer) == null);

    try testing.expectEqual(@as(u64, 2), nat.unknown);
    try testing.expectEqual(@as(usize, 0), nat.inFlight());
}

/// A broker for a test: it says what it was told to say and remembers what it was asked.
const Policy = struct {
    answer: Answer = .allowed,
    asked_port: u16 = 0,
    asked_remote: net.Ip4 = @splat(0),
    times: u32 = 0,

    fn asks(ctx: *anyopaque, remote: net.Ip4, port: u16, datagram: bool) Answer {
        const self: *Policy = @ptrCast(@alignCast(ctx));
        _ = datagram;
        self.asked_remote = remote;
        self.asked_port = port;
        self.times += 1;
        return self.answer;
    }

    fn broker(self: *Policy) Broker {
        return .{ .ctx = self, .asks = Policy.asks };
    }
};

test "a connection nobody allowed is reset, and one that is allowed is opened" {
    var nat = fixture();
    defer nat.deinit();

    var policy: Policy = .{ .answer = .refused };
    nat.broker = policy.broker();

    var frame: [256]u8 = undefined;
    var answer: [256]u8 = undefined;
    const opening: net.Tcp = .{
        .source = 40000,
        .destination = 443,
        .sequence = 100,
        .acknowledgement = 0,
        .flags = .{ .syn = true },
        .window = 64240,
        .header_size = net.Tcp.min_size,
        .payload_size = 0,
    };

    const reply = nat.fromGuest(guestSegment(&nat, .{ 93, 184, 216, 34 }, opening, &.{}, &frame), &answer) orelse
        return error.TestUnexpectedResult;
    const said = try segmentOf(reply);

    // Told there is nothing there, which is what a guest can act on, and nothing was opened.
    try std.testing.expect(said.flags.reset);
    try testing.expectEqual(@as(u64, 1), nat.refused_by_policy);
    try testing.expectEqual(@as(u64, 0), nat.streams_opened);
    try testing.expectEqual(@as(u16, 443), policy.asked_port);
    try testing.expectEqualSlices(u8, &[4]u8{ 93, 184, 216, 34 }, &policy.asked_remote);
}

test "a decision that has not come yet holds the connection rather than refusing it" {
    var nat = fixture();
    defer nat.deinit();

    var policy: Policy = .{ .answer = .waiting };
    nat.broker = policy.broker();

    var frame: [256]u8 = undefined;
    var answer: [256]u8 = undefined;
    const opening: net.Tcp = .{
        .source = 40001,
        .destination = 443,
        .sequence = 100,
        .acknowledgement = 0,
        .flags = .{ .syn = true },
        .window = 64240,
        .header_size = net.Tcp.min_size,
        .payload_size = 0,
    };

    // Nothing goes back. A reset would tell the guest there is nothing there, which is a different
    // thing from an answer that has not arrived: the guest sends this again and gets the decision.
    try std.testing.expect(nat.fromGuest(guestSegment(&nat, .{ 93, 184, 216, 34 }, opening, &.{}, &frame), &answer) == null);
    try testing.expectEqual(@as(u64, 1), nat.waiting_on_policy);
    try testing.expectEqual(@as(u64, 0), nat.streams_refused);
    try testing.expectEqual(@as(u64, 0), nat.streams_opened);
}

test "a name nobody allowed is not looked up" {
    var nat = fixture();
    defer nat.deinit();

    var policy: Policy = .{ .answer = .refused };
    nat.broker = policy.broker();

    var frame: [512]u8 = undefined;
    const asking = guestDatagram(&nat, .{ .source = 50000, .destination = dns_port, .payload_size = 16 }, "not a real query", &frame);
    var answer: [512]u8 = undefined;
    try std.testing.expect(nat.fromGuest(asking, &answer) == null);

    try testing.expectEqual(@as(u64, 1), nat.refused_by_policy);
    try testing.expectEqual(@as(u64, 0), nat.sent);
    try testing.expectEqual(@as(u16, dns_port), policy.asked_port);
}

/// Build a frame carrying a datagram from the guest, as a guest sends one.
fn guestDatagram(nat: *const Nat, datagram: net.Udp, body: []const u8, into: []u8) []const u8 {
    var inner: [1600]u8 = undefined;
    const carried = datagram.write(nat.guest_ip, nat.gateway_ip, body, &inner) catch unreachable;

    const outer: net.Ethernet = .{ .destination = nat.gateway_mac, .source = nat.guest_mac, .kind = .ip4 };
    const at = outer.write(into) catch unreachable;
    const header: net.Ip4Header = .{
        .source = nat.guest_ip,
        .destination = nat.gateway_ip,
        .protocol = .udp,
        .header_size = net.Ip4Header.min_size,
        .payload_size = carried,
        .identification = 1,
        .time_to_live = 64,
    };
    const wrote = header.write(into[at..]) catch unreachable;
    @memcpy(into[at + wrote ..][0..carried], inner[0..carried]);
    return into[0 .. at + wrote + carried];
}
