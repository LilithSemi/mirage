//! The protocols a guest speaks when it has a network device but no network.
//!
//! An unprivileged process cannot hand a frame to a kernel interface, so a guest that is to
//! reach anything has to be answered here: the frames it sends are read, and the answers are
//! written back. That means speaking ethernet, address resolution and IP rather than
//! forwarding them.
//!
//! Everything in this module is pure reading and writing of bytes. Nothing here opens a
//! socket or looks at a clock, so it compiles for a target with no operating system and can
//! be tested without one.
//!
//! Every field parsed here came from the guest. A length that runs past the frame, a header
//! shorter than its own declared size, an address that is not the one being asked for: each
//! one is refused and none of them assert.

const std = @import("std");
const testing = @import("mirage-testing");
const builtin = @import("builtin");

/// The socket to the helper. Only this knows that an operating system exists, which is why a
/// target without one still builds everything else here. Which system it is does not appear in it.
pub const Socket = switch (builtin.os.tag) {
    .freestanding, .other => void,
    else => @import("mirage-net/Socket.zig"),
};

/// A network of this VMM's own, for a guest with no helper to give it one. Guarded like the socket,
/// because it opens sockets of its own and a target with no operating system has none.
pub const Nat = switch (builtin.os.tag) {
    .freestanding, .other => void,
    else => @import("mirage-net/Nat.zig"),
};

pub const Mac = [6]u8;
pub const Ip4 = [4]u8;

/// The address every machine on the link answers to.
pub const broadcast: Mac = @splat(0xff);
/// No address at all, which is what an address resolution request leaves in the field it is
/// asking about.
pub const unknown: Mac = @splat(0x00);

/// What sits in an ethernet frame, as the two bytes after the addresses say.
pub const EtherType = enum(u16) {
    ip4 = 0x0800,
    arp = 0x0806,
    ip6 = 0x86dd,
    _,
};

pub const Error = error{
    /// The frame is shorter than the header it claims to have.
    TooShort,
    /// A field says the payload is longer than the frame that carried it.
    Truncated,
    /// A header this code has no layout for.
    Unsupported,
    /// A length that contradicts itself, such as one below the header it counts.
    Malformed,
};

/// The one's complement sum every internet header is checked with, from RFC 1071.
///
/// The sum is taken over pairs of bytes. An odd length leaves one byte at the end, which is
/// padded rather than dropped, because dropping it would let a change to the last byte go
/// unnoticed.
pub fn checksum(parts: []const []const u8) u16 {
    var total: u32 = 0;
    var odd: ?u8 = null;

    for (parts) |part| {
        var at: usize = 0;

        // A part that begins mid pair finishes the pair the last part left open.
        if (odd) |first| {
            if (part.len == 0) continue;
            total += (@as(u32, first) << 8) | part[0];
            at = 1;
            odd = null;
        }

        while (at + 1 < part.len) : (at += 2) {
            total += (@as(u32, part[at]) << 8) | part[at + 1];
        }
        if (at < part.len) odd = part[at];
    }

    // The last byte of an odd length is the high half of its pair.
    if (odd) |last| total += @as(u32, last) << 8;

    while (total >> 16 != 0) total = (total & 0xffff) + (total >> 16);
    return ~@as(u16, @truncate(total));
}

pub const Ethernet = struct {
    pub const header_size = 14;

    destination: Mac,
    source: Mac,
    kind: EtherType,

    pub fn parse(frame: []const u8) Error!Ethernet {
        if (frame.len < header_size) return Error.TooShort;
        return .{
            .destination = frame[0..6].*,
            .source = frame[6..12].*,
            // The two bytes come from the guest, so one this code has no name for stays a
            // number rather than becoming an invalid enum.
            .kind = @enumFromInt(std.mem.readInt(u16, frame[12..14], .big)),
        };
    }

    /// What follows the header, which is the packet the frame carries.
    pub fn payload(frame: []const u8) Error![]const u8 {
        if (frame.len < header_size) return Error.TooShort;
        return frame[header_size..];
    }

    pub fn write(self: Ethernet, into: []u8) Error!usize {
        if (into.len < header_size) return Error.TooShort;
        @memcpy(into[0..6], &self.destination);
        @memcpy(into[6..12], &self.source);
        std.mem.writeInt(u16, into[12..14], @intFromEnum(self.kind), .big);
        return header_size;
    }
};

/// Address resolution, which is how a guest learns what to put in the destination field
/// before it can send anything at all.
pub const Arp = struct {
    pub const packet_size = 28;

    /// Ethernet, which is the only hardware this speaks.
    const hardware_ethernet = 1;

    pub const Operation = enum(u16) { request = 1, reply = 2, _ };

    operation: Operation,
    sender_mac: Mac,
    sender_ip: Ip4,
    target_mac: Mac,
    target_ip: Ip4,

    pub fn parse(packet: []const u8) Error!Arp {
        if (packet.len < packet_size) return Error.TooShort;

        // Only ethernet and only IP version four. Anything else is a packet this code would
        // read the wrong fields out of.
        if (std.mem.readInt(u16, packet[0..2], .big) != hardware_ethernet) return Error.Unsupported;
        if (std.mem.readInt(u16, packet[2..4], .big) != @intFromEnum(EtherType.ip4)) return Error.Unsupported;
        if (packet[4] != 6 or packet[5] != 4) return Error.Unsupported;

        return .{
            .operation = @enumFromInt(std.mem.readInt(u16, packet[6..8], .big)),
            .sender_mac = packet[8..14].*,
            .sender_ip = packet[14..18].*,
            .target_mac = packet[18..24].*,
            .target_ip = packet[24..28].*,
        };
    }

    pub fn write(self: Arp, into: []u8) Error!usize {
        if (into.len < packet_size) return Error.TooShort;
        std.mem.writeInt(u16, into[0..2], hardware_ethernet, .big);
        std.mem.writeInt(u16, into[2..4], @intFromEnum(EtherType.ip4), .big);
        into[4] = 6;
        into[5] = 4;
        std.mem.writeInt(u16, into[6..8], @intFromEnum(self.operation), .big);
        @memcpy(into[8..14], &self.sender_mac);
        @memcpy(into[14..18], &self.sender_ip);
        @memcpy(into[18..24], &self.target_mac);
        @memcpy(into[24..28], &self.target_ip);
        return packet_size;
    }
};

pub const Protocol = enum(u8) {
    icmp = 1,
    tcp = 6,
    udp = 17,
    _,
};

pub const Ip4Header = struct {
    /// Without options. A header that declares more than this is refused rather than read as
    /// though the extra were payload.
    pub const min_size = 20;

    source: Ip4,
    destination: Ip4,
    protocol: Protocol,
    /// How long the header really is, which a guest may make larger with options.
    header_size: usize,
    /// How long the payload is, taken from the total length rather than from the frame, and
    /// checked against it.
    payload_size: usize,
    identification: u16,
    time_to_live: u8,

    pub fn parse(packet: []const u8) Error!Ip4Header {
        if (packet.len < min_size) return Error.TooShort;

        // The high half of the first byte is the version and the low half is the header
        // length in four byte words.
        if (packet[0] >> 4 != 4) return Error.Unsupported;
        const size = @as(usize, packet[0] & 0xf) * 4;
        if (size < min_size or size > packet.len) return Error.TooShort;

        const total = std.mem.readInt(u16, packet[2..4], .big);
        if (total < size) return Error.TooShort;
        if (total > packet.len) return Error.Truncated;

        return .{
            .source = packet[12..16].*,
            .destination = packet[16..20].*,
            .protocol = @enumFromInt(packet[9]),
            .header_size = size,
            .payload_size = total - size,
            .identification = std.mem.readInt(u16, packet[4..6], .big),
            .time_to_live = packet[8],
        };
    }

    /// Write a header with no options in front of a payload of `payload_size`, and fill in
    /// its checksum. Returns how many bytes the header took.
    pub fn write(self: Ip4Header, into: []u8) Error!usize {
        if (into.len < min_size) return Error.TooShort;
        const total = min_size + self.payload_size;
        if (total > std.math.maxInt(u16)) return Error.Truncated;

        @memset(into[0..min_size], 0);
        into[0] = 0x45;
        std.mem.writeInt(u16, into[2..4], @intCast(total), .big);
        std.mem.writeInt(u16, into[4..6], self.identification, .big);
        // Do not fragment, which is honest for a link that carries a whole frame or none.
        std.mem.writeInt(u16, into[6..8], 0x4000, .big);
        into[8] = self.time_to_live;
        into[9] = @intFromEnum(self.protocol);
        @memcpy(into[12..16], &self.source);
        @memcpy(into[16..20], &self.destination);

        // The checksum covers the header alone, and is taken with its own field zero.
        const sum = checksum(&.{into[0..min_size]});
        std.mem.writeInt(u16, into[10..12], sum, .big);
        return min_size;
    }

    /// Whether the checksum in the header matches the header. A guest is allowed to send a
    /// broken one, and answering it would be answering something nobody sent.
    pub fn valid(packet: []const u8) bool {
        const header = Ip4Header.parse(packet) catch return false;
        // A correct header sums to zero with its own checksum field included.
        return checksum(&.{packet[0..header.header_size]}) == 0;
    }
};

test "the internet checksum matches the worked example in rfc 1071" {
    // The bytes and the answer are both from the document, so this checks the function
    // against the specification rather than against itself.
    const bytes = [_]u8{ 0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7 };
    try testing.expectEqual(@as(u16, 0x220d), checksum(&.{&bytes}));
}

test "a checksum taken in pieces is the same as one taken whole" {
    // A header and its payload are never next to each other in memory here, so the sum has
    // to be able to cross the gap, including when a piece ends mid pair.
    const whole = [_]u8{ 0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10, 0x0a, 0x63 };

    const one = checksum(&.{&whole});
    try testing.expectEqual(one, checksum(&.{ whole[0..8], whole[8..] }));
    try testing.expectEqual(one, checksum(&.{ whole[0..3], whole[3..9], whole[9..] }));
    try testing.expectEqual(one, checksum(&.{ whole[0..1], whole[1..2], whole[2..] }));
}

test "an odd length keeps its last byte in the sum" {
    // A sum that drops the odd byte cannot tell these apart, and a change to the last byte
    // of a packet would go unnoticed.
    const three = [_]u8{ 1, 2, 3 };
    const other = [_]u8{ 1, 2, 4 };
    try std.testing.expect(checksum(&.{&three}) != checksum(&.{&other}));

    // And it is the high half of its pair, which is what padding with a zero means.
    const padded = [_]u8{ 1, 2, 3, 0 };
    try testing.expectEqual(checksum(&.{&padded}), checksum(&.{&three}));
}

test "an ethernet header goes out and comes back the same" {
    const original: Ethernet = .{
        .destination = .{ 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 },
        .source = .{ 0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc },
        .kind = .ip4,
    };

    var frame: [64]u8 = @splat(0);
    try testing.expectEqual(@as(usize, 14), try original.write(&frame));

    const back = try Ethernet.parse(&frame);
    try testing.expectEqualSlices(u8, &original.destination, &back.destination);
    try testing.expectEqualSlices(u8, &original.source, &back.source);
    try testing.expectEqual(EtherType.ip4, back.kind);

    // The type is big endian on the wire. A frame that says 0x0800 the other way round is a
    // frame a real machine would not understand.
    try testing.expectEqual(@as(u8, 0x08), frame[12]);
    try testing.expectEqual(@as(u8, 0x00), frame[13]);
}

test "a frame shorter than its header is refused" {
    var frame: [13]u8 = @splat(0);
    try testing.expectError(Error.TooShort, Ethernet.parse(&frame));
    try testing.expectError(Error.TooShort, Ethernet.payload(&frame));
}

test "an ethernet type this code has no name for stays a number" {
    var frame: [14]u8 = @splat(0);
    std.mem.writeInt(u16, frame[12..14], 0x1234, .big);

    // A guest can put anything here. Turning it into an enum this code has no member for
    // would be undefined behaviour rather than an unknown protocol.
    const parsed = try Ethernet.parse(&frame);
    try testing.expectEqual(@as(u16, 0x1234), @intFromEnum(parsed.kind));
}

test "an address resolution request goes out and comes back the same" {
    const original: Arp = .{
        .operation = .request,
        .sender_mac = .{ 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 },
        .sender_ip = .{ 10, 0, 2, 15 },
        .target_mac = unknown,
        .target_ip = .{ 10, 0, 2, 2 },
    };

    var packet: [Arp.packet_size]u8 = @splat(0);
    try testing.expectEqual(Arp.packet_size, try original.write(&packet));

    const back = try Arp.parse(&packet);
    try testing.expectEqual(Arp.Operation.request, back.operation);
    try testing.expectEqualSlices(u8, &original.sender_mac, &back.sender_mac);
    try testing.expectEqualSlices(u8, &original.sender_ip, &back.sender_ip);
    try testing.expectEqualSlices(u8, &original.target_ip, &back.target_ip);

    // A request leaves the address it is asking about empty.
    try testing.expectEqualSlices(u8, &unknown, &back.target_mac);
}

test "an address resolution packet for hardware this code cannot speak is refused" {
    var packet: [Arp.packet_size]u8 = @splat(0);
    const good: Arp = .{
        .operation = .request,
        .sender_mac = @splat(1),
        .sender_ip = .{ 10, 0, 2, 15 },
        .target_mac = unknown,
        .target_ip = .{ 10, 0, 2, 2 },
    };
    _ = try good.write(&packet);
    _ = try Arp.parse(&packet);

    // Token ring, which this code would read the wrong fields out of.
    std.mem.writeInt(u16, packet[0..2], 6, .big);
    try testing.expectError(Error.Unsupported, Arp.parse(&packet));

    // Ethernet again, but addresses of a length this code does not hold.
    std.mem.writeInt(u16, packet[0..2], 1, .big);
    packet[4] = 8;
    try testing.expectError(Error.Unsupported, Arp.parse(&packet));
}

test "an ip header goes out with a checksum that checks" {
    const original: Ip4Header = .{
        .source = .{ 10, 0, 2, 2 },
        .destination = .{ 10, 0, 2, 15 },
        .protocol = .udp,
        .header_size = Ip4Header.min_size,
        .payload_size = 12,
        .identification = 0x1c46,
        .time_to_live = 64,
    };

    var packet: [Ip4Header.min_size + 12]u8 = @splat(0);
    try testing.expectEqual(Ip4Header.min_size, try original.write(&packet));

    // The header this code wrote is one this code agrees is correct, and a real machine
    // checks it the same way.
    try std.testing.expect(Ip4Header.valid(&packet));

    const back = try Ip4Header.parse(&packet);
    try testing.expectEqualSlices(u8, &original.source, &back.source);
    try testing.expectEqualSlices(u8, &original.destination, &back.destination);
    try testing.expectEqual(Protocol.udp, back.protocol);
    try testing.expectEqual(@as(usize, 12), back.payload_size);
    try testing.expectEqual(@as(u8, 64), back.time_to_live);
}

test "one byte changed anywhere in an ip header breaks its checksum" {
    const original: Ip4Header = .{
        .source = .{ 10, 0, 2, 2 },
        .destination = .{ 10, 0, 2, 15 },
        .protocol = .tcp,
        .header_size = Ip4Header.min_size,
        .payload_size = 0,
        .identification = 7,
        .time_to_live = 64,
    };

    var packet: [Ip4Header.min_size]u8 = @splat(0);
    _ = try original.write(&packet);

    // Every byte of the header, one at a time. A checksum that misses one is a checksum that
    // lets a change through.
    for (0..Ip4Header.min_size) |index| {
        // The checksum field itself is where the answer lives, so changing it must also be
        // caught.
        var damaged = packet;
        damaged[index] ^= 0xff;
        try std.testing.expect(!Ip4Header.valid(&damaged));
    }
}

test "an ip header that claims more than the frame holds is refused" {
    var packet: [Ip4Header.min_size + 4]u8 = @splat(0);
    packet[0] = 0x45;
    // The total length says far more than arrived. A device that trusts it reads past the
    // frame into whatever follows.
    std.mem.writeInt(u16, packet[2..4], 9000, .big);
    try testing.expectError(Error.Truncated, Ip4Header.parse(&packet));

    // A header longer than the packet that carried it.
    packet[0] = 0x4f;
    std.mem.writeInt(u16, packet[2..4], 60, .big);
    try testing.expectError(Error.TooShort, Ip4Header.parse(&packet));

    // A header shorter than one without options can be.
    packet[0] = 0x44;
    try testing.expectError(Error.TooShort, Ip4Header.parse(&packet));
}

test "a packet that is not version four is refused rather than read" {
    var packet: [Ip4Header.min_size]u8 = @splat(0);
    packet[0] = 0x65;
    try testing.expectError(Error.Unsupported, Ip4Header.parse(&packet));
    try std.testing.expect(!Ip4Header.valid(&packet));
}

test "a header with options is measured by what it declares" {
    // Five words of header plus two of options, and eight bytes of payload behind them.
    var packet: [28 + 8]u8 = @splat(0);
    packet[0] = 0x47;
    std.mem.writeInt(u16, packet[2..4], 28 + 8, .big);

    const header = try Ip4Header.parse(&packet);
    try testing.expectEqual(@as(usize, 28), header.header_size);
    try testing.expectEqual(@as(usize, 8), header.payload_size);
}

/// The framing a hypervisor and a network helper use over a stream socket: four bytes of
/// length, most significant first, then that many bytes of frame.
///
/// A stream carries no message boundaries, so one read holds whatever happened to arrive.
/// Measured against `passt 2026_07_16`: a single read returned 146 bytes holding a 60 byte
/// frame and more behind it. Nothing here assumes one read is one frame.
/// A datagram header. Four numbers and a checksum that covers parts of the header above it as well,
/// which is why writing one needs the addresses.
pub const Udp = struct {
    pub const size = 8;

    source: u16,
    destination: u16,
    /// How long the payload is, taken from the length field rather than from the frame, and checked
    /// against what really arrived.
    payload_size: usize,

    pub fn parse(packet: []const u8) Error!Udp {
        if (packet.len < size) return Error.TooShort;
        const declared = std.mem.readInt(u16, packet[4..6], .big);
        // The length counts this header too, so anything below it is a length nobody could mean.
        if (declared < size) return Error.Malformed;
        if (declared > packet.len) return Error.Truncated;
        return .{
            .source = std.mem.readInt(u16, packet[0..2], .big),
            .destination = std.mem.readInt(u16, packet[2..4], .big),
            .payload_size = declared - size,
        };
    }

    pub fn payload(packet: []const u8) Error![]const u8 {
        const header = try Udp.parse(packet);
        return packet[size..][0..header.payload_size];
    }

    /// Write the header and the payload after it. The checksum reaches up into the addresses of the
    /// packet carrying it, so those are needed here and not only above.
    pub fn write(self: Udp, from: Ip4, to: Ip4, body: []const u8, into: []u8) Error!usize {
        const total = size + body.len;
        if (into.len < total) return Error.TooShort;
        if (total > std.math.maxInt(u16)) return Error.Truncated;

        std.mem.writeInt(u16, into[0..2], self.source, .big);
        std.mem.writeInt(u16, into[2..4], self.destination, .big);
        std.mem.writeInt(u16, into[4..6], @intCast(total), .big);
        std.mem.writeInt(u16, into[6..8], 0, .big);
        @memcpy(into[size..total], body);

        // The sum covers a made up header of the two addresses, the protocol and the length, then this
        // header and the payload. Zero is not a valid answer here and means the same as no checksum, so
        // it is written as all ones instead.
        var pseudo: [12]u8 = undefined;
        @memcpy(pseudo[0..4], &from);
        @memcpy(pseudo[4..8], &to);
        pseudo[8] = 0;
        pseudo[9] = @intFromEnum(Protocol.udp);
        std.mem.writeInt(u16, pseudo[10..12], @intCast(total), .big);

        const sum = checksum(&.{ &pseudo, into[0..total] });
        std.mem.writeInt(u16, into[6..8], if (sum == 0) 0xffff else sum, .big);
        return total;
    }
};

/// A stream header. Longer than the others and with more in it, because a stream carries its own idea
/// of where it is: two counters, a window, and the flags that open and close it.
pub const Tcp = struct {
    pub const min_size = 20;

    /// What a segment is for. More than one may be set at once, and a segment with none is ordinary
    /// data or an acknowledgement.
    pub const Flags = packed struct(u8) {
        fin: bool = false,
        syn: bool = false,
        reset: bool = false,
        push: bool = false,
        ack: bool = false,
        urgent: bool = false,
        reduced: bool = false,
        congested: bool = false,
    };

    source: u16,
    destination: u16,
    sequence: u32,
    acknowledgement: u32,
    flags: Flags,
    window: u16,
    /// How long the header really is. A sender may put options after the fixed part, and the payload
    /// begins past them.
    header_size: usize,
    payload_size: usize,

    pub fn parse(packet: []const u8) Error!Tcp {
        if (packet.len < min_size) return Error.TooShort;

        // The high four bits of this byte say how many four byte words the header is. Below five is a
        // header shorter than the fixed part, which is a length nobody could mean.
        const words = packet[12] >> 4;
        if (words < 5) return Error.Malformed;
        const header_size = @as(usize, words) * 4;
        if (header_size > packet.len) return Error.Truncated;

        return .{
            .source = std.mem.readInt(u16, packet[0..2], .big),
            .destination = std.mem.readInt(u16, packet[2..4], .big),
            .sequence = std.mem.readInt(u32, packet[4..8], .big),
            .acknowledgement = std.mem.readInt(u32, packet[8..12], .big),
            .flags = @bitCast(packet[13]),
            .window = std.mem.readInt(u16, packet[14..16], .big),
            .header_size = header_size,
            .payload_size = packet.len - header_size,
        };
    }

    pub fn payload(packet: []const u8) Error![]const u8 {
        const header = try Tcp.parse(packet);
        return packet[header.header_size..];
    }

    /// Write the header and the payload after it. Like a datagram, the checksum reaches up into the
    /// addresses of the packet carrying it.
    pub fn write(self: Tcp, from: Ip4, to: Ip4, body: []const u8, into: []u8) Error!usize {
        const total = min_size + body.len;
        if (into.len < total) return Error.TooShort;
        if (total > std.math.maxInt(u16)) return Error.Truncated;

        @memset(into[0..min_size], 0);
        std.mem.writeInt(u16, into[0..2], self.source, .big);
        std.mem.writeInt(u16, into[2..4], self.destination, .big);
        std.mem.writeInt(u32, into[4..8], self.sequence, .big);
        std.mem.writeInt(u32, into[8..12], self.acknowledgement, .big);
        // Five words, because nothing here writes options.
        into[12] = 5 << 4;
        into[13] = @bitCast(self.flags);
        std.mem.writeInt(u16, into[14..16], self.window, .big);
        @memcpy(into[min_size..total], body);

        var pseudo: [12]u8 = undefined;
        @memcpy(pseudo[0..4], &from);
        @memcpy(pseudo[4..8], &to);
        pseudo[8] = 0;
        pseudo[9] = @intFromEnum(Protocol.tcp);
        std.mem.writeInt(u16, pseudo[10..12], @intCast(total), .big);

        std.mem.writeInt(u16, into[16..18], checksum(&.{ &pseudo, into[0..total] }), .big);
        return total;
    }
};

/// An echo request or its answer. Only these two of the many kinds are understood, because a guest
/// that pings is asking whether anything is there and the rest are reports about traffic.
pub const Icmp = struct {
    pub const size = 8;
    pub const echo_request = 8;
    pub const echo_reply = 0;

    kind: u8,
    identifier: u16,
    sequence: u16,
    payload_size: usize,

    pub fn parse(packet: []const u8) Error!Icmp {
        if (packet.len < size) return Error.TooShort;
        return .{
            .kind = packet[0],
            .identifier = std.mem.readInt(u16, packet[4..6], .big),
            .sequence = std.mem.readInt(u16, packet[6..8], .big),
            .payload_size = packet.len - size,
        };
    }

    pub fn write(self: Icmp, body: []const u8, into: []u8) Error!usize {
        const total = size + body.len;
        if (into.len < total) return Error.TooShort;

        into[0] = self.kind;
        into[1] = 0;
        std.mem.writeInt(u16, into[2..4], 0, .big);
        std.mem.writeInt(u16, into[4..6], self.identifier, .big);
        std.mem.writeInt(u16, into[6..8], self.sequence, .big);
        @memcpy(into[size..total], body);

        std.mem.writeInt(u16, into[2..4], checksum(&.{into[0..total]}), .big);
        return total;
    }
};

pub const Stream = struct {
    pub const prefix_size = 4;

    /// The most a length field may claim. A helper on the other end is not the guest, but it
    /// is another process, and a length of four thousand million would have this side wait
    /// for bytes that are never coming.
    pub const max_claim = 64 * 1024;

    pub const Frame = struct {
        bytes: []const u8,
        /// How much of the buffer this frame and its length took, which is what the caller
        /// drops before looking again.
        used: usize,
    };

    /// The frame at the front of `buffer`, or null when a whole one has not arrived yet. A
    /// caller that gets null reads more into the buffer and asks again.
    pub fn next(buffer: []const u8) Error!?Frame {
        if (buffer.len < prefix_size) return null;

        const claimed = std.mem.readInt(u32, buffer[0..4], .big);
        if (claimed > max_claim) return Error.Truncated;
        if (claimed == 0) return Error.TooShort;

        const total = prefix_size + @as(usize, claimed);
        if (buffer.len < total) return null;
        return .{ .bytes = buffer[prefix_size..total], .used = total };
    }

    /// Write a frame with its length in front. Returns how many bytes that took.
    pub fn write(frame: []const u8, into: []u8) Error!usize {
        const total = prefix_size + frame.len;
        if (into.len < total) return Error.TooShort;
        if (frame.len > max_claim) return Error.Truncated;

        std.mem.writeInt(u32, into[0..4], @intCast(frame.len), .big);
        @memcpy(into[prefix_size..total], frame);
        return total;
    }
};

test "a frame goes out framed and comes back the same" {
    const frame = "a short frame standing in for a real one";
    var wire: [64]u8 = undefined;
    const used = try Stream.write(frame, &wire);
    try testing.expectEqual(Stream.prefix_size + frame.len, used);

    // The length is four bytes, most significant first, which is what the other end reads.
    try testing.expectEqual(@as(u32, frame.len), std.mem.readInt(u32, wire[0..4], .big));

    const back = (try Stream.next(wire[0..used])) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, frame, back.bytes);
    try testing.expectEqual(used, back.used);
}

test "several frames in one read come out one at a time" {
    // A read returns whatever arrived, and `passt` was measured putting more than one frame
    // in a single read. A reader that takes one frame per read loses the rest.
    var wire: [128]u8 = undefined;
    var at: usize = 0;
    at += try Stream.write("first", wire[at..]);
    at += try Stream.write("second one", wire[at..]);
    at += try Stream.write("third", wire[at..]);

    var left = wire[0..at];
    const one = (try Stream.next(left)) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, "first", one.bytes);
    left = left[one.used..];

    const two = (try Stream.next(left)) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, "second one", two.bytes);
    left = left[two.used..];

    const three = (try Stream.next(left)) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, "third", three.bytes);
    left = left[three.used..];

    try testing.expectEqual(@as(usize, 0), left.len);
    try std.testing.expect((try Stream.next(left)) == null);
}

test "half a frame is not a frame until the rest arrives" {
    const frame = "this one arrives in pieces";
    var wire: [64]u8 = undefined;
    const used = try Stream.write(frame, &wire);

    // Every prefix of the bytes, none of which is a whole frame. A reader that takes one
    // hands half a packet to the guest.
    var have: usize = 0;
    while (have < used) : (have += 1) {
        try std.testing.expect((try Stream.next(wire[0..have])) == null);
    }

    const whole = (try Stream.next(wire[0..used])) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, frame, whole.bytes);
}

test "a length nothing could carry is refused rather than waited for" {
    var wire: [8]u8 = @splat(0);

    // Four thousand million bytes. A reader that believes it waits for bytes that are never
    // coming and never reads anything again.
    std.mem.writeInt(u32, wire[0..4], 0xffff_ffff, .big);
    try testing.expectError(Error.Truncated, Stream.next(&wire));

    // And a frame of nothing, which is not a frame.
    std.mem.writeInt(u32, wire[0..4], 0, .big);
    try testing.expectError(Error.TooShort, Stream.next(&wire));
}

/// Moves frames between a guest's network device and a helper on the other end of a stream.
///
/// This does no reading or writing of its own. A caller pushes in the bytes that arrived and
/// takes out the bytes to send, which is what lets it be tested without a socket and built
/// for a target that has none. It holds the part of a frame that has arrived and is not whole
/// yet, because a stream can split one anywhere.
pub const Relay = struct {
    /// Enough for a burst of frames in either direction. A helper hands over several at once,
    /// and a guest that has been waiting sends several at once.
    pub const buffer_size = 32 * 1024;

    /// Bytes from the helper that have not become whole frames yet.
    inbound: [buffer_size]u8 = undefined,
    inbound_len: usize = 0,
    /// Bytes for the helper that have not been written yet.
    outbound: [buffer_size]u8 = undefined,
    outbound_len: usize = 0,

    /// Frames dropped because there was no room for them. A caller seeing these rise is
    /// moving bytes more slowly than the two ends are producing them.
    dropped_in: u64 = 0,
    dropped_out: u64 = 0,
    /// Frames the helper sent that made no sense. The helper is another process, not the
    /// guest, but a length it could never mean is still refused rather than waited for.
    refused: u64 = 0,
    /// How much of the front of the buffer the frame just handed out took, itself and the
    /// length in front of it.
    held: usize = 0,

    /// How much room is left for bytes arriving from the helper. A caller reads no more than
    /// this, because bytes read and not held are bytes lost.
    pub fn room(self: *const Relay) usize {
        return self.inbound.len - self.inbound_len;
    }

    /// Where to read into. The caller reads into this and then says how much arrived.
    pub fn reading(self: *Relay) []u8 {
        return self.inbound[self.inbound_len..];
    }

    /// Say how many bytes arrived from the helper.
    pub fn arrived(self: *Relay, count: usize) void {
        std.debug.assert(count <= self.room());
        self.inbound_len += count;
    }

    /// The next whole frame from the helper, or null when there is not one yet. The frame
    /// points into this struct and stays valid until `taken`.
    pub fn next(self: *Relay) ?[]const u8 {
        const frame = Stream.next(self.inbound[0..self.inbound_len]) catch {
            // A length this side can make no sense of. Everything held is suspect once the
            // stream is out of step, because there is no telling where the next frame starts,
            // so it goes rather than being read as frames.
            self.refused += 1;
            self.inbound_len = 0;
            return null;
        } orelse return null;

        self.held = frame.used;
        return frame.bytes;
    }

    /// Say the frame from `next` has been dealt with, so the bytes behind it move up.
    pub fn taken(self: *Relay) void {
        const left = self.inbound_len - self.held;
        std.mem.copyForwards(u8, self.inbound[0..left], self.inbound[self.held..self.inbound_len]);
        self.inbound_len = left;
        self.held = 0;
    }

    /// Put a frame from the guest in the queue for the helper. Returns whether there was room;
    /// a caller told no keeps the frame and offers it again.
    pub fn send(self: *Relay, frame: []const u8) bool {
        const total = Stream.prefix_size + frame.len;
        if (self.outbound.len - self.outbound_len < total) {
            self.dropped_out += 1;
            return false;
        }
        const used = Stream.write(frame, self.outbound[self.outbound_len..]) catch {
            self.dropped_out += 1;
            return false;
        };
        self.outbound_len += used;
        return true;
    }

    /// The bytes waiting to go to the helper.
    pub fn writing(self: *const Relay) []const u8 {
        return self.outbound[0..self.outbound_len];
    }

    /// Say how many of those bytes went. A stream takes what it can, so this is often fewer
    /// than were offered and the rest stays for the next turn.
    pub fn wrote(self: *Relay, count: usize) void {
        std.debug.assert(count <= self.outbound_len);
        const left = self.outbound_len - count;
        std.mem.copyForwards(u8, self.outbound[0..left], self.outbound[count..self.outbound_len]);
        self.outbound_len = left;
    }
};

test "a frame pushed in as bytes comes out as a frame" {
    var relay: Relay = .{};

    var wire: [64]u8 = undefined;
    const used = try Stream.write("hello from the helper", &wire);
    @memcpy(relay.reading()[0..used], wire[0..used]);
    relay.arrived(used);

    const frame = relay.next() orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, "hello from the helper", frame);
    relay.taken();

    try std.testing.expect(relay.next() == null);
}

test "frames split across two reads are joined" {
    var relay: Relay = .{};

    var wire: [64]u8 = undefined;
    const used = try Stream.write("arriving in two pieces", &wire);

    // The first read stops in the middle, which a stream is allowed to do.
    const split = used / 2;
    @memcpy(relay.reading()[0..split], wire[0..split]);
    relay.arrived(split);
    try std.testing.expect(relay.next() == null);

    @memcpy(relay.reading()[0 .. used - split], wire[split..used]);
    relay.arrived(used - split);

    const frame = relay.next() orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, "arriving in two pieces", frame);
}

test "several frames in one read come out in order" {
    var relay: Relay = .{};

    var wire: [128]u8 = undefined;
    var at: usize = 0;
    at += try Stream.write("one", wire[at..]);
    at += try Stream.write("two", wire[at..]);
    at += try Stream.write("three", wire[at..]);

    @memcpy(relay.reading()[0..at], wire[0..at]);
    relay.arrived(at);

    for ([_][]const u8{ "one", "two", "three" }) |expected| {
        const frame = relay.next() orelse return error.TestUnexpectedResult;
        try testing.expectEqualSlices(u8, expected, frame);
        relay.taken();
    }
    try std.testing.expect(relay.next() == null);
}

test "a length the helper could not have meant throws away what is held" {
    var relay: Relay = .{};

    // Once the stream is out of step there is no telling where the next frame starts, so
    // reading on would hand the guest whatever the bytes happened to look like.
    var wire: [8]u8 = @splat(0);
    std.mem.writeInt(u32, wire[0..4], 0xffff_ffff, .big);
    @memcpy(relay.reading()[0..8], &wire);
    relay.arrived(8);

    try std.testing.expect(relay.next() == null);
    try testing.expectEqual(@as(u64, 1), relay.refused);
    try testing.expectEqual(@as(usize, 0), relay.inbound_len);
}

test "a frame from the guest comes out framed for the helper" {
    var relay: Relay = .{};
    try std.testing.expect(relay.send("a frame going the other way"));

    const bytes = relay.writing();
    const back = (try Stream.next(bytes)) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, "a frame going the other way", back.bytes);

    // A stream takes what it can. What is left stays for the next turn rather than being
    // written twice or lost.
    relay.wrote(4);
    try testing.expectEqual(bytes.len - 4, relay.writing().len);
    relay.wrote(relay.writing().len);
    try testing.expectEqual(@as(usize, 0), relay.writing().len);
}

test "a frame is refused when the queue for the helper is full" {
    var relay: Relay = .{};

    const frame = [_]u8{'x'} ** 1024;
    var count: usize = 0;
    while (relay.send(&frame)) count += 1;

    // It said no rather than writing past the end, and it said why.
    try std.testing.expect(count > 0);
    try testing.expectEqual(@as(u64, 1), relay.dropped_out);
    try std.testing.expect(relay.writing().len <= Relay.buffer_size);
}

test {
    if (Socket != void) _ = Socket;
    if (Nat != void) _ = Nat;
}
