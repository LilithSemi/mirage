//! A kernel interface a guest's frames really go out of.
//!
//! What a guest gets here that a translator cannot give it is an address of its own on a real
//! network, so whoever runs it reaches the guest at that address. A guest behind a translator opens
//! connections and takes none.
//!
//! Making an interface and putting it on a bridge needs a privilege this process should not hold, so
//! that part is somebody else's: an interface is made once, kept across reboots, and owned by the
//! user who runs the guests. This attaches to one by name, which needs nothing beyond being that
//! user. A descriptor somebody has already attached is taken as well, which is how a service
//! manager hands one over.
//!
//! One read is one whole frame and one write takes one, so nothing here holds a piece of a frame.
//! Reading and writing never wait, for the same reason a helper socket does not: this runs on the
//! thread the guest runs on, so waiting for a quiet network stops the guest.
//!
//! Linux only. A Mac has nothing like this without a kernel extension, so a guest there reaches the
//! network through `Nat`.

const std = @import("std");
const linux = std.os.linux;

const Tap = @This();

/// `TUNSETIFF`, which attaches this descriptor to an interface.
const attach: u32 = 0x4004_54ca;

/// `IFF_TAP`: whole ethernet frames, rather than the IP packets a tun carries.
const want_frames: u16 = 0x0002;
/// `IFF_NO_PI`: nothing of the driver's own in front of a frame. Without it every frame arrives
/// behind four bytes the far end never sent.
const want_no_header: u16 = 0x1000;

/// What `TUNSETIFF` reads, which is `struct ifreq`. The struct is in `std.os.linux` with its flags
/// field named for a network interface's flags, and this driver reads other meanings out of the same
/// two bytes, so the shape is written out here.
const Ask = extern struct {
    name: [16]u8,
    flags: u16,
    rest: [22]u8 = @splat(0),
};

pub const Error = error{
    /// Empty, or longer than the kernel holds a name.
    BadName,
    /// No `/dev/net/tun`, which is a kernel built without the driver.
    NoDriver,
    /// There is no interface of that name, or it belongs to somebody else. Making one needs a
    /// privilege this process does not hold, so what to attach to is an interface that was made
    /// already and whose owner is this user.
    NotAllowed,
    /// Something else is carrying that interface's frames.
    Taken,
    /// The interface went away under the guest.
    Closed,
    Unexpected,
};

handle: std.posix.fd_t,

/// Attach to the interface of this name.
pub fn open(name: []const u8) Error!Tap {
    if (name.len == 0 or name.len >= @typeInfo(@FieldType(Ask, "name")).array.len) return Error.BadName;

    const opened = linux.open("/dev/net/tun", .{ .ACCMODE = .RDWR, .NONBLOCK = true }, 0);
    switch (std.posix.errno(opened)) {
        .SUCCESS => {},
        .NOENT, .NXIO, .NODEV => return Error.NoDriver,
        .ACCES, .PERM => return Error.NotAllowed,
        else => return Error.Unexpected,
    }
    const handle: std.posix.fd_t = @intCast(opened);
    errdefer _ = linux.close(handle);

    var asking: Ask = .{ .name = @splat(0), .flags = want_frames | want_no_header };
    @memcpy(asking.name[0..name.len], name);
    switch (std.posix.errno(linux.ioctl(handle, attach, @intFromPtr(&asking)))) {
        .SUCCESS => {},
        // An interface somebody else owns and no interface at all both arrive as this: a process
        // that may not make one is refused before it is told which of the two happened.
        .PERM, .ACCES => return Error.NotAllowed,
        .BUSY => return Error.Taken,
        else => return Error.Unexpected,
    }
    return .{ .handle = handle };
}

/// Take a descriptor somebody else attached. Whoever starts the guest makes the interface, attaches
/// to it and hands this over, which leaves nothing privileged in this process at all.
pub fn adopt(handle: std.posix.fd_t) Error!Tap {
    const self: Tap = .{ .handle = handle };
    try self.dontWait();
    return self;
}

/// Ask the descriptor not to wait, so a read with no frame behind it answers rather than blocks. One
/// that was opened here asked for this already; one that was handed over may not have.
fn dontWait(self: Tap) Error!void {
    const flags = linux.fcntl(self.handle, std.posix.F.GETFL, @as(usize, 0));
    if (std.posix.errno(flags) != .SUCCESS) return Error.Unexpected;

    const asking: std.posix.O = .{ .NONBLOCK = true };
    const wanted = @as(usize, @as(u32, @bitCast(asking))) | @as(usize, @intCast(flags));
    if (std.posix.errno(linux.fcntl(self.handle, std.posix.F.SETFL, wanted)) != .SUCCESS) {
        return Error.Unexpected;
    }
}

pub fn close(self: *Tap) void {
    _ = linux.close(self.handle);
    self.* = undefined;
}

/// Read one frame. Returns how long it is, which is zero when none had arrived.
pub fn read(self: Tap, into: []u8) Error!usize {
    if (into.len == 0) return 0;
    const got = linux.read(self.handle, into.ptr, into.len);
    return switch (std.posix.errno(got)) {
        .SUCCESS => @intCast(got),
        .AGAIN, .INTR => 0,
        .NODEV, .BADF => Error.Closed,
        else => Error.Unexpected,
    };
}

/// Write one frame. Returns whether it went: a kernel with a full queue takes none of it, and half a
/// frame is not a frame.
pub fn write(self: Tap, frame: []const u8) Error!bool {
    if (frame.len == 0) return true;
    const put = linux.write(self.handle, frame.ptr, frame.len);
    return switch (std.posix.errno(put)) {
        .SUCCESS => put == frame.len,
        .AGAIN, .INTR => false,
        .NODEV, .BADF => Error.Closed,
        // A frame this kernel will not take, which a guest is allowed to send. Saying it did not go
        // leaves the caller to count it and carry on.
        .INVAL, .MSGSIZE => false,
        else => Error.Unexpected,
    };
}

/// A pair of descriptors that keep frame edges, for a test that wants both ends. Nothing outside a
/// test uses this: a real one is a kernel interface.
fn pair() ?[2]std.posix.fd_t {
    var made: [2]i32 = undefined;
    const rc = linux.socketpair(std.posix.AF.UNIX, std.posix.SOCK.DGRAM, 0, &made);
    if (std.posix.errno(rc) != .SUCCESS) return null;
    return made;
}

test "a frame goes one way at a time and nothing waits for one" {
    const made = pair() orelse return error.SkipZigTest;

    var one = try Tap.adopt(made[0]);
    var two = try Tap.adopt(made[1]);
    defer one.close();
    defer two.close();

    // Nothing sent yet. A read that waited here would stop the guest for as long as the network
    // stays quiet, which is most of the time.
    var frame: [1514]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), try two.read(&frame));

    const sent = [_]u8{
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x52, 0x54, 0x00, 0x12, 0x34, 0x56,
        0x08, 0x06, 0x00, 0x01,
    };
    try std.testing.expect(try one.write(&sent));
    try std.testing.expectEqual(sent.len, try two.read(&frame));
    try std.testing.expectEqualSlices(u8, &sent, frame[0..sent.len]);

    // And one frame at a time: two written come back as two, not as one of twice the length.
    try std.testing.expect(try one.write(&sent));
    try std.testing.expect(try one.write(&sent));
    try std.testing.expectEqual(sent.len, try two.read(&frame));
    try std.testing.expectEqual(sent.len, try two.read(&frame));
}

test "a name the kernel could not hold is refused before anything is opened" {
    try std.testing.expectError(Error.BadName, Tap.open(""));
    try std.testing.expectError(Error.BadName, Tap.open("a-name-far-too-long"));
}
