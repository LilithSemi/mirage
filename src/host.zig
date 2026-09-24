//! The end of a guest that belongs to whoever started it, and the devices it holds.
//!
//! Every hypervisor this runs on needs the same things around the guest: a serial port to read, a
//! channel to answer, a network to carry, a chip to relay, a balloon to drain, and a session to pump.
//! None of that is a property of the hypervisor, so none of it lives with one.

const std = @import("std");
const backend = @import("mirage-backend");
const core = @import("mirage-core");
const arm64 = @import("mirage-arm64");
const device = @import("mirage-device");
const image = @import("mirage-image");
const netmod = @import("mirage-net");
const sessionmod = @import("mirage-session");
const Options = @import("Options.zig");
const GuestMemory = @import("mirage-memory").GuestMemory;
const attest = @import("mirage-attest");
const Manifest = attest.Manifest;
const fsmod = @import("mirage-fs");

/// Where the guest's memory starts, and where it sees its serial port.
pub const ram_base = 0x4000_0000;
pub const uart_base = 0x0900_0000;

/// The address the guest is given on the channel. Anything from three up is a guest;
/// the numbers below are reserved.
pub const guest_cid = 3;

/// The address the guest answers to on the network. Locally administered, so it cannot
/// collide with a real card, and fixed so a launch is reproducible.
pub const guest_mac = [6]u8{ 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 };

/// The lock the CPUs of one guest share, and the two calls `mirage-core` holds it with.
///
/// A spin lock rather than one that sleeps, because it is held only long enough to serve one device
/// access. A CPU that waited in the kernel for a lock this short would spend longer being put to sleep
/// and woken than it would spend waiting.
pub const Shared = struct {
    held: std.atomic.Mutex = .unlocked,

    pub fn guard(self: *Shared) core.Launch.Guard {
        return .{ .ctx = self, .lock = Shared.take, .unlock = Shared.release };
    }

    fn take(ctx: *anyopaque) void {
        const self: *Shared = @ptrCast(@alignCast(ctx));
        while (!self.held.tryLock()) std.atomic.spinLoopHint();
    }

    fn release(ctx: *anyopaque) void {
        const self: *Shared = @ptrCast(@alignCast(ctx));
        self.held.unlock();
    }
};

/// One CPU of a guest that has more than one.
///
/// Every CPU but the first starts stopped, so its thread waits inside the hypervisor until the guest
/// asks for it. Whatever this returns is not reported: the first CPU is the one that says how the
/// machine stopped, and a CPU still waiting when that happens has nothing to add.
pub fn driveCpu(hv: backend.Backend, id: backend.Backend.VcpuId, options: core.Launch.Run) void {
    _ = core.Launch.run(hv, id, options) catch {};
}

/// The first name server this machine uses, for a guest given a network of this VMM's own.
///
/// Read rather than guessed, because a guest looking a name up through an address that answers nothing
/// looks exactly like a network that does not work. A machine that names none falls back to a public
/// one, which is a guess and is said to be one.
pub fn hostResolver(io: std.Io, gpa: std.mem.Allocator) netmod.Ip4 {
    const fallback: netmod.Ip4 = .{ 1, 1, 1, 1 };

    const text = std.Io.Dir.cwd().readFileAlloc(io, "/etc/resolv.conf", gpa, .limited(64 << 10)) catch return fallback;
    defer gpa.free(text);

    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (!std.mem.startsWith(u8, trimmed, "nameserver")) continue;

        const rest = std.mem.trim(u8, trimmed["nameserver".len..], " \t");
        var parts = std.mem.splitScalar(u8, rest, '.');
        var address: netmod.Ip4 = undefined;
        var count: usize = 0;
        while (parts.next()) |part| : (count += 1) {
            if (count >= address.len) return fallback;
            address[count] = std.fmt.parseInt(u8, part, 10) catch return fallback;
        }
        if (count == address.len) return address;
    }
    return fallback;
}

/// What a guest is given, collected as it is decided.
///
/// The arrays were exactly the size of the devices this file can attach, with nothing spare, so one
/// more device meant writing past the end of them. Asking for room that is not there is a mistake
/// here and not something a guest can cause, so it asserts.
pub const Attached = struct {
    /// More than this file has devices to put in them, so adding one needs no arithmetic.
    const room = 8;

    devices: [room]device.Device = undefined,
    services: [room]device.Service = undefined,
    device_count: usize = 0,
    service_count: usize = 0,

    pub fn add(self: *Attached, one: device.Device) void {
        std.debug.assert(self.device_count < self.devices.len);
        self.devices[self.device_count] = one;
        self.device_count += 1;
    }

    /// A device that has work to do between exits as well as a window to answer.
    pub fn addServed(self: *Attached, one: device.Device, work: device.Service) void {
        std.debug.assert(self.service_count < self.services.len);
        self.add(one);
        self.services[self.service_count] = work;
        self.service_count += 1;
    }

    pub fn bus(self: *Attached) device.Bus {
        return .{ .devices = self.devices[0..self.device_count] };
    }

    pub fn served(self: *const Attached) []const device.Service {
        return self.services[0..self.service_count];
    }
};

/// The end of the run that belongs to this process: a clock, and the channel if there is
/// one. An exit count cannot say how long a guest has been wedged for, so the deadline
/// lives here where there is a clock to read.
pub const Host = struct {
    io: std.Io,
    /// The balloon, and the memory whose pages it hands over.
    balloon: ?*device.virtio.Balloon = null,
    memory: ?*GuestMemory = null,
    /// The network device, the socket to the helper, and the frames in flight between them.
    card: ?*device.virtio.Net = null,
    socket: ?netmod.Socket = null,
    relay: *netmod.Relay = undefined,
    /// A network of this VMM's own, given instead of a helper when the caller asked for one.
    nat: ?*netmod.Nat = null,
    /// Set when the run is over and every CPU should leave its loop. A CPU that kept going would be one
    /// whose registers cannot be read, because it holds its own lock while it is inside the hypervisor.
    stopping: std.atomic.Value(bool) = .init(false),
    /// Set once the helper has gone, so the reason can say so and the pumping stops.
    helper_gone: bool = false,
    frames_in: u64 = 0,
    frames_out: u64 = 0,

    /// What the launch register must hold, and what the guest said it holds. The guest is the one
    /// thing here that cannot be trusted about this, which is why it is checked rather than believed.
    expected_chain: ?[attest.Chain.length]u8 = null,
    chain_agreed: ?bool = null,

    /// The security chip, the socket to whatever answers its commands, and the relay between them.
    chip: ?*device.Tpm = null,
    chip_socket: ?netmod.Socket = null,
    chip_relay: device.Tpm.Relay(netmod.Socket) = .{},
    /// How many bytes have been given back to this machine.
    released: u64 = 0,
    /// Ranges that could not be given back, and why. A fault recovered without a trace is a
    /// bug that hides itself.
    unmapped: u64 = 0,
    unadvised: u64 = 0,
    /// Runs shorter than one of this machine's pages, which cannot be given back at all.
    too_small: u64 = 0,
    ranges_seen: u64 = 0,
    /// From the clock that only goes forwards, so a system clock the administrator moves
    /// does not move the deadline.
    deadline: ?i96,
    vsock: ?*device.virtio.Vsock,
    /// The socket somebody else holds this guest by. A session owns the channel: the streams the
    /// guest opens go to whoever connected rather than to this process's output.
    session: ?*sessionmod.Server = null,
    out: *std.Io.Writer,
    open: ?device.virtio.Vsock.Handle = null,
    answered: bool = false,
    /// True once the deadline stopped the guest, so the reason can say which it was.
    timed_out: bool = false,
    /// Counts the turns, so the serial output can be pushed out now and then. A guest that
    /// is killed before it stops would otherwise lose whatever is still buffered, which is
    /// exactly the output someone debugging needs.
    turns: u32 = 0,

    pub fn launchHost(self: *Host) core.Launch.Host {
        return .{ .ctx = self, .step = Host.step };
    }

    /// Take the pages the guest gave up and hand them back to this machine. A page the guest
    /// gave up has no contents worth keeping, and the guest agreed to ask before using one
    /// again, so throwing it away is safe and is the whole point of a balloon.
    fn drainBalloon(self: *Host) void {
        const balloon = self.balloon orelse return;
        const memory = self.memory orelse return;
        if (!balloon.mayRelease()) return;

        var ranges: [32]device.virtio.Balloon.Range = undefined;
        while (true) {
            const count = balloon.take(&ranges);
            if (count == 0) return;

            for (ranges[0..count]) |range| {
                self.ranges_seen += 1;
                // A tier that does not map guest memory refuses this, and then there is
                // nothing here to give back.
                const whole = range.hostAligned(std.heap.pageSize()) orelse {
                    self.too_small += 1;
                    continue;
                };

                const pages = memory.slice(whole.start, whole.len) catch {
                    self.unmapped += 1;
                    continue;
                };
                std.posix.madvise(
                    @alignCast(pages.ptr),
                    pages.len,
                    std.posix.MADV.DONTNEED,
                ) catch {
                    self.unadvised += 1;
                    continue;
                };
                self.released += whole.len;
            }
        }
    }

    /// Move frames between the guest and the helper. Neither side waits: what has arrived is
    /// taken and what will go is written, and the rest is left for the next turn.
    /// Carry frames between the card and a network of this VMM's own, for a guest given no helper.
    ///
    /// The same two directions as `pump`, with a translator in place of a socket. One answer per turn
    /// out of the translator, because the card takes one frame at a time anyway.
    fn pumpNat(self: *Host, memory: *GuestMemory) void {
        const card = self.card orelse return;
        const nat = self.nat orelse return;

        var frame: [device.virtio.Net.max_frame]u8 = undefined;
        var answer: [device.virtio.Net.max_frame]u8 = undefined;

        while (card.receive(memory, &frame) catch null) |length| {
            self.frames_out += 1;
            if (nat.fromGuest(frame[0..length], &answer)) |reply| {
                const went = card.send(memory, reply) catch break;
                if (went) self.frames_in += 1;
            }
        }

        if (nat.poll(&answer)) |reply| {
            const went = card.send(memory, reply) catch return;
            if (went) self.frames_in += 1;
        }
    }

    fn pump(self: *Host, memory: *GuestMemory) void {
        const card = self.card orelse return;
        const socket = self.socket orelse return;
        if (self.helper_gone) return;
        const relay = self.relay;

        // From the helper to the guest.
        if (relay.room() > 0) {
            const got = socket.read(relay.reading()) catch {
                self.helper_gone = true;
                return;
            };
            relay.arrived(got);
        }
        while (relay.next()) |frame| {
            // A guest that has left no buffer keeps the frame waiting rather than losing it.
            const went = card.send(memory, frame) catch break;
            if (!went) break;
            relay.taken();
            self.frames_in += 1;
        }

        // From the guest to the helper.
        var frame: [device.virtio.Net.max_frame]u8 = undefined;
        while (card.receive(memory, &frame) catch null) |length| {
            if (!relay.send(frame[0..length])) break;
            self.frames_out += 1;
        }
        if (relay.writing().len > 0) {
            const put = socket.write(relay.writing()) catch {
                self.helper_gone = true;
                return;
            };
            relay.wrote(put);
        }
    }

    /// Carry one command to whatever answers it, and its answer back.
    ///
    /// The guest is stopped while it waits, so nothing is lost by taking this a piece at a time: it
    /// cannot ask anything else until this is answered.
    /// Look for the guest saying what it believes its launch was, and check it. The guest chose these
    /// bytes, so nothing is read past what arrived and a line that is not one of these is ignored.
    fn checkChain(self: *Host, said: []const u8) void {
        const expected = self.expected_chain orelse return;
        if (self.chain_agreed != null) return;

        const label = "chain ";
        const at = std.mem.indexOf(u8, said, label) orelse return;
        const hex = said[at + label.len ..];
        if (hex.len < attest.Chain.length * 2) return;

        var told: [attest.Chain.length]u8 = undefined;
        _ = std.fmt.hexToBytes(&told, hex[0 .. attest.Chain.length * 2]) catch return;
        self.chain_agreed = std.mem.eql(u8, &told, &expected);
    }

    fn carryChip(self: *Host) void {
        const chip = self.chip orelse return;
        if (self.chip_socket) |*socket| self.chip_relay.carry(chip, socket);
    }

    fn step(ctx: *anyopaque) bool {
        const self: *Host = @ptrCast(@alignCast(ctx));

        // The run is over. Every CPU leaves its loop here, which is what lets its registers be read.
        if (self.stopping.load(.acquire)) return false;

        // Often enough to follow a boot, rarely enough not to be a write syscall per exit.
        self.turns +%= 1;
        if (self.turns % 512 == 0) self.out.flush() catch {};

        if (self.deadline) |when| {
            if (std.Io.Clock.awake.now(self.io).nanoseconds > when) {
                self.timed_out = true;
                return false;
            }
        }

        self.drainBalloon();
        self.carryChip();
        if (self.memory) |memory| {
            self.pump(memory);
            self.pumpNat(memory);
        }

        const channel = self.vsock orelse return true;

        // A session owns the channel. The streams the guest opens go to whoever holds the session,
        // and this process reads none of them: they are not its to read.
        if (self.session) |held| {
            held.pump(channel);
            return !held.asked_stop;
        }

        if (self.open == null) self.open = channel.accept();
        const handle = self.open orelse return true;

        var buffer: [512]u8 = undefined;
        const got = channel.read(handle, &buffer);
        if (got == 0) return true;

        // The guest chose these bytes, so they go out as they are and are never read as
        // a format string.
        self.out.print("channel {d}: ", .{got}) catch {};
        self.out.writeAll(buffer[0..got]) catch {};
        self.checkChain(buffer[0..got]);

        if (!self.answered) {
            _ = channel.write(handle, "the host heard you\n");
            self.answered = true;
        }
        return true;
    }
};

/// Hand a filesystem message to whatever answers it. Written here because both runners need it and
/// neither of them is where an export belongs.
pub fn answerFs(ctx: *anyopaque, request: []const u8, into: []u8) usize {
    const offered: *fsmod.Export = @ptrCast(@alignCast(ctx));
    return offered.answer(request, into);
}

/// Offer the guest a directory while it runs, for a session that was asked to. Returns whether it
/// could be: a name or a path nothing can be offered under is the caller's mistake, not a fault.
pub fn offerShare(ctx: *anyopaque, name: []const u8, at: []const u8, writable: bool) bool {
    const offered: *fsmod.Export = @ptrCast(@alignCast(ctx));
    offered.offer(name, at, writable) catch return false;
    return true;
}

pub fn withdrawShare(ctx: *anyopaque, name: []const u8) void {
    const offered: *fsmod.Export = @ptrCast(@alignCast(ctx));
    offered.withdraw(name);
}
