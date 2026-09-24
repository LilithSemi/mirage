//! The first process inside a Mirage guest.
//!
//! It proves the guest reached userspace, then opens the channel back to whoever
//! started it, says something and reads the answer. Last it asks the kernel to power
//! the machine off. That request becomes a PSCI call, which leaves the guest as a
//! system event exit, so the VMM sees a clean stop rather than a guest that simply
//! went quiet.
//!
//! No libc and no allocator. The kernel hands the first process `/dev/console` as its
//! first three descriptors, so writing to descriptor one reaches the serial port.

const std = @import("std");
const linux = std.os.linux;
const attest = @import("mirage-attest");
const Chain = attest.Chain;
const Log = attest.Log;

/// `AF_VSOCK`. Not in the standard library's address family enumeration yet.
const af_vsock = 40;

/// `VMADDR_CID_HOST`. Whoever started this guest is always at this address.
const cid_host = 2;

/// The port the VMM listens on. Both sides have to agree, and this is where they do.
const host_port = 1024;

/// The port to open a stream to when this guest wants to be connected somewhere. It writes a name
/// and a port, and either bytes come back or the stream ends. It never resolves a name itself and
/// never holds an address, which is the whole point of reaching this way.
const reaching_port = 1025;

/// `struct sockaddr_vm`, sixteen bytes. The reserved and zero fields are part of the
/// layout and the kernel checks they are zero.
const SockaddrVm = extern struct {
    family: u16 = af_vsock,
    reserved: u16 = 0,
    port: u32,
    cid: u32,
    flags: u8 = 0,
    zero: [3]u8 = @splat(0),
};

fn say(message: []const u8) void {
    _ = linux.write(1, message.ptr, message.len);
}

/// Open the channel, send a line and read what comes back. Every step says what it
/// did, because a step that fails silently looks the same as one that never ran.
fn channel() void {
    const opened = linux.socket(af_vsock, linux.SOCK.STREAM, 0);
    if (std.posix.errno(opened) != .SUCCESS) {
        say("channel: no socket\n");
        return;
    }
    const fd: i32 = @intCast(opened);
    defer _ = linux.close(fd);

    const address: SockaddrVm = .{ .port = host_port, .cid = cid_host };
    const joined = linux.connect(fd, @ptrCast(&address), @sizeOf(SockaddrVm));
    if (std.posix.errno(joined) != .SUCCESS) {
        say("channel: refused\n");
        return;
    }
    say("channel: open\n");

    const greeting = "hello from the guest\n";
    const sent = linux.write(fd, greeting.ptr, greeting.len);
    if (std.posix.errno(sent) != .SUCCESS) {
        say("channel: write failed\n");
        return;
    }

    // Say what this guest believes its launch was. Whoever started it measured the same inputs in
    // the same order, so they can check this against their own arithmetic without trusting anything
    // said here.
    if (chain_known) {
        const label = "chain ";
        _ = linux.write(fd, label.ptr, label.len);
        _ = linux.write(fd, &chain_hex, chain_hex.len);
        _ = linux.write(fd, "\n", 1);
    }

    // This blocks. Nothing in the guest runs again until the VMM puts the answer on the
    // channel and raises the interrupt, and the VMM only gets to do that because it takes
    // the CPU back on a timer. A short read is normal, so reading again is how the rest
    // arrives.
    var buffer: [64]u8 = undefined;
    var have: usize = 0;
    while (have < buffer.len) {
        const got = linux.read(fd, buffer[have..].ptr, buffer.len - have);
        if (std.posix.errno(got) != .SUCCESS) break;
        if (got == 0) break;
        have += got;
        if (std.mem.indexOfScalar(u8, buffer[0..have], '\n') != null) break;
    }

    if (have == 0) {
        say("channel: nothing came back\n");
        return;
    }
    say("channel said: ");
    say(buffer[0..have]);

    // A guest in a session stays. Whoever holds the session says so on the channel, and this guest
    // then answers lines until it is told to stop, which is what a guest that serves calls does.
    if (std.mem.startsWith(u8, buffer[0..have], "stay")) serve(fd);
}

/// Answer lines until one says to stop. Every line goes back as it came, so whoever holds the other
/// end learns the whole way through is open and not only the half it wrote.
fn serve(fd: i32) void {
    say("channel: staying\n");
    // Said before anything else is read. Whoever holds the other end waits for this, so what it
    // writes next arrives on its own rather than in the tail of the line that asked for this.
    const ready = "staying\n";
    _ = linux.write(fd, ready.ptr, ready.len);
    var buffer: [128]u8 = undefined;
    while (true) {
        const got = linux.read(fd, &buffer, buffer.len);
        if (std.posix.errno(got) != .SUCCESS) return;
        if (got == 0) return;
        if (std.mem.startsWith(u8, buffer[0..got], "stop")) {
            say("channel: told to stop\n");
            return;
        }
        // Asked what is in the shared directory. Read when asked rather than at boot, so whoever
        // asked hears the answer on the stream instead of reading it out of a console that may not
        // have been written out yet.
        if (std.mem.startsWith(u8, buffer[0..got], "read ")) {
            var came: [256]u8 = undefined;
            const asked_for = std.mem.trimEnd(u8, buffer[5..got], "\n");
            const heard = readShare(if (std.mem.eql(u8, asked_for, "share")) "store" else asked_for, &came);
            _ = linux.write(fd, came[0..heard].ptr, heard);
            if (heard == 0) _ = linux.write(fd, "nothing", 7);
            _ = linux.write(fd, "\n", 1);
            continue;
        }
        // Asked to reach somewhere by name. What comes back goes onto this stream, so whoever asked
        // sees what the guest saw.
        if (std.mem.startsWith(u8, buffer[0..got], "reach ")) {
            var came: [128]u8 = undefined;
            const heard = reach(std.mem.trimEnd(u8, buffer[6..got], "\n"), &came);
            _ = linux.write(fd, came[0..heard].ptr, heard);
            _ = linux.write(fd, "\n", 1);
            continue;
        }
        var sent: usize = 0;
        while (sent < got) {
            const put = linux.write(fd, buffer[sent..].ptr, got - sent);
            if (std.posix.errno(put) != .SUCCESS) return;
            if (put == 0) return;
            sent += put;
        }
    }
}

/// Ask to be connected somewhere by name, and read what comes back.
///
/// The name and the port go out as one line. Whoever holds the session decides, connects, and from
/// then on this stream carries the bytes. A refusal arrives as the stream ending, and this guest
/// cannot tell a refusal from a far end that said nothing, which is correct: it is told no more
/// than that it did not work.
fn reach(name_and_port: []const u8, into: []u8) usize {
    const opened = linux.socket(af_vsock, linux.SOCK.STREAM, 0);
    if (std.posix.errno(opened) != .SUCCESS) {
        say("reach: no socket\n");
        return 0;
    }
    const fd: i32 = @intCast(opened);
    defer _ = linux.close(fd);

    const address: SockaddrVm = .{ .port = reaching_port, .cid = cid_host };
    if (std.posix.errno(linux.connect(fd, @ptrCast(&address), @sizeOf(SockaddrVm))) != .SUCCESS) {
        say("reach: refused\n");
        return 0;
    }

    _ = linux.write(fd, name_and_port.ptr, name_and_port.len);
    _ = linux.write(fd, "\n", 1);
    say("reach: asked for ");
    say(name_and_port);
    say("\n");

    var have: usize = 0;
    while (have < into.len) {
        const got = linux.read(fd, into[have..].ptr, into.len - have);
        if (std.posix.errno(got) != .SUCCESS) break;
        if (got == 0) break;
        have += got;
        if (std.mem.indexOfScalar(u8, into[0..have], '\n') != null) break;
    }
    if (have == 0) say("reach: nothing came back\n") else {
        say("reach said: ");
        say(into[0..have]);
    }
    return std.mem.trimEnd(u8, into[0..have], "\n").len;
}

/// Mount what the host offered and read something out of it.
///
/// The name comes from the device's configuration space, so the guest mounts by the name whoever
/// started it chose. Everything read here came from the host's own filesystem: nothing in this guest
/// ever held those bytes, which is the whole point of a share rather than an image.
fn share() void {
    _ = linux.mkdir("/share", 0o755);
    // One filesystem, holding a name for each directory the host offered. What the host calls them is
    // what they are called in here, and this guest puts them nowhere else: a real one would bind them
    // where its tools expect them.
    if (std.posix.errno(linux.mount("mirage", "/share", "virtiofs", 0, 0)) != .SUCCESS) {
        say("share: would not mount\n");
        return;
    }
    say("share: mounted\n");

    // Every name in it first, which is the part that has to scale: a store holds tens of thousands of
    // them in one directory and the kernel takes them a few at a time.
    countNames();

    const opened = linux.open("/share/store/hello", .{}, 0);
    if (std.posix.errno(opened) != .SUCCESS) {
        say("share: nothing to read\n");
        return;
    }
    const fd: i32 = @intCast(opened);
    defer _ = linux.close(fd);

    var room: [128]u8 = undefined;
    const got = linux.read(fd, &room, room.len);
    if (std.posix.errno(got) != .SUCCESS or got == 0) {
        say("share: read nothing\n");
        return;
    }
    say("share said: ");
    say(room[0..got]);

    // A share the host said may be written to, which is where the work of a real guest would go.
    writeShare();

    // And nothing a guest does through it changes anything on the other side. The refusal comes from
    // the host rather than from the mount options, which is what makes it worth saying.
    const writing = linux.open("/share/store/hello", .{ .ACCMODE = .WRONLY }, 0);
    if (std.posix.errno(writing) == .SUCCESS) {
        say("share: it let me open for writing\n");
        _ = linux.close(@intCast(writing));
    } else {
        say("share: writing refused\n");
    }
}

/// Write into the share that allows it, and read back what was written.
///
/// A guest that only reads needs none of this. One that does the work does: it edits files, and the
/// host has to see the edits, because that is the whole point of giving a guest a place to work.
fn writeShare() void {
    const made = linux.open("/share/work/made-inside", .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    if (std.posix.errno(made) != .SUCCESS) {
        say("share: nowhere to write\n");
        return;
    }
    const fd: i32 = @intCast(made);
    const said = "written by the guest\n";
    const put = linux.write(fd, said.ptr, said.len);
    _ = linux.close(fd);
    if (std.posix.errno(put) != .SUCCESS or put != said.len) {
        say("share: the write failed\n");
        return;
    }
    say("share: wrote a file\n");

    // And a directory, because a toolchain makes those before it makes anything else.
    if (std.posix.errno(linux.mkdir("/share/work/made-dir", 0o755)) != .SUCCESS) {
        say("share: no directory\n");
        return;
    }
    say("share: made a directory\n");

    // The three a real toolchain needs that a guest reading files does not: a second name for a file,
    // a time it chose, and room to work in. A filesystem missing any of them makes a build that is
    // wrong rather than one that fails.
    if (std.posix.errno(linux.linkat(linux.AT.FDCWD, "/share/work/made-inside", linux.AT.FDCWD, "/share/work/linked", 0)) == .SUCCESS) {
        say("share: linked a file\n");
    } else {
        say("share: no second name\n");
    }

    const times = [2]linux.timespec{
        .{ .sec = 1_000_000_000, .nsec = 0 },
        .{ .sec = 1_000_000_000, .nsec = 0 },
    };
    if (std.posix.errno(linux.utimensat(linux.AT.FDCWD, "/share/work/made-inside", &times, 0)) == .SUCCESS) {
        say("share: set a time\n");
    } else {
        say("share: the time would not take\n");
    }

    // How much room there is, asked for with the system call rather than through a wrapper: nothing in
    // the standard library names this structure, and only the first few numbers are read here.
    var about: [120]u8 align(8) = @splat(0);
    const asked = linux.syscall2(.statfs, @intFromPtr("/share/work"), @intFromPtr(&about));
    const blocks = std.mem.readInt(u64, about[16..24], .little);
    if (std.posix.errno(asked) == .SUCCESS and blocks > 0) {
        say("share: there is room\n");
    } else {
        say("share: no room reported\n");
    }
}

/// Read `hello` out of one of the shared directories, named by whoever asked over the channel.
///
/// Opened when asked rather than held open, because the point of asking is to find out whether the
/// directory is there now: one offered for a piece of work is gone when that work is over.
fn readShare(name: []const u8, into: []u8) usize {
    var room: [256]u8 = undefined;
    const path = std.fmt.bufPrintZ(&room, "/share/{s}/hello", .{name}) catch return 0;
    const opened = linux.open(path.ptr, .{}, 0);
    if (std.posix.errno(opened) != .SUCCESS) return 0;
    const fd: i32 = @intCast(opened);
    defer _ = linux.close(fd);

    const got = linux.read(fd, into.ptr, into.len);
    if (std.posix.errno(got) != .SUCCESS) return 0;
    return std.mem.trimEnd(u8, into[0..got], "\n").len;
}

/// Walk the shared directory and say how many names are in it.
fn countNames() void {
    const opened = linux.open("/share/store", .{ .DIRECTORY = true }, 0);
    if (std.posix.errno(opened) != .SUCCESS) {
        say("share: cannot open the directory\n");
        return;
    }
    const fd: i32 = @intCast(opened);
    defer _ = linux.close(fd);

    var room: [8192]u8 align(8) = undefined;
    var names: usize = 0;
    while (true) {
        const got = linux.getdents64(fd, &room, room.len);
        if (std.posix.errno(got) != .SUCCESS) {
            say("share: the walk failed\n");
            return;
        }
        if (got == 0) break;

        var at: usize = 0;
        while (at + @sizeOf(linux.dirent64) <= got) {
            const one: *align(1) const linux.dirent64 = @ptrCast(&room[at]);
            if (one.reclen == 0) break;
            names += 1;
            at += one.reclen;
        }
    }

    var said: [64]u8 = undefined;
    say("share: ");
    say(std.fmt.bufPrint(&said, "{d}", .{names}) catch "many");
    say(" names\n");
}

/// `SIOCSIF*`, which is how an interface is given an address without a shell.
const siocsifaddr = 0x8916;
const siocsifnetmask = 0x891c;
const siocsifflags = 0x8914;
const iff_up = 0x1;
const iff_running = 0x40;

/// `struct ifreq`. The name, then a union wide enough for an address.
const IfReq = extern struct {
    name: [16]u8,
    data: extern union {
        address: linux.sockaddr.in,
        flags: i16,
        padding: [24]u8,
    },
};

fn inetAddress(a: u8, b: u8, c: u8, d: u8) linux.sockaddr.in {
    return .{
        .family = linux.AF.INET,
        .port = 0,
        .addr = std.mem.readInt(u32, &[4]u8{ a, b, c, d }, .little),
        .zero = @splat(0),
    };
}

/// Give the interface an address and bring it up. Without this it has a driver and no way to
/// be used, and nothing leaves the guest.
fn configure(fd: i32) bool {
    var request: IfReq = .{ .name = @splat(0), .data = .{ .padding = @splat(0) } };
    @memcpy(request.name[0..4], "eth0");

    request.data.address = inetAddress(10, 0, 2, 15);
    if (std.posix.errno(linux.ioctl(fd, siocsifaddr, @intFromPtr(&request))) != .SUCCESS) {
        say("network: no address\n");
        return false;
    }

    request.data.address = inetAddress(255, 255, 255, 0);
    if (std.posix.errno(linux.ioctl(fd, siocsifnetmask, @intFromPtr(&request))) != .SUCCESS) {
        say("network: no netmask\n");
        return false;
    }

    request.data = .{ .padding = @splat(0) };
    request.data.flags = iff_up | iff_running;
    if (std.posix.errno(linux.ioctl(fd, siocsifflags, @intFromPtr(&request))) != .SUCCESS) {
        say("network: will not come up\n");
        return false;
    }
    return true;
}

/// Ask the helper's resolver for a name, which is the shortest thing that proves a packet left
/// the guest, was translated, and was answered.
fn network() void {
    const fd = linux.socket(linux.AF.INET, linux.SOCK.DGRAM, 0);
    if (std.posix.errno(fd) != .SUCCESS) {
        say("network: no socket\n");
        return;
    }
    const sock: i32 = @intCast(fd);
    defer _ = linux.close(sock);

    if (!configure(sock)) return;
    say("network: eth0 is up\n");

    // A query for one A record. Written out rather than built, because a name server cares
    // about the bytes and not about how they were made.
    const query = [_]u8{
        0x12, 0x34, // what the answer will carry back
        0x01, 0x00, // a standard question, recursion wanted
        0x00, 0x01, // one question
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        7,    'e',
        'x',  'a',
        'm',  'p',
        'l',  'e',
        3,    'c',
        'o',  'm',
        0,
        0x00, 0x01, // an address record
        0x00, 0x01, // on the internet
    };

    var server = inetAddress(10, 0, 2, 2);
    server.port = std.mem.nativeToBig(u16, 53);
    const sent = linux.sendto(sock, &query, query.len, 0, @ptrCast(&server), @sizeOf(linux.sockaddr.in));
    if (std.posix.errno(sent) != .SUCCESS) {
        say("network: the query would not go\n");
        return;
    }
    say("network: asked about example.com\n");

    // The answer comes back when the helper has been round the world for it, so this waits a
    // little rather than reading once.
    var answer: [512]u8 = undefined;
    var tries: usize = 0;
    while (tries < 60) : (tries += 1) {
        const got = linux.recvfrom(sock, &answer, answer.len, 0x40, null, null);
        if (std.posix.errno(got) == .SUCCESS and got >= 12) {
            // The count of answers is in the fourth pair of bytes.
            const answers = std.mem.readInt(u16, answer[6..8], .big);
            if (answers > 0) {
                say("network: the name was answered\n");
                return;
            }
            say("network: answered with nothing\n");
            return;
        }
        var pause: linux.timespec = .{ .sec = 0, .nsec = 20 * std.time.ns_per_ms };
        while (linux.nanosleep(&pause, &pause) == @as(usize, @bitCast(@as(isize, -4)))) {}
    }
    say("network: no answer came back\n");
}

/// The character device the chip driver offers. Its numbers are fixed, so the node is made here
/// rather than waiting for something to populate `/dev`.
const tpm_major = 10;
const tpm_minor = 224;

/// Where this side looks for the launch, and where it puts its own. The launch register is written
/// before the guest runs and is never touched from in here, because a register the guest can add to
/// is a register that says nothing about what started it.
const launch_register = 0;
const our_register = 16;

/// What the guest believes its launch was, as hex, once it has read it. Whoever started this guest
/// measured the same inputs, so it can check this against its own arithmetic.
var chain_hex: [Chain.length * 2]u8 = undefined;
var chain_known = false;

fn hex(into: []u8, bytes: []const u8) []const u8 {
    const digits = "0123456789abcdef";
    for (bytes, 0..) |byte, i| {
        into[i * 2] = digits[byte >> 4];
        into[i * 2 + 1] = digits[byte & 0xf];
    }
    return into[0 .. bytes.len * 2];
}

/// The chip, reached through its character device. A read waits for the answer to the command that
/// was written, which is what the device promises, so nothing here has to spin.
const Chip = struct {
    fd: i32,

    pub fn write(self: *Chip, bytes: []const u8) !usize {
        const put = linux.write(self.fd, bytes.ptr, bytes.len);
        if (std.posix.errno(put) != .SUCCESS) return error.Unwritable;
        return put;
    }

    pub fn read(self: *Chip, into: []u8) !usize {
        const got = linux.read(self.fd, into.ptr, into.len);
        if (std.posix.errno(got) != .SUCCESS) return error.Unreadable;
        return got;
    }
};

/// Read the launch register, then fold something into a register of this guest's own and read that
/// back. The first is the chain: whoever started this guest can check it. The second proves the chip
/// keeps state between two commands, because a chip that only echoed would answer both reads alike.
fn chip() void {
    _ = linux.mkdir("/dev", 0o755);
    if (std.posix.errno(linux.mknod("/dev/tpm0", linux.S.IFCHR | 0o600, (tpm_major << 8) | tpm_minor)) != .SUCCESS) {
        say("chip: no node\n");
        return;
    }

    const opened = linux.open("/dev/tpm0", .{ .ACCMODE = .RDWR }, 0);
    if (std.posix.errno(opened) != .SUCCESS) {
        say("chip: no device\n");
        return;
    }
    var device: Chip = .{ .fd = @intCast(opened) };
    defer _ = linux.close(device.fd);

    var session: Chain.Session(Chip) = .{ .transport = &device };

    const chain = session.read(launch_register) catch {
        say("chip: the launch register would not be read\n");
        return;
    };
    @memcpy(&chain_hex, hex(&chain_hex, &chain));
    chain_known = true;
    say("chain: ");
    say(&chain_hex);
    say("\n");

    const before = session.read(our_register) catch {
        say("chip: no answer\n");
        return;
    };
    var command: [Chain.extend_size]u8 = undefined;
    var answer: [512]u8 = undefined;
    _ = session.ask(Chain.extendCommand(&command, our_register, @splat(0xab)), &answer) catch {
        say("chip: refused to extend\n");
        return;
    };
    const after = session.read(our_register) catch {
        say("chip: no answer after extending\n");
        return;
    };

    // The chip follows the same rule this side can work out, so the new value is not merely
    // different but the one it has to be.
    if (!std.mem.eql(u8, &after, &Chain.extend(before, @splat(0xab)))) {
        say("chip: the register is not what extending it should give\n");
        return;
    }
    say("chip: extending a register gives what the rule says\n");

    account(chain);
}

/// Read the list of measurements the kernel took from the tree, fold it, and check the answer against
/// the register.
///
/// This is the guest building its own account of what started it. The register alone says two launches
/// differ and never what either was: the list says what went in, and a list that folds to the register
/// is a list nothing has changed. A guest that has both can say what it is running, and say it in a
/// form somebody else can check.
fn account(chain: [Chain.length]u8) void {
    // The kernel offers the list through a filesystem of its own, which nothing has mounted yet
    // because this is the first process.
    _ = linux.mkdir("/sys", 0o755);
    if (std.posix.errno(linux.mount("none", "/sys", "sysfs", 0, 0)) != .SUCCESS) {
        say("account: no sysfs\n");
        return;
    }
    if (std.posix.errno(linux.mount("none", "/sys/kernel/security", "securityfs", 0, 0)) != .SUCCESS) {
        say("account: no securityfs\n");
        return;
    }

    const opened = linux.open("/sys/kernel/security/tpm0/binary_bios_measurements", .{}, 0);
    if (std.posix.errno(opened) != .SUCCESS) {
        say("account: no list\n");
        return;
    }
    const fd: i32 = @intCast(opened);
    defer _ = linux.close(fd);

    var bytes: [8192]u8 = undefined;
    var held: usize = 0;
    while (held < bytes.len) {
        const got = linux.read(fd, bytes[held..].ptr, bytes.len - held);
        if (std.posix.errno(got) != .SUCCESS) {
            say("account: the list would not be read\n");
            return;
        }
        if (got == 0) break;
        held += got;
    }
    if (held == 0) {
        say("account: the list is empty\n");
        return;
    }

    // Name each measurement, in the order it was taken. This is the account, and it is worth nothing
    // on its own: the fold below is what ties it to the chip.
    var reader: Log.Reader = .init(bytes[0..held]);
    var counted: usize = 0;
    while (reader.next()) |entry| {
        counted += 1;
        say("  measured ");
        say(entry.name);
        say("\n");
    }
    if (reader.ragged) {
        say("account: the list ended in the middle of an entry\n");
        return;
    }

    if (!std.mem.eql(u8, &Log.fold(bytes[0..held], launch_register), &chain)) {
        say("account: the list does not fold to the register\n");
        return;
    }
    say("account: the list folds to the register, over ");
    var digits: [8]u8 = undefined;
    say(count(&digits, counted));
    say(" measurements\n");
}

/// A number as decimal, without an allocator or a formatter.
fn count(into: []u8, value: usize) []const u8 {
    if (value == 0) return "0";
    var at = into.len;
    var left = value;
    while (left > 0) {
        at -= 1;
        into[at] = '0' + @as(u8, @intCast(left % 10));
        left /= 10;
    }
    return into[at..];
}

/// The port this guest tries to reach on the gateway. Whoever started the guest listens there, on its
/// own machine, because traffic to the gateway reaches that machine itself.
const stream_port = 18080;

/// Open a connection to the gateway, say something, and read the answer.
///
/// A name that resolves proves datagrams work. A connection proves the rest, which is what everything a
/// coding session does rests on: nothing clones a repository over datagrams.
fn stream() void {
    const opened = linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0);
    if (std.posix.errno(opened) != .SUCCESS) {
        say("stream: no socket\n");
        return;
    }
    const fd: i32 = @intCast(opened);
    defer _ = linux.close(fd);

    var address = inetAddress(10, 0, 2, 2);
    address.port = std.mem.nativeToBig(u16, stream_port);
    const joined = linux.connect(fd, @ptrCast(&address), @sizeOf(linux.sockaddr.in));
    if (std.posix.errno(joined) != .SUCCESS) {
        say("stream: would not connect\n");
        return;
    }
    say("stream: connected\n");

    const greeting = "hello from the guest over a stream\n";
    const sent = linux.write(fd, greeting.ptr, greeting.len);
    if (std.posix.errno(sent) != .SUCCESS) {
        say("stream: nothing would send\n");
        return;
    }

    // This waits. The other end answers as soon as it reads, and the VMM takes the CPU back on a timer,
    // so the answer arrives while the guest is sitting here.
    var buffer: [128]u8 = undefined;
    var have: usize = 0;
    while (have < buffer.len) {
        const got = linux.read(fd, buffer[have..].ptr, buffer.len - have);
        if (std.posix.errno(got) != .SUCCESS) break;
        if (got == 0) break;
        have += got;
        if (std.mem.indexOfScalar(u8, buffer[0..have], '\n') != null) break;
    }

    if (have == 0) {
        say("stream: nothing came back\n");
        return;
    }
    say("stream said: ");
    say(buffer[0..have]);
}

pub fn main() void {
    say("mirage guest is alive\n");
    chip();
    share();
    channel();
    network();
    stream();

    // Give the devices that work in the background time to do so. The balloon driver hands
    // pages over on a worker, and a guest that powers off the instant it starts proves
    // nothing about a device that had no chance to run.
    var pause: linux.timespec = .{ .sec = 0, .nsec = 300 * std.time.ns_per_ms };
    while (linux.nanosleep(&pause, &pause) == @as(usize, @bitCast(@as(isize, -4)))) {}

    _ = linux.reboot(
        .MAGIC1,
        .MAGIC2,
        .POWER_OFF,
        null,
    );

    // The kernel does not return from a power off it accepted.
    while (true) {}
}
