//! The first process inside a Mirage guest.
//!
//! It proves the guest reached userspace, then opens the channel back to whoever
//! started it, says something and reads the answer. Last it asks the kernel to stop.
//! That becomes a power off: a PSCI system_off call on aarch64, an ACPI `_S5` write
//! on x86_64. Either way the VMM sees a clean exit.
//!
//! No libc and no allocator. The guest opens the console itself and keeps the file
//! descriptor so its output is not lost. If opening fails it falls back to descriptor one.

const std = @import("std");
const builtin = @import("builtin");
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

/// Where the guest's lines go. The kernel hands the first process `/dev/console` as its first
/// descriptors, but only where it brought that console up as a tty the process may write. A guest
/// opens the console itself and keeps the descriptor, so a line is seen wherever the console lives
/// rather than lost when the kernel left the standard descriptors closed.
var console_fd: i32 = 1;

fn openConsole() void {
    const opened = linux.open("/dev/console", .{ .ACCMODE = .WRONLY }, 0);
    if (std.posix.errno(opened) == .SUCCESS) console_fd = @intCast(opened);
}

fn say(message: []const u8) void {
    _ = linux.write(console_fd, message.ptr, message.len);
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

    commitLikeABuild();
    walkLikeAFetch();
    hammerFromManyTasks();
    makeTheKernelForget();

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

/// Commit work the way a build system does: write into a temporary directory, then move the whole
/// directory into place and keep using what is in it.
///
/// This is the pattern that broke. The kernel keeps the numbers it holds for a file across a move,
/// because it is the same file, so a filesystem that answers about the old name afterwards tells a
/// build that the work it has just committed is not there.
fn commitLikeABuild() void {
    _ = linux.mkdir("/share/work/tmp-build", 0o755);
    const made = linux.open("/share/work/tmp-build/result", .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    if (std.posix.errno(made) != .SUCCESS) {
        say("commit: nowhere to build\n");
        return;
    }
    const fd: i32 = @intCast(made);
    const said = "the result of the build\n";
    _ = linux.write(fd, said.ptr, said.len);
    _ = linux.close(fd);

    // A directory the guest holds open across the move, which is what a build does: it keeps the
    // handle it was writing through.
    const holding = linux.open("/share/work/tmp-build", .{ .DIRECTORY = true }, 0);
    const held: i32 = if (std.posix.errno(holding) == .SUCCESS) @intCast(holding) else -1;
    defer if (held >= 0) {
        _ = linux.close(held);
    };

    if (std.posix.errno(linux.rename("/share/work/tmp-build", "/share/work/committed")) != .SUCCESS) {
        say("commit: the move failed\n");
        return;
    }
    say("commit: moved into place\n");

    // What broke: reading the work straight after committing it.
    const reading = linux.open("/share/work/committed/result", .{}, 0);
    if (std.posix.errno(reading) != .SUCCESS) {
        say("commit: the result is not there\n");
        return;
    }
    const again: i32 = @intCast(reading);
    defer _ = linux.close(again);
    var room: [64]u8 = undefined;
    const got = linux.read(again, &room, room.len);
    if (std.posix.errno(got) != .SUCCESS or got == 0) {
        say("commit: the result would not read\n");
        return;
    }
    say("commit said: ");
    say(room[0..got]);

    // And the directory the guest was holding open still works, which is the number it kept.
    if (held >= 0) {
        var about: [256]u8 align(8) = @splat(0);
        const asked = linux.syscall5(
            .statx,
            @bitCast(@as(isize, held)),
            @intFromPtr(""),
            0x1000, // AT_EMPTY_PATH
            0,
            @intFromPtr(&about),
        );
        if (std.posix.errno(asked) == .SUCCESS) {
            say("commit: what it held still answers\n");
        } else {
            say("commit: what it held went stale\n");
        }
    }
}

/// Do what a package fetch does: unpack a tree, then walk it to measure what was unpacked.
///
/// A recursive listing through coreutils passes where this fails, so the sequence matters: many
/// files written at mixed modes, then every name opened and measured rather than only counted.
/// Says the operation and the number when something refuses, because a walk that reports only
/// failure costs a day working out which call it was.
fn walkLikeAFetch() void {
    if (std.posix.errno(linux.mkdir("/share/work/.tmp-probe", 0o755)) != .SUCCESS) {
        say("fetch: cannot make the temporary directory\n");
        return;
    }

    const modes = [3]linux.mode_t{ 0o644, 0o755, 0o600 };
    var written: usize = 0;
    while (written < 48) : (written += 1) {
        var name: [96]u8 = undefined;
        const path = std.fmt.bufPrintSentinel(&name, "/share/work/.tmp-probe/file-{d}", .{written}, 0) catch break;
        const made = linux.open(path.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, modes[written % modes.len]);
        if (std.posix.errno(made) != .SUCCESS) {
            sayNumber("fetch: creating refused", @backingInt(std.posix.errno(made)));
            return;
        }
        const fd: i32 = @intCast(made);
        _ = linux.write(fd, "some bytes for the measure\n", 27);
        _ = linux.close(fd);
    }

    const opened = linux.open("/share/work/.tmp-probe", .{ .DIRECTORY = true }, 0);
    if (std.posix.errno(opened) != .SUCCESS) {
        sayNumber("fetch: opening the directory refused", @backingInt(std.posix.errno(opened)));
        return;
    }
    const dir: i32 = @intCast(opened);
    defer _ = linux.close(dir);

    var room: [4096]u8 align(8) = undefined;
    var measured: usize = 0;
    while (true) {
        const got = linux.getdents64(dir, &room, room.len);
        if (std.posix.errno(got) != .SUCCESS) {
            sayNumber("fetch: the walk refused", @backingInt(std.posix.errno(got)));
            return;
        }
        if (got == 0) break;

        var at: usize = 0;
        while (at + @sizeOf(linux.dirent64) <= got) {
            const one: *align(1) const linux.dirent64 = @ptrCast(&room[at]);
            if (one.reclen == 0) break;
            at += one.reclen;

            const name: [*:0]const u8 = @ptrCast(&one.name);
            if (name[0] == '.' and (name[1] == 0 or (name[1] == '.' and name[2] == 0))) continue;

            // What a hash needs: the mode, because an executable bit belongs in it, and the bytes.
            var about: [256]u8 align(8) = @splat(0);
            const asked = linux.syscall5(
                .statx,
                @bitCast(@as(isize, dir)),
                @intFromPtr(name),
                0,
                0,
                @intFromPtr(&about),
            );
            if (std.posix.errno(asked) != .SUCCESS) {
                sayNumber("fetch: measuring a name refused", @backingInt(std.posix.errno(asked)));
                return;
            }

            const file = linux.openat(dir, name, .{}, 0);
            if (std.posix.errno(file) != .SUCCESS) {
                sayNumber("fetch: opening a name refused", @backingInt(std.posix.errno(file)));
                return;
            }
            var bytes: [64]u8 = undefined;
            const read = linux.read(@intCast(file), &bytes, bytes.len);
            _ = linux.close(@intCast(file));
            if (std.posix.errno(read) != .SUCCESS) {
                sayNumber("fetch: reading a name refused", @backingInt(std.posix.errno(read)));
                return;
            }
            measured += 1;
        }
    }

    sayNumber("fetch: measured names", measured);
}

/// Push the filesystem from several tasks at once, which is what a parallel build does.
///
/// Every exercise above runs on one task, so the device is only ever asked for one thing at a time
/// and a queue that stopped being drained would never show. A compiler on twelve processors submits
/// continuously from all of them, so that is what this imitates: several tasks, each doing enough
/// work to keep asking while the others ask.
fn hammerFromManyTasks() void {
    const tasks = 8;
    const rounds = 60;

    var children: [tasks]i32 = @splat(-1);
    var started: usize = 0;
    while (started < tasks) : (started += 1) {
        const made = linux.fork();
        if (std.posix.errno(made) != .SUCCESS) break;
        if (made == 0) {
            // The child. Ask for names and bytes over and over, then go without running anything
            // the parent would run again.
            var round: usize = 0;
            while (round < rounds) : (round += 1) {
                var name: [96]u8 = undefined;
                const path = std.fmt.bufPrintSentinel(&name, "/share/work/.tmp-probe/file-{d}", .{round % 48}, 0) catch break;

                var about: [256]u8 align(8) = @splat(0);
                _ = linux.syscall5(.statx, @bitCast(@as(isize, linux.AT.FDCWD)), @intFromPtr(path.ptr), 0, 0, @intFromPtr(&about));

                const opened = linux.open(path.ptr, .{}, 0);
                if (std.posix.errno(opened) == .SUCCESS) {
                    var bytes: [64]u8 = undefined;
                    _ = linux.read(@intCast(opened), &bytes, bytes.len);
                    _ = linux.close(@intCast(opened));
                }
            }
            linux.exit(0);
        }
        children[started] = @intCast(made);
    }

    // Every task is waited for. A task still running when the guest powers off would be work the
    // device never finished, which is the opposite of what this is meant to prove.
    var finished: usize = 0;
    for (children[0..started]) |each| {
        if (each < 0) continue;
        var status: i32 = 0;
        if (std.posix.errno(linux.wait4(each, &status, 0, null)) == .SUCCESS) finished += 1;
    }

    if (finished == started and started == tasks) {
        sayNumber("hammer: tasks finished", finished);
    } else {
        sayNumber("hammer: tasks that did not finish", started - finished);
    }
}

/// Make the kernel let go of the names it is holding, which is what sends a forget.
///
/// A guest that runs for a second never forgets anything on its own: the kernel keeps its cache
/// until something presses on it. A session lasting hours does forget, constantly, so the path has
/// to be exercised here rather than trusted. Needs `/proc`, which is mounted for this.
fn makeTheKernelForget() void {
    _ = linux.mkdir("/proc", 0o755);
    if (std.posix.errno(linux.mount("none", "/proc", "proc", 0, 0)) != .SUCCESS) {
        say("forget: no proc\n");
        return;
    }
    const opened = linux.open("/proc/sys/vm/drop_caches", .{ .ACCMODE = .WRONLY }, 0);
    if (std.posix.errno(opened) != .SUCCESS) {
        say("forget: cannot ask the kernel to let go\n");
        return;
    }
    const fd: i32 = @intCast(opened);
    _ = linux.write(fd, "3\n", 2);
    _ = linux.close(fd);
    say("forget: asked the kernel to let go\n");
}
/// Say a line with a number on the end, for a guest with no formatter to spare.
fn sayNumber(what: []const u8, number: usize) void {
    var room: [96]u8 = undefined;
    const line = std.fmt.bufPrint(&room, "{s} {d}\n", .{ what, number }) catch {
        say(what);
        say("\n");
        return;
    };
    say(line);
}
/// Read `hello` out of one of the shared directories, named by whoever asked over the channel.
///
/// Opened when asked rather than held open, because the point of asking is to find out whether the
/// directory is there now: one offered for a piece of work is gone when that work is over.
fn readShare(name: []const u8, into: []u8) usize {
    var room: [256]u8 = undefined;
    const path = std.fmt.bufPrintSentinel(&room, "/share/{s}/hello", .{name}, 0) catch return 0;
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

/// What an echo asks with and what an answer carries: the kind, then the two numbers that come back.
const echo_request = 8;
const echo_reply = 0;

/// The sum the internet protocols check a header by: every pair of bytes added up, carried round, and
/// turned over.
fn onesComplement(bytes: []const u8) u16 {
    var sum: u32 = 0;
    var at: usize = 0;
    while (at + 1 < bytes.len) : (at += 2) sum += std.mem.readInt(u16, bytes[at..][0..2], .big);
    if (at < bytes.len) sum += @as(u16, bytes[at]) << 8;
    while (sum >> 16 != 0) sum = (sum & 0xffff) + (sum >> 16);
    return ~@as(u16, @truncate(sum));
}

/// Ask the gateway for an echo.
///
/// This is the shortest thing that proves a frame left the guest, that whatever is on the other side
/// read it and built an answer, and that the answer came back. What answers differs by how the guest
/// was given its network, and the line this prints is the same either way.
fn ping() void {
    const raw = linux.socket(linux.AF.INET, linux.SOCK.RAW, 1);
    if (std.posix.errno(raw) != .SUCCESS) {
        say("network: no raw socket\n");
        return;
    }
    const sock: i32 = @intCast(raw);
    defer _ = linux.close(sock);

    var request = [8]u8{ echo_request, 0, 0, 0, 0x12, 0x34, 0, 1 };
    std.mem.writeInt(u16, request[2..4], onesComplement(&request), .big);

    var gateway = inetAddress(10, 0, 2, 2);
    const sent = linux.sendto(sock, &request, request.len, 0, @ptrCast(&gateway), @sizeOf(linux.sockaddr.in));
    if (std.posix.errno(sent) != .SUCCESS) {
        say("network: the echo would not go\n");
        return;
    }

    // The header the kernel leaves in front of the answer is as long as it says it is, so where the
    // echo starts is read rather than assumed.
    var answer: [256]u8 = undefined;
    var tries: usize = 0;
    while (tries < 40) : (tries += 1) {
        const got = linux.recvfrom(sock, &answer, answer.len, 0x40, null, null);
        if (std.posix.errno(got) == .SUCCESS and got >= 20) {
            const header = @as(usize, answer[0] & 0x0f) * 4;
            if (got > header and answer[header] == echo_reply) {
                say("network: the gateway answered\n");
                return;
            }
        }
        var pause: linux.timespec = .{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
        while (linux.nanosleep(&pause, &pause) == @as(usize, @bitCast(@as(isize, -4)))) {}
    }
    say("network: the gateway said nothing\n");
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

    // One retry rather than the kernel's own handful, which take minutes between them. A far end
    // that never answers is a thing to be told about, not a thing to wait out.
    var once: u32 = 1;
    _ = linux.setsockopt(fd, 6, 7, @ptrCast(&once), @sizeOf(u32));

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

/// What a Glacier card answers with, and the registers a driver drives it through.
///
/// A driver has to know these. Everything else it reads off the card: the device table says where
/// each block of the fabric sits, and each block says what it is.
const glacier = struct {
    const vendor: u32 = 0x10ee;
    const model: u32 = 0x7203;

    /// The engine behind the first region, which carries words between this guest's memory and
    /// the fabric. Nothing outside the window can be reached any other way.
    const engine: u32 = 0x4844_4d41;
    const control = 0x04;
    const status = 0x08;
    const host_low = 0x0c;
    const host_high = 0x10;
    const local_low = 0x14;
    const local_high = 0x18;
    const length = 0x1c;
    const start: u32 = 1 << 0;
    const clear: u32 = 1 << 1;
    const to_host: u32 = 1 << 2;
    const done: u32 = 1 << 1;
    const failed: u32 = 1 << 2;

    /// The device table, and the blocks this driver looks for in it.
    const table = 0x100;
    const table_id: u32 = 0x4744_4556;
    const entries = 0x40;
    const window_block: u32 = 0x5744_574e;
    const display_block: u32 = 0x4744_4953;
    const core_block: u32 = 0x474c_4352;

    /// Inside a display block: where the first display starts, and the words of it worth reading.
    const displays = 0x40;
    const width = 0x10;
    const height = 0x14;
    const framebuffer = 0x1c;
    const pitch = 0x2c;
    const frames = 0x30;

    /// Inside a core's window: what a launch is written to, what it reports, and where a program
    /// goes.
    const core_control = 0x04;
    const launch_warp = 0x08;
    const launch_pc = 0x0c;
    const launch_mask = 0x10;
    const core_status = 0x14;
    const caps = 0x18;
    const program = 0x8000;
    const run: u32 = 1 << 0;
    const launch: u32 = 1 << 1;
    const issued: u32 = 1 << 1;
    const idle: u32 = 1 << 2;
    const bus_error: u32 = 1 << 3;

    /// The mark the kernel writes, with the warp folded into its low bits, so a word in the frame
    /// buffer says which warp put it there.
    const mark: u32 = 0x5a5a_0000;
};

/// A Glacier card this guest has mapped, and the page the engine moves words through.
const Card = struct {
    regs: usize,
    window: usize,
    /// The page the engine reads and writes, and where that page sits in the machine's memory. The
    /// engine takes an address off the bus, so a buffer whose physical address is unknown is no
    /// use to it.
    page: usize,
    page_at: u64,

    fn reg(self: Card, at: usize) u32 {
        return offBus(self.regs + at);
    }

    fn put(self: Card, at: usize, value: u32) void {
        ontoBus(self.regs + at, value);
    }

    fn word(self: Card, index: usize) u32 {
        return @as(*volatile u32, @ptrFromInt(self.page + index * 4)).*;
    }

    fn setWord(self: Card, index: usize, value: u32) void {
        @as(*volatile u32, @ptrFromInt(self.page + index * 4)).* = value;
    }

    /// Move words between the page and the fabric, and say whether the engine finished. A driver
    /// clears what the last transfer left, stages both addresses and the count, then starts.
    fn move(self: Card, at: u64, words: u32, out: bool) bool {
        self.put(glacier.control, glacier.clear);
        self.put(glacier.host_low, @truncate(self.page_at));
        self.put(glacier.host_high, @truncate(self.page_at >> 32));
        self.put(glacier.local_low, @truncate(at));
        self.put(glacier.local_high, @truncate(at >> 32));
        self.put(glacier.length, words);
        self.put(glacier.control, glacier.start | if (out) 0 else glacier.to_host);
        const state = self.reg(glacier.status);
        return state & glacier.done != 0 and state & glacier.failed == 0;
    }

    /// One word of the fabric, wherever in it the word sits.
    fn fabric(self: Card, at: u64) ?u32 {
        if (!self.move(at, 1, false)) return null;
        return self.word(0);
    }

    fn setFabric(self: Card, at: u64, value: u32) bool {
        self.setWord(0, value);
        return self.move(at, 1, true);
    }

    /// One word of the window, which this guest reaches without the engine.
    fn shown(self: Card, offset: usize) u32 {
        return offBus(self.window + offset);
    }
};

/// One word off a device region, and one word into it, with the instruction said here rather than
/// left to the compiler.
///
/// A loop of plain volatile reads becomes a post indexed load on aarch64, and a hypervisor cannot
/// say what a load that writes its own address register back did: the access leaves it with no
/// syndrome to report and the guest dies on it. Linux reaches a device register this way for the
/// same reason. Nothing else needs it, because the loads a compiler pairs are the ones in a row.
fn offBus(at: usize) u32 {
    if (builtin.cpu.arch != .aarch64) return @as(*volatile u32, @ptrFromInt(at)).*;
    // The register is named because the word has to be the one a `w` names: a value handed to
    // `%[...]` is printed as the whole register, which would make this a load of eight bytes.
    return asm volatile ("ldr w8, [%[at]]"
        : [got] "={x8}" (-> u32),
        : [at] "r" (at),
        : .{ .memory = true });
}

fn ontoBus(at: usize, value: u32) void {
    if (builtin.cpu.arch != .aarch64) {
        @as(*volatile u32, @ptrFromInt(at)).* = value;
        return;
    }
    asm volatile ("str w9, [%[at]]"
        :
        : [at] "r" (at),
          [value] "{x9}" (value),
        : .{ .memory = true });
}

/// The words of the kernel every warp runs: read which warp I am, then write one word for myself
/// into the frame buffer.
///
/// Written here rather than read from a file. A guest that cannot put eight words together has
/// nothing to launch, and the words a core runs are RISC-V.
fn kernel(into: []u32, at: u32) []u32 {
    const words = [_]u32{
        csrrs(5, 0xf14),
        lui(6, at >> 12),
        slli(7, 5, 2),
        add(6, 6, 7),
        lui(8, glacier.mark >> 12),
        bitOr(8, 8, 5),
        sw(8, 6),
        ebreak,
    };
    @memcpy(into[0..words.len], &words);
    return into[0..words.len];
}

fn csrrs(rd: u32, which: u32) u32 {
    return 0x73 | (rd << 7) | (2 << 12) | (which << 20);
}

fn lui(rd: u32, high: u32) u32 {
    return 0x37 | (rd << 7) | (high << 12);
}

fn slli(rd: u32, from: u32, by: u32) u32 {
    return 0x13 | (rd << 7) | (1 << 12) | (from << 15) | (by << 20);
}

fn add(rd: u32, left: u32, right: u32) u32 {
    return 0x33 | (rd << 7) | (left << 15) | (right << 20);
}

fn bitOr(rd: u32, left: u32, right: u32) u32 {
    return 0x33 | (rd << 7) | (6 << 12) | (left << 15) | (right << 20);
}

fn sw(value: u32, base: u32) u32 {
    return 0x23 | (2 << 12) | (base << 15) | (value << 20);
}

const ebreak: u32 = 0x0010_0073;

/// The sysfs name of the first Glacier card, or nothing where this guest has none.
fn cardNamed(into: []u8) ?[]const u8 {
    const opened = linux.open("/sys/bus/pci/devices", .{ .DIRECTORY = true }, 0);
    if (std.posix.errno(opened) != .SUCCESS) return null;
    const dir: i32 = @intCast(opened);
    defer _ = linux.close(dir);

    var room: [2048]u8 align(8) = undefined;
    while (true) {
        const got = linux.getdents64(dir, &room, room.len);
        if (std.posix.errno(got) != .SUCCESS or got == 0) return null;

        var at: usize = 0;
        while (at + @sizeOf(linux.dirent64) <= got) {
            const one: *align(1) const linux.dirent64 = @ptrCast(&room[at]);
            if (one.reclen == 0) return null;
            at += one.reclen;

            const name: [*:0]const u8 = @ptrCast(&one.name);
            if (name[0] == '.') continue;
            const named = std.mem.sliceTo(name, 0);
            if (named.len > into.len) continue;
            if (numberIn(named, "vendor") != glacier.vendor) continue;
            if (numberIn(named, "device") != glacier.model) continue;
            @memcpy(into[0..named.len], named);
            return into[0..named.len];
        }
    }
}

/// One of the numbers sysfs keeps about a device, which it writes as hexadecimal.
fn numberIn(named: []const u8, which: []const u8) u32 {
    var path: [96]u8 = undefined;
    const at = std.fmt.bufPrintSentinel(&path, "/sys/bus/pci/devices/{s}/{s}", .{ named, which }, 0) catch return 0;
    const opened = linux.open(at.ptr, .{}, 0);
    if (std.posix.errno(opened) != .SUCCESS) return 0;
    const fd: i32 = @intCast(opened);
    defer _ = linux.close(fd);

    var room: [32]u8 = undefined;
    const got = linux.read(fd, &room, room.len);
    if (std.posix.errno(got) != .SUCCESS or got < 3) return 0;
    const said = std.mem.trim(u8, room[0..got], " \n");
    if (said.len < 3 or said[0] != '0' or said[1] != 'x') return 0;
    return std.fmt.parseInt(u32, said[2..], 16) catch 0;
}

/// Let the card decode its regions. Nothing is bound to it, so this guest is what enables it, the
/// way a driver's first act does.
fn decodeOn(named: []const u8) bool {
    var path: [96]u8 = undefined;
    const at = std.fmt.bufPrintSentinel(&path, "/sys/bus/pci/devices/{s}/config", .{named}, 0) catch return false;
    const opened = linux.open(at.ptr, .{ .ACCMODE = .RDWR }, 0);
    if (std.posix.errno(opened) != .SUCCESS) return false;
    const fd: i32 = @intCast(opened);
    defer _ = linux.close(fd);

    var room: [2]u8 = undefined;
    const got = linux.pread(fd, &room, room.len, 0x04);
    if (std.posix.errno(got) != .SUCCESS or got != room.len) return false;
    const command = std.mem.readInt(u16, &room, .little);
    if (command & 0x0002 != 0) return true;

    std.mem.writeInt(u16, &room, command | 0x0002, .little);
    const written = linux.pwrite(fd, &room, room.len, 0x04);
    return std.posix.errno(written) == .SUCCESS and written == room.len;
}

/// One of the card's regions, mapped where this guest can reach it.
fn mapped(named: []const u8, which: u8, len: usize) ?usize {
    var path: [96]u8 = undefined;
    const at = std.fmt.bufPrintSentinel(&path, "/sys/bus/pci/devices/{s}/resource{d}", .{ named, which }, 0) catch return null;
    const opened = linux.open(at.ptr, .{ .ACCMODE = .RDWR }, 0);
    if (std.posix.errno(opened) != .SUCCESS) return null;
    const fd: i32 = @intCast(opened);
    defer _ = linux.close(fd);

    const where = linux.mmap(null, len, .{ .READ = true, .WRITE = true }, .{ .TYPE = .SHARED }, fd, 0);
    if (std.posix.errno(where) != .SUCCESS) return null;
    return where;
}

/// A page of this guest's memory the engine can reach, and where that page sits in the machine's
/// memory. The page is held where it is, because a page that moved would leave the engine writing
/// into whatever took its place.
fn enginePage() ?struct { at: usize, physical: u64 } {
    const size = 4096;
    const where = linux.mmap(null, size, .{ .READ = true, .WRITE = true }, .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0);
    if (std.posix.errno(where) != .SUCCESS) return null;

    @as(*volatile u32, @ptrFromInt(where)).* = 0;
    if (std.posix.errno(linux.mlock(@ptrFromInt(where), size)) != .SUCCESS) return null;

    return .{ .at = where, .physical = physicalOf(where) orelse return null };
}

/// Where a page of this process sits in the machine's memory, out of the kernel's own table.
fn physicalOf(at: usize) ?u64 {
    const opened = linux.open("/proc/self/pagemap", .{}, 0);
    if (std.posix.errno(opened) != .SUCCESS) return null;
    const fd: i32 = @intCast(opened);
    defer _ = linux.close(fd);

    var room: [8]u8 = undefined;
    const got = linux.pread(fd, &room, room.len, @intCast((at / 4096) * 8));
    if (std.posix.errno(got) != .SUCCESS or got != room.len) return null;

    const entry = std.mem.readInt(u64, &room, .little);
    // The top bit says the page is there to point at. Without it the rest of the word means
    // nothing.
    if (entry >> 63 == 0) return null;
    return (entry & 0x007f_ffff_ffff_ffff) * 4096;
}

/// Wait a while, which is what a driver does between reads of a status register.
fn rest(ms: u32) void {
    var pause: linux.timespec = .{ .sec = 0, .nsec = @as(isize, ms) * std.time.ns_per_ms };
    while (linux.nanosleep(&pause, &pause) == @as(usize, @bitCast(@as(isize, -4)))) {}
}

/// Drive the card: find it, read what it says it is, launch a kernel on its core, and read back
/// what the kernel wrote.
///
/// This is the whole path a driver takes, and every address comes off the card. The display and
/// the core sit past the window, so the engine is the only way to either, and the frame buffer is
/// inside the window, so the pixels are read straight.
fn card() void {
    _ = linux.mkdir("/sys", 0o755);
    _ = linux.mount("none", "/sys", "sysfs", 0, 0);
    _ = linux.mkdir("/proc", 0o755);
    _ = linux.mount("none", "/proc", "proc", 0, 0);

    var name: [32]u8 = undefined;
    const named = cardNamed(&name) orelse {
        say("card: no glacier card\n");
        return;
    };
    if (!decodeOn(named)) {
        say("card: the card would not decode\n");
        return;
    }

    const regs = mapped(named, 0, 0x1000) orelse {
        say("card: the registers would not be mapped\n");
        return;
    };
    var one: Card = .{ .regs = regs, .window = 0, .page = 0, .page_at = 0 };
    if (one.reg(0) != glacier.engine) {
        say("card: another card answers here\n");
        return;
    }
    if (one.reg(glacier.table) != glacier.table_id) {
        say("card: no device table\n");
        return;
    }

    // Where everything is, as the card says it rather than as this guest was built to think.
    var window_at: u64 = 0;
    var window_len: u64 = 0;
    var display_at: u64 = 0;
    var core_at: u64 = 0;
    const blocks = one.reg(glacier.table + 0x08);
    const stride = one.reg(glacier.table + 0x0c);
    var which: u32 = 0;
    while (which < blocks and stride != 0) : (which += 1) {
        const entry = glacier.table + glacier.entries + which * stride;
        const base = one.reg(entry + 0x04);
        switch (one.reg(entry)) {
            glacier.window_block => {
                window_at = base;
                window_len = one.reg(entry + 0x08);
            },
            glacier.display_block => display_at = base,
            glacier.core_block => core_at = base,
            else => {},
        }
    }
    sayNumber("card: blocks in the table", blocks);

    if (window_len == 0) {
        say("card: the table names no window\n");
        return;
    }
    // The window is the card's second region. The kernel module names it there, so a driver looks
    // there and nowhere else.
    one.window = mapped(named, 2, @intCast(window_len)) orelse {
        say("card: the window would not be mapped\n");
        return;
    };
    const page = enginePage() orelse {
        say("card: no page the engine can reach\n");
        return;
    };
    one.page = page.at;
    one.page_at = page.physical;

    if (display_at == 0) {
        say("card: the table names no display\n");
        return;
    }
    const first = display_at + glacier.displays;
    const width = one.fabric(first + glacier.width) orelse {
        say("card: the engine would not read the display\n");
        return;
    };
    const height = one.fabric(first + glacier.height) orelse 0;
    const pitch = one.fabric(first + glacier.pitch) orelse 0;
    const buffer = one.fabric(first + glacier.framebuffer) orelse 0;
    const began = one.fabric(first + glacier.frames) orelse 0;

    var line: [96]u8 = undefined;
    say(std.fmt.bufPrint(&line, "card: {d}x{d} pitch {d} at 0x{x}\n", .{
        width,
        height,
        pitch,
        buffer,
    }) catch "card: a mode too long to say\n");

    if (buffer < window_at or buffer - window_at >= window_len) {
        say("card: the frame buffer is outside the window\n");
        return;
    }
    if (core_at == 0) {
        say("card: the table names no core\n");
        return;
    }

    // What the core was built with. A driver can guess none of it.
    const caps = one.fabric(core_at + glacier.caps) orelse {
        say("card: the engine would not read the core\n");
        return;
    };
    const warps = caps & 0xff;
    const lanes = (caps >> 8) & 0xff;
    say(std.fmt.bufPrint(&line, "card: the core holds {d} warps of {d} lanes\n", .{ warps, lanes }) catch
        "card: a core too wide to say\n");
    if (warps == 0 or lanes == 0 or lanes > 32 or warps > 32) {
        say("card: a core nobody could have built\n");
        return;
    }

    var words: [16]u32 = undefined;
    const held = kernel(&words, buffer);
    for (held, 0..) |each, index| one.setWord(index, each);
    if (!one.move(core_at + glacier.program, @intCast(held.len), true)) {
        say("card: the program would not be written\n");
        return;
    }

    // Out of reset first, then one launch for each warp. Each warp writes a word of its own, so
    // the order they run in changes nothing.
    if (!one.setFabric(core_at + glacier.core_control, glacier.run)) {
        say("card: the core would not leave reset\n");
        return;
    }
    // Every lane of the datapath. The shift is done wide and cut back, because a core as wide as
    // the register would shift a word by its own width.
    const mask: u32 = @truncate((@as(u64, 1) << @intCast(lanes)) - 1);
    var warp: u32 = 0;
    while (warp < warps) : (warp += 1) {
        _ = one.setFabric(core_at + glacier.launch_warp, warp);
        _ = one.setFabric(core_at + glacier.launch_pc, 0);
        _ = one.setFabric(core_at + glacier.launch_mask, mask);
        if (!one.setFabric(core_at + glacier.core_control, glacier.run | glacier.launch)) {
            say("card: a launch was refused\n");
            return;
        }
    }

    // Every warp has issued and none is running. A kernel that retired without issuing would read
    // as idle from the start, which is why both bits are waited on.
    var state: u32 = 0;
    var tries: u32 = 0;
    while (tries < 200) : (tries += 1) {
        state = one.fabric(core_at + glacier.core_status) orelse break;
        if (state & glacier.issued != 0 and state & glacier.idle != 0) break;
        rest(5);
    }
    if (state & glacier.idle == 0) {
        say("card: the core never went idle\n");
        return;
    }
    if (state & glacier.bus_error != 0) say("card: a kernel reached an address nothing claims\n");

    // What the kernel wrote, read through the window. The words went into the fabric from the
    // core's side and come back from the guest's, so a match is the whole path.
    const offset: usize = @intCast(buffer - window_at);
    var wrote: u32 = 0;
    warp = 0;
    while (warp < warps) : (warp += 1) {
        if (one.shown(offset + warp * 4) == glacier.mark | warp) wrote += 1;
    }
    if (wrote == warps) {
        say("card: every warp wrote its own word\n");
    } else {
        sayNumber("card: warps that wrote their own word", wrote);
    }

    // The counter the card keeps for the display. Nothing scans out here, so this moves because
    // the machine says frames began, and a guest waiting on it is answered.
    const now = one.fabric(first + glacier.frames) orelse began;
    if (now > began) say("card: the frame counter moved\n") else say("card: the frame counter stood still\n");
}

pub fn main() void {
    openConsole();
    say("mirage guest is alive\n");
    chip();
    share();
    channel();
    network();
    ping();
    stream();
    card();

    // Give the devices that work in the background time to do so. The balloon driver hands
    // pages over on a worker, and a guest that powers off the instant it starts proves
    // nothing about a device that had no chance to run.
    var pause: linux.timespec = .{ .sec = 0, .nsec = 300 * std.time.ns_per_ms };
    while (linux.nanosleep(&pause, &pause) == @as(usize, @bitCast(@as(isize, -4)))) {}

    // The clean stop is a power off: PSCI system_off on aarch64, ACPI `_S5` on x86.
    _ = linux.reboot(.MAGIC1, .MAGIC2, .POWER_OFF, null);

    // The kernel does not return from a power off it accepted.
    while (true) {}
}
