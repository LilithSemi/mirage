//! A session as somebody else would use it: start a guest, take a stream into it, stop it.
//!
//! What this proves is the shape of the thing rather than the guest: the guest comes up, the session
//! says so before anything asks it for work, a stream handed over carries bytes both ways, and a
//! guest that never comes up is a refusal at the start and not a call that quietly does nothing.

const std = @import("std");
const image = @import("mirage-image");
const session = @import("mirage-session");
const options = @import("session-options");

const guest_init = @embedFile("guest-init");

/// Where the session's socket and the guest's filesystem go. One directory per test, taken away
/// afterwards, because a path left behind is a session somebody else could connect to.
/// Where temporary work goes. `TMPDIR` when there is one, because a machine may be shared: on macOS
/// it names a directory of this user's own, and other people read `/tmp` there.
fn temporaryRoot() []const u8 {
    var index: usize = 0;
    while (std.c.environ[index]) |entry| : (index += 1) {
        const said = std.mem.span(entry);
        if (std.mem.startsWith(u8, said, "TMPDIR=")) return said["TMPDIR=".len..];
    }
    return "/tmp";
}

fn workspace(gpa: std.mem.Allocator, io: std.Io, name: []const u8) ![]const u8 {
    const root = temporaryRoot();
    const at = try std.fmt.allocPrint(gpa, "{s}/mirage-session-{d}-{s}", .{
        std.mem.trimEnd(u8, root, "/"),
        std.c.getpid(),
        name,
    });
    std.Io.Dir.cwd().createDir(io, at, .default_dir) catch {};
    return at;
}

fn forget(io: std.Io, at: []const u8) void {
    std.Io.Dir.cwd().deleteTree(io, at) catch {};
}

/// Where a guest's console goes, and what it said if a test failed. A guest that did not do what it
/// was asked says why here and nowhere else, and this is a gate: nobody is watching it run.
fn console(io: std.Io, at: []const u8) !std.Io.File {
    var room: [128]u8 = undefined;
    const path = try std.fmt.bufPrint(&room, "{s}/console.log", .{at});
    return std.Io.Dir.cwd().createFile(io, path, .{});
}

fn showConsole(io: std.Io, gpa: std.mem.Allocator, at: []const u8) void {
    var room: [128]u8 = undefined;
    const path = std.fmt.bufPrint(&room, "{s}/console.log", .{at}) catch return;
    const said = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 20)) catch return;
    defer gpa.free(said);
    const tail = if (said.len > 2048) said[said.len - 2048 ..] else said;
    std.debug.print("the guest said:\n{s}\n", .{tail});
}

fn initramfs(gpa: std.mem.Allocator, io: std.Io, at: []const u8) ![]const u8 {
    var archive: image.Cpio = .init(gpa);
    defer archive.deinit();
    try archive.addCharacterDevice("dev/console", 0o600, 5, 1);
    try archive.addFile("init", 0o755, guest_init);
    const bytes = try archive.finish();
    defer gpa.free(bytes);

    const path = try std.fmt.allocPrint(gpa, "{s}/initrd", .{at});
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = bytes });
    return path;
}

/// What a shared directory holds for the gate below, and what the guest reads back out of it.
const shared_contents = "a tool from the host\n";

/// A directory to offer the guest, inside the workspace so it goes when that does.
fn offering(gpa: std.mem.Allocator, io: std.Io, at: []const u8) ![]const u8 {
    const where = try std.fmt.allocPrint(gpa, "{s}/store", .{at});
    try std.Io.Dir.cwd().createDir(io, where, .default_dir);
    var name: [256]u8 = undefined;
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = try std.fmt.bufPrint(&name, "{s}/hello", .{where}),
        .data = shared_contents,
    });
    return where;
}

test "a session holds a guest up and hands out a stream into it" {
    if (options.kernel_path.len == 0) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const at = try workspace(gpa, io, "stream");
    defer gpa.free(at);
    defer forget(io, at);
    const initrd = try initramfs(gpa, io, at);
    defer gpa.free(initrd);
    const socket = try std.fmt.allocPrint(gpa, "{s}/control", .{at});
    defer gpa.free(socket);

    // A directory to mount as well, when the gate was asked for one. That is the shape a harness
    // really runs in: a guest held up for it, with its tools mounted from the host.
    const shared: ?[]const u8 = if (options.share) try offering(gpa, io, at) else null;
    defer if (shared) |where| gpa.free(where);

    var held = session.Client.start(gpa, io, .{
        .program = options.mirage_path,
        .socket = socket,
        .kernel = options.kernel_path,
        .initrd = initrd,
        .port = 1024,
        .cpus = options.cpus,
        .share = if (shared) |where| .{ .name = "store", .at = where } else null,
        .boot_ms = 15_000,
        .console = .{ .file = try console(io, at) },
    }) catch |err| {
        std.debug.print("start said {t}\n", .{err});
        showConsole(io, gpa, at);
        return err;
    };
    defer held.stop();
    errdefer showConsole(io, gpa, at);

    // The guest is up before anything is built from it. That is the whole point of waiting here:
    // a session that cannot say this has no sandbox to offer.
    try std.testing.expect(held.up);
    try std.testing.expect(!held.gone);

    // The guest opened a stream when it came up, so one is waiting to be claimed.
    const stream = try held.channel(1024);
    defer session.socket.close(stream);

    var buffer: [128]u8 = undefined;
    const greeting = try expect(stream, &buffer);
    try std.testing.expect(std.mem.indexOf(u8, greeting, "hello from the guest") != null);

    // Telling the guest to stay is what makes it a resident guest: it answers lines from here on
    // rather than finishing and powering off.
    try sendAll(stream, "stay\n");
    const staying = try expect(stream, &buffer);
    try std.testing.expect(std.mem.indexOf(u8, staying, "staying") != null);

    // A line that comes back is the whole way through: this end, the stream it was handed, the
    // transport, the guest, and back again.
    try sendAll(stream, "ping\n");
    const back = try expect(stream, &buffer);
    try std.testing.expect(std.mem.indexOf(u8, back, "ping") != null);

    // The guest is still there, and the session still says so.
    try std.testing.expect(!held.gone);

    if (options.share) {
        // And the guest reads the host's files while the session holds it, which is the whole shape a
        // harness runs in: one guest, held up, with its tools mounted from outside it. Asked for over
        // the stream rather than read off the console, so the answer is the guest's and not a race
        // with whatever the runner has written out so far.
        try sendAll(stream, "read share\n");
        const inside = try expect(stream, &buffer);
        try std.testing.expect(std.mem.indexOf(u8, inside, shared_contents[0 .. shared_contents.len - 1]) != null);
    }
}

test "a guest that cannot boot is a refusal and not a session" {
    if (options.kernel_path.len == 0) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();

    const at = try workspace(gpa, threaded.io(), "refusal");
    defer gpa.free(at);
    defer forget(threaded.io(), at);
    const socket = try std.fmt.allocPrint(gpa, "{s}/nothing", .{at});
    defer gpa.free(socket);

    // A kernel that is not there. Whoever asked for a guest learns that at the start, before it
    // builds anything that needs one.
    const outcome = session.Client.start(gpa, threaded.io(), .{
        .program = options.mirage_path,
        .socket = socket,
        .kernel = "/nonexistent/Image",
        .port = 1024,
        .boot_ms = 4_000,
    });
    try std.testing.expectError(session.Client.Error.GuestDidNotBoot, outcome);
}

/// Read until there is a line, or give up. The guest is on the other side of a hypervisor and a
/// device model, so an answer takes as long as it takes.
fn expect(fd: std.posix.fd_t, buffer: []u8) ![]const u8 {
    var have: usize = 0;
    var left: u64 = 5_000;
    while (left > 0) : (left -= 20) {
        const got = session.socket.read(fd, buffer[have..]) catch return error.StreamEnded;
        have += got;
        if (std.mem.indexOfScalar(u8, buffer[0..have], '\n') != null) return buffer[0..have];
        session.socket.waitFor(fd, 20);
    }
    return error.NothingCameBack;
}

fn sendAll(fd: std.posix.fd_t, bytes: []const u8) !void {
    var sent: usize = 0;
    var left: u64 = 2_000;
    while (sent < bytes.len and left > 0) : (left -= 10) {
        sent += session.socket.write(fd, bytes[sent..]) catch return error.StreamEnded;
        if (sent < bytes.len) session.socket.rest(10);
    }
    if (sent < bytes.len) return error.CouldNotSend;
}

test "a guest held up for somebody else is refused a network of its own" {
    if (options.kernel_path.len == 0) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const at = try workspace(gpa, io, "onedoor");
    defer gpa.free(at);
    defer forget(io, at);
    const initrd = try initramfs(gpa, io, at);
    defer gpa.free(initrd);
    const socket = try std.fmt.allocPrint(gpa, "{s}/control", .{at});
    defer gpa.free(socket);

    // A session reaches by name and nothing else does. A guest given both would have one way out
    // that is decided about and one that is not, so asking for both is refused rather than served.
    const outcome = session.Client.start(gpa, io, .{
        .program = options.mirage_path,
        .socket = socket,
        .kernel = options.kernel_path,
        .initrd = initrd,
        .network = true,
        .boot_ms = 4_000,
    });
    try std.testing.expectError(session.Client.Error.GuestDidNotBoot, outcome);
}
test "a guest reaching for a name is handed a connection somebody else opened" {
    if (options.kernel_path.len == 0) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const at = try workspace(gpa, io, "reaching");
    defer gpa.free(at);
    defer forget(io, at);
    const initrd = try initramfs(gpa, io, at);
    defer gpa.free(initrd);
    const socket = try std.fmt.allocPrint(gpa, "{s}/control", .{at});
    defer gpa.free(socket);

    // No network of its own. The guest holds no address and has nothing to resolve a name with, which
    // is what makes the name the only thing that can cross.
    var held = try session.Client.start(gpa, io, .{
        .program = options.mirage_path,
        .socket = socket,
        .kernel = options.kernel_path,
        .initrd = initrd,
        .cpus = options.cpus,
        .boot_ms = 15_000,
        .console = .{ .file = try console(io, at) },
    });
    defer held.stop();
    errdefer showConsole(io, gpa, at);

    const control = try held.channel(session.wire.control_port);
    defer session.socket.close(control);

    var buffer: [256]u8 = undefined;
    _ = try expect(control, &buffer);
    try sendAll(control, "stay\n");
    const staying = try expect(control, &buffer);
    try std.testing.expect(std.mem.indexOf(u8, staying, "staying") != null);

    try sendAll(control, "reach example.com 443\n");

    // The name arrives here, with the port and nothing else. Nothing has been resolved and nothing
    // has been opened: that is this end's to do, which is why the guest cannot be handed elsewhere.
    var question: ?session.Client.Reaching = null;
    var left: u64 = 10_000;
    while (left > 0 and question == null) : (left -= 20) {
        if (try held.take()) |said| {
            // The name comes as a value and not as a pointer into a buffer, so holding it while a
            // decision is made, which can take as long as asking a person takes, is safe.
            if (said == .reaching) question = said.reaching;
            continue;
        }
        session.socket.waitFor(held.descriptor(), 20);
    }

    const asked = question orelse return error.TheGuestWasNotHeard;
    try std.testing.expectEqualSlices(u8, "example.com", asked.name());
    try std.testing.expectEqual(@as(u16, 443), asked.port);

    // A pair of descriptors stands in for a connection to that name. What matters is that the guest
    // reads what comes out of something this end opened, and never learns where it went.
    const pair = try session.socket.pair();
    defer session.socket.close(pair[0]);
    _ = try session.socket.write(pair[0], "the far end answered\n");
    try held.allow(asked, pair[1]);
    session.socket.close(pair[1]);

    // The guest read it off its own stream and said so back here.
    const echoed = try expect(control, &buffer);
    try std.testing.expect(std.mem.indexOf(u8, echoed, "the far end answered") != null);
}

test "a share offered while the guest runs appears, and a withdrawn one is gone" {
    if (options.kernel_path.len == 0 or !options.share) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const at = try workspace(gpa, io, "percall");
    defer gpa.free(at);
    defer forget(io, at);
    const initrd = try initramfs(gpa, io, at);
    defer gpa.free(initrd);
    const socket = try std.fmt.allocPrint(gpa, "{s}/control", .{at});
    defer gpa.free(socket);

    // Started with one directory, because a guest with none is given no filesystem at all and has
    // nothing to see a new name in.
    const first = try offering(gpa, io, at);
    defer gpa.free(first);

    var held = try session.Client.start(gpa, io, .{
        .program = options.mirage_path,
        .socket = socket,
        .kernel = options.kernel_path,
        .initrd = initrd,
        .port = 1024,
        .share = .{ .name = "store", .at = first },
        .boot_ms = 15_000,
        .console = .{ .file = try console(io, at) },
    });
    defer held.stop();
    errdefer showConsole(io, gpa, at);

    const control = try held.channel(session.wire.control_port);
    defer session.socket.close(control);

    var buffer: [256]u8 = undefined;
    _ = try expect(control, &buffer);
    try sendAll(control, "stay\n");
    _ = try expect(control, &buffer);

    // A second directory, made now and offered now. This is the shape a harness needs: what a piece of
    // work may reach is decided when the work starts, not when the guest booted.
    const second = try std.fmt.allocPrint(gpa, "{s}/secret", .{at});
    defer gpa.free(second);
    try std.Io.Dir.cwd().createDir(io, second, .default_dir);
    var name: [256]u8 = undefined;
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = try std.fmt.bufPrint(&name, "{s}/hello", .{second}),
        .data = "for this one call only\n",
    });

    try held.share("secret", second, false);

    // The guest reads it without mounting anything: it is a name in what it already mounted.
    try sendAll(control, "read secret\n");
    const inside = try expect(control, &buffer);
    try std.testing.expect(std.mem.indexOf(u8, inside, "for this one call only") != null);

    // Taken back. The name goes, and a guest that reads again finds nothing there, which is what a
    // secret bound for one piece of work has to do when that work is over.
    try held.unshare("secret");
    try sendAll(control, "read secret\n");
    const after = try expect(control, &buffer);
    try std.testing.expect(std.mem.indexOf(u8, after, "for this one call only") == null);
    try std.testing.expect(std.mem.indexOf(u8, after, "nothing") != null);

    // The one it started with is still there, so withdrawing one said nothing about the others.
    try sendAll(control, "read store\n");
    const still = try expect(control, &buffer);
    try std.testing.expect(std.mem.indexOf(u8, still, shared_contents[0 .. shared_contents.len - 1]) != null);
}

test "a guest that powers itself off says so, and is not a fault" {
    if (options.kernel_path.len == 0) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const at = try workspace(gpa, io, "ending");
    defer gpa.free(at);
    defer forget(io, at);
    const initrd = try initramfs(gpa, io, at);
    defer gpa.free(initrd);
    const socket = try std.fmt.allocPrint(gpa, "{s}/control", .{at});
    defer gpa.free(socket);

    var held = session.Client.start(gpa, io, .{
        .program = options.mirage_path,
        .socket = socket,
        .kernel = options.kernel_path,
        .initrd = initrd,
        .port = 1024,
        .cpus = options.cpus,
        .boot_ms = 15_000,
        .console = .{ .file = try console(io, at) },
    }) catch |err| {
        std.debug.print("start said {t}\n", .{err});
        showConsole(io, gpa, at);
        return err;
    };
    defer held.stop();
    errdefer showConsole(io, gpa, at);

    const stream = try held.channel(1024);
    defer session.socket.close(stream);

    var buffer: [128]u8 = undefined;
    _ = try expect(stream, &buffer);
    try sendAll(stream, "stay\n");
    _ = try expect(stream, &buffer);

    // Told to stop, this guest leaves its loop and powers itself off. That is work that finished,
    // and a harness reports it differently from a guest that faulted or ran out of room, so the
    // difference has to survive a real guest ending rather than only a unit test.
    try sendAll(stream, "stop\n");

    var went: ?session.Client.Lost = null;
    var left: u64 = 30_000;
    while (left > 0 and went == null) {
        if (try held.take()) |said| switch (said) {
            .lost => |how| went = how,
            else => {},
        };
        session.socket.waitFor(held.descriptor(), 20);
        left -= @min(left, 20);
    }

    try std.testing.expectEqual(session.Client.Lost.powered_off, went orelse {
        std.debug.print("the guest never said it had gone\n", .{});
        showConsole(io, gpa, at);
        return error.TestExpectedEqual;
    });
    try std.testing.expect(held.gone);
}
