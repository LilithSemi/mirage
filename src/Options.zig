//! What a caller asks for when it runs a guest, and how those words are read.
//!
//! One file because there is more than one runner: this machine's hypervisor is not the same on
//! every system, and what a caller may ask for is the same on all of them.

const std = @import("std");

pub const usage =
    \\mirage <command> [options]
    \\
    \\  probe                 report what this machine can do
    \\  run --kernel <path>   run a guest
    \\  pack <dir> <out>      build an initial filesystem from a directory
    \\  seal <dir> <out>      build a read only root with a hash tree over it
    \\
    \\run options:
    \\  --kernel <path>       the kernel image, required
    \\  --initrd <path>       an initial filesystem
    \\  --disk <path>         a disk for the guest to see
    \\  --cmdline <string>    the kernel command line
    \\  --memory <megabytes>  guest memory, 512 by default
    \\  --exits <count>       give up after this many exits
    \\  --vsock <port>        listen on this port for the guest to connect
    \\  --seconds <count>     give up after this long
    \\  --tick <ms>           how often to take the cpu back, 10 by default, 0 for never
    \\  --cpus <count>        how many cpus the guest has, 1 by default
    \\  --memory-limit <mb>   let the memory grow to this, or `max` for the machine's
    \\  --nat yes             give the guest a network of this vmm's own, with no helper
    \\  --net <path>          reach the network through a helper listening here
    \\  --net-fd <number>     reach it through a descriptor already connected to one
    \\  --save <path>         write everything the guest holds when the run ends
    \\  --restore <path>      start from that instead of from a kernel
    \\  --manifest yes        list what was measured, in the order it was measured
    \\  --firmware <path>     start this instead of a kernel, from the bottom of memory
    \\  --firmware-at <addr>  where to place it, 0 by default
    \\  --firmware-room <mb>  how much room to give it, 64 by default
    \\  --root-hash <hex>     the hash tree root of the root filesystem, measured by name
    \\  --tpm <path>          a socket a security chip is listening on
    \\  --share <name>=<dir>  offer that directory under that name, read only
    \\  --share <n>=<dir>:write  offer it and let the guest change what is in it
    \\  --session <path>      hold the guest up for whoever connects here
    \\
;

const Options = @This();

kernel: []const u8 = &.{},
initrd: ?[]const u8 = null,
disk: ?[]const u8 = null,
cmdline: []const u8 = "console=ttyAMA0 earlycon=pl011,0x9000000",
memory: u64 = 512,
/// Give up after this many exits. A guest that spins is a guest that never comes
/// back, and a tool that never returns has to be killed.
exits: u64 = 200_000_000,
/// A port to listen on for the guest, or nothing for a guest with no channel.
vsock: ?u32 = null,
/// Give up after this many seconds. An exit count says nothing about how long a guest
/// has been wedged for, and this does.
seconds: ?u64 = null,
/// How often to take the CPU back so the devices can be served. Zero leaves the guest
/// alone, which is right when nothing has to reach it while it waits.
tick_ms: u64 = 10,
/// How many CPUs the guest has. The first is started here and the guest brings up the rest
/// itself, each on a thread of its own.
cpus: u32 = 1,
/// The most memory the guest may come to use, in megabytes. Given only when the caller
/// wants a guest that grows, and a guest without it has what it started with and no
/// device to change that. `max` means as much as this machine has free.
limit: ?Limit = null,
/// Whether the guest is given a network of this VMM's own instead of a helper. A caller with no
/// helper to start, which is every caller on a Mac, gets its network this way.
nat: bool = false,
/// Where the helper that carries the guest's traffic is. Whoever starts a guest starts the
/// helper, so a descriptor that is already connected is the usual way in, and a path is for
/// a person at a shell.
net: ?Helper = null,
/// Where to write everything the guest holds when the run ends.
save: ?[]const u8 = null,
/// Where to read it back from, instead of loading a kernel. The devices given have to be the
/// same ones the guest was stopped with, because a guest resumed with a device it did not have
/// is a guest reading a window that answers nothing.
restore: ?[]const u8 = null,
/// Whether to say what was measured, and not only what it came to. Whoever started the guest
/// records provenance, and it cannot record what it was not told.
show_manifest: bool = false,
/// Start firmware rather than a kernel. Firmware is placed where it was built to run, which for
/// the machines this resembles is the bottom of the address space, and it finds the device tree
/// at the start of memory.
firmware: ?[]const u8 = null,
/// Where the firmware is placed, and how much room it is given. Both belong to whoever built
/// it: a firmware that relocates itself, or probes its own flash, needs the window its own
/// machine would have rather than the size of its image.
firmware_at: u64 = 0,
firmware_room: u64 = 64 * 1024 * 1024,
/// The root of the hash tree over the root filesystem, as `seal` printed it. Measured under its
/// own name so a verifier need not find it inside the command line.
root_hash: ?[]const u8 = null,
/// A socket a program implementing the chip's commands is listening on. Whoever starts a guest
/// starts that program, the same way it starts the network helper.
tpm: ?[]const u8 = null,
/// Directories on this machine the guest is offered, each under a name. The guest mounts one
/// filesystem and sees a name for each of them, which is what lets the set change while it runs.
shares: [max_shares]Share = @splat(.{}),
share_count: usize = 0,

/// Where to bind the socket that holds this guest up for somebody else. A guest started this
/// way stays until whoever connects says to stop, or until the guest stops itself, which is
/// what a caller that runs many calls in one guest needs.
session: ?[]const u8 = null,

/// How many a caller may name at boot. A harness names its store, the place work happens, a cache, a
/// scratch area, somewhere to keep notes, and whatever a project binds, so the number is not small.
pub const max_shares = 16;

pub const Share = struct {
    name: []const u8 = &.{},
    at: []const u8 = &.{},
    /// Whether the guest may change what is in it. Off unless the caller said so: a share that is
    /// writable by accident is a guest changing what every later guest will read.
    writable: bool = false,
};

/// A real number of megabytes, or as much as the machine has.
pub const Limit = union(enum) { megabytes: usize, machine };

pub const Helper = union(enum) { path: []const u8, fd: std.posix.fd_t };

pub fn parse(args: []const [:0]const u8) !Options {
    var options: Options = .{};
    var gave_exits = false;
    var index: usize = 0;
    while (index < args.len) : (index += 2) {
        if (index + 1 >= args.len) return error.MissingValue;
        const name = args[index];
        const value = args[index + 1];

        if (std.mem.eql(u8, name, "--kernel")) {
            options.kernel = value;
        } else if (std.mem.eql(u8, name, "--initrd")) {
            options.initrd = value;
        } else if (std.mem.eql(u8, name, "--disk")) {
            options.disk = value;
        } else if (std.mem.eql(u8, name, "--cmdline")) {
            options.cmdline = value;
        } else if (std.mem.eql(u8, name, "--memory")) {
            options.memory = try std.fmt.parseInt(u64, value, 10);
        } else if (std.mem.eql(u8, name, "--exits")) {
            options.exits = try std.fmt.parseInt(u64, value, 10);
            gave_exits = true;
        } else if (std.mem.eql(u8, name, "--vsock")) {
            options.vsock = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, name, "--session")) {
            options.session = value;
        } else if (std.mem.eql(u8, name, "--share")) {
            // A name, a directory, and whether the guest may write to it. Said as `name=dir` or
            // `name=dir:write`, and given once per directory.
            if (options.share_count == max_shares) return error.TooManyShares;
            const split = std.mem.indexOfScalar(u8, value, '=') orelse return error.MissingValue;
            var at: []const u8 = value[split + 1 ..];
            var writable = false;
            if (std.mem.lastIndexOfScalar(u8, at, ':')) |mark| {
                if (std.mem.eql(u8, at[mark + 1 ..], "write")) {
                    writable = true;
                    at = at[0..mark];
                }
            }
            options.shares[options.share_count] = .{
                .name = value[0..split],
                .at = at,
                .writable = writable,
            };
            options.share_count += 1;
        } else if (std.mem.eql(u8, name, "--seconds")) {
            options.seconds = try std.fmt.parseInt(u64, value, 10);
        } else if (std.mem.eql(u8, name, "--tick")) {
            options.tick_ms = try std.fmt.parseInt(u64, value, 10);
        } else if (std.mem.eql(u8, name, "--nat")) {
            options.nat = std.mem.eql(u8, value, "yes");
        } else if (std.mem.eql(u8, name, "--cpus")) {
            options.cpus = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, name, "--tpm")) {
            options.tpm = value;
        } else if (std.mem.eql(u8, name, "--root-hash")) {
            options.root_hash = value;
        } else if (std.mem.eql(u8, name, "--firmware-at")) {
            options.firmware_at = try std.fmt.parseInt(u64, value, 0);
        } else if (std.mem.eql(u8, name, "--firmware-room")) {
            options.firmware_room = try std.fmt.parseInt(u64, value, 0) * 1024 * 1024;
        } else if (std.mem.eql(u8, name, "--firmware")) {
            options.firmware = value;
        } else if (std.mem.eql(u8, name, "--manifest")) {
            options.show_manifest = std.mem.eql(u8, value, "yes");
        } else if (std.mem.eql(u8, name, "--save")) {
            options.save = value;
        } else if (std.mem.eql(u8, name, "--restore")) {
            options.restore = value;
        } else if (std.mem.eql(u8, name, "--net")) {
            options.net = .{ .path = value };
        } else if (std.mem.eql(u8, name, "--net-fd")) {
            options.net = .{ .fd = try std.fmt.parseInt(std.posix.fd_t, value, 10) };
        } else if (std.mem.eql(u8, name, "--memory-limit")) {
            options.limit = if (std.mem.eql(u8, value, "max"))
                .machine
            else
                .{ .megabytes = try std.fmt.parseInt(usize, value, 10) };
        } else {
            return error.UnknownOption;
        }
    }

    // A guest held up for somebody else runs for as long as they are there, which is hours and
    // not a number of exits anybody would write down. An exit ceiling is for a guest nobody is
    // watching, so a session raises it unless the caller asked for one of its own.
    if (options.session != null and !gave_exits) options.exits = std.math.maxInt(u64);
    return options;
}

/// Whether what the caller asked for cannot be done, said in words. True means it was said and
/// nothing should be started.
///
/// Here rather than in a runner because the rules are the same wherever a guest runs, and a rule
/// written twice is a rule that will be enforced once.
pub fn complain(self: Options, out: *std.Io.Writer, cpu_room: u64) !bool {
    if (self.kernel.len == 0 and self.restore == null and self.firmware == null) {
        try out.writeAll("a kernel is required\n\n");
        try out.writeAll(usage);
        return true;
    }
    if (self.cpus == 0) {
        try out.writeAll("a guest has at least one cpu\n");
        return true;
    }
    // A session reaches by name: the guest asks for one, whoever holds the session decides and hands
    // back a connection already made. A network of the guest's own is a second way out that answers
    // to nobody, and a guest with both has a door that is watched and a door that is not.
    if (self.session != null and (self.nat or self.net != null)) {
        try out.writeAll("a guest held up for somebody else reaches by name, so it gets no network of its own\n");
        return true;
    }
    // Each CPU gets a piece of the interrupt controller of its own, and they have to fit below the
    // guest's memory. This is in the thousands, so it is here to be told rather than to be met.
    for (self.shares[0..self.share_count]) |shared| {
        if (shared.name.len == 0 or shared.at.len == 0) {
            try out.writeAll("a share is a name and a directory, written as name=directory\n");
            return true;
        }
        // Opened by whole path on this side: a guest is started from wherever the caller happened to
        // be, and a relative path would mean somewhere else by the time it is read.
        if (shared.at[0] != '/') {
            try out.writeAll("a shared directory is named by its whole path\n");
            return true;
        }
    }
    if (self.cpus > cpu_room) {
        try out.print("the machine this describes has room for {d} cpus\n", .{cpu_room});
        return true;
    }
    return false;
}
