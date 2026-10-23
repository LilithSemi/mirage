//! The Glacier card as a pci endpoint: the Harbor engine behind the first region, the table a
//! driver reads the rest of the card out of, and the fabric memory the engine moves words to and
//! from.
//!
//! Nothing here raises an interrupt. A driver starts a transfer and reads the status until done is
//! set, which is what both the kernel module and the firmware driver do, so the engine finishes
//! inside the write that starts it and busy is never seen set.
//!
//! The register and table layouts come from the card's own headers rather than from anything
//! chosen here, so a driver written against the hardware reads the same words from this.

const std = @import("std");
const Bus = @import("Bus.zig");
const PciHost = @import("PciHost.zig");
const Settings = @import("Settings.zig");
const GuestMemory = @import("mirage-memory").GuestMemory;
const testing = @import("mirage-testing");

const Glacier = @This();

/// One compute core, which a host loads a program into and launches. A build may carry several,
/// and the table says where each window went.
pub const Core = @import("glacier/Core.zig");

/// What the card reports in config space. Read off the generated hardware for
/// `chenega_v1_ax7203`, so these are facts and not intent.
pub const vendor: u16 = 0x10ee;
pub const model: u16 = 0x7203;
pub const class: u8 = 0x03;
pub const subclass: u8 = 0x80;

/// The register block is one page, and the device table sits in the same page above the engine.
pub const registers_size = 0x1000;

/// How large the expansion rom is on the real card.
pub const rom_size = 0x4_0000;

/// Which region holds the window onto the fabric. The card's own choice: the kernel module
/// defines it as two, so a driver looks there and nowhere else.
pub const window_region = 2;

/// The prototype aperture: this much fabric from this address.
///
/// Not a shipping number. The kernel module wants that window for an allocator rather than for one
/// frame buffer, so the real aperture is larger and may want sixty four bits. Nothing in the model
/// or the bridge assumes a size, which is why these two are here and not inside either.
pub const prototype_window_at = 0x8000_0000;
pub const prototype_window_size = 0x20_0000;

/// The prototype mode, and where the block that reports it sits: past the window, so a guest
/// painting its frame buffer cannot write over the registers that describe it.
pub const prototype_display_at = prototype_window_at + prototype_window_size;

/// Where the block that reports allocatable memory sits, past the display block, and the pool it
/// reports: the fabric above the prototype frame buffer, which needs 0x12c000 of the window. A
/// driver builds its allocator over this, so a pool that overlapped the frame buffer would hand
/// out memory something else is already painting.
pub const prototype_pool_at = prototype_display_at + 0x1000;
pub const prototype_pool: Pool = .{
    .at = prototype_window_at + 0x14_0000,
    .len = prototype_window_size - 0x14_0000,
};

/// The window, and a page each for the two register blocks past it.
pub const prototype_fabric_size = prototype_window_size + 0x2000;

/// Where a core window sits. Every board puts it here, and the card keeps nothing in the fabric
/// behind it, so a window this far from the rest needs no memory to answer with.
pub const core_window_at = 0x1001_0000;

/// What the engine answers at the first word. A driver that reads anything else has found a
/// different card.
pub const id: u32 = 0x48444d41;

/// What the hard block in this build reports, from its generated parameters rather than from the
/// module's name: the largest payload the function can take, and a link of one lane at two and a
/// half gigatransfers a second.
///
/// The speed is worth more than a constant. One lane at that rate carries about two hundred
/// megabytes a second after encoding, which is where the board's memory already sits, so the link
/// and the memory run out together. A model that claimed five would report twice the budget the
/// card has, and an aperture sized against that number would be sized against nothing.
const max_payload: u3 = 1;
const link_speed: u4 = 1;
const link_width: u6 = 1;
/// The low power state the link supports, which is L0s and not L1.
const link_aspm: u2 = 1;

/// The engine's registers, as byte offsets into the first region. Harbor decodes them by word
/// index; a driver uses byte offsets, and these are those.
const reg = struct {
    const id = 0x00;
    /// Write only. Reads answer zero.
    const control = 0x04;
    /// Read only. The engine owns every bit of it.
    const status = 0x08;
    const host_low = 0x0c;
    const host_high = 0x10;
    const local_low = 0x14;
    const local_high = 0x18;
    /// In words rather than bytes, and so is `completed`.
    const length = 0x1c;
    const completed = 0x20;
    const data = 0x24;
    const error_code = 0x28;
};

/// Start a transfer, and only when busy is clear. The engine here finishes inside the write, so
/// busy is never set and a start is never refused for it.
const control_start: u32 = 1 << 0;
/// Clear done, the error and the error code without starting anything. What a driver writes
/// before it sets a transfer up.
const control_clear: u32 = 1 << 1;
/// Set means device to host.
const control_to_host: u32 = 1 << 2;

const status_busy: u32 = 1 << 0;
const status_done: u32 = 1 << 1;
const status_failed: u32 = 1 << 2;
/// The direction of the transfer that ran, not the one that is about to.
const status_to_host: u32 = 1 << 3;

/// What the engine puts in the error code. Two of these are faults on the wire between the card
/// and the fabric, which nothing in a model can produce: a completion with a bad status, and a
/// completion of the wrong type. The host access failing is the nearest thing a model has to the
/// first, because a word the engine could not place is a completion that did not come back.
pub const Failure = enum(u8) {
    none = 0,
    completion_status = 1,
    completion_type = 2,
    zero_length = 4,
    fabric = 5,
};

/// Where the device table sits in the first region, and how it is laid out.
pub const table_at = 0x100;
const table_id: u32 = 0x47444556;
const table_version: u32 = 1;
/// Entries start here, counted from the start of the table, and are this far apart. The stride is
/// in the header, so a driver reads it rather than assuming it.
const entries_at = 0x40;
const entry_stride = 0x10;

/// The window onto the fabric, as the table names it.
pub const window_kind: u32 = 0x5744574e;

/// The allocatable memory block, as the table names it and as the block answers at its own first
/// word. A build with nothing left over leaves it out, and a driver that finds no entry has no
/// memory to hand out rather than a fault to report.
pub const memory_kind: u32 = 0x474d454d;
pub const memory_version: u32 = 1;

/// Where the ranges start inside the memory block, and how far apart they are. The stride is in
/// the block's header because a driver reads it rather than assuming it.
const ranges_at = 0x40;
const range_stride = 0x10;

/// Bit zero of a range's flags: whether a driver may hand the range out. A range without it is
/// memory the card keeps for itself.
const range_usable: u32 = 1;

/// Memory the card has left over, which a driver hands out to whoever asks. The frame buffers and
/// the card's own scratch are already taken out of this, so every byte of it is free.
pub const Pool = struct {
    at: u64,
    len: u64,
};

/// The display block, as the table names it. The block answers the same fourcc at its own first
/// word, and a driver that reads anything else there has found no display block.
pub const display_kind: u32 = 0x47444953;
pub const display_version: u32 = 1;

/// Where the displays start inside the block, and how far apart they are. The stride is in the
/// block's header because a driver reads it rather than assuming it.
const displays_at = 0x40;
const display_stride = 0x40;

/// The two pixel formats a driver takes. Anything else it refuses rather than paint wrongly.
pub const xr24: u32 = 0x34325258;
pub const ar24: u32 = 0x34325241;

/// What a display says it can drive, and what it says is there. A driver with neither output bit
/// set reports DVI rather than refusing.
pub const caps_hdmi: u32 = 1 << 0;
pub const caps_dvi: u32 = 1 << 1;
/// There is an EDID to read over the sideband controller.
pub const caps_edid: u32 = 1 << 2;
pub const status_hotplug: u32 = 1 << 0;

/// One display, as its registers report it. The geometry is the caller's to state: a model that
/// invented it would be a card nobody built.
pub const Display = struct {
    width: u32,
    height: u32,
    /// Bytes per row, which is at least four times the width and may be more. The padding of the
    /// last row is inside what a frame buffer needs, so a window sized to width times four times
    /// height is too small whenever there is padding.
    pitch: u32,
    /// Where the frame buffer sits in the fabric.
    framebuffer: u64,
    format: u32 = xr24,
    caps: u32 = 0,
    status: u32 = 0,
    /// Hertz of the dot clock the mode needs. A driver may refuse a mode whose clock is zero,
    /// because no board can make one.
    pixel_clock: u32 = 0,
    /// The sideband controller, or zero where the board routes no pins for one.
    ddc: u32 = 0,
};

/// Six hundred and forty by four hundred and eighty, four bytes a pixel, at the bottom of the
/// window. A prototype mode like the window it sits in, and small enough that the frame buffer is
/// a long way inside a two megabyte aperture.
pub const prototype_display: Display = .{
    .width = 640,
    .height = 480,
    .pitch = 2560,
    .framebuffer = prototype_window_at,
    // The VESA dot clock for this mode at sixty hertz. A real number because a driver is right to
    // refuse a mode that asks a board for no clock at all.
    .pixel_clock = 25_175_000,
};

/// One entry of the device table. Every field is thirty two bits, which is what bounds the fabric
/// addresses a card can describe.
pub const Entry = struct {
    kind: u32,
    base: u32,
    size: u32,
    /// An instance number and a storage bit for the entry kinds that need them. A window needs
    /// neither.
    info: u32 = 0,
};

/// The aperture onto the fabric, where the card was built with one.
///
/// The region and the table entry are both derived from this, so what a driver reads in the table
/// and what the bridge decodes for the region cannot differ.
pub const Aperture = struct {
    /// The fabric address the region starts at.
    at: u64,
    /// How much fabric it covers, which is also how large the region is. Harbor confirmed the two
    /// are the same size, with no alias and no hole.
    len: u64,
    /// Whether the region is sixty four bits wide. A window larger than the low memory window has
    /// to be, and a prototype that fits below four gigabytes need not be.
    wide: bool = false,
};

/// What the card was asked to do, as it happens.
///
/// A counter says how much; this says what, in order, which is what a test on the other side reads
/// to say the driver did the right things rather than merely enough of them.
pub const Event = union(enum) {
    transfer: Transfer,
    mode: Mode,

    /// One run of the engine, after it finished. The address and the length are what the driver
    /// asked for, and the count is how far it got, so a refused transfer says both.
    pub const Transfer = struct {
        to_host: bool,
        host: u64,
        local: u64,
        words: u32,
        moved: u32,
        failure: Failure,
    };

    /// A mode asked of a display, which only firmware calling the driver can bring about.
    pub const Mode = struct {
        display: usize,
        value: u32,
    };
};

/// Whoever is writing down what the card did. Nothing here keeps the events: a watcher is given
/// each one as it happens and decides for itself what to do with it.
pub const Watcher = struct {
    ctx: *anyopaque,
    saw: *const fn (ctx: *anyopaque, what: Event) void,
};

/// What a card was built with: the aperture onto its fabric, the mode it reports, the memory a
/// driver may hand out, and the core behind all of it.
///
/// Glacier describes a board in `devices.nix`, one line for each block the fabric carries. This is
/// that description as one value, so a caller can ask for a board that exists or for one nobody
/// has built, and the model holds no board of its own. Every address the card answers with is
/// placed from here, which is why a runner and a test cannot place them differently.
pub const Build = struct {
    /// The window onto the fabric, which is also the region a guest sees.
    window: Aperture = .{ .at = prototype_window_at, .len = prototype_window_size },
    /// The one mode the card reports, or nothing for a build with no display.
    display: ?Display = null,
    /// The memory a driver may hand out, or nothing for a build with none left over.
    pool: ?Pool = null,
    /// The core, or nothing for a build without one.
    core: ?Core.Shape = null,
    /// Where the core's window sits in the fabric. Nowhere near the aperture on any board, because
    /// a core's registers and a frame buffer are not near each other.
    core_at: u64 = core_window_at,

    /// A page for the block that reports the mode and a page for the block that reports the
    /// memory, both past the window so a guest painting the frame buffer cannot write over what
    /// describes it.
    pub const blocks_size = 0x2000;

    /// What this runner has carried from the start: two megabytes of window at 640x480. Smaller
    /// than any board, and the card the boot gates hold a driver against.
    pub const prototype: Build = .{
        .window = .{ .at = prototype_window_at, .len = prototype_window_size },
        .display = prototype_display,
        .pool = prototype_pool,
        .core = Core.gc1mi,
    };

    /// `chenega-v1-ax7203`, as `devices.nix` writes it: thirty two megabytes of window into the
    /// board's gigabyte of dram, and the mode its parallel rgb output drives. The raster block the
    /// board carries is left out, because nothing models one yet.
    pub const ax7203: Build = .{
        .window = .{ .at = 0x8000_0000, .len = 32 * 1024 * 1024 },
        .display = .{
            .width = 1024,
            .height = 768,
            .pitch = 1024 * 4,
            .framebuffer = 0x8000_0000,
            // The VESA dot clock for this mode at sixty hertz.
            .pixel_clock = 65_000_000,
        },
        .pool = .{ .at = 0x8030_0000, .len = 32 * 1024 * 1024 - 0x30_0000 },
        .core = Core.gc1mi,
    };

    /// The board of this name. `prototype` is this runner's own card, and the rest are spelled the
    /// way `devices.nix` spells them.
    pub fn named(name: []const u8) ?Build {
        const every = [_]struct { []const u8, Build }{
            .{ "prototype", prototype },
            .{ "chenega-v1-ax7203", ax7203 },
        };
        for (every) |each| {
            if (std.mem.eql(u8, each[0], name)) return each[1];
        }
        return null;
    }

    /// How much memory the fabric needs: the window, and the two blocks past it.
    pub fn fabricSize(self: Build) u64 {
        return self.window.len + blocks_size;
    }

    /// Where the block that reports the mode sits, and where the one that reports the memory sits.
    pub fn displayAt(self: Build) u64 {
        return self.window.at + self.window.len;
    }

    pub fn poolAt(self: Build) u64 {
        return self.displayAt() + 0x1000;
    }

    /// Words of instruction aperture a core needs, and bytes of private scratch. The aperture is
    /// the same size whatever the profile; the scratch is a region for each resident warp.
    pub fn programWords(self: Build) usize {
        return if (self.core == null) 0 else Core.max_program_words;
    }

    pub fn scratchBytes(self: Build) usize {
        const shape = self.core orelse return 0;
        return @as(usize, shape.warps) * shape.scratch_per_warp;
    }

    /// Where the private scratch is reported, which is the first address past the fabric.
    ///
    /// A board carves the scratch out of the top of its dram, which the window does not cover, so
    /// an address past the fabric is where the hardware keeps it and nothing on the window can
    /// reach it. A kernel reads this from `mscratch` rather than assuming it.
    pub fn scratchAt(self: Build) u64 {
        return self.window.at + self.fabricSize();
    }

    /// The memory this build has left over: the window above the frame buffer, to the page. A
    /// build whose mode fills the window has none, and neither has one whose frame buffer the
    /// window does not reach.
    pub fn spare(self: Build) ?Pool {
        const end = self.window.at + self.window.len;
        var from = self.window.at;
        if (self.display) |shown| {
            if (shown.framebuffer < self.window.at) return null;
            const rows = @as(u64, shown.pitch) * shown.height;
            from = std.mem.alignForward(u64, shown.framebuffer + rows, 0x1000);
        }
        if (from >= end) return null;
        return .{ .at = from, .len = end - from };
    }

    /// What a card needs that a shape cannot carry: the guest's memory, and the memory a runner
    /// allocated for the card's own blocks.
    pub const Parts = struct {
        memory: *GuestMemory,
        /// `fabricSize()` bytes.
        fabric: []u8,
        /// `programWords()` words and `scratchBytes()` bytes, for a build with a core.
        program: []u32 = &.{},
        scratch: []u8 = &.{},
        rom: []const u8 = &.{},
        watching: ?Watcher = null,
        /// Whoever runs the words of a kernel, and the room it made for the state every warp of it
        /// keeps. A card with no engine answers its registers and runs nothing.
        engine: ?Core.Engine = null,
        room: []u8 = &.{},
    };

    /// The card this build describes.
    pub fn card(self: Build, parts: Parts) Glacier {
        return .{
            .memory = parts.memory,
            .watching = parts.watching,
            .fabric = parts.fabric,
            .fabric_at = self.window.at,
            .aperture = self.window,
            .display = self.display,
            .display_at = self.displayAt(),
            .pool = self.pool,
            .pool_at = self.poolAt(),
            .core = if (self.core) |shape| .{
                .shape = shape,
                .program = parts.program,
                .scratch = parts.scratch,
                .engine = parts.engine,
                .room = parts.room,
            } else null,
            .core_at = self.core_at,
            .rom = parts.rom,
        };
    }

    pub const Error = error{
        UnknownBoard,
        UnknownCore,
        UnknownFormat,
        UnknownOutput,
        BadNumber,
        BadResolution,
        BadPitch,
        BadWindow,
        BadCoreShape,
        BadScratch,
        WindowTooLarge,
        WindowTooSmall,
        PoolOutside,
        PoolPainted,
        TooManyWarps,
        CoreInWindow,
    };

    /// A card written the way a caller writes one: a board to start from, then what to change
    /// about it. `board=chenega-v1-ax7203,res=800x600,core=gc1.f` is a board with another mode and
    /// a wider core.
    ///
    /// A caller who moves the window or the mode and says nothing about the memory to hand out
    /// gets the fabric above the frame buffer, because the board's own pool was placed for the
    /// board's own mode.
    pub fn parse(settings: []const u8) Error!Build {
        var self: Build = prototype;
        if (Settings.get(settings, "board")) |name| {
            self = named(name) orelse return error.UnknownBoard;
        }

        self.window.at = try Settings.numberOr(settings, "window", self.window.at);
        self.window.len = try Settings.numberOr(settings, "windowsize", self.window.len);
        self.window.wide = Settings.flag(settings, "wide", self.window.wide);

        if (Settings.get(settings, "res")) |said| {
            if (std.mem.eql(u8, said, "none")) {
                self.display = null;
            } else {
                const split = std.mem.indexOfScalar(u8, said, 'x') orelse return error.BadResolution;
                const across = try Settings.number(said[0..split]);
                const down = try Settings.number(said[split + 1 ..]);
                if (across == 0 or down == 0 or across > 0xffff or down > 0xffff) return error.BadResolution;
                // Everything the board said about its display but the geometry stays: a caller
                // asking for another mode is asking for the same wires to carry it.
                var shown: Display = self.display orelse .{
                    .width = 0,
                    .height = 0,
                    .pitch = 0,
                    .framebuffer = self.window.at,
                };
                shown.width = @intCast(across);
                shown.height = @intCast(down);
                // A row of this mode with no padding. `pitch` is how a caller asks for some.
                shown.pitch = @intCast(across * 4);
                self.display = shown;
            }
        }
        if (self.display) |*shown| {
            shown.framebuffer = try Settings.numberOr(settings, "fb", shown.framebuffer);
            const pitch = try Settings.numberOr(settings, "pitch", shown.pitch);
            if (pitch > std.math.maxInt(u32)) return error.BadPitch;
            shown.pitch = @intCast(pitch);
            const clock = try Settings.numberOr(settings, "clock", shown.pixel_clock);
            if (clock > std.math.maxInt(u32)) return error.BadNumber;
            shown.pixel_clock = @intCast(clock);
            const ddc = try Settings.numberOr(settings, "ddc", shown.ddc);
            if (ddc > std.math.maxInt(u32)) return error.BadNumber;
            shown.ddc = @intCast(ddc);

            if (Settings.get(settings, "format")) |said| {
                if (std.mem.eql(u8, said, "xr24")) {
                    shown.format = xr24;
                } else if (std.mem.eql(u8, said, "ar24")) {
                    shown.format = ar24;
                } else return error.UnknownFormat;
            }
            if (Settings.get(settings, "out")) |said| {
                shown.caps &= ~(caps_hdmi | caps_dvi);
                if (std.mem.eql(u8, said, "hdmi")) {
                    shown.caps |= caps_hdmi;
                } else if (std.mem.eql(u8, said, "dvi")) {
                    shown.caps |= caps_dvi;
                } else if (!std.mem.eql(u8, said, "rgb") and !std.mem.eql(u8, said, "parallelRgb")) {
                    return error.UnknownOutput;
                }
            }
            if (Settings.flag(settings, "edid", shown.caps & caps_edid != 0)) {
                shown.caps |= caps_edid;
            } else {
                shown.caps &= ~caps_edid;
            }
            if (Settings.flag(settings, "hotplug", shown.status & status_hotplug != 0)) {
                shown.status |= status_hotplug;
            } else {
                shown.status &= ~status_hotplug;
            }
        }

        const said_at = Settings.get(settings, "pool");
        const said_len = Settings.get(settings, "poolsize");
        if (said_at) |said| {
            if (std.mem.eql(u8, said, "none")) {
                self.pool = null;
            } else {
                const at = try Settings.number(said);
                const end = self.window.at + self.window.len;
                self.pool = .{
                    .at = at,
                    .len = if (said_len) |much| try Settings.number(much) else (end -| at),
                };
            }
        } else if (said_len) |much| {
            var each = self.pool orelse self.spare() orelse return error.PoolOutside;
            each.len = try Settings.number(much);
            self.pool = each;
        } else if (moved(settings)) {
            self.pool = self.spare();
        }

        if (Settings.get(settings, "core")) |name| {
            self.core = if (std.mem.eql(u8, name, "none"))
                null
            else
                Core.profile(name) orelse return error.UnknownCore;
        }
        if (self.core) |*shape| {
            shape.warps = try lane(settings, "warps", shape.warps);
            shape.lanes = try lane(settings, "lanes", shape.lanes);
            shape.width = try lane(settings, "width", shape.width);
            const scratch = try Settings.numberOr(settings, "scratch", shape.scratch_per_warp);
            if (scratch > std.math.maxInt(u32)) return error.BadScratch;
            shape.scratch_per_warp = @intCast(scratch);
            shape.perf = Settings.flag(settings, "perf", shape.perf);
            self.core_at = try Settings.numberOr(settings, "core-at", self.core_at);
        }

        try self.check();
        return self;
    }

    /// Whether the caller moved anything the board's own pool was placed around.
    fn moved(settings: []const u8) bool {
        for ([_][]const u8{ "window", "windowsize", "res", "fb", "pitch" }) |each| {
            if (Settings.get(settings, each) != null) return true;
        }
        return false;
    }

    fn lane(settings: []const u8, key: []const u8, unless: u8) Error!u8 {
        const value = try Settings.numberOr(settings, key, unless);
        if (value == 0 or value > std.math.maxInt(u8)) return error.BadCoreShape;
        return @intCast(value);
    }

    /// Whether this is a card someone could build. A caller gives the numbers, so every one of
    /// these is the caller being wrong and not the guest.
    pub fn check(self: Build) Error!void {
        // A region is a power of two and at least sixteen bytes, which is the bus and not a choice
        // made here.
        if (self.window.len < 16 or !std.math.isPowerOfTwo(self.window.len)) return error.BadWindow;
        // The table describes the card in thirty two bit fields, so a card placed where it cannot
        // be described is one nobody can build.
        if (self.window.at + self.fabricSize() > std.math.maxInt(u32)) return error.WindowTooLarge;

        if (self.display) |shown| {
            if (shown.width == 0 or shown.height == 0) return error.BadResolution;
            if (shown.pitch < @as(u64, shown.width) * 4) return error.BadPitch;
            if (shown.format != xr24 and shown.format != ar24) return error.UnknownFormat;
            if (shown.framebuffer < self.window.at) return error.WindowTooSmall;
            const offset = shown.framebuffer - self.window.at;
            if (offset >= self.window.len) return error.WindowTooSmall;
            if (@as(u64, shown.pitch) * shown.height > self.window.len - offset) return error.WindowTooSmall;
        }

        if (self.pool) |each| {
            if (each.len == 0 or each.at < self.window.at) return error.PoolOutside;
            if (each.at + each.len > self.window.at + self.window.len) return error.PoolOutside;
            if (self.display) |shown| {
                const rows = @as(u64, shown.pitch) * shown.height;
                if (each.at < shown.framebuffer + rows and shown.framebuffer < each.at + each.len) {
                    return error.PoolPainted;
                }
            }
        }

        if (self.core) |shape| {
            if (shape.warps == 0 or shape.warps > Core.max_warps) return error.TooManyWarps;
            if (shape.lanes == 0 or shape.width == 0) return error.BadCoreShape;
            // A narrow store on this core writes a whole word, so a spill slot is four bytes and a
            // warp's region has to start word aligned or one warp would write over another's.
            if (shape.scratch_per_warp == 0 or shape.scratch_per_warp % 4 != 0) return error.BadScratch;
            if (self.core_at < self.window.at + self.fabricSize() and
                self.window.at < self.core_at + Core.window_size) return error.CoreInWindow;
        }
    }

    /// What to tell a caller who asked for a card nobody can build. One sentence each: a caller
    /// wrote one setting wrongly, not a program.
    pub fn trouble(what: Error) []const u8 {
        return switch (what) {
            error.UnknownBoard => "no board is called that, and this models prototype and chenega-v1-ax7203",
            error.UnknownCore => "no core is called that, and the profiles are gc1.n, gc1.mi, gc1.s, gc1.f and gc1.ma",
            error.UnknownFormat => "a format is xr24 or ar24",
            error.UnknownOutput => "an output is hdmi, dvi or rgb",
            error.BadNumber => "a number is decimal, or hex behind 0x, with K, M or G after it",
            error.BadResolution => "a mode is written as 1024x768",
            error.BadPitch => "a row holds at least four bytes for each pixel",
            error.BadWindow => "a window is a power of two, and at least sixteen bytes",
            error.BadCoreShape => "a core has at least one warp, one lane and one lane of width",
            error.BadScratch => "scratch is a multiple of four bytes, because a narrow store writes a whole word",
            error.WindowTooLarge => "the card is described in thirty two bits, so the window and the two blocks past it fit below four gigabytes",
            error.WindowTooSmall => "the window does not cover every row of the frame buffer",
            error.PoolOutside => "the memory the card hands out sits inside the window",
            error.PoolPainted => "the memory the card hands out covers the frame buffer",
            error.TooManyWarps => "a core holds between one and sixteen warps",
            error.CoreInWindow => "the core's window lands inside the aperture",
        };
    }
};

watching: ?Watcher = null,

/// The host's memory. The engine moves words to and from it, and a word it cannot reach is
/// answered as a completion that did not come back.
memory: *GuestMemory,
/// The card's own memory, and the fabric address it starts at.
fabric: []u8,
fabric_at: u64 = 0,
aperture: ?Aperture = null,
/// The memory a driver may hand out, and where the block that reports it sits in the fabric. A
/// card built with nothing left over has neither, and its table names no memory block.
pool: ?Pool = null,
pool_at: u64 = 0,
/// The core, where the card was built with one, and where its window sits in the fabric. A host
/// reaches it over the engine rather than through the aperture, because the window the board gives
/// a core is nowhere near the one it gives a frame buffer.
core: ?Core = null,
core_at: u64 = 0,
/// The one display this card reports, where it has one. A card with none is a build with no
/// aperture to paint into, and a driver refuses it rather than publishing an address.
display: ?Display = null,
/// Where the display block sits in the fabric. The table carries this, and a driver reads the
/// block through the engine like everything else that is not config space.
display_at: u64 = 0,
/// The expansion rom image, or nothing for a card built without one.
rom: []const u8 = &.{},

host: u64 = 0,
local: u64 = 0,
length: u32 = 0,
completed: u32 = 0,
data: u32 = 0,
failure: Failure = .none,
done: bool = false,
/// Whether a transfer is in flight. The hardware gates a start on this and drops one silently
/// while it is set, so the model does too.
busy: bool = false,
to_host: bool = false,

/// How many transfers were started. Not a register: a test needs to tell a transfer that moved
/// nothing from one that never began.
transfers: u64 = 0,
/// Accesses that named fabric the card does not have. The guest chooses the address, so this is
/// counted rather than refused loudly.
strayed: u64 = 0,

/// Reads of the device table, and of the word that says it is a table at all. A driver that read
/// nothing here and worked anyway was using addresses it was built with rather than the ones this
/// card reports, which is passing for the wrong reason.
table_reads: u64 = 0,
table_found: u64 = 0,
/// Writes to a display's mode select. Only a driver that has published a frame buffer and been
/// asked to use it writes this, so it separates a driver that refused from one that was never
/// called.
mode_selects: u64 = 0,
/// Bytes written into the frame buffer by the card's own engine: the driver painting for itself.
painted: u64 = 0,
/// Bytes written into the frame buffer straight through the window, which is firmware or an
/// operating system painting into the address the driver published. The window exists for this,
/// so these two are counted apart: the first says the driver painted, the second says something
/// else could, and only the second says the published address was usable.
painted_through_window: u64 = 0,
/// Bytes the window served, wherever in the fabric they went. Counted beside the frame buffer
/// numbers because a zero here says nothing came through the window at all, which is a different
/// fault from something arriving somewhere nobody expected.
read_through_window: u64 = 0,
written_through_window: u64 = 0,
/// Bytes that landed in the aperture and not in the frame buffer, whichever way they came. The
/// pool sits there, so a driver writing into memory it was handed counts here and is doing nothing
/// wrong. Named for the frame buffer and not for the fabric, because the bytes are inside the
/// card's memory either way.
outside_framebuffer: u64 = 0,

/// What the bridge puts in config space for this card.
pub fn function(self: *Glacier, at: PciHost.Address) PciHost.Function {
    var one: PciHost.Function = .{
        .at = at,
        .vendor = vendor,
        .device = model,
        .class = class,
        .subclass = subclass,
        .subsystem_vendor = vendor,
        .subsystem_device = model,
        .handler = self.regions(),
        // The chain the hard block answers: power management, then message signalled interrupts,
        // then pci express. Every interrupt line is tied off, so a guest can enable messages and
        // nothing will ever arrive, and the model carries that rather than hiding it.
        .capabilities = .{
            .power_management = true,
            .msi = true,
            .express = .{
                .max_payload = max_payload,
                .speed = link_speed,
                .width = link_width,
                .aspm = link_aspm,
            },
        },
    };
    one.regions[0] = .{ .size = registers_size };
    if (self.aperture) |each| {
        // The table describes an aperture in thirty two bit fields, so a card placed where it
        // cannot be described is one nobody can build. The caller chose this, not the guest.
        std.debug.assert(each.at <= std.math.maxInt(u32));
        std.debug.assert(each.len <= std.math.maxInt(u32));
        one.regions[window_region] = .{ .size = each.len, .wide = each.wide, .prefetchable = true };
    }
    if (self.rom.len != 0) {
        one.rom_size = rom_size;
        one.rom = self.rom;
    }
    return one;
}

pub fn regions(self: *Glacier) PciHost.Regions {
    return .{ .ctx = self, .vtable = &.{ .read = Glacier.read, .write = Glacier.write } };
}

/// How many entries the table holds. A card with nothing to describe has no table at all, and a
/// window of zeros is what a driver reads as one.
fn entryCount(self: *const Glacier) usize {
    var count: usize = 0;
    if (self.aperture != null) count += 1;
    if (self.display != null) count += 1;
    if (self.pool != null) count += 1;
    if (self.core != null) count += 1;
    return count;
}

fn entryAt(self: *const Glacier, index: usize) ?Entry {
    var count: usize = 0;
    if (self.aperture) |each| {
        if (index == count) return .{
            .kind = window_kind,
            .base = @truncate(each.at),
            .size = @truncate(each.len),
        };
        count += 1;
    }
    if (self.display != null) {
        if (index == count) return .{
            .kind = display_kind,
            .base = @truncate(self.display_at),
            .size = displays_at + display_stride,
        };
        count += 1;
    }
    if (self.pool != null) {
        if (index == count) return .{
            .kind = memory_kind,
            .base = @truncate(self.pool_at),
            .size = ranges_at + range_stride,
        };
        count += 1;
    }
    if (self.core != null) {
        if (index == count) return .{
            .kind = Core.kind,
            .base = @truncate(self.core_at),
            .size = Core.window_size,
        };
        count += 1;
    }
    return null;
}

/// One word of the memory block, or nothing where the address is not inside it.
///
/// One range, because the card has one pool. A driver reads the count and the stride first, so a
/// card with more would answer here and need nothing else changed.
fn poolWord(self: *const Glacier, at: u64) ?u32 {
    const pool = self.pool orelse return null;
    if (at < self.pool_at) return null;
    const within = at - self.pool_at;
    if (within >= ranges_at + range_stride) return null;

    if (within < ranges_at) return switch (within) {
        0x00 => memory_kind,
        0x04 => memory_version,
        0x08 => 1,
        0x0c => range_stride,
        else => 0,
    };

    return switch (within - ranges_at) {
        0x00 => @truncate(pool.at),
        0x04 => @truncate(pool.len),
        0x08 => range_usable,
        else => 0,
    };
}

/// Whether an address is inside the core window, and how far into it.
fn withinCore(self: *const Glacier, at: u64) ?u64 {
    if (self.core == null) return null;
    if (at < self.core_at) return null;
    const within = at - self.core_at;
    if (within >= Core.window_size) return null;
    return within;
}

/// One word of the core window, or nothing where the address is not inside it. A read moves the
/// core on, because reading a counter captures its high half for the read that follows.
fn coreWord(self: *Glacier, at: u64) ?u32 {
    const within = self.withinCore(at) orelse return null;
    return self.core.?.read(within);
}

/// One word of the display block, or nothing where the address is not inside it.
///
/// Served from what the card is rather than written into the fabric, so the geometry a driver
/// reads cannot drift from the geometry the model has. These are registers: a write to one is not
/// a write to memory.
fn displayWord(self: *const Glacier, at: u64) ?u32 {
    const shown = self.display orelse return null;
    if (at < self.display_at) return null;
    const within = at - self.display_at;
    if (within >= displays_at + display_stride) return null;

    if (within < displays_at) return switch (within) {
        0x00 => display_kind,
        0x04 => display_version,
        // One display. A driver refuses a count of zero rather than looking anyway.
        0x08 => 1,
        0x0c => display_stride,
        // Enabled, by index. A display nothing enabled is one a driver passes over.
        0x10 => 1,
        // Nothing has underrun, because nothing here scans out.
        0x14 => 0,
        else => 0,
    };

    return switch (within - displays_at) {
        0x00 => shown.caps,
        0x08, 0x0c => 0,
        0x10 => shown.width,
        0x14 => shown.height,
        0x18 => shown.pixel_clock,
        0x1c => @truncate(shown.framebuffer),
        0x20 => shown.status,
        0x24 => shown.ddc,
        0x28 => shown.format,
        0x2c => shown.pitch,
        // The frame counter counts started frames. Nothing here scans out, so no frame has begun.
        0x30 => 0,
        else => 0,
    };
}

/// Whether the aperture covers every row of the frame buffer.
///
/// The same arithmetic firmware does before it publishes an address, so a card built with a window
/// one byte too small is caught here rather than by a guest reading rows that land outside the
/// region. The padding of the last row counts.
pub fn covers(self: *const Glacier) bool {
    const each = self.aperture orelse return false;
    const shown = self.display orelse return false;
    if (each.len == 0) return false;
    if (shown.framebuffer < each.at) return false;

    const offset = shown.framebuffer - each.at;
    if (offset >= each.len) return false;
    return @as(u64, shown.pitch) * shown.height <= each.len - offset;
}

fn tableWord(self: *const Glacier, within: u64) u32 {
    if (self.entryCount() == 0) return 0;
    switch (within) {
        0x00 => return table_id,
        0x04 => return table_version,
        0x08 => return @intCast(self.entryCount()),
        0x0c => return entry_stride,
        else => {},
    }
    if (within < entries_at) return 0;
    const from_entries = within - entries_at;
    const each = self.entryAt(@intCast(from_entries / entry_stride)) orelse return 0;
    return switch (from_entries % entry_stride) {
        0x00 => each.kind,
        0x04 => each.base,
        0x08 => each.size,
        0x0c => each.info,
        else => 0,
    };
}

fn statusWord(self: *const Glacier) u32 {
    var value: u32 = 0;
    if (self.done) value |= status_done;
    if (self.failure != .none) value |= status_failed;
    if (self.to_host) value |= status_to_host;
    return value;
}

fn registerWord(self: *Glacier, at: u64) u32 {
    if (at >= table_at) return self.tableWord(at - table_at);
    return switch (at) {
        reg.id => id,
        reg.status => self.statusWord(),
        reg.host_low => @truncate(self.host),
        reg.host_high => @truncate(self.host >> 32),
        reg.local_low => @truncate(self.local),
        reg.local_high => @truncate(self.local >> 32),
        reg.length => self.length,
        reg.completed => self.completed,
        reg.data => self.data,
        reg.error_code => @backingInt(self.failure),
        else => 0,
    };
}

fn read(ctx: *anyopaque, region: usize, offset: u64, size: Bus.Size) u64 {
    const self: *Glacier = @ptrCast(@alignCast(ctx));
    if (region == window_region) return self.windowRead(offset, size);
    if (region != 0) return 0;

    // One access, however many bytes it takes. A driver reads the table to learn where the rest of
    // the card is, and one that read nothing here was built with addresses of its own.
    if (offset >= table_at) {
        self.table_reads += 1;
        if (offset == table_at and self.entryCount() != 0) self.table_found += 1;
    }

    // A driver reads whole words and firmware reads whatever it likes, so an access of any width
    // at any offset is assembled from the words it covers.
    const bytes: u64 = @backingInt(size);
    var value: u64 = 0;
    for (0..bytes) |taken| {
        const at = offset + taken;
        const word = self.registerWord(at & ~@as(u64, 3));
        const byte: u64 = (word >> @intCast((at & 3) * 8)) & 0xff;
        value |= byte << @intCast(taken * 8);
    }
    return value;
}

fn write(ctx: *anyopaque, region: usize, offset: u64, size: Bus.Size, value: u64) void {
    const self: *Glacier = @ptrCast(@alignCast(ctx));
    if (region == window_region) return self.windowWrite(offset, size, value);
    if (region != 0) return;
    // The table is read only, and the engine decodes by word, so anything narrower or unaligned
    // reaches no register. The guest is allowed to be wrong.
    if (offset >= table_at) return;
    if (size != .word or offset % 4 != 0) return;

    const word: u32 = @truncate(value);
    switch (offset) {
        reg.control => self.start(word),
        reg.host_low => self.host = (self.host & 0xFFFF_FFFF_0000_0000) | word,
        reg.host_high => self.host = (@as(u64, word) << 32) | (self.host & 0xFFFF_FFFF),
        reg.local_low => self.local = (self.local & 0xFFFF_FFFF_0000_0000) | word,
        reg.local_high => self.local = (@as(u64, word) << 32) | (self.local & 0xFFFF_FFFF),
        reg.length => self.length = word,
        else => {},
    }
}

fn start(self: *Glacier, word: u32) void {
    if (word & control_clear != 0) {
        self.done = false;
        self.failure = .none;
    }
    if (word & control_start == 0) return;

    // A start while a transfer is in flight is dropped, with no error and no done, which is what
    // the hardware does with it. One access runs to the end before the next begins here, so a
    // guest cannot reach this today; an engine that carried a transfer across several could.
    if (self.busy) return;

    // A start clears everything the last transfer left behind, so a driver that reads a count or
    // an error after one is reading this transfer's and never the one before.
    self.to_host = word & control_to_host != 0;
    self.done = false;
    self.failure = .none;
    self.completed = 0;
    self.data = 0;
    self.transfers += 1;

    self.busy = true;
    self.move();
    self.busy = false;

    // Done is set whether the transfer finished or failed. A driver waits for done and then reads
    // the error, so an engine that left done clear on a failure would leave it waiting.
    self.done = true;

    self.tell(.{ .transfer = .{
        .to_host = self.to_host,
        .host = self.host,
        .local = self.local,
        .words = self.length,
        .moved = self.completed,
        .failure = self.failure,
    } });
}

fn tell(self: *Glacier, what: Event) void {
    const watcher = self.watching orelse return;
    watcher.saw(watcher.ctx, what);
}

/// A whole word of the card's memory, or nothing where the card has no such address.
fn memoryWord(self: *Glacier, at: u64) ?*[4]u8 {
    if (at < self.fabric_at) return null;
    // The guest chooses this address, so the room for a word is checked by subtracting from the
    // length rather than by adding to the offset. Adding wraps at the top of the address space and
    // then passes a bounds test it should have failed.
    if (self.fabric.len < 4) return null;
    const within = at - self.fabric_at;
    if (within > self.fabric.len - 4) return null;
    return self.fabric[@intCast(within)..][0..4];
}

/// One word of the fabric: the display block where the address is inside it, and the card's
/// memory everywhere else. There is one fabric, and the engine and the window are two ways in.
fn fabricRead(self: *Glacier, at: u64) ?u32 {
    if (self.displayWord(at)) |value| return value;
    if (self.poolWord(at)) |value| return value;
    if (self.coreWord(at)) |value| return value;
    const word = self.memoryWord(at) orelse return null;
    return std.mem.readInt(u32, word, .little);
}

/// Returns whether the write landed. A write into the display block reaches a register rather than
/// memory, and nothing here changes a mode, so it is taken and dropped.
fn fabricWrite(self: *Glacier, at: u64, value: u32) bool {
    // What the card has left over is the card's to say. A driver reads it and does not write it.
    if (self.poolWord(at) != null) return true;
    // The core window takes writes: a program is written into it, and a launch is a write to one
    // of its registers.
    if (self.withinCore(at)) |within| {
        self.core.?.write(within, value);
        return true;
    }
    if (self.displayWord(at) != null) {
        // The one register in the block a driver writes. Firmware asks for a mode through the
        // protocol the driver published, and this is the only way that ask reaches the card.
        if (self.display != null and at == self.display_at + displays_at + 0x08) {
            self.mode_selects += 1;
            self.tell(.{ .mode = .{ .display = 0, .value = value } });
        }
        return true;
    }

    const word = self.memoryWord(at) orelse return false;
    std.mem.writeInt(u32, word, value, .little);
    return true;
}

/// Where bytes of fabric landed: in the frame buffer, or in the aperture around it, and by which
/// way they arrived. Counted by the caller rather than inside the write, because the window writes
/// a byte at a time while the engine writes a word, and both have to come to the same bytes.
fn landed(self: *Glacier, at: u64, bytes: u64, through_window: bool) void {
    const shown = self.display orelse return;
    const needed = @as(u64, shown.pitch) * shown.height;
    if (at >= shown.framebuffer and at < shown.framebuffer + needed) {
        if (through_window) self.painted_through_window += bytes else self.painted += bytes;
        return;
    }

    const each = self.aperture orelse return;
    if (at >= each.at and at < each.at + each.len) self.outside_framebuffer += bytes;
}

fn move(self: *Glacier) void {
    if (self.length == 0) {
        self.failure = .zero_length;
        return;
    }

    var moved: u32 = 0;
    while (moved < self.length) : (moved += 1) {
        const step = @as(u64, moved) * 4;

        // Both addresses and the length come from the guest, so a step past the top of the address
        // space is the fault of the end the address belonged to rather than a wrap into a low
        // address that answers. Guest memory refuses a word whose own end overflows, so the host
        // end cannot reach this; the fabric end can, and does.
        const host = std.math.add(u64, self.host, step) catch {
            self.failure = .completion_status;
            return;
        };
        const local = std.math.add(u64, self.local, step) catch {
            self.failure = .fabric;
            return;
        };

        if (self.to_host) {
            const word = self.fabricRead(local) orelse {
                self.failure = .fabric;
                return;
            };
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, word, .little);
            self.memory.write(host, &bytes) catch {
                self.failure = .completion_status;
                return;
            };
            self.data = word;
        } else {
            var taken: [4]u8 = undefined;
            self.memory.read(host, &taken) catch {
                self.failure = .completion_status;
                return;
            };
            const word = std.mem.readInt(u32, &taken, .little);
            if (!self.fabricWrite(local, word)) {
                self.failure = .fabric;
                return;
            }
            self.landed(local, 4, false);
            self.data = word;
        }
        // Counted as each word lands, so a transfer that stopped half way says how far it got.
        self.completed += 1;
    }
}

/// The aperture is fabric memory seen directly, which is what lets a frame buffer be written by
/// the guest rather than carried by the engine.
fn windowRead(self: *Glacier, offset: u64, size: Bus.Size) u64 {
    const each = self.aperture orelse return 0;
    const bytes: u64 = @backingInt(size);

    // Where in the fabric this access begins. The offset is the guest's, so the addition is
    // checked: wrapping here would read somewhere that answers.
    const from = std.math.add(u64, each.at, offset) catch {
        self.strayed += 1;
        return 0;
    };

    var value: u64 = 0;
    for (0..bytes) |taken| {
        const at = std.math.add(u64, from, taken) catch {
            self.strayed += 1;
            continue;
        };
        const whole = self.fabricRead(at & ~@as(u64, 3)) orelse {
            self.strayed += 1;
            continue;
        };
        const byte: u64 = (whole >> @intCast((at & 3) * 8)) & 0xff;
        value |= byte << @intCast(taken * 8);
        self.read_through_window += 1;
    }
    return value;
}

fn windowWrite(self: *Glacier, offset: u64, size: Bus.Size, value: u64) void {
    const each = self.aperture orelse return;
    const bytes: u64 = @backingInt(size);

    const from = std.math.add(u64, each.at, offset) catch {
        self.strayed += 1;
        return;
    };

    for (0..bytes) |taken| {
        const whole_at = std.math.add(u64, from, taken) catch {
            self.strayed += 1;
            continue;
        };
        const at = whole_at & ~@as(u64, 3);
        const shift: u5 = @intCast(whole_at & 3);
        const whole = self.fabricRead(at) orelse {
            self.strayed += 1;
            continue;
        };
        const byte: u32 = @intCast((value >> @intCast(taken * 8)) & 0xff);
        const mask = @as(u32, 0xff) << (shift * 8);
        if (self.fabricWrite(at, (whole & ~mask) | (byte << (shift * 8)))) {
            self.written_through_window += 1;
            self.landed(whole_at, 1, true);
        }
    }
}

/// A card, the memory it moves words to and from, and the fabric it owns. Holds its own storage,
/// because a `GuestMemory` borrows the regions it is given.
const Fixture = struct {
    host_bytes: [64]u8 = @splat(0),
    fabric_bytes: [64]u8 = @splat(0),
    regions: [1]GuestMemory.Region = undefined,
    memory: GuestMemory = undefined,

    const host_at = 0x4000_0000;
    // The same address the prototype card uses, so a test can take the prototype mode as it is.
    const fabric_at = Glacier.prototype_window_at;

    fn card(self: *Fixture) Glacier {
        self.regions = .{.{
            .gpa = host_at,
            .len = self.host_bytes.len,
            .backing = .{ .shared = &self.host_bytes },
        }};
        self.memory = .{ .regions = &self.regions };
        return .{
            .memory = &self.memory,
            .fabric = &self.fabric_bytes,
            .fabric_at = fabric_at,
        };
    }
};

fn peek(one: *Glacier, at: u64) u32 {
    var handler = one.regions();
    return @truncate(handler.vtable.read(handler.ctx, 0, at, .word));
}

fn put(one: *Glacier, at: u64, value: u32) void {
    var handler = one.regions();
    handler.vtable.write(handler.ctx, 0, at, .word, value);
}

test "the engine says which card it is" {
    var fixture: Fixture = .{};
    var one = fixture.card();

    // A driver reads this first and stops if it is anything else, so the whole model rests on it.
    try testing.expectEqual(id, peek(&one, reg.id));

    // Control is write only, and nothing has run, so the status is clear.
    try testing.expectEqual(@as(u32, 0), peek(&one, reg.control));
    try testing.expectEqual(@as(u32, 0), peek(&one, reg.status));
}

test "a transfer to the host carries the fabric into guest memory" {
    var fixture: Fixture = .{};
    @memcpy(fixture.fabric_bytes[0..8], &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 });
    var one = fixture.card();

    put(&one, reg.host_low, Fixture.host_at);
    put(&one, reg.host_high, 0);
    put(&one, reg.local_low, Fixture.fabric_at);
    put(&one, reg.local_high, 0);
    // In words, not bytes. A model that took bytes here would move a quarter of what was asked.
    put(&one, reg.length, 2);
    put(&one, reg.control, control_start | control_to_host);

    try testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 }, fixture.host_bytes[0..8]);

    // Done, no error, and the direction of the transfer that ran.
    try testing.expectEqual(status_done | status_to_host, peek(&one, reg.status));
    try testing.expectEqual(@as(u32, 0), peek(&one, reg.error_code));

    // The driver refuses a transfer unless this reads back exactly the length it asked for, so it
    // counts words and not bytes either.
    try testing.expectEqual(@as(u32, 2), peek(&one, reg.completed));
    try testing.expectEqual(@as(u32, 0x0807_0605), peek(&one, reg.data));
}

test "a transfer from the host carries guest memory into the fabric" {
    var fixture: Fixture = .{};
    @memcpy(fixture.host_bytes[0..4], &[_]u8{ 0xde, 0xad, 0xbe, 0xef });
    var one = fixture.card();

    put(&one, reg.host_low, Fixture.host_at);
    put(&one, reg.local_low, Fixture.fabric_at + 0x10);
    put(&one, reg.length, 1);
    put(&one, reg.control, control_start);

    try testing.expectEqualSlices(u8, &[_]u8{ 0xde, 0xad, 0xbe, 0xef }, fixture.fabric_bytes[0x10..0x14]);

    // Direction clear in the status, because the transfer that ran went the other way.
    try testing.expectEqual(status_done, peek(&one, reg.status));
    try testing.expectEqual(@as(u32, 1), peek(&one, reg.completed));
}

test "a transfer of nothing is refused and says why" {
    var fixture: Fixture = .{};
    var one = fixture.card();

    put(&one, reg.host_low, Fixture.host_at);
    put(&one, reg.local_low, Fixture.fabric_at);
    put(&one, reg.length, 0);
    put(&one, reg.control, control_start);

    // Done as well as failed: a driver waits for done and then reads the error, so an engine that
    // left done clear here would leave it waiting forever.
    try testing.expectEqual(status_done | status_failed, peek(&one, reg.status));
    try testing.expectEqual(@backingInt(Failure.zero_length), peek(&one, reg.error_code));
    try testing.expectEqual(@as(u64, 1), one.transfers);
}

test "a transfer that runs off the fabric stops where it ran out" {
    var fixture: Fixture = .{};
    var one = fixture.card();

    // The last word of the fabric, and two words asked for.
    put(&one, reg.host_low, Fixture.host_at);
    put(&one, reg.local_low, Fixture.fabric_at + fixture.fabric_bytes.len - 4);
    put(&one, reg.length, 2);
    put(&one, reg.control, control_start | control_to_host);

    try testing.expectEqual(@backingInt(Failure.fabric), peek(&one, reg.error_code));
    // One word landed before it ran out, and the count says so rather than reading as the length
    // that was asked for.
    try testing.expectEqual(@as(u32, 1), peek(&one, reg.completed));
}

test "a transfer to memory the guest does not have is a completion that never came back" {
    var fixture: Fixture = .{};
    var one = fixture.card();

    // An address no region covers. The card cannot place the word, which on the wire is a
    // completion with a status rather than a fabric error.
    put(&one, reg.host_low, 0x1000_0000);
    put(&one, reg.local_low, Fixture.fabric_at);
    put(&one, reg.length, 1);
    put(&one, reg.control, control_start | control_to_host);

    try testing.expectEqual(@backingInt(Failure.completion_status), peek(&one, reg.error_code));
    try testing.expectEqual(@as(u32, 0), peek(&one, reg.completed));
}

test "a start clears what the transfer before it left" {
    var fixture: Fixture = .{};
    var one = fixture.card();

    put(&one, reg.length, 0);
    put(&one, reg.control, control_start);
    try testing.expectEqual(@backingInt(Failure.zero_length), peek(&one, reg.error_code));

    // The driver's own way of clearing, which starts nothing.
    put(&one, reg.control, control_clear);
    try testing.expectEqual(@as(u32, 0), peek(&one, reg.status));
    try testing.expectEqual(@as(u32, 0), peek(&one, reg.error_code));
    try testing.expectEqual(@as(u64, 1), one.transfers);

    // And a start clears it too, so a driver reading a count after one is reading this transfer's.
    put(&one, reg.host_low, Fixture.host_at);
    put(&one, reg.local_low, Fixture.fabric_at);
    put(&one, reg.length, 0);
    put(&one, reg.control, control_start);
    try testing.expectEqual(@as(u32, 0), peek(&one, reg.completed));
    try testing.expectEqual(@as(u64, 2), one.transfers);
}

test "the engine is never seen busy, because it answers inside the write" {
    var fixture: Fixture = .{};
    var one = fixture.card();

    put(&one, reg.host_low, Fixture.host_at);
    put(&one, reg.local_low, Fixture.fabric_at);
    put(&one, reg.length, 1);
    put(&one, reg.control, control_start);

    // A driver polls for done and would wait forever on a busy that never clears.
    try testing.expectEqual(@as(u32, 0), peek(&one, reg.status) & status_busy);
    try testing.expectEqual(status_done, peek(&one, reg.status) & status_done);
}

test "a card with nothing to describe has no table at all" {
    var fixture: Fixture = .{};
    var one = fixture.card();

    // A window of zeros is what a driver reads as no table, and it falls back rather than
    // refusing, so this is a valid build of the card and not a broken one.
    try testing.expectEqual(@as(u32, 0), peek(&one, table_at));
    try testing.expectEqual(@as(u32, 0), peek(&one, table_at + 0x08));
}

test "the table names the window the region covers" {
    var fixture: Fixture = .{};
    var one = fixture.card();
    one.aperture = .{ .at = Fixture.fabric_at, .len = 0x20_0000 };

    try testing.expectEqual(table_id, peek(&one, table_at));
    try testing.expectEqual(table_version, peek(&one, table_at + 0x04));
    try testing.expectEqual(@as(u32, 1), peek(&one, table_at + 0x08));
    // The stride is in the header because a driver reads it rather than assuming it.
    try testing.expectEqual(@as(u32, entry_stride), peek(&one, table_at + 0x0c));

    const first = table_at + entries_at;
    try testing.expectEqual(window_kind, peek(&one, first));
    try testing.expectEqual(@as(u32, Fixture.fabric_at), peek(&one, first + 0x04));
    try testing.expectEqual(@as(u32, 0x20_0000), peek(&one, first + 0x08));
    // The window uses neither the instance number nor the storage bit.
    try testing.expectEqual(@as(u32, 0), peek(&one, first + 0x0c));

    // The driver takes the aperture size from the entry and never sizes the region, so the two
    // come from one place here. A card whose entry and region disagreed would publish an address
    // whose last rows land outside the region.
    const described = one.function(.{ .device = 1 });
    try testing.expectEqual(@as(u64, 0x20_0000), described.regions[window_region].size);
    try testing.expectEqual(true, described.regions[window_region].prefetchable);
}

test "the second entry is past the first, at the stride the header gives" {
    var fixture: Fixture = .{};
    var one = fixture.card();
    one.aperture = .{ .at = Fixture.fabric_at, .len = 0x1000 };

    // One entry, so the slot after it reads as nothing. A driver reads the count and stops, and a
    // model that answered here would hand it a second window it does not have.
    try testing.expectEqual(@as(u32, 0), peek(&one, table_at + entries_at + entry_stride));
}

test "the window is fabric memory the guest reaches without the engine" {
    var fixture: Fixture = .{};
    var one = fixture.card();
    one.aperture = .{ .at = Fixture.fabric_at, .len = fixture.fabric_bytes.len };

    var handler = one.regions();
    handler.vtable.write(handler.ctx, window_region, 0x10, .word, 0x1234_5678);

    // Written straight into the card's memory, which is what lets a frame buffer be painted by
    // the guest rather than carried a word at a time.
    try testing.expectEqual(@as(u32, 0x1234_5678), std.mem.readInt(u32, fixture.fabric_bytes[0x10..0x14], .little));
    try testing.expectEqual(@as(u64, 0x1234_5678), handler.vtable.read(handler.ctx, window_region, 0x10, .word));

    // And the engine sees the same bytes, because there is one fabric and two ways to it.
    put(&one, reg.host_low, Fixture.host_at);
    put(&one, reg.local_low, Fixture.fabric_at + 0x10);
    put(&one, reg.length, 1);
    put(&one, reg.control, control_start | control_to_host);
    try testing.expectEqual(@as(u32, 0x1234_5678), std.mem.readInt(u32, fixture.host_bytes[0..4], .little));
}

test "an access past the end of the window reaches no fabric" {
    var fixture: Fixture = .{};
    var one = fixture.card();
    // A window larger than the fabric behind it, which is a card built wrong rather than a guest
    // being wrong. The guest still chooses the address, so it is counted and not refused.
    one.aperture = .{ .at = Fixture.fabric_at, .len = 0x1000 };

    var handler = one.regions();
    handler.vtable.write(handler.ctx, window_region, 0x800, .word, 0xffff_ffff);
    try testing.expectEqual(@as(u64, 0), handler.vtable.read(handler.ctx, window_region, 0x800, .word));
    try testing.expectEqual(@as(u64, 8), one.strayed);
}

test "the card reports the identity the hardware does" {
    var fixture: Fixture = .{};
    var one = fixture.card();
    const described = one.function(.{ .device = 1 });

    try testing.expectEqual(vendor, described.vendor);
    try testing.expectEqual(model, described.device);
    try testing.expectEqual(@as(u64, registers_size), described.regions[0].size);

    // A card built without an image declares no rom, because a rom that reads as zeros is one
    // firmware tries to run.
    try testing.expectEqual(@as(u32, 0), described.rom_size);

    one.rom = &[_]u8{ 0x55, 0xaa };
    const with_rom = one.function(.{ .device = 1 });
    try testing.expectEqual(@as(u32, rom_size), with_rom.rom_size);
}

test "the table names the display block beside the window" {
    var fixture: Fixture = .{};
    var one = fixture.card();
    one.aperture = .{ .at = Fixture.fabric_at, .len = 0x20_0000 };
    one.display = prototype_display;
    one.display_at = Fixture.fabric_at + 0x20_0000;

    try testing.expectEqual(@as(u32, 2), peek(&one, table_at + 0x08));

    const second = table_at + entries_at + entry_stride;
    try testing.expectEqual(display_kind, peek(&one, second));
    try testing.expectEqual(@as(u32, Fixture.fabric_at + 0x20_0000), peek(&one, second + 0x04));
}

/// Read one word of the fabric the way a driver does: a transfer of one word into guest memory,
/// then the word out of there. Eighteen of these is what enumerating a display costs.
fn through(one: *Glacier, fixture: *Fixture, at: u64) u32 {
    put(one, reg.host_low, Fixture.host_at);
    put(one, reg.host_high, 0);
    put(one, reg.local_low, @truncate(at));
    put(one, reg.local_high, @truncate(at >> 32));
    put(one, reg.length, 1);
    put(one, reg.control, control_start | control_to_host);
    return std.mem.readInt(u32, fixture.host_bytes[0..4], .little);
}

test "a driver finds the display through the engine, a word at a time" {
    var fixture: Fixture = .{};
    var one = fixture.card();
    const block = Fixture.fabric_at + 0x20;
    one.aperture = .{ .at = Fixture.fabric_at, .len = 0x20 };
    one.display = prototype_display;
    one.display_at = block;

    // The header first. A driver that reads another fourcc here has found no display block, and
    // one that reads another version refuses rather than guessing the layout.
    try testing.expectEqual(display_kind, through(&one, &fixture, block));
    try testing.expectEqual(display_version, through(&one, &fixture, block + 0x04));
    try testing.expectEqual(@as(u32, 1), through(&one, &fixture, block + 0x08));
    try testing.expectEqual(@as(u32, display_stride), through(&one, &fixture, block + 0x0c));
    // Enabled by index, and nothing has underrun because nothing scans out.
    try testing.expectEqual(@as(u32, 1), through(&one, &fixture, block + 0x10));
    try testing.expectEqual(@as(u32, 0), through(&one, &fixture, block + 0x14));

    // Then the display itself.
    const display = block + displays_at;
    try testing.expectEqual(@as(u32, 640), through(&one, &fixture, display + 0x10));
    try testing.expectEqual(@as(u32, 480), through(&one, &fixture, display + 0x14));
    try testing.expectEqual(@as(u32, Fixture.fabric_at), through(&one, &fixture, display + 0x1c));
    try testing.expectEqual(xr24, through(&one, &fixture, display + 0x28));
    try testing.expectEqual(@as(u32, 2560), through(&one, &fixture, display + 0x2c));

    // Nothing routes sideband pins here, and no frame has begun.
    try testing.expectEqual(@as(u32, 0), through(&one, &fixture, display + 0x24));
    try testing.expectEqual(@as(u32, 0), through(&one, &fixture, display + 0x30));
}

test "the display registers are not memory, so nothing writes over the geometry" {
    var fixture: Fixture = .{};
    var one = fixture.card();
    const block = Fixture.fabric_at + 0x20;
    one.display = prototype_display;
    one.display_at = block;

    @memcpy(fixture.host_bytes[0..4], &[_]u8{ 0, 0, 0, 0 });
    put(&one, reg.host_low, Fixture.host_at);
    put(&one, reg.local_low, block + displays_at + 0x10);
    put(&one, reg.length, 1);
    put(&one, reg.control, control_start);

    // The transfer is taken, because the fabric answered it. The width still reads as the width.
    try testing.expectEqual(@as(u32, 0), peek(&one, reg.error_code));
    try testing.expectEqual(@as(u32, 1), peek(&one, reg.completed));
    try testing.expectEqual(@as(u32, 640), through(&one, &fixture, block + displays_at + 0x10));
}

test "a window one byte short of the last row is refused" {
    var fixture: Fixture = .{};
    var one = fixture.card();
    one.display = prototype_display;

    // Pitch times height. Six hundred and forty by four hundred and eighty at four bytes a pixel
    // and no padding comes to this, and one byte less is refused.
    const needed = 2560 * 480;
    try testing.expectEqual(@as(u64, 1_228_800), needed);

    one.aperture = .{ .at = Fixture.fabric_at, .len = needed };
    try testing.expectEqual(true, one.covers());

    one.aperture = .{ .at = Fixture.fabric_at, .len = needed - 1 };
    try testing.expectEqual(false, one.covers());

    // A row with padding in it needs the padding as well, including on the last row. A window
    // sized from the width rather than the pitch is short by that much, which is the mistake this
    // exists to catch.
    var padded = prototype_display;
    padded.pitch = 2816;
    one.display = padded;
    one.aperture = .{ .at = Fixture.fabric_at, .len = 640 * 4 * 480 };
    try testing.expectEqual(false, one.covers());
    one.aperture = .{ .at = Fixture.fabric_at, .len = 2816 * 480 };
    try testing.expectEqual(true, one.covers());
}

test "a frame buffer the window does not start at is measured from where it sits" {
    var fixture: Fixture = .{};
    var one = fixture.card();
    var moved = prototype_display;
    moved.framebuffer = Fixture.fabric_at + 0x1000;
    one.display = moved;

    // The rows start a page into the window, so the window needs that page as well.
    one.aperture = .{ .at = Fixture.fabric_at, .len = 0x1000 + 2560 * 480 };
    try testing.expectEqual(true, one.covers());
    one.aperture = .{ .at = Fixture.fabric_at, .len = 2560 * 480 };
    try testing.expectEqual(false, one.covers());

    // And a frame buffer below the window is not inside it however large the window is.
    moved.framebuffer = Fixture.fabric_at - 4;
    one.display = moved;
    one.aperture = .{ .at = Fixture.fabric_at, .len = 0x20_0000 };
    try testing.expectEqual(false, one.covers());
}

test "a card with no display and no window covers nothing" {
    var fixture: Fixture = .{};
    var one = fixture.card();

    // A build with no aperture publishes no address at all, which is a card a driver passes over
    // rather than one it refuses.
    try testing.expectEqual(false, one.covers());
    one.aperture = .{ .at = Fixture.fabric_at, .len = 0x20_0000 };
    try testing.expectEqual(false, one.covers());
}

test "an address at the top of the address space is refused rather than wrapped" {
    var fixture: Fixture = .{};
    var one = fixture.card();

    // The guest chooses both addresses and the length. Memory refuses a word that runs off the
    // end of the address space, so the transfer stops at the first one rather than carrying on
    // into whatever a wrapped address would have found.
    put(&one, reg.host_low, 0xFFFF_FFFC);
    put(&one, reg.host_high, 0xFFFF_FFFF);
    put(&one, reg.local_low, @truncate(Fixture.fabric_at));
    put(&one, reg.length, 2);
    put(&one, reg.control, control_start | control_to_host);

    try testing.expectEqual(@backingInt(Failure.completion_status), peek(&one, reg.error_code));
    try testing.expectEqual(status_done | status_failed | status_to_host, peek(&one, reg.status));
    try testing.expectEqual(@as(u32, 0), peek(&one, reg.completed));

    // And the fabric end, on a card whose memory starts at zero, which is the one a guest can
    // reach. The room for a word is checked by subtracting from the length, because adding four
    // to this offset wraps, passes a bounds test it should have failed, and reads a long way
    // outside the card's memory.
    var low: Glacier = .{ .memory = &fixture.memory, .fabric = &fixture.fabric_bytes };
    put(&low, reg.host_low, Fixture.host_at);
    put(&low, reg.local_low, 0xFFFF_FFFC);
    put(&low, reg.local_high, 0xFFFF_FFFF);
    put(&low, reg.length, 1);
    put(&low, reg.control, control_start | control_to_host);

    try testing.expectEqual(@backingInt(Failure.fabric), peek(&low, reg.error_code));
    try testing.expectEqual(@as(u32, 0), peek(&low, reg.completed));
}

test "the card says how far a driver got with it" {
    var fixture: Fixture = .{};
    var one = fixture.card();
    const block = Fixture.fabric_at + 0x20_0000;
    one.aperture = .{ .at = Fixture.fabric_at, .len = 0x20_0000 };
    one.display = prototype_display;
    one.display_at = block;

    // Nothing has been asked of it yet, so every one of these says nothing happened.
    try testing.expectEqual(@as(u64, 0), one.table_reads);
    try testing.expectEqual(@as(u64, 0), one.mode_selects);
    try testing.expectEqual(@as(u64, 0), one.painted);

    // A driver that reads the table and finds the word that names it was given the addresses this
    // card reports. One that read nothing and worked anyway was built with addresses of its own,
    // which is passing for the wrong reason.
    try testing.expectEqual(table_id, peek(&one, table_at));
    try testing.expectEqual(@as(u64, 1), one.table_found);
    try std.testing.expect(one.table_reads > 0);

    // The mode select, which only firmware asking the driver for a mode reaches.
    var handler = one.regions();
    _ = through(&one, &fixture, block + displays_at + 0x08);
    try testing.expectEqual(@as(u64, 0), one.mode_selects);
    put(&one, reg.host_low, Fixture.host_at);
    put(&one, reg.local_low, @truncate(block + displays_at + 0x08));
    put(&one, reg.length, 1);
    put(&one, reg.control, control_start);
    try testing.expectEqual(@as(u64, 1), one.mode_selects);

    // Pixels: bytes inside the frame buffer, and bytes in the aperture outside it. A mode small
    // enough to see both sides of the boundary, since a whole screen of the real one is more
    // fabric than this fixture has.
    var small = prototype_display;
    small.width = 4;
    small.height = 2;
    small.pitch = 16;
    one.display = small;

    const rows = @as(u64, small.pitch) * small.height;
    handler.vtable.write(handler.ctx, window_region, 0, .word, 0x00ff_00ff);

    // Through the window, so this is something other than the driver painting into the address
    // the driver published. The engine's own painting is counted apart from it.
    try testing.expectEqual(@as(u64, 4), one.painted_through_window);
    try testing.expectEqual(@as(u64, 0), one.painted);
    try testing.expectEqual(@as(u64, 0), one.outside_framebuffer);

    // One word past the last row, which is the aperture and not the screen. A driver painting
    // here is painting where it should not.
    handler.vtable.write(handler.ctx, window_region, rows, .word, 0);
    try testing.expectEqual(@as(u64, 4), one.painted_through_window);
    try testing.expectEqual(@as(u64, 4), one.outside_framebuffer);

    // And the last word of the screen is still the screen, so the boundary is where the rows end
    // and not a word either side of it.
    handler.vtable.write(handler.ctx, window_region, rows - 4, .word, 0);
    try testing.expectEqual(@as(u64, 8), one.painted_through_window);
    try testing.expectEqual(@as(u64, 4), one.outside_framebuffer);

    // The engine writing the same place is the driver painting, and counts on its own side.
    @memcpy(fixture.host_bytes[0..4], &[_]u8{ 1, 2, 3, 4 });
    put(&one, reg.host_low, Fixture.host_at);
    put(&one, reg.local_low, @truncate(small.framebuffer));
    put(&one, reg.length, 1);
    put(&one, reg.control, control_start);
    try testing.expectEqual(@as(u64, 4), one.painted);
    try testing.expectEqual(@as(u64, 8), one.painted_through_window);
}

/// Collects what the card was asked to do, so a test can look at it afterwards.
const Notebook = struct {
    transfers: usize = 0,
    modes: usize = 0,
    last_local: u64 = 0,
    last_mode: u32 = 0xffff_ffff,

    fn watcher(self: *Notebook) Watcher {
        return .{ .ctx = self, .saw = Notebook.saw };
    }

    fn saw(ctx: *anyopaque, what: Event) void {
        const self: *Notebook = @ptrCast(@alignCast(ctx));
        switch (what) {
            .transfer => |one| {
                self.transfers += 1;
                self.last_local = one.local;
            },
            .mode => |one| {
                self.modes += 1;
                self.last_mode = one.value;
            },
        }
    }
};

test "a watcher is told what the card was asked to do, in order" {
    var fixture: Fixture = .{};
    var notebook: Notebook = .{};
    var one = fixture.card();
    const block = Fixture.fabric_at + 0x20;
    one.display = prototype_display;
    one.display_at = block;
    one.watching = notebook.watcher();

    // One transfer, with where it went and how far it got.
    _ = through(&one, &fixture, block + 0x10);
    try testing.expectEqual(@as(usize, 1), notebook.transfers);
    try testing.expectEqual(block + 0x10, notebook.last_local);

    // And a mode, which is the one thing in the block a driver writes.
    put(&one, reg.host_low, Fixture.host_at);
    put(&one, reg.local_low, @truncate(block + displays_at + 0x08));
    put(&one, reg.length, 1);
    put(&one, reg.control, control_start);
    try testing.expectEqual(@as(usize, 1), notebook.modes);

    // A transfer that failed is still a transfer, and says how far it got before it did.
    put(&one, reg.length, 0);
    put(&one, reg.control, control_start);
    try testing.expectEqual(@as(usize, 3), notebook.transfers);
}

test "a card nobody is watching tells nothing and works the same" {
    var fixture: Fixture = .{};
    var one = fixture.card();

    // No watcher, which is how a guest runs when nobody asked for a trace.
    try testing.expectEqual(@as(?Watcher, null), one.watching);
    _ = through(&one, &fixture, Fixture.fabric_at);
    try testing.expectEqual(@as(u64, 1), one.transfers);
}

/// The bytes of the frame buffer as the card holds them, or nothing where this card has no
/// display, no window, or a window that does not cover every row.
///
/// Whoever wants a picture of the screen takes it from here and makes one: what the pixels mean is
/// the format the display reports, and turning that into a file is not a device's work.
pub fn screen(self: *const Glacier) ?[]const u8 {
    if (!self.covers()) return null;
    const shown = self.display orelse return null;
    if (shown.framebuffer < self.fabric_at) return null;

    const within = shown.framebuffer - self.fabric_at;
    const needed = @as(u64, shown.pitch) * shown.height;
    if (within + needed > self.fabric.len) return null;
    return self.fabric[@intCast(within)..][0..@intCast(needed)];
}

test "the screen is the rows of the frame buffer, or nothing where there is no screen" {
    var fixture: Fixture = .{};
    var one = fixture.card();

    // No display and no window, so there is nothing to take a picture of.
    try testing.expectEqual(@as(?[]const u8, null), one.screen());

    var small = prototype_display;
    small.width = 4;
    small.height = 2;
    small.pitch = 16;
    one.display = small;
    one.aperture = .{ .at = Fixture.fabric_at, .len = 32 };

    const taken = one.screen().?;
    try testing.expectEqual(@as(usize, 32), taken.len);

    // What the guest painted is what a picture of it holds.
    var handler = one.regions();
    handler.vtable.write(handler.ctx, window_region, 0, .word, 0x0011_2233);
    try testing.expectEqual(@as(u8, 0x33), taken[0]);

    // A card whose fabric is shorter than the rows has no whole screen to hand over, which is a
    // card built wrong rather than a guest being wrong.
    one.display = prototype_display;
    try testing.expectEqual(@as(?[]const u8, null), one.screen());
}

test "a frame buffer painted through the bridge lands in the fabric the display scans" {
    var fixture: Fixture = .{};
    var one = fixture.card();
    one.aperture = .{ .at = Fixture.fabric_at, .len = fixture.fabric_bytes.len };
    // A mode the size of the fixture's fabric, so the whole path fits in sixty four bytes.
    one.display = .{ .width = 4, .height = 2, .pitch = 16, .framebuffer = Fixture.fabric_at };
    one.display_at = Fixture.fabric_at + 0x1000;
    try testing.expectEqual(true, one.covers());

    var host: PciHost = .{};
    try testing.expectEqual(true, host.add(one.function(.{ .device = 1 })));

    const window_base: u64 = 0x1000_0000;
    var config = host.device(0);
    var window: PciHost.Window = .{ .host = &host, .at = window_base };
    var memory = window.device(0x1_0000);

    // What firmware does: place both regions, then set memory space enable.
    const slot: u64 = @as(u64, 1) << 15;
    config.vtable.write(config.ctx, slot | 0x10, .word, @intCast(window_base));
    config.vtable.write(config.ctx, slot | 0x18, .word, @intCast(window_base + 0x1000));
    config.vtable.write(config.ctx, slot | 0x04, .half, 0x02);

    // One pixel, painted the way firmware and an operating system paint one: a store into the
    // address the driver published, with no engine involved.
    memory.vtable.write(memory.ctx, 0x1000, .word, 0xffff_ffff);
    try testing.expectEqual(@as(u32, 0xffff_ffff), std.mem.readInt(u32, fixture.fabric_bytes[0..4], .little));
    try testing.expectEqual(@as(u64, 4), one.painted_through_window);
    try testing.expectEqual(@as(u64, 0), host.unclaimed);
    try testing.expectEqual(@as(u64, 0), host.refused);

    // The engine carries the same bytes out, which is the memory the display block scans.
    put(&one, reg.host_low, Fixture.host_at);
    put(&one, reg.local_low, Fixture.fabric_at);
    put(&one, reg.length, 1);
    put(&one, reg.control, control_start | control_to_host);
    try testing.expectEqual(@as(u32, 0xffff_ffff), std.mem.readInt(u32, fixture.host_bytes[0..4], .little));

    // The same store with the card switched off reaches nothing: a guest that paints into an
    // address whose card is off reads its writes back as all ones and sees a black screen.
    config.vtable.write(config.ctx, slot | 0x04, .half, 0x00);
    memory.vtable.write(memory.ctx, 0x1004, .word, 0xffff_ffff);
    try testing.expectEqual(@as(u64, 0xFFFF_FFFF), memory.vtable.read(memory.ctx, 0x1004, .word));
    try testing.expectEqual(@as(u64, 4), one.painted_through_window);
    try testing.expectEqual(@as(u64, 2), host.refused);
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, fixture.fabric_bytes[4..8], .little));
}

test "the table names the memory a driver may hand out" {
    var fixture: Fixture = .{};
    var one = fixture.card();
    one.aperture = .{ .at = Fixture.fabric_at, .len = prototype_window_size };
    one.display = prototype_display;
    one.display_at = Fixture.fabric_at + prototype_window_size;
    one.pool_at = Fixture.fabric_at + prototype_window_size + 0x1000;
    one.pool = prototype_pool;

    // Three entries, and the pool is the third.
    try testing.expectEqual(@as(u32, 3), peek(&one, table_at + 0x08));
    const third = table_at + entries_at + 2 * entry_stride;
    try testing.expectEqual(memory_kind, peek(&one, third));
    try testing.expectEqual(@as(u32, @truncate(one.pool_at)), peek(&one, third + 0x04));
    try testing.expectEqual(@as(u32, ranges_at + range_stride), peek(&one, third + 0x08));

    // The block itself answers through the engine, which is the only way a driver reaches it: it
    // sits past the window, so nothing painting a frame buffer can reach these words.
    put(&one, reg.host_low, Fixture.host_at);
    put(&one, reg.local_low, @truncate(one.pool_at));
    put(&one, reg.length, 4);
    put(&one, reg.control, control_start | control_to_host);
    try testing.expectEqual(memory_kind, std.mem.readInt(u32, fixture.host_bytes[0x00..0x04], .little));
    try testing.expectEqual(memory_version, std.mem.readInt(u32, fixture.host_bytes[0x04..0x08], .little));
    try testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, fixture.host_bytes[0x08..0x0c], .little));
    try testing.expectEqual(@as(u32, range_stride), std.mem.readInt(u32, fixture.host_bytes[0x0c..0x10], .little));

    // The one range: where it is, how much of it there is, and that a driver may have it.
    put(&one, reg.host_low, Fixture.host_at + 0x10);
    put(&one, reg.local_low, @truncate(one.pool_at + ranges_at));
    put(&one, reg.length, 3);
    put(&one, reg.control, control_start | control_to_host);
    try testing.expectEqual(@as(u32, @truncate(prototype_pool.at)), std.mem.readInt(u32, fixture.host_bytes[0x10..0x14], .little));
    try testing.expectEqual(@as(u32, @truncate(prototype_pool.len)), std.mem.readInt(u32, fixture.host_bytes[0x14..0x18], .little));
    try testing.expectEqual(range_usable, std.mem.readInt(u32, fixture.host_bytes[0x18..0x1c], .little));

    // The pool is inside the window and clear of the frame buffer, so a driver handing out its
    // first byte hands out memory a host can map and nothing else is painting.
    try std.testing.expect(prototype_pool.at >= prototype_display.framebuffer +
        @as(u64, prototype_display.pitch) * prototype_display.height);
    try std.testing.expect(prototype_pool.at + prototype_pool.len <= one.aperture.?.at + one.aperture.?.len);
}

test "the table names the core, and a host drives it over the engine" {
    var fixture: Fixture = .{};
    var words: [4]u32 = @splat(0);
    var one = fixture.card();
    one.aperture = .{ .at = Fixture.fabric_at, .len = prototype_window_size };
    one.display = prototype_display;
    one.display_at = Fixture.fabric_at + prototype_window_size;
    one.pool_at = Fixture.fabric_at + prototype_window_size + 0x1000;
    one.pool = prototype_pool;
    one.core_at = core_window_at;
    one.core = .{ .shape = Core.gc1mi, .program = &words };

    // Four entries now, and the core is the fourth.
    try testing.expectEqual(@as(u32, 4), peek(&one, table_at + 0x08));
    const fourth = table_at + entries_at + 3 * entry_stride;
    try testing.expectEqual(Core.kind, peek(&one, fourth));
    try testing.expectEqual(@as(u32, core_window_at), peek(&one, fourth + 0x04));
    try testing.expectEqual(@as(u32, Core.window_size), peek(&one, fourth + 0x08));

    // The window answers the engine and nothing else, because the board puts it a long way from
    // the aperture. A driver reads the name first, as it does with every other block.
    put(&one, reg.host_low, Fixture.host_at);
    put(&one, reg.local_low, core_window_at);
    put(&one, reg.length, 1);
    put(&one, reg.control, control_start | control_to_host);
    try testing.expectEqual(Core.kind, std.mem.readInt(u32, fixture.host_bytes[0..4], .little));

    // The sequence a host uses: the program into the aperture, then the launch registers, then run
    // and the strobe in one write.
    std.mem.writeInt(u32, fixture.host_bytes[0..4], 0x0010_0073, .little);
    put(&one, reg.host_low, Fixture.host_at);
    put(&one, reg.local_low, core_window_at + Core.program_at);
    put(&one, reg.length, 1);
    put(&one, reg.control, control_start);
    try testing.expectEqual(@as(u32, 0x0010_0073), words[0]);

    std.mem.writeInt(u32, fixture.host_bytes[0..4], Core.control_run | Core.control_launch, .little);
    put(&one, reg.local_low, core_window_at + Core.reg.control);
    put(&one, reg.control, control_start);
    try testing.expectEqual(@as(u64, 1), one.core.?.launches);

    // And the status it leaves: running, a warp issued, and nothing of it still live.
    put(&one, reg.host_low, Fixture.host_at + 0x10);
    put(&one, reg.local_low, core_window_at + Core.reg.status);
    put(&one, reg.control, control_start | control_to_host);
    const status = std.mem.readInt(u32, fixture.host_bytes[0x10..0x14], .little);
    try testing.expectEqual(Core.status_run | Core.status_issued | Core.status_idle, status);

    // The core keeps no fabric behind its window, so none of this touched the card's memory.
    try testing.expectEqual(@as(u64, 0), one.outside_framebuffer);
    try testing.expectEqual(@as(u64, 0), one.painted);
}

test "the prototype shape is the card this runner always had" {
    const shape = Build.prototype;
    try shape.check();

    try testing.expectEqual(@as(u64, prototype_window_at), shape.window.at);
    try testing.expectEqual(@as(u64, prototype_window_size), shape.window.len);
    try testing.expectEqual(@as(u64, prototype_fabric_size), shape.fabricSize());
    try testing.expectEqual(@as(u64, prototype_display_at), shape.displayAt());
    try testing.expectEqual(@as(u64, prototype_pool_at), shape.poolAt());
    try testing.expectEqual(@as(usize, Core.max_program_words), shape.programWords());
    try testing.expectEqual(@as(usize, 8 * 2048), shape.scratchBytes());

    // And the board, which is the card the gateware is built for. Both are cards someone could
    // build, which is the whole of what `check` answers.
    try Build.ax7203.check();
    try testing.expectEqual(@as(u32, 1024), Build.ax7203.display.?.width);
    try testing.expectEqual(@as(u64, 32 * 1024 * 1024), Build.ax7203.window.len);
}

test "a caller writes a card the way a board is written" {
    const shape = try Build.parse("board=chenega-v1-ax7203,res=800x600,out=hdmi,edid,core=gc1.f");

    try testing.expectEqual(@as(u64, 32 * 1024 * 1024), shape.window.len);
    try testing.expectEqual(@as(u32, 800), shape.display.?.width);
    try testing.expectEqual(@as(u32, 600), shape.display.?.height);
    // A row with no padding, until a caller asks for some.
    try testing.expectEqual(@as(u32, 3200), shape.display.?.pitch);
    try testing.expectEqual(caps_hdmi | caps_edid, shape.display.?.caps);
    try testing.expectEqual(@as(u8, 16), shape.core.?.lanes);

    // Settings nobody gave are the board's own, so the clock of the mode it was written with
    // stays. A caller changing a mode without its clock is asking for the same wires.
    try testing.expectEqual(@as(u32, 65_000_000), shape.display.?.pixel_clock);

    const bare = try Build.parse("res=none,core=none,pool=none");
    try testing.expectEqual(@as(?Display, null), bare.display);
    try testing.expectEqual(@as(?Pool, null), bare.pool);
    try testing.expectEqual(@as(?Core.Shape, null), bare.core);
    try testing.expectEqual(@as(usize, 0), bare.scratchBytes());

    try testing.expectError(error.UnknownBoard, Build.parse("board=chenega-v1-ulx3s"));
    try testing.expectError(error.UnknownCore, Build.parse("core=gc2.n"));
    try testing.expectError(error.BadResolution, Build.parse("res=1024"));
    try testing.expectError(error.BadNumber, Build.parse("windowsize=big"));
}

test "the memory to hand out follows a mode the caller moved" {
    // The board's own pool was placed under the board's own mode, so a larger mode in a smaller
    // window has to move it. A pool left where it was would be memory a driver hands out and the
    // display is painting.
    const shape = try Build.parse("windowsize=4M,res=1024x768");
    try shape.check();

    const rows = @as(u64, shape.display.?.pitch) * shape.display.?.height;
    try testing.expectEqual(shape.display.?.framebuffer + rows, shape.pool.?.at);
    try testing.expectEqual(shape.window.at + shape.window.len, shape.pool.?.at + shape.pool.?.len);

    // A caller who names the pool gets the one they named, and one that reaches over the frame
    // buffer is refused rather than handed out.
    const named = try Build.parse("windowsize=4M,res=1024x768,pool=0x80300000,poolsize=1M");
    try testing.expectEqual(@as(u64, 0x8030_0000), named.pool.?.at);
    try testing.expectError(error.PoolPainted, Build.parse("pool=0x80000000,poolsize=1M"));
    try testing.expectError(error.PoolOutside, Build.parse("pool=0x90000000,poolsize=1M"));
}

test "a card nobody could build is refused by what is wrong with it" {
    // A window that does not reach the last row of the mode, which is the arithmetic firmware
    // does before it publishes an address.
    try testing.expectError(error.WindowTooSmall, Build.parse("res=1024x768,windowsize=1M"));
    // A region is a power of two on this bus.
    try testing.expectError(error.BadWindow, Build.parse("windowsize=3M"));
    // The table describes the card in thirty two bit fields.
    try testing.expectError(error.WindowTooLarge, Build.parse("window=0xffff0000"));
    // A spill slot is four bytes, so a warp's scratch starts word aligned or one warp writes over
    // another's.
    try testing.expectError(error.BadScratch, Build.parse("scratch=1023"));
    try testing.expectError(error.TooManyWarps, Build.parse("warps=32"));
    // The core window answers from nothing, so it may not land where the fabric already answers.
    try testing.expectError(error.CoreInWindow, Build.parse("window=0x10000000,windowsize=1M,res=none"));

    // Each one says what to do about it rather than naming itself.
    try std.testing.expect(std.mem.indexOf(u8, Build.trouble(error.BadWindow), "power of two") != null);
}

test "a card is placed where its shape says, and nothing else places it" {
    var fixture: Fixture = .{};
    _ = fixture.card();

    // Small on purpose. The fabric is memory this test holds, so the window and the mode are the
    // smallest pair that still names every block the board has.
    const shape = try Build.parse("board=chenega-v1-ax7203,windowsize=16K,res=64x32");
    var fabric: [0x4000 + Build.blocks_size]u8 = @splat(0);
    var program: [Core.max_program_words]u32 = @splat(0);
    var scratch: [8 * 2048]u8 = @splat(0);

    // What a runner allocates comes from the shape, so these three are what it would have asked
    // for and not what this test chose.
    try testing.expectEqual(fabric.len, shape.fabricSize());
    try testing.expectEqual(program.len, shape.programWords());
    try testing.expectEqual(scratch.len, shape.scratchBytes());

    var one = shape.card(.{
        .memory = &fixture.memory,
        .fabric = &fabric,
        .program = &program,
        .scratch = &scratch,
    });

    // The window covers the mode, and the table names all four blocks the shape asked for.
    try std.testing.expect(one.covers());
    try testing.expectEqual(@as(u32, 4), peek(&one, table_at + 0x08));

    const second = table_at + entries_at + entry_stride;
    try testing.expectEqual(display_kind, peek(&one, second));
    try testing.expectEqual(@as(u32, @truncate(shape.displayAt())), peek(&one, second + 0x04));

    const fourth = table_at + entries_at + 3 * entry_stride;
    try testing.expectEqual(Core.kind, peek(&one, fourth));
    try testing.expectEqual(@as(u32, @truncate(shape.core_at)), peek(&one, fourth + 0x04));
}
