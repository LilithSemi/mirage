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
const GuestMemory = @import("mirage-memory").GuestMemory;
const testing = @import("mirage-testing");

const Glacier = @This();

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

/// What the engine answers at the first word. A driver that reads anything else has found a
/// different card.
pub const id: u32 = 0x48444d41;

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

/// The host's memory. The engine moves words to and from it, and a word it cannot reach is
/// answered as a completion that did not come back.
memory: *GuestMemory,
/// The card's own memory, and the fabric address it starts at.
fabric: []u8,
fabric_at: u64 = 0,
aperture: ?Aperture = null,
/// The expansion rom image, or nothing for a card built without one.
rom: []const u8 = &.{},

host: u64 = 0,
local: u64 = 0,
length: u32 = 0,
completed: u32 = 0,
data: u32 = 0,
failure: Failure = .none,
done: bool = false,
to_host: bool = false,

/// How many transfers were started. Not a register: a test needs to tell a transfer that moved
/// nothing from one that never began.
transfers: u64 = 0,
/// Accesses that named fabric the card does not have. The guest chooses the address, so this is
/// counted rather than refused loudly.
strayed: u64 = 0,

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
    return if (self.aperture != null) 1 else 0;
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
    return null;
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

fn registerWord(self: *const Glacier, at: u64) u32 {
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

    // A start clears everything the last transfer left behind, so a driver that reads a count or
    // an error after one is reading this transfer's and never the one before.
    self.to_host = word & control_to_host != 0;
    self.done = false;
    self.failure = .none;
    self.completed = 0;
    self.data = 0;
    self.transfers += 1;

    self.move();

    // Done is set whether the transfer finished or failed. A driver waits for done and then reads
    // the error, so an engine that left done clear on a failure would leave it waiting.
    self.done = true;
}

/// A whole word of fabric, or nothing where the card has no such address.
fn fabricWord(self: *Glacier, at: u64) ?*[4]u8 {
    if (at < self.fabric_at) return null;
    const within = at - self.fabric_at;
    if (within + 4 > self.fabric.len) return null;
    return self.fabric[@intCast(within)..][0..4];
}

fn move(self: *Glacier) void {
    if (self.length == 0) {
        self.failure = .zero_length;
        return;
    }

    var moved: u32 = 0;
    while (moved < self.length) : (moved += 1) {
        const step = @as(u64, moved) * 4;
        const local = self.fabricWord(self.local + step) orelse {
            self.failure = .fabric;
            return;
        };

        if (self.to_host) {
            const word = std.mem.readInt(u32, local, .little);
            self.memory.write(self.host + step, local) catch {
                self.failure = .completion_status;
                return;
            };
            self.data = word;
        } else {
            var taken: [4]u8 = undefined;
            self.memory.read(self.host + step, &taken) catch {
                self.failure = .completion_status;
                return;
            };
            local.* = taken;
            self.data = std.mem.readInt(u32, &taken, .little);
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

    var value: u64 = 0;
    for (0..bytes) |taken| {
        const at = each.at + offset + taken;
        const word = self.fabricWord(at & ~@as(u64, 3)) orelse {
            self.strayed += 1;
            continue;
        };
        const whole = std.mem.readInt(u32, word, .little);
        const byte: u64 = (whole >> @intCast((at & 3) * 8)) & 0xff;
        value |= byte << @intCast(taken * 8);
    }
    return value;
}

fn windowWrite(self: *Glacier, offset: u64, size: Bus.Size, value: u64) void {
    const each = self.aperture orelse return;
    const bytes: u64 = @backingInt(size);

    for (0..bytes) |taken| {
        const at = each.at + offset + taken;
        const word = self.fabricWord(at & ~@as(u64, 3)) orelse {
            self.strayed += 1;
            continue;
        };
        const shift: u5 = @intCast((at & 3) * 8);
        const whole = std.mem.readInt(u32, word, .little);
        const byte: u32 = @intCast((value >> @intCast(taken * 8)) & 0xff);
        std.mem.writeInt(u32, word, (whole & ~(@as(u32, 0xff) << shift)) | (byte << shift), .little);
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
    const fabric_at = 0x8000_0000;

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
