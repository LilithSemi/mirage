//! The flash firmware keeps its variables in.
//!
//! Reads answer the bytes of the store. Writes are commands: the part a plain block of memory
//! cannot do, and the reason this is a device at all. Firmware erases a block, programs words into
//! it, and reads a status register until it says the work is finished, so memory that took the
//! command bytes as data would leave it reading its own command back and waiting forever.
//!
//! The command set is the one the firmware's own driver speaks, which is a pair of sixteen bit
//! parts side by side. That is why the status has its bits in both halves of the word: the driver
//! asks both parts at once and waits for both to answer.

const std = @import("std");
const Bus = @import("Bus.zig");
const testing = @import("mirage-testing");

const NorFlash = @This();

/// How much of the store one erase takes with it. The driver does not ask: it is told this by the
/// platform it was built for, so it has to be the same number here.
pub const block_size = 256 * 1024;

/// Commands, as the driver sends them.
const read_array: u32 = 0xff;
const read_status: u32 = 0x70;
const clear_status: u32 = 0x50;
const read_device_id: u32 = 0x90;
const erase_setup: u32 = 0x20;
const confirm: u32 = 0xd0;
const lock_setup: u32 = 0x60;
const program_setup: u32 = 0x40;
const alternate_program_setup: u32 = 0x10;
const buffer_setup: u32 = 0xe8;

/// The status the driver waits on. Bit seven in each half says that part has finished what it was
/// asked to do, and the driver waits for both.
const ready: u64 = 0x0080_0080;

/// A command as both parts of the device see it. The driver writes one word to the pair, with the
/// command in each half, so what arrives is the command twice over and the two halves fold back
/// into the one command that was meant.
fn commandOf(word: u32) u32 {
    return (word >> 16) | (word & 0xffff);
}

/// What a read answers until the next command changes it.
const Answering = enum {
    /// The bytes of the store, which is where a read starts and returns to.
    array,
    status,
    /// Whether the block is locked. Nothing here locks one, so this answers that none are.
    device_id,
};

/// What the next write means, when it is not a command.
const Expecting = union(enum) {
    nothing,
    /// A block was named for erasing and the confirmation has not arrived.
    erase: u64,
    /// A block was named for locking or unlocking.
    lock,
    /// One word is to be programmed wherever the next write lands.
    word,
    /// A run of words is to be programmed. First the count arrives, then the words, then the
    /// confirmation.
    count,
    words: usize,
    /// Every word arrived and only the confirmation is outstanding.
    filled,
};

/// The bytes of the store. Borrowed: whoever started the guest owns them, and what is written here
/// is what they hold afterwards.
store: []u8,

answering: Answering = .array,
expecting: Expecting = .nothing,

/// How many blocks were erased and how many words programmed. Not registers: a test needs to tell
/// a store that was written from one that was only asked about.
erased: u64 = 0,
programmed: u64 = 0,
/// Commands this does not know. The guest chooses them, so one nobody models is counted rather
/// than refused.
unknown: u64 = 0,

pub fn device(self: *NorFlash, at: u64, len: u64) Bus.Device {
    return .{
        .base = at,
        .len = len,
        .ctx = self,
        .vtable = &.{ .read = NorFlash.read, .write = NorFlash.write },
    };
}

/// A byte of the store, or the erased value past the end of it. A bank is as long as the tree says
/// and the bytes behind it may be shorter, and erased is what a part nobody has written reads as.
fn byteOf(self: *const NorFlash, at: u64) u8 {
    if (at >= self.store.len) return 0xff;
    return self.store[@intCast(at)];
}

fn read(ctx: *anyopaque, offset: u64, size: Bus.Size) u64 {
    const self: *NorFlash = @ptrCast(@alignCast(ctx));
    const bytes: u64 = @backingInt(size);

    switch (self.answering) {
        .status => return ready,
        // Bit zero of each half says the block is locked. None of them are.
        .device_id => return 0,
        .array => {},
    }

    var value: u64 = 0;
    for (0..bytes) |taken| {
        const byte: u64 = self.byteOf(offset + taken);
        value |= byte << @intCast(taken * 8);
    }
    return value;
}

fn write(ctx: *anyopaque, offset: u64, size: Bus.Size, value: u64) void {
    const self: *NorFlash = @ptrCast(@alignCast(ctx));
    _ = size;
    const word: u32 = @truncate(value);

    // A write while a sequence is outstanding is the rest of that sequence rather than a new
    // command, because the data of a program looks like a command and must not be read as one.
    switch (self.expecting) {
        .nothing => {},
        .erase => |block| {
            self.expecting = .nothing;
            if (commandOf(word) != confirm) return;
            self.eraseBlock(block);
            self.answering = .status;
            return;
        },
        .lock => {
            // Locked or unlocked, nothing here holds a block either way.
            self.expecting = .nothing;
            self.answering = .status;
            return;
        },
        .word => {
            self.expecting = .nothing;
            self.program(offset, word);
            self.answering = .status;
            return;
        },
        .count => {
            // One less than the number of words to come, which is how the driver says it, and in
            // both halves like every other thing it writes that is not data.
            self.expecting = .{ .words = @as(usize, commandOf(word)) + 1 };
            return;
        },
        .words => |left| {
            self.program(offset, word);
            self.expecting = if (left <= 1) .filled else .{ .words = left - 1 };
            return;
        },
        .filled => {
            self.expecting = .nothing;
            if (commandOf(word) != confirm) return;
            self.answering = .status;
            return;
        },
    }

    switch (commandOf(word)) {
        read_array => self.answering = .array,
        read_status => self.answering = .status,
        clear_status => self.answering = .status,
        read_device_id => self.answering = .device_id,
        erase_setup => self.expecting = .{ .erase = offset & ~@as(u64, block_size - 1) },
        lock_setup => self.expecting = .lock,
        program_setup, alternate_program_setup => self.expecting = .word,
        buffer_setup => {
            // The driver reads the status straight after this to learn the device is ready to
            // take a run of words, so this answers the status from here until the run ends.
            self.answering = .status;
            self.expecting = .count;
        },
        else => self.unknown += 1,
    }
}

fn eraseBlock(self: *NorFlash, block: u64) void {
    self.erased += 1;
    if (block >= self.store.len) return;
    const end = @min(block + block_size, self.store.len);
    @memset(self.store[@intCast(block)..@intCast(end)], 0xff);
}

/// Programming clears bits and never sets them, which is what the part does: a word is written
/// over an erased one, and a driver that writes without erasing first gets what it asked for only
/// where the bits were already there.
fn program(self: *NorFlash, offset: u64, word: u32) void {
    self.programmed += 1;
    if (offset + 4 > self.store.len) return;
    const held = std.mem.readInt(u32, self.store[@intCast(offset)..][0..4], .little);
    std.mem.writeInt(u32, self.store[@intCast(offset)..][0..4], held & word, .little);
}

const bank = 2 * block_size;

/// A store with something in it, so a read that answers zeros is a read that went wrong.
fn fixture(bytes: *[bank]u8) NorFlash {
    @memset(bytes, 0xff);
    std.mem.writeInt(u32, bytes[0..4], 0x1234_5678, .little);
    return .{ .store = bytes };
}

test "a read answers the store until a command says otherwise" {
    var bytes: [bank]u8 = undefined;
    var flash = fixture(&bytes);
    var one = flash.device(0x0400_0000, bank);

    try testing.expectEqual(@as(u64, 0x1234_5678), one.vtable.read(one.ctx, 0, .word));

    // The status, which the driver waits on, has its bits in both halves because the part is two
    // of them side by side and the driver asks both at once.
    one.vtable.write(one.ctx, 0, .word, read_status);
    try testing.expectEqual(ready, one.vtable.read(one.ctx, 0, .word));

    // And back to the store, which is where every sequence ends.
    one.vtable.write(one.ctx, 0, .word, read_array);
    try testing.expectEqual(@as(u64, 0x1234_5678), one.vtable.read(one.ctx, 0, .word));
}

test "an erase takes the whole block and nothing beyond it" {
    var bytes: [bank]u8 = undefined;
    var flash = fixture(&bytes);
    var one = flash.device(0, bank);

    // Something in the second block, to show the erase stops where the block does.
    std.mem.writeInt(u32, bytes[block_size..][0..4], 0xabcd_ef01, .little);

    one.vtable.write(one.ctx, 0x40, .word, erase_setup);
    one.vtable.write(one.ctx, 0x40, .word, confirm);

    try testing.expectEqual(@as(u64, 1), flash.erased);
    one.vtable.write(one.ctx, 0, .word, read_array);
    try testing.expectEqual(@as(u64, 0xFFFF_FFFF), one.vtable.read(one.ctx, 0, .word));
    try testing.expectEqual(@as(u32, 0xabcd_ef01), std.mem.readInt(u32, bytes[block_size..][0..4], .little));
}

test "an erase that was set up and never confirmed takes nothing" {
    var bytes: [bank]u8 = undefined;
    var flash = fixture(&bytes);
    var one = flash.device(0, bank);

    one.vtable.write(one.ctx, 0, .word, erase_setup);
    one.vtable.write(one.ctx, 0, .word, read_array);

    try testing.expectEqual(@as(u64, 0), flash.erased);
    try testing.expectEqual(@as(u64, 0x1234_5678), one.vtable.read(one.ctx, 0, .word));
}

test "a word is programmed where the write that follows the command lands" {
    var bytes: [bank]u8 = undefined;
    var flash = fixture(&bytes);
    var one = flash.device(0, bank);

    one.vtable.write(one.ctx, 0x20, .word, program_setup);
    one.vtable.write(one.ctx, 0x20, .word, 0x0f0f_0f0f);

    try testing.expectEqual(@as(u64, 1), flash.programmed);
    try testing.expectEqual(@as(u32, 0x0f0f_0f0f), std.mem.readInt(u32, bytes[0x20..][0..4], .little));

    // And the status says it finished, which is what the driver waits for.
    try testing.expectEqual(ready, one.vtable.read(one.ctx, 0x20, .word));
}

test "programming clears bits and never sets them" {
    var bytes: [bank]u8 = undefined;
    var flash = fixture(&bytes);
    var one = flash.device(0, bank);

    // The first word holds something already. A part writes by clearing bits, so programming over
    // it without erasing first gives what both have, which is what the hardware does.
    one.vtable.write(one.ctx, 0, .word, program_setup);
    one.vtable.write(one.ctx, 0, .word, 0xFFFF_0000);
    try testing.expectEqual(@as(u32, 0x1234_0000), std.mem.readInt(u32, bytes[0..4], .little));
}

test "a run of words is taken between the count and the confirmation" {
    var bytes: [bank]u8 = undefined;
    var flash = fixture(&bytes);
    var one = flash.device(0, bank);

    one.vtable.write(one.ctx, 0x80, .word, erase_setup);
    one.vtable.write(one.ctx, 0x80, .word, confirm);

    // The driver asks for the run, reads the status to learn it may begin, says how many words
    // are coming as one less than the number, writes them, and confirms.
    one.vtable.write(one.ctx, 0x80, .word, buffer_setup);
    try testing.expectEqual(ready, one.vtable.read(one.ctx, 0x80, .word));
    one.vtable.write(one.ctx, 0x80, .word, 1);
    one.vtable.write(one.ctx, 0x80, .word, 0xaaaa_aaaa);
    one.vtable.write(one.ctx, 0x84, .word, 0xbbbb_bbbb);
    one.vtable.write(one.ctx, 0, .word, confirm);

    try testing.expectEqual(@as(u64, 2), flash.programmed);
    try testing.expectEqual(ready, one.vtable.read(one.ctx, 0x80, .word));

    one.vtable.write(one.ctx, 0, .word, read_array);
    try testing.expectEqual(@as(u32, 0xaaaa_aaaa), std.mem.readInt(u32, bytes[0x80..][0..4], .little));
    try testing.expectEqual(@as(u32, 0xbbbb_bbbb), std.mem.readInt(u32, bytes[0x84..][0..4], .little));
}

test "a word of a run that looks like a command is taken as data" {
    var bytes: [bank]u8 = undefined;
    var flash = fixture(&bytes);
    var one = flash.device(0, bank);

    one.vtable.write(one.ctx, 0, .word, erase_setup);
    one.vtable.write(one.ctx, 0, .word, confirm);
    one.vtable.write(one.ctx, 0, .word, buffer_setup);
    one.vtable.write(one.ctx, 0, .word, 0);
    // The value of a block erase command, as a word of data. A device that read it as a command
    // would erase the block it was in the middle of writing.
    one.vtable.write(one.ctx, 0, .word, erase_setup);
    one.vtable.write(one.ctx, 0, .word, confirm);

    try testing.expectEqual(@as(u64, 1), flash.erased);
    try testing.expectEqual(@as(u64, 1), flash.programmed);
    one.vtable.write(one.ctx, 0, .word, read_array);
    try testing.expectEqual(@as(u64, erase_setup), one.vtable.read(one.ctx, 0, .word));
}

test "no block is locked, so the driver never stops to unlock one" {
    var bytes: [bank]u8 = undefined;
    var flash = fixture(&bytes);
    var one = flash.device(0, bank);

    // The driver reads this before every erase and only unlocks when bit zero is set.
    one.vtable.write(one.ctx, 0, .word, read_device_id);
    try testing.expectEqual(@as(u64, 0), one.vtable.read(one.ctx, 8, .word) & 1);
}

test "a bank longer than the bytes behind it reads as erased" {
    var bytes: [bank]u8 = undefined;
    var flash = fixture(&bytes);
    // Twice the store, which is a bank the tree declared larger than what was given to it.
    var one = flash.device(0, bank * 2);

    try testing.expectEqual(@as(u64, 0xFFFF_FFFF), one.vtable.read(one.ctx, bank, .word));

    // And a write past the end changes nothing rather than reaching into something else.
    one.vtable.write(one.ctx, bank, .word, program_setup);
    one.vtable.write(one.ctx, bank, .word, 0);
    one.vtable.write(one.ctx, 0, .word, read_array);
    try testing.expectEqual(@as(u64, 0xFFFF_FFFF), one.vtable.read(one.ctx, bank, .word));
}

test "a command nobody models is counted rather than obeyed" {
    var bytes: [bank]u8 = undefined;
    var flash = fixture(&bytes);
    var one = flash.device(0, bank);

    one.vtable.write(one.ctx, 0, .word, 0xb0);
    try testing.expectEqual(@as(u64, 1), flash.unknown);
    try testing.expectEqual(@as(u64, 0x1234_5678), one.vtable.read(one.ctx, 0, .word));
}

test "a command arrives in both halves of the word, and both mean the one command" {
    var bytes: [bank]u8 = undefined;
    var flash = fixture(&bytes);
    var one = flash.device(0, bank);

    // What the driver actually writes: the command in each half, because it is talking to two
    // parts at once. A device that compared the whole word would take every command for one it
    // does not know and answer none of them.
    one.vtable.write(one.ctx, 0, .word, 0x0070_0070);
    try testing.expectEqual(ready, one.vtable.read(one.ctx, 0, .word));
    try testing.expectEqual(@as(u64, 0), flash.unknown);

    // An erase, both halves again, and the count of a run the same way.
    one.vtable.write(one.ctx, 0, .word, 0x0020_0020);
    one.vtable.write(one.ctx, 0, .word, 0x00d0_00d0);
    try testing.expectEqual(@as(u64, 1), flash.erased);

    one.vtable.write(one.ctx, 0, .word, 0x00e8_00e8);
    one.vtable.write(one.ctx, 0, .word, 0x0001_0001);
    one.vtable.write(one.ctx, 0, .word, 0x1111_2222);
    one.vtable.write(one.ctx, 4, .word, 0x3333_4444);
    one.vtable.write(one.ctx, 0, .word, 0x00d0_00d0);
    try testing.expectEqual(@as(u64, 2), flash.programmed);

    one.vtable.write(one.ctx, 0, .word, 0x00ff_00ff);
    try testing.expectEqual(@as(u64, 0x1111_2222), one.vtable.read(one.ctx, 0, .word));
    try testing.expectEqual(@as(u64, 0x3333_4444), one.vtable.read(one.ctx, 4, .word));
}
