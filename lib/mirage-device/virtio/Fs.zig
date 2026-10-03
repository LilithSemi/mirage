//! A virtio filesystem device: a directory on the host that the guest mounts.
//!
//! What travels over the queues is the kernel's own filesystem in userspace protocol, so this device
//! carries messages and answers none of them itself. Whoever starts the guest says what answers them,
//! which is what keeps the rules about who may read what out of a device model.
//!
//! A request is one chain: the readable parts are the message and the writable parts are where the
//! answer goes. Both are gathered into buffers here rather than being walked in place, because a
//! message may be split across parts wherever the driver felt like splitting it and an answer may be
//! larger than any one part.

const std = @import("std");
const testing = @import("mirage-testing");
const Bus = @import("../Bus.zig");
const Mmio = @import("Mmio.zig");
const Queue = @import("Queue.zig");
const mirage_device = @import("../../mirage-device.zig");
const Service = mirage_device.Service;
const Answering = mirage_device.Answering;
const GuestMemory = @import("mirage-memory").GuestMemory;

const Fs = @This();

/// `VIRTIO_ID_FS`.
const device_id = 26;
/// `VIRTIO_F_VERSION_1`.
const feature_version_1: u64 = 1 << 32;

/// The queue the guest sends what cannot wait on: forgetting a file, or giving up on a request. It
/// has to exist and be served, because the driver publishes to it whether or not anything is urgent.
pub const queue_hiprio = 0;
/// The queue everything else goes on. One is enough: a guest with more would have them served in turn
/// by the same loop anyway.
pub const queue_request = 1;
pub const queue_count = 2;

/// How long a name may be, which is what the configuration space holds.
pub const tag_size = 36;

/// The most one message or one answer may be. A read of the largest size the protocol agrees to has
/// to fit in the answer with its header, and a message is never anywhere near this.
pub const buffer_size = 132 * 1024;

/// Serving a queue can only fail the ways a queue can. Making the device needs memory, so that is
/// said separately: a device that cannot be made is a caller's problem and not a guest's.
pub const Error = Queue.Error;

mmio: Mmio,
queues: [queue_count]Queue,
/// The name the guest mounts, and how many request queues there are.
config: [tag_size + 4]u8,
/// Whoever answers the messages.
answering: Answering,
/// One message and one answer, gathered from the parts the driver published. Held rather than put on
/// the stack: they are far larger than a loop should be putting there every request.
asked: []u8,
answered: []u8,

/// Messages carried, and ones that could not be. A guest whose filesystem quietly does nothing looks
/// the same as an empty one, so what went wrong is counted.
carried: u64 = 0,
dropped: u64 = 0,
/// How often work was found in a ring with no doorbell set for it. A doorbell that goes missing is
/// a device that would have stopped for good, so this is the number that says whether that happens.
drained_unrung: u64 = 0,
/// Messages the protocol wants no answer to, `forget` above all. Counted apart from the ones that
/// could not be answered, because a guest telling this end to let a name go is work done and not
/// work lost.
told: u64 = 0,

/// Initialised in place, never returned by value: the transport points at `config` and `queues`
/// inside this same struct, and a copy leaves those pointers aimed at the copy that has gone.
/// The room for one message and one answer comes from the caller, because a device in this repository
/// does not allocate: whoever builds the machine owns its memory. Both have to be `buffer_size` or a
/// read of the largest size the protocol agrees to will not fit.
pub fn init(self: *Fs, tag: []const u8, answering: Answering, asked: []u8, answered: []u8) void {
    std.debug.assert(asked.len >= buffer_size and answered.len >= buffer_size);

    // Everything at once, so a counter added to this struct later starts where it says it starts.
    // Setting them one by one leaves a new one holding whatever was in that memory, which reads as a
    // device that has already done work it has not done.
    self.* = .{
        .mmio = undefined,
        .queues = undefined,
        .config = undefined,
        .answering = answering,
        .asked = asked,
        .answered = answered,
    };

    @memset(&self.config, 0);
    const named = @min(tag.len, tag_size);
    @memcpy(self.config[0..named], tag[0..named]);
    std.mem.writeInt(u32, self.config[tag_size..][0..4], 1, .little);

    self.queues = @splat(.{ .size = 0, .descriptor = 0, .available = 0, .used = 0 });
    self.mmio = .{
        .device_id = device_id,
        .device_features = feature_version_1,
        .config = &self.config,
        .queues = &self.queues,
    };
}

pub fn device(self: *Fs, at: u64) Bus.Device {
    return self.mmio.device(at);
}

pub fn service(self: *Fs, intid: u32) Service {
    return .{ .ctx = self, .intid = intid, .poll = Fs.askPoll };
}

fn askPoll(ctx: *anyopaque, memory: *GuestMemory) Service.Error!bool {
    const self: *Fs = @ptrCast(@alignCast(ctx));

    // What is in the ring decides, not only the doorbell about it. A device that drains on the
    // doorbell alone stops for good if one is ever missed: nothing drains the queue, the driver gets
    // no completions back, and every task waiting on one parks. The count says whether that ever
    // really happens, because a guess about a race is not worth a number.
    for ([2]usize{ queue_hiprio, queue_request }) |which| {
        const rung = self.mmio.rang(which);
        const left = self.queues[which].waiting(memory);
        if (left and !rung) self.drained_unrung += 1;
        if (rung or left) _ = try self.serve(memory, which);
    }
    return self.mmio.interrupt_status != 0;
}

/// Serve everything the driver has published on one queue. Returns how many messages were answered.
pub fn serve(self: *Fs, memory: *GuestMemory, which: usize) Error!u32 {
    const queue = &self.queues[which];
    if (!queue.ready) return 0;

    // Cleared before the drain, not after, which is the order `Vsock` already uses. A doorbell rung
    // while this loop runs belongs to the next pass, and erasing it afterwards would throw away the
    // one notice that work had arrived.
    self.mmio.served(which);

    var served: u32 = 0;
    while (try queue.next(memory)) |head| {
        var chain = queue.walk(head);

        // The message is every readable part, one after another. A driver may split it anywhere.
        var asked_len: usize = 0;
        var room_for_answer: usize = 0;

        while (try chain.next(memory)) |segment| {
            if (segment.writable) {
                room_for_answer += segment.len;
                continue;
            }
            const taking = @min(segment.len, self.asked.len - asked_len);
            if (taking == 0) continue;
            try memory.read(segment.addr, self.asked[asked_len..][0..taking]);
            asked_len += taking;
        }

        // Whoever answers is given no more room than the guest published, so an answer is sized to
        // what the guest can take rather than being written and then silently cut short.
        //
        // A chain with no writable part at all is a message the protocol wants no answer to, and
        // `forget` is the one that matters: it still has to reach whoever answers, or the names a
        // guest has finished with are never let go and the table grows for the whole session.
        const room = @min(room_for_answer, self.answered.len);
        const wrote = if (asked_len == 0) 0 else self.answering.answer(
            self.answering.ctx,
            self.asked[0..asked_len],
            self.answered[0..room],
        );
        if (asked_len == 0) {
            self.dropped += 1;
        } else if (room == 0) {
            self.told += 1;
        } else if (wrote == 0) {
            self.dropped += 1;
        } else {
            self.carried += 1;
        }

        // Scattered back into the parts the driver published, in the order it published them.
        //
        // **Walked again rather than remembered.** A chain holds as many parts as the driver
        // cared to publish, and a guest with 4K pages publishes 32 of them for one 128K read.
        // Keeping the first 16 in an array dropped the rest from the room above and from the
        // scatter below, so a read of 128K was answered with 60K. A short answer is legal for
        // `read`, which loops for the rest, and fatal for a page fault, which cannot: the pages
        // past the answer stay unfilled and the program dies on the first instruction in them.
        var back = queue.walk(head);
        var left = wrote;
        var at: usize = 0;
        while (try back.next(memory)) |segment| {
            if (left == 0) break;
            if (!segment.writable) continue;
            const putting = @min(segment.len, left);
            try memory.write(segment.addr, self.answered[at..][0..putting]);
            at += putting;
            left -= putting;
        }

        try queue.complete(memory, head, @intCast(wrote));
        served += 1;
    }

    if (served > 0) self.mmio.raise();
    return served;
}

/// An answering end for a test: it remembers what it was asked and fills what it was told to.
const Counter = struct {
    seen: usize = 0,
    said: usize = 0,
    room_offered: usize = 0,

    fn answer(ctx: *anyopaque, request: []const u8, into: []u8) usize {
        const self: *Counter = @ptrCast(@alignCast(ctx));
        self.seen = request.len;
        self.room_offered = into.len;
        const said = @min(self.said, into.len);
        @memset(into[0..said], 0xab);
        return said;
    }

    fn answering(self: *Counter) Answering {
        return .{ .ctx = self, .answer = Counter.answer };
    }
};

/// Room for a test's one message and one answer. Held rather than allocated: these tests build for a
/// machine with no allocator at all, which is the whole point of the freestanding build.
const Room = struct {
    asked: [buffer_size]u8,
    answered: [buffer_size]u8,
};

const ram = 0x4000_0000;
const ring_size = 8;
const desc_at = ram + 0x000;
const avail_at = ram + 0x100;
const used_at = ram + 0x200;

/// A queue with one request on it, built the way a driver builds one.
const Harness = struct {
    bytes: [8192]u8 = @splat(0),
    regions: [1]GuestMemory.Region = undefined,

    fn memory(self: *Harness) GuestMemory {
        self.regions = .{.{ .gpa = ram, .len = self.bytes.len, .backing = .{ .shared = &self.bytes } }};
        return .{ .regions = &self.regions };
    }

    fn descriptor(self: *Harness, index: u16, addr: u64, length: u32, flags: u16, next: u16) void {
        const at = @as(usize, index) * 16;
        std.mem.writeInt(u64, self.bytes[at..][0..8], addr, .little);
        std.mem.writeInt(u32, self.bytes[at + 8 ..][0..4], length, .little);
        std.mem.writeInt(u16, self.bytes[at + 12 ..][0..2], flags, .little);
        std.mem.writeInt(u16, self.bytes[at + 14 ..][0..2], next, .little);
    }

    fn publish(self: *Harness, parts: []const Queue.Segment) void {
        for (parts, 0..) |part, index| {
            const last = index + 1 == parts.len;
            self.descriptor(
                @intCast(index),
                part.addr,
                part.len,
                (if (last) 0 else Queue.flag_next) | (if (part.writable) Queue.flag_write else 0),
                @intCast(index + 1),
            );
        }
        // One request, at descriptor zero.
        std.mem.writeInt(u16, self.bytes[0x104..][0..2], 0, .little);
        std.mem.writeInt(u16, self.bytes[0x102..][0..2], 1, .little);
    }

    /// How much the device said it wrote, which is what the driver reads.
    fn written(self: *const Harness) u32 {
        return std.mem.readInt(u32, self.bytes[0x208..][0..4], .little);
    }

    fn attach(_: *Harness, offered: *Fs, which: usize) void {
        offered.queues[which] = .{
            .size = ring_size,
            .descriptor = desc_at,
            .available = avail_at,
            .used = used_at,
            .ready = true,
        };
    }
};

test "a message split across parts arrives whole and the answer goes back scattered" {
    var counter: Counter = .{ .said = 300 };
    var room: Room = undefined;
    var offered: Fs = undefined;
    offered.init("store", counter.answering(), &room.asked, &room.answered);

    var h: Harness = .{};
    h.attach(&offered, queue_request);
    @memcpy(h.bytes[0x300..][0..7], "hello, ");
    @memcpy(h.bytes[0x340..][0..10], "filesystem");
    h.publish(&.{
        .{ .addr = ram + 0x300, .len = 7, .writable = false },
        .{ .addr = ram + 0x340, .len = 10, .writable = false },
        .{ .addr = ram + 0x400, .len = 128, .writable = true },
        .{ .addr = ram + 0x800, .len = 256, .writable = true },
    });

    var memory = h.memory();
    try testing.expectEqual(@as(u32, 1), try offered.serve(&memory, queue_request));

    // The whole message, in the order the driver published its parts.
    try testing.expectEqual(@as(usize, 17), counter.seen);
    try testing.expectEqual(@as(u64, 1), offered.carried);
    try testing.expectEqualSlices(u8, "hello, filesystem", offered.asked[0..17]);

    // The answer filled the first part and then the second, and the queue says how much came back.
    try testing.expectEqual(@as(u8, 0xab), h.bytes[0x400]);
    try testing.expectEqual(@as(u8, 0xab), h.bytes[0x800]);
    try testing.expectEqual(@as(u8, 0xab), h.bytes[0x400 + 127]);
    try testing.expectEqual(@as(u32, 300), h.written());
}

test "a chain of many parts is answered whole, and never only its first sixteen" {

    // A guest with 4K pages publishes one part a page, so a 128K read arrives as 32 of them.
    // The count is what this measures, so the parts are small.
    const parts = 32;
    const part_len = 256;

    var counter: Counter = .{ .said = parts * part_len };
    var room: Room = undefined;
    var offered: Fs = undefined;
    offered.init("store", counter.answering(), &room.asked, &room.answered);

    // A table wide enough for the whole chain, which the narrow one above is not.
    const wide_desc = ram + 0x000;
    const wide_avail = ram + 0x400;
    const wide_used = ram + 0x500;
    const asked_at = 0x600;
    const answer_at = 0x1000;

    var bytes: [0x4000]u8 = @splat(0);
    var regions = [1]GuestMemory.Region{.{
        .gpa = ram,
        .len = bytes.len,
        .backing = .{ .shared = &bytes },
    }};
    var memory = GuestMemory{ .regions = &regions };

    const put = struct {
        fn one(into: []u8, index: u16, addr: u64, length: u32, flags: u16, next: u16) void {
            const at = @as(usize, index) * 16;
            std.mem.writeInt(u64, into[at..][0..8], addr, .little);
            std.mem.writeInt(u32, into[at + 8 ..][0..4], length, .little);
            std.mem.writeInt(u16, into[at + 12 ..][0..2], flags, .little);
            std.mem.writeInt(u16, into[at + 14 ..][0..2], next, .little);
        }
    }.one;

    @memcpy(bytes[asked_at..][0..3], "ask");
    put(&bytes, 0, ram + asked_at, 3, Queue.flag_next, 1);
    var index: u16 = 0;
    while (index < parts) : (index += 1) {
        const last = index + 1 == parts;
        put(
            &bytes,
            index + 1,
            ram + answer_at + @as(u64, index) * part_len,
            part_len,
            (if (last) 0 else Queue.flag_next) | Queue.flag_write,
            index + 2,
        );
    }

    // One request, at descriptor zero.
    std.mem.writeInt(u16, bytes[0x404..][0..2], 0, .little);
    std.mem.writeInt(u16, bytes[0x402..][0..2], 1, .little);

    offered.queues[queue_request] = .{
        .size = parts + 1,
        .descriptor = wide_desc,
        .available = wide_avail,
        .used = wide_used,
        .ready = true,
    };

    try testing.expectEqual(@as(u32, 1), try offered.serve(&memory, queue_request));

    // Every part counted as room, and every part written back. The whole of this: a cap on the
    // parts kept made a read answer short, and a page fault cannot ask for the rest.
    try testing.expectEqual(@as(usize, parts * part_len), counter.room_offered);
    try testing.expectEqual(
        @as(u32, parts * part_len),
        std.mem.readInt(u32, bytes[0x508..][0..4], .little),
    );
    try testing.expectEqual(@as(u8, 0xab), bytes[answer_at]);
    try testing.expectEqual(@as(u8, 0xab), bytes[answer_at + (parts - 1) * part_len]);
    try testing.expectEqual(@as(u8, 0xab), bytes[answer_at + parts * part_len - 1]);
}

test "an answer is never larger than the room the guest offered" {
    // Says it wrote more than the guest published room for. Whoever answers is handed only what the
    // guest offered, so it cannot be told to write past it.
    var counter: Counter = .{ .said = 4096 };
    var room: Room = undefined;
    var offered: Fs = undefined;
    offered.init("store", counter.answering(), &room.asked, &room.answered);

    var h: Harness = .{};
    h.attach(&offered, queue_request);
    @memcpy(h.bytes[0x300..][0..3], "ask");
    h.publish(&.{
        .{ .addr = ram + 0x300, .len = 3, .writable = false },
        .{ .addr = ram + 0x400, .len = 64, .writable = true },
    });

    var memory = h.memory();
    _ = try offered.serve(&memory, queue_request);
    try testing.expectEqual(@as(usize, 64), counter.room_offered);
    try testing.expectEqual(@as(u32, 64), h.written());
    // Nothing was written past what the guest offered.
    try testing.expectEqual(@as(u8, 0), h.bytes[0x440]);
}

test "a request with nowhere to put an answer is completed rather than left waiting" {
    var counter: Counter = .{ .said = 16 };
    var room: Room = undefined;
    var offered: Fs = undefined;
    offered.init("store", counter.answering(), &room.asked, &room.answered);

    var h: Harness = .{};
    h.attach(&offered, queue_hiprio);
    @memcpy(h.bytes[0x300..][0..8], "forget??");
    h.publish(&.{.{ .addr = ram + 0x300, .len = 8, .writable = false }});

    // A message the guest wants no answer to still has to be taken off the queue, or the driver waits
    // for a slot that never comes back.
    var memory = h.memory();
    try testing.expectEqual(@as(u32, 1), try offered.serve(&memory, queue_hiprio));
    try testing.expectEqual(@as(u32, 0), h.written());
    try testing.expectEqual(@as(u64, 1), offered.told);
    try testing.expectEqual(@as(u64, 0), offered.dropped);
}

test "the name the guest mounts is in the configuration space" {
    var counter: Counter = .{};
    var room: Room = undefined;
    var offered: Fs = undefined;
    offered.init("store", counter.answering(), &room.asked, &room.answered);

    try testing.expectEqualSlices(u8, "store", offered.config[0..5]);
    try testing.expectEqual(@as(u8, 0), offered.config[5]);
    // One request queue, which is what the driver reads to know how many to set up.
    try testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, offered.config[tag_size..][0..4], .little));
}

test "a name longer than the configuration space holds is cut rather than overflowing it" {
    var counter: Counter = .{};
    var room: Room = undefined;
    var offered: Fs = undefined;
    offered.init("x" ** 100, counter.answering(), &room.asked, &room.answered);
    try testing.expectEqual(@as(u8, 'x'), offered.config[tag_size - 1]);
    try testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, offered.config[tag_size..][0..4], .little));
}

test "work in the ring is served even when no doorbell was left set for it" {
    var counter: Counter = .{ .said = 32 };
    var room: Room = undefined;
    var offered: Fs = undefined;
    offered.init("store", counter.answering(), &room.asked, &room.answered);

    var h: Harness = .{};
    h.attach(&offered, queue_request);
    @memcpy(h.bytes[0x300..][0..5], "hello");
    h.publish(&.{
        .{ .addr = ram + 0x300, .len = 5, .writable = false },
        .{ .addr = ram + 0x400, .len = 64, .writable = true },
    });

    // No doorbell. Whether one can really be lost is a question about the loop above this, and this
    // is the answer to a different one: a ring with work in it is drained whatever the flag says, so
    // a doorbell that did go missing costs a turn rather than the whole mount.
    try testing.expectEqual(false, offered.mmio.rang(queue_request));

    var memory = h.memory();
    try testing.expectEqual(true, try offered.service(0).poll(&offered, &memory));
    try testing.expectEqual(@as(u64, 1), offered.carried);
    try testing.expectEqual(@as(u64, 1), offered.drained_unrung);

    // And a ring with nothing left in it is not counted as a missed doorbell, or the number would
    // climb on every quiet turn and mean nothing.
    _ = try offered.service(0).poll(&offered, &memory);
    try testing.expectEqual(@as(u64, 1), offered.drained_unrung);
}

test "a message that published no room for a reply still reaches whoever answers" {
    var counter: Counter = .{ .said = 0 };
    var room: Room = undefined;
    var offered: Fs = undefined;
    offered.init("store", counter.answering(), &room.asked, &room.answered);

    var h: Harness = .{};
    h.attach(&offered, queue_request);
    @memcpy(h.bytes[0x300..][0..8], "forgetme");

    // Readable parts only. The kernel publishes a chain like this for anything it wants no answer
    // to, and `forget` is the one that matters: a guest that is never told to let a name go is a
    // table that grows for the life of the session.
    h.publish(&.{.{ .addr = ram + 0x300, .len = 8, .writable = false }});

    var memory = h.memory();
    try testing.expectEqual(@as(u32, 1), try offered.serve(&memory, queue_request));
    try testing.expectEqual(@as(usize, 8), counter.seen);
    try testing.expectEqual(@as(u64, 0), offered.dropped);
}
