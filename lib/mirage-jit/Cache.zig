//! Guest-independent instruction-byte cache and translated block fetch.
const std = @import("std");
const GuestMemory = @import("mirage-memory").GuestMemory;

/// Guest supplies Cpu, Block, Error, max_instruction_bytes, pc, fetch,
/// terminates, and compile. Fetch returns one complete instruction's byte
/// length; variable-width encodings need no special treatment here.
pub fn Cache(comptime Guest: type) type {
    return struct {
        const Self = @This();
        pub const Error = Guest.Error || error{ AddressOverflow, InvalidInstructionLength };

        allocator: std.mem.Allocator,
        /// Where a translation's temporaries come from; reset after each one.
        scratch: std.heap.FixedBufferAllocator,
        blocks: std.ArrayList(Entry) = .empty,
        /// Where a block is, by the address and content it was translated from.
        /// A scan of every block on every lookup made the run time grow with the
        /// amount of code the guest had touched.
        index: std.AutoHashMapUnmanaged(Key, u32) = .empty,

        /// Blocks by the address they were last run from, so that running a block
        /// again costs one comparison rather than a fetch, decode and hash of every
        /// instruction in it. An entry is good only while nothing it was derived from
        /// can have changed: the translation regime (`Guest.context`) and the bytes
        /// of any page a block was fetched from (`invalidate`, called on a write to
        /// one, which `isCode` reports).
        fast: [fast_slots]Fast = @splat(.{}),
        /// Bumped by `invalidate`; an entry from an older epoch never matches.
        epoch: u64 = 1,
        /// One bit per physical 4KB page (folded, so a collision is a spurious
        /// invalidation and never a missed one) that some block was fetched from.
        code_pages: [code_page_bits / 8]u8 = @splat(0),

        const fast_slots = 1 << 14;
        const code_page_bits = 1 << 20;
        const Fast = struct { pc: u64 = 0, context: u64 = 0, epoch: u64 = 0, at: u32 = 0 };

        const Key = struct { pc: u64, fingerprint: u64 };
        const Entry = struct { pc: u64, fingerprint: u64, bytes: []u8, block: Guest.Block };

        /// Address space reserved for a translation's temporaries. Only what a
        /// translation touches is ever backed by memory.
        const scratch_bytes = 1 << 30;

        pub fn init(allocator: std.mem.Allocator) Self {
            // Not an arena: it is used from one thread, and an arena pays an atomic
            // operation per allocation, of which a translation makes hundreds.
            const memory: []u8 = std.heap.page_allocator.alloc(u8, scratch_bytes) catch &.{};
            return .{ .allocator = allocator, .scratch = .init(memory) };
        }

        pub fn deinit(self: *Self) void {
            std.heap.page_allocator.free(self.scratch.buffer);
            for (self.blocks.items) |*entry| {
                entry.block.deinit();
                self.allocator.free(entry.bytes);
            }
            self.blocks.deinit(self.allocator);
            self.index.deinit(self.allocator);
        }

        pub fn getOrCompile(self: *Self, pc: u64, bytes: []const u8) Error!*const Guest.Block {
            const fingerprint = std.hash.Wyhash.hash(0, bytes);
            const key: Key = .{ .pc = pc, .fingerprint = fingerprint };
            if (self.index.get(key)) |at| {
                const entry = &self.blocks.items[at];
                if (std.mem.eql(u8, entry.bytes, bytes)) return &entry.block;
            }

            const owned = try self.allocator.dupe(u8, bytes);
            errdefer self.allocator.free(owned);
            defer self.scratch.reset();
            const block = try Guest.compileIn(self.scratch.allocator(), self.allocator, pc, bytes);
            errdefer {
                var image = block;
                image.deinit();
            }
            try self.blocks.append(self.allocator, .{
                .pc = pc,
                .fingerprint = fingerprint,
                .bytes = owned,
                .block = block,
            });
            errdefer _ = self.blocks.pop();
            const at: u32 = @intCast(self.blocks.items.len - 1);
            try self.index.put(self.allocator, key, at);
            return &self.blocks.items[at].block;
        }

        fn pageBit(physical: u64) usize {
            return @as(usize, @truncate(physical >> 12)) & (code_page_bits - 1);
        }

        fn markCode(self: *Self, physical: u64) void {
            const bit = pageBit(physical);
            self.code_pages[bit / 8] |= @as(u8, 1) << @intCast(bit % 8);
        }

        /// Throw away every remembered address. Blocks themselves stay: they are
        /// still found, and checked, by their bytes.
        pub fn invalidate(self: *Self) void {
            self.epoch +%= 1;
        }

        /// Tell the cache the guest wrote to `physical`. If a block was fetched
        /// from that page, what is remembered about where blocks are can be wrong.
        pub fn written(self: *Self, physical: u64) void {
            const bit = pageBit(physical);
            const mask = @as(u8, 1) << @intCast(bit % 8);
            if (self.code_pages[bit / 8] & mask == 0) return;
            self.code_pages[bit / 8] &= ~mask;
            self.invalidate();
        }

        /// Compare fetched bytes on every lookup, including after guest writes.
        /// A translation executes at most 64 instructions before yielding.
        pub fn runBlock(self: *Self, memory: *GuestMemory, cpu: *Guest.Cpu, tlb: *Guest.Tlb) Error!u64 {
            const start = Guest.pc(cpu);
            const context = Guest.context(cpu, tlb);
            const slot = &self.fast[@as(usize, @truncate(start >> 2)) & (fast_slots - 1)];
            if (slot.pc == start and slot.context == context and slot.epoch == self.epoch) {
                return self.blocks.items[slot.at].block.run(cpu);
            }
            var bytes: [64 * Guest.max_instruction_bytes]u8 = undefined;
            var count: usize = 0;
            for (0..64) |_| {
                const at = std.math.add(u64, Guest.pc(cpu), count) catch return error.AddressOverflow;
                const room = bytes[count..][0..Guest.max_instruction_bytes];
                const length = Guest.fetch(memory, cpu, tlb, at, room) catch |err| switch (err) {
                    error.TranslationFault, error.PermissionFault => {
                        if (count > 0) break;
                        return err;
                    },
                    else => return err,
                };
                if (length == 0 or length > room.len) return error.InvalidInstructionLength;
                count += length;
                if (try Guest.terminates(room[0..length])) break;
            }
            const block = try self.getOrCompile(start, bytes[0..count]);
            // Remember the block only once the pages it came from are marked, so a
            // write between here and the next run is seen.
            self.markCode(try Guest.locate(memory, cpu, tlb, start));
            self.markCode(try Guest.locate(memory, cpu, tlb, start + count - 1));
            const key: Key = .{ .pc = start, .fingerprint = std.hash.Wyhash.hash(0, bytes[0..count]) };
            slot.* = .{ .pc = start, .context = context, .epoch = self.epoch, .at = self.index.get(key).? };
            return block.run(cpu);
        }
    };
}
