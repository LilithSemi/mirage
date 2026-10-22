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
        blocks: std.ArrayList(Entry) = .empty,
        /// Where a block is, by the address and content it was translated from.
        /// A scan of every block on every lookup made the run time grow with the
        /// amount of code the guest had touched.
        index: std.AutoHashMapUnmanaged(Key, u32) = .empty,

        const Key = struct { pc: u64, fingerprint: u64 };
        const Entry = struct { pc: u64, fingerprint: u64, bytes: []u8, block: Guest.Block };

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{ .allocator = allocator };
        }

        pub fn deinit(self: *Self) void {
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
            const block = try Guest.compile(self.allocator, pc, bytes);
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

        /// Compare fetched bytes on every lookup, including after guest writes.
        /// A translation executes at most 64 instructions before yielding.
        pub fn runBlock(self: *Self, memory: *GuestMemory, cpu: *Guest.Cpu, tlb: *Guest.Tlb) Error!u64 {
            var bytes: [64 * Guest.max_instruction_bytes]u8 = undefined;
            var count: usize = 0;
            for (0..64) |_| {
                const at = std.math.add(u64, Guest.pc(cpu), count) catch return error.AddressOverflow;
                const room = bytes[count..][0..Guest.max_instruction_bytes];
                const length = try Guest.fetch(memory, cpu, tlb, at, room);
                if (length == 0 or length > room.len) return error.InvalidInstructionLength;
                count += length;
                if (try Guest.terminates(room[0..length])) break;
            }
            const block = try self.getOrCompile(Guest.pc(cpu), bytes[0..count]);
            return block.run(cpu);
        }
    };
}
