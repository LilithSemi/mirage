//! The words of a Glacier kernel, run as native code on the machine this program is on.
//!
//! The card model holds the threads, the barrier, the counters and the registers a host reads. The
//! words are RISC-V, so running them means compiling them: Vulcan lifts the region a warp reaches
//! into its own intermediate form, compiles that for this cpu, and the result is called with the
//! warp's state. Nothing here decodes an instruction.
//!
//! A region is kept once it is compiled. One dispatch launches the same kernel for every workgroup
//! of a grid, so compiling it again for each one would cost more than running it. A host that
//! rewrites the aperture strobes flush, which is what makes the keeping safe.

const std = @import("std");
const device = @import("mirage-device");
const ir = @import("vulcan-ir");
const opt = @import("vulcan-opt");
const vulcan = @import("vulcan-target");

const Core = device.Glacier.Core;
const decode = vulcan.glacier.decode;
const lift = vulcan.glacier.lift;

const Jit = @This();

comptime {
    // Both sides count the arguments a launch carries, and a launch here is copied into a warp
    // there whole. The hardware's count is what both of them were written from.
    std.debug.assert(Core.launch_args == vulcan.glacier.encode.Csr.launch_args);
    std.debug.assert(Core.warp_registers == @typeInfo(@FieldType(lift.Warp, "x")).array.len);
}

allocator: std.mem.Allocator,
/// The card's memory and the fabric address it answers at, which is how a kernel reaches a buffer.
fabric: []u8,
fabric_at: u32,
/// The core's private scratch, one slice per warp in the order the warps are numbered, and the
/// address the first of them is reported at.
scratch: []u8,
scratch_at: u32,
/// The state of every warp. An engine owns this rather than the caller, because the compiled code
/// reads the shape of it and only this side knows that shape.
room: []align(@alignOf(State)) u8,

/// Whether the lifted form is tuned before it is compiled. Every scalar register starts in a stack
/// slot for the first pass to promote, so a kernel this is off for is correct and slow.
tuned: bool = true,

/// Regions already compiled, and the code a flush gave up on.
held: std.ArrayList(Region) = .empty,
spent: std.ArrayList(vulcan.native.CodeBuffer) = .empty,
/// Held while those two are read or written, because every warp runs on a thread of its own.
lock: std.Io.Mutex = .init,
/// What the locking is done through, taken from the seam. Every operation on a lock needs one, and
/// the calls the core makes carry none of their own.
io: std.Io = undefined,

/// Regions compiled, and the launches whose words this could not compile. Counted because a
/// kernel nothing could run reads to a guest like a kernel that faulted, and the difference
/// belongs to whoever is running this program.
compiled: u64 = 0,
refused: u64 = 0,

/// What a warp reports where its words are words this cannot run.
///
/// The vector set and the float set are not lifted yet, so a kernel that holds one reaches this.
/// The hardware reports no such code, because a fault code there is whatever register an `ecall`
/// named, which is why the count above is the honest signal and this is only what the warp carries
/// back.
pub const refused_code: u32 = 0xffff_ffff;

pub const Region = struct {
    /// The byte offset into the aperture the region starts at.
    entry: u32,
    code: vulcan.native.CodeBuffer,
};

/// What one warp holds: the state the compiled code reads and writes, and whoever answers the
/// accesses that code does not serve itself. The state is first, because its address is the only
/// argument a compiled region takes.
const State = extern struct {
    warp: lift.Warp = .{},
    jit: *Jit = undefined,
};

/// A compiled region, as something to call.
const Run = *const fn (state: *lift.Warp) callconv(.c) u32;

/// What an engine needs to answer a kernel's accesses.
pub const Parts = struct {
    /// The card's memory, and the fabric address it starts at.
    fabric: []u8,
    fabric_at: u64,
    /// The private scratch of every warp, and the address the first warp's slice is reported at.
    scratch: []u8,
    scratch_at: u64,
    /// Resident warps, which is how much state there is to hold.
    warps: u8,
};

pub const Error = error{
    /// A run of memory the atomics could not work against. A word atomic reads and writes a whole
    /// word at once, which a host cannot do to an address it holds unaligned.
    Unaligned,
    /// An address the card answers that does not fit the thirty two bits a kernel addresses with.
    TooHigh,
} || std.mem.Allocator.Error;

pub fn init(allocator: std.mem.Allocator, parts: Parts) Error!Jit {
    if (parts.fabric_at > std.math.maxInt(u32) or parts.scratch_at > std.math.maxInt(u32)) {
        return error.TooHigh;
    }
    if (@intFromPtr(parts.fabric.ptr) % 4 != 0 or @intFromPtr(parts.scratch.ptr) % 4 != 0) {
        return error.Unaligned;
    }
    return .{
        .allocator = allocator,
        .fabric = parts.fabric,
        .fabric_at = @intCast(parts.fabric_at),
        .scratch = parts.scratch,
        .scratch_at = @intCast(parts.scratch_at),
        .room = try allocator.alignedAlloc(u8, .of(State), @as(usize, parts.warps) * @sizeOf(State)),
    };
}

pub fn deinit(self: *Jit) void {
    for (self.held.items) |*each| each.code.deinit();
    for (self.spent.items) |*each| each.deinit();
    self.held.deinit(self.allocator);
    self.spent.deinit(self.allocator);
    self.allocator.free(self.room);
    self.* = undefined;
}

/// The seam the core drives this through.
pub fn engine(self: *Jit, io: std.Io) Core.Engine {
    self.io = io;
    return .{
        .ctx = self,
        .io = io,
        .room = @sizeOf(State),
        .begin = begin,
        .carry = carry,
        .halt = halt,
        .peek = peek,
        .where = where,
        .flush = flush,
    };
}

fn of(state: []u8) *State {
    return @ptrCast(@alignCast(state.ptr));
}

fn stateHeld(state: []const u8) *const State {
    return @ptrCast(@alignCast(state.ptr));
}

fn begin(ctx: *anyopaque, state: []u8, which: u8, from: Core.Launch, shape: Core.Shape) void {
    const self: *Jit = @ptrCast(@alignCast(ctx));
    const one = of(state);
    one.* = .{
        .jit = self,
        .warp = .{
            .pc = from.pc,
            .hart_id = which,
            .hart_count = shape.warps,
            // The core adds a warp's own number to the base it was launched with, so one dispatch
            // covers a run of workgroups and a kernel reads which of them it is.
            .workgroup_id = from.workgroup_base + which,
            // Zero asks for the resident warps instead, which is the answer the core's own
            // register gives.
            .grid_dim = if (from.grid_dim == 0) shape.warps else from.grid_dim,
            .args = from.args,
            .fabric = self.fabric.ptr,
            .fabric_at = self.fabric_at,
            .fabric_size = @intCast(self.fabric.len),
            .away = answer,
            .away_ctx = one,
        },
    };

    const per = shape.scratch_per_warp;
    const at = @as(usize, which) * per;
    if (per != 0 and at + per <= self.scratch.len) {
        one.warp.scratch = self.scratch[at..].ptr;
        one.warp.scratch_at = self.scratch_at + @as(u32, @intCast(at));
        one.warp.scratch_size = per;
        // A kernel starts its stack at one past the top of its own slice and spills downwards,
        // which is what the hardware answers `mscratch` with.
        one.warp.scratch_top = one.warp.scratch_at + per;
    }
}

fn carry(ctx: *anyopaque, state: []u8, program: []const u32) Core.Stop {
    const self: *Jit = @ptrCast(@alignCast(ctx));
    const one = of(state);

    const run = self.regionFor(one.warp.pc, program) catch {
        // Words this cannot run are a limit of this model and not a kernel being wrong, so the
        // warp carries a code of its own back and the count says how often it happened.
        one.warp.fault_code = refused_code;
        return .faulted;
    };

    return switch (run(&one.warp)) {
        @backingInt(lift.Exit.retired) => .retired,
        @backingInt(lift.Exit.faulted) => .faulted,
        @backingInt(lift.Exit.parked) => .parked,
        @backingInt(lift.Exit.jumped) => .jumped,
        @backingInt(lift.Exit.stopped) => .stopped,
        // A compiled region answers with one of the five. Anything else is this side having
        // compiled something other than what it lifted.
        else => unreachable,
    };
}

fn halt(ctx: *anyopaque, state: []u8, asked: bool) void {
    _ = ctx;
    // The compiled code reads this where control flows backwards. One thread writes it and another
    // reads it, so it goes as one whole access.
    @atomicStore(u32, &of(state).warp.stop, @intFromBool(asked), .release);
}

fn peek(ctx: *anyopaque, state: []const u8, which: u5) u32 {
    _ = ctx;
    return stateHeld(state).warp.x[which];
}

fn where(ctx: *anyopaque, state: []const u8) Core.Where {
    _ = ctx;
    const one = stateHeld(state);
    return .{
        .pc = one.warp.pc,
        .fault_code = one.warp.fault_code,
        .fault_at = one.warp.fault_at,
        .fault_pc = one.warp.fault_pc,
        .bus_error = one.warp.bus_error != 0,
    };
}

fn flush(ctx: *anyopaque) void {
    const self: *Jit = @ptrCast(@alignCast(ctx));
    self.lock.lockUncancelable(self.io);
    defer self.lock.unlock(self.io);

    // A host may strobe flush while a warp is inside compiled code. Freeing those pages would take
    // the ground out from under a running thread, so a flush only forgets the region here and the
    // pages go when the engine does. Room for them was taken when each one was compiled, because a
    // flush that could not take a region cannot leave it to run either.
    for (self.held.items) |each| {
        self.spent.appendAssumeCapacity(each.code);
    }
    self.held.clearRetainingCapacity();
}

/// The compiled region a warp at this program counter runs, compiling it where this is the first
/// warp to reach it.
fn regionFor(self: *Jit, pc: u32, program: []const u32) !Run {
    self.lock.lockUncancelable(self.io);
    defer self.lock.unlock(self.io);

    for (self.held.items) |*each| {
        if (each.entry == pc) return each.code.entry(Run, 0);
    }

    var func = ir.function.Function.init(self.allocator);
    defer func.deinit();

    lift.region(self.allocator, &func, program, pc) catch {
        self.refused += 1;
        return error.Refused;
    };
    if (self.tuned) _ = opt.optimize(self.allocator, &func) catch false;

    var code = vulcan.native.jitFunction(self.allocator, &func) catch {
        self.refused += 1;
        return error.Refused;
    };
    errdefer code.deinit();

    try self.spent.ensureUnusedCapacity(self.allocator, 1);
    try self.held.append(self.allocator, .{ .entry = pc, .code = code });
    self.compiled += 1;
    return self.held.items[self.held.items.len - 1].code.entry(Run, 0);
}

/// What the compiled code does not serve itself: every atomic, because neither host backend lowers
/// one yet, and every address no run of memory holds.
///
/// An access that reached nothing is reported by its address alone. The word that sent it is known
/// where a region is lifted and is not carried this far, so the card answers the fault pc with
/// zero where the hardware answers with the word.
fn answer(ctx: ?*anyopaque, at: u32, value: u32, kind: u32) callconv(.c) u64 {
    const one: *State = @ptrCast(@alignCast(ctx.?));
    const self = one.jit;

    if (kind & lift.away.atomic != 0) {
        if (self.cell(at)) |place| {
            const old = switch (@as(decode.Atomic, @fromBackingInt(@intCast((kind >> lift.away.atomic_shift) & 0b11)))) {
                .add => @atomicRmw(u32, place, .Add, value, .seq_cst),
                .swap => @atomicRmw(u32, place, .Xchg, value, .seq_cst),
                .@"and" => @atomicRmw(u32, place, .And, value, .seq_cst),
                .@"or" => @atomicRmw(u32, place, .Or, value, .seq_cst),
            };
            return lift.away.answered | old;
        }
    }

    // Nothing claimed the address. The access retires with no writeback, and the first one of
    // these explains the run, so a later access does not overwrite what it says.
    if (one.warp.bus_error == 0) {
        one.warp.bus_error = 1;
        one.warp.fault_at = at;
    }
    return 0;
}

/// The word of host memory an address names, for an access that works against a whole word.
fn cell(self: *Jit, at: u32) ?*u32 {
    if (at % 4 != 0) return null;
    if (self.fabric.len >= 4 and at >= self.fabric_at and at - self.fabric_at <= self.fabric.len - 4) {
        return @ptrCast(@alignCast(&self.fabric[at - self.fabric_at]));
    }
    if (self.scratch.len >= 4 and at >= self.scratch_at and at - self.scratch_at <= self.scratch.len - 4) {
        return @ptrCast(@alignCast(&self.scratch[at - self.scratch_at]));
    }
    return null;
}

const GuestMemory = @import("mirage-memory").GuestMemory;
const Card = device.Glacier;
const encode = vulcan.glacier.encode;
const rv = encode.rv;

/// A card with a core, an engine behind it, and the memory all three need. Driven through the
/// core's own window, which is what a transfer into the core window reaches.
const Fixture = struct {
    gpa: std.mem.Allocator,
    threads: std.Io.Threaded = undefined,
    fabric: []align(4) u8 = &.{},
    program: []u32 = &.{},
    scratch: []align(4) u8 = &.{},
    memory: GuestMemory = .{ .regions = &.{} },
    jit: Jit = undefined,
    card: Card = undefined,

    /// A card as small as one can be and still hold a core: a window of sixteen kilobytes, the
    /// smallest mode that fits it, and the profile both Chenega boards carry.
    const asked = "windowsize=16K,res=64x32,core=gc1.mi";

    fn open(self: *Fixture) !void {
        const shape = try Card.Build.parse(asked);
        self.threads = .init(self.gpa, .{});
        self.fabric = try self.gpa.alignedAlloc(u8, .fromByteUnits(4), @intCast(shape.fabricSize()));
        @memset(self.fabric, 0);
        self.program = try self.gpa.alloc(u32, shape.programWords());
        @memset(self.program, 0);
        self.scratch = try self.gpa.alignedAlloc(u8, .fromByteUnits(4), shape.scratchBytes());
        @memset(self.scratch, 0);
        self.jit = try Jit.init(self.gpa, .{
            .fabric = self.fabric,
            .fabric_at = shape.window.at,
            .scratch = self.scratch,
            .scratch_at = shape.scratchAt(),
            .warps = shape.core.?.warps,
        });
        self.card = shape.card(.{
            .memory = &self.memory,
            .fabric = self.fabric,
            .program = self.program,
            .scratch = self.scratch,
            .engine = self.jit.engine(self.threads.io()),
            .room = self.jit.room,
        });
    }

    fn close(self: *Fixture) void {
        self.card.core.?.quiet();
        self.jit.deinit();
        self.gpa.free(self.scratch);
        self.gpa.free(self.program);
        self.gpa.free(self.fabric);
        self.threads.deinit();
    }

    fn core(self: *Fixture) *Core {
        return &self.card.core.?;
    }

    /// The words of a kernel, written into the aperture the way a transfer into the core window
    /// writes them.
    fn load(self: *Fixture, words: []const u32) void {
        for (words, 0..) |each, which| {
            self.core().write(Core.program_at + which * 4, each);
        }
    }

    /// Launch one warp, which is the sequence a host driver uses: the registers, then the run bit
    /// and the strobe in one write.
    fn launch(self: *Fixture, which: u32) void {
        const one = self.core();
        one.write(Core.reg.launch_warp, which);
        one.write(Core.reg.launch_pc, 0);
        one.write(Core.reg.launch_mask, 0xf);
        one.write(Core.reg.control, Core.control_run | Core.control_launch);
    }

    /// Wait for every warp to end by itself, the way a host does: by reading status until it says
    /// the core issued and nothing of it is live. Bounded, so a kernel that never ends fails a
    /// test rather than holding the suite.
    fn settle(self: *Fixture) !void {
        var left: usize = 100_000_000;
        while (left > 0) : (left -= 1) {
            const status = self.core().read(Core.reg.status);
            if (status & Core.status_issued != 0 and status & Core.status_idle != 0) return;
            std.atomic.spinLoopHint();
        }
        return error.TestUnexpectedResult;
    }

    fn word(self: *Fixture, which: usize) u32 {
        return std.mem.readInt(u32, self.fabric[which * 4 ..][0..4], .little);
    }
};

/// What every program here starts with: the base of the window in a register, because a kernel
/// reaches memory by absolute address.
fn windowHigh() u20 {
    const shape = Card.Build.parse(Fixture.asked) catch unreachable;
    return @intCast(shape.window.at >> 12);
}

test "a kernel runs, and writes what the warp it is on was told" {
    var fixture: Fixture = .{ .gpa = std.testing.allocator };
    try fixture.open();
    defer fixture.close();

    const csr = encode.Csr;
    fixture.load(&.{
        rv.lui(.x1, windowHigh()),
        rv.csrrs(.x2, csr.mhartid, .x0),
        // A word for each warp, so what every one of them did stands on its own.
        rv.slli(.x3, .x2, 2),
        rv.add(.x1, .x1, .x3),
        rv.sw(.x2, .x1, 0),
        encode.ebreak,
    });

    const warps = fixture.card.core.?.shape.warps;
    for (0..warps) |which| fixture.launch(@intCast(which));
    try fixture.settle();

    for (0..warps) |which| {
        try std.testing.expectEqual(@as(u32, @intCast(which)), fixture.word(which));
    }
    // Nothing went anywhere it should not have, and the region was compiled once however many
    // warps ran it.
    try std.testing.expectEqual(@as(u32, 0), fixture.core().read(Core.reg.status) & Core.status_bus_error);
    try std.testing.expectEqual(@as(u64, 1), fixture.jit.compiled);
}

test "a kernel reads what its host staged for it" {
    var fixture: Fixture = .{ .gpa = std.testing.allocator };
    try fixture.open();
    defer fixture.close();

    const csr = encode.Csr;
    fixture.load(&.{
        rv.lui(.x1, windowHigh()),
        rv.csrrs(.x2, csr.launchArg(0).?, .x0),
        rv.csrrs(.x3, csr.workgroup_id, .x0),
        rv.csrrs(.x4, csr.grid_dim, .x0),
        rv.sw(.x2, .x1, 0),
        rv.sw(.x3, .x1, 4),
        rv.sw(.x4, .x1, 8),
        encode.ebreak,
    });

    const one = fixture.core();
    one.write(Core.reg.launch_arg0, 0xfeed);
    one.write(Core.reg.workgroup_base, 20);
    one.write(Core.reg.grid_dim, 64);
    fixture.launch(3);
    try fixture.settle();

    try std.testing.expectEqual(@as(u32, 0xfeed), fixture.word(0));
    // The core adds the warp's own number to the base it was launched with.
    try std.testing.expectEqual(@as(u32, 23), fixture.word(1));
    try std.testing.expectEqual(@as(u32, 64), fixture.word(2));
}

test "warps add to one word of the fabric without losing a count" {
    var fixture: Fixture = .{ .gpa = std.testing.allocator };
    try fixture.open();
    defer fixture.close();

    // An atomic is never compiled inline, so every one of these is an access this side answers.
    fixture.load(&.{
        rv.lui(.x1, windowHigh()),
        rv.addi(.x2, .x0, 1),
        rv.addi(.x3, .x0, 10),
        rv.amo(.add, .x0, .x1, .x2, false, false),
        rv.addi(.x3, .x3, -1),
        rv.bne(.x3, .x0, -8),
        encode.ebreak,
    });

    const warps = fixture.card.core.?.shape.warps;
    for (0..warps) |which| fixture.launch(@intCast(which));
    try fixture.settle();

    try std.testing.expectEqual(@as(u32, 10 * @as(u32, warps)), fixture.word(0));
}

test "a kernel that reaches an address nothing claims says where it went" {
    var fixture: Fixture = .{ .gpa = std.testing.allocator };
    try fixture.open();
    defer fixture.close();

    const nowhere: u32 = 0x5000_0000;
    fixture.load(&.{
        rv.lui(.x1, @intCast(nowhere >> 12)),
        rv.addi(.x2, .x0, 7),
        rv.sw(.x2, .x1, 0),
        encode.ebreak,
    });

    fixture.launch(0);
    try fixture.settle();

    const one = fixture.core();
    try std.testing.expect(one.read(Core.reg.status) & Core.status_bus_error != 0);
    try std.testing.expectEqual(nowhere, one.read(Core.reg.fault_at));
}

test "a kernel this cannot compile faults the warp rather than running something else" {
    var fixture: Fixture = .{ .gpa = std.testing.allocator };
    try fixture.open();
    defer fixture.close();

    // A word outside the set the core decodes. The vector and float sets are refused the same way,
    // which is what a kernel from a driver will meet first.
    fixture.load(&.{ 0xffff_ffff, encode.ebreak });

    fixture.launch(0);
    try fixture.settle();

    const one = fixture.core();
    try std.testing.expect(one.read(Core.reg.status) & Core.status_fault != 0);
    try std.testing.expectEqual(refused_code, one.read(Core.reg.fault));
    try std.testing.expectEqual(@as(u64, 1), fixture.jit.refused);
}

test "a kernel answers the same whether the lifted form was tuned or not" {
    const program = [_]u32{
        rv.lui(.x1, windowHigh()),
        rv.addi(.x2, .x0, 6),
        rv.addi(.x3, .x0, 7),
        rv.mul(.x4, .x2, .x3),
        rv.slli(.x5, .x4, 2),
        rv.sub(.x6, .x5, .x2),
        rv.sw(.x6, .x1, 0),
        encode.ebreak,
    };

    var answers: [2]u32 = @splat(0);
    for (&answers, 0..) |*answer_at, pass| {
        var fixture: Fixture = .{ .gpa = std.testing.allocator };
        try fixture.open();
        defer fixture.close();

        fixture.jit.tuned = pass == 0;
        fixture.load(&program);
        fixture.launch(0);
        try fixture.settle();
        answer_at.* = fixture.word(0);
    }

    try std.testing.expectEqual(@as(u32, 6 * 7 * 4 - 6), answers[0]);
    try std.testing.expectEqual(answers[0], answers[1]);
}
