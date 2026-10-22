//! One Glacier core as a host sees it: the window it is launched through, the aperture a program
//! is written into, and the registers that say what the last launch did.
//!
//! A core is a device and does not start itself. It leaves reset halted. A host writes the program
//! into the aperture, then the launch registers, then CONTROL with RUN and the launch strobe
//! together, which is the sequence the kernel module and the simulator both use.
//!
//! The layout comes from `pipelined_core_soc.dart` and not from the card's C header. The header
//! has no fault registers, no counters and no debug views, and it names two offsets by their write
//! side only. A model built from it would answer a read of 0x34 with the workgroup base, where the
//! hardware answers with the address of the first access that went nowhere.
//!
//! Nothing here runs a kernel yet. A launch therefore reads back as a core that issued and
//! finished, which is what the hardware says about a kernel that retired without writing anything.
//! `launches` is how a test tells those two apart.

const std = @import("std");
const testing = @import("mirage-testing");

const Core = @This();

/// What the device table names it, and what the first word of the window answers.
pub const kind: u32 = 0x474c4352;

/// A core's window, which is also the step from one core to the next.
pub const window_size = 0x1_0000;

/// Where the instruction aperture starts in the window, and the words it can address. A build may
/// hold fewer than it can address, which is what the program words register is for.
pub const program_at = 0x8000;
pub const max_program_words = program_at / 4;

/// Resident warps a core can be built with. The debug selector carries five bits for a warp, and
/// no profile asks for more than this.
pub const max_warps = 16;

/// Scalar registers a warp has, x0 included.
pub const warp_registers = 32;

/// The launch arguments, which a kernel reads as read only control registers. They belong to the
/// core and not to a warp, so every warp of one launch reads the same values.
pub const launch_args = 8;

/// The register offsets, public so a host and this decode read the same numbers and the two cannot
/// drift apart.
pub const reg = struct {
    pub const version = 0x00;
    pub const control = 0x04;
    pub const launch_warp = 0x08;
    pub const launch_pc = 0x0c;
    pub const launch_mask = 0x10;
    pub const status = 0x14;
    pub const caps = 0x18;
    pub const fault = 0x1c;
    pub const perf_cycle = 0x20;
    pub const perf_issued = 0x24;
    pub const perf_mem_wait = 0x28;
    pub const perf_mem_ops = 0x2c;
    pub const perf_high = 0x30;
    /// Read and written under different names. A read answers the first access that faulted, and a
    /// write stages what the next launch latches.
    pub const fault_at = 0x34;
    pub const workgroup_base = 0x34;
    pub const fault_pc = 0x38;
    pub const grid_dim = 0x38;
    pub const fault_warp = 0x3c;
    pub const launch_arg0 = 0x40;
    pub const debug_select = 0x60;
    pub const debug_data = 0x64;
    pub const halt_on_fault = 0x68;
    pub const scratch_at = 0x6c;
    pub const scratch_data = 0x70;
    pub const watch_at = 0x74;
    pub const watch_pc = 0x78;
    pub const watch_data = 0x7c;
    pub const watch_fired = 0x80;
    pub const program_words = 0x84;
};

/// Bit zero of control holds the core out of reset. The other two are strobes that clear
/// themselves, so a read of control answers with run alone.
pub const control_run: u32 = 1 << 0;
pub const control_launch: u32 = 1 << 1;
pub const control_flush: u32 = 1 << 2;

pub const status_run: u32 = 1 << 0;
/// A warp issued since the core was last held in reset. A host pairs it with idle to tell a kernel
/// that finished from one that never started.
pub const status_issued: u32 = 1 << 1;
pub const status_idle: u32 = 1 << 2;
/// An access went to an address no slave claims. The access retires with no writeback and the warp
/// carries on, so without this bit that run looks like a correct one.
pub const status_bus_error: u32 = 1 << 3;
/// A warp retired with an `ecall`. Code zero is a legal thing to report, so the code alone cannot
/// say whether anything reported it.
pub const status_fault: u32 = 1 << 4;
/// The three watchdogs, each with its own bit. They shared the bus error bit once, which made a
/// stuck load and a bad pointer read the same.
pub const status_mem_timeout: u32 = 1 << 5;
pub const status_fetch_timeout: u32 = 1 << 6;
pub const status_barrier_timeout: u32 = 1 << 7;

const caps_warps_shift = 0;
const caps_lanes_shift = 8;
const caps_width_shift = 16;
const caps_field: u32 = 0xff;
/// This build answers the counters. A host without the bit is talking to an older core and must
/// not read a counter as a count.
const caps_perf: u32 = 1 << 24;

/// What the core was built with. A host can guess none of it, which is why there is a caps
/// register at all.
pub const Shape = struct {
    /// Resident warps, which bounds the warp a launch may name.
    warps: u8,
    /// Lanes in the datapath. Fewer than the warp width makes a warp stream over them.
    lanes: u8,
    /// Lanes one vector instruction covers.
    width: u8,
    /// Bytes of private scratch each warp owns. A kernel reads the size rather than assuming it,
    /// so it is not part of the kernel ABI.
    scratch_per_warp: u32 = 2048,
    perf: bool = true,
};

/// The profile the Chenega boards are built with: four lanes with eight warps to hide latency
/// behind. From `config.dart` and `devices.nix`, so it is the shape of the card and not a choice
/// made here.
pub const gc1mi: Shape = .{ .warps = 8, .lanes = 4, .width = 4 };

shape: Shape,
/// The instruction aperture. The caller owns it, and a build may hold fewer words than the
/// aperture addresses.
program: []u32,
/// The private scratch, one slice of `scratch_per_warp` bytes per warp. Nothing on the bus can
/// reach it, so the debug peek is the only way a host sees a spill.
scratch: []u8 = &.{},
/// Every warp's scalar registers. A halted warp keeps them, which is how a host sees why one
/// faulted.
registers: [max_warps][warp_registers]u32 = @splat(@splat(0)),

/// Whether the core is out of reset. A launch strobe while it is held in reset does nothing.
running: bool = false,

/// What a launch will use, and what the launch it strobed is using. The strobe copies one to the
/// other, so a kernel reads the arguments that were written before it started.
staged: Launch = .{},
live: Launch = .{},

issued: bool = false,
bus_error: bool = false,
faulted: bool = false,
mem_timeout: bool = false,
fetch_timeout: bool = false,
barrier_timeout: bool = false,

/// The first fault wins, so the code explains the run rather than whichever warp failed last.
fault_code: u32 = 0,
fault_at: u32 = 0,
fault_pc: u32 = 0,
fault_warp: u32 = 0,

/// Halt the core the cycle a fault is first raised. A faulting access retires with no writeback
/// and the warp carries on, so without this the register file holds a later value by the time a
/// host reads it.
halt_on_fault: bool = false,

/// Which warp and register the debug view answers with. Readable, so a host can tell a selector
/// that did not take from a register that holds zero.
select: u32 = 0,
/// The scratch address the peek answers with.
peek_at: u32 = 0,

/// A scratch write to watch for, and what the write that fired was.
watch_at: u32 = 0,
watch_pc: u32 = 0,
watch_data: u32 = 0,
watch_fired: u32 = 0,

/// The counters, and the high half the last low word read captured. One register serves every
/// counter because a host takes the two halves of one together.
cycles: u64 = 0,
instructions: u64 = 0,
memory_waits: u64 = 0,
memory_ops: u64 = 0,
captured: u32 = 0,

/// Launches, flush strobes and words written into the aperture. None of them is a register. A test
/// needs to tell a host that drove the sequence from one that wrote to a window and gave up.
launches: u64 = 0,
flushes: u64 = 0,
program_writes: u64 = 0,

/// What a host stages before it launches, and what the strobe latches.
pub const Launch = struct {
    warp: u32 = 0,
    pc: u32 = 0,
    lanes: u32 = 0,
    workgroup_base: u32 = 0,
    /// Workgroups in the whole dispatch. Zero asks for the hart count instead.
    grid_dim: u32 = 0,
    args: [launch_args]u32 = @splat(0),
};

fn capsWord(self: *const Core) u32 {
    var value: u32 = 0;
    value |= @as(u32, self.shape.warps) << caps_warps_shift;
    value |= @as(u32, self.shape.lanes) << caps_lanes_shift;
    value |= @as(u32, self.shape.width) << caps_width_shift;
    if (self.shape.perf) value |= caps_perf;
    return value;
}

fn statusWord(self: *const Core) u32 {
    var value: u32 = 0;
    if (self.running) value |= status_run;
    if (self.issued) value |= status_issued;
    // No warp of this model is ever live, because nothing here runs a word.
    value |= status_idle;
    if (self.bus_error) value |= status_bus_error;
    if (self.faulted) value |= status_fault;
    if (self.mem_timeout) value |= status_mem_timeout;
    if (self.fetch_timeout) value |= status_fetch_timeout;
    if (self.barrier_timeout) value |= status_barrier_timeout;
    return value;
}

/// The register the debug view selects: the register in bits four to zero, the warp in bits twelve
/// to eight. Reading a register of a warp the core was not built with answers zero.
fn selected(self: *const Core) u32 {
    const which = self.select & 0x1f;
    const warp = (self.select >> 8) & 0x1f;
    if (warp >= self.shape.warps or warp >= max_warps) return 0;
    return self.registers[@intCast(warp)][@intCast(which)];
}

/// A word of the scratch the peek names, or zero where the core was built with none. The peek is
/// valid while the core is halted, which is when the load and store unit is idle.
fn peeked(self: *const Core) u32 {
    if (self.scratch.len < 4) return 0;
    const at = self.peek_at & ~@as(u32, 3);
    if (at > self.scratch.len - 4) return 0;
    return std.mem.readInt(u32, self.scratch[at..][0..4], .little);
}

/// A counter's low word. Reading it captures that counter's high half, so a host that reads the
/// two in order gets halves that belong to one instant.
fn counter(self: *Core, whole: u64) u32 {
    self.captured = @truncate(whole >> 32);
    return @truncate(whole);
}

/// How many words of the aperture this build holds. Zero says the core does not report its own
/// size rather than that it holds nothing.
fn programWords(self: *const Core) u32 {
    std.debug.assert(self.program.len <= max_program_words);
    return @intCast(self.program.len);
}

/// One word of the window. Everything the window does not decode reads zero, the write only
/// registers included.
pub fn read(self: *Core, within: u64) u32 {
    std.debug.assert(within < window_size);

    if (within >= program_at) {
        const word = (within - program_at) / 4;
        if (word >= self.program.len) return 0;
        return self.program[@intCast(word)];
    }

    return switch (within & ~@as(u64, 3)) {
        reg.version => kind,
        // Both strobes clear themselves, so a read answers with run alone.
        reg.control => if (self.running) control_run else 0,
        reg.status => self.statusWord(),
        reg.caps => self.capsWord(),
        reg.fault => self.fault_code,
        reg.perf_cycle => self.counter(self.cycles),
        reg.perf_issued => self.counter(self.instructions),
        reg.perf_mem_wait => self.counter(self.memory_waits),
        reg.perf_mem_ops => self.counter(self.memory_ops),
        reg.perf_high => self.captured,
        reg.fault_at => self.fault_at,
        reg.fault_pc => self.fault_pc,
        reg.fault_warp => self.fault_warp,
        reg.debug_select => self.select,
        reg.debug_data => self.selected(),
        reg.scratch_data => self.peeked(),
        reg.watch_pc => self.watch_pc,
        reg.watch_data => self.watch_data,
        reg.watch_fired => self.watch_fired,
        reg.program_words => self.programWords(),
        else => 0,
    };
}

/// One word written into the window. The core decodes words, so a caller that assembles a narrower
/// access reaches no register, which is what the hardware does with one.
pub fn write(self: *Core, within: u64, value: u32) void {
    std.debug.assert(within < window_size);

    if (within >= program_at) {
        const word = (within - program_at) / 4;
        // The aperture addresses more words than a build need hold. A write past what this one
        // holds lands nowhere, which is the trap the program words register exists to close.
        if (word >= self.program.len) return;
        self.program[@intCast(word)] = value;
        self.program_writes += 1;
        return;
    }

    switch (within & ~@as(u64, 3)) {
        reg.control => self.control(value),
        reg.launch_warp => self.staged.warp = value,
        reg.launch_pc => self.staged.pc = value,
        reg.launch_mask => self.staged.lanes = value,
        reg.workgroup_base => self.staged.workgroup_base = value,
        reg.grid_dim => self.staged.grid_dim = value,
        reg.debug_select => self.select = value,
        reg.halt_on_fault => self.halt_on_fault = value & 1 != 0,
        reg.scratch_at => self.peek_at = value,
        reg.watch_at => {
            self.watch_at = value;
            self.watch_fired = 0;
        },
        else => {
            const from_args = (within & ~@as(u64, 3)) -% reg.launch_arg0;
            if (from_args < launch_args * 4) self.staged.args[@intCast(from_args / 4)] = value;
        },
    }
}

/// A write to control: the run bit, then the two strobes.
fn control(self: *Core, value: u32) void {
    const run = value & control_run != 0;
    // A launch takes where the same write releases the core, or where it was already released. A
    // strobe into a core held in reset is swallowed.
    const launching = value & control_launch != 0 and (run or self.running);
    if (value & control_flush != 0) self.flushes += 1;

    self.running = run;
    // Held in reset the sticky clears, so a host that stops a core and reads status cannot see the
    // issue of the launch before.
    if (!run) self.issued = false;
    if (!launching) return;

    self.live = self.staged;
    self.launches += 1;
    // What a kernel that retired at once leaves behind. Nothing runs a word here, so this is the
    // whole of a launch.
    self.issued = true;
}

test "a core answers its name and the shape it was built with" {
    var words: [16]u32 = @splat(0);
    var one: Core = .{ .shape = gc1mi, .program = &words };

    try testing.expectEqual(kind, one.read(reg.version));
    try testing.expectEqual(@as(u32, 16), one.read(reg.program_words));

    const caps = one.read(reg.caps);
    try testing.expectEqual(@as(u32, 8), caps & caps_field);
    try testing.expectEqual(@as(u32, 4), (caps >> caps_lanes_shift) & caps_field);
    try testing.expectEqual(@as(u32, 4), (caps >> caps_width_shift) & caps_field);
    try std.testing.expect(caps & caps_perf != 0);
}

test "a core out of reset with nothing launched reads idle and not issued" {
    var words: [16]u32 = @splat(0);
    var one: Core = .{ .shape = gc1mi, .program = &words };

    try testing.expectEqual(status_idle, one.read(reg.status));

    one.write(reg.control, control_run);
    try testing.expectEqual(status_run | status_idle, one.read(reg.status));
    try testing.expectEqual(@as(u64, 0), one.launches);
}

test "a launch strobe into a core held in reset does nothing" {
    var words: [16]u32 = @splat(0);
    var one: Core = .{ .shape = gc1mi, .program = &words };

    one.write(reg.control, control_launch);
    try testing.expectEqual(@as(u64, 0), one.launches);
    try testing.expectEqual(@as(u32, 0), one.read(reg.status) & status_issued);

    // The same strobe with the run bit beside it is the sequence a host uses, and it launches.
    one.write(reg.control, control_run | control_launch);
    try testing.expectEqual(@as(u64, 1), one.launches);
    try testing.expectEqual(status_issued, one.read(reg.status) & status_issued);
}

test "the strobe latches the arguments that were written before it" {
    var words: [16]u32 = @splat(0);
    var one: Core = .{ .shape = gc1mi, .program = &words };

    one.write(reg.launch_arg0, 0x1111_0000);
    one.write(reg.launch_arg0 + 4 * 7, 0x7777_0000);
    one.write(reg.workgroup_base, 3);
    one.write(reg.grid_dim, 12);
    one.write(reg.launch_pc, 0x40);
    one.write(reg.launch_mask, 0xf);
    one.write(reg.control, control_run | control_launch);

    try testing.expectEqual(@as(u32, 0x1111_0000), one.live.args[0]);
    try testing.expectEqual(@as(u32, 0x7777_0000), one.live.args[7]);
    try testing.expectEqual(@as(u32, 3), one.live.workgroup_base);
    try testing.expectEqual(@as(u32, 12), one.live.grid_dim);
    try testing.expectEqual(@as(u32, 0x40), one.live.pc);
    try testing.expectEqual(@as(u32, 0xf), one.live.lanes);

    // A write after the strobe reaches the next launch and not this one.
    one.write(reg.launch_arg0, 0x2222_0000);
    try testing.expectEqual(@as(u32, 0x1111_0000), one.live.args[0]);
    try testing.expectEqual(@as(u32, 0x2222_0000), one.staged.args[0]);
}

test "the two split registers answer a read with the fault and not with what was written" {
    var words: [16]u32 = @splat(0);
    var one: Core = .{ .shape = gc1mi, .program = &words };

    one.write(reg.workgroup_base, 7);
    one.write(reg.grid_dim, 9);
    one.fault_at = 0x8004_0000;
    one.fault_pc = 0x2c;

    // A host that read these back to check its own write would be reading the hardware's answer to
    // a different question.
    try testing.expectEqual(@as(u32, 0x8004_0000), one.read(reg.fault_at));
    try testing.expectEqual(@as(u32, 0x2c), one.read(reg.fault_pc));
    try testing.expectEqual(@as(u32, 7), one.staged.workgroup_base);
    try testing.expectEqual(@as(u32, 9), one.staged.grid_dim);
}

test "holding a core in reset clears the issue it saw" {
    var words: [16]u32 = @splat(0);
    var one: Core = .{ .shape = gc1mi, .program = &words };

    one.write(reg.control, control_run | control_launch);
    try testing.expectEqual(status_issued, one.read(reg.status) & status_issued);

    one.write(reg.control, 0);
    try testing.expectEqual(@as(u32, 0), one.read(reg.status) & status_issued);
    try testing.expectEqual(@as(u32, 0), one.read(reg.control));
}

test "a program is written through the aperture and read back from it" {
    var words: [4]u32 = @splat(0);
    var one: Core = .{ .shape = gc1mi, .program = &words };

    one.write(program_at, 0x0010_0073);
    one.write(program_at + 4, 0x1000_000f);
    try testing.expectEqual(@as(u32, 0x0010_0073), one.read(program_at));
    try testing.expectEqual(@as(u32, 0x1000_000f), one.read(program_at + 4));
    try testing.expectEqual(@as(u64, 2), one.program_writes);

    // The aperture addresses eight thousand words whatever a build holds. A word past the end of
    // this one lands nowhere and reads zero, which is why a host reads the program words register.
    one.write(program_at + 4 * 4, 0xdead_beef);
    try testing.expectEqual(@as(u32, 0), one.read(program_at + 4 * 4));
    try testing.expectEqual(@as(u64, 2), one.program_writes);
}

test "a flush strobe is counted and leaves the launch alone" {
    var words: [16]u32 = @splat(0);
    var one: Core = .{ .shape = gc1mi, .program = &words };

    one.write(reg.control, control_run | control_flush);
    try testing.expectEqual(@as(u64, 1), one.flushes);
    try testing.expectEqual(@as(u64, 0), one.launches);
    try std.testing.expect(one.running);
}

test "a counter read takes its high half with it" {
    var words: [16]u32 = @splat(0);
    var one: Core = .{ .shape = gc1mi, .program = &words };
    one.cycles = 0x0000_0007_1234_5678;
    one.instructions = 0x0000_0003_0000_0001;

    try testing.expectEqual(@as(u32, 0x1234_5678), one.read(reg.perf_cycle));
    try testing.expectEqual(@as(u32, 7), one.read(reg.perf_high));

    // One register serves every counter, so it holds whichever low word was read last.
    try testing.expectEqual(@as(u32, 1), one.read(reg.perf_issued));
    try testing.expectEqual(@as(u32, 3), one.read(reg.perf_high));
}

test "the debug view answers the register the selector names" {
    var words: [16]u32 = @splat(0);
    var one: Core = .{ .shape = gc1mi, .program = &words };
    one.registers[3][10] = 0xabcd_0000;

    one.write(reg.debug_select, (3 << 8) | 10);
    try testing.expectEqual(@as(u32, 0xabcd_0000), one.read(reg.debug_data));
    // The selector reads back, so a host tells a selector that did not take from a register that
    // holds zero.
    try testing.expectEqual(@as(u32, (3 << 8) | 10), one.read(reg.debug_select));

    // A warp this core was not built with has no register file to answer with.
    one.write(reg.debug_select, (12 << 8) | 10);
    try testing.expectEqual(@as(u32, 0), one.read(reg.debug_data));
}

test "the scratch peek answers a word of the slice the core keeps to itself" {
    var words: [16]u32 = @splat(0);
    var room: [64]u8 = @splat(0);
    var one: Core = .{ .shape = gc1mi, .program = &words, .scratch = &room };
    std.mem.writeInt(u32, room[16..][0..4], 0x0f0f_0f0f, .little);

    one.write(reg.scratch_at, 16);
    try testing.expectEqual(@as(u32, 0x0f0f_0f0f), one.read(reg.scratch_data));

    // Past the end of the slice there is nothing to answer with.
    one.write(reg.scratch_at, 64);
    try testing.expectEqual(@as(u32, 0), one.read(reg.scratch_data));
}

test "an offset the window does not decode reads zero" {
    var words: [16]u32 = @splat(0);
    var one: Core = .{ .shape = gc1mi, .program = &words };

    one.write(reg.launch_warp, 5);
    one.write(reg.launch_pc, 0x80);

    // Write only registers read zero rather than the value a host put there.
    try testing.expectEqual(@as(u32, 0), one.read(reg.launch_warp));
    try testing.expectEqual(@as(u32, 0), one.read(reg.launch_pc));
    try testing.expectEqual(@as(u32, 0), one.read(0x100));
    try testing.expectEqual(@as(u32, 5), one.staged.warp);
}
