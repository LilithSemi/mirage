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
//! Words are run by an engine the caller gives it, on a thread of their own per warp. A core
//! without one answers a launch as a kernel that retired at once, which is what a host sees from a
//! kernel that wrote nothing, and `launches` is how a test tells those two apart.
//!
//! A THREAD PER WARP, rather than one per core. A resident kernel waits for work by spinning on a
//! word its host writes, so a warp that ran until it finished would hold every other warp of the
//! core forever. On the hardware the warps issue round robin and none of them can starve another.

const std = @import("std");
const testing = @import("mirage-testing");

const Core = @This();

/// Whether the target this is built for has threads under it.
///
/// A build with no operating system has no engine to run words with either, so nothing it
/// compiles ever reaches the waiting below. The alternative is a device model that will not
/// type check for a firmware target, which is where the rest of this library has to work.
const threaded = @import("builtin").target.os.tag != .freestanding;

const Threads = if (threaded) [max_warps]?std.Thread else void;

/// Take the lock the warps share, or do nothing where there are no warps to keep apart.
fn take(self: *Core) void {
    const engine = self.engine orelse return;
    self.keep.lock.lockUncancelable(engine.io);
}

fn give(self: *Core) void {
    const engine = self.engine orelse return;
    self.keep.lock.unlock(engine.io);
}

/// Wait for another warp to say something changed. The lock is given up while waiting and held
/// again on the way out.
fn hold(self: *Core) void {
    const engine = self.engine orelse return;
    self.keep.waking.waitUncancelable(engine.io, &self.keep.lock);
}

fn wake(self: *Core) void {
    const engine = self.engine orelse return;
    self.keep.waking.broadcast(engine.io);
}

/// The lock the warps of one core share, and the waiting a barrier is built from.
///
/// Both need an `Io` to work, which only an engine has, so the core takes neither where it has no
/// engine: with nothing running words there is one thread and nothing to keep apart.
const Keeper = struct {
    lock: std.Io.Mutex = .init,
    waking: std.Io.Condition = .init,
};

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

/// The rest of the generation, smallest to largest, from the same place. A profile is a build of
/// the hardware and not a dial, so a caller asks for one of these rather than for any pair of
/// numbers.
///
/// The warp width is what a kernel is compiled against, so a kernel built for one width does not
/// run on another. The resident warp count is not: it changes how much latency a core hides.
pub const gc1n: Shape = .{ .warps = 4, .lanes = 4, .width = 4 };
pub const gc1s: Shape = .{ .warps = 8, .lanes = 8, .width = 8 };
pub const gc1f: Shape = .{ .warps = 8, .lanes = 16, .width = 16 };
pub const gc1ma: Shape = .{ .warps = 16, .lanes = 16, .width = 16 };

/// The profile of this name, spelled the way `devices.nix` spells it. A name that is not one of
/// these is a core nobody builds.
pub fn profile(name: []const u8) ?Shape {
    const every = [_]struct { []const u8, Shape }{
        .{ "gc1.n", gc1n },
        .{ "gc1.mi", gc1mi },
        .{ "gc1.s", gc1s },
        .{ "gc1.f", gc1f },
        .{ "gc1.ma", gc1ma },
    };
    for (every) |each| {
        if (std.mem.eql(u8, each[0], name)) return each[1];
    }
    return null;
}

shape: Shape,
/// The instruction aperture. The caller owns it, and a build may hold fewer words than the
/// aperture addresses.
program: []u32,
/// The private scratch, one slice of `scratch_per_warp` bytes per warp. Nothing on the bus can
/// reach it, so the debug peek is the only way a host sees a spill.
scratch: []u8 = &.{},
/// Every warp's scalar registers, where no engine runs the words. An engine keeps its own, in
/// whatever shape it needs, and the debug view asks it instead.
registers: [max_warps][warp_registers]u32 = @splat(@splat(0)),

/// Whoever runs the words, where the caller gave the core one.
engine: ?Engine = null,
/// Room for every warp's state, `Engine.room` bytes each. The caller owns it, like the aperture.
room: []u8 = &.{},

/// The warps that are running, and the ones parked at a barrier, by bit.
busy: u16 = 0,
parked: u16 = 0,
/// Which release a parked warp waits for. A barrier moves this on rather than clearing a flag, so
/// a warp slow to wake does not take the next barrier's release as its own.
released: u64 = 0,
/// Every warp was asked to stop. A kernel cannot see this, and without it a host could not take a
/// spinning core down.
stopping: bool = false,
/// What keeps the warps apart, and the thread each one runs on.
keep: Keeper = .{},
threads: Threads = if (threaded) @splat(null) else {},

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
/// Launches the host could not be given a thread for. A guest cannot be told about this and must
/// not be, because it reads as a kernel that finished, so the count is the only way it shows.
unthreaded: u64 = 0,
/// Barriers released, which is how a test tells warps that met from warps that merely finished.
releases: u64 = 0,

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

/// Whoever turns the words of a kernel into something that runs, and holds what one warp needs
/// while it does.
///
/// A seam rather than a detail. The words are RISC-V, so running them on the host means compiling
/// them, and a compiler does not belong inside a device model. The core keeps the threads, the
/// barrier and the registers a host reads through its window; an engine keeps the program counter
/// and the register file, because only it knows what shape they are in.
pub const Engine = struct {
    ctx: *anyopaque,
    /// What the waiting is done through. A barrier parks a warp, and parking is something only the
    /// host can do.
    io: std.Io,
    /// Bytes of state one warp needs.
    room: usize,
    /// Set a warp up for a launch: where it starts, which lanes it runs, and who it is.
    begin: *const fn (ctx: *anyopaque, state: []u8, which: u8, of: Launch, shape: Shape) void,
    /// Run it from where it is until it stops, and say why.
    carry: *const fn (ctx: *anyopaque, state: []u8, program: []const u32) Stop,
    /// Ask it to stop where control next flows backwards.
    halt: *const fn (ctx: *anyopaque, state: []u8, asked: bool) void,
    /// One scalar register of a warp, for the debug view a host reads.
    peek: *const fn (ctx: *anyopaque, state: []const u8, which: u5) u32,
    /// Where the warp is, and what it left behind.
    where: *const fn (ctx: *anyopaque, state: []const u8) Where,
    /// Forget whatever was made of the words.
    ///
    /// An engine that turns a program into something else holds the result, and the words it was
    /// made from can be rewritten under it. A host that rewrites a program between launches
    /// strobes flush, and without this a warp would run what the words said before.
    flush: *const fn (ctx: *anyopaque) void,
};

/// Why a warp gave itself back.
pub const Stop = enum {
    /// `ebreak`. The warp is finished.
    retired,
    /// `ecall`. The code it reported is in `Where`.
    faulted,
    /// A barrier. It waits for every other live warp of this core.
    parked,
    /// A jump to an address a register held. The engine carries on from there, and the core only
    /// has to ask it again.
    jumped,
    /// It was asked to stop.
    stopped,
};

/// What a warp left behind when it stopped.
pub const Where = struct {
    pc: u32 = 0,
    fault_code: u32 = 0,
    fault_at: u32 = 0,
    fault_pc: u32 = 0,
    bus_error: bool = false,
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
    if (self.busy == 0) value |= status_idle;
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
    // Reading a register of a warp that is running is racy by nature. It is what a host asked for,
    // and the halt on fault bit is how a host reads a register file that stands still.
    if (self.engine) |engine| {
        return engine.peek(engine.ctx, self.stateHeld(@intCast(warp)), @intCast(which));
    }
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

    // Every register below is shared with the threads the warps run on, so a read of one is taken
    // under the same lock they change it under. A read of the aperture above is not: the words a
    // warp fetched are the words it was compiled from, and a host that rewrites them strobes
    // flush.
    self.take();
    defer self.give();

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

    const at = within & ~@as(u64, 3);
    // The one write that starts and stops threads, so it takes the lock for itself rather than
    // under one held here.
    if (at == reg.control) return self.control(value);

    self.take();
    defer self.give();

    switch (at) {
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
            const from_args = at -% reg.launch_arg0;
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
    if (value & control_flush != 0) {
        self.flushes += 1;
        if (self.engine) |engine| engine.flush(engine.ctx);
    }

    // Held in reset the core stops, and every warp of it with the core. Outside the lock, because
    // this waits for threads that take it themselves.
    if (!run) self.quiet();

    self.take();
    self.running = run;
    // Held in reset the sticky clears too, so a host that stops a core and reads status cannot
    // see the issue of the launch before.
    if (!run) self.issued = false;
    if (!launching) {
        self.give();
        return;
    }

    // The strobe takes a copy, so the arguments a kernel reads are the ones written before it
    // started rather than whatever a host writes next.
    self.live = self.staged;
    self.launches += 1;
    self.give();

    self.start();
}

/// The state of one warp, inside the room the caller gave the core.
fn stateOf(self: *Core, which: u8) []u8 {
    const engine = self.engine.?;
    const from = engine.room * which;
    // The caller sized this, so room for a warp the core was built with is their invariant.
    std.debug.assert(from + engine.room <= self.room.len);
    return self.room[from..][0..engine.room];
}

fn stateHeld(self: *const Core, which: u8) []const u8 {
    const engine = self.engine.?;
    const from = engine.room * which;
    std.debug.assert(from + engine.room <= self.room.len);
    return self.room[from..][0..engine.room];
}

/// Begin the warp the launch registers name.
///
/// A strobe naming a warp that is already running is dropped. A warp holds one program counter and
/// one register file, so it cannot be entered twice, and the hardware has nowhere to put a second
/// entry either.
fn start(self: *Core) void {
    const engine = self.engine orelse {
        // With nothing to run the words, a launch is a kernel that retired without writing
        // anything, which is a state the hardware has too.
        self.take();
        defer self.give();
        self.issued = true;
        return;
    };

    const which: u8 = @truncate(self.live.warp);
    if (which >= self.shape.warps) return;
    const bit = @as(u16, 1) << @intCast(which);

    self.take();
    if (self.busy & bit != 0) {
        self.give();
        return;
    }
    self.busy |= bit;
    self.issued = true;
    self.give();

    const state = self.stateOf(which);
    engine.begin(engine.ctx, state, which, self.live, self.shape);
    engine.halt(engine.ctx, state, false);

    if (!threaded) return;
    self.threads[which] = std.Thread.spawn(.{}, Core.carry, .{ self, which }) catch {
        // A thread the host would not give is resource exhaustion and not the guest being wrong,
        // so the warp never runs and the core reads as one that issued and finished. Running it
        // here instead would hold the guest inside one register write for as long as the kernel
        // takes, and a resident kernel never ends.
        self.take();
        defer self.give();
        self.busy &= ~bit;
        self.unthreaded += 1;
        return;
    };
}

/// One warp, on its own thread, until it stops for a reason that ends it.
fn carry(self: *Core, which: u8) void {
    const engine = self.engine.?;
    const state = self.stateOf(which);

    while (true) {
        switch (engine.carry(engine.ctx, state, self.program)) {
            // A jump to an address a register held. The engine knows where it went, so it only
            // has to be asked again. The stop is read here as well, because a kernel that jumps
            // to itself would otherwise never read one.
            .jumped => if (self.leaving()) break,
            .parked => if (!self.park(which)) break,
            .retired, .stopped => break,
            .faulted => {
                const left = engine.where(engine.ctx, state);
                self.take();
                // The first fault wins, so the code explains the run rather than whichever warp
                // failed most recently.
                if (!self.faulted) {
                    self.faulted = true;
                    self.fault_code = left.fault_code;
                }
                self.give();
                break;
            },
        }
    }

    // An access that went nowhere is reported whatever ended the warp: it retires with no
    // writeback and the warp carries on, so a kernel that lost a load still reaches its end.
    const left = engine.where(engine.ctx, state);
    if (left.bus_error) {
        self.take();
        if (!self.bus_error) {
            self.bus_error = true;
            self.fault_at = left.fault_at;
            self.fault_pc = left.fault_pc;
            self.fault_warp = which;
        }
        self.give();
    }

    self.done(which);
}

/// Whether the warps were asked to stop.
fn leaving(self: *Core) bool {
    self.take();
    defer self.give();
    return self.stopping;
}

/// Hold a warp until every other live warp of this core reaches a barrier.
///
/// Returns whether it carries on. A warp asked to stop leaves rather than waiting for one that is
/// never going to arrive, which is the difference between a host taking a core down and a hang.
fn park(self: *Core, which: u8) bool {
    const bit = @as(u16, 1) << @intCast(which);
    self.take();
    defer self.give();

    self.parked |= bit;
    if (self.parked == self.busy) {
        // Every live warp is here. A warp that has exited is not one of them, which is why a
        // barrier at the end of a kernel does not hold the rest forever.
        self.parked = 0;
        self.released += 1;
        self.releases += 1;
        self.wake();
        return !self.stopping;
    }

    const mine = self.released;
    while (self.released == mine and !self.stopping) self.hold();
    if (self.released == mine) {
        self.parked &= ~bit;
        return false;
    }
    return true;
}

/// A warp that has stopped for good. One leaving can be what completes a barrier for the rest.
fn done(self: *Core, which: u8) void {
    const bit = @as(u16, 1) << @intCast(which);
    self.take();
    defer self.give();

    self.busy &= ~bit;
    self.parked &= ~bit;
    if (self.busy != 0 and self.parked == self.busy) {
        self.parked = 0;
        self.released += 1;
        self.releases += 1;
        self.wake();
    }
}

/// Ask every warp to stop, and wait for each one.
///
/// Called where a host holds the core in reset, and by whoever takes the card down. A thread still
/// writing into the card's memory after that memory is gone is not something a guest can be blamed
/// for, so this is not optional.
pub fn quiet(self: *Core) void {
    const engine = self.engine orelse return;

    self.take();
    self.stopping = true;
    for (0..self.shape.warps) |which| {
        engine.halt(engine.ctx, self.stateOf(@intCast(which)), true);
    }
    self.wake();
    self.give();

    if (threaded) {
        for (&self.threads) |*each| {
            if (each.*) |thread| {
                thread.join();
                each.* = null;
            }
        }
    }

    self.take();
    defer self.give();
    self.stopping = false;
    self.parked = 0;
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

/// The tests that need threads, which a freestanding build has none of. A comptime false branch is
/// never analysed, so this is how they compile for a target that could not run them.
const threaded_tests = if (!threaded) struct {} else struct {
    /// An engine that does what a test tells it to rather than running any words. The core's job
    /// is the threads, the barrier and what a host reads, and that is what this leaves to test.
    const Faker = struct {
        /// What a warp answers each time it is asked to carry on. The last answer repeats.
        script: []const Stop,
        /// Held shut until a test opens it, so every warp of a dispatch is live before any of them
        /// reaches a barrier. A warp that arrives at one alone is the only live warp and goes
        /// straight through, on the hardware as much as here.
        gate: std.atomic.Value(bool) = .init(false),
        begun: u32 = 0,
        flushed: u32 = 0,

        /// What one warp holds. An engine owns this shape, and the core only holds the room.
        const State = extern struct {
            which: u8 = 0,
            step: u8 = 0,
            stopping: u8 = 0,
            bus: u8 = 0,
            pc: u32 = 0,
            code: u32 = 0,
            x: [warp_registers]u32 = @splat(0),
        };

        /// How long a warp waits for something it was told to wait for. Bounded, so a fault in the
        /// core under test fails a test rather than holding the suite forever.
        const patience = 100_000_000;

        fn engine(self: *Faker, io: std.Io) Engine {
            return .{
                .ctx = self,
                .io = io,
                .room = @sizeOf(State),
                .begin = Faker.begin,
                .carry = Faker.carry,
                .halt = Faker.halt,
                .peek = Faker.peek,
                .where = Faker.where,
                .flush = Faker.flush,
            };
        }

        fn of(room: []u8) *State {
            return @ptrCast(@alignCast(room.ptr));
        }

        fn held(room: []const u8) *const State {
            return @ptrCast(@alignCast(room.ptr));
        }

        fn begin(ctx: *anyopaque, state: []u8, which: u8, of_launch: Launch, shape: Shape) void {
            const self: *Faker = @ptrCast(@alignCast(ctx));
            _ = shape;
            const one = of(state);
            one.* = .{ .which = which, .pc = of_launch.pc };
            // Something a test can read back through the debug view, from the launch and from the
            // warp's own identity.
            one.x[1] = which;
            one.x[2] = of_launch.args[0];
            self.begun += 1;
        }

        fn carry(ctx: *anyopaque, state: []u8, program: []const u32) Stop {
            const self: *Faker = @ptrCast(@alignCast(ctx));
            _ = program;
            const one = of(state);

            if (one.step == 0) {
                var left: usize = patience;
                while (!self.gate.load(.acquire) and left > 0) : (left -= 1) std.atomic.spinLoopHint();
            }

            const at = @min(one.step, self.script.len - 1);
            one.step += 1;
            one.pc = 4 * @as(u32, one.step);

            const why = self.script[at];
            if (why == .faulted) one.code = 40 + @as(u32, one.which);
            if (why == .stopped) {
                // The shape a resident kernel has: it waits for its host and gives nothing back
                // until it is asked to.
                var left: usize = patience;
                while (@atomicLoad(u8, &one.stopping, .acquire) == 0 and left > 0) : (left -= 1) {
                    std.atomic.spinLoopHint();
                }
            }
            return why;
        }

        fn halt(ctx: *anyopaque, state: []u8, asked: bool) void {
            _ = ctx;
            @atomicStore(u8, &of(state).stopping, @intFromBool(asked), .release);
        }

        fn flush(ctx: *anyopaque) void {
            const self: *Faker = @ptrCast(@alignCast(ctx));
            self.flushed += 1;
        }

        fn peek(ctx: *anyopaque, state: []const u8, which: u5) u32 {
            _ = ctx;
            return held(state).x[which];
        }

        fn where(ctx: *anyopaque, state: []const u8) Where {
            _ = ctx;
            const one = held(state);
            return .{ .pc = one.pc, .fault_code = one.code, .bus_error = one.bus != 0 };
        }
    };

    /// A core with an engine behind it, and the room every warp of it needs.
    const Fixture = struct {
        words: [16]u32 = @splat(0),
        room: [max_warps * @sizeOf(Faker.State)]u8 align(@alignOf(Faker.State)) = @splat(0),

        fn core(self: *Fixture, with: Engine) Core {
            return .{ .shape = gc1mi, .program = &self.words, .engine = with, .room = &self.room };
        }
    };

    /// Wait for every warp to end by itself, the way a host does: by reading status until it says
    /// the core issued and nothing of it is live. Bounded, so a core that never finishes fails a
    /// test rather than holding the suite.
    ///
    /// Not `quiet`, which asks the warps to stop. A test that waited with that would pass whether
    /// the warps finished their work or were cut off part way through it.
    fn settle(one: *Core) !void {
        var left: usize = Faker.patience;
        while (left > 0) : (left -= 1) {
            const status = one.read(reg.status);
            if (status & status_issued != 0 and status & status_idle != 0) return;
            std.atomic.spinLoopHint();
        }
        return error.TestUnexpectedResult;
    }

    /// Launch one warp, the way a host does: the registers, then run and the strobe together.
    fn launch(one: *Core, which: u32, at: u32) void {
        one.write(reg.launch_warp, which);
        one.write(reg.launch_pc, at);
        one.write(reg.launch_mask, 0xf);
        one.write(reg.control, control_run | control_launch);
    }

    test "a launch runs a warp on a thread of its own" {
        var threads: std.Io.Threaded = .init(std.testing.allocator, .{});
        defer threads.deinit();

        var faker: Faker = .{ .script = &.{.retired} };
        faker.gate.store(true, .release);
        var fixture: Fixture = .{};
        var one = fixture.core(faker.engine(threads.io()));

        launch(&one, 0, 0);
        try settle(&one);
        defer one.quiet();

        try testing.expectEqual(@as(u32, 1), faker.begun);
        try testing.expectEqual(@as(u64, 1), one.launches);
        try testing.expectEqual(@as(u16, 0), one.busy);
        // Issued and idle together, which is how a host tells a kernel that finished from one that
        // never started.
        try testing.expectEqual(status_run | status_issued | status_idle, one.read(reg.status));
    }

    test "a strobe naming a warp that is already running is dropped" {
        var threads: std.Io.Threaded = .init(std.testing.allocator, .{});
        defer threads.deinit();

        var faker: Faker = .{ .script = &.{.stopped} };
        faker.gate.store(true, .release);
        var fixture: Fixture = .{};
        var one = fixture.core(faker.engine(threads.io()));

        launch(&one, 0, 0);
        // The same warp again while the first is still running. A warp holds one program counter
        // and one register file, so there is nowhere to put a second entry.
        launch(&one, 0, 0);
        one.quiet();

        try testing.expectEqual(@as(u32, 1), faker.begun);
        try testing.expectEqual(@as(u64, 2), one.launches);
    }

    test "every live warp meets at a barrier before any of them carries on" {
        var threads: std.Io.Threaded = .init(std.testing.allocator, .{});
        defer threads.deinit();

        var faker: Faker = .{ .script = &.{ .parked, .retired } };
        var fixture: Fixture = .{};
        var one = fixture.core(faker.engine(threads.io()));

        launch(&one, 0, 0);
        launch(&one, 1, 0);
        // Both are live now, so neither can take the barrier on its own.
        faker.gate.store(true, .release);
        try settle(&one);
        defer one.quiet();

        try testing.expectEqual(@as(u32, 2), faker.begun);
        try testing.expectEqual(@as(u64, 1), one.releases);
        try testing.expectEqual(@as(u16, 0), one.busy);
        // Both got past it, which is the point: a release that let one warp through and not the
        // other would leave a step behind.
        try testing.expectEqual(@as(u8, 2), Faker.of(one.room[0..@sizeOf(Faker.State)]).step);
        try testing.expectEqual(@as(u8, 2), Faker.of(one.room[@sizeOf(Faker.State)..][0..@sizeOf(Faker.State)]).step);
    }

    test "a warp alone at a barrier is the only live warp and goes straight through" {
        var threads: std.Io.Threaded = .init(std.testing.allocator, .{});
        defer threads.deinit();

        var faker: Faker = .{ .script = &.{ .parked, .retired } };
        faker.gate.store(true, .release);
        var fixture: Fixture = .{};
        var one = fixture.core(faker.engine(threads.io()));

        launch(&one, 0, 0);
        try settle(&one);
        defer one.quiet();

        // It released itself rather than waiting for a warp nothing launched. A barrier at the end
        // of a kernel would deadlock otherwise, and a warp that has exited holds nobody.
        try testing.expectEqual(@as(u64, 1), one.releases);
        try testing.expectEqual(@as(u16, 0), one.busy);
    }

    test "a core held in reset stops a warp that would not stop by itself" {
        var threads: std.Io.Threaded = .init(std.testing.allocator, .{});
        defer threads.deinit();

        var faker: Faker = .{ .script = &.{.stopped} };
        faker.gate.store(true, .release);
        var fixture: Fixture = .{};
        var one = fixture.core(faker.engine(threads.io()));

        launch(&one, 0, 0);
        try std.testing.expect(one.read(reg.control) & control_run != 0);

        // The only way a host takes a kernel down that waits for work and never retires.
        one.write(reg.control, 0);

        try testing.expectEqual(@as(u16, 0), one.busy);
        try testing.expectEqual(@as(u32, 0), one.read(reg.control));
        // Held in reset the issue sticky clears, so the launch before cannot be read as this one.
        try testing.expectEqual(@as(u32, status_idle), one.read(reg.status));
    }

    test "the first fault a warp reported is the one a host reads" {
        var threads: std.Io.Threaded = .init(std.testing.allocator, .{});
        defer threads.deinit();

        var faker: Faker = .{ .script = &.{.faulted} };
        faker.gate.store(true, .release);
        var fixture: Fixture = .{};
        var one = fixture.core(faker.engine(threads.io()));

        launch(&one, 3, 0);
        try settle(&one);
        defer one.quiet();

        // The code is the one that warp reported, and the bit beside it is what says anything
        // reported at all: code zero is a legal thing for a kernel to say.
        try testing.expectEqual(status_fault, one.read(reg.status) & status_fault);
        try testing.expectEqual(@as(u32, 43), one.read(reg.fault));
    }

    test "a flush strobe tells the engine to forget what it made of the words" {
        var threads: std.Io.Threaded = .init(std.testing.allocator, .{});
        defer threads.deinit();

        var faker: Faker = .{ .script = &.{.retired} };
        faker.gate.store(true, .release);
        var fixture: Fixture = .{};
        var one = fixture.core(faker.engine(threads.io()));

        // The sequence a host uses to run a second, different kernel on the same core: the new
        // words, the strobe that says the old ones are gone, then the launch.
        one.write(program_at, 0x0010_0073);
        one.write(reg.control, control_run | control_flush);
        try testing.expectEqual(@as(u32, 1), faker.flushed);

        launch(&one, 0, 0);
        try settle(&one);
        defer one.quiet();
        try testing.expectEqual(@as(u32, 1), faker.flushed);
    }

    test "the debug view reads the register file the engine holds" {
        var threads: std.Io.Threaded = .init(std.testing.allocator, .{});
        defer threads.deinit();

        var faker: Faker = .{ .script = &.{.retired} };
        faker.gate.store(true, .release);
        var fixture: Fixture = .{};
        var one = fixture.core(faker.engine(threads.io()));

        one.write(reg.launch_arg0, 0x1234_0000);
        launch(&one, 2, 0);
        try settle(&one);
        defer one.quiet();

        // Warp two's own registers, read through the window rather than out of the core: with an
        // engine the register file is the engine's and the core does not keep a copy.
        one.write(reg.debug_select, (2 << 8) | 1);
        try testing.expectEqual(@as(u32, 2), one.read(reg.debug_data));
        one.write(reg.debug_select, (2 << 8) | 2);
        try testing.expectEqual(@as(u32, 0x1234_0000), one.read(reg.debug_data));
    }
};

test {
    _ = threaded_tests;
}
