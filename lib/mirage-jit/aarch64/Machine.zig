//! One-vCPU Mirage Backend over translated guest blocks.
const std = @import("std");
const arm64 = @import("mirage-arm64");
/// The guest is aarch64 whatever the host is, so this is the aarch64 guest's backend and not the one
/// the host's hypervisor would be.
const Backend = @import("mirage-backend").For(arm64);
const GuestMemory = @import("mirage-memory").GuestMemory;
const Cpu = @import("Cpu.zig");
const Cache = @import("../aarch64.zig").Cache;
const Translate = @import("Translate.zig");
const Exception = @import("Exception.zig");

const Identification = @import("Identification.zig");

const Machine = @This();
memory: *GuestMemory,
cache: Cache,
cpu: Cpu = .{},
/// Remembered translations, shared by the fetch and the data path because the
/// two must agree: a page executable for one and not the other is not a state
/// the architecture has.
tlb: Translate.Tlb = .{},
regime_seen: [5]u64 = @splat(0),
pending_read: bool = false,
/// The level of the external interrupt line, as the interrupt controller last set it.
irq_line: bool = false,
/// True while the timer's condition has already been reported to the host. The
/// timer is a private interrupt of the controller, so the host raises it there
/// once per time it comes due, and the guest takes it as any other line.
timer_fired: bool = false,
/// What the read the host owes us is to be extended by, taken from the block when the
/// read was handed to the host, because the block's copy is spent by the time the
/// device answers.
pending_signed: Cpu.SignExtend = .none,
/// True when the read the host owes us belongs to the second access of a pair.
pending_second: bool = false,
added: bool = false,
/// Where the guest was when something here refused to run it, and what refused.
///
/// Every failure at this interface arrives as the same `HypervisorFault`, which
/// says nothing about where in a kernel it happened. A boot loop that can only
/// report "something failed" cannot be driven, because the next unsupported
/// instruction has to be named with an address. This stays set until the guest
/// runs again, so the reason it stopped is what a caller reads first.
stalled_at: u64 = 0,
stalled: ?[]const u8 = null,
/// An optional record of the blocks that ran, for a caller trying to find where a
/// guest went wrong. Null costs nothing; set, it keeps the most recent entries.
trace: ?*Trace = null,
/// Set by an access that took an exception instead of being performed, so that a
/// caller which needs to know can tell a completed access from one that did not
/// complete: both return no exit, and the difference matters to a store-exclusive,
/// which reports whether it stored.
faulted: bool = false,

/// The last `capacity` blocks: where each began, and the stack pointer it began
/// with. Two values are enough to walk back from a wrong result to the block that
/// first produced it, and a caller who wants more can read the registers itself.
pub const Trace = struct {
    pub const capacity = 512;
    pcs: [capacity]u64 = @splat(0),
    sps: [capacity]u64 = @splat(0),
    /// How many blocks have run in all, so that the newest is at `(count - 1) % capacity`.
    count: u64 = 0,

    fn push(self: *Trace, pc: u64, sp: u64) void {
        self.pcs[self.count % capacity] = pc;
        self.sps[self.count % capacity] = sp;
        self.count += 1;
    }
};

pub fn init(allocator: std.mem.Allocator, memory: *GuestMemory) Machine {
    return .{ .memory = memory, .cache = Cache.init(allocator) };
}

pub fn deinit(self: *Machine) void {
    self.cache.deinit();
}

pub fn backend(self: *Machine) Backend {
    return .{ .ctx = self, .vtable = &vtable };
}

const vtable: Backend.VTable = .{
    .addVcpu = addVcpu,
    .run = run,
    .completeMmioRead = completeMmioRead,
    .setRegister = setRegister,
    .getRegister = getRegister,
    .setInterrupt = setInterrupt,
};

fn cast(ctx: *anyopaque) *Machine {
    return @ptrCast(@alignCast(ctx));
}

fn check(self: *const Machine, vcpu: Backend.VcpuId) Backend.Error!void {
    if (!self.added or vcpu != 0) return error.NoSuchVcpu;
}

fn addVcpu(ctx: *anyopaque) Backend.Error!Backend.VcpuId {
    const self = cast(ctx);
    if (self.added) return error.TooManyVcpus;
    self.added = true;
    return 0;
}

fn run(ctx: *anyopaque, vcpu: Backend.VcpuId) Backend.Error!Backend.Exit {
    const self = cast(ctx);
    try self.check(vcpu);
    if (self.pending_read) return error.HypervisorFault;
    for (0..64) |_| {
        // The timer's rising edge goes to the host, which raises it in the
        // controller. It is recomputed here because the counter moves every block.
        if (self.timerEdge()) return .timer;
        // An interrupt is taken between blocks, and only while `I` is clear: a
        // line raised while the guest holds interrupts off stays pending until
        // it lets them in.
        if (self.irq_line and self.cpu.system.daif & 0b0010 == 0) {
            _ = Exception.take(&self.cpu, .{ .kind = .irq }, self.cpu.pc);
        }
        if (self.trace) |recorded| recorded.push(self.cpu.pc, self.cpu.sp);
        _ = self.cache.runBlock(self.memory, &self.cpu, &self.tlb) catch |err| switch (err) {
            error.TranslationFault, error.PermissionFault => {
                const ec: u6 = if (self.cpu.system.el == 1) 0b100001 else 0b100000;
                const status: u6 = if (err == error.PermissionFault)
                    Exception.status.permission_fetch
                else
                    Exception.status.translation;
                _ = Exception.take(&self.cpu, .{
                    .kind = .sync,
                    .ec = ec,
                    .instruction = true,
                    .status = status,
                }, self.cpu.pc);
                continue;
            },
            else => {
                self.stalled_at = self.cpu.pc;
                self.stalled = @errorName(err);
                return error.HypervisorFault;
            },
        };
        switch (self.cpu.trap) {
            .none => {},
            .wfi => {
                // Waiting with a due timer is an interrupt, not a nap: the host
                // is told so the controller can raise it.
                if (self.timerEdge()) return .timer else return .wfi;
            },
            .wfe => {
                self.cpu.trap = .none;
                // A set event means the wait falls through; the block already
                // consumed it on entry, so clear it and continue.
                if (self.cpu.event_set) {
                    self.cpu.event_set = false;
                    continue;
                }
                // A due timer interrupts, as at `WFI`.
                if (self.timerEdge()) return .timer else return .wfi;
            },
            // Zeroing a line is a write to the whole line, wherever the tables
            // say it is. A line that is not there is a data abort, like any
            // other access to it.
            .dc_zva => {
                self.cpu.trap = .none;
                try self.zeroLine(self.cpu.address);
            },
            // A return from an exception resumes at an address the translator
            // never saw, so the run loop sets it and the next block is fetched
            // through the walk like any other.
            .eret => {
                self.cpu.trap = .none;
                _ = Exception.eret(&self.cpu);
            },
            // A synchronous call from a lower level is an exception, and the
            // guest's own handler is what services it. The exception class for
            // `SVC` from AArch64 is 0b010101.
            .svc => {
                const pc = self.cpu.pc;
                self.cpu.trap = .none;
                _ = Exception.take(&self.cpu, .{ .kind = .sync, .ec = 0b010101 }, pc);
            },
            // A breakpoint is a synchronous exception too, with the undefined
            // instruction class, so a guest with a handler for it gets one.
            .brk => {
                const pc = self.cpu.pc;
                self.cpu.trap = .none;
                _ = Exception.take(&self.cpu, .{ .kind = .sync, .ec = 0b000000 }, pc);
            },
            .sync => {
                // An `ISB`. Nothing is reordered here, but the architecture
                // makes it the point where the translation regime is
                // synchronised, and a kernel that changed a page table executes
                // one straight afterwards. The trap is the whole signal: only
                // the block that executed the `ISB` can have set it.
                // Only a change to the registers the walk reads makes what is
                // remembered wrong; the kernel executes one around every timer read.
                // What a new mapping can make wrong is a remembered fault.
                const regime = [_]u64{ self.cpu.system.sctlr_el1, self.cpu.system.ttbr0_el1, self.cpu.system.ttbr1_el1, self.cpu.system.tcr_el1, self.cpu.system.mair_el1 };
                if (!std.mem.eql(u64, &regime, &self.regime_seen)) {
                    self.regime_seen = regime;
                    self.tlb.flush();
                } else {
                    self.tlb.dropFaults();
                }
                self.cpu.trap = .none;
            },
            .tlbi => {
                self.tlb.flush();
                self.cpu.trap = .none;
            },
            // A translation fault inside a translated block has already become an
            // exception by the time it reaches here; this one is a fetch that
            // could not be walked at all, which the guest has no status register
            // for yet. It is reported rather than handed over, because a guest
            // told nothing would retry the same fetch forever.
            .translation => {
                self.stalled_at = self.cpu.pc;
                self.stalled = "fetch did not translate";
                return error.HypervisorFault;
            },
            .psci => return .{ .psci = .{
                .function = @truncate(self.cpu.x[0]),
                .args = .{ self.cpu.x[1], self.cpu.x[2], self.cpu.x[3] },
            } },
            .load, .store => {
                // An exclusive access arms or checks the monitor around the access, and
                // is otherwise the same access. The kind is read and cleared first so
                // that it cannot leak onto the next block's plain load.
                const exclusive = self.cpu.exclusive;
                self.cpu.exclusive = .none;
                self.faulted = false;
                const outcome = switch (exclusive) {
                    .none => try self.access(self.cpu.address, self.cpu.width, self.cpu.dest, self.cpu.value),
                    .load => try self.loadExclusive(),
                    .store => try self.storeExclusive(),
                };
                if (self.faulted) {
                    self.cpu.writeback = false;
                    self.cpu.second_pending = false;
                    self.cpu.second_signed = .none;
                    continue;
                }
                if (self.cpu.second_pending) {
                    // The second half waits for the first to retire, so if the
                    // host has to service this one, the other is still owed and
                    // must be performed when the run resumes.
                    if (outcome != null) return outcome.?;
                    const second = .{
                        .address = self.cpu.second_address,
                        .width = self.cpu.second_width,
                        .dest = self.cpu.second_dest,
                        .value = self.cpu.second_value,
                        .signed = self.cpu.second_signed,
                    };
                    self.cpu.second_pending = false;
                    self.cpu.load_signed = second.signed;
                    self.cpu.second_signed = .none;
                    if (try self.access(second.address, second.width, second.dest, second.value)) |exit| return exit;
                    if (self.faulted) {
                        self.cpu.writeback = false;
                        continue;
                    }
                } else if (outcome) |exit| return exit;
                // A post-index access updates its base register only now that the
                // access it described has retired without faulting.
                if (self.cpu.writeback) {
                    // Register 31 is the stack pointer for an access, as it is
                    // for the base the translated block read.
                    if (self.cpu.writeback_dest == 31) {
                        self.cpu.sp = self.cpu.writeback_value;
                    } else {
                        self.cpu.x[self.cpu.writeback_dest] = self.cpu.writeback_value;
                    }
                    self.cpu.writeback = false;
                }
            },
        }
    }
    return .interrupted;
}

/// One access, of `width` bytes. `value` is the datum to store and is ignored by
/// a load. Returns null once the access has been carried out, or the exit the
/// backend asked for when the host has to intervene. The direction is read from
/// the caller's trap rather than from `dest`, so that a store to the discarded
/// register 31 still performs its write.
/// Zero the cache line holding `virtual`, which is sixty-four bytes. The line
/// boundary is the address with its low six bits clear, and a machine whose
/// memory is coherent with its cache has nothing to do beyond the zeroing.
fn zeroLine(self: *Machine, virtual: u64) Backend.Error!void {
    const base = virtual & ~@as(u64, 0x3f);
    const physical = Translate.translate(&self.tlb, &self.cpu, self.memory, base, .write) catch |fault_kind| {
        self.cpu.trap = .none;
        const status: u6 = if (fault_kind == error.PermissionFault)
            Exception.status.permission
        else
            Exception.status.translation;
        _ = Exception.take(&self.cpu, .{
            .kind = .sync,
            .ec = if (self.cpu.system.el == 1) 0b100101 else 0b100100,
            .write = true,
            .status = status,
        }, virtual);
        return;
    };
    var line: [64]u8 = @splat(0);
    self.memory.write(physical, &line) catch return error.HypervisorFault;
    self.cache.written(physical);
}

fn access(self: *Machine, address: u64, width: u8, dest: u8, value: u64) Backend.Error!?Backend.Exit {
    // The address a block formed is virtual. It becomes physical here, because
    // this is the one place where the translation regime can be consulted: a
    // block is cached by its instructions, and the instructions do not change
    // when the page they live in is remapped.
    const kind: Translate.Access = if (self.cpu.trap == .load) .read else .write;
    // A sign-extending load names its extension in the block, and it is taken here and
    // cleared, because the load may not finish now: a device may answer later, and by
    // then the block's copy is spent. Every path out of this function has consumed it.
    const signed = self.cpu.load_signed;
    self.cpu.load_signed = .none;
    const physical = Translate.translate(&self.tlb, &self.cpu, self.memory, address, kind) catch |fault_kind| {
        // A translation fault is an exception, and taking one needs the entry
        // path that is not built yet. What a handler would read is recorded so
        // that building it is a matter of routing to the vector rather than of
        // working out what went wrong after the fact.
        // A data abort, whose class says whether the access was made at the
        // level now running or a lower one.
        const ec: u6 = if (kind == .execute)
            (if (self.cpu.system.el == 1) 0b100001 else 0b100000)
        else
            (if (self.cpu.system.el == 1) 0b100101 else 0b100100);
        const status: u6 = switch (fault_kind) {
            error.PermissionFault => if (kind == .execute) Exception.status.permission_fetch else Exception.status.permission,
            else => Exception.status.translation,
        };
        self.cpu.trap = .none;
        // The block has already moved on, but an abort is taken on the instruction that
        // made the access, and a handler that returns without changing anything must
        // retry it rather than skip it.
        self.cpu.pc -%= 4;
        _ = Exception.take(&self.cpu, .{
            .kind = .sync,
            .ec = ec,
            .instruction = kind == .execute,
            .write = kind == .write,
            .status = status,
        }, address);
        self.faulted = true;
        return null;
    };
    const size: Backend.Size = switch (width) {
        1 => .byte,
        2 => .half,
        4 => .word,
        8 => .double,
        else => return error.HypervisorFault,
    };
    var bytes: [8]u8 = @splat(0);
    if (self.cpu.trap == .load) {
        self.memory.read(physical, bytes[0..width]) catch |err| switch (err) {
            // An address in no region is how this backend says a device is
            // there: the device model is the thing that decides, by claiming
            // the address. Deciding here that it is a fault instead would
            // quietly make every device unreachable.
            error.OutOfBounds => {
                // The block that set this access up has already finished, so its
                // own copy of the width and destination are spent. Recording this
                // access there is what the completion will read.
                self.cpu.width = width;
                self.cpu.dest = dest;
                self.pending_signed = signed;
                self.pending_read = true;
                return .{ .mmio_read = .{ .gpa = physical, .size = size, .dest = @intCast(dest) } };
            },
            else => return error.HypervisorFault,
        };
        self.finishRead(std.mem.readInt(u64, &bytes, .little), width, dest, signed);
        return null;
    }
    std.mem.writeInt(u64, &bytes, value, .little);
    const truncated = std.mem.readVarInt(u64, bytes[0..width], .little);
    self.memory.write(physical, bytes[0..width]) catch |err| switch (err) {
        error.OutOfBounds => return .{ .mmio_write = .{ .gpa = physical, .size = size, .value = truncated } },
        else => return error.HypervisorFault,
    };
    self.cache.written(physical);
    self.cache.written(physical +% (width - 1));
    return null;
}

/// A load-exclusive: the access, and a claim on its address and size. The claim is
/// made first, so that an access that takes an exception leaves none behind: taking
/// the exception clears it.
fn loadExclusive(self: *Machine) Backend.Error!?Backend.Exit {
    self.cpu.monitor_valid = true;
    self.cpu.monitor_address = self.cpu.address;
    self.cpu.monitor_width = self.cpu.width;
    return self.access(self.cpu.address, self.cpu.width, self.cpu.dest, self.cpu.value);
}

/// A store-exclusive. It stores only if the claim a load-exclusive made is still held
/// for this address and this size, and it tells the guest which happened: zero in the
/// status register if it stored, one if it did not. Either way the claim is spent.
/// A store that took an exception did not complete, so it reports nothing.
fn storeExclusive(self: *Machine) Backend.Error!?Backend.Exit {
    const held = self.cpu.monitor_valid and
        self.cpu.monitor_address == self.cpu.address and
        self.cpu.monitor_width == self.cpu.width;
    self.cpu.monitor_valid = false;
    if (!held) {
        self.report(1);
        return null;
    }
    self.faulted = false;
    const outcome = try self.access(self.cpu.address, self.cpu.width, self.cpu.dest, self.cpu.value);
    if (!self.faulted) self.report(0);
    return outcome;
}

/// Write a store-exclusive's result to its status register. Register 31 is the zero
/// register, and nothing is written.
fn report(self: *Machine, status: u64) void {
    if (self.cpu.status_dest != 31) self.cpu.x[self.cpu.status_dest] = status;
}

fn finishRead(self: *Machine, value: u64, width: u8, dest: u8, signed: Cpu.SignExtend) void {
    if (dest == 31) return;
    const bits: u7 = @intCast(width * 8);
    const kept = if (bits == 64) value else value & ((@as(u64, 1) << @as(u6, @intCast(bits))) - 1);
    // A sign extension fills from the top bit of what was read: shift it to the top of
    // the register and back down arithmetically. To 32 bits, nothing above bit 31 is kept.
    const extended = switch (signed) {
        .none => kept,
        .to32, .to64 => blk: {
            const drop: u6 = @intCast(64 - @as(u7, bits));
            const wide: u64 = @bitCast(@as(i64, @bitCast(kept << drop)) >> drop);
            break :blk if (signed == .to32) wide & 0xffff_ffff else wide;
        },
    };
    self.cpu.x[dest] = extended;
}

fn completeMmioRead(ctx: *anyopaque, vcpu: Backend.VcpuId, value: u64) Backend.Error!void {
    const self = cast(ctx);
    try self.check(vcpu);
    if (!self.pending_read) return error.HypervisorFault;
    self.finishRead(value, self.cpu.width, self.cpu.dest, self.pending_signed);
    self.pending_signed = .none;
    self.pending_read = false;
}

fn setRegister(ctx: *anyopaque, vcpu: Backend.VcpuId, reg: Backend.Register, value: u64) Backend.Error!void {
    const self = cast(ctx);
    try self.check(vcpu);
    switch (reg) {
        .pc => self.cpu.pc = value,
        .x0 => self.cpu.x[0] = value,
        .x1 => self.cpu.x[1] = value,
        .x2 => self.cpu.x[2] = value,
        .x3 => self.cpu.x[3] = value,
        .esr => self.cpu.system.esr_el1 = value,
        .far => self.cpu.system.far_el1 = value,
    }
}

fn getRegister(ctx: *anyopaque, vcpu: Backend.VcpuId, reg: Backend.Register) Backend.Error!u64 {
    const self = cast(ctx);
    try self.check(vcpu);
    return switch (reg) {
        .pc => self.cpu.pc,
        .x0 => self.cpu.x[0],
        .x1 => self.cpu.x[1],
        .x2 => self.cpu.x[2],
        .x3 => self.cpu.x[3],
        .esr => self.cpu.system.esr_el1,
        .far => self.cpu.system.far_el1,
    };
}

/// Raise an external interrupt. This is the asynchronous vector, and taking it
/// needs a source of interrupts to say one has happened; a backend with a timer
/// or a device behind it will call this, and a backend without one never does.
fn setInterrupt(ctx: *anyopaque, vcpu: Backend.VcpuId, level: bool) Backend.Error!void {
    const self = cast(ctx);
    try self.check(vcpu);
    self.irq_line = level;
}

/// True when the virtual timer's condition holds and it is allowed to fire: the
/// counter has reached the compare, the timer is enabled, and it is not masked.
/// The `IMASK` bit only stops the signal; the condition itself is `counter >=
/// compare`, recomputed here because the counter moves every block.
fn timerDue(self: *const Machine) bool {
    return self.cpu.system.cntvct_el0 >= self.cpu.system.cntv_cval_el0 and
        self.cpu.system.cntv_ctl_el0 & 0b1 != 0 and
        self.cpu.system.cntv_ctl_el0 & 0b10 == 0;
}

/// True once each time the timer comes due, and false while it stays so or is not.
fn timerEdge(self: *Machine) bool {
    if (!self.timerDue()) {
        self.timer_fired = false;
        return false;
    }
    if (self.timer_fired) return false;
    self.timer_fired = true;
    return true;
}
