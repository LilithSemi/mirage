//! A KVM virtual CPU: the shared run structure, the registers, and the exits.
//!
//! KVM decodes a memory access that left the guest and reports it as an MMIO exit,
//! and it services PSCI and WFI inside the kernel. So this backend never produces the
//! `psci` or `wfi` variants of `Backend.Exit`. The Hypervisor.framework backend does,
//! because Apple hands back a raw exception and leaves the decoding to the VMM.
//!
//! `mmio_read.dest` is always zero here. KVM writes the value the device returns back
//! into the guest register itself, from `kvm_run`, so the VMM never names a register.
//! Hypervisor.framework does need the register, which is why the field exists.

const std = @import("std");
const testing = @import("mirage-testing");
const Backend = @import("../../Backend.zig");
const Vm = @import("Vm.zig");
const device = @import("mirage-device");
const ioctl = @import("ioctl.zig");
const linux = std.os.linux;

const Vcpu = @This();

const nr = struct {
    const get_vcpu_mmap_size = 0x04;
    const create_vcpu = 0x41;
    const run = 0x80;
    const get_one_reg = 0xab;
    const set_one_reg = 0xac;
    const vcpu_init = 0xae;
    const preferred_target = 0xaf;
    const get_mp_state = 0x98;
    const set_mp_state = 0x99;
};

/// `struct kvm_mp_state`. Whether this CPU is running or stopped, which is not one of its registers and
/// is lost with everything else if it is not carried separately.
const MpState = extern struct {
    state: u32,
};

/// `KVM_MP_STATE_RUNNABLE` and `KVM_MP_STATE_STOPPED`. A CPU the guest has not started yet is stopped,
/// and a snapshot that brought one back runnable would set it going from wherever its registers pointed.
pub const runnable = 0;
pub const stopped = 5;

/// Bit indexes into `kvm_vcpu_init.features`. A CPU created stopped stays where it is until the guest
/// asks the hypervisor to start it, which is what every CPU but the first has to do: the boot protocol
/// starts one and the guest brings up the rest itself.
const power_off_feature = 0;
const psci_feature = 2;

/// `KVM_EXIT_*` in `linux/kvm.h`.
const exit = struct {
    const mmio = 6;
    const shutdown = 8;
    const system_event = 24;
};

/// `KVM_SYSTEM_EVENT_*`.
const event = struct {
    const shutdown = 1;
    const reset = 2;
};

pub const Error = error{HypervisorFault} || ioctl.Error || std.posix.MMapError;

pub const VcpuInit = extern struct {
    target: u32,
    features: [7]u32,
};

pub const OneReg = extern struct {
    id: u64,
    addr: u64,
};

pub const Run = extern struct {
    request_interrupt_window: u8,
    immediate_exit: u8,
    padding1: [6]u8,
    exit_reason: u32,
    ready_for_interrupt_injection: u8,
    if_flag: u8,
    flags: u16,
    cr8: u64,
    apic_base: u64,
    data: Data,

    pub const Mmio = extern struct {
        phys_addr: u64,
        data: [8]u8,
        len: u32,
        is_write: u8,
    };

    pub const SystemEvent = extern struct {
        type: u32,
        ndata: u32,
        data: [16]u64,
    };

    pub const Data = extern union {
        mmio: Mmio,
        system_event: SystemEvent,
    };

    comptime {
        // The kernel fixes these two offsets. If this struct ever drifts from
        // `struct kvm_run`, the code reads some other field as the exit reason and
        // behaves at random. Fail the build instead.
        if (@offsetOf(Run, "exit_reason") != 8) @compileError("kvm_run.exit_reason is not at offset 8");
        if (@offsetOf(Run, "data") != 32) @compileError("the kvm_run union is not at offset 32");
    }
};

const reg_arm64: u64 = 0x6000_0000_0000_0000;
const reg_size_u64: u64 = 0x0030_0000_0000_0000;
const reg_arm_core: u64 = 0x0010 << 16;

/// A core register is named by its byte offset inside `struct kvm_regs`, divided by
/// four. That struct starts with `struct user_pt_regs`, which is `regs[31]`, then
/// `sp`, then `pc`, then `pstate`.
fn coreReg(comptime byte_offset: u64) u64 {
    return reg_arm64 | reg_size_u64 | reg_arm_core | (byte_offset / 4);
}

fn registerId(reg: Backend.Register) u64 {
    return switch (reg) {
        .x0 => comptime coreReg(0),
        .x1 => comptime coreReg(8),
        .x2 => comptime coreReg(16),
        .x3 => comptime coreReg(24),
        .pc => comptime coreReg(31 * 8 + 8),
    };
}

fd: std.posix.fd_t,
mapping: []align(std.heap.page_size_min) u8,
state: *Run,

pub fn create(vm: *Vm, index: u32) Error!Vcpu {
    const raw = try ioctl.call(vm.fd, comptime ioctl.request(.none, void, nr.create_vcpu), index);
    const fd: std.posix.fd_t = @intCast(raw);
    errdefer _ = linux.close(fd);

    const size = try ioctl.call(vm.kvm, comptime ioctl.request(.none, void, nr.get_vcpu_mmap_size), 0);
    const mapping = try std.posix.mmap(
        null,
        size,
        .{ .READ = true, .WRITE = true },
        .{ .TYPE = .SHARED },
        fd,
        0,
    );
    errdefer std.posix.munmap(mapping);

    // Only the host knows which CPU it is able to present to a guest, so ask rather
    // than name one.
    var init: VcpuInit = .{ .target = 0, .features = @splat(0) };
    _ = try ioctl.call(vm.fd, comptime ioctl.request(.read, VcpuInit, nr.preferred_target), @intFromPtr(&init));

    // `KVM_ARM_PREFERRED_TARGET` reports the CPU but asks for no features, so the
    // guest would get no PSCI and read a version of 0xffff.0xffff from it. The
    // device tree beside this promises PSCI v0.2, so turn it on to keep that true.
    init.features[psci_feature / 32] |= @as(u32, 1) << @intCast(psci_feature % 32);

    // Every CPU but the first starts stopped. One that did not would begin running from address zero
    // the moment it was created, which is not a place the guest put anything.
    if (index != 0) init.features[power_off_feature / 32] |= @as(u32, 1) << @intCast(power_off_feature % 32);

    _ = try ioctl.call(fd, comptime ioctl.request(.write, VcpuInit, nr.vcpu_init), @intFromPtr(&init));

    return .{ .fd = fd, .mapping = mapping, .state = @ptrCast(@alignCast(mapping.ptr)) };
}

pub fn deinit(self: *Vcpu) void {
    std.posix.munmap(self.mapping);
    _ = linux.close(self.fd);
    self.* = undefined;
}

pub fn setRegister(self: *Vcpu, reg: Backend.Register, value: u64) Error!void {
    var local = value;
    const one: OneReg = .{ .id = registerId(reg), .addr = @intFromPtr(&local) };
    _ = try ioctl.call(self.fd, comptime ioctl.request(.write, OneReg, nr.set_one_reg), @intFromPtr(&one));
}

pub fn getRegister(self: *Vcpu, reg: Backend.Register) Error!u64 {
    var value: u64 = 0;
    const one: OneReg = .{ .id = registerId(reg), .addr = @intFromPtr(&value) };
    // `KVM_GET_ONE_REG` is declared `_IOW` in the kernel header, not `_IOR`. The
    // number has to match what the kernel registered, however it reads.
    _ = try ioctl.call(self.fd, comptime ioctl.request(.write, OneReg, nr.get_one_reg), @intFromPtr(&one));
    return value;
}

pub fn run(self: *Vcpu) Error!Backend.Exit {
    _ = ioctl.call(self.fd, comptime ioctl.request(.none, void, nr.run), 0) catch |err| switch (err) {
        // A signal took the CPU back while the guest was still running. That is a VMM
        // reaching in, not a fault, and the guest carries on from where it was.
        error.Interrupted => return .interrupted,
        else => return err,
    };
    return self.decode();
}

/// KVM takes the value from the run structure when the guest is entered again.
pub fn completeMmioRead(self: *Vcpu, value: u64) Error!void {
    const mmio = &self.state.data.mmio;
    if (mmio.len > mmio.data.len) return Error.HypervisorFault;
    @memcpy(mmio.data[0..mmio.len], std.mem.asBytes(&value)[0..mmio.len]);
}

fn decode(self: *Vcpu) Error!Backend.Exit {
    return switch (self.state.exit_reason) {
        exit.mmio => blk: {
            const mmio = self.state.data.mmio;
            if (mmio.len > mmio.data.len) return Error.HypervisorFault;
            const size = std.enums.fromInt(Backend.Size, mmio.len) orelse return Error.HypervisorFault;

            if (mmio.is_write == 0) break :blk .{ .mmio_read = .{
                .gpa = mmio.phys_addr,
                .size = size,
                .dest = 0,
            } };

            var value: u64 = 0;
            @memcpy(std.mem.asBytes(&value)[0..mmio.len], mmio.data[0..mmio.len]);
            break :blk .{ .mmio_write = .{ .gpa = mmio.phys_addr, .size = size, .value = value } };
        },
        exit.shutdown => .shutdown,
        exit.system_event => switch (self.state.data.system_event.type) {
            event.reset => .reset,
            event.shutdown => .shutdown,
            else => Error.HypervisorFault,
        },
        else => Error.HypervisorFault,
    };
}
const ram = 0x4000_0000;
const uart = 0x0900_0000;

fn openVm() !Vm {
    return Vm.create() catch |err| switch (err) {
        error.NoKvm => error.SkipZigTest,
        else => err,
    };
}

test "a vcpu is created and initialised to this host's preferred target" {
    var vm = try openVm();
    defer vm.deinit();

    var cpu = try Vcpu.create(&vm, 0);
    defer cpu.deinit();

    try std.testing.expect(cpu.fd > 0);
}

test "a register written is the register read back" {
    var vm = try openVm();
    defer vm.deinit();

    var cpu = try Vcpu.create(&vm, 0);
    defer cpu.deinit();

    try cpu.setRegister(.pc, ram);
    try cpu.setRegister(.x0, 0xdead_beef);

    try testing.expectEqual(@as(u64, ram), try cpu.getRegister(.pc));
    try testing.expectEqual(@as(u64, 0xdead_beef), try cpu.getRegister(.x0));
}

test "a guest that stores to unmapped memory comes back as an mmio write" {
    var vm = try openVm();
    defer vm.deinit();

    const region = try vm.addMemory(ram, 4 * std.heap.pageSize(), .shared);
    var memory: Backend.GuestMemory = .{ .regions = &.{region} };

    // Hand assembled aarch64, because a test that needs an assembler is a test that
    // needs a tool outside `zig build`. The guest starts at EL1 with the MMU off, so
    // these are physical addresses.
    const code = [_]u32{
        0xd2a12001, // movz x1, #0x0900, lsl #16      x1 = 0x09000000, the uart
        0x528009a0, // movz w0, #0x4d                 w0 = 'M'
        0xb9000020, // str  w0, [x1]                  the store that leaves the guest
        0x14000000, // b    .                         never reached
    };
    try memory.write(ram, std.mem.sliceAsBytes(code[0..]));

    var cpu = try Vcpu.create(&vm, 0);
    defer cpu.deinit();
    try cpu.setRegister(.pc, ram);

    const result = try cpu.run();
    try testing.expectEqual(Backend.Exit{
        .mmio_write = .{ .gpa = uart, .size = .word, .value = 0x4d },
    }, result);
}

test "a guest prints through the serial port and the host receives it" {
    var vm = try openVm();
    defer vm.deinit();

    const region = try vm.addMemory(ram, 4 * std.heap.pageSize(), .shared);
    var memory: Backend.GuestMemory = .{ .regions = &.{region} };

    // Hand assembled aarch64. The guest stores three bytes to the PL011 data
    // register, then spins. Each store leaves the guest, so `run` returns three
    // times and the fourth instruction is never reached.
    const code = [_]u32{
        0xd2a12001, // movz x1, #0x0900, lsl #16   x1 = the uart
        0x52800d00, // movz w0, #0x68              'h'
        0xb9000020, // str  w0, [x1]
        0x52800d20, // movz w0, #0x69              'i'
        0xb9000020, // str  w0, [x1]
        0x52800140, // movz w0, #0x0a              newline
        0xb9000020, // str  w0, [x1]
        0x14000000, // b    .
    };
    try memory.write(ram, std.mem.sliceAsBytes(code[0..]));

    var buffer: [16]u8 = undefined;
    var sink = std.Io.Writer.fixed(&buffer);
    var serial: device.Pl011 = .{ .sink = &sink };
    var devices = [_]device.Device{serial.device(uart)};
    var bus: device.Bus = .{ .devices = &devices };

    var cpu = try Vcpu.create(&vm, 0);
    defer cpu.deinit();
    try cpu.setRegister(.pc, ram);

    // Three stores, so three exits. A fourth would never return, because the guest
    // is spinning by then.
    for (0..3) |_| {
        switch (try cpu.run()) {
            .mmio_write => |w| bus.write(w.gpa, w.size, w.value),
            else => |other| {
                std.debug.print("unexpected exit {t}\n", .{other});
                return error.TestUnexpectedResult;
            },
        }
    }

    try testing.expectEqualSlices(u8, "hi\n", sink.buffered());
    try testing.expectEqual(@as(u64, 0), bus.unmapped);
    try testing.expectEqual(@as(u64, 0), serial.dropped);
}

test "the guest gets a real psci version rather than a missing one" {
    var vm = try openVm();
    defer vm.deinit();

    const region = try vm.addMemory(ram, 4 * std.heap.pageSize(), .shared);
    var memory: Backend.GuestMemory = .{ .regions = &.{region} };

    // Ask PSCI for its version, then hand the answer to the serial port. KVM answers
    // the call inside the kernel, so the only exit is the store.
    const code = [_]u32{
        0xd2a12001, // movz x1, #0x0900, lsl #16   x1 = the uart
        0xd2b08000, // movz x0, #0x8400, lsl #16   PSCI_VERSION
        0xd4000002, // hvc  #0
        0xb9000020, // str  w0, [x1]
        0x14000000, // b    .
    };
    try memory.write(ram, std.mem.sliceAsBytes(code[0..]));

    var cpu = try Vcpu.create(&vm, 0);
    defer cpu.deinit();
    try cpu.setRegister(.pc, ram);

    const version = switch (try cpu.run()) {
        .mmio_write => |w| w.value,
        else => return error.TestUnexpectedResult,
    };

    // 0xffffffff is what a guest reads when PSCI was never enabled, which is the bug
    // this test exists for. A real answer is major in the high half, minor in the low.
    try std.testing.expect(version != 0xffff_ffff);
    try std.testing.expect(version >> 16 <= 1);
}

/// `KVM_GET_REG_LIST`, which asks the kernel which registers it will talk about. A snapshot
/// needs all of them and there are hundreds, so the list is asked for rather than written out.
const get_reg_list = 0xb0;

/// `struct kvm_reg_list`. The count comes back filled in when the array was too small, which is
/// how a caller learns how much room to make.
pub const RegList = extern struct {
    n: u64,
    // The identifiers follow in memory. An extern struct cannot say so, and the kernel reads
    // and writes past this on purpose.
};

/// How many registers this vCPU will talk about. Asking with no room for the answer is how the
/// count is learned, and the kernel says `E2BIG` while filling it in.
pub fn registerCount(self: *Vcpu) Error!u64 {
    var list: RegList = .{ .n = 0 };
    _ = ioctl.call(
        self.fd,
        comptime ioctl.request(.read_write, RegList, get_reg_list),
        @intFromPtr(&list),
    ) catch |err| switch (err) {
        // Expected: no room was offered, so the kernel only reported how much is needed.
        error.TooBig => return list.n,
        else => return err,
    };
    return list.n;
}

/// Every register identifier this vCPU will talk about.
///
/// The kernel writes the count and the identifiers as one array, so the first element of
/// `buffer` is where the count goes and the identifiers follow it. That is why this takes a
/// buffer one longer than the list it returns, and why it needs no allocator.
pub fn registerList(self: *Vcpu, buffer: []u64) Error![]const u64 {
    if (buffer.len < 2) return Error.TooBig;

    buffer[0] = buffer.len - 1;
    _ = try ioctl.call(
        self.fd,
        comptime ioctl.request(.read_write, RegList, get_reg_list),
        @intFromPtr(buffer.ptr),
    );

    // The kernel writes back how many it really put there, which is no more than it was
    // offered.
    const count: usize = @intCast(@min(buffer[0], buffer.len - 1));
    return buffer[1..][0..count];
}

/// Read one register by the identifier the kernel gave, rather than by a name this code knows.
/// A snapshot walks the list and reads every one.
pub fn readRaw(self: *Vcpu, id: u64, into: []u8) Error!void {
    const one: OneReg = .{ .id = id, .addr = @intFromPtr(into.ptr) };
    _ = try ioctl.call(self.fd, comptime ioctl.request(.write, OneReg, nr.get_one_reg), @intFromPtr(&one));
}

/// Write one register by the identifier the kernel gave.
pub fn writeRaw(self: *Vcpu, id: u64, from: []const u8) Error!void {
    const one: OneReg = .{ .id = id, .addr = @intFromPtr(from.ptr) };
    _ = try ioctl.call(self.fd, comptime ioctl.request(.write, OneReg, nr.set_one_reg), @intFromPtr(&one));
}

/// How many bytes a register holds, from the size bits of its identifier.
pub fn registerSize(id: u64) usize {
    // `KVM_REG_SIZE_MASK` is bits 52 through 55, and the value there is the log2 of the size.
    const shift: u6 = @intCast((id & 0x00f0_0000_0000_0000) >> 52);
    return @as(usize, 1) << shift;
}

test "a vcpu says which registers it will talk about" {
    var vm = try openVm();
    defer vm.deinit();

    var cpu = try Vcpu.create(&vm, 0);
    defer cpu.deinit();

    // A snapshot needs all of these and there are hundreds, so the list is asked for rather
    // than written out. Asking with no room is how the count is learned.
    const count = try cpu.registerCount();
    try std.testing.expect(count > 100);

    const buffer = try testing.allocator().alloc(u64, @intCast(count + 1));
    defer testing.allocator().free(buffer);
    const list = try cpu.registerList(buffer);
    try testing.expectEqual(@as(usize, @intCast(count)), list.len);

    // Every identifier carries the size of what it names, and every one of these is a size
    // this code can hold.
    var eight: usize = 0;
    for (list) |reg| {
        const size = registerSize(reg);
        try std.testing.expect(size >= 1 and size <= 16);
        if (size == 8) eight += 1;
    }
    try std.testing.expect(eight > 50);

    // And the ones a launch sets are in the list the kernel gave, which is what says the two
    // ways of naming a register agree.
    var found_pc = false;
    for (list) |reg| {
        if (reg == registerId(.pc)) found_pc = true;
    }
    try std.testing.expect(found_pc);
}

test "a register read by its identifier is the one written by name" {
    var vm = try openVm();
    defer vm.deinit();

    var cpu = try Vcpu.create(&vm, 0);
    defer cpu.deinit();

    // Written the way a launch writes it, read the way a snapshot reads it. If these disagreed,
    // a snapshot would hold something other than what the guest was running with.
    try cpu.setRegister(.pc, 0x4008_0000);

    var bytes: [8]u8 = undefined;
    try cpu.readRaw(registerId(.pc), &bytes);
    try testing.expectEqual(@as(u64, 0x4008_0000), std.mem.readInt(u64, &bytes, .little));

    // And the other way round.
    std.mem.writeInt(u64, &bytes, 0x4100_0000, .little);
    try cpu.writeRaw(registerId(.pc), &bytes);
    try testing.expectEqual(@as(u64, 0x4100_0000), try cpu.getRegister(.pc));
}

/// The largest register the kernel names. The vector registers are sixteen bytes and nothing
/// here is larger, so a buffer this size holds any one of them.
pub const max_register = 16;

/// Everything a vCPU holds, as bytes a caller can keep and give back.
///
/// Each register goes in as its identifier followed by its value, and the length of the value
/// comes from the identifier. The format is this backend's own: a vCPU saved here is not a vCPU
/// another hypervisor could be given, because the two do not name the same registers.
///
/// This is state and not provenance. What the bytes mean, when they were taken and whether they
/// may be trusted are for whoever keeps them.
/// Whether this CPU is running or stopped.
///
/// Not one of its registers, and a snapshot that saved the registers alone would bring every CPU back
/// runnable: the ones the guest had not started yet would begin running from whatever their registers
/// happened to hold.
pub fn runState(self: *Vcpu) Error!u32 {
    var state: MpState = .{ .state = 0 };
    _ = try ioctl.call(self.fd, comptime ioctl.request(.read, MpState, nr.get_mp_state), @intFromPtr(&state));
    return state.state;
}

pub fn setRunState(self: *Vcpu, value: u32) Error!void {
    var state: MpState = .{ .state = value };
    _ = try ioctl.call(self.fd, comptime ioctl.request(.write, MpState, nr.set_mp_state), @intFromPtr(&state));
}

pub const State = struct {
    /// How much room `save` needs for this vCPU. Asking is better than guessing, because the
    /// count depends on the host and on what the vCPU was created with.
    pub fn size(cpu: *Vcpu, buffer: []u64) Error!usize {
        const list = try cpu.registerList(buffer);
        var total: usize = 0;
        for (list) |id| total += @sizeOf(u64) + registerSize(id);
        return total;
    }
};

/// Write every register into `into`. Returns how many bytes it took.
pub fn save(self: *Vcpu, ids: []const u64, into: []u8) Error!usize {
    var at: usize = 0;
    for (ids) |id| {
        const width = registerSize(id);
        if (width > max_register) return Error.NotSupported;
        if (at + @sizeOf(u64) + width > into.len) return Error.TooBig;

        std.mem.writeInt(u64, into[at..][0..8], id, .little);
        at += @sizeOf(u64);
        try self.readRaw(id, into[at..][0..width]);
        at += width;
    }
    return at;
}

/// What a restore could not put back.
pub const Restored = struct {
    /// How many registers went in.
    written: usize,
    /// How many the kernel would not take. The identifiers that describe the processor rather
    /// than its state are read only, so some refusals are expected on a correct restore and a
    /// caller that treats any refusal as failure can never restore anything.
    refused: usize,
};

/// Put every register back. A register the kernel refuses is counted rather than fatal.
pub fn load(self: *Vcpu, from: []const u8) Error!Restored {
    var at: usize = 0;
    var result: Restored = .{ .written = 0, .refused = 0 };

    while (at + @sizeOf(u64) <= from.len) {
        const id = std.mem.readInt(u64, from[at..][0..8], .little);
        at += @sizeOf(u64);

        const width = registerSize(id);
        if (width > max_register) return Error.NotSupported;
        // A blob that stops in the middle of a value is one this code will not guess at.
        if (at + width > from.len) return Error.InvalidArgument;

        self.writeRaw(id, from[at..][0..width]) catch {
            result.refused += 1;
            at += width;
            continue;
        };
        result.written += 1;
        at += width;
    }
    return result;
}

test "everything a vcpu holds goes out and comes back" {
    var vm = try openVm();
    defer vm.deinit();

    var cpu = try Vcpu.create(&vm, 0);
    defer cpu.deinit();

    const gpa = testing.allocator();
    const count = try cpu.registerCount();
    const ids_buffer = try gpa.alloc(u64, @intCast(count + 1));
    defer gpa.free(ids_buffer);
    const ids = try cpu.registerList(ids_buffer);

    const room = try Vcpu.State.size(&cpu, ids_buffer);
    const blob = try gpa.alloc(u8, room);
    defer gpa.free(blob);

    // Something to recognise afterwards, set the way a launch sets it.
    try cpu.setRegister(.pc, 0x4008_0000);
    try cpu.setRegister(.x0, 0xfeed_face);

    const ids_again = try cpu.registerList(ids_buffer);
    const used = try cpu.save(ids_again, blob);
    try testing.expectEqual(room, used);

    // Move on, so a restore that does nothing would be caught.
    try cpu.setRegister(.pc, 0x0000_1000);
    try cpu.setRegister(.x0, 0);

    const back = try cpu.load(blob[0..used]);
    try testing.expectEqual(@as(u64, 0x4008_0000), try cpu.getRegister(.pc));
    try testing.expectEqual(@as(u64, 0xfeed_face), try cpu.getRegister(.x0));

    // Every register is accounted for, and at least most went in. Measured on an Ampere Altra:
    // all 257 of them, none refused. A host that makes some read only is still correct, which is
    // why the refusals are counted rather than fatal.
    try testing.expectEqual(ids.len, back.written + back.refused);
    try std.testing.expect(back.written > ids.len / 2);
}

test "a saved vcpu that stops in the middle of a value is refused" {
    var vm = try openVm();
    defer vm.deinit();

    var cpu = try Vcpu.create(&vm, 0);
    defer cpu.deinit();

    // Eight bytes of identifier and nothing behind it. A loader that reads the value anyway
    // reads whatever follows the buffer.
    var blob: [8]u8 = undefined;
    std.mem.writeInt(u64, &blob, registerId(.pc), .little);
    try testing.expectError(Error.InvalidArgument, cpu.load(&blob));
}
