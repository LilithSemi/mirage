//! A KVM virtual CPU on x86-64: CPUID, flat protected mode, and the general registers.
//!
//! `create` puts the vCPU in flat 32-bit protected mode with paging off, so a
//! guest's RIP is a physical address. CPUID is loaded from the host so a guest
//! that executes `cpuid` does not fault.

const std = @import("std");
const testing = @import("mirage-testing");
const arch = @import("mirage-arch");
const Backend = @import("../../../Backend.zig");
const Vm = @import("../Vm.zig");
const ioctl = @import("../ioctl.zig");
const shared = @import("run.zig");
const linux = std.os.linux;

const Vcpu = @This();

const nr = struct {
    const get_vcpu_mmap_size = 0x04;
    const create_vcpu = 0x41;
    const run = 0x80;
    const get_regs = 0x81;
    const set_regs = 0x82;
    const get_sregs = 0x83;
    const set_sregs = 0x84;
    const get_lapic = 0x8e;
    const set_lapic = 0x8f;
    const get_mp_state = 0x98;
    const set_mp_state = 0x99;
    const get_vcpu_events = 0x9f;
    const set_vcpu_events = 0xa0;
    const get_xsave = 0xa4;
    const set_xsave = 0xa5;
    const set_cpuid2 = 0x90;
    const get_supported_cpuid = 0x05;
};

/// `struct kvm_regs` — the general-purpose registers the kernel reads and writes as one block.
const Regs = extern struct {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rsp: u64,
    rbp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    rflags: u64,
    comptime {
        if (@sizeOf(@This()) != 144) @compileError("kvm_regs is 18 u64 = 144 bytes");
    }
};

/// `struct kvm_segment` — one protected-mode segment descriptor in the form KVM accepts.
const Segment = extern struct {
    base: u64,
    limit: u32,
    selector: u16,
    kind: u8,
    present: u8,
    dpl: u8,
    db: u8,
    s: u8,
    l: u8,
    g: u8,
    avl: u8,
    unusable: u8,
    padding: u8,
    comptime {
        if (@sizeOf(@This()) != 24) @compileError("kvm_segment is 24 bytes");
    }
};

/// `struct kvm_dtable` — a descriptor table register (GDTR/IDTR).
const Dtable = extern struct {
    base: u64,
    limit: u16,
    padding: [3]u16,
    comptime {
        if (@sizeOf(@This()) != 16) @compileError("kvm_dtable is 16 bytes");
    }
};

/// `struct kvm_sregs` — the segment and control registers.
const Sregs = extern struct {
    cs: Segment,
    ds: Segment,
    es: Segment,
    fs: Segment,
    gs: Segment,
    ss: Segment,
    tr: Segment,
    ldt: Segment,
    gdt: Dtable,
    idt: Dtable,
    cr0: u64,
    cr2: u64,
    cr3: u64,
    cr4: u64,
    cr8: u64,
    efer: u64,
    apic_base: u64,
    interrupt_bitmap: [4]u64,
    comptime {
        if (@sizeOf(@This()) != 312) @compileError("kvm_sregs is 312 bytes");
    }
};

/// `struct kvm_xsave` — the extended processor state region (SSE, AVX, etc.).
const Xsave = extern struct {
    region: [1024]u32,
    comptime {
        if (@sizeOf(@This()) != 4096) @compileError("kvm_xsave is 1024 u32 = 4096 bytes");
    }
};

/// `struct kvm_mp_state` — whether this CPU is running or halted.
const MpState = extern struct {
    state: u32,
    comptime {
        if (@sizeOf(@This()) != 4) @compileError("kvm_mp_state is 4 bytes");
    }
};

/// `KVM_MP_STATE_RUNNABLE` — the CPU is executing guest code.
pub const runnable: u32 = 0;
/// `KVM_MP_STATE_STOPPED` — the CPU is not executing; used by APs before SIPI.
pub const stopped: u32 = 5;

/// `struct kvm_vcpu_events` — pending exceptions, interrupts, NMI, SMI, and related flags.
/// Layout mirrors `asm/kvm.h` exactly: the 56-byte prefix lands at a natural u64 boundary.
const VcpuEvents = extern struct {
    exc_injected: u8,
    exc_nr: u8,
    exc_has_error_code: u8,
    exc_pending: u8,
    exc_error_code: u32,
    int_injected: u8,
    int_nr: u8,
    int_soft: u8,
    int_shadow: u8,
    nmi_injected: u8,
    nmi_pending: u8,
    nmi_masked: u8,
    nmi_pad: u8,
    sipi_vector: u32,
    flags: u32,
    smi_smm: u8,
    smi_pending: u8,
    smi_smm_inside_nmi: u8,
    smi_latched_init: u8,
    // triple_fault.pending (1 byte) + reserved[26] + exception_has_payload (1 byte) = 28 bytes
    // total prefix: 8+4+4+8+4+28 = 56, which aligns exception_payload to offset 56
    triple_fault_pending: u8,
    reserved: [26]u8,
    exception_has_payload: u8,
    exception_payload: u64,
    comptime {
        if (@sizeOf(@This()) != 64) @compileError("kvm_vcpu_events must be 64 bytes");
    }
};

/// `struct kvm_lapic_state` — the local APIC register page (1024 bytes).
const LapicState = extern struct {
    regs: [1024]u8,
    comptime {
        if (@sizeOf(@This()) != 1024) @compileError("kvm_lapic_state is 1024 bytes");
    }
};

/// Snapshot blob: each sub-state is framed as [tag:u8][len:u32 LE][bytes].
/// The sequence is fixed for x86 — there is no register-id list.
const frame_overhead = 5; // 1 byte tag + 4 bytes length

const Tag = struct {
    const regs: u8 = 0x81;
    const sregs: u8 = 0x83;
    const xsave: u8 = 0xa4;
    const mp_state: u8 = 0x98;
    const vcpu_events: u8 = 0x9f;
    const lapic: u8 = 0x8e;
};

/// Fixed byte count every x86 vCPU snapshot needs.
const blob_size: usize =
    frame_overhead + @sizeOf(Regs) +
    frame_overhead + @sizeOf(Sregs) +
    frame_overhead + @sizeOf(Xsave) +
    frame_overhead + @sizeOf(MpState) +
    frame_overhead + @sizeOf(VcpuEvents) +
    frame_overhead + @sizeOf(LapicState);

/// `struct kvm_cpuid_entry2` — one leaf the kernel will answer for the guest.
const CpuidEntry2 = extern struct {
    function: u32,
    index: u32,
    flags: u32,
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
    padding: [3]u32,
    comptime {
        if (@sizeOf(@This()) != 40) @compileError("kvm_cpuid_entry2 is 40 bytes");
    }
};

/// `struct kvm_cpuid2` header — the kernel sees just this size in the ioctl number because
/// `entries` is a flexible array in C. Entries follow immediately in memory.
const Cpuid2Header = extern struct {
    nent: u32,
    padding: u32,
    comptime {
        if (@sizeOf(@This()) != 8) @compileError("kvm_cpuid2 header is 8 bytes");
    }
};

/// Maximum CPUID leaves the host is likely to report. 128 is well above any current CPU.
const max_cpuid_entries = 128;

/// On-stack buffer: the header followed by space for entries.
const Cpuid2Buffer = extern struct {
    header: Cpuid2Header,
    entries: [max_cpuid_entries]CpuidEntry2,
    comptime {
        if (@sizeOf(@This()) != 8 + max_cpuid_entries * 40) @compileError("kvm_cpuid2 buffer is the header plus its entries");
    }
};

pub const Run = shared.Run;

pub const Error = error{HypervisorFault} || ioctl.Error || std.posix.MMapError;

/// Which exit the last run came back with, kept for routing completeMmioRead.
/// An IO exit records the data_offset so the completion can write back to the right place.
pub const LastExit = union(enum) {
    none,
    mmio,
    /// Port read: the KVM data page offset and byte width, so completeMmioRead writes there.
    io: struct { data_offset: u64, size: u8 },
};

fd: std.posix.fd_t,
mapping: []align(std.heap.page_size_min) u8,
state: *Run,
last_exit: LastExit = .none,

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

    try loadCpuid(vm.kvm, fd, vm.sev_es);
    try enterFlatMode(fd);

    return .{ .fd = fd, .mapping = mapping, .state = @ptrCast(@alignCast(mapping.ptr)) };
}

/// Copy the host's supported CPUID leaves to the vCPU so a guest `cpuid` does not fault.
///
/// The ioctl number encodes the header size only, because `entries` is a C flexible array.
/// The kernel reads and writes past the header on purpose.
fn loadCpuid(kvm_fd: std.posix.fd_t, vcpu_fd: std.posix.fd_t, sev_es: bool) Error!void {
    var buf: Cpuid2Buffer = .{
        .header = .{ .nent = max_cpuid_entries, .padding = 0 },
        .entries = undefined,
    };

    // Offer room for every leaf and let the kernel write back how many it used. This ioctl
    // says `E2BIG` without reporting a count, so a host with more leaves than this buffer
    // holds is named rather than silently truncated.
    _ = ioctl.call(
        kvm_fd,
        comptime ioctl.request(.read_write, Cpuid2Header, nr.get_supported_cpuid),
        @intFromPtr(&buf),
    ) catch |err| switch (err) {
        error.TooBig => return Error.TooBig,
        else => return err,
    };

    if (sev_es) hideCetXstate(buf.entries[0..buf.header.nent]);

    // The ioctl number is built from the 8-byte header type on purpose; the pointer is the
    // full buffer. The entries the read filled in follow the header the kernel reads back.
    _ = try ioctl.call(
        vcpu_fd,
        comptime ioctl.request(.write, Cpuid2Header, nr.set_cpuid2),
        @intFromPtr(&buf),
    );
}

/// The CET shadow stack xstate components in CPUID leaf 0xD. They are supervisor states managed
/// through IA32_XSS, which a SEV-ES guest kernel does not enable, so it leaves them out of its
/// xstate size while the host leaf still counts them. That size disagreement makes the guest
/// disable XSAVE and fault in early boot, so the launch presents the leaf without them.
const cet_u_bit = 11;
const cet_s_bit = 12;
const cet_xss_mask: u32 = (1 << cet_u_bit) | (1 << cet_s_bit);

/// Clear the CET supervisor components from CPUID leaf 0xD so a SEV-ES guest sees an xstate size
/// it agrees with. Sub-leaf 1 holds the supervisor mask in ecx; the per-component sub-leaves 11
/// and 12 describe their size and offset and are zeroed with them.
fn hideCetXstate(entries: []CpuidEntry2) void {
    for (entries) |*entry| {
        if (entry.function != 0xD) continue;
        switch (entry.index) {
            1 => entry.ecx &= ~cet_xss_mask,
            cet_u_bit, cet_s_bit => entry.* = .{
                .function = 0xD,
                .index = entry.index,
                .flags = entry.flags,
                .eax = 0,
                .ebx = 0,
                .ecx = 0,
                .edx = 0,
                .padding = .{ 0, 0, 0 },
            },
            else => {},
        }
    }
}

/// A flat code segment: base 0, 4G limit, 32-bit, present, executable/readable.
const cs_flat: Segment = .{
    .base = 0,
    .limit = 0xffff_ffff,
    .selector = 0x8,
    .kind = 0xb, // executable, readable, accessed
    .present = 1,
    .dpl = 0,
    .db = 1,
    .s = 1,
    .l = 0,
    .g = 1,
    .avl = 0,
    .unusable = 0,
    .padding = 0,
};

/// A flat data segment: same span as code, read/write.
const ds_flat: Segment = .{
    .base = 0,
    .limit = 0xffff_ffff,
    .selector = 0x10,
    .kind = 0x3, // read/write, accessed
    .present = 1,
    .dpl = 0,
    .db = 1,
    .s = 1,
    .l = 0,
    .g = 1,
    .avl = 0,
    .unusable = 0,
    .padding = 0,
};

/// Put the vCPU in flat 32-bit protected mode with paging off.
///
/// Linear addresses equal physical addresses, so a test can point RIP at a GPA directly
/// without building page tables.
fn enterFlatMode(vcpu_fd: std.posix.fd_t) Error!void {
    var sregs: Sregs = undefined;
    _ = try ioctl.call(
        vcpu_fd,
        comptime ioctl.request(.read, Sregs, nr.get_sregs),
        @intFromPtr(&sregs),
    );

    sregs.cs = cs_flat;
    sregs.ds = ds_flat;
    sregs.es = ds_flat;
    sregs.ss = ds_flat;

    // PE=1 enables protected mode; PG (bit 31) stays 0 so paging is off.
    sregs.cr0 = (sregs.cr0 | 1) & ~@as(u64, 1 << 31);
    sregs.cr4 = 0;

    _ = try ioctl.call(
        vcpu_fd,
        comptime ioctl.request(.write, Sregs, nr.set_sregs),
        @intFromPtr(&sregs),
    );
}

/// A 64-bit code segment: the long-mode bit set, byte granular limit, present and executable.
const cs_long: Segment = .{
    .base = 0,
    .limit = 0xffff_ffff,
    .selector = arch.boot.code_selector,
    .kind = 0xb, // executable, readable, accessed
    .present = 1,
    .dpl = 0,
    .db = 0, // must be clear while L is set
    .s = 1,
    .l = 1,
    .g = 1,
    .avl = 0,
    .unusable = 0,
    .padding = 0,
};

/// A data segment for long mode: flat, read/write, 32-bit default size.
const ds_long: Segment = .{
    .base = 0,
    .limit = 0xffff_ffff,
    .selector = arch.boot.data_selector,
    .kind = 0x3, // read/write, accessed
    .present = 1,
    .dpl = 0,
    .db = 1,
    .s = 1,
    .l = 0,
    .g = 1,
    .avl = 0,
    .unusable = 0,
    .padding = 0,
};

/// Put the vCPU in 64-bit long mode and place it at its entry.
///
/// The page tables, the GDT, and the entry all live in guest RAM the caller has already
/// filled. A wrong control bit or a code segment without the long-mode bit triple-faults
/// the guest the moment it runs.
pub fn enterLongMode(self: *Vcpu, cr3: u64, entry: u64, boot_params: u64, gdt: u64) Error!void {
    var sregs: Sregs = undefined;
    _ = try ioctl.call(self.fd, comptime ioctl.request(.read, Sregs, nr.get_sregs), @intFromPtr(&sregs));

    sregs.cs = cs_long;
    sregs.ds = ds_long;
    sregs.es = ds_long;
    sregs.ss = ds_long;
    sregs.fs = ds_long;
    sregs.gs = ds_long;

    // PE | PG, PAE, and LME | LMA together are the state a CPU holds once it is in long mode.
    sregs.cr0 = 0x8000_0001;
    sregs.cr4 = 0x20;
    sregs.efer = 0x500;
    sregs.cr3 = cr3;

    // Three eight-byte descriptors: null, code, data.
    sregs.gdt = .{ .base = gdt, .limit = 23, .padding = @splat(0) };

    _ = try ioctl.call(self.fd, comptime ioctl.request(.write, Sregs, nr.set_sregs), @intFromPtr(&sregs));

    var regs: Regs = undefined;
    _ = try ioctl.call(self.fd, comptime ioctl.request(.read, Regs, nr.get_regs), @intFromPtr(&regs));
    regs.rip = entry;
    regs.rsi = boot_params; // the zero page pointer the 64-bit entry reads
    regs.rflags = 0x2; // bit one is always set
    _ = try ioctl.call(self.fd, comptime ioctl.request(.write, Regs, nr.set_regs), @intFromPtr(&regs));
}

pub fn deinit(self: *Vcpu) void {
    std.posix.munmap(self.mapping);
    _ = linux.close(self.fd);
    self.* = undefined;
}

pub fn setRegister(self: *Vcpu, reg: Backend.Register, value: u64) Error!void {
    var regs: Regs = undefined;
    _ = try ioctl.call(self.fd, comptime ioctl.request(.read, Regs, nr.get_regs), @intFromPtr(&regs));
    switch (reg) {
        .rip => regs.rip = value,
        .rsi => regs.rsi = value,
        .rdi => regs.rdi = value,
        .rdx => regs.rdx = value,
        .rcx => regs.rcx = value,
        .rflags => regs.rflags = value,
    }
    _ = try ioctl.call(self.fd, comptime ioctl.request(.write, Regs, nr.set_regs), @intFromPtr(&regs));
}

pub fn getRegister(self: *Vcpu, reg: Backend.Register) Error!u64 {
    var regs: Regs = undefined;
    _ = try ioctl.call(self.fd, comptime ioctl.request(.read, Regs, nr.get_regs), @intFromPtr(&regs));
    return switch (reg) {
        .rip => regs.rip,
        .rsi => regs.rsi,
        .rdi => regs.rdi,
        .rdx => regs.rdx,
        .rcx => regs.rcx,
        .rflags => regs.rflags,
    };
}

pub fn run(self: *Vcpu) Error!Backend.Exit {
    _ = ioctl.call(self.fd, comptime ioctl.request(.none, void, nr.run), 0) catch |err| switch (err) {
        // A signal took the CPU back while the guest was still running, or the CPU was
        // not runnable yet and KVM handed it back. Neither is a fault: the guest carries
        // on from where it was, or enters once a startup signal makes it runnable.
        error.Interrupted, error.WouldBlock => return .interrupted,
        else => return err,
    };
    return self.decode();
}

/// KVM takes the value from the run structure when the guest is entered again.
/// A port read routes to the IO data page; an MMIO read goes to the MMIO data buffer.
pub fn completeMmioRead(self: *Vcpu, value: u64) Error!void {
    switch (self.last_exit) {
        .io => |io| {
            // The IO data lives at data_offset in the kvm_run mapping, not in the struct fields.
            if (io.data_offset > self.mapping.len or io.size > self.mapping.len - io.data_offset) return Error.HypervisorFault;
            @memcpy(self.mapping[io.data_offset..][0..io.size], std.mem.asBytes(&value)[0..io.size]);
        },
        .mmio, .none => {
            const mmio = &self.state.data.mmio;
            if (mmio.len > mmio.data.len) return Error.HypervisorFault;
            @memcpy(mmio.data[0..mmio.len], std.mem.asBytes(&value)[0..mmio.len]);
        },
    }
}

fn decode(self: *Vcpu) Error!Backend.Exit {
    const exit = shared.exit;
    const event = shared.event;
    return switch (self.state.exit_reason) {
        exit.io => blk: {
            const io = self.state.data.io;
            // String I/O (count > 1) is not yet supported.
            if (io.count != 1) return Error.HypervisorFault;
            const size = std.enums.fromInt(Backend.Size, io.size) orelse return Error.HypervisorFault;
            // The data page is at data_offset in the kvm_run mapping; never read past it.
            if (io.data_offset > self.mapping.len or io.size > self.mapping.len - io.data_offset) return Error.HypervisorFault;

            switch (io.direction) {
                1 => {
                    // OUT: read the value the guest wrote from the data page.
                    var value: u64 = 0;
                    @memcpy(std.mem.asBytes(&value)[0..io.size], self.mapping[io.data_offset..][0..io.size]);
                    self.last_exit = .{ .io = .{ .data_offset = io.data_offset, .size = io.size } };
                    break :blk .{ .port_out = .{ .port = io.port, .size = size, .value = value } };
                },
                0 => {
                    // IN: record where to write the completion value before re-entry.
                    self.last_exit = .{ .io = .{ .data_offset = io.data_offset, .size = io.size } };
                    break :blk .{ .port_in = .{ .port = io.port, .size = size } };
                },
                // The kernel only emits 0 or 1; any other value is untrusted data.
                else => return Error.HypervisorFault,
            }
        },
        exit.mmio => blk: {
            const mmio = self.state.data.mmio;
            if (mmio.len > mmio.data.len) return Error.HypervisorFault;
            const size = std.enums.fromInt(Backend.Size, mmio.len) orelse return Error.HypervisorFault;
            self.last_exit = .mmio;

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

/// Whether this CPU is running or halted, via KVM_GET_MP_STATE.
pub fn runState(self: *Vcpu) Error!u32 {
    var state: MpState = .{ .state = 0 };
    _ = try ioctl.call(self.fd, comptime ioctl.request(.read, MpState, nr.get_mp_state), @intFromPtr(&state));
    return state.state;
}

/// Set the run state via KVM_SET_MP_STATE.
pub fn setRunState(self: *Vcpu, value: u32) Error!void {
    var state: MpState = .{ .state = value };
    _ = try ioctl.call(self.fd, comptime ioctl.request(.write, MpState, nr.set_mp_state), @intFromPtr(&state));
}

/// x86 enumerates its state internally through fixed sub-states, not through an id list.
/// The count is always zero; the caller allocates no id buffer.
pub fn registerCount(self: *Vcpu) Error!u64 {
    _ = self;
    return 0;
}

/// x86 has no register-id list; returns an empty slice.
pub fn registerList(self: *Vcpu, buffer: []u64) Error![]const u64 {
    _ = self;
    return buffer[0..0];
}

/// Write a frame header into `into[at..]` and advance `at`.
fn writeFrame(into: []u8, at: *usize, tag: u8, len: usize) void {
    std.debug.assert(at.* + frame_overhead <= into.len); // caller must have verified capacity
    into[at.*] = tag;
    at.* += 1;
    std.mem.writeInt(u32, into[at.*..][0..4], @intCast(len), .little);
    at.* += 4;
}

/// Capture all vCPU sub-states into `into` as a fixed framed blob.
/// The `ids` parameter is unused on x86; the blob format is fixed.
pub fn save(self: *Vcpu, ids: []const u64, into: []u8) Error!usize {
    _ = ids;
    if (into.len < blob_size) return Error.InvalidArgument;

    var at: usize = 0;

    var regs: Regs = undefined;
    _ = try ioctl.call(self.fd, comptime ioctl.request(.read, Regs, nr.get_regs), @intFromPtr(&regs));
    writeFrame(into, &at, Tag.regs, @sizeOf(Regs));
    @memcpy(into[at..][0..@sizeOf(Regs)], std.mem.asBytes(&regs));
    at += @sizeOf(Regs);

    var sregs: Sregs = undefined;
    _ = try ioctl.call(self.fd, comptime ioctl.request(.read, Sregs, nr.get_sregs), @intFromPtr(&sregs));
    writeFrame(into, &at, Tag.sregs, @sizeOf(Sregs));
    @memcpy(into[at..][0..@sizeOf(Sregs)], std.mem.asBytes(&sregs));
    at += @sizeOf(Sregs);

    var xsave: Xsave = undefined;
    _ = try ioctl.call(self.fd, comptime ioctl.request(.read, Xsave, nr.get_xsave), @intFromPtr(&xsave));
    writeFrame(into, &at, Tag.xsave, @sizeOf(Xsave));
    @memcpy(into[at..][0..@sizeOf(Xsave)], std.mem.asBytes(&xsave));
    at += @sizeOf(Xsave);

    var mp: MpState = .{ .state = 0 };
    _ = try ioctl.call(self.fd, comptime ioctl.request(.read, MpState, nr.get_mp_state), @intFromPtr(&mp));
    writeFrame(into, &at, Tag.mp_state, @sizeOf(MpState));
    @memcpy(into[at..][0..@sizeOf(MpState)], std.mem.asBytes(&mp));
    at += @sizeOf(MpState);

    var events: VcpuEvents = undefined;
    _ = try ioctl.call(self.fd, comptime ioctl.request(.read, VcpuEvents, nr.get_vcpu_events), @intFromPtr(&events));
    writeFrame(into, &at, Tag.vcpu_events, @sizeOf(VcpuEvents));
    @memcpy(into[at..][0..@sizeOf(VcpuEvents)], std.mem.asBytes(&events));
    at += @sizeOf(VcpuEvents);

    var lapic: LapicState = undefined;
    _ = try ioctl.call(self.fd, comptime ioctl.request(.read, LapicState, nr.get_lapic), @intFromPtr(&lapic));
    writeFrame(into, &at, Tag.lapic, @sizeOf(LapicState));
    @memcpy(into[at..][0..@sizeOf(LapicState)], std.mem.asBytes(&lapic));
    at += @sizeOf(LapicState);

    return at;
}

pub const Restored = struct {
    written: usize,
    refused: usize,
};

/// Restore vCPU sub-states from a blob written by `save`.
/// A SET the kernel refuses is counted rather than fatal; a frame that runs past the blob
/// is a fault the caller passed bad data for.
pub fn load(self: *Vcpu, from: []const u8) Error!Restored {
    var at: usize = 0;
    var result: Restored = .{ .written = 0, .refused = 0 };

    while (at < from.len) {
        // A frame needs at least a tag byte and a 4-byte length.
        if (at + 5 > from.len) return Error.InvalidArgument;
        const tag = from[at];
        at += 1;
        const len: usize = std.mem.readInt(u32, from[at..][0..4], .little);
        at += 4;
        // A frame whose payload runs past the blob is an error, not a soft refusal.
        if (at + len > from.len) return Error.InvalidArgument;
        const payload = from[at..][0..len];
        at += len;

        const refused = switch (tag) {
            Tag.regs => blk: {
                if (len != @sizeOf(Regs)) break :blk true;
                var s: Regs = undefined;
                @memcpy(std.mem.asBytes(&s), payload);
                _ = ioctl.call(self.fd, comptime ioctl.request(.write, Regs, nr.set_regs), @intFromPtr(&s)) catch {
                    break :blk true;
                };
                break :blk false;
            },
            Tag.sregs => blk: {
                if (len != @sizeOf(Sregs)) break :blk true;
                var s: Sregs = undefined;
                @memcpy(std.mem.asBytes(&s), payload);
                _ = ioctl.call(self.fd, comptime ioctl.request(.write, Sregs, nr.set_sregs), @intFromPtr(&s)) catch {
                    break :blk true;
                };
                break :blk false;
            },
            Tag.xsave => blk: {
                if (len != @sizeOf(Xsave)) break :blk true;
                var s: Xsave = undefined;
                @memcpy(std.mem.asBytes(&s), payload);
                _ = ioctl.call(self.fd, comptime ioctl.request(.write, Xsave, nr.set_xsave), @intFromPtr(&s)) catch {
                    break :blk true;
                };
                break :blk false;
            },
            Tag.mp_state => blk: {
                if (len != @sizeOf(MpState)) break :blk true;
                var s: MpState = undefined;
                @memcpy(std.mem.asBytes(&s), payload);
                _ = ioctl.call(self.fd, comptime ioctl.request(.write, MpState, nr.set_mp_state), @intFromPtr(&s)) catch {
                    break :blk true;
                };
                break :blk false;
            },
            Tag.vcpu_events => blk: {
                if (len != @sizeOf(VcpuEvents)) break :blk true;
                var s: VcpuEvents = undefined;
                @memcpy(std.mem.asBytes(&s), payload);
                _ = ioctl.call(self.fd, comptime ioctl.request(.write, VcpuEvents, nr.set_vcpu_events), @intFromPtr(&s)) catch {
                    break :blk true;
                };
                break :blk false;
            },
            Tag.lapic => blk: {
                if (len != @sizeOf(LapicState)) break :blk true;
                var s: LapicState = undefined;
                @memcpy(std.mem.asBytes(&s), payload);
                _ = ioctl.call(self.fd, comptime ioctl.request(.write, LapicState, nr.set_lapic), @intFromPtr(&s)) catch {
                    break :blk true;
                };
                break :blk false;
            },
            // An unknown tag is counted as refused, not fatal.
            else => true,
        };
        if (refused) {
            result.refused += 1;
        } else {
            result.written += 1;
        }
    }
    return result;
}

pub const State = struct {
    /// The blob size is fixed for x86; the buffer argument is unused.
    pub fn size(cpu: *Vcpu, buffer: []u64) Error!usize {
        _ = cpu;
        _ = buffer;
        return blob_size;
    }
};

const ram = 0x4000_0000;

fn openVm() !Vm {
    return Vm.create() catch |err| switch (err) {
        error.NoKvm => error.SkipZigTest,
        else => err,
    };
}

test "a vcpu is created and its run structure is mapped" {
    var vm = try openVm();
    defer vm.deinit();

    var cpu = try Vcpu.create(&vm, 0);
    defer cpu.deinit();

    try std.testing.expect(cpu.fd > 0);
}

test "an x86 register written is the register read back" {
    var vm = try openVm();
    defer vm.deinit();
    var cpu = try Vcpu.create(&vm, 0);
    defer cpu.deinit();
    try cpu.setRegister(.rip, 0x1000);
    try cpu.setRegister(.rsi, 0xdead_beef);
    try testing.expectEqual(@as(u64, 0x1000), try cpu.getRegister(.rip));
    try testing.expectEqual(@as(u64, 0xdead_beef), try cpu.getRegister(.rsi));
}

test "an x86 store to unmapped memory comes back as an mmio write" {
    var vm = try openVm();
    defer vm.deinit();
    const region = try vm.addMemory(0x1000, 4 * std.heap.pageSize(), .shared);
    var memory: Backend.GuestMemory = .{ .regions = &.{region} };
    // mov byte ptr [0xd0000000], 0x4d ; jmp $
    const code = [_]u8{ 0xc6, 0x05, 0x00, 0x00, 0x00, 0xd0, 0x4d, 0xeb, 0xfe };
    try memory.write(0x1000, &code);
    var cpu = try Vcpu.create(&vm, 0);
    defer cpu.deinit();
    try cpu.setRegister(.rip, 0x1000);
    try testing.expectEqual(Backend.Exit{
        .mmio_write = .{ .gpa = 0xd000_0000, .size = .byte, .value = 0x4d },
    }, try cpu.run());
}

test "an x86 out instruction comes back as a port write" {
    var vm = try openVm();
    defer vm.deinit();
    const region = try vm.addMemory(ram, 4 * std.heap.pageSize(), .shared);
    var memory: Backend.GuestMemory = .{ .regions = &.{region} };
    // mov al,0x4d ; out 0xe9,al ; jmp $
    const code = [_]u8{ 0xb0, 0x4d, 0xe6, 0xe9, 0xeb, 0xfe };
    try memory.write(ram, &code);
    var cpu = try Vcpu.create(&vm, 0);
    defer cpu.deinit();
    try cpu.setRegister(.rip, ram);
    try testing.expectEqual(Backend.Exit{
        .port_out = .{ .port = 0xe9, .size = .byte, .value = 0x4d },
    }, try cpu.run());
}

test "an x86 in instruction takes the value the host completes" {
    var vm = try openVm();
    defer vm.deinit();
    const region = try vm.addMemory(ram, 4 * std.heap.pageSize(), .shared);
    var memory: Backend.GuestMemory = .{ .regions = &.{region} };
    // in al,0xe9 ; out 0xe9,al ; jmp $
    // The out after the in echoes back whatever came from the host, avoiding any need
    // to read registers while the guest is spinning.
    const code = [_]u8{ 0xe4, 0xe9, 0xe6, 0xe9, 0xeb, 0xfe };
    try memory.write(ram, &code);
    var cpu = try Vcpu.create(&vm, 0);
    defer cpu.deinit();
    try cpu.setRegister(.rip, ram);
    // First exit: the guest read a port and is waiting for the host to fill the value.
    try testing.expectEqual(Backend.Exit{
        .port_in = .{ .port = 0xe9, .size = .byte },
    }, try cpu.run());
    // Route 0x5a into the IO data buffer so KVM loads it into AL on re-entry.
    try cpu.completeMmioRead(0x5a);
    // Second exit: the guest echoed the value back out, proving 0x5a reached AL.
    try testing.expectEqual(Backend.Exit{
        .port_out = .{ .port = 0xe9, .size = .byte, .value = 0x5a },
    }, try cpu.run());
}

test "a long-mode x86 guest runs and writes a port" {
    var vm = try openVm();
    defer vm.deinit();

    // One region spans the page tables, the GDT, and the entry so every GPA the guest
    // touches on the way into long mode is backed.
    const span = 0x200000;
    const region = try vm.addMemory(0, span, .shared);
    var memory: Backend.GuestMemory = .{ .regions = &.{region} };

    const low = arch.boot.default_low;
    try arch.boot.buildLongMode(&memory, low, span, null);

    // mov al,0x4d ; out 0xe9,al ; jmp $ — placed inside the 2 MB page the PD identity-maps.
    const entry = 0x100000;
    const code = [_]u8{ 0xb0, 0x4d, 0xe6, 0xe9, 0xeb, 0xfe };
    try memory.write(entry, &code);

    var cpu = try Vcpu.create(&vm, 0);
    defer cpu.deinit();

    try cpu.enterLongMode(low.pml4, entry, low.boot_params, low.gdt);
    try testing.expectEqual(Backend.Exit{
        .port_out = .{ .port = 0xe9, .size = .byte, .value = 0x4d },
    }, try cpu.run());
}

test "everything an x86 vcpu holds goes out and comes back" {
    var vm = try openVm();
    defer vm.deinit();
    var cpu = try Vcpu.create(&vm, 0);
    defer cpu.deinit();
    try cpu.setRegister(.rip, 0x4008_0000);
    try cpu.setRegister(.rsi, 0xfeed_face);

    var blob: [8192]u8 = undefined;
    const used = try cpu.save(&.{}, &blob);

    try cpu.setRegister(.rip, 0x1000);
    try cpu.setRegister(.rsi, 0);
    _ = try cpu.load(blob[0..used]);

    try testing.expectEqual(@as(u64, 0x4008_0000), try cpu.getRegister(.rip));
    try testing.expectEqual(@as(u64, 0xfeed_face), try cpu.getRegister(.rsi));
}
