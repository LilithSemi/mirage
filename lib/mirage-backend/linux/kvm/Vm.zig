//! A KVM virtual machine and the memory slots it owns.
//!
//! A shared slot is ordinary anonymous memory the VMM maps and the guest sees at a
//! guest physical address. A private slot is a `guest_memfd` created without
//! `GUEST_MEMFD_FLAG_MMAP`, so the VMM has nothing to map and `GuestMemory.slice`
//! refuses it.
//!
//! On aarch64 the two are separate slots decided before launch, because this kernel
//! has no `KVM_CAP_MEMORY_ATTRIBUTES` and a guest cannot move a page between private
//! and shared while it runs. See the probe in `probe.zig` for what was asked.

const std = @import("std");
const testing = @import("mirage-testing");
const GuestMemory = @import("mirage-memory").GuestMemory;
const ioctl = @import("ioctl.zig");
const linux = std.os.linux;

const Vm = @This();

pub const max_slots = 16;

const nr = struct {
    const check_extension = 0x03;
    const create_vm = 0x01;
    const irq_line = 0x61;
    const create_guest_memfd = 0xd4;
    const set_user_memory_region2 = 0x49;
};

/// `KVM_MEM_GUEST_MEMFD` in `linux/kvm.h`.
const mem_guest_memfd: u32 = 1 << 2;

pub const Kind = enum { shared, private };

pub const IrqLevel = extern struct {
    irq: u32,
    level: u32,
};

/// An SPI is a shared interrupt, the kind a device raises. The interrupt number a
/// device tree calls `n` is `32 + n` to the controller, because the first 32 are
/// reserved for interrupts private to a CPU.
const spi_base = 32;

/// `irq_type` 1 selects a shared interrupt on the in kernel controller.
const irq_type_spi = 1;

/// Raise or lower a device interrupt. The guest sees it through the GIC, so the
/// controller has to exist before this is called.
pub fn setIrq(self: *Vm, spi: u32, level: bool) Error!void {
    const request: IrqLevel = .{
        .irq = (irq_type_spi << 24) | (spi_base + spi),
        .level = @intFromBool(level),
    };
    _ = try ioctl.call(
        self.fd,
        comptime ioctl.request(.write, IrqLevel, nr.irq_line),
        @intFromPtr(&request),
    );
}

pub const Error = error{
    NoKvm,
    TooManySlots,
    Misaligned,
    PrivateMemoryUnsupported,
} || ioctl.Error || std.posix.MMapError;

const Slot = struct {
    mapping: ?[]align(std.heap.page_size_min) u8 = null,
    memfd: ?std.posix.fd_t = null,

    fn release(self: Slot) void {
        if (self.mapping) |m| std.posix.munmap(m);
        if (self.memfd) |fd| _ = linux.close(fd);
    }
};

kvm: std.posix.fd_t,
fd: std.posix.fd_t,
slots: u32 = 0,
owned: [max_slots]Slot = @splat(.{}),

pub fn create() Error!Vm {
    const opened = linux.open("/dev/kvm", .{ .ACCMODE = .RDWR, .CLOEXEC = true }, 0);
    if (std.posix.errno(opened) != .SUCCESS) return Error.NoKvm;
    const kvm: std.posix.fd_t = @intCast(opened);
    errdefer _ = linux.close(kvm);

    // Machine type zero asks for this host's default intermediate physical address
    // size. aarch64 encodes a wider address space in the low bits of this argument.
    const raw = try ioctl.call(kvm, comptime ioctl.request(.none, void, nr.create_vm), 0);
    return .{ .kvm = kvm, .fd = @intCast(raw) };
}

pub fn deinit(self: *Vm) void {
    for (self.owned[0..self.slots]) |slot| slot.release();
    _ = linux.close(self.fd);
    _ = linux.close(self.kvm);
    self.* = undefined;
}

pub fn addMemory(self: *Vm, gpa: u64, len: u64, kind: Kind) Error!GuestMemory.Region {
    if (self.slots >= max_slots) return Error.TooManySlots;

    // KVM measures a memory slot in host pages. This host uses 64K pages, so a size
    // that looks reasonable for a 4K host is refused with EINVAL several calls later.
    // Refusing it here names the real problem.
    const page = std.heap.pageSize();
    if (gpa % page != 0 or len % page != 0 or len == 0) return Error.Misaligned;

    var request: ioctl.UserspaceMemoryRegion2 = .{
        .slot = self.slots,
        .flags = 0,
        .guest_phys_addr = gpa,
        .memory_size = len,
        .userspace_addr = 0,
        .guest_memfd_offset = 0,
        .guest_memfd = 0,
        .pad1 = 0,
        .pad2 = @splat(0),
    };

    var slot: Slot = .{};
    var backing: GuestMemory.Backing = .private;
    errdefer slot.release();

    switch (kind) {
        .shared => {
            const mapping = try std.posix.mmap(
                null,
                @intCast(len),
                .{ .READ = true, .WRITE = true },
                .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
                -1,
                0,
            );
            slot.mapping = mapping;
            request.userspace_addr = @intFromPtr(mapping.ptr);
            backing = .{ .shared = mapping };
        },
        .private => {
            var args: ioctl.CreateGuestMemfd = .{ .size = len, .flags = 0, .reserved = @splat(0) };
            const raw = try ioctl.call(
                self.fd,
                comptime ioctl.request(.read_write, ioctl.CreateGuestMemfd, nr.create_guest_memfd),
                @intFromPtr(&args),
            );
            slot.memfd = @intCast(raw);
            request.flags = mem_guest_memfd;
            request.guest_memfd = @intCast(raw);
        },
    }

    _ = ioctl.call(
        self.fd,
        comptime ioctl.request(.write, ioctl.UserspaceMemoryRegion2, nr.set_user_memory_region2),
        @intFromPtr(&request),
    ) catch |err| switch (err) {
        // aarch64 refuses a slot backed by memory the VMM cannot map, because with
        // no memory attributes it has no way to fault a private page. Say that,
        // rather than let a caller read EINVAL and guess. A caller that wants a
        // guest anyway asks for `.shared` and records the tier it actually got.
        error.InvalidArgument => if (kind == .private) return Error.PrivateMemoryUnsupported else return err,
        else => return err,
    };

    self.owned[self.slots] = slot;
    self.slots += 1;
    return .{ .gpa = gpa, .len = len, .backing = backing };
}

const base = 0x4000_0000;

fn pages(n: u64) u64 {
    return n * std.heap.pageSize();
}

fn open() !Vm {
    return Vm.create() catch |err| switch (err) {
        error.NoKvm => error.SkipZigTest,
        else => err,
    };
}

test "a shared region can be written and read back through guest memory" {
    var vm = try open();
    defer vm.deinit();

    const region = try vm.addMemory(base, pages(4), .shared);
    var memory: GuestMemory = .{ .regions = &.{region} };

    try memory.write(base + 8, "mirage");
    var out: [6]u8 = undefined;
    try memory.read(base + 8, &out);
    try testing.expectEqualSlices(u8, "mirage", &out);
}

test "a private region is refused where the kernel cannot fault private pages" {
    var vm = try open();
    defer vm.deinit();

    // See the probe for the measurement behind this. Mirage refuses by name instead
    // of quietly giving back memory the VMM can read.
    try testing.expectError(error.PrivateMemoryUnsupported, vm.addMemory(base, pages(4), .private));
}

test "each added region takes the next slot number" {
    var vm = try open();
    defer vm.deinit();

    _ = try vm.addMemory(base, pages(1), .shared);
    _ = try vm.addMemory(base + 0x1000_0000, pages(1), .shared);
    try testing.expectEqual(@as(u32, 2), vm.slots);
}

test "a region that is not a whole number of host pages is refused" {
    var vm = try open();
    defer vm.deinit();

    // 4096 is a page on most hosts and is not a page on this one.
    try testing.expectError(error.Misaligned, vm.addMemory(base, 4096, .shared));
    try testing.expectError(error.Misaligned, vm.addMemory(base + 1, pages(1), .shared));
}

/// `KVM_CAP_MAX_VCPUS` and `KVM_CAP_NR_VCPUS`, which are what the kernel will say about how many CPUs
/// a guest may have. The first is the hard limit and the second is what it recommends.
const cap_nr_vcpus = 9;
const cap_max_vcpus = 66;

/// The most CPUs this host will give a guest.
///
/// Asked rather than decided. How many CPUs a guest may have belongs to the kernel and the machine it
/// runs on, and a number written here would be wrong on the first host that disagreed. A kernel too
/// old to answer still allows four, which is what the interface promised before the question existed.
pub fn maxVcpus(self: *const Vm) u32 {
    const request = comptime ioctl.request(.none, void, nr.check_extension);
    if (ioctl.call(self.kvm, request, cap_max_vcpus)) |most| {
        if (most > 0) return @intCast(most);
    } else |_| {}
    if (ioctl.call(self.kvm, request, cap_nr_vcpus)) |advised| {
        if (advised > 0) return @intCast(advised);
    } else |_| {}
    return 4;
}
