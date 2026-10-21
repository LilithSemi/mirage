//! Where a guest's devices sit on this architecture, and how many CPUs its memory holds.
//!
//! A runner that does not name an architecture still has to place a serial port, a block
//! device, and the rest somewhere. On x86 the serial port is reached through an I/O port,
//! the one a PC has always put the first serial line at, and the rest are virtio over
//! memory mapped I/O in a hole below the region a thirty two bit machine keeps for its
//! buses. Their interrupts are routed by the I/O APIC the hypervisor built with the
//! machine, so the numbers here are its global interrupts, chosen above the sixteen a PC
//! reserves for its legacy devices.

/// A device the guest finds at a fixed place. For a memory mapped device `addr` is a guest
/// physical address; for the serial port it is the I/O port the guest writes.
pub const Device = struct {
    addr: u64,
    intid: u32,
};

/// The base of the virtio over memory mapped I/O window. It sits below the hole a thirty two
/// bit PC keeps for its buses and the local and I/O APICs, and above every address the boot
/// path writes, so nothing the loader placed is overwritten by a device.
const virtio_window = 0xd000_0000;

/// One virtio device's window. The same width the other architecture gives one, which is all
/// the registers a virtio over memory mapped I/O device needs.
const virtio_stride = 0x200;

/// The first global interrupt a device is given. The sixteen below it are the legacy lines a PC
/// reserves, so a device numbered from here cannot collide with one.
const gsi_base = 16;

/// The first serial line of a PC, reached through an I/O port rather than memory. Its legacy
/// interrupt is four; the in kernel controller routes it, so this runner does not raise it by hand.
pub const serial: Device = .{ .addr = 0x3f8, .intid = 4 };

pub const virtio: Device = .{ .addr = virtio_window + 0 * virtio_stride, .intid = gsi_base + 0 };
pub const vsock: Device = .{ .addr = virtio_window + 1 * virtio_stride, .intid = gsi_base + 1 };
pub const balloon: Device = .{ .addr = virtio_window + 2 * virtio_stride, .intid = gsi_base + 2 };
pub const net: Device = .{ .addr = virtio_window + 3 * virtio_stride, .intid = gsi_base + 3 };
pub const fs: Device = .{ .addr = virtio_window + 4 * virtio_stride, .intid = gsi_base + 4 };
// 0xfed4_0000 is the x86 TCG TIS base; the TIS region spans 0x5000 bytes (5 localities),
// sitting in high MMIO clear of the virtio window and below the IOAPIC at 0xfec0_0000.
pub const tpm: Device = .{ .addr = 0xfed4_0000, .intid = 0 };

/// Whether the guest's serial port is reached through an I/O port rather than memory. x86 puts
/// it on a port, so the run loop gives the serial a port bus rather than the memory one.
pub const serial_is_port = true;

/// One window a region may be placed in.
pub const Window = struct {
    at: u64,
    len: u64,
};

/// Where a pci host bridge sits. There is none here: a guest on this architecture learns of one
/// from the ACPI memory mapped config space table, which this VMM does not write, and a bridge no
/// guest is told about is a window nothing ever reads.
pub const Bridge = struct {
    ecam: u64,
    memory: Window,
    memory64: Window,
};

pub const pci: ?Bridge = null;

const testing = @import("mirage-testing");
const std = @import("std");

test "the x86 tpm sits at the tis base" {
    try testing.expectEqual(@as(u64, 0xfed4_0000), tpm.addr);

    // TIS region: [tpm.addr, tpm.addr + 0x5000)
    const tis_lo = tpm.addr;
    const tis_hi = tpm.addr + 0x5000;

    // Virtio window: [0xd000_0000, 0xd000_0000 + 6*0x200)
    const virt_lo: u64 = 0xd000_0000;
    const virt_hi: u64 = 0xd000_0000 + 6 * virtio_stride;
    try std.testing.expect(tis_hi <= virt_lo or tis_lo >= virt_hi);

    // IOAPIC: [0xfec0_0000, 0xfec0_0000 + 0x1000)
    const ioapic_lo: u64 = 0xfec0_0000;
    const ioapic_hi: u64 = 0xfec0_0000 + 0x1000;
    try std.testing.expect(tis_hi <= ioapic_lo or tis_lo >= ioapic_hi);

    // LAPIC: [0xfee0_0000, 0xfee0_0000 + 0x1000)
    const lapic_lo: u64 = 0xfee0_0000;
    const lapic_hi: u64 = 0xfee0_0000 + 0x1000;
    try std.testing.expect(tis_hi <= lapic_lo or tis_lo >= lapic_hi);
}

/// How many CPUs a guest may have. The interrupt controller the hypervisor builds holds far more
/// than any guest this runner starts, so the bound is a plain ceiling rather than one worked out
/// from where anything sits in memory.
pub fn cpusThatFit(ram_base: u64) u32 {
    _ = ram_base;
    return 255;
}

/// Read the AMD SEV C-bit position from CPUID leaf 0x8000001F, EBX bits [5:0].
pub fn hostCBit() u6 {
    var eax_out: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx_out: u32 = undefined;
    var edx_out: u32 = undefined;
    asm volatile ("cpuid"
        : [a] "={eax}" (eax_out),
          [b] "={ebx}" (ebx),
          [c] "={ecx}" (ecx_out),
          [d] "={edx}" (edx_out),
        : [leaf] "{eax}" (@as(u32, 0x8000001F)),
          [sub] "{ecx}" (@as(u32, 0)),
    );
    const bit: u6 = @intCast(ebx & 0x3f);

    // A SEV C-bit always sits high in the physical address, around 47 to 51. A zero or low value
    // means the leaf is unsupported (not an AMD SEV host), and treating it as a page-table bit
    // would corrupt the mapping. Only call this once SEV is confirmed.
    std.debug.assert(bit >= 32);
    return bit;
}
