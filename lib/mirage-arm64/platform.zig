//! Where a guest's devices sit on this architecture, and how many CPUs its memory holds.
//!
//! A runner that does not name an architecture still has to place a serial port, a block
//! device, and the rest somewhere, and the somewhere is a property of the machine. On arm
//! the addresses are the ones the device tree names, so they come from there and the two
//! cannot disagree.

const fdt = @import("fdt.zig");

/// A device the guest finds at a fixed place. The serial port is memory mapped here, so
/// its `addr` is a guest physical address like every other device's.
pub const Device = struct {
    addr: u64,
    intid: u32,
};

/// The serial port, memory mapped at the address the device tree names it. Its interrupt
/// is the one the tree gives the pl011, so a driver that waits to send has a line to wait on.
pub const serial: Device = .{ .addr = 0x0900_0000, .intid = fdt.uart_intid };
pub const fs: Device = .{ .addr = fdt.fs_base, .intid = fdt.fs_intid };
pub const tpm: Device = .{ .addr = fdt.tpm_base, .intid = 0 };
/// The firmware configuration device, where this machine has one. Firmware reads it before it
/// reaches any of its own code, and a machine that cannot describe one to a guest has none.
pub const fw_cfg: ?Device = .{ .addr = fdt.fw_cfg_base, .intid = 0 };
pub const virtio: Device = .{ .addr = fdt.virtio_base, .intid = fdt.virtio_intid };
pub const vsock: Device = .{ .addr = fdt.vsock_base, .intid = fdt.vsock_intid };
pub const balloon: Device = .{ .addr = fdt.balloon_base, .intid = fdt.balloon_intid };
pub const net: Device = .{ .addr = fdt.net_base, .intid = fdt.net_intid };

/// One window a region may be placed in.
pub const Window = struct {
    at: u64,
    len: u64,
};

/// Where a pci host bridge sits: config space, and the windows it decodes. The addresses are the
/// ones the device tree names, so the bus the guest reads and the tree it was given cannot
/// disagree. A narrow region goes in the low window, a wide one may go in either.
pub const Bridge = struct {
    ecam: u64,
    memory: Window,
    memory64: Window,
};

pub const pci: ?Bridge = .{
    .ecam = fdt.ecam_base,
    .memory = .{ .at = fdt.pci_memory_base, .len = fdt.pci_memory_size },
    .memory64 = .{ .at = fdt.pci_memory64_base, .len = fdt.pci_memory64_size },
};

/// Whether the guest's serial port is reached through an I/O port rather than memory. arm
/// has no port space, so every device is memory mapped and the run loop needs no port bus.
pub const serial_is_port = false;

/// How many CPUs fit in the memory below a guest's RAM, where the redistributors live. A
/// machine asked for more than this cannot place a redistributor for each.
pub fn cpusThatFit(ram_base: u64) u32 {
    return @intCast(fdt.cpusThatFit(ram_base));
}
