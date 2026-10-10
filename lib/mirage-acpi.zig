//! Builds the ACPI tables the guest firmware reads at boot.
//!
//! The module is buffer-based and freestanding-clean. No allocator, no std.Io,
//! no std.heap. It composes over almanac, which holds the same property.

const std = @import("std");
const testing = @import("mirage-testing");

pub const almanac = @import("almanac");

/// The I/O port the FADT sleep-control and sleep-status registers name.
pub const sleep_port: u16 = 0x600;

/// The S5 sleep type value written to the hw-reduced sleep-control register
/// to trigger poweroff. Task 5's shutdown-port device decodes
/// (s5_slp_typ << 2) | (1 << 5) on that register.
pub const s5_slp_typ: u8 = 5;

/// A TPM device to describe in the ACPI set.
pub const Tpm = struct {
    /// Physical address of the TPM control area.
    control: u64,
    /// Physical address of the event-log area (0 = none).
    log_addr: u64 = 0,
    /// Length of the event-log area in bytes (0 = none).
    log_len: u32 = 0,
};

/// Options for building the ACPI table set.
pub const Options = struct {
    /// How many Processor Local APIC entries the MADT carries.
    cpus: u32 = 1,
    /// Virtio-mmio devices to describe as ACPI Device objects in the DSDT.
    virtio: []const VirtioDevice = &.{},
    /// When set, a TPM2 table is emitted and listed in the XSDT.
    tpm: ?Tpm = null,
};

/// The result of building the table set: the bytes to copy into guest RAM and
/// the physical address of the RSDP, reported by the Builder rather than
/// recomputed, so adding tables cannot desync where the RSDP lands.
pub const Built = struct {
    bytes: []u8,
    rsdp: u64,
};

// The FADT is 276 bytes (ACPI 6.x). Layout is fixed by the spec; fields are
// written by offset using std.mem.writeInt. Asserts below pin every field used.
const fadt_size: usize = 276;

// AML encoding for: Name (_S5, Package (2) { 5, 5 })
//
// ACPI spec §20.2.3: NameOp NameString; §20.2.5.4: PackageOp PkgLength
// NumElements PackageElementList.
//
// PkgLength counts itself plus the body that follows it:
//   body = NumElements(1 byte) + ByteData(2 bytes) + ByteData(2 bytes) = 5 bytes
//   PkgLength = 1 (self) + 5 (body) = 6
//
// The two Byte() elements encode s5_slp_typ for SLP_TYPa and SLP_TYPb.
const s5_aml = [_]u8{
    0x08, // NameOp
    0x5F, 0x53, 0x35, 0x5F, // "_S5_" NameSeg
    0x12, // PackageOp
    0x06, // PkgLength = 6 (self + 5 body bytes)
    0x02, // NumElements = 2
    almanac.aml.encoding.byte_prefix, s5_slp_typ, // SLP_TYPa = 5
    almanac.aml.encoding.byte_prefix, s5_slp_typ, // SLP_TYPb = 5
};

comptime {
    // PkgLength body: NumElements(1) + 2*ByteData(2 each) = 5; PkgLength = 1+5 = 6.
    std.debug.assert(s5_aml[6] == 6);
    std.debug.assert(s5_aml.len == 12);
}

// The Generic Address Structure is 12 bytes. The assert below confirms it.
comptime {
    std.debug.assert(@sizeOf(almanac.Gas) == 12);
    // sleep-control GAS lives at FADT offset 244; sleep-status at 256.
    // The assertions are on the constants, not on a struct field, because the
    // FADT body is a raw [276]u8 built field-by-field.
    std.debug.assert(sleep_control_off == 244);
    std.debug.assert(sleep_status_off == 256);
    std.debug.assert(sleep_status_off + @sizeOf(almanac.Gas) <= fadt_size);
}

// Byte offsets within the 276-byte FADT for the two sleep GAS fields.
const sleep_control_off: usize = 244;
const sleep_status_off: usize = 256;

// Bit 20 of the FADT flags field: hardware-reduced ACPI platform.
const flag_hw_reduced: u32 = 1 << 20;

// These three structs pin sizes via @sizeOf for the raw-offset writer, they are never memcpy'd, so do not fold the offset writes into struct stores and pick up padding.
// MADT fixed header that follows the 36-byte SDT header: local APIC address
// and the multiple-APIC flags word. Eight bytes total.
const MadtHeader = extern struct {
    local_apic_address: u32,
    flags: u32,
};

// Type 0x00 interrupt-controller entry: Processor Local APIC. Eight bytes.
const LocalApicEntry = extern struct {
    type: u8,
    length: u8,
    acpi_processor_id: u8,
    apic_id: u8,
    flags: u32 align(1),
};

// Type 0x01 interrupt-controller entry: I/O APIC. Twelve bytes.
const IoApicEntry = extern struct {
    type: u8,
    length: u8,
    ioapic_id: u8,
    reserved: u8,
    address: u32 align(1),
    global_system_interrupt_base: u32 align(1),
};

comptime {
    std.debug.assert(@sizeOf(MadtHeader) == 8);
    std.debug.assert(@sizeOf(LocalApicEntry) == 8);
    std.debug.assert(@sizeOf(IoApicEntry) == 12);
}

/// Build the MADT body (everything after the 36-byte SDT header) into `dst`.
/// `dst` must be exactly `madtBodyLen(cpus)` bytes.
fn writeMadtBody(dst: []u8, cpus: u32) void {
    // Fixed header: local APIC address and flags (bit 0 = PCAT_COMPAT).
    std.mem.writeInt(u32, dst[0..4], 0xfee00000, .little);
    std.mem.writeInt(u32, dst[4..8], 1, .little); // PCAT_COMPAT

    var off: usize = @sizeOf(MadtHeader);

    // One Processor Local APIC entry per cpu.
    var i: u32 = 0;
    while (i < cpus) : (i += 1) {
        const id: u8 = @intCast(i);
        dst[off + 0] = 0; // type: Processor Local APIC
        dst[off + 1] = @sizeOf(LocalApicEntry);
        dst[off + 2] = id; // acpi_processor_id
        dst[off + 3] = id; // apic_id
        std.mem.writeInt(u32, dst[off + 4 ..][0..4], 1, .little); // enabled
        off += @sizeOf(LocalApicEntry);
    }

    // One I/O APIC entry.
    dst[off + 0] = 1; // type: I/O APIC
    dst[off + 1] = @sizeOf(IoApicEntry);
    dst[off + 2] = 0; // ioapic_id
    dst[off + 3] = 0; // reserved
    std.mem.writeInt(u32, dst[off + 4 ..][0..4], 0xfec00000, .little);
    std.mem.writeInt(u32, dst[off + 8 ..][0..4], 0, .little); // gsi_base
}

/// Number of bytes in the MADT body for the given cpu count.
fn madtBodyLen(cpus: u32) usize {
    return @sizeOf(MadtHeader) + cpus * @sizeOf(LocalApicEntry) + @sizeOf(IoApicEntry);
}

/// Write a 12-byte GAS into `dst` at `off`. address_space=1 (SystemIO),
/// bit_width=8, bit_offset=0, access_size=1 (byte), address=port.
fn writeGas(dst: []u8, off: usize, port: u16) void {
    dst[off + 0] = 1; // address_space: SystemIO
    dst[off + 1] = 8; // bit_width
    dst[off + 2] = 0; // bit_offset
    dst[off + 3] = 1; // access_size: byte
    std.mem.writeInt(u64, dst[off + 4 ..][0..8], port, .little);
}

/// A virtio-mmio device to encode as an ACPI Device object in the DSDT.
pub const VirtioDevice = struct {
    addr: u64,
    size: u32,
    gsi: u32,
};

// Fixed body lengths used in emitDevice.
const mem32_body_len: usize = 9; // info(1) + base(4) + length(4)
const extirq_body_len: usize = 6; // flags(1) + count(1) + gsi(4)
const crs_resources_len: usize = 23; // Memory32Fixed + ExtInterrupt + EndTag

// Fixed resource lengths for the TPM TIS device _CRS.
// Only a Memory32Fixed (12 bytes) + EndTag (2 bytes): no interrupt.
const tpm_crs_resources_len: usize = 14;

comptime {
    // Cross-check each length against the field widths it holds, so a wrong
    // constant trips the assert. A large resource carries a 3-byte header
    // (tag + u16 length); the EndTag is 2 bytes.
    std.debug.assert(@sizeOf(u8) + @sizeOf(u32) + @sizeOf(u32) == mem32_body_len);
    std.debug.assert(@sizeOf(u8) + @sizeOf(u8) + @sizeOf(u32) == extirq_body_len);
    std.debug.assert(3 + mem32_body_len + 3 + extirq_body_len + 2 == crs_resources_len);
    std.debug.assert(mem32_body_len == 9);
    std.debug.assert(tpm_crs_resources_len == 14); // Memory32Fixed(12) + EndTag(2)
}

/// Write an ACPI PkgLength for a package whose content (not counting the
/// PkgLength bytes) is `content_len` bytes. Returns the number of bytes
/// written: 1 when total < 0x40, 2 otherwise.
fn writePkgLength(buf: []u8, content_len: usize) usize {
    const total1 = content_len + 1;
    if (total1 < 0x40) {
        buf[0] = @intCast(total1);
        return 1;
    }
    const total2 = content_len + 2;
    std.debug.assert(total2 < 0x1000);
    buf[0] = @intCast(0x40 | (total2 & 0x0F));
    buf[1] = @intCast(total2 >> 4);
    return 2;
}

/// Write one Device(VRnn){ _HID "LNRO0005"; _UID index; _CRS ... } into buf.
/// Returns bytes written.
fn emitDevice(buf: []u8, index: u8, dev: VirtioDevice) usize {
    std.debug.assert(index < 100);
    std.debug.assert(dev.addr <= 0xFFFF_FFFF);

    // Resource descriptors (23 bytes total).
    var resources: [crs_resources_len]u8 = undefined;
    // Memory32Fixed: tag 0x86, body-length u16 LE = 9, then info + base + length.
    resources[0] = 0x86;
    resources[1] = mem32_body_len;
    resources[2] = 0x00;
    resources[3] = 0x01; // ReadWrite
    std.mem.writeInt(u32, resources[4..8], @intCast(dev.addr), .little);
    std.mem.writeInt(u32, resources[8..12], dev.size, .little);
    // Extended Interrupt: tag 0x89, body-length u16 LE = 6, flags, count, gsi.
    resources[12] = 0x89;
    resources[13] = extirq_body_len;
    resources[14] = 0x00;
    resources[15] = 0x01; // Consumer, Level, ActiveHigh, Exclusive
    resources[16] = 0x01; // interrupt count = 1
    std.mem.writeInt(u32, resources[17..21], dev.gsi, .little);
    // EndTag.
    resources[21] = 0x79;
    resources[22] = 0x00;

    // _CRS Name object: NameOp + "_CRS" + BufferOp + PkgLength + BufferSize + resources.
    // BufferOp PkgLength content = BufferSize(2) + resources(23) = 25; total = 26 = 0x1A.
    var crs: [32]u8 = undefined;
    var cp: usize = 0;
    crs[cp] = 0x08;
    cp += 1; // NameOp
    crs[cp] = 0x5F;
    crs[cp + 1] = 0x43;
    crs[cp + 2] = 0x52;
    crs[cp + 3] = 0x53;
    cp += 4; // _CRS
    crs[cp] = 0x11;
    cp += 1; // BufferOp
    cp += writePkgLength(crs[cp..], 2 + crs_resources_len); // BufferSize(2) + resources(23)
    crs[cp] = almanac.aml.encoding.byte_prefix;
    cp += 1;
    crs[cp] = crs_resources_len;
    cp += 1; // 0x17 = 23
    @memcpy(crs[cp .. cp + crs_resources_len], &resources);
    cp += crs_resources_len;
    const crs_len = cp;

    // Name(_HID,"LNRO0005"): 08 + _HID + 0D + "LNRO0005" + 00 = 15 bytes.
    const hid = [15]u8{
        0x08, // NameOp
        0x5F, 0x48, 0x49, 0x44, // _HID
        0x0D, // StringPrefix
        'L',
        'N',
        'R',
        'O',
        '0',
        '0',
        '0',
        '5',
        0x00, // NUL
    };

    // Name(_UID,n): 08 + _UID + BytePrefix + n = 7 bytes.
    const uid = [7]u8{
        0x08, // NameOp
        0x5F,                             0x55,  0x49, 0x44, // _UID
        almanac.aml.encoding.byte_prefix, index,
    };

    // Device = 5B 82 + PkgLength(NameSeg(4) + body) + NameSeg + body.
    const body_len = hid.len + uid.len + crs_len;
    const pkg_content = 4 + body_len; // NameSeg(4) + body

    var p: usize = 0;
    buf[p] = 0x5B;
    p += 1; // ExtOpPrefix
    buf[p] = 0x82;
    p += 1; // DeviceOp
    p += writePkgLength(buf[p..], pkg_content);
    buf[p] = 'V';
    p += 1;
    buf[p] = 'R';
    p += 1;
    buf[p] = '0' + (index / 10);
    p += 1;
    buf[p] = '0' + (index % 10);
    p += 1;
    @memcpy(buf[p .. p + hid.len], &hid);
    p += hid.len;
    @memcpy(buf[p .. p + uid.len], &uid);
    p += uid.len;
    @memcpy(buf[p .. p + crs_len], crs[0..crs_len]);
    p += crs_len;
    return p;
}

/// Write Scope(\_SB_){ <one Device per dev> } into buf. Returns bytes written.
pub fn emitSystemBus(buf: []u8, devs: []const VirtioDevice) usize {
    // Encode all devices into a scratch area first to know total length.
    var scratch: [4096]u8 = undefined;
    var dev_total: usize = 0;
    for (devs, 0..) |dev, i| {
        dev_total += emitDevice(scratch[dev_total..], @intCast(i), dev);
    }

    // Scope(\_SB_): 10 + PkgLength(over \_SB_ name(5) + devices) + \_SB_(5) + devices
    const scope_content = 5 + dev_total; // \_SB_(5) + devices
    var p: usize = 0;
    buf[p] = 0x10;
    p += 1; // ScopeOp
    p += writePkgLength(buf[p..], scope_content);
    // \_SB_ = root_char + "_SB_" = 5C 5F 53 42 5F
    buf[p] = 0x5C;
    p += 1; // root_char '\'
    buf[p] = 0x5F;
    buf[p + 1] = 0x53;
    buf[p + 2] = 0x42;
    buf[p + 3] = 0x5F;
    p += 4; // _SB_
    @memcpy(buf[p .. p + dev_total], scratch[0..dev_total]);
    p += dev_total;
    return p;
}

/// Write Device(TPM0){ Name(_HID,"MSFT0101") Name(_CRS,...) } into buf.
/// Returns bytes written. No _UID; _CRS holds only Memory32Fixed + EndTag.
fn emitTpmDevice(buf: []u8, control: u32) usize {
    // Resource descriptors: Memory32Fixed(12) + EndTag(2) = 14 bytes.
    var resources: [tpm_crs_resources_len]u8 = undefined;
    resources[0] = 0x86; // Memory32Fixed tag
    resources[1] = mem32_body_len; // body length = 9
    resources[2] = 0x00; // high byte of u16 body length
    resources[3] = 0x01; // ReadWrite
    std.mem.writeInt(u32, resources[4..8], control, .little);
    std.mem.writeInt(u32, resources[8..12], 0x5000, .little); // TIS size
    resources[12] = 0x79; // EndTag
    resources[13] = 0x00;

    // _CRS Name: NameOp + "_CRS" + BufferOp + PkgLength + BufferSize + resources.
    // BufferPkg content = BufferSize(2) + resources(14) = 16; total1 = 17 < 0x40.
    var crs: [32]u8 = undefined;
    var cp: usize = 0;
    crs[cp] = 0x08;
    cp += 1; // NameOp
    crs[cp] = 0x5F;
    crs[cp + 1] = 0x43;
    crs[cp + 2] = 0x52;
    crs[cp + 3] = 0x53;
    cp += 4; // _CRS
    crs[cp] = 0x11;
    cp += 1; // BufferOp
    cp += writePkgLength(crs[cp..], 2 + tpm_crs_resources_len); // 16
    crs[cp] = almanac.aml.encoding.byte_prefix;
    cp += 1;
    crs[cp] = tpm_crs_resources_len;
    cp += 1; // 0x0E = 14
    @memcpy(crs[cp .. cp + tpm_crs_resources_len], &resources);
    cp += tpm_crs_resources_len;
    const crs_len = cp;

    // Name(_HID,"MSFT0101"): same encoding as LNRO0005, 15 bytes.
    const hid = [15]u8{
        0x08, // NameOp
        0x5F, 0x48, 0x49, 0x44, // _HID
        0x0D, // StringPrefix
        'M',
        'S',
        'F',
        'T',
        '0',
        '1',
        '0',
        '1',
        0x00, // NUL
    };

    // Device body: _HID(15) + _CRS(crs_len). No _UID for TPM0.
    const body_len = hid.len + crs_len;
    const pkg_content = 4 + body_len; // NameSeg(4) + body

    var p: usize = 0;
    buf[p] = 0x5B;
    p += 1; // ExtOpPrefix
    buf[p] = 0x82;
    p += 1; // DeviceOp
    p += writePkgLength(buf[p..], pkg_content);
    buf[p] = 'T';
    p += 1;
    buf[p] = 'P';
    p += 1;
    buf[p] = 'M';
    p += 1;
    buf[p] = '0';
    p += 1;
    @memcpy(buf[p .. p + hid.len], &hid);
    p += hid.len;
    @memcpy(buf[p .. p + crs_len], crs[0..crs_len]);
    p += crs_len;
    return p;
}

/// Write Scope(\_SB_){ Device(TPM0){...} } into buf. Returns bytes written.
pub fn emitTpmScope(buf: []u8, control: u32) usize {
    var scratch: [128]u8 = undefined;
    const dev_len = emitTpmDevice(&scratch, control);

    // Scope(\_SB_): ScopeOp + PkgLength + \_SB_(5) + device
    const scope_content = 5 + dev_len;
    var p: usize = 0;
    buf[p] = 0x10;
    p += 1; // ScopeOp
    p += writePkgLength(buf[p..], scope_content);
    buf[p] = 0x5C;
    p += 1; // root_char '\'
    buf[p] = 0x5F;
    buf[p + 1] = 0x53;
    buf[p + 2] = 0x42;
    buf[p + 3] = 0x5F;
    p += 4; // _SB_
    @memcpy(buf[p .. p + dev_len], scratch[0..dev_len]);
    p += dev_len;
    return p;
}

/// Build an RSDP, XSDT, hardware-reduced FADT, and DSDT carrying _S5 into
/// `buf` at guest physical address `base_phys`. Returns the bytes written and
/// the RSDP's physical address as the Builder placed it.
pub fn build(buf: []u8, base_phys: u64, opts: Options) !Built {
    var b = almanac.Builder.init(buf, base_phys);

    // The DSDT is placed before the FADT so its physical address is known when
    // the FADT's DSDT and X_DSDT fields are written. The DSDT is referenced
    // only by the FADT and is never listed in the XSDT (ACPI rule).
    //
    // Body = s5_aml ++ emitSystemBus(virtio)? ++ emitTpmScope(control)?
    // When neither virtio nor tpm, use s5_aml directly (byte-identical).
    const dsdt_phys = dsdt: {
        if (opts.virtio.len == 0 and opts.tpm == null) {
            break :dsdt try b.addTable("DSDT", &s5_aml, 2);
        }
        var body: [512]u8 = undefined;
        @memcpy(body[0..s5_aml.len], &s5_aml);
        var total = s5_aml.len;
        if (opts.virtio.len > 0) {
            total += emitSystemBus(body[total..], opts.virtio);
        }
        if (opts.tpm) |t| {
            total += emitTpmScope(body[total..], @intCast(t.control));
        }
        std.debug.assert(total <= body.len);
        break :dsdt try b.addTable("DSDT", body[0..total], 2);
    };

    // Build the FADT body by hand because almanac's fadt() helper does not set
    // the sleep-control/status registers.
    var fadt_bytes: [fadt_size]u8 = @splat(0);

    // SDT header (36 bytes): signature, length, revision, checksum (0 for now),
    // OEM id, OEM table id, OEM revision, creator id, creator revision.
    @memcpy(fadt_bytes[0..4], "FACP");
    std.mem.writeInt(u32, fadt_bytes[4..8], fadt_size, .little);
    fadt_bytes[8] = 6; // ACPI revision 6
    fadt_bytes[9] = 0; // checksum placeholder

    // These OEM / creator values mirror almanac.Builder's defaults so read-back agrees, a coupling.
    @memcpy(fadt_bytes[10..16], "MIDSTL");
    @memcpy(fadt_bytes[16..24], "ALMANAC ");
    std.mem.writeInt(u32, fadt_bytes[24..28], 1, .little);
    @memcpy(fadt_bytes[28..32], "ALMA");
    std.mem.writeInt(u32, fadt_bytes[32..36], 1, .little);

    // DSDT (32-bit, offset 40) and X_DSDT (64-bit, offset 140) point at the
    // DSDT placed above.
    std.mem.writeInt(u32, fadt_bytes[40..44], @truncate(dsdt_phys), .little);
    std.mem.writeInt(u64, fadt_bytes[140..148], dsdt_phys, .little);

    // Flags at offset 112: set HW_REDUCED_ACPI.
    std.mem.writeInt(u32, fadt_bytes[112..116], flag_hw_reduced, .little);

    // Minor version at offset 131 = 1 (ACPI 6.1+).
    fadt_bytes[131] = 1;

    // Sleep-control GAS at offset 244, sleep-status GAS at offset 256.
    writeGas(&fadt_bytes, sleep_control_off, sleep_port);
    writeGas(&fadt_bytes, sleep_status_off, sleep_port);

    // Stamp the checksum into byte 9 (the SDT header checksum slot).
    fadt_bytes[9] = almanac.checksum.compute(&fadt_bytes);

    const fadt_phys = try b.addRaw(&fadt_bytes);

    // Build the MADT body into a stack buffer sized for the cpu count. The
    // xAPIC id is one byte, so 256 is the ceiling; cpus is VMM config, so a
    // caller past it is a programmer error, caught here before the body is
    // sized and before the per-cpu loop narrows each id to a u8.
    const madt_max_cpus: u32 = 256;
    std.debug.assert(opts.cpus <= madt_max_cpus);
    const madt_max_body = @sizeOf(MadtHeader) + madt_max_cpus * @sizeOf(LocalApicEntry) + @sizeOf(IoApicEntry);
    var madt_body_buf: [madt_max_body]u8 = @splat(0);
    const madt_body = madt_body_buf[0..madtBodyLen(opts.cpus)];
    writeMadtBody(madt_body, opts.cpus);
    const madt_phys = try b.addTable("APIC", madt_body, 4);

    // Build the XSDT entry list. Max 3: FADT, MADT, and optionally TPM2.
    var xsdt_entries: [3]u64 = undefined;
    var n: usize = 0;
    xsdt_entries[n] = fadt_phys;
    n += 1;
    xsdt_entries[n] = madt_phys;
    n += 1;
    if (opts.tpm) |t| {
        // The TPM2 table, hand-built to the TCG2 layout the kernel reads the event log from: the log
        // fields sit at offset 64 (after a 12-byte start-method area), for a 76-byte table. almanac's
        // tpm2() places them at 52, which the kernel's tpm_read_log_acpi does not read.
        var tpm2_bytes: [76]u8 = @splat(0);
        @memcpy(tpm2_bytes[0..4], "TPM2");
        std.mem.writeInt(u32, tpm2_bytes[4..8], 76, .little);
        tpm2_bytes[8] = 4; // revision
        @memcpy(tpm2_bytes[10..16], "MIDSTL");
        @memcpy(tpm2_bytes[16..24], "ALMANAC ");
        std.mem.writeInt(u32, tpm2_bytes[24..28], 1, .little);
        @memcpy(tpm2_bytes[28..32], "ALMA");
        std.mem.writeInt(u32, tpm2_bytes[32..36], 1, .little);
        std.mem.writeInt(u64, tpm2_bytes[40..48], t.control, .little); // control address
        std.mem.writeInt(u32, tpm2_bytes[48..52], 6, .little); // start method: TIS
        // 52..64 start-method-specific parameters stay zero for TIS.
        std.mem.writeInt(u32, tpm2_bytes[64..68], t.log_len, .little); // log_area_minimum_length
        std.mem.writeInt(u64, tpm2_bytes[68..76], t.log_addr, .little); // log_area_start_address
        tpm2_bytes[9] = almanac.checksum.compute(&tpm2_bytes);
        const tpm2_phys = try b.addRaw(&tpm2_bytes);
        xsdt_entries[n] = tpm2_phys;
        n += 1;
    }

    const xsdt_phys = try b.xsdt(xsdt_entries[0..n]);
    const rsdp = try b.rsdp(xsdt_phys);

    return .{ .bytes = b.finish(), .rsdp = rsdp };
}

test "the madt describes the cpu and the ioapic" {
    var buf: [4096]u8 align(16) = undefined;
    const base: u64 = 0x80000;
    const built = try build(&buf, base, .{ .cpus = 1 });
    const Tables = almanac.TablesGeneric(almanac.OffsetMapper);
    const offset: u64 = @intFromPtr(&buf) -% base;
    const tabs = try Tables.init(.{ .offset = offset }, built.rsdp);
    const madt = (try tabs.findAs(almanac.Madt)).?;

    try testing.expectEqual(@as(u32, 0xfee00000), madt.localApicAddress());

    var local_apic_count: u32 = 0;
    var io_apic_count: u32 = 0;
    var io_apic_address: u32 = 0;
    var it = madt.iterator();
    while (try it.next()) |entry| {
        switch (entry) {
            .local_apic => local_apic_count += 1,
            .io_apic => |ia| {
                io_apic_count += 1;
                io_apic_address = ia.address;
            },
            else => {},
        }
    }
    try testing.expectEqual(true, local_apic_count >= 1);
    try testing.expectEqual(@as(u32, 1), io_apic_count);
    try testing.expectEqual(@as(u32, 0xfec00000), io_apic_address);
}

test "the acpi set has a hw-reduced fadt discoverable from the rsdp" {
    var buf: [4096]u8 align(16) = undefined;
    const base: u64 = 0x80000;
    const built = try build(&buf, base, .{});
    const Tables = almanac.TablesGeneric(almanac.OffsetMapper);
    // The OffsetMapper maps phys -> virt by adding the offset. We want:
    //   virt = @intFromPtr(&buf) + (phys - base)
    //        = phys + (@intFromPtr(&buf) - base)
    const offset: u64 = @intFromPtr(&buf) -% base;
    const tabs = try Tables.init(.{ .offset = offset }, built.rsdp);
    try std.testing.expect(tabs.usesXsdt());
    const fadt = (try tabs.findAs(almanac.Fadt)).?;
    try std.testing.expect(fadt.isHwReduced());
}

test "the fadt names the sleep port" {
    var buf: [4096]u8 align(16) = undefined;
    const base: u64 = 0x80000;
    const built = try build(&buf, base, .{});

    const Tables = almanac.TablesGeneric(almanac.OffsetMapper);
    const offset: u64 = @intFromPtr(&buf) -% base;
    const tabs = try Tables.init(.{ .offset = offset }, built.rsdp);
    const fadt = (try tabs.findAs(almanac.Fadt)).?;

    // SLEEP_CONTROL_REG is at FADT byte offset 244.
    const gas_bytes = fadt.bytes[sleep_control_off .. sleep_control_off + @sizeOf(almanac.Gas)];
    const g = almanac.Gas.fromBytes(gas_bytes);
    try testing.expectEqual(@as(u8, 1), g.address_space); // SystemIO
    try testing.expectEqual(sleep_port, @as(u16, @intCast(g.address)));
}

test "the dsdt carries an s5 package the fadt points at" {
    var buf: [4096]u8 align(16) = undefined;
    const base: u64 = 0x80000;
    const built = try build(&buf, base, .{});

    const Tables = almanac.TablesGeneric(almanac.OffsetMapper);
    const offset: u64 = @intFromPtr(&buf) -% base;
    const tabs = try Tables.init(.{ .offset = offset }, built.rsdp);

    // The FADT must point at a non-zero DSDT address.
    const fadt = (try tabs.findAs(almanac.Fadt)).?;
    const dsdt_addr = fadt.preferredDsdt();
    try std.testing.expect(dsdt_addr != 0);

    // Read the DSDT bytes via the offset mapper and spot-check the _S5 AML.
    // The DSDT begins with a 36-byte SDT header; the AML body follows.
    const dsdt_total = 36 + s5_aml.len;
    const dsdt_bytes = (almanac.OffsetMapper{ .offset = offset }).slice(dsdt_addr, dsdt_total);
    // Verify signature "DSDT" in the header.
    try std.testing.expect(std.mem.eql(u8, dsdt_bytes[0..4], "DSDT"));
    // The AML body starts at byte 36. Spot-check: NameOp, "_S5_", PackageOp,
    // PkgLength, and the two SLP_TYP bytes.
    const aml_body = dsdt_bytes[36..];
    try std.testing.expect(aml_body[0] == 0x08); // NameOp
    try std.testing.expect(std.mem.eql(u8, aml_body[1..5], "_S5_")); // NameSeg
    try std.testing.expect(aml_body[5] == 0x12); // PackageOp
    try std.testing.expect(aml_body[6] == 0x06); // PkgLength = 6
    try std.testing.expect(aml_body[8] == almanac.aml.encoding.byte_prefix); // SLP_TYPa prefix
    try std.testing.expect(aml_body[9] == s5_slp_typ); // SLP_TYPa = 5
    try std.testing.expect(aml_body[10] == almanac.aml.encoding.byte_prefix); // SLP_TYPb prefix
    try std.testing.expect(aml_body[11] == s5_slp_typ); // SLP_TYPb = 5
}

test "an aml device object decodes back to its resources" {
    const dev = VirtioDevice{ .addr = 0xd0000200, .size = 0x200, .gsi = 17 };
    var buf: [256]u8 = undefined;
    const len = emitSystemBus(&buf, &.{dev});

    // Scan the emitted bytes for the Device opcode (5B 82) to locate VR00.
    const aml = buf[0..len];
    var device_off: ?usize = null;
    var i: usize = 0;
    while (i + 1 < aml.len) : (i += 1) {
        if (aml[i] == 0x5B and aml[i + 1] == 0x82) {
            device_off = i;
            break;
        }
    }
    try std.testing.expect(device_off != null);

    // After 5B 82 + PkgLength(1 byte for <0x40) comes the NameSeg "VR00".
    const dev_start = device_off.?;
    const pkg = try almanac.aml.encoding.pkgLength(aml[dev_start + 2 ..]);
    const nameseg_off = dev_start + 2 + pkg.byte_count;
    try std.testing.expect(std.mem.eql(u8, aml[nameseg_off .. nameseg_off + 4], "VR00"));

    // Walk the Device body to find _HID and _UID values.
    const body_start = nameseg_off + 4;
    const device_end = dev_start + 2 + pkg.value;

    var body_pos = body_start;
    var found_hid = false;
    var found_uid = false;
    var crs_resource_bytes: []const u8 = &.{};

    while (body_pos < device_end) {
        if (aml[body_pos] != 0x08) break; // only Name() objects expected here
        const name_bytes = aml[body_pos + 1 ..];
        const ns = try almanac.aml.encoding.nameString(name_bytes);
        const value_off = body_pos + 1 + ns.byte_count;

        if (ns.segments.len == 1 and std.mem.eql(u8, &ns.segments[0], "_HID")) {
            // StringPrefix (0D) + "LNRO0005" + NUL
            try std.testing.expect(aml[value_off] == 0x0D);
            const str_end = std.mem.indexOfScalarPos(u8, aml, value_off + 1, 0).?;
            try std.testing.expect(std.mem.eql(u8, aml[value_off + 1 .. str_end], "LNRO0005"));
            found_hid = true;
            body_pos = str_end + 1;
        } else if (ns.segments.len == 1 and std.mem.eql(u8, &ns.segments[0], "_UID")) {
            // BytePrefix + n
            try std.testing.expect(aml[value_off] == almanac.aml.encoding.byte_prefix);
            try testing.expectEqual(@as(u8, 0), aml[value_off + 1]);
            found_uid = true;
            body_pos = value_off + 2;
        } else if (ns.segments.len == 1 and std.mem.eql(u8, &ns.segments[0], "_CRS")) {
            // BufferOp(0x11) + PkgLength + BufferSize + resource bytes.
            const buf_op_off = value_off;
            try std.testing.expect(aml[buf_op_off] == 0x11);
            const buf_pkg = try almanac.aml.encoding.pkgLength(aml[buf_op_off + 1 ..]);
            // Skip BufferOp(1) + PkgLength + BufferSize(BytePrefix + byte = 2).
            const res_off = buf_op_off + 1 + buf_pkg.byte_count + 2;
            const crs_end = buf_op_off + 1 + buf_pkg.value;
            crs_resource_bytes = aml[res_off..crs_end];
            body_pos = crs_end;
        } else {
            break;
        }
    }

    try std.testing.expect(found_hid);
    try std.testing.expect(found_uid);
    try std.testing.expect(crs_resource_bytes.len > 0);

    // Decode the _CRS resources with almanac's resource.Iterator.
    var res_it = almanac.resource.iterate(crs_resource_bytes);
    const r0 = (try res_it.next()).?;
    try std.testing.expect(r0 == .fixed_memory32);
    try testing.expectEqual(@as(u32, 0xd0000200), r0.fixed_memory32.base);
    try testing.expectEqual(@as(u32, 0x200), r0.fixed_memory32.length);

    const r1 = (try res_it.next()).?;
    try std.testing.expect(r1 == .extended_irq);
    try testing.expectEqual(@as(usize, 1), r1.extended_irq.interrupts.len);
    try testing.expectEqual(@as(u32, 17), r1.extended_irq.interrupts[0]);

    try std.testing.expect((try res_it.next()) == null); // EndTag terminates
}

test "the dsdt carries a virtio-mmio device when one is given" {
    var buf: [4096]u8 align(16) = undefined;
    const base: u64 = 0x80000;

    // Assert that empty virtio yields a DSDT body length equal to s5_aml.len.
    const empty_built = try build(&buf, base, .{});
    const Tables = almanac.TablesGeneric(almanac.OffsetMapper);
    const offset: u64 = @intFromPtr(&buf) -% base;
    {
        const tabs = try Tables.init(.{ .offset = offset }, empty_built.rsdp);
        const fadt = (try tabs.findAs(almanac.Fadt)).?;
        const dsdt_addr = fadt.preferredDsdt();
        const dsdt_bytes = (almanac.OffsetMapper{ .offset = offset }).slice(dsdt_addr, 36 + s5_aml.len + 1);
        const body_len = std.mem.readInt(u32, dsdt_bytes[4..8], .little) - 36;
        try testing.expectEqual(@as(u32, s5_aml.len), body_len);
    }

    // Build with one virtio device.
    const dev = VirtioDevice{ .addr = 0xd0000200, .size = 0x200, .gsi = 17 };
    const built = try build(&buf, base, .{ .virtio = &.{dev} });
    const tabs = try Tables.init(.{ .offset = offset }, built.rsdp);
    const fadt = (try tabs.findAs(almanac.Fadt)).?;
    const dsdt_addr = fadt.preferredDsdt();
    try std.testing.expect(dsdt_addr != 0);

    // Read the DSDT: SDT header length field tells us total size.
    const dsdt_hdr = (almanac.OffsetMapper{ .offset = offset }).slice(dsdt_addr, 36);
    const dsdt_total: usize = std.mem.readInt(u32, dsdt_hdr[4..8], .little);
    const dsdt_bytes = (almanac.OffsetMapper{ .offset = offset }).slice(dsdt_addr, dsdt_total);
    const aml_body = dsdt_bytes[36..];

    // Locate the VR00 device object in the AML body.
    var device_off: ?usize = null;
    var i: usize = 0;
    while (i + 1 < aml_body.len) : (i += 1) {
        if (aml_body[i] == 0x5B and aml_body[i + 1] == 0x82) {
            device_off = i;
            break;
        }
    }
    try std.testing.expect(device_off != null);

    const dev_start = device_off.?;
    const pkg = try almanac.aml.encoding.pkgLength(aml_body[dev_start + 2 ..]);
    const nameseg_off = dev_start + 2 + pkg.byte_count;
    try std.testing.expect(std.mem.eql(u8, aml_body[nameseg_off .. nameseg_off + 4], "VR00"));

    const body_start = nameseg_off + 4;
    const device_end = dev_start + 2 + pkg.value;
    var body_pos = body_start;
    var found_hid = false;
    var crs_resource_bytes: []const u8 = &.{};

    while (body_pos < device_end) {
        if (aml_body[body_pos] != 0x08) break;
        const name_bytes = aml_body[body_pos + 1 ..];
        const ns = try almanac.aml.encoding.nameString(name_bytes);
        const value_off = body_pos + 1 + ns.byte_count;

        if (ns.segments.len == 1 and std.mem.eql(u8, &ns.segments[0], "_HID")) {
            try std.testing.expect(aml_body[value_off] == 0x0D);
            const str_end = std.mem.indexOfScalarPos(u8, aml_body, value_off + 1, 0).?;
            try std.testing.expect(std.mem.eql(u8, aml_body[value_off + 1 .. str_end], "LNRO0005"));
            found_hid = true;
            body_pos = str_end + 1;
        } else if (ns.segments.len == 1 and std.mem.eql(u8, &ns.segments[0], "_UID")) {
            body_pos = value_off + 2;
        } else if (ns.segments.len == 1 and std.mem.eql(u8, &ns.segments[0], "_CRS")) {
            const buf_op_off = value_off;
            try std.testing.expect(aml_body[buf_op_off] == 0x11);
            const buf_pkg = try almanac.aml.encoding.pkgLength(aml_body[buf_op_off + 1 ..]);
            const res_off = buf_op_off + 1 + buf_pkg.byte_count + 2;
            const crs_end = buf_op_off + 1 + buf_pkg.value;
            crs_resource_bytes = aml_body[res_off..crs_end];
            body_pos = crs_end;
        } else {
            break;
        }
    }

    try std.testing.expect(found_hid);
    try std.testing.expect(crs_resource_bytes.len > 0);

    var res_it = almanac.resource.iterate(crs_resource_bytes);
    const r0 = (try res_it.next()).?;
    try std.testing.expect(r0 == .fixed_memory32);
    try testing.expectEqual(@as(u32, 0xd0000200), r0.fixed_memory32.base);
    try testing.expectEqual(@as(u32, 0x200), r0.fixed_memory32.length);

    const r1 = (try res_it.next()).?;
    try std.testing.expect(r1 == .extended_irq);
    try testing.expectEqual(@as(usize, 1), r1.extended_irq.interrupts.len);
    try testing.expectEqual(@as(u32, 17), r1.extended_irq.interrupts[0]);

    try std.testing.expect((try res_it.next()) == null);
}

test "the acpi set carries a tpm2 table when a tpm is given" {
    var buf: [4096]u8 align(16) = undefined;
    const base: u64 = 0x80000;
    const Tables = almanac.TablesGeneric(almanac.OffsetMapper);
    const offset: u64 = @intFromPtr(&buf) -% base;

    // Build with a TPM. Verify the TPM2 table is present and fields match.
    const built = try build(&buf, base, .{
        .tpm = .{ .control = 0xfed4_0000, .log_addr = 0x90000, .log_len = 0x1000 },
    });
    const tabs = try Tables.init(.{ .offset = offset }, built.rsdp);
    const tpm2 = (try tabs.findAs(almanac.Tpm2)).?;
    try testing.expectEqual(@as(u64, 0xfed4_0000), tpm2.controlAddress());
    try testing.expectEqual(almanac.tables.tpm2.StartMethod.tis, tpm2.startMethod());
    // The log fields sit at the TCG2 offsets the kernel reads (64 and 68), not almanac's 52/56, so
    // they are read straight from the table bytes. The table is 76 bytes for exactly this reason.
    try testing.expectEqual(@as(u32, 76), std.mem.readInt(u32, tpm2.bytes[4..8], .little));
    try testing.expectEqual(@as(u32, 0x1000), std.mem.readInt(u32, tpm2.bytes[64..68], .little));
    try testing.expectEqual(@as(u64, 0x90000), std.mem.readInt(u64, tpm2.bytes[68..76], .little));

    // Build without a TPM. Verify no TPM2 table in the set.
    const built_no_tpm = try build(&buf, base, .{});
    const tabs_no_tpm = try Tables.init(.{ .offset = offset }, built_no_tpm.rsdp);
    try testing.expectEqual(@as(?almanac.Tpm2, null), try tabs_no_tpm.findAs(almanac.Tpm2));
}

test "the dsdt names the tpm as an msft0101 device" {
    var buf: [4096]u8 align(16) = undefined;
    const base: u64 = 0x80000;
    const Tables = almanac.TablesGeneric(almanac.OffsetMapper);
    const offset: u64 = @intFromPtr(&buf) -% base;

    // Build with tpm only (no virtio). Decode DSDT and find MSFT0101 device.
    const built = try build(&buf, base, .{
        .tpm = .{ .control = 0xfed4_0000 },
    });
    {
        const tabs = try Tables.init(.{ .offset = offset }, built.rsdp);
        const fadt = (try tabs.findAs(almanac.Fadt)).?;
        const dsdt_addr = fadt.preferredDsdt();
        const dsdt_hdr = (almanac.OffsetMapper{ .offset = offset }).slice(dsdt_addr, 36);
        const dsdt_total: usize = std.mem.readInt(u32, dsdt_hdr[4..8], .little);
        const dsdt_bytes = (almanac.OffsetMapper{ .offset = offset }).slice(dsdt_addr, dsdt_total);
        const aml_body = dsdt_bytes[36..];

        // Find the TPM0 Device (5B 82) in the AML body.
        var device_off: ?usize = null;
        var i: usize = 0;
        while (i + 1 < aml_body.len) : (i += 1) {
            if (aml_body[i] == 0x5B and aml_body[i + 1] == 0x82) {
                device_off = i;
                break;
            }
        }
        try std.testing.expect(device_off != null);

        const dev_start = device_off.?;
        const pkg = try almanac.aml.encoding.pkgLength(aml_body[dev_start + 2 ..]);
        const nameseg_off = dev_start + 2 + pkg.byte_count;
        try std.testing.expect(std.mem.eql(u8, aml_body[nameseg_off .. nameseg_off + 4], "TPM0"));

        const body_start = nameseg_off + 4;
        const device_end = dev_start + 2 + pkg.value;
        var body_pos = body_start;
        var found_hid = false;
        var crs_resource_bytes: []const u8 = &.{};

        while (body_pos < device_end) {
            if (aml_body[body_pos] != 0x08) break;
            const name_bytes = aml_body[body_pos + 1 ..];
            const ns = try almanac.aml.encoding.nameString(name_bytes);
            const value_off = body_pos + 1 + ns.byte_count;

            if (ns.segments.len == 1 and std.mem.eql(u8, &ns.segments[0], "_HID")) {
                try std.testing.expect(aml_body[value_off] == 0x0D);
                const str_end = std.mem.indexOfScalarPos(u8, aml_body, value_off + 1, 0).?;
                try std.testing.expect(std.mem.eql(u8, aml_body[value_off + 1 .. str_end], "MSFT0101"));
                found_hid = true;
                body_pos = str_end + 1;
            } else if (ns.segments.len == 1 and std.mem.eql(u8, &ns.segments[0], "_CRS")) {
                const buf_op_off = value_off;
                try std.testing.expect(aml_body[buf_op_off] == 0x11);
                const buf_pkg = try almanac.aml.encoding.pkgLength(aml_body[buf_op_off + 1 ..]);
                const res_off = buf_op_off + 1 + buf_pkg.byte_count + 2;
                const crs_end = buf_op_off + 1 + buf_pkg.value;
                crs_resource_bytes = aml_body[res_off..crs_end];
                body_pos = crs_end;
            } else {
                break;
            }
        }

        try std.testing.expect(found_hid);
        try std.testing.expect(crs_resource_bytes.len > 0);

        // _CRS must have Memory32Fixed(base=0xfed40000, len=0x5000) and nothing else.
        var res_it = almanac.resource.iterate(crs_resource_bytes);
        const r0 = (try res_it.next()).?;
        try std.testing.expect(r0 == .fixed_memory32);
        try testing.expectEqual(@as(u32, 0xfed4_0000), r0.fixed_memory32.base);
        try testing.expectEqual(@as(u32, 0x5000), r0.fixed_memory32.length);
        try std.testing.expect((try res_it.next()) == null); // no interrupt
    }

    // Build with both virtio and tpm: both devices must decode.
    const dev = VirtioDevice{ .addr = 0xd0000200, .size = 0x200, .gsi = 17 };
    const built2 = try build(&buf, base, .{
        .virtio = &.{dev},
        .tpm = .{ .control = 0xfed4_0000 },
    });
    {
        const tabs = try Tables.init(.{ .offset = offset }, built2.rsdp);
        const fadt = (try tabs.findAs(almanac.Fadt)).?;
        const dsdt_addr = fadt.preferredDsdt();
        const dsdt_hdr = (almanac.OffsetMapper{ .offset = offset }).slice(dsdt_addr, 36);
        const dsdt_total: usize = std.mem.readInt(u32, dsdt_hdr[4..8], .little);
        const dsdt_bytes = (almanac.OffsetMapper{ .offset = offset }).slice(dsdt_addr, dsdt_total);
        const aml_body = dsdt_bytes[36..];

        var found_lnro = false;
        var found_msft = false;
        var i: usize = 0;
        while (i + 1 < aml_body.len) : (i += 1) {
            if (aml_body[i] != 0x5B or aml_body[i + 1] != 0x82) continue;
            const pkg = try almanac.aml.encoding.pkgLength(aml_body[i + 2 ..]);
            const ns_off = i + 2 + pkg.byte_count;
            const body_start = ns_off + 4;
            const device_end = i + 2 + pkg.value;
            var bp = body_start;
            while (bp < device_end) {
                if (aml_body[bp] != 0x08) break;
                const ns = try almanac.aml.encoding.nameString(aml_body[bp + 1 ..]);
                const val_off = bp + 1 + ns.byte_count;
                if (ns.segments.len == 1 and std.mem.eql(u8, &ns.segments[0], "_HID")) {
                    if (aml_body[val_off] == 0x0D) {
                        const str_end = std.mem.indexOfScalarPos(u8, aml_body, val_off + 1, 0).?;
                        const hid_str = aml_body[val_off + 1 .. str_end];
                        if (std.mem.eql(u8, hid_str, "LNRO0005")) found_lnro = true;
                        if (std.mem.eql(u8, hid_str, "MSFT0101")) found_msft = true;
                    }
                    break;
                }
                bp += 1;
            }
            i += 1;
        }
        try std.testing.expect(found_lnro);
        try std.testing.expect(found_msft);
    }

    // Build with neither: DSDT body == s5_aml exactly.
    const built3 = try build(&buf, base, .{});
    {
        const tabs = try Tables.init(.{ .offset = offset }, built3.rsdp);
        const fadt = (try tabs.findAs(almanac.Fadt)).?;
        const dsdt_addr = fadt.preferredDsdt();
        const dsdt_bytes = (almanac.OffsetMapper{ .offset = offset }).slice(dsdt_addr, 36 + s5_aml.len);
        const body_len = std.mem.readInt(u32, dsdt_bytes[4..8], .little) - 36;
        try testing.expectEqual(@as(u32, s5_aml.len), body_len);
    }
}

test {
    _ = almanac;
}
