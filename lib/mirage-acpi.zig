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

const Emitter = almanac.aml.Emitter;

/// Every system description table starts with the same 36 byte header, which the builder writes.
const sdt_header_size: usize = 36;

/// Room reserved for the DSDT's AML before any of it is written. The length is not known until it
/// has been, and `endTable` gives back whatever was not used, so this only has to be generous.
const dsdt_room: usize = 512;

/// The register window a TIS chip answers on, and the start method that names it.
const tis_size: u32 = 0x5000;
const tis_start_method: u32 = 6;

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

/// A virtio-mmio device to encode as an ACPI Device object in the DSDT.
pub const VirtioDevice = struct {
    addr: u64,
    size: u32,
    gsi: u32,
};

/// The resources a `_CRS` carries, encoded into an AML buffer object.
///
/// The buffer's size is written before its contents, so the descriptors go into scratch first to
/// learn their length. `almanac.resource.encode` lays each one out, which is what keeps the tag
/// bytes and the little endian widths in one place rather than in this file.
fn emitCrs(aml: *Emitter, resources: []const almanac.resource.Resource) !void {
    var scratch: [64]u8 = undefined;
    var used: usize = 0;
    for (resources) |each| used += try almanac.resource.encode(scratch[used..], each);
    used += try almanac.resource.encodeEndTag(scratch[used..]);

    const frame = try aml.beginNameBuffer("_CRS", used);
    try aml.raw(scratch[0..used]);
    try aml.end(frame);
}

/// `Device(VRnn){ _HID "LNRO0005"; _UID nn; _CRS ... }`.
fn emitDevice(aml: *Emitter, index: u8, dev: VirtioDevice) !void {
    std.debug.assert(index < 100);
    std.debug.assert(dev.addr <= 0xFFFF_FFFF);

    var path: [4]u8 = undefined;
    const named = std.fmt.bufPrint(&path, "VR{d:0>2}", .{index}) catch unreachable;

    const frame = try aml.beginDevice(named);
    try aml.name("_HID", .{ .text = "LNRO0005" });
    try aml.name("_UID", .{ .integer = index });

    // Held in a local because the descriptor borrows it rather than copying.
    const interrupts = [_]u32{dev.gsi};
    try emitCrs(aml, &.{
        .{ .fixed_memory32 = .{ .info = 1, .base = @intCast(dev.addr), .length = dev.size } },
        .{ .extended_irq = .{ .flags = 1, .interrupts = &interrupts, .source = "" } },
    });
    try aml.end(frame);
}

/// `Scope(\_SB_){ <one Device per dev> }`.
pub fn emitSystemBus(aml: *Emitter, devs: []const VirtioDevice) !void {
    const frame = try aml.beginScope("\\_SB_");
    for (devs, 0..) |dev, i| try emitDevice(aml, @intCast(i), dev);
    try aml.end(frame);
}

/// `Scope(\_SB_){ Device(TPM0){ _HID "MSFT0101"; _CRS ... } }`.
///
/// No `_UID`, and the resources are the control area alone: a TIS chip has no interrupt here.
pub fn emitTpmScope(aml: *Emitter, control: u32) !void {
    const scope = try aml.beginScope("\\_SB_");
    const device = try aml.beginDevice("TPM0");
    try aml.name("_HID", .{ .text = "MSFT0101" });
    try emitCrs(aml, &.{
        .{ .fixed_memory32 = .{ .info = 1, .base = control, .length = tis_size } },
    });
    try aml.end(device);
    try aml.end(scope);
}

/// `Name(_S5, Package(2){ 5, 5 })`, which is what a hardware reduced platform powers off through.
///
/// The two elements are SLP_TYPa and SLP_TYPb.
fn emitSleepState(aml: *Emitter) !void {
    const frame = try aml.beginNamePackage("_S5_", 2);
    try aml.integer(s5_slp_typ);
    try aml.integer(s5_slp_typ);
    try aml.end(frame);
}

/// Build an RSDP, XSDT, hardware-reduced FADT, and DSDT carrying _S5 into
/// `buf` at guest physical address `base_phys`. Returns the bytes written and
/// the RSDP's physical address as the Builder placed it.
/// Write the guest's AML into `into`, and say how long it came out.
///
/// The emitter can fail nine structural ways, all of which mean this module built AML that does not
/// hold together: unbalanced containers, a bad name, a package too long. None of them is a condition
/// a caller can do anything about, so they arrive as one error rather than nine. Running out of room
/// stays its own error, because that one a caller fixes by giving a bigger buffer.
fn emitAml(into: []u8, opts: Options) error{ OutOfSpace, BadAml }!usize {
    var aml = Emitter.init(into);
    const body = emit: {
        emitSleepState(&aml) catch |err| break :emit err;
        if (opts.virtio.len > 0) emitSystemBus(&aml, opts.virtio) catch |err| break :emit err;
        if (opts.tpm) |t| emitTpmScope(&aml, @intCast(t.control)) catch |err| break :emit err;
        break :emit aml.finish();
    } catch |err| switch (err) {
        error.OutOfSpace => return error.OutOfSpace,
        else => return error.BadAml,
    };
    return body.len;
}

pub fn build(buf: []u8, base_phys: u64, opts: Options) !Built {
    var b = almanac.Builder.init(buf, base_phys);

    // The DSDT is placed before the FADT so its address is known when the FADT names it. It is
    // referenced only by the FADT and never listed in the XSDT, which is an ACPI rule.
    //
    // Reserved generously and then cut back, because AML's length is not known until it has been
    // written. `endTable` rewrites the length, stamps the checksum, and hands the unused tail back.
    const dsdt_phys = dsdt: {
        const table = try b.beginTable("DSDT", sdt_header_size + dsdt_room, 2);
        const used = try emitAml(table[sdt_header_size..], opts);
        // `used` came from the slice this reserved, so the length is in range by construction.
        // Mapped rather than asserted, because a panic in a library is the caller's problem.
        break :dsdt b.endTable(table, sdt_header_size + used) catch return error.BadAml;
    };

    // Hardware reduced, so the sleep registers are the only way this guest powers itself off: the
    // PM1 legacy blocks are not there to fall back to.
    const fadt_phys = try b.fadt(.{
        .dsdt_phys = dsdt_phys,
        .hw_reduced = true,
        .sleep_control_reg = .at(.system_io, 8, sleep_port),
        .sleep_status_reg = .at(.system_io, 8, sleep_port),
    });

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
        // Revision 4, which is the layout the kernel reads the event log from: a 76 byte table with
        // the log fields after the start method parameters. Asking for the revision is what selects
        // that, rather than this file knowing the offsets.
        const tpm2_phys = try b.tpm2(.{
            .revision = 4,
            .control_address = t.control,
            .start_method = tis_start_method,
            .log_area_length = t.log_len,
            .log_area_start = t.log_addr,
        });
        xsdt_entries[n] = tpm2_phys;
        n += 1;
    }

    const xsdt_phys = try b.xsdt(xsdt_entries[0..n]);
    const rsdp = try b.rsdp(xsdt_phys);

    return .{ .bytes = b.finish(), .rsdp = rsdp };
}

/// How long the AML is when nothing but the sleep state is in it. `NameOp` and the four byte name,
/// then `PackageOp`, its length and element count, then two one byte elements with their prefixes:
/// 1 + 4 + 1 + 1 + 1 + 4. Asserted by the tests below, so extra AML appearing cannot go unnoticed.
const s5_body_len: u32 = 12;

/// Read an AML integer written in its shortest form, and say how many bytes it took.
///
/// Zero and one have opcodes of their own, so a reader that expects a prefixed byte for every small
/// number is reading an encoding choice rather than a value. Used by the tests below.
fn smallInteger(bytes: []const u8) ?struct { value: u64, len: usize } {
    if (bytes.len == 0) return null;
    return switch (bytes[0]) {
        0x00 => .{ .value = 0, .len = 1 }, // ZeroOp
        0x01 => .{ .value = 1, .len = 1 }, // OneOp
        0xFF => .{ .value = 0xFF, .len = 1 }, // OnesOp
        almanac.aml.encoding.byte_prefix => if (bytes.len >= 2)
            .{ .value = bytes[1], .len = 2 }
        else
            null,
        else => null,
    };
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

    // Read through the accessor rather than at byte 244. A test that reads the offset this file
    // wrote cannot notice the two drifting apart, which is how the same class of bug lived in
    // almanac's TPM2 reader. The accessor gates on the table's length, so too short reads as absent.
    const g = fadt.sleepControlRegister().?;
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
    const dsdt_total = 36 + s5_body_len;
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
    var emitter = Emitter.init(&buf);
    try emitSystemBus(&emitter, &.{dev});
    const aml = try emitter.finish();

    // Scan the emitted bytes for the Device opcode (5B 82) to locate VR00.
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
            // AML writes small integers in their shortest form, so zero is `ZeroOp` and one is
            // `OneOp` rather than a prefixed byte. Read the value rather than the byte, or this
            // asserts an encoding choice instead of the number it stands for.
            const read = smallInteger(aml[value_off..]).?;
            try testing.expectEqual(@as(u64, 0), read.value);
            found_uid = true;
            body_pos = value_off + read.len;
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

    // Assert that empty virtio yields a DSDT body length equal to the sleep state alone.
    const empty_built = try build(&buf, base, .{});
    const Tables = almanac.TablesGeneric(almanac.OffsetMapper);
    const offset: u64 = @intFromPtr(&buf) -% base;
    {
        const tabs = try Tables.init(.{ .offset = offset }, empty_built.rsdp);
        const fadt = (try tabs.findAs(almanac.Fadt)).?;
        const dsdt_addr = fadt.preferredDsdt();
        const dsdt_bytes = (almanac.OffsetMapper{ .offset = offset }).slice(dsdt_addr, 36 + s5_body_len + 1);
        const body_len = std.mem.readInt(u32, dsdt_bytes[4..8], .little) - 36;
        try testing.expectEqual(@as(u32, s5_body_len), body_len);
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
            // Shortest form again, so zero is one byte and not two. Advancing by a fixed two here
            // walked past the next object and the loop gave up before reaching `_CRS`.
            body_pos = value_off + smallInteger(aml_body[value_off..]).?.len;
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

    // Build with neither: DSDT body is the sleep state alone.
    const built3 = try build(&buf, base, .{});
    {
        const tabs = try Tables.init(.{ .offset = offset }, built3.rsdp);
        const fadt = (try tabs.findAs(almanac.Fadt)).?;
        const dsdt_addr = fadt.preferredDsdt();
        const dsdt_bytes = (almanac.OffsetMapper{ .offset = offset }).slice(dsdt_addr, 36 + s5_body_len);
        const body_len = std.mem.readInt(u32, dsdt_bytes[4..8], .little) - 36;
        try testing.expectEqual(@as(u32, s5_body_len), body_len);
    }
}

test {
    _ = almanac;
}
