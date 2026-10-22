//! Stage-1 address translation.
//!
//! The guest's own page tables are walked here, and the result is a physical
//! address, which is the only thing `GuestMemory` is indexed by. Nothing about
//! this is known to the translator: a translated block forms a virtual address
//! and the run loop turns it into a physical one, because a block is cached by
//! its instructions and cannot be re-chosen by what those instructions will do.
//!
//! What is modelled is the 48-bit virtual address space `arm64 defconfig` uses:
//! a 4KB granule with 2MB and 1GB blocks, which is what that kernel builds. The
//! 16KB and 64KB granules fall out of the same walk with a different shift. The
//! 52-bit form needs `LPA`, which does not exist at EL1, so it is not here.
const std = @import("std");
const GuestMemory = @import("mirage-memory").GuestMemory;
const Cpu = @import("Cpu.zig");

const Translate = @This();

/// What an access is. It decides between the two execute-forbidden bits: an
/// instruction fetch may not run code where `PXN` forbids it and may not where
/// `UXN` forbids it, and the two are separately settable.
pub const Access = enum { read, write, execute };

/// What went wrong, reported rather than guessed at. A guest that cannot tell a
/// missing mapping from a permission problem cannot fix either, and Linux reads
/// `ESR_EL1` to decide what to do about it.
pub const Fault = error{
    TranslationFault,
    PermissionFault,
    /// A table was malformed in a way the architecture reserves, so following
    /// it would be reading something that is not a table.
    MalformedTables,
};

/// The translation regime in force, read out of the control registers once per
/// access rather than field by field, which is what keeps the walk readable.
const Regime = struct {
    /// False when `SCTLR_EL1.M` is clear, in which case every address is its own
    /// translation and no walk happens at all.
    enabled: bool,
    /// The virtual address bit that selects the upper root. An address at or
    /// above `2^(64 - T1SZ)` is in the upper region, so this is that bit. It is
    /// `T1SZ` and not `T0SZ` that decides: the two roots describe different
    /// sized regions, and the smaller one is where the split falls. Linux leaves
    /// the kernel in the low half and user in the high one, which is why the
    /// two sizes differ at all. Wide enough to hold 64 because that is what a
    /// size of zero describes, though `regime` refuses that case.
    split_bit: u7,
};

/// The physical address size `TCR_EL1.IPS` names.
fn input_bits(ips: u3) u8 {
    return switch (ips) {
        0 => 32,
        1 => 36,
        2 => 40,
        3 => 42,
        4 => 48,
        5 => 52,
        else => 56,
    };
}

/// The granule size a `TG0` field names, as the shift that divides an address by
/// one. The encoding is 4KB, then 64KB, then 16KB, which is not the order of
/// the sizes. Field 3 is reserved and is a zero here, which `walk` refuses rather
/// than mapping it onto something.
const granule_for_tg0 = [_]u6{ 12, 16, 14, 0 };

/// The same for `TG1`, which numbers the sizes differently: 16KB, 4KB and 64KB in
/// that order, with 0 reserved. Reading one field with the other's table makes a
/// kernel's 4KB upper half look like 16KB, and every walk of it then indexes
/// the wrong bits.
const granule_for_tg1 = [_]u6{ 0, 14, 12, 16 };

/// Where each field of `TCR_EL1` sits. `T1SZ` is six bits at 16, and `TG1` is
/// nowhere near it: it is at 31:30, so reading a granule from the low bits of
/// `T1SZ` gets a size the guest never asked for.
const fields = struct {
    const t0sz_shift: u6 = 0;
    const t1sz_shift: u6 = 16;
    const tg0_shift: u6 = 14;
    const tg1_shift: u6 = 30;
    const eps_shift: u6 = 23;
    const epd1_shift: u6 = 23;
    const epd0_shift: u6 = 7;
    const ips_shift: u6 = 32;
};

/// The physical size an address is truncated to, which a page table naming a
/// larger physical address is not allowed to widen.
pub fn physical_bits(cpu: *const Cpu) Fault!u8 {
    if (!try enabled(cpu)) return 64;
    return input_bits(@as(u3, @truncate(cpu.system.tcr_el1 >> fields.ips_shift)));
}

fn enabled(cpu: *const Cpu) Fault!bool {
    // SCTLR_EL1.M is bit 0. Until the guest sets it, addresses are physical.
    if ((cpu.system.sctlr_el1 & 1) == 0) return false;
    const tcr = cpu.system.tcr_el1;
    // A region of zero bytes is what a zero `T0SZ` describes, and it is
    // reserved rather than a whole-address-space region.
    if (@as(u6, @truncate(tcr)) == 0) return error.MalformedTables;
    // `TG0` and `TG1` are checked where the region they describe is walked: an upper
    // half that is disabled has no size to be wrong about.
    return true;
}

fn regime(cpu: *const Cpu) Fault!Regime {
    if (!try enabled(cpu)) return .{ .enabled = false, .split_bit = 0 };
    // Six bits, 21:16. Bit 22 above it is `A1`, which selects which root holds the
    // ASID and has nothing to do with the size: reading seven bits made a kernel
    // that sets it look like it had asked for a region of a negative size.
    const t1sz: u6 = @truncate(cpu.system.tcr_el1 >> fields.t1sz_shift);
    if (t1sz == 0) return error.MalformedTables;
    return .{
        .enabled = true,
        .split_bit = @intCast(@as(u8, 64) - t1sz),
    };
}

/// One remembered translation. The address is kept whole rather than as a page
/// number, because a wrong hit here is a wrong memory access rather than a
/// wrong value, and because the page size is not known until the walk has run.
pub const Entry = struct {
    /// Zero means the slot is empty, which no real virtual address is.
    virtual: u64 = 0,
    physical: u64 = 0,
    /// The generation this was translated under, so a changed page table base or
    /// address size cannot be answered from an entry made under the old one.
    generation: u64 = 0,
    /// What the descriptor said about access, checked again on a hit: making a
    /// page read-only and keeping the entry would let the write through.
    ap: u2 = 0,
    executable: bool = false,
    /// True when the entry records a fault, so that an address in no table is
    /// not walked again on every access to it.
    faulted: bool = false,
};

/// A small direct-mapped cache of translations. A walk is up to four dependent
/// memory reads, and a translated block is about to do a great many more, so
/// this is most of the reason the two designs fit together.
pub const Tlb = struct {
    entries: [256]Entry = @splat(.{}),
    /// Bumped whenever the translation regime may have changed. An entry from an
    /// older generation never matches, which makes a flush one addition rather
    /// than a sweep of the array.
    generation: u64 = 1,

    pub fn flush(self: *Tlb) void {
        self.generation +%= 1;
        // Wrapping would let an entry from a very old regime match again, so on
        // the way back to the start the array is cleared instead. Failing that
        // way is the safe one: a missed entry is walked again, a wrong one is a
        // wrong memory access.
        if (self.generation <= 1) self.entries = @splat(.{});
    }

    fn slot(virtual: u64) usize {
        return @as(usize, @truncate(virtual >> 12)) & (256 - 1);
    }

    fn find(self: *const Tlb, virtual: u64) ?*const Entry {
        const entry = &self.entries[slot(virtual)];
        if (entry.generation != self.generation) return null;
        if (entry.virtual != virtual) return null;
        return entry;
    }
};

/// What a walk found: the physical address, and enough of the descriptor to
/// enforce the same permissions on a later hit.
const Mapped = struct {
    physical: u64,
    ap: u2,
    executable: bool,
};

/// Translate one virtual address. A fault is returned rather than a sentinel, so
/// that a failed walk cannot be mistaken for a mapping of address zero.
pub fn translate(
    tlb: *Tlb,
    cpu: *const Cpu,
    memory: *GuestMemory,
    virtual: u64,
    access: Access,
) Fault!u64 {
    const cfg = try regime(cpu);
    if (!cfg.enabled) return virtual;
    // A 48-bit space has the top sixteen bits as a sign extension of bit 55. An
    // address that disagrees with that is not addressable, rather than
    // untranslated.
    if ((virtual >> 55 & 1) != 0) {
        if (virtual >> 48 != 0xffff) return error.TranslationFault;
    } else if (virtual >> 48 != 0) {
        return error.TranslationFault;
    }

    if (tlb.find(virtual)) |entry| {
        if (entry.faulted) return error.TranslationFault;
        try permitted(entry.ap, entry.executable, access);
        return entry.physical;
    }

    const found = walk(cpu, memory, virtual, access, cfg) catch |fault_kind| {
        // An address in no table would otherwise be walked again on the next
        // access, which for a faulting instruction stream is every instruction.
        // Only faults that do not depend on the kind of access are remembered:
        // a page that refuses execution is a real page, and remembering that as
        // a fault would go on refusing the reads that are perfectly allowed.
        if (fault_kind != error.PermissionFault) {
            tlb.entries[Tlb.slot(virtual)] = .{ .virtual = virtual, .generation = tlb.generation, .faulted = true };
        }
        return fault_kind;
    };
    tlb.entries[Tlb.slot(virtual)] = .{
        .virtual = virtual,
        .physical = found.physical,
        .generation = tlb.generation,
        .ap = found.ap,
        .executable = found.executable,
    };
    return found.physical;
}

/// The access flag, bit 10 of a block or page descriptor.
const accessed: u64 = 1 << 10;

/// Whether this access is the first one to the page, as far as the access flag
/// is concerned. A read of a read-only page is not: the architecture lets it
/// through without the flag being set, because there is nothing to fault on and
/// nothing to remember.
fn needsAccessFlag(ap: u2, access: Access) bool {
    // AP[2] is the high bit of the field, bit 7 of the descriptor, and it is what
    // makes the page read-only. Bit 6, AP[1], says only whether EL0 may use it.
    return !(access == .read and ap & 0b10 != 0);
}

/// Set the access flag in a descriptor the walk has just read, so that a later
/// walk finds it already set. A hardware walker does this in the hardware; here
/// it is a write to guest memory, and a guest that made its own page tables
/// read-only cannot be written to. That is left as it is rather than faulting,
/// because the access itself has already been allowed and faulting now would
/// make the page unreachable rather than merely unrecorded.
fn markAccessed(memory: *GuestMemory, at: u64, entry: u64) void {
    const updated = entry | accessed;
    memory.write(at, std.mem.asBytes(&updated)) catch {};
}

/// Whether the descriptor's permission fields allow this access. `ap` is the
/// descriptor's AP[2:1] at bits 7:6, and the two bits mean different things: the
/// high one, AP[2], makes the page read-only, and the low one, AP[1], makes it
/// reachable from EL0. So `00` is read-write at EL1 only, `01` read-write from both,
/// `10` read-only at EL1 only and `11` read-only from both. This walk is made at EL1
/// and there is no privileged-access-never, which the guest is not told exists, so
/// EL1 may read anything and may write what is not read-only. A kernel maps its own
/// code and constants `10`, so refusing them a read would refuse it its own text.
fn permitted(ap: u2, executable: bool, access: Access) Fault!void {
    switch (access) {
        .read => {},
        .write => if (ap & 0b10 != 0) return error.PermissionFault,
        .execute => if (!executable) return error.PermissionFault,
    }
}

/// The walk. The root is always the level 3 table, and each level's index is the
/// nine bits of the address above what that level covers, so one loop handles the
/// whole space for every granule.
fn walk(
    cpu: *const Cpu,
    memory: *GuestMemory,
    virtual: u64,
    access: Access,
    cfg: Regime,
) Fault!Mapped {
    // Which root an address belongs to is decided by the bit just above the
    // lower region, so that bit and everything above it is the upper half.
    const upper = (virtual >> @as(u6, @truncate(cfg.split_bit))) & 1 != 0;
    // `EPD1` says a miss belonging to the upper root is a fault with no walk at
    // all. Following the tables anyway would translate an address the guest has
    // said must not be translated.
    if (upper and (cpu.system.tcr_el1 & (@as(u64, 1) << fields.epd1_shift)) != 0) {
        return error.TranslationFault;
    }
    const granule = if (upper)
        granule_for_tg1[@as(u2, @truncate(cpu.system.tcr_el1 >> fields.tg1_shift))]
    else
        granule_for_tg0[@as(u2, @truncate(cpu.system.tcr_el1 >> fields.tg0_shift))];
    if (granule == 0) return error.MalformedTables; // the reserved encoding
    const root = if (upper) cpu.system.ttbr1_el1 else cpu.system.ttbr0_el1;

    var table = root & ~@as(u64, 0xfff);
    var level: i8 = 3;
    while (level >= 0) : (level -= 1) {
        // The index is the address above what this level covers, which is the
        // granule widened by one step for each level beneath the root. For a
        // 4KB granule the leaves are therefore 4KB, 2MB and 1GB.
        const shift: u6 = granule + @as(u6, @intCast(9 * @as(u8, @intCast(level))));
        const index = (virtual >> shift) & 0x1ff;
        var word: [8]u8 = undefined;
        memory.read(table +% (index * 8), &word) catch return error.TranslationFault;
        const entry = std.mem.readInt(u64, &word, .little);

        // Bits 1:0 are the type, and what they mean depends on the level. At the last
        // level `0b11` is a page and `0b01` is reserved. At the levels above it `0b11`
        // is a pointer to the next table and `0b01` is a block, except at the root of
        // a 4 KiB granule, where a block would be 512 GiB and is not allowed. An
        // all-zero entry, which is what an absent mapping looks like, is invalid at
        // every level, and so is anything else.
        const kind = entry & 3;
        const last = level == 0;
        const top_level = level == 3;
        if (kind == 0b11 and !last) {
            // Bits 9:4 of a table descriptor are reserved, and a nonzero one means this
            // is not the table the architecture describes, so following it would walk
            // nonsense.
            if (entry & 0x0000_03f0 != 0) return error.MalformedTables;
            table = entry & 0x0000_ffff_f000;
            continue;
        }
        const leaf = (kind == 0b11 and last) or (kind == 0b01 and !last and !top_level);
        if (!leaf) return error.TranslationFault;

        // The output address is bits 47:12, and the rest of the descriptor is
        // permission and attribute. Clearing the low bits of the field to the size
        // this level maps is what turns a 2MB or 1GB block into a base rather than
        // a page.
        const output = entry & 0x0000_ffff_f000 & ~((@as(u64, 1) << shift) - 1);
        const found = Mapped{
            .physical = output | (virtual & ((@as(u64, 1) << shift) - 1)),
            .ap = @truncate(entry >> 6),
            // PXN is bit 53, and this walk is at EL1, which is the level that bit
            // governs. UXN at bit 54 is not consulted: it is the EL0 half of the same
            // question, and nothing here runs at EL0.
            .executable = (entry & (@as(u64, 1) << 53)) == 0,
        };
        try permitted(found.ap, found.executable, access);
        // The access flag records that the page has been touched. A hardware walker
        // sets it on the first access and lets that access through, so a guest that
        // allocated a page without setting it is not punished for it.
        if (entry & accessed == 0 and needsAccessFlag(found.ap, access)) {
            markAccessed(memory, table +% (index * 8), entry);
        }
        return found;
    }
    return error.TranslationFault;
}
