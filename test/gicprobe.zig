const std = @import("std");
const backend = @import("mirage-backend");
const arm64 = @import("mirage-arm64");

const ram = 0x4000_0000;
const uart = 0x0900_0000;

fn say(comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const line = std.fmt.bufPrint(&buf, fmt ++ "\n", args) catch return;
    _ = std.c.write(1, line.ptr, line.len);
}

pub fn main() void {
    var machine = backend.hvf.Machine.create(std.heap.smp_allocator, 1) catch |e| {
        say("no hypervisor: {t}", .{e});
        std.process.exit(1);
    };
    defer machine.deinit();

    const memory = std.posix.mmap(null, 1 << 20, .{ .READ = true, .WRITE = true }, .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0) catch unreachable;
    machine.map(memory, ram) catch unreachable;

    // Read the processor feature register, then try to read the GIC CPU interface
    // register. Whether the second one traps, faults, or reads decides how an
    // interrupt controller can be built here at all.
    const code = [_]u32{
        0xd5380400, // mrs  x0, ID_AA64PFR0_EL1
        0xd2a12001, // movz x1, #0x0900, lsl #16
        0xb9000020, // str  w0, [x1]
        0xd538cca0, // mrs  x0, ICC_SRE_EL1
        0xb9000020, // str  w0, [x1]
        0x14000000, // b    .
    };
    @memcpy(memory[0..@sizeOf(@TypeOf(code))], std.mem.sliceAsBytes(code[0..]));

    const hv = machine.backend();
    const id = hv.addVcpu() catch unreachable;
    hv.setRegister(id, .pc, ram) catch unreachable;

    for (0..2) |step| {
        const exit = hv.run(id) catch |e| {
            const raw = machine.vcpus[id].exit;
            say("step {d}: {t}, reason {d}, class 0x{x}, syndrome 0x{x}", .{
                step,                                    e,                      @intFromEnum(raw.reason),
                arm64.esr.class(raw.exception.syndrome), raw.exception.syndrome,
            });
            return;
        };
        switch (exit) {
            .mmio_write => |w| {
                if (step == 0) {
                    const gic: u4 = @truncate(w.value >> 24);
                    say("ID_AA64PFR0_EL1 = 0x{x}, GIC field = {d} ({s})", .{
                        w.value,                                                                           gic,
                        if (gic == 0) "NO system register GIC interface" else "GIC CPU interface present",
                    });
                } else {
                    say("ICC_SRE_EL1 read back as 0x{x}", .{w.value});
                }
            },
            else => |other| say("step {d}: unexpected {t}", .{ step, other }),
        }
    }
}
