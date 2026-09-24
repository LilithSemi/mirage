const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Mirage is meant to run as a UEFI application one day, which makes it a type 1
    // hypervisor. That stays possible only while the portable modules build with no
    // operating system under them, and `zig build -Dtarget=<arch>-freestanding` is
    // the check.
    //
    // It has to be a test build. Zig does not analyse the body of a function that
    // nothing calls, so a module that opens a file compiles clean as an object for a
    // target that has no files. It also has to stop before the linker: linking a
    // freestanding aarch64 test binary does not terminate under Zig 0.16, with LLD or
    // without it, and a binary nothing will ever run is not worth producing anyway.
    const has_os = target.result.os.tag != .freestanding;

    const dtree = b.dependency("dtree", .{
        .target = target,
        .optimize = optimize,
        .@"no-tests" = true,
        .@"no-docs" = true,
    }).module("dtree");

    // Which kernel the gates boot and how many cpus they give the guest. Declared once: a word a
    // caller says has one meaning, and asking for it twice is a mistake this build would not survive.
    const kernel_path = b.option([]const u8, "kernel", "Kernel image for the boot gates") orelse
        "/run/current-system/kernel";
    const cpus = b.option(u32, "cpus", "How many cpus the guest has") orelse 1;
    const share_on = b.option(bool, "share", "Offer the guest a directory to mount") orelse false;

    const test_step = b.step("test", "Run all tests");

    const mirage_testing = b.addModule("mirage-testing", .{
        .root_source_file = b.path("lib/mirage-testing.zig"),
        .target = target,
        .optimize = optimize,
    });

    var add = Adder{
        .b = b,
        .target = target,
        .optimize = optimize,
        .has_os = has_os,
        .test_step = test_step,
        .mirage_testing = mirage_testing,
    };

    const attest = add.lib("mirage-attest", &.{});
    const memory = add.lib("mirage-memory", &.{});
    const device = add.lib("mirage-device", &.{.{ .name = "mirage-memory", .module = memory }});
    const image = add.lib("mirage-image", &.{});
    const net = add.lib("mirage-net", &.{});
    const arm64 = add.lib("mirage-arm64", &.{
        .{ .name = "dtree", .module = dtree },
        .{ .name = "mirage-device", .module = device },
    });
    const backend = add.lib("mirage-backend", &.{
        .{ .name = "mirage-memory", .module = memory },
        .{ .name = "mirage-device", .module = device },
        .{ .name = "mirage-arm64", .module = arm64 },
    });
    const core = add.lib("mirage-core", &.{
        .{ .name = "mirage-backend", .module = backend },
        .{ .name = "mirage-memory", .module = memory },
        .{ .name = "mirage-device", .module = device },
        .{ .name = "mirage-arm64", .module = arm64 },
        .{ .name = "mirage-attest", .module = attest },
    });
    if (target.result.os.tag == .macos) {
        const mac_options = b.addOptions();
        mac_options.addOption([]const u8, "kernel_path", kernel_path);
        mac_options.addOption([]const u8, "rootfs", "initramfs");
        // A program answering the chip's commands, if the Mac running this has one. Empty means the
        // guest gets no chip: a chip whose commands nobody answers makes the guest's driver wait out
        // its own timeouts, which stalls the boot for minutes and proves nothing.
        const mac_chip = b.option([]const u8, "mac-tpm", "Socket of a program answering chip commands") orelse "";
        mac_options.addOption([]const u8, "chip_socket", mac_chip);
        // How many CPUs the guest is given. The guest starts the others through the power interface,
        // which this backend answers itself.
        const mac_cpus = b.option(u32, "mac-cpus", "How many cpus the macos guest has") orelse 1;
        mac_options.addOption(u32, "cpus", mac_cpus);

        // The guest for a Mac is the same source, so it needs the same imports. The chain is read
        // inside the guest with the code this side writes it with.
        const mac_guest_target = b.resolveTargetQuery(.{ .cpu_arch = .aarch64, .os_tag = .linux });
        const guest_for_mac = b.addExecutable(.{
            .name = "guest-init-mac",
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/guest/init.zig"),
                .target = mac_guest_target,
                .optimize = .ReleaseSmall,
                .imports = &.{.{ .name = "mirage-attest", .module = b.createModule(.{
                    .root_source_file = b.path("lib/mirage-attest.zig"),
                    .target = mac_guest_target,
                    .optimize = .ReleaseSmall,
                }) }},
            }),
        });
        // Cross compiled here and run on a Mac. Hypervisor.framework is opened at
        // run time, so this needs no macOS SDK.
        const hvf_test = b.addExecutable(.{
            .name = "mirage-hvf-test",
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/hvf.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "mirage-backend", .module = backend },
                    .{ .name = "mirage-arm64", .module = arm64 },
                    .{ .name = "mirage-device", .module = device },
                    .{ .name = "mirage-core", .module = core },
                },
            }),
        });
        b.installArtifact(hvf_test);

        const gic_probe = b.addExecutable(.{
            .name = "mirage-gic-probe",
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/gicprobe.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "mirage-backend", .module = backend },
                    .{ .name = "mirage-arm64", .module = arm64 },
                },
            }),
        });
        b.installArtifact(gic_probe);

        const mac_boot = b.addExecutable(.{
            .name = "mirage-mac-boot",
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/macboot.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "mirage-backend", .module = backend },
                    .{ .name = "mirage-core", .module = core },
                    .{ .name = "mirage-arm64", .module = arm64 },
                    .{ .name = "mirage-device", .module = device },
                    .{ .name = "mirage-image", .module = image },
                    .{ .name = "mirage-net", .module = net },
                    .{ .name = "mirage-memory", .module = memory },
                    .{ .name = "mirage-attest", .module = attest },
                    .{ .name = "guest-init", .module = b.createModule(.{ .root_source_file = guest_for_mac.getEmittedBin() }) },
                    .{ .name = "boot-options", .module = mac_options.createModule() },
                },
            }),
        });
        b.installArtifact(mac_boot);
    }

    // A session is two processes talking over a socket, so unlike the modules above it has an
    // operating system under it by definition and is left out of the freestanding build.
    // A filesystem offered to a guest reads real files, so like a session it has an operating system
    // under it by definition and is left out of the freestanding build.
    const filesystem = if (has_os) add.lib("mirage-fs", &.{}) else undefined;
    const session = if (has_os) add.lib("mirage-session", &.{
        .{ .name = "mirage-device", .module = device },
    }) else undefined;

    // The guest userspace is built by the same `zig build` as everything else,
    // so no archiver and no cross compiler has to exist on the machine.
    // The guest reads its own chain with the same code this side writes it with, so a
    // disagreement is a real disagreement and not two spellings of the same rule.
    const guest_target = b.resolveTargetQuery(.{ .cpu_arch = .aarch64, .os_tag = .linux });
    const guest_attest = b.createModule(.{
        .root_source_file = b.path("lib/mirage-attest.zig"),
        .target = guest_target,
        .optimize = .ReleaseSmall,
    });
    const guest_init = b.addExecutable(.{
        .name = "guest-init",
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/guest/init.zig"),
            .target = guest_target,
            .optimize = .ReleaseSmall,
            .imports = &.{.{ .name = "mirage-attest", .module = guest_attest }},
        }),
    });

    // The runner itself, for whichever hypervisor this system has. Which one that is, is decided
    // inside `src/main.zig` and nowhere else.
    if (has_os) {
        const mirage = b.addExecutable(.{
            .name = "mirage",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/main.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "mirage-backend", .module = backend },
                    .{ .name = "mirage-core", .module = core },
                    .{ .name = "mirage-arm64", .module = arm64 },
                    .{ .name = "mirage-device", .module = device },
                    .{ .name = "mirage-image", .module = image },
                    .{ .name = "mirage-net", .module = net },
                    .{ .name = "mirage-memory", .module = memory },
                    .{ .name = "mirage-attest", .module = attest },
                    .{ .name = "mirage-session", .module = session },
                    .{ .name = "mirage-fs", .module = filesystem },
                },
            }),
        });
        b.installArtifact(mirage);

        // A session as a caller holds it: the runner is a program this starts, so the gate drives
        // the same two processes a harness would rather than a loop of its own.
        const session_options = b.addOptions();
        session_options.addOption([]const u8, "kernel_path", kernel_path);
        // Where the runner is. A gate that runs on this machine finds it where it was installed; one
        // built here and run somewhere else is told, because the path it would find is this machine's.
        const runner_path = b.option([]const u8, "runner", "Where the runner is, for a gate run elsewhere") orelse
            b.getInstallPath(.bin, "mirage");
        session_options.addOption([]const u8, "mirage_path", runner_path);
        // The same option the boot gate uses, so one number covers both. A session with more than one
        // cpu is the interesting case: every cpu runs the loop that pumps the session, and they share it.
        session_options.addOption(u32, "cpus", cpus);
        // Whether the guest is also offered a directory to mount, which is how a harness gives one its
        // tools: the same option the boot gate uses, and the same kernel is needed for it.
        session_options.addOption(bool, "share", share_on);
        const session_module = b.createModule(.{
            .root_source_file = b.path("test/session.zig"),
            .target = target,
            .optimize = optimize,
            // For the environment, which is the C library's on every system this runs on. A gate may
            // share a machine with other people, so where it writes has to be asked for rather than
            // assumed.
            .link_libc = true,
            .imports = &.{
                .{ .name = "mirage-session", .module = session },
                .{ .name = "mirage-image", .module = image },
                .{ .name = "session-options", .module = session_options.createModule() },
            },
        });
        session_module.addAnonymousImport("guest-init", .{
            .root_source_file = guest_init.getEmittedBin(),
        });
        const session_tests = b.addTest(.{ .name = "session", .root_module = session_module });
        const session_gate = b.step("test-session", "Hold a guest up for another program");
        session_gate.dependOn(b.getInstallStep());
        session_gate.dependOn(&b.addRunArtifact(session_tests).step);
    }

    if (has_os and target.result.os.tag == .linux) {
        const rootfs = b.option([]const u8, "rootfs", "initramfs or erofs") orelse "initramfs";
        // The channel needs `AF_VSOCK` built into the kernel rather than left as a
        // module, because the guest has no filesystem to load a module from.
        const vsock = b.option(bool, "vsock", "Give the guest a channel to the test") orelse false;

        const boot_options = b.addOptions();
        boot_options.addOption([]const u8, "kernel_path", kernel_path);
        boot_options.addOption([]const u8, "rootfs", rootfs);
        boot_options.addOption(bool, "vsock", vsock);
        // Checking the root block by block needs the verity target and the command line
        // device builder in the kernel, both of which are modules by default.
        const verity = b.option(bool, "verity", "Check the erofs root against a hash tree") orelse false;
        boot_options.addOption(bool, "verity", verity);
        // Changes one byte of the root after the tree is built over it, so the guest must
        // refuse to mount. A check that is never seen to refuse is a check nobody tested.
        const tampered = b.option(bool, "tampered", "Damage the root so verity has to refuse it") orelse false;
        boot_options.addOption(bool, "tampered", tampered);
        // Gives the guest a balloon and asks it to hold half the memory, so the device is
        // driven by a real driver and not only by a fixture.
        const balloon = b.option(bool, "balloon", "Give the guest a balloon and inflate it") orelse false;
        boot_options.addOption(bool, "balloon", balloon);
        // A helper carries the guest's traffic, so this gate needs one listening. Empty means
        // no network, because a path that is not there is not a thing to guess at.
        const net_socket = b.option([]const u8, "net", "Socket of a network helper such as passt") orelse "";
        boot_options.addOption([]const u8, "net_socket", net_socket);
        // A network of the VMM's own instead of a helper. Needs nothing running beside the test, which
        // is what makes it a gate that can always run, unlike the one that needs passt.
        const nat_on = b.option(bool, "nat", "Give the guest a network of this vmm's own") orelse false;
        boot_options.addOption(bool, "nat", nat_on);
        // Whether the guest is offered a directory on this machine to mount. Needs a kernel with the
        // filesystem driver built in, which the default kernel here does not have.
        boot_options.addOption(bool, "share", share_on);
        // A program on the far end of this socket answers the chip's commands. Empty means the
        // guest gets no chip, because a chip nothing answers is worse than none.
        const chip_socket = b.option([]const u8, "tpm", "Socket of a program answering chip commands") orelse "";
        boot_options.addOption([]const u8, "chip_socket", chip_socket);
        boot_options.addOption(u32, "cpus", cpus);
        // Where a guest is stopped and moved, in exits. Different points leave it with different
        // state in flight, so a snapshot that works at one is not proof it works at all of them.
        const move_after = b.option(usize, "move-after", "Exits before a snapshot is taken") orelse 20_000;
        boot_options.addOption(usize, "move_after", move_after);
        const boot_module = b.createModule(.{
            .root_source_file = b.path("test/boot.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "mirage-core", .module = core },
                .{ .name = "mirage-backend", .module = backend },
                .{ .name = "mirage-device", .module = device },
                .{ .name = "mirage-arm64", .module = arm64 },
                .{ .name = "mirage-memory", .module = memory },
                .{ .name = "mirage-attest", .module = attest },
                .{ .name = "mirage-image", .module = image },
                .{ .name = "mirage-net", .module = net },
                .{ .name = "mirage-fs", .module = filesystem },
                .{ .name = "boot-options", .module = boot_options.createModule() },
            },
        });
        boot_module.addAnonymousImport("guest-init", .{ .root_source_file = guest_init.getEmittedBin() });

        const boot_tests = b.addTest(.{ .name = "boot", .root_module = boot_module });
        b.step("test-boot", "Boot a real kernel under KVM").dependOn(&b.addRunArtifact(boot_tests).step);

        // Stops a guest, moves it to a machine that has never run, and lets it carry on. Its own
        // target because it needs a kernel and because what it proves is separate.
        const snapshot_module = b.createModule(.{
            .root_source_file = b.path("test/snapshot.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "mirage-core", .module = core },
                .{ .name = "mirage-backend", .module = backend },
                .{ .name = "mirage-device", .module = device },
                .{ .name = "mirage-arm64", .module = arm64 },
                .{ .name = "mirage-memory", .module = memory },
                .{ .name = "mirage-attest", .module = attest },
                .{ .name = "mirage-image", .module = image },
                .{ .name = "boot-options", .module = boot_options.createModule() },
            },
        });
        snapshot_module.addAnonymousImport("guest-init", .{
            .root_source_file = guest_init.getEmittedBin(),
        });
        const snapshot_tests = b.addTest(.{ .name = "snapshot", .root_module = snapshot_module });
        b.step("test-snapshot", "Move a running guest to another machine")
            .dependOn(&b.addRunArtifact(snapshot_tests).step);
    }
}

/// Each library is published without its test support, and is tested through a second
/// module with the same root that also imports `mirage-testing`. A consumer of
/// `mirage-attest` must not inherit a dependency that only its tests need.
const Adder = struct {
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    has_os: bool,
    test_step: *std.Build.Step,
    mirage_testing: *std.Build.Module,

    fn lib(self: *Adder, name: []const u8, imports: []const std.Build.Module.Import) *std.Build.Module {
        const b = self.b;
        const root = b.path(b.fmt("lib/{s}.zig", .{name}));

        const module = b.addModule(name, .{
            .root_source_file = root,
            .target = self.target,
            .optimize = self.optimize,
            .imports = imports,
        });

        const test_imports = b.allocator.alloc(std.Build.Module.Import, imports.len + 1) catch @panic("OOM");
        @memcpy(test_imports[0..imports.len], imports);
        test_imports[imports.len] = .{ .name = "mirage-testing", .module = self.mirage_testing };

        const tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = root,
                .target = self.target,
                .optimize = self.optimize,
                .imports = test_imports,
            }),
        });

        if (self.has_os) {
            const run = b.addRunArtifact(tests);
            // Zig knows whether it can execute a binary for this target. Let it
            // decide, and keep the analysis that building the test binary already did.
            run.skip_foreign_checks = true;
            self.test_step.dependOn(&run.step);
        } else {
            // `-fno-emit-bin`. The analysis is the check.
            tests.generated_bin = null;
            self.test_step.dependOn(&tests.step);
        }

        b.default_step.dependOn(&tests.step);
        return module;
    }
};
