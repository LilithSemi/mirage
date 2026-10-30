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
    }).module("dtree");

    const almanac = b.dependency("almanac", .{
        .target = target,
        .optimize = optimize,
    }).module("almanac");

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
    const acpi = add.lib("mirage-acpi", &.{
        .{ .name = "almanac", .module = almanac },
        .{ .name = "mirage-memory", .module = memory },
    });
    const device = add.lib("mirage-device", &.{.{ .name = "mirage-memory", .module = memory }});
    const image = add.lib("mirage-image", &.{});
    const net = add.lib("mirage-net", &.{});
    const arm64 = add.lib("mirage-arm64", &.{
        .{ .name = "dtree", .module = dtree },
        .{ .name = "mirage-device", .module = device },
        .{ .name = "mirage-memory", .module = memory },
        .{ .name = "mirage-attest", .module = attest },
    });
    // The x86 arch module is built on every host so its tests run, even while a build
    // for another target does not select it.
    const x86_64 = add.lib("mirage-x86_64", &.{
        .{ .name = "mirage-memory", .module = memory },
        .{ .name = "mirage-attest", .module = attest },
        .{ .name = "mirage-acpi", .module = acpi },
        .{ .name = "almanac", .module = almanac },
    });
    // One architecture, chosen by the target, exposed under the one name the backend and
    // the core name. The concrete modules stay available where a file names an arch.
    const arch = switch (target.result.cpu.arch) {
        .aarch64 => arm64,
        .x86_64 => x86_64,
        else => @panic("mirage supports aarch64 and x86_64 hosts"),
    };
    const backend = add.lib("mirage-backend", &.{
        .{ .name = "mirage-memory", .module = memory },
        .{ .name = "mirage-device", .module = device },
        .{ .name = "mirage-arm64", .module = arm64 },
        .{ .name = "mirage-arch", .module = arch },
    });
    const core = add.lib("mirage-core", &.{
        .{ .name = "mirage-backend", .module = backend },
        .{ .name = "mirage-memory", .module = memory },
        .{ .name = "mirage-device", .module = device },
        .{ .name = "mirage-arm64", .module = arm64 },
        .{ .name = "mirage-arch", .module = arch },
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

    const guest_target_x86 = b.resolveTargetQuery(.{ .cpu_arch = .x86_64, .os_tag = .linux });
    const guest_attest_x86 = b.createModule(.{
        .root_source_file = b.path("lib/mirage-attest.zig"),
        .target = guest_target_x86,
        .optimize = .ReleaseSmall,
    });
    const guest_init_x86 = b.addExecutable(.{
        .name = "guest-init-x86",
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/guest/init.zig"),
            .target = guest_target_x86,
            .optimize = .ReleaseSmall,
            .imports = &.{.{ .name = "mirage-attest", .module = guest_attest_x86 }},
        }),
    });

    // The runner itself, for whichever hypervisor this system has. Which one that is, is decided
    // inside `src/main.zig` and nowhere else.
    if (has_os) {
        // Whoever runs the words of a kernel. Compiling them for this cpu is a compiler's work, so
        // Vulcan does it, and this edge is why the models carry a seam instead of a decoder. Only a
        // hosted build takes it: a build with no operating system under it has no threads to run a
        // warp on and nowhere to map code it compiled.
        const vulcan = b.dependency("vulcan", .{
            .target = target,
            .optimize = optimize,
        });
        const jit = add.lib("mirage-jit", &.{
            .{ .name = "mirage-device", .module = device },
            .{ .name = "mirage-memory", .module = memory },
            .{ .name = "mirage-backend", .module = backend },
            .{ .name = "mirage-arm64", .module = arm64 },
            .{ .name = "vulcan-ir", .module = vulcan.module("vulcan-ir") },
            .{ .name = "vulcan-opt", .module = vulcan.module("vulcan-opt") },
            .{ .name = "vulcan-target", .module = vulcan.module("vulcan-target") },
        });

        const jit_tests = b.addTest(.{ .name = "mirage-jit", .root_module = b.createModule(.{
            .root_source_file = b.path("lib/mirage-jit/aarch64/tests.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "mirage-jit", .module = jit },
                .{ .name = "mirage-testing", .module = mirage_testing },
                .{ .name = "mirage-memory", .module = memory },
                .{ .name = "mirage-backend", .module = backend },
                .{ .name = "mirage-arm64", .module = arm64 },
            },
        }) });
        b.step("test-jit", "Run native AArch64 JIT tests").dependOn(&b.addRunArtifact(jit_tests).step);
        const launch_tests = b.addTest(.{ .name = "mirage-jit-launch", .root_module = b.createModule(.{
            .root_source_file = b.path("test/jit-launch.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "mirage-jit", .module = jit },
                .{ .name = "mirage-core", .module = core },
                .{ .name = "mirage-device", .module = device },
                .{ .name = "mirage-arm64", .module = arm64 },
                .{ .name = "mirage-memory", .module = memory },
            },
        }) });
        b.step("test-jit-launch", "Run JIT guest through the Mirage launch loop").dependOn(&b.addRunArtifact(launch_tests).step);

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
                    .{ .name = "mirage-arch", .module = arch },
                    .{ .name = "mirage-device", .module = device },
                    .{ .name = "mirage-image", .module = image },
                    .{ .name = "mirage-net", .module = net },
                    .{ .name = "mirage-memory", .module = memory },
                    .{ .name = "mirage-attest", .module = attest },
                    .{ .name = "mirage-session", .module = session },
                    .{ .name = "mirage-fs", .module = filesystem },
                    .{ .name = "mirage-jit", .module = jit },
                },
            }),
        });
        b.installArtifact(mirage);

        // What a caller may ask for, held to the same gate as everything else. The runner is a
        // program and not a library, so its own tests need naming here or they never run.
        const option_tests = b.addTest(.{
            .name = "options",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/Options.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{.{ .name = "mirage-device", .module = device }},
            }),
        });
        const run_option_tests = b.addRunArtifact(option_tests);
        // Built for whichever target was asked for, so let Zig decide whether this machine can run
        // the binary. The analysis happened either way.
        run_option_tests.skip_foreign_checks = true;
        test_step.dependOn(&run_option_tests.step);

        // A session as a caller holds it: the runner is a program this starts, so the gate drives
        // the same two processes a harness would rather than a loop of its own.
        const session_options = b.addOptions();
        session_options.addOption([]const u8, "kernel_path", kernel_path);
        // Where the runner is. A gate built here and run on another machine is told, because no path
        // this one can compute means anything there. Otherwise it is the binary this build emits,
        // which brings its own dependency with it: the gate needs no install, and cannot be handed a
        // binary something else installed over the top of.
        if (b.option([]const u8, "runner", "Where the runner is, for a gate run elsewhere")) |given| {
            session_options.addOption([]const u8, "mirage_path", given);
        } else {
            session_options.addOptionPath("mirage_path", mirage.getEmittedBin());
        }
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
        // A pci host bridge with nothing behind it. The guest enumerates an empty bus, which is what
        // says the config window, the two memory windows and the tree all agree. Needs a kernel with
        // the generic host bridge driver built in, which the small kernel here does not have.
        const pci_on = b.option(bool, "pci", "Give the guest a pci host bridge") orelse false;
        boot_options.addOption(bool, "pci", pci_on);
        // And a glacier card behind it, so the guest sizes real regions and firmware places them.
        const glacier_on = b.option(bool, "glacier", "Put a glacier card behind the bridge") orelse false;
        boot_options.addOption(bool, "glacier", glacier_on);
        // And which card, in the same settings the runner takes, so one gate covers any board.
        const glacier_card = b.option([]const u8, "glacier-card", "The card, as --device writes one") orelse "";
        boot_options.addOption([]const u8, "glacier_card", glacier_card);
        // Whether the guest is offered a directory on this machine to mount. Needs a kernel with the
        // filesystem driver built in, which the default kernel here does not have.
        boot_options.addOption(bool, "share", share_on);
        // A program on the far end of this socket answers the chip's commands. Empty means the
        // guest gets no chip, because a chip nothing answers is worse than none.
        const chip_socket = b.option([]const u8, "tpm", "Socket of a program answering chip commands") orelse "";
        boot_options.addOption([]const u8, "chip_socket", chip_socket);
        // Where the x86 tpm gate finds a swtpm binary to spawn. swtpm is not on the default PATH
        // here, so the gate takes its path; the default lets it be found if it is.
        const swtpm = b.option([]const u8, "swtpm", "Path to a swtpm binary for the x86 tpm gate") orelse "swtpm";
        boot_options.addOption([]const u8, "swtpm_path", swtpm);
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

        // The x86 capstone: a real bzImage reaches long mode and prints its banner to the serial port.
        // Its own step so the arm boot gate above stays one kernel and one architecture, and so the
        // main test run does not need an x86 kernel to pass.
        const x86boot_module = b.createModule(.{
            .root_source_file = b.path("test/x86boot.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "mirage-core", .module = core },
                .{ .name = "mirage-backend", .module = backend },
                .{ .name = "mirage-device", .module = device },
                .{ .name = "mirage-acpi", .module = acpi },
                .{ .name = "mirage-arch", .module = arch },
                .{ .name = "mirage-memory", .module = memory },
                .{ .name = "mirage-attest", .module = attest },
                .{ .name = "mirage-image", .module = image },
                .{ .name = "mirage-net", .module = net },
                .{ .name = "mirage-fs", .module = filesystem },
                .{ .name = "boot-options", .module = boot_options.createModule() },
            },
        });
        x86boot_module.addAnonymousImport("guest-init-x86", .{
            .root_source_file = guest_init_x86.getEmittedBin(),
        });
        // Boot to the serial banner only. The capstone test lives in the same file, so this step is
        // filtered to the one test that is the B1 gate and nothing else.
        const x86boot_tests = b.addTest(.{
            .name = "x86boot",
            .root_module = x86boot_module,
            .filters = &.{"serial banner"},
        });

        // The pci gate for this architecture: a guest learns of the bridge from ACPI rather than
        // from a device tree, so this is the one that says those tables are right.
        const x86pci_tests = b.addTest(.{
            .name = "x86pci",
            .root_module = x86boot_module,
            .filters = &.{"enumerates a pci bus"},
        });
        b.step("test-x86pci", "Boot a real x86 kernel and enumerate a pci bus under KVM")
            .dependOn(&b.addRunArtifact(x86pci_tests).step);
        b.step("test-x86boot", "Boot a real x86 kernel to its serial banner under KVM")
            .dependOn(&b.addRunArtifact(x86boot_tests).step);

        // The x86 capstone: a real bzImage unpacks an initramfs, runs an x86 `/init` in userspace,
        // and stops cleanly. Its own step so `zig build test` does not need an x86 kernel.
        const x86userspace_tests = b.addTest(.{
            .name = "x86userspace",
            .root_module = x86boot_module,
            .filters = &.{"userspace"},
        });
        b.step("test-x86userspace", "Boot a real x86 kernel to a guest in userspace under KVM")
            .dependOn(&b.addRunArtifact(x86userspace_tests).step);

        // The x86 vsock capstone: the guest finds a virtio-mmio vsock device through an ACPI DSDT
        // device object, its interrupt is mapped from the _CRS and delivered through the controller
        // line, and the guest exchanges a line over the channel. Needs `-Dkernel=` a kernel with
        // virtio-mmio + vsock built in (an initramfs guest cannot load modules); skips otherwise. Its
        // own step so `zig build test` does not need an x86 kernel.
        const x86vsock_tests = b.addTest(.{
            .name = "x86vsock",
            .root_module = x86boot_module,
            .filters = &.{"vsock"},
        });
        b.step("test-x86vsock", "Boot a real x86 kernel and talk to the guest over vsock under KVM")
            .dependOn(&b.addRunArtifact(x86vsock_tests).step);

        // The x86 block gate: the guest mounts an erofs image as its root over the virtio-mmio block
        // device and reaches userspace from it. Needs `-Dkernel=` a kernel with virtio-mmio + erofs
        // built in; skips otherwise. Its own step so `zig build test` does not need an x86 kernel.
        const x86block_tests = b.addTest(.{
            .name = "x86block",
            .root_module = x86boot_module,
            .filters = &.{"erofs root"},
        });
        b.step("test-x86block", "Boot a real x86 kernel from an erofs root over virtio-mmio under KVM")
            .dependOn(&b.addRunArtifact(x86block_tests).step);

        // The x86 net gate: the guest brings up a virtio-mmio net card and exchanges frames with the
        // VMM's own NAT. Needs `-Dkernel=` a kernel with virtio-mmio + virtio-net built in; skips
        // otherwise. Its own step so `zig build test` does not need an x86 kernel.
        const x86net_tests = b.addTest(.{
            .name = "x86net",
            .root_module = x86boot_module,
            .filters = &.{"reaches a network"},
        });
        b.step("test-x86net", "Boot a real x86 kernel and exchange network frames through the vmm nat under KVM")
            .dependOn(&b.addRunArtifact(x86net_tests).step);

        // The x86 balloon gate: the guest's balloon driver hands pages back to reach the target the
        // gate sets. Needs `-Dkernel=` a kernel with virtio-mmio + virtio-balloon built in; skips
        // otherwise. Its own step so `zig build test` does not need an x86 kernel.
        const x86balloon_tests = b.addTest(.{
            .name = "x86balloon",
            .root_module = x86boot_module,
            .filters = &.{"hands memory back"},
        });
        b.step("test-x86balloon", "Boot a real x86 kernel and inflate a balloon under KVM")
            .dependOn(&b.addRunArtifact(x86balloon_tests).step);

        // The x86 tpm gate: spawn swtpm, measure the launch into a TPM, boot the guest with the TPM
        // (via a TPM2 ACPI table) + vsock, and verify the launch chain the guest reports matches the
        // host's. Needs `-Dkernel=` a kernel with TCG_TIS + virtio-vsock built in and a swtpm binary
        // (-Dswtpm=<path>); skips otherwise. Its own step so `zig build test` needs no x86 kernel.
        const x86tpm_tests = b.addTest(.{
            .name = "x86tpm",
            .root_module = x86boot_module,
            .filters = &.{"launch chain through a tpm"},
        });
        b.step("test-x86tpm", "Boot a real x86 kernel and verify its launch chain through a tpm under KVM")
            .dependOn(&b.addRunArtifact(x86tpm_tests).step);

        // The x86 share gate: the guest mounts a writable virtio-fs share, reads a host file and writes
        // one the host then sees on disk. Needs `-Dkernel=` a kernel with virtio-mmio + FUSE + virtio-fs
        // built in; skips otherwise. Its own step so `zig build test` needs no x86 kernel.
        const x86share_tests = b.addTest(.{
            .name = "x86share",
            .root_module = x86boot_module,
            .filters = &.{"reads and writes a shared"},
        });
        b.step("test-x86share", "Boot a real x86 kernel and read and write a shared host directory under KVM")
            .dependOn(&b.addRunArtifact(x86share_tests).step);

        // The x86 SEV gate: the guest boots with its memory encrypted through the KVM SEV launch flow
        // and reaches userspace over its unencrypted serial port. Runs as the normal user; skips where
        // the host KVM lacks SEV or the launch is refused. Needs `-Dkernel=` a bootable x86 kernel.
        const x86sev_tests = b.addTest(.{
            .name = "x86sev",
            .root_module = x86boot_module,
            .filters = &.{"boots encrypted under sev and"},
        });
        b.step("test-x86sev", "Boot a real x86 kernel with its memory encrypted under SEV through KVM")
            .dependOn(&b.addRunArtifact(x86sev_tests).step);

        // The x86 SEV-ES gate: the guest boots with both its memory and its vCPU VMSA encrypted, reaching
        // userspace over its GHCB-mediated serial. Root only (needs the /dev/sev fd); skips as the
        // normal user. Needs `-Dkernel=` a bootable x86 kernel with AMD_MEM_ENCRYPT.
        const x86seves_tests = b.addTest(.{
            .name = "x86seves",
            .root_module = x86boot_module,
            .filters = &.{"boots encrypted under sev-es"},
        });
        b.step("test-x86seves", "Boot a real x86 kernel with memory and vCPU state encrypted under SEV-ES through KVM")
            .dependOn(&b.addRunArtifact(x86seves_tests).step);

        // The x86 SEV attestation gate: the guest owner establishes transport keys through the
        // platform and verifies the launch measurement under its own TIK. Root only (needs /dev/sev);
        // skips as the normal user. Needs `-Dkernel=` a bootable x86 kernel.
        const x86sevattest_tests = b.addTest(.{
            .name = "x86sevattest",
            .root_module = x86boot_module,
            .filters = &.{"verifies its launch measurement under sev"},
        });
        b.step("test-x86sevattest", "Verify the SEV launch measurement of a real x86 guest through KVM")
            .dependOn(&b.addRunArtifact(x86sevattest_tests).step);

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
            tests.generated_bin = .none;
            self.test_step.dependOn(&tests.step);
        }

        b.default_step.dependOn(&tests.step);
        return module;
    }
};
