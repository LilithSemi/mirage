//! The hypervisor a virtual machine runs on.
//!
//! KVM and Hypervisor.framework both implement one interface, so the device model
//! above never learns which one is under it. Only this module's platform directories
//! know that an operating system exists.

const builtin = @import("builtin");

const generic = @import("mirage-backend/Backend.zig");

/// The backend interface for a guest of the architecture `Guest`, a module such as `mirage-arm64`.
/// What a backend runs is a guest, and a translator runs one the host is not.
pub const For = generic.For;

/// The parts of a backend's vocabulary that are the same for every guest.
pub const shared = generic.shared;

/// The backend for the guest this build's hypervisor runs: a hardware hypervisor can only run a
/// guest of its own architecture.
pub const Backend = For(@import("mirage-arch"));
pub const Exit = Backend.Exit;

pub const hvf = switch (builtin.os.tag) {
    .macos => @import("mirage-backend/darwin/hvf.zig"),
    else => void,
};

/// The interrupt controller the guest is given, chosen by the architecture. A runner names this
/// rather than the GIC, so one runner serves a guest whose controller it builds and one whose
/// controller the kernel already holds. Only a Linux build reaches it; macOS runs its own runner.
pub const platform = switch (builtin.os.tag) {
    .linux => @import("mirage-backend/platform.zig"),
    else => void,
};

pub const kvm = switch (builtin.os.tag) {
    .linux => struct {
        pub const ioctl = @import("mirage-backend/linux/kvm/ioctl.zig");
        pub const probe = @import("mirage-backend/linux/kvm/probe.zig");
        pub const Vm = @import("mirage-backend/linux/kvm/Vm.zig");
        pub const Vcpu = @import("mirage-backend/linux/kvm/Vcpu.zig").Vcpu;
        pub const Machine = @import("mirage-backend/linux/kvm/Machine.zig");
        pub const sev_host = @import("mirage-backend/linux/kvm/sev_host.zig");
        pub const sev_cert = @import("mirage-backend/linux/kvm/sev_cert.zig");
        pub const sev_session = @import("mirage-backend/linux/kvm/sev_session.zig");
        // The interrupt controller is arm's. An x86 build keeps it out so nothing drags
        // in `mirage-arm64`.
        pub const Gic = if (builtin.cpu.arch == .aarch64) @import("mirage-backend/linux/kvm/Gic.zig") else void;
    },
    else => void,
};

test {
    _ = generic;
    if (builtin.os.tag == .macos) {
        _ = hvf.binding;
        _ = hvf.Machine;
    }
    if (builtin.os.tag == .linux) {
        _ = kvm.ioctl;
        _ = kvm.probe;
        _ = kvm.Vm;
        _ = kvm.Vcpu;
        _ = kvm.Machine;
        if (builtin.cpu.arch == .aarch64) _ = kvm.Gic;
        _ = kvm.sev_host;
        _ = kvm.sev_cert;
        _ = kvm.sev_session;
        _ = platform;
    }
}
