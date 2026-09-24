//! The hypervisor a virtual machine runs on.
//!
//! KVM and Hypervisor.framework both implement one interface, so the device model
//! above never learns which one is under it. Only this module's platform directories
//! know that an operating system exists.

const builtin = @import("builtin");

pub const Backend = @import("mirage-backend/Backend.zig");
pub const Exit = Backend.Exit;

pub const hvf = switch (builtin.os.tag) {
    .macos => @import("mirage-backend/darwin/hvf.zig"),
    else => void,
};

pub const kvm = switch (builtin.os.tag) {
    .linux => struct {
        pub const ioctl = @import("mirage-backend/linux/kvm/ioctl.zig");
        pub const probe = @import("mirage-backend/linux/kvm/probe.zig");
        pub const Vm = @import("mirage-backend/linux/kvm/Vm.zig");
        pub const Vcpu = @import("mirage-backend/linux/kvm/Vcpu.zig");
        pub const Machine = @import("mirage-backend/linux/kvm/Machine.zig");
        pub const Gic = @import("mirage-backend/linux/kvm/Gic.zig");
    },
    else => void,
};

test {
    _ = Backend;
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
        _ = kvm.Gic;
    }
}
