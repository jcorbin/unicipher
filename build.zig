const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const exe = b.addExecutable("unicipher", "unicipher.zig");
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.install();

    const exe_tests = b.addTest("unicipher.zig");
    exe_tests.setTarget(target);
    exe_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&exe_tests.step);

    const enc_cmd = exe.run();
    enc_cmd.step.dependOn(b.getInstallStep());
    enc_cmd.addArgs(&[_][]const u8{"encrypt"});

    const enc_step = b.step("run-enc", "Run unicipher encrypt");
    enc_step.dependOn(&enc_cmd.step);

    const dec_cmd = exe.run();
    dec_cmd.step.dependOn(b.getInstallStep());
    dec_cmd.addArgs(&[_][]const u8{"decrypt"});

    const dec_step = b.step("run-dec", "Run unicipher decrypt");
    dec_step.dependOn(&dec_cmd.step);
}
