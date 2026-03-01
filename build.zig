const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const use_llvm = b.option(bool, "use-llvm", "Use Zig's LLVM backend (needed for kcov coverage)");

    _ = b.addModule("mongodb", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    // Unit tests
    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
        .use_llvm = use_llvm,
        .use_lld = use_llvm,
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // Integration tests — starts Docker mongo, runs all tests (unit + integration)
    //   zig build integration-test  (requires docker)
    const integ_step = b.step("integration-test", "Run integration tests (requires docker)");
    if (b.findProgram(&.{"docker"}, &.{})) |_| {} else |_| {
        integ_step.dependOn(&b.addFail("docker is required for integration tests. Install Docker to proceed.").step);
        return;
    }
    const integ_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
        .use_llvm = use_llvm,
        .use_lld = use_llvm,
    });
    const integ_run = b.addSystemCommand(&.{
        b.path("integration-test.sh").getPath(b),
    });
    integ_run.addArtifactArg(integ_tests);
    integ_run.has_side_effects = true;
    integ_step.dependOn(&integ_run.step);

    // Coverage via kcov (requires docker; kcov is installed inside the container)
    //   zig build coverage
    //   Report output: coverage/index.html
    const cov_step = b.step("coverage", "Run tests with kcov code coverage");
    const cov_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
        .use_llvm = true,
        .use_lld = true,
    });
    const cov_run = b.addSystemCommand(&.{
        b.path("coverage.sh").getPath(b),
    });
    cov_run.addArtifactArg(cov_tests);
    cov_run.has_side_effects = true;
    cov_step.dependOn(&cov_run.step);
}
