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

    // Coverage via kcov (requires kcov, docker)
    //   zig build coverage
    //   Report output: coverage/index.html
    const cov_step = b.step("coverage", "Run tests with kcov code coverage");
    if (b.findProgram(&.{"kcov"}, &.{})) |_| {} else |_| {
        cov_step.dependOn(&b.addFail("kcov is required for coverage. Install with: apt install kcov").step);
        return;
    }
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
        "sh", "-c",
        \\CONTAINER=$(docker run --rm -d -p 27099:27017 -e MONGO_INITDB_ROOT_USERNAME=testuser -e MONGO_INITDB_ROOT_PASSWORD=testpass mongo:7)
        \\trap "docker stop $CONTAINER >/dev/null 2>&1" EXIT
        \\echo "Waiting for MongoDB..."
        \\for i in $(seq 1 30); do
        \\  docker exec "$CONTAINER" mongosh --quiet -u testuser -p testpass --eval "db.runCommand({ping:1})" >/dev/null 2>&1 && break
        \\  [ "$i" -eq 30 ] && echo "MongoDB failed to start" >&2 && exit 1
        \\  sleep 1
        \\done
        \\echo "MongoDB ready"
        \\COV_DIR="coverage/$(date +%Y%m%d-%H%M%S)"
        \\MONGO_URI="mongodb://testuser:testpass@localhost:27099/zig_mongo_test?authSource=admin" kcov --include-path=src "$COV_DIR" "$1"
        \\echo "Coverage report: $COV_DIR/index.html"
    , "_",
    });
    cov_run.addArtifactArg(cov_tests);
    cov_run.has_side_effects = true;
    cov_step.dependOn(&cov_run.step);
}
