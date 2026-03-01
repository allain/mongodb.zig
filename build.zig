const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    _ = b.addModule("mongodb", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    // Tests — runs all tests with kcov coverage against a real MongoDB instance
    // via docker compose. Report output: coverage/index.html
    //   zig build test  (requires docker)
    const test_step = b.step("test", "Run tests with coverage (requires docker)");
    if (b.findProgram(&.{"docker"}, &.{})) |_| {} else |_| {
        test_step.dependOn(&b.addFail("docker is required for tests. Install Docker to proceed.").step);
        return;
    }
    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
        .use_llvm = true,
        .use_lld = true,
    });
    const test_compose = ComposeStep.create(b, .{
        .compose_file = b.path("docker-compose.test.yml"),
        .test_bin = tests.getEmittedBin(),
    });
    test_step.dependOn(&test_compose.step);
}

/// Custom build step that runs a test binary with kcov coverage inside a docker
/// compose service and always tears down containers afterward, even on failure.
/// Coverage output accumulates in coverage/ across runs — kcov maintains its own
/// index showing each run with a timestamped title.
const ComposeStep = struct {
    step: std.Build.Step,
    compose_file: std.Build.LazyPath,
    test_bin: std.Build.LazyPath,

    const Options = struct {
        compose_file: std.Build.LazyPath,
        test_bin: std.Build.LazyPath,
    };

    fn create(b: *std.Build, options: Options) *ComposeStep {
        const self = b.allocator.create(ComposeStep) catch @panic("OOM");
        self.* = .{
            .step = std.Build.Step.init(.{
                .id = .custom,
                .name = "docker compose test",
                .owner = b,
                .makeFn = make,
            }),
            .compose_file = options.compose_file,
            .test_bin = options.test_bin,
        };
        self.compose_file.addStepDependencies(&self.step);
        self.test_bin.addStepDependencies(&self.step);
        return self;
    }

    fn make(step: *std.Build.Step, _: std.Build.Step.MakeOptions) anyerror!void {
        const self: *ComposeStep = @fieldParentPtr("step", step);
        const b = step.owner;
        const io = b.graph.io;

        const compose_path = self.compose_file.getPath2(b, step);
        const bin_path = self.test_bin.getPath2(b, step);
        const container_bin = b.fmt("/workspace/{s}", .{bin_path});
        const user_flag = b.fmt("{d}:{d}", .{ std.os.linux.getuid(), std.os.linux.getgid() });
        const title = getTimestamp(io);

        const test_ok = exec(io, &.{
            "docker",       "compose",  "-f",     compose_path,
            "run",          "--rm",     "-v",     ".:/workspace",
            "--user",       user_flag,
            "coverage-runner",
            "kcov",
            b.fmt("--replace-src-path={s}:/workspace", .{
                b.build_root.path orelse ".",
            }),
            "--include-path=/workspace/src",
            b.fmt("--configure=command-name={s}", .{title}),
            "/workspace/coverage",
            container_bin,
        }, b);

        // Always tear down, regardless of test result
        _ = exec(io, &.{
            "docker", "compose", "-f", compose_path,
            "down", "--remove-orphans",
        }, b);

        if (!test_ok) {
            return step.fail("docker compose test failed", .{});
        }
    }

    fn getTimestamp(io: std.Io) []const u8 {
        const now = std.Io.Timestamp.now(io, .real);
        const secs: u64 = @intCast(now.toSeconds());
        const epoch = std.time.epoch.EpochSeconds{ .secs = secs };
        const day = epoch.getEpochDay().calculateYearDay();
        const month_day = day.calculateMonthDay();
        const day_secs = epoch.getDaySeconds();

        var buf: [19]u8 = undefined;
        _ = std.fmt.bufPrint(&buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}", .{
            day.year,
            @intFromEnum(month_day.month),
            month_day.day_index + 1,
            day_secs.getHoursIntoDay(),
            day_secs.getMinutesIntoHour(),
            day_secs.getSecondsIntoMinute(),
        }) catch unreachable;

        return std.heap.page_allocator.dupe(u8, &buf) catch @panic("OOM");
    }

    fn exec(io: std.Io, argv: []const []const u8, b: *std.Build) bool {
        var child = std.process.spawn(io, .{
            .argv = argv,
            .cwd = .{ .path = b.build_root.path orelse "." },
        }) catch return false;
        const term = child.wait(io) catch return false;
        return switch (term) {
            .exited => |code| code == 0,
            else => false,
        };
    }
};
