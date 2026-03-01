# Changelog

## 0.2.0

### Changed

- Replaced shell scripts (`integration-test.sh`, `coverage.sh`) with a cross-platform custom build step in `build.zig` — no bash dependency, Windows-compatible
- Unified `zig build test`, `zig build integration-test`, and `zig build coverage` into a single `zig build test` that runs all tests against a real MongoDB instance with kcov coverage
- Test infrastructure uses Docker Compose with an internal network — no host port binding, so port conflicts are impossible
- MongoDB is only reachable from the test container, not exposed to the host
- Coverage runs use the `kcov/kcov` Docker image instead of requiring a host kcov install
- Coverage output accumulates across runs in `coverage/`, with each run labeled by timestamp via `--configure=command-name`
- Coverage output files are owned by the invoking user, not root
- Containers are always torn down after tests, even on failure
- Removed `--use-llvm` build option (LLVM backend is always used since kcov requires it)
- Removed the spin lock in connection handling, replaced with `std.Io.Mutex`

### Fixed

- Replaced Linux-specific code (`std.posix`, `std.os.linux`) with cross-platform `std.Io` equivalents throughout the codebase

## 0.1.1

### Changed

- Replaced Linux-specific networking and I/O with `std.Io` cross-platform abstractions
- Improved client code test coverage

### Added

- BSON types: binary, datetime, timestamp, regex, javascript, decimal128, min/max key, undefined, symbol, db_pointer, code_with_scope

## 0.1.0

- Initial release
- CRUD operations: `findOne`, `find`, `insertMany`, `replaceOne`, `deleteOne`, `findOneAndDelete`
- Aggregation pipelines and index creation
- SCRAM-SHA-256 authentication
- BSON encoding/decoding via `std.json.ObjectMap`
- Automatic cursor iteration with `getMore`
- Configurable connection retries with exponential backoff
