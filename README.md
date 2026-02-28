# mongodb

A native MongoDB client library for Zig. Connects over the MongoDB wire protocol with SCRAM-SHA-256 authentication, BSON encoding/decoding, and cursor-based iteration.

## Features

- CRUD operations: `findOne`, `find`, `insertMany`, `replaceOne`, `deleteOne`, `findOneAndDelete`
- Aggregation pipelines
- Index creation
- SCRAM-SHA-256 authentication
- Automatic cursor iteration with `getMore`
- BSON encoding and decoding via `std.json.ObjectMap`
- Configurable connection retries with exponential backoff

## Requirements

- Zig 0.16.0-dev or later
- A running MongoDB instance

## Installation

Fetch the package:

```sh
zig fetch --save git+https://codeberg.org/allain/mongodb.zig
```

Then add it to your `build.zig`:

```zig
const mongodb_dep = b.dependency("mongodb", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("mongodb", mongodb_dep.module("mongodb"));
```

## Usage

```zig
const std = @import("std");
const mongodb = @import("mongodb");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    // Set up I/O
    const threaded = try allocator.create(std.Io.Threaded);
    threaded.* = std.Io.Threaded.init(allocator, .{});
    const io = threaded.io();

    // Connect
    const uri = try mongodb.parseUri("mongodb://user:pass@localhost:27017/mydb?authSource=admin");
    const conn = try allocator.create(mongodb.Connection);
    conn.* = try mongodb.Connection.connect(allocator, io, uri, .{});
    defer conn.close();

    // Create client
    var client = mongodb.Client.init(allocator, conn);

    // Insert
    var doc = std.json.ObjectMap.init(allocator);
    defer doc.deinit();
    try doc.put("name", .{ .string = "alice" });
    try doc.put("age", .{ .integer = 30 });
    try client.insertMany(allocator, "users", &.{doc});

    // Find
    var filter = std.json.ObjectMap.init(allocator);
    defer filter.deinit();
    try filter.put("name", .{ .string = "alice" });

    if (try client.findOne(allocator, "users", filter)) |*found| {
        defer mongodb.bson.freeObjectMap(allocator, @constCast(found));
        // Use found document...
    }
}
```

## API

### Connection

```zig
const uri = try mongodb.parseUri("mongodb://user:pass@localhost:27017/mydb");
conn.* = try mongodb.Connection.connect(allocator, io, uri, .{});
conn.* = try mongodb.Connection.connect(allocator, io, uri, .{
    .max_retries = 10,
    .retry_delay_ms = 1000,
    .backoff_ratio = 2,
});
```

### Client Operations

| Method | Description |
|--------|-------------|
| `findOne(allocator, collection, filter)` | Find a single matching document |
| `find(allocator, collection, filter, opts)` | Find multiple documents with sort/limit/skip/projection |
| `insertMany(allocator, collection, docs)` | Insert one or more documents |
| `replaceOne(allocator, collection, filter, replacement, upsert)` | Replace a document |
| `deleteOne(allocator, collection, filter)` | Delete a single document |
| `findOneAndDelete(allocator, collection, filter)` | Atomically find and delete a document |
| `aggregate(allocator, collection, pipeline)` | Run an aggregation pipeline |
| `createIndex(allocator, collection, keys, name)` | Create an index |

### BSON

Documents use `std.json.ObjectMap` and `std.json.Value`. The `bson` namespace provides encoding, decoding, and memory management:

```zig
// Encode an ObjectMap to BSON bytes
const bytes = try mongodb.bson.encode(allocator, doc);
defer allocator.free(bytes);

// Decode BSON bytes back to an ObjectMap
var decoded = try mongodb.bson.decode(allocator, bytes);
defer mongodb.bson.freeObjectMap(allocator, &decoded);
```

## Testing

Run unit tests (no MongoDB required):

```sh
zig build test
```

Run integration tests (requires Docker):

```sh
zig build integration-test
```

Run tests with coverage (requires Docker and kcov):

```sh
zig build coverage
```

## License

MIT
