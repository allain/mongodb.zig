const std = @import("std");
const json = std.json;
const Value = json.Value;
const ObjectMap = json.ObjectMap;
const Array = json.Array;
const Allocator = std.mem.Allocator;
const bson = @import("bson.zig");
const connection_mod = @import("connection.zig");
const Connection = connection_mod.Connection;
const MongoUri = connection_mod.MongoUri;

pub const FindOpts = struct {
    sort: ?ObjectMap = null,
    limit: i64 = 0,
    skip: i64 = 0,
    projection: ?ObjectMap = null,
    batch_size: i64 = 0,
};

pub const Client = struct {
    conn: *Connection,
    database: []const u8,
    allocator: Allocator,

    pub fn init(allocator: Allocator, conn: *Connection) Client {
        return .{
            .conn = conn,
            .database = conn.uri.database,
            .allocator = allocator,
        };
    }

    /// Find a single document matching the filter.
    pub fn findOne(self: *Client, allocator: Allocator, collection: []const u8, filter: ObjectMap) !?ObjectMap {
        var cmd = ObjectMap.init(allocator);
        defer cmd.deinit();
        try cmd.put("find", .{ .string = collection });
        try cmd.put("filter", .{ .object = filter });
        try cmd.put("limit", .{ .integer = 1 });
        try cmd.put("singleBatch", .{ .bool = true });

        var response = try self.conn.runCommand(allocator, self.database, cmd);
        defer bson.freeObjectMap(allocator, &response);

        // Extract first document from cursor.firstBatch
        const cursor = response.get("cursor") orelse return null;
        switch (cursor) {
            .object => |cursor_obj| {
                const first_batch = cursor_obj.get("firstBatch") orelse return null;
                switch (first_batch) {
                    .array => |arr| {
                        if (arr.items.len == 0) return null;
                        switch (arr.items[0]) {
                            .object => |doc| return try cloneObjectMap(allocator, doc),
                            else => return null,
                        }
                    },
                    else => return null,
                }
            },
            else => return null,
        }
    }

    /// Find multiple documents matching the filter.
    pub fn find(self: *Client, allocator: Allocator, collection: []const u8, filter: ObjectMap, opts: FindOpts) ![]ObjectMap {
        var cmd = ObjectMap.init(allocator);
        defer cmd.deinit();
        try cmd.put("find", .{ .string = collection });
        try cmd.put("filter", .{ .object = filter });

        if (opts.sort) |sort| {
            try cmd.put("sort", .{ .object = sort });
        }
        if (opts.limit > 0) {
            try cmd.put("limit", .{ .integer = opts.limit });
        }
        if (opts.skip > 0) {
            try cmd.put("skip", .{ .integer = opts.skip });
        }
        if (opts.projection) |proj| {
            try cmd.put("projection", .{ .object = proj });
        }
        if (opts.batch_size > 0) {
            try cmd.put("batchSize", .{ .integer = opts.batch_size });
        }

        var response = try self.conn.runCommand(allocator, self.database, cmd);

        // Extract documents from cursor
        return try extractCursorDocs(self, allocator, &response, collection);
    }

    /// Replace a single document, optionally upserting.
    pub fn replaceOne(self: *Client, allocator: Allocator, collection: []const u8, filter: ObjectMap, replacement: ObjectMap, upsert: bool) !void {
        // Build update array with one element
        var update_doc = ObjectMap.init(allocator);
        defer update_doc.deinit();
        try update_doc.put("q", .{ .object = filter });
        try update_doc.put("u", .{ .object = replacement });
        try update_doc.put("upsert", .{ .bool = upsert });

        var updates = Array.init(allocator);
        defer updates.deinit();
        try updates.append(.{ .object = update_doc });

        var cmd = ObjectMap.init(allocator);
        defer cmd.deinit();
        try cmd.put("update", .{ .string = collection });
        try cmd.put("updates", .{ .array = updates });

        var response = try self.conn.runCommand(allocator, self.database, cmd);
        defer bson.freeObjectMap(allocator, &response);
    }

    /// Insert multiple documents.
    pub fn insertMany(self: *Client, allocator: Allocator, collection: []const u8, docs: []const ObjectMap) !void {
        if (docs.len == 0) return;

        // Encode each document as BSON for document sequence
        var doc_bsons: std.ArrayList([]const u8) = .empty;
        defer {
            for (doc_bsons.items) |d| allocator.free(d);
            doc_bsons.deinit(allocator);
        }

        for (docs) |doc| {
            const encoded = try bson.encode(allocator, doc);
            try doc_bsons.append(allocator, encoded);
        }

        var cmd = ObjectMap.init(allocator);
        defer cmd.deinit();
        try cmd.put("insert", .{ .string = collection });

        // Use document sequence for the documents
        var response = try self.conn.runCommandWithSequence(
            allocator,
            self.database,
            cmd,
            "documents",
            doc_bsons.items,
        );
        defer bson.freeObjectMap(allocator, &response);
    }

    /// Find and delete a single document, returning the deleted doc.
    pub fn findOneAndDelete(self: *Client, allocator: Allocator, collection: []const u8, filter: ObjectMap) !?ObjectMap {
        var cmd = ObjectMap.init(allocator);
        defer cmd.deinit();
        try cmd.put("findAndModify", .{ .string = collection });
        try cmd.put("query", .{ .object = filter });
        try cmd.put("remove", .{ .bool = true });

        var response = try self.conn.runCommand(allocator, self.database, cmd);
        defer bson.freeObjectMap(allocator, &response);

        if (response.get("value")) |val| {
            switch (val) {
                .object => |doc| return try cloneObjectMap(allocator, doc),
                .null => return null,
                else => return null,
            }
        }
        return null;
    }

    /// Delete a single document matching the filter.
    pub fn deleteOne(self: *Client, allocator: Allocator, collection: []const u8, filter: ObjectMap) !void {
        var delete_doc = ObjectMap.init(allocator);
        defer delete_doc.deinit();
        try delete_doc.put("q", .{ .object = filter });
        try delete_doc.put("limit", .{ .integer = 1 });

        var deletes = Array.init(allocator);
        defer deletes.deinit();
        try deletes.append(.{ .object = delete_doc });

        var cmd = ObjectMap.init(allocator);
        defer cmd.deinit();
        try cmd.put("delete", .{ .string = collection });
        try cmd.put("deletes", .{ .array = deletes });

        var response = try self.conn.runCommand(allocator, self.database, cmd);
        defer bson.freeObjectMap(allocator, &response);
    }

    /// Run an aggregation pipeline.
    pub fn aggregate(self: *Client, allocator: Allocator, collection: []const u8, pipeline: []const Value) ![]ObjectMap {
        var pipeline_arr = Array.init(allocator);
        defer pipeline_arr.deinit();
        for (pipeline) |stage| {
            try pipeline_arr.append(stage);
        }

        var cmd = ObjectMap.init(allocator);
        defer cmd.deinit();
        try cmd.put("aggregate", .{ .string = collection });
        try cmd.put("pipeline", .{ .array = pipeline_arr });

        // cursor must be present for aggregate
        var cursor_opts = ObjectMap.init(allocator);
        defer cursor_opts.deinit();
        try cmd.put("cursor", .{ .object = cursor_opts });

        var response = try self.conn.runCommand(allocator, self.database, cmd);
        return try extractCursorDocs(self, allocator, &response, collection);
    }

    /// Create an index on a collection.
    pub fn createIndex(self: *Client, allocator: Allocator, collection: []const u8, keys: ObjectMap, name: []const u8) !void {
        var index_doc = ObjectMap.init(allocator);
        defer index_doc.deinit();
        try index_doc.put("key", .{ .object = keys });
        try index_doc.put("name", .{ .string = name });

        var indexes = Array.init(allocator);
        defer indexes.deinit();
        try indexes.append(.{ .object = index_doc });

        var cmd = ObjectMap.init(allocator);
        defer cmd.deinit();
        try cmd.put("createIndexes", .{ .string = collection });
        try cmd.put("indexes", .{ .array = indexes });

        var response = try self.conn.runCommand(allocator, self.database, cmd);
        defer bson.freeObjectMap(allocator, &response);
    }

    /// Extract documents from a cursor response, handling getMore for large result sets.
    fn extractCursorDocs(self: *Client, allocator: Allocator, response: *ObjectMap, collection: []const u8) ![]ObjectMap {
        var results: std.ArrayList(ObjectMap) = .empty;
        errdefer {
            for (results.items) |*d| bson.freeObjectMap(allocator, d);
            results.deinit(allocator);
        }

        const cursor = response.get("cursor") orelse {
            bson.freeObjectMap(allocator, response);
            return results.toOwnedSlice(allocator);
        };

        switch (cursor) {
            .object => |cursor_obj| {
                // Get firstBatch
                if (cursor_obj.get("firstBatch")) |batch| {
                    switch (batch) {
                        .array => |arr| {
                            for (arr.items) |item| {
                                switch (item) {
                                    .object => |doc| {
                                        const cloned = try cloneObjectMap(allocator, doc);
                                        try results.append(allocator, cloned);
                                    },
                                    else => {},
                                }
                            }
                        },
                        else => {},
                    }
                }

                // Check cursor ID for getMore
                var cursor_id: i64 = 0;
                if (cursor_obj.get("id")) |id_val| {
                    switch (id_val) {
                        .integer => cursor_id = id_val.integer,
                        .float => cursor_id = @intFromFloat(id_val.float),
                        else => {},
                    }
                }

                bson.freeObjectMap(allocator, response);

                // getMore loop
                while (cursor_id != 0) {
                    var gm_cmd = ObjectMap.init(allocator);
                    defer gm_cmd.deinit();
                    try gm_cmd.put("getMore", .{ .integer = cursor_id });
                    try gm_cmd.put("collection", .{ .string = collection });

                    var gm_response = try self.conn.runCommand(allocator, self.database, gm_cmd);

                    const gm_cursor = gm_response.get("cursor") orelse {
                        bson.freeObjectMap(allocator, &gm_response);
                        break;
                    };

                    switch (gm_cursor) {
                        .object => |gm_cursor_obj| {
                            if (gm_cursor_obj.get("nextBatch")) |batch| {
                                switch (batch) {
                                    .array => |arr| {
                                        for (arr.items) |item| {
                                            switch (item) {
                                                .object => |doc| {
                                                    const cloned = try cloneObjectMap(allocator, doc);
                                                    try results.append(allocator, cloned);
                                                },
                                                else => {},
                                            }
                                        }
                                    },
                                    else => {},
                                }
                            }

                            cursor_id = 0;
                            if (gm_cursor_obj.get("id")) |id_val| {
                                switch (id_val) {
                                    .integer => cursor_id = id_val.integer,
                                    .float => cursor_id = @intFromFloat(id_val.float),
                                    else => {},
                                }
                            }
                        },
                        else => cursor_id = 0,
                    }

                    bson.freeObjectMap(allocator, &gm_response);
                }
            },
            else => {
                bson.freeObjectMap(allocator, response);
            },
        }

        return results.toOwnedSlice(allocator);
    }
};

/// Clone an ObjectMap, duping all keys and values.
fn cloneObjectMap(allocator: Allocator, source: ObjectMap) !ObjectMap {
    var result = ObjectMap.init(allocator);
    errdefer {
        var it = result.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            bson.freeValue(allocator, entry.value_ptr.*);
        }
        result.deinit();
    }
    var it = source.iterator();
    while (it.next()) |entry| {
        const new_key = try allocator.dupe(u8, entry.key_ptr.*);
        const new_value = try bson.cloneValue(allocator, entry.value_ptr.*);
        try result.put(new_key, new_value);
    }
    return result;
}

test "Client compiles" {
    // Verify types compile
    _ = Client;
    _ = FindOpts;
}

// ---------------------------------------------------------------------------
// Integration tests — only run when MONGO_URI is set (e.g. via integration-test.sh)
// ---------------------------------------------------------------------------

const testing = std.testing;

extern "c" fn getenv(name: [*:0]const u8) ?[*:0]const u8;

fn getMongoUri() ?[]const u8 {
    const ptr = getenv("MONGO_URI") orelse return null;
    return std.mem.sliceTo(ptr, 0);
}

const TestContext = struct {
    conn: *Connection,
    client: *Client,
    threaded: *std.Io.Threaded,
};

fn connectForTest(allocator: Allocator) !TestContext {
    const uri_str = getMongoUri() orelse return error.SkipTest;
    const uri = try connection_mod.parseUri(uri_str);
    const threaded = try allocator.create(std.Io.Threaded);
    threaded.* = std.Io.Threaded.init(allocator, .{});
    const io = threaded.io();
    const conn = try allocator.create(Connection);
    conn.* = try Connection.connect(allocator, uri, io, .{});
    const client = try allocator.create(Client);
    client.* = Client.init(allocator, conn);
    return .{ .conn = conn, .client = client, .threaded = threaded };
}

fn dropDatabase(client: *Client, allocator: Allocator) !void {
    var cmd = ObjectMap.init(allocator);
    defer cmd.deinit();
    try cmd.put("dropDatabase", .{ .integer = 1 });
    var response = try client.conn.runCommand(allocator, client.database, cmd);
    bson.freeObjectMap(allocator, &response);
}

fn cleanupTest(ctx: TestContext, allocator: Allocator) void {
    ctx.conn.close();
    allocator.destroy(ctx.client);
    allocator.destroy(ctx.conn);
    allocator.destroy(ctx.threaded);
}

test "integration: insertMany + findOne round-trip" {
    const allocator = testing.allocator;
    const ctx = connectForTest(allocator) catch |err| {
        if (err == error.SkipTest) return;
        return err;
    };
    defer cleanupTest(ctx, allocator);
    try dropDatabase(ctx.client, allocator);

    // Insert documents
    var doc1 = ObjectMap.init(allocator);
    defer doc1.deinit();
    try doc1.put("name", .{ .string = "alice" });
    try doc1.put("age", .{ .integer = 30 });

    var doc2 = ObjectMap.init(allocator);
    defer doc2.deinit();
    try doc2.put("name", .{ .string = "bob" });
    try doc2.put("age", .{ .integer = 25 });

    const docs = [_]ObjectMap{ doc1, doc2 };
    try ctx.client.insertMany(allocator, "users", &docs);

    // Find alice
    var filter = ObjectMap.init(allocator);
    defer filter.deinit();
    try filter.put("name", .{ .string = "alice" });

    var found = (try ctx.client.findOne(allocator, "users", filter)) orelse
        return error.ExpectedDocument;
    defer bson.freeObjectMap(allocator, &found);

    try testing.expectEqualStrings("alice", found.get("name").?.string);
    try testing.expectEqual(@as(i64, 30), found.get("age").?.integer);
}

test "integration: find with sort/limit/skip" {
    const allocator = testing.allocator;
    const ctx = connectForTest(allocator) catch |err| {
        if (err == error.SkipTest) return;
        return err;
    };
    defer cleanupTest(ctx, allocator);
    try dropDatabase(ctx.client, allocator);

    // Insert 5 documents
    var docs_buf: [5]ObjectMap = undefined;
    for (&docs_buf, 0..) |*d, i| {
        d.* = ObjectMap.init(allocator);
        d.put("name", .{ .string = "user" }) catch unreachable;
        d.put("seq", .{ .integer = @intCast(i) }) catch unreachable;
    }
    defer for (&docs_buf) |*d| d.deinit();
    try ctx.client.insertMany(allocator, "items", &docs_buf);

    // Find with sort desc, skip 1, limit 2
    var empty_filter = ObjectMap.init(allocator);
    defer empty_filter.deinit();
    var sort = ObjectMap.init(allocator);
    defer sort.deinit();
    try sort.put("seq", .{ .integer = -1 });

    const results = try ctx.client.find(allocator, "items", empty_filter, .{
        .sort = sort,
        .skip = 1,
        .limit = 2,
    });
    defer {
        for (results) |*r| bson.freeObjectMap(allocator, @constCast(r));
        allocator.free(results);
    }

    try testing.expectEqual(@as(usize, 2), results.len);
    // Sorted desc, skipped first (4) → expect 3, 2
    try testing.expectEqual(@as(i64, 3), results[0].get("seq").?.integer);
    try testing.expectEqual(@as(i64, 2), results[1].get("seq").?.integer);
}

test "integration: replaceOne + verify" {
    const allocator = testing.allocator;
    const ctx = connectForTest(allocator) catch |err| {
        if (err == error.SkipTest) return;
        return err;
    };
    defer cleanupTest(ctx, allocator);
    try dropDatabase(ctx.client, allocator);

    // Insert a document
    var doc = ObjectMap.init(allocator);
    defer doc.deinit();
    try doc.put("name", .{ .string = "charlie" });
    try doc.put("score", .{ .integer = 10 });
    const docs = [_]ObjectMap{doc};
    try ctx.client.insertMany(allocator, "scores", &docs);

    // Replace it
    var filter = ObjectMap.init(allocator);
    defer filter.deinit();
    try filter.put("name", .{ .string = "charlie" });

    var replacement = ObjectMap.init(allocator);
    defer replacement.deinit();
    try replacement.put("name", .{ .string = "charlie" });
    try replacement.put("score", .{ .integer = 99 });

    try ctx.client.replaceOne(allocator, "scores", filter, replacement, false);

    // Verify
    var filter2 = ObjectMap.init(allocator);
    defer filter2.deinit();
    try filter2.put("name", .{ .string = "charlie" });
    var found = (try ctx.client.findOne(allocator, "scores", filter2)) orelse
        return error.ExpectedDocument;
    defer bson.freeObjectMap(allocator, &found);

    try testing.expectEqual(@as(i64, 99), found.get("score").?.integer);
}

test "integration: deleteOne + verify" {
    const allocator = testing.allocator;
    const ctx = connectForTest(allocator) catch |err| {
        if (err == error.SkipTest) return;
        return err;
    };
    defer cleanupTest(ctx, allocator);
    try dropDatabase(ctx.client, allocator);

    var doc = ObjectMap.init(allocator);
    defer doc.deinit();
    try doc.put("name", .{ .string = "delete_me" });
    const docs = [_]ObjectMap{doc};
    try ctx.client.insertMany(allocator, "del_test", &docs);

    var filter = ObjectMap.init(allocator);
    defer filter.deinit();
    try filter.put("name", .{ .string = "delete_me" });

    try ctx.client.deleteOne(allocator, "del_test", filter);

    // Verify deleted
    var filter2 = ObjectMap.init(allocator);
    defer filter2.deinit();
    try filter2.put("name", .{ .string = "delete_me" });
    const found = try ctx.client.findOne(allocator, "del_test", filter2);
    try testing.expect(found == null);
}

test "integration: findOneAndDelete + verify" {
    const allocator = testing.allocator;
    const ctx = connectForTest(allocator) catch |err| {
        if (err == error.SkipTest) return;
        return err;
    };
    defer cleanupTest(ctx, allocator);
    try dropDatabase(ctx.client, allocator);

    var doc = ObjectMap.init(allocator);
    defer doc.deinit();
    try doc.put("key", .{ .string = "ephemeral" });
    try doc.put("val", .{ .integer = 42 });
    const docs = [_]ObjectMap{doc};
    try ctx.client.insertMany(allocator, "fad_test", &docs);

    var filter = ObjectMap.init(allocator);
    defer filter.deinit();
    try filter.put("key", .{ .string = "ephemeral" });

    var deleted = (try ctx.client.findOneAndDelete(allocator, "fad_test", filter)) orelse
        return error.ExpectedDocument;
    defer bson.freeObjectMap(allocator, &deleted);

    try testing.expectEqualStrings("ephemeral", deleted.get("key").?.string);
    try testing.expectEqual(@as(i64, 42), deleted.get("val").?.integer);

    // Verify gone
    var filter2 = ObjectMap.init(allocator);
    defer filter2.deinit();
    try filter2.put("key", .{ .string = "ephemeral" });
    const found = try ctx.client.findOne(allocator, "fad_test", filter2);
    try testing.expect(found == null);
}

test "integration: aggregate pipeline" {
    const allocator = testing.allocator;
    const ctx = connectForTest(allocator) catch |err| {
        if (err == error.SkipTest) return;
        return err;
    };
    defer cleanupTest(ctx, allocator);
    try dropDatabase(ctx.client, allocator);

    // Insert documents with categories
    var d1 = ObjectMap.init(allocator);
    defer d1.deinit();
    try d1.put("cat", .{ .string = "a" });
    try d1.put("v", .{ .integer = 10 });

    var d2 = ObjectMap.init(allocator);
    defer d2.deinit();
    try d2.put("cat", .{ .string = "a" });
    try d2.put("v", .{ .integer = 20 });

    var d3 = ObjectMap.init(allocator);
    defer d3.deinit();
    try d3.put("cat", .{ .string = "b" });
    try d3.put("v", .{ .integer = 5 });

    const docs = [_]ObjectMap{ d1, d2, d3 };
    try ctx.client.insertMany(allocator, "agg_test", &docs);

    // Build pipeline: [ { $group: { _id: "$cat", total: { $sum: "$v" } } }, { $sort: { _id: 1 } } ]
    var sum_expr = ObjectMap.init(allocator);
    defer sum_expr.deinit();
    try sum_expr.put("$sum", .{ .string = "$v" });

    var group_fields = ObjectMap.init(allocator);
    defer group_fields.deinit();
    try group_fields.put("_id", .{ .string = "$cat" });
    try group_fields.put("total", .{ .object = sum_expr });

    var group_stage = ObjectMap.init(allocator);
    defer group_stage.deinit();
    try group_stage.put("$group", .{ .object = group_fields });

    var sort_fields = ObjectMap.init(allocator);
    defer sort_fields.deinit();
    try sort_fields.put("_id", .{ .integer = 1 });

    var sort_stage = ObjectMap.init(allocator);
    defer sort_stage.deinit();
    try sort_stage.put("$sort", .{ .object = sort_fields });

    const pipeline = [_]Value{
        .{ .object = group_stage },
        .{ .object = sort_stage },
    };

    const results = try ctx.client.aggregate(allocator, "agg_test", &pipeline);
    defer {
        for (results) |*r| bson.freeObjectMap(allocator, @constCast(r));
        allocator.free(results);
    }

    try testing.expectEqual(@as(usize, 2), results.len);
    // Sorted by _id: "a" first, "b" second
    try testing.expectEqualStrings("a", results[0].get("_id").?.string);
    try testing.expectEqual(@as(i64, 30), results[0].get("total").?.integer);
    try testing.expectEqualStrings("b", results[1].get("_id").?.string);
    try testing.expectEqual(@as(i64, 5), results[1].get("total").?.integer);
}

test "integration: createIndex" {
    const allocator = testing.allocator;
    const ctx = connectForTest(allocator) catch |err| {
        if (err == error.SkipTest) return;
        return err;
    };
    defer cleanupTest(ctx, allocator);
    try dropDatabase(ctx.client, allocator);

    // Insert a doc so the collection exists
    var doc = ObjectMap.init(allocator);
    defer doc.deinit();
    try doc.put("email", .{ .string = "test@example.com" });
    const docs = [_]ObjectMap{doc};
    try ctx.client.insertMany(allocator, "idx_test", &docs);

    // Create index
    var keys = ObjectMap.init(allocator);
    defer keys.deinit();
    try keys.put("email", .{ .integer = 1 });

    try ctx.client.createIndex(allocator, "idx_test", keys, "email_1");

    // Verify index exists via listIndexes command
    var cmd = ObjectMap.init(allocator);
    defer cmd.deinit();
    try cmd.put("listIndexes", .{ .string = "idx_test" });

    var response = try ctx.client.conn.runCommand(allocator, ctx.client.database, cmd);
    defer bson.freeObjectMap(allocator, &response);

    const cursor_val = response.get("cursor") orelse return error.ExpectedCursor;
    const first_batch = cursor_val.object.get("firstBatch") orelse return error.ExpectedBatch;
    const indexes = first_batch.array.items;

    // Should have at least 2 indexes: _id_ and email_1
    try testing.expect(indexes.len >= 2);

    var found_email_idx = false;
    for (indexes) |idx| {
        if (idx.object.get("name")) |name_val| {
            if (std.mem.eql(u8, name_val.string, "email_1")) {
                found_email_idx = true;
                break;
            }
        }
    }
    try testing.expect(found_email_idx);
}
