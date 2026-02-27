const std = @import("std");
const json = std.json;
const Value = json.Value;
const ObjectMap = json.ObjectMap;
const Array = json.Array;
const Allocator = std.mem.Allocator;

// BSON type codes
const TYPE_DOUBLE: u8 = 0x01;
const TYPE_STRING: u8 = 0x02;
const TYPE_DOCUMENT: u8 = 0x03;
const TYPE_ARRAY: u8 = 0x04;
const TYPE_OBJECTID: u8 = 0x07;
const TYPE_BOOL: u8 = 0x08;
const TYPE_NULL: u8 = 0x0A;
const TYPE_BINARY: u8 = 0x05;
const TYPE_DATETIME: u8 = 0x09;
const TYPE_REGEX: u8 = 0x0B;
const TYPE_INT32: u8 = 0x10;
const TYPE_TIMESTAMP: u8 = 0x11;
const TYPE_INT64: u8 = 0x12;

/// Encode an ObjectMap to BSON bytes.
pub fn encode(allocator: Allocator, doc: ObjectMap) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    // Placeholder for document size (4 bytes)
    try buf.appendNTimes(allocator, 0, 4);

    var it = doc.iterator();
    while (it.next()) |entry| {
        try encodeElement(allocator, &buf, entry.key_ptr.*, entry.value_ptr.*);
    }

    // Null terminator
    try buf.append(allocator, 0);

    // Write document size (little-endian i32)
    const size: i32 = @intCast(buf.items.len);
    const size_bytes = std.mem.asBytes(&std.mem.nativeToLittle(i32, size));
    @memcpy(buf.items[0..4], size_bytes);

    return buf.toOwnedSlice(allocator);
}

/// Encode a single Value to BSON document bytes (wraps in a document with empty key if needed).
pub fn encodeValue(allocator: Allocator, value: Value) ![]u8 {
    switch (value) {
        .object => |obj| return encode(allocator, obj),
        else => {
            // Wrap non-object values in a document with key ""
            var doc = ObjectMap.init(allocator);
            defer doc.deinit();
            try doc.put("", value);
            return encode(allocator, doc);
        },
    }
}

fn encodeElement(allocator: Allocator, buf: *std.ArrayList(u8), key: []const u8, value: Value) !void {
    switch (value) {
        .float => |f| {
            try buf.append(allocator, TYPE_DOUBLE);
            try encodeCString(allocator, buf, key);
            const bytes = std.mem.asBytes(&std.mem.nativeToLittle(u64, @bitCast(f)));
            try buf.appendSlice(allocator, bytes);
        },
        .integer => |i| {
            if (i >= std.math.minInt(i32) and i <= std.math.maxInt(i32)) {
                try buf.append(allocator, TYPE_INT32);
                try encodeCString(allocator, buf, key);
                const val: i32 = @intCast(i);
                const bytes = std.mem.asBytes(&std.mem.nativeToLittle(i32, val));
                try buf.appendSlice(allocator, bytes);
            } else {
                try buf.append(allocator, TYPE_INT64);
                try encodeCString(allocator, buf, key);
                const bytes = std.mem.asBytes(&std.mem.nativeToLittle(i64, i));
                try buf.appendSlice(allocator, bytes);
            }
        },
        .string => |s| {
            try buf.append(allocator, TYPE_STRING);
            try encodeCString(allocator, buf, key);
            const len: i32 = @intCast(s.len + 1);
            const len_bytes = std.mem.asBytes(&std.mem.nativeToLittle(i32, len));
            try buf.appendSlice(allocator, len_bytes);
            try buf.appendSlice(allocator, s);
            try buf.append(allocator, 0);
        },
        .bool => |b| {
            try buf.append(allocator, TYPE_BOOL);
            try encodeCString(allocator, buf, key);
            try buf.append(allocator, if (b) 1 else 0);
        },
        .null => {
            try buf.append(allocator, TYPE_NULL);
            try encodeCString(allocator, buf, key);
        },
        .object => |obj| {
            try buf.append(allocator, TYPE_DOCUMENT);
            try encodeCString(allocator, buf, key);
            // Encode sub-document inline
            const start = buf.items.len;
            try buf.appendNTimes(allocator, 0, 4); // placeholder
            var it = obj.iterator();
            while (it.next()) |entry| {
                try encodeElement(allocator, buf, entry.key_ptr.*, entry.value_ptr.*);
            }
            try buf.append(allocator, 0);
            const size: i32 = @intCast(buf.items.len - start);
            const size_bytes = std.mem.asBytes(&std.mem.nativeToLittle(i32, size));
            @memcpy(buf.items[start..][0..4], size_bytes);
        },
        .array => |arr| {
            try buf.append(allocator, TYPE_ARRAY);
            try encodeCString(allocator, buf, key);
            // BSON arrays are documents with "0","1","2",... keys
            const start = buf.items.len;
            try buf.appendNTimes(allocator, 0, 4); // placeholder
            var idx_buf: [20]u8 = undefined;
            for (arr.items, 0..) |item, idx| {
                const idx_str = std.fmt.bufPrint(&idx_buf, "{d}", .{idx}) catch unreachable;
                try encodeElement(allocator, buf, idx_str, item);
            }
            try buf.append(allocator, 0);
            const size: i32 = @intCast(buf.items.len - start);
            const size_bytes = std.mem.asBytes(&std.mem.nativeToLittle(i32, size));
            @memcpy(buf.items[start..][0..4], size_bytes);
        },
        .number_string => |s| {
            // Encode as string
            try buf.append(allocator, TYPE_STRING);
            try encodeCString(allocator, buf, key);
            const len: i32 = @intCast(s.len + 1);
            const len_bytes = std.mem.asBytes(&std.mem.nativeToLittle(i32, len));
            try buf.appendSlice(allocator, len_bytes);
            try buf.appendSlice(allocator, s);
            try buf.append(allocator, 0);
        },
    }
}

fn encodeCString(allocator: Allocator, buf: *std.ArrayList(u8), s: []const u8) !void {
    try buf.appendSlice(allocator, s);
    try buf.append(allocator, 0);
}

pub const BsonError = error{ InvalidBSON, OutOfMemory };

/// Decode BSON bytes into an ObjectMap.
/// ObjectId _id fields are dropped. Non-ObjectId _id fields are kept.
pub fn decode(allocator: Allocator, bytes: []const u8) BsonError!ObjectMap {
    if (bytes.len < 5) return error.InvalidBSON;
    const doc_size = readI32(bytes[0..4]);
    if (doc_size < 5 or doc_size > @as(i32, @intCast(bytes.len))) return error.InvalidBSON;

    var result = ObjectMap.init(allocator);
    errdefer {
        var it = result.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            freeValue(allocator, entry.value_ptr.*);
        }
        result.deinit();
    }

    var pos: usize = 4;
    const end: usize = @intCast(doc_size - 1); // before null terminator

    while (pos < end) {
        const type_byte = bytes[pos];
        pos += 1;

        // Read element name (cstring)
        const name_start = pos;
        while (pos < bytes.len and bytes[pos] != 0) : (pos += 1) {}
        const name = bytes[name_start..pos];
        pos += 1; // skip null terminator

        // Skip ObjectId _id fields
        if (type_byte == TYPE_OBJECTID and std.mem.eql(u8, name, "_id")) {
            pos += 12; // ObjectId is 12 bytes
            continue;
        }

        const value = try decodeElementValue(allocator, type_byte, bytes, &pos);

        // Keep non-ObjectId _id fields (e.g., from $group)
        const duped_name = try allocator.dupe(u8, name);
        try result.put(duped_name, value);
    }

    return result;
}

fn decodeElementValue(allocator: Allocator, type_byte: u8, bytes: []const u8, pos: *usize) BsonError!Value {
    switch (type_byte) {
        TYPE_DOUBLE => {
            if (pos.* + 8 > bytes.len) return error.InvalidBSON;
            const bits = readU64(bytes[pos.*..][0..8]);
            pos.* += 8;
            return .{ .float = @bitCast(bits) };
        },
        TYPE_STRING => {
            if (pos.* + 4 > bytes.len) return error.InvalidBSON;
            const str_len = readI32(bytes[pos.*..][0..4]);
            pos.* += 4;
            if (str_len < 1) return error.InvalidBSON;
            const slen: usize = @intCast(str_len - 1); // exclude null
            if (pos.* + slen + 1 > bytes.len) return error.InvalidBSON;
            const s = try allocator.dupe(u8, bytes[pos.*..][0..slen]);
            pos.* += slen + 1; // skip string + null
            return .{ .string = s };
        },
        TYPE_DOCUMENT => {
            if (pos.* + 4 > bytes.len) return error.InvalidBSON;
            const sub_size = readI32(bytes[pos.*..][0..4]);
            if (sub_size < 5) return error.InvalidBSON;
            const sub_end: usize = pos.* + @as(usize, @intCast(sub_size));
            if (sub_end > bytes.len) return error.InvalidBSON;
            const sub_doc = try decode(allocator, bytes[pos.*..sub_end]);
            pos.* = sub_end;
            return .{ .object = sub_doc };
        },
        TYPE_ARRAY => {
            if (pos.* + 4 > bytes.len) return error.InvalidBSON;
            const sub_size = readI32(bytes[pos.*..][0..4]);
            if (sub_size < 5) return error.InvalidBSON;
            const sub_end: usize = pos.* + @as(usize, @intCast(sub_size));
            if (sub_end > bytes.len) return error.InvalidBSON;
            // Decode as document, then extract values in order
            const sub_doc = try decode(allocator, bytes[pos.*..sub_end]);
            pos.* = sub_end;
            // Convert document with "0","1","2" keys to array
            var arr = Array.init(allocator);
            var idx: usize = 0;
            var idx_buf: [20]u8 = undefined;
            while (true) : (idx += 1) {
                const idx_str = std.fmt.bufPrint(&idx_buf, "{d}", .{idx}) catch break;
                if (sub_doc.get(idx_str)) |val| {
                    try arr.append(val);
                } else break;
            }
            // Free the temporary document keys (but not values, they're moved to array)
            var it = sub_doc.iterator();
            while (it.next()) |entry| {
                allocator.free(entry.key_ptr.*);
            }
            var doc_copy = sub_doc;
            doc_copy.deinit();
            return .{ .array = arr };
        },
        TYPE_BINARY => {
            // binary: int32 length + byte subtype + bytes
            if (pos.* + 4 > bytes.len) return error.InvalidBSON;
            const bin_len = readI32(bytes[pos.*..][0..4]);
            pos.* += 4;
            if (bin_len < 0) return error.InvalidBSON;
            pos.* += 1; // subtype byte
            const blen: usize = @intCast(bin_len);
            if (pos.* + blen > bytes.len) return error.InvalidBSON;
            // Represent as string for now
            const s = try allocator.dupe(u8, bytes[pos.*..][0..blen]);
            pos.* += blen;
            return .{ .string = s };
        },
        TYPE_OBJECTID => {
            // 12 bytes - skip (this handles non-_id ObjectId fields)
            pos.* += 12;
            return .null;
        },
        TYPE_DATETIME => {
            // UTC datetime: int64 milliseconds since epoch
            if (pos.* + 8 > bytes.len) return error.InvalidBSON;
            const val = readI64(bytes[pos.*..][0..8]);
            pos.* += 8;
            return .{ .integer = val };
        },
        TYPE_REGEX => {
            // regex: cstring pattern + cstring options
            while (pos.* < bytes.len and bytes[pos.*] != 0) : (pos.* += 1) {}
            pos.* += 1; // null terminator for pattern
            while (pos.* < bytes.len and bytes[pos.*] != 0) : (pos.* += 1) {}
            pos.* += 1; // null terminator for options
            return .null;
        },
        TYPE_BOOL => {
            if (pos.* >= bytes.len) return error.InvalidBSON;
            const b = bytes[pos.*] != 0;
            pos.* += 1;
            return .{ .bool = b };
        },
        TYPE_NULL => {
            return .null;
        },
        TYPE_INT32 => {
            if (pos.* + 4 > bytes.len) return error.InvalidBSON;
            const val = readI32(bytes[pos.*..][0..4]);
            pos.* += 4;
            return .{ .integer = val };
        },
        TYPE_TIMESTAMP => {
            // MongoDB internal timestamp: uint32 increment + uint32 seconds (8 bytes total)
            if (pos.* + 8 > bytes.len) return error.InvalidBSON;
            const val = readI64(bytes[pos.*..][0..8]);
            pos.* += 8;
            return .{ .integer = val };
        },
        TYPE_INT64 => {
            if (pos.* + 8 > bytes.len) return error.InvalidBSON;
            const val = readI64(bytes[pos.*..][0..8]);
            pos.* += 8;
            return .{ .integer = val };
        },
        else => {
            // Unknown type - can't safely skip without knowing size
            return error.InvalidBSON;
        },
    }
}

fn readI32(bytes: *const [4]u8) i32 {
    return @bitCast(std.mem.littleToNative(u32, std.mem.bytesToValue(u32, bytes)));
}

fn readI64(bytes: *const [8]u8) i64 {
    return @bitCast(std.mem.littleToNative(u64, std.mem.bytesToValue(u64, bytes)));
}

fn readU64(bytes: *const [8]u8) u64 {
    return std.mem.littleToNative(u64, std.mem.bytesToValue(u64, bytes));
}

/// Free a Value recursively.
pub fn freeValue(allocator: Allocator, value: Value) void {
    switch (value) {
        .string => |s| allocator.free(s),
        .number_string => |s| allocator.free(s),
        .array => |arr| {
            for (arr.items) |item| freeValue(allocator, item);
            var mut_arr = arr;
            mut_arr.deinit();
        },
        .object => |obj| {
            var it = obj.iterator();
            while (it.next()) |entry| {
                allocator.free(entry.key_ptr.*);
                freeValue(allocator, entry.value_ptr.*);
            }
            var mut_obj = obj;
            mut_obj.deinit();
        },
        else => {},
    }
}

/// Free an ObjectMap and all its keys/values.
pub fn freeObjectMap(allocator: Allocator, map: *ObjectMap) void {
    var it = map.iterator();
    while (it.next()) |entry| {
        allocator.free(entry.key_ptr.*);
        freeValue(allocator, entry.value_ptr.*);
    }
    map.deinit();
}

/// Deep clone a Value, duplicating all allocated memory.
pub fn cloneValue(allocator: Allocator, value: Value) error{OutOfMemory}!Value {
    switch (value) {
        .null => return .null,
        .bool => |b| return .{ .bool = b },
        .integer => |i| return .{ .integer = i },
        .float => |f| return .{ .float = f },
        .number_string => |s| return .{ .number_string = try allocator.dupe(u8, s) },
        .string => |s| return .{ .string = try allocator.dupe(u8, s) },
        .array => |arr| {
            var new_arr = Array.initCapacity(allocator, arr.items.len) catch return error.OutOfMemory;
            for (arr.items) |item| {
                new_arr.appendAssumeCapacity(try cloneValue(allocator, item));
            }
            return .{ .array = new_arr };
        },
        .object => |obj| {
            var new_obj = ObjectMap.init(allocator);
            var it = obj.iterator();
            while (it.next()) |entry| {
                const new_key = try allocator.dupe(u8, entry.key_ptr.*);
                const new_value = try cloneValue(allocator, entry.value_ptr.*);
                try new_obj.put(new_key, new_value);
            }
            return .{ .object = new_obj };
        },
    }
}

// --- Tests ---

test "BSON encode/decode round-trip: simple document" {
    const allocator = std.testing.allocator;

    var doc = ObjectMap.init(allocator);
    defer doc.deinit();
    try doc.put("name", .{ .string = "Alice" });
    try doc.put("age", .{ .integer = 30 });
    try doc.put("active", .{ .bool = true });

    const encoded = try encode(allocator, doc);
    defer allocator.free(encoded);

    var decoded = try decode(allocator, encoded);
    defer freeObjectMap(allocator, &decoded);

    try std.testing.expectEqualStrings("Alice", decoded.get("name").?.string);
    try std.testing.expectEqual(@as(i64, 30), decoded.get("age").?.integer);
    try std.testing.expect(decoded.get("active").?.bool);
}

test "BSON encode/decode round-trip: nested document" {
    const allocator = std.testing.allocator;

    var inner = ObjectMap.init(allocator);
    try inner.put("city", .{ .string = "NYC" });
    try inner.put("zip", .{ .integer = 10001 });

    var doc = ObjectMap.init(allocator);
    defer {
        if (doc.getPtr("address")) |addr_val| {
            addr_val.object.deinit();
        }
        doc.deinit();
    }
    try doc.put("address", .{ .object = inner });
    try doc.put("name", .{ .string = "Bob" });

    const encoded = try encode(allocator, doc);
    defer allocator.free(encoded);

    var decoded = try decode(allocator, encoded);
    defer freeObjectMap(allocator, &decoded);

    try std.testing.expectEqualStrings("Bob", decoded.get("name").?.string);
    const addr = decoded.get("address").?.object;
    try std.testing.expectEqualStrings("NYC", addr.get("city").?.string);
    try std.testing.expectEqual(@as(i64, 10001), addr.get("zip").?.integer);
}

test "BSON encode/decode round-trip: array" {
    const allocator = std.testing.allocator;

    var arr = Array.init(allocator);
    try arr.append(.{ .string = "a" });
    try arr.append(.{ .string = "b" });
    try arr.append(.{ .integer = 42 });

    var doc = ObjectMap.init(allocator);
    defer {
        if (doc.getPtr("items")) |items_val| {
            items_val.array.deinit();
        }
        doc.deinit();
    }
    try doc.put("items", .{ .array = arr });

    const encoded = try encode(allocator, doc);
    defer allocator.free(encoded);

    var decoded = try decode(allocator, encoded);
    defer freeObjectMap(allocator, &decoded);

    const items = decoded.get("items").?.array;
    try std.testing.expectEqual(@as(usize, 3), items.items.len);
    try std.testing.expectEqualStrings("a", items.items[0].string);
    try std.testing.expectEqualStrings("b", items.items[1].string);
    try std.testing.expectEqual(@as(i64, 42), items.items[2].integer);
}

test "BSON encode/decode round-trip: null and float" {
    const allocator = std.testing.allocator;

    var doc = ObjectMap.init(allocator);
    defer doc.deinit();
    try doc.put("x", .null);
    try doc.put("pi", .{ .float = 3.14 });

    const encoded = try encode(allocator, doc);
    defer allocator.free(encoded);

    var decoded = try decode(allocator, encoded);
    defer freeObjectMap(allocator, &decoded);

    try std.testing.expect(decoded.get("x").? == .null);
    try std.testing.expectApproxEqAbs(@as(f64, 3.14), decoded.get("pi").?.float, 0.001);
}

test "BSON encode/decode round-trip: i64 large value" {
    const allocator = std.testing.allocator;

    var doc = ObjectMap.init(allocator);
    defer doc.deinit();
    const big: i64 = 1_700_000_000_000; // millisecond timestamp
    try doc.put("ts", .{ .integer = big });

    const encoded = try encode(allocator, doc);
    defer allocator.free(encoded);

    var decoded = try decode(allocator, encoded);
    defer freeObjectMap(allocator, &decoded);

    try std.testing.expectEqual(big, decoded.get("ts").?.integer);
}

test "BSON decode: ObjectId _id is stripped" {
    const allocator = std.testing.allocator;

    // Build BSON manually with an ObjectId _id
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);

    try buf.appendNTimes(allocator, 0, 4); // size placeholder

    // ObjectId _id
    try buf.append(allocator, TYPE_OBJECTID);
    try buf.appendSlice(allocator, "_id");
    try buf.append(allocator, 0);
    try buf.appendNTimes(allocator, 0xAB, 12); // 12 bytes of ObjectId

    // A normal field
    try buf.append(allocator, TYPE_STRING);
    try buf.appendSlice(allocator, "name");
    try buf.append(allocator, 0);
    const name = "test";
    const name_len: i32 = @intCast(name.len + 1);
    const name_len_bytes = std.mem.asBytes(&std.mem.nativeToLittle(i32, name_len));
    try buf.appendSlice(allocator, name_len_bytes);
    try buf.appendSlice(allocator, name);
    try buf.append(allocator, 0);

    try buf.append(allocator, 0); // doc terminator

    // Write size
    const size: i32 = @intCast(buf.items.len);
    const size_bytes = std.mem.asBytes(&std.mem.nativeToLittle(i32, size));
    @memcpy(buf.items[0..4], size_bytes);

    var decoded = try decode(allocator, buf.items);
    defer freeObjectMap(allocator, &decoded);

    // _id should be stripped
    try std.testing.expect(decoded.get("_id") == null);
    try std.testing.expectEqualStrings("test", decoded.get("name").?.string);
}

test "BSON decode: non-ObjectId _id is kept" {
    const allocator = std.testing.allocator;

    // A document with string _id (from $group aggregation)
    var doc = ObjectMap.init(allocator);
    defer doc.deinit();
    try doc.put("_id", .{ .string = "group_key" });
    try doc.put("count", .{ .integer = 5 });

    const encoded = try encode(allocator, doc);
    defer allocator.free(encoded);

    var decoded = try decode(allocator, encoded);
    defer freeObjectMap(allocator, &decoded);

    // String _id should be preserved
    try std.testing.expectEqualStrings("group_key", decoded.get("_id").?.string);
    try std.testing.expectEqual(@as(i64, 5), decoded.get("count").?.integer);
}

test "BSON encode/decode: empty document" {
    const allocator = std.testing.allocator;

    var doc = ObjectMap.init(allocator);
    defer doc.deinit();

    const encoded = try encode(allocator, doc);
    defer allocator.free(encoded);

    // Minimum BSON doc is 5 bytes: 4-byte size + null terminator
    try std.testing.expectEqual(@as(usize, 5), encoded.len);

    var decoded = try decode(allocator, encoded);
    defer freeObjectMap(allocator, &decoded);
    try std.testing.expectEqual(@as(usize, 0), decoded.count());
}
