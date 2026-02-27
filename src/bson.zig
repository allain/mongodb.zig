const std = @import("std");
const json = std.json;
const Value = json.Value;
const ObjectMap = json.ObjectMap;
const Array = json.Array;
const Allocator = std.mem.Allocator;

/// BSON element type codes as defined by the BSON specification.
/// See https://bsonspec.org/spec.html for details.
pub const BsonType = enum(u8) {
    double = 0x01,
    string = 0x02,
    document = 0x03,
    array = 0x04,
    binary = 0x05,
    undefined = 0x06, // deprecated
    object_id = 0x07,
    boolean = 0x08,
    datetime = 0x09,
    null = 0x0A,
    regex = 0x0B,
    db_pointer = 0x0C, // deprecated
    javascript = 0x0D,
    symbol = 0x0E, // deprecated
    code_with_scope = 0x0F, // deprecated
    int32 = 0x10,
    timestamp = 0x11,
    int64 = 0x12,
    decimal128 = 0x13,
    max_key = 0x7F,
    min_key = 0xFF,
    _,
};

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
            try buf.append(allocator, @intFromEnum(BsonType.double));
            try encodeCString(allocator, buf, key);
            const bytes = std.mem.asBytes(&std.mem.nativeToLittle(u64, @bitCast(f)));
            try buf.appendSlice(allocator, bytes);
        },
        .integer => |i| {
            if (i >= std.math.minInt(i32) and i <= std.math.maxInt(i32)) {
                try buf.append(allocator, @intFromEnum(BsonType.int32));
                try encodeCString(allocator, buf, key);
                const val: i32 = @intCast(i);
                const bytes = std.mem.asBytes(&std.mem.nativeToLittle(i32, val));
                try buf.appendSlice(allocator, bytes);
            } else {
                try buf.append(allocator, @intFromEnum(BsonType.int64));
                try encodeCString(allocator, buf, key);
                const bytes = std.mem.asBytes(&std.mem.nativeToLittle(i64, i));
                try buf.appendSlice(allocator, bytes);
            }
        },
        .string => |s| {
            try buf.append(allocator, @intFromEnum(BsonType.string));
            try encodeCString(allocator, buf, key);
            const len: i32 = @intCast(s.len + 1);
            const len_bytes = std.mem.asBytes(&std.mem.nativeToLittle(i32, len));
            try buf.appendSlice(allocator, len_bytes);
            try buf.appendSlice(allocator, s);
            try buf.append(allocator, 0);
        },
        .bool => |b| {
            try buf.append(allocator, @intFromEnum(BsonType.boolean));
            try encodeCString(allocator, buf, key);
            try buf.append(allocator, if (b) 1 else 0);
        },
        .null => {
            try buf.append(allocator, @intFromEnum(BsonType.null));
            try encodeCString(allocator, buf, key);
        },
        .object => |obj| {
            try buf.append(allocator, @intFromEnum(BsonType.document));
            try encodeCString(allocator, buf, key);
            const start = buf.items.len;
            try buf.appendNTimes(allocator, 0, 4);
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
            try buf.append(allocator, @intFromEnum(BsonType.array));
            try encodeCString(allocator, buf, key);
            const start = buf.items.len;
            try buf.appendNTimes(allocator, 0, 4);
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
            try buf.append(allocator, @intFromEnum(BsonType.string));
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
        const bson_type: BsonType = @enumFromInt(bytes[pos]);
        pos += 1;

        // Read element name (cstring)
        const name_start = pos;
        while (pos < bytes.len and bytes[pos] != 0) : (pos += 1) {}
        const name = bytes[name_start..pos];
        pos += 1; // skip null terminator

        // Skip ObjectId _id fields
        if (bson_type == .object_id and std.mem.eql(u8, name, "_id")) {
            pos += 12; // ObjectId is 12 bytes
            continue;
        }

        const value = try decodeElementValue(allocator, bson_type, bytes, &pos);

        // Keep non-ObjectId _id fields (e.g., from $group)
        const duped_name = try allocator.dupe(u8, name);
        try result.put(duped_name, value);
    }

    return result;
}

fn decodeElementValue(allocator: Allocator, bson_type: BsonType, bytes: []const u8, pos: *usize) BsonError!Value {
    switch (bson_type) {
        .double => {
            if (pos.* + 8 > bytes.len) return error.InvalidBSON;
            const bits = readU64(bytes[pos.*..][0..8]);
            pos.* += 8;
            return .{ .float = @bitCast(bits) };
        },
        .string => {
            if (pos.* + 4 > bytes.len) return error.InvalidBSON;
            const str_len = readI32(bytes[pos.*..][0..4]);
            pos.* += 4;
            if (str_len < 1) return error.InvalidBSON;
            const slen: usize = @intCast(str_len - 1);
            if (pos.* + slen + 1 > bytes.len) return error.InvalidBSON;
            const s = try allocator.dupe(u8, bytes[pos.*..][0..slen]);
            pos.* += slen + 1;
            return .{ .string = s };
        },
        .document => {
            if (pos.* + 4 > bytes.len) return error.InvalidBSON;
            const sub_size = readI32(bytes[pos.*..][0..4]);
            if (sub_size < 5) return error.InvalidBSON;
            const sub_end: usize = pos.* + @as(usize, @intCast(sub_size));
            if (sub_end > bytes.len) return error.InvalidBSON;
            const sub_doc = try decode(allocator, bytes[pos.*..sub_end]);
            pos.* = sub_end;
            return .{ .object = sub_doc };
        },
        .array => {
            if (pos.* + 4 > bytes.len) return error.InvalidBSON;
            const sub_size = readI32(bytes[pos.*..][0..4]);
            if (sub_size < 5) return error.InvalidBSON;
            const sub_end: usize = pos.* + @as(usize, @intCast(sub_size));
            if (sub_end > bytes.len) return error.InvalidBSON;
            const sub_doc = try decode(allocator, bytes[pos.*..sub_end]);
            pos.* = sub_end;
            var arr = Array.init(allocator);
            var idx: usize = 0;
            var idx_buf: [20]u8 = undefined;
            while (true) : (idx += 1) {
                const idx_str = std.fmt.bufPrint(&idx_buf, "{d}", .{idx}) catch break;
                if (sub_doc.get(idx_str)) |val| {
                    try arr.append(val);
                } else break;
            }
            var it = sub_doc.iterator();
            while (it.next()) |entry| {
                allocator.free(entry.key_ptr.*);
            }
            var doc_copy = sub_doc;
            doc_copy.deinit();
            return .{ .array = arr };
        },
        .binary => {
            if (pos.* + 4 > bytes.len) return error.InvalidBSON;
            const bin_len = readI32(bytes[pos.*..][0..4]);
            pos.* += 4;
            if (bin_len < 0) return error.InvalidBSON;
            pos.* += 1; // subtype byte
            const blen: usize = @intCast(bin_len);
            if (pos.* + blen > bytes.len) return error.InvalidBSON;
            const s = try allocator.dupe(u8, bytes[pos.*..][0..blen]);
            pos.* += blen;
            return .{ .string = s };
        },
        .object_id => {
            if (pos.* + 12 > bytes.len) return error.InvalidBSON;
            pos.* += 12;
            return .null;
        },
        .boolean => {
            if (pos.* >= bytes.len) return error.InvalidBSON;
            const b = bytes[pos.*] != 0;
            pos.* += 1;
            return .{ .bool = b };
        },
        .datetime => {
            if (pos.* + 8 > bytes.len) return error.InvalidBSON;
            const val = readI64(bytes[pos.*..][0..8]);
            pos.* += 8;
            return .{ .integer = val };
        },
        .null => {
            return .null;
        },
        .regex => {
            // cstring pattern + cstring options
            while (pos.* < bytes.len and bytes[pos.*] != 0) : (pos.* += 1) {}
            pos.* += 1;
            while (pos.* < bytes.len and bytes[pos.*] != 0) : (pos.* += 1) {}
            pos.* += 1;
            return .null;
        },
        .javascript => {
            // Same wire format as string: int32 length + bytes + null
            if (pos.* + 4 > bytes.len) return error.InvalidBSON;
            const str_len = readI32(bytes[pos.*..][0..4]);
            pos.* += 4;
            if (str_len < 1) return error.InvalidBSON;
            const slen: usize = @intCast(str_len - 1);
            if (pos.* + slen + 1 > bytes.len) return error.InvalidBSON;
            const s = try allocator.dupe(u8, bytes[pos.*..][0..slen]);
            pos.* += slen + 1;
            return .{ .string = s };
        },
        .int32 => {
            if (pos.* + 4 > bytes.len) return error.InvalidBSON;
            const val = readI32(bytes[pos.*..][0..4]);
            pos.* += 4;
            return .{ .integer = val };
        },
        .timestamp => {
            if (pos.* + 8 > bytes.len) return error.InvalidBSON;
            const val = readI64(bytes[pos.*..][0..8]);
            pos.* += 8;
            return .{ .integer = val };
        },
        .int64 => {
            if (pos.* + 8 > bytes.len) return error.InvalidBSON;
            const val = readI64(bytes[pos.*..][0..8]);
            pos.* += 8;
            return .{ .integer = val };
        },
        .decimal128 => {
            // 128-bit IEEE 754 decimal: 16 bytes
            if (pos.* + 16 > bytes.len) return error.InvalidBSON;
            // Represent as float by reading the low and high 64-bit parts.
            // This is lossy but avoids introducing a new value type.
            const low = readU64(bytes[pos.*..][0..8]);
            const high = readU64(bytes[pos.* + 8 ..][0..8]);
            pos.* += 16;
            _ = low;
            _ = high;
            // TODO: proper Decimal128 decoding; for now return null to avoid data loss
            return .null;
        },
        .min_key, .max_key => {
            // Zero-length values used in range queries and sharding
            return .null;
        },
        // Deprecated types — skip their data to avoid crashing on legacy documents
        .undefined => {
            // Zero-length deprecated type
            return .null;
        },
        .db_pointer => {
            // Deprecated: string (int32 len + bytes + null) + 12-byte ObjectId
            if (pos.* + 4 > bytes.len) return error.InvalidBSON;
            const str_len = readI32(bytes[pos.*..][0..4]);
            pos.* += 4;
            if (str_len < 1) return error.InvalidBSON;
            const slen: usize = @intCast(str_len);
            if (pos.* + slen + 12 > bytes.len) return error.InvalidBSON;
            pos.* += slen + 12;
            return .null;
        },
        .symbol => {
            // Deprecated: same wire format as string
            if (pos.* + 4 > bytes.len) return error.InvalidBSON;
            const str_len = readI32(bytes[pos.*..][0..4]);
            pos.* += 4;
            if (str_len < 1) return error.InvalidBSON;
            const slen: usize = @intCast(str_len - 1);
            if (pos.* + slen + 1 > bytes.len) return error.InvalidBSON;
            const s = try allocator.dupe(u8, bytes[pos.*..][0..slen]);
            pos.* += slen + 1;
            return .{ .string = s };
        },
        .code_with_scope => {
            // Deprecated: int32 total length + string + document
            if (pos.* + 4 > bytes.len) return error.InvalidBSON;
            const total_len = readI32(bytes[pos.*..][0..4]);
            if (total_len < 14) return error.InvalidBSON;
            const tlen: usize = @intCast(total_len);
            if (pos.* + tlen > bytes.len) return error.InvalidBSON;
            pos.* += tlen;
            return .null;
        },
        _ => return error.InvalidBSON,
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
    try buf.append(allocator, @intFromEnum(BsonType.object_id));
    try buf.appendSlice(allocator, "_id");
    try buf.append(allocator, 0);
    try buf.appendNTimes(allocator, 0xAB, 12); // 12 bytes of ObjectId

    // A normal field
    try buf.append(allocator, @intFromEnum(BsonType.string));
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

// --- Helper: build a single-element BSON document from raw bytes ---
fn buildBsonDoc(allocator: Allocator, type_byte: u8, field_name: []const u8, value_bytes: []const u8) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    try buf.appendNTimes(allocator, 0, 4); // size placeholder
    try buf.append(allocator, type_byte);
    try buf.appendSlice(allocator, field_name);
    try buf.append(allocator, 0); // cstring null
    try buf.appendSlice(allocator, value_bytes);
    try buf.append(allocator, 0); // doc terminator
    const size: i32 = @intCast(buf.items.len);
    @memcpy(buf.items[0..4], std.mem.asBytes(&std.mem.nativeToLittle(i32, size)));
    return buf.toOwnedSlice(allocator);
}

// --- encodeValue tests ---

test "encodeValue: object value passes through to encode" {
    const allocator = std.testing.allocator;
    var doc = ObjectMap.init(allocator);
    defer doc.deinit();
    try doc.put("x", .{ .integer = 1 });

    const bytes = try encodeValue(allocator, .{ .object = doc });
    defer allocator.free(bytes);

    var decoded = try decode(allocator, bytes);
    defer freeObjectMap(allocator, &decoded);
    try std.testing.expectEqual(@as(i64, 1), decoded.get("x").?.integer);
}

test "encodeValue: non-object value wraps in document" {
    const allocator = std.testing.allocator;
    const bytes = try encodeValue(allocator, .{ .integer = 42 });
    defer allocator.free(bytes);

    var decoded = try decode(allocator, bytes);
    defer freeObjectMap(allocator, &decoded);
    try std.testing.expectEqual(@as(i64, 42), decoded.get("").?.integer);
}

// --- number_string encoding ---

test "BSON encode/decode: number_string encodes as string" {
    const allocator = std.testing.allocator;
    var doc = ObjectMap.init(allocator);
    defer doc.deinit();
    try doc.put("n", .{ .number_string = "123.456" });

    const encoded = try encode(allocator, doc);
    defer allocator.free(encoded);

    var decoded = try decode(allocator, encoded);
    defer freeObjectMap(allocator, &decoded);
    try std.testing.expectEqualStrings("123.456", decoded.get("n").?.string);
}

// --- decode error paths ---

test "BSON decode: too short returns InvalidBSON" {
    try std.testing.expectError(error.InvalidBSON, decode(std.testing.allocator, &[_]u8{ 0, 0, 0 }));
}

test "BSON decode: bad size returns InvalidBSON" {
    // Size says 100 but only 5 bytes provided
    const bad = [_]u8{ 100, 0, 0, 0, 0 };
    try std.testing.expectError(error.InvalidBSON, decode(std.testing.allocator, &bad));
}

test "BSON decode: size too small returns InvalidBSON" {
    const bad = [_]u8{ 3, 0, 0, 0, 0 };
    try std.testing.expectError(error.InvalidBSON, decode(std.testing.allocator, &bad));
}

test "BSON decode: unknown type byte returns InvalidBSON" {
    const allocator = std.testing.allocator;
    const doc = try buildBsonDoc(allocator, 0xFE, "x", &.{});
    defer allocator.free(doc);
    try std.testing.expectError(error.InvalidBSON, decode(allocator, doc));
}

// --- decode: binary type ---

test "BSON decode: binary" {
    const allocator = std.testing.allocator;
    var value_bytes: [7]u8 = undefined;
    // int32 length = 2
    @memcpy(value_bytes[0..4], std.mem.asBytes(&std.mem.nativeToLittle(i32, 2)));
    value_bytes[4] = 0x00; // subtype generic
    value_bytes[5] = 0xCA;
    value_bytes[6] = 0xFE;

    const doc = try buildBsonDoc(allocator, @intFromEnum(BsonType.binary), "b", &value_bytes);
    defer allocator.free(doc);

    var decoded = try decode(allocator, doc);
    defer freeObjectMap(allocator, &decoded);
    const s = decoded.get("b").?.string;
    try std.testing.expectEqual(@as(u8, 0xCA), s[0]);
    try std.testing.expectEqual(@as(u8, 0xFE), s[1]);
}

// --- decode: datetime ---

test "BSON decode: datetime" {
    const allocator = std.testing.allocator;
    const ms: i64 = 1_700_000_000_000;
    const value_bytes = std.mem.asBytes(&std.mem.nativeToLittle(i64, ms));
    const doc = try buildBsonDoc(allocator, @intFromEnum(BsonType.datetime), "dt", value_bytes);
    defer allocator.free(doc);

    var decoded = try decode(allocator, doc);
    defer freeObjectMap(allocator, &decoded);
    try std.testing.expectEqual(ms, decoded.get("dt").?.integer);
}

// --- decode: timestamp ---

test "BSON decode: timestamp" {
    const allocator = std.testing.allocator;
    const ts: i64 = 42;
    const value_bytes = std.mem.asBytes(&std.mem.nativeToLittle(i64, ts));
    const doc = try buildBsonDoc(allocator, @intFromEnum(BsonType.timestamp), "ts", value_bytes);
    defer allocator.free(doc);

    var decoded = try decode(allocator, doc);
    defer freeObjectMap(allocator, &decoded);
    try std.testing.expectEqual(ts, decoded.get("ts").?.integer);
}

// --- decode: regex ---

test "BSON decode: regex returns null" {
    const allocator = std.testing.allocator;
    // pattern "ab" + null + options "i" + null
    const value_bytes = [_]u8{ 'a', 'b', 0, 'i', 0 };
    const doc = try buildBsonDoc(allocator, @intFromEnum(BsonType.regex), "r", &value_bytes);
    defer allocator.free(doc);

    var decoded = try decode(allocator, doc);
    defer freeObjectMap(allocator, &decoded);
    try std.testing.expect(decoded.get("r").? == .null);
}

// --- decode: javascript ---

test "BSON decode: javascript decoded as string" {
    const allocator = std.testing.allocator;
    const code = "return 1";
    var value_bytes: [4 + code.len + 1]u8 = undefined;
    const len: i32 = @intCast(code.len + 1);
    @memcpy(value_bytes[0..4], std.mem.asBytes(&std.mem.nativeToLittle(i32, len)));
    @memcpy(value_bytes[4..][0..code.len], code);
    value_bytes[4 + code.len] = 0;

    const doc = try buildBsonDoc(allocator, @intFromEnum(BsonType.javascript), "js", &value_bytes);
    defer allocator.free(doc);

    var decoded = try decode(allocator, doc);
    defer freeObjectMap(allocator, &decoded);
    try std.testing.expectEqualStrings("return 1", decoded.get("js").?.string);
}

// --- decode: decimal128 ---

test "BSON decode: decimal128 returns null" {
    const allocator = std.testing.allocator;
    const value_bytes = [_]u8{0} ** 16;
    const doc = try buildBsonDoc(allocator, @intFromEnum(BsonType.decimal128), "d", &value_bytes);
    defer allocator.free(doc);

    var decoded = try decode(allocator, doc);
    defer freeObjectMap(allocator, &decoded);
    try std.testing.expect(decoded.get("d").? == .null);
}

// --- decode: min_key / max_key ---

test "BSON decode: min_key returns null" {
    const allocator = std.testing.allocator;
    const doc = try buildBsonDoc(allocator, @intFromEnum(BsonType.min_key), "mk", &.{});
    defer allocator.free(doc);

    var decoded = try decode(allocator, doc);
    defer freeObjectMap(allocator, &decoded);
    try std.testing.expect(decoded.get("mk").? == .null);
}

test "BSON decode: max_key returns null" {
    const allocator = std.testing.allocator;
    const doc = try buildBsonDoc(allocator, @intFromEnum(BsonType.max_key), "mk", &.{});
    defer allocator.free(doc);

    var decoded = try decode(allocator, doc);
    defer freeObjectMap(allocator, &decoded);
    try std.testing.expect(decoded.get("mk").? == .null);
}

// --- decode: deprecated types ---

test "BSON decode: undefined returns null" {
    const allocator = std.testing.allocator;
    const doc = try buildBsonDoc(allocator, @intFromEnum(BsonType.undefined), "u", &.{});
    defer allocator.free(doc);

    var decoded = try decode(allocator, doc);
    defer freeObjectMap(allocator, &decoded);
    try std.testing.expect(decoded.get("u").? == .null);
}

test "BSON decode: symbol decoded as string" {
    const allocator = std.testing.allocator;
    const sym = "my_sym";
    var value_bytes: [4 + sym.len + 1]u8 = undefined;
    const len: i32 = @intCast(sym.len + 1);
    @memcpy(value_bytes[0..4], std.mem.asBytes(&std.mem.nativeToLittle(i32, len)));
    @memcpy(value_bytes[4..][0..sym.len], sym);
    value_bytes[4 + sym.len] = 0;

    const doc = try buildBsonDoc(allocator, @intFromEnum(BsonType.symbol), "s", &value_bytes);
    defer allocator.free(doc);

    var decoded = try decode(allocator, doc);
    defer freeObjectMap(allocator, &decoded);
    try std.testing.expectEqualStrings("my_sym", decoded.get("s").?.string);
}

test "BSON decode: db_pointer skipped as null" {
    const allocator = std.testing.allocator;
    // string "ns" (len=3 including null) + 12-byte ObjectId
    var value_bytes: [4 + 3 + 12]u8 = undefined;
    const len: i32 = 3;
    @memcpy(value_bytes[0..4], std.mem.asBytes(&std.mem.nativeToLittle(i32, len)));
    value_bytes[4] = 'n';
    value_bytes[5] = 's';
    value_bytes[6] = 0;
    @memset(value_bytes[7..19], 0xAB); // 12 byte ObjectId

    const doc = try buildBsonDoc(allocator, @intFromEnum(BsonType.db_pointer), "p", &value_bytes);
    defer allocator.free(doc);

    var decoded = try decode(allocator, doc);
    defer freeObjectMap(allocator, &decoded);
    try std.testing.expect(decoded.get("p").? == .null);
}

test "BSON decode: code_with_scope skipped as null" {
    const allocator = std.testing.allocator;
    // int32 total_len = 14 (minimum: 4 len + 4 str_len + 1 str_null + 5 empty_doc)
    // string: len=1 + null
    // scope: empty doc (5 bytes)
    var value_bytes: [14]u8 = undefined;
    @memcpy(value_bytes[0..4], std.mem.asBytes(&std.mem.nativeToLittle(i32, 14)));
    // string length = 1 (just null terminator)
    @memcpy(value_bytes[4..8], std.mem.asBytes(&std.mem.nativeToLittle(i32, 1)));
    value_bytes[8] = 0; // string null terminator
    // empty document: size=5 + null terminator
    @memcpy(value_bytes[9..13], std.mem.asBytes(&std.mem.nativeToLittle(i32, 5)));
    value_bytes[13] = 0; // doc null terminator

    const doc = try buildBsonDoc(allocator, @intFromEnum(BsonType.code_with_scope), "cs", &value_bytes);
    defer allocator.free(doc);

    var decoded = try decode(allocator, doc);
    defer freeObjectMap(allocator, &decoded);
    try std.testing.expect(decoded.get("cs").? == .null);
}

// --- decode: non-_id ObjectId field ---

test "BSON decode: non-_id ObjectId returns null" {
    const allocator = std.testing.allocator;
    const value_bytes = [_]u8{0xAB} ** 12;
    const doc = try buildBsonDoc(allocator, @intFromEnum(BsonType.object_id), "ref", &value_bytes);
    defer allocator.free(doc);

    var decoded = try decode(allocator, doc);
    defer freeObjectMap(allocator, &decoded);
    try std.testing.expect(decoded.get("ref").? == .null);
}

// --- cloneValue coverage ---

test "cloneValue: number_string" {
    const allocator = std.testing.allocator;
    const cloned = try cloneValue(allocator, .{ .number_string = "99" });
    defer freeValue(allocator, cloned);
    try std.testing.expectEqualStrings("99", cloned.number_string);
}

test "cloneValue: array" {
    const allocator = std.testing.allocator;

    var arr = Array.init(allocator);
    try arr.append(.{ .integer = 1 });
    try arr.append(.{ .integer = 2 });
    defer arr.deinit();

    const cloned = try cloneValue(allocator, .{ .array = arr });
    defer freeValue(allocator, cloned);

    try std.testing.expectEqual(@as(usize, 2), cloned.array.items.len);
    try std.testing.expectEqual(@as(i64, 1), cloned.array.items[0].integer);
    try std.testing.expectEqual(@as(i64, 2), cloned.array.items[1].integer);
}

test "cloneValue: object" {
    const allocator = std.testing.allocator;

    var obj = ObjectMap.init(allocator);
    try obj.put("k", .{ .integer = 7 });
    defer obj.deinit();

    const cloned = try cloneValue(allocator, .{ .object = obj });
    defer freeValue(allocator, cloned);

    try std.testing.expectEqual(@as(i64, 7), cloned.object.get("k").?.integer);
}

// --- freeValue coverage for nested structures ---

test "freeValue: nested array with strings" {
    const allocator = std.testing.allocator;
    var arr = Array.init(allocator);
    const s = try allocator.dupe(u8, "hello");
    try arr.append(.{ .string = s });
    freeValue(allocator, .{ .array = arr });
}

test "freeValue: nested object" {
    const allocator = std.testing.allocator;
    var obj = ObjectMap.init(allocator);
    const key = try allocator.dupe(u8, "k");
    const val = try allocator.dupe(u8, "v");
    try obj.put(key, .{ .string = val });
    freeValue(allocator, .{ .object = obj });
}

test "freeValue: number_string" {
    const allocator = std.testing.allocator;
    const s = try allocator.dupe(u8, "42");
    freeValue(allocator, .{ .number_string = s });
}
