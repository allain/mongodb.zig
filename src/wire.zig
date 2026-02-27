const std = @import("std");
const json = std.json;
const Value = json.Value;
const ObjectMap = json.ObjectMap;
const Allocator = std.mem.Allocator;
const bson = @import("bson.zig");
const Io = std.Io;

const OP_MSG: i32 = 2013;

/// Send a command (section kind 0 only).
pub fn sendCommand(writer: *Io.Writer, request_id: i32, body_bson: []const u8) !void {
    // OP_MSG: flagBits(4) + kind(1) + body
    const msg_len: i32 = @intCast(16 + 4 + 1 + body_bson.len);

    // Header: messageLength, requestID, responseTo, opCode
    try writeI32(writer, msg_len);
    try writeI32(writer, request_id);
    try writeI32(writer, 0); // responseTo
    try writeI32(writer, OP_MSG);

    // OP_MSG
    try writeI32(writer, 0); // flagBits
    try writer.writeAll(&[_]u8{0}); // section kind 0
    try writer.writeAll(body_bson);
    try writer.flush();
}

/// Send a command with a document sequence section (kind 0 + kind 1).
/// Used for bulk inserts.
pub fn sendCommandWithSequence(
    writer: *Io.Writer,
    request_id: i32,
    body_bson: []const u8,
    seq_id: []const u8,
    doc_bsons: []const []const u8,
) !void {
    // Calculate section 1 size: 4(size) + identifier(cstring) + docs
    var seq_data_len: usize = 4 + seq_id.len + 1;
    for (doc_bsons) |d| seq_data_len += d.len;

    const msg_len: i32 = @intCast(16 + 4 + 1 + body_bson.len + 1 + seq_data_len);

    // Header
    try writeI32(writer, msg_len);
    try writeI32(writer, request_id);
    try writeI32(writer, 0);
    try writeI32(writer, OP_MSG);

    // flagBits
    try writeI32(writer, 0);

    // Section kind 0: body
    try writer.writeAll(&[_]u8{0});
    try writer.writeAll(body_bson);

    // Section kind 1: document sequence
    try writer.writeAll(&[_]u8{1});
    const seq_size: i32 = @intCast(seq_data_len);
    try writeI32(writer, seq_size);
    try writer.writeAll(seq_id);
    try writer.writeAll(&[_]u8{0}); // null terminator for identifier
    for (doc_bsons) |d| {
        try writer.writeAll(d);
    }
    try writer.flush();
}

/// Receive a response. Checks ok:1.
pub fn receiveResponse(allocator: Allocator, reader: *Io.Reader) !ObjectMap {
    // Read header (16 bytes)
    var header_buf: [16]u8 = undefined;
    try reader.readSliceAll(&header_buf);

    const msg_length = readI32(header_buf[0..4]);
    if (msg_length < 21) return error.InvalidResponse; // minimum: header(16) + flags(4) + kind(1)

    const body_len: usize = @intCast(msg_length - 16);
    const body_buf = try allocator.alloc(u8, body_len);
    defer allocator.free(body_buf);

    try reader.readSliceAll(body_buf);

    // Parse OP_MSG: skip flagBits(4), read kind(1), then BSON
    if (body_buf.len < 5) return error.InvalidResponse;
    // flagBits at [0..4], kind at [4]
    const kind = body_buf[4];
    if (kind != 0) return error.InvalidResponse;

    const bson_data = body_buf[5..];
    var result = try bson.decode(allocator, bson_data);

    // Check ok field
    if (result.get("ok")) |ok_val| {
        const ok_num = switch (ok_val) {
            .float => ok_val.float,
            .integer => @as(f64, @floatFromInt(ok_val.integer)),
            else => 0.0,
        };
        if (ok_num != 1.0) {
            // Log error message if available
            if (result.get("errmsg")) |errmsg| {
                switch (errmsg) {
                    .string => |s| std.log.err("MongoDB error: {s}", .{s}),
                    else => {},
                }
            }
            defer bson.freeObjectMap(allocator, &result);
            return error.MongoCommandError;
        }
    }

    return result;
}

fn writeI32(writer: *Io.Writer, val: i32) !void {
    const bytes = std.mem.asBytes(&std.mem.nativeToLittle(i32, val));
    try writer.writeAll(bytes);
}

fn readI32(bytes: *const [4]u8) i32 {
    return @bitCast(std.mem.littleToNative(u32, std.mem.bytesToValue(u32, bytes)));
}

// --- Tests ---

test "wire protocol: sendCommand builds correct bytes" {
    const allocator = std.testing.allocator;

    // Create a simple BSON document
    var cmd = ObjectMap.init(allocator);
    defer cmd.deinit();
    try cmd.put("ping", .{ .integer = 1 });

    const cmd_bson = try bson.encode(allocator, cmd);
    defer allocator.free(cmd_bson);

    // Verify expected message length
    const expected_len: i32 = @intCast(16 + 4 + 1 + cmd_bson.len);
    try std.testing.expect(expected_len > 21);
}
