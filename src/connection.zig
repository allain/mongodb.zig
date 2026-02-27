const std = @import("std");
const json = std.json;
const Value = json.Value;
const ObjectMap = json.ObjectMap;
const Allocator = std.mem.Allocator;
const bson = @import("bson.zig");
const wire = @import("wire.zig");
const Io = std.Io;
const net = Io.net;
const linux = std.os.linux;

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;


/// Parsed components of a MongoDB connection URI.
pub const MongoUri = struct {
    host: []const u8,
    port: u16,
    database: []const u8,
    username: []const u8,
    password: []const u8,
    auth_source: []const u8,
};

/// Parse a MongoDB URI string.
/// Format: mongodb://[user:pass@]host[:port]/database[?authSource=admin]
pub fn parseUri(uri_str: []const u8) !MongoUri {
    var remaining = uri_str;

    // Strip scheme
    if (std.mem.startsWith(u8, remaining, "mongodb://")) {
        remaining = remaining["mongodb://".len..];
    } else {
        return error.InvalidUri;
    }

    // Parse credentials
    var username: []const u8 = "";
    var password: []const u8 = "";
    if (std.mem.indexOf(u8, remaining, "@")) |at_idx| {
        const creds = remaining[0..at_idx];
        remaining = remaining[at_idx + 1 ..];
        if (std.mem.indexOf(u8, creds, ":")) |colon| {
            username = creds[0..colon];
            password = creds[colon + 1 ..];
        } else {
            username = creds;
        }
    }

    // Parse query params (before splitting host/db)
    var auth_source: []const u8 = "admin";
    var path_and_query = remaining;
    if (std.mem.indexOf(u8, remaining, "?")) |qmark| {
        const query = remaining[qmark + 1 ..];
        path_and_query = remaining[0..qmark];
        // Simple query param parser
        var params = std.mem.splitScalar(u8, query, '&');
        while (params.next()) |param| {
            if (std.mem.startsWith(u8, param, "authSource=")) {
                auth_source = param["authSource=".len..];
            }
        }
    }

    // Parse host:port/database
    var host: []const u8 = "localhost";
    var port: u16 = 27017;
    var database: []const u8 = "test";

    // Split host+port from database
    if (std.mem.indexOf(u8, path_and_query, "/")) |slash| {
        const host_part = path_and_query[0..slash];
        database = path_and_query[slash + 1 ..];

        if (std.mem.indexOf(u8, host_part, ":")) |colon| {
            host = host_part[0..colon];
            port = std.fmt.parseInt(u16, host_part[colon + 1 ..], 10) catch 27017;
        } else {
            host = host_part;
        }
    } else {
        // No database specified
        const host_part = path_and_query;
        if (std.mem.indexOf(u8, host_part, ":")) |colon| {
            host = host_part[0..colon];
            port = std.fmt.parseInt(u16, host_part[colon + 1 ..], 10) catch 27017;
        } else {
            if (host_part.len > 0) host = host_part;
        }
    }

    return .{
        .host = host,
        .port = port,
        .database = database,
        .username = username,
        .password = password,
        .auth_source = auth_source,
    };
}

/// Simple spinlock mutex for thread-safe command execution.
const Mutex = struct {
    state: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    pub fn lock(self: *Mutex) void {
        while (self.state.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
        }
    }

    pub fn unlock(self: *Mutex) void {
        self.state.store(0, .release);
    }
};

fn sleep(ns: u64) void {
    var req: linux.timespec = .{
        .sec = @intCast(ns / std.time.ns_per_s),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
    while (true) {
        const rc = linux.nanosleep(&req, &req);
        if (rc == 0) return;
    }
}

fn randomBytes(buf: []u8) void {
    _ = linux.getrandom(buf.ptr, buf.len, 0);
}

/// Options controlling connection retry behavior.
pub const ConnectOptions = struct {
    max_retries: u32 = 60,
    retry_delay_ms: u32 = 500,
    backoff_ratio: u32 = 2,
};

/// A TCP connection to a MongoDB server with SCRAM-SHA-256 authentication.
pub const Connection = struct {
    stream: net.Stream,
    io: Io,
    allocator: Allocator,
    uri: MongoUri,
    next_request_id: i32 = 1,
    mutex: Mutex = .{},

    /// Connect to MongoDB with retries and exponential backoff.
    pub fn connect(allocator: Allocator, io: Io, uri: MongoUri, options: ConnectOptions) !Connection {
        var attempts: u32 = 0;
        var delay_ms: u64 = options.retry_delay_ms;
        while (attempts < options.max_retries) : (attempts += 1) {
            const stream = tcpConnect(uri.host, uri.port, io) catch {
                std.log.warn("MongoDB connection attempt {d}/{d} failed, retrying in {d}ms...", .{ attempts + 1, options.max_retries, delay_ms });
                sleep(delay_ms * std.time.ns_per_ms);
                delay_ms *|= options.backoff_ratio;
                continue;
            };
            var conn = Connection{
                .stream = stream,
                .io = io,
                .allocator = allocator,
                .uri = uri,
            };
            conn.handshake() catch {
                conn.stream.close(io);
                sleep(delay_ms * std.time.ns_per_ms);
                delay_ms *|= options.backoff_ratio;
                continue;
            };
            if (uri.username.len > 0) {
                conn.authenticate() catch {
                    conn.stream.close(io);
                    sleep(delay_ms * std.time.ns_per_ms);
                    delay_ms *|= options.backoff_ratio;
                    continue;
                };
            }
            return conn;
        }
        return error.ConnectionFailed;
    }

    /// Close the underlying TCP connection.
    pub fn close(self: *Connection) void {
        self.stream.close(self.io);
    }

    /// Run a command against a database. Returns the response document.
    pub fn runCommand(self: *Connection, allocator: Allocator, db: []const u8, cmd: ObjectMap) !ObjectMap {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Build command with $db field
        var cmd_with_db = ObjectMap.init(allocator);

        // Copy all entries from cmd (borrowing, not cloning)
        var it = cmd.iterator();
        while (it.next()) |entry| {
            cmd_with_db.put(entry.key_ptr.*, entry.value_ptr.*) catch |err| {
                cmd_with_db.deinit();
                return err;
            };
        }
        const db_key = allocator.dupe(u8, "$db") catch |err| {
            cmd_with_db.deinit();
            return err;
        };
        cmd_with_db.put(db_key, .{ .string = db }) catch |err| {
            allocator.free(db_key);
            cmd_with_db.deinit();
            return err;
        };

        const cmd_bson = bson.encode(allocator, cmd_with_db) catch |err| {
            allocator.free(db_key);
            cmd_with_db.deinit();
            return err;
        };
        defer allocator.free(cmd_bson);

        // Clean up the borrowed map — only free the $db key we allocated
        allocator.free(db_key);
        cmd_with_db.deinit();

        const req_id = self.next_request_id;
        self.next_request_id += 1;

        var write_buf: [8192]u8 = undefined;
        var read_buf: [8192]u8 = undefined;
        var writer = self.stream.writer(self.io, &write_buf);
        var reader = self.stream.reader(self.io, &read_buf);

        try wire.sendCommand(&writer.interface, req_id, cmd_bson);
        return wire.receiveResponse(allocator, &reader.interface);
    }

    /// Run a command with a document sequence section.
    pub fn runCommandWithSequence(
        self: *Connection,
        allocator: Allocator,
        db: []const u8,
        cmd: ObjectMap,
        seq_id: []const u8,
        doc_bsons: []const []const u8,
    ) !ObjectMap {
        self.mutex.lock();
        defer self.mutex.unlock();

        var cmd_with_db = ObjectMap.init(allocator);

        var it = cmd.iterator();
        while (it.next()) |entry| {
            cmd_with_db.put(entry.key_ptr.*, entry.value_ptr.*) catch |err| {
                cmd_with_db.deinit();
                return err;
            };
        }
        const db_key = allocator.dupe(u8, "$db") catch |err| {
            cmd_with_db.deinit();
            return err;
        };
        cmd_with_db.put(db_key, .{ .string = db }) catch |err| {
            allocator.free(db_key);
            cmd_with_db.deinit();
            return err;
        };

        const cmd_bson = bson.encode(allocator, cmd_with_db) catch |err| {
            allocator.free(db_key);
            cmd_with_db.deinit();
            return err;
        };
        defer allocator.free(cmd_bson);

        allocator.free(db_key);
        cmd_with_db.deinit();

        const req_id = self.next_request_id;
        self.next_request_id += 1;

        var write_buf: [8192]u8 = undefined;
        var read_buf: [8192]u8 = undefined;
        var writer = self.stream.writer(self.io, &write_buf);
        var reader = self.stream.reader(self.io, &read_buf);

        try wire.sendCommandWithSequence(&writer.interface, req_id, cmd_bson, seq_id, doc_bsons);
        return wire.receiveResponse(allocator, &reader.interface);
    }

    fn handshake(self: *Connection) !void {
        var cmd = ObjectMap.init(self.allocator);
        defer cmd.deinit();
        try cmd.put("hello", .{ .integer = 1 });

        var response = try self.runCommand(self.allocator, "admin", cmd);
        defer bson.freeObjectMap(self.allocator, &response);
    }

    fn authenticate(self: *Connection) !void {
        try scramSha256Auth(self);
    }
};

/// Resolve a hostname and connect via std.Io.net, returning a Stream.
fn tcpConnect(host: []const u8, port: u16, io: Io) !net.Stream {
    const host_name: net.HostName = .{ .bytes = host };
    return host_name.connect(io, port, .{ .mode = .stream }) catch error.ConnectionFailed;
}

/// SCRAM-SHA-256 authentication.
fn scramSha256Auth(conn: *Connection) !void {
    const allocator = conn.allocator;

    // Generate client nonce
    var nonce_bytes: [24]u8 = undefined;
    randomBytes(&nonce_bytes);
    const client_nonce = std.base64.standard.Encoder.calcSize(nonce_bytes.len);
    var client_nonce_buf: [36]u8 = undefined; // base64 of 24 bytes = 32 chars, leave room
    const client_nonce_str = client_nonce_buf[0..client_nonce];
    _ = std.base64.standard.Encoder.encode(client_nonce_str, &nonce_bytes);

    // Build client-first-message
    const client_first_bare = try std.fmt.allocPrint(allocator, "n={s},r={s}", .{ conn.uri.username, client_nonce_str });
    defer allocator.free(client_first_bare);
    const client_first_msg = try std.fmt.allocPrint(allocator, "n,,{s}", .{client_first_bare});
    defer allocator.free(client_first_msg);

    // saslStart
    {
        const payload_b64_size = std.base64.standard.Encoder.calcSize(client_first_msg.len);
        const payload_b64 = try allocator.alloc(u8, payload_b64_size);
        defer allocator.free(payload_b64);
        _ = std.base64.standard.Encoder.encode(payload_b64, client_first_msg);

        var cmd = ObjectMap.init(allocator);
        defer cmd.deinit();
        try cmd.put("saslStart", .{ .integer = 1 });
        try cmd.put("mechanism", .{ .string = "SCRAM-SHA-256" });
        try cmd.put("payload", .{ .string = payload_b64 });

        var response = try conn.runCommand(allocator, conn.uri.auth_source, cmd);
        defer bson.freeObjectMap(allocator, &response);

        const server_payload_b64 = response.get("payload").?.string;

        // Decode server response
        const decoded_size = try std.base64.standard.Decoder.calcSizeForSlice(server_payload_b64);
        const server_first = try allocator.alloc(u8, decoded_size);
        defer allocator.free(server_first);
        try std.base64.standard.Decoder.decode(server_first, server_payload_b64);

        // Parse server-first-message: r=<nonce>,s=<salt>,i=<iterations>
        var server_nonce: []const u8 = "";
        var salt_b64: []const u8 = "";
        var iterations: u32 = 4096;

        var parts = std.mem.splitScalar(u8, server_first, ',');
        while (parts.next()) |part| {
            if (std.mem.startsWith(u8, part, "r=")) {
                server_nonce = part[2..];
            } else if (std.mem.startsWith(u8, part, "s=")) {
                salt_b64 = part[2..];
            } else if (std.mem.startsWith(u8, part, "i=")) {
                iterations = std.fmt.parseInt(u32, part[2..], 10) catch 4096;
            }
        }

        // Decode salt
        const salt_size = try std.base64.standard.Decoder.calcSizeForSlice(salt_b64);
        const salt = try allocator.alloc(u8, salt_size);
        defer allocator.free(salt);
        try std.base64.standard.Decoder.decode(salt, salt_b64);

        // Compute PBKDF2
        const salted_password = pbkdf2HmacSha256(conn.uri.password, salt, iterations);

        // ClientKey = HMAC(SaltedPassword, "Client Key")
        var client_key: [32]u8 = undefined;
        HmacSha256.create(&client_key, "Client Key", &salted_password);

        // StoredKey = SHA256(ClientKey)
        var stored_key: [32]u8 = undefined;
        Sha256.hash(&client_key, &stored_key, .{});

        // AuthMessage = client-first-bare + "," + server-first + "," + client-final-without-proof
        const channel_binding = "biws"; // base64("n,,") = "biws"... actually base64 of "n,,"
        // Compute proper channel binding
        const cb_b64_size = std.base64.standard.Encoder.calcSize(3); // "n,," is 3 bytes
        var cb_b64_buf: [8]u8 = undefined;
        const cb_b64 = cb_b64_buf[0..cb_b64_size];
        _ = std.base64.standard.Encoder.encode(cb_b64, "n,,");

        const client_final_without_proof = try std.fmt.allocPrint(allocator, "c={s},r={s}", .{ cb_b64, server_nonce });
        defer allocator.free(client_final_without_proof);

        const auth_message = try std.fmt.allocPrint(allocator, "{s},{s},{s}", .{ client_first_bare, server_first, client_final_without_proof });
        defer allocator.free(auth_message);

        // ClientSignature = HMAC(StoredKey, AuthMessage)
        var client_signature: [32]u8 = undefined;
        HmacSha256.create(&client_signature, auth_message, &stored_key);

        // ClientProof = ClientKey XOR ClientSignature
        var client_proof: [32]u8 = undefined;
        for (&client_proof, client_key, client_signature) |*p, k, s| {
            p.* = k ^ s;
        }

        // Encode proof
        const proof_b64_size = std.base64.standard.Encoder.calcSize(32);
        var proof_b64_buf: [48]u8 = undefined;
        const proof_b64 = proof_b64_buf[0..proof_b64_size];
        _ = std.base64.standard.Encoder.encode(proof_b64, &client_proof);

        const client_final = try std.fmt.allocPrint(allocator, "{s},p={s}", .{ client_final_without_proof, proof_b64 });
        defer allocator.free(client_final);

        // saslContinue
        const conversation_id = response.get("conversationId");

        const final_b64_size = std.base64.standard.Encoder.calcSize(client_final.len);
        const final_b64 = try allocator.alloc(u8, final_b64_size);
        defer allocator.free(final_b64);
        _ = std.base64.standard.Encoder.encode(final_b64, client_final);

        var cmd2 = ObjectMap.init(allocator);
        defer cmd2.deinit();
        try cmd2.put("saslContinue", .{ .integer = 1 });
        if (conversation_id) |cid| {
            try cmd2.put("conversationId", cid);
        }
        try cmd2.put("payload", .{ .string = final_b64 });

        var response2 = try conn.runCommand(allocator, conn.uri.auth_source, cmd2);
        defer bson.freeObjectMap(allocator, &response2);

        // Check if we need one more empty saslContinue (MongoDB sometimes requires it)
        if (response2.get("done")) |done_val| {
            if (done_val == .bool and !done_val.bool) {
                var cmd3 = ObjectMap.init(allocator);
                defer cmd3.deinit();
                try cmd3.put("saslContinue", .{ .integer = 1 });
                if (response2.get("conversationId")) |cid| {
                    try cmd3.put("conversationId", cid);
                }
                // Empty payload
                const empty_b64_size = std.base64.standard.Encoder.calcSize(0);
                var empty_b64_buf: [4]u8 = undefined;
                const empty_b64 = empty_b64_buf[0..empty_b64_size];
                _ = std.base64.standard.Encoder.encode(empty_b64, "");
                try cmd3.put("payload", .{ .string = empty_b64 });

                var response3 = try conn.runCommand(allocator, conn.uri.auth_source, cmd3);
                defer bson.freeObjectMap(allocator, &response3);
            }
        }

        _ = channel_binding;
    }
}

/// PBKDF2 with HMAC-SHA-256.
fn pbkdf2HmacSha256(password: []const u8, salt: []const u8, iterations: u32) [32]u8 {
    // PBKDF2 with dkLen = 32 (one block)
    // U1 = HMAC(password, salt || INT_32_BE(1))
    var salt_with_block_idx: [128]u8 = undefined;
    if (salt.len + 4 > salt_with_block_idx.len) {
        // Fallback for very large salts
        var result: [32]u8 = undefined;
        @memset(&result, 0);
        return result;
    }
    @memcpy(salt_with_block_idx[0..salt.len], salt);
    salt_with_block_idx[salt.len] = 0;
    salt_with_block_idx[salt.len + 1] = 0;
    salt_with_block_idx[salt.len + 2] = 0;
    salt_with_block_idx[salt.len + 3] = 1; // block index 1 (big-endian)

    var u_prev: [32]u8 = undefined;
    HmacSha256.create(&u_prev, salt_with_block_idx[0 .. salt.len + 4], password);

    var result = u_prev;

    var i: u32 = 1;
    while (i < iterations) : (i += 1) {
        var u_next: [32]u8 = undefined;
        HmacSha256.create(&u_next, &u_prev, password);
        for (&result, u_next) |*r, n| {
            r.* ^= n;
        }
        u_prev = u_next;
    }

    return result;
}

// --- Tests ---

// ---------------------------------------------------------------------------
// parseUri tests
// ---------------------------------------------------------------------------

test "parseUri: full URI" {
    const uri = try parseUri("mongodb://user:pass@localhost:27017/mydb?authSource=admin");
    try std.testing.expectEqualStrings("localhost", uri.host);
    try std.testing.expectEqual(@as(u16, 27017), uri.port);
    try std.testing.expectEqualStrings("mydb", uri.database);
    try std.testing.expectEqualStrings("user", uri.username);
    try std.testing.expectEqualStrings("pass", uri.password);
    try std.testing.expectEqualStrings("admin", uri.auth_source);
}

test "parseUri: no auth" {
    const uri = try parseUri("mongodb://localhost:27017/testdb");
    try std.testing.expectEqualStrings("localhost", uri.host);
    try std.testing.expectEqual(@as(u16, 27017), uri.port);
    try std.testing.expectEqualStrings("testdb", uri.database);
    try std.testing.expectEqualStrings("", uri.username);
    try std.testing.expectEqualStrings("", uri.password);
}

test "parseUri: default port" {
    const uri = try parseUri("mongodb://localhost/mydb");
    try std.testing.expectEqualStrings("localhost", uri.host);
    try std.testing.expectEqual(@as(u16, 27017), uri.port);
    try std.testing.expectEqualStrings("mydb", uri.database);
}

test "parseUri: no database" {
    const uri = try parseUri("mongodb://localhost:27017");
    try std.testing.expectEqualStrings("localhost", uri.host);
    try std.testing.expectEqual(@as(u16, 27017), uri.port);
}

test "parseUri: invalid scheme" {
    try std.testing.expectError(error.InvalidUri, parseUri("http://localhost:27017/db"));
    try std.testing.expectError(error.InvalidUri, parseUri("localhost:27017/db"));
    try std.testing.expectError(error.InvalidUri, parseUri(""));
}

test "parseUri: username without password" {
    const uri = try parseUri("mongodb://admin@localhost:27017/mydb");
    try std.testing.expectEqualStrings("admin", uri.username);
    try std.testing.expectEqualStrings("", uri.password);
    try std.testing.expectEqualStrings("localhost", uri.host);
    try std.testing.expectEqual(@as(u16, 27017), uri.port);
    try std.testing.expectEqualStrings("mydb", uri.database);
}

test "parseUri: host only no port no database" {
    const uri = try parseUri("mongodb://myhost");
    try std.testing.expectEqualStrings("myhost", uri.host);
    try std.testing.expectEqual(@as(u16, 27017), uri.port);
    try std.testing.expectEqualStrings("test", uri.database);
}

test "parseUri: host with port no database" {
    const uri = try parseUri("mongodb://myhost:9999");
    try std.testing.expectEqualStrings("myhost", uri.host);
    try std.testing.expectEqual(@as(u16, 9999), uri.port);
    try std.testing.expectEqualStrings("test", uri.database);
}

test "parseUri: custom authSource" {
    const uri = try parseUri("mongodb://user:pass@localhost:27017/mydb?authSource=myauth");
    try std.testing.expectEqualStrings("myauth", uri.auth_source);
}

test "parseUri: default authSource is admin" {
    const uri = try parseUri("mongodb://user:pass@localhost:27017/mydb");
    try std.testing.expectEqualStrings("admin", uri.auth_source);
}

test "parseUri: query params with unknown params" {
    const uri = try parseUri("mongodb://localhost:27017/mydb?retryWrites=true&authSource=custom&w=majority");
    try std.testing.expectEqualStrings("custom", uri.auth_source);
    try std.testing.expectEqualStrings("mydb", uri.database);
}

test "parseUri: credentials with special chars in password" {
    const uri = try parseUri("mongodb://user:p%40ss@localhost/db");
    try std.testing.expectEqualStrings("user", uri.username);
    try std.testing.expectEqualStrings("p%40ss", uri.password);
    try std.testing.expectEqualStrings("localhost", uri.host);
    try std.testing.expectEqualStrings("db", uri.database);
}

test "parseUri: non-standard port" {
    const uri = try parseUri("mongodb://localhost:12345/db");
    try std.testing.expectEqual(@as(u16, 12345), uri.port);
}

test "parseUri: auth with default port and database" {
    const uri = try parseUri("mongodb://root:secret@dbhost/admin");
    try std.testing.expectEqualStrings("root", uri.username);
    try std.testing.expectEqualStrings("secret", uri.password);
    try std.testing.expectEqualStrings("dbhost", uri.host);
    try std.testing.expectEqual(@as(u16, 27017), uri.port);
    try std.testing.expectEqualStrings("admin", uri.database);
}

test "parseUri: empty path after scheme defaults to localhost" {
    const uri = try parseUri("mongodb://");
    try std.testing.expectEqualStrings("localhost", uri.host);
    try std.testing.expectEqual(@as(u16, 27017), uri.port);
    try std.testing.expectEqualStrings("test", uri.database);
}

// ---------------------------------------------------------------------------
// pbkdf2HmacSha256 tests
// ---------------------------------------------------------------------------

test "PBKDF2 produces deterministic output" {
    const result1 = pbkdf2HmacSha256("password", "salt", 1);
    const result2 = pbkdf2HmacSha256("password", "salt", 1);
    try std.testing.expectEqualSlices(u8, &result1, &result2);
}

test "PBKDF2 different passwords produce different output" {
    const r1 = pbkdf2HmacSha256("password1", "salt", 1);
    const r2 = pbkdf2HmacSha256("password2", "salt", 1);
    try std.testing.expect(!std.mem.eql(u8, &r1, &r2));
}

test "PBKDF2 different salts produce different output" {
    const r1 = pbkdf2HmacSha256("password", "salt1", 1);
    const r2 = pbkdf2HmacSha256("password", "salt2", 1);
    try std.testing.expect(!std.mem.eql(u8, &r1, &r2));
}

test "PBKDF2 more iterations produce different output" {
    const r1 = pbkdf2HmacSha256("password", "salt", 1);
    const r2 = pbkdf2HmacSha256("password", "salt", 2);
    try std.testing.expect(!std.mem.eql(u8, &r1, &r2));
}

test "PBKDF2 multiple iterations" {
    const r1 = pbkdf2HmacSha256("password", "salt", 100);
    const r2 = pbkdf2HmacSha256("password", "salt", 100);
    try std.testing.expectEqualSlices(u8, &r1, &r2);
}

test "PBKDF2 RFC 7677 test vector" {
    // RFC 7677 / RFC 6070 PBKDF2-HMAC-SHA-256 test vector:
    // password="password", salt="salt", iterations=4096, dkLen=32
    const expected = [_]u8{
        0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41,
        0xaa, 0x53, 0x0d, 0xb6, 0x84, 0x5c, 0x4c, 0x8d,
        0x96, 0x28, 0x93, 0xa0, 0x01, 0xce, 0x4e, 0x11,
        0xa4, 0x96, 0x38, 0x73, 0xaa, 0x98, 0x13, 0x4a,
    };
    const result = pbkdf2HmacSha256("password", "salt", 4096);
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "PBKDF2 empty password" {
    const r1 = pbkdf2HmacSha256("", "salt", 1);
    const r2 = pbkdf2HmacSha256("", "salt", 1);
    try std.testing.expectEqualSlices(u8, &r1, &r2);
}

test "PBKDF2 empty salt" {
    const r1 = pbkdf2HmacSha256("password", "", 1);
    const r2 = pbkdf2HmacSha256("password", "", 1);
    try std.testing.expectEqualSlices(u8, &r1, &r2);
}

test "PBKDF2 large salt fallback" {
    // Salt larger than 124 bytes (128 - 4) triggers fallback
    const large_salt = "a" ** 125;
    const result = pbkdf2HmacSha256("password", large_salt, 1);
    // Fallback returns all zeros
    const zeros = [_]u8{0} ** 32;
    try std.testing.expectEqualSlices(u8, &zeros, &result);
}

// ---------------------------------------------------------------------------
// Connection failure tests
// ---------------------------------------------------------------------------

test "connect: fails with ConnectionFailed when server is down" {
    const allocator = std.testing.allocator;
    const threaded = try allocator.create(Io.Threaded);
    defer allocator.destroy(threaded);
    threaded.* = Io.Threaded.init(allocator, .{});
    const io = threaded.io();
    const uri = try parseUri("mongodb://127.0.0.1:19/testdb");
    const result = Connection.connect(allocator, io, uri, .{ .max_retries = 1, .retry_delay_ms = 0 });
    try std.testing.expectError(error.ConnectionFailed, result);
}

test "tcpConnect: fails when server is not listening" {
    const allocator = std.testing.allocator;
    const threaded = try allocator.create(Io.Threaded);
    defer allocator.destroy(threaded);
    threaded.* = Io.Threaded.init(allocator, .{});
    const io = threaded.io();
    // Port 19 (chargen) is almost certainly not running on localhost
    const result = tcpConnect("127.0.0.1", 19, io);
    try std.testing.expectError(error.ConnectionFailed, result);
}

test "tcpConnect: fails for unresolvable host" {
    const allocator = std.testing.allocator;
    const threaded = try allocator.create(Io.Threaded);
    defer allocator.destroy(threaded);
    threaded.* = Io.Threaded.init(allocator, .{});
    const io = threaded.io();
    const result = tcpConnect("host.invalid.zzz", 27017, io);
    try std.testing.expectError(error.ConnectionFailed, result);
}
