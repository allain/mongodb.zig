pub const Client = @import("client.zig").Client;
pub const FindOpts = @import("client.zig").FindOpts;
pub const Connection = @import("connection.zig").Connection;
pub const MongoUri = @import("connection.zig").MongoUri;
pub const parseUri = @import("connection.zig").parseUri;
pub const bson = @import("bson.zig");

test {
    _ = @import("bson.zig");
    _ = @import("wire.zig");
    _ = @import("connection.zig");
    _ = @import("client.zig");
}
