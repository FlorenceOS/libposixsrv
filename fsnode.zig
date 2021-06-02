const std = @import("std");

/// Node in filesystem tree
pub fn FSNode(comptime T: type, max_name_length: usize) type {
    return struct {
        /// Hashmap key & value type
        pub const HashMapKeyVal = *[]const u8;

        /// Node data
        ref: T = .{},
        /// Name buffer
        name_buf: [max_name_length]u8 = undefined,
        /// Node name. Always points to name_buf
        name: []const u8 = undefined,
        /// Node children
        children: std.HashMapUnmanaged(HashMapKeyVal, HashMapKeyVal, struct {
            pub fn hashFn(k: HashMapKeyVal) u64 {
                return std.hash_map.hashString(k.*);
            }
        }.hashFn, struct {
            pub fn eqlFn(k1: HashMapKeyVal, k2: HashMapKeyVal) bool {
                return std.mem.eql(u8, k1.*, k2.*);
            }
        }.eqlFn, 80) = .{},
        /// Node parent
        parent: ?*@This() = null,
        /// Mount pointer. Points to root dentry of mounted fs if not null
        mount: ?*@This() = null,
        /// Mount link. Points to the directory entry on which fs was mounted if this directory
        /// entry is root of the filesystem
        origin: ?*@This() = null,
        /// Next node in cache
        next_in_cache: ?*@This() = null,
        /// Previous node in cache
        prev_in_cache: ?*@This() = null,
        /// Node reference count
        ref_count: usize = 1,
        /// True if reachable from fs root
        reachable_from_root: bool = true,

        /// Get hashmap key
        pub fn key(self: *@This()) HashMapKeyVal {
            return &self.name;
        }

        /// Get node from key
        pub fn fromKey(k: HashMapKeyVal) *@This() {
            return @fieldParentPtr(@This(), "name", k);
        }

        /// Recursively enter mounts
        /// NOTE: Does not modify reference counts
        pub fn traceMounts(self: *@This()) *@This() {
            var current = self;
            while (current.mount) |mount| : (current = mount) {}
            return current;
        }

        /// Recursively exit from mounted filesystems
        /// NOTE: Does not modify reference counts
        pub fn backtraceMounts(self: *@This()) *@This() {
            var current = self;
            while (current.origin) |origin| : (current = origin) {}
            return current;
        }

        /// Update node's name
        /// NOTE: node should not be inserted in child hashmap
        pub fn updateName(self: *@This(), name: []const u8) void {
            std.debug.assert(name.len <= max_name_length);
            self.name = self.name_buf[0..name.len];
            std.mem.copy(u8, self.name_buf[0..name.len], name);
        }

        /// Looks up node child and traces mounts as needed
        /// NOTE: Does not modify reference counts
        pub fn getChild(self: *@This(), name: []const u8) ?*@This() {
            var slice_buf = name;
            return fromKey(self.children.get(&slice_buf) orelse return null).traceMounts();
        }

        /// Add child node
        /// NOTE: Does not modify reference counts
        pub fn addChild(self: *@This(), child: *@This(), allocator: *std.mem.Allocator) !void {
            child.parent = self;
            try self.children.put(allocator, child.key(), child.key());
        }

        /// Remove child
        /// NOTE: Does not modify reference counts
        pub fn removeChild(self: *@This(), child: *@This()) void {
            if (std.debug.runtime_safety) {
                child.parent = null;
            }
            std.debug.assert(self.children.remove(child.key()) != null);
            child.reachable_from_root = false;
        }

        /// Add mount. This node should not have mount beforehand
        /// NOTE: Does not modify reference counts
        pub fn addMount(self: *@This(), mount: *@This()) void {
            std.debug.assert(self.mount == null);
            self.mount = mount;
            mount.origin = self;
        }

        /// Remove mount. Mount pointer should be non-null and there should be
        /// no mounts on top. Pointer to the unmounted node is returned. If no mount is present,
        /// null is returned
        pub fn removeMount(self: *@This()) ?*@This() {
            if (self.mount) |mount| {
                std.debug.assert(mount.mount == null);
                self.mount = null;
                return mount;
            }
            return null;
        }

        /// Get node's backtraced parent. Exits mounts. Used to implement .. lookup
        /// NOTE: Does not modify reference counts
        pub fn getParent(self: *@This()) ?*@This() {
            return self.backtraceMounts().parent;
        }

        /// Create node
        pub fn create(allocator: *std.mem.Allocator, name: []const u8) !*@This() {
            std.debug.assert(name.len <= max_name_length);
            const result = try allocator.create(@This());
            result.* = .{};
            result.updateName(name);
            return result;
        }

        /// Dispose node
        pub fn destroy(self: *@This(), allocator: *std.mem.Allocator) void {
            self.children.deinit(allocator);
            allocator.destroy(self);
        }
    };
}

test "Basic FSNode operations" {
    const MyDEntry = FSNode(struct { ino: usize = 0 }, 255);

    const makeDEntry = struct {
        fn makeDEntry(name: []const u8, id: usize) !*MyDEntry {
            const result = try MyDEntry.create(std.testing.allocator, name);
            result.ref.ino = id;
            return result;
        }
    }.makeDEntry;

    // /
    // - home/
    //   - anon/
    // - dev/ -> devroot/
    //           - block/
    const root = try makeDEntry("", 1);
    const home = try makeDEntry("home", 2);
    const anon = try makeDEntry("anon", 3);
    const dev = try makeDEntry("dev", 4);
    const devRoot = try makeDEntry("", 5);
    const block = try makeDEntry("block", 6);
    try root.addChild(home, std.testing.allocator);
    try root.addChild(dev, std.testing.allocator);
    try home.addChild(anon, std.testing.allocator);
    try devRoot.addChild(block, std.testing.allocator);
    dev.addMount(devRoot);

    std.testing.expectEqual(root.getChild("dev").?.getChild("block").?.ref.ino, 6);
    std.testing.expectEqual(root.getChild("usr"), null);
    std.testing.expectEqual(root.getChild("home").?.getChild("anon").?.ref.ino, 3);
    std.testing.expectEqual(block.getParent().?.getParent().?.ref.ino, 1);

    // Mount fs on top of home
    const tmpHomeRoot = try makeDEntry("", 8);
    const anon2 = try makeDEntry("anon", 9);
    try tmpHomeRoot.addChild(anon2, std.testing.allocator);
    home.addMount(tmpHomeRoot);
    std.testing.expectEqual(root.getChild("home").?.getChild("anon").?.ref.ino, 9);
    std.testing.expectEqual(home.removeMount(), tmpHomeRoot);
    std.testing.expectEqual(root.getChild("home").?.getChild("anon").?.ref.ino, 3);

    root.removeChild(home);
    std.testing.expectEqual(root.getChild("usr"), null);

    root.destroy(std.testing.allocator);
    home.destroy(std.testing.allocator);
    anon.destroy(std.testing.allocator);
    dev.destroy(std.testing.allocator);
    devRoot.destroy(std.testing.allocator);
    block.destroy(std.testing.allocator);
    tmpHomeRoot.destroy(std.testing.allocator);
    anon2.destroy(std.testing.allocator);
}
