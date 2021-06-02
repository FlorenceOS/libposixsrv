const std = @import("std");
const fsnode = @import("fsnode.zig");
const cache = @import("cache.zig");

const FSTreeConfig = struct {
    InodeRefType: type,
    MutexType: type,
    CredentialsType: type,
    separator: []const u8 = "/",
    parent_link: []const u8 = "..",
    current_link: []const u8 = ".",
    root: []const u8 = "/",
    max_name_length: usize = 255,
    ignore_empty: bool = true,
};

/// FSTree structure represents the entirety of the filesystem tree
/// cfg.MutexType should confirm to std.Mutex interface
/// cfg.InodeRefType should implement
///
/// - drop(self: @This()) void - drops this reference to the inode
/// - lookup(self: @This(), name: []const u8) !@This() - load inode ref for child
/// - resolveHook(self: @This(), credentials: cfg.CredentialsType) !void - hook that is called
/// on directory resolution
///
/// On each of those operations, tree lock is released and acquired back after the operation
/// InodeRefType and MutexType should be initializable to a valid state with .{}v
/// cfg.separator, cfg.parent_linkk, cfg.current_link, cfg.root are used in path resolution.
/// max_name_length is maximum length of component name
pub fn FSTree(comptime cfg: FSTreeConfig) type {
    return struct {
        const Node = fsnode.FSNode(cfg.InodeRefType, cfg.max_name_length);
        const NodeCache = cache.QueueCache(.{ .T = Node, .Owner = @This() }, cacheDisposeFn);

        /// Allocator used for tree operations
        allocator: *std.mem.Allocator,
        /// Root node
        root: *Node,
        /// Tree mutex
        mutex: cfg.MutexType = .{},
        /// Held mutex structure
        held: cfg.MutexType.Held = undefined,
        /// Node cache
        cache: NodeCache,

        /// Check credentials while doing path resolution
        fn checkResolveCredentials(
            self: *@This(),
            ref: cfg.InodeRefType,
            credentials: cfg.CredentialsType,
        ) !void {
            self.releaseLock();
            defer self.acquireLock();

            return ref.resolveHook(credentials);
        }

        /// Look up child inode ref using lookup method
        fn loadChild(self: *@This(), current: *Node, component: []const u8) !cfg.InodeRefType {
            self.releaseLock();
            defer self.acquireLock();

            return current.ref.lookup(component);
        }

        /// Link child using link() inode ref method
        fn linkChild(
            self: *@This(),
            current: *Node,
            component: []const u8,
            child: cfg.InodeRefType,
            credentials: cfg.CredentialsType,
        ) !void {
            self.releaseLock();
            defer self.acquireLock();

            return current.ref.linkHook(child, component, credentials);
        }

        /// Unlink child using unlink() inode ref method
        fn unlinkChild(
            self: *@This(),
            current: *Node,
            component: []const u8,
            child: cfg.InodeRefType,
            credentials: cfg.CredentialsType,
        ) !void {
            self.releaseLock();
            defer self.acquireLock();

            return current.ref.unlinkHook(child, component, credentials);
        }

        /// Drop reference to Inode using its drop method
        fn dropInodeRef(self: *@This(), ref: cfg.InodeRefType) void {
            self.releaseLock();
            ref.drop();
            self.acquireLock();
        }

        /// Flush cache
        pub fn flushCache(self: *@This()) void {
            self.acquireLock();
            self.cache.flush(self);
            self.releaseLock();
        }

        /// Release tree lock
        fn releaseLock(self: *@This()) void {
            self.held.release();
        }

        /// Acquire tree lock
        fn acquireLock(self: *@This()) void {
            self.held = self.mutex.acquire();
        }

        /// Dispose node from cache
        fn cacheDisposeFn(self: *@This(), node: *Node) void {
            // Disposal of the current node may also trigger disposal of the parent, grandparent,
            // etc. Hence the need for the loop
            var current = node;
            std.debug.assert(current.ref_count == 0); // node in cache should have ref_count = 0
            while (current.ref_count == 0) {
                if (current.parent) |parent| {
                    // Unlink from the parent
                    parent.removeChild(current);
                    parent.ref_count -= 1;
                    // Drop lock for a moment
                    self.releaseLock();
                    // Dispose node ref
                    current.ref.drop();
                    current.destroy(self.allocator);
                    // Take lock back
                    self.acquireLock();
                    // Move on
                    current = parent;
                } else {
                    // ref_counts of mounted FSes are always at least one
                    @panic("libvfs: Reference count of FS root is zero!");
                }
            }
        }

        /// Increment node's reference count. Load from cache if needed
        fn incRefCount(self: *@This(), node: *Node) void {
            node.ref_count += 1;
            // If node is in the cache, load it back
            if (node.ref_count == 1) {
                self.cache.cut(node);
            }
        }

        /// Drop reference to the node. Load to cache if needed
        fn decRefCount(self: *@This(), node: *Node) void {
            node.ref_count -= 1;
            // If node reference count is 0, put it in the cache
            if (node.ref_count == 0) {
                self.cache.enqueue(self, node);
            }
        }

        /// Go to loaded child or return null
        fn resolveLoadedChildComponent(
            self: *@This(),
            current: *Node,
            component: []const u8,
            credentials: cfg.CredentialsType,
        ) !?*Node {
            const child = current.getChild(component) orelse return null;
            try self.checkResolveCredentials(child.ref, credentials);
            self.incRefCount(child);
            current.ref_count -= 1;
            return child;
        }

        /// Go to child
        fn resolveChildComponent(
            self: *@This(),
            current: *Node,
            component: []const u8,
            credentials: cfg.CredentialsType,
        ) !*Node {
            // First, check if node is already there
            return (try self.resolveLoadedChildComponent(current, component, credentials)) orelse {
                // If not, try to lookup child ref
                const new_ref = try self.loadChild(current, component);
                errdefer self.dropInodeRef(new_ref);
                // While we were loading this node, it could have been that someone else loaded it,
                // so we check again
                if (try self.resolveLoadedChildComponent(current, component, credentials)) |res| {
                    // errdefer won't execute, since result is not error.
                    self.dropInodeRef(new_ref);
                    return res;
                }
                // Verify credentials
                try self.checkResolveCredentials(new_ref, credentials);
                // Alright, let's create a new node
                const child = try Node.create(self.allocator, component);
                errdefer child.destroy(self.allocator);

                child.ref = new_ref;
                try current.addChild(child, self.allocator);

                return child;
            };
        }

        /// Go to parent. If there is no parent, current is returned
        fn resolveParentComponent(
            self: *@This(),
            current: *Node,
            credentials: cfg.CredentialsType,
            root: ?*Node,
        ) !*Node {
            if (current == root) {
                return current;
            }
            if (current.getParent()) |parent| {
                try self.checkResolveCredentials(parent.ref, credentials);
                parent.ref_count += 1;
                self.decRefCount(current);
                return parent;
            }
            return current;
        }

        /// Resolve one component
        fn resolveComponent(
            self: *@This(),
            current: *Node,
            component: []const u8,
            credentials: cfg.CredentialsType,
            root: ?*Node,
        ) !*Node {
            errdefer self.decRefCount(current);
            if (std.mem.eql(u8, component, cfg.current_link)) {
                return current;
            } else if (component.len == 0 and cfg.ignore_empty) {
                return current;
            } else if (std.mem.eql(u8, component, cfg.parent_link)) {
                return self.resolveParentComponent(current, credentials, root);
            } else {
                return self.resolveChildComponent(current, component, credentials);
            }
        }

        /// Walk from a given node. If consume_last is set to false, all elements except last
        /// will be ignored
        fn walkImpl(
            self: *@This(),
            node: ?*Node,
            root: ?*Node,
            path: []const u8,
            last: ?*[]const u8,
            consume_last: bool,
            credentials: cfg.CredentialsType,
        ) !*Node {
            const is_root_path = std.mem.startsWith(u8, path, cfg.root);
            const real_root = if (root) |r| r else self.root;
            const start = if (is_root_path) real_root else (node orelse real_root);
            const real_path = if (is_root_path) path[cfg.root.len..] else path;

            self.acquireLock();
            defer self.releaseLock();

            var current = start.traceMounts();
            self.incRefCount(current);

            var iterator = std.mem.split(real_path, cfg.separator);
            var prev_component = iterator.next() orelse return current;
            var current_component = iterator.next();

            while (current_component) |component| {
                current = try self.resolveComponent(current, prev_component, credentials, root);
                prev_component = component;
                current_component = iterator.next();
            }

            if (last) |nonnull| {
                nonnull.* = prev_component;
            }
            if (consume_last) {
                current = try self.resolveComponent(current, prev_component, credentials, root);
            }
            return current;
        }

        /// Print filesystem tree with a given root
        fn dumpFromNode(self: *@This(), node: *Node, tab_level: usize, writer: anytype) void {
            switch (tab_level) {
                0 => {},
                else => {
                    writer.writeByteNTimes(' ', 2 * (tab_level - 1)) catch {};
                    _ = writer.write("- ") catch {};
                },
            }
            writer.print("{s} (rc={})\n", .{ node.name, node.ref_count }) catch {};
            var iterator = node.children.iterator();
            while (iterator.next()) |child| {
                self.dumpFromNode(Node.fromKey(child.value), tab_level + 1, writer);
            }
        }

        /// Duplicate reference to the tree node
        pub fn dupeRef(self: *@This(), node: *Node) *Node {
            self.acquireLock();
            node.ref_count += 1;
            self.releaseLock();
        }

        /// Drop reference to the tree node
        pub fn dropRef(self: *@This(), node: *Node) void {
            self.acquireLock();
            self.decRefCount(node);
            self.releaseLock();
        }

        /// Walk from a given node by a given path
        /// node is a pointer to the CWD. If null, walk() starts walking from root
        /// chroot is a pointer to chrooted root. If null, walk() starts walking from real FS root
        /// path is actual path to file
        /// credentials are passed to resolveHook to verify if resolution of a given path is
        /// allowed
        /// NOTE: if chroot is not null, method assumes that node is in subtree of chroot
        pub fn walk(
            self: *@This(),
            node: ?*Node,
            chroot: ?*Node,
            path: []const u8,
            credentials: cfg.CredentialsType,
        ) !*Node {
            return self.walkImpl(node, chroot, path, null, true, credentials);
        }

        /// Walk from a given node by a given path, ignoring the last path component
        /// Fat pointer to the last path component is stored in the buffer provided by last
        /// This fat pointer would point inside the path
        /// node is a pointer to the CWD. If null, walk() starts walking from root
        /// chroot is a pointer to chrooted root. If null, walk() starts walking from real FS root
        /// path is actual path to file
        /// credentials are passed to resolveHook to verify if resolution of a given path is
        /// allowed
        /// NOTE: if chroot is not null, method assumes that node is in subtree of chroot
        pub fn walkIgnoreLast(
            self: *@This(),
            node: ?*Node,
            chroot: ?*Node,
            path: []const u8,
            last: *[]const u8,
            credentials: cfg.CredentialsType,
        ) !*Node {
            return self.walkImpl(node, chroot, path, last, false, credentials);
        }

        /// Creates tree instance.
        pub fn init(
            allocator: *std.mem.Allocator,
            max_cache_size: ?usize,
            root: cfg.InodeRefType,
        ) !@This() {
            // Make root node
            const child = try Node.create(allocator, "");
            child.ref = root;
            return @This(){
                .allocator = allocator,
                .cache = .{ .max_count = max_cache_size },
                .root = child,
            };
        }

        /// Dump tree state to stderr
        pub fn dump(self: *@This()) void {
            self.acquireLock();
            const writer = std.io.getStdErr().writer();
            writer.print("TREE DUMP\n", .{}) catch {};
            self.dumpFromNode(self.root, 0, writer);
            writer.print("CACHE DUMP\n", .{}) catch {};
            var current = self.cache.tail;
            while (current) |node| {
                writer.print("- {s} (rc={})\n", .{ node.name, node.ref_count }) catch {};
                current = node.next_in_cache;
            }
            self.releaseLock();
        }

        /// Dispose filesystem tree. Requires that all references to the objects in tree are lost
        pub fn deinit(self: *@This()) void {
            self.flushCache();
            std.debug.assert(self.root.ref_count == 1);
            self.root.destroy(self.allocator);
        }

        /// Errors that can be returned from path function
        const PathError = error{
            /// buffer is not big enough to store the name
            OutOfRange,
            /// node can't be reached from filesystem root
            UnreachableFromRoot,
        };

        /// Render path to file in a buffer.
        /// NOTE: Do not use directly on shared memory, otherwise sensitive data can be leaked
        /// NOTE: if chroot is not null, node is assumed to be in subtree of chroot
        pub fn emitPath(
            self: *@This(),
            node: *Node,
            chroot: ?*Node,
            buf: []u8,
        ) PathError![]const u8 {
            self.acquireLock();
            defer self.releaseLock();

            const prepend = struct {
                fn prepend(storage: []u8, curent: []const u8, new: []const u8) ![]const u8 {
                    const new_length = new.len + curent.len;
                    if (new_length > storage.len) {
                        return error.OutOfRange;
                    }
                    const new_index = storage.len - new_length;
                    std.mem.copy(u8, storage[new_index..(new_index + new.len)], new);
                    return storage[new_index..];
                }
            }.prepend;

            var current = node;
            var last = false;
            var result: []const u8 = buf[buf.len..];
            while (!last) {
                const parent = current.getParent();
                if (parent) |par| {
                    last = (par == chroot) or (par.getParent() == null);
                }
                result = try prepend(buf, result, current.name);
                if (!last) {
                    result = try prepend(buf, result, cfg.separator);
                }
                if (parent) |par| current = par;
            }
            result = try prepend(buf, result, cfg.root);
            return result;
        }
    };
}

test "walking" {
    // Dummy mutex type
    const Mutex = struct {
        const Self = @This();
        const Held = struct {
            owner: *Self,
            fn release(self: *@This()) void {
                std.testing.expect(self.owner.acquired);
                self.owner.acquired = false;
            }
        };
        acquired: bool = false,
        fn acquire(self: *@This()) Held {
            std.testing.expect(!self.acquired);
            self.acquired = true;
            return .{ .owner = self };
        }
    };
    // Dummy inode ref type.
    const InodeRef = struct {
        allow_pass: bool = true,

        fn drop(self: @This()) void {}
        fn lookup(self: @This(), name: []const u8) !@This() {
            if (std.mem.eql(u8, name, "invisible")) {
                return error.NotFound;
            } else if (std.mem.eql(u8, name, "nopass")) {
                return @This(){ .allow_pass = false };
            }
            return @This(){};
        }
        fn resolveHook(self: @This(), superuser: bool) !void {
            if (superuser or self.allow_pass) {
                return;
            }
            return error.PermissionDenied;
        }
    };
    // Buffer for rendering paths
    var path_buf: [1024]u8 = undefined;
    const MyTree = FSTree(.{ .InodeRefType = InodeRef, .MutexType = Mutex, .CredentialsType = bool });
    var tree = try MyTree.init(std.testing.allocator, null, .{});
    const usrbin = try tree.walk(null, null, "/usr/bin", true);
    // All paths starting from / resolve from root, even if cwd is supplied
    const relativeUsrBin = try tree.walk(usrbin, null, "/usr/bin", true);
    std.testing.expectEqual(usrbin, relativeUsrBin);
    tree.dropRef(relativeUsrBin);
    // Try to open /usr/bin/posixsrv in two possible ways
    const posix = try tree.walk(usrbin, null, "posixsrv", true);
    const posixFromAbsolute = try tree.walk(null, null, "/../usr/bin/posixsrv", false);
    std.testing.expectEqual(posix, posixFromAbsolute);
    // Test path function
    const emitted = try tree.emitPath(posix, null, &path_buf);
    std.testing.expect(std.mem.eql(u8, emitted, "/usr/bin/posixsrv"));
    // Drop nodes
    tree.dropRef(posix);
    tree.dropRef(posixFromAbsolute);
    tree.dropRef(usrbin);
    // Load posixsrv back to test loading from cache
    const posixFromAbsolute2 = try tree.walk(null, null, "/usr/bin/posixsrv", true);
    std.testing.expectEqual(posixFromAbsolute, posixFromAbsolute2);
    tree.dropRef(posixFromAbsolute2);
    // Try resolving file that does not exist
    if (tree.walk(null, null, "/home/invisible/???", false)) {
        @panic("/home/invisible/??? file should not exist");
    } else |err| {
        std.testing.expectEqual(err, error.NotFound);
    }
    // Let's make chroot jail!
    const jail = try tree.walk(null, null, "/jail", true);
    // Now let's try to escape it
    const escape_attempt = try tree.walk(null, jail, "/../../../", false);
    // We shall not pass
    std.testing.expectEqual(jail, escape_attempt);
    tree.dropRef(escape_attempt);
    // Test path rendering in chrooted environment
    const test_node = try tree.walk(null, jail, "/nopass/test_node", true);
    const emitted2 = try tree.emitPath(test_node, jail, &path_buf);
    std.testing.expect(std.mem.eql(u8, emitted2, "/nopass/test_node"));
    tree.dropRef(test_node);
    tree.dropRef(jail);
    // Test credentials verification
    const init = try tree.walk(null, null, "/etc/nopass/init", true);
    tree.dropRef(init);
    if (tree.walk(null, null, "/etc/nopass/init", false)) {
        @panic("We should not be allowed to access /etc/nopass/init");
    } else |err| {
        std.testing.expectEqual(err, error.PermissionDenied);
    }
    tree.deinit();
}
