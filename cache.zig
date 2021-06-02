const std = @import("std");

const QueueCacheConfig = struct {
    T: type,
    Owner: type,
    next_name: []const u8 = "next_in_cache",
    prev_name: []const u8 = "prev_in_cache",
};

/// Cache of nodes.disposeFn is used to drop nodes from cache. disposeFn does not have to held
/// exclusive ownership of the cache while its running (e.g. if QueueCache is protected by mutex,
/// disposeFn can drop mutex and acquire it back before returning, thread safety is still
/// guaranteed)
/// disposeFn is called whenever there are too much nodes in the queue (see max_count field) or
/// if flush mehtod was called
/// Cached type should have two pointers (next and prev) to *?T. Their names are specified by
/// cfg.next_name and cfg.prev_name parameters.
/// disposeFn accepts owner parameter that could be used to pass context
pub fn QueueCache(
    comptime cfg: QueueCacheConfig,
    comptime disposeFn: fn (*cfg.Owner, *cfg.T) void,
) type {
    return struct {
        head: ?*cfg.T = null,
        tail: ?*cfg.T = null,
        count: usize = 0,
        max_count: ?usize = null,
        reject_new_counter: usize = 0,

        /// Dequeue latest node from the cache
        fn dequeue(self: *@This()) ?*cfg.T {
            if (self.tail) |tail| {
                self.cut(tail);
                return tail;
            }
            return null;
        }

        /// Check if disposeFn should be called. Returns false if cache has no place for the node
        fn disposeIfNeeded(self: *@This(), owner: *cfg.Owner) bool {
            if (self.max_count) |max| {
                while (self.count == max) {
                    const node_to_delete = self.dequeue() orelse return false;
                    // Prevent insertions in cache while this thread executes disposeFn
                    self.reject_new_counter += 1;
                    disposeFn(owner, node_to_delete);
                    self.reject_new_counter -= 1;
                }
            }
            return true;
        }

        /// Clear cache. Use on OOM errors
        pub fn flush(self: *@This(), owner: *cfg.Owner) void {
            // Prevent insertions in cache while flush does its work
            self.reject_new_counter += 1;
            while (self.dequeue()) |node| {
                disposeFn(owner, node);
            }
            self.reject_new_counter -= 1;
        }

        /// Enqueue node in the cache
        pub fn enqueue(self: *@This(), owner: *cfg.Owner, node: *cfg.T) void {
            // If flushing operation is in progress, turn node down
            if (self.reject_new_counter != 0) {
                disposeFn(owner, node);
                return;
            }
            // If cache size is 0, dispose node directly
            if (!self.disposeIfNeeded(owner)) {
                disposeFn(owner, node);
                return;
            }
            @field(node, cfg.next_name) = null;
            @field(node, cfg.prev_name) = self.head;
            if (self.head) |head| {
                @field(head, cfg.next_name) = node;
            } else {
                self.tail = node;
            }
            self.head = node;
            self.count += 1;
        }

        /// Cut node from the cache
        pub fn cut(self: *@This(), node: *cfg.T) void {
            const prev = @field(node, cfg.prev_name);
            const next = @field(node, cfg.next_name);
            if (next) |next_nonnull| {
                if (prev) |prev_nonnull| {
                    @field(prev_nonnull, cfg.next_name) = next_nonnull;
                    @field(next_nonnull, cfg.prev_name) = next_nonnull;
                } else {
                    @field(next_nonnull, cfg.prev_name) = null;
                    self.tail = next_nonnull;
                }
            } else {
                if (prev) |prev_nonnull| {
                    @field(prev_nonnull, cfg.next_name) = null;
                    self.head = prev_nonnull;
                } else {
                    self.head = null;
                    self.tail = null;
                }
            }
            if (comptime std.debug.runtime_safety) {
                @field(node, cfg.prev_name) = null;
                @field(node, cfg.next_name) = null;
            }
            self.count -= 1;
        }
    };
}
