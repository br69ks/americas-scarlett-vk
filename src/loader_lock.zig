//! Recursive lock serializing the module loader.
//!
//! `LoadLibrary`/`loadModulePath`/`patchImports` call each other through
//! import resolution (`A.dll` imports from `B.dll`, `B.dll` imports back), so
//! the loader lock must be recursive.  It is a process-wide lock: allocation of
//! module registry entries, trampoline slots and per-thread TLS templates must
//! be atomic with respect to each other and to other guest threads.
//!
//! This module has no dependencies so both `loader.zig` and `pe_loader.zig`
//! can use it without an import cycle.

const std = @import("std");
const builtin = @import("builtin");

const SpinLock = struct {
    v: std.atomic.Value(u32) = .init(0),

    fn lock(self: *SpinLock) void {
        while (self.v.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
            while (self.v.load(.monotonic) != 0) std.atomic.spinLoopHint();
        }
    }

    fn unlock(self: *SpinLock) void {
        self.v.store(0, .release);
    }
};

fn currentThreadId() u32 {
    if (builtin.os.tag == .linux) {
        return @intCast(std.os.linux.gettid());
    }
    if (builtin.os.tag == .windows) {
        const k32 = struct {
            extern "kernel32" fn GetCurrentThreadId() callconv(.winapi) u32;
        };
        return k32.GetCurrentThreadId();
    }
    return 0;
}

var g_mutex = SpinLock{};
var g_owner: std.atomic.Value(u32) = .init(0);
var g_depth: u32 = 0;

/// Acquire the loader lock for the current thread.  Recursive.
pub fn lock() void {
    const tid = currentThreadId();
    if (tid == 0) return; // unsupported host: behave as a no-op
    if (g_owner.load(.acquire) == tid) {
        g_depth += 1;
        return;
    }
    g_mutex.lock();
    g_owner.store(tid, .release);
    g_depth = 1;
}

/// Release one level of the loader lock.
pub fn unlock() void {
    const tid = currentThreadId();
    if (tid == 0) return;
    if (g_owner.load(.acquire) != tid) return;
    if (g_depth > 1) {
        g_depth -= 1;
        return;
    }
    g_depth = 0;
    g_owner.store(0, .release);
    g_mutex.unlock();
}

/// True when the current thread holds the loader lock (used by assertions).
pub fn isHeldByCurrentThread() bool {
    const tid = currentThreadId();
    return tid != 0 and g_owner.load(.acquire) == tid;
}

test "loader lock is recursive for one thread" {
    lock();
    try std.testing.expect(isHeldByCurrentThread());
    lock();
    try std.testing.expect(isHeldByCurrentThread());
    unlock();
    try std.testing.expect(isHeldByCurrentThread());
    unlock();
    try std.testing.expect(!isHeldByCurrentThread());
}

test "loader lock excludes other threads" {
    var ready = std.atomic.Value(u32).init(0);
    var observed = std.atomic.Value(u32).init(0);

    lock();
    try std.testing.expect(isHeldByCurrentThread());

    const Waiter = struct {
        fn run(r: *std.atomic.Value(u32), o: *std.atomic.Value(u32)) void {
            r.store(1, .release);
            lock();
            o.store(1, .release); // only reached once the lock is free
            unlock();
        }
    };
    const thread = try std.Thread.spawn(.{}, Waiter.run, .{ &ready, &observed });
    while (ready.load(.acquire) == 0) std.atomic.spinLoopHint();
    // Give the waiter a chance to run and block.
    std.Thread.yield() catch {};
    try std.testing.expectEqual(@as(u32, 0), observed.load(.acquire));
    unlock();
    thread.join();
    try std.testing.expectEqual(@as(u32, 1), observed.load(.acquire));
    try std.testing.expect(!isHeldByCurrentThread());
}
