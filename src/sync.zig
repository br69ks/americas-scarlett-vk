//! Host-backed implementations of the Win32 synchronization objects the guest
//! uses.  Handles are small integers into a fixed table; the objects live on
//! the host heap and use futex (Linux) / WaitOnAddress (Windows) for blocking.

const std = @import("std");
const builtin = @import("builtin");
const teb = @import("teb.zig");

const AtomicU32 = std.atomic.Value(u32);
const linux = std.os.linux;

pub const INFINITE: u32 = 0xFFFF_FFFF;
pub const WAIT_OBJECT_0: u32 = 0;
pub const WAIT_TIMEOUT: u32 = 0x102;
pub const WAIT_FAILED: u32 = 0xFFFF_FFFF;
pub const WAIT_ABANDONED: u32 = 0x80;
pub const ERROR_INVALID_HANDLE: u32 = 6;
pub const ERROR_NOT_OWNER: u32 = 288;
pub const ERROR_TOO_MANY_POSTS: u32 = 298;
pub const STILL_ACTIVE: u32 = 259;

const HANDLE_BASE: usize = 0x100;
const HANDLE_STRIDE: usize = 8;
const MAX_HANDLES: usize = 4096;


const SpinLock = struct {
    v: AtomicU32 = .init(0),

    fn lock(self: *SpinLock) void {
        while (self.v.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
            while (self.v.load(.monotonic) != 0) std.atomic.spinLoopHint();
        }
    }
    fn unlock(self: *SpinLock) void {
        self.v.store(0, .release);
    }
};

const Kind = enum { event, mutex, semaphore, thread };

const Entry = struct {
    kind: Kind,
    ptr: *anyopaque,
};

var g_handles: [MAX_HANDLES]?Entry = @splat(null);
var g_handle_lock: SpinLock = .{};
var g_cs_lock: SpinLock = .{};

// ---------------------------------------------------------------------------
// Time / futex plumbing
// ---------------------------------------------------------------------------

fn nowMs() u64 {
    if (builtin.os.tag == .linux) {
        var ts: linux.timespec = undefined;
        _ = linux.clock_gettime(.MONOTONIC, &ts);
        return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(@divTrunc(ts.nsec, 1_000_000)));
    }
    if (builtin.os.tag == .windows) {
        var freq: i64 = 0;
        var counter: i64 = 0;
        _ = std.os.windows.ntdll.RtlQueryPerformanceFrequency(&freq);
        _ = std.os.windows.ntdll.RtlQueryPerformanceCounter(&counter);
        if (freq <= 0) return 0;
        const freq_ms = @divTrunc(freq, 1000);
        if (freq_ms <= 0) return @intCast(@divTrunc(counter, freq) * 1000);
        return @intCast(@divTrunc(counter, freq_ms));
    }
    return 0;
}

const WaitResult = enum { signaled, timed_out, failed };

const FUTEX_WAIT_PRIVATE: usize = 128;
const FUTEX_WAKE_PRIVATE: usize = 129;

fn futexWait(addr: *const AtomicU32, expected: u32, ms: u32) WaitResult {
    if (builtin.os.tag == .linux) {
        var ts: linux.timespec = .{ .sec = 0, .nsec = 0 };
        var timeout_ptr: usize = 0;
        if (ms != INFINITE) {
            ts = .{
                .sec = @intCast(ms / 1000),
                .nsec = @intCast((ms % 1000) * 1_000_000),
            };
            timeout_ptr = @intFromPtr(&ts);
        }
        const raw = linux.syscall6(
            .futex,
            @intFromPtr(@as(*const u32, @ptrCast(addr))),
            FUTEX_WAIT_PRIVATE,
            expected,
            timeout_ptr,
            0,
            0,
        );
        const rc: isize = @bitCast(raw);
        if (rc == 0) return .signaled;
        return switch (-rc) {
            11 => .signaled, // EAGAIN: value changed before sleeping
            110 => .timed_out, // ETIMEDOUT
            4 => .signaled, // EINTR: let the caller re-check
            else => .failed,
        };
    } else if (builtin.os.tag == .windows) {
        // No WaitOnAddress import: poll the atomic with a short sleep. The
        // waiter is woken logically by the value change, not by a kernel wake.
        const deadline = deadlineFrom(ms);
        while (addr.load(.acquire) == expected) {
            const left = remaining(deadline);
            if (left == 0) return .timed_out;
            sleepMs(1);
        }
        return .signaled;
    }
    return .failed;
}

fn futexWake(addr: *const AtomicU32, count: u32) void {
    if (builtin.os.tag == .linux) {
        _ = linux.syscall6(
            .futex,
            @intFromPtr(@as(*const u32, @ptrCast(addr))),
            FUTEX_WAKE_PRIVATE,
            count,
            0,
            0,
            0,
        );
    } else if (builtin.os.tag == .windows) {
        // Pollers observe the value change; no explicit wake is required.
    }
}

fn deadlineFrom(ms: u32) u64 {
    if (ms == INFINITE) return 0;
    return nowMs() + ms;
}

fn remaining(deadline: u64) u32 {
    if (deadline == 0) return INFINITE;
    const now = nowMs();
    if (now >= deadline) return 0;
    const r = deadline - now;
    return if (r > std.math.maxInt(u32)) std.math.maxInt(u32) else @intCast(r);
}

fn sleepMs(ms: u32) void {
    if (builtin.os.tag == .linux) {
        var ts: linux.timespec = .{
            .sec = @intCast(ms / 1000),
            .nsec = @intCast((ms % 1000) * 1_000_000),
        };
        _ = linux.nanosleep(&ts, null);
    } else if (builtin.os.tag == .windows) {
        var delay: i64 = -@as(i64, @intCast(ms)) * 10_000;
        _ = std.os.windows.ntdll.NtDelayExecution(.FALSE, &delay);
    }
}

fn currentThreadId() u32 {
    if (teb.currentTeb()) |t| return @truncate(t.client_id.unique_thread);
    if (builtin.os.tag == .linux) return @bitCast(@as(i32, @truncate(linux.gettid())));
    return 1;
}

// ---------------------------------------------------------------------------
// Objects
// ---------------------------------------------------------------------------

const Event = struct {
    manual: bool,
    state: AtomicU32 = .init(0),
};

const Mutex = struct {
    owner: AtomicU32 = .init(0),
    recursion: u32 = 0,
};

const Semaphore = struct {
    count: AtomicU32 = .init(0),
    max: u32 = 1,
};

const ThreadObj = struct {
    tid: u32,
    exited: AtomicU32 = .init(0),
};

fn createEvent(manual: bool, initial: bool) usize {
    const e = std.heap.page_allocator.create(Event) catch return 0;
    e.* = .{ .manual = manual };
    if (initial) e.state.store(1, .release);
    const h = allocHandle(.event, e);
    if (h == 0) std.heap.page_allocator.destroy(e);
    return h;
}

fn createMutex(initial_owner: bool) usize {
    const m = std.heap.page_allocator.create(Mutex) catch return 0;
    m.* = .{};
    if (initial_owner) _ = lockMutex(m, INFINITE);
    const h = allocHandle(.mutex, m);
    if (h == 0) std.heap.page_allocator.destroy(m);
    return h;
}

fn createSemaphore(initial: u32, max: u32) usize {
    const s = std.heap.page_allocator.create(Semaphore) catch return 0;
    s.* = .{ .max = @max(max, 1) };
    s.count.store(@min(initial, s.max), .release);
    const h = allocHandle(.semaphore, s);
    if (h == 0) std.heap.page_allocator.destroy(s);
    return h;
}

pub fn createThreadHandle(tid: u32) usize {
    const t = std.heap.page_allocator.create(ThreadObj) catch return 0;
    t.* = .{ .tid = tid };
    const h = allocHandle(.thread, t);
    if (h == 0) std.heap.page_allocator.destroy(t);
    return h;
}

pub fn markThreadExited(handle: usize) void {
    const e = lookup(handle) orelse return;
    if (e.kind != .thread) return;
    const t: *ThreadObj = @ptrCast(@alignCast(e.ptr));
    t.exited.store(1, .release);
    futexWake(&t.exited, std.math.maxInt(u32));
}

fn allocHandle(kind: Kind, ptr: *anyopaque) usize {
    g_handle_lock.lock();
    defer g_handle_lock.unlock();
    for (&g_handles, 0..) |*slot, i| {
        if (slot.* == null) {
            slot.* = .{ .kind = kind, .ptr = ptr };
            return HANDLE_BASE + i * HANDLE_STRIDE;
        }
    }
    return 0;
}

fn lookup(handle: usize) ?Entry {
    if (handle < HANDLE_BASE) return null;
    const off = handle - HANDLE_BASE;
    if (off % HANDLE_STRIDE != 0) return null;
    const idx = off / HANDLE_STRIDE;
    if (idx >= MAX_HANDLES) return null;
    g_handle_lock.lock();
    defer g_handle_lock.unlock();
    return g_handles[idx];
}

fn releaseHandle(handle: usize) bool {
    if (handle < HANDLE_BASE) return false;
    const off = handle - HANDLE_BASE;
    if (off % HANDLE_STRIDE != 0) return false;
    const idx = off / HANDLE_STRIDE;
    if (idx >= MAX_HANDLES) return false;
    g_handle_lock.lock();
    const entry = g_handles[idx];
    g_handles[idx] = null;
    g_handle_lock.unlock();
    if (entry) |e| destroy(e);
    return entry != null;
}

fn destroy(e: Entry) void {
    switch (e.kind) {
        .event => std.heap.page_allocator.destroy(@as(*Event, @ptrCast(@alignCast(e.ptr)))),
        .mutex => std.heap.page_allocator.destroy(@as(*Mutex, @ptrCast(@alignCast(e.ptr)))),
        .semaphore => std.heap.page_allocator.destroy(@as(*Semaphore, @ptrCast(@alignCast(e.ptr)))),
        .thread => std.heap.page_allocator.destroy(@as(*ThreadObj, @ptrCast(@alignCast(e.ptr)))),
    }
}

// ---------------------------------------------------------------------------
// Mutex / event / semaphore primitives
// ---------------------------------------------------------------------------

fn lockMutex(m: *Mutex, ms: u32) bool {
    const tid = currentThreadId();
    if (m.owner.load(.acquire) == tid) {
        m.recursion += 1;
        return true;
    }
    const deadline = deadlineFrom(ms);
    while (true) {
        if (m.owner.cmpxchgWeak(0, tid, .acquire, .monotonic) == null) {
            m.recursion = 1;
            return true;
        }
        const left = remaining(deadline);
        if (left == 0) return false;
        _ = futexWait(&m.owner, m.owner.load(.monotonic), left);
    }
}

fn unlockMutex(m: *Mutex) bool {
    if (m.owner.load(.acquire) != currentThreadId()) return false;
    if (m.recursion > 1) {
        m.recursion -= 1;
        return true;
    }
    m.recursion = 0;
    m.owner.store(0, .release);
    futexWake(&m.owner, 1);
    return true;
}

fn waitEvent(e: *Event, ms: u32) u32 {
    const deadline = deadlineFrom(ms);
    while (true) {
        const s = e.state.load(.acquire);
        if (s != 0) {
            if (e.manual) return WAIT_OBJECT_0;
            if (e.state.cmpxchgWeak(s, 0, .acq_rel, .acquire) == null) return WAIT_OBJECT_0;
            continue;
        }
        const left = remaining(deadline);
        if (left == 0) return WAIT_TIMEOUT;
        _ = futexWait(&e.state, 0, left);
    }
}

fn waitSemaphore(s: *Semaphore, ms: u32) u32 {
    const deadline = deadlineFrom(ms);
    while (true) {
        const c = s.count.load(.acquire);
        if (c > 0 and s.count.cmpxchgWeak(c, c - 1, .acq_rel, .acquire) == null) return WAIT_OBJECT_0;
        const left = remaining(deadline);
        if (left == 0) return WAIT_TIMEOUT;
        _ = futexWait(&s.count, 0, left);
    }
}

fn waitThread(t: *ThreadObj, ms: u32) u32 {
    const deadline = deadlineFrom(ms);
    while (true) {
        if (t.exited.load(.acquire) != 0) return WAIT_OBJECT_0;
        const left = remaining(deadline);
        if (left == 0) return WAIT_TIMEOUT;
        _ = futexWait(&t.exited, 0, left);
    }
}

fn isSignaled(e: Entry) bool {
    switch (e.kind) {
        .event => {
            const ev: *Event = @ptrCast(@alignCast(e.ptr));
            return ev.state.load(.acquire) != 0;
        },
        .mutex => {
            const m: *Mutex = @ptrCast(@alignCast(e.ptr));
            const owner = m.owner.load(.acquire);
            return owner == 0 or owner == currentThreadId();
        },
        .semaphore => {
            const s: *Semaphore = @ptrCast(@alignCast(e.ptr));
            return s.count.load(.acquire) > 0;
        },
        .thread => {
            const t: *ThreadObj = @ptrCast(@alignCast(e.ptr));
            return t.exited.load(.acquire) != 0;
        },
    }
}

fn tryAcquire(e: Entry) bool {
    switch (e.kind) {
        .event => {
            const ev: *Event = @ptrCast(@alignCast(e.ptr));
            if (ev.manual) return ev.state.load(.acquire) != 0;
            while (true) {
                const s = ev.state.load(.acquire);
                if (s == 0) return false;
                if (ev.state.cmpxchgWeak(s, 0, .acq_rel, .acquire) == null) return true;
            }
        },
        .mutex => {
            const m: *Mutex = @ptrCast(@alignCast(e.ptr));
            return lockMutex(m, 0);
        },
        .semaphore => {
            const s: *Semaphore = @ptrCast(@alignCast(e.ptr));
            while (true) {
                const c = s.count.load(.acquire);
                if (c == 0) return false;
                if (s.count.cmpxchgWeak(c, c - 1, .acq_rel, .acquire) == null) return true;
            }
        },
        .thread => {
            const t: *ThreadObj = @ptrCast(@alignCast(e.ptr));
            return t.exited.load(.acquire) != 0;
        },
    }
}

// ---------------------------------------------------------------------------
// Public Win32-shaped operations (called from shims)
// ---------------------------------------------------------------------------

pub fn createEventW(manual: bool, initial: bool) usize {
    return createEvent(manual, initial);
}

pub fn setEvent(handle: usize) bool {
    const e = lookup(handle) orelse return false;
    if (e.kind != .event) return false;
    const ev: *Event = @ptrCast(@alignCast(e.ptr));
    ev.state.store(1, .release);
    futexWake(&ev.state, std.math.maxInt(u32));
    return true;
}

pub fn resetEvent(handle: usize) bool {
    const e = lookup(handle) orelse return false;
    if (e.kind != .event) return false;
    const ev: *Event = @ptrCast(@alignCast(e.ptr));
    ev.state.store(0, .release);
    return true;
}

pub fn pulseEvent(handle: usize) bool {
    const e = lookup(handle) orelse return false;
    if (e.kind != .event) return false;
    const ev: *Event = @ptrCast(@alignCast(e.ptr));
    ev.state.store(1, .release);
    futexWake(&ev.state, std.math.maxInt(u32));
    ev.state.store(0, .release);
    return true;
}

pub fn createMutexW(initial_owner: bool) usize {
    return createMutex(initial_owner);
}

pub fn releaseMutex(handle: usize) bool {
    const e = lookup(handle) orelse return false;
    if (e.kind != .mutex) return false;
    const m: *Mutex = @ptrCast(@alignCast(e.ptr));
    return unlockMutex(m);
}

pub fn createSemaphoreW(initial: u32, max: u32) usize {
    return createSemaphore(initial, max);
}

pub fn releaseSemaphore(handle: usize, count: u32, previous: ?*u32) bool {
    const e = lookup(handle) orelse return false;
    if (e.kind != .semaphore) return false;
    const s: *Semaphore = @ptrCast(@alignCast(e.ptr));
    while (true) {
        const cur = s.count.load(.acquire);
        if (count > s.max -| cur) {
            teb.setLastError(ERROR_TOO_MANY_POSTS);
            return false;
        }
        if (s.count.cmpxchgWeak(cur, cur + count, .acq_rel, .acquire) == null) {
            if (previous) |p| p.* = cur;
            futexWake(&s.count, count);
            return true;
        }
    }
}

pub fn waitForSingleObject(handle: usize, ms: u32) u32 {
    // Pseudo-handles.
    if (handle == @as(usize, @bitCast(@as(isize, -1)))) return WAIT_OBJECT_0; // current process
    if (handle == @as(usize, @bitCast(@as(isize, -2)))) return WAIT_OBJECT_0; // current thread

    const e = lookup(handle) orelse {
        teb.setLastError(ERROR_INVALID_HANDLE);
        return WAIT_FAILED;
    };
    return switch (e.kind) {
        .event => waitEvent(@ptrCast(@alignCast(e.ptr)), ms),
        .mutex => if (lockMutex(@ptrCast(@alignCast(e.ptr)), ms)) WAIT_OBJECT_0 else WAIT_TIMEOUT,
        .semaphore => waitSemaphore(@ptrCast(@alignCast(e.ptr)), ms),
        .thread => waitThread(@ptrCast(@alignCast(e.ptr)), ms),
    };
}

pub fn waitForMultipleObjects(handles: []const usize, wait_all: bool, ms: u32) u32 {
    const deadline = deadlineFrom(ms);
    while (true) {
        if (wait_all) {
            var all = true;
            for (handles) |h| {
                const e = lookup(h) orelse {
                    teb.setLastError(ERROR_INVALID_HANDLE);
                    return WAIT_FAILED;
                };
                if (!isSignaled(e)) {
                    all = false;
                    break;
                }
            }
            if (all) {
                // Consume auto-reset objects only once all were signaled.
                for (handles) |h| {
                    const e = lookup(h) orelse continue;
                    _ = tryAcquire(e);
                }
                return WAIT_OBJECT_0;
            }
        } else {
            for (handles, 0..) |h, i| {
                const e = lookup(h) orelse {
                    teb.setLastError(ERROR_INVALID_HANDLE);
                    return WAIT_FAILED;
                };
                if (isSignaled(e) and tryAcquire(e)) return WAIT_OBJECT_0 + @as(u32, @intCast(i));
            }
        }
        const left = remaining(deadline);
        if (left == 0) return WAIT_TIMEOUT;
        // No single futex covers N objects; poll at 1 ms granularity.
        sleepMs(@min(left, 1));
    }
}

pub fn closeHandle(handle: usize) bool {
    return releaseHandle(handle);
}

pub fn getExitCodeThread(handle: usize, out: *u32) bool {
    const e = lookup(handle) orelse return false;
    if (e.kind != .thread) return false;
    const t: *ThreadObj = @ptrCast(@alignCast(e.ptr));
    out.* = if (t.exited.load(.acquire) != 0) 0 else STILL_ACTIVE;
    return true;
}

// ---------------------------------------------------------------------------
// CRITICAL_SECTION
// ---------------------------------------------------------------------------

const CS_MAGIC: u64 = 0x5343_5343_5343_5343;

const GuestCs = extern struct {
    host: *Mutex,
    magic: u64,
};

fn csHost(cs: *anyopaque) *Mutex {
    const g: *GuestCs = @ptrCast(@alignCast(cs));
    if (g.magic == CS_MAGIC) return g.host;
    g_cs_lock.lock();
    defer g_cs_lock.unlock();
    if (g.magic != CS_MAGIC) {
        const m = std.heap.page_allocator.create(Mutex) catch @panic("out of memory allocating critical section");
        m.* = .{};
        g.host = m;
        g.magic = CS_MAGIC;
    }
    return g.host;
}

pub fn initializeCriticalSection(cs: *anyopaque) void {
    _ = csHost(cs);
}

pub fn enterCriticalSection(cs: *anyopaque) void {
    _ = lockMutex(csHost(cs), INFINITE);
}

pub fn tryEnterCriticalSection(cs: *anyopaque) bool {
    return lockMutex(csHost(cs), 0);
}

pub fn leaveCriticalSection(cs: *anyopaque) void {
    _ = unlockMutex(csHost(cs));
}

pub fn deleteCriticalSection(cs: *anyopaque) void {
    const g: *GuestCs = @ptrCast(@alignCast(cs));
    g_cs_lock.lock();
    const had = g.magic == CS_MAGIC;
    const host_ptr = if (had) g.host else undefined;
    g.magic = 0;
    g_cs_lock.unlock();
    if (had) std.heap.page_allocator.destroy(host_ptr);
}

// ---------------------------------------------------------------------------
// SRW locks
// ---------------------------------------------------------------------------

const WRITER_BIT: u32 = 0x8000_0000;

const RwLock = struct {
    state: AtomicU32 = .init(0),
};

const GuestSrw = extern struct {
    host: ?*RwLock,
};

fn srwHost(srw: *anyopaque) *RwLock {
    const g: *GuestSrw = @ptrCast(@alignCast(srw));
    if (g.host) |h| return h;
    g_cs_lock.lock();
    defer g_cs_lock.unlock();
    if (g.host == null) {
        const rw = std.heap.page_allocator.create(RwLock) catch @panic("out of memory allocating SRW lock");
        rw.* = .{};
        g.host = rw;
    }
    return g.host.?;
}

fn srwLockShared(rw: *RwLock, ms: u32) bool {
    const deadline = deadlineFrom(ms);
    while (true) {
        const s = rw.state.load(.acquire);
        if (s & WRITER_BIT == 0) {
            if (rw.state.cmpxchgWeak(s, s + 1, .acquire, .monotonic) == null) return true;
            continue;
        }
        const left = remaining(deadline);
        if (left == 0) return false;
        _ = futexWait(&rw.state, s, left);
    }
}

fn srwUnlockShared(rw: *RwLock) void {
    const prev = rw.state.fetchSub(1, .release);
    if (prev & ~WRITER_BIT == 1) futexWake(&rw.state, 1);
}

fn srwLockExclusive(rw: *RwLock, ms: u32) bool {
    const deadline = deadlineFrom(ms);
    while (true) {
        const s = rw.state.load(.acquire);
        if (s == 0 and rw.state.cmpxchgWeak(0, WRITER_BIT, .acquire, .monotonic) == null) return true;
        const left = remaining(deadline);
        if (left == 0) return false;
        _ = futexWait(&rw.state, s, left);
    }
}

fn srwUnlockExclusive(rw: *RwLock) void {
    rw.state.store(0, .release);
    futexWake(&rw.state, std.math.maxInt(u32));
}

pub fn initializeSrwLock(srw: *anyopaque) void {
    const g: *GuestSrw = @ptrCast(@alignCast(srw));
    g.host = null;
}

pub fn acquireSrwExclusive(srw: *anyopaque) void {
    _ = srwLockExclusive(srwHost(srw), INFINITE);
}

pub fn acquireSrwShared(srw: *anyopaque) void {
    _ = srwLockShared(srwHost(srw), INFINITE);
}

pub fn tryAcquireSrwExclusive(srw: *anyopaque) bool {
    return srwLockExclusive(srwHost(srw), 0);
}

pub fn tryAcquireSrwShared(srw: *anyopaque) bool {
    return srwLockShared(srwHost(srw), 0);
}

pub fn releaseSrwExclusive(srw: *anyopaque) void {
    srwUnlockExclusive(srwHost(srw));
}

pub fn releaseSrwShared(srw: *anyopaque) void {
    srwUnlockShared(srwHost(srw));
}

// ---------------------------------------------------------------------------
// Condition variables
// ---------------------------------------------------------------------------

const Cond = struct {
    seq: AtomicU32 = .init(0),
};

const GuestCv = extern struct {
    host: ?*Cond,
};

fn cvHost(cv: *anyopaque) *Cond {
    const g: *GuestCv = @ptrCast(@alignCast(cv));
    if (g.host) |h| return h;
    g_cs_lock.lock();
    defer g_cs_lock.unlock();
    if (g.host == null) {
        const c = std.heap.page_allocator.create(Cond) catch @panic("out of memory allocating condition variable");
        c.* = .{};
        g.host = c;
    }
    return g.host.?;
}

fn condWait(c: *Cond, ms: u32) u32 {
    const deadline = deadlineFrom(ms);
    const start = c.seq.load(.acquire);
    while (true) {
        const left = remaining(deadline);
        if (left == 0) return WAIT_TIMEOUT;
        const now = c.seq.load(.acquire);
        if (now != start) return WAIT_OBJECT_0;
        _ = futexWait(&c.seq, now, left);
    }
}

pub fn initializeConditionVariable(cv: *anyopaque) void {
    const g: *GuestCv = @ptrCast(@alignCast(cv));
    g.host = null;
}

pub fn sleepConditionVariableCS(cv: *anyopaque, cs: *anyopaque, ms: u32) u32 {
    const c = cvHost(cv);
    const m = csHost(cs);
    _ = unlockMutex(m);
    const rc = condWait(c, ms);
    _ = lockMutex(m, INFINITE);
    return rc;
}

pub fn sleepConditionVariableSRW(cv: *anyopaque, srw: *anyopaque, ms: u32, flags: u32) u32 {
    _ = flags;
    const c = cvHost(cv);
    const rw = srwHost(srw);
    srwUnlockExclusive(rw);
    const rc = condWait(c, ms);
    _ = srwLockExclusive(rw, INFINITE);
    return rc;
}

pub fn wakeConditionVariable(cv: *anyopaque) void {
    const c = cvHost(cv);
    _ = c.seq.fetchAdd(1, .acq_rel);
    futexWake(&c.seq, 1);
}

pub fn wakeAllConditionVariable(cv: *anyopaque) void {
    const c = cvHost(cv);
    _ = c.seq.fetchAdd(1, .acq_rel);
    futexWake(&c.seq, std.math.maxInt(u32));
}

// ---------------------------------------------------------------------------
// WaitOnAddress
// ---------------------------------------------------------------------------

pub fn waitOnAddress(addr: *const anyopaque, compare: *const anyopaque, size: usize, ms: u32) bool {
    switch (size) {
        1 => {
            const a: *const u8 = @ptrCast(addr);
            const c: *const u8 = @ptrCast(compare);
            if (a.* != c.*) return false;
            return futexWait(@ptrCast(@alignCast(addr)), @as(u32, a.*), ms) != .timed_out;
        },
        2 => {
            const a: *const u16 = @ptrCast(@alignCast(addr));
            const c: *const u16 = @ptrCast(@alignCast(compare));
            if (a.* != c.*) return false;
            return futexWait(@ptrCast(@alignCast(addr)), @as(u32, a.*), ms) != .timed_out;
        },
        4 => {
            const a: *const u32 = @ptrCast(@alignCast(addr));
            const c: *const u32 = @ptrCast(@alignCast(compare));
            if (a.* != c.*) return false;
            return futexWait(@ptrCast(@alignCast(addr)), a.*, ms) != .timed_out;
        },
        8 => {
            const a: *const u64 = @ptrCast(@alignCast(addr));
            const c: *const u64 = @ptrCast(@alignCast(compare));
            if (a.* != c.*) return false;
            const low: u32 = @truncate(a.*);
            return futexWait(@ptrCast(@alignCast(addr)), low, ms) != .timed_out;
        },
        else => return false,
    }
}

pub fn wakeByAddressSingle(addr: *const anyopaque) void {
    futexWake(@ptrCast(@alignCast(addr)), 1);
}

pub fn wakeByAddressAll(addr: *const anyopaque) void {
    futexWake(@ptrCast(@alignCast(addr)), std.math.maxInt(u32));
}
