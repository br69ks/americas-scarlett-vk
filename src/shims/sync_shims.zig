//! Win64 ABI wrappers for the host synchronization core.

const std = @import("std");
const sync = @import("../sync.zig");
const teb = @import("../teb.zig");
const win32_fs = @import("win32_fs.zig");

const win: std.builtin.CallingConvention = .{ .x86_64_win = .{} };

const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;

fn fail() usize {
    teb.setLastError(ERROR_NOT_ENOUGH_MEMORY);
    return 0;
}

fn shim_CreateEventW(_: ?*anyopaque, manual: i32, initial: i32, _: ?[*:0]const u16) callconv(win) usize {
    const h = sync.createEventW(manual != 0, initial != 0);
    return if (h == 0) fail() else h;
}

fn shim_CreateEventA(_: ?*anyopaque, manual: i32, initial: i32, _: ?[*:0]const u8) callconv(win) usize {
    return shim_CreateEventW(null, manual, initial, null);
}

fn shim_CreateEventExW(_: ?*anyopaque, _: ?[*:0]const u16, flags: u32, _: u32) callconv(win) usize {
    const manual = flags & 0x1 != 0;
    const initial = flags & 0x2 != 0;
    const h = sync.createEventW(manual, initial);
    return if (h == 0) fail() else h;
}

fn shim_SetEvent(handle: usize) callconv(win) i32 {
    return if (sync.setEvent(handle)) 1 else 0;
}

fn shim_ResetEvent(handle: usize) callconv(win) i32 {
    return if (sync.resetEvent(handle)) 1 else 0;
}

fn shim_PulseEvent(handle: usize) callconv(win) i32 {
    return if (sync.pulseEvent(handle)) 1 else 0;
}

fn shim_CreateMutexW(_: ?*anyopaque, initial_owner: i32, _: ?[*:0]const u16) callconv(win) usize {
    const h = sync.createMutexW(initial_owner != 0);
    return if (h == 0) fail() else h;
}

fn shim_CreateMutexA(_: ?*anyopaque, initial_owner: i32, _: ?[*:0]const u8) callconv(win) usize {
    return shim_CreateMutexW(null, initial_owner, null);
}

fn shim_CreateMutexExW(_: ?*anyopaque, _: ?[*:0]const u16, flags: u32, _: u32) callconv(win) usize {
    const h = sync.createMutexW(flags & 0x1 != 0);
    return if (h == 0) fail() else h;
}

fn shim_ReleaseMutex(handle: usize) callconv(win) i32 {
    if (sync.releaseMutex(handle)) return 1;
    teb.setLastError(sync.ERROR_NOT_OWNER);
    return 0;
}

fn shim_CreateSemaphoreW(_: ?*anyopaque, initial: i32, maximum: i32, _: ?[*:0]const u16) callconv(win) usize {
    if (initial < 0 or maximum <= 0 or initial > maximum) {
        teb.setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    const h = sync.createSemaphoreW(@intCast(initial), @intCast(maximum));
    return if (h == 0) fail() else h;
}

fn shim_CreateSemaphoreExW(_: ?*anyopaque, initial: i32, maximum: i32, _: ?[*:0]const u16, _: u32, _: u32) callconv(win) usize {
    return shim_CreateSemaphoreW(null, initial, maximum, null);
}

fn shim_ReleaseSemaphore(handle: usize, count: i32, previous: ?*i32) callconv(win) i32 {
    if (count <= 0) {
        teb.setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    var prev: u32 = 0;
    if (!sync.releaseSemaphore(handle, @intCast(count), &prev)) return 0;
    if (previous) |p| p.* = @intCast(prev);
    return 1;
}

fn shim_WaitForSingleObject(handle: usize, ms: u32) callconv(win) u32 {
    return sync.waitForSingleObject(handle, ms);
}

fn shim_WaitForSingleObjectEx(handle: usize, ms: u32, _: i32) callconv(win) u32 {
    return sync.waitForSingleObject(handle, ms);
}

fn shim_WaitForMultipleObjects(count: u32, handles: ?[*]const usize, wait_all: i32, ms: u32) callconv(win) u32 {
    const ptr = handles orelse {
        teb.setLastError(ERROR_INVALID_PARAMETER);
        return sync.WAIT_FAILED;
    };
    if (count == 0 or count > 64) {
        teb.setLastError(ERROR_INVALID_PARAMETER);
        return sync.WAIT_FAILED;
    }
    return sync.waitForMultipleObjects(ptr[0..@intCast(count)], wait_all != 0, ms);
}

fn shim_WaitForMultipleObjectsEx(count: u32, handles: ?[*]const usize, wait_all: i32, ms: u32, _: i32) callconv(win) u32 {
    return shim_WaitForMultipleObjects(count, handles, wait_all, ms);
}

fn shim_CloseHandle(handle: usize) callconv(win) i32 {
    if (sync.closeHandle(handle)) return 1;
    if (win32_fs.closeHandle(handle)) return 1;
    teb.setLastError(sync.ERROR_INVALID_HANDLE);
    return 0;
}

fn shim_GetExitCodeThread(handle: usize, out: ?*u32) callconv(win) i32 {
    const p = out orelse {
        teb.setLastError(sync.ERROR_INVALID_PARAMETER);
        return 0;
    };
    if (!sync.getExitCodeThread(handle, p)) {
        teb.setLastError(sync.ERROR_INVALID_HANDLE);
        return 0;
    }
    return 1;
}

fn shim_InitializeCriticalSection(cs: ?*anyopaque) callconv(win) void {
    if (cs) |p| sync.initializeCriticalSection(p);
}

fn shim_EnterCriticalSection(cs: ?*anyopaque) callconv(win) void {
    if (cs) |p| sync.enterCriticalSection(p);
}

fn shim_LeaveCriticalSection(cs: ?*anyopaque) callconv(win) void {
    if (cs) |p| sync.leaveCriticalSection(p);
}

fn shim_DeleteCriticalSection(cs: ?*anyopaque) callconv(win) void {
    if (cs) |p| sync.deleteCriticalSection(p);
}

fn shim_TryEnterCriticalSection(cs: ?*anyopaque) callconv(win) i32 {
    const p = cs orelse return 0;
    return if (sync.tryEnterCriticalSection(p)) 1 else 0;
}

fn shim_InitializeCriticalSectionAndSpinCount(cs: ?*anyopaque, _: u32) callconv(win) i32 {
    if (cs) |p| sync.initializeCriticalSection(p);
    return 1;
}

fn shim_InitializeCriticalSectionEx(cs: ?*anyopaque, _: u32, _: u32) callconv(win) i32 {
    if (cs) |p| sync.initializeCriticalSection(p);
    return 1;
}

fn shim_InitializeSRWLock(srw: ?*anyopaque) callconv(win) void {
    if (srw) |p| sync.initializeSrwLock(p);
}

fn shim_AcquireSRWLockExclusive(srw: ?*anyopaque) callconv(win) void {
    if (srw) |p| sync.acquireSrwExclusive(p);
}

fn shim_AcquireSRWLockShared(srw: ?*anyopaque) callconv(win) void {
    if (srw) |p| sync.acquireSrwShared(p);
}

fn shim_TryAcquireSRWLockExclusive(srw: ?*anyopaque) callconv(win) i32 {
    const p = srw orelse return 0;
    return if (sync.tryAcquireSrwExclusive(p)) 1 else 0;
}

fn shim_TryAcquireSRWLockShared(srw: ?*anyopaque) callconv(win) i32 {
    const p = srw orelse return 0;
    return if (sync.tryAcquireSrwShared(p)) 1 else 0;
}

fn shim_ReleaseSRWLockExclusive(srw: ?*anyopaque) callconv(win) void {
    if (srw) |p| sync.releaseSrwExclusive(p);
}

fn shim_ReleaseSRWLockShared(srw: ?*anyopaque) callconv(win) void {
    if (srw) |p| sync.releaseSrwShared(p);
}

fn shim_InitializeConditionVariable(cv: ?*anyopaque) callconv(win) void {
    if (cv) |p| sync.initializeConditionVariable(p);
}

fn shim_SleepConditionVariableCS(cv: ?*anyopaque, cs: ?*anyopaque, ms: u32) callconv(win) i32 {
    const c = cv orelse return 0;
    const s = cs orelse return 0;
    return @intCast(sync.sleepConditionVariableCS(c, s, ms));
}

fn shim_SleepConditionVariableSRW(cv: ?*anyopaque, srw: ?*anyopaque, ms: u32, flags: u32) callconv(win) i32 {
    const c = cv orelse return 0;
    const s = srw orelse return 0;
    return @intCast(sync.sleepConditionVariableSRW(c, s, ms, flags));
}

fn shim_WakeConditionVariable(cv: ?*anyopaque) callconv(win) void {
    if (cv) |p| sync.wakeConditionVariable(p);
}

fn shim_WakeAllConditionVariable(cv: ?*anyopaque) callconv(win) void {
    if (cv) |p| sync.wakeAllConditionVariable(p);
}

fn shim_WaitOnAddress(addr: ?*const anyopaque, compare: ?*const anyopaque, size: usize, ms: u32) callconv(win) i32 {
    const a = addr orelse return 0;
    const c = compare orelse return 0;
    return if (sync.waitOnAddress(a, c, size, ms)) 1 else 0;
}

fn shim_WakeByAddressSingle(addr: ?*const anyopaque) callconv(win) void {
    const a = addr orelse return;
    sync.wakeByAddressSingle(a);
}

fn shim_WakeByAddressAll(addr: ?*const anyopaque) callconv(win) void {
    const a = addr orelse return;
    sync.wakeByAddressAll(a);
}

pub fn resolve(sym_name: []const u8) ?usize {
    const map = .{
        .{ "CreateEventW", @intFromPtr(&shim_CreateEventW) },
        .{ "CreateEventA", @intFromPtr(&shim_CreateEventA) },
        .{ "CreateEventExW", @intFromPtr(&shim_CreateEventExW) },
        .{ "SetEvent", @intFromPtr(&shim_SetEvent) },
        .{ "ResetEvent", @intFromPtr(&shim_ResetEvent) },
        .{ "PulseEvent", @intFromPtr(&shim_PulseEvent) },
        .{ "CreateMutexW", @intFromPtr(&shim_CreateMutexW) },
        .{ "CreateMutexA", @intFromPtr(&shim_CreateMutexA) },
        .{ "CreateMutexExW", @intFromPtr(&shim_CreateMutexExW) },
        .{ "ReleaseMutex", @intFromPtr(&shim_ReleaseMutex) },
        .{ "CreateSemaphoreW", @intFromPtr(&shim_CreateSemaphoreW) },
        .{ "CreateSemaphoreExW", @intFromPtr(&shim_CreateSemaphoreExW) },
        .{ "ReleaseSemaphore", @intFromPtr(&shim_ReleaseSemaphore) },
        .{ "WaitForSingleObject", @intFromPtr(&shim_WaitForSingleObject) },
        .{ "WaitForSingleObjectEx", @intFromPtr(&shim_WaitForSingleObjectEx) },
        .{ "WaitForMultipleObjects", @intFromPtr(&shim_WaitForMultipleObjects) },
        .{ "WaitForMultipleObjectsEx", @intFromPtr(&shim_WaitForMultipleObjectsEx) },
        .{ "CloseHandle", @intFromPtr(&shim_CloseHandle) },
        .{ "GetExitCodeThread", @intFromPtr(&shim_GetExitCodeThread) },
        .{ "InitializeCriticalSection", @intFromPtr(&shim_InitializeCriticalSection) },
        .{ "EnterCriticalSection", @intFromPtr(&shim_EnterCriticalSection) },
        .{ "LeaveCriticalSection", @intFromPtr(&shim_LeaveCriticalSection) },
        .{ "DeleteCriticalSection", @intFromPtr(&shim_DeleteCriticalSection) },
        .{ "TryEnterCriticalSection", @intFromPtr(&shim_TryEnterCriticalSection) },
        .{ "InitializeCriticalSectionAndSpinCount", @intFromPtr(&shim_InitializeCriticalSectionAndSpinCount) },
        .{ "InitializeCriticalSectionEx", @intFromPtr(&shim_InitializeCriticalSectionEx) },
        .{ "InitializeSRWLock", @intFromPtr(&shim_InitializeSRWLock) },
        .{ "AcquireSRWLockExclusive", @intFromPtr(&shim_AcquireSRWLockExclusive) },
        .{ "AcquireSRWLockShared", @intFromPtr(&shim_AcquireSRWLockShared) },
        .{ "TryAcquireSRWLockExclusive", @intFromPtr(&shim_TryAcquireSRWLockExclusive) },
        .{ "TryAcquireSRWLockShared", @intFromPtr(&shim_TryAcquireSRWLockShared) },
        .{ "ReleaseSRWLockExclusive", @intFromPtr(&shim_ReleaseSRWLockExclusive) },
        .{ "ReleaseSRWLockShared", @intFromPtr(&shim_ReleaseSRWLockShared) },
        .{ "InitializeConditionVariable", @intFromPtr(&shim_InitializeConditionVariable) },
        .{ "SleepConditionVariableCS", @intFromPtr(&shim_SleepConditionVariableCS) },
        .{ "SleepConditionVariableSRW", @intFromPtr(&shim_SleepConditionVariableSRW) },
        .{ "WakeConditionVariable", @intFromPtr(&shim_WakeConditionVariable) },
        .{ "WakeAllConditionVariable", @intFromPtr(&shim_WakeAllConditionVariable) },
        .{ "WaitOnAddress", @intFromPtr(&shim_WaitOnAddress) },
        .{ "WakeByAddressSingle", @intFromPtr(&shim_WakeByAddressSingle) },
        .{ "WakeByAddressAll", @intFromPtr(&shim_WakeByAddressAll) },
    };

    inline for (map) |entry| {
        if (std.mem.eql(u8, entry.@"0", sym_name)) return entry.@"1";
    }
    return null;
}
