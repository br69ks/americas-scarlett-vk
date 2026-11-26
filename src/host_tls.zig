//! Windows TLS API wrappers used by the native-TEB backend.

const std = @import("std");
const builtin = @import("builtin");
const host_imports = @import("host_imports.zig");
const teb = @import("teb.zig");

extern "kernel32" fn TlsAlloc() callconv(.winapi) u32;
extern "kernel32" fn TlsFree(index: u32) callconv(.winapi) i32;
extern "kernel32" fn TlsGetValue(index: u32) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn TlsSetValue(index: u32, value: ?*anyopaque) callconv(.winapi) i32;

pub fn alloc() ?u32 {
    if (builtin.os.tag != .windows) return null;
    const index = TlsAlloc();
    if (index == 0xFFFF_FFFF) return null;
    return index;
}

/// Windows can hand out a slot that host static TLS already uses (seen with
/// index 1).  Reserve the first few allocations and take one whose slot is
/// still empty and is not index 1.
var g_pool: [63]u32 = undefined;
var g_pool_len: usize = 0;
var g_pool_next: usize = 0;

pub fn allocGuest() ?u32 {
    if (builtin.os.tag != .windows) return null;
    if (g_pool_len == 0) {
        var i: usize = 0;
        while (i < g_pool.len) : (i += 1) {
            const idx = TlsAlloc();
            if (idx == 0xFFFF_FFFF) break;
            g_pool[i] = idx;
            g_pool_len += 1;
        }
        g_pool_next = g_pool_len;
    }
    var used: [32]u32 = undefined;
    const n = host_imports.usedTlsIndexes(&used);
    std.log.info("[TLS] host tls indexes n={d}: {any}", .{ n, used[0..@min(n, 8)] });
    while (g_pool_next > 0) {
        g_pool_next -= 1;
        const candidate = g_pool[g_pool_next];
        if (candidate >= 64) continue;
        var busy = false;
        for (used[0..n]) |u| {
            if (u == candidate) {
                busy = true;
                break;
            }
        }
        if (!busy and getRaw(candidate) == 0) return candidate;
    }
    return null;
}

pub fn free(index: u32) bool {
    if (builtin.os.tag != .windows) return false;
    return TlsFree(index) != 0;
}

pub fn get(index: u32) usize {
    if (builtin.os.tag != .windows) return 0;
    const p = TlsGetValue(index) orelse return 0;
    return @intFromPtr(p);
}

pub fn set(index: u32, value: usize) bool {
    if (builtin.os.tag != .windows) return false;
    return TlsSetValue(index, if (value == 0) null else @ptrFromInt(value)) != 0;
}

pub fn getRaw(index: u32) usize {
    if (builtin.os.tag != .windows) return 0;
    if (index >= 64) return 0;
    if (teb.currentTeb()) |t| return t.tls_slots[index];
    return 0;
}

pub fn setRaw(index: u32, value: usize) bool {
    if (builtin.os.tag != .windows) return false;
    if (index >= 64) return false;
    if (teb.currentTeb()) |t| {
        t.tls_slots[index] = value;
        return true;
    }
    return false;
}
