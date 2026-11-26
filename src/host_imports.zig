//! Host DLL imports for the Windows backend.
//!
//! On Windows the title should use the host's real crypto/OS DLLs where the
//! semantics match.  Linux keeps the HLE shims.

const std = @import("std");
const builtin = @import("builtin");

const HMODULE = usize;

const HostFn = *const anyopaque;

extern "kernel32" fn LoadLibraryW(name: [*:0]const u16) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn LoadLibraryExW(name: [*:0]const u16, file: usize, flags: u32) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn GetProcAddress(module: *anyopaque, name: [*:0]const u8) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn GetLastError() callconv(.winapi) u32;
extern "kernel32" fn GetModuleHandleW(name: ?[*:0]const u16) callconv(.winapi) usize;
extern "kernel32" fn GetModuleFileNameW(module: usize, name: [*]u16, size: u32) callconv(.winapi) u32;
extern "kernel32" fn CopyFileW(existing: [*:0]const u16, new: [*:0]const u16, fail_if_exists: i32) callconv(.winapi) i32;

const Cached = struct {
    name: [64]u8,
    len: usize,
    module: HMODULE,
};

var g_cache: [16]Cached = undefined;
var g_cache_len: usize = 0;

pub var g_game_dir: []const u8 = "";

pub fn isHostDll(dll: []const u8) bool {
    const base = std.fs.path.basename(dll);
    return std.ascii.eqlIgnoreCase(base, "bcrypt.dll") or
        std.ascii.eqlIgnoreCase(base, "crypt32.dll") or
        std.ascii.eqlIgnoreCase(base, "ncrypt.dll") or
        std.ascii.eqlIgnoreCase(base, "msvcp140.dll") or
        std.ascii.eqlIgnoreCase(base, "msvcp140_1.dll") or
        std.ascii.eqlIgnoreCase(base, "msvcp140_2.dll") or
        std.ascii.eqlIgnoreCase(base, "msvcp140_atomic_wait.dll") or
        std.ascii.eqlIgnoreCase(base, "msvcp140_codecvt_ids.dll") or
        std.ascii.eqlIgnoreCase(base, "ucrtbase.dll");
}

fn widePath(path: []const u8, out: *[1024]u16) ?[*:0]const u16 {
    if (path.len >= out.len - 1) return null;
    const n = std.unicode.utf8ToUtf16Le(out[0 .. out.len - 1], path) catch return null;
    out[n] = 0;
    return @ptrCast(out);
}

fn remember(name: []const u8, module: usize) usize {
    for (g_cache[0..g_cache_len]) |c| {
        if (c.len == name.len and std.ascii.eqlIgnoreCase(c.name[0..c.len], name)) return c.module;
    }
    if (g_cache_len < g_cache.len) {
        var copy: [64]u8 = @splat(0);
        const k = @min(name.len, copy.len);
        @memcpy(copy[0..k], name[0..k]);
        g_cache[g_cache_len] = .{ .name = copy, .len = k, .module = module };
        g_cache_len += 1;
    }
    return module;
}

fn localBesideExe(dll: []const u8) ?usize {
    var exe_wide: [1024]u16 = @splat(0);
    const n = GetModuleFileNameW(0, &exe_wide, exe_wide.len);
    if (n == 0 or n >= exe_wide.len) return null;
    var dir_len: usize = n;
    while (dir_len > 0) : (dir_len -= 1) {
        if (exe_wide[dir_len - 1] == '\\' or exe_wide[dir_len - 1] == '/') break;
    }
    var local_wide: [1024]u16 = @splat(0);
    const prefix_len = dir_len;
    @memcpy(local_wide[0..prefix_len], exe_wide[0..prefix_len]);
    var idx = prefix_len;
    const utf8_len = std.unicode.utf8ToUtf16Le(local_wide[idx..], dll) catch return null;
    idx += utf8_len;
    local_wide[idx] = 0;
    if (LoadLibraryW(@ptrCast(&local_wide))) |m| {
        std.log.info("[HOST] LoadLibraryW(local {s}) -> 0x{x}", .{ dll, @intFromPtr(m) });
        return @intFromPtr(m);
    }

    // Copy from the game dir beside the loader, then load the local copy.
    if (g_game_dir.len == 0) return null;
    var source_buf: [1024]u8 = undefined;
    const sep = if (g_game_dir[g_game_dir.len - 1] == '\\' or g_game_dir[g_game_dir.len - 1] == '/') "" else "\\";
    const source = std.fmt.bufPrint(&source_buf, "{s}{s}{s}", .{ g_game_dir, sep, dll }) catch return null;
    var source_wide: [1024]u16 = @splat(0);
    const src_len = std.unicode.utf8ToUtf16Le(source_wide[0 .. source_wide.len - 1], source) catch return null;
    source_wide[src_len] = 0;
    if (CopyFileW(@ptrCast(&source_wide), @ptrCast(&local_wide), 0) == 0) {
        std.log.warn("[HOST] CopyFileW({s}) failed, error={d}", .{ source, GetLastError() });
        return null;
    }
    if (LoadLibraryW(@ptrCast(&local_wide))) |m| {
        std.log.info("[HOST] copied+loaded {s} -> 0x{x}", .{ dll, @intFromPtr(m) });
        return @intFromPtr(m);
    }
    return null;
}

pub fn loadLibrary(dll: []const u8) ?usize {
    if (builtin.os.tag != .windows) return null;
    for (g_cache[0..g_cache_len]) |c| {
        if (c.len == dll.len and std.ascii.eqlIgnoreCase(c.name[0..c.len], dll)) return c.module;
    }
    var wide: [1024]u16 = undefined;
    if (g_game_dir.len != 0) {
        var joined: [1024]u8 = undefined;
        const sep = if (g_game_dir[g_game_dir.len - 1] == '\\' or g_game_dir[g_game_dir.len - 1] == '/') "" else "\\";
        const path = std.fmt.bufPrint(&joined, "{s}{s}{s}", .{ g_game_dir, sep, dll }) catch "";
        if (path.len != 0) {
            if (widePath(path, &wide)) |w| {
                // LOAD_WITH_ALTERED_SEARCH_PATH lets dependencies resolve beside it.
                if (LoadLibraryExW(w, 0, 0x8)) |m| {
                    std.log.info("[HOST] LoadLibraryExW({s}) -> 0x{x}", .{ path, @intFromPtr(m) });
                    return remember(dll, @intFromPtr(m));
                }
                if (LoadLibraryW(w)) |m| {
                    std.log.info("[HOST] LoadLibraryW({s}) -> 0x{x}", .{ path, @intFromPtr(m) });
                    return remember(dll, @intFromPtr(m));
                }
                const err = GetLastError();
                std.log.warn("[HOST] {s} failed, error={d}", .{ path, err });
                if (localBesideExe(dll)) |local| return remember(dll, local);
            }
        }
    }
    if (widePath(dll, &wide)) |w| {
        if (LoadLibraryW(w)) |m| return remember(dll, @intFromPtr(m));
    }
    return null;
}

pub fn getProcAddress(base: usize, name: ?[]const u8, ordinal: ?u16) ?usize {
    if (builtin.os.tag != .windows or base == 0) return null;
    const mod_ptr: *anyopaque = @ptrFromInt(base);
    if (name) |n| {
        var cname: [128]u8 = @splat(0);
        if (n.len >= cname.len) return null;
        @memcpy(cname[0..n.len], n);
        cname[n.len] = 0;
        const proc = GetProcAddress(mod_ptr, @ptrCast(&cname)) orelse return null;
        return @intFromPtr(proc);
    }
    if (ordinal) |ord| {
        const proc = GetProcAddress(mod_ptr, @ptrFromInt(ord)) orelse return null;
        return @intFromPtr(proc);
    }
    return null;
}

fn addTlsIndex(out: []u32, n: *usize, base_addr: usize) void {
    if (base_addr < 0x10000) return;
    const base: [*]const u8 = @ptrFromInt(base_addr);
    const e_lfanew = std.mem.readInt(u32, base[0x3C..][0..4], .little);
    const nt = base + e_lfanew;
    const optional = nt + 0x18;
    if (std.mem.readInt(u16, optional[0..2], .little) != 0x20B) return;
    const tls_rva = std.mem.readInt(u32, optional[0xB8..][0..4], .little);
    if (tls_rva == 0) return;
    const tls = base + tls_rva;
    const index_va = std.mem.readInt(u64, tls[0x10..][0..8], .little);
    if (index_va == 0) return;
    const idx_ptr: [*]const u8 = @ptrFromInt(@as(usize, @intCast(index_va)));
    const idx = std.mem.readInt(u32, idx_ptr[0..4], .little);
    if (n.* < out.len) {
        out[n.*] = idx;
        n.* += 1;
    }
}

pub fn usedTlsIndexes(out: []u32) usize {
    var n: usize = 0;
    addTlsIndex(out, &n, GetModuleHandleW(null));
    for (g_cache[0..g_cache_len]) |c| addTlsIndex(out, &n, c.module);
    return n;
}

pub fn isHostModule(base: usize) bool {
    for (g_cache[0..g_cache_len]) |c| {
        if (c.module == base) return true;
    }
    return false;
}

fn load(name: []const u8) ?HMODULE {
    return loadLibrary(name);
}

fn resolveWindows(dll: []const u8, name: ?[]const u8, ordinal: ?u16) ?usize {
    const module = load(dll) orelse return null;
    const mod_ptr: *anyopaque = @ptrFromInt(module);
    if (name) |n| {
        var cname: [128]u8 = @splat(0);
        if (n.len >= cname.len) return null;
        @memcpy(cname[0..n.len], n);
        cname[n.len] = 0;
        const proc = GetProcAddress(mod_ptr, @ptrCast(&cname)) orelse return null;
        return @intFromPtr(proc);
    }
    if (ordinal) |ord| {
        const proc = GetProcAddress(mod_ptr, @ptrFromInt(ord)) orelse return null;
        return @intFromPtr(proc);
    }
    return null;
}

pub fn resolve(dll: []const u8, name: ?[]const u8, ordinal: ?u16) ?usize {
    if (builtin.os.tag != .windows) return null;
    if (!isHostDll(dll)) return null;
    return resolveWindows(dll, name, ordinal);
}
