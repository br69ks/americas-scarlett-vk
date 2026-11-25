const std = @import("std");

const c_stdio = struct {
    extern "c" fn fseek(stream: *std.c.FILE, offset: c_long, whence: c_int) c_int;
    extern "c" fn ftell(stream: *std.c.FILE) c_long;
};

pub var g_game_dir: []const u8 = "/home/brad/GTA6.Xbox.v1.0.2.1-CYBERLEEK";

const MAX_FILES = 256;
var g_files_storage: [MAX_FILES]?*std.c.FILE = @splat(null);
var g_file_lock = std.atomic.Value(u32).init(0);

fn lockFiles() void {
    while (g_file_lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
        std.atomic.spinLoopHint();
    }
}

fn unlockFiles() void {
    g_file_lock.store(0, .release);
}

const HANDLE_BASE: usize = 0x50000;

fn utf16ToHostPath(wpath: ?[*:0]const u16, out_buf: [*]u8, out_cap: usize) []const u8 {
    if (out_cap < 2) return "";
    const ptr = wpath orelse return "";
    var raw_storage: [512]u8 = undefined;
    var raw_len: usize = 0;
    while (ptr[raw_len] != 0 and raw_len < 511) : (raw_len += 1) {
        const ch = ptr[raw_len];
        raw_storage[raw_len] = if (ch == '\\') '/' else @truncate(ch & 0x7F);
    }
    var rel: []const u8 = raw_storage[0..raw_len];

    if (rel.len >= 3 and rel[1] == ':' and rel[2] == '/') {
        rel = rel[3..];
    } else if (rel.len >= 2 and rel[0] == '.' and rel[1] == '/') {
        rel = rel[2..];
    }

    const written = std.fmt.bufPrint(out_buf[0 .. out_cap - 1], "{s}/{s}", .{ g_game_dir, rel }) catch return "";
    out_buf[written.len] = 0;
    return written;
}

fn shim_MultiByteToWideChar(
    code_page: u32,
    flags: u32,
    src_ptr: ?[*]const u8,
    src_len: c_int,
    dst_ptr: ?[*]u16,
    dst_len: c_int,
) callconv(.{ .x86_64_win = .{} }) c_int {
    _ = code_page;
    _ = flags;
    const src = src_ptr orelse return 0;
    const actual_len: usize = if (src_len < 0)
    std.mem.len(@as([*:0]const u8, @ptrCast(src))) + 1
    else
        @intCast(src_len);

    if (dst_ptr == null or dst_len == 0) {
        return @intCast(actual_len);
    }

    const dst = dst_ptr.?;
    const copy_count = @min(actual_len, @as(usize, @intCast(dst_len)));
    var i: usize = 0;
    while (i < copy_count) : (i += 1) {
        dst[i] = src[i];
    }
    return @intCast(copy_count);
}

fn shim_WideCharToMultiByte(
    code_page: u32,
    flags: u32,
    src_ptr: ?[*]const u16,
    src_len: c_int,
    dst_ptr: ?[*]u8,
    dst_len: c_int,
    default_char: ?*const u8,
        used_default: ?*i32,
) callconv(.{ .x86_64_win = .{} }) c_int {
    _ = code_page;
    _ = flags;
    _ = default_char;
    if (used_default) |u| u.* = 0;
    const src = src_ptr orelse return 0;
    const actual_len: usize = if (src_len < 0) blk: {
        var n: usize = 0;
        while (src[n] != 0) : (n += 1) {}
        break :blk n + 1;
    } else @intCast(src_len);

    if (dst_ptr == null or dst_len == 0) {
        return @intCast(actual_len);
    }

    const dst = dst_ptr.?;
    const copy_count = @min(actual_len, @as(usize, @intCast(dst_len)));
    var i: usize = 0;
    while (i < copy_count) : (i += 1) {
        dst[i] = @truncate(src[i] & 0x7F);
    }
    return @intCast(copy_count);
}

fn shim_strcspn(s: ?[*:0]const u8, reject: ?[*:0]const u8) callconv(.{ .x86_64_win = .{} }) usize {
    const str = std.mem.span(s orelse return 0);
    const rej = std.mem.span(reject orelse return str.len);
    return std.mem.indexOfAny(u8, str, rej) orelse str.len;
}

fn shim_strspn(s: ?[*:0]const u8, accept: ?[*:0]const u8) callconv(.{ .x86_64_win = .{} }) usize {
    const str = std.mem.span(s orelse return 0);
    const acc = std.mem.span(accept orelse return 0);
    var i: usize = 0;
    while (i < str.len) : (i += 1) {
        if (std.mem.indexOfScalar(u8, acc, str[i]) == null) break;
    }
    return i;
}

var g_strtok_cursor: ?[*:0]u8 = null;

fn shim_strtok_s(
    str: ?[*:0]u8,
    delim: ?[*:0]const u8,
    context: ?*?[*]u8,
) callconv(.{ .x86_64_win = .{} }) ?[*:0]u8 {
    const del = std.mem.span(delim orelse return null);
    const cur: ?[*:0]u8 = if (str != null) str else if (context) |ctx| @ptrCast(ctx.*) else g_strtok_cursor;
    const p = cur orelse return null;

    var i: usize = 0;
    while (p[i] != 0 and std.mem.indexOfScalar(u8, del, p[i]) != null) : (i += 1) {}
    if (p[i] == 0) {
        if (context) |ctx| ctx.* = null;
        g_strtok_cursor = null;
        return null;
    }

    const token_start = p + i;
    while (p[i] != 0 and std.mem.indexOfScalar(u8, del, p[i]) == null) : (i += 1) {}
    if (p[i] != 0) {
        p[i] = 0;
        const next_ptr: [*:0]u8 = p + i + 1;
        if (context) |ctx| ctx.* = @ptrCast(next_ptr);
        g_strtok_cursor = next_ptr;
    } else {
        if (context) |ctx| ctx.* = null;
        g_strtok_cursor = null;
    }
    return token_start;
}

fn probeFileSize(path_z: [*:0]const u8) ?u64 {
    const fp = std.c.fopen(path_z, "rb") orelse return null;
    defer _ = std.c.fclose(fp);
    if (c_stdio.fseek(fp, 0, 2) != 0) return null;
    const pos = c_stdio.ftell(fp);
    if (pos < 0) return null;
    return @intCast(pos);
}

fn shim_GetFileAttributesW(lpFileName: ?[*:0]const u16) callconv(.{ .x86_64_win = .{} }) u32 {
    var path_storage: [512]u8 = undefined;
    const host_path = utf16ToHostPath(lpFileName, &path_storage, path_storage.len);
    if (host_path.len == 0) return 0xFFFFFFFF;
    const path_z: [*:0]const u8 = @ptrCast(host_path.ptr);
    if (host_path[host_path.len - 1] == '/') {
        return 0x10; // FILE_ATTRIBUTE_DIRECTORY
    }
    if (probeFileSize(path_z) != null) {
        std.log.info("[FS] GetFileAttributesW(\"{s}\") -> OK", .{host_path});
        return 0x80;
    }
    std.log.info("[FS] GetFileAttributesW(\"{s}\") -> NOT_FOUND", .{host_path});
    return 0xFFFFFFFF;
}

fn shim_GetFileAttributesExW(
    lpFileName: ?[*:0]const u16,
    fInfoLevelId: u32,
    lpFileInformation: ?[*]u8,
) callconv(.{ .x86_64_win = .{} }) i32 {
    _ = fInfoLevelId;
    var path_storage: [512]u8 = undefined;
    const host_path = utf16ToHostPath(lpFileName, &path_storage, path_storage.len);
    if (host_path.len == 0) return 0;
    const path_z: [*:0]const u8 = @ptrCast(host_path.ptr);
    const size = probeFileSize(path_z) orelse {
        std.log.info("[FS] GetFileAttributesExW(\"{s}\") -> NOT_FOUND", .{host_path});
        return 0;
    };
    if (lpFileInformation) |info| {
        @memset(info[0..36], 0);
        std.mem.writeInt(u32, info[0..4], 0x80, .little);
        std.mem.writeInt(u32, info[28..32], @truncate(size >> 32), .little);
        std.mem.writeInt(u32, info[32..36], @truncate(size & 0xFFFFFFFF), .little);
    }
    std.log.info("[FS] GetFileAttributesExW(\"{s}\", size={d}) -> OK", .{ host_path, size });
    return 1;
}

fn shim_CreateFileW(
    lpFileName: ?[*:0]const u16,
    dwDesiredAccess: u32,
    dwShareMode: u32,
    lpSecurityAttributes: ?*anyopaque,
    dwCreationDisposition: u32,
    dwFlagsAndAttributes: u32,
    hTemplateFile: usize,
) callconv(.{ .x86_64_win = .{} }) usize {
    _ = dwDesiredAccess;
    _ = dwShareMode;
    _ = lpSecurityAttributes;
    _ = dwCreationDisposition;
    _ = dwFlagsAndAttributes;
    _ = hTemplateFile;

    var path_storage: [512]u8 = undefined;
    const host_path = utf16ToHostPath(lpFileName, &path_storage, path_storage.len);
    if (host_path.len == 0) return std.math.maxInt(usize);
    const path_z: [*:0]const u8 = @ptrCast(host_path.ptr);

    const fp = std.c.fopen(path_z, "rb") orelse {
        std.log.warn("[FS] CreateFileW(\"{s}\") -> INVALID_HANDLE", .{host_path});
        return std.math.maxInt(usize);
    };

    lockFiles();
    defer unlockFiles();

    var idx: usize = 0;
    while (idx < MAX_FILES) : (idx += 1) {
        if (g_files_storage[idx] == null) {
            g_files_storage[idx] = fp;
            const handle = HANDLE_BASE + idx * 8;
            std.log.info("[FS] CreateFileW(\"{s}\") -> handle=0x{x}", .{ host_path, handle });
            return handle;
        }
    }
    _ = std.c.fclose(fp);
    return std.math.maxInt(usize);
}

fn lookupFile(handle: usize) ?*std.c.FILE {
    if (handle < HANDLE_BASE) return null;
    const idx = (handle - HANDLE_BASE) / 8;
    if (idx >= MAX_FILES) return null;
    return g_files_storage[idx];
}

fn shim_ReadFile(
    hFile: usize,
    lpBuffer: ?[*]u8,
    nNumberOfBytesToRead: u32,
    lpNumberOfBytesRead: ?*u32,
    lpOverlapped: ?[*]u8,
) callconv(.{ .x86_64_win = .{} }) i32 {
    const fp = lookupFile(hFile) orelse return 0;
    const buf = lpBuffer orelse return 0;

    if (lpOverlapped) |ov| {
        const off_lo = std.mem.readInt(u32, ov[16..20], .little);
        const off_hi = std.mem.readInt(u32, ov[20..24], .little);
        const offset: c_long = @intCast((@as(u64, off_hi) << 32) | off_lo);
        if (c_stdio.fseek(fp, offset, 0) != 0) return 0;
    }

    const bytes_read = std.c.fread(buf, 1, nNumberOfBytesToRead, fp);
    if (lpNumberOfBytesRead) |out_read| out_read.* = @intCast(bytes_read);
    return 1;
}

fn shim_SetFilePointerEx(
    hFile: usize,
    liDistanceToMove: i64,
    lpNewFilePointer: ?*i64,
    dwMoveMethod: u32,
) callconv(.{ .x86_64_win = .{} }) i32 {
    const fp = lookupFile(hFile) orelse return 0;
    const whence: c_int = @intCast(dwMoveMethod);
    if (whence < 0 or whence > 2) return 0;
    if (c_stdio.fseek(fp, @intCast(liDistanceToMove), whence) != 0) return 0;
    if (lpNewFilePointer) |out_pos| {
        const pos = c_stdio.ftell(fp);
        if (pos < 0) return 0;
        out_pos.* = @intCast(pos);
    }
    return 1;
}

fn shim_GetFileSizeEx(hFile: usize, lpFileSize: ?*i64) callconv(.{ .x86_64_win = .{} }) i32 {
    const fp = lookupFile(hFile) orelse return 0;
    const cur = c_stdio.ftell(fp);
    if (c_stdio.fseek(fp, 0, 2) != 0) return 0;
    const end = c_stdio.ftell(fp);
    _ = c_stdio.fseek(fp, cur, 0);
    if (end < 0) return 0;
    if (lpFileSize) |out_sz| out_sz.* = @intCast(end);
    return 1;
}

fn shim_GetUserDefaultGeoName(geo_name: ?[*]u16, geo_name_count: c_int) callconv(.{ .x86_64_win = .{} }) c_int {
    const out = geo_name orelse return 3;
    if (geo_name_count < 3) return 0;
    out[0] = 'U';
    out[1] = 'S';
    out[2] = 0;
    return 3;
}

fn shim_GetUserDefaultLocaleName(locale_name: ?[*]u16, cch_locale_name: c_int) callconv(.{ .x86_64_win = .{} }) c_int {
    const out = locale_name orelse return 6;
    if (cch_locale_name < 6) return 0;
    out[0] = 'e';
    out[1] = 'n';
    out[2] = '-';
    out[3] = 'U';
    out[4] = 'S';
    out[5] = 0;
    return 6;
}

fn shim_strcpy(dst: ?[*:0]u8, src: ?[*:0]const u8) callconv(.{ .x86_64_win = .{} }) ?[*:0]u8 {
    const d = dst orelse return null;
    const s = src orelse {
        std.mem.writeInt(u8, @as([*]u8, @ptrCast(d))[0..1], 0, .little);
        return d;
    };
    var i: usize = 0;
    while (true) : (i += 1) {
        d[i] = s[i];
        if (s[i] == 0) break;
    }
    return d;
}

fn shim_strncpy(dst: ?[*:0]u8, src: ?[*:0]const u8, count: usize) callconv(.{ .x86_64_win = .{} }) ?[*:0]u8 {
    const d = dst orelse return null;
    const s = src orelse return d;
    var i: usize = 0;
    while (i < count and s[i] != 0) : (i += 1) {
        d[i] = s[i];
    }
    while (i < count) : (i += 1) {
        d[i] = 0;
    }
    return d;
}

fn shim_memcmp(s1: ?[*]const u8, s2: ?[*]const u8, n: usize) callconv(.{ .x86_64_win = .{} }) c_int {
    if (n == 0) return 0;
    const a = s1 orelse return -1;
    const b = s2 orelse return 1;
    return switch (std.mem.order(u8, a[0..n], b[0..n])) {
        .lt => -1,
        .eq => 0,
        .gt => 1,
    };
}

fn shim_GetFileTime(
    hFile: usize,
    lpCreationTime: ?*u64,
    lpLastAccessTime: ?*u64,
    lpLastWriteTime: ?*u64,
) callconv(.{ .x86_64_win = .{} }) i32 {
    _ = lookupFile(hFile) orelse return 0;
    const stamp: u64 = 134100000000000000; // Valid 2026 Windows FILETIME
    if (lpCreationTime) |t| t.* = stamp;
    if (lpLastAccessTime) |t| t.* = stamp;
    if (lpLastWriteTime) |t| t.* = stamp;
    return 1;
}

fn shim_strstr(haystack: ?[*:0]const u8, needle: ?[*:0]const u8) callconv(.{ .x86_64_win = .{} }) ?[*:0]const u8 {
    const h_ptr = haystack orelse return null;
    const n_ptr = needle orelse return h_ptr;
    const h = std.mem.span(h_ptr);
    const n = std.mem.span(n_ptr);
    if (n.len == 0) return h_ptr;
    const idx = std.mem.indexOf(u8, h, n) orelse return null;
    return h_ptr + idx;
}

const WinQsortCmp = *const fn (*const anyopaque, *const anyopaque) callconv(.{ .x86_64_win = .{} }) c_int;

fn shim_qsort(
    base_ptr: ?[*]u8,
    num: usize,
    width: usize,
    compar: ?WinQsortCmp,
) callconv(.{ .x86_64_win = .{} }) void {
    const base = base_ptr orelse return;
    const cmp = compar orelse return;
    if (num < 2 or width == 0) return;

    var tmp_storage: [1024]u8 = undefined;
    if (width > tmp_storage.len) return;
    const tmp = tmp_storage[0..width];

    var i: usize = 1;
    while (i < num) : (i += 1) {
        @memcpy(tmp, (base + i * width)[0..width]);
        var j: usize = i;
        while (j > 0) {
            const prev = base + (j - 1) * width;
            if (cmp(prev, tmp.ptr) <= 0) break;
            @memcpy((base + j * width)[0..width], prev[0..width]);
            j -= 1;
        }
        @memcpy((base + j * width)[0..width], tmp);
    }
}

fn shim_wcscmp(s1: ?[*:0]const u16, s2: ?[*:0]const u16) callconv(.{ .x86_64_win = .{} }) c_int {
    const a = s1 orelse return -1;
    const b = s2 orelse return 1;
    var i: usize = 0;
    while (true) : (i += 1) {
        if (a[i] != b[i]) return if (a[i] < b[i]) -1 else 1;
        if (a[i] == 0) return 0;
    }
}

fn shim_wcsicmp(s1: ?[*:0]const u16, s2: ?[*:0]const u16) callconv(.{ .x86_64_win = .{} }) c_int {
    const a = s1 orelse return -1;
    const b = s2 orelse return 1;
    var i: usize = 0;
    while (true) : (i += 1) {
        const ca = std.ascii.toLower(@as(u8, @truncate(a[i] & 0xFF)));
        const cb = std.ascii.toLower(@as(u8, @truncate(b[i] & 0xFF)));
        if (ca != cb) return if (ca < cb) -1 else 1;
        if (a[i] == 0) return 0;
    }
}

var g_stricmp_logs: usize = 0;

fn shim_stricmp(s1: ?[*:0]const u8, s2: ?[*:0]const u8) callconv(.{ .x86_64_win = .{} }) c_int {
    const a = std.mem.span(s1 orelse return -1);
    const b = std.mem.span(s2 orelse return 1);
    if (g_stricmp_logs < 25) {
        g_stricmp_logs += 1;
        std.log.info("[STR] _stricmp(\"{s}\", \"{s}\")", .{ a, b });
    }
    return switch (std.ascii.orderIgnoreCase(a, b)) {
        .lt => -1,
        .eq => 0,
        .gt => 1,
    };
}

fn shim_LocaleNameToLCID(lpName: ?[*:0]const u16, dwFlags: u32) callconv(.{ .x86_64_win = .{} }) u32 {
    _ = lpName;
    _ = dwFlags;
    return 0x0409;
}

pub fn resolve(sym_name: []const u8) ?usize {
    const map = .{
        .{ "MultiByteToWideChar", @intFromPtr(&shim_MultiByteToWideChar) },
        .{ "WideCharToMultiByte", @intFromPtr(&shim_WideCharToMultiByte) },
        .{ "strcspn", @intFromPtr(&shim_strcspn) },
        .{ "strspn", @intFromPtr(&shim_strspn) },
        .{ "strtok_s", @intFromPtr(&shim_strtok_s) },
        .{ "GetFileAttributesW", @intFromPtr(&shim_GetFileAttributesW) },
        .{ "GetFileAttributesExW", @intFromPtr(&shim_GetFileAttributesExW) },
        .{ "CreateFileW", @intFromPtr(&shim_CreateFileW) },
        .{ "ReadFile", @intFromPtr(&shim_ReadFile) },
        .{ "SetFilePointerEx", @intFromPtr(&shim_SetFilePointerEx) },
        .{ "GetFileSizeEx", @intFromPtr(&shim_GetFileSizeEx) },
        .{ "GetUserDefaultGeoName", @intFromPtr(&shim_GetUserDefaultGeoName) },
        .{ "GetUserDefaultLocaleName", @intFromPtr(&shim_GetUserDefaultLocaleName) },
        .{ "strcpy", @intFromPtr(&shim_strcpy) },
        .{ "strncpy", @intFromPtr(&shim_strncpy) },
        .{ "memcmp", @intFromPtr(&shim_memcmp) },
        .{ "GetFileTime", @intFromPtr(&shim_GetFileTime) },
        .{ "strstr", @intFromPtr(&shim_strstr) },
        .{ "qsort", @intFromPtr(&shim_qsort) },
        .{ "wcscmp", @intFromPtr(&shim_wcscmp) },
        .{ "_wcsicmp", @intFromPtr(&shim_wcsicmp) },
        .{ "wcsicmp", @intFromPtr(&shim_wcsicmp) },
        .{ "_stricmp", @intFromPtr(&shim_stricmp) },
        .{ "stricmp", @intFromPtr(&shim_stricmp) },
        .{ "LocaleNameToLCID", @intFromPtr(&shim_LocaleNameToLCID) },
    };

    inline for (map) |entry| {
        if (std.mem.eql(u8, entry.@"0", sym_name)) {
            return entry.@"1";
        }
    }
    return null;
}
