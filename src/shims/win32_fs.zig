//! Win32 file I/O backed by the host filesystem.
//!
//! Guest paths are mapped into one of two roots: the game directory (read-only
//! assets) or a writable save directory (user data).  The previous version was
//! hard-coded to one leaked install prefix and opened every file `"rb"`.

const std = @import("std");
const builtin = @import("builtin");
const teb = @import("../teb.zig");
const sync = @import("../sync.zig");
const host = @import("../win32_host.zig");

pub var g_game_dir: []const u8 = ".";
pub var g_save_dir: []const u8 = ".";
var g_initialized = false;

const MAX_FILES: usize = 256;
const FILE_HANDLE_BASE: usize = 0x50000;
const MAX_FINDS: usize = 32;
const FIND_HANDLE_BASE: usize = 0x60000;

const c_stdio = struct {
    extern "c" fn fseek(stream: *std.c.FILE, offset: c_long, whence: c_int) c_int;
    extern "c" fn ftell(stream: *std.c.FILE) c_long;
    extern "c" fn fflush(stream: *std.c.FILE) c_int;
};

const INVALID_HANDLE: usize = std.math.maxInt(usize);
const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFF_FFFF;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const FILE_APPEND_DATA: u32 = 0x0004;

const CREATE_NEW: u32 = 1;
const CREATE_ALWAYS: u32 = 2;
const OPEN_EXISTING: u32 = 3;
const OPEN_ALWAYS: u32 = 4;
const TRUNCATE_EXISTING: u32 = 5;

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

const FileObj = struct {
    fp: *std.c.FILE,
    writable: bool,
    append: bool,
    op_lock: SpinLock = .{},
};

const LinuxDirent = extern struct {
    ino: u64,
    off: i64,
    reclen: u16,
    type: u8,
    name: [256]u8,
};

extern "c" fn readdir(dir: *std.c.DIR) ?*LinuxDirent;

const FindObj = struct {
    dir: *std.c.DIR,
    pattern: [260]u8 = @splat(0),
    dir_path: [1024]u8 = @splat(0),
};

var g_files: [MAX_FILES]?*FileObj = @splat(null);
var g_file_lock: SpinLock = .{};
var g_finds: [MAX_FINDS]?*FindObj = @splat(null);
var g_find_lock: SpinLock = .{};

var g_audio_dir: ?[]const u8 = null;

pub fn init(game_dir: []const u8, save_dir: []const u8) void {
    g_game_dir = game_dir;
    g_save_dir = save_dir;
    g_initialized = true;
    ensureDir(save_dir);
}

pub fn setAudioDir(path: []const u8) void {
    g_audio_dir = path;
}

fn ensureDir(path: []const u8) void {
    if (builtin.os.tag == .linux) {
        if (path.len == 0 or path.len >= 1000) return;
        var buf: [1024]u8 = undefined;
        @memcpy(buf[0..path.len], path);
        buf[path.len] = 0;
        var i: usize = 1;
        while (i <= path.len) : (i += 1) {
            if (i != path.len and buf[i] != '/') continue;
            const saved = buf[i];
            buf[i] = 0;
            _ = std.c.mkdir(@ptrCast(&buf), 0o755);
            buf[i] = saved;
        }
    }
}

fn setErr(code: u32) void {
    teb.setLastError(code);
}

fn errnoNow() c_int {
    return std.c._errno().*;
}

// Win32 error codes used by the file APIs in this module.
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_NOT_SAME_DEVICE: u32 = 17;
const ERROR_WRITE_PROTECT: u32 = 19;
const ERROR_SHARING_VIOLATION: u32 = 32;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_DISK_FULL: u32 = 112;
const ERROR_DIR_NOT_EMPTY: u32 = 145;
const ERROR_ALREADY_EXISTS: u32 = 183;
const ERROR_DIRECTORY: u32 = 267;

/// Translate the current host errno into the Win32 error the equivalent API
/// reports.  Callers must read this immediately after the failing libc call.
fn win32ErrorFromErrno() u32 {
    if (builtin.os.tag == .windows) return ERROR_ACCESS_DENIED;
    return switch (errnoNow()) {
        @backingInt(std.c.E.NOENT) => ERROR_FILE_NOT_FOUND,
        @backingInt(std.c.E.ACCES), @backingInt(std.c.E.PERM) => ERROR_ACCESS_DENIED,
        @backingInt(std.c.E.EXIST) => ERROR_ALREADY_EXISTS,
        @backingInt(std.c.E.NOTEMPTY) => ERROR_DIR_NOT_EMPTY,
        @backingInt(std.c.E.ISDIR) => ERROR_ACCESS_DENIED,
        @backingInt(std.c.E.NOTDIR) => ERROR_DIRECTORY,
        @backingInt(std.c.E.XDEV) => ERROR_NOT_SAME_DEVICE,
        @backingInt(std.c.E.NOSPC) => ERROR_DISK_FULL,
        @backingInt(std.c.E.ROFS) => ERROR_WRITE_PROTECT,
        @backingInt(std.c.E.BUSY) => ERROR_SHARING_VIOLATION,
        else => ERROR_FILE_NOT_FOUND,
    };
}

const FILE_TYPE_UNKNOWN: u32 = 0;
const FILE_TYPE_DISK: u32 = 1;
const FILE_TYPE_CHAR: u32 = 2;
const FILE_TYPE_PIPE: u32 = 3;

const STD_INPUT_HANDLE: u32 = 0xFFFF_FFF6; // (DWORD)-10
const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5; // (DWORD)-11
const STD_ERROR_HANDLE: u32 = 0xFFFF_FFF4; // (DWORD)-12

var g_std_handles: [3]usize = .{ 0, 0, 0 }; // 0 = not created, INVALID_HANDLE = cleared
var g_std_lock: SpinLock = .{};

fn stdSlot(n: u32) ?usize {
    return switch (n) {
        STD_INPUT_HANDLE => 0,
        STD_OUTPUT_HANDLE => 1,
        STD_ERROR_HANDLE => 2,
        else => null,
    };
}

/// Wrap a host std fd in a FILE* so the regular file handle path serves it.
fn createStdHandle(slot: usize) usize {
    if (builtin.os.tag == .windows) {
        // Windows uses the host's std handles through host_imports.
        return INVALID_HANDLE;
    } else {
        const fd = std.c.dup(@intCast(slot));
        if (fd < 0) return INVALID_HANDLE;
        const fp = fdopen(fd, if (slot == 0) "rb" else "wb") orelse {
            _ = std.c.close(fd);
            return INVALID_HANDLE;
        };
        const handle = allocFile(fp, slot != 0, false);
        if (handle == 0) {
            _ = std.c.fclose(fp);
            return INVALID_HANDLE;
        }
        return handle;
    }
}

fn shim_GetStdHandle(nStdHandle: u32) callconv(.{ .x86_64_win = .{} }) usize {
    const slot = stdSlot(nStdHandle) orelse {
        setErr(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE;
    };
    g_std_lock.lock();
    defer g_std_lock.unlock();
    if (g_std_handles[slot] == 0) {
        const handle = createStdHandle(slot);
        if (handle == INVALID_HANDLE) return INVALID_HANDLE;
        g_std_handles[slot] = handle;
    }
    if (g_std_handles[slot] == INVALID_HANDLE) return 0; // cleared with SetStdHandle
    return g_std_handles[slot];
}

fn shim_SetStdHandle(nStdHandle: u32, hHandle: usize) callconv(.{ .x86_64_win = .{} }) i32 {
    const slot = stdSlot(nStdHandle) orelse {
        setErr(ERROR_INVALID_PARAMETER);
        return 0;
    };
    g_std_lock.lock();
    g_std_handles[slot] = if (hHandle == 0) INVALID_HANDLE else hHandle;
    g_std_lock.unlock();
    return 1;
}

fn shim_GetFileType(hFile: usize) callconv(.{ .x86_64_win = .{} }) u32 {
    if (hFile == 0 or hFile == INVALID_HANDLE) {
        setErr(ERROR_INVALID_HANDLE);
        return FILE_TYPE_UNKNOWN;
    }
    const obj = lookupFile(hFile) orelse {
        setErr(ERROR_INVALID_HANDLE);
        return FILE_TYPE_UNKNOWN;
    };
    if (builtin.os.tag == .windows) return FILE_TYPE_CHAR;
    const fd = cFileno(obj.fp);
    if (fd < 0) {
        setErr(ERROR_INVALID_HANDLE);
        return FILE_TYPE_UNKNOWN;
    }
    if (std.c.isatty(fd) != 0) return FILE_TYPE_CHAR;
    var sx: std.os.linux.Statx = undefined;
    @memset(std.mem.asBytes(&sx), 0);
    const mask: std.os.linux.STATX = .{ .TYPE = true };
    if (std.c.statx(fd, "", std.os.linux.AT.EMPTY_PATH, mask, &sx) != 0) {
        setErr(win32ErrorFromErrno());
        return FILE_TYPE_UNKNOWN;
    }
    return switch (sx.mode & 0xF000) {
        0x8000, 0x6000 => FILE_TYPE_DISK, // regular file / block device
        0x2000 => FILE_TYPE_CHAR, // character device
        0x1000, 0xC000 => FILE_TYPE_PIPE, // FIFO / socket
        else => FILE_TYPE_UNKNOWN,
    };
}

// ---------------------------------------------------------------------------
// Path mapping
// ---------------------------------------------------------------------------

fn utf16Len(p: [*:0]const u16) usize {
    var n: usize = 0;
    while (p[n] != 0) : (n += 1) {}
    return n;
}

fn toUtf8(w: [*:0]const u16, out: []u8) []const u8 {
    const n = std.unicode.utf16LeToUtf8(out, w[0..utf16Len(w)]) catch return "";
    return out[0..n];
}

fn isUserPath(lower: []const u8) bool {
    return std.mem.indexOf(u8, lower, "users/") != null or
        std.mem.indexOf(u8, lower, "appdata/") != null or
        std.mem.indexOf(u8, lower, "documents/") != null or
        std.mem.indexOf(u8, lower, "saved games/") != null or
        std.mem.indexOf(u8, lower, "programdata/") != null;
}

/// Convert a guest path to a host path, refusing to escape the chosen root.
/// `out` is always NUL-terminated on success.
fn mapPathBytes(raw: []const u8, out: *[2048]u8) []const u8 {
    var tmp: [1024]u8 = undefined;
    if (raw.len >= tmp.len) return "";
    for (raw, 0..) |c, i| tmp[i] = if (c == '\\') '/' else c;
    var path: []const u8 = tmp[0..raw.len];

    if (std.mem.startsWith(u8, path, "//?/")) path = path[4..];
    if (std.mem.startsWith(u8, path, "//./")) path = path[4..];
    var explicit_save = false;
    var explicit_audio = false;
    if (path.len >= 6 and std.ascii.eqlIgnoreCase(path[0..6], "audio:")) {
        explicit_audio = true;
        path = path[6..];
    } else if (path.len >= 2 and path[1] == ':') {
        explicit_save = std.ascii.toLower(path[0]) == 'x';
        path = path[2..];
    }
    while (path.len > 0 and path[0] == '/') path = path[1..];

    var lower_buf: [1024]u8 = undefined;
    const lower_len = @min(path.len, lower_buf.len);
    for (path[0..lower_len], 0..) |c, i| lower_buf[i] = std.ascii.toLower(c);
    const use_save = explicit_save or isUserPath(lower_buf[0..lower_len]);

    var parts: [64][]const u8 = undefined;
    var count: usize = 0;
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".")) continue;
        if (std.mem.eql(u8, part, "..")) {
            if (count > 0) count -= 1;
            continue;
        }
        if (count < parts.len) {
            parts[count] = part;
            count += 1;
        }
    }

    var rel: [1024]u8 = undefined;
    var rel_len: usize = 0;
    for (parts[0..count]) |part| {
        if (rel_len + part.len + 2 >= rel.len) return "";
        if (rel_len != 0) {
            rel[rel_len] = '/';
            rel_len += 1;
        }
        @memcpy(rel[rel_len .. rel_len + part.len], part);
        rel_len += part.len;
    }

    const base = if (explicit_audio)
        (g_audio_dir orelse g_game_dir)
    else if (use_save)
        g_save_dir
    else
        g_game_dir;
    const written = std.fmt.bufPrint(out[0 .. out.len - 1], "{s}/{s}", .{ base, rel[0..rel_len] }) catch return "";
    out[written.len] = 0;
    return written;
}

fn mapPath(w: ?[*:0]const u16, out: *[2048]u8) []const u8 {
    const ptr = w orelse return "";
    var utf8: [1024]u8 = undefined;
    const raw = toUtf8(ptr, &utf8);
    if (raw.len == 0 and ptr[0] != 0) return "";
    return mapPathBytes(raw, out);
}

fn mapPathA(a: ?[*:0]const u8, out: *[2048]u8) []const u8 {
    const ptr = a orelse return "";
    return mapPathBytes(std.mem.span(ptr), out);
}

fn zPath(buf: *[2048]u8, path: []const u8) [:0]const u8 {
    return buf[0..path.len :0];
}

// ---------------------------------------------------------------------------
// File handles
// ---------------------------------------------------------------------------

fn allocFile(fp: *std.c.FILE, writable: bool, append: bool) usize {
    const obj = std.heap.page_allocator.create(FileObj) catch return 0;
    obj.* = .{ .fp = fp, .writable = writable, .append = append };
    g_file_lock.lock();
    defer g_file_lock.unlock();
    for (&g_files, 0..) |*slot, i| {
        if (slot.* == null) {
            slot.* = obj;
            return FILE_HANDLE_BASE + i * 8;
        }
    }
    std.heap.page_allocator.destroy(obj);
    return 0;
}

fn lookupFile(handle: usize) ?*FileObj {
    if (handle < FILE_HANDLE_BASE) return null;
    const off = handle - FILE_HANDLE_BASE;
    if (off % 8 != 0) return null;
    const idx = off / 8;
    if (idx >= MAX_FILES) return null;
    g_file_lock.lock();
    defer g_file_lock.unlock();
    return g_files[idx];
}

fn freeFile(handle: usize) bool {
    if (handle < FILE_HANDLE_BASE) return false;
    const off = handle - FILE_HANDLE_BASE;
    if (off % 8 != 0) return false;
    const idx = off / 8;
    if (idx >= MAX_FILES) return false;
    g_file_lock.lock();
    const obj = g_files[idx];
    g_files[idx] = null;
    g_file_lock.unlock();
    if (obj) |o| {
        _ = std.c.fclose(o.fp);
        std.heap.page_allocator.destroy(o);
        return true;
    }
    return false;
}

fn probeFileSize(path_z: [*:0]const u8) ?u64 {
    const fp = std.c.fopen(path_z, "rb") orelse return null;
    defer _ = std.c.fclose(fp);
    if (c_stdio.fseek(fp, 0, 2) != 0) return null;
    const pos = c_stdio.ftell(fp);
    if (pos < 0) return null;
    return @intCast(pos);
}

fn isDirectory(path_z: [*:0]const u8) bool {
    if (builtin.os.tag == .linux) {
        const dir = std.c.opendir(path_z) orelse return false;
        _ = std.c.closedir(dir);
        return true;
    }
    return false;
}

/// Query one path with statx so callers can distinguish "missing" from
/// "denied".  On failure the host errno is left for `win32ErrorFromErrno`.
fn statxPath(path_z: [*:0]const u8) ?std.os.linux.Statx {
    if (builtin.os.tag == .windows) {
        // Non-Linux builds keep the previous libc metadata probe.
        var sx: std.os.linux.Statx = std.mem.zeroes(std.os.linux.Statx);
        if (isDirectory(path_z)) {
            sx.mode = 0x4000;
            return sx;
        }
        const size = probeFileSize(path_z) orelse return null;
        sx.mode = 0x8000;
        sx.size = size;
        return sx;
    } else {
        var sx: std.os.linux.Statx = undefined;
        @memset(std.mem.asBytes(&sx), 0);
        const mask: std.os.linux.STATX = .{ .TYPE = true, .SIZE = true };
        if (std.c.statx(std.os.linux.AT.FDCWD, path_z, 0, mask, &sx) != 0) return null;
        return sx;
    }
}

fn attributeFromMode(mode: u16) u32 {
    return switch (mode & 0xF000) {
        0x4000 => FILE_ATTRIBUTE_DIRECTORY,
        else => FILE_ATTRIBUTE_NORMAL,
    };
}

// ---------------------------------------------------------------------------
// CreateFile / reads / writes
// ---------------------------------------------------------------------------

fn accessWritable(access: u32) bool {
    return access & (GENERIC_WRITE | GENERIC_ALL | FILE_APPEND_DATA) != 0;
}

fn chooseMode(access: u32, disposition: u32) [:0]const u8 {
    const write = accessWritable(access);
    const read = access & (GENERIC_READ | GENERIC_ALL) != 0;
    if (access & FILE_APPEND_DATA != 0) return "ab";
    return switch (disposition) {
        CREATE_NEW => if (write and read) "w+xb" else if (write) "wxb" else "rb",
        CREATE_ALWAYS => if (write and read) "w+b" else if (write) "wb" else "rb",
        OPEN_EXISTING => if (write) "r+b" else "rb",
        OPEN_ALWAYS => if (write and read) "r+b" else if (write) "r+b" else "rb",
        TRUNCATE_EXISTING => if (write and read) "w+b" else if (write) "wb" else "rb",
        else => if (write) "r+b" else "rb",
    };
}

fn shim_CreateFileW(
    lpFileName: ?[*:0]const u16,
    dwDesiredAccess: u32,
    dwShareMode: u32,
    _: ?*anyopaque,
    dwCreationDisposition: u32,
    dwFlagsAndAttributes: u32,
    _: usize,
) callconv(.{ .x86_64_win = .{} }) usize {
    const name = lpFileName orelse {
        setErr(87);
        return INVALID_HANDLE;
    };
    var path_buf: [2048]u8 = undefined;
    const mapped = mapPath(name, &path_buf);
    if (mapped.len == 0) {
        setErr(87);
        return INVALID_HANDLE;
    }
    if (comptime builtin.os.tag == .windows) {
        const h = host.createFileW(mapped, dwDesiredAccess, dwShareMode, dwCreationDisposition, dwFlagsAndAttributes);
        if (h == INVALID_HANDLE) {
            setErr(host.lastError());
            std.log.warn("[FS] CreateFileW(\"{s}\") -> host error {d}", .{ mapped, host.lastError() });
            return INVALID_HANDLE;
        }
        std.log.info("[FS] CreateFileW(\"{s}\", host) -> 0x{x}", .{ mapped, h });
        return h;
    }
    const z = zPath(&path_buf, mapped);
    const write = accessWritable(dwDesiredAccess);
    const append = dwDesiredAccess & FILE_APPEND_DATA != 0;

    var fp = std.c.fopen(z.ptr, chooseMode(dwDesiredAccess, dwCreationDisposition).ptr);
    if (fp == null and dwCreationDisposition == OPEN_ALWAYS and write) {
        fp = std.c.fopen(z.ptr, "w+b");
    }
    if (fp == null) {
        setErr(2); // ERROR_FILE_NOT_FOUND
        std.log.warn("[FS] CreateFileW(\"{s}\") -> not found", .{mapped});
        return INVALID_HANDLE;
    }
    const handle = allocFile(fp.?, write, append);
    if (handle == 0) {
        _ = std.c.fclose(fp.?);
        setErr(8);
        return INVALID_HANDLE;
    }
    std.log.info("[FS] CreateFileW(\"{s}\", access=0x{x}, share=0x{x}, disp={d}, flags=0x{x}) -> 0x{x}", .{
        mapped, dwDesiredAccess, dwShareMode, dwCreationDisposition, dwFlagsAndAttributes, handle,
    });
    return handle;
}

fn shim_ReadFile(
    hFile: usize,
    lpBuffer: ?[*]u8,
    nNumberOfBytesToRead: u32,
    lpNumberOfBytesRead: ?*u32,
    lpOverlapped: ?[*]u8,
) callconv(.{ .x86_64_win = .{} }) i32 {
    if (comptime builtin.os.tag == .windows) {
        const buf = lpBuffer orelse return 0;
        return host.readFile(hFile, buf, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    }
    const obj = lookupFile(hFile) orelse {
        setErr(6);
        return 0;
    };
    const buf = lpBuffer orelse return 0;
    if (lpOverlapped) |ov| {
        const lo = std.mem.readInt(u32, ov[16..20], .little);
        const hi = std.mem.readInt(u32, ov[20..24], .little);
        const offset: u64 = (@as(u64, hi) << 32) | lo;
        const event = std.mem.readInt(usize, ov[24..32], .little);
        if (traceFs()) {
            std.log.info("[FS] ReadFile(h=0x{x}, len={d}, ov offset=0x{x}, event=0x{x})", .{
                hFile, nNumberOfBytesToRead, offset, event,
            });
        }
        // Overlapped reads are positional: pread must not move the Win32 file
        // pointer (Windows leaves it untouched for FILE_FLAG_OVERLAPPED I/O).
        const n = readAt(hFile, offset, buf[0..nNumberOfBytesToRead]) orelse {
            setErr(ERROR_INVALID_PARAMETER);
            std.mem.writeInt(u64, ov[0..8], 0xC000_0001, .little); // STATUS_UNSUCCESSFUL
            std.mem.writeInt(u64, ov[8..16], 0, .little);
            if (event != 0) _ = sync.setEvent(event);
            return 0;
        };
        if (lpNumberOfBytesRead) |out| out.* = @intCast(n);
        std.mem.writeInt(u64, ov[0..8], 0, .little);
        std.mem.writeInt(u64, ov[8..16], n, .little);
        if (event != 0) _ = sync.setEvent(event);
        if (traceFs()) std.log.info("[FS] ReadFile(h=0x{x}) -> n={d}", .{ hFile, n });
        return 1;
    }

    obj.op_lock.lock();
    defer obj.op_lock.unlock();
    const n = std.c.fread(buf, 1, nNumberOfBytesToRead, obj.fp);
    if (lpNumberOfBytesRead) |out| out.* = @intCast(n);
    if (traceFs()) {
        std.log.info("[FS] ReadFile(h=0x{x}, len={d}, sync) -> n={d}", .{
            hFile, nNumberOfBytesToRead, n,
        });
    }
    return 1;
}

fn shim_GetOverlappedResult(
    _: usize,
    lpOverlapped: ?[*]u8,
    lpNumberOfBytesTransferred: ?*u32,
    bWait: i32,
) callconv(.{ .x86_64_win = .{} }) i32 {
    const ov = lpOverlapped orelse {
        setErr(87);
        return 0;
    };
    const status = std.mem.readInt(u32, ov[0..4], .little);
    if (status == 0x103 and bWait != 0) {
        const event = std.mem.readInt(usize, ov[24..32], .little);
        if (event != 0) _ = sync.waitForSingleObject(event, 0xFFFF_FFFF);
    }
    if (status != 0 and status != 0x103) {
        // Mirrors a completed overlapped operation that failed.
        setErr(ERROR_INVALID_PARAMETER);
        if (lpNumberOfBytesTransferred) |out| out.* = 0;
        return 0;
    }
    const n = std.mem.readInt(u64, ov[8..16], .little);
    if (lpNumberOfBytesTransferred) |out| out.* = @intCast(n);
    return 1;
}

fn shim_CancelIo(_: usize) callconv(.{ .x86_64_win = .{} }) i32 {
    return 1;
}

fn shim_CancelIoEx(_: usize, _: ?[*]u8) callconv(.{ .x86_64_win = .{} }) i32 {
    return 1;
}

fn shim_WriteFile(
    hFile: usize,
    lpBuffer: ?[*]const u8,
    nNumberOfBytesToWrite: u32,
    lpNumberOfBytesWritten: ?*u32,
    lpOverlapped: ?[*]u8,
) callconv(.{ .x86_64_win = .{} }) i32 {
    if (comptime builtin.os.tag == .windows) {
        const buf = lpBuffer orelse return 0;
        return host.writeFile(hFile, buf, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
    }
    const obj = lookupFile(hFile) orelse {
        setErr(6);
        return 0;
    };
    if (!obj.writable) {
        setErr(5); // ERROR_ACCESS_DENIED
        return 0;
    }
    const buf = lpBuffer orelse return 0;
    if (lpOverlapped) |ov| {
        const lo = std.mem.readInt(u32, ov[16..20], .little);
        const hi = std.mem.readInt(u32, ov[20..24], .little);
        const offset: u64 = (@as(u64, hi) << 32) | lo;
        const event = std.mem.readInt(usize, ov[24..32], .little);
        const n = writeAt(hFile, offset, buf[0..nNumberOfBytesToWrite]) orelse {
            setErr(ERROR_ACCESS_DENIED);
            std.mem.writeInt(u64, ov[0..8], 0xC000_0001, .little);
            std.mem.writeInt(u64, ov[8..16], 0, .little);
            if (event != 0) _ = sync.setEvent(event);
            return 0;
        };
        if (lpNumberOfBytesWritten) |out| out.* = @intCast(n);
        std.mem.writeInt(u64, ov[0..8], 0, .little);
        std.mem.writeInt(u64, ov[8..16], n, .little);
        if (event != 0) _ = sync.setEvent(event);
        if (traceFs()) std.log.info("[FS] WriteFile(h=0x{x}, len={d}, ov offset=0x{x}) -> n={d}", .{
            hFile, nNumberOfBytesToWrite, offset, n,
        });
        return 1;
    }
    obj.op_lock.lock();
    defer obj.op_lock.unlock();
    const n = std.c.fwrite(buf, 1, nNumberOfBytesToWrite, obj.fp);
    _ = c_stdio.fflush(obj.fp);
    if (lpNumberOfBytesWritten) |out| out.* = @intCast(n);
    if (traceFs()) std.log.info("[FS] WriteFile(h=0x{x}, len={d}, sync) -> n={d}", .{
        hFile, nNumberOfBytesToWrite, n,
    });
    return 1;
}

fn shim_SetFilePointerEx(
    hFile: usize,
    liDistanceToMove: i64,
    lpNewFilePointer: ?*i64,
    dwMoveMethod: u32,
) callconv(.{ .x86_64_win = .{} }) i32 {
    if (comptime builtin.os.tag == .windows) {
        const pos = host.setFilePointer(hFile, liDistanceToMove, dwMoveMethod) orelse return 0;
        if (lpNewFilePointer) |out| out.* = @intCast(pos);
        return 1;
    }
    const obj = lookupFile(hFile) orelse return 0;
    const whence: c_int = @intCast(dwMoveMethod);
    if (whence < 0 or whence > 2) return 0;
    obj.op_lock.lock();
    defer obj.op_lock.unlock();
    if (c_stdio.fseek(obj.fp, @intCast(liDistanceToMove), whence) != 0) return 0;
    const pos = c_stdio.ftell(obj.fp);
    if (traceFs()) {
        std.log.info("[FS] SetFilePointerEx(h=0x{x}, dist={d}, method={d}) -> 0x{x}", .{
            hFile, liDistanceToMove, dwMoveMethod, pos,
        });
    }
    if (lpNewFilePointer) |out| {
        if (pos < 0) return 0;
        out.* = @intCast(pos);
    }
    return 1;
}

fn shim_GetFileSizeEx(hFile: usize, lpFileSize: ?*i64) callconv(.{ .x86_64_win = .{} }) i32 {
    if (comptime builtin.os.tag == .windows) {
        const size = host.getFileSize(hFile) orelse return 0;
        if (lpFileSize) |out| out.* = @intCast(size);
        return 1;
    }
    const obj = lookupFile(hFile) orelse return 0;
    obj.op_lock.lock();
    defer obj.op_lock.unlock();
    const cur = c_stdio.ftell(obj.fp);
    if (c_stdio.fseek(obj.fp, 0, 2) != 0) return 0;
    const end = c_stdio.ftell(obj.fp);
    _ = c_stdio.fseek(obj.fp, cur, 0);
    if (end < 0) return 0;
    if (traceFs()) std.log.info("[FS] GetFileSizeEx(h=0x{x}) -> {d}", .{ hFile, end });
    if (lpFileSize) |out| out.* = @intCast(end);
    return 1;
}

fn shim_SetEndOfFile(hFile: usize) callconv(.{ .x86_64_win = .{} }) i32 {
    if (comptime builtin.os.tag == .windows) {
        return if (host.setEndOfFile(hFile)) 1 else 0;
    }
    const obj = lookupFile(hFile) orelse return 0;
    obj.op_lock.lock();
    defer obj.op_lock.unlock();
    _ = c_stdio.fflush(obj.fp);
    if (builtin.os.tag == .linux) {
        const pos = c_stdio.ftell(obj.fp);
        if (pos < 0) return 0;
        const fd = cFileno(obj.fp);
        if (fd < 0) return 0;
        if (std.c.ftruncate(fd, @intCast(pos)) != 0) return 0;
    }
    return 1;
}

fn shim_FlushFileBuffers(hFile: usize) callconv(.{ .x86_64_win = .{} }) i32 {
    if (comptime builtin.os.tag == .windows) {
        return if (host.flush(hFile)) 1 else 0;
    }
    const obj = lookupFile(hFile) orelse return 0;
    obj.op_lock.lock();
    defer obj.op_lock.unlock();
    return if (c_stdio.fflush(obj.fp) == 0) 1 else 0;
}

pub fn closeHandle(hFile: usize) bool {
    if (comptime builtin.os.tag == .windows) return host.close(hFile);
    return freeFile(hFile);
}

extern "c" fn fileno(stream: *std.c.FILE) c_int;
fn cFileno(fp: *std.c.FILE) c_int {
    return fileno(fp);
}

const posix_io = if (builtin.os.tag == .linux) struct {
    extern "c" fn pread(fd: c_int, buf: ?*anyopaque, count: usize, offset: i64) isize;
    extern "c" fn pwrite(fd: c_int, buf: ?*const anyopaque, count: usize, offset: i64) isize;
} else struct {};

var g_host_io_lock: SpinLock = .{};

/// Open a guest path read-only and return a loader file handle.  Used by the
/// DStorage `IDStorageFileX` objects so `GetHandle` returns a handle that the
/// normal Win32 ReadFile/GetFileSizeEx shims understand.
pub fn openReadOnlyWide(path: ?[*:0]const u16) ?usize {
    var buf: [2048]u8 = undefined;
    const mapped = mapPath(path, &buf);
    if (mapped.len == 0) return null;
    if (comptime builtin.os.tag == .windows) {
        const h = host.createFileW(mapped, GENERIC_READ, 1, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL);
        return if (h == INVALID_HANDLE) null else h;
    }
    const z = zPath(&buf, mapped);
    const fp = std.c.fopen(z.ptr, "rb") orelse return null;
    const handle = allocFile(fp, false, false);
    if (handle == 0) {
        _ = std.c.fclose(fp);
        return null;
    }
    return handle;
}

/// Positional read that does not disturb the Win32 file pointer.  This is the
/// primitive behind overlapped ReadFile and DStorage file requests.
pub fn readAt(handle: usize, offset: u64, buf: []u8) ?usize {
    if (buf.len == 0) return 0;
    if (offset > @as(u64, std.math.maxInt(i64))) return null;
    if (comptime builtin.os.tag == .windows) {
        g_host_io_lock.lock();
        defer g_host_io_lock.unlock();
        const saved = host.setFilePointer(handle, 0, 1) orelse return null;
        defer _ = host.setFilePointer(handle, @intCast(saved), 0);
        if (host.setFilePointer(handle, @intCast(offset), 0) == null) return null;
        var got: u32 = 0;
        const want: u32 = @intCast(@min(buf.len, @as(usize, std.math.maxInt(u32))));
        if (host.readFile(handle, buf.ptr, want, &got, null) == 0) return null;
        return got;
    }
    const obj = lookupFile(handle) orelse return null;
    const fd = cFileno(obj.fp);
    if (fd < 0) return null;
    var total: usize = 0;
    while (total < buf.len) {
        const at = offset + total;
        if (at > @as(u64, std.math.maxInt(i64))) return null;
        const rc = posix_io.pread(fd, buf.ptr + total, buf.len - total, @intCast(at));
        if (rc < 0) {
            if (errnoNow() == @backingInt(std.c.E.INTR)) continue;
            return null;
        }
        if (rc == 0) break;
        total += @intCast(rc);
    }
    return total;
}

/// Positional write that does not disturb the Win32 file pointer.
pub fn writeAt(handle: usize, offset: u64, buf: []const u8) ?usize {
    if (buf.len == 0) return 0;
    if (offset > @as(u64, std.math.maxInt(i64))) return null;
    if (comptime builtin.os.tag == .windows) {
        g_host_io_lock.lock();
        defer g_host_io_lock.unlock();
        const saved = host.setFilePointer(handle, 0, 1) orelse return null;
        defer _ = host.setFilePointer(handle, @intCast(saved), 0);
        if (host.setFilePointer(handle, @intCast(offset), 0) == null) return null;
        var put: u32 = 0;
        const want: u32 = @intCast(@min(buf.len, @as(usize, std.math.maxInt(u32))));
        if (host.writeFile(handle, buf.ptr, want, &put, null) == 0) return null;
        return put;
    }
    const obj = lookupFile(handle) orelse return null;
    if (!obj.writable) return null;
    const fd = cFileno(obj.fp);
    if (fd < 0) return null;
    var total: usize = 0;
    while (total < buf.len) {
        const at = offset + total;
        if (at > @as(u64, std.math.maxInt(i64))) return null;
        const rc = posix_io.pwrite(fd, buf.ptr + total, buf.len - total, @intCast(at));
        if (rc < 0) {
            if (errnoNow() == @backingInt(std.c.E.INTR)) continue;
            return null;
        }
        if (rc == 0) break;
        total += @intCast(rc);
    }
    return total;
}

/// Current Win32 file pointer (stdio logical position on Linux).
pub fn currentOffset(handle: usize) ?u64 {
    if (comptime builtin.os.tag == .windows) {
        return host.setFilePointer(handle, 0, 1);
    }
    const obj = lookupFile(handle) orelse return null;
    obj.op_lock.lock();
    defer obj.op_lock.unlock();
    const pos = c_stdio.ftell(obj.fp);
    if (pos < 0) return null;
    return @intCast(pos);
}

var g_trace_fs: i8 = -1;
fn traceFs() bool {
    if (g_trace_fs < 0) g_trace_fs = if (std.c.getenv("SCARLETT_TRACE_FS") != null) 1 else 0;
    return g_trace_fs == 1;
}

extern "c" fn fdopen(fd: c_int, mode: [*:0]const u8) ?*std.c.FILE;

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

fn shim_GetFileAttributesW(lpFileName: ?[*:0]const u16) callconv(.{ .x86_64_win = .{} }) u32 {
    const name = lpFileName orelse {
        setErr(ERROR_INVALID_PARAMETER);
        return INVALID_FILE_ATTRIBUTES;
    };
    var buf: [2048]u8 = undefined;
    const mapped = mapPath(name, &buf);
    if (mapped.len == 0) {
        setErr(ERROR_FILE_NOT_FOUND);
        return INVALID_FILE_ATTRIBUTES;
    }
    const sx = statxPath(zPath(&buf, mapped).ptr) orelse {
        setErr(win32ErrorFromErrno());
        return INVALID_FILE_ATTRIBUTES;
    };
    return attributeFromMode(sx.mode);
}

fn shim_GetFileAttributesA(lpFileName: ?[*:0]const u8) callconv(.{ .x86_64_win = .{} }) u32 {
    const name = lpFileName orelse {
        setErr(ERROR_INVALID_PARAMETER);
        return INVALID_FILE_ATTRIBUTES;
    };
    var buf: [2048]u8 = undefined;
    const mapped = mapPathA(name, &buf);
    if (mapped.len == 0) {
        setErr(ERROR_FILE_NOT_FOUND);
        return INVALID_FILE_ATTRIBUTES;
    }
    const sx = statxPath(zPath(&buf, mapped).ptr) orelse {
        setErr(win32ErrorFromErrno());
        return INVALID_FILE_ATTRIBUTES;
    };
    return attributeFromMode(sx.mode);
}

fn shim_GetFileAttributesExW(
    lpFileName: ?[*:0]const u16,
    _: u32,
    lpFileInformation: ?[*]u8,
) callconv(.{ .x86_64_win = .{} }) i32 {
    const name = lpFileName orelse {
        setErr(ERROR_INVALID_PARAMETER);
        return 0;
    };
    var buf: [2048]u8 = undefined;
    const mapped = mapPath(name, &buf);
    if (mapped.len == 0) {
        setErr(ERROR_FILE_NOT_FOUND);
        return 0;
    }
    const sx = statxPath(zPath(&buf, mapped).ptr) orelse {
        setErr(win32ErrorFromErrno());
        return 0;
    };
    if (lpFileInformation) |info| {
        @memset(info[0..36], 0);
        std.mem.writeInt(u32, info[0..4], attributeFromMode(sx.mode), .little);
        std.mem.writeInt(u32, info[28..32], @truncate(sx.size >> 32), .little);
        std.mem.writeInt(u32, info[32..36], @truncate(sx.size & 0xFFFF_FFFF), .little);
    }
    return 1;
}

fn shim_SetFileAttributesW(lpFileName: ?[*:0]const u16, _: u32) callconv(.{ .x86_64_win = .{} }) i32 {
    const name = lpFileName orelse {
        setErr(ERROR_INVALID_PARAMETER);
        return 0;
    };
    var buf: [2048]u8 = undefined;
    const mapped = mapPath(name, &buf);
    if (mapped.len == 0) {
        setErr(ERROR_FILE_NOT_FOUND);
        return 0;
    }
    // DOS attribute bits are not modelled; report success once the path exists
    // and is accessible.
    _ = statxPath(zPath(&buf, mapped).ptr) orelse {
        setErr(win32ErrorFromErrno());
        return 0;
    };
    return 1;
}

fn shim_GetFileTime(
    hFile: usize,
    creation: ?*u64,
    access: ?*u64,
    write: ?*u64,
) callconv(.{ .x86_64_win = .{} }) i32 {
    _ = lookupFile(hFile) orelse return 0;
    const stamp: u64 = 134_100_000_000_000_000;
    if (creation) |p| p.* = stamp;
    if (access) |p| p.* = stamp;
    if (write) |p| p.* = stamp;
    return 1;
}

fn shim_SetFileTime(_: usize, _: ?*const u64, _: ?*const u64, _: ?*const u64) callconv(.{ .x86_64_win = .{} }) i32 {
    return 1;
}

fn shim_GetDiskFreeSpaceExW(
    _: ?[*:0]const u16,
    free_bytes: ?*u64,
    total_bytes: ?*u64,
    total_free: ?*u64,
) callconv(.{ .x86_64_win = .{} }) i32 {
    if (free_bytes) |p| p.* = 512 * 1024 * 1024 * 1024;
    if (total_bytes) |p| p.* = 1024 * 1024 * 1024 * 1024;
    if (total_free) |p| p.* = 512 * 1024 * 1024 * 1024;
    return 1;
}

// ---------------------------------------------------------------------------
// Directories, delete, move
// ---------------------------------------------------------------------------

fn shim_CreateDirectoryW(lpPathName: ?[*:0]const u16, _: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32 {
    const name = lpPathName orelse {
        setErr(ERROR_INVALID_PARAMETER);
        return 0;
    };
    var buf: [2048]u8 = undefined;
    const mapped = mapPath(name, &buf);
    if (mapped.len == 0) {
        setErr(ERROR_FILE_NOT_FOUND);
        return 0;
    }
    if (builtin.os.tag == .linux) {
        if (std.c.mkdir(zPath(&buf, mapped).ptr, 0o755) == 0) return 1;
        // Win32: an existing directory (or file) is FALSE + ERROR_ALREADY_EXISTS.
        setErr(win32ErrorFromErrno());
        return 0;
    }
    return 0;
}

fn shim_RemoveDirectoryW(lpPathName: ?[*:0]const u16) callconv(.{ .x86_64_win = .{} }) i32 {
    const name = lpPathName orelse {
        setErr(ERROR_INVALID_PARAMETER);
        return 0;
    };
    var buf: [2048]u8 = undefined;
    const mapped = mapPath(name, &buf);
    if (mapped.len == 0) {
        setErr(ERROR_FILE_NOT_FOUND);
        return 0;
    }
    if (builtin.os.tag == .linux) {
        if (std.c.rmdir(zPath(&buf, mapped).ptr) == 0) return 1;
        setErr(win32ErrorFromErrno());
        return 0;
    }
    return 0;
}

fn shim_DeleteFileW(lpFileName: ?[*:0]const u16) callconv(.{ .x86_64_win = .{} }) i32 {
    const name = lpFileName orelse {
        setErr(ERROR_INVALID_PARAMETER);
        return 0;
    };
    var buf: [2048]u8 = undefined;
    const mapped = mapPath(name, &buf);
    if (mapped.len == 0) {
        setErr(ERROR_FILE_NOT_FOUND);
        return 0;
    }
    if (builtin.os.tag == .linux) {
        if (std.c.unlink(zPath(&buf, mapped).ptr) == 0) return 1;
        setErr(win32ErrorFromErrno());
        return 0;
    }
    return 0;
}

fn shim_MoveFileExW(
    existing: ?[*:0]const u16,
    new_name: ?[*:0]const u16,
    flags: u32,
) callconv(.{ .x86_64_win = .{} }) i32 {
    const a = existing orelse return 0;
    const b = new_name orelse return 0;
    var buf_a: [2048]u8 = undefined;
    var buf_b: [2048]u8 = undefined;
    const old = mapPath(a, &buf_a);
    const new = mapPath(b, &buf_b);
    if (old.len == 0 or new.len == 0) return 0;
    const old_z = zPath(&buf_a, old);
    const new_z = zPath(&buf_b, new);
    if (builtin.os.tag == .linux) {
        if (std.c.rename(old_z.ptr, new_z.ptr) == 0) return 1;
        if (flags & 0x1 != 0) { // MOVEFILE_REPLACE_EXISTING
            _ = std.c.unlink(new_z.ptr);
            if (std.c.rename(old_z.ptr, new_z.ptr) == 0) return 1;
        }
        setErr(win32ErrorFromErrno());
        return 0;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// FindFirstFile / FindNextFile
// ---------------------------------------------------------------------------

fn wildcardMatch(pattern: []const u8, name: []const u8) bool {
    var pi: usize = 0;
    var ni: usize = 0;
    var star: ?usize = null;
    var star_name: usize = 0;
    while (ni < name.len) {
        if (pi < pattern.len and (pattern[pi] == '?' or
            std.ascii.toLower(pattern[pi]) == std.ascii.toLower(name[ni])))
        {
            pi += 1;
            ni += 1;
        } else if (pi < pattern.len and pattern[pi] == '*') {
            star = pi;
            pi += 1;
            star_name = ni;
        } else if (star) |s| {
            pi = s + 1;
            star_name += 1;
            ni = star_name;
        } else return false;
    }
    while (pi < pattern.len and pattern[pi] == '*') pi += 1;
    return pi == pattern.len;
}

fn fillFindData(obj: *FindObj, name: []const u8, data: [*]u8, is_dir: bool) void {
    @memset(data[0..592], 0);
    const attrs: u32 = if (is_dir) FILE_ATTRIBUTE_DIRECTORY else FILE_ATTRIBUTE_NORMAL;
    std.mem.writeInt(u32, data[0..4], attrs, .little);
    if (!is_dir) {
        var full: [2048]u8 = undefined;
        const dir_len = std.mem.indexOfScalar(u8, obj.dir_path[0..], 0) orelse 0;
        const written = std.fmt.bufPrint(full[0 .. full.len - 1], "{s}/{s}", .{
            obj.dir_path[0..dir_len], name,
        }) catch "";
        if (written.len > 0) {
            full[written.len] = 0;
            if (probeFileSize(@ptrCast(&full)) != null) {
                const size = probeFileSize(@ptrCast(&full)).?;
                std.mem.writeInt(u32, data[28..32], @truncate(size >> 32), .little);
                std.mem.writeInt(u32, data[32..36], @truncate(size & 0xFFFF_FFFF), .little);
            }
        }
    }
    var wbuf: [260]u16 = undefined;
    const n = std.unicode.utf8ToUtf16Le(&wbuf, name) catch 0;
    const copy = @min(n, 259);
    var i: usize = 0;
    while (i < copy) : (i += 1) std.mem.writeInt(u16, data[44 + i * 2 ..][0..2], wbuf[i], .little);
    std.mem.writeInt(u16, data[44 + copy * 2 ..][0..2], 0, .little);
}

fn findNext(obj: *FindObj, data: [*]u8) bool {
    while (true) {
        const ent = readdir(obj.dir) orelse return false;
        const name = std.mem.sliceTo(ent.name[0..], 0);
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
        if (!wildcardMatch(std.mem.sliceTo(obj.pattern[0..], 0), name)) continue;
        fillFindData(obj, name, data, ent.type == 4);
        return true;
    }
}

fn allocFind(obj: *FindObj) usize {
    g_find_lock.lock();
    defer g_find_lock.unlock();
    for (&g_finds, 0..) |*slot, i| {
        if (slot.* == null) {
            slot.* = obj;
            return FIND_HANDLE_BASE + i * 8;
        }
    }
    return INVALID_HANDLE;
}

fn lookupFind(handle: usize) ?*FindObj {
    if (handle < FIND_HANDLE_BASE) return null;
    const off = handle - FIND_HANDLE_BASE;
    if (off % 8 != 0) return null;
    const idx = off / 8;
    if (idx >= MAX_FINDS) return null;
    g_find_lock.lock();
    defer g_find_lock.unlock();
    return g_finds[idx];
}

fn freeFind(handle: usize) bool {
    if (handle < FIND_HANDLE_BASE) return false;
    const off = handle - FIND_HANDLE_BASE;
    if (off % 8 != 0) return false;
    const idx = off / 8;
    if (idx >= MAX_FINDS) return false;
    g_find_lock.lock();
    const obj = g_finds[idx];
    g_finds[idx] = null;
    g_find_lock.unlock();
    if (obj) |o| {
        _ = std.c.closedir(o.dir);
        std.heap.page_allocator.destroy(o);
        return true;
    }
    return false;
}

fn findFirstLinux(raw: []const u8, out: [*]u8) usize {
    var dir_part: []const u8 = ".";
    var pattern: []const u8 = raw;
    if (std.mem.lastIndexOfScalar(u8, raw, '/')) |slash| {
        dir_part = raw[0..slash];
        pattern = raw[slash + 1 ..];
        if (dir_part.len == 0) dir_part = "/";
    }
    if (pattern.len == 0) pattern = "*";

    var host_dir: [2048]u8 = undefined;
    const mapped_dir = mapPathBytes(dir_part, &host_dir);
    if (mapped_dir.len == 0) return INVALID_HANDLE;
    const z = zPath(&host_dir, mapped_dir);
    const dir = std.c.opendir(z.ptr) orelse {
        setErr(2);
        return INVALID_HANDLE;
    };

    const obj = std.heap.page_allocator.create(FindObj) catch {
        _ = std.c.closedir(dir);
        return INVALID_HANDLE;
    };
    obj.* = .{ .dir = dir };
    const plen = @min(pattern.len, obj.pattern.len - 1);
    @memcpy(obj.pattern[0..plen], pattern[0..plen]);
    obj.pattern[plen] = 0;
    const dlen = @min(mapped_dir.len, obj.dir_path.len - 1);
    @memcpy(obj.dir_path[0..dlen], mapped_dir[0..dlen]);
    obj.dir_path[dlen] = 0;

    if (!findNext(obj, out)) {
        _ = std.c.closedir(dir);
        std.heap.page_allocator.destroy(obj);
        setErr(18); // ERROR_NO_MORE_FILES
        return INVALID_HANDLE;
    }
    const handle = allocFind(obj);
    if (handle == INVALID_HANDLE) {
        _ = std.c.closedir(dir);
        std.heap.page_allocator.destroy(obj);
        return INVALID_HANDLE;
    }
    return handle;
}

fn shim_FindFirstFileW(lpFileName: ?[*:0]const u16, data: ?[*]u8) callconv(.{ .x86_64_win = .{} }) usize {
    const name = lpFileName orelse return INVALID_HANDLE;
    const out = data orelse return INVALID_HANDLE;
    var utf8: [1024]u8 = undefined;
    const raw = toUtf8(name, &utf8);
    if (raw.len == 0) return INVALID_HANDLE;

    if (builtin.os.tag == .linux) {
        var norm: [1024]u8 = undefined;
        for (raw, 0..) |c, i| norm[i] = if (c == '\\') '/' else c;
        return findFirstLinux(norm[0..raw.len], out);
    }
    setErr(50); // ERROR_NOT_SUPPORTED
    return INVALID_HANDLE;
}

fn shim_FindNextFileW(handle: usize, data: ?[*]u8) callconv(.{ .x86_64_win = .{} }) i32 {
    if (builtin.os.tag == .linux) {
        const obj = lookupFind(handle) orelse return 0;
        const out = data orelse return 0;
        return if (findNext(obj, out)) 1 else 0;
    }
    return 0;
}

fn shim_FindClose(handle: usize) callconv(.{ .x86_64_win = .{} }) i32 {
    return if (freeFind(handle)) 1 else 0;
}

// ---------------------------------------------------------------------------
// CRT file helpers
// ---------------------------------------------------------------------------

fn shim__wstat64(path: ?[*:0]const u16, out: ?[*]u8) callconv(.{ .x86_64_win = .{} }) i32 {
    const name = path orelse return -1;
    const buf = out orelse return -1;
    var pbuf: [2048]u8 = undefined;
    const mapped = mapPath(name, &pbuf);
    if (mapped.len == 0) return -1;
    const z = zPath(&pbuf, mapped);
    const size = probeFileSize(z.ptr) orelse blk: {
        if (!isDirectory(z.ptr)) return -1;
        break :blk 0;
    };
    @memset(buf[0..56], 0);
    const is_dir = isDirectory(z.ptr);
    std.mem.writeInt(u16, buf[6..8], if (is_dir) 0x4000 else 0x8000, .little);
    std.mem.writeInt(i64, buf[24..32], @intCast(size), .little);
    return 0;
}

fn shim_remove(path: ?[*:0]const u8) callconv(.{ .x86_64_win = .{} }) c_int {
    const name = path orelse return -1;
    var buf: [2048]u8 = undefined;
    const mapped = mapPathA(name, &buf);
    if (mapped.len == 0) return -1;
    if (builtin.os.tag == .linux) {
        return std.c.unlink(zPath(&buf, mapped).ptr);
    }
    return -1;
}

fn shim__lock_file(_: ?*std.c.FILE) callconv(.{ .x86_64_win = .{} }) void {}
fn shim__unlock_file(_: ?*std.c.FILE) callconv(.{ .x86_64_win = .{} }) void {}

// ---------------------------------------------------------------------------
// Existing string / locale shims retained
// ---------------------------------------------------------------------------

fn shim_MultiByteToWideChar(
    _: u32,
    _: u32,
    src_ptr: ?[*]const u8,
    src_len: c_int,
    dst_ptr: ?[*]u16,
    dst_len: c_int,
) callconv(.{ .x86_64_win = .{} }) c_int {
    const src = src_ptr orelse return 0;
    const actual_len: usize = if (src_len < 0)
        std.mem.len(@as([*:0]const u8, @ptrCast(src))) + 1
    else
        @intCast(src_len);
    if (dst_ptr == null or dst_len == 0) return @intCast(actual_len);
    const dst = dst_ptr.?;
    const copy_count = @min(actual_len, @as(usize, @intCast(dst_len)));
    var i: usize = 0;
    while (i < copy_count) : (i += 1) dst[i] = src[i];
    return @intCast(copy_count);
}

fn shim_WideCharToMultiByte(
    _: u32,
    _: u32,
    src_ptr: ?[*]const u16,
    src_len: c_int,
    dst_ptr: ?[*]u8,
    dst_len: c_int,
    _: ?*const u8,
    used_default: ?*i32,
) callconv(.{ .x86_64_win = .{} }) c_int {
    if (used_default) |u| u.* = 0;
    const src = src_ptr orelse return 0;
    const actual_len: usize = if (src_len < 0) blk: {
        var n: usize = 0;
        while (src[n] != 0) : (n += 1) {}
        break :blk n + 1;
    } else @intCast(src_len);
    if (dst_ptr == null or dst_len == 0) return @intCast(actual_len);
    const dst = dst_ptr.?;
    const copy_count = @min(actual_len, @as(usize, @intCast(dst_len)));
    var i: usize = 0;
    while (i < copy_count) : (i += 1) dst[i] = @truncate(src[i] & 0x7F);
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

fn shim_strtok_s(str: ?[*:0]u8, delim: ?[*:0]const u8, context: ?*?[*]u8) callconv(.{ .x86_64_win = .{} }) ?[*:0]u8 {
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
    const text = "en-US\x00";
    for (text, 0..) |c, i| out[i] = c;
    return 6;
}

fn shim_strcpy(dst: ?[*:0]u8, src: ?[*:0]const u8) callconv(.{ .x86_64_win = .{} }) ?[*:0]u8 {
    const d = dst orelse return null;
    const s = src orelse {
        d[0] = 0;
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
    while (i < count and s[i] != 0) : (i += 1) d[i] = s[i];
    while (i < count) : (i += 1) d[i] = 0;
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

fn shim_qsort(base_ptr: ?[*]u8, num: usize, width: usize, compar: ?WinQsortCmp) callconv(.{ .x86_64_win = .{} }) void {
    const base = base_ptr orelse return;
    const cmp = compar orelse return;
    if (num < 2 or width == 0 or width > 1024) return;
    var tmp_storage: [1024]u8 = undefined;
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

fn shim_LocaleNameToLCID(_: ?[*:0]const u16, _: u32) callconv(.{ .x86_64_win = .{} }) u32 {
    return 0x0409;
}

pub fn mapWidePath(w: ?[*:0]const u16, out: *[2048]u8) []const u8 {
    return mapPath(w, out);
}

pub fn mapAnsiPath(a: ?[*:0]const u8, out: *[2048]u8) []const u8 {
    return mapPathA(a, out);
}

/// File size for a handle, preserving the current file position.
pub fn fileSize(handle: usize) ?u64 {
    if (comptime builtin.os.tag == .windows) return host.getFileSize(handle);
    const obj = lookupFile(handle) orelse return null;
    const cur = c_stdio.ftell(obj.fp);
    if (c_stdio.fseek(obj.fp, 0, 2) != 0) return null;
    const end = c_stdio.ftell(obj.fp);
    _ = c_stdio.fseek(obj.fp, cur, 0);
    if (end < 0) return null;
    return @intCast(end);
}

fn shim_FindFirstFileExW(
    lpFileName: ?[*:0]const u16,
    _: u32,
    data: ?[*]u8,
    _: u32,
    _: ?*anyopaque,
    _: ?*anyopaque,
) callconv(.{ .x86_64_win = .{} }) usize {
    return shim_FindFirstFileW(lpFileName, data);
}

fn shim_GetFileInformationByHandle(hFile: usize, out: ?[*]u8) callconv(.{ .x86_64_win = .{} }) i32 {
    if (comptime builtin.os.tag == .windows) {
        const buf = out orelse return 0;
        return if (host.fileInformation(hFile, @ptrCast(buf))) 1 else 0;
    }
    const buf = out orelse return 0;
    const size = fileSize(hFile) orelse return 0;
    @memset(buf[0..52], 0);
    std.mem.writeInt(u32, buf[0..4], FILE_ATTRIBUTE_NORMAL, .little);
    std.mem.writeInt(u32, buf[32..36], @truncate(size >> 32), .little);
    std.mem.writeInt(u32, buf[36..40], @truncate(size & 0xFFFF_FFFF), .little);
    std.mem.writeInt(u32, buf[40..44], 1, .little);
    return 1;
}

fn shim_GetTempPathW(nBufferLength: u32, lpBuffer: ?[*]u16) callconv(.{ .x86_64_win = .{} }) u32 {
    const out = lpBuffer orelse return 0;
    const text = "C:\\Users\\Temp\\";
    if (nBufferLength < text.len + 1) return @intCast(text.len + 1);
    var i: usize = 0;
    while (i < text.len) : (i += 1) out[i] = text[i];
    out[i] = 0;
    return @intCast(i);
}

fn shim__wrename(old: ?[*:0]const u16, new: ?[*:0]const u16) callconv(.{ .x86_64_win = .{} }) c_int {
    var a: [2048]u8 = undefined;
    var b: [2048]u8 = undefined;
    const old_path = mapPath(old, &a);
    const new_path = mapPath(new, &b);
    if (old_path.len == 0 or new_path.len == 0) return -1;
    if (builtin.os.tag == .linux) {
        return std.c.rename(zPath(&a, old_path).ptr, zPath(&b, new_path).ptr);
    }
    return -1;
}

fn shim__wremove(path: ?[*:0]const u16) callconv(.{ .x86_64_win = .{} }) c_int {
    var buf: [2048]u8 = undefined;
    const mapped = mapPath(path, &buf);
    if (mapped.len == 0) return -1;
    if (builtin.os.tag == .linux) {
        return std.c.unlink(zPath(&buf, mapped).ptr);
    }
    return -1;
}

fn shim__wrmdir(path: ?[*:0]const u16) callconv(.{ .x86_64_win = .{} }) c_int {
    var buf: [2048]u8 = undefined;
    const mapped = mapPath(path, &buf);
    if (mapped.len == 0) return -1;
    if (builtin.os.tag == .linux) {
        return std.c.rmdir(zPath(&buf, mapped).ptr);
    }
    return -1;
}

fn shim__wchdir(path: ?[*:0]const u16) callconv(.{ .x86_64_win = .{} }) c_int {
    var buf: [2048]u8 = undefined;
    const mapped = mapPath(path, &buf);
    if (mapped.len == 0) return -1;
    if (builtin.os.tag == .linux) {
        return std.c.chdir(zPath(&buf, mapped).ptr);
    }
    return -1;
}

fn shim__wgetcwd(buf: ?[*]u16, size: c_int) callconv(.{ .x86_64_win = .{} }) ?[*]u16 {
    const out = buf orelse return null;
    if (size <= 0) return null;
    const src = teb.cwdW();
    if (src.len >= @as(usize, @intCast(size))) return null;
    @memcpy(out[0..src.len], src);
    out[src.len] = 0;
    return out;
}

fn shim_CreateHardLinkW(new_name: ?[*:0]const u16, existing: ?[*:0]const u16, _: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32 {
    var a: [2048]u8 = undefined;
    var b: [2048]u8 = undefined;
    const new_path = mapPath(new_name, &a);
    const old_path = mapPath(existing, &b);
    if (new_path.len == 0 or old_path.len == 0) return 0;
    if (builtin.os.tag == .linux) {
        return if (std.c.link(zPath(&b, old_path).ptr, zPath(&a, new_path).ptr) == 0) 1 else 0;
    }
    return 0;
}

fn shim_CreateSymbolicLinkW(new_name: ?[*:0]const u16, existing: ?[*:0]const u16, flags: u32) callconv(.{ .x86_64_win = .{} }) i32 {
    _ = flags;
    var a: [2048]u8 = undefined;
    var b: [2048]u8 = undefined;
    const new_path = mapPath(new_name, &a);
    const old_path = mapPath(existing, &b);
    if (new_path.len == 0 or old_path.len == 0) return 0;
    if (builtin.os.tag == .linux) {
        return if (std.c.symlink(zPath(&b, old_path).ptr, zPath(&a, new_path).ptr) == 0) 1 else 0;
    }
    return 0;
}

fn shim_CopyFile2(existing: ?[*:0]const u16, new_name: ?[*:0]const u16, _: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32 {
    var a: [2048]u8 = undefined;
    var b: [2048]u8 = undefined;
    const src_path = mapPath(existing, &a);
    const dst_path = mapPath(new_name, &b);
    if (src_path.len == 0 or dst_path.len == 0) return -2147024894;
    const src = std.c.fopen(zPath(&a, src_path).ptr, "rb") orelse return -2147024894;
    defer _ = std.c.fclose(src);
    const dst = std.c.fopen(zPath(&b, dst_path).ptr, "wb") orelse return -2147024894;
    defer _ = std.c.fclose(dst);
    var buf: [65536]u8 = undefined;
    while (true) {
        const n = std.c.fread(&buf, 1, buf.len, src);
        if (n == 0) break;
        if (std.c.fwrite(&buf, 1, n, dst) != n) return -2147024882;
    }
    return 0;
}

pub fn resolve(sym_name: []const u8) ?usize {
    const map = .{
        .{ "MultiByteToWideChar", @intFromPtr(&shim_MultiByteToWideChar) },
        .{ "WideCharToMultiByte", @intFromPtr(&shim_WideCharToMultiByte) },
        .{ "strcspn", @intFromPtr(&shim_strcspn) },
        .{ "strspn", @intFromPtr(&shim_strspn) },
        .{ "strtok_s", @intFromPtr(&shim_strtok_s) },
        .{ "GetFileAttributesW", @intFromPtr(&shim_GetFileAttributesW) },
        .{ "GetFileAttributesA", @intFromPtr(&shim_GetFileAttributesA) },
        .{ "GetFileAttributesExW", @intFromPtr(&shim_GetFileAttributesExW) },
        .{ "SetFileAttributesW", @intFromPtr(&shim_SetFileAttributesW) },
        .{ "CreateFileW", @intFromPtr(&shim_CreateFileW) },
        .{ "ReadFile", @intFromPtr(&shim_ReadFile) },
        .{ "GetOverlappedResult", @intFromPtr(&shim_GetOverlappedResult) },
        .{ "CancelIo", @intFromPtr(&shim_CancelIo) },
        .{ "CancelIoEx", @intFromPtr(&shim_CancelIoEx) },
        .{ "WriteFile", @intFromPtr(&shim_WriteFile) },
        .{ "SetFilePointerEx", @intFromPtr(&shim_SetFilePointerEx) },
        .{ "GetFileSizeEx", @intFromPtr(&shim_GetFileSizeEx) },
        .{ "SetEndOfFile", @intFromPtr(&shim_SetEndOfFile) },
        .{ "FlushFileBuffers", @intFromPtr(&shim_FlushFileBuffers) },
        .{ "GetStdHandle", @intFromPtr(&shim_GetStdHandle) },
        .{ "SetStdHandle", @intFromPtr(&shim_SetStdHandle) },
        .{ "GetFileType", @intFromPtr(&shim_GetFileType) },
        .{ "GetFileTime", @intFromPtr(&shim_GetFileTime) },
        .{ "SetFileTime", @intFromPtr(&shim_SetFileTime) },
        .{ "GetDiskFreeSpaceExW", @intFromPtr(&shim_GetDiskFreeSpaceExW) },
        .{ "CreateDirectoryW", @intFromPtr(&shim_CreateDirectoryW) },
        .{ "RemoveDirectoryW", @intFromPtr(&shim_RemoveDirectoryW) },
        .{ "DeleteFileW", @intFromPtr(&shim_DeleteFileW) },
        .{ "MoveFileExW", @intFromPtr(&shim_MoveFileExW) },
        .{ "FindFirstFileW", @intFromPtr(&shim_FindFirstFileW) },
        .{ "FindFirstFileExW", @intFromPtr(&shim_FindFirstFileExW) },
        .{ "GetFileInformationByHandle", @intFromPtr(&shim_GetFileInformationByHandle) },
        .{ "GetTempPathW", @intFromPtr(&shim_GetTempPathW) },
        .{ "_wrename", @intFromPtr(&shim__wrename) },
        .{ "_wremove", @intFromPtr(&shim__wremove) },
        .{ "_wrmdir", @intFromPtr(&shim__wrmdir) },
        .{ "_wchdir", @intFromPtr(&shim__wchdir) },
        .{ "_wgetcwd", @intFromPtr(&shim__wgetcwd) },
        .{ "CreateHardLinkW", @intFromPtr(&shim_CreateHardLinkW) },
        .{ "CreateSymbolicLinkW", @intFromPtr(&shim_CreateSymbolicLinkW) },
        .{ "CopyFile2", @intFromPtr(&shim_CopyFile2) },
        .{ "FindNextFileW", @intFromPtr(&shim_FindNextFileW) },
        .{ "FindClose", @intFromPtr(&shim_FindClose) },
        .{ "_wstat64", @intFromPtr(&shim__wstat64) },
        .{ "remove", @intFromPtr(&shim_remove) },
        .{ "_lock_file", @intFromPtr(&shim__lock_file) },
        .{ "_unlock_file", @intFromPtr(&shim__unlock_file) },
        .{ "GetUserDefaultGeoName", @intFromPtr(&shim_GetUserDefaultGeoName) },
        .{ "GetUserDefaultLocaleName", @intFromPtr(&shim_GetUserDefaultLocaleName) },
        .{ "strcpy", @intFromPtr(&shim_strcpy) },
        .{ "strncpy", @intFromPtr(&shim_strncpy) },
        .{ "memcmp", @intFromPtr(&shim_memcmp) },
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
        if (std.mem.eql(u8, entry.@"0", sym_name)) return entry.@"1";
    }
    return null;
}

test "guest paths map into game/save roots" {
    const old_game = g_game_dir;
    const old_save = g_save_dir;
    defer {
        g_game_dir = old_game;
        g_save_dir = old_save;
    }
    g_game_dir = "/game";
    g_save_dir = "/save";

    var buf: [2048]u8 = undefined;
    try std.testing.expectEqualStrings("/game/data/file.bin", mapPathBytes("data\\file.bin", &buf));
    try std.testing.expectEqualStrings("/save/Users/bob/save.dat", mapPathBytes("C:\\Users\\bob\\save.dat", &buf));
    try std.testing.expectEqualStrings("/game/etc", mapPathBytes("../../../etc", &buf));
}
