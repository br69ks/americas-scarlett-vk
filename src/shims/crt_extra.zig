//! SEH, FLS, pointer-encoding, and locale/CRT entry points that the MSVC
//! runtime needs before it can load.  The full x64 unwinder is not here yet;
//! this provides real .pdata lookup and a correct CONTEXT capture so the CRT
//! can install its handlers.

const std = @import("std");
const builtin = @import("builtin");
const teb = @import("../teb.zig");
const module = @import("../module.zig");
const seh = @import("../seh.zig");
const sync = @import("../sync.zig");
const thread_exit = @import("../thread_exit.zig");
const win32_fs = @import("win32_fs.zig");

const win: std.builtin.CallingConvention = .{ .x86_64_win = .{} };

// ---------------------------------------------------------------------------
// CONTEXT / SEH
// ---------------------------------------------------------------------------

// CONTEXT capture/restore, virtual unwind, dispatch and RtlUnwind live in
// ../seh.zig; crt_extra only re-exports them through `resolve`.

fn shim_IsDebuggerPresent() callconv(win) i32 {
    return 0;
}

/// The loader never converts guest threads to fibers, so every thread is a
/// plain thread.  The UCRT checks this before using the TEB global-state slot.
fn shim_IsThreadAFiber() callconv(win) i32 {
    return 0;
}

// ---------------------------------------------------------------------------
// OS version
// ---------------------------------------------------------------------------

/// The guest is a Windows 10 GDK title; report the version it was built for.
/// The UCRT selects the TEB `ReservedForCrt` global-state slot over an FLS
/// slot when `VerifyVersionInfoW` says the OS is Windows 10 or newer.
const os_major: u32 = 10;
const os_minor: u32 = 0;
const os_build: u32 = 19041;
const os_platform_id: u32 = 2; // VER_PLATFORM_WIN32_NT
const os_product_type: u8 = 1; // VER_NT_WORKSTATION

const VER_MINORVERSION: u32 = 0x01;
const VER_MAJORVERSION: u32 = 0x02;
const VER_BUILDNUMBER: u32 = 0x04;
const VER_PLATFORMID: u32 = 0x08;
const VER_SERVICEPACKMINOR: u32 = 0x10;
const VER_SERVICEPACKMAJOR: u32 = 0x20;
const VER_SUITENAME: u32 = 0x40;
const VER_PRODUCT_TYPE: u32 = 0x80;

const VER_EQUAL: u8 = 1;
const VER_GREATER: u8 = 2;
const VER_GREATER_EQUAL: u8 = 3;
const VER_LESS: u8 = 4;
const VER_LESS_EQUAL: u8 = 5;
const VER_AND: u8 = 6;
const VER_OR: u8 = 7;

const ERROR_OLD_WIN_VERSION: u32 = 1150;

const OsVersionInfoW = extern struct {
    dwOSVersionInfoSize: u32,
    dwMajorVersion: u32,
    dwMinorVersion: u32,
    dwBuildNumber: u32,
    dwPlatformId: u32,
    szCSDVersion: [128]u16,
};

const OsVersionInfoExW = extern struct {
    base: OsVersionInfoW,
    wServicePackMajor: u16,
    wServicePackMinor: u16,
    wSuiteMask: u16,
    wProductType: u8,
    wReserved: u8,
};

/// Three condition bits per `VER_*` field, in field order.
fn conditionAt(condition_mask: u64, comptime field: u6) u8 {
    return @truncate((condition_mask >> (field * 3)) & 0x7);
}

fn testCondition(condition: u8, actual: u64, requested: u64) bool {
    return switch (condition) {
        VER_EQUAL => actual == requested,
        VER_GREATER => actual > requested,
        VER_GREATER_EQUAL => actual >= requested,
        VER_LESS => actual < requested,
        VER_LESS_EQUAL => actual <= requested,
        // Suite mask conditions are set tests, not ordering comparisons.
        VER_AND => (actual & requested) == requested,
        VER_OR => (actual & requested) != 0,
        else => false,
    };
}

fn shim_VerSetConditionMask(condition_mask: u64, type_mask: u32, condition: u8) callconv(win) u64 {
    var mask = condition_mask;
    for (0..8) |i| {
        const type_bit: u32 = @as(u32, 1) << @intCast(i);
        if (type_mask & type_bit == 0) continue;
        const shift: u6 = @intCast(i * 3);
        const clear = ~(@as(u64, 0x7) << shift);
        mask = (mask & clear) | (@as(u64, condition & 0x7) << shift);
    }
    return mask;
}

fn shim_VerifyVersionInfoW(
    info: ?*anyopaque,
    type_mask: u32,
    condition_mask: u64,
) callconv(win) i32 {
    const raw = info orelse return 0;
    const version: *const OsVersionInfoW = @ptrCast(@alignCast(raw));
    if (version.dwOSVersionInfoSize < @sizeOf(OsVersionInfoW)) return 0;

    var sp_major: u64 = 0;
    var sp_minor: u64 = 0;
    var suite_mask: u64 = 0;
    var product_type: u64 = os_product_type;
    if (version.dwOSVersionInfoSize >= @sizeOf(OsVersionInfoExW)) {
        const ex: *const OsVersionInfoExW = @ptrCast(@alignCast(raw));
        sp_major = ex.wServicePackMajor;
        sp_minor = ex.wServicePackMinor;
        suite_mask = ex.wSuiteMask;
        product_type = ex.wProductType;
    }

    var satisfied = true;
    if (type_mask & VER_MAJORVERSION != 0 and
        !testCondition(conditionAt(condition_mask, 0), os_major, version.dwMajorVersion)) satisfied = false;
    if (type_mask & VER_MINORVERSION != 0 and
        !testCondition(conditionAt(condition_mask, 1), os_minor, version.dwMinorVersion)) satisfied = false;
    if (type_mask & VER_BUILDNUMBER != 0 and
        !testCondition(conditionAt(condition_mask, 2), os_build, version.dwBuildNumber)) satisfied = false;
    if (type_mask & VER_PLATFORMID != 0 and
        !testCondition(conditionAt(condition_mask, 3), os_platform_id, version.dwPlatformId)) satisfied = false;
    if (type_mask & VER_SERVICEPACKMINOR != 0 and
        !testCondition(conditionAt(condition_mask, 4), sp_minor, 0)) satisfied = false;
    if (type_mask & VER_SERVICEPACKMAJOR != 0 and
        !testCondition(conditionAt(condition_mask, 5), sp_major, 0)) satisfied = false;
    if (type_mask & VER_SUITENAME != 0 and
        !testCondition(conditionAt(condition_mask, 6), suite_mask, 0)) satisfied = false;
    if (type_mask & VER_PRODUCT_TYPE != 0 and
        !testCondition(conditionAt(condition_mask, 7), product_type, 0)) satisfied = false;

    if (!satisfied) teb.setLastError(ERROR_OLD_WIN_VERSION);
    return if (satisfied) 1 else 0;
}

// ---------------------------------------------------------------------------
// Pointer encoding / FLS / one-time init
// ---------------------------------------------------------------------------

fn shim_EncodePointer(ptr: ?*anyopaque) callconv(win) ?*anyopaque {
    return ptr;
}

fn shim_DecodePointer(ptr: ?*anyopaque) callconv(win) ?*anyopaque {
    return ptr;
}

fn shim_FlsAlloc(destructor: ?*anyopaque) callconv(win) u32 {
    return teb.flsAlloc(if (destructor) |d| @intFromPtr(d) else 0);
}

fn shim_FlsFree(index: u32) callconv(win) i32 {
    return if (teb.flsFree(index)) 1 else 0;
}

fn shim_FlsGetValue(index: u32) callconv(win) ?*anyopaque {
    const value = teb.tlsGet(index);
    return if (value == 0) null else @ptrFromInt(value);
}

fn shim_FlsSetValue(index: u32, value: ?*anyopaque) callconv(win) i32 {
    const addr: usize = if (value) |v| @intFromPtr(v) else 0;
    return if (teb.tlsSet(index, addr)) 1 else 0;
}

const InitOnceFn = *const fn (?*anyopaque, ?*anyopaque, ?*?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32;

fn shim_InitOnceExecuteOnce(
    init_once: ?*anyopaque,
    init_fn: ?InitOnceFn,
    parameter: ?*anyopaque,
    context: ?*?*anyopaque,
) callconv(win) i32 {
    const state: *u32 = @ptrCast(@alignCast(init_once orelse return 0));
    const f = init_fn orelse return 0;
    while (true) {
        const current = @atomicLoad(u32, state, .acquire);
        if (current == 2) return 1;
        if (current == 0 and @cmpxchgWeak(u32, state, 0, 1, .acq_rel, .acquire) == null) {
            const rc = f(init_once, parameter, context);
            @atomicStore(u32, state, 2, .release);
            return if (rc == 0) 0 else 1;
        }
        std.atomic.spinLoopHint();
    }
}

fn shim_SwitchToThread() callconv(win) i32 {
    if (builtin.os.tag == .linux) {
        _ = std.os.linux.sched_yield();
    }
    return 1;
}

fn shim_GetModuleHandleExW(
    flags: u32,
    module_name: ?[*:0]const u16,
    out: ?*usize,
) callconv(win) i32 {
    const result = out orelse return 0;
    var base: usize = 0;
    if (flags & 0x4 != 0) { // GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
        const addr: usize = @intFromPtr(module_name);
        const m = module.findByAddress(addr) orelse return 0;
        base = m.base;
    } else if (module_name) |name| {
        var utf8: [512]u8 = undefined;
        const n = std.unicode.utf16LeToUtf8(&utf8, std.mem.span(name)) catch return 0;
        const m = module.findByName(utf8[0..n]) orelse return 0;
        base = m.base;
    } else if (teb.process()) |p| {
        base = p.peb_ptr.ImageBaseAddress;
    }
    if (base == 0) return 0;
    if (flags & 0x2 == 0) { // UNCHANGED_REFCOUNT
        if (module.findByBase(base)) |m| m.refcount += 1;
    }
    result.* = base;
    return 1;
}

// ---------------------------------------------------------------------------
// Minimal CRT entry points
// ---------------------------------------------------------------------------

fn shim_execute_onexit_table(_: ?*anyopaque) callconv(win) i32 {
    return 0;
}

fn shim_set_new_handler(handler: ?*anyopaque) callconv(win) ?*anyopaque {
    _ = handler;
    return null;
}

fn shim_callnewh(_: usize) callconv(win) i32 {
    return 0;
}

fn shim_seh_filter_dll(_: ?*anyopaque, _: ?*anyopaque) callconv(win) i32 {
    return 1; // EXCEPTION_EXECUTE_HANDLER
}

fn shim_setlocale(_: c_int, locale: ?[*:0]const u8) callconv(win) ?[*:0]const u8 {
    _ = locale;
    return "C";
}

const ctype_table = blk: {
    var table: [256]u16 = @splat(0);
    for (0..256) |i| {
        const c: u8 = @intCast(i);
        var flags: u16 = 0;
        if (c >= 'A' and c <= 'Z') flags |= 0x1 | 0x100;
        if (c >= 'a' and c <= 'z') flags |= 0x2 | 0x100;
        if (c >= '0' and c <= '9') flags |= 0x4 | 0x80;
        if (c == ' ' or (c >= 0x09 and c <= 0x0D)) flags |= 0x8;
        if (c >= 0x21 and c <= 0x2F) flags |= 0x10;
        if (c < 0x20 or c == 0x7F) flags |= 0x20;
        if (c == ' ' or c == '\t') flags |= 0x40;
        table[i] = flags;
    }
    break :blk table;
};

fn shim_pctype_func() callconv(win) ?[*]const u16 {
    return &ctype_table;
}

fn shim_mb_cur_max_func() callconv(win) c_int {
    return 1;
}

fn shim_lc_codepage_func() callconv(win) c_int {
    return 65001;
}

fn shim_lc_collate_cp_func() callconv(win) c_int {
    return 65001;
}

var g_locale_name: [6]u16 = .{ 'e', 'n', '-', 'U', 'S', 0 };

/// UCRT's ___lc_locale_name_func returns `wchar_t**`: an array of per-category
/// locale-name pointers.  msvcp140 reads [1] from it.
var g_locale_names: [6]?[*:0]const u16 = .{
    @ptrCast(&g_locale_name),
    @ptrCast(&g_locale_name),
    @ptrCast(&g_locale_name),
    @ptrCast(&g_locale_name),
    @ptrCast(&g_locale_name),
    @ptrCast(&g_locale_name),
};

fn shim_lc_locale_name_func() callconv(win) ?[*]?[*:0]const u16 {
    return &g_locale_names;
}

fn shim_lock_locales() callconv(win) void {}
fn shim_unlock_locales() callconv(win) void {}

fn shim_atol(text: ?[*:0]const u8) callconv(win) c_long {
    const s = std.mem.span(text orelse return 0);
    const trimmed = std.mem.trimStart(u8, s, " \t\r\n");
    var end: usize = 0;
    if (end < trimmed.len and (trimmed[end] == '-' or trimmed[end] == '+')) end += 1;
    while (end < trimmed.len and std.ascii.isDigit(trimmed[end])) : (end += 1) {}
    if (end == 0) return 0;
    return std.fmt.parseInt(c_long, trimmed[0..end], 10) catch 0;
}

fn shim_btowc(c: c_int) callconv(win) u16 {
    if (c < 0 or c > 0xFF) return 0xFFFF;
    return @intCast(c & 0xFF);
}

fn shim_isupper(c: c_int) callconv(win) c_int {
    return if (c >= 'A' and c <= 'Z') 1 else 0;
}

fn shim_iswdigit(c: u16) callconv(win) c_int {
    return if (c >= '0' and c <= '9') 1 else 0;
}

fn shim_iswalnum(c: u16) callconv(win) c_int {
    return if ((c >= '0' and c <= '9') or (c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z')) 1 else 0;
}

fn shim_iswspace(c: u16) callconv(win) c_int {
    return if (c == ' ' or (c >= 0x09 and c <= 0x0D)) 1 else 0;
}

fn shim_iswxdigit(c: u16) callconv(win) c_int {
    return if ((c >= '0' and c <= '9') or (c >= 'A' and c <= 'F') or (c >= 'a' and c <= 'f')) 1 else 0;
}

fn shim_wcsnlen(s: ?[*:0]const u16, max: usize) callconv(win) usize {
    const p = s orelse return 0;
    var i: usize = 0;
    while (i < max and p[i] != 0) : (i += 1) {}
    return i;
}

fn shim_wcscpy_s(dst: ?[*]u16, dst_size: usize, src: ?[*:0]const u16) callconv(win) c_int {
    const d = dst orelse return 22;
    const s = src orelse return 22;
    var i: usize = 0;
    while (i + 1 < dst_size and s[i] != 0) : (i += 1) d[i] = s[i];
    if (i < dst_size) d[i] = 0;
    return 0;
}

fn shim_strncnt(s: ?[*:0]const u8, max: usize) callconv(win) usize {
    const p = s orelse return 0;
    var i: usize = 0;
    while (i < max and p[i] != 0) : (i += 1) {}
    return i;
}

fn shim_wcsdup(s: ?[*:0]const u16) callconv(win) ?[*:0]u16 {
    const src = s orelse return null;
    var n: usize = 0;
    while (src[n] != 0) : (n += 1) {}
    const mem = std.c.malloc((n + 1) * 2) orelse return null;
    const out: [*]u16 = @ptrCast(@alignCast(mem));
    @memcpy(out[0..n], src[0..n]);
    out[n] = 0;
    return @ptrCast(out);
}

fn shim_rand_s(out: ?*u32) callconv(win) c_int {
    const p = out orelse return 22;
    if (builtin.os.tag == .linux) {
        _ = std.os.linux.getrandom(std.mem.asBytes(p), 4, 0);
    } else {
        p.* = 0x1234_5678;
    }
    return 0;
}

fn shim_Getdays() callconv(win) ?[*:0]const u8 {
    return "Sunday\x00Monday\x00Tuesday\x00Wednesday\x00Thursday\x00Friday\x00Saturday\x00\x00";
}

fn shim_Getmonths() callconv(win) ?[*:0]const u8 {
    return "January\x00February\x00March\x00April\x00May\x00June\x00July\x00August\x00September\x00October\x00November\x00December\x00\x00";
}

fn shim_strftime(_: ?[*]u8, _: usize, _: ?[*:0]const u8, _: ?*const anyopaque) callconv(win) usize {
    return 0;
}

fn shim_wcsftime(_: ?[*]u16, _: usize, _: ?[*:0]const u16, _: ?*const anyopaque) callconv(win) usize {
    return 0;
}

// ---------------------------------------------------------------------------
// SLIST / threadpool / remaining CRT-adjacent APIs
// ---------------------------------------------------------------------------

var g_slist_lock: std.atomic.Value(u32) = .init(0);

fn slistLock() void {
    while (g_slist_lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
        while (g_slist_lock.load(.monotonic) != 0) std.atomic.spinLoopHint();
    }
}
fn slistUnlock() void {
    g_slist_lock.store(0, .release);
}

fn shim_InterlockedPushEntrySList(header: ?*anyopaque, entry: ?*anyopaque) callconv(win) ?*anyopaque {
    const h: *usize = @ptrCast(@alignCast(header orelse return null));
    const e: *usize = @ptrCast(@alignCast(entry orelse return null));
    slistLock();
    const old = h.*;
    e.* = old;
    h.* = @intFromPtr(entry.?);
    slistUnlock();
    return if (old == 0) null else @ptrFromInt(old);
}

fn shim_InterlockedFlushSList(header: ?*anyopaque) callconv(win) ?*anyopaque {
    const h: *usize = @ptrCast(@alignCast(header orelse return null));
    slistLock();
    const old = h.*;
    h.* = 0;
    slistUnlock();
    return if (old == 0) null else @ptrFromInt(old);
}

const TpCallback = *const fn (?*anyopaque, ?*anyopaque, ?*anyopaque) callconv(.{ .x86_64_win = .{} }) void;

const TpWork = struct {
    callback: TpCallback,
    context: ?*anyopaque,
};

fn shim_CreateThreadpoolWork(callback: ?TpCallback, context: ?*anyopaque, _: ?*anyopaque) callconv(win) ?*anyopaque {
    const cb = callback orelse return null;
    const work = std.heap.page_allocator.create(TpWork) catch return null;
    work.* = .{ .callback = cb, .context = context };
    return @ptrCast(work);
}

fn shim_SubmitThreadpoolWork(work: ?*anyopaque) callconv(win) void {
    const w: *TpWork = @ptrCast(@alignCast(work orelse return));
    w.callback(work, w.context, work);
}

fn shim_CloseThreadpoolWork(work: ?*anyopaque) callconv(win) void {
    const w: *TpWork = @ptrCast(@alignCast(work orelse return));
    std.heap.page_allocator.destroy(w);
}

fn shim_FreeLibraryWhenCallbackReturns(_: ?*anyopaque, base: usize) callconv(win) void {
    _ = module.release(base);
}

fn shim_RtlCaptureStackBackTrace(_: u32, _: u32, _: ?[*]?*anyopaque, _: ?*u32) callconv(win) u16 {
    return 0;
}

fn shim_CompareStringEx(
    _: ?[*:0]const u16,
    flags: u32,
    s1: ?[*:0]const u16,
    cch1: c_int,
    s2: ?[*:0]const u16,
    cch2: c_int,
    _: ?*anyopaque,
    _: ?*anyopaque,
    _: ?*anyopaque,
) callconv(win) c_int {
    const a = s1 orelse return 0;
    const b = s2 orelse return 0;
    var la: usize = if (cch1 < 0) std.mem.len(a) else @intCast(cch1);
    var lb: usize = if (cch2 < 0) std.mem.len(b) else @intCast(cch2);
    la = @min(la, std.mem.len(a));
    lb = @min(lb, std.mem.len(b));
    const ignore_case = flags & 0x1 != 0; // NORM_IGNORECASE
    var i: usize = 0;
    while (i < la and i < lb) : (i += 1) {
        const ca = if (ignore_case and a[i] < 0x80) std.ascii.toLower(@intCast(a[i])) else a[i];
        const cb = if (ignore_case and b[i] < 0x80) std.ascii.toLower(@intCast(b[i])) else b[i];
        if (ca < cb) return 1;
        if (ca > cb) return 3;
    }
    if (la < lb) return 1;
    if (la > lb) return 3;
    return 2;
}

fn shim_LCMapStringEx(
    _: ?[*:0]const u16,
    _: u32,
    src: ?[*:0]const u16,
    cch_src: c_int,
    dst: ?[*]u16,
    cch_dst: c_int,
    _: ?*anyopaque,
    _: ?*anyopaque,
    _: ?*anyopaque,
) callconv(win) c_int {
    const s = src orelse return 0;
    const len: usize = if (cch_src < 0) std.mem.len(s) else @intCast(cch_src);
    if (dst == null or cch_dst == 0) return @intCast(len);
    const d = dst.?;
    const n = @min(len, @as(usize, @intCast(cch_dst)));
    @memcpy(d[0..n], s[0..n]);
    return @intCast(n);
}

fn shim_GetLocaleInfoEx(
    _: ?[*:0]const u16,
    _: u32,
    out: ?[*]u16,
    cch: c_int,
) callconv(win) c_int {
    const text = [_]u16{ 'e', 'n', '-', 'U', 'S', 0 };
    if (out == null or cch == 0) return text.len;
    if (cch < text.len) return 0;
    @memcpy(out.?[0..text.len], &text);
    return text.len;
}

/// `IsValidCodePage`: the code pages this Windows 10 environment can serve.
fn shim_IsValidCodePage(code_page: u32) callconv(win) i32 {
    return switch (code_page) {
        0, 437, 850, 852, 855, 857, 866, 869, 874 => 1,
        932, 936, 949, 950 => 1,
        1250, 1251, 1252, 1253, 1254, 1255, 1256, 1257, 1258 => 1,
        10000, 10007, 20866, 20932, 21866, 28591, 28592, 28593, 28594, 28595 => 1,
        28596, 28597, 28598, 28599 => 1,
        20127, 28603, 28605, 50220, 50221, 50222, 50225, 50227, 51932, 51936 => 1,
        51949, 52936, 54936, 65000, 65001 => 1,
        else => 0,
    };
}

fn shim_GetCPInfo(_: u32, out: ?[*]u8) callconv(win) i32 {
    const p = out orelse return 0;
    @memset(p[0..18], 0);
    std.mem.writeInt(u32, p[0..4], 1, .little);
    p[4] = '?';
    return 1;
}

fn shim_GetStringTypeW(_: u32, src: ?[*:0]const u16, cch: c_int, out: ?[*]u16) callconv(win) i32 {
    const s = src orelse return 0;
    const d = out orelse return 0;
    const len: usize = if (cch < 0) std.mem.len(s) else @intCast(cch);
    var i: usize = 0;
    while (i < len) : (i += 1) {
        const c = s[i];
        var t: u16 = 0;
        if (c < 0x80) {
            const b: u8 = @intCast(c);
            if (b >= 'A' and b <= 'Z') t |= 0x1 | 0x100;
            if (b >= 'a' and b <= 'z') t |= 0x2 | 0x100;
            if (b >= '0' and b <= '9') t |= 0x4;
            if (b == ' ' or (b >= 0x09 and b <= 0x0D)) t |= 0x8;
        }
        d[i] = t;
    }
    return 1;
}

fn shim_configthreadlocale(_: c_int) callconv(win) c_int {
    return 0;
}

const E_NOTIMPL: i32 = -2147467263;

fn shim_RegisterAppStateChangeNotification(
    _: ?*anyopaque,
    _: ?*anyopaque,
    registration: ?*?*anyopaque,
) callconv(win) i32 {
    if (registration) |p| p.* = null;
    return E_NOTIMPL;
}

fn shim_RegisterAppConstrainedChangeNotification(
    _: ?*anyopaque,
    _: ?*anyopaque,
    registration: ?*?*anyopaque,
) callconv(win) i32 {
    if (registration) |p| p.* = null;
    return E_NOTIMPL;
}

fn shim_OpenThread(_: u32, _: i32, tid: u32) callconv(win) usize {
    if (tid == 0) return 0;
    return 0x7000_0000 | (tid & 0xFFFFF);
}

fn shim_XGameRuntimeInitialize() callconv(win) i32 {
    std.log.info("[GDK] XGameRuntimeInitialize() -> S_OK", .{});
    return 0;
}

fn shim_XGameRuntimeInitializeWithOptions(_: ?*const anyopaque) callconv(win) i32 {
    std.log.info("[GDK] XGameRuntimeInitializeWithOptions() -> S_OK", .{});
    return 0;
}

fn shim_XGameRuntimeUninitialize() callconv(win) void {}

extern "c" var stdin: *std.c.FILE;
extern "c" var stdout: *std.c.FILE;
extern "c" var stderr: *std.c.FILE;

fn shim_acrt_iob_func(index: u32) callconv(win) ?*std.c.FILE {
    if (builtin.os.tag == .linux) {
        return switch (index) {
            0 => stdin,
            1 => stdout,
            2 => stderr,
            else => null,
        };
    }
    return null;
}

var g_stream_buffer: [4096]u8 = undefined;
var g_stream_count: c_int = 0;

fn shim_get_stream_buffer_pointers(
    _: ?*anyopaque,
    base_out: ?*?[*]u8,
    ptr_out: ?*?[*]u8,
    count_out: ?*?*c_int,
) callconv(win) c_int {
    if (base_out) |p| p.* = &g_stream_buffer;
    if (ptr_out) |p| p.* = &g_stream_buffer;
    if (count_out) |p| p.* = &g_stream_count;
    return 0;
}

extern "c" fn fputs(s: [*:0]const u8, stream: *std.c.FILE) c_int;
extern "c" fn fputwc(c: u16, stream: *std.c.FILE) u32;
extern "c" fn fgetwc(stream: *std.c.FILE) u32;
extern "c" fn ungetwc(c: u32, stream: *std.c.FILE) u32;
extern "c" fn frexp(x: f64, exp: *c_int) f64;
extern "c" fn ldexp(x: f64, exp: c_int) f64;

fn shim_fputs(s: ?[*:0]const u8, stream: ?*std.c.FILE) callconv(win) c_int {
    return fputs(s orelse return -1, stream orelse return -1);
}

fn shim_fputwc(c: u32, stream: ?*std.c.FILE) callconv(win) u32 {
    return fputwc(@truncate(c), stream orelse return 0xFFFF_FFFF);
}

fn shim_fgetwc(stream: ?*std.c.FILE) callconv(win) u32 {
    return fgetwc(stream orelse return 0xFFFF_FFFF);
}

fn shim_ungetwc(c: u32, stream: ?*std.c.FILE) callconv(win) u32 {
    return ungetwc(c, stream orelse return 0xFFFF_FFFF);
}

fn shim_frexp(x: f64, exp: ?*c_int) callconv(win) f64 {
    var e: c_int = 0;
    const r = frexp(x, &e);
    if (exp) |p| p.* = e;
    return r;
}

fn shim_ldexp(x: f64, exp: c_int) callconv(win) f64 {
    return ldexp(x, exp);
}

fn shim__wfsopen(path: ?[*:0]const u16, mode: ?[*:0]const u16, _: c_int) callconv(win) ?*std.c.FILE {
    var mbuf: [32]u8 = undefined;
    var mlen: usize = 0;
    if (mode) |m| {
        while (mlen + 1 < mbuf.len and m[mlen] != 0) : (mlen += 1) mbuf[mlen] = @truncate(m[mlen] & 0x7F);
    }
    mbuf[mlen] = 0;
    var pbuf: [2048]u8 = undefined;
    const mapped = win32_fs.mapWidePath(path, &pbuf);
    if (mapped.len == 0) return null;
    return std.c.fopen(@ptrCast(&pbuf), @ptrCast(&mbuf));
}

fn shim__fsopen(path: ?[*:0]const u8, mode: ?[*:0]const u8, _: c_int) callconv(win) ?*std.c.FILE {
    var pbuf: [2048]u8 = undefined;
    const mapped = win32_fs.mapAnsiPath(path, &pbuf);
    if (mapped.len == 0) return null;
    return std.c.fopen(@ptrCast(&pbuf), @ptrCast(mode orelse return null));
}

const BeginThreadFn = *const fn (?*anyopaque) callconv(.{ .x86_64_win = .{} }) u32;

const BeginThreadCtx = struct {
    start: BeginThreadFn,
    arg: ?*anyopaque,
    handle: usize,
    stack_size: usize,
    thread_ref: ?*anyopaque = null,
};

fn beginThreadBootstrap(ctx: BeginThreadCtx) void {
    if (builtin.os.tag == .linux) {
        var rsp: usize = undefined;
        asm volatile ("movq %%rsp, %[out]"
            : [out] "=r" (rsp),
        );
        const base = rsp & ~@as(usize, 0xF);
        _ = teb.initThread(base, base - ctx.stack_size, @truncate(ctx.handle)) catch {};
    }
    thread_exit.setThreadRef(ctx.thread_ref);
    const code = ctx.start(ctx.arg);
    thread_exit.finish(code);
}

fn shim_beginthreadex(
    _: ?*anyopaque,
    stack_size: u32,
    start: ?BeginThreadFn,
    arglist: ?*anyopaque,
    _: u32,
    thread_id: ?*u32,
) callconv(win) usize {
    const start_fn = start orelse return 0;
    const size: usize = if (stack_size == 0) 1024 * 1024 else stack_size;
    const handle = sync.createThreadHandle(@truncate(@intFromPtr(start_fn)));
    if (handle == 0) return 0;
    if (thread_id) |out| out.* = @truncate(handle);
    const thread_ref = sync.acquireThreadRef(handle);
    const thread = std.Thread.spawn(.{ .stack_size = size }, beginThreadBootstrap, .{BeginThreadCtx{
        .start = start_fn,
        .arg = arglist,
        .handle = handle,
        .stack_size = size,
        .thread_ref = thread_ref,
    }}) catch {
        if (thread_ref) |r| sync.releaseThreadRef(r);
        _ = sync.closeHandle(handle);
        return 0;
    };
    thread.detach();
    return handle;
}

fn shim_endthreadex(code: u32) callconv(win) noreturn {
    thread_exit.exitCurrent(code);
}

pub fn resolve(sym_name: []const u8) ?usize {
    if (seh.resolve(sym_name)) |ptr| return ptr;
    const map = .{
        .{ "IsDebuggerPresent", @intFromPtr(&shim_IsDebuggerPresent) },
        .{ "IsThreadAFiber", @intFromPtr(&shim_IsThreadAFiber) },
        .{ "VerSetConditionMask", @intFromPtr(&shim_VerSetConditionMask) },
        .{ "VerifyVersionInfoW", @intFromPtr(&shim_VerifyVersionInfoW) },
        .{ "EncodePointer", @intFromPtr(&shim_EncodePointer) },
        .{ "DecodePointer", @intFromPtr(&shim_DecodePointer) },
        .{ "FlsAlloc", @intFromPtr(&shim_FlsAlloc) },
        .{ "FlsFree", @intFromPtr(&shim_FlsFree) },
        .{ "FlsGetValue", @intFromPtr(&shim_FlsGetValue) },
        .{ "FlsSetValue", @intFromPtr(&shim_FlsSetValue) },
        .{ "InitOnceExecuteOnce", @intFromPtr(&shim_InitOnceExecuteOnce) },
        .{ "SwitchToThread", @intFromPtr(&shim_SwitchToThread) },
        .{ "GetModuleHandleExW", @intFromPtr(&shim_GetModuleHandleExW) },
        .{ "_execute_onexit_table", @intFromPtr(&shim_execute_onexit_table) },
        .{ "_set_new_handler", @intFromPtr(&shim_set_new_handler) },
        .{ "_callnewh", @intFromPtr(&shim_callnewh) },
        .{ "_seh_filter_dll", @intFromPtr(&shim_seh_filter_dll) },
        .{ "setlocale", @intFromPtr(&shim_setlocale) },
        .{ "__pctype_func", @intFromPtr(&shim_pctype_func) },
        .{ "___mb_cur_max_func", @intFromPtr(&shim_mb_cur_max_func) },
        .{ "___lc_codepage_func", @intFromPtr(&shim_lc_codepage_func) },
        .{ "___lc_collate_cp_func", @intFromPtr(&shim_lc_collate_cp_func) },
        .{ "___lc_locale_name_func", @intFromPtr(&shim_lc_locale_name_func) },
        .{ "_lock_locales", @intFromPtr(&shim_lock_locales) },
        .{ "_unlock_locales", @intFromPtr(&shim_unlock_locales) },
        .{ "atol", @intFromPtr(&shim_atol) },
        .{ "btowc", @intFromPtr(&shim_btowc) },
        .{ "isupper", @intFromPtr(&shim_isupper) },
        .{ "iswdigit", @intFromPtr(&shim_iswdigit) },
        .{ "iswalnum", @intFromPtr(&shim_iswalnum) },
        .{ "iswspace", @intFromPtr(&shim_iswspace) },
        .{ "iswxdigit", @intFromPtr(&shim_iswxdigit) },
        .{ "wcsnlen", @intFromPtr(&shim_wcsnlen) },
        .{ "wcscpy_s", @intFromPtr(&shim_wcscpy_s) },
        .{ "__strncnt", @intFromPtr(&shim_strncnt) },
        .{ "_wcsdup", @intFromPtr(&shim_wcsdup) },
        .{ "rand_s", @intFromPtr(&shim_rand_s) },
        .{ "_Getdays", @intFromPtr(&shim_Getdays) },
        .{ "_Getmonths", @intFromPtr(&shim_Getmonths) },
        .{ "_W_Getdays", @intFromPtr(&shim_Getdays) },
        .{ "_W_Getmonths", @intFromPtr(&shim_Getmonths) },
        .{ "_Gettnames", @intFromPtr(&shim_strftime) },
        .{ "_W_Gettnames", @intFromPtr(&shim_wcsftime) },
        .{ "_Strftime", @intFromPtr(&shim_strftime) },
        .{ "_Wcsftime", @intFromPtr(&shim_wcsftime) },
        .{ "_configthreadlocale", @intFromPtr(&shim_configthreadlocale) },
        .{ "RegisterAppStateChangeNotification", @intFromPtr(&shim_RegisterAppStateChangeNotification) },
        .{ "RegisterAppConstrainedChangeNotification", @intFromPtr(&shim_RegisterAppConstrainedChangeNotification) },
        .{ "OpenThread", @intFromPtr(&shim_OpenThread) },
        .{ "XGameRuntimeInitialize", @intFromPtr(&shim_XGameRuntimeInitialize) },
        .{ "XGameRuntimeInitializeWithOptions", @intFromPtr(&shim_XGameRuntimeInitializeWithOptions) },
        .{ "XGameRuntimeUninitialize", @intFromPtr(&shim_XGameRuntimeUninitialize) },
        .{ "InterlockedPushEntrySList", @intFromPtr(&shim_InterlockedPushEntrySList) },
        .{ "InterlockedFlushSList", @intFromPtr(&shim_InterlockedFlushSList) },
        .{ "CreateThreadpoolWork", @intFromPtr(&shim_CreateThreadpoolWork) },
        .{ "SubmitThreadpoolWork", @intFromPtr(&shim_SubmitThreadpoolWork) },
        .{ "CloseThreadpoolWork", @intFromPtr(&shim_CloseThreadpoolWork) },
        .{ "FreeLibraryWhenCallbackReturns", @intFromPtr(&shim_FreeLibraryWhenCallbackReturns) },
        .{ "RtlCaptureStackBackTrace", @intFromPtr(&shim_RtlCaptureStackBackTrace) },
        .{ "CompareStringEx", @intFromPtr(&shim_CompareStringEx) },
        .{ "LCMapStringEx", @intFromPtr(&shim_LCMapStringEx) },
        .{ "GetLocaleInfoEx", @intFromPtr(&shim_GetLocaleInfoEx) },
        .{ "IsValidCodePage", @intFromPtr(&shim_IsValidCodePage) },
        .{ "GetCPInfo", @intFromPtr(&shim_GetCPInfo) },
        .{ "GetStringTypeW", @intFromPtr(&shim_GetStringTypeW) },
        .{ "__acrt_iob_func", @intFromPtr(&shim_acrt_iob_func) },
        .{ "_get_stream_buffer_pointers", @intFromPtr(&shim_get_stream_buffer_pointers) },
        .{ "fputs", @intFromPtr(&shim_fputs) },
        .{ "fputwc", @intFromPtr(&shim_fputwc) },
        .{ "fgetwc", @intFromPtr(&shim_fgetwc) },
        .{ "ungetwc", @intFromPtr(&shim_ungetwc) },
        .{ "frexp", @intFromPtr(&shim_frexp) },
        .{ "ldexp", @intFromPtr(&shim_ldexp) },
        .{ "_wfsopen", @intFromPtr(&shim__wfsopen) },
        .{ "_fsopen", @intFromPtr(&shim__fsopen) },
        .{ "_beginthreadex", @intFromPtr(&shim_beginthreadex) },
        .{ "_endthreadex", @intFromPtr(&shim_endthreadex) },
    };

    inline for (map) |entry| {
        if (std.mem.eql(u8, entry.@"0", sym_name)) return entry.@"1";
    }
    return null;
}
