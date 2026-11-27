const std = @import("std");
const builtin = @import("builtin");
const teb = @import("../teb.zig");
const sync = @import("../sync.zig");
const mod = @import("../module.zig");
const thread_exit = @import("../thread_exit.zig");
const host_imports = @import("../host_imports.zig");
const xgameruntime_min = @import("xgameruntime_min.zig");
const audio_min = @import("audio_min.zig");

const WinFn = *const fn () callconv(.{ .x86_64_win = .{} }) void;
const WinInitFn = *const fn () callconv(.{ .x86_64_win = .{} }) c_int;

var g_commode: c_int = 0;
var g_thread_count = std.atomic.Value(u32).init(0);
var g_thread_logs = std.atomic.Value(u32).init(0);
var g_thread_failures = std.atomic.Value(u32).init(0);

fn noteThreadFailure() void {
    const n = g_thread_failures.fetchAdd(1, .monotonic) + 1;
    if (n <= 8 or n % 64 == 0) {
        std.log.err("[THREAD] thread-creation failure #{d}", .{n});
    }
}
var g_fmode: c_int = 0;
var g_app_type: c_int = 2; // _crt_gui_app
var g_next_guest_tid = std.atomic.Value(u32).init(0x1_0000);

fn allocGuestThreadId() u32 {
    return g_next_guest_tid.fetchAdd(1, .monotonic);
}

fn logWideStr(prefix: []const u8, wptr: ?[*:0]const u16) void {
    const ptr = wptr orelse return;
    var storage: u512 = 0;
    const buf: [*]u8 = @ptrCast(&storage);
    var len: usize = 0;
    while (ptr[len] != 0 and len < 63) : (len += 1) {
        buf[len] = @truncate(ptr[len] & 0x7F);
    }
    std.log.warn("{s}(\"{s}\")", .{ prefix, buf[0..len] });
}

fn shim_GetLastError() callconv(.{ .x86_64_win = .{} }) u32 {
    return teb.getLastError();
}

fn shim_SetLastError(err: u32) callconv(.{ .x86_64_win = .{} }) void {
    teb.setLastError(err);
}

fn shim_initterm(first: ?*const anyopaque, last: ?*const anyopaque) callconv(.{ .x86_64_win = .{} }) void {
    var cur_addr = @intFromPtr(first);
    const end_addr = @intFromPtr(last);
    while (cur_addr < end_addr) : (cur_addr += @sizeOf(usize)) {
        const slot: *const ?WinFn = @ptrFromInt(cur_addr);
        if (slot.*) |func| {
            func();
        }
    }
}

fn shim_initterm_e(first: ?*const anyopaque, last: ?*const anyopaque) callconv(.{ .x86_64_win = .{} }) c_int {
    var cur_addr = @intFromPtr(first);
    const end_addr = @intFromPtr(last);
    while (cur_addr < end_addr) : (cur_addr += @sizeOf(usize)) {
        const slot: *const ?WinInitFn = @ptrFromInt(cur_addr);
        if (slot.*) |func| {
            const rc = func();
            if (rc != 0) return rc;
        }
    }
    return 0;
}

fn shim_initialize_onexit_table(table: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) c_int {
    _ = table;
    return 0;
}

fn shim_register_onexit_function(table: ?*anyopaque, func: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) c_int {
    _ = table;
    _ = func;
    return 0;
}

fn shim_crt_atexit(func: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) c_int {
    _ = func;
    return 0;
}

fn shim_exit(code: c_int) callconv(.{ .x86_64_win = .{} }) noreturn {
    std.log.warn("[CRT] exit({d}) called!", .{code});
    std.process.exit(@truncate(@as(c_uint, @bitCast(code))));
}

fn shim_cexit() callconv(.{ .x86_64_win = .{} }) void {
    std.log.warn("[CRT] _cexit() called!", .{});
}

fn shim_ExitProcess(code: u32) callconv(.{ .x86_64_win = .{} }) noreturn {
    std.log.warn("[KERNEL] ExitProcess({d}) called!", .{code});
    std.process.exit(@truncate(code));
}

fn shim_p_commode() callconv(.{ .x86_64_win = .{} }) *c_int {
    return &g_commode;
}

fn shim_p_fmode() callconv(.{ .x86_64_win = .{} }) *c_int {
    return &g_fmode;
}

fn shim_set_fmode(mode: c_int) callconv(.{ .x86_64_win = .{} }) c_int {
    g_fmode = mode;
    return 0;
}

fn shim_set_app_type(app_type: c_int) callconv(.{ .x86_64_win = .{} }) void {
    g_app_type = app_type;
}

fn shim_configure_narrow_argv(mode: c_int) callconv(.{ .x86_64_win = .{} }) c_int {
    _ = mode;
    return 0;
}

fn shim_initialize_narrow_environment() callconv(.{ .x86_64_win = .{} }) c_int {
    return 0;
}

fn shim_IsProcessorFeaturePresent(feature: u32) callconv(.{ .x86_64_win = .{} }) i32 {
    if (feature == 0x17) {
        return 0;
    }
    return 1;
}

fn isSystemDllName(name: []const u8) bool {
    const exact = [_][]const u8{
        "kernel32.dll",    "ntdll.dll",         "user32.dll",            "advapi32.dll",
        "bcrypt.dll",      "ws2_32.dll",        "winhttp.dll",           "mfplat.dll",
        "mfreadwrite.dll", "gameinput.dll",     "xmem.dll",              "chad.dll",
        "d3d12_xs.dll",    "xg_xs.dll",         "xapu.dll",              "acphal.dll",
        "xcrdapi.dll",     "bink2scarlett.dll", "libhttpclient.gdk.dll", "xgameruntime.dll",
    };
    for (exact) |e| {
        if (std.ascii.eqlIgnoreCase(name, e)) return true;
    }
    return std.ascii.startsWithIgnoreCase(name, "api-ms-win-") or
        std.ascii.startsWithIgnoreCase(name, "ext-ms-win-");
}

const PSEUDO_SYSTEM_BASE: usize = 0x7FFE_0000;

fn shim_VirtualProtect(addr: ?*anyopaque, size: usize, new_protect: u32, old_protect: *u32) callconv(.{ .x86_64_win = .{} }) i32 {
    old_protect.* = 0x04;
    if (builtin.os.tag == .linux) {
        const c = struct {
            extern "c" fn mprotect(addr: usize, len: usize, prot: i32) i32;
        };
        if (addr == null or size == 0) return 0;
        const base = @intFromPtr(addr);
        const page = base & ~@as(usize, 0xFFF);
        const end = (base + size + 0xFFF) & ~@as(usize, 0xFFF);
        // Keep pages executable; HLE code may restore/execute after a protect.
        old_protect.* = 0x20;
        return if (c.mprotect(page, end - page, 0x7) == 0) 1 else 0;
    }
    const c = struct {
        extern "kernel32" fn VirtualProtect(?*anyopaque, usize, u32, *u32) callconv(.winapi) i32;
    };
    return c.VirtualProtect(addr, size, new_protect, old_protect);
}

fn shim_AppPolicyGetProcessTerminationMethod(_: ?*anyopaque, policy: *u32) callconv(.{ .x86_64_win = .{} }) i32 {
    policy.* = 0; // AppPolicyProcessTerminationMethod_ExitProcess
    return 0;
}

fn shim_GetModuleHandleW(module_name: ?[*:0]const u16) callconv(.{ .x86_64_win = .{} }) usize {
    if (module_name) |name| {
        if (teb.findModuleByNameW(name)) |entry| return entry.DllBase;
        var utf8: [256]u8 = undefined;
        const n = std.unicode.utf16LeToUtf8(&utf8, std.mem.span(name)) catch 0;
        if (isSystemDllName(utf8[0..n])) return PSEUDO_SYSTEM_BASE;
        return 0;
    }
    return if (teb.process()) |p| p.peb_ptr.ImageBaseAddress else 0;
}

fn shim_GetModuleHandleA(module_name: ?[*:0]const u8) callconv(.{ .x86_64_win = .{} }) usize {
    if (module_name) |aptr| {
        const name = std.mem.span(aptr);
        if (teb.findModuleByName(name)) |entry| return entry.DllBase;
        if (isSystemDllName(name)) return PSEUDO_SYSTEM_BASE;
        return 0;
    }
    return if (teb.process()) |p| p.peb_ptr.ImageBaseAddress else 0;
}

pub var wrap_guest_fn: ?*const fn (usize) ?usize = null;

fn wrapGuest(fn_ptr: usize) usize {
    if (builtin.os.tag == .windows) {
        if (wrap_guest_fn) |f| {
            if (f(fn_ptr)) |thunk| return thunk;
        }
    }
    return fn_ptr;
}

fn isCryptoProc(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "BCrypt") or
        std.mem.startsWith(u8, name, "NCrypt") or
        std.mem.startsWith(u8, name, "Crypt");
}

fn shim_GetProcAddress(hmodule: usize, proc_name: ?[*:0]const u8) callconv(.{ .x86_64_win = .{} }) usize {
    const name_ptr = proc_name orelse return 0;
    const addr_val = @intFromPtr(name_ptr);
    const base = if (hmodule != 0)
        hmodule
    else if (teb.process()) |p| p.peb_ptr.ImageBaseAddress else 0;

    if (host_imports.isHostModule(base)) {
        const p = host_imports.getProcAddress(base, null, @intCast(addr_val)) orelse return 0;
        return wrapGuest(p);
    }
    if (addr_val <= 0xFFFF) {
        const ordinal: u16 = @intCast(addr_val);
        const p = mod.getProcAddress(base, null, ordinal, 0) orelse return 0;
        return wrapGuest(p);
    }

    const name = std.mem.span(name_ptr);
    if (host_imports.isHostModule(base)) {
        const p = host_imports.getProcAddress(base, name, null) orelse return 0;
        return wrapGuest(p);
    }
    const crypto = isCryptoProc(name);
    if (mod.getProcAddress(base, name, null, 0)) |fn_ptr| {
        if (crypto) std.log.info("[CRT] GetProcAddress(0x{x}, \"{s}\") -> 0x{x}", .{ base, name, fn_ptr });
        return wrapGuest(fn_ptr);
    }
    if (mod.resolve_shim_fn) |f| {
        if (f(name)) |fn_ptr| {
            if (crypto) std.log.info("[CRT] GetProcAddress(0x{x}, \"{s}\") -> shim 0x{x}", .{ base, name, fn_ptr });
            return wrapGuest(fn_ptr);
        }
    }
    if (resolve(name)) |fn_ptr| {
        if (crypto) std.log.info("[CRT] GetProcAddress(0x{x}, \"{s}\") -> crt 0x{x}", .{ base, name, fn_ptr });
        const out = wrapGuest(fn_ptr);
        return out;
    }
    std.log.warn("[CRT] GetProcAddress(0x{x}, \"{s}\") -> unresolved", .{ base, name });
    return 0;
}

/// `SystemFunction036` / `RtlGenRandom`: fill a buffer with cryptographically
/// strong random bytes from the host kernel.
fn shim_SystemFunction036(buffer: ?*anyopaque, len: u32) callconv(.{ .x86_64_win = .{} }) u8 {
    const out: [*]u8 = @ptrCast(buffer orelse return 0);
    if (len == 0) return 1;
    if (builtin.os.tag != .linux) return 0;
    var filled: usize = 0;
    while (filled < len) {
        const res = std.os.linux.syscall3(.getrandom, @intFromPtr(out + filled), len - filled, 0);
        const signed: isize = @bitCast(res);
        if (signed <= 0) return 0;
        filled += @intCast(signed);
    }
    return 1;
}

// ---------------------------------------------------------------------------
// Headless windowing (ntuser ANSI API sets)
// ---------------------------------------------------------------------------
//
// The loader has no Win32 window station/desktop.  Classes and windows are
// modelled headlessly, but unlike the old empty message queue this registry
// stores the WNDPROC and synthesizes the create/size/activate/paint messages
// the engine's pump expects.  PeekMessageA returns them; DispatchMessageA
// routes them to the registered procedure.

pub const WNDCLASSEXA = extern struct {
    cbSize: u32,
    style: u32,
    lpfnWndProc: usize,
    cbClsExtra: i32,
    cbWndExtra: i32,
    hInstance: usize,
    hIcon: usize,
    hCursor: usize,
    hbrBackground: usize,
    lpszMenuName: ?[*:0]const u8,
    lpszClassName: ?[*:0]const u8,
    hIconSm: usize,
};

/// Win32 `MSG` on x64 (48 bytes).
pub const MSG = extern struct {
    hwnd: usize,
    message: u32,
    reserved: u32,
    wparam: usize,
    lparam: isize,
    time: u32,
    pt_x: i32,
    pt_y: i32,
    lprivate: u32,
};

/// Win32 `CREATESTRUCTA` on x64 (80 bytes).
pub const CREATESTRUCTA = extern struct {
    lpCreateParams: usize,
    hInstance: usize,
    hMenu: usize,
    hwndParent: usize,
    cy: i32,
    cx: i32,
    y: i32,
    x: i32,
    style: i32,
    lpszName: ?[*:0]const u8,
    lpszClass: ?[*:0]const u8,
    dwExStyle: u32,
};

const WM_NCCREATE: u32 = 0x0081;
const WM_CREATE: u32 = 0x0001;
const WM_SIZE: u32 = 0x0005;
const WM_ACTIVATE: u32 = 0x0006;
const WM_PAINT: u32 = 0x000F;
const WM_ERASEBKGND: u32 = 0x0014;
const SIZE_RESTORED: u32 = 0;
const WA_ACTIVE: u32 = 1;
const CLIENT_WIDTH: i32 = 1280;
const CLIENT_HEIGHT: i32 = 720;

const MAX_WINDOW_CLASSES = 32;
const MAX_WINDOWS = 64;
const MAX_MESSAGES = 128;
const ATOM_BASE: u16 = 0xC000;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_CLASS_ALREADY_EXISTS: u32 = 1410;
const ERROR_CLASS_DOES_NOT_EXIST: u32 = 1407;

const WindowClass = struct {
    name: [64]u8 = undefined,
    name_len: u8 = 0,
    wndproc: usize = 0,
    hinstance: usize = 0,
    style: u32 = 0,
    background: usize = 0,
};

const Window = struct {
    in_use: bool = false,
    hwnd: usize = 0,
    class_index: usize = 0,
    wndproc: usize = 0,
    hinstance: usize = 0,
    visible: bool = false,
    active: bool = false,
    width: i32 = CLIENT_WIDTH,
    height: i32 = CLIENT_HEIGHT,
    title: [64]u8 = undefined,
    title_len: u8 = 0,
    create: CREATESTRUCTA = std.mem.zeroes(CREATESTRUCTA),
};

var g_window_classes: [MAX_WINDOW_CLASSES]WindowClass = undefined;
var g_window_class_count: usize = 0;
var g_windows: [MAX_WINDOWS]Window = @splat(.{});
var g_messages: [MAX_MESSAGES]MSG = undefined;
var g_message_count: usize = 0;
var g_next_window: usize = 1;
var g_window_lock = std.atomic.Value(u8).init(0);

fn lockWindows() void {
    while (g_window_lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
        std.atomic.spinLoopHint();
    }
}
fn unlockWindows() void {
    g_window_lock.store(0, .release);
}

fn classNameEql(existing: *const WindowClass, name: []const u8) bool {
    return existing.name_len == name.len and std.mem.eql(u8, existing.name[0..name.len], name);
}

fn findClassUnlocked(name: []const u8) ?usize {
    for (g_window_classes[0..g_window_class_count], 0..) |*entry, i| {
        if (classNameEql(entry, name)) return i;
    }
    return null;
}

fn findWindowUnlocked(hwnd: usize) ?*Window {
    for (&g_windows) |*w| {
        if (w.in_use and w.hwnd == hwnd) return w;
    }
    return null;
}

fn monotonicMillis() u32 {
    if (comptime builtin.os.tag == .linux) {
        var ts: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
        return @truncate(@as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(@divTrunc(ts.nsec, 1_000_000))));
    }
    return 0;
}

fn queueMessageUnlocked(hwnd: usize, message: u32, wparam: usize, lparam: isize) void {
    if (g_message_count >= g_messages.len) {
        // Keep the oldest messages rather than silently dropping new ones at
        // the head; a full headless queue is a loader bug.
        std.log.warn("[WINDOW] message queue full; dropping msg 0x{x}", .{message});
        return;
    }
    g_messages[g_message_count] = .{
        .hwnd = hwnd,
        .message = message,
        .reserved = 0,
        .wparam = wparam,
        .lparam = lparam,
        .time = monotonicMillis(),
        .pt_x = 0,
        .pt_y = 0,
        .lprivate = 0,
    };
    g_message_count += 1;
}

fn shim_RegisterClassExA(wc: ?*const WNDCLASSEXA) callconv(.{ .x86_64_win = .{} }) u16 {
    const window_class = wc orelse {
        teb.setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    };
    if (window_class.cbSize != @sizeOf(WNDCLASSEXA)) {
        teb.setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    const name_ptr = window_class.lpszClassName orelse {
        teb.setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    };
    const name = std.mem.span(name_ptr);
    if (name.len == 0 or name.len >= 64) {
        teb.setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    lockWindows();
    defer unlockWindows();
    if (findClassUnlocked(name) != null) {
        teb.setLastError(ERROR_CLASS_ALREADY_EXISTS);
        return 0; // Win32: existing class is FALSE + ERROR_CLASS_ALREADY_EXISTS
    }
    if (g_window_class_count >= MAX_WINDOW_CLASSES) {
        teb.setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    const index = g_window_class_count;
    const entry = &g_window_classes[index];
    @memcpy(entry.name[0..name.len], name);
    entry.name[name.len] = 0;
    entry.name_len = @intCast(name.len);
    entry.wndproc = window_class.lpfnWndProc;
    entry.hinstance = window_class.hInstance;
    entry.style = window_class.style;
    entry.background = window_class.hbrBackground;
    g_window_class_count += 1;
    const atom = ATOM_BASE + @as(u16, @intCast(index));
    std.log.info("[WINDOW] RegisterClassExA(\"{s}\") -> atom 0x{x}, wndproc=0x{x}", .{
        name, atom, window_class.lpfnWndProc,
    });
    return atom;
}

fn shim_CreateWindowExA(
    _: u32,
    class_name: ?[*:0]const u8,
    window_name: ?[*:0]const u8,
    style: u32,
    _: i32,
    _: i32,
    _: i32,
    _: i32,
    _: usize,
    _: usize,
    hinstance: usize,
    lp_param: ?*anyopaque,
) callconv(.{ .x86_64_win = .{} }) usize {
    const class_ptr = class_name orelse {
        teb.setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    };
    const class_text = std.mem.span(class_ptr);
    lockWindows();
    defer unlockWindows();
    const class_index = findClassUnlocked(class_text) orelse {
        teb.setLastError(ERROR_CLASS_DOES_NOT_EXIST);
        return 0;
    };
    var slot: ?*Window = null;
    for (&g_windows) |*w| {
        if (!w.in_use) {
            slot = w;
            break;
        }
    }
    const w = slot orelse {
        teb.setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    };
    const cls = &g_window_classes[class_index];
    const handle = 0x0001_0000 + g_next_window;
    g_next_window += 1;

    w.* = .{
        .in_use = true,
        .hwnd = handle,
        .class_index = class_index,
        .wndproc = cls.wndproc,
        .hinstance = if (hinstance != 0) hinstance else cls.hinstance,
        .visible = false,
        .active = true,
        .width = CLIENT_WIDTH,
        .height = CLIENT_HEIGHT,
    };
    const title = window_name orelse @as([*:0]const u8, "");
    const title_text = std.mem.span(title);
    const title_len = @min(title_text.len, w.title.len - 1);
    @memcpy(w.title[0..title_len], title_text[0..title_len]);
    w.title[title_len] = 0;
    w.title_len = @intCast(title_len);

    w.create = .{
        .lpCreateParams = if (lp_param) |p| @intFromPtr(p) else 0,
        .hInstance = w.hinstance,
        .hMenu = 0,
        .hwndParent = 0,
        .cy = CLIENT_HEIGHT,
        .cx = CLIENT_WIDTH,
        .y = 0,
        .x = 0,
        .style = @intCast(style),
        .lpszName = @ptrCast(&w.title),
        .lpszClass = @ptrCast(&cls.name),
        .dwExStyle = 0,
    };

    // These messages are delivered by PeekMessageA in this order.
    queueMessageUnlocked(handle, WM_NCCREATE, 0, @intCast(@intFromPtr(&w.create)));
    queueMessageUnlocked(handle, WM_CREATE, 0, @intCast(@intFromPtr(&w.create)));
    queueMessageUnlocked(handle, WM_SIZE, SIZE_RESTORED, (@as(isize, CLIENT_HEIGHT) << 16) | @as(isize, CLIENT_WIDTH));
    queueMessageUnlocked(handle, WM_ACTIVATE, WA_ACTIVE, 0);
    queueMessageUnlocked(handle, WM_PAINT, 0, 0);

    std.log.info("[WINDOW] CreateWindowExA(class=\"{s}\", title=\"{s}\") -> hwnd 0x{x} ({d}x{d})", .{
        class_text, title_text, handle, CLIENT_WIDTH, CLIENT_HEIGHT,
    });
    return handle;
}

fn shim_ShowWindow(hwnd: usize, cmd: i32) callconv(.{ .x86_64_win = .{} }) i32 {
    lockWindows();
    defer unlockWindows();
    const w = findWindowUnlocked(hwnd) orelse return 0;
    const previous: i32 = if (w.visible) 1 else 0;
    w.visible = cmd != 0; // SW_HIDE == 0
    return previous;
}

fn shim_DefWindowProcA(_: usize, message: u32, _: usize, _: usize) callconv(.{ .x86_64_win = .{} }) isize {
    return switch (message) {
        WM_NCCREATE => 1,
        WM_ERASEBKGND => 1,
        else => 0,
    };
}

fn shim_PeekMessageA(
    msg: ?*MSG,
    hwnd: usize,
    filter_min: u32,
    filter_max: u32,
    remove: u32,
) callconv(.{ .x86_64_win = .{} }) i32 {
    const out = msg orelse return 0;
    lockWindows();
    defer unlockWindows();
    var i: usize = 0;
    while (i < g_message_count) : (i += 1) {
        const candidate = g_messages[i];
        if (hwnd != 0 and candidate.hwnd != hwnd) continue;
        if (filter_min != 0 or filter_max != 0) {
            if (candidate.message < filter_min or candidate.message > filter_max) continue;
        }
        out.* = candidate;
        if ((remove & 1) != 0) { // PM_REMOVE
            var j = i;
            while (j + 1 < g_message_count) : (j += 1) g_messages[j] = g_messages[j + 1];
            g_message_count -= 1;
        }
        return 1;
    }
    return 0;
}

fn shim_DispatchMessageA(msg: ?*const MSG) callconv(.{ .x86_64_win = .{} }) isize {
    const m = msg orelse return 0;
    lockWindows();
    const w = findWindowUnlocked(m.hwnd);
    const proc = if (w) |win| win.wndproc else 0;
    unlockWindows();
    if (proc == 0) return 0;
    const WndProc = *const fn (usize, u32, usize, isize) callconv(.{ .x86_64_win = .{} }) isize;
    const f: WndProc = @ptrFromInt(proc);
    return f(m.hwnd, m.message, m.wparam, m.lparam);
}

fn shim_TranslateMessage(msg: ?*const MSG) callconv(.{ .x86_64_win = .{} }) i32 {
    _ = msg;
    // No keyboard-to-character translation is synthesized; returning 0 is
    // truthful (no WM_CHAR was posted).
    return 0;
}

/// Test hook: clear classes, windows and queued messages.
pub fn resetWindowStateForTest() void {
    lockWindows();
    defer unlockWindows();
    g_window_class_count = 0;
    g_message_count = 0;
    g_next_window = 1;
    for (&g_windows) |*w| w.in_use = false;
}

fn shim_RegOpenKeyW(hKey: usize, lpSubKey: ?[*:0]const u16, phkResult: ?*usize) callconv(.{ .x86_64_win = .{} }) i32 {
    _ = hKey;
    _ = phkResult;
    _ = lpSubKey;
    return 2;
}

fn shim_RegOpenKeyExW(
    hKey: usize,
    lpSubKey: ?[*:0]const u16,
    ulOptions: u32,
    samDesired: u32,
    phkResult: ?*usize,
) callconv(.{ .x86_64_win = .{} }) i32 {
    _ = hKey;
    _ = ulOptions;
    _ = samDesired;
    _ = phkResult;
    logWideStr("[REG] RegOpenKeyExW", lpSubKey);
    return 2;
}

fn shim_RegQueryValueExW(
    hKey: usize,
    lpValueName: ?[*:0]const u16,
    lpReserved: ?*u32,
    lpType: ?*u32,
    lpData: ?[*]u8,
    lpcbData: ?*u32,
) callconv(.{ .x86_64_win = .{} }) i32 {
    _ = hKey;
    _ = lpReserved;
    _ = lpType;
    _ = lpData;
    _ = lpcbData;
    logWideStr("[REG] RegQueryValueExW", lpValueName);
    return 2;
}

fn shim_RegCloseKey(hKey: usize) callconv(.{ .x86_64_win = .{} }) i32 {
    _ = hKey;
    return 0;
}

fn shim_ExitThread(code: u32) callconv(.{ .x86_64_win = .{} }) noreturn {
    thread_exit.exitCurrent(code);
}

fn shim_TerminateThread(handle: ?*anyopaque, code: u32) callconv(.{ .x86_64_win = .{} }) i32 {
    _ = handle;
    if (builtin.os.tag == .windows) std.log.warn("[TERM] TerminateThread(0x{x})", .{code});
    return 1;
}

threadlocal var g_rand_state: u32 = 1;

fn shim_abort() callconv(.{ .x86_64_win = .{} }) noreturn {
    if (builtin.os.tag == .linux) std.log.err("[ABORT] CRT abort() called by engine", .{});
    std.process.exit(134);
}

fn shim_terminate() callconv(.{ .x86_64_win = .{} }) noreturn {
    if (builtin.os.tag == .linux) std.log.err("[ABORT] C++ terminate called by engine", .{});
    std.process.exit(134);
}

fn shim_srand(seed: u32) callconv(.{ .x86_64_win = .{} }) void {
    g_rand_state = seed;
}

fn shim_rand() callconv(.{ .x86_64_win = .{} }) c_int {
    // MSVC-compatible LCG so guest code and native code agree.
    g_rand_state = g_rand_state *% 214013 +% 2531011;
    return @intCast((g_rand_state >> 16) & 0x7fff);
}

fn shim_TerminateProcess(handle: ?*anyopaque, code: u32) callconv(.{ .x86_64_win = .{} }) i32 {
    _ = handle;
    if (builtin.os.tag == .windows) std.log.warn("[TERM] TerminateProcess(0x{x})", .{code});
    std.process.exit(@truncate(code));
}

fn shim_RtlExitUserProcess(code: u32) callconv(.{ .x86_64_win = .{} }) noreturn {
    if (builtin.os.tag == .windows) std.log.warn("[TERM] RtlExitUserProcess(0x{x})", .{code});
    std.process.exit(@truncate(code));
}

fn shim_QueryPerformanceCounter(lpPerformanceCount: *i64) callconv(.{ .x86_64_win = .{} }) i32 {
    if (builtin.os.tag == .linux) {
        var ts: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
        lpPerformanceCount.* = @as(i64, ts.sec) * 10_000_000 + @divTrunc(@as(i64, ts.nsec), 100);
    } else {
        lpPerformanceCount.* = 1;
    }
    return 1;
}

fn shim_QueryPerformanceFrequency(lpFrequency: *i64) callconv(.{ .x86_64_win = .{} }) i32 {
    lpFrequency.* = 10_000_000;
    return 1;
}

fn shim_GetSystemTimeAsFileTime(lpFileTime: *u64) callconv(.{ .x86_64_win = .{} }) void {
    const epoch_diff: u64 = 116444736000000000;
    if (builtin.os.tag == .linux) {
        var ts: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(.REALTIME, &ts);
        const unix_100ns: u64 = @as(u64, @intCast(ts.sec)) * 10_000_000 + @as(u64, @intCast(@divTrunc(ts.nsec, 100)));
        lpFileTime.* = epoch_diff + unix_100ns;
    } else {
        lpFileTime.* = epoch_diff;
    }
}

fn shim_GetCurrentThreadId() callconv(.{ .x86_64_win = .{} }) u32 {
    if (teb.currentTeb()) |t| return @truncate(t.client_id.unique_thread);
    if (builtin.os.tag == .linux) return @bitCast(@as(i32, @truncate(std.os.linux.gettid())));
    return 1001;
}

fn shim_GetCurrentThread() callconv(.{ .x86_64_win = .{} }) usize {
    return sync.CURRENT_THREAD_HANDLE;
}

fn shim_GetProcessId(handle: usize) callconv(.{ .x86_64_win = .{} }) u32 {
    if (handle == @as(usize, @bitCast(@as(isize, -1)))) {
        if (teb.process()) |p| return p.pid;
        return shim_GetCurrentProcessId();
    }
    teb.setLastError(sync.ERROR_INVALID_HANDLE);
    return 0;
}

fn shim_GetCurrentThreadStackLimits(low: ?*usize, high: ?*usize) callconv(.{ .x86_64_win = .{} }) void {
    const bounds = teb.stackBounds() orelse {
        if (low) |p| p.* = 0;
        if (high) |p| p.* = 0;
        return;
    };
    if (low) |p| p.* = bounds.limit;
    if (high) |p| p.* = bounds.base;
}

fn shim_GetCurrentProcessId() callconv(.{ .x86_64_win = .{} }) u32 {
    if (teb.currentTeb()) |t| return @truncate(t.client_id.unique_process);
    if (builtin.os.tag == .linux) return @bitCast(std.os.linux.getpid());
    return 1000;
}

/// ANSI code page of the guest Windows environment.
fn shim_GetACP() callconv(.{ .x86_64_win = .{} }) u32 {
    return 1252;
}

/// OEM code page of the guest Windows environment.
fn shim_GetOEMCP() callconv(.{ .x86_64_win = .{} }) u32 {
    return 437;
}

fn shim_malloc(size: usize) callconv(.{ .x86_64_win = .{} }) ?*anyopaque {
    return std.c.malloc(size);
}

fn shim_calloc(nmemb: usize, size: usize) callconv(.{ .x86_64_win = .{} }) ?*anyopaque {
    const total = nmemb * size;
    const ptr = std.c.malloc(total) orelse return null;
    const bytes: [*]u8 = @ptrCast(ptr);
    @memset(bytes[0..total], 0);
    return ptr;
}

fn shim_realloc(ptr: ?*anyopaque, size: usize) callconv(.{ .x86_64_win = .{} }) ?*anyopaque {
    return std.c.realloc(ptr, size);
}

fn shim_free(ptr: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) void {
    std.c.free(ptr);
}

fn shim_memcpy(dst: [*]u8, src: [*]const u8, len: usize) callconv(.{ .x86_64_win = .{} }) [*]u8 {
    @memcpy(dst[0..len], src[0..len]);
    return dst;
}

fn shim_memmove(dst: [*]u8, src: [*]const u8, len: usize) callconv(.{ .x86_64_win = .{} }) [*]u8 {
    std.mem.copyForwards(u8, dst[0..len], src[0..len]);
    return dst;
}

fn shim_memset(dst: [*]u8, val: c_int, len: usize) callconv(.{ .x86_64_win = .{} }) [*]u8 {
    @memset(dst[0..len], @truncate(@as(c_uint, @bitCast(val))));
    return dst;
}

const SystemLogicalProcessorInformation = extern struct {
    processor_mask: usize,
    relationship: u32,
    pad0: u32 = 0,
    pad1: u64 = 0,
    pad2: u64 = 0,
};

fn shim_GetLogicalProcessorInformation(
    buffer: ?[*]u8,
    return_length: *u32,
) callconv(.{ .x86_64_win = .{} }) i32 {
    const entry_size: u32 = @sizeOf(SystemLogicalProcessorInformation);
    if (buffer == null or return_length.* < entry_size) {
        return_length.* = entry_size;
        teb.setLastError(122); // ERROR_INSUFFICIENT_BUFFER
        return 0;
    }

    const out: *SystemLogicalProcessorInformation = @ptrCast(@alignCast(buffer.?));
    out.* = .{
        .processor_mask = 0xFF, // 8 cores (Xbox Series X Zen 2 topology)
        .relationship = 0, // RelationProcessorCore
    };
    return_length.* = entry_size;
    return 1;
}

fn shim_GetLogicalProcessorInformationEx(
    relationship_type: u32,
    buffer: ?[*]u8,
    returned_length: *u32,
) callconv(.{ .x86_64_win = .{} }) i32 {
    _ = relationship_type;
    _ = buffer;
    returned_length.* = 0;
    teb.setLastError(120); // ERROR_CALL_NOT_IMPLEMENTED
    return 0;
}

fn shim_GetSystemInfo(sys_info: [*]u8) callconv(.{ .x86_64_win = .{} }) void {
    @memset(sys_info[0..48], 0);
    std.mem.writeInt(u16, sys_info[0..2], 9, .little); // PROCESSOR_ARCHITECTURE_AMD64
    std.mem.writeInt(u32, sys_info[4..8], 4096, .little); // dwPageSize
    std.mem.writeInt(usize, sys_info[8..16], 0x10000, .little); // lpMinimumApplicationAddress
    std.mem.writeInt(usize, sys_info[16..24], 0x7FFFFFFEFFFF, .little); // lpMaximumApplicationAddress
    std.mem.writeInt(usize, sys_info[24..32], 0xFF, .little); // dwActiveProcessorMask (8 cores)
    std.mem.writeInt(u32, sys_info[32..36], 8, .little); // dwNumberOfProcessors = 8
    std.mem.writeInt(u32, sys_info[36..40], 8664, .little); // dwProcessorType = PROCESSOR_AMD_X8664
    std.mem.writeInt(u32, sys_info[40..44], 65536, .little); // dwAllocationGranularity = 64KB
}

fn shim_GetActiveProcessorCount(group_number: u16) callconv(.{ .x86_64_win = .{} }) u32 {
    _ = group_number;
    return 8;
}

const cmd_line_a: [*:0]const u8 = "game_scarlett_master.exe";

fn shim_GetCommandLineA() callconv(.{ .x86_64_win = .{} }) [*:0]const u8 {
    return teb.commandLineA().ptr;
}

fn shim_GetCommandLineW() callconv(.{ .x86_64_win = .{} }) [*:0]const u16 {
    return teb.commandLineW().ptr;
}

fn shim_tanf(x: f32) callconv(.{ .x86_64_win = .{} }) f32 {
    return @tan(x);
}

fn shim_sinf(x: f32) callconv(.{ .x86_64_win = .{} }) f32 {
    return @sin(x);
}

fn shim_cosf(x: f32) callconv(.{ .x86_64_win = .{} }) f32 {
    return @cos(x);
}

fn shim_sqrtf(x: f32) callconv(.{ .x86_64_win = .{} }) f32 {
    return @sqrt(x);
}

fn shim_atan2f(y: f32, x: f32) callconv(.{ .x86_64_win = .{} }) f32 {
    return std.math.atan2(y, x);
}

fn shim_strlen(s: ?[*:0]const u8) callconv(.{ .x86_64_win = .{} }) usize {
    const ptr = s orelse return 0;
    return std.mem.len(ptr);
}

fn shim_strcmp(s1: ?[*:0]const u8, s2: ?[*:0]const u8) callconv(.{ .x86_64_win = .{} }) c_int {
    const a = std.mem.span(s1 orelse return -1);
    const b = std.mem.span(s2 orelse return 1);
    return switch (std.mem.order(u8, a, b)) {
        .lt => -1,
        .eq => 0,
        .gt => 1,
    };
}

fn shim_strnicmp(s1: ?[*:0]const u8, s2: ?[*:0]const u8, n: usize) callconv(.{ .x86_64_win = .{} }) c_int {
    const a = std.mem.span(s1 orelse return -1);
    const b = std.mem.span(s2 orelse return 1);
    const len = @min(n, @min(a.len, b.len));
    const ord = std.ascii.orderIgnoreCase(a[0..len], b[0..len]);
    if (ord != .eq) return if (ord == .lt) -1 else 1;
    if (len == n or a.len == b.len) return 0;
    return if (a.len < b.len) -1 else 1;
}

fn shim_GetTickCount64() callconv(.{ .x86_64_win = .{} }) u64 {
    if (builtin.os.tag == .linux) {
        var ts: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
        return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(@divTrunc(ts.nsec, 1_000_000)));
    }
    return 1000;
}

fn shim_time64(timer: ?*i64) callconv(.{ .x86_64_win = .{} }) i64 {
    var now: i64 = 1795490000;
    if (builtin.os.tag == .linux) {
        var ts: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(.REALTIME, &ts);
        now = ts.sec;
    }
    if (timer) |t| t.* = now;
    return now;
}

fn shim_exp2f(x: f32) callconv(.{ .x86_64_win = .{} }) f32 {
    return @exp2(x);
}

fn shim_log10f(x: f32) callconv(.{ .x86_64_win = .{} }) f32 {
    return @log10(x);
}

fn shim_powf(base: f32, exp: f32) callconv(.{ .x86_64_win = .{} }) f32 {
    return std.math.pow(f32, base, exp);
}

fn shim_GetStartupInfoW(lpStartupInfo: [*]u8) callconv(.{ .x86_64_win = .{} }) void {
    @memset(lpStartupInfo[0..104], 0);
    std.mem.writeInt(u32, lpStartupInfo[0..4], 104, .little); // cb = sizeof(STARTUPINFOW)
    std.mem.writeInt(u32, lpStartupInfo[60..64], 1, .little); // dwFlags = STARTF_USESHOWWINDOW
    std.mem.writeInt(u16, lpStartupInfo[64..66], 1, .little); // wShowWindow = SW_SHOWNORMAL
}

fn shim_get_narrow_winmain_command_line() callconv(.{ .x86_64_win = .{} }) [*:0]const u8 {
    return "";
}

fn shim_register_thread_local_exe_atexit_callback(cb: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) void {
    _ = cb;
}

fn shim_GetModuleFileNameW(hModule: usize, lpFilename: [*]u16, nSize: u32) callconv(.{ .x86_64_win = .{} }) u32 {
    if (nSize == 0) return 0;
    const base = if (hModule != 0)
        hModule
    else if (teb.process()) |p| p.peb_ptr.ImageBaseAddress else 0;
    return @intCast(teb.moduleFileNameW(base, lpFilename, nSize));
}

fn shim_LoadLibraryExW(lpLibFileName: ?[*:0]const u16, hFile: usize, dwFlags: u32) callconv(.{ .x86_64_win = .{} }) usize {
    _ = hFile;
    _ = dwFlags;
    const name = lpLibFileName orelse return 0;
    if (mod.load_library_fn) |f| return f(name);
    return 0;
}

fn shim_InitializeApiImpl(reserved: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32 {
    _ = reserved;
    const hr = xgameruntime_min.initialize(xgameruntime_min.SUPPORTED_GDK_VERSION);
    std.log.info("[GDK] InitializeApiImpl() -> 0x{x}", .{@as(u32, @bitCast(hr))});
    return hr;
}

fn shim_InitializeApiImplEx(options: ?*const anyopaque, reserved: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32 {
    _ = options;
    _ = reserved;
    const hr = xgameruntime_min.initialize(xgameruntime_min.SUPPORTED_GDK_VERSION);
    std.log.info("[GDK] InitializeApiImplEx() -> 0x{x}", .{@as(u32, @bitCast(hr))});
    return hr;
}

fn shim_InitializeApiImplEx2(
    options: ?*const anyopaque,
    version: u64,
    reserved: ?*anyopaque,
) callconv(.{ .x86_64_win = .{} }) i32 {
    _ = options;
    _ = reserved;
    const hr = xgameruntime_min.initialize(version);
    std.log.info("[GDK] InitializeApiImplEx2(version=0x{x}, build={d}) -> 0x{x}", .{
        version, @as(u32, @truncate(version >> 32)), @as(u32, @bitCast(hr)),
    });
    return hr;
}

fn shim_UninitializeApiImpl() callconv(.{ .x86_64_win = .{} }) void {
    xgameruntime_min.uninitialize();
    std.log.info("[GDK] UninitializeApiImpl()", .{});
}

fn shim_XErrorReport(hr: i32, msg: ?[*:0]const u8) callconv(.{ .x86_64_win = .{} }) i32 {
    if (msg) |m| {
        std.log.warn("[GDK] XErrorReport(hr=0x{x}, msg=\"{s}\")", .{ @as(u32, @bitCast(hr)), std.mem.span(m) });
    }
    return 1;
}

fn shim_QueryApiImpl(
    rclsid: ?[*]const u8,
    riid: ?[*]const u8,
    ppv: ?*?*anyopaque,
) callconv(.{ .x86_64_win = .{} }) i32 {
    if (rclsid) |g| {
        const d1 = std.mem.readInt(u32, g[0..4], .little);
        const d2 = std.mem.readInt(u16, g[4..6], .little);
        const d3 = std.mem.readInt(u16, g[6..8], .little);
        if (riid) |r| {
            const e1 = std.mem.readInt(u32, r[0..4], .little);
            const e2 = std.mem.readInt(u16, r[4..6], .little);
            const e3 = std.mem.readInt(u16, r[6..8], .little);
            std.log.warn("[GDK] QueryApiImpl(clsid={{{x:0>8}-{x:0>4}-{x:0>4}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}}} riid={{{x:0>8}-{x:0>4}-{x:0>4}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}}})", .{
                d1, d2, d3, g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15],
                e1, e2, e3, r[8], r[9], r[10], r[11], r[12], r[13], r[14], r[15],
            });
        } else {
            std.log.warn("[GDK] QueryApiImpl(clsid={{{x:0>8}-{x:0>4}-{x:0>4}-...}}, riid=null)", .{ d1, d2, d3 });
        }
    }
    if (ppv) |out| out.* = null;
    if (!xgameruntime_min.isInitialized()) {
        std.log.warn("[GDK] QueryApiImpl before a supported InitializeApiImpl call", .{});
        return xgameruntime_min.CO_E_NOTINITIALIZED;
    }
    if (rclsid) |g| {
        if (xgameruntime_min.queryApi(
            @ptrCast(@alignCast(g)),
            if (riid) |r| @ptrCast(@alignCast(r)) else null,
            ppv,
        )) |hr| {
            std.log.info("[GDK] QueryApiImpl -> provider object (hr=0x{x})", .{@as(u32, @bitCast(hr))});
            return hr;
        }
    }
    std.log.warn("[GDK] QueryApiImpl -> E_NOINTERFACE", .{});
    return -2147467262;
}

var g_argc: c_int = 1;
var g_argv_storage: usize = 0;

fn shim_p_argc() callconv(.{ .x86_64_win = .{} }) *c_int {
    return &g_argc;
}

fn shim_p_argv() callconv(.{ .x86_64_win = .{} }) *usize {
    g_argv_storage = @intFromPtr(&cmd_line_a);
    return &g_argv_storage;
}

const WinThreadProc = *const fn (?*anyopaque) callconv(.{ .x86_64_win = .{} }) u32;

const ThreadSpawnCtx = struct {
    start_fn: WinThreadProc,
    param: ?*anyopaque,
    tid: u32,
    stack_size: usize,
    handle: usize,
    /// Acquired reference to this thread's sync handle object; the exit path
    /// publishes the exit code through it (see thread_exit.zig).
    thread_ref: ?*anyopaque = null,
    gate: ?*ThreadGate = null,
};

/// CreateThread(CREATE_SUSPENDED) must not run the guest entry (or the CRT's
/// thread-attach callbacks) until ResumeThread drops the suspend count to
/// zero.  Each created thread gets a gate kept in a small static table keyed
/// by the guest's thread handle.
const ThreadGate = struct {
    handle: usize = 0,
    running: std.atomic.Value(u32) = std.atomic.Value(u32).init(1),
    suspend_count: u32 = 0,
};

const MAX_THREAD_GATES = 128;
var g_gates: [MAX_THREAD_GATES]ThreadGate = @splat(.{});
var g_gate_lock = std.atomic.Value(u8).init(0);

fn lockGates() void {
    while (g_gate_lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
        std.atomic.spinLoopHint();
    }
}

fn unlockGates() void {
    g_gate_lock.store(0, .release);
}

fn allocGate(handle: usize, suspended: bool) ?*ThreadGate {
    lockGates();
    defer unlockGates();
    for (&g_gates) |*g| {
        if (g.handle != 0) continue;
        g.* = .{
            .handle = handle,
            .running = std.atomic.Value(u32).init(if (suspended) 0 else 1),
            .suspend_count = if (suspended) 1 else 0,
        };
        return g;
    }
    return null;
}

fn findGate(handle: usize) ?*ThreadGate {
    lockGates();
    defer unlockGates();
    for (&g_gates) |*g| {
        if (g.handle == handle) return g;
    }
    return null;
}

fn releaseGate(handle: usize) void {
    lockGates();
    defer unlockGates();
    for (&g_gates) |*g| {
        if (g.handle == handle) {
            g.* = .{};
            return;
        }
    }
}

fn waitForResume(gate: *ThreadGate) void {
    while (gate.running.load(.acquire) == 0) {
        var req = std.os.linux.timespec{ .sec = 0, .nsec = 1_000_000 };
        _ = std.os.linux.nanosleep(&req, null);
    }
}

/// Guest threads must run on a host thread with its own TLS block: glibc keeps
/// `errno` and the malloc `tcache` in TLS, so inheriting the creator's FS base
/// (as a raw `clone` without CLONE_SETTLS does) makes concurrent guest heap
/// calls corrupt the host allocator.  pthread_create allocates a fresh TLS
/// area for the child.
const PthreadArgs = struct {
    ctx: ThreadSpawnCtx,
};

fn pthreadEntry(raw: ?*anyopaque) callconv(.c) ?*anyopaque {
    const args: *PthreadArgs = @ptrCast(@alignCast(raw orelse return null));
    const ctx = args.ctx;
    std.heap.c_allocator.destroy(args);
    threadBootstrap(ctx);
    return null;
}

const pthread_getattr_np = struct {
    extern "c" fn pthread_getattr_np(thread: std.c.pthread_t, attr: *std.c.pthread_attr_t) c_int;
}.pthread_getattr_np;
const pthread_attr_getstack = struct {
    extern "c" fn pthread_attr_getstack(attr: *const std.c.pthread_attr_t, stackaddr: *?*anyopaque, stacksize: *usize) c_int;
}.pthread_attr_getstack;

/// The host stack top of the current thread (the highest valid stack address).
/// Linux-only: on Windows the host TEB already describes the thread stack.
fn hostStackTop() ?usize {
    if (builtin.os.tag == .linux) {
        var attr: std.c.pthread_attr_t = undefined;
        if (pthread_getattr_np(std.c.pthread_self(), &attr) != 0) return null;
        defer _ = std.c.pthread_attr_destroy(&attr);
        var addr: ?*anyopaque = null;
        var size: usize = 0;
        if (pthread_attr_getstack(&attr, &addr, &size) != 0) return null;
        const base: usize = @intFromPtr(addr);
        if (base == 0 or size == 0) return null;
        return base + size;
    }
    return null;
}

fn spawnLinuxThread(stack_size: usize, spawn_ctx: ThreadSpawnCtx) !void {
    const args = std.heap.c_allocator.create(PthreadArgs) catch return error.OutOfMemory;
    args.* = .{ .ctx = spawn_ctx };

    // Default pthread stack unless the guest asked for more than the default:
    // host libc rejects explicit stack sizes below 1 MiB with EINVAL, and the
    // guest's own __chkstk enforces the requested size via the TEB StackLimit.
    var attr: std.c.pthread_attr_t = undefined;
    var use_attr = false;
    if (stack_size > 1024 * 1024) {
        if (std.c.pthread_attr_init(&attr) != .SUCCESS) {
            std.heap.c_allocator.destroy(args);
            return error.SystemResources;
        }
        use_attr = true;
        const size = std.mem.alignForward(usize, stack_size, 4096);
        _ = std.c.pthread_attr_setstacksize(&attr, size);
    }
    defer if (use_attr) {
        _ = std.c.pthread_attr_destroy(&attr);
    };

    var handle: std.c.pthread_t = undefined;
    const rc = std.c.pthread_create(&handle, if (use_attr) &attr else null, pthreadEntry, args);
    if (rc != .SUCCESS) {
        std.heap.c_allocator.destroy(args);
        std.log.err("[THREAD] pthread_create failed: {s} size=0x{x}", .{ @tagName(rc), stack_size });
        return error.SystemResources;
    }
    _ = std.c.pthread_detach(handle);
}

fn threadBootstrap(ctx: ThreadSpawnCtx) void {
    defer _ = g_thread_count.fetchSub(1, .monotonic);
    defer releaseGate(ctx.handle);
    // CREATE_SUSPENDED: the guest entry and the CRT thread-attach callbacks do
    // not run until ResumeThread has dropped the suspend count to zero.
    if (ctx.gate) |g| waitForResume(g);

    if (builtin.os.tag == .linux or builtin.os.tag == .windows) {
        var stack_base: usize = 0;
        if (hostStackTop()) |top| {
            // High end of this thread's host stack.
            stack_base = top;
        } else {
            var rsp: usize = undefined;
            asm volatile ("movq %%rsp, %[out]"
                : [out] "=r" (rsp),
            );
            stack_base = rsp & ~@as(usize, 0xF);
        }
        // The guest's requested stack size is enforced by guest __chkstk
        // through TEB.StackLimit, independent of the host stack size.
        const stack_size = if (ctx.stack_size != 0) ctx.stack_size else 1024 * 1024;
        _ = teb.initThread(stack_base, stack_base - stack_size, ctx.tid) catch {};
    }

    thread_exit.setThreadRef(ctx.thread_ref);
    if (mod.thread_attach_fn) |f| f();

    teb.enterGuest();
    const code = ctx.start_fn(ctx.param);
    // Normal thread return: DLL_THREAD_DETACH, FLS destructors, exit code,
    // TEB/TLS release.  (ExitThread/_endthreadex use the same path.)
    thread_exit.finish(code);
}

const WinStartFn = *const fn (?*anyopaque) callconv(.winapi) u32;

extern "kernel32" fn CloseHandle(h: ?*anyopaque) callconv(.winapi) i32;

extern "kernel32" fn CreateThread(
    lpThreadAttributes: ?*anyopaque,
    dwStackSize: usize,
    lpStartAddress: WinStartFn,
    lpParameter: ?*anyopaque,
    dwCreationFlags: u32,
    lpThreadId: ?*u32,
) callconv(.winapi) ?*anyopaque;

fn winThreadStart(param: ?*anyopaque) callconv(.winapi) u32 {
    const ctx: *ThreadSpawnCtx = @ptrCast(@alignCast(param orelse return 1));
    threadBootstrap(ctx.*);
    return 0;
}

fn shim_CreateThread(
    security_attrs: ?*anyopaque,
    stack_size_arg: usize,
    start_address: ?WinThreadProc,
    parameter: ?*anyopaque,
    creation_flags: u32,
    thread_id: ?*u32,
) callconv(.{ .x86_64_win = .{} }) usize {
    _ = security_attrs;
    const func = start_address orelse return 0;
    const tid: u32 = allocGuestThreadId();
    if (thread_id) |tid_out| tid_out.* = tid;

    const live = g_thread_count.fetchAdd(1, .monotonic);
    const handle = sync.createThreadHandle(tid);
    if (handle == 0) {
        _ = g_thread_count.fetchSub(1, .monotonic);
        return 0;
    }

    // CreateThread(0) uses the process default (the executable's
    // SizeOfStackReserve); the guest TEB limit always reflects the request.
    const requested_stack: usize = if (stack_size_arg != 0)
        @min(stack_size_arg, 64 * 1024 * 1024)
    else
        teb.processStackReserve();
    const stack_size: usize = @min(requested_stack, 8 * 1024 * 1024);

    const log_index = g_thread_logs.fetchAdd(1, .monotonic);
    if (log_index < 24 or log_index % 64 == 0) {
        std.log.info("[THREAD] CreateThread(entry=0x{x}, tid={d}, handle=0x{x}, live={d}, stack=0x{x}, flags=0x{x})", .{
            @intFromPtr(func), tid, handle, live, requested_stack, creation_flags,
        });
    }
    const suspended = (creation_flags & CREATE_SUSPENDED) != 0;
    const gate = allocGate(handle, suspended);
    const spawn_ctx = ThreadSpawnCtx{
        .start_fn = func,
        .param = parameter,
        .tid = tid,
        .stack_size = stack_size,
        .handle = handle,
        .thread_ref = sync.acquireThreadRef(handle),
        .gate = gate,
    };

    if (builtin.os.tag == .linux) {
        spawnLinuxThread(stack_size, spawn_ctx) catch |err| {
            _ = g_thread_count.fetchSub(1, .monotonic);
            std.log.err("[THREAD] spawn failed for tid={d}: {s}", .{ tid, @errorName(err) });
            noteThreadFailure();
            releaseGate(handle);
            if (spawn_ctx.thread_ref) |r| sync.releaseThreadRef(r);
            _ = sync.closeHandle(handle);
            return 0;
        };
        return handle;
    }

    const ctx = std.heap.c_allocator.create(ThreadSpawnCtx) catch {
        _ = g_thread_count.fetchSub(1, .monotonic);
        _ = sync.closeHandle(handle);
        return 0;
    };
    ctx.* = spawn_ctx;
    const native = CreateThread(null, stack_size, &winThreadStart, ctx, 0, null) orelse {
        std.heap.c_allocator.destroy(ctx);
        _ = g_thread_count.fetchSub(1, .monotonic);
        noteThreadFailure();
        releaseGate(handle);
        if (spawn_ctx.thread_ref) |r| sync.releaseThreadRef(r);
        _ = sync.closeHandle(handle);
        return 0;
    };
    _ = CloseHandle(native);
    return handle;
}

fn shim_Sleep(milliseconds: u32) callconv(.{ .x86_64_win = .{} }) void {
    if (builtin.os.tag == .linux) {
        var req = std.os.linux.timespec{
            .sec = @intCast(milliseconds / 1000),
            .nsec = @intCast((milliseconds % 1000) * 1_000_000),
        };
        _ = std.os.linux.nanosleep(&req, null);
    }
}

fn shim_LoadLibraryW(lpLibFileName: ?[*:0]const u16) callconv(.{ .x86_64_win = .{} }) usize {
    const name = lpLibFileName orelse return 0;
    if (mod.load_library_fn) |f| return f(name);
    return 0;
}

fn shim_LoadLibraryA(lpLibFileName: ?[*:0]const u8) callconv(.{ .x86_64_win = .{} }) usize {
    const name = lpLibFileName orelse return 0;
    if (mod.load_library_a_fn) |f| return f(name);
    return 0;
}

fn shim_LoadLibraryExA(lpLibFileName: ?[*:0]const u8, hFile: usize, dwFlags: u32) callconv(.{ .x86_64_win = .{} }) usize {
    _ = hFile;
    _ = dwFlags;
    return shim_LoadLibraryA(lpLibFileName);
}

fn shim_FreeLibrary(hModule: usize) callconv(.{ .x86_64_win = .{} }) i32 {
    if (mod.free_library_fn) |f| return f(hModule);
    return 0;
}

fn shim_GetModuleFileNameA(hModule: usize, lpFilename: ?[*]u8, nSize: u32) callconv(.{ .x86_64_win = .{} }) u32 {
    const out = lpFilename orelse return 0;
    if (nSize == 0) return 0;
    const base = if (hModule != 0)
        hModule
    else if (teb.process()) |p| p.peb_ptr.ImageBaseAddress else 0;
    return @intCast(mod.fileNameA(base, out, nSize));
}

fn shim_wcscat_s(dest: ?[*]u16, destsz: usize, src: ?[*:0]const u16) callconv(.{ .x86_64_win = .{} }) i32 {
    const d = dest orelse return 22; // EINVAL
    const s = src orelse return 22;
    if (destsz == 0) return 22;
    var len: usize = 0;
    while (len < destsz and d[len] != 0) : (len += 1) {}
    if (len == destsz) return 34; // ERANGE
    var i: usize = 0;
    while (s[i] != 0) : (i += 1) {
        if (len + i + 1 >= destsz) {
            d[0] = 0;
            return 34;
        }
        d[len + i] = s[i];
    }
    d[len + i] = 0;
    return 0;
}

fn shim_wcslen(s: ?[*:0]const u16) callconv(.{ .x86_64_win = .{} }) usize {
    const ptr = s orelse return 0;
    var len: usize = 0;
    while (ptr[len] != 0) : (len += 1) {}
    return len;
}

fn shim_UuidCreate(uuid_out: ?[*]u8) callconv(.{ .x86_64_win = .{} }) i32 {
    const out = uuid_out orelse return 1;
    if (builtin.os.tag == .linux) {
        _ = std.os.linux.getrandom(out, 16, 0);
    } else {
        @memset(out[0..16], 0x42);
    }
    const b6 = std.mem.readInt(u8, out[6..7], .little);
    const b8 = std.mem.readInt(u8, out[8..9], .little);
    std.mem.writeInt(u8, out[6..7], (b6 & 0x0F) | 0x40, .little);
    std.mem.writeInt(u8, out[8..9], (b8 & 0x3F) | 0x80, .little);
    return 0; // RPC_S_OK
}

fn shim_GetCurrentProcess() callconv(.{ .x86_64_win = .{} }) usize {
    return @bitCast(@as(isize, -1));
}

fn shim_strchr(s: ?[*:0]const u8, c: c_int) callconv(.{ .x86_64_win = .{} }) ?[*:0]const u8 {
    const ptr = s orelse return null;
    const target: u8 = @truncate(@as(c_uint, @bitCast(c)));
    var i: usize = 0;
    while (true) : (i += 1) {
        if (ptr[i] == target) return ptr + i;
        if (ptr[i] == 0) return null;
    }
}

fn shim_strrchr(s: ?[*:0]const u8, c: c_int) callconv(.{ .x86_64_win = .{} }) ?[*:0]const u8 {
    const ptr = s orelse return null;
    const target: u8 = @truncate(@as(c_uint, @bitCast(c)));
    var last: ?[*:0]const u8 = null;
    var i: usize = 0;
    while (true) : (i += 1) {
        if (ptr[i] == target) last = ptr + i;
        if (ptr[i] == 0) return last;
    }
}

fn shim_strncmp(s1: ?[*:0]const u8, s2: ?[*:0]const u8, n: usize) callconv(.{ .x86_64_win = .{} }) c_int {
    if (n == 0) return 0;
    const a = s1 orelse return -1;
    const b = s2 orelse return 1;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        if (a[i] != b[i]) return if (a[i] < b[i]) -1 else 1;
        if (a[i] == 0) return 0;
    }
    return 0;
}

fn shim_wfopen(filename: ?[*:0]const u16, mode: ?[*:0]const u16) callconv(.{ .x86_64_win = .{} }) ?*anyopaque {
    _ = mode;
    if (filename) |f| {
        if (std.mem.len(f) > 0) logWideStr("[FS] _wfopen", filename);
    }
    return null;
}

fn shim_SetThreadPriority(_: usize, _: c_int) callconv(.{ .x86_64_win = .{} }) i32 {
    return 1;
}
const CREATE_SUSPENDED: u32 = 0x0000_0004;

fn shim_ResumeThread(handle: usize) callconv(.{ .x86_64_win = .{} }) u32 {
    const gate = findGate(handle) orelse return 0xFFFF_FFFF;
    const previous = gate.suspend_count;
    if (previous != 0) {
        gate.suspend_count = previous - 1;
        if (gate.suspend_count == 0) gate.running.store(1, .release);
    }
    return previous;
}

fn shim_SuspendThread(handle: usize) callconv(.{ .x86_64_win = .{} }) u32 {
    const gate = findGate(handle) orelse return 0xFFFF_FFFF;
    const previous = gate.suspend_count;
    gate.suspend_count = previous + 1;
    gate.running.store(0, .release);
    return previous;
}
fn shim_GetThreadGroupAffinity(_: usize, affinity: ?[*]u8) callconv(.{ .x86_64_win = .{} }) i32 {
    if (affinity) |a| {
        @memset(a[0..16], 0);
        std.mem.writeInt(usize, a[0..8], 0xFF, .little);
    }
    return 1;
}
fn shim_SetThreadGroupAffinity(_: usize, _: ?*const anyopaque, prev: ?[*]u8) callconv(.{ .x86_64_win = .{} }) i32 {
    if (prev) |p| {
        @memset(p[0..16], 0);
        std.mem.writeInt(usize, p[0..8], 0xFF, .little);
    }
    return 1;
}
fn shim_GetLocalTime(st: [*]u8) callconv(.{ .x86_64_win = .{} }) void {
    @memset(st[0..16], 0);
    std.mem.writeInt(u16, st[0..2], 2026, .little); // wYear
    std.mem.writeInt(u16, st[2..4], 11, .little); // wMonth
    std.mem.writeInt(u16, st[6..8], 24, .little); // wDay
}

fn shim_purecall() callconv(.{ .x86_64_win = .{} }) void {
    std.log.warn("[CRT] _purecall() called from 0x{x}!", .{@returnAddress()});
}

fn shim_InitializeSListHead(list_head: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) void {
    const addr = @intFromPtr(list_head);
    if (addr < 0x10000) return;
    const bytes: [*]u8 = @ptrFromInt(addr);
    @memset(bytes[0..16], 0);
}

fn shim_TlsAlloc() callconv(.{ .x86_64_win = .{} }) u32 {
    return teb.tlsAlloc();
}

fn shim_TlsFree(index: u32) callconv(.{ .x86_64_win = .{} }) i32 {
    return if (teb.tlsFree(index)) 1 else 0;
}

fn shim_TlsGetValue(index: u32) callconv(.{ .x86_64_win = .{} }) ?*anyopaque {
    const value = teb.tlsGet(index);
    return if (value == 0) null else @ptrFromInt(value);
}

fn shim_TlsSetValue(index: u32, value: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32 {
    const addr: usize = if (value) |v| @intFromPtr(v) else 0;
    return if (teb.tlsSet(index, addr)) 1 else 0;
}

fn shim_GetEnvironmentStringsW() callconv(.{ .x86_64_win = .{} }) ?[*:0]const u16 {
    return teb.environmentW();
}

fn shim_GetEnvironmentStringsA() callconv(.{ .x86_64_win = .{} }) ?[*:0]const u8 {
    return teb.environmentA();
}

fn shim_FreeEnvironmentStringsW(_: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32 {
    return 1;
}

fn shim_FreeEnvironmentStringsA(_: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32 {
    return 1;
}

fn shim_GetCurrentDirectoryW(nBufferLength: u32, lpBuffer: ?[*]u16) callconv(.{ .x86_64_win = .{} }) u32 {
    const out = lpBuffer orelse return 0;
    if (nBufferLength == 0) return 0;
    const src = teb.cwdW();
    const n = @min(src.len, @as(usize, nBufferLength) - 1);
    @memcpy(out[0..n], src[0..n]);
    out[n] = 0;
    return @intCast(n);
}

fn shim_GetCurrentDirectoryA(nBufferLength: u32, lpBuffer: ?[*]u8) callconv(.{ .x86_64_win = .{} }) u32 {
    const out = lpBuffer orelse return 0;
    if (nBufferLength == 0) return 0;
    const src = teb.cwdA();
    const n = @min(src.len, @as(usize, nBufferLength) - 1);
    @memcpy(out[0..n], src[0..n]);
    out[n] = 0;
    return @intCast(n);
}

fn shim_GetProcessHeap() callconv(.{ .x86_64_win = .{} }) usize {
    if (teb.process()) |p| return p.peb_ptr.ProcessHeap;
    return 0x1400000;
}

fn shim_HeapAlloc(heap: usize, flags: u32, bytes: usize) callconv(.{ .x86_64_win = .{} }) ?*anyopaque {
    _ = heap;
    const ptr = std.c.malloc(@max(bytes, 1)) orelse return null;
    if (flags & 0x8 != 0) @memset(@as([*]u8, @ptrCast(ptr))[0..bytes], 0);
    return ptr;
}

fn shim_HeapFree(heap: usize, flags: u32, mem: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32 {
    _ = heap;
    _ = flags;
    std.c.free(mem);
    return 1;
}

fn shim_HeapReAlloc(heap: usize, flags: u32, mem: ?*anyopaque, bytes: usize) callconv(.{ .x86_64_win = .{} }) ?*anyopaque {
    _ = heap;
    _ = flags;
    return std.c.realloc(mem, @max(bytes, 1));
}

/// Guest heap blocks are host libc allocations, so the usable size is what
/// the host allocator reports.  UCRT's `_realloc_base`/`_free_base` use this
/// to validate blocks; returning 0 made them take a bogus slow path.
fn shim_HeapSize(heap: usize, flags: u32, mem: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) usize {
    _ = heap;
    _ = flags;
    const ptr = mem orelse return 0;
    if (builtin.os.tag == .linux) {
        const libc = struct {
            extern "c" fn malloc_usable_size(ptr: ?*anyopaque) usize;
        };
        return libc.malloc_usable_size(ptr);
    }
    return 0;
}

pub fn resolve(sym_name: []const u8) ?usize {
    const map = .{
        .{ "_initterm", @intFromPtr(&shim_initterm) },
        .{ "_initterm_e", @intFromPtr(&shim_initterm_e) },
        .{ "_initialize_onexit_table", @intFromPtr(&shim_initialize_onexit_table) },
        .{ "_register_onexit_function", @intFromPtr(&shim_register_onexit_function) },
        .{ "_crt_atexit", @intFromPtr(&shim_crt_atexit) },
        .{ "exit", @intFromPtr(&shim_exit) },
        .{ "_exit", @intFromPtr(&shim_exit) },
        .{ "_cexit", @intFromPtr(&shim_cexit) },
        .{ "ExitProcess", @intFromPtr(&shim_ExitProcess) },
        .{ "TerminateProcess", @intFromPtr(&shim_TerminateProcess) },
        .{ "RtlExitUserProcess", @intFromPtr(&shim_RtlExitUserProcess) },
        .{ "NtTerminateProcess", @intFromPtr(&shim_TerminateProcess) },
        .{ "ExitThread", @intFromPtr(&shim_ExitThread) },
        .{ "RtlExitUserThread", @intFromPtr(&shim_ExitThread) },
        .{ "TerminateThread", @intFromPtr(&shim_TerminateThread) },
        .{ "NtTerminateThread", @intFromPtr(&shim_TerminateThread) },
        .{ "GetLastError", @intFromPtr(&shim_GetLastError) },
        .{ "SetLastError", @intFromPtr(&shim_SetLastError) },
        .{ "__p__commode", @intFromPtr(&shim_p_commode) },
        .{ "__p__fmode", @intFromPtr(&shim_p_fmode) },
        .{ "_set_fmode", @intFromPtr(&shim_set_fmode) },
        .{ "_set_app_type", @intFromPtr(&shim_set_app_type) },
        .{ "_configure_narrow_argv", @intFromPtr(&shim_configure_narrow_argv) },
        .{ "_initialize_narrow_environment", @intFromPtr(&shim_initialize_narrow_environment) },
        .{ "IsProcessorFeaturePresent", @intFromPtr(&shim_IsProcessorFeaturePresent) },
        .{ "GetModuleHandleW", @intFromPtr(&shim_GetModuleHandleW) },
        .{ "VirtualProtect", @intFromPtr(&shim_VirtualProtect) },
        .{ "AppPolicyGetProcessTerminationMethod", @intFromPtr(&shim_AppPolicyGetProcessTerminationMethod) },
        .{ "GetModuleHandleA", @intFromPtr(&shim_GetModuleHandleA) },
        .{ "GetProcAddress", @intFromPtr(&shim_GetProcAddress) },
        .{ "RegisterClassExA", @intFromPtr(&shim_RegisterClassExA) },
        .{ "CreateWindowExA", @intFromPtr(&shim_CreateWindowExA) },
        .{ "ShowWindow", @intFromPtr(&shim_ShowWindow) },
        .{ "DefWindowProcA", @intFromPtr(&shim_DefWindowProcA) },
        .{ "PeekMessageA", @intFromPtr(&shim_PeekMessageA) },
        .{ "DispatchMessageA", @intFromPtr(&shim_DispatchMessageA) },
        .{ "TranslateMessage", @intFromPtr(&shim_TranslateMessage) },
        .{ "SystemFunction036", @intFromPtr(&shim_SystemFunction036) },
        .{ "RtlGenRandom", @intFromPtr(&shim_SystemFunction036) },
        .{ "RegOpenKeyW", @intFromPtr(&shim_RegOpenKeyW) },
        .{ "RegOpenKeyExW", @intFromPtr(&shim_RegOpenKeyExW) },
        .{ "RegQueryValueExW", @intFromPtr(&shim_RegQueryValueExW) },
        .{ "RegCloseKey", @intFromPtr(&shim_RegCloseKey) },
        .{ "QueryPerformanceCounter", @intFromPtr(&shim_QueryPerformanceCounter) },
        .{ "QueryPerformanceFrequency", @intFromPtr(&shim_QueryPerformanceFrequency) },
        .{ "GetSystemTimeAsFileTime", @intFromPtr(&shim_GetSystemTimeAsFileTime) },
        // Same semantics; the precise variant writes the same FILETIME.
        .{ "GetSystemTimePreciseAsFileTime", @intFromPtr(&shim_GetSystemTimeAsFileTime) },
        .{ "GetCurrentThreadId", @intFromPtr(&shim_GetCurrentThreadId) },
        .{ "GetCurrentThread", @intFromPtr(&shim_GetCurrentThread) },
        .{ "GetCurrentThreadStackLimits", @intFromPtr(&shim_GetCurrentThreadStackLimits) },
        .{ "GetCurrentProcessId", @intFromPtr(&shim_GetCurrentProcessId) },
        .{ "GetProcessId", @intFromPtr(&shim_GetProcessId) },
        .{ "GetACP", @intFromPtr(&shim_GetACP) },
        .{ "GetOEMCP", @intFromPtr(&shim_GetOEMCP) },
        .{ "malloc", @intFromPtr(&shim_malloc) },
        .{ "calloc", @intFromPtr(&shim_calloc) },
        .{ "realloc", @intFromPtr(&shim_realloc) },
        .{ "free", @intFromPtr(&shim_free) },
        .{ "memcpy", @intFromPtr(&shim_memcpy) },
        .{ "memmove", @intFromPtr(&shim_memmove) },
        .{ "memset", @intFromPtr(&shim_memset) },
        .{ "GetLogicalProcessorInformation", @intFromPtr(&shim_GetLogicalProcessorInformation) },
        .{ "GetLogicalProcessorInformationEx", @intFromPtr(&shim_GetLogicalProcessorInformationEx) },
        .{ "GetSystemInfo", @intFromPtr(&shim_GetSystemInfo) },
        .{ "GetNativeSystemInfo", @intFromPtr(&shim_GetSystemInfo) },
        .{ "GetActiveProcessorCount", @intFromPtr(&shim_GetActiveProcessorCount) },
        .{ "GetCommandLineA", @intFromPtr(&shim_GetCommandLineA) },
        .{ "GetCommandLineW", @intFromPtr(&shim_GetCommandLineW) },
        .{ "tanf", @intFromPtr(&shim_tanf) },
        .{ "sinf", @intFromPtr(&shim_sinf) },
        .{ "cosf", @intFromPtr(&shim_cosf) },
        .{ "sqrtf", @intFromPtr(&shim_sqrtf) },
        .{ "atan2f", @intFromPtr(&shim_atan2f) },
        .{ "strlen", @intFromPtr(&shim_strlen) },
        .{ "strcmp", @intFromPtr(&shim_strcmp) },
        .{ "_strnicmp", @intFromPtr(&shim_strnicmp) },
        .{ "GetTickCount64", @intFromPtr(&shim_GetTickCount64) },
        .{ "_time64", @intFromPtr(&shim_time64) },
        .{ "exp2f", @intFromPtr(&shim_exp2f) },
        .{ "log10f", @intFromPtr(&shim_log10f) },
        .{ "powf", @intFromPtr(&shim_powf) },
        .{ "GetStartupInfoW", @intFromPtr(&shim_GetStartupInfoW) },
        .{ "_get_narrow_winmain_command_line", @intFromPtr(&shim_get_narrow_winmain_command_line) },
        .{ "_register_thread_local_exe_atexit_callback", @intFromPtr(&shim_register_thread_local_exe_atexit_callback) },
        .{ "GetModuleFileNameW", @intFromPtr(&shim_GetModuleFileNameW) },
        .{ "LoadLibraryExW", @intFromPtr(&shim_LoadLibraryExW) },
        .{ "InitializeApiImpl", @intFromPtr(&shim_InitializeApiImpl) },
        .{ "InitializeApiImplEx", @intFromPtr(&shim_InitializeApiImplEx) },
        .{ "InitializeApiImplEx2", @intFromPtr(&shim_InitializeApiImplEx2) },
        .{ "UninitializeApiImpl", @intFromPtr(&shim_UninitializeApiImpl) },
        .{ "XErrorReport", @intFromPtr(&shim_XErrorReport) },
        .{ "QueryApiImpl", @intFromPtr(&shim_QueryApiImpl) },
        .{ "AcpHalCreate", @intFromPtr(&audio_min.acpHalCreate) },
        .{ "AcpHalAllocateShapeContexts", @intFromPtr(&audio_min.acpHalAllocateShapeContexts) },
        .{ "AcpHalReleaseShapeContexts", @intFromPtr(&audio_min.acpHalReleaseShapeContexts) },
        .{ "ApuCreateHeap", @intFromPtr(&audio_min.apuCreateHeap) },
        .{ "ApuAlloc", @intFromPtr(&audio_min.apuAlloc) },
        .{ "ApuFree", @intFromPtr(&audio_min.apuFree) },
        .{ "ApuMapApuAddress", @intFromPtr(&audio_min.apuMapApuAddress) },
        .{ "ApuMapVirtualAddress", @intFromPtr(&audio_min.apuMapVirtualAddress) },
        .{ "ApuIsVirtualAddressValid", @intFromPtr(&audio_min.apuValid) },
        .{ "__p___argc", @intFromPtr(&shim_p_argc) },
        .{ "__p___argv", @intFromPtr(&shim_p_argv) },
        .{ "CreateThread", @intFromPtr(&shim_CreateThread) },
        .{ "Sleep", @intFromPtr(&shim_Sleep) },
        .{ "LoadLibraryW", @intFromPtr(&shim_LoadLibraryW) },
        .{ "LoadLibraryA", @intFromPtr(&shim_LoadLibraryA) },
        .{ "wcslen", @intFromPtr(&shim_wcslen) },
        .{ "wcscat_s", @intFromPtr(&shim_wcscat_s) },
        .{ "UuidCreate", @intFromPtr(&shim_UuidCreate) },
        .{ "GetCurrentProcess", @intFromPtr(&shim_GetCurrentProcess) },
        .{ "srand", @intFromPtr(&shim_srand) },
        .{ "abort", @intFromPtr(&shim_abort) },
        .{ "terminate", @intFromPtr(&shim_terminate) },
        .{ "__std_terminate", @intFromPtr(&shim_terminate) },
        .{ "rand", @intFromPtr(&shim_rand) },
        .{ "strchr", @intFromPtr(&shim_strchr) },
        .{ "strrchr", @intFromPtr(&shim_strrchr) },
        .{ "strncmp", @intFromPtr(&shim_strncmp) },
        .{ "_wfopen", @intFromPtr(&shim_wfopen) },
        .{ "SetThreadPriority", @intFromPtr(&shim_SetThreadPriority) },
        .{ "ResumeThread", @intFromPtr(&shim_ResumeThread) },
        .{ "SuspendThread", @intFromPtr(&shim_SuspendThread) },
        .{ "GetThreadGroupAffinity", @intFromPtr(&shim_GetThreadGroupAffinity) },
        .{ "SetThreadGroupAffinity", @intFromPtr(&shim_SetThreadGroupAffinity) },
        .{ "GetLocalTime", @intFromPtr(&shim_GetLocalTime) },
        .{ "_purecall", @intFromPtr(&shim_purecall) },
        .{ "InitializeSListHead", @intFromPtr(&shim_InitializeSListHead) },
        .{ "TlsAlloc", @intFromPtr(&shim_TlsAlloc) },
        .{ "TlsFree", @intFromPtr(&shim_TlsFree) },
        .{ "TlsGetValue", @intFromPtr(&shim_TlsGetValue) },
        .{ "TlsSetValue", @intFromPtr(&shim_TlsSetValue) },
        .{ "GetEnvironmentStringsW", @intFromPtr(&shim_GetEnvironmentStringsW) },
        .{ "GetEnvironmentStringsA", @intFromPtr(&shim_GetEnvironmentStringsA) },
        .{ "GetEnvironmentStrings", @intFromPtr(&shim_GetEnvironmentStringsA) },
        .{ "FreeEnvironmentStringsW", @intFromPtr(&shim_FreeEnvironmentStringsW) },
        .{ "FreeEnvironmentStringsA", @intFromPtr(&shim_FreeEnvironmentStringsA) },
        .{ "GetCurrentDirectoryW", @intFromPtr(&shim_GetCurrentDirectoryW) },
        .{ "GetCurrentDirectoryA", @intFromPtr(&shim_GetCurrentDirectoryA) },
        .{ "GetProcessHeap", @intFromPtr(&shim_GetProcessHeap) },
        .{ "HeapAlloc", @intFromPtr(&shim_HeapAlloc) },
        .{ "HeapFree", @intFromPtr(&shim_HeapFree) },
        .{ "HeapReAlloc", @intFromPtr(&shim_HeapReAlloc) },
        .{ "HeapSize", @intFromPtr(&shim_HeapSize) },
        .{ "LoadLibraryExA", @intFromPtr(&shim_LoadLibraryExA) },
        .{ "FreeLibrary", @intFromPtr(&shim_FreeLibrary) },
        .{ "GetModuleFileNameA", @intFromPtr(&shim_GetModuleFileNameA) },
    };

    inline for (map) |entry| {
        if (std.mem.eql(u8, entry.@"0", sym_name)) {
            return entry.@"1";
        }
    }
    return null;
}
