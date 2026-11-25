const std = @import("std");
const builtin = @import("builtin");
const teb = @import("../teb.zig");
const sync = @import("../sync.zig");
const mod = @import("../module.zig");

const c_mmap = struct {
    extern "c" fn mmap(addr: ?*anyopaque, len: usize, prot: i32, flags: i32, fd: i32, offset: i64) ?*anyopaque;
    extern "c" fn munmap(addr: ?*anyopaque, len: usize) c_int;
};

const WinFn = *const fn () callconv(.{ .x86_64_win = .{} }) void;
const WinInitFn = *const fn () callconv(.{ .x86_64_win = .{} }) c_int;

var g_commode: c_int = 0;
var g_thread_count = std.atomic.Value(u32).init(0);
var g_thread_logs = std.atomic.Value(u32).init(0);
var g_thread_failures = std.atomic.Value(u32).init(0);

fn noteThreadFailure() void {
    const n = g_thread_failures.fetchAdd(1, .monotonic) + 1;
    if (n >= 32) {
        std.log.err("[THREAD] aborting after {d} consecutive thread-creation failures", .{n});
        std.process.exit(71);
    }
}
var g_fmode: c_int = 0;
var g_app_type: c_int = 2; // _crt_gui_app
var next_handle: usize = 0x10000;

fn allocDummyHandle() usize {
    const h = next_handle;
    next_handle += 8;
    return h;
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
        "kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll",
        "bcrypt.dll", "ws2_32.dll", "winhttp.dll", "mfplat.dll",
        "mfreadwrite.dll", "gameinput.dll", "xmem.dll", "chad.dll",
        "d3d12_xs.dll", "xg_xs.dll", "xapu.dll", "acphal.dll", "xcrdapi.dll",
        "bink2scarlett.dll", "libhttpclient.gdk.dll", "xgameruntime.dll",
    };
    for (exact) |e| {
        if (std.ascii.eqlIgnoreCase(name, e)) return true;
    }
    return std.ascii.startsWithIgnoreCase(name, "api-ms-win-") or
        std.ascii.startsWithIgnoreCase(name, "ext-ms-win-");
}

const PSEUDO_SYSTEM_BASE: usize = 0x7FFE_0000;

fn shim_GetModuleHandleW(module_name: ?[*:0]const u16) callconv(.{ .x86_64_win = .{} }) usize {
    if (module_name) |name| {
        if (teb.findModuleByNameW(name)) |entry| return entry.DllBase;
        var utf8: [256]u8 = undefined;
        const n = std.unicode.utf16LeToUtf8(&utf8, std.mem.span(name)) catch 0;
        if (isSystemDllName(utf8[0..n])) return PSEUDO_SYSTEM_BASE;
        logWideStr("[CRT] GetModuleHandleW (not loaded)", name);
        return 0;
    }
    return if (teb.process()) |p| p.peb_ptr.ImageBaseAddress else 0;
}

fn shim_GetModuleHandleA(module_name: ?[*:0]const u8) callconv(.{ .x86_64_win = .{} }) usize {
    if (module_name) |aptr| {
        const name = std.mem.span(aptr);
        if (teb.findModuleByName(name)) |entry| return entry.DllBase;
        if (isSystemDllName(name)) return PSEUDO_SYSTEM_BASE;
        std.log.warn("[CRT] GetModuleHandleA(\"{s}\") -> not loaded", .{name});
        return 0;
    }
    return if (teb.process()) |p| p.peb_ptr.ImageBaseAddress else 0;
}

fn shim_GetProcAddress(hmodule: usize, proc_name: ?[*:0]const u8) callconv(.{ .x86_64_win = .{} }) usize {
    const name_ptr = proc_name orelse return 0;
    const addr_val = @intFromPtr(name_ptr);
    const base = if (hmodule != 0)
        hmodule
    else if (teb.process()) |p| p.peb_ptr.ImageBaseAddress else 0;

    if (addr_val <= 0xFFFF) {
        const ordinal: u16 = @intCast(addr_val);
        return mod.getProcAddress(base, null, ordinal, 0) orelse 0;
    }

    const name = std.mem.span(name_ptr);
    if (mod.getProcAddress(base, name, null, 0)) |fn_ptr| return fn_ptr;
    if (mod.resolve_shim_fn) |f| {
        if (f(name)) |fn_ptr| return fn_ptr;
    }
    if (resolve(name)) |fn_ptr| return fn_ptr;
    std.log.warn("[CRT] GetProcAddress(\"{s}\") -> unresolved", .{name});
    return 0;
}

fn shim_RegOpenKeyW(hKey: usize, lpSubKey: ?[*:0]const u16, phkResult: ?*usize) callconv(.{ .x86_64_win = .{} }) i32 {
    _ = hKey;
    _ = phkResult;
    logWideStr("[REG] RegOpenKeyW", lpSubKey);
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

fn shim_CreateSemaphoreW(
    security_attrs: ?*anyopaque,
    initial_count: i32,
    maximum_count: i32,
    name: ?[*:0]const u16,
) callconv(.{ .x86_64_win = .{} }) usize {
    _ = security_attrs;
    _ = initial_count;
    _ = maximum_count;
    _ = name;
    return allocDummyHandle();
}

fn shim_CreateSemaphoreExW(
    security_attrs: ?*anyopaque,
    initial_count: i32,
    maximum_count: i32,
    name: ?[*:0]const u16,
    flags: u32,
    desired_access: u32,
) callconv(.{ .x86_64_win = .{} }) usize {
    _ = security_attrs;
    _ = initial_count;
    _ = maximum_count;
    _ = name;
    _ = flags;
    _ = desired_access;
    return allocDummyHandle();
}

fn shim_ReleaseSemaphore(handle: usize, release_count: i32, previous_count: ?*i32) callconv(.{ .x86_64_win = .{} }) i32 {
    _ = handle;
    _ = release_count;
    if (previous_count) |prev| prev.* = 0;
    return 1;
}

fn shim_CreateMutexW(
    security_attrs: ?*anyopaque,
    initial_owner: i32,
    name: ?[*:0]const u16,
) callconv(.{ .x86_64_win = .{} }) usize {
    _ = security_attrs;
    _ = initial_owner;
    _ = name;
    return allocDummyHandle();
}

fn shim_CreateMutexExW(
    security_attrs: ?*anyopaque,
    name: ?[*:0]const u16,
    flags: u32,
    desired_access: u32,
) callconv(.{ .x86_64_win = .{} }) usize {
    _ = security_attrs;
    _ = name;
    _ = flags;
    _ = desired_access;
    return allocDummyHandle();
}

fn shim_ReleaseMutex(handle: usize) callconv(.{ .x86_64_win = .{} }) i32 {
    _ = handle;
    return 1;
}

fn shim_InitializeConditionVariable(cv: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) void {
    _ = cv;
}

fn shim_SleepConditionVariableCS(cv: ?*anyopaque, cs: ?*anyopaque, ms: u32) callconv(.{ .x86_64_win = .{} }) i32 {
    _ = cv;
    _ = cs;
    _ = ms;
    return 1;
}

fn shim_SleepConditionVariableSRW(cv: ?*anyopaque, srw: ?*anyopaque, ms: u32, flags: u32) callconv(.{ .x86_64_win = .{} }) i32 {
    _ = cv;
    _ = srw;
    _ = ms;
    _ = flags;
    return 1;
}

fn shim_WakeConditionVariable(cv: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) void {
    _ = cv;
}

fn shim_WakeAllConditionVariable(cv: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) void {
    _ = cv;
}

fn shim_InitializeSRWLock(srw: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) void {
    _ = srw;
}

fn shim_AcquireSRWLockExclusive(srw: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) void {
    _ = srw;
}

fn shim_ReleaseSRWLockExclusive(srw: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) void {
    _ = srw;
}

fn shim_AcquireSRWLockShared(srw: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) void {
    _ = srw;
}

fn shim_ReleaseSRWLockShared(srw: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) void {
    _ = srw;
}

fn shim_InitializeCriticalSectionAndSpinCount(cs: ?*anyopaque, spin_count: u32) callconv(.{ .x86_64_win = .{} }) i32 {
    _ = cs;
    _ = spin_count;
    return 1;
}

fn shim_InitializeCriticalSectionEx(cs: ?*anyopaque, spin_count: u32, flags: u32) callconv(.{ .x86_64_win = .{} }) i32 {
    _ = cs;
    _ = spin_count;
    _ = flags;
    return 1;
}

fn shim_CreateEventW(
    security_attrs: ?*anyopaque,
    manual_reset: i32,
    initial_state: i32,
    name: ?[*:0]const u16,
) callconv(.{ .x86_64_win = .{} }) usize {
    _ = security_attrs;
    _ = manual_reset;
    _ = initial_state;
    _ = name;
    return allocDummyHandle();
}

fn shim_CreateEventA(
    security_attrs: ?*anyopaque,
    manual_reset: i32,
    initial_state: i32,
    name: ?[*:0]const u8,
) callconv(.{ .x86_64_win = .{} }) usize {
    _ = security_attrs;
    _ = manual_reset;
    _ = initial_state;
    _ = name;
    return allocDummyHandle();
}

fn shim_SetEvent(handle: usize) callconv(.{ .x86_64_win = .{} }) i32 {
    _ = handle;
    return 1;
}

fn shim_ResetEvent(handle: usize) callconv(.{ .x86_64_win = .{} }) i32 {
    _ = handle;
    return 1;
}

fn shim_WaitForSingleObject(handle: usize, milliseconds: u32) callconv(.{ .x86_64_win = .{} }) u32 {
    _ = handle;
    _ = milliseconds;
    return 0;
}

fn shim_WaitForSingleObjectEx(handle: usize, milliseconds: u32, alertable: i32) callconv(.{ .x86_64_win = .{} }) u32 {
    _ = handle;
    _ = milliseconds;
    _ = alertable;
    return 0;
}

fn shim_CloseHandle(handle: usize) callconv(.{ .x86_64_win = .{} }) i32 {
    _ = handle;
    return 1;
}

fn shim_WaitOnAddress(
    address: *const anyopaque,
    compare_address: *const anyopaque,
    address_size: usize,
    milliseconds: u32,
) callconv(.{ .x86_64_win = .{} }) i32 {
    _ = address;
    _ = compare_address;
    _ = address_size;
    _ = milliseconds;
    return 1;
}

fn shim_WakeByAddressSingle(address: *const anyopaque) callconv(.{ .x86_64_win = .{} }) void {
    _ = address;
}

fn shim_WakeByAddressAll(address: *const anyopaque) callconv(.{ .x86_64_win = .{} }) void {
    _ = address;
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

fn shim_GetCurrentProcessId() callconv(.{ .x86_64_win = .{} }) u32 {
    if (teb.currentTeb()) |t| return @truncate(t.client_id.unique_process);
    if (builtin.os.tag == .linux) return @bitCast(std.os.linux.getpid());
    return 1000;
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
const cmd_line_w = [_:0]u16{
    'g', 'a', 'm', 'e', '_', 's', 'c', 'a', 'r', 'l', 'e', 't', 't', '_',
    'm', 'a', 's', 't', 'e', 'r', '.', 'e', 'x', 'e',
};

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
    std.log.info("[GDK] InitializeApiImpl() -> S_OK", .{});
    return 0;
}

fn shim_InitializeApiImplEx(options: ?*const anyopaque, reserved: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32 {
    _ = options;
    _ = reserved;
    std.log.info("[GDK] InitializeApiImplEx() -> S_OK", .{});
    return 0;
}

fn shim_InitializeApiImplEx2(
    options: ?*const anyopaque,
    version: u64,
    reserved: ?*anyopaque,
) callconv(.{ .x86_64_win = .{} }) i32 {
    _ = options;
    _ = reserved;
    std.log.info("[GDK] InitializeApiImplEx2(version=0x{x}) -> S_OK", .{version});
    return 0;
}

fn shim_UninitializeApiImpl() callconv(.{ .x86_64_win = .{} }) void {
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
    _ = riid;
    if (rclsid) |g| {
        const d1 = std.mem.readInt(u32, g[0..4], .little);
        const d2 = std.mem.readInt(u16, g[4..6], .little);
        const d3 = std.mem.readInt(u16, g[6..8], .little);
        std.log.warn("[GDK] QueryApiImpl({{{x:0>8}-{x:0>4}-{x:0>4}-...}}) -> E_NOINTERFACE", .{ d1, d2, d3 });
    }
    if (ppv) |out| {
        out.* = null;
    }
    return -2147467262; // E_NOINTERFACE (0x80004002 -> `test eax, eax; js` skips dereference!)
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

pub var g_tls_block_addr: usize = 0;
pub var g_main_tls_addr: usize = 0;

const WinThreadProc = *const fn (?*anyopaque) callconv(.{ .x86_64_win = .{} }) u32;

const ThreadSpawnCtx = struct {
    start_fn: WinThreadProc,
    param: ?*anyopaque,
    tid: u32,
    stack_size: usize,
    handle: usize,
};

const LinuxThreadCtx = struct {
    spawn: ThreadSpawnCtx,
    ptid: i32 = 0,
    ctid: i32 = 0,
};

fn linuxCloneEntry(arg: usize) callconv(.c) u8 {
    const c: *LinuxThreadCtx = @ptrFromInt(arg);
    threadBootstrap(c.spawn);
    return 0;
}

/// pthread_create's stack handling either commits memory (ENOMEM on an
/// over-committed host) or rejects a supplied stack (EINVAL).  Raw clone with
/// a MAP_NORESERVE stack avoids both.  FS/TLS is inherited from the caller.
fn spawnLinuxThread(stack_size: usize, spawn_ctx: ThreadSpawnCtx) !void {
    const page: usize = 4096;
    const total = std.mem.alignForward(usize, @max(stack_size, 256 * 1024) + page, page);
    const PROT_READ: i32 = 1;
    const PROT_WRITE: i32 = 2;
    const MAP_PRIVATE: i32 = 2;
    const MAP_ANONYMOUS: i32 = 0x20;
    const MAP_NORESERVE: i32 = 0x4000;
    const MAP_FAILED: usize = @bitCast(@as(isize, -1));

    const mem = c_mmap.mmap(null, total, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0) orelse return error.SystemResources;
    if (@intFromPtr(mem) == MAP_FAILED) return error.SystemResources;

    const ctx = std.heap.c_allocator.create(LinuxThreadCtx) catch {
        _ = c_mmap.munmap(mem, total);
        return error.OutOfMemory;
    };
    ctx.* = .{ .spawn = spawn_ctx };

    const flags: u32 = std.os.linux.CLONE.VM |
        std.os.linux.CLONE.FS |
        std.os.linux.CLONE.FILES |
        std.os.linux.CLONE.SIGHAND |
        std.os.linux.CLONE.THREAD |
        std.os.linux.CLONE.SYSVSEM |
        std.os.linux.CLONE.PARENT_SETTID |
        std.os.linux.CLONE.CHILD_CLEARTID;

    const stack_top = @intFromPtr(mem) + total;
    const rc = std.os.linux.clone(
        &linuxCloneEntry,
        stack_top,
        flags,
        @intFromPtr(ctx),
        &ctx.ptid,
        0,
        &ctx.ctid,
    );
    const signed: isize = @bitCast(rc);
    if (signed < 0) {
        std.log.err("[THREAD] clone failed: errno={d} stack=0x{x} size=0x{x}", .{ -signed, @intFromPtr(mem), total });
        std.heap.c_allocator.destroy(ctx);
        _ = c_mmap.munmap(mem, total);
        return switch (-signed) {
            11 => error.SystemResources, // EAGAIN
            12 => error.OutOfMemory, // ENOMEM
            else => error.Unexpected,
        };
    }
    // The stack and ctx belong to the child now; they are intentionally leaked
    // because a detached thread cannot unmap the stack it is running on.
}

fn threadBootstrap(ctx: ThreadSpawnCtx) void {
    defer _ = g_thread_count.fetchSub(1, .monotonic);
    defer sync.markThreadExited(ctx.handle);
    if (mod.thread_attach_fn) |f| f();
    defer {
        if (mod.thread_detach_fn) |f| f();
    }
    if (builtin.os.tag == .linux) {
        var rsp: usize = undefined;
        asm volatile ("movq %%rsp, %[out]" : [out] "=r" (rsp));
        const stack_base = rsp & ~@as(usize, 0xF);
        const stack_size = if (ctx.stack_size != 0) ctx.stack_size else 1024 * 1024;
        _ = teb.initThread(stack_base, stack_base - stack_size, ctx.tid) catch {};
    }
    _ = ctx.start_fn(ctx.param);
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
    _ = creation_flags;
    const func = start_address orelse return 0;
    const serial = allocDummyHandle();
    const tid: u32 = @truncate(serial);
    if (thread_id) |tid_out| tid_out.* = tid;

    const live = g_thread_count.fetchAdd(1, .monotonic);
    if (live >= 128) {
        _ = g_thread_count.fetchSub(1, .monotonic);
        std.log.err("[THREAD] refusing thread {d}: live limit reached", .{tid});
        noteThreadFailure();
        return 0;
    }

    const handle = sync.createThreadHandle(tid);
    if (handle == 0) {
        _ = g_thread_count.fetchSub(1, .monotonic);
        return 0;
    }

    const requested_stack: usize = if (stack_size_arg != 0) stack_size_arg else 1024 * 1024;
    const stack_size: usize = @min(requested_stack, 8 * 1024 * 1024);

    const log_index = g_thread_logs.fetchAdd(1, .monotonic);
    if (log_index < 24 or log_index % 64 == 0) {
        std.log.info("[THREAD] CreateThread(entry=0x{x}, tid={d}, handle=0x{x}, live={d}, stack=0x{x})", .{
            @intFromPtr(func), tid, handle, live, requested_stack,
        });
    }
    const spawn_ctx = ThreadSpawnCtx{
        .start_fn = func,
        .param = parameter,
        .tid = tid,
        .stack_size = stack_size,
        .handle = handle,
    };

    if (builtin.os.tag == .linux) {
        spawnLinuxThread(stack_size, spawn_ctx) catch |err| {
            _ = g_thread_count.fetchSub(1, .monotonic);
            std.log.err("[THREAD] spawn failed for tid={d}: {s}", .{ tid, @errorName(err) });
            noteThreadFailure();
            _ = sync.closeHandle(handle);
            return 0;
        };
        return handle;
    }

    const thread = std.Thread.spawn(.{ .stack_size = stack_size }, threadBootstrap, .{spawn_ctx}) catch |err| {
        _ = g_thread_count.fetchSub(1, .monotonic);
        std.log.err("[THREAD] spawn failed for tid={d}: {s}", .{ tid, @errorName(err) });
        noteThreadFailure();
        _ = sync.closeHandle(handle);
        return 0;
    };
    thread.detach();
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

fn shim_EnterCriticalSection(_: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) void {}
fn shim_LeaveCriticalSection(_: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) void {}
fn shim_InitializeCriticalSection(_: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) void {}
fn shim_DeleteCriticalSection(_: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) void {}
fn shim_SetThreadPriority(_: usize, _: c_int) callconv(.{ .x86_64_win = .{} }) i32 {
    return 1;
}
fn shim_ResumeThread(_: usize) callconv(.{ .x86_64_win = .{} }) u32 {
    return 0;
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

fn shim_CreateMutexA(
    security_attrs: ?*anyopaque,
    initial_owner: i32,
    name: ?[*:0]const u8,
) callconv(.{ .x86_64_win = .{} }) usize {
    _ = security_attrs;
    _ = initial_owner;
    _ = name;
    return allocDummyHandle();
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
        .{ "GetModuleHandleA", @intFromPtr(&shim_GetModuleHandleA) },
        .{ "GetProcAddress", @intFromPtr(&shim_GetProcAddress) },
        .{ "RegOpenKeyW", @intFromPtr(&shim_RegOpenKeyW) },
        .{ "RegOpenKeyExW", @intFromPtr(&shim_RegOpenKeyExW) },
        .{ "RegQueryValueExW", @intFromPtr(&shim_RegQueryValueExW) },
        .{ "RegCloseKey", @intFromPtr(&shim_RegCloseKey) },
        .{ "CreateSemaphoreW", @intFromPtr(&shim_CreateSemaphoreW) },
        .{ "CreateSemaphoreExW", @intFromPtr(&shim_CreateSemaphoreExW) },
        .{ "ReleaseSemaphore", @intFromPtr(&shim_ReleaseSemaphore) },
        .{ "CreateMutexW", @intFromPtr(&shim_CreateMutexW) },
        .{ "CreateMutexExW", @intFromPtr(&shim_CreateMutexExW) },
        .{ "ReleaseMutex", @intFromPtr(&shim_ReleaseMutex) },
        .{ "InitializeConditionVariable", @intFromPtr(&shim_InitializeConditionVariable) },
        .{ "SleepConditionVariableCS", @intFromPtr(&shim_SleepConditionVariableCS) },
        .{ "SleepConditionVariableSRW", @intFromPtr(&shim_SleepConditionVariableSRW) },
        .{ "WakeConditionVariable", @intFromPtr(&shim_WakeConditionVariable) },
        .{ "WakeAllConditionVariable", @intFromPtr(&shim_WakeAllConditionVariable) },
        .{ "InitializeSRWLock", @intFromPtr(&shim_InitializeSRWLock) },
        .{ "AcquireSRWLockExclusive", @intFromPtr(&shim_AcquireSRWLockExclusive) },
        .{ "ReleaseSRWLockExclusive", @intFromPtr(&shim_ReleaseSRWLockExclusive) },
        .{ "AcquireSRWLockShared", @intFromPtr(&shim_AcquireSRWLockShared) },
        .{ "ReleaseSRWLockShared", @intFromPtr(&shim_ReleaseSRWLockShared) },
        .{ "InitializeCriticalSectionAndSpinCount", @intFromPtr(&shim_InitializeCriticalSectionAndSpinCount) },
        .{ "InitializeCriticalSectionEx", @intFromPtr(&shim_InitializeCriticalSectionEx) },
        .{ "CreateEventW", @intFromPtr(&shim_CreateEventW) },
        .{ "CreateEventA", @intFromPtr(&shim_CreateEventA) },
        .{ "SetEvent", @intFromPtr(&shim_SetEvent) },
        .{ "ResetEvent", @intFromPtr(&shim_ResetEvent) },
        .{ "WaitForSingleObject", @intFromPtr(&shim_WaitForSingleObject) },
        .{ "WaitForSingleObjectEx", @intFromPtr(&shim_WaitForSingleObjectEx) },
        .{ "CloseHandle", @intFromPtr(&shim_CloseHandle) },
        .{ "WaitOnAddress", @intFromPtr(&shim_WaitOnAddress) },
        .{ "WakeByAddressSingle", @intFromPtr(&shim_WakeByAddressSingle) },
        .{ "WakeByAddressAll", @intFromPtr(&shim_WakeByAddressAll) },
        .{ "QueryPerformanceCounter", @intFromPtr(&shim_QueryPerformanceCounter) },
        .{ "QueryPerformanceFrequency", @intFromPtr(&shim_QueryPerformanceFrequency) },
        .{ "GetSystemTimeAsFileTime", @intFromPtr(&shim_GetSystemTimeAsFileTime) },
        .{ "GetCurrentThreadId", @intFromPtr(&shim_GetCurrentThreadId) },
        .{ "GetCurrentProcessId", @intFromPtr(&shim_GetCurrentProcessId) },
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
        .{ "__p___argc", @intFromPtr(&shim_p_argc) },
        .{ "__p___argv", @intFromPtr(&shim_p_argv) },
        .{ "CreateThread", @intFromPtr(&shim_CreateThread) },
        .{ "Sleep", @intFromPtr(&shim_Sleep) },
        .{ "LoadLibraryW", @intFromPtr(&shim_LoadLibraryW) },
        .{ "LoadLibraryA", @intFromPtr(&shim_LoadLibraryA) },
        .{ "wcslen", @intFromPtr(&shim_wcslen) },
        .{ "UuidCreate", @intFromPtr(&shim_UuidCreate) },
        .{ "GetCurrentProcess", @intFromPtr(&shim_GetCurrentProcess) },
        .{ "strchr", @intFromPtr(&shim_strchr) },
        .{ "strrchr", @intFromPtr(&shim_strrchr) },
        .{ "strncmp", @intFromPtr(&shim_strncmp) },
        .{ "_wfopen", @intFromPtr(&shim_wfopen) },
        .{ "EnterCriticalSection", @intFromPtr(&shim_EnterCriticalSection) },
        .{ "LeaveCriticalSection", @intFromPtr(&shim_LeaveCriticalSection) },
        .{ "InitializeCriticalSection", @intFromPtr(&shim_InitializeCriticalSection) },
        .{ "DeleteCriticalSection", @intFromPtr(&shim_DeleteCriticalSection) },
        .{ "SetThreadPriority", @intFromPtr(&shim_SetThreadPriority) },
        .{ "ResumeThread", @intFromPtr(&shim_ResumeThread) },
        .{ "GetThreadGroupAffinity", @intFromPtr(&shim_GetThreadGroupAffinity) },
        .{ "SetThreadGroupAffinity", @intFromPtr(&shim_SetThreadGroupAffinity) },
        .{ "GetLocalTime", @intFromPtr(&shim_GetLocalTime) },
        .{ "_purecall", @intFromPtr(&shim_purecall) },
        .{ "InitializeSListHead", @intFromPtr(&shim_InitializeSListHead) },
        .{ "CreateMutexA", @intFromPtr(&shim_CreateMutexA) },
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
