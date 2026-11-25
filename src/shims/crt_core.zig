const std = @import("std");
const builtin = @import("builtin");

const WinFn = *const fn () callconv(.{ .x86_64_win = .{} }) void;
const WinInitFn = *const fn () callconv(.{ .x86_64_win = .{} }) c_int;

var g_commode: c_int = 0;
var g_fmode: c_int = 0;
var g_app_type: c_int = 2; // _crt_gui_app
var g_last_error: u32 = 0;
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
    return g_last_error;
}

fn shim_SetLastError(err: u32) callconv(.{ .x86_64_win = .{} }) void {
    g_last_error = err;
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

fn shim_GetModuleHandleW(module_name: ?[*:0]const u16) callconv(.{ .x86_64_win = .{} }) usize {
    if (module_name != null) {
        logWideStr("[CRT] GetModuleHandleW", module_name);
    }
    return 0x140000000;
}

fn shim_GetModuleHandleA(module_name: ?[*:0]const u8) callconv(.{ .x86_64_win = .{} }) usize {
    if (module_name) |aptr| {
        std.log.warn("[CRT] GetModuleHandleA(\"{s}\")", .{std.mem.span(aptr)});
    }
    return 0x140000000;
}

fn shim_GetProcAddress(module: usize, proc_name: ?[*:0]const u8) callconv(.{ .x86_64_win = .{} }) usize {
    _ = module;
    const name_ptr = proc_name orelse return 0;
    const addr_val = @intFromPtr(name_ptr);
    if (addr_val < 0x10000) return 0;

    const name = std.mem.span(name_ptr);
    if (resolve(name)) |fn_ptr| {
        return fn_ptr;
    }
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
    if (builtin.os.tag == .linux) {
        return @bitCast(@as(i32, @truncate(std.os.linux.gettid())));
    }
    return 1001;
}

fn shim_GetCurrentProcessId() callconv(.{ .x86_64_win = .{} }) u32 {
    if (builtin.os.tag == .linux) {
        return @bitCast(std.os.linux.getpid());
    }
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
        g_last_error = 122; // ERROR_INSUFFICIENT_BUFFER
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
    g_last_error = 120; // ERROR_CALL_NOT_IMPLEMENTED
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
    return cmd_line_a;
}

fn shim_GetCommandLineW() callconv(.{ .x86_64_win = .{} }) [*:0]const u16 {
    return &cmd_line_w;
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
}

fn shim_get_narrow_winmain_command_line() callconv(.{ .x86_64_win = .{} }) [*:0]const u8 {
    return "";
}

fn shim_register_thread_local_exe_atexit_callback(cb: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) void {
    _ = cb;
}

fn shim_GetModuleFileNameW(hModule: usize, lpFilename: [*]u16, nSize: u32) callconv(.{ .x86_64_win = .{} }) u32 {
    _ = hModule;
    if (nSize == 0) return 0;
    const max_copy = @min(@as(usize, nSize - 1), cmd_line_w.len);
    var i: usize = 0;
    while (i < max_copy) : (i += 1) {
        lpFilename[i] = cmd_line_w[i];
    }
    lpFilename[max_copy] = 0;
    return @intCast(max_copy);
}

fn shim_LoadLibraryExW(lpLibFileName: ?[*:0]const u16, hFile: usize, dwFlags: u32) callconv(.{ .x86_64_win = .{} }) usize {
    _ = hFile;
    _ = dwFlags;
    logWideStr("[LOADER] LoadLibraryExW", lpLibFileName);
    return 0x140000000;
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
};

fn threadBootstrap(ctx: ThreadSpawnCtx) void {
    if (builtin.os.tag == .linux) {
        const page_align = comptime std.mem.Alignment.fromByteUnits(4096);
        const teb = std.heap.page_allocator.alignedAlloc(u8, page_align, 0x1000) catch return;
        @memset(teb, 0);

        const tls_slots = std.heap.page_allocator.alloc(usize, 64) catch return;
        @memset(tls_slots, 0);

        const src_tls = if (g_main_tls_addr != 0) g_main_tls_addr else g_tls_block_addr;
        if (src_tls != 0) {
            const tls_copy = std.heap.page_allocator.alignedAlloc(
                u8,
                comptime std.mem.Alignment.fromByteUnits(64),
                0x4000,
            ) catch return;
            @memset(tls_copy, 0);
            const src_bytes: [*]const u8 = @ptrFromInt(g_tls_block_addr);
            @memcpy(tls_copy[0..0x2000], src_bytes[0..0x2000]);
            std.mem.writeInt(usize, std.mem.sliceAsBytes(tls_slots)[0..8], @intFromPtr(tls_copy.ptr), .little);
        }

        const teb_addr = @intFromPtr(teb.ptr);
        std.mem.writeInt(usize, teb[0x00..][0..8], std.math.maxInt(usize), .little);
        std.mem.writeInt(usize, teb[0x08..][0..8], 0x7FFFFFFFFFFF, .little);
        std.mem.writeInt(usize, teb[0x10..][0..8], 0x10000, .little);
        std.mem.writeInt(usize, teb[0x30..][0..8], teb_addr, .little);
        std.mem.writeInt(u32, teb[0x40..][0..4], 1000, .little);
        std.mem.writeInt(u32, teb[0x48..][0..4], ctx.tid, .little);
        std.mem.writeInt(usize, teb[0x58..][0..8], @intFromPtr(tls_slots.ptr), .little);

        const ARCH_SET_GS: usize = 0x1001;
        _ = std.os.linux.syscall2(.arch_prctl, ARCH_SET_GS, teb_addr);
    }

    _ = ctx.start_fn(ctx.param);
}

fn shim_CreateThread(
    security_attrs: ?*anyopaque,
    stack_size: usize,
    start_address: ?WinThreadProc,
    parameter: ?*anyopaque,
    creation_flags: u32,
    thread_id: ?*u32,
) callconv(.{ .x86_64_win = .{} }) usize {
    _ = security_attrs;
    _ = stack_size;
    _ = creation_flags;
    const func = start_address orelse return 0;
    const handle = allocDummyHandle();
    const tid: u32 = @truncate(handle);
    if (thread_id) |tid_out| tid_out.* = tid;

    std.log.info("[THREAD] CreateThread(entry=0x{x}, tid={d})", .{ @intFromPtr(func), tid });

    const thread = std.Thread.spawn(.{}, threadBootstrap, .{ThreadSpawnCtx{
        .start_fn = func,
        .param = parameter,
        .tid = tid,
    }}) catch return 0;
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
    logWideStr("[LOADER] LoadLibraryW", lpLibFileName);
    return 0x140000000;
}

fn shim_LoadLibraryA(lpLibFileName: ?[*:0]const u8) callconv(.{ .x86_64_win = .{} }) usize {
    if (lpLibFileName) |p| {
        std.log.warn("[LOADER] LoadLibraryA(\"{s}\")", .{std.mem.span(p)});
    }
    return 0x140000000;
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
    };

    inline for (map) |entry| {
        if (std.mem.eql(u8, entry.@"0", sym_name)) {
            return entry.@"1";
        }
    }
    return null;
}
