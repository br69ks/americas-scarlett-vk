//! Process/thread environment for the guest: PEB, RTL_USER_PROCESS_PARAMETERS,
//! TEB, real stack bounds, per-module TLS, and TlsAlloc slots.
//!
//! On Linux the TEB is synthetic and installed with arch_prctl(ARCH_SET_GS).
//! On Windows the host already provides a TEB/PEB; we only fill in the cached
//! process data and leave the host structures alone.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;

pub const MAX_TLS_SLOTS = 64;
pub const TEB_SIZE = 0x1800;

pub const OFF = struct {
    pub const exception_list = 0x00;
    pub const stack_base = 0x08;
    pub const stack_limit = 0x10;
    pub const self_ptr = 0x30;
    pub const client_id_process = 0x40;
    pub const client_id_thread = 0x48;
    pub const tls_pointer = 0x58;
    pub const peb = 0x60;
    pub const last_error = 0x68;
    pub const tls_slots = 0x1480;
};

/// x64 TEB prefix.  The field names follow the Wine/ReactOS layout; offsets
/// that matter are asserted in `checkLayout()`.
pub const TEB = extern struct {
    nt_tib: extern struct {
        exception_list: usize,
        stack_base: usize,
        stack_limit: usize,
        sub_system_tib: usize,
        fiber_data: usize,
        arbitrary_user_pointer: usize,
        self_ptr: usize,
    },
    environment_pointer: usize,
    client_id: extern struct {
        unique_process: usize,
        unique_thread: usize,
    },
    active_rpc_handle: usize,
    thread_local_storage_pointer: usize,
    process_environment_block: usize,
    last_error_value: u32,
    count_of_owned_critical_sections: u32,
    _pad: [0x1480 - 0x70]u8,
    tls_slots: [MAX_TLS_SLOTS]usize,
};

pub const UNICODE_STRING = extern struct {
    Length: u16,
    MaximumLength: u16,
    Buffer: ?[*]u16,

    pub fn fromZ(allocator: Allocator, text: []const u8) !UNICODE_STRING {
        const w = try std.unicode.utf8ToUtf16LeAllocZ(allocator, text);
        return .{
            .Length = @intCast(w.len * 2),
            .MaximumLength = @intCast((w.len + 1) * 2),
            .Buffer = w.ptr,
        };
    }
};

pub const CURDIR = extern struct {
    DosPath: UNICODE_STRING,
    Handle: usize,
};

pub const RTL_USER_PROCESS_PARAMETERS = extern struct {
    MaximumLength: u32,
    Length: u32,
    Flags: u32,
    DebugFlags: u32,
    ConsoleHandle: usize,
    ConsoleFlags: u32,
    _pad0: u32,
    StandardInput: usize,
    StandardOutput: usize,
    StandardError: usize,
    CurrentDirectory: CURDIR,
    DllPath: UNICODE_STRING,
    ImagePathName: UNICODE_STRING,
    CommandLine: UNICODE_STRING,
    Environment: ?[*]u16,
    StartingX: u32,
    StartingY: u32,
    CountX: u32,
    CountY: u32,
    CountCharsX: u32,
    CountCharsY: u32,
    FillAttribute: u32,
    WindowFlags: u32,
    ShowWindowFlags: u32,
    WindowTitle: UNICODE_STRING,
    DesktopInfo: UNICODE_STRING,
    ShellInfo: UNICODE_STRING,
    RuntimeData: UNICODE_STRING,
    CurrentDirectories: [32]CURDIR,
    EnvironmentSize: usize,
    EnvironmentVersion: usize,
    PackageDependencyData: usize,
    ProcessGroupId: u32,
    LoaderThreads: u32,
    _tail: [0x100]u8,
};

pub const LIST_ENTRY = extern struct {
    Flink: *LIST_ENTRY,
    Blink: *LIST_ENTRY,
};

pub const PEB_LDR_DATA = extern struct {
    Length: u32,
    Initialized: u8,
    _pad: [3]u8,
    _pad2: u32,
    SsHandle: usize,
    InLoadOrderModuleList: LIST_ENTRY,
    InMemoryOrderModuleList: LIST_ENTRY,
    InInitializationOrderModuleList: LIST_ENTRY,
};

pub const LDR_DATA_TABLE_ENTRY = extern struct {
    InLoadOrderLinks: LIST_ENTRY,
    InMemoryOrderLinks: LIST_ENTRY,
    InInitializationOrderLinks: LIST_ENTRY,
    DllBase: usize,
    EntryPoint: usize,
    SizeOfImage: usize,
    FullDllName: UNICODE_STRING,
    BaseDllName: UNICODE_STRING,
    Flags: u32,
    ObsoleteLoadCount: u16,
    TlsIndex: u16,
    HashLinks: LIST_ENTRY,
    TimeDateStamp: u32,
    _pad0: u32,
    _tail: [0x60]u8,
};

pub const PEB = extern struct {
    InheritedAddressSpace: u8,
    ReadImageFileExecOptions: u8,
    BeingDebugged: u8,
    BitField: u8,
    _pad0: u32,
    Mutant: usize,
    ImageBaseAddress: usize,
    Ldr: *PEB_LDR_DATA,
    ProcessParameters: *RTL_USER_PROCESS_PARAMETERS,
    SubSystemData: usize,
    ProcessHeap: usize,
    FastPebLock: usize,
    AtlThunkSListPtr: usize,
    IFEOKey: usize,
    CrossProcessFlags: u32,
    _pad1: u32,
    UserSharedInfoPtr: usize,
    SystemAssemblyStorageMap: usize,
    SystemPatchOption: usize,
    _tail: [0x100]u8,
};

comptime {
    std.debug.assert(@offsetOf(TEB, "nt_tib") == 0x00);
    std.debug.assert(@offsetOf(TEB, "client_id") == 0x40);
    std.debug.assert(@offsetOf(TEB, "thread_local_storage_pointer") == 0x58);
    std.debug.assert(@offsetOf(TEB, "process_environment_block") == 0x60);
    std.debug.assert(@offsetOf(TEB, "tls_slots") == 0x1480);
    std.debug.assert(@offsetOf(PEB, "ImageBaseAddress") == 0x10);
    std.debug.assert(@offsetOf(PEB, "Ldr") == 0x18);
    std.debug.assert(@offsetOf(PEB, "ProcessParameters") == 0x20);
    std.debug.assert(@offsetOf(LDR_DATA_TABLE_ENTRY, "DllBase") == 0x30);
    std.debug.assert(@offsetOf(LDR_DATA_TABLE_ENTRY, "FullDllName") == 0x48);
    std.debug.assert(@offsetOf(LDR_DATA_TABLE_ENTRY, "BaseDllName") == 0x58);
}

pub const Process = struct {
    allocator: Allocator,
    teb_ptr: *TEB,
    peb_ptr: *PEB,
    params: *RTL_USER_PROCESS_PARAMETERS,
    ldr: *PEB_LDR_DATA,
    cmdline_w: [:0]u16,
    cmdline_a: [:0]u8,
    image_path_w: [:0]u16,
    image_path_a: [:0]u8,
    cwd_w: [:0]u16,
    cwd_a: [:0]u8,
    env_w: []u16,
    env_a: []u8,
    dll_path_w: [:0]u16,
    game_dir: []const u8,
    pid: u32,
    tid: u32,
    tls_template: [MAX_TLS_SLOTS]usize = @splat(0),
    tls_template_sizes: [MAX_TLS_SLOTS]u32 = @splat(0),
    tls_template_len: usize = 0,
    host_teb: usize = 0,
};

var g_process: ?*Process = null;
var g_fallback_last_error: u32 = 0;
var g_tls_bitmap = std.atomic.Value(u64).init(0);

pub fn process() ?*Process {
    return g_process;
}

fn readHostTeb() usize {
    var p: usize = 0;
    asm volatile ("movq %%gs:0x30, %[out]" : [out] "=r" (p));
    return p;
}

fn setGsBase(base: usize) void {
    asm volatile ("wrgsbase %[base]" :: [base] "r" (base));
}

pub fn currentTeb() ?*TEB {
    if (builtin.os.tag == .windows) {
        var p: usize = 0;
        asm volatile ("movq %%gs:0x30, %[out]" : [out] "=r" (p));
        if (p >= 0x10000) return @ptrFromInt(p);
        if (g_process) |proc| return proc.teb_ptr;
        return null;
    }
    // The loader installs a synthetic GS base only after initProcess(); a plain
    // host test binary has GS = 0, where `%gs:0x30` would fault at address 0x30.
    if (g_process == null) return null;
    var p: usize = undefined;
    asm volatile ("movq %%gs:0x30, %[out]"
        : [out] "=r" (p),
    );
    if (p < 0x10000) return null;
    return @ptrFromInt(p);
}

pub var g_entry_gs: usize = 0;
pub var g_guest_teb: usize = 0;
pub var g_enter_count: usize = 0;
pub var g_leave_count: usize = 0;
pub var g_leave_trace: [8]usize = @splat(0);
pub var g_enter_trace: [8]usize = @splat(0);

pub fn readGsBase() usize {
    var p: usize = 0;
    if (builtin.os.tag == .windows) asm volatile ("rdgsbase %[out]" : [out] "=r" (p));
    return p;
}

pub fn testGsBase(target: usize) usize {
    if (builtin.os.tag != .windows) return 0;
    var orig: usize = 0;
    asm volatile ("rdgsbase %[out]" : [out] "=r" (orig));
    setGsBase(target);
    var got: usize = 0;
    asm volatile ("rdgsbase %[out]" : [out] "=r" (got));
    setGsBase(orig);
    return got;
}

pub fn enterGuest() void {
    if (builtin.os.tag != .windows) return;
    const guest = if (g_process) |p| p.teb_ptr else (currentTeb() orelse return);
    g_guest_teb = @intFromPtr(guest);
    g_enter_count += 1;
    const ra = @returnAddress();
    g_enter_trace[g_enter_count % 8] = ra;
    const cur = readGsBase();
    const guest_addr = @intFromPtr(guest);
    if (cur >= 0x10000 and cur != guest_addr) {
        @as(*usize, @ptrFromInt(guest_addr + 0x1FF8)).* = cur;
    } else if (@as(*const usize, @ptrFromInt(guest_addr + 0x1FF8)).* == 0) {
        return;
    }
    setGsBase(guest_addr);
}

pub fn forceGuest() void {
    if (builtin.os.tag != .windows) return;
    const p = g_process orelse return;
    const guest_addr = @intFromPtr(p.teb_ptr);
    var host: usize = @as(*const usize, @ptrFromInt(guest_addr + 0x1FF8)).*;
    if (host < 0x10000) host = p.host_teb;
    if (host >= 0x10000) {
        @as(*usize, @ptrFromInt(guest_addr + 0x1FF8)).* = host;
        setGsBase(guest_addr);
    }
}

pub fn enterHost() void {
    if (builtin.os.tag != .windows) return;
    if (readGsBase() != g_guest_teb) return;
    if (g_guest_teb == 0) return;
    const guest: *TEB = @ptrFromInt(g_guest_teb);
    const host = @as(*const usize, @ptrFromInt(@intFromPtr(guest) + 0x1FF8)).*;
    if (host >= 0x10000) setGsBase(host);
}

pub fn leaveHost() void {
    if (builtin.os.tag != .windows) return;
    if (g_guest_teb >= 0x10000) setGsBase(g_guest_teb);
}

pub fn restoreGs() callconv(.c) void {
    if (builtin.os.tag != .windows) return;
    if (g_guest_teb >= 0x10000) {
        asm volatile ("wrgsbase %[base]" :: [base] "r" (g_guest_teb));
    }
}

pub fn leaveGuest() void {
    if (builtin.os.tag != .windows) return;
    g_leave_count += 1;
    const ra = @returnAddress();
    g_leave_trace[g_leave_count % 8] = ra;
    var host: usize = 0;
    asm volatile ("movq %%gs:0x1FF8, %[out]" : [out] "=r" (host));
    if (host >= 0x10000) setGsBase(host);
}

/// Guest TEB for this thread even while a host thunk has switched GS.
/// Host thunks maintain host TEB+0x28 = guest TEB and host TEB+0x1FF8 = 0.
fn guestTeb() ?*TEB {
    if (builtin.os.tag != .windows) return currentTeb();
    var p: usize = 0;
    asm volatile ("movq %%gs:0x30, %[out]" : [out] "=r" (p));
    if (p < 0x10000) {
        if (g_process) |proc| return proc.teb_ptr;
        return null;
    }
    const guest = @as(*const usize, @ptrFromInt(p + 0x1FE0)).*;
    if (guest >= 0x10000) {
        const self = @as(*const usize, @ptrFromInt(guest + 0x30)).*;
        if (self == guest) return @ptrFromInt(guest);
    }
    return @ptrFromInt(p);
}

pub fn getLastError() u32 {
    if (guestTeb()) |t| return t.last_error_value;
    return g_fallback_last_error;
}

pub fn setLastError(value: u32) void {
    if (guestTeb()) |t| {
        t.last_error_value = value;
    } else {
        g_fallback_last_error = value;
    }
}

fn makeZ(allocator: Allocator, text: []const u8) ![:0]u8 {
    return allocator.dupeSentinel(u8, text, 0);
}

fn makeWZ(allocator: Allocator, text: []const u8) ![:0]u16 {
    return std.unicode.utf8ToUtf16LeAllocZ(allocator, text);
}

fn unicodeFromW(w: [:0]const u16) UNICODE_STRING {
    return .{
        .Length = @intCast(w.len * 2),
        .MaximumLength = @intCast((w.len + 1) * 2),
        .Buffer = @constCast(w.ptr),
    };
}

/// Quote one argument using the MSVC/CommandLineToArgvW rules.
fn appendQuoted(list: *std.array_list.Managed(u8), arg: []const u8) !void {
    const needs_quotes = std.mem.indexOfAny(u8, arg, " \t\n\x0b\"") != null or arg.len == 0;
    if (!needs_quotes) {
        try list.appendSlice(arg);
        return;
    }
    try list.append('"');
    var backslashes: usize = 0;
    for (arg) |c| {
        switch (c) {
            '\\' => backslashes += 1,
            '"' => {
                try list.appendNTimes('\\', backslashes * 2 + 1);
                try list.append('"');
                backslashes = 0;
            },
            else => {
                try list.appendNTimes('\\', backslashes);
                backslashes = 0;
                try list.append(c);
            },
        }
    }
    try list.appendNTimes('\\', backslashes * 2);
    try list.append('"');
}

fn buildCommandLine(allocator: Allocator, argv: []const []const u8) ![:0]u8 {
    var list = std.array_list.Managed(u8).init(allocator);
    errdefer list.deinit();
    for (argv, 0..) |arg, i| {
        if (i != 0) try list.append(' ');
        try appendQuoted(&list, arg);
    }
    try list.append(0);
    return list.toOwnedSliceSentinel(0);
}

pub fn currentPath(allocator: Allocator, io: std.Io) ![]u8 {
    var buf: [4096]u8 = undefined;
    const n = std.process.currentPath(io, &buf) catch {
        return allocator.dupe(u8, ".");
    };
    return allocator.dupe(u8, buf[0..n]);
}

fn buildEnvironment(
    allocator: Allocator,
    environ_map: *std.process.Environ.Map,
) !struct { w: []u16, a: []u8, size: usize } {
    var wl = std.array_list.Managed(u16).init(allocator);
    errdefer wl.deinit();
    var al = std.array_list.Managed(u8).init(allocator);
    errdefer al.deinit();

    var it = environ_map.iterator();
    while (it.next()) |entry| {
        const line = try std.fmt.allocPrint(allocator, "{s}={s}", .{ entry.key_ptr.*, entry.value_ptr.* });
        defer allocator.free(line);
        const w = try std.unicode.utf8ToUtf16LeAllocZ(allocator, line);
        defer allocator.free(w);
        try wl.appendSlice(w);
        try wl.append(0);
        try al.appendSlice(line);
        try al.append(0);
    }
    try wl.append(0);
    try al.append(0);
    const env_size = wl.items.len * 2;
    return .{
        .w = try wl.toOwnedSlice(),
        .a = try al.toOwnedSlice(),
        .size = env_size,
    };
}

/// Read the main thread's real stack range from /proc/self/maps.
pub fn mainStackBounds() struct { base: usize, limit: usize } {
    if (builtin.os.tag == .linux) {
        const fd = std.os.linux.open("/proc/self/maps", .{ .ACCMODE = .RDONLY }, 0);
        const signed: isize = @bitCast(fd);
        if (signed >= 0) {
            defer _ = std.os.linux.close(@intCast(signed));
            var buf: [16384]u8 = undefined;
            const n = std.os.linux.read(@intCast(signed), &buf, buf.len);
            const signed_n: isize = @bitCast(n);
            if (signed_n > 0) {
                var lines = std.mem.splitScalar(u8, buf[0..@intCast(signed_n)], '\n');
                while (lines.next()) |line| {
                    if (std.mem.indexOf(u8, line, "[stack]") == null) continue;
                    const dash = std.mem.indexOfScalar(u8, line, '-') orelse continue;
                    const space = std.mem.indexOfScalar(u8, line, ' ') orelse continue;
                    const start = std.fmt.parseInt(usize, line[0..dash], 16) catch continue;
                    const end = std.fmt.parseInt(usize, line[dash + 1 .. space], 16) catch continue;
                    if (end > start) return .{ .base = end, .limit = start };
                }
            }
        }
    }
    // Fallback: current RSP and the process stack rlimit (usually 8 MiB).
    var rsp: usize = undefined;
    asm volatile ("movq %%rsp, %[out]" : [out] "=r" (rsp));
    return .{ .base = rsp, .limit = rsp - 8 * 1024 * 1024 };
}

fn initLdr(allocator: Allocator) !*PEB_LDR_DATA {
    const ldr = try allocator.create(PEB_LDR_DATA);
    ldr.* = std.mem.zeroes(PEB_LDR_DATA);
    ldr.Length = @sizeOf(PEB_LDR_DATA);
    ldr.Initialized = 1;
    ldr.InLoadOrderModuleList = .{ .Flink = &ldr.InLoadOrderModuleList, .Blink = &ldr.InLoadOrderModuleList };
    ldr.InMemoryOrderModuleList = .{ .Flink = &ldr.InMemoryOrderModuleList, .Blink = &ldr.InMemoryOrderModuleList };
    ldr.InInitializationOrderModuleList = .{ .Flink = &ldr.InInitializationOrderModuleList, .Blink = &ldr.InInitializationOrderModuleList };
    return ldr;
}

fn insertTail(head: *LIST_ENTRY, e: *LIST_ENTRY) void {
    const tail = head.Blink;
    e.Flink = head;
    e.Blink = tail;
    tail.Flink = e;
    head.Blink = e;
}

pub fn addLdrEntry(
    allocator: Allocator,
    base: usize,
    entry: usize,
    size: usize,
    full_path: []const u8,
    base_name: []const u8,
) !*LDR_DATA_TABLE_ENTRY {
    const p = g_process orelse return error.ProcessNotInitialized;
    const e = try allocator.create(LDR_DATA_TABLE_ENTRY);
    e.* = std.mem.zeroes(LDR_DATA_TABLE_ENTRY);
    e.DllBase = base;
    e.EntryPoint = entry;
    e.SizeOfImage = size;
    e.FullDllName = try UNICODE_STRING.fromZ(allocator, full_path);
    e.BaseDllName = try UNICODE_STRING.fromZ(allocator, base_name);
    insertTail(&p.ldr.InLoadOrderModuleList, &e.InLoadOrderLinks);
    insertTail(&p.ldr.InMemoryOrderModuleList, &e.InMemoryOrderLinks);
    insertTail(&p.ldr.InInitializationOrderModuleList, &e.InInitializationOrderLinks);
    return e;
}

pub fn setImageBase(base: usize) void {
    const p = g_process orelse return;
    p.peb_ptr.ImageBaseAddress = base;
}

pub fn initProcess(
    allocator: Allocator,
    io: std.Io,
    exe_path: []const u8,
    argv: []const []const u8,
    environ_map: *std.process.Environ.Map,
    game_dir: []const u8,
    cwd_override: ?[]const u8,
) !*Process {
    const cwd = if (cwd_override) |c|
        try allocator.dupe(u8, c)
    else
        try currentPath(allocator, io);
    const win_drive = exe_path.len >= 2 and exe_path[1] == ':';
    const abs_exe = if (win_drive or std.fs.path.isAbsolute(exe_path))
        try allocator.dupe(u8, exe_path)
    else
        try std.fs.path.join(allocator, &.{ cwd, exe_path });

    const cmdline_a = try buildCommandLine(allocator, argv);
    const cmdline_w = try makeWZ(allocator, cmdline_a);
    const image_a = try makeZ(allocator, abs_exe);
    const image_w = try makeWZ(allocator, abs_exe);
    const cwd_a = try makeZ(allocator, cwd);
    const cwd_with_sep = try std.fmt.allocPrint(allocator, "{s}{c}", .{ cwd, std.fs.path.sep });
    defer allocator.free(cwd_with_sep);
    const cwd_w = try makeWZ(allocator, cwd_with_sep);
    const env = try buildEnvironment(allocator, environ_map);

    const dll_path_a = try std.fmt.allocPrint(allocator, "{s}{c}{s}", .{ game_dir, std.fs.path.sep, "" });
    defer allocator.free(dll_path_a);
    const dll_path_w = try makeWZ(allocator, dll_path_a);

    const params = try allocator.create(RTL_USER_PROCESS_PARAMETERS);
    params.* = std.mem.zeroes(RTL_USER_PROCESS_PARAMETERS);
    params.MaximumLength = @sizeOf(RTL_USER_PROCESS_PARAMETERS) + 0x200;
    params.Length = @sizeOf(RTL_USER_PROCESS_PARAMETERS);
    params.Flags = 0x4000; // PROCESS_PARAMETERS_NORMALIZED
    params.ConsoleHandle = 0;
    params.StandardInput = 0;
    params.StandardOutput = 0;
    params.StandardError = 0;
    params.CurrentDirectory = .{ .DosPath = unicodeFromW(cwd_w), .Handle = 0 };
    params.DllPath = unicodeFromW(dll_path_w);
    params.ImagePathName = unicodeFromW(image_w);
    params.CommandLine = unicodeFromW(cmdline_w);
    params.Environment = env.w.ptr;
    params.EnvironmentSize = env.size;
    params.WindowTitle = unicodeFromW(image_w);
    params.DesktopInfo = unicodeFromW(cwd_w);

    const ldr = try initLdr(allocator);

    const peb_mem = try allocator.alignedAlloc(u8, comptime std.mem.Alignment.fromByteUnits(16), @sizeOf(PEB));
    @memset(peb_mem, 0);
    const peb: *PEB = @ptrCast(@alignCast(peb_mem.ptr));
    peb.Ldr = ldr;
    peb.ProcessParameters = params;
    peb.ProcessHeap = 0x1400000;
    peb.BeingDebugged = 0;

    const teb_mem = try allocator.alignedAlloc(u8, comptime std.mem.Alignment.fromByteUnits(4096), TEB_SIZE + 0x2800);
    @memset(teb_mem, 0);
    const teb: *TEB = @ptrCast(@alignCast(teb_mem.ptr));

    const bounds = mainStackBounds();
    const pid: u32 = if (builtin.os.tag == .linux) @intCast(std.os.linux.getpid()) else 1;
    const tid: u32 = if (builtin.os.tag == .linux) @intCast(std.os.linux.gettid()) else 1;

    teb.nt_tib.exception_list = std.math.maxInt(usize);
    teb.nt_tib.stack_base = bounds.base;
    teb.nt_tib.stack_limit = bounds.limit;
    teb.nt_tib.self_ptr = @intFromPtr(teb);
    teb.client_id = .{ .unique_process = pid, .unique_thread = tid };
    const module_tls = try allocator.alloc(usize, MAX_TLS_SLOTS);
    @memset(module_tls, 0);
    teb.thread_local_storage_pointer = @intFromPtr(module_tls.ptr);
    teb.process_environment_block = @intFromPtr(peb);
    g_guest_teb = @intFromPtr(teb);

    const p = try allocator.create(Process);
    p.* = .{
        .allocator = allocator,
        .teb_ptr = teb,
        .host_teb = if (builtin.os.tag == .windows) readHostTeb() else 0,
        .peb_ptr = peb,
        .params = params,
        .ldr = ldr,
        .cmdline_w = cmdline_w,
        .cmdline_a = cmdline_a,
        .image_path_w = image_w,
        .image_path_a = image_a,
        .cwd_w = cwd_w,
        .cwd_a = cwd_a,
        .env_w = env.w,
        .env_a = env.a,
        .dll_path_w = dll_path_w,
        .game_dir = try allocator.dupe(u8, game_dir),
        .pid = pid,
        .tid = tid,
    };
    g_process = p;

    // Slot 0 is the CRT per-thread data (PTD), not a module TLS template.
    const crt_tls = try allocator.alloc(u8, 0x10000);
    @memset(crt_tls, 0);
    p.tls_template[0] = @intFromPtr(crt_tls.ptr);
    p.tls_template_sizes[0] = 0x10000;
    p.tls_template_len = 1;
    module_tls[0] = @intFromPtr(crt_tls.ptr);

    if (builtin.os.tag == .windows) {
        const host = readHostTeb();
        if (host != 0) {
            @as(*usize, @ptrFromInt(@intFromPtr(teb) + 0x1FF8)).* = host;
            @as(*usize, @ptrFromInt(host + 0x1FF8)).* = 0;
            @as(*usize, @ptrFromInt(host + 0x28)).* = @intFromPtr(teb);
        }
    }

    if (builtin.os.tag == .linux) {
        const ARCH_SET_GS: usize = 0x1001;
        const rc = std.os.linux.syscall2(.arch_prctl, ARCH_SET_GS, @intFromPtr(teb));
        if (@as(isize, @bitCast(rc)) != 0) return error.ArchPrctlFailed;
    }

    return p;
}

pub fn initThread(stack_base: usize, stack_limit: usize, tid: u32) !*TEB {
    const p = g_process orelse return error.ProcessNotInitialized;
    const mem = try std.heap.page_allocator.alignedAlloc(u8, comptime std.mem.Alignment.fromByteUnits(4096), TEB_SIZE + 0x2800);
    @memset(mem, 0);
    const teb: *TEB = @ptrCast(@alignCast(mem.ptr));

    const tls_mem = try std.heap.page_allocator.alloc(usize, MAX_TLS_SLOTS);
    @memset(tls_mem, 0);
    for (0..p.tls_template_len) |i| {
        tls_mem[i] = cloneTlsBlock(p.tls_template[i], p.tls_template_sizes[i]);
    }

    teb.nt_tib.exception_list = std.math.maxInt(usize);
    teb.nt_tib.stack_base = stack_base;
    teb.nt_tib.stack_limit = stack_limit;
    teb.nt_tib.self_ptr = @intFromPtr(teb);
    teb.client_id = .{ .unique_process = p.pid, .unique_thread = tid };
    teb.thread_local_storage_pointer = @intFromPtr(tls_mem.ptr);
    teb.process_environment_block = @intFromPtr(p.peb_ptr);
    g_guest_teb = @intFromPtr(teb);

    if (builtin.os.tag == .linux) {
        const ARCH_SET_GS: usize = 0x1001;
        const rc = std.os.linux.syscall2(.arch_prctl, ARCH_SET_GS, @intFromPtr(teb));
        if (@as(isize, @bitCast(rc)) != 0) return error.ArchPrctlFailed;
    } else if (builtin.os.tag == .windows) {
        const host = readHostTeb();
        if (host != 0) {
            @as(*usize, @ptrFromInt(@intFromPtr(teb) + 0x1FF8)).* = host;
            @as(*usize, @ptrFromInt(host + 0x1FF8)).* = 0;
            @as(*usize, @ptrFromInt(host + 0x28)).* = @intFromPtr(teb);
        }
    }
    return teb;
}

fn cloneTlsBlock(template: usize, size: usize) usize {
    if (template == 0 or size == 0) return template;
    const mem = std.heap.page_allocator.alignedAlloc(u8, comptime std.mem.Alignment.fromByteUnits(64), size) catch return template;
    const src: [*]const u8 = @ptrFromInt(template);
    @memcpy(mem[0..size], src[0..size]);
    return @intFromPtr(mem.ptr);
}

/// Assign the next per-module TLS index and publish the block for future
/// threads.  The current thread is updated too.
pub fn allocModuleTls(block: usize, block_size: usize) !u16 {
    const p = g_process orelse return error.ProcessNotInitialized;
    if (p.tls_template_len >= MAX_TLS_SLOTS) return error.TlsSlotsExhausted;
    if (builtin.os.tag == .windows) {
        // Guest TLS indexes are image TLS indexes, not host tlsAlloc slots.
        const index: u16 = @intCast(p.tls_template_len);
        p.tls_template_len += 1;
        p.tls_template[index] = block;
        p.tls_template_sizes[index] = @intCast(block_size);
        const t: *TEB = p.teb_ptr;
        const base: [*]usize = @ptrFromInt(t.thread_local_storage_pointer);
        base[index] = cloneTlsBlock(block, block_size);
        return index;
    }
    const index: u16 = @intCast(p.tls_template_len);
    p.tls_template_len += 1;
    p.tls_template[index] = block;
    p.tls_template_sizes[index] = @intCast(block_size);
    if (currentTeb()) |t| {
        const base: [*]usize = @ptrFromInt(t.thread_local_storage_pointer);
        base[index] = block;
    }
    return index;
}

pub fn setModuleTlsCurrent(index: u16, block: usize, block_size: usize) void {
    if (builtin.os.tag == .windows) {
        if (g_process) |p| {
            const base: [*]usize = @ptrFromInt(p.teb_ptr.thread_local_storage_pointer);
            if (index < MAX_TLS_SLOTS) base[index] = cloneTlsBlock(block, block_size);
            return;
        }
    }
    if (currentTeb()) |t| {
        const base: [*]usize = @ptrFromInt(t.thread_local_storage_pointer);
        if (index < MAX_TLS_SLOTS) base[index] = cloneTlsBlock(block, block_size);
    }
}

pub fn tlsAlloc() u32 {
    while (true) {
        const cur = g_tls_bitmap.load(.acquire);
        const free_bits = ~cur;
        if (free_bits == 0) return 0xFFFFFFFF;
        const index: u32 = if (builtin.os.tag == .windows)
            @intCast(MAX_TLS_SLOTS - 1 - @ctz(free_bits))
        else
            @intCast(@ctz(free_bits));
        if (index >= MAX_TLS_SLOTS) return 0xFFFFFFFF;
        const new = cur | (@as(u64, 1) << @intCast(index));
        if (g_tls_bitmap.cmpxchgWeak(cur, new, .acq_rel, .acquire) == null) return index;
    }
}

pub fn tlsFree(index: u32) bool {
    if (index >= MAX_TLS_SLOTS) return false;
    const bit = @as(u64, 1) << @intCast(index);
    while (true) {
        const cur = g_tls_bitmap.load(.acquire);
        if (cur & bit == 0) return false;
        if (g_tls_bitmap.cmpxchgWeak(cur, cur & ~bit, .acq_rel, .acquire) == null) break;
    }
    if (currentTeb()) |t| {
        const base: [*]usize = @ptrFromInt(t.thread_local_storage_pointer);
        base[index] = 0;
    }
    return true;
}

pub fn tlsGet(index: u32) usize {
    if (index >= MAX_TLS_SLOTS) return 0;
    if (currentTeb()) |t| {
        const base: [*]usize = @ptrFromInt(t.thread_local_storage_pointer);
        return base[index];
    }
    return 0;
}

pub fn tlsSet(index: u32, value: usize) bool {
    if (index >= MAX_TLS_SLOTS) return false;
    if (currentTeb()) |t| {
        const base: [*]usize = @ptrFromInt(t.thread_local_storage_pointer);
        base[index] = value;
        return true;
    }
    return false;
}

pub fn commandLineA() [:0]const u8 {
    if (g_process) |p| return p.cmdline_a;
    return "";
}

pub fn commandLineW() [:0]const u16 {
    if (g_process) |p| return p.cmdline_w;
    return &[_:0]u16{};
}

pub fn imagePathA() [:0]const u8 {
    if (g_process) |p| return p.image_path_a;
    return "";
}

pub fn imagePathW() [:0]const u16 {
    if (g_process) |p| return p.image_path_w;
    return &[_:0]u16{};
}

pub fn cwdA() [:0]const u8 {
    if (g_process) |p| return p.cwd_a;
    return "";
}

pub fn cwdW() [:0]const u16 {
    if (g_process) |p| return p.cwd_w;
    return &[_:0]u16{};
}

pub fn environmentW() ?[*:0]const u16 {
    if (g_process) |p| return @ptrCast(p.env_w.ptr);
    return null;
}

pub fn environmentA() ?[*:0]const u8 {
    if (g_process) |p| return @ptrCast(p.env_a.ptr);
    return null;
}

fn eqlWAscii(a: []const u16, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (ca > 0x7F) return false;
        if (std.ascii.toLower(@intCast(ca)) != std.ascii.toLower(cb)) return false;
    }
    return true;
}

fn eqlW(a: []const u16, b: []const u16) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        const la = if (ca < 0x80) std.ascii.toLower(@intCast(ca)) else ca;
        const lb = if (cb < 0x80) std.ascii.toLower(@intCast(cb)) else cb;
        if (la != lb) return false;
    }
    return true;
}

fn wLen(ptr: [*:0]const u16) usize {
    var n: usize = 0;
    while (ptr[n] != 0) : (n += 1) {}
    return n;
}

pub fn findModuleByNameW(name_w: [*:0]const u16) ?*LDR_DATA_TABLE_ENTRY {
    const p = g_process orelse return null;
    const head = &p.ldr.InLoadOrderModuleList;
    var cur = head.Flink;
    while (cur != head) : (cur = cur.Flink) {
        const e: *LDR_DATA_TABLE_ENTRY = @fieldParentPtr("InLoadOrderLinks", cur);
        const buf = e.BaseDllName.Buffer orelse continue;
        const len = e.BaseDllName.Length / 2;
        if (eqlW(buf[0..len], name_w[0..wLen(name_w)])) return e;
    }
    return null;
}

pub fn findModuleByName(name: []const u8) ?*LDR_DATA_TABLE_ENTRY {
    const p = g_process orelse return null;
    const head = &p.ldr.InLoadOrderModuleList;
    var cur = head.Flink;
    while (cur != head) : (cur = cur.Flink) {
        const e: *LDR_DATA_TABLE_ENTRY = @fieldParentPtr("InLoadOrderLinks", cur);
        const buf = e.BaseDllName.Buffer orelse continue;
        const len = e.BaseDllName.Length / 2;
        if (eqlWAscii(buf[0..len], name)) return e;
    }
    return null;
}

pub fn findModuleByBase(base: usize) ?*LDR_DATA_TABLE_ENTRY {
    const p = g_process orelse return null;
    const head = &p.ldr.InLoadOrderModuleList;
    var cur = head.Flink;
    while (cur != head) : (cur = cur.Flink) {
        const e: *LDR_DATA_TABLE_ENTRY = @fieldParentPtr("InLoadOrderLinks", cur);
        if (e.DllBase == base) return e;
    }
    return null;
}

/// Returns the number of UTF-16 code units copied, excluding the terminator.
pub fn moduleFileNameW(base: usize, out: [*]u16, cap: usize) usize {
    if (cap == 0) return 0;
    const e = findModuleByBase(base) orelse {
        out[0] = 0;
        return 0;
    };
    const buf = e.FullDllName.Buffer orelse {
        out[0] = 0;
        return 0;
    };
    const len = @min(e.FullDllName.Length / 2, cap - 1);
    @memcpy(out[0..len], buf[0..len]);
    out[len] = 0;
    return len;
}


test "TEB/PEB layout offsets" {
    try std.testing.expectEqual(@as(usize, 0x00), @offsetOf(TEB, "nt_tib"));
    try std.testing.expectEqual(@as(usize, 0x40), @offsetOf(TEB, "client_id"));
    try std.testing.expectEqual(@as(usize, 0x58), @offsetOf(TEB, "thread_local_storage_pointer"));
    try std.testing.expectEqual(@as(usize, 0x60), @offsetOf(TEB, "process_environment_block"));
    try std.testing.expectEqual(@as(usize, 0x1480), @offsetOf(TEB, "tls_slots"));
    try std.testing.expectEqual(@as(usize, 0x10), @offsetOf(PEB, "ImageBaseAddress"));
    try std.testing.expectEqual(@as(usize, 0x20), @offsetOf(PEB, "ProcessParameters"));
}
