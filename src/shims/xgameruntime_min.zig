//! Minimal xgameruntime providers: task queue/XAsync, XPackage and
//! persistent local storage.  Semantics are completed synchronously; every
//! method whose behavior is unknown is fail-closed.

const std = @import("std");
const builtin = @import("builtin");

const HRESULT = i32;
const S_OK: HRESULT = 0;
const E_NOTIMPL: HRESULT = @bitCast(@as(u32, 0x8000_4001));
const E_INVALIDARG: HRESULT = @bitCast(@as(u32, 0x8007_0057));
const E_FAIL: HRESULT = @bitCast(@as(u32, 0x8000_4005));
const E_PENDING: HRESULT = @bitCast(@as(u32, 0x8000_000A));
const NO_PACKAGE: HRESULT = @bitCast(@as(u32, 0x8924_5208));

const Guid = extern struct {
    d1: u32,
    d2: u16,
    d3: u16,
    d4: [8]u8,
};

fn eqGuid(a: *const Guid, d1: u32, d2: u16, d3: u16, d4: [8]u8) bool {
    return a.d1 == d1 and a.d2 == d2 and a.d3 == d3 and std.mem.eql(u8, &a.d4, &d4);
}

pub const XASYNC = Guid{ .d1 = 0x073b_7dcb, .d2 = 0x1fcf, .d3 = 0x4030, .d4 = .{ 0x94, 0xbe, 0xe3, 0xc9, 0xeb, 0x62, 0x34, 0x28 } };
pub const XPACKAGE = Guid{ .d1 = 0xaf40_6016, .d2 = 0xe850, .d3 = 0x4aa8, .d4 = .{ 0xa8, 0x8d, 0x2f, 0x3d, 0xcb, 0x9d, 0xac, 0x7e } };
pub const XPACKAGE_IID = Guid{ .d1 = 0x0b9d_556e, .d2 = 0xab70, .d3 = 0x43f4, .d4 = .{ 0xba, 0xa0, 0x99, 0x99, 0xac, 0x4c, 0xb0, 0x40 } };
pub const STORAGE = Guid{ .d1 = 0xf4fa_f4d4, .d2 = 0x2d04, .d3 = 0x4fce, .d4 = .{ 0xb3, 0xe0, 0x47, 0x4a, 0x71, 0x3a, 0x3e, 0x84 } };
pub const STORAGE_IID = Guid{ .d1 = 0x41a4_e10c, .d2 = 0x5a7e, .d3 = 0x41d9, .d4 = .{ 0x8c, 0x37, 0x37, 0xbd, 0xe6, 0x2a, 0x07, 0xd6 } };

const AsyncBlock = extern struct {
    queue: usize,
    context: usize,
    callback: usize,
    internal: [4]usize,
};

const ProviderData = extern struct {
    block: *AsyncBlock,
    buffer_size: usize,
    buffer: ?*anyopaque,
    context: ?*anyopaque,
};

const ProviderFn = *const fn (u32, *const ProviderData) callconv(.{ .x86_64_win = .{} }) HRESULT;
const WorkFn = *const fn (*AsyncBlock) callconv(.{ .x86_64_win = .{} }) void;
const CompletionFn = *const fn (*AsyncBlock) callconv(.{ .x86_64_win = .{} }) void;
const CallbackFn = *const fn (?*anyopaque, bool) callconv(.{ .x86_64_win = .{} }) void;

const Object = extern struct { lpVtbl: *const anyopaque };

fn qi(this: *Object, iid: ?*const Guid, ppv: ?*?*anyopaque) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = iid;
    if (ppv) |out| out.* = this;
    return S_OK;
}
fn addRef(_: *Object) callconv(.{ .x86_64_win = .{} }) u32 {
    return 2;
}
fn release(_: *Object) callconv(.{ .x86_64_win = .{} }) u32 {
    return 1;
}
fn missing(_: *Object) callconv(.{ .x86_64_win = .{} }) HRESULT {
    return E_NOTIMPL;
}

const Queue = extern struct {
    work_mode: u32,
    completion_mode: u32,
    live: bool = true,
};

const Task = struct {
    queue: ?*Queue,
    port: u32,
    context: ?*anyopaque,
    callback: ?CallbackFn,
};

var g_queues: [8]Queue = undefined;
var g_queue_count: usize = 0;
var g_tasks: [64]Task = undefined;
var g_task_count: usize = 0;
var g_task_lock = std.atomic.Value(u32).init(0);
fn lockTasks() void {
    while (g_task_lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
        while (g_task_lock.load(.monotonic) != 0) std.atomic.spinLoopHint();
    }
}
fn unlockTasks() void {
    g_task_lock.store(0, .release);
}

fn immediate(mode: u32) bool {
    return mode == 3;
}
fn enqueue(q: ?*Queue, port: u32, ctx: ?*anyopaque, cb: ?CallbackFn) void {
    if (immediate(if (port == 0) (q orelse &g_queues[0]).work_mode else (q orelse &g_queues[0]).completion_mode)) {
        if (cb) |f| f(ctx, false);
        return;
    }
    lockTasks();
    defer unlockTasks();
    if (g_task_count < g_tasks.len) {
        g_tasks[g_task_count] = .{ .queue = q, .port = port, .context = ctx, .callback = cb };
        g_task_count += 1;
    }
}

// ---------------------------------------------------------------------------
// XAsync
// ---------------------------------------------------------------------------

fn aGetStatus(_: *Object, b: ?*AsyncBlock, wait: u8) callconv(.{ .x86_64_win = .{} }) HRESULT {
    const block = b orelse return E_INVALIDARG;
    if (block.internal[1] == 2) return S_OK;
    _ = wait;
    return E_PENDING;
}
fn aGetResultSize(_: *Object, b: ?*AsyncBlock, out: ?*usize) callconv(.{ .x86_64_win = .{} }) HRESULT {
    const block = b orelse return E_INVALIDARG;
    if (out) |o| o.* = block.internal[3];
    return if (block.internal[1] == 2) S_OK else E_PENDING;
}
fn aCancel(_: *Object, b: ?*AsyncBlock) callconv(.{ .x86_64_win = .{} }) void {
    const block = b orelse return;
    block.internal[1] = 2;
}
fn complete(block: *AsyncBlock, hr: HRESULT, size: usize) void {
    block.internal[1] = 2;
    block.internal[2] = @as(u32, @bitCast(hr));
    block.internal[3] = size;
    if (block.callback != 0) {
        const cb: CompletionFn = @ptrFromInt(block.callback);
        cb(block);
    }
}
fn aRun(_: *Object, b: ?*AsyncBlock, work: ?WorkFn) callconv(.{ .x86_64_win = .{} }) HRESULT {
    const block = b orelse return E_INVALIDARG;
    const w = work orelse return E_INVALIDARG;
    block.internal[1] = 1;
    w(block);
    if (block.internal[1] != 2) complete(block, S_OK, 0);
    return S_OK;
}
fn aBegin(_: *Object, b: ?*AsyncBlock, context: ?*anyopaque, identity: ?*const anyopaque, name: ?[*:0]const u8, provider: ?ProviderFn) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = identity;
    _ = name;
    const block = b orelse return E_INVALIDARG;
    block.context = @intFromPtr(context);
    block.internal[0] = if (provider) |p| @intFromPtr(p) else 0;
    block.internal[1] = 1;
    block.internal[2] = 0;
    block.internal[3] = 0;
    return S_OK;
}
fn aSchedule(_: *Object, b: ?*AsyncBlock, delay: u32) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = delay;
    const block = b orelse return E_INVALIDARG;
    if (block.internal[0] != 0) {
        const provider: ProviderFn = @ptrFromInt(block.internal[0]);
        const data = ProviderData{ .block = block, .buffer_size = 0, .buffer = null, .context = @ptrFromInt(block.context) };
        const hr = provider(1, &data);
        if (block.internal[1] != 2) complete(block, hr, 0);
    } else if (block.internal[1] != 2) {
        complete(block, S_OK, 0);
    }
    return S_OK;
}
fn aComplete(_: *Object, b: ?*AsyncBlock, hr: HRESULT, size: usize) callconv(.{ .x86_64_win = .{} }) void {
    const block = b orelse return;
    complete(block, hr, size);
}
fn aGetResult(_: *Object, b: ?*AsyncBlock, identity: ?*const anyopaque, size: usize, buffer: ?*anyopaque, used: ?*usize) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = identity;
    const block = b orelse return E_INVALIDARG;
    if (block.internal[1] != 2) return E_PENDING;
    if (used) |u| u.* = block.internal[3];
    if (buffer) |buf| {
        if (size < block.internal[3]) return E_INVALIDARG;
        if (block.internal[0] != 0) {
            const provider: ProviderFn = @ptrFromInt(block.internal[0]);
            const data = ProviderData{ .block = block, .buffer_size = size, .buffer = buf, .context = @ptrFromInt(block.context) };
            return provider(2, &data);
        }
    }
    return S_OK;
}
fn aCreate(_: *Object, work: u32, completion: u32, out: ?*?*anyopaque) callconv(.{ .x86_64_win = .{} }) HRESULT {
    if (g_queue_count >= g_queues.len) return E_FAIL;
    const q = &g_queues[g_queue_count];
    g_queue_count += 1;
    q.* = .{ .work_mode = work, .completion_mode = completion };
    if (out) |o| o.* = @ptrCast(@constCast(q));
    return S_OK;
}
fn aCreateComposite(_: *Object, work: ?*anyopaque, completion: ?*anyopaque, out: ?*?*anyopaque) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = work;
    _ = completion;
    return aCreate(undefined, 0, 0, out);
}
fn aGetPort(_: *Object, q: ?*anyopaque, port: u32, out: ?*?*anyopaque) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = port;
    if (out) |o| o.* = q;
    return S_OK;
}
fn aDuplicate(_: *Object, q: ?*anyopaque, out: ?*?*anyopaque) callconv(.{ .x86_64_win = .{} }) HRESULT {
    if (out) |o| o.* = q;
    return S_OK;
}
fn aDispatch(_: *Object, q: ?*anyopaque, port: u32, timeout: u32) callconv(.{ .x86_64_win = .{} }) bool {
    _ = timeout;
    var found: ?Task = null;
    lockTasks();
    var i: usize = 0;
    while (i < g_task_count) : (i += 1) {
        if (g_tasks[i].port == port and (q == null or @intFromPtr(g_tasks[i].queue) == @intFromPtr(q))) {
            found = g_tasks[i];
            var j = i;
            while (j + 1 < g_task_count) : (j += 1) g_tasks[j] = g_tasks[j + 1];
            g_task_count -= 1;
            break;
        }
    }
    unlockTasks();
    if (found) |t| {
        if (t.callback) |cb| cb(t.context, false);
        return true;
    }
    return false;
}
fn aClose(_: *Object, q: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) void {
    _ = q;
}
fn aSubmit(_: *Object, q: ?*anyopaque, port: u32, context: ?*anyopaque, callback: ?CallbackFn) callconv(.{ .x86_64_win = .{} }) HRESULT {
    enqueue(@ptrCast(@alignCast(q)), port, context, callback);
    return S_OK;
}
fn aSubmitDelayed(_: *Object, q: ?*anyopaque, port: u32, delay: u32, context: ?*anyopaque, callback: ?CallbackFn) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = delay;
    enqueue(@ptrCast(@alignCast(q)), port, context, callback);
    return S_OK;
}
fn aTerminate(_: *Object, q: ?*anyopaque, wait: u8, context: ?*anyopaque, callback: ?CallbackFn) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = q;
    _ = wait;
    if (callback) |cb| cb(context, false);
    return S_OK;
}
fn aRegisterMonitor(_: *Object, q: ?*anyopaque, context: ?*anyopaque, callback: ?*anyopaque, token: ?*u64) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = q;
    _ = context;
    _ = callback;
    if (token) |t| t.* = 1;
    return S_OK;
}
fn aUnregisterMonitor(_: *Object, q: ?*anyopaque, token: u64) callconv(.{ .x86_64_win = .{} }) void {
    _ = q;
    _ = token;
}
fn aGetProcessQueue(_: *Object, out: ?*?*anyopaque) callconv(.{ .x86_64_win = .{} }) bool {
    if (out) |o| o.* = @ptrCast(@constCast(&g_queues[0]));
    return true;
}
fn aSetProcessQueue(_: *Object, q: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) void {
    _ = q;
}

var async_vtbl = [31]*const anyopaque{
    @ptrCast(&qi), @ptrCast(&addRef), @ptrCast(&release),
    @ptrCast(&aGetStatus), @ptrCast(&aGetResultSize), @ptrCast(&aCancel),
    @ptrCast(&aRun), @ptrCast(&aBegin), @ptrCast(&missing),
    @ptrCast(&aSchedule), @ptrCast(&aComplete), @ptrCast(&aGetResult),
    @ptrCast(&aCreate), @ptrCast(&aCreateComposite), @ptrCast(&aGetPort),
    @ptrCast(&aDuplicate), @ptrCast(&aDispatch), @ptrCast(&aClose),
    @ptrCast(&aSubmit), @ptrCast(&aSubmitDelayed), @ptrCast(&missing),
    @ptrCast(&missing), @ptrCast(&aTerminate), @ptrCast(&aRegisterMonitor),
    @ptrCast(&aUnregisterMonitor), @ptrCast(&aGetProcessQueue), @ptrCast(&aSetProcessQueue),
    @ptrCast(&missing), @ptrCast(&missing), @ptrCast(&missing), @ptrCast(&missing),
};
const async_obj = Object{ .lpVtbl = @ptrCast(&async_vtbl) };

// ---------------------------------------------------------------------------
// XPackage
// ---------------------------------------------------------------------------

const Progress = extern struct { total: u64, installed: u64, launch: u64, launchable: bool, completed: bool };
var g_monitor: u8 = 0;

fn pCurrentId(_: *Object, size: usize, buffer: ?[*]u8) callconv(.{ .x86_64_win = .{} }) HRESULT {
    const id = "7952987A";
    const out = buffer orelse return E_INVALIDARG;
    if (size <= id.len) return E_FAIL;
    @memcpy(out[0..id.len], id);
    out[id.len] = 0;
    return S_OK;
}
fn pPackaged(_: *Object) callconv(.{ .x86_64_win = .{} }) bool {
    return true;
}
fn pCreateMonitor(_: *Object, id: ?[*:0]const u8, count: u32, sel: ?*const anyopaque, ms: u32, q: ?*anyopaque, out: ?*?*const anyopaque) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = id;
    _ = count;
    _ = sel;
    _ = ms;
    _ = q;
    if (out) |o| o.* = &g_monitor;
    return S_OK;
}
fn pCloseMonitor(_: *Object, m: ?*const anyopaque) callconv(.{ .x86_64_win = .{} }) void {
    _ = m;
}
fn pProgress(_: *Object, m: ?*const anyopaque, out: ?*Progress) callconv(.{ .x86_64_win = .{} }) void {
    _ = m;
    if (out) |o| o.* = .{ .total = 1, .installed = 1, .launch = 1, .launchable = true, .completed = true };
}
fn pRegisterProgress(_: *Object, m: ?*const anyopaque, ctx: ?*anyopaque, cb: ?*anyopaque, out: ?*u64) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = m;
    _ = ctx;
    _ = cb;
    if (out) |o| o.* = 1;
    return S_OK;
}
fn pAvailability(_: *Object, id: ?[*:0]const u8, count: u32, sel: ?*const anyopaque, out: ?*u32) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = id;
    _ = count;
    _ = sel;
    if (out) |o| o.* = 0;
    return S_OK;
}
fn pChangeOrder(_: *Object, id: ?[*:0]const u8, count: u32, sel: ?*const anyopaque) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = id;
    _ = count;
    _ = sel;
    return S_OK;
}
fn pInstallAsync(_: *Object, id: ?[*:0]const u8, count: u32, sel: ?*const anyopaque, ms: u32, suppress: bool, block: ?*AsyncBlock) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = id;
    _ = count;
    _ = sel;
    _ = ms;
    _ = suppress;
    if (block) |b| complete(b, S_OK, 0);
    return S_OK;
}
fn pInstallResult(_: *Object, block: ?*AsyncBlock, out: ?*?*const anyopaque) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = block;
    if (out) |o| o.* = &g_monitor;
    return S_OK;
}
fn pEstimate(_: *Object, id: ?[*:0]const u8, count: u32, sel: ?*const anyopaque, bytes: ?*u64, confirm: ?*bool) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = id;
    _ = count;
    _ = sel;
    if (bytes) |b| b.* = 0;
    if (confirm) |c| c.* = false;
    return S_OK;
}
fn pUninstall(_: *Object, id: ?[*:0]const u8, count: u32, sel: ?*const anyopaque) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = id;
    _ = count;
    _ = sel;
    return E_NOTIMPL;
}
fn pMountPath(_: *Object, m: ?*const anyopaque, size: usize, buf: ?[*]u8) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = m;
    _ = size;
    _ = buf;
    return E_INVALIDARG;
}
fn pCloseMount(_: *Object, m: ?*const anyopaque) callconv(.{ .x86_64_win = .{} }) void {
    _ = m;
}
fn pUninstallPackage(_: *Object, id: ?[*:0]const u8) callconv(.{ .x86_64_win = .{} }) bool {
    _ = id;
    return false;
}
fn pMountAsync(_: *Object, id: ?[*:0]const u8, block: ?*AsyncBlock) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = id;
    if (block) |b| complete(b, NO_PACKAGE, 0);
    return S_OK;
}
fn pMountResult(_: *Object, block: ?*AsyncBlock, out: ?*?*const anyopaque) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = block;
    if (out) |o| o.* = &g_monitor;
    return S_OK;
}
fn pEnumerate(_: *Object, kind: u32, scope: u32, ctx: ?*anyopaque, cb: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = kind;
    _ = scope;
    _ = ctx;
    _ = cb;
    return S_OK;
}

var package_vtbl = [40]*const anyopaque{
    @ptrCast(&qi), @ptrCast(&addRef), @ptrCast(&release),
    @ptrCast(&pCurrentId), @ptrCast(&pPackaged), @ptrCast(&pCreateMonitor),
    @ptrCast(&pCloseMonitor), @ptrCast(&pProgress), @ptrCast(&missing),
    @ptrCast(&pRegisterProgress), @ptrCast(&missing), @ptrCast(&missing),
    @ptrCast(&pAvailability), @ptrCast(&missing), @ptrCast(&pChangeOrder),
    @ptrCast(&missing), @ptrCast(&pInstallAsync), @ptrCast(&pInstallResult),
    @ptrCast(&pEstimate), @ptrCast(&pUninstall), @ptrCast(&missing),
    @ptrCast(&missing), @ptrCast(&missing), @ptrCast(&missing),
    @ptrCast(&missing), @ptrCast(&pMountPath), @ptrCast(&pCloseMount),
    @ptrCast(&missing), @ptrCast(&missing), @ptrCast(&missing),
    @ptrCast(&missing), @ptrCast(&missing), @ptrCast(&missing),
    @ptrCast(&missing), @ptrCast(&pUninstallPackage), @ptrCast(&missing),
    @ptrCast(&missing), @ptrCast(&pMountAsync), @ptrCast(&pMountResult),
    @ptrCast(&pEnumerate),
};
const package_obj = Object{ .lpVtbl = @ptrCast(&package_vtbl) };

// ---------------------------------------------------------------------------
// Persistent local storage
// ---------------------------------------------------------------------------

const SpaceInfo = extern struct { available_free: u64, total_free: u64, used: u64, total: u64 };
const storage_path = "X:\\";

fn sPathSize(_: *Object, out: ?*usize) callconv(.{ .x86_64_win = .{} }) HRESULT {
    if (out) |o| o.* = storage_path.len + 1;
    return S_OK;
}
fn sPath(_: *Object, size: usize, buffer: ?[*]u8, used: ?*usize) callconv(.{ .x86_64_win = .{} }) HRESULT {
    if (size <= storage_path.len) return E_FAIL;
    const out = buffer orelse return E_INVALIDARG;
    @memcpy(out[0..storage_path.len], storage_path);
    out[storage_path.len] = 0;
    if (used) |u| u.* = storage_path.len;
    return S_OK;
}
fn sSpace(_: *Object, out: ?*SpaceInfo) callconv(.{ .x86_64_win = .{} }) HRESULT {
    if (out) |o| o.* = .{ .available_free = 2 * 1024 * 1024 * 1024, .total_free = 2 * 1024 * 1024 * 1024, .used = 0, .total = 2 * 1024 * 1024 * 1024 };
    return S_OK;
}
fn sPrompt(_: *Object, bytes: u64, block: ?*AsyncBlock) callconv(.{ .x86_64_win = .{} }) HRESULT {
    const hr: HRESULT = if (bytes <= 2 * 1024 * 1024 * 1024) S_OK else E_FAIL;
    if (block) |b| complete(b, hr, 0);
    return S_OK;
}
fn sPromptResult(_: *Object, block: ?*AsyncBlock) callconv(.{ .x86_64_win = .{} }) HRESULT {
    const b = block orelse return E_INVALIDARG;
    return @bitCast(@as(u32, @truncate(b.internal[2])));
}

var storage_vtbl = [8]*const anyopaque{
    @ptrCast(&qi), @ptrCast(&addRef), @ptrCast(&release),
    @ptrCast(&sPathSize), @ptrCast(&sPath), @ptrCast(&sSpace),
    @ptrCast(&sPrompt), @ptrCast(&sPromptResult),
};
const storage_obj = Object{ .lpVtbl = @ptrCast(&storage_vtbl) };

pub fn queryApi(clsid: ?*const Guid, riid: ?*const Guid, ppv: ?*?*anyopaque) ?HRESULT {
    const c = clsid orelse return null;
    if (ppv) |out| out.* = null;
    if (eqGuid(c, XASYNC.d1, XASYNC.d2, XASYNC.d3, XASYNC.d4)) return null;
    if (eqGuid(c, XPACKAGE.d1, XPACKAGE.d2, XPACKAGE.d3, XPACKAGE.d4)) {
        _ = riid;
        if (ppv) |out| out.* = @ptrCast(@constCast(&package_obj));
        return S_OK;
    }
    if (eqGuid(c, STORAGE.d1, STORAGE.d2, STORAGE.d3, STORAGE.d4)) {
        _ = riid;
        if (ppv) |out| out.* = @ptrCast(@constCast(&storage_obj));
        return S_OK;
    }
    return null;
}
