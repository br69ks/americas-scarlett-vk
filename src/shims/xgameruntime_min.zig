//! Minimal xgameruntime providers: task queue/XAsync, XPackage and
//! persistent local storage.  Semantics are completed synchronously; every
//! method whose behavior is unknown is fail-closed.

const std = @import("std");

const HRESULT = i32;
const S_OK: HRESULT = 0;
const E_NOTIMPL: HRESULT = @bitCast(@as(u32, 0x8000_4001));
const E_INVALIDARG: HRESULT = @bitCast(@as(u32, 0x8007_0057));
const E_FAIL: HRESULT = @bitCast(@as(u32, 0x8000_4005));
const E_NOINTERFACE: HRESULT = @bitCast(@as(u32, 0x8000_4002));
const E_ABORT: HRESULT = @bitCast(@as(u32, 0x8000_4004));
const E_OUTOFMEMORY: HRESULT = @bitCast(@as(u32, 0x8007_000E));
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

const CompletionFn = *const fn (*AsyncBlock) callconv(.{ .x86_64_win = .{} }) void;

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

// ---------------------------------------------------------------------------
// XAsync
// ---------------------------------------------------------------------------

fn complete(block: *AsyncBlock, hr: HRESULT, size: usize) void {
    block.internal[1] = 2;
    block.internal[2] = @as(u32, @bitCast(hr));
    block.internal[3] = size;
    if (block.callback != 0) {
        const cb: CompletionFn = @ptrFromInt(block.callback);
        cb(block);
    }
}

// ---------------------------------------------------------------------------
// GDK runtime version
// ---------------------------------------------------------------------------

pub const SUPPORTED_GDK_BUILD: u32 = 26100;
pub const SUPPORTED_GDK_VERSION: u64 = 0x65f4_0000_1edd;
pub const CO_E_NOTINITIALIZED: HRESULT = @bitCast(@as(u32, 0x8004_01F0));

var g_gdk_version: u64 = 0;
var g_gdk_build: u32 = 0;
var g_gdk_initialized: bool = false;

/// Accept only the GRDK build this HLE models (261000 / build 26100).
/// Any other build fails closed; QueryApiImpl refuses to hand out providers
/// until a supported InitializeApiImpl* call has happened.
pub fn initialize(version: u64) HRESULT {
    const build: u32 = @truncate(version >> 32);
    if (build != SUPPORTED_GDK_BUILD) {
        std.log.warn("[GDK] unsupported runtime version 0x{x} (build {d}); supported build {d}", .{
            version, build, SUPPORTED_GDK_BUILD,
        });
        g_gdk_initialized = false;
        g_gdk_build = 0;
        g_gdk_version = 0;
        return E_FAIL;
    }
    g_gdk_initialized = true;
    g_gdk_build = build;
    g_gdk_version = version;
    std.log.info("[GDK] runtime initialized: version=0x{x} build={d}", .{ version, build });
    return S_OK;
}

pub fn uninitialize() void {
    g_gdk_initialized = false;
    g_gdk_build = 0;
    g_gdk_version = 0;
}

pub fn isInitialized() bool {
    return g_gdk_initialized;
}
pub fn gdkBuild() u32 {
    return g_gdk_build;
}
pub fn resetForTest() void {
    uninitialize();
}

// ---------------------------------------------------------------------------
// XPackage (261000 XPackage.h declaration order)
// ---------------------------------------------------------------------------

const Progress = extern struct { total: u64, installed: u64, launch: u64, launchable: bool, completed: bool };
const WriteStats = extern struct { interval: u64, budget: u64, elapsed: u64, bytes_written: u64 };
const Details = extern struct {
    package_identifier: [*:0]const u8,
    version: u64, // XVersion union (major, minor, build, revision)
    kind: u32, // XPackageKind: Game=0
    display_name: [*:0]const u8,
    description: [*:0]const u8,
    publisher: [*:0]const u8,
    store_id: [*:0]const u8,
    installing: bool,
    index: u32,
    count: u32,
    age_restricted: bool,
    title_id: [*:0]const u8,
};

const CURRENT_ID = "7952987A";
const DISPLAY_NAME = "Grand Theft Auto VI";
const PUBLISHER = "Rockstar Games";
const STORE_ID = "9NL3WWNZLZZN";
const TITLE_ID = "7952987A";
const EMPTY = "";
const LOCALE = "en-US";
const X_VERSION_1_0_2_1: u64 = 0x0001_0002_0000_0001; // major=1, minor=0, build=2, revision=1
const CHUNK_UNAVAILABLE: u32 = 3;

const Mount = struct { path: [8]u8 };

fn mountCreate() ?*Mount {
    const m = std.heap.page_allocator.create(Mount) catch return null;
    m.* = .{ .path = .{ 'G', ':', '\\', 0, 0, 0, 0, 0 } };
    return m;
}

fn isCurrentId(id: ?[*:0]const u8) bool {
    const text = id orelse return false;
    return std.mem.eql(u8, std.mem.span(text), CURRENT_ID);
}

var g_monitor: u8 = 0;

fn pCurrentId(_: *Object, size: usize, buffer: ?[*]u8) callconv(.{ .x86_64_win = .{} }) HRESULT {
    const out = buffer orelse return E_INVALIDARG;
    if (size <= CURRENT_ID.len) return E_FAIL;
    @memcpy(out[0..CURRENT_ID.len], CURRENT_ID);
    out[CURRENT_ID.len] = 0;
    return S_OK;
}
fn pPackaged(_: *Object) callconv(.{ .x86_64_win = .{} }) bool {
    return true;
}
fn pCreateMonitor(_: *Object, id: ?[*:0]const u8, count: u32, sel: ?*const anyopaque, ms: u32, q: ?*anyopaque, out: ?*?*const anyopaque) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = count;
    _ = sel;
    _ = ms;
    _ = q;
    if (!isCurrentId(id)) return E_INVALIDARG;
    const o = out orelse return E_INVALIDARG;
    o.* = &g_monitor;
    return S_OK;
}
fn pCloseMonitor(_: *Object, m: ?*const anyopaque) callconv(.{ .x86_64_win = .{} }) void {
    _ = m;
}
fn pProgress(_: *Object, m: ?*const anyopaque, out: ?*Progress) callconv(.{ .x86_64_win = .{} }) void {
    _ = m;
    if (out) |o| o.* = .{ .total = 1, .installed = 1, .launch = 1, .launchable = true, .completed = true };
}
fn pUpdateMonitor(_: *Object, m: ?*const anyopaque) callconv(.{ .x86_64_win = .{} }) bool {
    _ = m;
    return true;
}
fn pRegisterProgress(_: *Object, m: ?*const anyopaque, ctx: ?*anyopaque, cb: ?*anyopaque, out: ?*u64) callconv(.{ .x86_64_win = .{} }) HRESULT {
    const callback = cb orelse return E_INVALIDARG;
    const monitor = m orelse return E_INVALIDARG;
    // Installation progress is already complete, so invoke the callback once
    // instead of pretending a future notification exists.
    const f: *const fn (?*anyopaque, ?*const anyopaque) callconv(.{ .x86_64_win = .{} }) void = @ptrCast(callback);
    f(ctx, monitor);
    if (out) |o| o.* = 1;
    return S_OK;
}
fn pUnregisterProgress(_: *Object, m: ?*const anyopaque, token: u64, wait: bool) callconv(.{ .x86_64_win = .{} }) bool {
    _ = m;
    _ = token;
    _ = wait;
    return true;
}
fn pGetUserLocale(_: *Object, size: usize, buffer: ?[*]u8) callconv(.{ .x86_64_win = .{} }) HRESULT {
    const out = buffer orelse return E_INVALIDARG;
    if (size < LOCALE.len + 1) return E_FAIL;
    @memcpy(out[0..LOCALE.len], LOCALE);
    out[LOCALE.len] = 0;
    return S_OK;
}
fn pAvailability(_: *Object, id: ?[*:0]const u8, count: u32, sel: ?*const anyopaque, out: ?*u32) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = count;
    _ = sel;
    const result = out orelse return E_INVALIDARG;
    if (id == null) return E_INVALIDARG;
    // The current game package is fully installed; no content package is
    // known to this loader, so unknown identifiers are Unavailable.
    result.* = if (isCurrentId(id)) 0 else CHUNK_UNAVAILABLE;
    return S_OK;
}
fn pEnumerateChunkAvailability(_: *Object, id: ?[*:0]const u8, typ: u32, ctx: ?*anyopaque, cb: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = id;
    _ = typ;
    _ = ctx;
    _ = cb;
    // No chunk metadata is available; do not fake an enumeration.
    return E_NOTIMPL;
}
fn pChangeOrder(_: *Object, id: ?[*:0]const u8, count: u32, sel: ?*const anyopaque) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = count;
    _ = sel;
    if (!isCurrentId(id)) return NO_PACKAGE;
    return S_OK;
}
fn pInstallChunks(_: *Object, id: ?[*:0]const u8, count: u32, sel: ?*const anyopaque, ms: u32, suppress: bool, out: ?*?*const anyopaque) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = id;
    _ = count;
    _ = sel;
    _ = ms;
    _ = suppress;
    _ = out;
    // No content installation support.
    return E_NOTIMPL;
}
fn pInstallAsync(_: *Object, id: ?[*:0]const u8, count: u32, sel: ?*const anyopaque, ms: u32, suppress: bool, block: ?*AsyncBlock) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = count;
    _ = sel;
    _ = ms;
    _ = suppress;
    const b = block orelse return E_INVALIDARG;
    if (isCurrentId(id)) {
        complete(b, S_OK, 0);
    } else {
        complete(b, NO_PACKAGE, 0);
    }
    return S_OK;
}
fn pInstallResult(_: *Object, block: ?*AsyncBlock, out: ?*?*const anyopaque) callconv(.{ .x86_64_win = .{} }) HRESULT {
    const b = block orelse return E_INVALIDARG;
    const hr: HRESULT = @bitCast(@as(u32, @truncate(b.internal[2])));
    if (out) |o| o.* = if (hr == S_OK) &g_monitor else null;
    return hr;
}
fn pEstimate(_: *Object, id: ?[*:0]const u8, count: u32, sel: ?*const anyopaque, bytes: ?*u64, confirm: ?*bool) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = count;
    _ = sel;
    if (!isCurrentId(id)) return NO_PACKAGE;
    if (bytes) |b| b.* = 0;
    if (confirm) |c| c.* = false;
    return S_OK;
}
fn pUninstall(_: *Object, id: ?[*:0]const u8, count: u32, sel: ?*const anyopaque) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = count;
    _ = sel;
    if (id == null) return E_INVALIDARG;
    return if (isCurrentId(id)) E_NOTIMPL else NO_PACKAGE;
}

const EnumCallback = *const fn (?*anyopaque, *const Details) callconv(.{ .x86_64_win = .{} }) bool;

fn pEnumerate(_: *Object, kind: u32, scope: u32, ctx: ?*anyopaque, cb: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = scope;
    if (cb == null) return E_INVALIDARG;
    // XPackageKind.Game == 0.  Content/PublisherContent have no additional
    // packages in this install, so a successful empty enumeration is truthful.
    if (kind != 0) return S_OK;
    var details = Details{
        .package_identifier = CURRENT_ID,
        .version = X_VERSION_1_0_2_1,
        .kind = 0,
        .display_name = DISPLAY_NAME,
        .description = EMPTY,
        .publisher = PUBLISHER,
        .store_id = STORE_ID,
        .installing = false,
        .index = 0,
        .count = 1,
        .age_restricted = false,
        .title_id = TITLE_ID,
    };
    const callback: EnumCallback = @ptrCast(cb.?);
    return if (callback(ctx, &details)) S_OK else E_ABORT;
}
fn pGetPackageKind(_: *Object, id: ?[*:0]const u8, out: ?*u32) callconv(.{ .x86_64_win = .{} }) HRESULT {
    const result = out orelse return E_INVALIDARG;
    if (!isCurrentId(id)) return E_INVALIDARG;
    result.* = 0; // XPackageKind.Game
    return S_OK;
}
fn pRegisterPackageInstalled(_: *Object, q: ?*anyopaque, ctx: ?*anyopaque, cb: ?*anyopaque, token: ?*u64) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = q;
    _ = ctx;
    _ = cb;
    if (token) |t| t.* = 0;
    return E_NOTIMPL;
}
fn pUnregisterPackageInstalled(_: *Object, token: u64, wait: bool) callconv(.{ .x86_64_win = .{} }) bool {
    _ = token;
    _ = wait;
    return false;
}
fn pEnumerateFeatures(_: *Object, id: ?[*:0]const u8, ctx: ?*anyopaque, cb: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = id;
    _ = ctx;
    _ = cb;
    // No features are declared by this package.
    return S_OK;
}
fn pMount(_: *Object, id: ?[*:0]const u8, out: ?*?*const anyopaque) callconv(.{ .x86_64_win = .{} }) HRESULT {
    const result = out orelse return E_INVALIDARG;
    result.* = null;
    if (!isCurrentId(id)) return NO_PACKAGE;
    const mount = mountCreate() orelse return E_OUTOFMEMORY;
    result.* = mount;
    return S_OK;
}
fn pMountAsync(_: *Object, id: ?[*:0]const u8, block: ?*AsyncBlock) callconv(.{ .x86_64_win = .{} }) HRESULT {
    const b = block orelse return E_INVALIDARG;
    if (!isCurrentId(id)) {
        complete(b, NO_PACKAGE, 0);
        return S_OK;
    }
    const mount = mountCreate() orelse {
        complete(b, E_OUTOFMEMORY, 0);
        return S_OK;
    };
    complete(b, S_OK, @intFromPtr(mount));
    return S_OK;
}
fn pMountResult(_: *Object, block: ?*AsyncBlock, out: ?*?*const anyopaque) callconv(.{ .x86_64_win = .{} }) HRESULT {
    const b = block orelse return E_INVALIDARG;
    const hr: HRESULT = @bitCast(@as(u32, @truncate(b.internal[2])));
    if (hr != S_OK) {
        if (out) |o| o.* = null;
        return hr;
    }
    const ptr = b.internal[3];
    if (ptr == 0) {
        if (out) |o| o.* = null;
        return E_FAIL;
    }
    if (out) |o| o.* = @ptrFromInt(ptr);
    return S_OK;
}
fn pMountPathSize(_: *Object, m: ?*const anyopaque, size: ?*usize) callconv(.{ .x86_64_win = .{} }) HRESULT {
    if (m == null) return E_INVALIDARG;
    const out = size orelse return E_INVALIDARG;
    out.* = "G:\\".len + 1;
    return S_OK;
}
fn pMountPath(_: *Object, m: ?*const anyopaque, size: usize, buf: ?[*]u8) callconv(.{ .x86_64_win = .{} }) HRESULT {
    if (m == null) return E_INVALIDARG;
    const out = buf orelse return E_INVALIDARG;
    const path = "G:\\";
    if (size < path.len + 1) return E_FAIL;
    @memcpy(out[0..path.len], path);
    out[path.len] = 0;
    return S_OK;
}
fn pCloseMount(_: *Object, m: ?*const anyopaque) callconv(.{ .x86_64_win = .{} }) void {
    const mount: *Mount = @ptrCast(@alignCast(@constCast(m orelse return)));
    std.heap.page_allocator.destroy(mount);
}
fn pGetWriteStats(_: *Object, out: ?*WriteStats) callconv(.{ .x86_64_win = .{} }) HRESULT {
    if (out) |o| o.* = .{ .interval = 0, .budget = 0, .elapsed = 0, .bytes_written = 0 };
    return S_OK;
}
fn pUninstallUWPInstance(_: *Object, name: ?[*:0]const u8) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = name;
    return E_NOTIMPL;
}
fn pUninstallPackage(_: *Object, id: ?[*:0]const u8) callconv(.{ .x86_64_win = .{} }) bool {
    _ = id;
    return false;
}

// 64 slots: [0..2] IUnknown, [3..33] the 31 XPackage.h methods in declaration
// order, [34..63] fail-closed padding so an unexpected slot cannot run off the
// end of the table.
var package_vtbl = blk: {
    var table: [64]*const anyopaque = @splat(@ptrCast(&missing));
    const methods = [_]*const anyopaque{
        @ptrCast(&pCurrentId), // 1 GetCurrentProcessPackageIdentifier
        @ptrCast(&pPackaged), // 2 IsPackagedProcess
        @ptrCast(&pCreateMonitor), // 3 CreateInstallationMonitor
        @ptrCast(&pCloseMonitor), // 4 CloseInstallationMonitorHandle
        @ptrCast(&pProgress), // 5 GetInstallationProgress
        @ptrCast(&pUpdateMonitor), // 6 UpdateInstallationMonitor
        @ptrCast(&pRegisterProgress), // 7 RegisterInstallationProgressChanged
        @ptrCast(&pUnregisterProgress), // 8 UnregisterInstallationProgressChanged
        @ptrCast(&pGetUserLocale), // 9 GetUserLocale
        @ptrCast(&pAvailability), // 10 FindChunkAvailability
        @ptrCast(&pEnumerateChunkAvailability), // 11 EnumerateChunkAvailability
        @ptrCast(&pChangeOrder), // 12 ChangeChunkInstallOrder
        @ptrCast(&pInstallChunks), // 13 InstallChunks
        @ptrCast(&pInstallAsync), // 14 InstallChunksAsync
        @ptrCast(&pInstallResult), // 15 InstallChunksResult
        @ptrCast(&pEstimate), // 16 EstimateDownloadSize
        @ptrCast(&pUninstall), // 17 UninstallChunks
        @ptrCast(&pEnumerate), // 18 EnumeratePackages
        @ptrCast(&pGetPackageKind), // 19 GetPackageKind
        @ptrCast(&pRegisterPackageInstalled), // 20 RegisterPackageInstalled
        @ptrCast(&pUnregisterPackageInstalled), // 21 UnregisterPackageInstalled
        @ptrCast(&pEnumerateFeatures), // 22 EnumerateFeatures
        @ptrCast(&pMount), // 23 Mount (deprecated)
        @ptrCast(&pMountAsync), // 24 MountWithUiAsync
        @ptrCast(&pMountResult), // 25 MountWithUiResult
        @ptrCast(&pMountPathSize), // 26 GetMountPathSize
        @ptrCast(&pMountPath), // 27 GetMountPath
        @ptrCast(&pCloseMount), // 28 CloseMountHandle
        @ptrCast(&pGetWriteStats), // 29 GetWriteStats
        @ptrCast(&pUninstallUWPInstance), // 30 UninstallUWPInstance
        @ptrCast(&pUninstallPackage), // 31 UninstallPackage
    };
    table[0] = @ptrCast(&qi);
    table[1] = @ptrCast(&addRef);
    table[2] = @ptrCast(&release);
    @memcpy(table[3..34], &methods);
    break :blk table;
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
    @ptrCast(&qi),        @ptrCast(&addRef),        @ptrCast(&release),
    @ptrCast(&sPathSize), @ptrCast(&sPath),         @ptrCast(&sSpace),
    @ptrCast(&sPrompt),   @ptrCast(&sPromptResult),
};
const storage_obj = Object{ .lpVtbl = @ptrCast(&storage_vtbl) };

fn isIUnknown(g: *const Guid) bool {
    return g.d1 == 0 and g.d2 == 0 and g.d3 == 0 and
        std.mem.eql(u8, &g.d4, &[_]u8{ 0xC0, 0, 0, 0, 0, 0, 0, 0x46 });
}

fn riidMatches(riid: ?*const Guid, expected: *const Guid) bool {
    const r = riid orelse return false;
    if (isIUnknown(r)) return true;
    return eqGuid(r, expected.d1, expected.d2, expected.d3, expected.d4);
}

pub fn queryApi(clsid: ?*const Guid, riid: ?*const Guid, ppv: ?*?*anyopaque) ?HRESULT {
    const c = clsid orelse return null;
    if (ppv) |out| out.* = null;
    if (eqGuid(c, XASYNC.d1, XASYNC.d2, XASYNC.d3, XASYNC.d4)) {
        // No XAsync provider object is implemented; the flat XAsync APIs are
        // not claimed either.  Report the truth instead of handing out a
        // guessed vtable.
        return E_NOINTERFACE;
    }
    if (eqGuid(c, XPACKAGE.d1, XPACKAGE.d2, XPACKAGE.d3, XPACKAGE.d4)) {
        if (!riidMatches(riid, &XPACKAGE_IID)) return E_NOINTERFACE;
        if (ppv) |out| out.* = @ptrCast(@constCast(&package_obj));
        return S_OK;
    }
    if (eqGuid(c, STORAGE.d1, STORAGE.d2, STORAGE.d3, STORAGE.d4)) {
        if (!riidMatches(riid, &STORAGE_IID)) return E_NOINTERFACE;
        if (ppv) |out| out.* = @ptrCast(@constCast(&storage_obj));
        return S_OK;
    }
    return null;
}
