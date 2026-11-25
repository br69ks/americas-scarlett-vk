//! Recursive PE module loader.
//!
//! Loads the executable and its DLL dependencies, registers exports, patches
//! each module's IAT, sets up per-module TLS, and calls TLS callbacks and
//! DllMain.  Import resolution prefers the real shipped DLL (notably the MSVC
//! runtime) and falls back to the built-in shims.

const std = @import("std");
const builtin = @import("builtin");
const pe_loader = @import("pe_loader.zig");
const module = @import("module.zig");
const teb = @import("teb.zig");
const crt_core = @import("shims/crt_core.zig");
const xmem = @import("shims/xmem.zig");
const dstorage = @import("shims/dstorage.zig");
const win32_fs = @import("shims/win32_fs.zig");
const sync_shims = @import("shims/sync_shims.zig");
const game_input = @import("shims/game_input.zig");
const registry = @import("shims/generated/registry.zig");
const crt_extra = @import("shims/crt_extra.zig");

const Allocator = std.mem.Allocator;
const DllMainFn = *const fn (usize, u32, ?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32;

const DLL_PROCESS_DETACH = 0;
const DLL_PROCESS_ATTACH = 1;
const DLL_THREAD_ATTACH = 2;
const DLL_THREAD_DETACH = 3;

const Ctx = struct {
    allocator: Allocator,
    io: std.Io,
};

var g_allocator: ?Allocator = null;
var g_io: ?std.Io = null;
var g_dirs: []const []const u8 = &.{};

pub fn init(allocator: Allocator, io: std.Io, dirs: []const []const u8) void {
    g_allocator = allocator;
    g_io = io;
    g_dirs = dirs;
    module.init(allocator);
    module.load_library_fn = &loadLibraryW;
    module.load_library_a_fn = &loadLibraryA;
    module.free_library_fn = &freeLibrary;
    module.thread_attach_fn = &threadAttach;
    module.thread_detach_fn = &threadDetach;
    module.resolve_shim_fn = &resolveShimByName;
}

pub const LoadedExe = struct {
    image: pe_loader.MappedImage,
    mod: *module.Module,
};

pub fn loadExecutable(allocator: Allocator, io: std.Io, path: []const u8) !LoadedExe {
    var ctx = Ctx{ .allocator = allocator, .io = io };
    var image = try pe_loader.mapImage(allocator, io, path);
    errdefer image.deinit();

    const exports = try loadExports(allocator, &image);
    const m = try module.register(
        allocator,
        path,
        std.fs.path.basename(path),
        image.base_addr,
        image.image_size,
        image.entry_point,
        image.base_addr + image.pdata_rva,
        image.pdata_size / @sizeOf(module.RuntimeFunction),
        exports,
        true,
    );

    setupTls(&image, m) catch |err| {
        std.log.err("TLS setup failed for {s}: {s}", .{ path, @errorName(err) });
    };

    _ = try pe_loader.patchImports(&image, .{
        .ctx = @ptrCast(&ctx),
        .resolve = &resolveImport,
        .arena = null,
        .allocator = allocator,
    });

    runTlsCallbacks(m, DLL_PROCESS_ATTACH);
    return .{ .image = image, .mod = m };
}

fn loadExports(allocator: Allocator, image: *const pe_loader.MappedImage) ![]module.Export {
    const pe_exports = try pe_loader.parseExports(allocator, image);
    defer allocator.free(pe_exports);
    const out = try allocator.alloc(module.Export, pe_exports.len);
    for (pe_exports, 0..) |e, i| {
        out[i] = .{ .name = e.name, .ordinal = e.ordinal, .rva = e.rva, .forwarder = e.forwarder };
    }
    return out;
}

fn setupTls(image: *const pe_loader.MappedImage, m: *module.Module) !void {
    m.tls_block = image.tls_block_addr;
    m.tls_callbacks = image.tls_callbacks;
    if (image.tls_block_addr == 0) return;
    const index = try teb.allocModuleTls(image.tls_block_addr);
    m.tls_index = index;
    if (image.tls_index_va != 0) {
        const idx_ptr: *u32 = @ptrFromInt(image.tls_index_va);
        idx_ptr.* = index;
    }
}

fn runTlsCallbacks(m: *module.Module, reason: u32) void {
    if (m.tls_callbacks == 0) return;
    const callbacks: [*]const usize = @ptrFromInt(m.tls_callbacks);
    var i: usize = 0;
    while (callbacks[i] != 0) : (i += 1) {
        if (i > 256) break;
        const f: DllMainFn = @ptrFromInt(callbacks[i]);
        _ = f(m.base, reason, null);
    }
}

fn callDllMain(m: *module.Module, reason: u32) void {
    if (m.entry == 0 or m.is_exe) return;
    const f: DllMainFn = @ptrFromInt(m.entry);
    _ = f(m.base, reason, null);
}

fn threadAttach() void {
    for (module.all()) |m| {
        runTlsCallbacks(m, DLL_THREAD_ATTACH);
        callDllMain(m, DLL_THREAD_ATTACH);
    }
}

fn threadDetach() void {
    var i = module.all().len;
    while (i > 0) {
        i -= 1;
        const m = module.all()[i];
        callDllMain(m, DLL_THREAD_DETACH);
        runTlsCallbacks(m, DLL_THREAD_DETACH);
    }
}

fn shimResolve(dll: []const u8, name: ?[]const u8, ordinal: ?u16) ?usize {
    if (ordinal) |ord| {
        if (std.ascii.eqlIgnoreCase(dll, "gameinput.dll") and ord == 1) {
            return @intFromPtr(&game_input.shim_GameInputCreate);
        }
        return registry.resolve(dll, null, ord);
    }
    const n = name orelse return null;
    if (sync_shims.resolve(n)) |ptr| return ptr;
    if (crt_core.resolve(n)) |ptr| return ptr;
    if (crt_extra.resolve(n)) |ptr| return ptr;
    if (xmem.resolve(n)) |ptr| return ptr;
    if (dstorage.resolve(n)) |ptr| return ptr;
    if (win32_fs.resolve(n)) |ptr| return ptr;
    return registry.resolve(dll, n, null);
}

fn resolveShimByName(name: []const u8) ?usize {
    if (sync_shims.resolve(name)) |ptr| return ptr;
    if (crt_core.resolve(name)) |ptr| return ptr;
    if (crt_extra.resolve(name)) |ptr| return ptr;
    if (xmem.resolve(name)) |ptr| return ptr;
    if (dstorage.resolve(name)) |ptr| return ptr;
    if (win32_fs.resolve(name)) |ptr| return ptr;
    return null;
}

fn isShimPreferred(dll: []const u8) bool {
    const name = std.fs.path.basename(dll);
    const preferred = [_][]const u8{
        "kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll", "bcrypt.dll",
        "ws2_32.dll",   "winhttp.dll", "mfplat.dll", "mfreadwrite.dll", "xmem.dll",
        "chad.dll",     "xapu.dll",   "acphal.dll", "d3d12_xs.dll",   "xg_xs.dll",
        "xboxbvhbuilder.dll", "bink2scarlett.dll", "gameinput.dll", "xcrdapi.dll",
        "libhttpclient.gdk.dll", "amd_fidelityfx_loader_xbox.dll", "xgameruntime.dll",
    };
    for (preferred) |p| {
        if (std.ascii.eqlIgnoreCase(name, p)) return true;
    }
    return std.ascii.startsWithIgnoreCase(name, "api-ms-win-") or
        std.ascii.startsWithIgnoreCase(name, "ext-ms-win-");
}

fn pathExists(allocator: Allocator, path: []const u8) bool {
    const z = allocator.dupeSentinel(u8, path, 0) catch return false;
    defer allocator.free(z);
    const fp = std.c.fopen(z.ptr, "rb") orelse return false;
    _ = std.c.fclose(fp);
    return true;
}

fn findDllPath(allocator: Allocator, dll: []const u8) ?[]u8 {
    const base = std.fs.path.basename(dll);
    var candidates: [6][]const u8 = undefined;
    var n: usize = 0;
    candidates[n] = base;
    n += 1;
    var lower_buf: [256]u8 = undefined;
    if (base.len <= lower_buf.len) {
        for (base, 0..) |c, i| lower_buf[i] = std.ascii.toLower(c);
        candidates[n] = lower_buf[0..base.len];
        n += 1;
    }

    for (g_dirs) |dir| {
        for (candidates[0..n]) |cand| {
            const joined = std.fs.path.join(allocator, &.{ dir, cand }) catch continue;
            if (pathExists(allocator, joined)) return joined;
            allocator.free(joined);
            if (!std.mem.endsWith(u8, cand, ".dll") and !std.mem.endsWith(u8, cand, ".DLL")) {
                const with_ext = std.fmt.allocPrint(allocator, "{s}.dll", .{cand}) catch continue;
                defer allocator.free(with_ext);
                const p = std.fs.path.join(allocator, &.{ dir, with_ext }) catch continue;
                if (pathExists(allocator, p)) return p;
                allocator.free(p);
            }
        }
    }
    return null;
}

fn resolveImport(ctx_ptr: *anyopaque, dll: []const u8, name: ?[]const u8, ordinal: ?u16) ?usize {
    // Already-loaded modules (including the module currently being patched)
    // satisfy cyclic imports.
    if (module.resolveImport(dll, name, ordinal)) |ptr| return ptr;

    if (!isShimPreferred(dll)) {
        if (findDllPath(module.defaultAllocator(), dll)) |path| {
            defer module.defaultAllocator().free(path);
            const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr));
            const m = loadModulePath(ctx, path, false) catch |err| {
                std.log.warn("[LOAD] {s} failed: {s}; falling back to shims", .{ path, @errorName(err) });
                return shimResolve(dll, name, ordinal);
            };
            if (module.getProcAddress(m.base, name, ordinal, 0)) |ptr| return ptr;
            std.log.warn("[LOAD] {s} has no export for {s}!{s}", .{
                path, dll, name orelse "ordinal",
            });
        }
    }
    return shimResolve(dll, name, ordinal);
}

fn loadModulePath(ctx: *Ctx, path: []const u8, is_exe: bool) !*module.Module {
    const base_name = std.fs.path.basename(path);
    if (module.findByName(base_name)) |existing| {
        existing.refcount += 1;
        return existing;
    }

    var image = try pe_loader.mapImage(ctx.allocator, ctx.io, path);
    const exports = try loadExports(ctx.allocator, &image);
    const m = try module.register(
        ctx.allocator,
        path,
        base_name,
        image.base_addr,
        image.image_size,
        image.entry_point,
        image.base_addr + image.pdata_rva,
        image.pdata_size / @sizeOf(module.RuntimeFunction),
        exports,
        is_exe,
    );

    setupTls(&image, m) catch |err| {
        std.log.warn("[LOAD] TLS setup failed for {s}: {s}", .{ path, @errorName(err) });
    };

    _ = try pe_loader.patchImports(&image, .{
        .ctx = @ptrCast(ctx),
        .resolve = &resolveImport,
        .arena = null,
        .allocator = ctx.allocator,
    });

    if (!is_exe) {
        std.log.info("[LOAD] {s} mapped at 0x{x}, entry=0x{x}", .{ path, m.base, m.entry });
        runTlsCallbacks(m, DLL_PROCESS_ATTACH);
        callDllMain(m, DLL_PROCESS_ATTACH);
        std.log.info("[LOAD] {s} loaded at 0x{x}", .{ path, m.base });
    }
    return m;
}

fn nameFromW(allocator: Allocator, name: [*:0]const u16) ?[]u8 {
    return std.unicode.utf16LeToUtf8AllocZ(allocator, std.mem.span(name)) catch null;
}

fn loadLibraryW(name: [*:0]const u16) usize {
    const allocator = g_allocator orelse return 0;
    const io = g_io orelse return 0;
    const utf8 = nameFromW(allocator, name) orelse return 0;
    defer allocator.free(utf8);
    return loadLibraryByName(allocator, io, utf8);
}

fn loadLibraryA(name: [*:0]const u8) usize {
    const allocator = g_allocator orelse return 0;
    const io = g_io orelse return 0;
    return loadLibraryByName(allocator, io, std.mem.span(name));
}

fn loadLibraryByName(allocator: Allocator, io: std.Io, name: []const u8) usize {
    if (module.findByName(name)) |m| {
        m.refcount += 1;
        return m.base;
    }
    if (isShimPreferred(name)) return 0x7FFE_0000;
    const path = if (std.mem.indexOfAny(u8, name, "/\\") != null)
        allocator.dupe(u8, name) catch return 0
    else
        findDllPath(allocator, name) orelse return 0;
    defer allocator.free(path);
    var ctx = Ctx{ .allocator = allocator, .io = io };
    const m = loadModulePath(&ctx, path, false) catch |err| {
        std.log.err("[LOAD] LoadLibrary({s}) failed: {s}", .{ name, @errorName(err) });
        return 0;
    };
    return m.base;
}

fn freeLibrary(base: usize) i32 {
    return module.release(base);
}

pub fn getProcAddress(base: usize, name: ?[]const u8, ordinal: ?u16) ?usize {
    return module.getProcAddress(base, name, ordinal, 0);
}

pub fn processDetach() void {
    var i = module.all().len;
    while (i > 0) {
        i -= 1;
        const m = module.all()[i];
        callDllMain(m, DLL_PROCESS_DETACH);
        runTlsCallbacks(m, DLL_PROCESS_DETACH);
    }
}
