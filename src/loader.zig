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
const wsa = @import("shims/wsa.zig");
const d3d12_xs = @import("shims/d3d12_xs.zig");
const host_imports = @import("host_imports.zig");
const loader_lock = @import("loader_lock.zig");

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
var g_arena: ?pe_loader.TrampolineArena = null;

fn arenaPtr() ?*pe_loader.TrampolineArena {
    if (g_arena) |*a| return a;
    return null;
}

pub fn wrapGuestFunction(ptr: usize) ?usize {
    if (builtin.os.tag != .windows or module.findByAddress(ptr) != null) return null;
    const a = arenaPtr() orelse return null;
    return a.emitThunk(ptr) catch null;
}

pub fn refreshGuestTls() void {
    if (builtin.os.tag != .windows) return;
    for (module.all()) |m| {
        if (m.tls_index != 0 and m.tls_block != 0) teb.setModuleTlsCurrent(@intCast(m.tls_index), m.tls_block, m.tls_block_size);
    }
}

pub fn init(allocator: Allocator, io: std.Io, dirs: []const []const u8) void {
    host_imports.g_game_dir = if (dirs.len > 0) dirs[0] else "";
    g_allocator = allocator;
    g_io = io;
    g_dirs = dirs;
    module.init(allocator);
    module.load_library_fn = &loadLibraryW;
    module.load_library_a_fn = &loadLibraryA;
    module.free_library_fn = &freeLibrary;
    module.thread_attach_fn = &threadAttach;
    module.thread_detach_fn = &threadDetach;
    g_arena = pe_loader.TrampolineArena.init(1024 * 1024) catch null;
    crt_core.wrap_guest_fn = &wrapGuestFunction;
    module.resolve_shim_fn = &resolveShimByName;
}

pub const LoadedExe = struct {
    image: pe_loader.MappedImage,
    mod: *module.Module,
};

pub fn loadExecutable(allocator: Allocator, io: std.Io, path: []const u8, display_path: []const u8) !LoadedExe {
    loader_lock.lock();
    defer loader_lock.unlock();
    var ctx = Ctx{ .allocator = allocator, .io = io };
    var image = try pe_loader.mapImage(allocator, io, path);
    errdefer image.deinit();
    teb.setProcessStackSizes(image.stack_reserve, image.stack_commit);

    const exports = try loadExports(allocator, &image);
    const m = try module.register(
        allocator,
        path,
        display_path,
        std.fs.path.basename(display_path),
        image.base_addr,
        image.image_size,
        image.entry_point,
        image.base_addr + image.pdata_rva,
        image.pdata_size / @sizeOf(module.RuntimeFunction),
        exports,
        true,
    );
    m.host_mode = isHostModeDll(std.fs.path.basename(path));

    setupTls(&image, m) catch |err| {
        std.log.err("TLS setup failed for {s}: {s}", .{ path, @errorName(err) });
    };

    _ = try pe_loader.patchImports(&image, .{
        .ctx = @ptrCast(&ctx),
        .resolve = &resolveImport,
        .arena = arenaPtr(),
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
    m.tls_block_size = image.tls_block_size;
    m.tls_callbacks = image.tls_callbacks;
    if (image.tls_block_addr == 0) return;
    const index = try teb.allocModuleTls(image.tls_block_addr, image.tls_block_size);
    m.tls_index = index;
    // The `_tls_index` slot lives inside the mapped image.  Never write
    // through a bogus relocation/TLS-directory value.
    if (image.tls_index_va != 0 and
        image.tls_index_va >= image.base_addr and
        image.tls_index_va + @sizeOf(u32) <= image.base_addr + image.image_size and
        image.tls_index_va % @alignOf(u32) == 0)
    {
        const idx_ptr: *u32 = @ptrFromInt(image.tls_index_va);
        idx_ptr.* = index;
    } else {
        std.log.warn("[TLS] {s}: ignoring out-of-image _tls_index VA 0x{x}", .{ m.name, image.tls_index_va });
    }
}

fn runTlsCallbacks(m: *module.Module, reason: u32) void {
    if (m.tls_callbacks == 0) return;
    const callbacks: [*]const usize = @ptrFromInt(m.tls_callbacks);
    if (!m.host_mode) {
        teb.enterGuest();
        defer teb.leaveGuest();
    }
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
    if (!m.host_mode) {
        teb.enterGuest();
        defer teb.leaveGuest();
    }
    _ = f(m.base, reason, null);
}

fn threadAttach() void {
    loader_lock.lock();
    defer loader_lock.unlock();
    for (module.all()) |m| {
        runTlsCallbacks(m, DLL_THREAD_ATTACH);
        callDllMain(m, DLL_THREAD_ATTACH);
    }
}

fn threadDetach() void {
    loader_lock.lock();
    defer loader_lock.unlock();
    var i = module.all().len;
    while (i > 0) {
        i -= 1;
        const m = module.all()[i];
        callDllMain(m, DLL_THREAD_DETACH);
        runTlsCallbacks(m, DLL_THREAD_DETACH);
    }
}

fn shimResolve(dll: []const u8, name: ?[]const u8, ordinal: ?u16) ?usize {
    if (host_imports.resolve(dll, name, ordinal)) |ptr| return ptr;
    if (ordinal) |ord| {
        if (std.ascii.eqlIgnoreCase(dll, "gameinput.dll") and ord == 1) {
            return @intFromPtr(&game_input.shim_GameInputCreate);
        }
        if (wsa.resolveOrdinal(dll, ord)) |ptr| return ptr;
        return registry.resolve(dll, null, ord);
    }
    const n = name orelse return null;
    if (sync_shims.resolve(n)) |ptr| return ptr;
    if (crt_core.resolve(n)) |ptr| return ptr;
    if (crt_extra.resolve(n)) |ptr| return ptr;
    if (xmem.resolve(n)) |ptr| return ptr;
    if (dstorage.resolve(n)) |ptr| return ptr;
    if (win32_fs.resolve(n)) |ptr| return ptr;
    if (wsa.resolve(n)) |ptr| return ptr;
    if (d3d12_xs.resolve(n)) |ptr| return ptr;
    return registry.resolve(dll, n, null);
}

fn resolveShimByName(name: []const u8) ?usize {
    if (sync_shims.resolve(name)) |ptr| return ptr;
    if (crt_core.resolve(name)) |ptr| return ptr;
    if (crt_extra.resolve(name)) |ptr| return ptr;
    if (xmem.resolve(name)) |ptr| return ptr;
    if (dstorage.resolve(name)) |ptr| return ptr;
    if (win32_fs.resolve(name)) |ptr| return ptr;
    if (d3d12_xs.resolve(name)) |ptr| return ptr;
    return null;
}

fn isShimPreferred(dll: []const u8) bool {
    const name = std.fs.path.basename(dll);
    const preferred = [_][]const u8{
        "kernel32.dll",                   "ntdll.dll",         "user32.dll",    "advapi32.dll",    "bcrypt.dll",
        "ws2_32.dll",                     "winhttp.dll",       "mfplat.dll",    "mfreadwrite.dll", "xmem.dll",
        "chad.dll",                       "xapu.dll",          "acphal.dll",    "d3d12_xs.dll",    "xg_xs.dll",
        "xboxbvhbuilder.dll",             "bink2scarlett.dll", "gameinput.dll", "xcrdapi.dll",     "libhttpclient.gdk.dll",
        "amd_fidelityfx_loader_xbox.dll", "xgameruntime.dll",
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

fn isHostModeDll(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "vcruntime140.dll") or
        std.ascii.eqlIgnoreCase(name, "vcruntime140_1.dll");
}

fn resolveImport(ctx_ptr: *anyopaque, dll: []const u8, name: ?[]const u8, ordinal: ?u16) ?usize {
    if (builtin.os.tag == .linux) {
        if (name) |n| {
            if (std.mem.eql(u8, n, "RtlCaptureContext") or std.mem.eql(u8, n, "RtlCaptureStackBackTrace")) {
                return shimResolve(dll, name, ordinal);
            }
        }
    }
    // On Linux, use the real guest UCRT for CRT API-set imports so UCRT can
    // initialize per-thread CRT state itself.
    if (builtin.os.tag == .linux and
        (std.mem.startsWith(u8, dll, "api-ms-win-crt-") or
            std.mem.startsWith(u8, dll, "api-ms-win-core-rtlsupport")))
    {
        const mm_opt: ?*module.Module = module.findByName("ucrtbase.dll") orelse blk: {
            const path = findDllPath(module.defaultAllocator(), "ucrtbase.dll") orelse break :blk null;
            defer module.defaultAllocator().free(path);
            const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr));
            break :blk loadModulePath(ctx, path, false) catch null;
        };
        if (mm_opt) |mm| {
            if (std.mem.startsWith(u8, dll, "api-ms-win-core-rtlsupport")) {
                if (name) |n| {
                    if (std.mem.eql(u8, n, "RtlCaptureContext") or std.mem.eql(u8, n, "RtlCaptureStackBackTrace")) return shimResolve(dll, name, ordinal);
                    if (module.getProcAddress(mm.base, n, ordinal, 0)) |ptr| {
                        const target_rva = std.mem.readInt(u32, @as([*]const u8, @ptrFromInt(ptr))[0..4], .little);
                        if (target_rva >= 0x1000 and target_rva < 0x10000000) return mm.base + target_rva;
                    }
                }
            }
            if (module.getProcAddress(mm.base, name, ordinal, 0)) |ptr| return ptr;
        }
    }
    // On Windows, guest CRT state must not come from host ucrtbase.
    if (builtin.os.tag == .windows) {
        if (name) |n| {
            if (crt_core.resolve(n)) |ptr| return ptr;
        }
    }
    // Windows host DLLs must not be guest-mapped.
    if (host_imports.resolve(dll, name, ordinal)) |ptr| return ptr;
    if (builtin.os.tag == .windows and host_imports.isHostDll(dll)) {
        std.log.warn("[HOST] {s} could not be resolved from host; guest fallback", .{dll});
    }
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
    loader_lock.lock();
    defer loader_lock.unlock();
    const base_name = std.fs.path.basename(path);
    if (module.findByName(base_name)) |existing| {
        existing.refcount += 1;
        return existing;
    }

    var image = try pe_loader.mapImage(ctx.allocator, ctx.io, path);
    const exports = try loadExports(ctx.allocator, &image);
    const virtual_path = try std.fmt.allocPrint(ctx.allocator, "G:\\{s}", .{base_name});
    const m = try module.register(
        ctx.allocator,
        path,
        virtual_path,
        base_name,
        image.base_addr,
        image.image_size,
        image.entry_point,
        image.base_addr + image.pdata_rva,
        image.pdata_size / @sizeOf(module.RuntimeFunction),
        exports,
        is_exe,
    );
    m.host_mode = isHostModeDll(std.fs.path.basename(path));

    _ = try pe_loader.patchImports(&image, .{
        .ctx = @ptrCast(ctx),
        .resolve = &resolveImport,
        .arena = arenaPtr(),
        .allocator = ctx.allocator,
    });

    setupTls(&image, m) catch |err| {
        std.log.warn("[LOAD] TLS setup failed for {s}: {s}", .{ path, @errorName(err) });
    };

    if (!is_exe) {
        std.log.info("[LOAD] {s} mapped at 0x{x}, entry=0x{x}", .{ path, m.base, m.entry });
        std.log.info("[LOAD] {s} TLS callbacks", .{path});
        runTlsCallbacks(m, DLL_PROCESS_ATTACH);
        std.log.info("[LOAD] {s} DllMain", .{path});
        callDllMain(m, DLL_PROCESS_ATTACH);
        std.log.info("[LOAD] {s} DllMain returned", .{path});
        std.log.info("[LOAD] {s} loaded at 0x{x}", .{ path, m.base });
    }
    return m;
}

fn nameFromW(allocator: Allocator, name: [*:0]const u16) ?[]u8 {
    // No NUL sentinel is needed by loadLibraryByName, and the exact-size
    // allocation lets the caller free it with allocator.free without a
    // DebugAllocator length mismatch.
    return std.unicode.utf16LeToUtf8Alloc(allocator, std.mem.span(name)) catch null;
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

fn isCryptoDll(name: []const u8) bool {
    const base = std.fs.path.basename(name);
    return std.ascii.eqlIgnoreCase(base, "bcrypt.dll") or
        std.ascii.eqlIgnoreCase(base, "bcryptprimitives.dll") or
        std.ascii.eqlIgnoreCase(base, "ncrypt.dll") or
        std.ascii.eqlIgnoreCase(base, "crypt32.dll");
}

fn loadLibraryByName(allocator: Allocator, io: std.Io, name: []const u8) usize {
    loader_lock.lock();
    defer loader_lock.unlock();
    if (builtin.os.tag == .windows and host_imports.isHostDll(name)) {
        if (host_imports.loadLibrary(name)) |base| {
            std.log.info("[LOAD] host {s} at 0x{x}", .{ name, base });
            return base;
        }
    }
    if (module.findByName(name)) |m| {
        m.refcount += 1;
        return m.base;
    }
    if (isCryptoDll(name)) std.log.info("[LOAD] LoadLibrary(\"{s}\")", .{name});
    if (isShimPreferred(name)) {
        if (isCryptoDll(name)) std.log.info("[LOAD] {s} -> shim pseudo handle 0x7FFE0000", .{name});
        return 0x7FFE_0000;
    }
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
    loader_lock.lock();
    defer loader_lock.unlock();
    return module.release(base);
}

pub fn getProcAddress(base: usize, name: ?[]const u8, ordinal: ?u16) ?usize {
    return module.getProcAddress(base, name, ordinal, 0);
}

pub fn processDetach() void {
    loader_lock.lock();
    defer loader_lock.unlock();
    var i = module.all().len;
    while (i > 0) {
        i -= 1;
        const m = module.all()[i];
        callDllMain(m, DLL_PROCESS_DETACH);
        runTlsCallbacks(m, DLL_PROCESS_DETACH);
    }
}
