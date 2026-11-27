//! Loaded-module registry and per-module export lookup.
//!
//! This is deliberately independent of the PE loader so CRT shims can call
//! `GetProcAddress` without importing the loader (which imports the shims).

const std = @import("std");
const teb = @import("teb.zig");

pub const RuntimeFunction = extern struct {
    begin: u32,
    end: u32,
    unwind: u32,
};

pub const Export = struct {
    name: ?[]const u8,
    ordinal: u32,
    rva: u32,
    forwarder: ?[]const u8,
};

pub const Module = struct {
    name: []const u8, // lower-case base name, e.g. "msvcp140.dll"
    /// Host path (internal: loader search, diagnostics); never guest-visible.
    path: []const u8,
    /// Guest-visible module path (e.g. `G:\ucrtbase.dll`) reported through the
    /// PEB Ldr list and GetModuleFileName.
    virtual_path: []const u8,
    base: usize,
    size: usize,
    entry: usize,
    pdata_base: usize,
    pdata_count: usize,
    exports: []Export,
    tls_index: u32 = 0,
    host_mode: bool = false,
    tls_block: usize = 0,
    tls_block_size: usize = 0,
    tls_callbacks: usize = 0,
    is_exe: bool = false,
    refcount: u32 = 1,
    ldr: ?*teb.LDR_DATA_TABLE_ENTRY = null,
};

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

var g_modules: std.ArrayListUnmanaged(*Module) = .empty;
var g_lock: SpinLock = .{};
var g_allocator: ?std.mem.Allocator = null;

/// Hooks installed by the loader, called from crt_core without a module cycle.
pub var load_library_fn: ?*const fn (name_w: [*:0]const u16) usize = null;
pub var load_library_a_fn: ?*const fn (name: [*:0]const u8) usize = null;
pub var free_library_fn: ?*const fn (base: usize) i32 = null;
pub var thread_attach_fn: ?*const fn () void = null;
pub var thread_detach_fn: ?*const fn () void = null;
pub var resolve_shim_fn: ?*const fn (name: []const u8) ?usize = null;

pub fn init(allocator: std.mem.Allocator) void {
    g_allocator = allocator;
}

pub fn defaultAllocator() std.mem.Allocator {
    return g_allocator orelse std.heap.page_allocator;
}

pub fn all() []*Module {
    return g_modules.items;
}

fn lowerDupe(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, text.len);
    for (text, 0..) |c, i| out[i] = std.ascii.toLower(c);
    return out;
}

pub fn register(
    allocator: std.mem.Allocator,
    path: []const u8,
    virtual_path: []const u8,
    display_name: []const u8,
    base: usize,
    size: usize,
    entry: usize,
    pdata_base: usize,
    pdata_count: usize,
    exports: []Export,
    is_exe: bool,
) !*Module {
    const m = try allocator.create(Module);
    m.* = .{
        .name = try lowerDupe(allocator, display_name),
        .path = try allocator.dupe(u8, path),
        .virtual_path = try allocator.dupe(u8, virtual_path),
        .base = base,
        .size = size,
        .entry = entry,
        .pdata_base = pdata_base,
        .pdata_count = pdata_count,
        .exports = exports,
        .is_exe = is_exe,
    };

    if (teb.process() != null) {
        m.ldr = try teb.addLdrEntry(allocator, base, entry, size, virtual_path, display_name);
    }

    g_lock.lock();
    defer g_lock.unlock();
    try g_modules.append(allocator, m);
    publishImageInfo(base, size, pdata_base, pdata_count);
    if (is_exe) teb.setImageBase(base);
    return m;
}

/// Minimal image description for lock-free PC -> image lookup.
pub const ImageInfo = extern struct {
    base: usize,
    end: usize,
    pdata_base: usize,
    pdata_count: usize,
};

pub const MAX_IMAGE_INFO = 256;
var g_image_info: [MAX_IMAGE_INFO]ImageInfo = undefined;
var g_image_count = std.atomic.Value(usize).init(0);

/// Publish an image range.  Called with `g_lock` held, so writers are
/// serialized; readers never take the lock.
fn publishImageInfo(base: usize, size: usize, pdata_base: usize, pdata_count: usize) void {
    const idx = g_image_count.load(.monotonic);
    if (idx >= MAX_IMAGE_INFO) return;
    g_image_info[idx] = .{
        .base = base,
        .end = base + size,
        .pdata_base = pdata_base,
        .pdata_count = pdata_count,
    };
    g_image_count.store(idx + 1, .release);
}

/// Lock-free "which loaded image contains this PC".  The x64 exception
/// dispatcher (and the Linux signal handler, which may interrupt a thread that
/// holds `g_lock`) must not take the module spinlock to answer this.
pub fn findImageInfo(addr: usize) ?*const ImageInfo {
    const n = g_image_count.load(.acquire);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const e = &g_image_info[i];
        if (addr >= e.base and addr < e.end) return e;
    }
    return null;
}

pub fn findByName(name: []const u8) ?*Module {
    const base_name = std.fs.path.basename(name);
    g_lock.lock();
    defer g_lock.unlock();
    for (g_modules.items) |m| {
        if (std.ascii.eqlIgnoreCase(m.name, base_name)) return m;
    }
    return null;
}

pub fn findByBase(base: usize) ?*Module {
    g_lock.lock();
    defer g_lock.unlock();
    for (g_modules.items) |m| {
        if (m.base == base) return m;
    }
    return null;
}

pub fn findByAddress(addr: usize) ?*Module {
    g_lock.lock();
    defer g_lock.unlock();
    for (g_modules.items) |m| {
        if (addr >= m.base and addr < m.base + m.size) return m;
    }
    return null;
}

pub fn lookupFunctionEntry(pc: usize) ?*const RuntimeFunction {
    const m = findByAddress(pc) orelse return null;
    if (m.pdata_base == 0 or m.pdata_count == 0) return null;
    const entries: [*]const RuntimeFunction = @ptrFromInt(m.pdata_base);
    const rva: u32 = @intCast(pc - m.base);
    var lo: usize = 0;
    var hi: usize = m.pdata_count;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const e = &entries[mid];
        if (rva < e.begin) {
            hi = mid;
        } else if (rva >= e.end) {
            lo = mid + 1;
        } else {
            return e;
        }
    }
    return null;
}

fn forwarderTarget(m: *Module, forwarder: []const u8, depth: u32) ?usize {
    if (depth > 8) return null;
    const dot = std.mem.lastIndexOfScalar(u8, forwarder, '.') orelse return null;
    const dll = forwarder[0..dot];
    const func = forwarder[dot + 1 ..];
    const target = findByName(dll) orelse return null;
    if (target == m) return null;
    return getProcAddress(target.base, func, null, depth + 1);
}

pub fn getProcAddress(base: usize, name: ?[]const u8, ordinal: ?u16, depth: u32) ?usize {
    const m = findByBase(base) orelse return null;
    if (name) |wanted| {
        for (m.exports) |e| {
            const n = e.name orelse continue;
            if (!std.mem.eql(u8, n, wanted)) continue;
            if (e.forwarder) |f| return forwarderTarget(m, f, depth);
            if (e.rva == 0) continue;
            return m.base + e.rva;
        }
        return null;
    }
    if (ordinal) |wanted| {
        for (m.exports) |e| {
            if (e.ordinal != wanted) continue;
            if (e.forwarder) |f| return forwarderTarget(m, f, depth);
            if (e.rva == 0) continue;
            return m.base + e.rva;
        }
    }
    return null;
}

pub fn resolveImport(dll: []const u8, name: ?[]const u8, ordinal: ?u16) ?usize {
    const m = findByName(dll) orelse return null;
    return getProcAddress(m.base, name, ordinal, 0);
}

/// Returns the number of bytes copied (excluding the terminator), or 0.
pub fn fileNameA(base: usize, out: [*]u8, cap: usize) usize {
    if (cap == 0) return 0;
    const m = findByBase(base) orelse {
        out[0] = 0;
        return 0;
    };
    const n = @min(m.virtual_path.len, cap - 1);
    @memcpy(out[0..n], m.virtual_path[0..n]);
    out[n] = 0;
    return n;
}

pub fn release(base: usize) i32 {
    g_lock.lock();
    defer g_lock.unlock();
    for (g_modules.items) |m| {
        if (m.base == base) {
            if (m.refcount > 0) m.refcount -= 1;
            return 1;
        }
    }
    return 0;
}
