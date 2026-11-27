//! Minimal AcpHal/APU object: the console audio device, its heap and
//! coprocessor message queue. DSP/XMA are deliberately not emulated.

const std = @import("std");

const HRESULT = i32;
const E_NOTIMPL: HRESULT = @bitCast(@as(u32, 0x8000_4001));

/// Audio is intentionally disabled in this milestone.  AcpHalCreate fails
/// cleanly so the engine can disable audio; it never returns a half-working
/// object whose XApu* command path is still a fail-closed stub.
pub fn acpHalCreate(out: ?*?*anyopaque) callconv(.{ .x86_64_win = .{} }) HRESULT {
    if (out) |o| o.* = null;
    std.log.info("[AUDIO] AcpHalCreate -> E_NOTIMPL (audio disabled in this milestone)", .{});
    return E_NOTIMPL;
}

pub fn isAudioEnabled() bool {
    return false;
}

// ---------------------------------------------------------------------------
// APU heap
// ---------------------------------------------------------------------------

const Block = struct { ptr: usize, apu: u32, size: usize };
var g_blocks: [256]Block = undefined;
var g_block_count: usize = 0;
var g_heap_lock = std.atomic.Value(u32).init(0);

fn lockHeap() void {
    while (g_heap_lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
        while (g_heap_lock.load(.monotonic) != 0) std.atomic.spinLoopHint();
    }
}
fn unlockHeap() void {
    g_heap_lock.store(0, .release);
}

pub fn apuCreateHeap(cached: u32, non_cached: u32) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = cached;
    _ = non_cached;
    return E_NOTIMPL; // audio disabled with AcpHalCreate
}

pub fn apuAlloc(out: ?*?*anyopaque, apu: ?*u32, size: u32, alignment: u32, flags: u32) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = flags;
    _ = size;
    _ = alignment;
    if (out) |o| o.* = null;
    if (apu) |a| a.* = 0;
    return E_NOTIMPL; // audio disabled with AcpHalCreate
}

pub fn apuFree(ptr: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) void {
    const p = @intFromPtr(ptr orelse return);
    lockHeap();
    var i: usize = 0;
    while (i < g_block_count) : (i += 1) {
        if (g_blocks[i].ptr == p) {
            const size = g_blocks[i].size;
            g_block_count -= 1;
            g_blocks[i] = g_blocks[g_block_count];
            unlockHeap();
            const buf: [*]u8 = @ptrFromInt(p);
            std.heap.page_allocator.free(buf[0..size]);
            return;
        }
    }
    unlockHeap();
}

pub fn apuMapVirtualAddress(ptr: ?*const anyopaque) callconv(.{ .x86_64_win = .{} }) u32 {
    const p = @intFromPtr(ptr orelse return 0);
    lockHeap();
    defer unlockHeap();
    for (g_blocks[0..g_block_count]) |b| {
        if (p >= b.ptr and p < b.ptr + b.size) return b.apu + @as(u32, @intCast(p - b.ptr));
    }
    return 0;
}

pub fn apuMapApuAddress(addr: u32) callconv(.{ .x86_64_win = .{} }) ?*anyopaque {
    lockHeap();
    defer unlockHeap();
    for (g_blocks[0..g_block_count]) |b| {
        if (addr >= b.apu and addr < b.apu + b.size) return @ptrFromInt(b.ptr + (addr - b.apu));
    }
    return null;
}

pub fn apuValid(ptr: ?*const anyopaque, alignment: u32) callconv(.{ .x86_64_win = .{} }) bool {
    const a = apuMapVirtualAddress(ptr);
    return a != 0 and (alignment == 0 or a % alignment == 0);
}

// SHAPE contexts: six counts, arrays and APU addresses.
const ShapeContexts = extern struct {
    counts: [6]u32,
    arrays: [6]?*anyopaque,
    apu: [6]u32,
};

pub fn acpHalAllocateShapeContexts(ctx: ?*ShapeContexts) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = ctx;
    return E_NOTIMPL; // audio disabled with AcpHalCreate
}

pub fn acpHalReleaseShapeContexts() callconv(.{ .x86_64_win = .{} }) HRESULT {
    return E_NOTIMPL; // audio disabled with AcpHalCreate
}
