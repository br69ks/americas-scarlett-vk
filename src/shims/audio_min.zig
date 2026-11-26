//! Minimal AcpHal/APU object: the console audio device, its heap and
//! coprocessor message queue. DSP/XMA are deliberately not emulated.

const std = @import("std");
const builtin = @import("builtin");

const HRESULT = i32;
const S_OK: HRESULT = 0;
const E_INVALIDARG: HRESULT = @bitCast(@as(u32, 0x8007_0057));
const E_FAIL: HRESULT = @bitCast(@as(u32, 0x8000_4005));
const E_OUTOFMEMORY: HRESULT = @bitCast(@as(u32, 0x8007_000E));

const Message = extern struct {
    kind: u32,
    dropped: u32,
    usec: u32,
    data: [16]u8,
};

const Acp = extern struct {
    vtable: *const AcpMethods,
    connected: bool,
    mask: u32,
    capacity: u32,
    head: u32,
    count: u32,
    messages: [256]Message,
};

const AcpMethods = extern struct {
    connect: *const fn (*Acp, u32, u32) callconv(.{ .x86_64_win = .{} }) HRESULT,
    disconnect: *const fn (*Acp) callconv(.{ .x86_64_win = .{} }) HRESULT,
    submit: *const fn (*Acp, u32, u64, u32, ?*const anyopaque, u32) callconv(.{ .x86_64_win = .{} }) HRESULT,
    pop_message: *const fn (*Acp, ?*Message) callconv(.{ .x86_64_win = .{} }) bool,
    message_count: *const fn (*Acp) callconv(.{ .x86_64_win = .{} }) u32,
    release: *const fn (*Acp) callconv(.{ .x86_64_win = .{} }) void,
};

const COMMAND_COMPLETED: u32 = 0x10;
const FLOWGRAPH_COMPLETED: u32 = 0x02;

var g_acp = Acp{
    .vtable = undefined,
    .connected = false,
    .mask = 0,
    .capacity = 0,
    .head = 0,
    .count = 0,
    .messages = undefined,
};

fn post(a: *Acp, kind: u32, data: []const u8) void {
    if (a.mask & kind == 0 or a.count >= a.capacity) return;
    var m = Message{ .kind = kind, .dropped = 0, .usec = 0, .data = @splat(0) };
    const n = @min(data.len, 16);
    @memcpy(m.data[0..n], data[0..n]);
    const at = (a.head + a.count) % a.messages.len;
    a.messages[at] = m;
    a.count += 1;
}

fn acpConnect(a: *Acp, commands: u32, messages: u32) callconv(.{ .x86_64_win = .{} }) HRESULT {
    if (commands == 0) return E_INVALIDARG;
    a.connected = true;
    a.capacity = @min(messages, a.messages.len);
    return S_OK;
}
fn acpDisconnect(a: *Acp) callconv(.{ .x86_64_win = .{} }) HRESULT {
    if (!a.connected) return E_FAIL;
    a.connected = false;
    return S_OK;
}
fn acpSubmit(a: *Acp, command: u32, id: u64, frame: u32, data: ?*const anyopaque, notification: u32) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = frame;
    if (command == 8) { // register messages
        a.mask |= if (data) |p| @as(*const u32, @ptrCast(@alignCast(p))).* else 0;
    } else if (command == 9) { // unregister
        a.mask &= ~(if (data) |p| @as(*const u32, @ptrCast(@alignCast(p))).* else 0);
    } else if (command == 15) { // load flowgraph
        var fg: u32 = 0;
        if (data) |p| fg = @as(*const u32, @ptrCast(@alignCast(p))).*; // word 1 is at +4
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, fg, .little);
        post(a, FLOWGRAPH_COMPLETED, &bytes);
    }
    if (id != 0) {
        var done: [16]u8 = @splat(0);
        std.mem.writeInt(u32, done[0..4], command, .little);
        std.mem.writeInt(u64, done[4..12], id, .little);
        post(a, COMMAND_COMPLETED, &done);
    }
    if (notification != 0) {
        const p: *volatile u32 = @ptrFromInt(notification);
        p.* = 1;
    }
    return S_OK;
}
fn acpPop(a: *Acp, out: ?*Message) callconv(.{ .x86_64_win = .{} }) bool {
    if (a.count == 0) return false;
    const m = a.messages[a.head];
    a.head = (a.head + 1) % @as(u32, @intCast(a.messages.len));
    a.count -= 1;
    if (out) |o| o.* = m;
    return true;
}
fn acpCount(a: *Acp) callconv(.{ .x86_64_win = .{} }) u32 {
    return a.count;
}
fn acpRelease(_: *Acp) callconv(.{ .x86_64_win = .{} }) void {}

const acp_methods = AcpMethods{
    .connect = &acpConnect,
    .disconnect = &acpDisconnect,
    .submit = &acpSubmit,
    .pop_message = &acpPop,
    .message_count = &acpCount,
    .release = &acpRelease,
};

pub fn acpHalCreate(out: ?*?*anyopaque) callconv(.{ .x86_64_win = .{} }) HRESULT {
    if (out == null) return E_INVALIDARG;
    g_acp.vtable = &acp_methods;
    g_acp.connected = false;
    g_acp.mask = 0;
    g_acp.capacity = 0;
    g_acp.head = 0;
    g_acp.count = 0;
    out.?.* = @ptrCast(&g_acp);
    return S_OK;
}

// ---------------------------------------------------------------------------
// APU heap
// ---------------------------------------------------------------------------

const Block = struct { ptr: usize, apu: u32, size: usize };
var g_blocks: [256]Block = undefined;
var g_block_count: usize = 0;
var g_next_apu: u32 = 0x10000;
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
    return S_OK;
}

pub fn apuAlloc(out: ?*?*anyopaque, apu: ?*u32, size: u32, alignment: u32, flags: u32) callconv(.{ .x86_64_win = .{} }) HRESULT {
    _ = flags;
    if (out == null or size == 0 or alignment < 4 or !std.math.isPowerOfTwo(alignment)) return E_INVALIDARG;
    const a: usize = @max(alignment, 16);
    const buf = std.heap.page_allocator.alloc(u8, @max(size, 1)) catch return E_OUTOFMEMORY;
    @memset(buf, 0);
    lockHeap();
    defer unlockHeap();
    if (g_block_count >= g_blocks.len) {
        std.heap.page_allocator.free(buf);
        return E_OUTOFMEMORY;
    }
    const addr = std.mem.alignForward(u32, g_next_apu, @intCast(a));
    g_next_apu = addr + size;
    g_blocks[g_block_count] = .{ .ptr = @intFromPtr(buf.ptr), .apu = addr, .size = size };
    g_block_count += 1;
    out.?.* = buf.ptr;
    if (apu) |p| p.* = addr;
    return S_OK;
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

var g_shape: ShapeContexts = std.mem.zeroes(ShapeContexts);
var g_shape_live = false;

pub fn acpHalAllocateShapeContexts(ctx: ?*ShapeContexts) callconv(.{ .x86_64_win = .{} }) HRESULT {
    const c = ctx orelse return E_INVALIDARG;
    if (g_shape_live) return E_FAIL;
    const bytes = [_]usize{ 32, 256, 256, 16, 64, 256 };
    for (0..6) |i| {
        if (c.counts[i] == 0) continue;
        var p: ?*anyopaque = null;
        var a: u32 = 0;
        const hr = apuAlloc(&p, &a, c.counts[i] * @as(u32, @intCast(bytes[i])), 256, 1);
        if (hr != S_OK) {
            // release what we took
            for (0..i) |j| apuFree(c.arrays[j]);
            return hr;
        }
        c.arrays[i] = p;
        c.apu[i] = a;
    }
    g_shape = c.*;
    g_shape_live = true;
    return S_OK;
}

pub fn acpHalReleaseShapeContexts() callconv(.{ .x86_64_win = .{} }) HRESULT {
    if (!g_shape_live) return E_FAIL;
    for (g_shape.arrays) |p| apuFree(p);
    g_shape_live = false;
    return S_OK;
}
