//! Xbox DirectStorage (`XCRDAPI.dll!DStorageGetFactory`) HLE.
//!
//! This models the GDK `dstorage_xs.h` surface only:
//!   * `IDStorageFactoryX`
//!   * `IDStorageFileX`  (Close, GetHandle — no Windows `IDStorageFile::GetFileSize`)
//!   * `IDStorageQueueX` (per-queue objects, ordered status/signal entries)
//!   * `IDStorageStatusArray`
//!
//! Requests are copied on `EnqueueRequest` and performed on `Submit`, so the
//! guest may reuse its request structure immediately (the documented
//! DirectStorage contract).  File reads use `win32_fs.readAt` (pread), which
//! preserves the Win32 file pointer exactly like real overlapped I/O.
//!
//! Unsupported request features (compression, non-memory destinations,
//! physical-page destinations) are failed closed: the request is never copied
//! raw, its status reports `E_NOTIMPL`, and the queue error event is signalled.
//! A fence signal requires a D3D12 backend hook.  Until one registers
//! `g_fence_signal`, enqueueing a signal is a hard `[STUB]` stop rather than a
//! silent no-op.

const std = @import("std");
const builtin = @import("builtin");
const win32_fs = @import("win32_fs.zig");
const sync = @import("../sync.zig");
const stub_policy = @import("stub_policy.zig");

const win: std.builtin.CallingConvention = .{ .x86_64_win = .{} };

const HRESULT = i32;
const S_OK: HRESULT = 0;
const E_FAIL: HRESULT = @bitCast(@as(u32, 0x8000_4005));
const E_NOTIMPL: HRESULT = @bitCast(@as(u32, 0x8000_4001));
const E_INVALIDARG: HRESULT = @bitCast(@as(u32, 0x8007_0057));
const E_OUTOFMEMORY: HRESULT = @bitCast(@as(u32, 0x8007_000E));
const E_ABORT: HRESULT = @bitCast(@as(u32, 0x8000_4004));
const FILE_NOT_FOUND: HRESULT = @bitCast(@as(u32, 0x8007_0002));

const INVALID_HANDLE_VALUE: usize = std.math.maxInt(usize);

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

// ---------------------------------------------------------------------------
// DSTORAGE_REQUEST (dstorage_xs.h, x64)
// ---------------------------------------------------------------------------

/// `DSTORAGE_REQUEST_OPTIONS`, 16 bytes on x64 (MSVC bitfield packing):
///   offset 0x00: CompressionFormat : 8
///   offset 0x01: padding
///   offset 0x08: SourceType : 1, DestinationType : 7, Reserved : 48
pub const DSTORAGE_REQUEST_OPTIONS = extern struct {
    compression_format: u8,
    reserved: [7]u8,
    bits: u64,
};

pub const DSTORAGE_SOURCE_TYPE_FILE: u1 = 1;

pub const DSTORAGE_DESTINATION_TYPE_MEMORY: u7 = 0;

/// `DSTORAGE_REQUEST` per dstorage_xs.h.  Layout:
///   0x00 Options (16)
///   0x10 Destination (union: memory pointer / page array)
///   0x18 DestinationPageOffset (u16)
///   0x20 DestinationSize (u32)
///   0x28 Source (union: memory pointer / IDStorageFileX*)
///   0x30 FileOffset (u64)
///   0x38 SourceSize (u32)
///   0x3C IntermediateSize (u32)
///   0x40 CancellationTag (u64)
///   0x48 Name (const char*)
pub const DSTORAGE_REQUEST = extern struct {
    options: DSTORAGE_REQUEST_OPTIONS,
    destination: usize,
    destination_page_offset: u16,
    destination_padding: [6]u8,
    destination_size: u32,
    destination_size_padding: u32,
    source: usize,
    file_offset: u64,
    source_size: u32,
    intermediate_size: u32,
    cancellation_tag: u64,
    name: usize,
};

comptime {
    if (@sizeOf(DSTORAGE_REQUEST_OPTIONS) != 0x10) @compileError("DSTORAGE_REQUEST_OPTIONS must be 16 bytes");
    if (@offsetOf(DSTORAGE_REQUEST_OPTIONS, "compression_format") != 0x00) @compileError("CompressionFormat must be at 0x00");
    if (@offsetOf(DSTORAGE_REQUEST_OPTIONS, "bits") != 0x08) @compileError("SourceType bitfield must be at 0x08");

    if (@sizeOf(DSTORAGE_REQUEST) != 0x50) @compileError("DSTORAGE_REQUEST must be 0x50 bytes");
    if (@offsetOf(DSTORAGE_REQUEST, "options") != 0x00) @compileError("Options must be at 0x00");
    if (@offsetOf(DSTORAGE_REQUEST, "destination") != 0x10) @compileError("Destination must be at 0x10");
    if (@offsetOf(DSTORAGE_REQUEST, "destination_page_offset") != 0x18) @compileError("DestinationPageOffset must be at 0x18");
    if (@offsetOf(DSTORAGE_REQUEST, "destination_size") != 0x20) @compileError("DestinationSize must be at 0x20");
    if (@offsetOf(DSTORAGE_REQUEST, "source") != 0x28) @compileError("Source must be at 0x28");
    if (@offsetOf(DSTORAGE_REQUEST, "file_offset") != 0x30) @compileError("FileOffset must be at 0x30");
    if (@offsetOf(DSTORAGE_REQUEST, "source_size") != 0x38) @compileError("SourceSize must be at 0x38");
    if (@offsetOf(DSTORAGE_REQUEST, "intermediate_size") != 0x3C) @compileError("IntermediateSize must be at 0x3C");
    if (@offsetOf(DSTORAGE_REQUEST, "cancellation_tag") != 0x40) @compileError("CancellationTag must be at 0x40");
    if (@offsetOf(DSTORAGE_REQUEST, "name") != 0x48) @compileError("Name must be at 0x48");
}

pub const RequestClass = enum {
    ok,
    unsupported_compression,
    unsupported_destination,
    invalid,
};

/// Pure classifier used by `EnqueueRequest` and by tests.  It never inspects
/// guest memory; only the request header fields.
pub fn classifyRequest(req: *const DSTORAGE_REQUEST) RequestClass {
    if (req.options.compression_format != 0) return .unsupported_compression;
    const source_is_file = (req.options.bits & 1) != 0;
    const destination_type: u7 = @truncate((req.options.bits >> 1) & 0x7F);
    if (destination_type != DSTORAGE_DESTINATION_TYPE_MEMORY) return .unsupported_destination;
    if (req.destination == 0 or req.destination_size == 0) return .invalid;
    if (req.source == 0 or req.source_size == 0) return .invalid;
    if (req.source_size > req.destination_size) return .invalid;
    if (source_is_file) {
        if (req.file_offset > std.math.maxInt(i64)) return .invalid;
    }
    return .ok;
}

// ---------------------------------------------------------------------------
// IDStorageFileX
// ---------------------------------------------------------------------------

pub const IDStorageFileVtbl = extern struct {
    QueryInterface: *const fn (*IDStorageFileX, ?*const anyopaque, *?*anyopaque) callconv(win) HRESULT,
    AddRef: *const fn (*IDStorageFileX) callconv(win) u32,
    Release: *const fn (*IDStorageFileX) callconv(win) u32,
    Close: *const fn (*IDStorageFileX) callconv(win) void,
    GetHandle: *const fn (*IDStorageFileX) callconv(win) usize,
};

pub const IDStorageFileX = extern struct {
    lpVtbl: *const IDStorageFileVtbl,
};

const StorageFile = struct {
    lpVtbl: *const IDStorageFileVtbl,
    refs: std.atomic.Value(u32),
    handle: usize,
    size: u64,
    closed: bool,
};

fn asFile(self: *IDStorageFileX) *StorageFile {
    return @ptrCast(@alignCast(self));
}

fn fileQueryInterface(self: *IDStorageFileX, _: ?*const anyopaque, ppv: *?*anyopaque) callconv(win) HRESULT {
    ppv.* = self;
    _ = self.lpVtbl.AddRef(self);
    return S_OK;
}

fn fileAddRef(self: *IDStorageFileX) callconv(win) u32 {
    const f = asFile(self);
    return f.refs.fetchAdd(1, .monotonic) + 1;
}

fn fileRelease(self: *IDStorageFileX) callconv(win) u32 {
    const f = asFile(self);
    const remaining = f.refs.fetchSub(1, .acq_rel) - 1;
    if (remaining == 0) {
        if (!f.closed and f.handle != 0) _ = win32_fs.closeHandle(f.handle);
        std.heap.page_allocator.destroy(f);
    }
    return remaining;
}

fn fileClose(self: *IDStorageFileX) callconv(win) void {
    const f = asFile(self);
    if (f.closed) return;
    f.closed = true;
    const h = f.handle;
    f.handle = 0;
    if (h != 0) {
        if (!win32_fs.closeHandle(h)) {
            std.log.warn("[DSTORAGE] Close(handle=0x{x}) failed", .{h});
        }
    }
}

fn fileGetHandle(self: *IDStorageFileX) callconv(win) usize {
    const f = asFile(self);
    if (f.closed or f.handle == 0) return INVALID_HANDLE_VALUE;
    return f.handle;
}

const g_file_vtbl = IDStorageFileVtbl{
    .QueryInterface = &fileQueryInterface,
    .AddRef = &fileAddRef,
    .Release = &fileRelease,
    .Close = &fileClose,
    .GetHandle = &fileGetHandle,
};

fn fileReadAt(self: *StorageFile, offset: u64, buf: []u8) ?usize {
    if (self.closed or self.handle == 0) return null;
    return win32_fs.readAt(self.handle, offset, buf);
}

// ---------------------------------------------------------------------------
// IDStorageStatusArray
// ---------------------------------------------------------------------------

pub const IDStorageStatusArrayVtbl = extern struct {
    QueryInterface: *const fn (*IDStorageStatusArray, ?*const anyopaque, *?*anyopaque) callconv(win) HRESULT,
    AddRef: *const fn (*IDStorageStatusArray) callconv(win) u32,
    Release: *const fn (*IDStorageStatusArray) callconv(win) u32,
    IsComplete: *const fn (*IDStorageStatusArray, u32) callconv(win) bool,
    GetHResult: *const fn (*IDStorageStatusArray, u32) callconv(win) HRESULT,
};

pub const IDStorageStatusArray = extern struct {
    lpVtbl: *const IDStorageStatusArrayVtbl,
};

const StatusEntry = struct {
    complete: std.atomic.Value(u32) = .init(0),
    hr: std.atomic.Value(i32) = .init(0),
};

const StorageArray = struct {
    lpVtbl: *const IDStorageStatusArrayVtbl,
    refs: std.atomic.Value(u32),
    entries: []StatusEntry,
};

fn asArray(self: *IDStorageStatusArray) *StorageArray {
    return @ptrCast(@alignCast(self));
}

fn arrayQueryInterface(self: *IDStorageStatusArray, _: ?*const anyopaque, ppv: *?*anyopaque) callconv(win) HRESULT {
    ppv.* = self;
    _ = self.lpVtbl.AddRef(self);
    return S_OK;
}

fn arrayAddRef(self: *IDStorageStatusArray) callconv(win) u32 {
    const a = asArray(self);
    return a.refs.fetchAdd(1, .monotonic) + 1;
}

fn arrayRelease(self: *IDStorageStatusArray) callconv(win) u32 {
    const a = asArray(self);
    const remaining = a.refs.fetchSub(1, .acq_rel) - 1;
    if (remaining == 0) {
        std.heap.page_allocator.free(a.entries);
        std.heap.page_allocator.destroy(a);
    }
    return remaining;
}

fn arrayIsComplete(self: *IDStorageStatusArray, index: u32) callconv(win) bool {
    const a = asArray(self);
    if (index >= a.entries.len) return true;
    return a.entries[index].complete.load(.acquire) != 0;
}

fn arrayGetHResult(self: *IDStorageStatusArray, index: u32) callconv(win) HRESULT {
    const a = asArray(self);
    if (index >= a.entries.len) return S_OK;
    return a.entries[index].hr.load(.acquire);
}

const g_status_vtbl = IDStorageStatusArrayVtbl{
    .QueryInterface = &arrayQueryInterface,
    .AddRef = &arrayAddRef,
    .Release = &arrayRelease,
    .IsComplete = &arrayIsComplete,
    .GetHResult = &arrayGetHResult,
};

fn setStatus(self: *IDStorageStatusArray, index: u32, hr: HRESULT) void {
    const a = asArray(self);
    if (index >= a.entries.len) return;
    a.entries[index].hr.store(hr, .release);
    a.entries[index].complete.store(1, .release);
}

// ---------------------------------------------------------------------------
// IDStorageQueueX
// ---------------------------------------------------------------------------

pub const IDStorageQueueVtbl = extern struct {
    QueryInterface: *const fn (*IDStorageQueue, ?*const anyopaque, *?*anyopaque) callconv(win) HRESULT,
    AddRef: *const fn (*IDStorageQueue) callconv(win) u32,
    Release: *const fn (*IDStorageQueue) callconv(win) u32,
    EnqueueRequest: *const fn (*IDStorageQueue, ?*const DSTORAGE_REQUEST) callconv(win) void,
    EnqueueStatus: *const fn (*IDStorageQueue, ?*IDStorageStatusArray, u32) callconv(win) void,
    EnqueueSignal: *const fn (*IDStorageQueue, ?*anyopaque, u64) callconv(win) void,
    Submit: *const fn (*IDStorageQueue) callconv(win) void,
    CancelRequestsWithTag: *const fn (*IDStorageQueue, u64, u64) callconv(win) void,
    Close: *const fn (*IDStorageQueue) callconv(win) void,
    GetErrorEvent: *const fn (*IDStorageQueue) callconv(win) usize,
    RetrieveErrorRecord: *const fn (*IDStorageQueue, ?*anyopaque) callconv(win) void,
    Query: *const fn (*IDStorageQueue, ?*anyopaque) callconv(win) void,
};

pub const IDStorageQueue = extern struct {
    lpVtbl: *const IDStorageQueueVtbl,
};

const OpKind = enum { request, status, signal };

const Op = struct {
    kind: OpKind,
    request: DSTORAGE_REQUEST = undefined,
    /// Set for a request that must fail without touching guest memory.
    failure: ?HRESULT = null,
    status_array: ?*IDStorageStatusArray = null,
    status_index: u32 = 0,
    fence: usize = 0,
    fence_value: u64 = 0,
};

const StorageQueue = struct {
    lpVtbl: *const IDStorageQueueVtbl,
    refs: std.atomic.Value(u32),
    ops: std.array_list.Managed(Op),
    lock: SpinLock = .{},
    error_event: usize = 0,
    closed: bool = false,
    has_error: bool = false,
    first_error: HRESULT = S_OK,
    error_count: u32 = 0,
};

fn asQueue(self: *IDStorageQueue) *StorageQueue {
    return @ptrCast(@alignCast(self));
}

/// Called by a D3D12 backend once fences exist.  Returns false if the signal
/// could not be delivered.  The queue never emulates D3D12 itself.
pub const FenceSignalFn = *const fn (fence: usize, value: u64) callconv(.c) bool;
pub var g_fence_signal: ?FenceSignalFn = null;

fn newOps() std.array_list.Managed(Op) {
    return std.array_list.Managed(Op).init(std.heap.page_allocator);
}

fn queueQueryInterface(self: *IDStorageQueue, _: ?*const anyopaque, ppv: *?*anyopaque) callconv(win) HRESULT {
    ppv.* = self;
    _ = self.lpVtbl.AddRef(self);
    return S_OK;
}

fn queueAddRef(self: *IDStorageQueue) callconv(win) u32 {
    const q = asQueue(self);
    return q.refs.fetchAdd(1, .monotonic) + 1;
}

fn queueFail(q: *StorageQueue, hr: HRESULT) void {
    q.lock.lock();
    if (!q.has_error) {
        q.has_error = true;
        q.first_error = hr;
    }
    q.error_count +%= 1;
    const event = q.error_event;
    q.lock.unlock();
    if (event != 0) _ = sync.setEvent(event);
}

fn enqueueRequest(self: *IDStorageQueue, req_ptr: ?*const DSTORAGE_REQUEST) callconv(win) void {
    const q = asQueue(self);
    const req = req_ptr orelse {
        queueFail(q, E_INVALIDARG);
        return;
    };
    const copy = req.*;
    var failure_reason: []const u8 = "";
    var op = Op{ .kind = .request, .request = copy };
    switch (classifyRequest(&copy)) {
        .ok => {},
        .unsupported_compression => {
            op.failure = E_NOTIMPL;
            failure_reason = "unsupported compression format";
        },
        .unsupported_destination => {
            op.failure = E_NOTIMPL;
            failure_reason = "unsupported destination type";
        },
        .invalid => {
            op.failure = E_INVALIDARG;
            failure_reason = "invalid request";
        },
    }

    q.lock.lock();
    if (q.closed) {
        q.lock.unlock();
        return;
    }
    q.ops.append(op) catch {
        q.lock.unlock();
        queueFail(q, E_OUTOFMEMORY);
        return;
    };
    q.lock.unlock();

    if (op.failure) |hr| {
        std.log.warn("[DSTORAGE] EnqueueRequest rejected ({s}); compression={d} bits=0x{x}, not copying", .{
            failure_reason, copy.options.compression_format, copy.options.bits,
        });
        _ = hr;
    }
}

fn enqueueStatus(self: *IDStorageQueue, status: ?*IDStorageStatusArray, index: u32) callconv(win) void {
    const q = asQueue(self);
    const sa = status orelse {
        queueFail(q, E_INVALIDARG);
        return;
    };
    _ = sa.lpVtbl.AddRef(sa);
    q.lock.lock();
    if (q.closed) {
        q.lock.unlock();
        _ = sa.lpVtbl.Release(sa);
        return;
    }
    q.ops.append(.{ .kind = .status, .status_array = sa, .status_index = index }) catch {
        q.lock.unlock();
        _ = sa.lpVtbl.Release(sa);
        queueFail(q, E_OUTOFMEMORY);
        return;
    };
    q.lock.unlock();
}

fn enqueueSignal(self: *IDStorageQueue, fence: ?*anyopaque, value: u64) callconv(win) void {
    const q = asQueue(self);
    const f = fence orelse {
        queueFail(q, E_INVALIDARG);
        return;
    };
    q.lock.lock();
    if (q.closed) {
        q.lock.unlock();
        return;
    }
    q.ops.append(.{ .kind = .signal, .fence = @intFromPtr(f), .fence_value = value }) catch {
        q.lock.unlock();
        queueFail(q, E_OUTOFMEMORY);
        return;
    };
    q.lock.unlock();
}

fn performRequest(req: *const DSTORAGE_REQUEST) HRESULT {
    const source_is_file = (req.options.bits & 1) != 0;
    const n: usize = req.source_size;
    const dst: [*]u8 = @ptrFromInt(req.destination);
    if (source_is_file) {
        const iface: *IDStorageFileX = @ptrFromInt(req.source);
        const file: *StorageFile = @ptrCast(@alignCast(iface));
        const read = fileReadAt(file, req.file_offset, dst[0..n]) orelse return E_FAIL;
        if (read != n) return E_FAIL;
    } else {
        const src: [*]const u8 = @ptrFromInt(req.source);
        if (@intFromPtr(dst) <= @intFromPtr(src)) {
            std.mem.copyForwards(u8, dst[0..n], src[0..n]);
        } else {
            std.mem.copyBackwards(u8, dst[0..n], src[0..n]);
        }
    }
    return S_OK;
}

fn deliverSignal(q: *StorageQueue, fence: usize, value: u64) void {
    if (fence == 0) {
        queueFail(q, E_INVALIDARG);
        return;
    }
    if (g_fence_signal) |signal| {
        if (!signal(fence, value)) queueFail(q, E_FAIL);
        return;
    }
    // No D3D12 backend exists yet.  Do not pretend the fence was signalled:
    // stop loudly so a post-boundary run fails at the first real fence use.
    std.log.err("[DSTORAGE] EnqueueSignal(fence=0x{x}, value={d}) requires a D3D12 fence backend", .{ fence, value });
    _ = stub_policy.missing("dstorage_xs.dll", "IDStorageQueueX::EnqueueSignal(fence)");
    queueFail(q, E_NOTIMPL);
}

fn submit(self: *IDStorageQueue) callconv(win) void {
    const q = asQueue(self);
    q.lock.lock();
    if (q.closed or q.ops.items.len == 0) {
        q.lock.unlock();
        return;
    }
    var ops = q.ops;
    q.ops = newOps();
    q.lock.unlock();
    defer ops.deinit();

    var batch_hr: HRESULT = S_OK;
    for (ops.items) |*op| {
        switch (op.kind) {
            .request => {
                if (op.failure) |hr| {
                    if (batch_hr == S_OK) batch_hr = hr;
                    queueFail(q, hr);
                    continue;
                }
                const hr = performRequest(&op.request);
                if (hr != S_OK) {
                    if (batch_hr == S_OK) batch_hr = hr;
                    queueFail(q, hr);
                }
            },
            .status => {
                if (op.status_array) |sa| {
                    setStatus(sa, op.status_index, batch_hr);
                    _ = sa.lpVtbl.Release(sa);
                }
                batch_hr = S_OK;
            },
            .signal => deliverSignal(q, op.fence, op.fence_value),
        }
    }
}

fn cancelRequestsWithTag(self: *IDStorageQueue, tag: u64, value: u64) callconv(win) void {
    const q = asQueue(self);
    q.lock.lock();
    defer q.lock.unlock();
    if (q.closed) return;
    var i: usize = 0;
    while (i < q.ops.items.len) {
        const op = q.ops.items[i];
        if (op.kind == .request and (op.request.cancellation_tag & value) == tag) {
            _ = q.ops.orderedRemove(i);
        } else {
            i += 1;
        }
    }
}

fn releasePendingStatuses(ops: *std.array_list.Managed(Op)) void {
    for (ops.items) |op| {
        if (op.kind == .status) {
            if (op.status_array) |sa| {
                setStatus(sa, op.status_index, E_ABORT);
                _ = sa.lpVtbl.Release(sa);
            }
        }
    }
}

fn closeQueueObject(q: *StorageQueue) void {
    q.lock.lock();
    if (q.closed) {
        q.lock.unlock();
        return;
    }
    q.closed = true;
    var ops = q.ops;
    q.ops = newOps();
    const event = q.error_event;
    q.error_event = 0;
    q.lock.unlock();

    releasePendingStatuses(&ops);
    ops.deinit();
    if (event != 0) _ = sync.closeHandle(event);
}

fn queueClose(self: *IDStorageQueue) callconv(win) void {
    closeQueueObject(asQueue(self));
}

fn queueRelease(self: *IDStorageQueue) callconv(win) u32 {
    const q = asQueue(self);
    const remaining = q.refs.fetchSub(1, .acq_rel) - 1;
    if (remaining == 0) {
        closeQueueObject(q);
        q.ops.deinit();
        std.heap.page_allocator.destroy(q);
    }
    return remaining;
}

fn queueGetErrorEvent(self: *IDStorageQueue) callconv(win) usize {
    const q = asQueue(self);
    q.lock.lock();
    const event = q.error_event;
    q.lock.unlock();
    return event;
}

fn queueRetrieveErrorRecord(self: *IDStorageQueue, record: ?*anyopaque) callconv(win) void {
    const q = asQueue(self);
    if (record) |r| {
        const bytes: [*]u8 = @ptrCast(r);
        @memset(bytes[0..64], 0);
    }
    q.lock.lock();
    const has_error = q.has_error;
    const first_error = q.first_error;
    const error_count = q.error_count;
    q.lock.unlock();
    if (has_error) {
        std.log.warn("[DSTORAGE] RetrieveErrorRecord: first error 0x{x}, count={d}", .{
            @as(u32, @bitCast(first_error)), error_count,
        });
    }
}

fn queueQuery(_: *IDStorageQueue, info: ?*anyopaque) callconv(win) void {
    if (info) |p| {
        const bytes: [*]u8 = @ptrCast(p);
        @memset(bytes[0..32], 0);
    }
}

const g_queue_vtbl = IDStorageQueueVtbl{
    .QueryInterface = &queueQueryInterface,
    .AddRef = &queueAddRef,
    .Release = &queueRelease,
    .EnqueueRequest = &enqueueRequest,
    .EnqueueStatus = &enqueueStatus,
    .EnqueueSignal = &enqueueSignal,
    .Submit = &submit,
    .CancelRequestsWithTag = &cancelRequestsWithTag,
    .Close = &queueClose,
    .GetErrorEvent = &queueGetErrorEvent,
    .RetrieveErrorRecord = &queueRetrieveErrorRecord,
    .Query = &queueQuery,
};

// ---------------------------------------------------------------------------
// IDStorageFactoryX
// ---------------------------------------------------------------------------

pub const IDStorageFactoryVtbl = extern struct {
    QueryInterface: *const fn (*IDStorageFactory, ?*const anyopaque, *?*anyopaque) callconv(win) HRESULT,
    AddRef: *const fn (*IDStorageFactory) callconv(win) u32,
    Release: *const fn (*IDStorageFactory) callconv(win) u32,
    CreateQueueLegacy: *const fn (*IDStorageFactory, ?*const anyopaque, ?*const anyopaque, *?*anyopaque) callconv(win) HRESULT,
    OpenFile: *const fn (*IDStorageFactory, ?[*:0]const u16, ?*const anyopaque, *?*anyopaque) callconv(win) HRESULT,
    CreateStatusArray: *const fn (*IDStorageFactory, u32, ?[*:0]const u8, ?*const anyopaque, *?*anyopaque) callconv(win) HRESULT,
    SetCpuAffinity: *const fn (*IDStorageFactory, u64) callconv(win) HRESULT,
    SetDebugFlags: *const fn (*IDStorageFactory, u32) callconv(win) void,
    SetStagingBufferSize: *const fn (*IDStorageFactory, u32) callconv(win) HRESULT,
    ReservedSlot9: *const fn (*IDStorageFactory) callconv(win) HRESULT,
    CreateQueue: *const fn (*IDStorageFactory, ?*const anyopaque, ?*const anyopaque, *?*anyopaque) callconv(win) HRESULT,
    ReservedSlot11: *const fn (*IDStorageFactory) callconv(win) HRESULT,
    ReservedSlot12: *const fn (*IDStorageFactory) callconv(win) HRESULT,
    ReservedSlot13: *const fn (*IDStorageFactory) callconv(win) HRESULT,
    ReservedSlot14: *const fn (*IDStorageFactory) callconv(win) HRESULT,
    ReservedSlot15: *const fn (*IDStorageFactory) callconv(win) HRESULT,
};

pub const IDStorageFactory = extern struct {
    lpVtbl: *const IDStorageFactoryVtbl,
};

var g_factory_vtbl = IDStorageFactoryVtbl{
    .QueryInterface = &factoryQueryInterface,
    .AddRef = &factoryAddRef,
    .Release = &factoryRelease,
    .CreateQueueLegacy = &factoryCreateQueue,
    .OpenFile = &factoryOpenFile,
    .CreateStatusArray = &factoryCreateStatusArray,
    .SetCpuAffinity = &factorySetCpuAffinity,
    .SetDebugFlags = &factorySetDebugFlags,
    .SetStagingBufferSize = &factorySetStagingBufferSize,
    .ReservedSlot9 = &factoryReserved,
    .CreateQueue = &factoryCreateQueue,
    .ReservedSlot11 = &factoryReserved,
    .ReservedSlot12 = &factoryReserved,
    .ReservedSlot13 = &factoryReserved,
    .ReservedSlot14 = &factoryReserved,
    .ReservedSlot15 = &factoryReserved,
};

var g_factory = IDStorageFactory{ .lpVtbl = &g_factory_vtbl };
var g_debug_flags: u32 = 0;
var g_cpu_affinity: u64 = 0;
var g_staging_size: u32 = 0;

fn factoryQueryInterface(self: *IDStorageFactory, _: ?*const anyopaque, ppv: *?*anyopaque) callconv(win) HRESULT {
    ppv.* = self;
    return S_OK;
}
fn factoryAddRef(_: *IDStorageFactory) callconv(win) u32 {
    return 2;
}
fn factoryRelease(_: *IDStorageFactory) callconv(win) u32 {
    return 1;
}
fn factoryReserved(_: *IDStorageFactory) callconv(win) HRESULT {
    return E_NOTIMPL;
}

fn factoryCreateQueue(
    _: *IDStorageFactory,
    _: ?*const anyopaque,
    _: ?*const anyopaque,
    ppv: *?*anyopaque,
) callconv(win) HRESULT {
    const q = std.heap.page_allocator.create(StorageQueue) catch return E_OUTOFMEMORY;
    q.* = .{
        .lpVtbl = &g_queue_vtbl,
        .refs = std.atomic.Value(u32).init(1),
        .ops = newOps(),
        .error_event = sync.createEventW(true, false),
    };
    std.log.info("[DSTORAGE] CreateQueue -> 0x{x}", .{@intFromPtr(q)});
    ppv.* = q;
    return S_OK;
}

fn factoryCreateStatusArray(
    _: *IDStorageFactory,
    capacity: u32,
    _: ?[*:0]const u8,
    _: ?*const anyopaque,
    ppv: *?*anyopaque,
) callconv(win) HRESULT {
    if (capacity == 0) return E_INVALIDARG;
    const entries = std.heap.page_allocator.alloc(StatusEntry, capacity) catch return E_OUTOFMEMORY;
    for (entries) |*e| e.* = .{};
    const a = std.heap.page_allocator.create(StorageArray) catch {
        std.heap.page_allocator.free(entries);
        return E_OUTOFMEMORY;
    };
    a.* = .{
        .lpVtbl = &g_status_vtbl,
        .refs = std.atomic.Value(u32).init(1),
        .entries = entries,
    };
    std.log.info("[DSTORAGE] CreateStatusArray(capacity={d}) -> 0x{x}", .{ capacity, @intFromPtr(a) });
    ppv.* = a;
    return S_OK;
}

fn factoryOpenFile(
    _: *IDStorageFactory,
    path: ?[*:0]const u16,
    _: ?*const anyopaque,
    ppv: *?*anyopaque,
) callconv(win) HRESULT {
    ppv.* = null;
    const wpath = path orelse return E_INVALIDARG;

    const handle = win32_fs.openReadOnlyWide(wpath) orelse {
        var raw_buf: [512]u8 = undefined;
        const raw_len = std.unicode.utf16LeToUtf8(&raw_buf, std.mem.span(wpath)) catch 0;
        std.log.warn("[DSTORAGE] OpenFile(\"{s}\") -> NOT_FOUND", .{raw_buf[0..raw_len]});
        return FILE_NOT_FOUND;
    };
    const size = win32_fs.fileSize(handle) orelse 0;

    const obj = std.heap.page_allocator.create(StorageFile) catch {
        _ = win32_fs.closeHandle(handle);
        return E_OUTOFMEMORY;
    };
    obj.* = .{
        .lpVtbl = &g_file_vtbl,
        .refs = std.atomic.Value(u32).init(1),
        .handle = handle,
        .size = size,
        .closed = false,
    };

    var raw_buf: [512]u8 = undefined;
    const raw_len = std.unicode.utf16LeToUtf8(&raw_buf, std.mem.span(wpath)) catch 0;
    std.log.info("[DSTORAGE] OpenFile(raw=\"{s}\", handle=0x{x}, size={d}) -> S_OK (0x{x})", .{
        raw_buf[0..raw_len], handle, size, @intFromPtr(obj),
    });
    ppv.* = obj;
    return S_OK;
}

fn factorySetCpuAffinity(_: *IDStorageFactory, mask: u64) callconv(win) HRESULT {
    g_cpu_affinity = mask;
    std.log.info("[DSTORAGE] SetCpuAffinity(0x{x}) -> S_OK", .{mask});
    return S_OK;
}
fn factorySetDebugFlags(_: *IDStorageFactory, flags: u32) callconv(win) void {
    g_debug_flags = flags;
    std.log.info("[DSTORAGE] SetDebugFlags(0x{x})", .{flags});
}
fn factorySetStagingBufferSize(_: *IDStorageFactory, size: u32) callconv(win) HRESULT {
    g_staging_size = size;
    std.log.info("[DSTORAGE] SetStagingBufferSize(0x{x}) -> S_OK", .{size});
    return S_OK;
}

pub fn shim_DStorageGetFactory(riid: ?*const anyopaque, ppv: ?*?*IDStorageFactory) callconv(win) HRESULT {
    _ = riid;
    std.log.info("[DSTORAGE] DStorageGetFactory() -> S_OK (0x{x})", .{@intFromPtr(&g_factory)});
    if (ppv) |out| out.* = &g_factory;
    return S_OK;
}

pub fn resolve(sym_name: []const u8) ?usize {
    if (std.mem.eql(u8, sym_name, "DStorageGetFactory")) {
        return @intFromPtr(&shim_DStorageGetFactory);
    }
    return null;
}
