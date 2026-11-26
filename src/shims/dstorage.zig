const std = @import("std");
const win32_fs = @import("win32_fs.zig");

const c_stdio = struct {
    extern "c" fn fseek(stream: *std.c.FILE, offset: c_long, whence: c_int) c_int;
    extern "c" fn ftell(stream: *std.c.FILE) c_long;
};

pub const IDStorageFileVtbl = extern struct {
    QueryInterface: *const fn (*IDStorageFile, ?*const anyopaque, *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32,
    AddRef: *const fn (*IDStorageFile) callconv(.{ .x86_64_win = .{} }) u32,
    Release: *const fn (*IDStorageFile) callconv(.{ .x86_64_win = .{} }) u32,
    GetFileSize: *const fn (*IDStorageFile, *u64) callconv(.{ .x86_64_win = .{} }) i32,
    Close: *const fn (*IDStorageFile) callconv(.{ .x86_64_win = .{} }) void,
    Reserved5: *const fn (*IDStorageFile) callconv(.{ .x86_64_win = .{} }) i32,
    Reserved6: *const fn (*IDStorageFile) callconv(.{ .x86_64_win = .{} }) i32,
    Reserved7: *const fn (*IDStorageFile) callconv(.{ .x86_64_win = .{} }) i32,
};

pub const IDStorageFile = extern struct {
    lpVtbl: *const IDStorageFileVtbl,
    fp: ?*std.c.FILE,
    size: u64,
};

fn file_QueryInterface(self: *IDStorageFile, _: ?*const anyopaque, ppv: *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32 {
    ppv.* = self;
    return 0;
}
fn file_AddRef(_: *IDStorageFile) callconv(.{ .x86_64_win = .{} }) u32 {
    return 2;
}
fn file_Release(_: *IDStorageFile) callconv(.{ .x86_64_win = .{} }) u32 {
    return 1;
}
fn file_GetFileSize(self: *IDStorageFile, size_out: *u64) callconv(.{ .x86_64_win = .{} }) i32 {
    size_out.* = self.size;
    std.log.info("[DSTORAGE] GetFileSize(0x{x}) -> {d}", .{ @intFromPtr(self), self.size });
    return 0;
}
fn file_Reserved(_: *IDStorageFile) callconv(.{ .x86_64_win = .{} }) i32 {
    return -2147467263; // E_NOTIMPL
}

fn file_Close(self: *IDStorageFile) callconv(.{ .x86_64_win = .{} }) void {
    std.log.info("[DSTORAGE] CloseFile(0x{x})", .{@intFromPtr(self)});
    if (self.fp) |f| {
        _ = std.c.fclose(f);
        self.fp = null;
    }
}

const g_dstorage_file_vtbl = IDStorageFileVtbl{
    .QueryInterface = &file_QueryInterface,
    .AddRef = &file_AddRef,
    .Release = &file_Release,
    .GetFileSize = &file_GetFileSize,
    .Close = &file_Close,
    .Reserved5 = &file_Reserved,
    .Reserved6 = &file_Reserved,
    .Reserved7 = &file_Reserved,
};

pub const IDStorageStatusArrayVtbl = extern struct {
    QueryInterface: *const fn (*IDStorageStatusArray, ?*const anyopaque, *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32,
    AddRef: *const fn (*IDStorageStatusArray) callconv(.{ .x86_64_win = .{} }) u32,
    Release: *const fn (*IDStorageStatusArray) callconv(.{ .x86_64_win = .{} }) u32,
    IsComplete: *const fn (*IDStorageStatusArray, u32) callconv(.{ .x86_64_win = .{} }) bool,
    GetHResult: *const fn (*IDStorageStatusArray, u32) callconv(.{ .x86_64_win = .{} }) i32,
};

pub const IDStorageStatusArray = extern struct {
    lpVtbl: *const IDStorageStatusArrayVtbl,
};

fn st_QueryInterface(self: *IDStorageStatusArray, _: ?*const anyopaque, ppv: *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32 {
    ppv.* = self;
    return 0;
}
fn st_AddRef(_: *IDStorageStatusArray) callconv(.{ .x86_64_win = .{} }) u32 {
    return 2;
}
fn st_Release(_: *IDStorageStatusArray) callconv(.{ .x86_64_win = .{} }) u32 {
    return 1;
}
fn st_IsComplete(_: *IDStorageStatusArray, _: u32) callconv(.{ .x86_64_win = .{} }) bool {
    return true;
}
fn st_GetHResult(_: *IDStorageStatusArray, _: u32) callconv(.{ .x86_64_win = .{} }) i32 {
    return 0;
}

const g_dstorage_status_vtbl = IDStorageStatusArrayVtbl{
    .QueryInterface = &st_QueryInterface,
    .AddRef = &st_AddRef,
    .Release = &st_Release,
    .IsComplete = &st_IsComplete,
    .GetHResult = &st_GetHResult,
};

var g_dstorage_status_instance = IDStorageStatusArray{
    .lpVtbl = &g_dstorage_status_vtbl,
};

pub const IDStorageQueueVtbl = extern struct {
    QueryInterface: *const fn (*IDStorageQueue, ?*const anyopaque, *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32,
    AddRef: *const fn (*IDStorageQueue) callconv(.{ .x86_64_win = .{} }) u32,
    Release: *const fn (*IDStorageQueue) callconv(.{ .x86_64_win = .{} }) u32,
    EnqueueRequest: *const fn (*IDStorageQueue, ?[*]const u8) callconv(.{ .x86_64_win = .{} }) void,
    EnqueueStatus: *const fn (*IDStorageQueue, ?*anyopaque, u32) callconv(.{ .x86_64_win = .{} }) void,
    EnqueueSignal: *const fn (*IDStorageQueue, ?*anyopaque, u64) callconv(.{ .x86_64_win = .{} }) void,
    Submit: *const fn (*IDStorageQueue) callconv(.{ .x86_64_win = .{} }) void,
    CancelRequestsWithTag: *const fn (*IDStorageQueue, u64, u64) callconv(.{ .x86_64_win = .{} }) void,
    Close: *const fn (*IDStorageQueue) callconv(.{ .x86_64_win = .{} }) void,
    GetErrorEvent: *const fn (*IDStorageQueue) callconv(.{ .x86_64_win = .{} }) usize,
    RetrieveErrorRecord: *const fn (*IDStorageQueue, ?*anyopaque) callconv(.{ .x86_64_win = .{} }) void,
    Query: *const fn (*IDStorageQueue, ?*anyopaque) callconv(.{ .x86_64_win = .{} }) void,
};

pub const IDStorageQueue = extern struct {
    lpVtbl: *const IDStorageQueueVtbl,
};

fn q_QueryInterface(self: *IDStorageQueue, _: ?*const anyopaque, ppv: *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32 {
    ppv.* = self;
    return 0;
}
fn q_AddRef(_: *IDStorageQueue) callconv(.{ .x86_64_win = .{} }) u32 {
    return 2;
}
fn q_Release(_: *IDStorageQueue) callconv(.{ .x86_64_win = .{} }) u32 {
    return 1;
}
var g_ds_logs = std.atomic.Value(u32).init(0);

fn q_EnqueueRequest(_: *IDStorageQueue, req_ptr: ?[*]const u8) callconv(.{ .x86_64_win = .{} }) void {
    const req = req_ptr orelse return;
    if (g_ds_logs.fetchAdd(1, .monotonic) < 32) {
        std.log.info("[DSTORAGE] EnqueueRequest raw: 00={x} 08={x} 10={x} 18={x} 20={x} 28={x} 30={x}", .{
            std.mem.readInt(u64, req[0..8], .little),
            std.mem.readInt(u64, req[8..16], .little),
            std.mem.readInt(u64, req[16..24], .little),
            std.mem.readInt(u64, req[24..32], .little),
            std.mem.readInt(u64, req[32..40], .little),
            std.mem.readInt(u64, req[40..48], .little),
            std.mem.readInt(u64, req[48..56], .little),
        });
    }
    // DSTORAGE_REQUEST layout (x64):
    //   0x00 QueueType (u32)
    //   0x08 Options (u64)
    //   0x10 Source (ptr, u32 offset, u32 size)
    //   0x20 Destination (ptr, u32 offset, u32 size)
    //   0x30 UncompressedSize, 0x34 Reserved
    const options = std.mem.readInt(u64, req[0x08..0x10], .little);
    const source_type = (options >> 8) & 1; // 0 = memory, 1 = file
    const dst_addr = std.mem.readInt(usize, req[0x20..0x28], .little);
    const dst_offset = std.mem.readInt(u32, req[0x28..0x2C], .little);
    const dst_size = std.mem.readInt(u32, req[0x2C..0x30], .little);
    if (dst_addr == 0 or dst_size == 0) return;
    const dst: [*]u8 = @ptrFromInt(dst_addr + dst_offset);
    if (source_type == 0) {
        const src_addr = std.mem.readInt(usize, req[0x10..0x18], .little);
        const src_size = std.mem.readInt(u32, req[0x1C..0x20], .little);
        if (src_addr != 0) {
            const src: [*]const u8 = @ptrFromInt(src_addr);
            const n = @min(src_size, dst_size);
            @memcpy(dst[0..n], src[0..n]);
        }
    } else {
        const file_addr = std.mem.readInt(usize, req[0x10..0x18], .little);
        const file_offset = std.mem.readInt(u32, req[0x18..0x1C], .little);
        const file_size = std.mem.readInt(u32, req[0x1C..0x20], .little);
        if (file_addr != 0) {
            const ds_file: *IDStorageFile = @ptrFromInt(file_addr);
            if (ds_file.fp) |fp| {
                _ = c_stdio.fseek(fp, @intCast(file_offset), 0);
                const n = @min(file_size, dst_size);
                _ = std.c.fread(dst, 1, n, fp);
            }
        }
    }
}

fn q_EnqueueStatus(_: *IDStorageQueue, status: ?*anyopaque, index: u32) callconv(.{ .x86_64_win = .{} }) void {
    if (g_ds_logs.fetchAdd(1, .monotonic) < 32) {
        std.log.info("[DSTORAGE] EnqueueStatus status=0x{x} index={d}", .{ @intFromPtr(status), index });
    }
}
fn q_EnqueueSignal(_: *IDStorageQueue, fence: ?*anyopaque, value: u64) callconv(.{ .x86_64_win = .{} }) void {
    if (g_ds_logs.fetchAdd(1, .monotonic) < 32) {
        std.log.info("[DSTORAGE] EnqueueSignal fence=0x{x} value={d}", .{ @intFromPtr(fence), value });
    }
}
fn q_Submit(_: *IDStorageQueue) callconv(.{ .x86_64_win = .{} }) void {
    if (g_ds_logs.fetchAdd(1, .monotonic) < 32) std.log.info("[DSTORAGE] Submit", .{});
}
fn q_CancelRequestsWithTag(_: *IDStorageQueue, _: u64, _: u64) callconv(.{ .x86_64_win = .{} }) void {}
fn q_Close(_: *IDStorageQueue) callconv(.{ .x86_64_win = .{} }) void {}
fn q_GetErrorEvent(_: *IDStorageQueue) callconv(.{ .x86_64_win = .{} }) usize {
    return 0x20000;
}
fn q_RetrieveErrorRecord(_: *IDStorageQueue, record: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) void {
    if (record) |r| {
        const bytes: [*]u8 = @ptrCast(r);
        @memset(bytes[0..64], 0);
    }
}
fn q_Query(_: *IDStorageQueue, info: ?*anyopaque) callconv(.{ .x86_64_win = .{} }) void {
    if (info) |p| {
        const bytes: [*]u8 = @ptrCast(p);
        @memset(bytes[0..32], 0);
    }
}

const g_dstorage_queue_vtbl = IDStorageQueueVtbl{
    .QueryInterface = &q_QueryInterface,
    .AddRef = &q_AddRef,
    .Release = &q_Release,
    .EnqueueRequest = &q_EnqueueRequest,
    .EnqueueStatus = &q_EnqueueStatus,
    .EnqueueSignal = &q_EnqueueSignal,
    .Submit = &q_Submit,
    .CancelRequestsWithTag = &q_CancelRequestsWithTag,
    .Close = &q_Close,
    .GetErrorEvent = &q_GetErrorEvent,
    .RetrieveErrorRecord = &q_RetrieveErrorRecord,
    .Query = &q_Query,
};

var g_dstorage_queue_instance = IDStorageQueue{
    .lpVtbl = &g_dstorage_queue_vtbl,
};

pub const IDStorageFactoryVtbl = extern struct {
    QueryInterface: *const fn (*IDStorageFactory, ?*const anyopaque, *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32,
    AddRef: *const fn (*IDStorageFactory) callconv(.{ .x86_64_win = .{} }) u32,
    Release: *const fn (*IDStorageFactory) callconv(.{ .x86_64_win = .{} }) u32,
    CreateQueueLegacy: *const fn (*IDStorageFactory, ?*const anyopaque, ?*const anyopaque, *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32,
    OpenFile: *const fn (*IDStorageFactory, ?[*:0]const u16, ?*const anyopaque, *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32,
    CreateStatusArray: *const fn (*IDStorageFactory, u32, ?[*:0]const u8, ?*const anyopaque, *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32,
    SetCpuAffinity: *const fn (*IDStorageFactory, u64) callconv(.{ .x86_64_win = .{} }) i32,
    SetDebugFlags: *const fn (*IDStorageFactory, u32) callconv(.{ .x86_64_win = .{} }) void,
    SetStagingBufferSize: *const fn (*IDStorageFactory, u32) callconv(.{ .x86_64_win = .{} }) i32,
    ReservedSlot9: *const fn (*IDStorageFactory) callconv(.{ .x86_64_win = .{} }) i32,
    CreateQueue: *const fn (*IDStorageFactory, ?*const anyopaque, ?*const anyopaque, *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32,
    ReservedSlot11: *const fn (*IDStorageFactory) callconv(.{ .x86_64_win = .{} }) i32,
    ReservedSlot12: *const fn (*IDStorageFactory) callconv(.{ .x86_64_win = .{} }) i32,
    ReservedSlot13: *const fn (*IDStorageFactory) callconv(.{ .x86_64_win = .{} }) i32,
    ReservedSlot14: *const fn (*IDStorageFactory) callconv(.{ .x86_64_win = .{} }) i32,
    ReservedSlot15: *const fn (*IDStorageFactory) callconv(.{ .x86_64_win = .{} }) i32,
};

pub const IDStorageFactory = extern struct {
    lpVtbl: *const IDStorageFactoryVtbl,
};

fn f_QueryInterface(self: *IDStorageFactory, _: ?*const anyopaque, ppv: *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32 {
    ppv.* = self;
    return 0;
}
fn f_AddRef(_: *IDStorageFactory) callconv(.{ .x86_64_win = .{} }) u32 {
    return 2;
}
fn f_Release(_: *IDStorageFactory) callconv(.{ .x86_64_win = .{} }) u32 {
    return 1;
}
fn f_OpenFile(_: *IDStorageFactory, path: ?[*:0]const u16, _: ?*const anyopaque, ppv: *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32 {
    const wptr = path orelse {
        ppv.* = null;
        return -2147024894;
    };
    var raw_storage: [512]u8 = undefined;
    var raw_len: usize = 0;
    while (wptr[raw_len] != 0 and raw_len < 511) : (raw_len += 1) {
        const ch = wptr[raw_len];
        raw_storage[raw_len] = if (ch == '\\') '/' else @truncate(ch & 0x7F);
    }
    var rel: []const u8 = raw_storage[0..raw_len];
    if (rel.len >= 3 and rel[1] == ':' and rel[2] == '/') {
        rel = rel[3..];
    } else if (rel.len >= 2 and rel[0] == '.' and rel[1] == '/') {
        rel = rel[2..];
    }

    var host_buf: [1024]u8 = undefined;
    const written = std.fmt.bufPrint(host_buf[0 .. host_buf.len - 1], "{s}/{s}", .{ win32_fs.g_game_dir, rel }) catch {
        ppv.* = null;
        return -2147024894;
    };
    host_buf[written.len] = 0;
    const path_z: [*:0]const u8 = @ptrCast(&host_buf);

    const fp = std.c.fopen(path_z, "rb") orelse {
        std.log.warn("[DSTORAGE] OpenFile(\"{s}\") -> NOT_FOUND", .{written});
        ppv.* = null;
        return -2147024894;
    };

    _ = c_stdio.fseek(fp, 0, 2);
    const sz_pos = c_stdio.ftell(fp);
    _ = c_stdio.fseek(fp, 0, 0);

    const obj = std.heap.page_allocator.create(IDStorageFile) catch {
        _ = std.c.fclose(fp);
        ppv.* = null;
        return -2147024882;
    };
    obj.* = .{
        .lpVtbl = &g_dstorage_file_vtbl,
        .fp = fp,
        .size = if (sz_pos > 0) @intCast(sz_pos) else 0,
    };

    std.log.info("[DSTORAGE] OpenFile(raw=\"{s}\", host=\"{s}\", size={d}) -> S_OK (0x{x})", .{ raw_storage[0..raw_len], written, obj.size, @intFromPtr(obj) });
    ppv.* = obj;
    return 0;
}
fn f_CreateStatusArray(_: *IDStorageFactory, capacity: u32, _: ?[*:0]const u8, _: ?*const anyopaque, ppv: *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32 {
    std.log.info("[DSTORAGE] CreateStatusArray(capacity={d}) -> S_OK", .{capacity});
    ppv.* = &g_dstorage_status_instance;
    return 0;
}
fn f_SetDebugFlags(_: *IDStorageFactory, flags: u32) callconv(.{ .x86_64_win = .{} }) void {
    std.log.info("[DSTORAGE] SetDebugFlags(0x{x})", .{flags});
}
fn f_SetCpuAffinity(_: *IDStorageFactory, mask: u64) callconv(.{ .x86_64_win = .{} }) i32 {
    std.log.info("[DSTORAGE] SetCpuAffinity(0x{x}) -> S_OK", .{mask});
    return 0;
}
fn f_SetStagingBufferSize(_: *IDStorageFactory, size: u32) callconv(.{ .x86_64_win = .{} }) i32 {
    std.log.info("[DSTORAGE] SetStagingBufferSize(0x{x}) -> S_OK", .{size});
    return 0;
}
fn f_ReservedSlot9(_: *IDStorageFactory) callconv(.{ .x86_64_win = .{} }) i32 {
    return 0;
}
fn f_CreateQueue(_: *IDStorageFactory, _: ?*const anyopaque, _: ?*const anyopaque, ppv: *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32 {
    std.log.info("[DSTORAGE] CreateQueue() -> S_OK (0x{x})", .{@intFromPtr(&g_dstorage_queue_instance)});
    ppv.* = &g_dstorage_queue_instance;
    return 0;
}

fn f_ReservedFactory(_: *IDStorageFactory) callconv(.{ .x86_64_win = .{} }) i32 {
    return -2147467263; // E_NOTIMPL
}

const g_dstorage_factory_vtbl = IDStorageFactoryVtbl{
    .QueryInterface = &f_QueryInterface,
    .AddRef = &f_AddRef,
    .Release = &f_Release,
    .CreateQueueLegacy = &f_CreateQueue,
    .OpenFile = &f_OpenFile,
    .CreateStatusArray = &f_CreateStatusArray,
    .SetCpuAffinity = &f_SetCpuAffinity,
    .SetDebugFlags = &f_SetDebugFlags,
    .SetStagingBufferSize = &f_SetStagingBufferSize,
    .ReservedSlot9 = &f_ReservedSlot9,
    .CreateQueue = &f_CreateQueue,
    .ReservedSlot11 = &f_ReservedFactory,
    .ReservedSlot12 = &f_ReservedFactory,
    .ReservedSlot13 = &f_ReservedFactory,
    .ReservedSlot14 = &f_ReservedFactory,
    .ReservedSlot15 = &f_ReservedFactory,
};

var g_dstorage_factory_instance = IDStorageFactory{
    .lpVtbl = &g_dstorage_factory_vtbl,
};

pub fn shim_DStorageGetFactory(riid: ?*const anyopaque, ppv: ?*?*IDStorageFactory) callconv(.{ .x86_64_win = .{} }) i32 {
    _ = riid;
    std.log.info("[DSTORAGE] DStorageGetFactory() -> S_OK (0x{x})", .{@intFromPtr(&g_dstorage_factory_instance)});
    if (ppv) |out| {
        out.* = &g_dstorage_factory_instance;
    }
    return 0;
}

pub fn resolve(sym_name: []const u8) ?usize {
    if (std.mem.eql(u8, sym_name, "DStorageGetFactory")) {
        return @intFromPtr(&shim_DStorageGetFactory);
    }
    return null;
}
