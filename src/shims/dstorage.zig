const std = @import("std");
const win32_fs = @import("win32_fs.zig");

var g_req_logs = std.atomic.Value(u32).init(0);

const c_stdio = struct {
    extern "c" fn fseek(stream: *std.c.FILE, offset: c_long, whence: c_int) c_int;
    extern "c" fn ftell(stream: *std.c.FILE) c_long;
};

pub const IDStorageFileVtbl = extern struct {
    QueryInterface: *const fn (*IDStorageFile, ?*const anyopaque, *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32,
    AddRef: *const fn (*IDStorageFile) callconv(.{ .x86_64_win = .{} }) u32,
    Release: *const fn (*IDStorageFile) callconv(.{ .x86_64_win = .{} }) u32,
    Close: *const fn (*IDStorageFile) callconv(.{ .x86_64_win = .{} }) void,
    GetFileInformation: *const fn (*IDStorageFile, ?[*]u8) callconv(.{ .x86_64_win = .{} }) i32,
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
fn file_Close(self: *IDStorageFile) callconv(.{ .x86_64_win = .{} }) void {
    if (self.fp) |f| {
        _ = std.c.fclose(f);
        self.fp = null;
    }
}
fn file_GetFileInformation(self: *IDStorageFile, info_out: ?[*]u8) callconv(.{ .x86_64_win = .{} }) i32 {
    if (info_out) |out| {
        @memset(out[0..52], 0);
        std.mem.writeInt(u32, out[0..4], 0x80, .little);
        std.mem.writeInt(u32, out[32..36], @truncate(self.size >> 32), .little);
        std.mem.writeInt(u32, out[36..40], @truncate(self.size & 0xFFFFFFFF), .little);
    }
    return 0;
}

const g_dstorage_file_vtbl = IDStorageFileVtbl{
    .QueryInterface = &file_QueryInterface,
    .AddRef = &file_AddRef,
    .Release = &file_Release,
    .Close = &file_Close,
    .GetFileInformation = &file_GetFileInformation,
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
fn q_EnqueueRequest(_: *IDStorageQueue, req_ptr: ?[*]const u8) callconv(.{ .x86_64_win = .{} }) void {
    const req = req_ptr orelse return;
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
    const req_log = g_req_logs.fetchAdd(1, .monotonic);
    if (req_log < 16) {
        std.log.info("[DSTORAGE] request src_type={d} dst=0x{x}+0x{x} size=0x{x} src=0x{x} src_off=0x{x}", .{
            source_type, dst_addr, dst_offset, dst_size,
            std.mem.readInt(usize, req[0x10..0x18], .little),
            std.mem.readInt(u32, req[0x18..0x1C], .little),
        });
    }
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


fn q_EnqueueStatus(_: *IDStorageQueue, _: ?*anyopaque, _: u32) callconv(.{ .x86_64_win = .{} }) void {}
fn q_EnqueueSignal(_: *IDStorageQueue, _: ?*anyopaque, _: u64) callconv(.{ .x86_64_win = .{} }) void {}
fn q_Submit(_: *IDStorageQueue) callconv(.{ .x86_64_win = .{} }) void {}
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
    SetDebugFlags: *const fn (*IDStorageFactory, u32) callconv(.{ .x86_64_win = .{} }) void,
    SetCpuAffinity: *const fn (*IDStorageFactory, u64) callconv(.{ .x86_64_win = .{} }) i32,
    SetStagingBufferSize: *const fn (*IDStorageFactory, u32) callconv(.{ .x86_64_win = .{} }) i32,
    ReservedSlot9: *const fn (*IDStorageFactory) callconv(.{ .x86_64_win = .{} }) i32,
    CreateQueue: *const fn (*IDStorageFactory, ?*const anyopaque, ?*const anyopaque, *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32,
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

    std.log.info("[DSTORAGE] OpenFile(\"{s}\", size={d}) -> S_OK (0x{x})", .{ written, obj.size, @intFromPtr(obj) });
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

const g_dstorage_factory_vtbl = IDStorageFactoryVtbl{
    .QueryInterface = &f_QueryInterface,
    .AddRef = &f_AddRef,
    .Release = &f_Release,
    .CreateQueueLegacy = &f_CreateQueue,
    .OpenFile = &f_OpenFile,
    .CreateStatusArray = &f_CreateStatusArray,
    .SetDebugFlags = &f_SetDebugFlags,
    .SetCpuAffinity = &f_SetCpuAffinity,
    .SetStagingBufferSize = &f_SetStagingBufferSize,
    .ReservedSlot9 = &f_ReservedSlot9,
    .CreateQueue = &f_CreateQueue,
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
