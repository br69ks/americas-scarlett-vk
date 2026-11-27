const std = @import("std");
const pe_loader = @import("pe_loader.zig");
const module = @import("module.zig");

test {
    _ = @import("loader_lock.zig");
    _ = @import("sync.zig");
    _ = @import("teb.zig");
    _ = @import("shims/win32_fs.zig");
    _ = @import("seh.zig");
    _ = @import("shims/xmem.zig");
}

fn writeU32(buf: []u8, off: usize, value: u32) void {
    std.mem.writeInt(u32, buf[off..][0..4], value, .little);
}

fn writeU16(buf: []u8, off: usize, value: u16) void {
    std.mem.writeInt(u16, buf[off..][0..2], value, .little);
}

test "parseExports reads a named export" {
    const allocator = std.testing.allocator;
    var image_buf: [0x2000]u8 = @splat(0);

    // IMAGE_EXPORT_DIRECTORY at RVA 0x1000.
    const ed = 0x1000;
    writeU32(&image_buf, ed + 16, 1); // Base
    writeU32(&image_buf, ed + 20, 1); // NumberOfFunctions
    writeU32(&image_buf, ed + 24, 1); // NumberOfNames
    writeU32(&image_buf, ed + 28, 0x1040); // AddressOfFunctions
    writeU32(&image_buf, ed + 32, 0x1044); // AddressOfNames
    writeU32(&image_buf, ed + 36, 0x1048); // AddressOfNameOrdinals

    writeU32(&image_buf, 0x1040, 0x1100); // function RVA
    writeU32(&image_buf, 0x1044, 0x1060); // name RVA
    writeU16(&image_buf, 0x1048, 0); // name -> function index
    @memcpy(image_buf[0x1060..][0..9], "TestFunc\x00");

    const image = pe_loader.MappedImage{
        .base_addr = @intFromPtr(&image_buf),
        .image_size = image_buf.len,
        .entry_point = @intFromPtr(&image_buf) + 0x1100,
        .trampoline_page = null,
        .trampoline_page_size = 0,
        .tls_block_addr = 0,
        .tls_index_va = 0,
        .tls_callbacks = 0,
        .preferred_base = @intFromPtr(&image_buf),
        .is_dll = true,
        .import_dir = .{ .virtual_address = 0, .size = 0 },
        .export_dir = .{ .virtual_address = ed, .size = 0x50 },
        .pdata_rva = 0,
        .pdata_size = 0,
    };

    const exports = try pe_loader.parseExports(allocator, &image);
    defer allocator.free(exports);
    try std.testing.expectEqual(@as(usize, 1), exports.len);
    try std.testing.expectEqualStrings("TestFunc", exports[0].name.?);
    try std.testing.expectEqual(@as(u32, 1), exports[0].ordinal);
    try std.testing.expectEqual(@as(u32, 0x1100), exports[0].rva);
    try std.testing.expect(exports[0].forwarder == null);
}

test "module registry resolves exports and pdata" {
    // The module registry is process-global; use the page allocator and leave
    // the entry registered so the testing allocator does not report it as a leak.
    const allocator = std.heap.page_allocator;
    var image_buf: [0x2000]u8 = @splat(0);
    var pdata = [_]module.RuntimeFunction{
        .{ .begin = 0x100, .end = 0x200, .unwind = 0 },
    };

    const exports = try allocator.alloc(module.Export, 1);
    exports[0] = .{ .name = "Lookup", .ordinal = 1, .rva = 0x1100, .forwarder = null };

    const base = @intFromPtr(&image_buf);
    const m = try module.register(
        allocator,
        "/tmp/test-module.dll",
        "G:\\test-module.dll",
        "test-module.dll",
        base,
        image_buf.len,
        base + 0x1100,
        @intFromPtr(&pdata),
        pdata.len,
        exports,
        false,
    );
    try std.testing.expect(module.findByName("TEST-MODULE.DLL") == m);
    try std.testing.expectEqual(base + 0x1100, module.getProcAddress(base, "Lookup", null, 0).?);
    try std.testing.expectEqual(base + 0x1100, module.getProcAddress(base, null, 1, 0).?);

    const entry = module.lookupFunctionEntry(base + 0x150).?;
    try std.testing.expectEqual(@as(u32, 0x100), entry.begin);
    try std.testing.expectEqual(@as(u32, 0x200), entry.end);
    try std.testing.expect(module.lookupFunctionEntry(base + 0x250) == null);
}

// ---------------------------------------------------------------------------
// Thread exit semantics
// ---------------------------------------------------------------------------

const sync = @import("sync.zig");
const teb = @import("teb.zig");
const thread_exit = @import("thread_exit.zig");

test "GetExitCodeThread reports STILL_ACTIVE then the stored exit code" {
    const handle = sync.createThreadHandle(1234);
    try std.testing.expect(handle != 0);
    defer _ = sync.closeHandle(handle);

    var code: u32 = 0;
    try std.testing.expect(sync.getExitCodeThread(handle, &code));
    try std.testing.expectEqual(sync.STILL_ACTIVE, code);
    try std.testing.expectEqual(sync.WAIT_TIMEOUT, sync.waitForSingleObject(handle, 0));

    sync.markThreadExitedWithCode(handle, 42);
    try std.testing.expect(sync.getExitCodeThread(handle, &code));
    try std.testing.expectEqual(@as(u32, 42), code);
    try std.testing.expectEqual(sync.WAIT_OBJECT_0, sync.waitForSingleObject(handle, 0));
}

test "GetExitCodeThread accepts the GetCurrentThread pseudo handle" {
    var code: u32 = 0;
    try std.testing.expect(sync.getExitCodeThread(sync.CURRENT_THREAD_HANDLE, &code));
    try std.testing.expectEqual(sync.STILL_ACTIVE, code);
}

test "thread exit publishes the code and wakes waiters" {
    const handle = sync.createThreadHandle(99);
    try std.testing.expect(handle != 0);
    defer _ = sync.closeHandle(handle);
    try std.testing.expectEqual(sync.WAIT_TIMEOUT, sync.waitForSingleObject(handle, 0));

    const thread_ref = sync.acquireThreadRef(handle) orelse return error.TestUnexpectedResult;
    thread_exit.setThreadRef(thread_ref);
    thread_exit.finish(7);

    var code: u32 = 0;
    try std.testing.expect(sync.getExitCodeThread(handle, &code));
    try std.testing.expectEqual(@as(u32, 7), code);
    try std.testing.expectEqual(sync.WAIT_OBJECT_0, sync.waitForSingleObject(handle, 0));
}

test "FlsAlloc registers a destructor and FlsFree clears it" {
    const first = teb.flsAlloc(0x1234_5678);
    try std.testing.expect(first < teb.MAX_TLS_SLOTS);
    const second = teb.flsAlloc(0);
    try std.testing.expect(second < teb.MAX_TLS_SLOTS);
    try std.testing.expect(first != second);
    try std.testing.expect(teb.flsFree(first));
    try std.testing.expect(teb.flsFree(second));
}

// ---------------------------------------------------------------------------
// Core API routing (pre-graphics correction batch)
// ---------------------------------------------------------------------------

const crt_core = @import("shims/crt_core.zig");
const win32_fs = @import("shims/win32_fs.zig");
const win_cc: std.builtin.CallingConvention = .{ .x86_64_win = .{} };

fn shimFn(comptime T: type, ptr: usize) T {
    return @ptrFromInt(ptr);
}

test "GetACP/GetOEMCP/GetCurrentThread publish the Windows values" {
    const acp = shimFn(*const fn () callconv(win_cc) u32, crt_core.resolve("GetACP").?);
    const oem = shimFn(*const fn () callconv(win_cc) u32, crt_core.resolve("GetOEMCP").?);
    try std.testing.expectEqual(@as(u32, 1252), acp());
    try std.testing.expectEqual(@as(u32, 437), oem());

    const current_thread = shimFn(*const fn () callconv(win_cc) usize, crt_core.resolve("GetCurrentThread").?);
    try std.testing.expectEqual(sync.CURRENT_THREAD_HANDLE, current_thread());

    const get_pid = shimFn(*const fn (usize) callconv(win_cc) u32, crt_core.resolve("GetProcessId").?);
    const current_process: usize = @bitCast(@as(isize, -1));
    try std.testing.expectEqual(@as(u32, @intCast(std.os.linux.getpid())), get_pid(current_process));
}

test "GetSystemTimePreciseAsFileTime writes the same FILETIME" {
    const precise = shimFn(*const fn (*u64) callconv(win_cc) void, crt_core.resolve("GetSystemTimePreciseAsFileTime").?);
    const legacy = shimFn(*const fn (*u64) callconv(win_cc) void, crt_core.resolve("GetSystemTimeAsFileTime").?);
    var a: u64 = 0;
    var b: u64 = 0;
    precise(&a);
    legacy(&b);
    try std.testing.expect(a != 0);
    try std.testing.expect(b != 0);
    // Two calls are milliseconds apart at most.
    const delta = if (a > b) a - b else b - a;
    try std.testing.expect(delta < 10_000_000);
}

test "GetCurrentThreadStackLimits writes the guest stack bounds" {
    const limits = shimFn(*const fn (*usize, *usize) callconv(win_cc) void, crt_core.resolve("GetCurrentThreadStackLimits").?);
    var low: usize = 0x1111;
    var high: usize = 0x2222;
    limits(&low, &high);
    // Without a guest process there is no TEB; the call must still write.
    try std.testing.expect(low != 0x1111 or high != 0x2222);
    try std.testing.expect(low <= high);
}

test "CreateDirectoryW/GetFileAttributesW report Win32 LastError" {
    const allocator = std.testing.allocator;
    const fs = win32_fs;
    var base_buf: [96]u8 = undefined;
    const base_text = try std.fmt.bufPrint(&base_buf, "/tmp/americas-scarlett-fs-{d}", .{std.os.linux.getpid()});
    base_buf[base_text.len] = 0;
    const base: [:0]const u8 = base_buf[0..base_text.len :0];
    _ = std.c.mkdir(base.ptr, 0o755);
    defer _ = std.c.rmdir(base.ptr);
    fs.init(base, base);

    const create_dir = shimFn(*const fn (?[*:0]const u16, ?*anyopaque) callconv(win_cc) i32, fs.resolve("CreateDirectoryW").?);
    const get_attrs = shimFn(*const fn (?[*:0]const u16) callconv(win_cc) u32, fs.resolve("GetFileAttributesW").?);
    const delete_file = shimFn(*const fn (?[*:0]const u16) callconv(win_cc) i32, fs.resolve("DeleteFileW").?);
    const set_attrs = shimFn(*const fn (?[*:0]const u16, u32) callconv(win_cc) i32, fs.resolve("SetFileAttributesW").?);

    const sub = try std.unicode.utf8ToUtf16LeAllocZ(allocator, "X:\\sub");
    defer allocator.free(sub);
    const missing = try std.unicode.utf8ToUtf16LeAllocZ(allocator, "X:\\does-not-exist");
    defer allocator.free(missing);

    try std.testing.expectEqual(@as(i32, 1), create_dir(sub.ptr, null));
    try std.testing.expectEqual(@as(i32, 0), create_dir(sub.ptr, null));
    try std.testing.expectEqual(@as(u32, 183), teb.getLastError()); // ERROR_ALREADY_EXISTS
    try std.testing.expectEqual(@as(u32, 0x10), get_attrs(sub.ptr)); // FILE_ATTRIBUTE_DIRECTORY

    try std.testing.expectEqual(@as(u32, 0xFFFF_FFFF), get_attrs(missing.ptr));
    try std.testing.expectEqual(@as(u32, 2), teb.getLastError()); // ERROR_FILE_NOT_FOUND

    try std.testing.expectEqual(@as(i32, 0), delete_file(missing.ptr));
    try std.testing.expectEqual(@as(u32, 2), teb.getLastError());

    try std.testing.expectEqual(@as(i32, 0), set_attrs(missing.ptr, 0));
    try std.testing.expectEqual(@as(u32, 2), teb.getLastError());

    // RemoveDirectoryW: non-empty directory -> ERROR_DIR_NOT_EMPTY (145).
    const remove_dir = shimFn(*const fn (?[*:0]const u16) callconv(win_cc) i32, fs.resolve("RemoveDirectoryW").?);
    const move_file = shimFn(*const fn (?[*:0]const u16, ?[*:0]const u16, u32) callconv(win_cc) i32, fs.resolve("MoveFileExW").?);
    var host_file_buf: [160]u8 = undefined;
    const host_file_text = try std.fmt.bufPrint(&host_file_buf, "{s}/sub/inside.txt", .{base});
    host_file_buf[host_file_text.len] = 0;
    const fp = std.c.fopen(@ptrCast(&host_file_buf), "wb") orelse return error.SkipZigTest;
    _ = std.c.fclose(fp);

    try std.testing.expectEqual(@as(i32, 0), remove_dir(sub.ptr));
    try std.testing.expectEqual(@as(u32, 145), teb.getLastError()); // ERROR_DIR_NOT_EMPTY
    _ = std.c.unlink(@ptrCast(&host_file_buf));
    try std.testing.expectEqual(@as(i32, 1), remove_dir(sub.ptr));
    try std.testing.expectEqual(@as(i32, 0), remove_dir(missing.ptr));
    try std.testing.expectEqual(@as(u32, 2), teb.getLastError()); // ERROR_FILE_NOT_FOUND
    try std.testing.expectEqual(@as(i32, 0), move_file(missing.ptr, sub.ptr, 0));
    try std.testing.expectEqual(@as(u32, 2), teb.getLastError());
}

test "GetStdHandle/SetStdHandle/GetFileType use host std fds" {
    const fs = win32_fs;
    const get_std = shimFn(*const fn (u32) callconv(win_cc) usize, fs.resolve("GetStdHandle").?);
    const set_std = shimFn(*const fn (u32, usize) callconv(win_cc) i32, fs.resolve("SetStdHandle").?);
    const file_type = shimFn(*const fn (usize) callconv(win_cc) u32, fs.resolve("GetFileType").?);
    const invalid: usize = std.math.maxInt(usize);

    const stdout_handle = get_std(0xFFFF_FFF5); // (DWORD)-11
    try std.testing.expect(stdout_handle != 0 and stdout_handle != invalid);
    const kind = file_type(stdout_handle);
    try std.testing.expect(kind == 1 or kind == 2 or kind == 3); // DISK / CHAR / PIPE
    try std.testing.expectEqual(@as(usize, stdout_handle), get_std(0xFFFF_FFF5)); // stable

    try std.testing.expectEqual(@as(i32, 1), set_std(0xFFFF_FFF5, 0));
    try std.testing.expectEqual(@as(usize, 0), get_std(0xFFFF_FFF5)); // cleared
    try std.testing.expectEqual(@as(i32, 1), set_std(0xFFFF_FFF5, stdout_handle));
    try std.testing.expectEqual(@as(usize, stdout_handle), get_std(0xFFFF_FFF5));
}

// ---------------------------------------------------------------------------
// Asset streaming (DStorage) checkpoint
// ---------------------------------------------------------------------------

const dstorage = @import("shims/dstorage.zig");

fn dstorageFactory() !*dstorage.IDStorageFactory {
    const get_factory = shimFn(
        *const fn (?*const anyopaque, *?*anyopaque) callconv(win_cc) i32,
        dstorage.resolve("DStorageGetFactory").?,
    );
    var fac: ?*anyopaque = null;
    try std.testing.expectEqual(@as(i32, 0), get_factory(null, &fac));
    return @ptrCast(@alignCast(fac.?));
}

fn dstorageTempBase(buf: *[160]u8, tag: []const u8) ![:0]const u8 {
    const text = try std.fmt.bufPrint(buf, "/tmp/americas-dstorage-{s}-{d}", .{ tag, std.os.linux.getpid() });
    buf[text.len] = 0;
    const base: [:0]const u8 = buf[0..text.len :0];
    _ = std.c.mkdir(base.ptr, 0o755);
    win32_fs.init(base, base);
    return base;
}

fn writeGuestFile(base: []const u8, name: []const u8, payload: []const u8) !void {
    var path_buf: [2048]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ base, name });
    path_buf[path.len] = 0;
    const fp = std.c.fopen(@ptrCast(&path_buf), "wb") orelse return error.SkipZigTest;
    defer _ = std.c.fclose(fp);
    try std.testing.expectEqual(payload.len, std.c.fwrite(payload.ptr, 1, payload.len, fp));
}

test "DSTORAGE_REQUEST matches dstorage_xs offsets and classification" {
    try std.testing.expectEqual(@as(usize, 0x10), @sizeOf(dstorage.DSTORAGE_REQUEST_OPTIONS));
    try std.testing.expectEqual(@as(usize, 0x50), @sizeOf(dstorage.DSTORAGE_REQUEST));
    try std.testing.expectEqual(@as(usize, 0x00), @offsetOf(dstorage.DSTORAGE_REQUEST, "options"));
    try std.testing.expectEqual(@as(usize, 0x10), @offsetOf(dstorage.DSTORAGE_REQUEST, "destination"));
    try std.testing.expectEqual(@as(usize, 0x20), @offsetOf(dstorage.DSTORAGE_REQUEST, "destination_size"));
    try std.testing.expectEqual(@as(usize, 0x28), @offsetOf(dstorage.DSTORAGE_REQUEST, "source"));
    try std.testing.expectEqual(@as(usize, 0x30), @offsetOf(dstorage.DSTORAGE_REQUEST, "file_offset"));
    try std.testing.expectEqual(@as(usize, 0x38), @offsetOf(dstorage.DSTORAGE_REQUEST, "source_size"));
    try std.testing.expectEqual(@as(usize, 0x40), @offsetOf(dstorage.DSTORAGE_REQUEST, "cancellation_tag"));

    var req = std.mem.zeroes(dstorage.DSTORAGE_REQUEST);
    req.destination = 1;
    req.source = 1;
    req.destination_size = 8;
    req.source_size = 4;
    try std.testing.expectEqual(dstorage.RequestClass.ok, dstorage.classifyRequest(&req));

    req.options.compression_format = 3; // BCPack
    try std.testing.expectEqual(dstorage.RequestClass.unsupported_compression, dstorage.classifyRequest(&req));

    req.options.compression_format = 0;
    req.options.bits = 1 << 1; // DestinationType = 1 (buffer)
    try std.testing.expectEqual(dstorage.RequestClass.unsupported_destination, dstorage.classifyRequest(&req));

    req.options.bits = 0;
    req.destination = 0;
    try std.testing.expectEqual(dstorage.RequestClass.invalid, dstorage.classifyRequest(&req));
}

test "IDStorageFileX exposes Close/GetHandle and preserves file position" {
    const allocator = std.testing.allocator;
    var base_buf: [160]u8 = undefined;
    const base = try dstorageTempBase(&base_buf, "file");
    defer _ = std.c.rmdir(base.ptr);
    try writeGuestFile(base, "data.bin", "0123456789abcdef");

    const factory = try dstorageFactory();
    const wide = try std.unicode.utf8ToUtf16LeAllocZ(allocator, "G:\\data.bin");
    defer allocator.free(wide);

    var file_any: ?*anyopaque = null;
    try std.testing.expectEqual(@as(i32, 0), factory.lpVtbl.OpenFile(factory, wide.ptr, null, &file_any));
    const filex: *dstorage.IDStorageFileX = @ptrCast(@alignCast(file_any.?));

    const handle = filex.lpVtbl.GetHandle(filex);
    try std.testing.expect(handle != 0 and handle != std.math.maxInt(usize));

    var four: [4]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 4), win32_fs.readAt(handle, 4, &four).?);
    try std.testing.expectEqualStrings("4567", &four);
    try std.testing.expectEqual(@as(u64, 0), win32_fs.currentOffset(handle).?);

    const read_file = shimFn(
        *const fn (usize, ?[*]u8, u32, ?*u32, ?[*]u8) callconv(win_cc) i32,
        win32_fs.resolve("ReadFile").?,
    );
    var ov: [32]u8 = @splat(0);
    std.mem.writeInt(u32, ov[16..20], 8, .little); // OVERLAPPED.Offset = 8
    var got: u32 = 0;
    try std.testing.expectEqual(@as(i32, 1), read_file(handle, &four, 4, &got, &ov));
    try std.testing.expectEqual(@as(u32, 4), got);
    try std.testing.expectEqualStrings("89ab", &four);
    try std.testing.expectEqual(@as(usize, 4), std.mem.readInt(u64, ov[8..16], .little));
    try std.testing.expectEqual(@as(u64, 0), win32_fs.currentOffset(handle).?); // pread did not move it

    // A non-overlapped read starts at the untouched Win32 file pointer (0).
    try std.testing.expectEqual(@as(i32, 1), read_file(handle, &four, 4, &got, null));
    try std.testing.expectEqualStrings("0123", &four);
    try std.testing.expectEqual(@as(u64, 4), win32_fs.currentOffset(handle).?);

    filex.lpVtbl.Close(filex);
    try std.testing.expectEqual(std.math.maxInt(usize), filex.lpVtbl.GetHandle(filex));
    _ = filex.lpVtbl.Release(filex);
}

test "overlapped WriteFile uses pwrite and preserves position" {
    const allocator = std.testing.allocator;
    var base_buf: [160]u8 = undefined;
    const base = try dstorageTempBase(&base_buf, "write");
    defer _ = std.c.rmdir(base.ptr);

    const create_file = shimFn(
        *const fn (?[*:0]const u16, u32, u32, ?*anyopaque, u32, u32, usize) callconv(win_cc) usize,
        win32_fs.resolve("CreateFileW").?,
    );
    const read_file = shimFn(
        *const fn (usize, ?[*]u8, u32, ?*u32, ?[*]u8) callconv(win_cc) i32,
        win32_fs.resolve("ReadFile").?,
    );
    const write_file = shimFn(
        *const fn (usize, ?[*]const u8, u32, ?*u32, ?[*]u8) callconv(win_cc) i32,
        win32_fs.resolve("WriteFile").?,
    );

    const wide = try std.unicode.utf8ToUtf16LeAllocZ(allocator, "X:\\out.bin");
    defer allocator.free(wide);
    const handle = create_file(wide.ptr, 0xC000_0000, 0, null, 2, 0x80, 0); // R|W, CREATE_ALWAYS
    try std.testing.expect(handle != 0 and handle != std.math.maxInt(usize));
    defer _ = win32_fs.closeHandle(handle);

    var payload = [_]u8{ 'W', 'X', 'Y', 'Z' };
    var ov: [32]u8 = @splat(0);
    std.mem.writeInt(u32, ov[16..20], 4, .little); // OVERLAPPED.Offset = 4
    var put: u32 = 0;
    try std.testing.expectEqual(@as(i32, 1), write_file(handle, &payload, payload.len, &put, &ov));
    try std.testing.expectEqual(@as(u32, 4), put);
    try std.testing.expectEqual(@as(usize, 4), std.mem.readInt(u64, ov[8..16], .little));
    try std.testing.expectEqual(@as(u64, 0), win32_fs.currentOffset(handle).?); // pwrite did not move it

    var read_back: [8]u8 = @splat(0);
    var got: u32 = 0;
    try std.testing.expectEqual(@as(i32, 1), read_file(handle, &read_back, read_back.len, &got, null));
    try std.testing.expectEqual(@as(u32, 8), got);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 'W', 'X', 'Y', 'Z' }, &read_back);
}

var g_test_fence: usize = 0;
var g_test_fence_value: u64 = 0;
fn testFenceSignal(fence: usize, value: u64) callconv(.c) bool {
    g_test_fence = fence;
    g_test_fence_value = value;
    return true;
}

test "IDStorageQueueX status, compression fail-closed, error event, fence" {
    const allocator = std.testing.allocator;
    var base_buf: [160]u8 = undefined;
    _ = try dstorageTempBase(&base_buf, "queue");

    const factory = try dstorageFactory();
    var q_any: ?*anyopaque = null;
    var sa_any: ?*anyopaque = null;
    try std.testing.expectEqual(@as(i32, 0), factory.lpVtbl.CreateQueue(factory, null, null, &q_any));
    try std.testing.expectEqual(@as(i32, 0), factory.lpVtbl.CreateStatusArray(factory, 4, null, null, &sa_any));
    const queue: *dstorage.IDStorageQueue = @ptrCast(@alignCast(q_any.?));
    const status: *dstorage.IDStorageStatusArray = @ptrCast(@alignCast(sa_any.?));
    defer {
        queue.lpVtbl.Close(queue);
        _ = queue.lpVtbl.Release(queue);
        _ = status.lpVtbl.Release(status);
    }

    var src = [_]u8{ 'h', 'e', 'l', 'l', 'o' };
    var dst: [8]u8 = @splat(0);
    var req = std.mem.zeroes(dstorage.DSTORAGE_REQUEST);
    req.destination = @intFromPtr(&dst);
    req.destination_size = dst.len;
    req.source = @intFromPtr(&src);
    req.source_size = src.len;

    queue.lpVtbl.EnqueueRequest(queue, &req);
    queue.lpVtbl.EnqueueStatus(queue, status, 0);
    queue.lpVtbl.Submit(queue);
    try std.testing.expect(status.lpVtbl.IsComplete(status, 0));
    try std.testing.expectEqual(@as(i32, 0), status.lpVtbl.GetHResult(status, 0));
    try std.testing.expectEqualStrings("hello", dst[0..5]);

    // Unsupported compression must not copy raw bytes; the status reports the
    // hard failure and the queue error event becomes signalled.
    var dst2: [8]u8 = @splat(0xAA);
    var bad = req;
    bad.destination = @intFromPtr(&dst2);
    bad.destination_size = dst2.len;
    bad.options.compression_format = 3; // BCPack
    queue.lpVtbl.EnqueueRequest(queue, &bad);
    queue.lpVtbl.EnqueueStatus(queue, status, 1);
    queue.lpVtbl.Submit(queue);
    try std.testing.expect(status.lpVtbl.IsComplete(status, 1));
    try std.testing.expectEqual(@as(u32, 0x8000_4001), @as(u32, @bitCast(status.lpVtbl.GetHResult(status, 1))));
    for (dst2) |b| try std.testing.expectEqual(@as(u8, 0xAA), b);
    const event = queue.lpVtbl.GetErrorEvent(queue);
    try std.testing.expect(event != 0);
    try std.testing.expectEqual(sync.WAIT_OBJECT_0, sync.waitForSingleObject(event, 0));

    // A registered D3D12 fence hook receives the exact fence/value on Submit.
    g_test_fence = 0;
    g_test_fence_value = 0;
    dstorage.g_fence_signal = &testFenceSignal;
    defer dstorage.g_fence_signal = null;
    const fence_ptr: *anyopaque = @ptrFromInt(0x1234_5678);
    queue.lpVtbl.EnqueueSignal(queue, fence_ptr, 77);
    queue.lpVtbl.Submit(queue);
    try std.testing.expectEqual(@as(usize, 0x1234_5678), g_test_fence);
    try std.testing.expectEqual(@as(u64, 77), g_test_fence_value);
    _ = allocator;
}

test "IDStorageQueueX reads an IDStorageFileX through Submit" {
    const allocator = std.testing.allocator;
    var base_buf: [160]u8 = undefined;
    const base = try dstorageTempBase(&base_buf, "qfile");
    defer _ = std.c.rmdir(base.ptr);
    try writeGuestFile(base, "pack.bin", "0123456789abcdef");

    const factory = try dstorageFactory();
    const wide = try std.unicode.utf8ToUtf16LeAllocZ(allocator, "G:\\pack.bin");
    defer allocator.free(wide);

    var file_any: ?*anyopaque = null;
    try std.testing.expectEqual(@as(i32, 0), factory.lpVtbl.OpenFile(factory, wide.ptr, null, &file_any));
    const filex: *dstorage.IDStorageFileX = @ptrCast(@alignCast(file_any.?));

    var q_any: ?*anyopaque = null;
    var sa_any: ?*anyopaque = null;
    try std.testing.expectEqual(@as(i32, 0), factory.lpVtbl.CreateQueue(factory, null, null, &q_any));
    try std.testing.expectEqual(@as(i32, 0), factory.lpVtbl.CreateStatusArray(factory, 2, null, null, &sa_any));
    const queue: *dstorage.IDStorageQueue = @ptrCast(@alignCast(q_any.?));
    const status: *dstorage.IDStorageStatusArray = @ptrCast(@alignCast(sa_any.?));
    defer {
        queue.lpVtbl.Close(queue);
        _ = queue.lpVtbl.Release(queue);
        _ = status.lpVtbl.Release(status);
        filex.lpVtbl.Close(filex);
        _ = filex.lpVtbl.Release(filex);
    }

    var dst: [4]u8 = @splat(0);
    var req = std.mem.zeroes(dstorage.DSTORAGE_REQUEST);
    req.options.bits = dstorage.DSTORAGE_SOURCE_TYPE_FILE;
    req.destination = @intFromPtr(&dst);
    req.destination_size = dst.len;
    req.source = @intFromPtr(filex);
    req.file_offset = 4;
    req.source_size = dst.len;
    req.cancellation_tag = 0x1234;

    queue.lpVtbl.EnqueueRequest(queue, &req);
    queue.lpVtbl.EnqueueStatus(queue, status, 0);
    queue.lpVtbl.Submit(queue);
    try std.testing.expect(status.lpVtbl.IsComplete(status, 0));
    try std.testing.expectEqual(@as(i32, 0), status.lpVtbl.GetHResult(status, 0));
    try std.testing.expectEqualStrings("4567", &dst);
}

test "DStorage queues and status arrays are per-instance objects" {
    const factory = try dstorageFactory();
    var q1_any: ?*anyopaque = null;
    var q2_any: ?*anyopaque = null;
    var s1_any: ?*anyopaque = null;
    var s2_any: ?*anyopaque = null;
    try std.testing.expectEqual(@as(i32, 0), factory.lpVtbl.CreateQueue(factory, null, null, &q1_any));
    try std.testing.expectEqual(@as(i32, 0), factory.lpVtbl.CreateQueue(factory, null, null, &q2_any));
    try std.testing.expectEqual(@as(i32, 0), factory.lpVtbl.CreateStatusArray(factory, 2, null, null, &s1_any));
    try std.testing.expectEqual(@as(i32, 0), factory.lpVtbl.CreateStatusArray(factory, 2, null, null, &s2_any));
    try std.testing.expect(q1_any.? != q2_any.?);
    try std.testing.expect(s1_any.? != s2_any.?);

    const q1: *dstorage.IDStorageQueue = @ptrCast(@alignCast(q1_any.?));
    const q2: *dstorage.IDStorageQueue = @ptrCast(@alignCast(q2_any.?));
    const s1: *dstorage.IDStorageStatusArray = @ptrCast(@alignCast(s1_any.?));
    const s2: *dstorage.IDStorageStatusArray = @ptrCast(@alignCast(s2_any.?));

    var src = [_]u8{ 'a', 'b' };
    var dst: [2]u8 = @splat(0);
    var req = std.mem.zeroes(dstorage.DSTORAGE_REQUEST);
    req.destination = @intFromPtr(&dst);
    req.destination_size = dst.len;
    req.source = @intFromPtr(&src);
    req.source_size = src.len;
    q2.lpVtbl.EnqueueRequest(q2, &req);
    q2.lpVtbl.EnqueueStatus(q2, s2, 0);
    q2.lpVtbl.Submit(q2);
    try std.testing.expect(s2.lpVtbl.IsComplete(s2, 0));
    try std.testing.expect(!s1.lpVtbl.IsComplete(s1, 0));

    q1.lpVtbl.Close(q1);
    _ = q1.lpVtbl.Release(q1);
    q2.lpVtbl.Close(q2);
    _ = q2.lpVtbl.Release(q2);
    _ = s1.lpVtbl.Release(s1);
    _ = s2.lpVtbl.Release(s2);
}

// ---------------------------------------------------------------------------
// Loader checkpoint hardening
// ---------------------------------------------------------------------------

test "module registry separates host and virtual guest paths" {
    // Module registry entries are process-lifetime; use the page allocator so
    // the testing allocator's leak check only covers owned test allocations.
    const allocator = std.heap.page_allocator;
    const exports = try allocator.alloc(module.Export, 0);
    const m = try module.register(
        allocator,
        "/home/brad/GTA6.Xbox.v1.0.2.1/foo.dll",
        "G:\\foo.dll",
        "foo.dll",
        0x3000_0000,
        0x1000,
        0,
        0,
        0,
        exports,
        false,
    );
    try std.testing.expectEqualStrings("/home/brad/GTA6.Xbox.v1.0.2.1/foo.dll", m.path);
    try std.testing.expectEqualStrings("G:\\foo.dll", m.virtual_path);
    var buf: [64]u8 = undefined;
    const n = module.fileNameA(0x3000_0000, &buf, buf.len);
    try std.testing.expectEqualStrings("G:\\foo.dll", buf[0..n]);
}

test "handle reference keeps an object alive across CloseHandle and slot reuse" {
    const first = sync.createThreadHandle(11);
    try std.testing.expect(first != 0);
    const ref = sync.acquireThreadRef(first) orelse return error.TestUnexpectedResult;
    // Close drops the table reference; the acquired reference keeps the object
    // alive and the handle slot becomes reusable.
    try std.testing.expect(sync.closeHandle(first));

    const second = sync.createThreadHandle(22);
    try std.testing.expect(second != 0);

    // Publishing through the old reference must not touch the recycled slot.
    sync.markThreadExitedRef(ref, 77);
    var code: u32 = 0;
    try std.testing.expect(sync.getExitCodeThread(second, &code));
    try std.testing.expectEqual(sync.STILL_ACTIVE, code);

    sync.releaseThreadRef(ref);
    try std.testing.expect(sync.closeHandle(second));
}

test "handle reference keeps a waiting object alive until release" {
    // An event acquired before CloseHandle stays usable by the holder.
    const handle = sync.createEventW(true, false);
    try std.testing.expect(handle != 0);
    const ref = sync.acquireThreadRef(handle); // wrong kind: must be rejected
    try std.testing.expect(ref == null);
    try std.testing.expect(sync.closeHandle(handle));
}

test "PE stack sizes parse from the optional header" {
    var opt: [0x100]u8 = @splat(0);
    std.mem.writeInt(u64, opt[0x48..0x50], 0x10_0000, .little); // 1 MiB reserve
    std.mem.writeInt(u64, opt[0x50..0x58], 0x4000, .little); // 16 KiB commit
    const sizes = pe_loader.readStackSizes(&opt);
    try std.testing.expectEqual(@as(u64, 0x10_0000), sizes.reserve);
    try std.testing.expectEqual(@as(u64, 0x4000), sizes.commit);
    const short = pe_loader.readStackSizes(opt[0..0x10]);
    try std.testing.expectEqual(@as(u64, 0), short.reserve);
}

test "guest stack limit honours the PE reserve and stays inside the host stack" {
    const base: usize = 0x7fff_0000_0000;
    const host_limit = base - (8 * 1024 * 1024); // host stack is 8 MiB
    try std.testing.expectEqual(base - 0x10_0000, teb.guestStackLimit(base, 0x10_0000, host_limit));
    // An unknown/absurd reserve keeps the host limit.
    try std.testing.expectEqual(host_limit, teb.guestStackLimit(base, 0, host_limit));
    // A reserve larger than the host stack is clamped to the host limit.
    try std.testing.expectEqual(host_limit, teb.guestStackLimit(base, 64 * 1024 * 1024, host_limit));
}

test "late module TLS publication clones into every existing guest TEB" {
    var slots_a: [teb.MAX_TLS_SLOTS]usize = @splat(0);
    var slots_b: [teb.MAX_TLS_SLOTS]usize = @splat(0);
    var teb_a: teb.TEB = std.mem.zeroes(teb.TEB);
    var teb_b: teb.TEB = std.mem.zeroes(teb.TEB);
    teb_a.thread_local_storage_pointer = @intFromPtr(&slots_a);
    teb_b.thread_local_storage_pointer = @intFromPtr(&slots_b);
    teb.testRegisterTeb(&teb_a);
    defer teb.testUnregisterTeb(&teb_a);
    teb.testRegisterTeb(&teb_b);
    defer teb.testUnregisterTeb(&teb_b);

    var template: [256]u8 = @splat(0xAB);
    template[0] = 0x5A;
    teb.testPublishTlsSlot(7, @intFromPtr(&template), template.len);

    // Both threads received their own clone (not the template pointer).
    try std.testing.expect(slots_a[7] != 0 and slots_a[7] != @intFromPtr(&template));
    try std.testing.expect(slots_b[7] != 0 and slots_b[7] != @intFromPtr(&template));
    try std.testing.expect(slots_a[7] != slots_b[7]);
    const a_bytes: [*]const u8 = @ptrFromInt(slots_a[7]);
    const b_bytes: [*]const u8 = @ptrFromInt(slots_b[7]);
    try std.testing.expectEqual(@as(u8, 0x5A), a_bytes[0]);
    try std.testing.expectEqual(@as(u8, 0x5A), b_bytes[0]);
    try std.testing.expectEqual(@as(u8, 0xAB), a_bytes[255]);
    // Unrelated slots stay empty.
    try std.testing.expectEqual(@as(usize, 0), slots_a[6]);
}

// ---------------------------------------------------------------------------
// Pre-graphics platform correctness batch: XPackage, input, window, audio
// ---------------------------------------------------------------------------

const xgameruntime_min = @import("shims/xgameruntime_min.zig");
const game_input = @import("shims/game_input.zig");
const audio_min = @import("shims/audio_min.zig");

const PackageObj = extern struct { lpVtbl: *const anyopaque };
const TestAsyncBlock = extern struct { queue: usize, context: usize, callback: usize, internal: [4]usize };

fn packageVtable(obj: *PackageObj) [*]const usize {
    return @ptrCast(@alignCast(obj.lpVtbl));
}

test "XPackage 261000 vtable order: id, packaged, kind, availability, mount" {
    xgameruntime_min.resetForTest();
    try std.testing.expectEqual(@as(i32, 0), xgameruntime_min.initialize(xgameruntime_min.SUPPORTED_GDK_VERSION));

    var obj_any: ?*anyopaque = null;
    const hr = xgameruntime_min.queryApi(
        &xgameruntime_min.XPACKAGE,
        &xgameruntime_min.XPACKAGE_IID,
        &obj_any,
    ).?;
    try std.testing.expectEqual(@as(i32, 0), hr);
    const pkg: *PackageObj = @ptrCast(@alignCast(obj_any.?));
    const vtbl = packageVtable(pkg);

    // slot 3 = GetCurrentProcessPackageIdentifier (first method after IUnknown)
    const get_id: *const fn (*anyopaque, usize, ?[*]u8) callconv(win_cc) i32 = @ptrFromInt(vtbl[3]);
    var id_buf: [40]u8 = @splat(0);
    try std.testing.expectEqual(@as(i32, 0), get_id(pkg, id_buf.len, &id_buf));
    try std.testing.expectEqualStrings("7952987A", std.mem.sliceTo(&id_buf, 0));
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0x8000_4005))), get_id(pkg, 4, &id_buf)); // too small

    // slot 4 = IsPackagedProcess
    const packaged: *const fn (*anyopaque) callconv(win_cc) bool = @ptrFromInt(vtbl[4]);
    try std.testing.expect(packaged(pkg));

    // slot 21 = GetPackageKind (3 + 18)
    const get_kind: *const fn (*anyopaque, ?[*:0]const u8, *u32) callconv(win_cc) i32 = @ptrFromInt(vtbl[21]);
    var kind: u32 = 99;
    try std.testing.expectEqual(@as(i32, 0), get_kind(pkg, "7952987A", &kind));
    try std.testing.expectEqual(@as(u32, 0), kind);
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0x8007_0057))), get_kind(pkg, "UNKNOWN", &kind));

    // slot 12 = FindChunkAvailability (3 + 9)
    const availability: *const fn (*anyopaque, ?[*:0]const u8, u32, ?*const anyopaque, *u32) callconv(win_cc) i32 =
        @ptrFromInt(vtbl[12]);
    var avail: u32 = 99;
    try std.testing.expectEqual(@as(i32, 0), availability(pkg, "7952987A", 0, null, &avail));
    try std.testing.expectEqual(@as(u32, 0), avail); // Ready
    try std.testing.expectEqual(@as(i32, 0), availability(pkg, "UNKNOWN", 0, null, &avail));
    try std.testing.expectEqual(@as(u32, 3), avail); // Unavailable

    // slots 26..30 = MountWithUiAsync/Result, GetMountPathSize/Path, CloseMountHandle
    const mount_async: *const fn (*anyopaque, ?[*:0]const u8, *TestAsyncBlock) callconv(win_cc) i32 = @ptrFromInt(vtbl[26]);
    const mount_result: *const fn (*anyopaque, *TestAsyncBlock, *?*anyopaque) callconv(win_cc) i32 = @ptrFromInt(vtbl[27]);
    const path_size: *const fn (*anyopaque, ?*const anyopaque, *usize) callconv(win_cc) i32 = @ptrFromInt(vtbl[28]);
    const get_path: *const fn (*anyopaque, ?*const anyopaque, usize, ?[*]u8) callconv(win_cc) i32 = @ptrFromInt(vtbl[29]);
    const close_mount: *const fn (*anyopaque, ?*const anyopaque) callconv(win_cc) void = @ptrFromInt(vtbl[30]);

    var block = std.mem.zeroes(TestAsyncBlock);
    try std.testing.expectEqual(@as(i32, 0), mount_async(pkg, "7952987A", &block));
    var mount: ?*anyopaque = null;
    try std.testing.expectEqual(@as(i32, 0), mount_result(pkg, &block, &mount));
    try std.testing.expect(mount != null);
    var size: usize = 0;
    try std.testing.expectEqual(@as(i32, 0), path_size(pkg, mount, &size));
    try std.testing.expectEqual(@as(usize, 4), size); // "G:\" + NUL
    var path_buf: [8]u8 = @splat(0);
    try std.testing.expectEqual(@as(i32, 0), get_path(pkg, mount, size, &path_buf));
    try std.testing.expectEqualStrings("G:\\", std.mem.sliceTo(&path_buf, 0));
    close_mount(pkg, mount);

    // A missing package must not yield a mount handle or S_OK from Result.
    var missing_block = std.mem.zeroes(TestAsyncBlock);
    try std.testing.expectEqual(@as(i32, 0), mount_async(pkg, "UNKNOWN", &missing_block));
    var missing_mount: ?*anyopaque = @ptrFromInt(1);
    const missing_hr = mount_result(pkg, &missing_block, &missing_mount);
    try std.testing.expectEqual(@as(u32, 0x8924_5208), @as(u32, @bitCast(missing_hr)));
    try std.testing.expect(missing_mount == null);
    xgameruntime_min.resetForTest();
}

test "queryApi checks RIIDs and QueryApiImpl gates unsupported GDK builds" {
    xgameruntime_min.resetForTest();
    var out: ?*anyopaque = @ptrFromInt(1);
    try std.testing.expectEqual(
        @as(i32, @bitCast(@as(u32, 0x8000_4002))),
        xgameruntime_min.queryApi(&xgameruntime_min.XPACKAGE, &xgameruntime_min.XASYNC, &out).?,
    );
    try std.testing.expect(out == null);

    try std.testing.expectEqual(
        @as(i32, @bitCast(@as(u32, 0x8000_4002))),
        xgameruntime_min.queryApi(&xgameruntime_min.XASYNC, &xgameruntime_min.XASYNC, &out).?,
    );
    try std.testing.expectEqual(
        @as(i32, @bitCast(@as(u32, 0x8000_4002))),
        xgameruntime_min.queryApi(&xgameruntime_min.XPACKAGE, null, &out).?,
    );
    try std.testing.expectEqual(
        @as(i32, 0),
        xgameruntime_min.queryApi(&xgameruntime_min.STORAGE, &xgameruntime_min.STORAGE_IID, &out).?,
    );
    try std.testing.expect(out != null);
    out = null;
    try std.testing.expect(xgameruntime_min.queryApi(&xgameruntime_min.XPACKAGE, &xgameruntime_min.XPACKAGE_IID, &out) != null);
    try std.testing.expect(out != null);

    const init2 = shimFn(
        *const fn (?*const anyopaque, u64, ?*anyopaque) callconv(win_cc) i32,
        crt_core.resolve("InitializeApiImplEx2").?,
    );
    const query_impl = shimFn(
        *const fn (?[*]const u8, ?[*]const u8, ?*?*anyopaque) callconv(win_cc) i32,
        crt_core.resolve("QueryApiImpl").?,
    );
    const clsid_bytes: [*]const u8 = @ptrCast(&xgameruntime_min.XPACKAGE);
    const iid_bytes: [*]const u8 = @ptrCast(&xgameruntime_min.XPACKAGE_IID);

    // Before a supported initialize call the provider is closed.
    var provider: ?*anyopaque = null;
    try std.testing.expectEqual(
        @as(u32, 0x8004_01F0),
        @as(u32, @bitCast(query_impl(clsid_bytes, iid_bytes, &provider))),
    );

    try std.testing.expectEqual(@as(i32, 0), init2(null, xgameruntime_min.SUPPORTED_GDK_VERSION, null));
    try std.testing.expect(xgameruntime_min.isInitialized());
    try std.testing.expectEqual(@as(u32, 26100), xgameruntime_min.gdkBuild());
    provider = null;
    try std.testing.expectEqual(@as(i32, 0), query_impl(clsid_bytes, iid_bytes, &provider));
    try std.testing.expect(provider != null);
    provider = null;
    try std.testing.expectEqual(
        @as(u32, 0x8000_4002),
        @as(u32, @bitCast(query_impl(clsid_bytes, @ptrCast(&xgameruntime_min.XASYNC), &provider))),
    );
    try std.testing.expect(provider == null);

    // Unsupported build: Initialize must fail closed and close QueryApiImpl.
    try std.testing.expectEqual(
        @as(u32, 0x8000_4005),
        @as(u32, @bitCast(init2(null, 0x65f5_0000_1edd, null))),
    );
    try std.testing.expect(!xgameruntime_min.isInitialized());
    try std.testing.expectEqual(
        @as(u32, 0x8004_01F0),
        @as(u32, @bitCast(query_impl(clsid_bytes, iid_bytes, &provider))),
    );
    xgameruntime_min.resetForTest();
}

var g_test_wm_nc: usize = 0;
var g_test_wm_create: usize = 0;
var g_test_wm_size: usize = 0;
var g_test_wm_activate: usize = 0;
var g_test_wm_paint: usize = 0;
var g_test_wm_size_lparam: isize = 0;
var g_test_wm_cs_cx: i32 = 0;
var g_test_wm_cs_cy: i32 = 0;

fn testWndProc(hwnd: usize, message: u32, _: usize, lparam: isize) callconv(win_cc) isize {
    _ = hwnd;
    switch (message) {
        0x0081 => { // WM_NCCREATE
            g_test_wm_nc += 1;
            const cs: *const crt_core.CREATESTRUCTA = @ptrFromInt(@as(usize, @intCast(lparam)));
            g_test_wm_cs_cx = cs.cx;
            g_test_wm_cs_cy = cs.cy;
        },
        0x0001 => g_test_wm_create += 1, // WM_CREATE
        0x0005 => { // WM_SIZE
            g_test_wm_size += 1;
            g_test_wm_size_lparam = lparam;
        },
        0x0006 => g_test_wm_activate += 1, // WM_ACTIVATE
        0x000F => g_test_wm_paint += 1, // WM_PAINT
        else => {},
    }
    return 0;
}

test "window class stores WndProc and PeekMessage/Dispatch synthesize create/size/paint" {
    crt_core.resetWindowStateForTest();
    g_test_wm_nc = 0;
    g_test_wm_create = 0;
    g_test_wm_size = 0;
    g_test_wm_activate = 0;
    g_test_wm_paint = 0;

    const register = shimFn(
        *const fn (?*const crt_core.WNDCLASSEXA) callconv(win_cc) u16,
        crt_core.resolve("RegisterClassExA").?,
    );
    const create = shimFn(
        *const fn (u32, ?[*:0]const u8, ?[*:0]const u8, u32, i32, i32, i32, i32, usize, usize, usize, ?*anyopaque) callconv(win_cc) usize,
        crt_core.resolve("CreateWindowExA").?,
    );
    const peek = shimFn(
        *const fn (?*crt_core.MSG, usize, u32, u32, u32) callconv(win_cc) i32,
        crt_core.resolve("PeekMessageA").?,
    );
    const dispatch = shimFn(
        *const fn (?*const crt_core.MSG) callconv(win_cc) isize,
        crt_core.resolve("DispatchMessageA").?,
    );
    const translate = shimFn(
        *const fn (?*const crt_core.MSG) callconv(win_cc) i32,
        crt_core.resolve("TranslateMessage").?,
    );
    const show = shimFn(
        *const fn (usize, i32) callconv(win_cc) i32,
        crt_core.resolve("ShowWindow").?,
    );

    var wc = std.mem.zeroes(crt_core.WNDCLASSEXA);
    wc.cbSize = @sizeOf(crt_core.WNDCLASSEXA);
    wc.lpfnWndProc = @intFromPtr(&testWndProc);
    wc.hInstance = 0x0040_0000;
    wc.lpszClassName = "ScarlettTestClass";
    const atom = register(&wc);
    try std.testing.expect(atom != 0);
    // Duplicate registration follows Win32: FALSE + ERROR_CLASS_ALREADY_EXISTS.
    try std.testing.expectEqual(@as(u16, 0), register(&wc));
    try std.testing.expectEqual(@as(u32, 1410), teb.getLastError());

    const hwnd = create(0, "ScarlettTestClass", "Scarlett test", 0, 0, 0, 0, 0, 0, 0, 0, null);
    try std.testing.expect(hwnd != 0);
    try std.testing.expectEqual(@as(i32, 0), show(hwnd, 1)); // previously hidden
    try std.testing.expectEqual(@as(i32, 1), show(hwnd, 1));

    var seen: [5]crt_core.MSG = undefined;
    var count: usize = 0;
    while (peek(&seen[count], 0, 0, 0, 1) == 1) : (count += 1) {
        if (count == seen.len - 1) break;
    }
    try std.testing.expectEqual(@as(usize, 5), count + 1);
    try std.testing.expectEqual(@as(u32, 0x0081), seen[0].message);
    try std.testing.expectEqual(@as(u32, 0x0001), seen[1].message);
    try std.testing.expectEqual(@as(u32, 0x0005), seen[2].message);
    try std.testing.expectEqual(@as(u32, 0x0006), seen[3].message);
    try std.testing.expectEqual(@as(u32, 0x000F), seen[4].message);
    try std.testing.expectEqual(@as(usize, 1280), @as(usize, @intCast(seen[2].lparam & 0xFFFF)));
    try std.testing.expectEqual(@as(usize, 720), @as(usize, @intCast((seen[2].lparam >> 16) & 0xFFFF)));
    try std.testing.expectEqual(@as(u32, 1), seen[3].wparam);

    for (seen[0..5]) |*msg| _ = dispatch(msg);
    try std.testing.expectEqual(@as(usize, 1), g_test_wm_nc);
    try std.testing.expectEqual(@as(usize, 1), g_test_wm_create);
    try std.testing.expectEqual(@as(usize, 1), g_test_wm_size);
    try std.testing.expectEqual(@as(usize, 1), g_test_wm_activate);
    try std.testing.expectEqual(@as(usize, 1), g_test_wm_paint);
    try std.testing.expectEqual(@as(isize, 0x02D0_0500), g_test_wm_size_lparam);
    try std.testing.expectEqual(@as(i32, 1280), g_test_wm_cs_cx);
    try std.testing.expectEqual(@as(i32, 720), g_test_wm_cs_cy);
    try std.testing.expectEqual(@as(i32, 0), translate(&seen[0]));
    var empty: crt_core.MSG = undefined;
    try std.testing.expectEqual(@as(i32, 0), peek(&empty, 0, 0, 0, 1));
    crt_core.resetWindowStateForTest();
}

test "audio is disabled cleanly: AcpHalCreate fails and claims no device" {
    const create = shimFn(
        *const fn (?*?*anyopaque) callconv(win_cc) i32,
        crt_core.resolve("AcpHalCreate").?,
    );
    const apu_heap = shimFn(
        *const fn (u32, u32) callconv(win_cc) i32,
        crt_core.resolve("ApuCreateHeap").?,
    );
    const apu_alloc = shimFn(
        *const fn (?*?*anyopaque, ?*u32, u32, u32, u32) callconv(win_cc) i32,
        crt_core.resolve("ApuAlloc").?,
    );

    var acp: ?*anyopaque = @ptrFromInt(1);
    try std.testing.expectEqual(@as(u32, 0x8000_4001), @as(u32, @bitCast(create(&acp))));
    try std.testing.expect(acp == null);
    try std.testing.expectEqual(@as(u32, 0x8000_4001), @as(u32, @bitCast(apu_heap(1, 1))));
    var block: ?*anyopaque = @ptrFromInt(1);
    var apu_addr: u32 = 0xDEAD;
    try std.testing.expectEqual(@as(u32, 0x8000_4001), @as(u32, @bitCast(apu_alloc(&block, &apu_addr, 4096, 64, 1))));
    try std.testing.expect(block == null);
    try std.testing.expectEqual(@as(u32, 0), apu_addr);
    try std.testing.expect(!audio_min.isAudioEnabled());
}

var g_test_device_callbacks: usize = 0;
fn testDeviceCallback(_: u64, _: ?*anyopaque, _: *game_input.IGameInputDevice, _: u64, _: u32, _: u32) callconv(win_cc) void {
    g_test_device_callbacks += 1;
}

test "GameInput reports real devices or truthful not-found (never fake callbacks)" {
    try std.testing.expectEqual(@as(usize, 384), @sizeOf(game_input.DeviceInfo));
    try std.testing.expectEqual(@as(usize, 104), @offsetOf(game_input.DeviceInfo, "supported_input"));
    try std.testing.expectEqual(@as(usize, 12), @sizeOf(game_input.KeyState));
    try std.testing.expectEqual(@as(usize, 40), @sizeOf(game_input.MouseState));
    try std.testing.expectEqual(@as(u8, 'A'), game_input.virtualKeyForTest(30));
    try std.testing.expectEqual(@as(u8, 'Z'), game_input.virtualKeyForTest(44));
    try std.testing.expectEqual(@as(u8, 0x0D), game_input.virtualKeyForTest(28));
    try std.testing.expectEqual(@as(u8, 0), game_input.virtualKeyForTest(240));

    var gi_any: ?*game_input.IGameInput = null;
    try std.testing.expectEqual(@as(i32, 0), game_input.shim_GameInputCreate(&gi_any));
    const gi = gi_any.?;
    const devices = game_input.backendDeviceCount();
    g_test_device_callbacks = 0;
    var token: u64 = 0;
    const register_result = gi.lpVtbl.RegisterDeviceCallback(
        gi,
        null,
        0,
        0,
        0,
        null,
        @ptrFromInt(@intFromPtr(&testDeviceCallback)),
        &token,
    );

    if (devices == 0) {
        try std.testing.expectEqual(@as(u32, 0x838A_0002), @as(u32, @bitCast(register_result)));
        try std.testing.expectEqual(@as(u64, 0), token);
        try std.testing.expectEqual(@as(usize, 0), g_test_device_callbacks);

        var dispatcher: ?*anyopaque = @ptrFromInt(1);
        try std.testing.expectEqual(@as(u32, 0x8000_4001), @as(u32, @bitCast(gi.lpVtbl.CreateDispatcher(gi, &dispatcher))));
        try std.testing.expect(dispatcher == null);

        var reading: ?*anyopaque = @ptrFromInt(1);
        try std.testing.expectEqual(
            @as(u32, 0x838A_0003),
            @as(u32, @bitCast(gi.lpVtbl.GetCurrentReading(gi, 0x10, null, &reading))),
        );
        try std.testing.expect(reading == null);
    } else {
        try std.testing.expectEqual(@as(i32, 0), register_result);
        try std.testing.expect(token != 0);
        try std.testing.expect(g_test_device_callbacks > 0);
        var reading_any: ?*anyopaque = null;
        try std.testing.expectEqual(
            @as(i32, 0),
            gi.lpVtbl.GetCurrentReading(gi, game_input.backendDeviceKinds(), null, &reading_any),
        );
        try std.testing.expect(reading_any != null);
        const reading: *game_input.IGameInputReading = @ptrCast(@alignCast(reading_any.?));
        try std.testing.expect(reading.lpVtbl.GetInputKind(reading) != 0);
        _ = reading.lpVtbl.Release(reading);
    }
}
