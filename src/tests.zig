const std = @import("std");
const pe_loader = @import("pe_loader.zig");
const module = @import("module.zig");

test {
    _ = @import("sync.zig");
    _ = @import("teb.zig");
    _ = @import("shims/win32_fs.zig");
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
