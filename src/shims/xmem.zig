const std = @import("std");
const builtin = @import("builtin");

const c = if (builtin.os.tag == .windows) struct {
    extern "kernel32" fn VirtualAlloc(lpAddress: ?*anyopaque, dwSize: usize, flAllocationType: u32, flProtect: u32) callconv(.{ .x86_64_win = .{} }) ?*anyopaque;
    extern "kernel32" fn VirtualFree(lpAddress: ?*anyopaque, dwSize: usize, dwFreeType: u32) callconv(.{ .x86_64_win = .{} }) i32;
} else struct {
    extern "c" fn mmap(addr: ?*anyopaque, len: usize, prot: i32, flags: i32, fd: i32, offset: i64) ?*anyopaque;
    extern "c" fn munmap(addr: ?*anyopaque, len: usize) i32;
};

fn hostAlloc(lpAddress: ?*anyopaque, dwSize: usize) ?*anyopaque {
    if (dwSize == 0) return null;
    if (builtin.os.tag == .windows) {
        const MEM_COMMIT: u32 = 0x00001000;
        const MEM_RESERVE: u32 = 0x00002000;
        const PAGE_READWRITE: u32 = 0x04;
        return c.VirtualAlloc(lpAddress, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) orelse
        c.VirtualAlloc(null, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    } else {
        const PROT_READ: i32 = 0x1;
        const PROT_WRITE: i32 = 0x2;
        const MAP_PRIVATE: i32 = 0x02;
        const MAP_ANONYMOUS: i32 = 0x20;
        const MAP_NORESERVE: i32 = 0x4000;
        const MAP_FAILED: usize = @bitCast(@as(isize, -1));

        const ptr = c.mmap(lpAddress, dwSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0) orelse return null;
        if (@intFromPtr(ptr) == MAP_FAILED) {
            const fallback = c.mmap(null, dwSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0) orelse return null;
            if (@intFromPtr(fallback) == MAP_FAILED) return null;
            return fallback;
        }
        return ptr;
    }
}

fn shim_XMemVirtualAlloc(
    lpAddress: ?*anyopaque,
    dwSize: usize,
    flAllocationType: u32,
    flProtect: u32,
) callconv(.{ .x86_64_win = .{} }) ?*anyopaque {
    _ = flAllocationType;
    _ = flProtect;
    const ptr = hostAlloc(lpAddress, dwSize);
    std.log.info("[XMEM] XMemVirtualAlloc(addr=0x{x}, size=0x{x}) -> 0x{x}", .{
        @intFromPtr(lpAddress),
                 dwSize,
                 @intFromPtr(ptr),
    });
    return ptr;
}

fn shim_XMemAlloc(dwSize: usize, dwAllocAttributes: u64) callconv(.{ .x86_64_win = .{} }) ?*anyopaque {
    _ = dwAllocAttributes;
    const aligned_size = std.mem.alignForward(usize, @max(dwSize, 4096), 4096);
    const ptr = hostAlloc(null, aligned_size);
    std.log.info("[XMEM] XMemAlloc(size=0x{x}) -> 0x{x}", .{ dwSize, @intFromPtr(ptr) });
    return ptr;
}

fn shim_XMemFree(pAddress: ?*anyopaque, dwAllocAttributes: u64) callconv(.{ .x86_64_win = .{} }) void {
    _ = pAddress;
    _ = dwAllocAttributes;
}

fn shim_XMemAllocatePhysicalPages(
    flags: usize,
    numberOfPages: *usize,
    pageArray: [*]usize,
) callconv(.{ .x86_64_win = .{} }) i32 {
    const count = numberOfPages.*;

    std.log.info(
        "[XMEM] XMemAllocatePhysicalPages(flags=0x{x}, count={}, pageArray=0x{x})",
                 .{ flags, count, @intFromPtr(pageArray) },
    );

    return 0;
}

fn shim_XMemMapPhysicalPages(
    virtualAddress: ?*anyopaque,
    numberOfPages: usize,
    pageSize: usize,
    flProtect: u32,
    pageArray: [*]const usize,
) callconv(.{ .x86_64_win = .{} }) ?*anyopaque {
    _ = flProtect;
    const total_bytes = numberOfPages * pageSize;
    const dst_ptr = hostAlloc(virtualAddress, total_bytes) orelse return null;
    const dst_bytes: [*]u8 = @ptrCast(dst_ptr);

    var i: usize = 0;
    while (i < numberOfPages) : (i += 1) {
        const slot = @as([*]const u8, @ptrCast(pageArray)) + i * 8;
        const page_addr = std.mem.readInt(usize, slot[0..8], .little);
        if (page_addr != 0) {
            const src_bytes: [*]const u8 = @ptrFromInt(page_addr);
            @memcpy((dst_bytes + i * pageSize)[0..pageSize], src_bytes[0..pageSize]);
        }
    }
    return dst_ptr;
}

fn shim_XMemFreePhysicalPages(numberOfPages: usize, pageArray: [*]const usize) callconv(.{ .x86_64_win = .{} }) i32 {
    _ = numberOfPages;
    _ = pageArray;
    return 0;
}

fn shim_XMemIsToolsMemAvailable() callconv(.{ .x86_64_win = .{} }) i32 {
    return 0;
}

fn shim_D3D12ConfigureVirtualMemoryX(params: ?*const anyopaque) callconv(.{ .x86_64_win = .{} }) i32 {
    _ = params;
    std.log.info("[D3D12X] D3D12ConfigureVirtualMemoryX() -> S_OK", .{});
    return 0; // S_OK
}

pub fn resolve(sym_name: []const u8) ?usize {
    const map = .{
        .{ "XMemVirtualAlloc", @intFromPtr(&shim_XMemVirtualAlloc) },
        .{ "XMemAlloc", @intFromPtr(&shim_XMemAlloc) },
        .{ "XMemAllocDefault", @intFromPtr(&shim_XMemAlloc) },
        .{ "XMemFree", @intFromPtr(&shim_XMemFree) },
        .{ "XMemFreeDefault", @intFromPtr(&shim_XMemFree) },
        .{ "XMemAllocatePhysicalPages", @intFromPtr(&shim_XMemAllocatePhysicalPages) },
        .{ "XMemMapPhysicalPages", @intFromPtr(&shim_XMemMapPhysicalPages) },
        .{ "XMemFreePhysicalPages", @intFromPtr(&shim_XMemFreePhysicalPages) },
        .{ "XMemIsToolsMemAvailable", @intFromPtr(&shim_XMemIsToolsMemAvailable) },
        .{ "D3D12ConfigureVirtualMemoryX", @intFromPtr(&shim_D3D12ConfigureVirtualMemoryX) },
    };

    inline for (map) |entry| {
        if (std.mem.eql(u8, entry.@"0", sym_name)) {
            return entry.@"1";
        }
    }
    return null;
}
