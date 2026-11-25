const std = @import("std");
const builtin = @import("builtin");
const pe_loader = @import("pe_loader.zig");

const ARCH_SET_GS: usize = 0x1001;

fn setupLinuxTebPeb(allocator: std.mem.Allocator, image_base: usize) !void {
    if (builtin.os.tag != .linux) return;

    // Allocate zeroed 4KB pages for fake Windows x64 TEB and PEB
    const page_align = comptime std.mem.Alignment.fromByteUnits(4096);
    const teb = try allocator.alignedAlloc(u8, page_align, 0x1000);
    @memset(teb, 0);

    const peb = try allocator.alignedAlloc(u8, page_align, 0x1000);
    @memset(peb, 0);

    const teb_addr = @intFromPtr(teb.ptr);
    const peb_addr = @intFromPtr(peb.ptr);

    // TEB + 0x30: NtCurrentTeb() self-pointer (gs:[0x30])
    std.mem.writeInt(u64, teb[0x30..0x38], teb_addr, .little);
    // TEB + 0x60: ProcessEnvironmentBlock pointer (gs:[0x60])
    std.mem.writeInt(u64, teb[0x60..0x68], peb_addr, .little);
    // PEB + 0x10: ImageBaseAddress
    std.mem.writeInt(u64, peb[0x10..0x18], image_base, .little);

    // Set x86-64 GS segment base via Linux arch_prctl syscall (158)
    const rc = std.os.linux.syscall2(.arch_prctl, ARCH_SET_GS, teb_addr);
    if (rc != 0) {
        std.log.err("arch_prctl(ARCH_SET_GS) failed with code {d}", .{rc});
        return error.TebSetupFailed;
    }

    std.log.info("Initialized Linux GS segment -> TEB=0x{x}, PEB=0x{x}", .{ teb_addr, peb_addr });
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const arena = init.arena.allocator();
    const io = init.io;

    const args = try init.minimal.args.toSlice(arena);

    if (args.len < 2) {
        std.debug.print("Usage: {s} <path/to/game_scarlett_master.exe>\n", .{args.ptr[0]});
        std.process.exit(1);
    }

    const exe_path: []const u8 = args.ptr[1];
    std.log.info("Loading Scarlett PE image: {s}", .{exe_path});

    var mapped = try pe_loader.loadAndPatch(gpa, io, exe_path);
    defer mapped.deinit();

    try setupLinuxTebPeb(arena, mapped.base_addr);

    std.log.info("Image mapped at 0x{x}, jumping to entry point 0x{x}...", .{
        mapped.base_addr,
        mapped.entry_point,
    });

    const EntryFn = *const fn () callconv(.{ .x86_64_win = .{} }) void;
    const entry: EntryFn = @ptrFromInt(mapped.entry_point);
    entry();
}
