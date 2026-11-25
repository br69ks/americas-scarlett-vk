const std = @import("std");
const builtin = @import("builtin");
const pe_loader = @import("pe_loader.zig");
const crt_core = @import("shims/crt_core.zig");

const WinEntryFn = *const fn () callconv(.{ .x86_64_win = .{} }) i32;

fn setupLinuxTebPeb(allocator: std.mem.Allocator, tls_block_addr: usize) !void {
    if (builtin.os.tag != .linux) return;

    const page_align = comptime std.mem.Alignment.fromByteUnits(4096);
    const teb = try allocator.alignedAlloc(u8, page_align, 0x1000);
    @memset(teb, 0);

    const peb = try allocator.alignedAlloc(u8, page_align, 0x1000);
    @memset(peb, 0);

    const tls_slots = try allocator.alloc(usize, 64);
    @memset(tls_slots, 0);
    std.mem.writeInt(usize, std.mem.sliceAsBytes(tls_slots)[0..8], tls_block_addr, .little);

    const teb_addr = @intFromPtr(teb.ptr);
    const peb_addr = @intFromPtr(peb.ptr);

    // TEB + 0x00: ExceptionList (-1 = end of SEH chain)
    std.mem.writeInt(usize, teb[0x00..][0..8], std.math.maxInt(usize), .little);
    // TEB + 0x08: StackBase
    std.mem.writeInt(usize, teb[0x08..][0..8], 0x7FFFFFFFFFFF, .little);
    // TEB + 0x10: StackLimit
    std.mem.writeInt(usize, teb[0x10..][0..8], 0x10000, .little);
    // TEB + 0x30: Self pointer (NtCurrentTeb)
    std.mem.writeInt(usize, teb[0x30..][0..8], teb_addr, .little);
    // TEB + 0x40: ProcessId
    std.mem.writeInt(u32, teb[0x40..][0..4], 1000, .little);
    // TEB + 0x48: ThreadId
    std.mem.writeInt(u32, teb[0x48..][0..4], 1001, .little);
    // TEB + 0x58: ThreadLocalStoragePointer (implicit __declspec(thread) TLS array)
    std.mem.writeInt(usize, teb[0x58..][0..8], @intFromPtr(tls_slots.ptr), .little);
    // TEB + 0x60: ProcessEnvironmentBlock (PEB)
    std.mem.writeInt(usize, teb[0x60..][0..8], peb_addr, .little);

    // PEB + 0x02: BeingDebugged = 0
    @memset(peb[0..4], 0);

    // Set x86-64 GS base register to our fake TEB via arch_prctl(ARCH_SET_GS = 0x1001)
    const ARCH_SET_GS: usize = 0x1001;
    const rc = std.os.linux.syscall2(.arch_prctl, ARCH_SET_GS, teb_addr);
    if (rc != 0) {
        std.log.err("arch_prctl(ARCH_SET_GS) failed with code {d}", .{rc});
        return error.ArchPrctlFailed;
    }

    std.log.info("Initialized Linux GS segment -> TEB=0x{x}, PEB=0x{x}", .{ teb_addr, peb_addr });
}

const GlibcSigaction = extern struct {
    handler: ?*const fn (i32, *const anyopaque, ?*anyopaque) callconv(.c) void,
    mask: [16]u64,
    flags: c_int,
    restorer: ?*const fn () callconv(.c) void,
};

extern "c" fn sigaction(signum: c_int, act: ?*const GlibcSigaction, oldact: ?*GlibcSigaction) c_int;

fn sigtrapHandler(sig: i32, info: *const anyopaque, ucontext_ptr: ?*anyopaque) callconv(.c) void {
    _ = sig;
    _ = info;
    if (ucontext_ptr) |uctx| {
        const base = @intFromPtr(uctx);
        const rip_ptr: *u64 = @ptrFromInt(base + 0xA8);
        const cs_ptr: *u16 = @ptrFromInt(base + 0xB8);
        const ss_ptr: *u16 = @ptrFromInt(base + 0xBE);

        const trap_addr = rip_ptr.*;
        if (trap_addr == 0x141df7bea or trap_addr == 0x141df7beb) {
            const rdx_val = @as(*const u64, @ptrFromInt(base + 0x88)).*;
            if (rdx_val > 0x10000) {
                const msg_ptr: [*:0]const u8 = @ptrFromInt(rdx_val);
                std.log.err("[RAGE MSG] {s}", .{std.mem.span(msg_ptr)});
            }
        }

        // Hot-patch the 1-byte `int3` (0xCC) to `nop` (0x90) so it never traps again!
        if (trap_addr > 0x140000000) {
            const code_byte: *u8 = @ptrFromInt(trap_addr);
            if (code_byte.* == 0xCC) {
                code_byte.* = 0x90;
            }
        }

        const uc_flags_ptr: *u64 = @ptrFromInt(base);
        uc_flags_ptr.* |= 4; // UC_STRICT_RESTORE_SS: force kernel rt_sigreturn to restore 64-bit SS=0x2B!
        cs_ptr.* = 0x33; // __USER_CS (64-bit)
        ss_ptr.* = 0x2B; // __USER_DS (64-bit stack segment -> preserves 64-bit RSP!)
        rip_ptr.* += 1;
    }
}

fn installSigtrapHandler() void {
    if (builtin.os.tag != .linux) return;
    const SA_SIGINFO: c_int = 4;
    var act = GlibcSigaction{
        .handler = &sigtrapHandler,
        .mask = @splat(0),
        .flags = SA_SIGINFO,
        .restorer = null,
    };
    _ = sigaction(5, &act, null); // SIGTRAP = 5
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var args = try init.minimal.args.iterateAllocator(allocator);
    defer args.deinit();

    _ = args.skip(); // skip binary name
    const exe_path = args.next() orelse "game_scarlett_master.exe";

    std.log.info("Loading Scarlett PE image: {s}", .{exe_path});

    var image = try pe_loader.loadAndPatch(allocator, io, exe_path);
    crt_core.g_tls_block_addr = image.tls_block_addr;
    defer image.deinit();

    try setupLinuxTebPeb(allocator, image.tls_block_addr);
    installSigtrapHandler();

    std.log.info("Image mapped at 0x{x}, jumping to entry point 0x{x}...", .{
        image.base_addr,
        image.entry_point,
    });

    const entry_fn: WinEntryFn = @ptrFromInt(image.entry_point);
    const exit_code = entry_fn();
    std.log.info("Game exited with code: {d}", .{exit_code});
}
