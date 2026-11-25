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

var g_image_base: usize = 0;
var g_image_size: usize = 0;

const SigInfo = extern struct {
    si_signo: i32,
    si_errno: i32,
    si_code: i32,
    _pad: i32 = 0,
    si_addr: usize,
};

const GlibcSigaction = extern struct {
    handler: ?*const fn (i32, *const SigInfo, ?*anyopaque) callconv(.c) void,
    mask: [16]u64,
    flags: c_int,
    restorer: ?*const fn () callconv(.c) void,
};

extern "c" fn sigaction(signum: c_int, act: ?*const GlibcSigaction, oldact: ?*GlibcSigaction) c_int;

fn sigtrapHandler(sig: i32, info: *const SigInfo, ucontext_ptr: ?*anyopaque) callconv(.c) void {
    _ = sig;
    _ = info;
    if (ucontext_ptr) |uctx| {
        const base = @intFromPtr(uctx);
        const rip_ptr: *u64 = @ptrFromInt(base + 0xA8);
        const cs_ptr: *u16 = @ptrFromInt(base + 0xB8);
        const ss_ptr: *u16 = @ptrFromInt(base + 0xBE);

        const trap_addr: usize = @intCast(rip_ptr.*);
        const in_image = g_image_base != 0 and trap_addr >= g_image_base and trap_addr < (g_image_base + g_image_size);
        const rva: usize = if (in_image) trap_addr - g_image_base else 0;

        if (in_image and (rva == 0x1df7bea or rva == 0x1df7beb)) {
            const rdx_val = @as(*const u64, @ptrFromInt(base + 0x88)).*;
            if (rdx_val > 0x10000) {
                const msg_ptr: [*:0]const u8 = @ptrFromInt(rdx_val);
                std.log.err("[RAGE MSG] {s}", .{std.mem.span(msg_ptr)});
            }
        } else if (in_image) {
            std.log.warn("[SIGTRAP] Hit int3 at 0x{x} (RVA 0x{x}), hot-patching to NOP", .{ trap_addr, rva });
        }

        // Hot-patch 1-byte `int3` (0xCC) to `nop` (0x90) if inside mapped PE image
        if (in_image) {
            const code_byte: *u8 = @ptrFromInt(trap_addr);
            if (code_byte.* == 0xCC) {
                code_byte.* = 0x90;
            }
        }

        const uc_flags_ptr: *u64 = @ptrFromInt(base);
        uc_flags_ptr.* |= 4; // UC_STRICT_RESTORE_SS
        cs_ptr.* = 0x33; // __USER_CS (64-bit)
        ss_ptr.* = 0x2B; // __USER_DS (64-bit)
        rip_ptr.* += 1;
    }
}

fn crashSignalHandler(sig: i32, info: *const SigInfo, ucontext_ptr: ?*anyopaque) callconv(.c) void {
    const sig_name = switch (sig) {
        11 => "SIGSEGV",
        7 => "SIGBUS",
        4 => "SIGILL",
        else => "SIGNAL",
    };

        if (ucontext_ptr) |uctx| {
            const base = @intFromPtr(uctx);
            const r8 = @as(*const u64, @ptrFromInt(base + 0x28)).*;
            const r9 = @as(*const u64, @ptrFromInt(base + 0x30)).*;
            const rdx = @as(*const u64, @ptrFromInt(base + 0x88)).*;
            const rax = @as(*const u64, @ptrFromInt(base + 0x90)).*;
            const rcx = @as(*const u64, @ptrFromInt(base + 0x98)).*;
            const rsp = @as(*const u64, @ptrFromInt(base + 0xA0)).*;
            const rip: usize = @intCast(@as(*const u64, @ptrFromInt(base + 0xA8)).*);

            const in_image = g_image_base != 0 and rip >= g_image_base and rip < (g_image_base + g_image_size);
            if (in_image) {
                std.log.err("[CRASH] {s} at RIP=0x{x} (RVA=0x{x}) fault_addr=0x{x}", .{
                    sig_name,
                    rip,
                    rip - g_image_base,
                    info.si_addr,
                });
            } else {
                std.log.err("[CRASH] {s} outside PE image at RIP=0x{x} fault_addr=0x{x}", .{
                    sig_name,
                    rip,
                    info.si_addr,
                });
            }
            std.log.err("  RAX=0x{x} RCX=0x{x} RDX=0x{x} R8=0x{x} R9=0x{x} RSP=0x{x}", .{
                rax, rcx, rdx, r8, r9, rsp,
            });
        } else {
            std.log.err("[CRASH] {s} fault_addr=0x{x}", .{ sig_name, info.si_addr });
        }

        std.process.exit(128 + @as(u8, @intCast(sig)));
}

fn installSignalHandlers() void {
    if (builtin.os.tag != .linux) return;
    const SA_SIGINFO: c_int = 4;

    var trap_act = GlibcSigaction{
        .handler = &sigtrapHandler,
        .mask = @splat(0),
        .flags = SA_SIGINFO,
        .restorer = null,
    };
    _ = sigaction(5, &trap_act, null); // SIGTRAP

    var crash_act = GlibcSigaction{
        .handler = &crashSignalHandler,
        .mask = @splat(0),
        .flags = SA_SIGINFO,
        .restorer = null,
    };
    _ = sigaction(11, &crash_act, null); // SIGSEGV
    _ = sigaction(7, &crash_act, null); // SIGBUS
    _ = sigaction(4, &crash_act, null); // SIGILL
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
    g_image_base = image.base_addr;
    g_image_size = image.image_size;
    crt_core.g_tls_block_addr = image.tls_block_addr;
    defer image.deinit();

    try setupLinuxTebPeb(allocator, image.tls_block_addr);
    installSignalHandlers();

    std.log.info("Image mapped at 0x{x}, jumping to entry point 0x{x}...", .{
        image.base_addr,
        image.entry_point,
    });

    const entry_fn: WinEntryFn = @ptrFromInt(image.entry_point);
    const exit_code = entry_fn();
    std.log.info("Game exited with code: {d}", .{exit_code});
}
