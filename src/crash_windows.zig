//! Minimal Windows unhandled-exception reporter for the loader.

const std = @import("std");
const teb = @import("teb.zig");

const EXCEPTION_RECORD = extern struct {
    ExceptionCode: u32,
    ExceptionFlags: u32,
    ExceptionRecord: ?*anyopaque,
    ExceptionAddress: usize,
    NumberParameters: u32,
    _pad: u32,
    ExceptionInformation: [15]usize,
};

const EXCEPTION_POINTERS = extern struct {
    ExceptionRecord: *EXCEPTION_RECORD,
    ContextRecord: *anyopaque,
};

extern "kernel32" fn SetUnhandledExceptionFilter(
    filter: *const fn (*EXCEPTION_POINTERS) callconv(.winapi) i32,
) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn AddVectoredExceptionHandler(
    first: u32,
    handler: *const fn (*EXCEPTION_POINTERS) callconv(.winapi) i32,
) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn GetStdHandle(which: u32) callconv(.winapi) usize;
extern "kernel32" fn WriteFile(
    handle: usize,
    buffer: [*]const u8,
    len: u32,
    written: ?*u32,
    overlapped: ?*anyopaque,
) callconv(.winapi) i32;
extern "kernel32" fn GetCurrentThreadId() callconv(.winapi) u32;
extern "kernel32" fn GetModuleHandleW(name: ?[*:0]const u16) callconv(.winapi) usize;

fn write(text: []const u8) void {
    const h = GetStdHandle(@bitCast(@as(i32, -12)));
    if (h == 0 or h == std.math.maxInt(usize)) return;
    var done: u32 = 0;
    _ = WriteFile(h, text.ptr, @intCast(text.len), &done, null);
}

fn report(info: *EXCEPTION_POINTERS, tag: []const u8) void {
    const rec = info.ExceptionRecord;
    const ctx: [*]const u8 = @ptrCast(info.ContextRecord);
    const rip = std.mem.readInt(u64, ctx[0xF8..][0..8], .little);
    const base = GetModuleHandleW(null);
    const info0 = if (rec.NumberParameters > 0) rec.ExceptionInformation[0] else 0;
    const info1 = if (rec.NumberParameters > 1) rec.ExceptionInformation[1] else 0;
    const rbx = std.mem.readInt(u64, ctx[0x90..][0..8], .little);
    const rcx = std.mem.readInt(u64, ctx[0x80..][0..8], .little);
    const rdx = std.mem.readInt(u64, ctx[0x88..][0..8], .little);
    const rsi = std.mem.readInt(u64, ctx[0xA8..][0..8], .little);
    const rdi = std.mem.readInt(u64, ctx[0xB0..][0..8], .little);
    var gsbase: u64 = 0;
    asm volatile ("rdgsbase %[out]" : [out] "=r" (gsbase));
    const guest_teb: u64 = if (teb.process()) |p| @intFromPtr(p.teb_ptr) else 0;
    var buf: [768]u8 = undefined;
    const text = std.fmt.bufPrint(&buf,
        "\n[{s}] exception 0x{x:0>8} at 0x{x} (RIP=0x{x}, loader_base=0x{x}, rva=0x{x}, arg0=0x{x}, arg1=0x{x}, rbx=0x{x}, rcx=0x{x}, rdx=0x{x}, rdi=0x{x}, rsi=0x{x}, gsbase=0x{x}, entry_gs=0x{x}, guest_teb=0x{x}, tid={d})\n",
        .{ tag, rec.ExceptionCode, rec.ExceptionAddress, rip, base, rip - base, info0, info1, rbx, rcx, rdx, rdi, rsi, gsbase, teb.g_entry_gs, guest_teb, GetCurrentThreadId() }) catch return;
    write(text);
    const trace = std.fmt.bufPrint(&buf, "[TRACE] enter={d} leave={d} enter_ra=0x{x} leave_ra=0x{x}\n", .{
        teb.g_enter_count, teb.g_leave_count,
        teb.g_enter_trace[teb.g_enter_count % 8], teb.g_leave_trace[teb.g_leave_count % 8],
    }) catch return;
    write(trace);

    const rsp = std.mem.readInt(u64, ctx[0x98..][0..8], .little);
    if (rsp >= 0x10000) {
        const sp: [*]const u8 = @ptrFromInt(@as(usize, @intCast(rsp)));
        var i: usize = 0;
        while (i < 12) : (i += 1) {
            const ret = std.mem.readInt(u64, sp[i * 8 ..][0..8], .little);
            const line = std.fmt.bufPrint(&buf, "[STACK] {d}: 0x{x}\n", .{ i, ret }) catch break;
            write(line);
        }
    }
}

fn veh(info: *EXCEPTION_POINTERS) callconv(.winapi) i32 {
    const code = info.ExceptionRecord.ExceptionCode;
    if (code == 0xC0000005 or code == 0xC000001D or code == 0xC0000096 or code == 0xC00000FD or code == 0x80000003 or
        code == 0xC0000409 or code == 0xC0000374 or code == 0xE06D7363) {
        // A guest exception cannot be safely unwound by Windows because the
        // guest image is manually mapped.  Switch to the host TEB for
        // reporting, then terminate instead of entering the unwinder.
        if (teb.process()) |p| {
            const guest = @intFromPtr(p.teb_ptr);
            var cur: usize = 0;
            asm volatile ("movq %%gs:0x30, %[out]" : [out] "=r" (cur));
            if (cur == guest) {
                const host = @as(*const usize, @ptrFromInt(guest + 0x1FF8)).*;
                if (host >= 0x10000) asm volatile ("wrgsbase %[base]" :: [base] "r" (host));
            }
        }
        write("[VEH] entered\n");
        report(info, "VEH");
        std.process.exit(1);
    }
    return 0; // EXCEPTION_CONTINUE_SEARCH
}

fn handler(info: *EXCEPTION_POINTERS) callconv(.winapi) i32 {
    // If the fault came from guest code, GS is the synthetic TEB.  Its
    // ArbitraryUserPointer at +0x28 is the host TEB; switch back before
    // calling any host API to print.
    const guest: usize = if (teb.process()) |p| @intFromPtr(p.teb_ptr) else 0;
    var cur: usize = 0;
    asm volatile ("movq %%gs:0x30, %[out]" : [out] "=r" (cur));
    if (guest != 0 and cur == guest) {
        var host: usize = 0;
        asm volatile ("movq %%gs:0x28, %[out]" : [out] "=r" (host));
        if (host >= 0x10000) asm volatile ("wrgsbase %[base]" :: [base] "r" (host));
    }
    const rec = info.ExceptionRecord;
    const ctx: [*]const u8 = @ptrCast(info.ContextRecord);
    const rip = std.mem.readInt(u64, ctx[0xF8..][0..8], .little);
    var buf: [512]u8 = undefined;
    const base = GetModuleHandleW(null);
    const info0 = if (rec.NumberParameters > 0) rec.ExceptionInformation[0] else 0;
    const info1 = if (rec.NumberParameters > 1) rec.ExceptionInformation[1] else 0;
    const text = std.fmt.bufPrint(&buf,
        "\n[FATAL] Windows exception 0x{x:0>8} at 0x{x} (RIP=0x{x}, loader_base=0x{x}, rva=0x{x}, arg0=0x{x}, arg1=0x{x}, tid={d})\n",
        .{ rec.ExceptionCode, rec.ExceptionAddress, rip, base, rip - base, info0, info1, GetCurrentThreadId() }) catch return 1;
    write(text);
    return 1; // EXCEPTION_EXECUTE_HANDLER
}

pub fn install() void {
    const h = AddVectoredExceptionHandler(1, &veh);
    write(if (h != null) "[VEH] installed\n" else "[VEH] install FAILED\n");
    _ = SetUnhandledExceptionFilter(&handler);
}
