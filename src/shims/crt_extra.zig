//! SEH, FLS, pointer-encoding, and locale/CRT entry points that the MSVC
//! runtime needs before it can load.  The full x64 unwinder is not here yet;
//! this provides real .pdata lookup and a correct CONTEXT capture so the CRT
//! can install its handlers.

const std = @import("std");
const builtin = @import("builtin");
const teb = @import("../teb.zig");
const module = @import("../module.zig");
const sync = @import("../sync.zig");
const win32_fs = @import("win32_fs.zig");

const win: std.builtin.CallingConvention = .{ .x86_64_win = .{} };

var g_unhandled_filter: usize = 0;

// ---------------------------------------------------------------------------
// CONTEXT / SEH
// ---------------------------------------------------------------------------

/// x64 CONTEXT prefix up to Rip.  Offsets match winnt.h.
const Context = extern struct {
    p1: u64 = 0,
    p2: u64 = 0,
    p3: u64 = 0,
    p4: u64 = 0,
    p5: u64 = 0,
    p6: u64 = 0,
    context_flags: u32 = 0,
    mx_csr: u32 = 0,
    seg_cs: u16 = 0,
    seg_ds: u16 = 0,
    seg_es: u16 = 0,
    seg_fs: u16 = 0,
    seg_gs: u16 = 0,
    seg_ss: u16 = 0,
    eflags: u32 = 0,
    dr0: u64 = 0,
    dr1: u64 = 0,
    dr2: u64 = 0,
    dr3: u64 = 0,
    dr6: u64 = 0,
    dr7: u64 = 0,
    rax: u64 = 0,
    rcx: u64 = 0,
    rdx: u64 = 0,
    rbx: u64 = 0,
    rsp: u64 = 0,
    rbp: u64 = 0,
    rsi: u64 = 0,
    rdi: u64 = 0,
    r8: u64 = 0,
    r9: u64 = 0,
    r10: u64 = 0,
    r11: u64 = 0,
    r12: u64 = 0,
    r13: u64 = 0,
    r14: u64 = 0,
    r15: u64 = 0,
    rip: u64 = 0,
    _pad_xmm: [0x300 - 0x100]u8 = @splat(0),
    xmm: [16][16]u8 = @splat(@splat(0)),
};

comptime {
    std.debug.assert(@offsetOf(Context, "context_flags") == 0x30);
    std.debug.assert(@offsetOf(Context, "rax") == 0x78);
    std.debug.assert(@offsetOf(Context, "rip") == 0xF8);
    std.debug.assert(@offsetOf(Context, "xmm") == 0x300);
}

/// Naked on purpose: the guest calls this with RCX = CONTEXT*.  It must not
/// have a prologue, or the captured RSP/RIP belong to the shim.
fn rtlCaptureContext() callconv(.naked) void {
    asm volatile (
        \\ movq %%rax, 0x78(%%rcx)
        \\ movq %%rcx, 0x80(%%rcx)
        \\ movq %%rdx, 0x88(%%rcx)
        \\ movq %%rbx, 0x90(%%rcx)
        \\ movq %%rsp, 0x98(%%rcx)
        \\ movq %%rbp, 0xA0(%%rcx)
        \\ movq %%rsi, 0xA8(%%rcx)
        \\ movq %%rdi, 0xB0(%%rcx)
        \\ movq %%r8,  0xB8(%%rcx)
        \\ movq %%r9,  0xC0(%%rcx)
        \\ movq %%r10, 0xC8(%%rcx)
        \\ movq %%r11, 0xD0(%%rcx)
        \\ movq %%r12, 0xD8(%%rcx)
        \\ movq %%r13, 0xE0(%%rcx)
        \\ movq %%r14, 0xE8(%%rcx)
        \\ movq %%r15, 0xF0(%%rcx)
        \\ movq (%%rsp), %%rax
        \\ movq %%rax, 0xF8(%%rcx)
        \\ leaq 8(%%rsp), %%rax
        \\ movq %%rax, 0x98(%%rcx)
        \\ movl $0x0010000F, 0x30(%%rcx)
        \\ stmxcsr 0x34(%%rcx)
        \\ movw %%cs, 0x38(%%rcx)
        \\ movw %%ss, 0x42(%%rcx)
        \\ pushfq
        \\ popq %%rax
        \\ movl %%eax, 0x44(%%rcx)
        \\ ret
    );
}

fn shim_RtlLookupFunctionEntry(
    control_pc: u64,
    image_base_out: ?*u64,
    _: ?*anyopaque,
) callconv(win) ?*const module.RuntimeFunction {
    const m = module.findByAddress(@intCast(control_pc)) orelse return null;
    if (image_base_out) |out| out.* = m.base;
    return module.lookupFunctionEntry(@intCast(control_pc));
}

fn shim_RtlPcToFileHeader(pc: u64, image_base_out: ?*u64) callconv(win) u64 {
    const m = module.findByAddress(@intCast(pc)) orelse return 0;
    if (image_base_out) |out| out.* = m.base;
    return m.base;
}

const UnwindOp = struct {
    kind: u8,
    info: u8,
    operand: u64,
};

fn readU16(p: [*]const u8, off: usize) u16 {
    return std.mem.readInt(u16, p[off..][0..2], .little);
}

fn readU32(p: [*]const u8, off: usize) u32 {
    return std.mem.readInt(u32, p[off..][0..4], .little);
}

fn readU64(p: [*]const u8, off: usize) u64 {
    return std.mem.readInt(u64, p[off..][0..8], .little);
}

fn regField(ctx: *Context, reg: u8) *u64 {
    return switch (reg) {
        0 => &ctx.rax,
        1 => &ctx.rcx,
        2 => &ctx.rdx,
        3 => &ctx.rbx,
        4 => &ctx.rsp,
        5 => &ctx.rbp,
        6 => &ctx.rsi,
        7 => &ctx.rdi,
        8 => &ctx.r8,
        9 => &ctx.r9,
        10 => &ctx.r10,
        11 => &ctx.r11,
        12 => &ctx.r12,
        13 => &ctx.r13,
        14 => &ctx.r14,
        15 => &ctx.r15,
        else => &ctx.rsp,
    };
}

fn applyUnwindOp(ctx: *Context, op: UnwindOp) void {
    const stack: [*]const u8 = @ptrFromInt(@as(usize, @intCast(ctx.rsp)));
    switch (op.kind) {
        0 => { // PUSH_NONVOL
            regField(ctx, op.info).* = readU64(stack, 0);
            ctx.rsp += 8;
        },
        1 => { // ALLOC_LARGE
            ctx.rsp += op.operand;
        },
        2 => { // ALLOC_SMALL
            ctx.rsp += @as(u64, op.info) * 8 + 8;
        },
        3 => {}, // SET_FPREG, handled by the caller
        4 => { // SAVE_NONVOL
            regField(ctx, op.info).* = readU64(stack, @intCast(op.operand));
        },
        5 => { // SAVE_NONVOL_FAR
            regField(ctx, op.info).* = readU64(stack, @intCast(op.operand));
        },
        8 => { // SAVE_XMM128
            const off: usize = @intCast(op.operand);
            @memcpy(ctx.xmm[op.info][0..16], stack[off..][0..16]);
        },
        9 => { // SAVE_XMM128_FAR
            const off: usize = @intCast(op.operand);
            @memcpy(ctx.xmm[op.info][0..16], stack[off..][0..16]);
        },
        10 => { // PUSH_MACHFRAME
            if (op.info != 0) ctx.rsp += 8; // error code
            ctx.rip = readU64(stack, 8);
            ctx.rsp += 8 + 32; // RIP, CS, EFLAGS, RSP, SS
        },
        else => {},
    }
}

fn shim_RtlVirtualUnwind(
    _: u32,
    image_base: u64,
    control_pc: u64,
    function_entry: ?*const module.RuntimeFunction,
    context_record: ?*anyopaque,
    handler_data: ?*?*anyopaque,
    establisher: ?*u64,
    _: ?*anyopaque,
) callconv(win) ?*anyopaque {
    const fe = function_entry orelse return null;
    const ctx: *Context = @ptrCast(@alignCast(context_record orelse return null));
    const info: [*]const u8 = @ptrFromInt(@as(usize, @intCast(image_base + fe.unwind)));

    const version_flags = info[0];
    if (builtin.os.tag == .linux) {
        std.log.err("[UNW] img=0x{x} pc=0x{x} rva=0x{x} fe=0x{x} begin=0x{x} end=0x{x} unwind=0x{x} info={x:0>2}{x:0>2}{x:0>2}{x:0>2} rsp=0x{x}", .{
            image_base, control_pc, control_pc - image_base, @intFromPtr(fe), fe.begin, fe.end, fe.unwind, info[0], info[1], info[2], info[3], ctx.rsp,
        });
    }
    if (version_flags & 0x7 != 1) return null;
    const flags = version_flags >> 3;
    const count: usize = info[2];
    const frame_reg: u8 = info[3] & 0xF;
    const frame_offset: u8 = info[3] >> 4;

    const alloc = std.heap.c_allocator;
    const ops = alloc.alloc(UnwindOp, 256) catch return null;
    defer alloc.free(ops);
    var op_count: usize = 0;
    var idx: usize = 0;
    while (idx < count and idx < 255) {
        const code_off = idx * 2;
        const b0 = info[4 + code_off];
        const b1 = info[4 + code_off + 1];
        const kind = b1 & 0xF;
        const op_info = b1 >> 4;
        var operand: u64 = 0;
        var slots: usize = 1;

        switch (kind) {
            1 => { // ALLOC_LARGE
                if (op_info == 0) {
                    operand = @as(u64, readU16(info, 4 + (idx + 1) * 2)) * 8;
                    slots = 2;
                } else {
                    operand = @as(u64, readU16(info, 4 + (idx + 1) * 2)) |
                        (@as(u64, readU16(info, 4 + (idx + 2) * 2)) << 16);
                    slots = 3;
                }
            },
            2 => operand = @as(u64, op_info) * 8 + 8,
            4 => {
                operand = @as(u64, readU16(info, 4 + (idx + 1) * 2)) * 8;
                slots = 2;
            },
            5 => {
                operand = @as(u64, readU16(info, 4 + (idx + 1) * 2)) |
                    (@as(u64, readU16(info, 4 + (idx + 2) * 2)) << 16);
                slots = 3;
            },
            8 => { // SAVE_XMM128
                operand = @as(u64, readU16(info, 4 + (idx + 1) * 2)) * 16;
                slots = 2;
            },
            9 => { // SAVE_XMM128_FAR
                operand = @as(u64, readU16(info, 4 + (idx + 1) * 2)) |
                    (@as(u64, readU16(info, 4 + (idx + 2) * 2)) << 16);
                slots = 3;
            },
            else => {},
        }

        if (builtin.os.tag == .linux and op_count < 12) {
            std.log.err("[UNWOP] {d}: kind={d} info={d} operand=0x{x}", .{ op_count, kind, op_info, operand });
        }
        ops[op_count] = .{ .kind = kind, .info = op_info, .operand = operand };
        op_count += 1;
        idx += slots;
        _ = b0;
    }

    // Unwind codes are stored in descending prolog-offset order; applying them
    // in that order undoes the prolog.
    var i: usize = 0;
    while (i < op_count) : (i += 1) {
        if (ops[i].kind == 3) {
            if (frame_reg != 0) {
                ctx.rsp = regField(ctx, frame_reg).* - @as(u64, frame_offset) * 16;
            }
            continue;
        }
        applyUnwindOp(ctx, ops[i]);
    }

    if (establisher) |out| out.* = ctx.rsp;

    // Pop the return address.
    const stack: [*]const u8 = @ptrFromInt(@as(usize, @intCast(ctx.rsp)));
    ctx.rip = readU64(stack, 0);
    ctx.rsp += 8;

    if (flags & 0x3 != 0) {
        const handler_off = std.mem.alignForward(usize, 4 + count * 2, 4);
        const handler_rva = readU32(info, handler_off);
        if (handler_data) |out| out.* = @ptrFromInt(@as(usize, @intCast(image_base + handler_off + 4)));
        return @ptrFromInt(@as(usize, @intCast(image_base + handler_rva)));
    }
    return null;
}

fn shim_RtlUnwind(_: ?*anyopaque, _: ?*anyopaque, _: ?*anyopaque, _: ?*anyopaque) callconv(win) void {
    std.log.warn("[SEH] RtlUnwind called (no-op)", .{});
}

fn shim_RtlUnwindEx(
    target_frame: ?*anyopaque,
    target_ip: ?*anyopaque,
    exception_record: ?*anyopaque,
    return_value: ?*anyopaque,
    context_record: ?*anyopaque,
    history_table: ?*anyopaque,
) callconv(win) void {
    _ = target_frame;
    _ = target_ip;
    _ = exception_record;
    _ = return_value;
    _ = context_record;
    _ = history_table;
    std.log.warn("[SEH] RtlUnwindEx called (no-op)", .{});
}

fn shim_RaiseException(
    code: u32,
    flags: u32,
    nargs: u32,
    args: ?[*]const u64,
) callconv(win) noreturn {
    std.log.err("[SEH] RaiseException(code=0x{x}, flags=0x{x}, nargs={d})", .{ code, flags, nargs });
    if (args) |a| {
        var i: usize = 0;
        while (i < nargs and i < 8) : (i += 1) {
            std.log.err("  arg[{d}] = 0x{x}", .{ i, a[i] });
        }
    }
    std.process.exit(@as(u8, 0xE0) | @as(u8, @truncate(code)));
}

fn shim_SetUnhandledExceptionFilter(filter: ?*anyopaque) callconv(win) ?*anyopaque {
    const previous = g_unhandled_filter;
    g_unhandled_filter = if (filter) |f| @intFromPtr(f) else 0;
    return if (previous == 0) null else @ptrFromInt(previous);
}

const UnhandledFilterFn = *const fn (?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32;

fn shim_UnhandledExceptionFilter(info: ?*anyopaque) callconv(win) i32 {
    if (g_unhandled_filter != 0) {
        const f: UnhandledFilterFn = @ptrFromInt(g_unhandled_filter);
        return f(info);
    }
    return 1; // EXCEPTION_EXECUTE_HANDLER
}

fn shim_AddVectoredExceptionHandler(_: u32, _: ?*anyopaque) callconv(win) ?*anyopaque {
    return @ptrFromInt(@as(usize, 1));
}

fn shim_RemoveVectoredExceptionHandler(_: ?*anyopaque) callconv(win) u32 {
    return 1;
}

fn shim_IsDebuggerPresent() callconv(win) i32 {
    return 0;
}

// ---------------------------------------------------------------------------
// Pointer encoding / FLS / one-time init
// ---------------------------------------------------------------------------

fn shim_EncodePointer(ptr: ?*anyopaque) callconv(win) ?*anyopaque {
    return ptr;
}

fn shim_DecodePointer(ptr: ?*anyopaque) callconv(win) ?*anyopaque {
    return ptr;
}

fn shim_FlsAlloc(_: ?*anyopaque) callconv(win) u32 {
    return teb.tlsAlloc();
}

fn shim_FlsFree(index: u32) callconv(win) i32 {
    return if (teb.tlsFree(index)) 1 else 0;
}

fn shim_FlsGetValue(index: u32) callconv(win) ?*anyopaque {
    const value = teb.tlsGet(index);
    return if (value == 0) null else @ptrFromInt(value);
}

fn shim_FlsSetValue(index: u32, value: ?*anyopaque) callconv(win) i32 {
    const addr: usize = if (value) |v| @intFromPtr(v) else 0;
    return if (teb.tlsSet(index, addr)) 1 else 0;
}

const InitOnceFn = *const fn (?*anyopaque, ?*anyopaque, ?*?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32;

fn shim_InitOnceExecuteOnce(
    init_once: ?*anyopaque,
    init_fn: ?InitOnceFn,
    parameter: ?*anyopaque,
    context: ?*?*anyopaque,
) callconv(win) i32 {
    const state: *u32 = @ptrCast(@alignCast(init_once orelse return 0));
    const f = init_fn orelse return 0;
    while (true) {
        const current = @atomicLoad(u32, state, .acquire);
        if (current == 2) return 1;
        if (current == 0 and @cmpxchgWeak(u32, state, 0, 1, .acq_rel, .acquire) == null) {
            const rc = f(init_once, parameter, context);
            @atomicStore(u32, state, 2, .release);
            return if (rc == 0) 0 else 1;
        }
        std.atomic.spinLoopHint();
    }
}

fn shim_SwitchToThread() callconv(win) i32 {
    if (builtin.os.tag == .linux) {
        _ = std.os.linux.sched_yield();
    }
    return 1;
}

fn shim_GetModuleHandleExW(
    flags: u32,
    module_name: ?[*:0]const u16,
    out: ?*usize,
) callconv(win) i32 {
    const result = out orelse return 0;
    var base: usize = 0;
    if (flags & 0x4 != 0) { // GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
        const addr: usize = @intFromPtr(module_name);
        const m = module.findByAddress(addr) orelse return 0;
        base = m.base;
    } else if (module_name) |name| {
        var utf8: [512]u8 = undefined;
        const n = std.unicode.utf16LeToUtf8(&utf8, std.mem.span(name)) catch return 0;
        const m = module.findByName(utf8[0..n]) orelse return 0;
        base = m.base;
    } else if (teb.process()) |p| {
        base = p.peb_ptr.ImageBaseAddress;
    }
    if (base == 0) return 0;
    if (flags & 0x2 == 0) { // UNCHANGED_REFCOUNT
        if (module.findByBase(base)) |m| m.refcount += 1;
    }
    result.* = base;
    return 1;
}

// ---------------------------------------------------------------------------
// Minimal CRT entry points
// ---------------------------------------------------------------------------

fn shim_execute_onexit_table(_: ?*anyopaque) callconv(win) i32 {
    return 0;
}

fn shim_set_new_handler(handler: ?*anyopaque) callconv(win) ?*anyopaque {
    _ = handler;
    return null;
}

fn shim_callnewh(_: usize) callconv(win) i32 {
    return 0;
}

fn shim_seh_filter_dll(_: ?*anyopaque, _: ?*anyopaque) callconv(win) i32 {
    return 1; // EXCEPTION_EXECUTE_HANDLER
}

fn shim_setlocale(_: c_int, locale: ?[*:0]const u8) callconv(win) ?[*:0]const u8 {
    _ = locale;
    return "C";
}

const ctype_table = blk: {
    var table: [256]u16 = @splat(0);
    for (0..256) |i| {
        const c: u8 = @intCast(i);
        var flags: u16 = 0;
        if (c >= 'A' and c <= 'Z') flags |= 0x1 | 0x100;
        if (c >= 'a' and c <= 'z') flags |= 0x2 | 0x100;
        if (c >= '0' and c <= '9') flags |= 0x4 | 0x80;
        if (c == ' ' or (c >= 0x09 and c <= 0x0D)) flags |= 0x8;
        if (c >= 0x21 and c <= 0x2F) flags |= 0x10;
        if (c < 0x20 or c == 0x7F) flags |= 0x20;
        if (c == ' ' or c == '\t') flags |= 0x40;
        table[i] = flags;
    }
    break :blk table;
};

fn shim_pctype_func() callconv(win) ?[*]const u16 {
    return &ctype_table;
}

fn shim_mb_cur_max_func() callconv(win) c_int {
    return 1;
}

fn shim_lc_codepage_func() callconv(win) c_int {
    return 65001;
}

fn shim_lc_collate_cp_func() callconv(win) c_int {
    return 65001;
}

var g_locale_name: [6]u16 = .{ 'e', 'n', '-', 'U', 'S', 0 };

/// UCRT's ___lc_locale_name_func returns `wchar_t**`: an array of per-category
/// locale-name pointers.  msvcp140 reads [1] from it.
var g_locale_names: [6]?[*:0]const u16 = .{
    @ptrCast(&g_locale_name),
    @ptrCast(&g_locale_name),
    @ptrCast(&g_locale_name),
    @ptrCast(&g_locale_name),
    @ptrCast(&g_locale_name),
    @ptrCast(&g_locale_name),
};

fn shim_lc_locale_name_func() callconv(win) ?[*]?[*:0]const u16 {
    return &g_locale_names;
}

fn shim_lock_locales() callconv(win) void {}
fn shim_unlock_locales() callconv(win) void {}

fn shim_atol(text: ?[*:0]const u8) callconv(win) c_long {
    const s = std.mem.span(text orelse return 0);
    const trimmed = std.mem.trimStart(u8, s, " \t\r\n");
    var end: usize = 0;
    if (end < trimmed.len and (trimmed[end] == '-' or trimmed[end] == '+')) end += 1;
    while (end < trimmed.len and std.ascii.isDigit(trimmed[end])) : (end += 1) {}
    if (end == 0) return 0;
    return std.fmt.parseInt(c_long, trimmed[0..end], 10) catch 0;
}

fn shim_btowc(c: c_int) callconv(win) u16 {
    if (c < 0 or c > 0xFF) return 0xFFFF;
    return @intCast(c & 0xFF);
}

fn shim_isupper(c: c_int) callconv(win) c_int {
    return if (c >= 'A' and c <= 'Z') 1 else 0;
}

fn shim_iswdigit(c: u16) callconv(win) c_int {
    return if (c >= '0' and c <= '9') 1 else 0;
}

fn shim_iswalnum(c: u16) callconv(win) c_int {
    return if ((c >= '0' and c <= '9') or (c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z')) 1 else 0;
}

fn shim_iswspace(c: u16) callconv(win) c_int {
    return if (c == ' ' or (c >= 0x09 and c <= 0x0D)) 1 else 0;
}

fn shim_iswxdigit(c: u16) callconv(win) c_int {
    return if ((c >= '0' and c <= '9') or (c >= 'A' and c <= 'F') or (c >= 'a' and c <= 'f')) 1 else 0;
}

fn shim_wcsnlen(s: ?[*:0]const u16, max: usize) callconv(win) usize {
    const p = s orelse return 0;
    var i: usize = 0;
    while (i < max and p[i] != 0) : (i += 1) {}
    return i;
}

fn shim_wcscpy_s(dst: ?[*]u16, dst_size: usize, src: ?[*:0]const u16) callconv(win) c_int {
    const d = dst orelse return 22;
    const s = src orelse return 22;
    var i: usize = 0;
    while (i + 1 < dst_size and s[i] != 0) : (i += 1) d[i] = s[i];
    if (i < dst_size) d[i] = 0;
    return 0;
}

fn shim_strncnt(s: ?[*:0]const u8, max: usize) callconv(win) usize {
    const p = s orelse return 0;
    var i: usize = 0;
    while (i < max and p[i] != 0) : (i += 1) {}
    return i;
}

fn shim_wcsdup(s: ?[*:0]const u16) callconv(win) ?[*:0]u16 {
    const src = s orelse return null;
    var n: usize = 0;
    while (src[n] != 0) : (n += 1) {}
    const mem = std.c.malloc((n + 1) * 2) orelse return null;
    const out: [*]u16 = @ptrCast(@alignCast(mem));
    @memcpy(out[0..n], src[0..n]);
    out[n] = 0;
    return @ptrCast(out);
}

fn shim_rand_s(out: ?*u32) callconv(win) c_int {
    const p = out orelse return 22;
    if (builtin.os.tag == .linux) {
        _ = std.os.linux.getrandom(std.mem.asBytes(p), 4, 0);
    } else {
        p.* = 0x1234_5678;
    }
    return 0;
}

fn shim_Getdays() callconv(win) ?[*:0]const u8 {
    return "Sunday\x00Monday\x00Tuesday\x00Wednesday\x00Thursday\x00Friday\x00Saturday\x00\x00";
}

fn shim_Getmonths() callconv(win) ?[*:0]const u8 {
    return "January\x00February\x00March\x00April\x00May\x00June\x00July\x00August\x00September\x00October\x00November\x00December\x00\x00";
}

fn shim_strftime(_: ?[*]u8, _: usize, _: ?[*:0]const u8, _: ?*const anyopaque) callconv(win) usize {
    return 0;
}

fn shim_wcsftime(_: ?[*]u16, _: usize, _: ?[*:0]const u16, _: ?*const anyopaque) callconv(win) usize {
    return 0;
}

// ---------------------------------------------------------------------------
// SLIST / threadpool / remaining CRT-adjacent APIs
// ---------------------------------------------------------------------------

var g_slist_lock: std.atomic.Value(u32) = .init(0);

fn slistLock() void {
    while (g_slist_lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
        while (g_slist_lock.load(.monotonic) != 0) std.atomic.spinLoopHint();
    }
}
fn slistUnlock() void {
    g_slist_lock.store(0, .release);
}

fn shim_InterlockedPushEntrySList(header: ?*anyopaque, entry: ?*anyopaque) callconv(win) ?*anyopaque {
    const h: *usize = @ptrCast(@alignCast(header orelse return null));
    const e: *usize = @ptrCast(@alignCast(entry orelse return null));
    slistLock();
    const old = h.*;
    e.* = old;
    h.* = @intFromPtr(entry.?);
    slistUnlock();
    return if (old == 0) null else @ptrFromInt(old);
}

fn shim_InterlockedFlushSList(header: ?*anyopaque) callconv(win) ?*anyopaque {
    const h: *usize = @ptrCast(@alignCast(header orelse return null));
    slistLock();
    const old = h.*;
    h.* = 0;
    slistUnlock();
    return if (old == 0) null else @ptrFromInt(old);
}

const TpCallback = *const fn (?*anyopaque, ?*anyopaque, ?*anyopaque) callconv(.{ .x86_64_win = .{} }) void;

const TpWork = struct {
    callback: TpCallback,
    context: ?*anyopaque,
};

fn shim_CreateThreadpoolWork(callback: ?TpCallback, context: ?*anyopaque, _: ?*anyopaque) callconv(win) ?*anyopaque {
    const cb = callback orelse return null;
    const work = std.heap.page_allocator.create(TpWork) catch return null;
    work.* = .{ .callback = cb, .context = context };
    return @ptrCast(work);
}

fn shim_SubmitThreadpoolWork(work: ?*anyopaque) callconv(win) void {
    const w: *TpWork = @ptrCast(@alignCast(work orelse return));
    w.callback(work, w.context, work);
}

fn shim_CloseThreadpoolWork(work: ?*anyopaque) callconv(win) void {
    const w: *TpWork = @ptrCast(@alignCast(work orelse return));
    std.heap.page_allocator.destroy(w);
}

fn shim_FreeLibraryWhenCallbackReturns(_: ?*anyopaque, base: usize) callconv(win) void {
    _ = module.release(base);
}

fn shim_RtlCaptureStackBackTrace(_: u32, _: u32, _: ?[*]?*anyopaque, _: ?*u32) callconv(win) u16 {
    return 0;
}

fn shim_CompareStringEx(
    _: ?[*:0]const u16,
    flags: u32,
    s1: ?[*:0]const u16,
    cch1: c_int,
    s2: ?[*:0]const u16,
    cch2: c_int,
    _: ?*anyopaque,
    _: ?*anyopaque,
    _: ?*anyopaque,
) callconv(win) c_int {
    const a = s1 orelse return 0;
    const b = s2 orelse return 0;
    var la: usize = if (cch1 < 0) std.mem.len(a) else @intCast(cch1);
    var lb: usize = if (cch2 < 0) std.mem.len(b) else @intCast(cch2);
    la = @min(la, std.mem.len(a));
    lb = @min(lb, std.mem.len(b));
    const ignore_case = flags & 0x1 != 0; // NORM_IGNORECASE
    var i: usize = 0;
    while (i < la and i < lb) : (i += 1) {
        const ca = if (ignore_case and a[i] < 0x80) std.ascii.toLower(@intCast(a[i])) else a[i];
        const cb = if (ignore_case and b[i] < 0x80) std.ascii.toLower(@intCast(b[i])) else b[i];
        if (ca < cb) return 1;
        if (ca > cb) return 3;
    }
    if (la < lb) return 1;
    if (la > lb) return 3;
    return 2;
}

fn shim_LCMapStringEx(
    _: ?[*:0]const u16,
    _: u32,
    src: ?[*:0]const u16,
    cch_src: c_int,
    dst: ?[*]u16,
    cch_dst: c_int,
    _: ?*anyopaque,
    _: ?*anyopaque,
    _: ?*anyopaque,
) callconv(win) c_int {
    const s = src orelse return 0;
    const len: usize = if (cch_src < 0) std.mem.len(s) else @intCast(cch_src);
    if (dst == null or cch_dst == 0) return @intCast(len);
    const d = dst.?;
    const n = @min(len, @as(usize, @intCast(cch_dst)));
    @memcpy(d[0..n], s[0..n]);
    return @intCast(n);
}

fn shim_GetLocaleInfoEx(
    _: ?[*:0]const u16,
    _: u32,
    out: ?[*]u16,
    cch: c_int,
) callconv(win) c_int {
    const text = [_]u16{ 'e', 'n', '-', 'U', 'S', 0 };
    if (out == null or cch == 0) return text.len;
    if (cch < text.len) return 0;
    @memcpy(out.?[0..text.len], &text);
    return text.len;
}

fn shim_GetCPInfo(_: u32, out: ?[*]u8) callconv(win) i32 {
    const p = out orelse return 0;
    @memset(p[0..18], 0);
    std.mem.writeInt(u32, p[0..4], 1, .little);
    p[4] = '?';
    return 1;
}

fn shim_GetStringTypeW(_: u32, src: ?[*:0]const u16, cch: c_int, out: ?[*]u16) callconv(win) i32 {
    const s = src orelse return 0;
    const d = out orelse return 0;
    const len: usize = if (cch < 0) std.mem.len(s) else @intCast(cch);
    var i: usize = 0;
    while (i < len) : (i += 1) {
        const c = s[i];
        var t: u16 = 0;
        if (c < 0x80) {
            const b: u8 = @intCast(c);
            if (b >= 'A' and b <= 'Z') t |= 0x1 | 0x100;
            if (b >= 'a' and b <= 'z') t |= 0x2 | 0x100;
            if (b >= '0' and b <= '9') t |= 0x4;
            if (b == ' ' or (b >= 0x09 and b <= 0x0D)) t |= 0x8;
        }
        d[i] = t;
    }
    return 1;
}

fn shim_configthreadlocale(_: c_int) callconv(win) c_int {
    return 0;
}

const E_NOTIMPL: i32 = -2147467263;

fn shim_RegisterAppStateChangeNotification(
    _: ?*anyopaque,
    _: ?*anyopaque,
    registration: ?*?*anyopaque,
) callconv(win) i32 {
    if (registration) |p| p.* = null;
    return E_NOTIMPL;
}

fn shim_RegisterAppConstrainedChangeNotification(
    _: ?*anyopaque,
    _: ?*anyopaque,
    registration: ?*?*anyopaque,
) callconv(win) i32 {
    if (registration) |p| p.* = null;
    return E_NOTIMPL;
}

fn shim_OpenThread(_: u32, _: i32, tid: u32) callconv(win) usize {
    if (tid == 0) return 0;
    return 0x7000_0000 | (tid & 0xFFFFF);
}

fn shim_XGameRuntimeInitialize() callconv(win) i32 {
    std.log.info("[GDK] XGameRuntimeInitialize() -> S_OK", .{});
    return 0;
}

fn shim_XGameRuntimeInitializeWithOptions(_: ?*const anyopaque) callconv(win) i32 {
    std.log.info("[GDK] XGameRuntimeInitializeWithOptions() -> S_OK", .{});
    return 0;
}

fn shim_XGameRuntimeUninitialize() callconv(win) void {}


extern "c" var stdin: *std.c.FILE;
extern "c" var stdout: *std.c.FILE;
extern "c" var stderr: *std.c.FILE;

fn shim_acrt_iob_func(index: u32) callconv(win) ?*std.c.FILE {
    if (builtin.os.tag == .linux) {
        return switch (index) {
            0 => stdin,
            1 => stdout,
            2 => stderr,
            else => null,
        };
    }
    return null;
}

var g_stream_buffer: [4096]u8 = undefined;
var g_stream_count: c_int = 0;

fn shim_get_stream_buffer_pointers(
    _: ?*anyopaque,
    base_out: ?*?[*]u8,
    ptr_out: ?*?[*]u8,
    count_out: ?*?*c_int,
) callconv(win) c_int {
    if (base_out) |p| p.* = &g_stream_buffer;
    if (ptr_out) |p| p.* = &g_stream_buffer;
    if (count_out) |p| p.* = &g_stream_count;
    return 0;
}

extern "c" fn fputs(s: [*:0]const u8, stream: *std.c.FILE) c_int;
extern "c" fn fputwc(c: u16, stream: *std.c.FILE) u32;
extern "c" fn fgetwc(stream: *std.c.FILE) u32;
extern "c" fn ungetwc(c: u32, stream: *std.c.FILE) u32;
extern "c" fn frexp(x: f64, exp: *c_int) f64;
extern "c" fn ldexp(x: f64, exp: c_int) f64;

fn shim_fputs(s: ?[*:0]const u8, stream: ?*std.c.FILE) callconv(win) c_int {
    return fputs(s orelse return -1, stream orelse return -1);
}

fn shim_fputwc(c: u32, stream: ?*std.c.FILE) callconv(win) u32 {
    return fputwc(@truncate(c), stream orelse return 0xFFFF_FFFF);
}

fn shim_fgetwc(stream: ?*std.c.FILE) callconv(win) u32 {
    return fgetwc(stream orelse return 0xFFFF_FFFF);
}

fn shim_ungetwc(c: u32, stream: ?*std.c.FILE) callconv(win) u32 {
    return ungetwc(c, stream orelse return 0xFFFF_FFFF);
}

fn shim_frexp(x: f64, exp: ?*c_int) callconv(win) f64 {
    var e: c_int = 0;
    const r = frexp(x, &e);
    if (exp) |p| p.* = e;
    return r;
}

fn shim_ldexp(x: f64, exp: c_int) callconv(win) f64 {
    return ldexp(x, exp);
}

fn wideToUtf8Z(w: ?[*:0]const u16, buf: *[2048]u8) [:0]const u8 {
    const src = w orelse return "";
    var tmp: [1024]u8 = undefined;
    const n = std.unicode.utf16LeToUtf8(&tmp, std.mem.span(src)) catch return "";
    if (n >= buf.len) return "";
    @memcpy(buf[0..n], tmp[0..n]);
    buf[n] = 0;
    return buf[0..n :0];
}

fn shim__wfsopen(path: ?[*:0]const u16, mode: ?[*:0]const u16, _: c_int) callconv(win) ?*std.c.FILE {
    var mbuf: [32]u8 = undefined;
    var mlen: usize = 0;
    if (mode) |m| {
        while (mlen + 1 < mbuf.len and m[mlen] != 0) : (mlen += 1) mbuf[mlen] = @truncate(m[mlen] & 0x7F);
    }
    mbuf[mlen] = 0;
    var pbuf: [2048]u8 = undefined;
    const mapped = win32_fs.mapWidePath(path, &pbuf);
    if (mapped.len == 0) return null;
    return std.c.fopen(@ptrCast(&pbuf), @ptrCast(&mbuf));
}

fn shim__fsopen(path: ?[*:0]const u8, mode: ?[*:0]const u8, _: c_int) callconv(win) ?*std.c.FILE {
    var pbuf: [2048]u8 = undefined;
    const mapped = win32_fs.mapAnsiPath(path, &pbuf);
    if (mapped.len == 0) return null;
    return std.c.fopen(@ptrCast(&pbuf), @ptrCast(mode orelse return null));
}

const BeginThreadFn = *const fn (?*anyopaque) callconv(.{ .x86_64_win = .{} }) u32;

const BeginThreadCtx = struct {
    start: BeginThreadFn,
    arg: ?*anyopaque,
    handle: usize,
    stack_size: usize,
};

fn beginThreadBootstrap(ctx: BeginThreadCtx) void {
    defer sync.markThreadExited(ctx.handle);
    if (builtin.os.tag == .linux) {
        var rsp: usize = undefined;
        asm volatile ("movq %%rsp, %[out]" : [out] "=r" (rsp));
        const base = rsp & ~@as(usize, 0xF);
        _ = teb.initThread(base, base - ctx.stack_size, @truncate(ctx.handle)) catch {};
    }
    _ = ctx.start(ctx.arg);
}

fn shim_beginthreadex(
    _: ?*anyopaque,
    stack_size: u32,
    start: ?BeginThreadFn,
    arglist: ?*anyopaque,
    _: u32,
    thread_id: ?*u32,
) callconv(win) usize {
    const start_fn = start orelse return 0;
    const size: usize = if (stack_size == 0) 1024 * 1024 else stack_size;
    const handle = sync.createThreadHandle(@truncate(@intFromPtr(start_fn)));
    if (handle == 0) return 0;
    if (thread_id) |out| out.* = @truncate(handle);
    const thread = std.Thread.spawn(.{ .stack_size = size }, beginThreadBootstrap, .{BeginThreadCtx{
        .start = start_fn,
        .arg = arglist,
        .handle = handle,
        .stack_size = size,
    }}) catch {
        _ = sync.closeHandle(handle);
        return 0;
    };
    thread.detach();
    return handle;
}

fn shim_endthreadex(code: u32) callconv(win) noreturn {
    if (builtin.os.tag == .linux) std.os.linux.exit(@intCast(code));
    std.process.exit(@truncate(code));
}

pub fn resolve(sym_name: []const u8) ?usize {
    const map = .{
        .{ "RtlCaptureContext", @intFromPtr(&rtlCaptureContext) },
        .{ "RtlLookupFunctionEntry", @intFromPtr(&shim_RtlLookupFunctionEntry) },
        .{ "RtlPcToFileHeader", @intFromPtr(&shim_RtlPcToFileHeader) },
        .{ "RtlVirtualUnwind", @intFromPtr(&shim_RtlVirtualUnwind) },
        .{ "RtlUnwind", @intFromPtr(&shim_RtlUnwind) },
        .{ "RtlUnwindEx", @intFromPtr(&shim_RtlUnwindEx) },
        .{ "RaiseException", @intFromPtr(&shim_RaiseException) },
        .{ "SetUnhandledExceptionFilter", @intFromPtr(&shim_SetUnhandledExceptionFilter) },
        .{ "UnhandledExceptionFilter", @intFromPtr(&shim_UnhandledExceptionFilter) },
        .{ "AddVectoredExceptionHandler", @intFromPtr(&shim_AddVectoredExceptionHandler) },
        .{ "RemoveVectoredExceptionHandler", @intFromPtr(&shim_RemoveVectoredExceptionHandler) },
        .{ "IsDebuggerPresent", @intFromPtr(&shim_IsDebuggerPresent) },
        .{ "EncodePointer", @intFromPtr(&shim_EncodePointer) },
        .{ "DecodePointer", @intFromPtr(&shim_DecodePointer) },
        .{ "FlsAlloc", @intFromPtr(&shim_FlsAlloc) },
        .{ "FlsFree", @intFromPtr(&shim_FlsFree) },
        .{ "FlsGetValue", @intFromPtr(&shim_FlsGetValue) },
        .{ "FlsSetValue", @intFromPtr(&shim_FlsSetValue) },
        .{ "InitOnceExecuteOnce", @intFromPtr(&shim_InitOnceExecuteOnce) },
        .{ "SwitchToThread", @intFromPtr(&shim_SwitchToThread) },
        .{ "GetModuleHandleExW", @intFromPtr(&shim_GetModuleHandleExW) },
        .{ "_execute_onexit_table", @intFromPtr(&shim_execute_onexit_table) },
        .{ "_set_new_handler", @intFromPtr(&shim_set_new_handler) },
        .{ "_callnewh", @intFromPtr(&shim_callnewh) },
        .{ "_seh_filter_dll", @intFromPtr(&shim_seh_filter_dll) },
        .{ "setlocale", @intFromPtr(&shim_setlocale) },
        .{ "__pctype_func", @intFromPtr(&shim_pctype_func) },
        .{ "___mb_cur_max_func", @intFromPtr(&shim_mb_cur_max_func) },
        .{ "___lc_codepage_func", @intFromPtr(&shim_lc_codepage_func) },
        .{ "___lc_collate_cp_func", @intFromPtr(&shim_lc_collate_cp_func) },
        .{ "___lc_locale_name_func", @intFromPtr(&shim_lc_locale_name_func) },
        .{ "_lock_locales", @intFromPtr(&shim_lock_locales) },
        .{ "_unlock_locales", @intFromPtr(&shim_unlock_locales) },
        .{ "atol", @intFromPtr(&shim_atol) },
        .{ "btowc", @intFromPtr(&shim_btowc) },
        .{ "isupper", @intFromPtr(&shim_isupper) },
        .{ "iswdigit", @intFromPtr(&shim_iswdigit) },
        .{ "iswalnum", @intFromPtr(&shim_iswalnum) },
        .{ "iswspace", @intFromPtr(&shim_iswspace) },
        .{ "iswxdigit", @intFromPtr(&shim_iswxdigit) },
        .{ "wcsnlen", @intFromPtr(&shim_wcsnlen) },
        .{ "wcscpy_s", @intFromPtr(&shim_wcscpy_s) },
        .{ "__strncnt", @intFromPtr(&shim_strncnt) },
        .{ "_wcsdup", @intFromPtr(&shim_wcsdup) },
        .{ "rand_s", @intFromPtr(&shim_rand_s) },
        .{ "_Getdays", @intFromPtr(&shim_Getdays) },
        .{ "_Getmonths", @intFromPtr(&shim_Getmonths) },
        .{ "_W_Getdays", @intFromPtr(&shim_Getdays) },
        .{ "_W_Getmonths", @intFromPtr(&shim_Getmonths) },
        .{ "_Gettnames", @intFromPtr(&shim_strftime) },
        .{ "_W_Gettnames", @intFromPtr(&shim_wcsftime) },
        .{ "_Strftime", @intFromPtr(&shim_strftime) },
        .{ "_Wcsftime", @intFromPtr(&shim_wcsftime) },
        .{ "_configthreadlocale", @intFromPtr(&shim_configthreadlocale) },
        .{ "RegisterAppStateChangeNotification", @intFromPtr(&shim_RegisterAppStateChangeNotification) },
        .{ "RegisterAppConstrainedChangeNotification", @intFromPtr(&shim_RegisterAppConstrainedChangeNotification) },
        .{ "OpenThread", @intFromPtr(&shim_OpenThread) },
        .{ "XGameRuntimeInitialize", @intFromPtr(&shim_XGameRuntimeInitialize) },
        .{ "XGameRuntimeInitializeWithOptions", @intFromPtr(&shim_XGameRuntimeInitializeWithOptions) },
        .{ "XGameRuntimeUninitialize", @intFromPtr(&shim_XGameRuntimeUninitialize) },
        .{ "InterlockedPushEntrySList", @intFromPtr(&shim_InterlockedPushEntrySList) },
        .{ "InterlockedFlushSList", @intFromPtr(&shim_InterlockedFlushSList) },
        .{ "CreateThreadpoolWork", @intFromPtr(&shim_CreateThreadpoolWork) },
        .{ "SubmitThreadpoolWork", @intFromPtr(&shim_SubmitThreadpoolWork) },
        .{ "CloseThreadpoolWork", @intFromPtr(&shim_CloseThreadpoolWork) },
        .{ "FreeLibraryWhenCallbackReturns", @intFromPtr(&shim_FreeLibraryWhenCallbackReturns) },
        .{ "RtlCaptureStackBackTrace", @intFromPtr(&shim_RtlCaptureStackBackTrace) },
        .{ "CompareStringEx", @intFromPtr(&shim_CompareStringEx) },
        .{ "LCMapStringEx", @intFromPtr(&shim_LCMapStringEx) },
        .{ "GetLocaleInfoEx", @intFromPtr(&shim_GetLocaleInfoEx) },
        .{ "GetCPInfo", @intFromPtr(&shim_GetCPInfo) },
        .{ "GetStringTypeW", @intFromPtr(&shim_GetStringTypeW) },
        .{ "__acrt_iob_func", @intFromPtr(&shim_acrt_iob_func) },
        .{ "_get_stream_buffer_pointers", @intFromPtr(&shim_get_stream_buffer_pointers) },
        .{ "fputs", @intFromPtr(&shim_fputs) },
        .{ "fputwc", @intFromPtr(&shim_fputwc) },
        .{ "fgetwc", @intFromPtr(&shim_fgetwc) },
        .{ "ungetwc", @intFromPtr(&shim_ungetwc) },
        .{ "frexp", @intFromPtr(&shim_frexp) },
        .{ "ldexp", @intFromPtr(&shim_ldexp) },
        .{ "_wfsopen", @intFromPtr(&shim__wfsopen) },
        .{ "_fsopen", @intFromPtr(&shim__fsopen) },
        .{ "_beginthreadex", @intFromPtr(&shim_beginthreadex) },
        .{ "_endthreadex", @intFromPtr(&shim_endthreadex) },
    };

    inline for (map) |entry| {
        if (std.mem.eql(u8, entry.@"0", sym_name)) return entry.@"1";
    }
    return null;
}

test "RtlVirtualUnwind undoes a small stack allocation" {
    var image: [0x200]u8 = @splat(0);
    const image_base = @intFromPtr(&image);

    // UNWIND_INFO at RVA 0x100: version 1, one UWOP_ALLOC_SMALL(3) at prolog 4.
    image[0x100] = 0x01; // version 1, flags 0
    image[0x101] = 0x04; // SizeOfProlog
    image[0x102] = 0x01; // CountOfCodes
    image[0x103] = 0x00; // FrameRegister/Offset
    image[0x104] = 0x04; // code offset
    image[0x105] = 0x23; // UWOP_ALLOC_SMALL, op_info 3 => 0x20 bytes

    var stack: [0x200]u8 align(16) = @splat(0);
    const entry_rsp = @intFromPtr(&stack) + 0x100;
    const return_addr: u64 = 0x140001234;
    std.mem.writeInt(u64, stack[0x100..][0..8], return_addr, .little);

    var ctx = Context{};
    ctx.rsp = entry_rsp - 0x20;

    const fe = module.RuntimeFunction{ .begin = 0x1000, .end = 0x2000, .unwind = 0x100 };
    var handler_data: ?*anyopaque = null;
    var establisher: u64 = 0;
    const handler = shim_RtlVirtualUnwind(
        0,
        image_base,
        image_base + 0x1000,
        &fe,
        &ctx,
        &handler_data,
        &establisher,
        null,
    );

    try std.testing.expect(handler == null);
    try std.testing.expectEqual(@as(u64, entry_rsp), establisher);
    try std.testing.expectEqual(return_addr, ctx.rip);
    try std.testing.expectEqual(@as(u64, entry_rsp + 8), ctx.rsp);
}

test "RtlVirtualUnwind reports the exception handler" {
    var image: [0x200]u8 = @splat(0);
    const image_base = @intFromPtr(&image);

    image[0x100] = 0x09; // version 1, UNW_FLAG_EHANDLER (0x1 << 3)
    image[0x101] = 0x00;
    image[0x102] = 0x00;
    image[0x103] = 0x00;
    std.mem.writeInt(u32, image[0x104..][0..4], 0x80, .little); // handler RVA

    var stack: [0x100]u8 align(16) = @splat(0);
    const rsp = @intFromPtr(&stack) + 0x80;
    std.mem.writeInt(u64, stack[0x80..][0..8], 0x140005678, .little);

    var ctx = Context{};
    ctx.rsp = rsp;
    const fe = module.RuntimeFunction{ .begin = 0x1000, .end = 0x2000, .unwind = 0x100 };
    var handler_data: ?*anyopaque = null;
    var establisher: u64 = 0;
    const handler = shim_RtlVirtualUnwind(
        0,
        image_base,
        image_base + 0x1000,
        &fe,
        &ctx,
        &handler_data,
        &establisher,
        null,
    );

    try std.testing.expect(handler != null);
    try std.testing.expectEqual(image_base + 0x80, @intFromPtr(handler.?));
    try std.testing.expectEqual(image_base + 0x108, @intFromPtr(handler_data.?));
}
