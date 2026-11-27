//! x64 guest structured exception handling.
//!
//! This is the Windows-side of exceptions: CONTEXT capture/restore, `.pdata`
//! driven virtual unwind (including chained unwind info and machine frames),
//! the exception dispatcher (`RtlVirtualUnwind` handlers such as the guest
//! `__C_specific_handler` / `__CxxFrameHandler4`), and a real
//! `RtlUnwind`/`RtlUnwindEx` that runs termination handlers and transfers
//! control to the target frame through a restored CONTEXT.
//!
//! The x64 ABI has no per-thread exception registration chain: dispatch is
//! driven by the `RUNTIME_FUNCTION` table in each image (`TEB.ExceptionList`
//! stays -1, as on Windows).  The table lookups here are lock-free because the
//! Linux signal handler must be able to unwind guest state without taking the
//! loader's module spinlock.

const std = @import("std");
const builtin = @import("builtin");
const teb = @import("teb.zig");
const module = @import("module.zig");

const win: std.builtin.CallingConvention = .{ .x86_64_win = .{} };

pub const CONTEXT_AMD64: u32 = 0x0010_0000;
pub const CONTEXT_CONTROL: u32 = 0x1;
pub const CONTEXT_INTEGER: u32 = 0x2;
pub const CONTEXT_SEGMENTS: u32 = 0x4;
pub const CONTEXT_FLOATING_POINT: u32 = 0x8;
pub const CONTEXT_FULL: u32 = CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER |
    CONTEXT_FLOATING_POINT;
/// What our RtlCaptureContext writes (segments included, like the Windows one).
pub const CONTEXT_CAPTURE_FLAGS: u32 = CONTEXT_FULL | CONTEXT_SEGMENTS;

pub const EXCEPTION_UNWINDING: u32 = 0x02;
pub const EXCEPTION_TARGET_UNWIND: u32 = 0x20;

pub const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
pub const EXCEPTION_EXECUTE_HANDLER: i32 = 1;

pub const ExceptionContinueExecution: i32 = 0;
pub const ExceptionContinueSearch: i32 = 1;

pub const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
pub const STATUS_IN_PAGE_ERROR: u32 = 0xC000_0006;
pub const STATUS_ILLEGAL_INSTRUCTION: u32 = 0xC000_001D;
pub const STATUS_UNWIND: u32 = 0xC000_0027;
pub const STATUS_STACK_OVERFLOW: u32 = 0xC000_00FD;
pub const STATUS_PRIVILEGED_INSTRUCTION: u32 = 0xC000_0096;
pub const STATUS_INTEGER_DIVIDE_BY_ZERO: u32 = 0xC000_0094;
pub const STATUS_INTEGER_OVERFLOW: u32 = 0xC000_0095;
pub const STATUS_FLOAT_DIVIDE_BY_ZERO: u32 = 0xC000_008E;
pub const STATUS_FLOAT_INEXACT_RESULT: u32 = 0xC000_008F;
pub const STATUS_FLOAT_INVALID_OPERATION: u32 = 0xC000_0090;
pub const STATUS_FLOAT_OVERFLOW: u32 = 0xC000_0091;
pub const STATUS_FLOAT_STACK_CHECK: u32 = 0xC000_0092;
pub const STATUS_FLOAT_UNDERFLOW: u32 = 0xC000_0093;
pub const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
pub const STATUS_BREAKPOINT: u32 = 0x8000_0003;
pub const STATUS_SINGLE_STEP: u32 = 0x8000_0004;

pub const UNW_FLAG_EHANDLER: u8 = 0x1;
pub const UNW_FLAG_UHANDLER: u8 = 0x2;
pub const UNW_FLAG_CHAININFO: u8 = 0x4;

/// x64 CONTEXT, laid out exactly like winnt.h (0x4D0 bytes, Xmm0 at 0x1A0).
/// Guest handlers and the real vcruntime expect the Windows layout: the
/// XMM save area lives inside `FltSave`, not at 0x300.
pub const Context = extern struct {
    p1: u64 align(16) = 0,
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
    /// FltSave Header[2] + Legacy[8] (0x100..0x1A0).
    _flt_head: [0xA0]u8 = @splat(0),
    /// Xmm0..Xmm15 (0x1A0..0x2A0).
    xmm: [16][16]u8 = @splat(@splat(0)),
    /// Remaining FltSave bytes (0x2A0..0x300).
    _flt_tail: [0x60]u8 = @splat(0),
    vector: [26][16]u8 = @splat(@splat(0)),
    vector_control: u64 = 0,
    debug_control: u64 = 0,
    last_branch_to: u64 = 0,
    last_branch_from: u64 = 0,
    last_exception_to: u64 = 0,
    last_exception_from: u64 = 0,
};

comptime {
    std.debug.assert(@offsetOf(Context, "context_flags") == 0x30);
    std.debug.assert(@offsetOf(Context, "mx_csr") == 0x34);
    std.debug.assert(@offsetOf(Context, "rax") == 0x78);
    std.debug.assert(@offsetOf(Context, "rsp") == 0x98);
    std.debug.assert(@offsetOf(Context, "rip") == 0xF8);
    std.debug.assert(@offsetOf(Context, "xmm") == 0x1A0);
    std.debug.assert(@sizeOf(Context) == 0x4D0);
    std.debug.assert(@alignOf(Context) == 16);
}

pub const ExceptionRecord = extern struct {
    exception_code: u32 = 0,
    exception_flags: u32 = 0,
    exception_record: ?*ExceptionRecord = null,
    exception_address: u64 = 0,
    number_parameters: u32 = 0,
    _pad: u32 = 0,
    exception_information: [15]u64 = @splat(0),
};

comptime {
    std.debug.assert(@sizeOf(ExceptionRecord) == 0x98);
}

pub const DispatcherContext = extern struct {
    control_pc: u64 = 0,
    image_base: u64 = 0,
    function_entry: ?*const module.RuntimeFunction = null,
    establisher_frame: u64 = 0,
    target_ip: u64 = 0,
    context_record: ?*Context = null,
    language_handler: usize = 0,
    handler_data: ?*anyopaque = null,
    history_table: ?*anyopaque = null,
    scope_index: u32 = 0,
    fill: u32 = 0,
};

comptime {
    std.debug.assert(@sizeOf(DispatcherContext) == 0x50);
}

pub const ExceptionPointers = extern struct {
    exception_record: *ExceptionRecord,
    context_record: *Context,
};

pub const Handler = *const fn (*ExceptionRecord, u64, *Context, *DispatcherContext) callconv(win) i32;

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

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

/// Stack top (highest valid address) for the current guest thread, if known.
/// Uses the thread-local TEB pointer, never `%gs`, so it is safe in a signal
/// handler.
pub fn stackTop() u64 {
    if (teb.threadTeb()) |t| return t.nt_tib.stack_base;
    if (teb.process()) |p| return p.teb_ptr.nt_tib.stack_base;
    return 0;
}

pub fn stackLimit() u64 {
    if (teb.threadTeb()) |t| return t.nt_tib.stack_limit;
    if (teb.process()) |p| return p.teb_ptr.nt_tib.stack_limit;
    return 0;
}

const Frame = struct {
    base: usize = 0,
    function: ?*const module.RuntimeFunction = null,
};

/// Lock-free `.pdata` lookup for `pc` (used by both dispatch and the signal
/// path).  A missing entry means a leaf function: the caller pops the return
/// address.
pub fn lookupFrame(pc: usize) Frame {
    const img = module.findImageInfo(pc) orelse return .{};
    if (img.pdata_base == 0 or img.pdata_count == 0) return .{ .base = img.base };
    const entries: [*]const module.RuntimeFunction = @ptrFromInt(img.pdata_base);
    const rva: u32 = @intCast(pc - img.base);
    var lo: usize = 0;
    var hi: usize = img.pdata_count;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const e = &entries[mid];
        if (rva < e.begin) {
            hi = mid;
        } else if (rva >= e.end) {
            lo = mid + 1;
        } else {
            return .{ .base = img.base, .function = e };
        }
    }
    return .{ .base = img.base };
}

/// Undo one frame.  On return `ctx` describes the caller; `establisher` is the
/// frame's own stack pointer (return-address slot).  A null return value means
/// "no exception handler for this frame"; the context was still advanced.
pub fn virtualUnwind(
    image_base: usize,
    function: ?*const module.RuntimeFunction,
    ctx: *Context,
    handler_data: *?*anyopaque,
    establisher: *u64,
) ?Handler {
    handler_data.* = null;
    var entry = function;
    var guard: usize = 0;
    while (true) : (guard += 1) {
        if (guard > 16) return null;
        const fe = entry orelse {
            // Leaf function: the return address is on the stack.
            const sp: [*]const u8 = @ptrFromInt(@as(usize, @intCast(ctx.rsp)));
            establisher.* = ctx.rsp;
            ctx.rip = readU64(sp, 0);
            ctx.rsp +%= 8;
            return null;
        };
        const info: [*]const u8 = @ptrFromInt(image_base + fe.unwind);
        const version_flags = info[0];
        if (version_flags & 0x7 != 1) {
            const sp: [*]const u8 = @ptrFromInt(@as(usize, @intCast(ctx.rsp)));
            establisher.* = ctx.rsp;
            ctx.rip = readU64(sp, 0);
            ctx.rsp +%= 8;
            return null;
        }
        const flags: u8 = version_flags >> 3;
        const count: usize = info[2];
        const frame_reg: u8 = info[3] & 0xF;
        const frame_off: u8 = info[3] >> 4;

        var machine_frame = false;
        var machine_frame_establisher: u64 = 0;
        var idx: usize = 0;
        while (idx < count) {
            const b1 = info[4 + idx * 2 + 1];
            const kind = b1 & 0xF;
            const opinfo = b1 >> 4;
            switch (kind) {
                0 => { // UWOP_PUSH_NONVOL
                    const sp: [*]const u8 = @ptrFromInt(@as(usize, @intCast(ctx.rsp)));
                    regField(ctx, opinfo).* = readU64(sp, 0);
                    ctx.rsp +%= 8;
                    idx += 1;
                },
                1 => { // UWOP_ALLOC_LARGE
                    if (opinfo == 0) {
                        const slots = readU16(info, 4 + (idx + 1) * 2);
                        ctx.rsp +%= @as(u64, slots) * 8;
                        idx += 2;
                    } else {
                        const size = @as(u64, readU16(info, 4 + (idx + 1) * 2)) |
                            (@as(u64, readU16(info, 4 + (idx + 2) * 2)) << 16);
                        ctx.rsp +%= size;
                        idx += 3;
                    }
                },
                2 => { // UWOP_ALLOC_SMALL
                    ctx.rsp +%= @as(u64, opinfo) * 8 + 8;
                    idx += 1;
                },
                3 => { // UWOP_SET_FPREG
                    if (frame_reg != 0) ctx.rsp = regField(ctx, frame_reg).* -% (@as(u64, frame_off) * 16);
                    idx += 1;
                },
                4 => { // UWOP_SAVE_NONVOL
                    const off = @as(u64, readU16(info, 4 + (idx + 1) * 2)) * 8;
                    const sp: [*]const u8 = @ptrFromInt(@as(usize, @intCast(ctx.rsp +% off)));
                    regField(ctx, opinfo).* = readU64(sp, 0);
                    idx += 2;
                },
                5 => { // UWOP_SAVE_NONVOL_FAR
                    const off = @as(u64, readU16(info, 4 + (idx + 1) * 2)) |
                        (@as(u64, readU16(info, 4 + (idx + 2) * 2)) << 16);
                    const sp: [*]const u8 = @ptrFromInt(@as(usize, @intCast(ctx.rsp +% off)));
                    regField(ctx, opinfo).* = readU64(sp, 0);
                    idx += 3;
                },
                8 => { // UWOP_SAVE_XMM128
                    const off = @as(u64, readU16(info, 4 + (idx + 1) * 2)) * 16;
                    const sp: [*]const u8 = @ptrFromInt(@as(usize, @intCast(ctx.rsp +% off)));
                    @memcpy(ctx.xmm[opinfo & 0xF][0..16], sp[0..16]);
                    idx += 2;
                },
                9 => { // UWOP_SAVE_XMM128_FAR
                    const off = @as(u64, readU16(info, 4 + (idx + 1) * 2)) |
                        (@as(u64, readU16(info, 4 + (idx + 2) * 2)) << 16);
                    const sp: [*]const u8 = @ptrFromInt(@as(usize, @intCast(ctx.rsp +% off)));
                    @memcpy(ctx.xmm[opinfo & 0xF][0..16], sp[0..16]);
                    idx += 3;
                },
                10 => { // UWOP_PUSH_MACHFRAME
                    // The trap frame is {RIP, CS, EFLAGS, RSP, SS}, optionally
                    // preceded by an error code (opinfo != 0).
                    machine_frame_establisher = ctx.rsp;
                    var p: u64 = ctx.rsp;
                    if (opinfo != 0) p +%= 8;
                    const frame: [*]const u8 = @ptrFromInt(@as(usize, @intCast(p)));
                    ctx.rip = readU64(frame, 0);
                    ctx.seg_cs = readU16(frame, 8);
                    ctx.eflags = readU32(frame, 16);
                    ctx.rsp = readU64(frame, 24);
                    ctx.seg_ss = readU16(frame, 32);
                    machine_frame = true;
                    idx += 1;
                },
                else => idx += 1,
            }
        }

        const handler_off = std.mem.alignForward(usize, 4 + count * 2, 4);
        if (flags & UNW_FLAG_CHAININFO != 0) {
            // Secondary record: after our codes comes a chained RUNTIME_FUNCTION
            // (BeginAddress/EndAddress unused, UnwindData -> primary info).
            entry = @ptrCast(@alignCast(info + handler_off));
            continue;
        }

        if (!machine_frame) {
            establisher.* = ctx.rsp;
            const sp: [*]const u8 = @ptrFromInt(@as(usize, @intCast(ctx.rsp)));
            ctx.rip = readU64(sp, 0);
            ctx.rsp +%= 8;
        } else {
            establisher.* = machine_frame_establisher;
        }

        if (flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0) {
            const handler_rva = readU32(info, handler_off);
            if (handler_rva == 0) return null;
            handler_data.* = @ptrFromInt(image_base + fe.unwind + handler_off + 4);
            return @ptrFromInt(@as(usize, @intCast(image_base + handler_rva)));
        }
        return null;
    }
}

fn shim_RtlVirtualUnwind(
    _: u32,
    image_base: u64,
    _: u64,
    function_entry: ?*const module.RuntimeFunction,
    context_record: ?*anyopaque,
    handler_data: ?*?*anyopaque,
    establisher: ?*u64,
    _: ?*anyopaque,
) callconv(win) ?*anyopaque {
    const ctx: *Context = @ptrCast(@alignCast(context_record orelse return null));
    var hd: ?*anyopaque = null;
    var est: u64 = 0;
    const handler = virtualUnwind(@intCast(image_base), function_entry, ctx, &hd, &est);
    if (handler_data) |p| p.* = hd;
    if (establisher) |p| p.* = est;
    return if (handler) |h| @ptrFromInt(@intFromPtr(h)) else null;
}

/// RtlLookupFunctionEntry: lock-free `.pdata` lookup over the loaded images.
fn shim_RtlLookupFunctionEntry(
    control_pc: u64,
    image_base_out: ?*u64,
    _: ?*anyopaque,
) callconv(win) ?*const module.RuntimeFunction {
    const f = lookupFrame(@intCast(control_pc));
    if (f.base != 0) {
        if (image_base_out) |out| out.* = f.base;
    }
    return f.function;
}

fn shim_RtlPcToFileHeader(pc: u64, image_base_out: ?*u64) callconv(win) u64 {
    if (module.findImageInfo(@intCast(pc))) |img| {
        if (image_base_out) |out| out.* = img.base;
        return img.base;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// CONTEXT capture / restore
// ---------------------------------------------------------------------------

/// `RtlCaptureContext`: naked, captures the *caller* (RCX = CONTEXT*).
/// GP registers, flags, segments, MXCSR and Xmm0-15 are written.
export fn seh_capture_context() callconv(.naked) void {
    asm volatile (
        \\ movq %%rax, 0x78(%%rcx)
        \\ movq %%rcx, 0x80(%%rcx)
        \\ movq %%rdx, 0x88(%%rcx)
        \\ movq %%rbx, 0x90(%%rcx)
        \\ movq %%rbp, 0xa0(%%rcx)
        \\ movq %%rsi, 0xa8(%%rcx)
        \\ movq %%rdi, 0xb0(%%rcx)
        \\ movq %%r8,  0xb8(%%rcx)
        \\ movq %%r9,  0xc0(%%rcx)
        \\ movq %%r10, 0xc8(%%rcx)
        \\ movq %%r11, 0xd0(%%rcx)
        \\ movq %%r12, 0xd8(%%rcx)
        \\ movq %%r13, 0xe0(%%rcx)
        \\ movq %%r14, 0xe8(%%rcx)
        \\ movq %%r15, 0xf0(%%rcx)
        \\ movq (%%rsp), %%rax
        \\ movq %%rax, 0xf8(%%rcx)
        \\ leaq 8(%%rsp), %%rax
        \\ movq %%rax, 0x98(%%rcx)
        \\ movl $0x0010000f, 0x30(%%rcx)
        \\ stmxcsr 0x34(%%rcx)
        \\ movw %%cs, 0x38(%%rcx)
        \\ movw %%ss, 0x42(%%rcx)
        \\ pushfq
        \\ popq %%rax
        \\ movl %%eax, 0x44(%%rcx)
        \\ fxsave 0x100(%%rcx)
        \\ ret
    );
}

/// Resume execution at `ctx`.  Used after a handler returned
/// EXCEPTION_CONTINUE_EXECUTION and by the Linux signal path.
pub fn continueExecution(ctx: *Context) noreturn {
    restoreAndJump(ctx);
    unreachable;
}

/// Restore `ctx` (GP registers, RSP, RIP, MXCSR, XMM) and jump to `ctx.rip`.
/// Never returns.  RDX is used as the CONTEXT base and is intentionally not
/// restored (volatile register).
export fn seh_restore_context() callconv(.naked) void {
    asm volatile (
        \\ movq %%rcx, %%rdx
        \\ fxrstor 0x100(%%rdx)
        \\ ldmxcsr 0x34(%%rdx)
        \\ movq 0x78(%%rdx), %%rax
        \\ movq 0x90(%%rdx), %%rbx
        \\ movq 0xa0(%%rdx), %%rbp
        \\ movq 0xa8(%%rdx), %%rsi
        \\ movq 0xb0(%%rdx), %%rdi
        \\ movq 0xb8(%%rdx), %%r8
        \\ movq 0xc0(%%rdx), %%r9
        \\ movq 0xc8(%%rdx), %%r10
        \\ movq 0xd0(%%rdx), %%r11
        \\ movq 0xd8(%%rdx), %%r12
        \\ movq 0xe0(%%rdx), %%r13
        \\ movq 0xe8(%%rdx), %%r14
        \\ movq 0xf0(%%rdx), %%r15
        \\ movq 0x80(%%rdx), %%rcx
        \\ movq 0x98(%%rdx), %%rsp
        \\ jmpq *0xf8(%%rdx)
    );
}

noinline fn restoreAndJump(ctx: *Context) callconv(.c) void {
    // Never returns: the naked routine restores the context and jumps.
    asm volatile (
        \\ movq %[ctx], %%rcx
        \\ call seh_restore_context
        \\ ud2
        :
        : [ctx] "r" (ctx),
    );
}

// ---------------------------------------------------------------------------
// Vectored exception handlers / unhandled exception filter
// ---------------------------------------------------------------------------

const MAX_VEH = 16;
/// Bit 63 marks a "first chance" registration; the low bits are the handler.
var g_veh: [MAX_VEH]std.atomic.Value(usize) = @splat(std.atomic.Value(usize).init(0));
const VEH_FIRST: usize = 1 << 63;

fn vehHandlerFn(p: usize) *const fn (*ExceptionPointers) callconv(win) i32 {
    return @ptrFromInt(p);
}

pub fn addVectoredHandler(first: bool, handler: usize) ?usize {
    const entry = handler | (if (first) VEH_FIRST else 0);
    var i: usize = 0;
    while (i < MAX_VEH) : (i += 1) {
        if (g_veh[i].load(.acquire) != 0) continue;
        if (g_veh[i].cmpxchgWeak(0, entry, .acq_rel, .acquire) == null) {
            return @intFromPtr(&g_veh[i]);
        }
        i -%= 1;
    }
    return null;
}

pub fn removeVectoredHandler(cookie: usize) bool {
    var i: usize = 0;
    while (i < MAX_VEH) : (i += 1) {
        if (@intFromPtr(&g_veh[i]) != cookie) continue;
        g_veh[i].store(0, .release);
        return true;
    }
    return false;
}

fn dispatchVectored(record: *ExceptionRecord, ctx: *Context) bool {
    var pass: usize = 0;
    while (pass < 2) : (pass += 1) {
        var i: usize = 0;
        while (i < MAX_VEH) : (i += 1) {
            const raw = g_veh[i].load(.acquire);
            if (raw == 0) continue;
            const is_first = (raw & VEH_FIRST) != 0;
            if (is_first != (pass == 0)) continue;
            var ep = ExceptionPointers{ .exception_record = record, .context_record = ctx };
            const rc = vehHandlerFn(raw & ~VEH_FIRST)(&ep);
            if (rc == EXCEPTION_CONTINUE_EXECUTION) return true;
        }
    }
    return false;
}

var g_unhandled_filter: usize = 0;

fn unhandledFilterFn(p: usize) *const fn (*ExceptionPointers) callconv(win) i32 {
    return @ptrFromInt(p);
}

/// Returns true when the filter asked us to terminate (EXECUTE_HANDLER).
pub fn callUnhandledFilter(record: *ExceptionRecord, ctx: *Context) bool {
    const filter = @atomicLoad(usize, &g_unhandled_filter, .acquire);
    if (filter == 0) return false;
    var ep = ExceptionPointers{ .exception_record = record, .context_record = ctx };
    return unhandledFilterFn(filter)(&ep) == EXCEPTION_EXECUTE_HANDLER;
}

fn shim_SetUnhandledExceptionFilter(filter: ?*anyopaque) callconv(win) ?*anyopaque {
    const previous = @atomicLoad(usize, &g_unhandled_filter, .acquire);
    const next: usize = if (filter) |f| @intFromPtr(f) else 0;
    @atomicStore(usize, &g_unhandled_filter, next, .release);
    return if (previous == 0) null else @ptrFromInt(previous);
}

fn shim_UnhandledExceptionFilter(info: ?*anyopaque) callconv(win) i32 {
    const filter = @atomicLoad(usize, &g_unhandled_filter, .acquire);
    if (filter == 0) return EXCEPTION_EXECUTE_HANDLER;
    if (info) |p| {
        const ep: *ExceptionPointers = @ptrCast(@alignCast(p));
        return unhandledFilterFn(filter)(ep);
    }
    return unhandledFilterFn(filter)(undefined);
}

fn shim_AddVectoredExceptionHandler(first: u32, handler: ?*anyopaque) callconv(win) ?*anyopaque {
    const h = handler orelse return null;
    const cookie = addVectoredHandler(first != 0, @intFromPtr(h)) orelse return null;
    return @ptrFromInt(cookie);
}

fn shim_RemoveVectoredExceptionHandler(cookie: ?*anyopaque) callconv(win) u32 {
    const value = cookie orelse return 0;
    return if (removeVectoredHandler(@intFromPtr(value))) 1 else 0;
}

fn shim_AddVectoredContinueHandler(first: u32, handler: ?*anyopaque) callconv(win) ?*anyopaque {
    _ = first;
    _ = handler;
    return null;
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// First-chance dispatch: VEH handlers, then the `.pdata` handler chain.  The
/// handlers are the guest's real `__C_specific_handler` / `__CxxFrameHandler*`
/// (they do their own filter/catch work and call RtlUnwindEx to transfer
/// control).  Returns true when some handler asked to continue execution at
/// `ctx`; false means unhandled.
pub fn dispatchException(record: *ExceptionRecord, ctx: *Context) bool {
    if (dispatchVectored(record, ctx)) return true;

    var walk = ctx.*;
    const top = stackTop();
    var frames: usize = 0;
    while (frames < 4096) : (frames += 1) {
        const pc = walk.rip;
        const found = lookupFrame(@intCast(pc));
        var handler_data: ?*anyopaque = null;
        var establisher: u64 = 0;
        const handler = virtualUnwind(found.base, found.function, &walk, &handler_data, &establisher);
        if (handler) |h| {
            var dc = DispatcherContext{
                .control_pc = pc,
                .image_base = found.base,
                .function_entry = found.function,
                .establisher_frame = establisher,
                .target_ip = 0,
                .context_record = ctx,
                .language_handler = @intFromPtr(h),
                .handler_data = handler_data,
                .history_table = null,
                .scope_index = 0,
            };
            const disposition = h(record, establisher, ctx, &dc);
            if (disposition != ExceptionContinueSearch) return true;
        }
        if (walk.rip == 0) break;
        if (top != 0 and walk.rsp >= top) break;
    }
    return false;
}

fn defaultUnwindRecord() ExceptionRecord {
    var r = std.mem.zeroes(ExceptionRecord);
    r.exception_code = STATUS_UNWIND;
    r.exception_flags = EXCEPTION_UNWINDING;
    return r;
}

/// Second pass: run termination handlers from `ctx` down to `target_frame` and
/// rewrite `ctx` to the target (rip = target_ip, rsp = target_frame,
/// rax = return_value).  `ctx` is *not* jumped to here; callers either jump
/// (`restoreAndJump`) or inspect it (tests).
pub fn unwindToTarget(
    ctx: *Context,
    target_frame: u64,
    target_ip: u64,
    exception_record: ?*ExceptionRecord,
    return_value: u64,
) void {
    const base_record: ExceptionRecord = if (exception_record) |r| r.* else defaultUnwindRecord();
    var walk = ctx.*;
    const top = stackTop();
    var frames: usize = 0;
    while (frames < 4096) : (frames += 1) {
        const pc = walk.rip;
        const found = lookupFrame(@intCast(pc));
        var handler_data: ?*anyopaque = null;
        var establisher: u64 = 0;
        const handler = virtualUnwind(found.base, found.function, &walk, &handler_data, &establisher);
        const is_target = establisher == target_frame;
        if (handler) |h| {
            var rec = base_record;
            rec.exception_flags |= EXCEPTION_UNWINDING;
            if (is_target) rec.exception_flags |= EXCEPTION_TARGET_UNWIND;
            var dc = DispatcherContext{
                .control_pc = pc,
                .image_base = found.base,
                .function_entry = found.function,
                .establisher_frame = establisher,
                .target_ip = target_ip,
                .context_record = ctx,
                .language_handler = @intFromPtr(h),
                .handler_data = handler_data,
                .history_table = null,
                .scope_index = 0,
            };
            _ = h(&rec, establisher, ctx, &dc);
        }
        if (is_target) break;
        if (walk.rip == 0) break;
        if (top != 0 and walk.rsp > top) break;
    }

    ctx.* = walk;
    ctx.rip = target_ip;
    ctx.rsp = target_frame;
    ctx.rax = return_value;
}

fn shim_RtlUnwindEx(
    target_frame: ?*anyopaque,
    target_ip: ?*anyopaque,
    exception_record: ?*ExceptionRecord,
    return_value: ?*anyopaque,
    context_record: ?*Context,
    _: ?*anyopaque,
) callconv(win) void {
    const ctx = context_record orelse {
        std.log.err("[SEH] RtlUnwindEx with a NULL CONTEXT record", .{});
        return;
    };
    unwindToTarget(
        ctx,
        @intFromPtr(target_frame),
        @intFromPtr(target_ip),
        exception_record,
        if (return_value) |rv| @intFromPtr(rv) else 0,
    );
    restoreAndJump(ctx);
    unreachable;
}

// ---------------------------------------------------------------------------
// RaiseException / RtlUnwind entry points
//
// The context must describe the *caller* of the API, so the entry points are
// naked: capture the caller's register state, then tail-call the Zig
// implementation (which never returns: it either jumps into a guest handler or
// terminates the process).
// ---------------------------------------------------------------------------

export fn seh_raise_entry() callconv(.naked) void {
    asm volatile (
    // Entry: RSP = S, [S] = return address, S % 16 == 8.
    // Make a 0x548-byte frame so RSP is 16-byte aligned at the call.
        \\ subq $0x548, %%rsp
        // ---- capture the caller's CONTEXT at 0x50(%rsp) ----
        \\ movq %%rax, 0x50+0x78(%%rsp)
        \\ movq %%rcx, 0x50+0x80(%%rsp)
        \\ movq %%rdx, 0x50+0x88(%%rsp)
        \\ movq %%rbx, 0x50+0x90(%%rsp)
        \\ movq %%rbp, 0x50+0xa0(%%rsp)
        \\ movq %%rsi, 0x50+0xa8(%%rsp)
        \\ movq %%rdi, 0x50+0xb0(%%rsp)
        \\ movq %%r8,  0x50+0xb8(%%rsp)
        \\ movq %%r9,  0x50+0xc0(%%rsp)
        \\ movq %%r10, 0x50+0xc8(%%rsp)
        \\ movq %%r11, 0x50+0xd0(%%rsp)
        \\ movq %%r12, 0x50+0xd8(%%rsp)
        \\ movq %%r13, 0x50+0xe0(%%rsp)
        \\ movq %%r14, 0x50+0xe8(%%rsp)
        \\ movq %%r15, 0x50+0xf0(%%rsp)
        \\ leaq 0x548(%%rsp), %%rax
        \\ movq (%%rax), %%rcx
        \\ movq %%rcx, 0x50+0xf8(%%rsp)
        \\ addq $8, %%rax
        \\ movq %%rax, 0x50+0x98(%%rsp)
        \\ movl $0x0010000f, 0x50+0x30(%%rsp)
        \\ stmxcsr 0x50+0x34(%%rsp)
        \\ movw %%cs, 0x50+0x38(%%rsp)
        \\ movw %%ss, 0x50+0x42(%%rsp)
        \\ pushfq
        \\ popq %%rax
        \\ movl %%eax, 0x50+0x44(%%rsp)
        \\ fxsave 0x50+0x100(%%rsp)
        // ---- call seh_raise_impl(ctx, code, flags, nargs, args) ----
        \\ leaq 0x50(%%rsp), %%rcx
        \\ movl 0x50+0x80(%%rsp), %%edx
        \\ movl 0x50+0x88(%%rsp), %%r8d
        \\ movl 0x50+0xb8(%%rsp), %%r9d
        \\ movq 0x50+0xc0(%%rsp), %%rax
        \\ movq %%rax, 0x20(%%rsp)
        \\ call seh_raise_impl
        \\ ud2
    );
}

export fn seh_unwind_entry() callconv(.naked) void {
    asm volatile (
        \\ subq $0x548, %%rsp
        \\ movq %%rax, 0x50+0x78(%%rsp)
        \\ movq %%rcx, 0x50+0x80(%%rsp)
        \\ movq %%rdx, 0x50+0x88(%%rsp)
        \\ movq %%rbx, 0x50+0x90(%%rsp)
        \\ movq %%rbp, 0x50+0xa0(%%rsp)
        \\ movq %%rsi, 0x50+0xa8(%%rsp)
        \\ movq %%rdi, 0x50+0xb0(%%rsp)
        \\ movq %%r8,  0x50+0xb8(%%rsp)
        \\ movq %%r9,  0x50+0xc0(%%rsp)
        \\ movq %%r10, 0x50+0xc8(%%rsp)
        \\ movq %%r11, 0x50+0xd0(%%rsp)
        \\ movq %%r12, 0x50+0xd8(%%rsp)
        \\ movq %%r13, 0x50+0xe0(%%rsp)
        \\ movq %%r14, 0x50+0xe8(%%rsp)
        \\ movq %%r15, 0x50+0xf0(%%rsp)
        \\ leaq 0x548(%%rsp), %%rax
        \\ movq (%%rax), %%rcx
        \\ movq %%rcx, 0x50+0xf8(%%rsp)
        \\ addq $8, %%rax
        \\ movq %%rax, 0x50+0x98(%%rsp)
        \\ movl $0x0010000f, 0x50+0x30(%%rsp)
        \\ stmxcsr 0x50+0x34(%%rsp)
        \\ movw %%cs, 0x50+0x38(%%rsp)
        \\ movw %%ss, 0x50+0x42(%%rsp)
        \\ pushfq
        \\ popq %%rax
        \\ movl %%eax, 0x50+0x44(%%rsp)
        \\ fxsave 0x50+0x100(%%rsp)
        // ---- call seh_unwind_impl(ctx, target_frame, target_ip, record, rv) ----
        \\ leaq 0x50(%%rsp), %%rcx
        \\ movq 0x50+0x80(%%rsp), %%rdx
        \\ movq 0x50+0x88(%%rsp), %%r8
        \\ movq 0x50+0xb8(%%rsp), %%r9
        \\ movq 0x50+0xc0(%%rsp), %%rax
        \\ movq %%rax, 0x20(%%rsp)
        \\ call seh_unwind_impl
        \\ ud2
    );
}

export fn seh_raise_impl(
    ctx: *Context,
    code: u32,
    flags: u32,
    nargs: u32,
    args: ?[*]const u64,
) callconv(win) noreturn {
    var record = std.mem.zeroes(ExceptionRecord);
    record.exception_code = code;
    record.exception_flags = flags;
    record.exception_address = ctx.rip;
    const n = @min(nargs, 15);
    record.number_parameters = n;
    if (args) |a| {
        var i: usize = 0;
        while (i < n) : (i += 1) record.exception_information[i] = a[i];
    }

    if (dispatchException(&record, ctx)) {
        // A handler asked to continue execution (possibly after rewriting the
        // context): resume there.
        continueExecution(ctx);
    }

    _ = callUnhandledFilter(&record, ctx);
    std.log.err(
        "[SEH] unhandled guest exception code=0x{x} address=0x{x} rip=0x{x}",
        .{ record.exception_code, record.exception_address, ctx.rip },
    );
    std.process.exit(@truncate(record.exception_code));
}

export fn seh_unwind_impl(
    ctx: *Context,
    target_frame: u64,
    target_ip: u64,
    exception_record: ?*ExceptionRecord,
    return_value: u64,
) callconv(win) noreturn {
    unwindToTarget(ctx, target_frame, target_ip, exception_record, return_value);
    continueExecution(ctx);
}

// ---------------------------------------------------------------------------
// Registration table consumed by crt_extra
// ---------------------------------------------------------------------------

pub fn resolve(sym_name: []const u8) ?usize {
    const map = .{
        .{ "RtlCaptureContext", @intFromPtr(&seh_capture_context) },
        .{ "RtlLookupFunctionEntry", @intFromPtr(&shim_RtlLookupFunctionEntry) },
        .{ "RtlPcToFileHeader", @intFromPtr(&shim_RtlPcToFileHeader) },
        .{ "RtlVirtualUnwind", @intFromPtr(&shim_RtlVirtualUnwind) },
        .{ "RtlUnwind", @intFromPtr(&seh_unwind_entry) },
        .{ "RtlUnwindEx", @intFromPtr(&shim_RtlUnwindEx) },
        .{ "RaiseException", @intFromPtr(&seh_raise_entry) },
        .{ "SetUnhandledExceptionFilter", @intFromPtr(&shim_SetUnhandledExceptionFilter) },
        .{ "UnhandledExceptionFilter", @intFromPtr(&shim_UnhandledExceptionFilter) },
        .{ "AddVectoredExceptionHandler", @intFromPtr(&shim_AddVectoredExceptionHandler) },
        .{ "RemoveVectoredExceptionHandler", @intFromPtr(&shim_RemoveVectoredExceptionHandler) },
        .{ "AddVectoredContinueHandler", @intFromPtr(&shim_AddVectoredContinueHandler) },
    };
    inline for (map) |entry| {
        if (std.mem.eql(u8, entry.@"0", sym_name)) return entry.@"1";
    }
    return null;
}

// ===========================================================================
// Tests
// ===========================================================================

const c = struct {
    extern "c" fn mmap(addr: ?*anyopaque, len: usize, prot: i32, flags: i32, fd: i32, offset: i64) ?*anyopaque;
};

fn allocTestImage(size: usize) [*]u8 {
    const p = c.mmap(null, size, 0x7, 0x22, -1, 0) orelse @panic("mmap failed");
    const bytes: [*]u8 = @ptrCast(p);
    @memset(bytes[0..size], 0);
    return bytes;
}

fn writeU16(p: [*]u8, off: usize, v: u16) void {
    std.mem.writeInt(u16, p[off..][0..2], v, .little);
}
fn writeU32(p: [*]u8, off: usize, v: u32) void {
    std.mem.writeInt(u32, p[off..][0..4], v, .little);
}
fn writeU64(p: [*]u8, off: usize, v: u64) void {
    std.mem.writeInt(u64, p[off..][0..8], v, .little);
}

/// `movabs $target, %rax ; jmp *%rax`
fn writeJumpStub(p: [*]u8, off: usize, target: usize) void {
    p[off + 0] = 0x48;
    p[off + 1] = 0xB8;
    writeU64(p, off + 2, target);
    p[off + 10] = 0xFF;
    p[off + 11] = 0xE0;
}

fn registerImage(base: usize, size: usize, pdata_rva: u32, pdata_count: u32) void {
    _ = module.register(
        std.heap.page_allocator,
        "seh-test-image",
        "seh-test-image",
        "seh-test-image",
        base,
        size,
        0,
        base + pdata_rva,
        pdata_count,
        &.{},
        false,
    ) catch @panic("module.register failed");
}

/// .pdata entry + UNWIND_INFO for a leaf-only function with a handler.
fn writeFunction(
    img: [*]u8,
    pdata_off: usize,
    begin: u32,
    end: u32,
    info_off: usize,
    handler_rva: u32,
) void {
    writeU32(img, pdata_off + 0, begin);
    writeU32(img, pdata_off + 4, end);
    writeU32(img, pdata_off + 8, @intCast(info_off));
    // version 1, UNW_FLAG_EHANDLER, no prolog, no codes.
    img[info_off + 0] = 0x01 | (UNW_FLAG_EHANDLER << 3);
    img[info_off + 1] = 0;
    img[info_off + 2] = 0;
    img[info_off + 3] = 0;
    writeU32(img, info_off + 4, handler_rva);
}

var g_disp_calls: usize = 0;
var g_disp_establisher: u64 = 0;
var g_disp_code: u32 = 0;
var g_disp_return: i32 = ExceptionContinueSearch;

fn testDispatchHandler(
    record: *ExceptionRecord,
    establisher: u64,
    _: *Context,
    _: *DispatcherContext,
) callconv(win) i32 {
    g_disp_calls += 1;
    g_disp_establisher = establisher;
    g_disp_code = record.exception_code;
    return g_disp_return;
}

test "virtual unwind: leaf frame pops the return address" {
    var stack: [0x100]u8 align(16) = @splat(0);
    writeU64(&stack, 0x40, 0x1_4000_1234);
    var ctx = Context{};
    ctx.rsp = @intFromPtr(&stack) + 0x40;
    var hd: ?*anyopaque = null;
    var est: u64 = 0;
    const handler = virtualUnwind(0, null, &ctx, &hd, &est);
    try std.testing.expect(handler == null);
    try std.testing.expectEqual(@as(u64, @intFromPtr(&stack) + 0x40), est);
    try std.testing.expectEqual(@as(u64, 0x1_4000_1234), ctx.rip);
    try std.testing.expectEqual(@as(u64, @intFromPtr(&stack) + 0x48), ctx.rsp);
}

test "virtual unwind: alloc small and report the handler" {
    var image: [0x400]u8 = @splat(0);
    const image_base = @intFromPtr(&image);
    image[0x100] = 0x09; // version 1, UNW_FLAG_EHANDLER
    image[0x101] = 0x04;
    image[0x102] = 0x01; // one code
    image[0x103] = 0x00;
    image[0x104] = 0x04; // prolog offset
    image[0x105] = 0x32; // UWOP_ALLOC_SMALL, info 3 => 0x20 bytes
    writeU32(&image, 0x108, 0x80); // handler RVA

    var stack: [0x200]u8 align(16) = @splat(0);
    const entry_rsp = @intFromPtr(&stack) + 0x100;
    writeU64(&stack, 0x100, 0x1_4000_1234);

    var ctx = Context{};
    ctx.rsp = entry_rsp - 0x20;
    const fe = module.RuntimeFunction{ .begin = 0x1000, .end = 0x2000, .unwind = 0x100 };
    var hd: ?*anyopaque = null;
    var est: u64 = 0;
    const handler = virtualUnwind(image_base, &fe, &ctx, &hd, &est);
    try std.testing.expect(handler != null);
    try std.testing.expectEqual(image_base + 0x80, @intFromPtr(handler.?));
    try std.testing.expectEqual(entry_rsp, est);
    try std.testing.expectEqual(@as(u64, 0x1_4000_1234), ctx.rip);
    try std.testing.expectEqual(entry_rsp + 8, ctx.rsp);
    try std.testing.expectEqual(image_base + 0x10C, @intFromPtr(hd.?));
}

test "virtual unwind: chained unwind info applies both records" {
    var image: [0x800]u8 = @splat(0);
    const image_base = @intFromPtr(&image);

    // Secondary record: version 1 + UNW_FLAG_CHAININFO, one PUSH_NONVOL rbx.
    image[0x100] = 0x01 | (UNW_FLAG_CHAININFO << 3);
    image[0x101] = 0x08;
    image[0x102] = 0x01;
    image[0x103] = 0x00;
    image[0x104] = 0x08; // prolog offset
    image[0x105] = 0x30; // UWOP_PUSH_NONVOL, rbx
    // Chained RUNTIME_FUNCTION at align4(4 + 2) == 8 -> 0x108.
    writeU32(&image, 0x108, 0);
    writeU32(&image, 0x10C, 0);
    writeU32(&image, 0x110, 0x200); // primary UNWIND_INFO

    // Primary record: version 1 + EHANDLER, one ALLOC_SMALL(0x20).
    image[0x200] = 0x01 | (UNW_FLAG_EHANDLER << 3);
    image[0x201] = 0x10;
    image[0x202] = 0x01;
    image[0x203] = 0x00;
    image[0x204] = 0x10;
    image[0x205] = 0x32; // UWOP_ALLOC_SMALL, info 3
    writeU32(&image, 0x208, 0x400); // primary handler RVA

    var stack: [0x200]u8 align(16) = @splat(0);
    const sp = @intFromPtr(&stack) + 0x80;
    writeU64(&stack, 0x80, 0xDEAD_BEEF_0BAD_F00D); // saved rbx
    writeU64(&stack, 0xA8, 0x1_4000_5678); // return address after both ops

    var ctx = Context{};
    ctx.rsp = sp;
    const fe = module.RuntimeFunction{ .begin = 0x1000, .end = 0x2000, .unwind = 0x100 };
    var hd: ?*anyopaque = null;
    var est: u64 = 0;
    const handler = virtualUnwind(image_base, &fe, &ctx, &hd, &est);
    try std.testing.expect(handler != null);
    try std.testing.expectEqual(image_base + 0x400, @intFromPtr(handler.?));
    try std.testing.expectEqual(@as(u64, 0xDEAD_BEEF_0BAD_F00D), ctx.rbx);
    try std.testing.expectEqual(sp + 0x28, est);
    try std.testing.expectEqual(@as(u64, 0x1_4000_5678), ctx.rip);
    try std.testing.expectEqual(sp + 0x30, ctx.rsp);
    try std.testing.expectEqual(image_base + 0x20C, @intFromPtr(hd.?));
}

test "virtual unwind: machine frame skips the error code" {
    var image: [0x400]u8 = @splat(0);
    const image_base = @intFromPtr(&image);
    image[0x100] = 0x01; // version 1, no flags
    image[0x101] = 0x00;
    image[0x102] = 0x01;
    image[0x103] = 0x00;
    image[0x104] = 0x00; // prolog offset
    image[0x105] = 0x1A; // UWOP_PUSH_MACHFRAME, info 1 => error code present

    var stack: [0x200]u8 align(16) = @splat(0);
    const sp = @intFromPtr(&stack) + 0x40;
    writeU64(&stack, 0x40, 0xFFFF_FFFF_FFFF_FFFF); // error code
    writeU64(&stack, 0x48, 0x1_4000_ABCD); // rip
    writeU16(&stack, 0x50, 0x33); // cs
    writeU32(&stack, 0x58, 0x202); // eflags
    writeU64(&stack, 0x60, 0x7FFF_0000_1000); // interrupted rsp
    writeU16(&stack, 0x68, 0x2B); // ss

    var ctx = Context{};
    ctx.rsp = sp;
    const fe = module.RuntimeFunction{ .begin = 0x1000, .end = 0x2000, .unwind = 0x100 };
    var hd: ?*anyopaque = null;
    var est: u64 = 0;
    const handler = virtualUnwind(image_base, &fe, &ctx, &hd, &est);
    try std.testing.expect(handler == null);
    try std.testing.expectEqual(@as(u64, 0x1_4000_ABCD), ctx.rip);
    try std.testing.expectEqual(@as(u64, 0x7FFF_0000_1000), ctx.rsp);
    try std.testing.expectEqual(@as(u16, 0x33), ctx.seg_cs);
    try std.testing.expectEqual(@as(u16, 0x2B), ctx.seg_ss);
    try std.testing.expectEqual(@as(u32, 0x202), ctx.eflags);
    try std.testing.expectEqual(sp, est);
}

test "RtlCaptureContext stores XMM, flags and the caller context" {
    var ctx = Context{};
    var value: [16]u8 align(16) = .{
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
    };
    // Build a valid FXSAVE image with the known Xmm0, load it, then capture.
    // (`fxrstor` is used instead of `movdqu` because Zig's debug assembler does
    // not accept SSE moves with memory operands.)
    var fpu: [0x200]u8 align(16) = @splat(0);
    std.mem.writeInt(u16, fpu[0..2], 0x037F, .little); // FCW
    std.mem.writeInt(u32, fpu[0x18..0x1C], 0x1F80, .little); // MXCSR
    @memcpy(fpu[0xA0..0xB0], &value); // Xmm0 in FXSAVE layout
    _ = asm volatile (
        \\ fxrstor (%[p])
        \\ movq %[ctx], %%rcx
        \\ call seh_capture_context
        : [out_rax] "={rax}" (-> usize),
        : [p] "r" (@intFromPtr(&fpu)),
          [ctx] "r" (&ctx),
    );
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        try std.testing.expectEqual(value[i], ctx.xmm[0][i]);
    }
    try std.testing.expectEqual(CONTEXT_CAPTURE_FLAGS, ctx.context_flags);
    try std.testing.expect(ctx.rip != 0);
    try std.testing.expect(ctx.rsp != 0);
}

var g_veh_calls: usize = 0;

fn testVeh(_: *ExceptionPointers) callconv(win) i32 {
    g_veh_calls += 1;
    return EXCEPTION_CONTINUE_EXECUTION;
}

test "RaiseException reaches a VEH and resumes execution" {
    g_veh_calls = 0;
    const cookie = addVectoredHandler(false, @intFromPtr(&testVeh)) orelse return error.OutOfMemory;
    defer _ = removeVectoredHandler(cookie);
    // The raise entry captures the caller's registers, so the volatile ones
    // are saved/restored here.  An even number of pushes keeps the 16-byte
    // call alignment that the FXSAVE inside the entry point requires.
    asm volatile (
        \\ pushq %rax
        \\ pushq %rcx
        \\ pushq %rdx
        \\ pushq %r8
        \\ pushq %r9
        \\ pushq %r10
        \\ pushq %r11
        \\ pushq %rsi
        \\ movl $0xE0000001, %ecx
        \\ xorl %edx, %edx
        \\ xorl %r8d, %r8d
        \\ xorl %r9d, %r9d
        \\ call seh_raise_entry
        \\ popq %rsi
        \\ popq %r11
        \\ popq %r10
        \\ popq %r9
        \\ popq %r8
        \\ popq %rdx
        \\ popq %rcx
        \\ popq %rax
    );
    try std.testing.expectEqual(@as(usize, 1), g_veh_calls);
}

test "dispatch: calls the frame handler with the establisher frame" {
    const img = allocTestImage(0x2000);
    const base = @intFromPtr(img);
    writeFunction(img, 0x100, 0x1010, 0x1100, 0x200, 0x300);
    writeJumpStub(img, 0x300, @intFromPtr(&testDispatchHandler));
    registerImage(base, 0x2000, 0x100, 1);

    var stack: [0x200]u8 align(16) = @splat(0);
    const sp = @intFromPtr(&stack) + 0x100;
    // A zero return address ends the walk after the first frame.
    writeU64(&stack, 0x100, 0);

    var ctx = Context{};
    ctx.rip = base + 0x1010;
    ctx.rsp = sp;

    var record = std.mem.zeroes(ExceptionRecord);
    record.exception_code = STATUS_ACCESS_VIOLATION;
    record.exception_address = ctx.rip;
    g_disp_calls = 0;
    g_disp_return = ExceptionContinueSearch;
    const handled = dispatchException(&record, &ctx);
    try std.testing.expect(!handled);
    try std.testing.expectEqual(@as(usize, 1), g_disp_calls);
    try std.testing.expectEqual(@as(u64, sp), g_disp_establisher);
    try std.testing.expectEqual(STATUS_ACCESS_VIOLATION, g_disp_code);
}

test "dispatch: a handler can request continue-execution" {
    const img = allocTestImage(0x2000);
    const base = @intFromPtr(img);
    writeFunction(img, 0x100, 0x1010, 0x1100, 0x200, 0x300);
    writeJumpStub(img, 0x300, @intFromPtr(&testDispatchHandler));
    registerImage(base, 0x2000, 0x100, 1);

    var stack: [0x100]u8 align(16) = @splat(0);
    const sp = @intFromPtr(&stack) + 0x80;
    writeU64(&stack, 0x80, 0);

    var ctx = Context{};
    ctx.rip = base + 0x1010;
    ctx.rsp = sp;
    var record = std.mem.zeroes(ExceptionRecord);
    record.exception_code = STATUS_ILLEGAL_INSTRUCTION;
    g_disp_return = ExceptionContinueExecution;
    const handled = dispatchException(&record, &ctx);
    try std.testing.expect(handled);
    g_disp_return = ExceptionContinueSearch;
}

var g_unwind_order: [4]u64 = @splat(0);
var g_unwind_flags: [4]u32 = @splat(0);
var g_unwind_count: usize = 0;

fn testUnwindHandler(
    record: *ExceptionRecord,
    establisher: u64,
    _: *Context,
    _: *DispatcherContext,
) callconv(win) i32 {
    if (g_unwind_count < g_unwind_order.len) {
        g_unwind_order[g_unwind_count] = establisher;
        g_unwind_flags[g_unwind_count] = record.exception_flags;
    }
    g_unwind_count += 1;
    return ExceptionContinueSearch;
}

test "unwind: runs termination handlers and rewrites the context to the target" {
    const img = allocTestImage(0x2000);
    const base = @intFromPtr(img);
    writeFunction(img, 0x100, 0x1010, 0x1100, 0x200, 0x300);
    writeFunction(img, 0x10C, 0x1110, 0x1200, 0x240, 0x320);
    writeJumpStub(img, 0x300, @intFromPtr(&testUnwindHandler));
    writeJumpStub(img, 0x320, @intFromPtr(&testUnwindHandler));
    registerImage(base, 0x2000, 0x100, 2);

    var stack: [0x200]u8 align(16) = @splat(0);
    const sp = @intFromPtr(&stack) + 0x100;
    writeU64(&stack, 0x100, base + 0x1110); // return address -> caller frame

    var ctx = Context{};
    ctx.rip = base + 0x1010;
    ctx.rsp = sp;

    var record = std.mem.zeroes(ExceptionRecord);
    record.exception_code = STATUS_ACCESS_VIOLATION;
    const target_frame: u64 = sp + 8;
    const target_ip: u64 = base + 0x1F00;
    g_unwind_count = 0;
    unwindToTarget(&ctx, target_frame, target_ip, &record, 0x1234);

    try std.testing.expectEqual(@as(usize, 2), g_unwind_count);
    try std.testing.expectEqual(sp, g_unwind_order[0]);
    try std.testing.expectEqual(sp + 8, g_unwind_order[1]);
    try std.testing.expect(g_unwind_flags[0] & EXCEPTION_UNWINDING != 0);
    try std.testing.expect(g_unwind_flags[0] & EXCEPTION_TARGET_UNWIND == 0);
    try std.testing.expect(g_unwind_flags[1] & EXCEPTION_UNWINDING != 0);
    try std.testing.expect(g_unwind_flags[1] & EXCEPTION_TARGET_UNWIND != 0);
    try std.testing.expectEqual(target_ip, ctx.rip);
    try std.testing.expectEqual(target_frame, ctx.rsp);
    try std.testing.expectEqual(@as(u64, 0x1234), ctx.rax);
}
