//! Async-signal-safe crash reporting and guest exception translation.
//!
//! A fault whose RIP is inside a loaded guest image is no longer a loader
//! crash: it becomes a Windows exception (`STATUS_ACCESS_VIOLATION`,
//! `STATUS_ILLEGAL_INSTRUCTION`, `STATUS_*_DIVIDE_BY_ZERO`,
//! `STATUS_STACK_OVERFLOW`, `STATUS_BREAKPOINT`, ...) and is dispatched through
//! the guest SEH machinery in ../seh.zig (VEH, `.pdata` handlers, RtlUnwindEx).
//! Faults in the loader itself keep the register/stack diagnostics.
//!
//! The handler must not take locks or allocate: image lookups are lock-free,
//! the unwinder uses a fixed stack buffer, and all messages use raw write(2).

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const teb = @import("teb.zig");
const module = @import("module.zig");
const seh = @import("seh.zig");

comptime {
    if (builtin.os.tag != .linux) @compileError("signals_linux is Linux-only");
}

/// Guest image range, used to turn a host RIP into a PE RVA in diagnostics.
pub var image_base: usize = 0;
pub var image_size: usize = 0;

const PROT_READ: i32 = 0x1;
const PROT_WRITE: i32 = 0x2;
const MAP_PRIVATE: i32 = 0x02;
const MAP_ANONYMOUS: i32 = 0x20;
const SIG_UNBLOCK: u32 = 1;

const Stack = extern struct {
    sp: u64,
    flags: i32,
    _pad: i32 = 0,
    size: u64,
};

/// glibc x86_64 `ucontext_t` prefix.  `mcontext.gregs` starts at 0x28 and uses
/// the Linux `REG_*` ordering (R8..R15, RDI, RSI, RBP, RBX, RDX, RAX, RCX, RSP,
/// RIP, EFL, CSGSFS, ERR, TRAPNO, OLDMASK, CR2).
const UContext = extern struct {
    flags: u64,
    link: ?*UContext,
    stack: Stack,
    mcontext: extern struct {
        gregs: [23]u64,
        fpregs: ?*anyopaque,
        _reserved: [8]u64,
    },
    sigmask: [16]u64,
};

comptime {
    std.debug.assert(@offsetOf(UContext, "mcontext") == 0x28);
    std.debug.assert(@offsetOf(UContext, "mcontext") + 16 * 8 == 0xA8);
}

const REG_R8 = 0;
const REG_R9 = 1;
const REG_R10 = 2;
const REG_R11 = 3;
const REG_R12 = 4;
const REG_R13 = 5;
const REG_R14 = 6;
const REG_R15 = 7;
const REG_RDI = 8;
const REG_RSI = 9;
const REG_RBP = 10;
const REG_RBX = 11;
const REG_RDX = 12;
const REG_RAX = 13;
const REG_RCX = 14;
const REG_RSP = 15;
const REG_RIP = 16;
const REG_EFL = 17;
const REG_CSGSFS = 18;

fn writeAll(bytes: []const u8) void {
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = linux.write(2, bytes.ptr + off, bytes.len - off);
        const signed: isize = @bitCast(rc);
        if (signed == -4) continue;
        if (signed <= 0) return;
        off += rc;
    }
}

fn writeFmt(buf: []u8, comptime fmt: []const u8, args: anytype) void {
    const text = std.fmt.bufPrint(buf, fmt, args) catch return;
    writeAll(text);
}

fn inImage(addr: usize) bool {
    return image_base != 0 and addr >= image_base and addr < image_base + image_size;
}

fn inGuestCode(addr: usize) bool {
    return module.findImageInfo(addr) != null;
}

fn signalName(sig: u32) []const u8 {
    return switch (sig) {
        4 => "SIGILL",
        5 => "SIGTRAP",
        7 => "SIGBUS",
        8 => "SIGFPE",
        11 => "SIGSEGV",
        else => "signal",
    };
}

fn dumpContext(buf: []u8, uc: *const UContext) void {
    const g = &uc.mcontext.gregs;
    const rip: usize = @intCast(g[REG_RIP]);
    const rsp: usize = @intCast(g[REG_RSP]);
    if (inImage(rip)) {
        writeFmt(buf, "  RIP=0x{x} (RVA=0x{x}) RSP=0x{x}\n", .{ rip, rip - image_base, rsp });
    } else {
        writeFmt(buf, "  RIP=0x{x} (outside image) RSP=0x{x}\n", .{ rip, rsp });
    }
    writeFmt(buf, "  RAX=0x{x} RBX=0x{x} RCX=0x{x} RDX=0x{x}\n", .{
        g[REG_RAX], g[REG_RBX], g[REG_RCX], g[REG_RDX],
    });
    writeFmt(buf, "  RSI=0x{x} RDI=0x{x} RBP=0x{x}\n", .{
        g[REG_RSI], g[REG_RDI], g[REG_RBP],
    });
    writeFmt(buf, "  R8=0x{x} R9=0x{x} R10=0x{x} R11=0x{x}\n", .{
        g[REG_R8], g[REG_R9], g[REG_R10], g[REG_R11],
    });
    writeFmt(buf, "  R12=0x{x} R13=0x{x} R14=0x{x} R15=0x{x}\n", .{
        g[REG_R12], g[REG_R13], g[REG_R14], g[REG_R15],
    });

    const stack: [*]const usize = @ptrFromInt(rsp);
    var i: usize = 0;
    while (i < 24) : (i += 1) {
        const value = stack[i];
        if (value >= 0x10000 and value < 0x8000_0000_0000) {
            writeFmt(buf, "  [rsp+0x{x}] = 0x{x}\n", .{ i * 8, value });
        }
    }

    // Best-effort ASCII runs on the current stack.  The failing guest path is
    // usually built into a stack buffer immediately before the assert.
    const bytes: [*]const u8 = @ptrFromInt(rsp);
    var start: ?usize = null;
    var j: usize = 0;
    while (j < 1024) : (j += 1) {
        const ch = bytes[j];
        const printable = ch >= 0x20 and ch < 0x7f;
        if (printable) {
            if (start == null) start = j;
        } else if (start) |s| {
            if (j - s >= 4) {
                writeFmt(buf, "  str[rsp+0x{x}]: {s}\n", .{ s, bytes[s..@min(j, s + 120)] });
            }
            start = null;
        }
    }
}

fn hostFailure(sig: linux.SIG, info: *const linux.siginfo_t, uc: *const UContext) noreturn {
    var buf: [1024]u8 = undefined;
    writeFmt(&buf, "\n[FATAL] {s} (signal {d}) in host/loader code\n", .{
        signalName(@intFromEnum(sig)), @intFromEnum(sig),
    });
    dumpContext(&buf, uc);
    writeFmt(&buf, "  fault_addr=0x{x}\n", .{@intFromPtr(info.fields.sigfault.addr)});
    writeAll("[FATAL] aborting; stack contents are not trusted\n");
    linux.exit_group(128 + @as(i32, @intCast(@as(u8, @truncate(@intFromEnum(sig))))));
}

fn readU32(p: [*]const u8, off: usize) u32 {
    return std.mem.readInt(u32, p[off..][0..4], .little);
}

/// Build a Windows CONTEXT from the Linux signal frame.
fn contextFromUContext(uc: *const UContext) seh.Context {
    const g = &uc.mcontext.gregs;
    var ctx = seh.Context{};
    ctx.rax = g[REG_RAX];
    ctx.rcx = g[REG_RCX];
    ctx.rdx = g[REG_RDX];
    ctx.rbx = g[REG_RBX];
    ctx.rsp = g[REG_RSP];
    ctx.rbp = g[REG_RBP];
    ctx.rsi = g[REG_RSI];
    ctx.rdi = g[REG_RDI];
    ctx.r8 = g[REG_R8];
    ctx.r9 = g[REG_R9];
    ctx.r10 = g[REG_R10];
    ctx.r11 = g[REG_R11];
    ctx.r12 = g[REG_R12];
    ctx.r13 = g[REG_R13];
    ctx.r14 = g[REG_R14];
    ctx.r15 = g[REG_R15];
    ctx.rip = g[REG_RIP];
    ctx.eflags = @truncate(g[REG_EFL]);
    ctx.seg_cs = @truncate(g[REG_CSGSFS]);
    ctx.context_flags = seh.CONTEXT_FULL;
    if (uc.mcontext.fpregs) |fp| {
        // The kernel's fpstate is the legacy FXSAVE layout, which is exactly
        // CONTEXT.FltSave (Xmm0-15 at FltSave+0xA0 == CONTEXT+0x1A0), so the
        // whole 512-byte area can be carried over and later `fxrstor`ed.
        const base: [*]const u8 = @ptrCast(fp);
        ctx.mx_csr = readU32(base, 0x18);
        const fpu: *const [0x200]u8 = @ptrCast(base);
        @memcpy(std.mem.asBytes(&ctx._flt_head), fpu[0..0xA0]);
        const xmm_bytes: *const [0x100]u8 = @ptrCast(base + 0xA0);
        @memcpy(std.mem.asBytes(&ctx.xmm), xmm_bytes);
        const tail: *const [0x60]u8 = @ptrCast(base + 0x1A0);
        @memcpy(std.mem.asBytes(&ctx._flt_tail), tail);
    }
    return ctx;
}

fn stackOverflow(fault: usize, rsp: u64) bool {
    const limit = seh.stackLimit();
    if (limit == 0) return false;
    const near_limit = fault + 0x100000 >= limit and fault < limit + 0x1000;
    if (!near_limit) return false;
    return rsp <= limit + 0x40000;
}

const Translated = struct {
    code: u32,
    parameters: [2]u64 = .{ 0, 0 },
    count: u32 = 0,
};

fn translate(sig: linux.SIG, info: *const linux.siginfo_t, ctx: *const seh.Context) Translated {
    const fault: u64 = @intFromPtr(info.fields.sigfault.addr);
    const rsp = ctx.rsp;
    switch (sig) {
        .SEGV => {
            if (stackOverflow(@intCast(fault), rsp)) {
                return .{ .code = seh.STATUS_STACK_OVERFLOW, .parameters = .{ 0, fault }, .count = 2 };
            }
            const code: u32 = switch (info.code) {
                1 => seh.STATUS_IN_PAGE_ERROR, // SEGV_MAPERR: not mapped at all
                else => seh.STATUS_ACCESS_VIOLATION,
            };
            return .{ .code = code, .parameters = .{ 0, fault }, .count = 2 };
        },
        .ILL => {
            const code: u32 = switch (info.code) {
                5 => seh.STATUS_PRIVILEGED_INSTRUCTION, // ILL_PRVOPC
                else => seh.STATUS_ILLEGAL_INSTRUCTION,
            };
            return .{ .code = code, .parameters = .{ 0, 0 }, .count = 0 };
        },
        .FPE => {
            const code: u32 = switch (info.code) {
                1 => seh.STATUS_INTEGER_DIVIDE_BY_ZERO,
                2 => seh.STATUS_INTEGER_OVERFLOW,
                3 => seh.STATUS_FLOAT_DIVIDE_BY_ZERO,
                4 => seh.STATUS_FLOAT_OVERFLOW,
                5 => seh.STATUS_FLOAT_UNDERFLOW,
                6 => seh.STATUS_FLOAT_INEXACT_RESULT,
                7 => seh.STATUS_FLOAT_INVALID_OPERATION,
                8 => seh.STATUS_FLOAT_STACK_CHECK,
                else => seh.STATUS_FLOAT_INVALID_OPERATION,
            };
            return .{ .code = code, .parameters = .{ 0, 0 }, .count = 0 };
        },
        .BUS => {
            const code: u32 = if (info.code == 1) seh.STATUS_DATATYPE_MISALIGNMENT else seh.STATUS_ACCESS_VIOLATION;
            return .{ .code = code, .parameters = .{ 0, fault }, .count = 2 };
        },
        else => return .{ .code = seh.STATUS_BREAKPOINT, .parameters = .{ 0, 0 }, .count = 0 },
    }
}

fn unblockSignal(sig: linux.SIG) void {
    var set: linux.sigset_t = .{0};
    const bit: u6 = @intCast(@intFromEnum(sig) - 1);
    set[0] |= @as(@TypeOf(set[0]), 1) << bit;
    _ = linux.sigprocmask(SIG_UNBLOCK, &set, null);
}

fn guestHandler(sig: linux.SIG, info: *const linux.siginfo_t, uc: *const UContext) noreturn {
    var ctx = contextFromUContext(uc);

    var record = std.mem.zeroes(seh.ExceptionRecord);
    record.exception_address = ctx.rip;

    var int3_addr: usize = 0;
    if (sig == .TRAP) {
        // Linux delivers #BP with RIP pointing past the one-byte int3.
        const after: usize = @intCast(ctx.rip);
        const candidate = after -% 1;
        const is_int3 = inGuestCode(candidate) and
            @as(*const u8, @ptrFromInt(candidate)).* == 0xCC;
        if (is_int3) {
            int3_addr = candidate;
            record.exception_code = seh.STATUS_BREAKPOINT;
            record.exception_address = int3_addr;
        } else {
            record.exception_code = seh.STATUS_SINGLE_STEP;
        }
    } else {
        const t = translate(sig, info, &ctx);
        record.exception_code = t.code;
        record.number_parameters = t.count;
        record.exception_information[0] = t.parameters[0];
        record.exception_information[1] = t.parameters[1];
    }

    // A handled guest exception leaves through restoreAndJump (or RtlUnwindEx)
    // rather than sigreturn, so the kernel would keep this signal blocked for
    // the rest of the thread's life.  Unblock it before entering guest code.
    unblockSignal(sig);

    if (seh.dispatchException(&record, &ctx)) {
        // A handler asked to continue execution (context may have been fixed).
        seh.continueExecution(&ctx);
    }
    _ = seh.callUnhandledFilter(&record, &ctx);

    var buf: [1024]u8 = undefined;
    if (record.exception_code == seh.STATUS_BREAKPOINT) {
        writeFmt(&buf, "\n[FATAL] guest breakpoint (int3) at 0x{x} (RVA=0x{x})\n", .{
            int3_addr, int3_addr -% image_base,
        });
        writeAll("[FATAL] This is the engine's own assert/break path. It is not patched.\n");
    } else {
        writeFmt(&buf, "\n[FATAL] unhandled guest exception 0x{x} ({s}, signal {d})\n", .{
            record.exception_code, signalName(@intFromEnum(sig)), @intFromEnum(sig),
        });
    }
    dumpContext(&buf, uc);
    writeFmt(&buf, "  fault_addr=0x{x}\n", .{@intFromPtr(info.fields.sigfault.addr)});
    writeAll("[FATAL] aborting; stack contents are not trusted\n");
    linux.exit_group(128 + @as(i32, @intCast(@as(u8, @truncate(@intFromEnum(sig))))));
}

fn handler(sig: linux.SIG, info: *const linux.siginfo_t, uctx: ?*anyopaque) callconv(.c) void {
    const ucp = uctx orelse {
        writeAll("\n[FATAL] signal without a ucontext\n");
        linux.exit_group(133);
    };
    const uc: *const UContext = @ptrCast(@alignCast(ucp));
    const rip: usize = @intCast(uc.mcontext.gregs[REG_RIP]);

    if (!inGuestCode(rip)) {
        // A guest int3 is reported with RIP one byte past the instruction.
        if (sig == .TRAP and inGuestCode(rip -% 1)) {
            guestHandler(sig, info, uc);
        }
        hostFailure(sig, info, uc);
    }
    guestHandler(sig, info, uc);
}

pub fn setImage(base: usize, size: usize) void {
    image_base = base;
    image_size = size;
}

// ---------------------------------------------------------------------------
// Alternate signal stack (per thread)
// ---------------------------------------------------------------------------

const ALT_STACK_SIZE = 128 * 1024;
threadlocal var g_alt_stack: ?[]u8 = null;

/// Install an alternate stack on the calling thread so a stack overflow can
/// still be translated (the handler would otherwise run on the exhausted
/// stack).  Called for the main thread by install() and for every guest thread
/// through `teb.thread_init_hook`.
pub fn installForThread() void {
    if (g_alt_stack != null) return;
    const mem = std.heap.page_allocator.alignedAlloc(u8, comptime std.mem.Alignment.fromByteUnits(16), ALT_STACK_SIZE) catch return;
    var ss = linux.stack_t{ .sp = mem.ptr, .flags = 0, .size = mem.len };
    if (linux.sigaltstack(&ss, null) != 0) return;
    g_alt_stack = mem;
}

pub fn install() void {
    installForThread();
    teb.thread_init_hook = &installForThread;

    var act = linux.Sigaction{
        .handler = .{ .sigaction = &handler },
        .mask = std.mem.zeroes(linux.sigset_t),
        .flags = linux.SA.SIGINFO | linux.SA.ONSTACK,
    };

    inline for ([_]linux.SIG{ .TRAP, .SEGV, .BUS, .ILL, .FPE }) |sig| {
        const rc = linux.sigaction(sig, &act, null);
        if (rc != 0) {
            var buf: [128]u8 = undefined;
            writeFmt(&buf, "[warn] sigaction({d}) failed: {d}\n", .{ @intFromEnum(sig), rc });
        }
    }
}
