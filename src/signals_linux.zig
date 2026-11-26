//! Async-signal-safe crash reporting for the Linux host.
//!
//! This replaces the previous "SIGTRAP means int3, so NOP it" behaviour.  A
//! breakpoint in the guest image is a real failure: report where it happened
//! and stop.  Nothing here uses the allocator, std.log, or any other lock.

const std = @import("std");
const builtin = @import("builtin");

comptime {
    if (builtin.os.tag != .linux) @compileError("signals_linux is Linux-only");
}

const linux = std.os.linux;

/// Guest image range, used to turn a host RIP into a PE RVA.
pub var image_base: usize = 0;
pub var image_size: usize = 0;

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

fn writeAll(bytes: []const u8) void {
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = linux.write(2, bytes.ptr + off, bytes.len - off);
        // EINTR (-4) means retry; anything else non-positive means give up.
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

fn dumpContext(buf: []u8, ctx: *const UContext) void {
    const g = &ctx.mcontext.gregs;
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
        const c = bytes[j];
        const printable = c >= 0x20 and c < 0x7f;
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

fn handler(sig: linux.SIG, info: *const linux.siginfo_t, uctx: ?*anyopaque) callconv(.c) void {
    var buf: [1024]u8 = undefined;
    const ctx: ?*const UContext = if (uctx) |p| @ptrCast(@alignCast(p)) else null;

    if (sig == .TRAP) {
        // Linux delivers #BP with RIP pointing *after* the one-byte int3.
        // The old handler patched the byte at RIP and then incremented RIP
        // again, skipping the first byte of the following instruction.
        var int3_addr: usize = 0;
        var is_int3 = false;
        if (ctx) |c| {
            const rip: usize = @intCast(c.mcontext.gregs[REG_RIP]);
            if (rip != 0) {
                int3_addr = rip - 1;
                is_int3 = inImage(int3_addr) and @as(*const u8, @ptrFromInt(int3_addr)).* == 0xCC;
            }
        }

        if (is_int3) {
            writeFmt(&buf, "\n[FATAL] guest breakpoint (int3) at 0x{x} (RVA=0x{x})\n", .{
                int3_addr, int3_addr - image_base,
            });
            writeAll("[FATAL] This is the engine's own assert/break path. It is not patched.\n");
        } else {
            writeAll("\n[FATAL] unexpected SIGTRAP outside a guest int3\n");
        }
        if (ctx) |c| dumpContext(&buf, c);
        linux.exit_group(133); // 128 + SIGTRAP
    }

    writeFmt(&buf, "\n[FATAL] {s} (signal {d})\n", .{ signalName(@intFromEnum(sig)), @intFromEnum(sig) });
    if (ctx) |c| dumpContext(&buf, c);
    writeFmt(&buf, "  fault_addr=0x{x}\n", .{@intFromPtr(info.fields.sigfault.addr)});
    writeAll("[FATAL] aborting; stack contents are not trusted\n");
    linux.exit_group(128 + @as(i32, @intCast(@as(u8, @truncate(@intFromEnum(sig))))));
}

pub fn setImage(base: usize, size: usize) void {
    image_base = base;
    image_size = size;
}

pub fn install() void {
    var act = linux.Sigaction{
        .handler = .{ .sigaction = &handler },
        .mask = std.mem.zeroes(linux.sigset_t),
        .flags = linux.SA.SIGINFO,
    };

    inline for ([_]linux.SIG{ .TRAP, .SEGV, .BUS, .ILL, .FPE }) |sig| {
        const rc = linux.sigaction(sig, &act, null);
        if (rc != 0) {
            var buf: [128]u8 = undefined;
            writeFmt(&buf, "[warn] sigaction({d}) failed: {d}\n", .{ @intFromEnum(sig), rc });
        }
    }
}
