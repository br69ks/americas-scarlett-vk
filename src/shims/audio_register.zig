//! Register the real Core.Metadata RPF with the engine's native device
//! manager.  This uses the engine's own constructor; nothing is synthesized.

const std = @import("std");
const builtin = @import("builtin");

const MANAGER: usize = 0x1_4745_34f8;
const CREATE_DEVICE: usize = 0x1_40fc_20d0;
const HELPER_CALL: usize = 0x1_41df_7bc0;

extern "kernel32" fn VirtualProtect(lpAddress: ?*anyopaque, dwSize: usize, flNewProtect: u32, lpflOldProtect: *u32) callconv(.winapi) i32;

fn virtualProtect(p: [*]u8, n: usize, prot: u32, old: *u32) i32 {
    return VirtualProtect(@ptrCast(p), n, prot, old);
}

var g_rpf: ?[]const u8 = null;
var g_name: [512]u8 = undefined;
var g_name_len: usize = 0;
var g_done = false;
var g_attempted = false;

pub fn init(rpf: []const u8, host_path: []const u8) void {
    g_rpf = rpf;
    const n = @min(host_path.len, g_name.len - 1);
    for (host_path[0..n], 0..) |c, i| g_name[i] = c;
    g_name[n] = 0;
    g_name_len = n;
}

fn managerDevice() usize {
    const p: *const usize = @ptrFromInt(MANAGER + 8);
    return p.*;
}

fn text() []const u8 {
    return "Core.Metadata.rpf";
}


fn allocExec(size: usize) ?[]u8 {
    if (builtin.os.tag == .windows) {
        const k32 = struct {
            extern "kernel32" fn VirtualAlloc(?*anyopaque, usize, u32, u32) callconv(.winapi) ?*anyopaque;
        };
        const ptr = k32.VirtualAlloc(null, size, 0x3000, 0x40) orelse return null;
        return @as([*]u8, @ptrCast(ptr))[0..size];
    }
    const c = struct {
        extern "c" fn mmap(?*anyopaque, usize, i32, i32, i32, i64) ?*anyopaque;
    };
    const ptr = c.mmap(null, size, 0x7, 0x22, -1, 0) orelse return null;
    if (@intFromPtr(ptr) == std.math.maxInt(usize)) return null;
    return @as([*]u8, @ptrCast(ptr))[0..size];
}

fn allocExecAt(preferred: usize, size: usize) ?[]u8 {
    if (builtin.os.tag != .windows) return allocExec(size);
    const k32 = struct {
        extern "kernel32" fn VirtualAlloc(?*anyopaque, usize, u32, u32) callconv(.winapi) ?*anyopaque;
    };
    const ptr = k32.VirtualAlloc(@ptrFromInt(preferred), size, 0x3000, 0x40) orelse return null;
    return @as([*]u8, @ptrCast(ptr))[0..size];
}

fn patchText(addr: usize, bytes: []const u8) bool {
    if (builtin.os.tag == .windows) {
        const k32 = struct {
            extern "kernel32" fn VirtualProtect(?*anyopaque, usize, u32, *u32) callconv(.winapi) i32;
        };
        var old: u32 = 0;
        if (k32.VirtualProtect(@ptrFromInt(addr), bytes.len, 0x40, &old) == 0) return false;
        @memcpy(@as([*]u8, @ptrFromInt(addr))[0..bytes.len], bytes);
        var ignored: u32 = 0;
        _ = k32.VirtualProtect(@ptrFromInt(addr), bytes.len, old, &ignored);
        return true;
    }
    @memcpy(@as([*]u8, @ptrFromInt(addr))[0..bytes.len], bytes);
    return true;
}

/// Replace the helper's `CreateDevice(audio:/..., r8=0)` call with a call
/// to a guest stub that uses the real relative pack path.  This keeps the
/// engine's own constructor and runs it on the audio thread that calls the
/// helper, avoiding cross-thread registration races.



/// Called from a guest shim (guest GS is active).  Creates the engine's
/// native device for audio:/Core.Metadata.rpf with the real pack bytes.

pub var g_audio_tid: i32 = 0;
var g_mount_attempted: bool = false;
var g_mounted: bool = false;
var g_pack_obj: [0x20]u8 align(8) = std.mem.zeroes([0x20]u8);

pub fn noteAudioThread(entry: usize, os_tid: i32) void {
    if (entry == 0x1_455e_8b00) g_audio_tid = os_tid;
}

fn signalOtherThreads(sig: i32) void {
    if (builtin.os.tag != .linux) return;
    const c = struct {
        extern "c" fn getpid() i32;
        extern "c" fn gettid() i32;
        extern "c" fn tgkill(pid: i32, tid: i32, sig: i32) i32;
        extern "c" fn opendir(path: [*:0]const u8) ?*anyopaque;
        extern "c" fn readdir(dir: *anyopaque) ?*const DirEnt;
        extern "c" fn closedir(dir: *anyopaque) i32;
        const DirEnt = extern struct {
            d_ino: u64,
            d_off: i64,
            d_reclen: u16,
            d_type: u8,
            d_name: [256]u8,
        };
    };
    const self = c.gettid();
    const dir = c.opendir("/proc/self/task") orelse return;
    defer _ = c.closedir(dir);
    while (c.readdir(dir)) |ent| {
        const name = std.mem.sliceTo(&ent.d_name, 0);
        const tid = std.fmt.parseInt(i32, name, 10) catch continue;
        if (tid == self or tid == g_audio_tid) continue;
        _ = c.tgkill(c.getpid(), tid, sig); // SIGSTOP/SIGCONT
    }
}

fn pauseOtherThreads() void {
    signalOtherThreads(19);
}

fn resumeOtherThreads() void {
    signalOtherThreads(18);
}

pub fn mountAudioPack() bool {
    if (builtin.os.tag != .linux) return false;
    if (g_mount_attempted) return g_mounted;
    g_mount_attempted = true;
    const create_file = @as(*const fn ([*:0]const u8, u32) callconv(.{ .x86_64_win = .{} }) usize, @ptrFromInt(0x1_4096_8480));
    var path: [32]u8 = undefined;
    const n = @min("audio.rpf".len, path.len - 1);
    @memcpy(path[0..n], "audio.rpf"[0..n]);
    path[n] = 0;
    const fd = create_file(@ptrCast(&path), 1);
    if (fd == 0) {
        std.log.err("[AUDIO] audio.rpf file device creation failed", .{});
        return false;
    }
    std.mem.writeInt(u32, g_pack_obj[0..4], 0x52504639, .little); // 9FPR
    std.mem.writeInt(u64, g_pack_obj[0x18..0x20], fd, .little);
    const add = @as(*const fn (usize, [*:0]const u8, ?*anyopaque) callconv(.{ .x86_64_win = .{} }) void, @ptrFromInt(0x1_40fc_20d0));
    add(MANAGER, "audio.rpf", &g_pack_obj);
    var name: [8]u8 = undefined;
    @memcpy(name[0..7], "audio:/"[0..7]);
    name[7] = 0;
    const dev = managerDevice();
    g_mounted = dev != 0;
    const f38 = if (dev != 0) @as(*const usize, @ptrFromInt(dev + 0x38)).* else 0;
    const f40 = if (dev != 0) @as(*const usize, @ptrFromInt(dev + 0x40)).* else 0;
    if (dev != 0 and f38 != 0 and f40 > 8) {
        const name_ptr: [*]u8 = @ptrFromInt(f38);
        @memcpy(name_ptr[0..7], "audio:/");
        name_ptr[7] = 0;
        const readd = @as(*const fn (usize, usize) callconv(.{ .x86_64_win = .{} }) void, @ptrFromInt(0x1_455b_2550));
        const mgr = @as(*const usize, @ptrFromInt(0x1_498d_4b30)).*;
        if (mgr != 0) readd(mgr, dev);
    }
    std.log.err("[AUDIO] pack mount audio.rpf fd=0x{x} dev=0x{x} mounted={}", .{ fd, dev, g_mounted });
    return g_mounted;
}

pub fn tryRegisterIfReady() void {
    if (g_attempted) return;
    const ready = @as(*const u32, @ptrFromInt(0x1_498d_4b30)).*;
    if (ready != 0) tryRegister();
}

pub fn tryRegister() void {
    if (g_attempted) return;
    g_attempted = true;
    if (g_rpf == null) return;
    const f: *const fn (*anyopaque, [*:0]const u8, ?*anyopaque) callconv(.{ .x86_64_win = .{} }) void =
        @ptrFromInt(CREATE_DEVICE);
    f(@ptrFromInt(MANAGER), @as([*:0]const u8, @ptrCast(&g_name)), null);
    const dev = managerDevice();
    std.log.info("[AUDIO] native device registration: host path len={d} manager=0x{x} dev=0x{x}", .{ g_name_len, MANAGER, dev });
    if (dev != 0) {
        // The helper unconditionally calls the same constructor with a null
        // RPF, replacing our device.  Keep the native device by skipping that
        // one call; the helper then uses the manager entry we just made.
        const p: [*]u8 = @ptrFromInt(HELPER_CALL);
        if (builtin.os.tag == .windows) {
            var old_protect: u32 = 0;
            if (virtualProtect(p, 5, 0x40, &old_protect) != 0) {
                p[0] = 0x90; p[1] = 0x90; p[2] = 0x90; p[3] = 0x90; p[4] = 0x90;
                var ignored: u32 = 0;
                _ = virtualProtect(p, 5, old_protect, &ignored);
                g_done = true;
                std.log.info("[AUDIO] kept native device for {s}", .{text()});
            } else {
                std.log.err("[AUDIO] VirtualProtect failed for helper patch", .{});
            }
        } else {
            p[0] = 0x90; p[1] = 0x90; p[2] = 0x90; p[3] = 0x90; p[4] = 0x90;
            g_done = true;
            std.log.info("[AUDIO] kept native device for {s}", .{text()});
        }
    }
}
