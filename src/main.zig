const std = @import("std");
const builtin = @import("builtin");
const teb = @import("teb.zig");
const loader = @import("loader.zig");
const audio_register = @import("shims/audio_register.zig");
const win32_fs = @import("shims/win32_fs.zig");

const signals = if (builtin.os.tag == .linux) @import("signals_linux.zig") else struct {
    pub fn install() void {}
    pub fn setImage(_: usize, _: usize) void {}
};
const crash_windows = if (builtin.os.tag == .windows) @import("crash_windows.zig") else struct {
    pub fn install() void {}
};

const WinEntryFn = *const fn () callconv(.{ .x86_64_win = .{} }) i32;

const Options = struct {
    exe_path: []const u8 = "game_scarlett_master.exe",
    game_dir: ?[]const u8 = null,
    args: []const []const u8 = &.{},
};

fn parseOptions(allocator: std.mem.Allocator, raw: []const []const u8, env: *std.process.Environ.Map) !Options {
    var opts = Options{};
    var positional = std.array_list.Managed([]const u8).init(allocator);
    errdefer positional.deinit();

    var i: usize = 0;
    while (i < raw.len) : (i += 1) {
        const a = raw[i];
        if (std.mem.eql(u8, a, "--game-dir")) {
            i += 1;
            if (i >= raw.len) return error.MissingGameDir;
            opts.game_dir = raw[i];
        } else if (std.mem.startsWith(u8, a, "--game-dir=")) {
            opts.game_dir = a["--game-dir=".len..];
        } else if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) {
            return error.HelpRequested;
        } else {
            try positional.append(a);
        }
    }

    if (positional.items.len > 0) {
        opts.exe_path = positional.items[0];
        opts.args = try allocator.dupe([]const u8, positional.items[1..]);
    }
    if (opts.game_dir == null) {
        if (env.get("SCARLETT_GAME_DIR")) |dir| opts.game_dir = dir;
    }
    return opts;
}

pub fn main(init: std.process.Init) !void {
    crash_windows.install();
    const allocator = init.gpa;
    const io = init.io;

    var raw_args = std.array_list.Managed([]const u8).init(allocator);
    defer raw_args.deinit();
    var arg_it = try init.minimal.args.iterateAllocator(allocator);
    defer arg_it.deinit();
    _ = arg_it.skip();
    while (arg_it.next()) |a| try raw_args.append(a);

    const opts = parseOptions(allocator, raw_args.items, init.environ_map) catch |err| {
        if (err == error.HelpRequested) {
            std.log.info("usage: americas-loader [--game-dir DIR] <game.exe> [game args...]", .{});
            return;
        }
        return err;
    };

    const exe_abs = try std.fs.path.resolveAlloc(allocator, &.{opts.exe_path});
    const game_dir_input = opts.game_dir orelse std.fs.path.dirname(exe_abs) orelse ".";
    const game_dir = try std.fs.path.resolveAlloc(allocator, &.{game_dir_input});
    const save_dir = if (init.environ_map.get("SCARLETT_SAVE_DIR")) |dir|
        try allocator.dupe(u8, dir)
    else if (init.environ_map.get("XDG_DATA_HOME")) |base|
        try std.fmt.allocPrint(allocator, "{s}/americas-scarlett", .{base})
    else if (init.environ_map.get("HOME")) |home|
        try std.fmt.allocPrint(allocator, "{s}/.local/share/americas-scarlett", .{home})
    else
        try std.fs.path.join(allocator, &.{ game_dir, "saves" });

    std.log.info("Loading Scarlett PE image: {s} (game dir {s}, save dir {s})", .{ exe_abs, game_dir, save_dir });

    const virtual_game_dir = "G:\\";
    const virtual_exe = try std.fmt.allocPrint(allocator, "G:\\{s}", .{std.fs.path.basename(exe_abs)});
    var game_argv = std.array_list.Managed([]const u8).init(allocator);
    defer game_argv.deinit();
    try game_argv.append(virtual_exe);
    try game_argv.appendSlice(opts.args);

    // Process/TEB/PEB must exist before modules are registered.
    _ = try teb.initProcess(allocator, io, virtual_exe, game_argv.items, init.environ_map, virtual_game_dir, "G:\\");
    win32_fs.init(game_dir, save_dir);
    const audio_dir = try std.fmt.allocPrint(allocator, "{s}/.scarlett/audio", .{game_dir});
    win32_fs.setAudioDir(audio_dir);
    const meta_path = try std.fmt.allocPrint(allocator, "{s}/Core.Metadata.rpf", .{audio_dir});
    if (std.Io.Dir.cwd().readFileAlloc(io, meta_path, allocator, .limited(32 * 1024 * 1024))) |meta| {
        audio_register.init(meta, ".scarlett/audio/Core.Metadata.rpf");
        std.log.info("[AUDIO] loaded real Core.Metadata.rpf: {d} bytes", .{meta.len});
    } else |err| {
        std.log.warn("[AUDIO] no real Core.Metadata.rpf at {s}: {s}", .{ meta_path, @errorName(err) });
    }

    const search_dirs = [_][]const u8{ game_dir, std.fs.path.dirname(exe_abs) orelse game_dir };
    loader.init(allocator, io, &search_dirs);
    if (std.c.getenv("SCARLETT_NO_SIGNALS") == null) signals.install();

    var loaded = try loader.loadExecutable(allocator, io, exe_abs, virtual_exe);
    defer loaded.image.deinit();
    signals.setImage(loaded.image.base_addr, loaded.image.image_size);

    std.log.info("Image mapped at 0x{x}, entry point 0x{x}; TEB=0x{x}", .{
        loaded.image.base_addr,
        loaded.image.entry_point,
        @intFromPtr(teb.currentTeb().?),
    });

    const entry_fn: WinEntryFn = @ptrFromInt(loaded.image.entry_point);
    loader.refreshGuestTls();
    if (builtin.os.tag == .windows) {
        if (teb.process()) |proc| {
            std.log.info("[GS] wrgsbase test -> 0x{x} (synthetic=0x{x})", .{
                teb.testGsBase(@intFromPtr(proc.teb_ptr)), @intFromPtr(proc.teb_ptr),
            });
        }
    }
    const idx_mem: *u32 = @ptrFromInt(loaded.image.tls_index_va);
    std.log.info("[TLS] pre-entry idx_mem={d} mod_index={d} slot=0x{x}", .{
        idx_mem.*, loaded.mod.tls_index, teb.tlsGet(idx_mem.*),
    });
    std.log.info("[ENTRY] calling 0x{x}", .{loaded.image.entry_point});
    teb.forceGuest();
    const exit_code = entry_fn();
    teb.leaveGuest();
    std.log.info("[ENTRY] returned {d}", .{exit_code});
    loader.processDetach();
    std.log.info("Game exited with code: {d}", .{exit_code});
}

fn winLog(comptime level: std.log.Level, comptime scope: @EnumLiteral(), comptime format: []const u8, args: anytype) void {
    _ = level;
    _ = scope;
    if (builtin.os.tag != .windows) return;
    var buf: [1024]u8 = undefined;
    const text = std.fmt.bufPrint(&buf, format, args) catch return;
    const k32 = struct {
        extern "kernel32" fn GetStdHandle(id: u32) callconv(.winapi) ?*anyopaque;
        extern "kernel32" fn WriteFile(h: ?*anyopaque, p: ?*const anyopaque, n: u32, done: *u32, ov: ?*anyopaque) callconv(.winapi) i32;
    };
    const guest = if (teb.process()) |p| @intFromPtr(p.teb_ptr) else 0;
    const cur = teb.readGsBase();
    var host: usize = 0;
    if (guest != 0 and cur == guest) {
        host = @as(*const usize, @ptrFromInt(guest + 0x1FF8)).*;
        if (host >= 0x10000) asm volatile ("wrgsbase %[base]"
            :
            : [base] "r" (host),
        );
    }
    const h = k32.GetStdHandle(0xFFFFFFF4); // STD_ERROR_HANDLE
    var done: u32 = 0;
    _ = k32.WriteFile(h, text.ptr, @intCast(text.len), &done, null);
    if (host >= 0x10000) asm volatile ("wrgsbase %[base]"
        :
        : [base] "r" (guest),
    );
}

pub const std_options: std.Options = if (builtin.os.tag == .windows) .{ .logFn = winLog } else .{ .log_level = .info };
