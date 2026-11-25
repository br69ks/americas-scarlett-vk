const std = @import("std");
const builtin = @import("builtin");
const teb = @import("teb.zig");
const loader = @import("loader.zig");
const win32_fs = @import("shims/win32_fs.zig");

const signals = if (builtin.os.tag == .linux) @import("signals_linux.zig") else struct {
    pub fn install() void {}
    pub fn setImage(_: usize, _: usize) void {}
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

    var game_argv = std.array_list.Managed([]const u8).init(allocator);
    defer game_argv.deinit();
    try game_argv.append(exe_abs);
    try game_argv.appendSlice(opts.args);

    // Process/TEB/PEB must exist before modules are registered.
    _ = try teb.initProcess(allocator, io, exe_abs, game_argv.items, init.environ_map, game_dir);
    win32_fs.init(game_dir, save_dir);

    const search_dirs = [_][]const u8{ game_dir, std.fs.path.dirname(exe_abs) orelse game_dir };
    loader.init(allocator, io, &search_dirs);
    signals.install();

    var loaded = try loader.loadExecutable(allocator, io, exe_abs);
    defer loaded.image.deinit();
    signals.setImage(loaded.image.base_addr, loaded.image.image_size);

    if (builtin.os.tag == .linux) {
        const limits = std.Io.Dir.cwd().readFileAlloc(io, "/proc/self/limits", allocator, .limited(4096)) catch null;
        if (limits) |text| {
            var it = std.mem.splitScalar(u8, text, '\n');
            while (it.next()) |line| {
                if (std.mem.startsWith(u8, line, "Max address space") or
                    std.mem.startsWith(u8, line, "Max stack size"))
                {
                    std.log.info("[LIMIT] {s}", .{line});
                }
            }
            allocator.free(text);
        }
        const status = std.Io.Dir.cwd().readFileAlloc(io, "/proc/self/status", allocator, .limited(8192)) catch null;
        if (status) |text| {
            var it = std.mem.splitScalar(u8, text, '\n');
            while (it.next()) |line| {
                if (std.mem.startsWith(u8, line, "VmSize:") or
                    std.mem.startsWith(u8, line, "VmRSS:") or
                    std.mem.startsWith(u8, line, "Threads:"))
                {
                    std.log.info("[MEM] {s}", .{line});
                }
            }
            allocator.free(text);
        }
    }

    std.log.info("Image mapped at 0x{x}, entry point 0x{x}; TEB=0x{x}", .{
        loaded.image.base_addr,
        loaded.image.entry_point,
        @intFromPtr(teb.currentTeb().?),
    });

    const entry_fn: WinEntryFn = @ptrFromInt(loaded.image.entry_point);
    const exit_code = entry_fn();
    loader.processDetach();
    std.log.info("Game exited with code: {d}", .{exit_code});
}
