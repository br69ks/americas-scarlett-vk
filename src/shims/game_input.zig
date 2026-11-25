const std = @import("std");
const builtin = @import("builtin");

pub const IGameInputVtbl = extern struct {
    // 0..2: IUnknown
    QueryInterface: *const fn (*IGameInput, ?*const anyopaque, *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32,
    AddRef: *const fn (*IGameInput) callconv(.{ .x86_64_win = .{} }) u32,
    Release: *const fn (*IGameInput) callconv(.{ .x86_64_win = .{} }) u32,
    // 3..7: Core reading queries
    GetCurrentTimestamp: *const fn (*IGameInput) callconv(.{ .x86_64_win = .{} }) u64,
    GetCurrentReading: *const fn (*IGameInput, u32, ?*anyopaque, *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32,
    GetNextReading: *const fn (*IGameInput, ?*anyopaque, u32, ?*anyopaque, *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32,
    GetPreviousReading: *const fn (*IGameInput, ?*anyopaque, u32, ?*anyopaque, *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32,
    GetTemporalReading: *const fn (*IGameInput, u64, ?*anyopaque, *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32,
    // 8..13: Callbacks
    RegisterReadingCallback: *const fn (*IGameInput, ?*anyopaque, u32, f32, ?*anyopaque, ?*anyopaque, ?*u64) callconv(.{ .x86_64_win = .{} }) i32,
    RegisterDeviceCallback: *const fn (*IGameInput, ?*anyopaque, u32, u32, u32, ?*anyopaque, ?*anyopaque, ?*u64) callconv(.{ .x86_64_win = .{} }) i32,
    RegisterGuideButtonCallback: *const fn (*IGameInput, ?*anyopaque, ?*anyopaque, ?*anyopaque, ?*u64) callconv(.{ .x86_64_win = .{} }) i32,
    RegisterKeyboardLayoutCallback: *const fn (*IGameInput, ?*anyopaque, ?*anyopaque, ?*anyopaque, ?*u64) callconv(.{ .x86_64_win = .{} }) i32,
    StopCallback: *const fn (*IGameInput, u64) callconv(.{ .x86_64_win = .{} }) void,
    UnregisterCallback: *const fn (*IGameInput, u64, u64) callconv(.{ .x86_64_win = .{} }) bool,
    // 14..21: Dispatcher & Device Management
    CreateDispatcher: *const fn (*IGameInput, *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32,
    CreateAggregateDevice: *const fn (*IGameInput, u32, *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32,
    FindDeviceFromId: *const fn (*IGameInput, ?*const anyopaque, *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32,
    FindDeviceFromObject: *const fn (*IGameInput, ?*anyopaque, *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32,
    FindDeviceFromPlatformHandle: *const fn (*IGameInput, usize, *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32,
    FindDeviceFromPlatformString: *const fn (*IGameInput, ?[*:0]const u16, *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32,
    EnableOemDeviceSupport: *const fn (*IGameInput, u16, u16, u8, u8) callconv(.{ .x86_64_win = .{} }) i32,
    SetFocusPolicy: *const fn (*IGameInput, u32) callconv(.{ .x86_64_win = .{} }) void,
};

pub const IGameInput = extern struct {
    lpVtbl: *const IGameInputVtbl,
};

fn gi_QueryInterface(self: *IGameInput, riid: ?*const anyopaque, ppv: *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32 {
    _ = riid;
    ppv.* = self;
    return 0;
}
fn gi_AddRef(_: *IGameInput) callconv(.{ .x86_64_win = .{} }) u32 {
    return 2;
}
fn gi_Release(_: *IGameInput) callconv(.{ .x86_64_win = .{} }) u32 {
    return 1;
}
fn gi_GetCurrentTimestamp(_: *IGameInput) callconv(.{ .x86_64_win = .{} }) u64 {
    if (builtin.os.tag == .linux) {
        var ts: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
        return @as(u64, @intCast(ts.sec)) * 1_000_000 + @as(u64, @intCast(@divTrunc(ts.nsec, 1000)));
    }
    return 1000;
}
fn gi_GetCurrentReading(_: *IGameInput, _: u32, _: ?*anyopaque, out_reading: *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32 {
    out_reading.* = null;
    return -2089877497; // GAMEINPUT_E_READING_NOT_FOUND (0x837A0007)
}
fn gi_GetNextReading(_: *IGameInput, _: ?*anyopaque, _: u32, _: ?*anyopaque, out_reading: *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32 {
    out_reading.* = null;
    return -2089877497;
}
fn gi_GetPreviousReading(_: *IGameInput, _: ?*anyopaque, _: u32, _: ?*anyopaque, out_reading: *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32 {
    out_reading.* = null;
    return -2089877497;
}
fn gi_GetTemporalReading(_: *IGameInput, _: u64, _: ?*anyopaque, out_reading: *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32 {
    out_reading.* = null;
    return -2089877497;
}
fn gi_RegisterReadingCallback(_: *IGameInput, _: ?*anyopaque, _: u32, _: f32, _: ?*anyopaque, _: ?*anyopaque, token: ?*u64) callconv(.{ .x86_64_win = .{} }) i32 {
    if (token) |t| t.* = 1;
    return 0;
}
fn gi_RegisterDeviceCallback(_: *IGameInput, _: ?*anyopaque, _: u32, _: u32, _: u32, _: ?*anyopaque, _: ?*anyopaque, token: ?*u64) callconv(.{ .x86_64_win = .{} }) i32 {
    if (token) |t| t.* = 2;
    return 0;
}
fn gi_RegisterGuideButtonCallback(_: *IGameInput, _: ?*anyopaque, _: ?*anyopaque, _: ?*anyopaque, token: ?*u64) callconv(.{ .x86_64_win = .{} }) i32 {
    if (token) |t| t.* = 3;
    return 0;
}
fn gi_RegisterKeyboardLayoutCallback(_: *IGameInput, _: ?*anyopaque, _: ?*anyopaque, _: ?*anyopaque, token: ?*u64) callconv(.{ .x86_64_win = .{} }) i32 {
    if (token) |t| t.* = 4;
    return 0;
}
fn gi_StopCallback(_: *IGameInput, _: u64) callconv(.{ .x86_64_win = .{} }) void {}
fn gi_UnregisterCallback(_: *IGameInput, _: u64, _: u64) callconv(.{ .x86_64_win = .{} }) bool {
    return true;
}
fn gi_CreateDispatcher(_: *IGameInput, out_disp: *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32 {
    out_disp.* = null;
    return -2147467262; // E_NOINTERFACE
}
fn gi_CreateAggregateDevice(_: *IGameInput, _: u32, out_dev: *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32 {
    out_dev.* = null;
    return -2147467262;
}
fn gi_FindDeviceFromId(_: *IGameInput, _: ?*const anyopaque, out_dev: *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32 {
    out_dev.* = null;
    return -2147467262;
}
fn gi_FindDeviceFromObject(_: *IGameInput, _: ?*anyopaque, out_dev: *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32 {
    out_dev.* = null;
    return -2147467262;
}
fn gi_FindDeviceFromPlatformHandle(_: *IGameInput, _: usize, out_dev: *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32 {
    out_dev.* = null;
    return -2147467262;
}
fn gi_FindDeviceFromPlatformString(_: *IGameInput, _: ?[*:0]const u16, out_dev: *?*anyopaque) callconv(.{ .x86_64_win = .{} }) i32 {
    out_dev.* = null;
    return -2147467262;
}
fn gi_EnableOemDeviceSupport(_: *IGameInput, _: u16, _: u16, _: u8, _: u8) callconv(.{ .x86_64_win = .{} }) i32 {
    return 0;
}
fn gi_SetFocusPolicy(_: *IGameInput, _: u32) callconv(.{ .x86_64_win = .{} }) void {}

const g_game_input_vtbl = IGameInputVtbl{
    .QueryInterface = &gi_QueryInterface,
    .AddRef = &gi_AddRef,
    .Release = &gi_Release,
    .GetCurrentTimestamp = &gi_GetCurrentTimestamp,
    .GetCurrentReading = &gi_GetCurrentReading,
    .GetNextReading = &gi_GetNextReading,
    .GetPreviousReading = &gi_GetPreviousReading,
    .GetTemporalReading = &gi_GetTemporalReading,
    .RegisterReadingCallback = &gi_RegisterReadingCallback,
    .RegisterDeviceCallback = &gi_RegisterDeviceCallback,
    .RegisterGuideButtonCallback = &gi_RegisterGuideButtonCallback,
    .RegisterKeyboardLayoutCallback = &gi_RegisterKeyboardLayoutCallback,
    .StopCallback = &gi_StopCallback,
    .UnregisterCallback = &gi_UnregisterCallback,
    .CreateDispatcher = &gi_CreateDispatcher,
    .CreateAggregateDevice = &gi_CreateAggregateDevice,
    .FindDeviceFromId = &gi_FindDeviceFromId,
    .FindDeviceFromObject = &gi_FindDeviceFromObject,
    .FindDeviceFromPlatformHandle = &gi_FindDeviceFromPlatformHandle,
    .FindDeviceFromPlatformString = &gi_FindDeviceFromPlatformString,
    .EnableOemDeviceSupport = &gi_EnableOemDeviceSupport,
    .SetFocusPolicy = &gi_SetFocusPolicy,
};

var g_game_input_instance = IGameInput{
    .lpVtbl = &g_game_input_vtbl,
};

pub fn shim_GameInputCreate(out_game_input: ?*?*IGameInput) callconv(.{ .x86_64_win = .{} }) i32 {
    std.log.info("[INPUT] GameInputCreate() -> S_OK (0x{x})", .{@intFromPtr(&g_game_input_instance)});
    if (out_game_input) |out| {
        out.* = &g_game_input_instance;
    }
    return 0; // S_OK
}
