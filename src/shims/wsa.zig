//! Minimal ws2_32 entry points needed for startup.  Network features are not
//! implemented; these only satisfy the Winsock initialization contract.

const std = @import("std");
const teb = @import("../teb.zig");

const win: std.builtin.CallingConvention = .{ .x86_64_win = .{} };

pub const WSADATA = extern struct {
    wVersion: u16 = 0,
    wHighVersion: u16 = 0,
    szDescription: [257]u8 = @splat(0),
    szSystemStatus: [129]u8 = @splat(0),
    iMaxSockets: u16 = 0,
    iMaxUdpDg: u16 = 0,
    lpVendorInfo: ?*anyopaque = null,
};

fn shim_WSAStartup(requested: u16, data: ?*WSADATA) callconv(win) i32 {
    _ = requested;
    if (data) |d| {
        d.* = .{};
        d.wVersion = 0x0202;
        d.wHighVersion = 0x0202;
        const desc = "Americas compatibility loader";
        @memcpy(d.szDescription[0..desc.len], desc);
        const status = "Running";
        @memcpy(d.szSystemStatus[0..status.len], status);
    }
    return 0;
}

fn shim_WSACleanup() callconv(win) i32 {
    return 0;
}

fn shim_WSAGetLastError() callconv(win) i32 {
    return @bitCast(teb.getLastError());
}

fn shim_WSASetLastError(err: i32) callconv(win) void {
    teb.setLastError(@bitCast(err));
}

pub fn resolveOrdinal(dll: []const u8, ordinal: u16) ?usize {
    if (!std.ascii.eqlIgnoreCase(dll, "ws2_32.dll")) return null;
    return switch (ordinal) {
        115 => @intFromPtr(&shim_WSAStartup),
        116 => @intFromPtr(&shim_WSACleanup),
        else => null,
    };
}

pub fn resolve(name: []const u8) ?usize {
    const map = .{
        .{ "WSAStartup", @intFromPtr(&shim_WSAStartup) },
        .{ "WSACleanup", @intFromPtr(&shim_WSACleanup) },
        .{ "WSAGetLastError", @intFromPtr(&shim_WSAGetLastError) },
        .{ "WSASetLastError", @intFromPtr(&shim_WSASetLastError) },
    };
    inline for (map) |entry| {
        if (std.mem.eql(u8, entry.@"0", name)) return entry.@"1";
    }
    return null;
}
