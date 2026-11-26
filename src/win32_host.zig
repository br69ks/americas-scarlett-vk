//! Real Windows kernel32 file calls for the Windows backend.
//! Paths are already translated by win32_fs; this module only wraps the host.

const std = @import("std");
const builtin = @import("builtin");

const INVALID: usize = std.math.maxInt(usize);

extern "kernel32" fn CreateFileW(
    name: [*:0]const u16,
    access: u32,
    share: u32,
    security: ?*anyopaque,
    disposition: u32,
    flags: u32,
    template: usize,
) callconv(.winapi) usize;
extern "kernel32" fn ReadFile(handle: usize, buffer: [*]u8, len: u32, read: ?*u32, overlapped: ?*anyopaque) callconv(.winapi) i32;
extern "kernel32" fn WriteFile(handle: usize, buffer: [*]const u8, len: u32, written: ?*u32, overlapped: ?*anyopaque) callconv(.winapi) i32;
extern "kernel32" fn GetFileSizeEx(handle: usize, size: *i64) callconv(.winapi) i32;
extern "kernel32" fn SetFilePointerEx(handle: usize, distance: i64, new_pos: ?*i64, method: u32) callconv(.winapi) i32;
extern "kernel32" fn SetEndOfFile(handle: usize) callconv(.winapi) i32;
extern "kernel32" fn FlushFileBuffers(handle: usize) callconv(.winapi) i32;
extern "kernel32" fn CloseHandle(handle: usize) callconv(.winapi) i32;
extern "kernel32" fn GetFileInformationByHandle(handle: usize, info: *anyopaque) callconv(.winapi) i32;
extern "kernel32" fn GetLastError() callconv(.winapi) u32;

fn wide(path: []const u8, out: *[2048]u16) ?[*:0]const u16 {
    if (path.len >= out.len - 1) return null;
    const n = std.unicode.utf8ToUtf16Le(out[0 .. out.len - 1], path) catch return null;
    out[n] = 0;
    return @ptrCast(out);
}

pub fn createFileW(path: []const u8, access: u32, share: u32, disposition: u32, flags: u32) usize {
    var buf: [2048]u16 = undefined;
    const name = wide(path, &buf) orelse return INVALID;
    return CreateFileW(name, access, share, null, disposition, flags, 0);
}

pub fn readFile(handle: usize, buffer: [*]u8, len: u32, read: ?*u32, overlapped: ?*anyopaque) i32 {
    return ReadFile(handle, buffer, len, read, overlapped);
}

pub fn writeFile(handle: usize, buffer: [*]const u8, len: u32, written: ?*u32, overlapped: ?*anyopaque) i32 {
    return WriteFile(handle, buffer, len, written, overlapped);
}

pub fn getFileSize(handle: usize) ?u64 {
    var size: i64 = 0;
    if (GetFileSizeEx(handle, &size) == 0) return null;
    return @intCast(size);
}

pub fn setFilePointer(handle: usize, distance: i64, method: u32) ?u64 {
    var pos: i64 = 0;
    if (SetFilePointerEx(handle, distance, &pos, method) == 0) return null;
    return @intCast(pos);
}

pub fn setEndOfFile(handle: usize) bool {
    return SetEndOfFile(handle) != 0;
}

pub fn flush(handle: usize) bool {
    return FlushFileBuffers(handle) != 0;
}

pub fn close(handle: usize) bool {
    return CloseHandle(handle) != 0;
}

pub fn fileInformation(handle: usize, out: *anyopaque) bool {
    return GetFileInformationByHandle(handle, out) != 0;
}

pub fn lastError() u32 {
    return GetLastError();
}

comptime {
    if (builtin.os.tag != .windows) {
        // The externs are harmless on Linux, but keep the intent explicit.
    }
}
