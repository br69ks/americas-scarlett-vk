//! Policy for generated IAT fallback stubs.
//!
//! The generated stubs have no ABI signature, so returning 0 (success) is
//! unsafe: callers proceed with unwritten out-parameters.  By default an
//! unimplemented API therefore terminates the process with a clear message.
//! `SCARLETT_STUB_POLICY=zero` restores the old diagnostic behaviour for
//! debugging a specific path.

const std = @import("std");

fn isBenign(name: []const u8) bool {
    const benign = [_][]const u8{
        "_set_new_mode",
        "_set_invalid_parameter_handler",
        "SetProcessPriorityBoost",
        "GetProcessPriorityBoost",
        "SetThreadPriority",
        "GetThreadPriority",
        "GetSystemTimePreciseAsFileTime",
        "SetThreadDescription",
        "GetThreadDescription",
    };
    for (benign) |b| {
        if (std.mem.eql(u8, name, b)) return true;
    }
    // Formatting-only CRT exports are frequently optional; the engine has its
    // own logging path when these fail.
    return std.mem.startsWith(u8, name, "__stdio_common_");
}

fn zeroMode() bool {
    const value = std.c.getenv("SCARLETT_STUB_POLICY") orelse return false;
    return std.mem.eql(u8, std.mem.span(value), "zero");
}

pub fn missing(dll: []const u8, name: []const u8) usize {
    if (isBenign(name) or zeroMode()) {
        return 0;
    }
    std.log.err(
        "[STUB] unimplemented {s}!{s}; aborting. Set SCARLETT_STUB_POLICY=zero to continue with a zero return.",
        .{ dll, name },
    );
    std.process.exit(90);
}
