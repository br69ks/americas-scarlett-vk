//! D3D12 Xbox device API boundary.
//!
//! The loader has no D3D12-to-Vulkan backend yet.  The current development
//! milestone is *correctness up to the first `D3D12XboxCreateDevice` call*, so
//! that call is modelled as an explicit boundary: the loader reports the guest
//! call site and arguments and stops there.  Nothing past this point (device
//! objects, queues, swapchains, PSOs) is implemented or emulated.
//!
//! `D3D12XboxCreateDevice`'s parameters are intentionally not modelled, so the
//! four Win64 register arguments are reported raw.

const std = @import("std");
const module = @import("../module.zig");

const win: std.builtin.CallingConvention = .{ .x86_64_win = .{} };

/// Exit code used for a deliberate stop at the D3D12 boundary.
pub const EXIT_BOUNDARY: u8 = 0;

fn logBoundaryCaller(return_address: usize) void {
    if (module.findByAddress(return_address)) |m| {
        std.log.info("[BOUNDARY] caller {s}+0x{x}", .{ m.name, return_address - m.base });
    } else {
        std.log.info("[BOUNDARY] caller 0x{x}", .{return_address});
    }
}

/// Boundary stop for the first `D3D12XboxCreateDevice` call.
fn shim_D3D12XboxCreateDevice(
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
) callconv(win) usize {
    std.log.info("[BOUNDARY] D3D12XboxCreateDevice(rcx=0x{x}, rdx=0x{x}, r8=0x{x}, r9=0x{x})", .{
        arg0, arg1, arg2, arg3,
    });
    logBoundaryCaller(@returnAddress());
    std.log.info("[BOUNDARY] stopping before D3D12 device creation (no D3D12 implementation); exit code {d}", .{EXIT_BOUNDARY});
    std.process.exit(EXIT_BOUNDARY);
}

pub fn resolve(sym_name: []const u8) ?usize {
    if (std.mem.eql(u8, sym_name, "D3D12XboxCreateDevice")) {
        return @intFromPtr(&shim_D3D12XboxCreateDevice);
    }
    return null;
}
