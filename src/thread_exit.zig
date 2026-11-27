//! Per-thread exit semantics.
//!
//! `ExitThread`, `RtlExitUserThread`, `_endthreadex` and a normal return from a
//! guest thread entry all end *only* the calling thread: they run the
//! DLL_THREAD_DETACH notifications, the FLS destructors, publish the exit code
//! to `GetExitCodeThread`/waiters, and release the thread's guest TEB/TLS.
//! They never use `exit_group`; `ExitProcess`/`TerminateProcess` remain
//! process-wide.

const std = @import("std");
const builtin = @import("builtin");
const teb = @import("teb.zig");
const sync = @import("sync.zig");
const module = @import("module.zig");

/// Reference to this thread's `sync` handle object, acquired at thread start.
/// Publishing the exit code through this reference (rather than through the
/// guest handle value) cannot hit a handle slot recycled by CloseHandle.
threadlocal var tls_thread_ref: ?*anyopaque = null;

pub fn setThreadRef(thread_ref: ?*anyopaque) void {
    tls_thread_ref = thread_ref;
}

/// Run the cleanup for the current thread without terminating it.
pub fn finish(code: u32) void {
    // 1. DLL_THREAD_DETACH + per-module TLS callbacks (guest code, needs TEB).
    if (module.thread_detach_fn) |f| f();
    // 2. FLS destructors.  After step 1 the UCRT has freed its per-thread data
    //    and cleared its FLS slot in DllMain(DLL_THREAD_DETACH), so this pass
    //    sees no value instead of a stale pointer.
    teb.runFlsDestructors();
    // 3. Publish the exit code and wake waiters while the TEB is still valid.
    if (tls_thread_ref) |thread_ref| {
        sync.markThreadExitedRef(thread_ref, code);
    }
    // 4. Leave the guest TEB (Windows host code needs its own GS) and release
    //    the guest TEB/TLS allocations.
    teb.leaveGuest();
    teb.releaseCurrentThread();
    if (tls_thread_ref) |thread_ref| {
        tls_thread_ref = null;
        sync.releaseThreadRef(thread_ref);
    }
}

/// Terminate only the current guest thread.
pub fn exitCurrent(code: u32) noreturn {
    finish(code);
    if (builtin.os.tag == .linux) {
        // SYS_exit: terminates the calling thread, never the process.
        std.os.linux.exit(@bitCast(code));
    }
    if (builtin.os.tag == .windows) {
        const k32 = struct {
            extern "kernel32" fn ExitThread(code: u32) callconv(.winapi) noreturn;
        };
        k32.ExitThread(code);
    }
    std.process.exit(@truncate(code));
}
