//! XMem / GDK unified-memory HLE.
//!
//! The Xbox GDK memory API is modelled from the public GDK documentation and
//! the shipped title's call sites:
//!
//!  * `XMemVirtualAlloc(addr, size, type, XMemFlags, flProtect)` keeps a
//!    reservation registry so `MEM_RESERVE`, `MEM_COMMIT` at an address,
//!    `MEM_DECOMMIT` and `VirtualFree(..., MEM_RELEASE)` have Windows
//!    semantics.  Page-granularity bits are `MEM_64K_PAGES` (0x20400000) and
//!    `MEM_2MB_PAGES` (0x20000000).
//!  * `XMemAllocatePhysicalPages` returns 64 KiB page-frame-number tokens
//!    (opaque to the guest); the backing store is a `memfd` so that
//!    `XMemMapPhysicalPages` can create real shared aliases of the same pages.
//!  * `XMemMapPhysicalPages(va, pages, pageArray)` maps PFN tokens at an exact
//!    reserved VA range; a NULL `pageArray` decommits the range.
//!  * `XMemMapPhysicalPagesScatter(vaArray, pages, pageArray)` is the parallel
//!    array variant; a NULL `pageArray` or NULL element unmaps that VA.
//!  * `VirtualFree(addr, 0, MEM_RELEASE)` releases an XMem reservation.
//!
//! The host is unified memory, so cache attributes (XMEM_CPU/XMEM_GPU etc.)
//! are recorded but do not change the backing pages.  Reserved (uncommitted)
//! pages are PROT_NONE; committed pages are CPU-accessible and executable only
//! when the requested protection asks for it.

const std = @import("std");
const builtin = @import("builtin");

const win_cc: std.builtin.CallingConvention = .{ .x86_64_win = .{} };

// ---------------------------------------------------------------------------
// GDK / Win32 constants
// ---------------------------------------------------------------------------

const MEM_COMMIT: u32 = 0x0000_1000;
const MEM_RESERVE: u32 = 0x0000_2000;
const MEM_DECOMMIT: u32 = 0x0000_4000;
const MEM_RELEASE: u32 = 0x0000_8000;
const MEM_64K_PAGES: u32 = 0x2040_0000;
const MEM_2MB_PAGES: u32 = 0x2000_0000;

const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_WRITECOPY: u32 = 0x08;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

const PAGE_64K_SIZE: usize = 0x1_0000;
const PAGE_2MB_SIZE: usize = 0x20_0000;
/// `XMEM_2MB_CLUSTERS` for XMemAllocatePhysicalPages: each group of 32 pages
/// must be 2 MiB aligned.  The returned array still contains one 64 KiB PFN
/// token per page.
const XMEM_2MB_CLUSTERS: usize = 0x2000_0000;
const WORKING_SET_STATS_SIZE: usize = 0x78;

const PROT_NONE: c_int = 0x0;
const PROT_READ: c_int = 0x1;
const PROT_WRITE: c_int = 0x2;
const PROT_EXEC: c_int = 0x4;

const MAP_SHARED: c_int = 0x01;
const MAP_PRIVATE: c_int = 0x02;
const MAP_FIXED: c_int = 0x10;
const MAP_ANONYMOUS: c_int = 0x20;
const MAP_NORESERVE: c_int = 0x4000;
const MAP_FIXED_NOREPLACE: c_int = 0x10_0000;
const MADV_DONTNEED: c_int = 4;
const MFD_CLOEXEC: c_uint = 1;

const XMEM_ALLOC_MAGIC: u64 = 0x584D_454D_414C_4C4F; // "XMEMALLO"
const XMEM_ALLOC_ALIGN: usize = PAGE_64K_SIZE;

const LC = if (builtin.os.tag == .windows) struct {
    extern "kernel32" fn VirtualAlloc(lpAddress: ?*anyopaque, dwSize: usize, flAllocationType: u32, flProtect: u32) callconv(win_cc) ?*anyopaque;
    extern "kernel32" fn VirtualFree(lpAddress: ?*anyopaque, dwSize: usize, dwFreeType: u32) callconv(win_cc) i32;
} else struct {
    extern "c" fn mmap(addr: ?*anyopaque, len: usize, prot: c_int, flags: c_int, fd: c_int, offset: i64) ?*anyopaque;
    extern "c" fn munmap(addr: ?*anyopaque, len: usize) c_int;
    extern "c" fn mprotect(addr: ?*anyopaque, len: usize, prot: c_int) c_int;
    extern "c" fn madvise(addr: ?*anyopaque, len: usize, advice: c_int) c_int;
    extern "c" fn memfd_create(name: [*:0]const u8, flags: c_uint) c_int;
    extern "c" fn ftruncate(fd: c_int, length: i64) c_int;
    extern "c" fn close(fd: c_int) c_int;
};

// ---------------------------------------------------------------------------
// Host helpers
// ---------------------------------------------------------------------------

fn alignUpChecked(value: usize, alignment: usize) ?usize {
    if (alignment == 0 or !std.math.isPowerOfTwo(alignment)) return null;
    const add = alignment - 1;
    const sum = std.math.add(usize, value, add) catch return null;
    return sum & ~add;
}

fn pageAlignDown(value: usize) usize {
    return value & ~@as(usize, 0xFFF);
}

fn rangeEnd(base: usize, size: usize) ?usize {
    return std.math.add(usize, base, size) catch null;
}

fn guestProtToLinux(prot: u32) c_int {
    const base = prot & 0xFF;
    if ((base & PAGE_NOACCESS) != 0 and (base & ~PAGE_NOACCESS) == 0) return PROT_NONE;
    var out: c_int = 0;
    const readable = (base & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
        PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    const writable = (base & (PAGE_READWRITE | PAGE_WRITECOPY |
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    const executable = (base & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    if (readable) out |= PROT_READ;
    if (writable) out |= PROT_WRITE;
    if (executable) out |= PROT_EXEC;
    return out;
}

fn guestProtToWindows(prot: u32) u32 {
    var base = prot & 0xFF;
    if (base == 0) base = PAGE_READWRITE;
    if ((base & 0x01) != 0 and base != PAGE_NOACCESS) {
        // Xbox XMem protection values mix cache/GPU bits into the low byte.
        // Any non-PAGE_NOACCESS value is treated as read/write.
        base = PAGE_READWRITE;
    }
    return base;
}

/// Protection used for a physical-page mapping.  The 3-argument
/// `XMemMapPhysicalPages` has no protection parameter, so the reservation's
/// protection applies.  UMA aliases must remain CPU-visible for the HLE even
/// when the title requested a GPU-only/read-only protection.
fn mappingProt(prot: u32) c_int {
    var out = guestProtToLinux(prot);
    if ((out & (PROT_READ | PROT_WRITE)) == 0) out |= PROT_READ | PROT_WRITE;
    return out;
}

fn hostReserveAny(size: usize, gran: usize) ?usize {
    if (builtin.os.tag == .windows) {
        const p = LC.VirtualAlloc(null, size, MEM_RESERVE, PAGE_NOACCESS) orelse return null;
        return @intFromPtr(p);
    }
    const total = std.math.add(usize, size, gran) catch return null;
    const raw = LC.mmap(null, total, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0) orelse return null;
    const raw_addr = @intFromPtr(raw);
    if (raw_addr == std.math.maxInt(usize)) return null;
    const base = alignUpChecked(raw_addr, gran) orelse {
        _ = LC.munmap(@ptrFromInt(raw_addr), total);
        return null;
    };
    if (base > raw_addr) _ = LC.munmap(@ptrFromInt(raw_addr), base - raw_addr);
    const end = base + size;
    const raw_end = raw_addr + total;
    if (raw_end > end) _ = LC.munmap(@ptrFromInt(end), raw_end - end);
    return base;
}

fn hostReserveExact(addr: usize, size: usize) bool {
    if (builtin.os.tag == .windows) {
        const p = LC.VirtualAlloc(@ptrFromInt(addr), size, MEM_RESERVE, PAGE_NOACCESS) orelse return false;
        return @intFromPtr(p) == addr;
    }
    const p = LC.mmap(@ptrFromInt(addr), size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED_NOREPLACE, -1, 0) orelse return false;
    const got = @intFromPtr(p);
    if (got == std.math.maxInt(usize)) return false;
    if (got != addr) {
        _ = LC.munmap(p, size);
        return false;
    }
    return true;
}

fn commitWindowsProt(guest_prot: u32) u32 {
    const base = guestProtToWindows(guest_prot);
    if (base == PAGE_NOACCESS or base == PAGE_READONLY) return PAGE_READWRITE;
    return base;
}

fn hostCommit(addr: usize, size: usize, guest_prot: u32) bool {
    // XMem protection values mix GPU/cache bits into the low byte; committed
    // UMA pages must stay CPU-accessible for the HLE while the raw value is
    // kept in the reservation registry for diagnostics.
    if (builtin.os.tag == .windows) {
        const p = LC.VirtualAlloc(@ptrFromInt(addr), size, MEM_COMMIT, commitWindowsProt(guest_prot)) orelse return false;
        return @intFromPtr(p) == addr;
    }
    return LC.mprotect(@ptrFromInt(addr), size, mappingProt(guest_prot)) == 0;
}

fn hostDecommit(addr: usize, size: usize) bool {
    if (builtin.os.tag == .windows) {
        return LC.VirtualFree(@ptrFromInt(addr), size, MEM_DECOMMIT) != 0;
    }
    _ = LC.madvise(@ptrFromInt(addr), size, MADV_DONTNEED);
    return LC.mprotect(@ptrFromInt(addr), size, PROT_NONE) == 0;
}

fn hostRelease(addr: usize, size: usize) bool {
    if (builtin.os.tag == .windows) {
        return LC.VirtualFree(@ptrFromInt(addr), 0, MEM_RELEASE) != 0;
    }
    return LC.munmap(@ptrFromInt(addr), size) == 0;
}

fn hostMapNone(addr: usize, size: usize) bool {
    if (builtin.os.tag == .windows) {
        // Reserved-only pages need no work; committed pages are returned to the
        // reservation state by decommitting them.
        _ = LC.VirtualFree(@ptrFromInt(addr), size, MEM_DECOMMIT);
        return true;
    }
    const p = LC.mmap(@ptrFromInt(addr), size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED, -1, 0) orelse return false;
    return @intFromPtr(p) == addr;
}

fn hostAnonAlloc(size: usize) ?usize {
    if (builtin.os.tag == .windows) {
        const p = LC.VirtualAlloc(null, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) orelse return null;
        return @intFromPtr(p);
    }
    const p = LC.mmap(null, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0) orelse return null;
    const addr = @intFromPtr(p);
    if (addr == std.math.maxInt(usize)) return null;
    return addr;
}

fn hostAnonFree(addr: usize, size: usize) void {
    if (builtin.os.tag == .windows) {
        _ = LC.VirtualFree(@ptrFromInt(addr), 0, MEM_RELEASE);
        return;
    }
    _ = LC.munmap(@ptrFromInt(addr), size);
}

fn hostMapShared(addr: usize, size: usize, prot: c_int, fd: c_int, offset: usize) bool {
    if (builtin.os.tag == .windows) return false;
    const p = LC.mmap(@ptrFromInt(addr), size, prot, MAP_SHARED | MAP_FIXED, fd, @intCast(offset)) orelse return false;
    return @intFromPtr(p) == addr;
}

fn hostMapCopy(addr: usize, size: usize, src: [*]const u8) bool {
    if (builtin.os.tag == .windows) {
        const p = LC.VirtualAlloc(@ptrFromInt(addr), size, MEM_COMMIT, PAGE_READWRITE) orelse return false;
        if (@intFromPtr(p) != addr) return false;
    } else {
        const p = LC.mmap(@ptrFromInt(addr), size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED, -1, 0) orelse return false;
        if (@intFromPtr(p) != addr) return false;
    }
    @memcpy(@as([*]u8, @ptrFromInt(addr))[0..size], src[0..size]);
    return true;
}

fn allBytesZero(ptr: [*]const u8, len: usize) bool {
    var i: usize = 0;
    while (i < len) : (i += 1) {
        if (ptr[i] != 0) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Virtual-address reservation registry
// ---------------------------------------------------------------------------

const VirtualRange = struct {
    base: usize,
    size: usize,
    /// Allocation granularity (64 KiB or 2 MiB).
    gran: usize,
    /// The protection the title requested.  Reserved pages stay PROT_NONE
    /// until a commit (or a physical-page mapping) makes them accessible.
    prot: u32,
    xmem_flags: u32,
    alloc_type: u32,
    committed: bool,
    next: ?*VirtualRange = null,
};

const PhysArena = struct {
    base: usize,
    bytes: usize,
    pages: usize,
    first_pfn: usize,
    fd: c_int,
    next: ?*PhysArena = null,
};

const PhysMap = struct {
    va: usize,
    bytes: usize,
    arena: ?*PhysArena,
    next: ?*PhysMap = null,
};

var g_mutex: std.atomic.Mutex = .unlocked;

fn lockXmem() void {
    while (!g_mutex.tryLock()) std.atomic.spinLoopHint();
}

fn unlockXmem() void {
    g_mutex.unlock();
}
var g_virtual: ?*VirtualRange = null;
var g_arenas: ?*PhysArena = null;
var g_maps: ?*PhysMap = null;
var g_next_pfn: usize = 1;

fn pageGranularity(alloc_type: u32) usize {
    if ((alloc_type & MEM_64K_PAGES) == MEM_64K_PAGES) return PAGE_64K_SIZE;
    if ((alloc_type & MEM_2MB_PAGES) != 0) return PAGE_2MB_SIZE;
    return PAGE_64K_SIZE;
}

fn findVirtualLocked(addr: usize, size: usize) ?*VirtualRange {
    var it = g_virtual;
    while (it) |range| : (it = range.next) {
        if (addr < range.base) continue;
        const offset = addr - range.base;
        if (offset > range.size) continue;
        if (size > range.size - offset) continue;
        return range;
    }
    return null;
}

fn findVirtualByBaseLocked(addr: usize) ?*VirtualRange {
    var it = g_virtual;
    while (it) |range| : (it = range.next) {
        if (range.base == addr) return range;
    }
    return null;
}

fn insertVirtualLocked(range: *VirtualRange) void {
    range.next = g_virtual;
    g_virtual = range;
}

fn removeVirtualLocked(target: *VirtualRange) void {
    var link = &g_virtual;
    while (link.*) |range| {
        if (range == target) {
            link.* = range.next;
            return;
        }
        link = &range.next;
    }
}

fn insertArenaLocked(arena: *PhysArena) void {
    arena.next = g_arenas;
    g_arenas = arena;
}

fn removeArenaLocked(target: *PhysArena) void {
    var link = &g_arenas;
    while (link.*) |arena| {
        if (arena == target) {
            link.* = arena.next;
            return;
        }
        link = &arena.next;
    }
}

fn findArenaByPfnLocked(pfn: usize) ?struct { arena: *PhysArena, index: usize } {
    var it = g_arenas;
    while (it) |arena| : (it = arena.next) {
        if (pfn < arena.first_pfn) continue;
        const index = pfn - arena.first_pfn;
        if (index >= arena.pages) continue;
        return .{ .arena = arena, .index = index };
    }
    return null;
}

fn insertMapLocked(map: *PhysMap) void {
    map.next = g_maps;
    g_maps = map;
}

fn dropMapsInRangeLocked(va: usize, size: usize) void {
    const end = rangeEnd(va, size) orelse return;
    var link = &g_maps;
    while (link.*) |map| {
        const map_end = rangeEnd(map.va, map.bytes) orelse 0;
        const overlaps = map.va < end and va < map_end;
        if (!overlaps) {
            link = &map.next;
            continue;
        }
        link.* = map.next;
        _ = hostMapNone(map.va, map.bytes);
        std.heap.page_allocator.destroy(map);
    }
}

fn dropMapsForArenaLocked(arena: *PhysArena) void {
    var link = &g_maps;
    while (link.*) |map| {
        if (map.arena != arena) {
            link = &map.next;
            continue;
        }
        link.* = map.next;
        _ = hostMapNone(map.va, map.bytes);
        std.heap.page_allocator.destroy(map);
    }
}

fn reserveLocked(base: usize, size: usize, gran: usize, alloc_type: u32, xmem_flags: u32, prot: u32) ?*VirtualRange {
    const range = std.heap.page_allocator.create(VirtualRange) catch return null;
    range.* = .{
        .base = base,
        .size = size,
        .gran = gran,
        .prot = prot,
        .xmem_flags = xmem_flags,
        .alloc_type = alloc_type,
        .committed = false,
    };
    insertVirtualLocked(range);
    return range;
}

fn virtualAllocInternal(addr_in: ?usize, size_in: usize, alloc_type: u32, xmem_flags: u32, fl_protect: u32) ?usize {
    if (size_in == 0) return null;
    const gran = pageGranularity(alloc_type);
    const size = alignUpChecked(size_in, gran) orelse return null;
    const fl_reserve = (alloc_type & MEM_RESERVE) != 0;
    const fl_commit = (alloc_type & MEM_COMMIT) != 0;
    if (!fl_reserve and !fl_commit) return null;

    lockXmem();
    defer unlockXmem();

    // Commit of a previously reserved range (`XMemVirtualAlloc(addr, size,
    // MEM_COMMIT, ...)`).  Windows requires the range to be reserved.
    if (fl_commit and !fl_reserve) {
        const addr = addr_in orelse return null;
        const aligned_addr = pageAlignDown(addr);
        const raw_end = rangeEnd(addr, size_in) orelse return null;
        const aligned_end = alignUpChecked(raw_end, 0x1000) orelse return null;
        const aligned_size = aligned_end - aligned_addr;
        const range = findVirtualLocked(aligned_addr, aligned_size) orelse return null;
        if (!hostCommit(aligned_addr, aligned_size, fl_protect)) return null;
        range.prot = fl_protect;
        range.committed = true;
        return aligned_addr;
    }

    var base: usize = undefined;
    if (addr_in) |requested| {
        if (requested % gran != 0) return null;
        if (!hostReserveExact(requested, size)) return null;
        base = requested;
    } else {
        base = hostReserveAny(size, gran) orelse return null;
    }

    const range = reserveLocked(base, size, gran, alloc_type, xmem_flags, fl_protect) orelse {
        _ = hostRelease(base, size);
        return null;
    };

    if (fl_commit) {
        if (!hostCommit(base, size, fl_protect)) {
            removeVirtualLocked(range);
            std.heap.page_allocator.destroy(range);
            _ = hostRelease(base, size);
            return null;
        }
        range.committed = true;
    }
    return base;
}

fn virtualDecommitInternal(addr_in: usize, size_in: usize) bool {
    if (size_in == 0) return false;
    const addr = pageAlignDown(addr_in);
    const raw_end = rangeEnd(addr_in, size_in) orelse return false;
    const end = alignUpChecked(raw_end, 0x1000) orelse return false;
    const size = end - addr;
    lockXmem();
    defer unlockXmem();
    const range = findVirtualLocked(addr, size) orelse return false;
    // Physical-page aliases cannot be decommitted with MADV_DONTNEED without
    // zeroing the shared pages, so return those VAs to the reservation first.
    dropMapsInRangeLocked(addr, size);
    if (!hostDecommit(addr, size)) return false;
    if (addr == range.base and size == range.size) range.committed = false;
    return true;
}

fn virtualReleaseInternal(addr: usize) bool {
    lockXmem();
    defer unlockXmem();
    const range = findVirtualByBaseLocked(addr) orelse return false;
    removeVirtualLocked(range);
    // Remove mapping records first; the release below unmaps the whole range,
    // so the VAs must not be turned back into reservations.
    const end = rangeEnd(range.base, range.size) orelse 0;
    var link = &g_maps;
    while (link.*) |map| {
        const map_end = rangeEnd(map.va, map.bytes) orelse 0;
        const overlaps = map.va < end and range.base < map_end;
        if (!overlaps) {
            link = &map.next;
            continue;
        }
        link.* = map.next;
        std.heap.page_allocator.destroy(map);
    }
    const released = hostRelease(range.base, range.size);
    std.heap.page_allocator.destroy(range);
    return released;
}

// ---------------------------------------------------------------------------
// XMemVirtualAlloc / VirtualFree
// ---------------------------------------------------------------------------

fn shim_XMemVirtualAlloc(
    lpAddress: ?*anyopaque,
    dwSize: usize,
    flAllocationType: u32,
    xmem_flags: u32,
    flProtect: u32,
) callconv(win_cc) ?*anyopaque {
    const addr: ?usize = if (lpAddress) |p| @intFromPtr(p) else null;
    const result = virtualAllocInternal(addr, dwSize, flAllocationType, xmem_flags, flProtect);
    if (result) |base| {
        std.log.info("[XMEM] XMemVirtualAlloc(addr=0x{x}, size=0x{x}, type=0x{x}, flags=0x{x}, prot=0x{x}) -> 0x{x}", .{
            addr orelse 0, dwSize, flAllocationType, xmem_flags, flProtect, base,
        });
        return @ptrFromInt(base);
    }
    std.log.warn("[XMEM] XMemVirtualAlloc(addr=0x{x}, size=0x{x}, type=0x{x}, flags=0x{x}, prot=0x{x}) failed", .{
        addr orelse 0, dwSize, flAllocationType, xmem_flags, flProtect,
    });
    return null;
}

fn shim_VirtualFree(lpAddress: ?*anyopaque, dwSize: usize, dwFreeType: u32) callconv(win_cc) i32 {
    const addr = if (lpAddress) |p| @intFromPtr(p) else return 0;
    if (dwFreeType == MEM_RELEASE) {
        if (dwSize != 0) return 0;
        return if (virtualReleaseInternal(addr)) 1 else 0;
    }
    if (dwFreeType == MEM_DECOMMIT) {
        return if (virtualDecommitInternal(addr, dwSize)) 1 else 0;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// XMemAlloc / XMemFree
// ---------------------------------------------------------------------------
//
// GDK XMemAlloc attribute values seen in the title (0 and 0xF0814000) pack the
// memory class and alignment hints into a 64-bit value.  The HLE always
// returns 64 KiB-aligned UMA memory, which is a superset of the page/16 KiB
// alignments the title asks for, and records the attributes for diagnostics.
// The allocation header lives immediately below the 64 KiB-aligned user
// pointer so XMemFree can release the whole mapping in O(1).

const AllocHeader = extern struct {
    magic: u64,
    raw: usize,
    total: usize,
    size: usize,
    attributes: u64,
};

fn xmemAllocInternal(size_in: usize, attributes: u64) ?*anyopaque {
    const size = @max(size_in, 1);
    const header_size = @sizeOf(AllocHeader);
    const slack = std.math.add(usize, XMEM_ALLOC_ALIGN, header_size) catch return null;
    const need = std.math.add(usize, size, slack) catch return null;
    const total = alignUpChecked(need, 0x1000) orelse return null;
    const raw = hostAnonAlloc(total) orelse return null;
    const user = alignUpChecked(raw + header_size, XMEM_ALLOC_ALIGN) orelse {
        hostAnonFree(raw, total);
        return null;
    };
    if (user + size > raw + total) {
        hostAnonFree(raw, total);
        return null;
    }
    const header: *AllocHeader = @ptrFromInt(user - header_size);
    header.* = .{
        .magic = XMEM_ALLOC_MAGIC,
        .raw = raw,
        .total = total,
        .size = size,
        .attributes = attributes,
    };
    return @ptrFromInt(user);
}

fn shim_XMemAlloc(dwSize: usize, dwAllocAttributes: u64) callconv(win_cc) ?*anyopaque {
    const ptr = xmemAllocInternal(dwSize, dwAllocAttributes);
    std.log.debug("[XMEM] XMemAlloc(size=0x{x}, attrs=0x{x}) -> 0x{x}", .{
        dwSize, dwAllocAttributes, if (ptr) |p| @intFromPtr(p) else 0,
    });
    return ptr;
}

fn shim_XMemFree(pAddress: ?*anyopaque, dwAllocAttributes: u64) callconv(win_cc) void {
    _ = dwAllocAttributes;
    const addr = if (pAddress) |p| @intFromPtr(p) else return;
    if (addr < @sizeOf(AllocHeader)) return;
    const header: *const AllocHeader = @ptrFromInt(addr - @sizeOf(AllocHeader));
    if (header.magic != XMEM_ALLOC_MAGIC) {
        std.log.warn("[XMEM] XMemFree(0x{x}) ignored: not an XMemAlloc block", .{addr});
        return;
    }
    hostAnonFree(header.raw, header.total);
}

// ---------------------------------------------------------------------------
// Physical-page arena registry
// ---------------------------------------------------------------------------

fn arenaAllocInternal(flags: usize, number_of_pages: *usize, page_array: [*]usize) i32 {
    const requested = number_of_pages.*;
    if (requested == 0) return 1;
    const bytes = std.math.mul(usize, requested, PAGE_64K_SIZE) catch {
        number_of_pages.* = 0;
        return 0;
    };
    if (bytes > std.math.maxInt(i64)) {
        number_of_pages.* = 0;
        return 0;
    }
    const clusters = (flags & XMEM_2MB_CLUSTERS) != 0;
    const alignment = if (clusters) PAGE_2MB_SIZE else PAGE_64K_SIZE;

    lockXmem();
    defer unlockXmem();

    var fd: c_int = -1;
    var base: usize = 0;
    if (builtin.os.tag == .windows) {
        const p = LC.VirtualAlloc(null, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) orelse {
            std.log.err("[XMEM] XMemAllocatePhysicalPages: host arena of 0x{x} bytes failed", .{bytes});
            number_of_pages.* = 0;
            return 0;
        };
        base = @intFromPtr(p);
        if (base % alignment != 0) {
            // VirtualAlloc only guarantees 64 KiB; 2 MiB clusters are not
            // required by the Linux target and are reported as unsupported.
            _ = LC.VirtualFree(@ptrFromInt(base), 0, MEM_RELEASE);
            std.log.err("[XMEM] XMemAllocatePhysicalPages: 2 MiB cluster alignment unavailable", .{});
            number_of_pages.* = 0;
            return 0;
        }
    } else {
        fd = LC.memfd_create("xmem-physical", MFD_CLOEXEC);
        if (fd >= 0) {
            if (LC.ftruncate(fd, @intCast(bytes)) != 0) {
                _ = LC.close(fd);
                fd = -1;
            }
        }
        const reserve_bytes = std.math.add(usize, bytes, alignment) catch {
            if (fd >= 0) _ = LC.close(fd);
            number_of_pages.* = 0;
            return 0;
        };
        const raw = LC.mmap(null, reserve_bytes, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0) orelse {
            if (fd >= 0) _ = LC.close(fd);
            number_of_pages.* = 0;
            return 0;
        };
        const raw_addr = @intFromPtr(raw);
        if (raw_addr == std.math.maxInt(usize)) {
            if (fd >= 0) _ = LC.close(fd);
            number_of_pages.* = 0;
            return 0;
        }
        const aligned = alignUpChecked(raw_addr, alignment) orelse {
            _ = LC.munmap(@ptrFromInt(raw_addr), reserve_bytes);
            if (fd >= 0) _ = LC.close(fd);
            number_of_pages.* = 0;
            return 0;
        };
        base = aligned;
        const mapped_ok = if (fd >= 0)
            hostMapShared(base, bytes, PROT_READ | PROT_WRITE, fd, 0)
        else
            hostAnonFixed(base, bytes);
        if (!mapped_ok) {
            _ = LC.munmap(@ptrFromInt(raw_addr), reserve_bytes);
            if (fd >= 0) _ = LC.close(fd);
            std.log.err("[XMEM] XMemAllocatePhysicalPages: host arena of 0x{x} bytes failed", .{bytes});
            number_of_pages.* = 0;
            return 0;
        }
        if (base > raw_addr) _ = LC.munmap(@ptrFromInt(raw_addr), base - raw_addr);
        const tail_start = base + bytes;
        const raw_end = raw_addr + reserve_bytes;
        if (raw_end > tail_start) _ = LC.munmap(@ptrFromInt(tail_start), raw_end - tail_start);
    }

    var first_pfn = g_next_pfn;
    if (clusters) first_pfn = alignUpChecked(first_pfn, 32) orelse {
        releaseArenaBacking(base, bytes, fd);
        number_of_pages.* = 0;
        return 0;
    };
    g_next_pfn = std.math.add(usize, first_pfn, requested) catch {
        releaseArenaBacking(base, bytes, fd);
        number_of_pages.* = 0;
        return 0;
    };

    const arena = std.heap.page_allocator.create(PhysArena) catch {
        releaseArenaBacking(base, bytes, fd);
        number_of_pages.* = 0;
        return 0;
    };
    arena.* = .{
        .base = base,
        .bytes = bytes,
        .pages = requested,
        .first_pfn = first_pfn,
        .fd = fd,
    };
    insertArenaLocked(arena);

    var i: usize = 0;
    while (i < requested) : (i += 1) page_array[i] = first_pfn + i;
    std.log.info("[XMEM] XMemAllocatePhysicalPages(flags=0x{x}, pages={d}, bytes=0x{x}) -> 0x{x} pfn=0x{x}", .{
        flags, requested, bytes, base, first_pfn,
    });
    return 1;
}

fn releaseArenaBacking(base: usize, bytes: usize, fd: c_int) void {
    if (builtin.os.tag == .windows) {
        _ = LC.VirtualFree(@ptrFromInt(base), 0, MEM_RELEASE);
        return;
    }
    _ = LC.munmap(@ptrFromInt(base), bytes);
    if (fd >= 0) _ = LC.close(fd);
}

fn hostAnonFixed(addr: usize, size: usize) bool {
    const p = LC.mmap(@ptrFromInt(addr), size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED, -1, 0) orelse return false;
    return @intFromPtr(p) == addr;
}

fn shim_XMemAllocatePhysicalPages(
    flags: usize,
    numberOfPages: *usize,
    pageArray: [*]usize,
) callconv(win_cc) i32 {
    return arenaAllocInternal(flags, numberOfPages, pageArray);
}

fn shim_XMemFreePhysicalPages(numberOfPages: usize, pageArray: [*]const usize) callconv(win_cc) i32 {
    if (numberOfPages == 0) return 1;
    lockXmem();
    defer unlockXmem();

    const first = pageArray[0];
    const found = findArenaByPfnLocked(first) orelse return 0;
    const arena = found.arena;
    // Only whole, unchanged arenas are freed.  Partial frees would require
    // per-page ownership tracking; rejecting them is safer than unmapping a
    // range that includes another allocation.
    if (numberOfPages != arena.pages) return 0;
    var i: usize = 0;
    while (i < numberOfPages) : (i += 1) {
        if (pageArray[i] != arena.first_pfn + i) return 0;
    }
    dropMapsForArenaLocked(arena);
    removeArenaLocked(arena);
    releaseArenaBacking(arena.base, arena.bytes, arena.fd);
    std.log.info("[XMEM] XMemFreePhysicalPages(pages={d}, pfn=0x{x}) -> TRUE", .{ numberOfPages, arena.first_pfn });
    std.heap.page_allocator.destroy(arena);
    return 1;
}

/// Map `count` pages starting at `va` using the reservation's protection.
/// Returns false without changing the mapping on validation failure; partial
/// mappings are rolled back to reservation state.
fn mapRunLocked(
    va: usize,
    arena: *PhysArena,
    start_index: usize,
    count: usize,
    gran: usize,
    guest_prot: u32,
) bool {
    const bytes = std.math.mul(usize, count, gran) catch return false;
    const src_offset = std.math.mul(usize, start_index, PAGE_64K_SIZE) catch return false;
    if (src_offset > arena.bytes or bytes > arena.bytes - src_offset) return false;

    const rec = std.heap.page_allocator.create(PhysMap) catch return false;
    if (arena.fd >= 0) {
        if (!hostMapShared(va, bytes, mappingProt(guest_prot), arena.fd, src_offset)) {
            std.heap.page_allocator.destroy(rec);
            return false;
        }
    } else {
        const src: [*]const u8 = @ptrFromInt(arena.base + src_offset);
        if (!hostMapCopy(va, bytes, src)) {
            std.heap.page_allocator.destroy(rec);
            return false;
        }
    }
    rec.* = .{ .va = va, .bytes = bytes, .arena = arena };
    insertMapLocked(rec);
    return true;
}

fn shim_XMemMapPhysicalPages(
    virtualAddress: ?*anyopaque,
    numberOfPages: usize,
    pageArray: ?[*]const usize,
) callconv(win_cc) ?*anyopaque {
    const va = if (virtualAddress) |p| @intFromPtr(p) else return null;
    lockXmem();
    defer unlockXmem();

    if (numberOfPages == 0) return @ptrFromInt(va);
    const probe_range = findVirtualLocked(va, 1) orelse return null;
    const gran = probe_range.gran;

    if (pageArray == null) {
        // Decommit the range; the reservation (and its protection) remains.
        const bytes = std.math.mul(usize, numberOfPages, gran) catch return null;
        if (findVirtualLocked(va, bytes) == null) return null;
        dropMapsInRangeLocked(va, bytes);
        if (!hostDecommit(va, bytes)) return null;
        return @ptrFromInt(va);
    }

    const pages = pageArray.?;
    const page_size_for_entry: usize = if (gran == PAGE_2MB_SIZE) 32 else 1;
    const total_bytes = std.math.mul(usize, numberOfPages, gran) catch return null;
    if (findVirtualLocked(va, total_bytes) == null) return null;
    if (va % gran != 0) return null;
    // The GDK unmaps pages that are already mapped in the target range.
    dropMapsInRangeLocked(va, total_bytes);

    var i: usize = 0;
    while (i < numberOfPages) {
        const ref = findArenaByPfnLocked(pages[i]) orelse return null;
        if (gran == PAGE_2MB_SIZE) {
            if (ref.index % 32 != 0 or ref.index + 32 > ref.arena.pages) return null;
        }
        var run: usize = 1;
        while (i + run < numberOfPages) : (run += 1) {
            const next = pages[i + run];
            const expect = pages[i] + run * page_size_for_entry;
            if (next != expect) break;
            const next_ref = findArenaByPfnLocked(next) orelse break;
            if (next_ref.arena != ref.arena) break;
        }
        if (!mapRunLocked(va + i * gran, ref.arena, ref.index, run * page_size_for_entry, gran, probe_range.prot)) {
            // Roll back the pages mapped so far and leave the reservation.
            dropMapsInRangeLocked(va, i * gran);
            return null;
        }
        i += run;
    }
    return @ptrFromInt(va);
}

fn shim_XMemMapPhysicalPagesScatter(
    virtualAddressArray: [*]const usize,
    numberOfPages: usize,
    pageArray: ?[*]const usize,
) callconv(win_cc) i32 {
    if (numberOfPages == 0) return 1;
    lockXmem();
    defer unlockXmem();

    var i: usize = 0;
    while (i < numberOfPages) : (i += 1) {
        const va = virtualAddressArray[i];
        const range = findVirtualLocked(va, PAGE_64K_SIZE) orelse return 0;
        if (range.gran != PAGE_64K_SIZE or va % PAGE_64K_SIZE != 0) return 0;
        const token: usize = if (pageArray) |pages| pages[i] else 0;
        if (token == 0) {
            dropMapsInRangeLocked(va, PAGE_64K_SIZE);
            if (!hostMapNone(va, PAGE_64K_SIZE)) return 0;
            continue;
        }
        const ref = findArenaByPfnLocked(token) orelse return 0;
        dropMapsInRangeLocked(va, PAGE_64K_SIZE);
        if (!mapRunLocked(va, ref.arena, ref.index, 1, PAGE_64K_SIZE, range.prot)) return 0;
    }
    return 1;
}

// ---------------------------------------------------------------------------
// Diagnostics: XMemTransferMemory / XMemGetWorkingSetStatistics
// ---------------------------------------------------------------------------

/// `XMemTransferMemory(flags, size)` moves pages between the title and tools
/// partitions.  A single-process UMA host has no separate partition, so the
/// transfer is already complete and the call succeeds.
fn shim_XMemTransferMemory(flags: u32, size: usize) callconv(win_cc) i32 {
    std.log.debug("[XMEM] XMemTransferMemory(flags=0x{x}, size=0x{x}) -> TRUE (UMA)", .{ flags, size });
    return 1;
}

/// The `XMEM_WORKING_SET_STATISTICS` layout is 0x78 bytes on the shipped
/// title (the caller zeroes exactly that many bytes before the call).  The
/// individual fields are not public; zeroed diagnostics make the title's
/// pressure/trim logic take the no-pressure and no-transfer paths.
fn shim_XMemGetWorkingSetStatistics(flags: u32, statistics: ?[*]u8) callconv(win_cc) i32 {
    const out = statistics orelse return 0;
    @memset(out[0..WORKING_SET_STATS_SIZE], 0);
    std.log.debug("[XMEM] XMemGetWorkingSetStatistics(flags=0x{x}) -> TRUE (zeroed stats)", .{flags});
    return 1;
}

fn shim_XMemIsToolsMemAvailable() callconv(win_cc) i32 {
    return 0;
}

fn shim_D3D12ConfigureVirtualMemoryX(params: ?*const anyopaque) callconv(win_cc) i32 {
    _ = params;
    std.log.info("[D3D12X] D3D12ConfigureVirtualMemoryX() -> S_OK", .{});
    return 0; // S_OK
}

// ---------------------------------------------------------------------------
// Diagnostic helpers used by the unit tests
// ---------------------------------------------------------------------------

const VirtualInfo = struct {
    base: usize,
    size: usize,
    gran: usize,
    prot: u32,
    xmem_flags: u32,
    alloc_type: u32,
    committed: bool,
};

fn debugVirtualInfo(addr: usize) ?VirtualInfo {
    lockXmem();
    defer unlockXmem();
    const range = findVirtualLocked(addr, 1) orelse return null;
    return .{
        .base = range.base,
        .size = range.size,
        .gran = range.gran,
        .prot = range.prot,
        .xmem_flags = range.xmem_flags,
        .alloc_type = range.alloc_type,
        .committed = range.committed,
    };
}

fn debugArenaCount() usize {
    lockXmem();
    defer unlockXmem();
    var n: usize = 0;
    var it = g_arenas;
    while (it) |_| : (it = it.?.next) n += 1;
    return n;
}


// ---------------------------------------------------------------------------
// Import table
// ---------------------------------------------------------------------------

pub fn resolve(sym_name: []const u8) ?usize {
    const map = .{
        .{ "XMemVirtualAlloc", @intFromPtr(&shim_XMemVirtualAlloc) },
        .{ "VirtualFree", @intFromPtr(&shim_VirtualFree) },
        .{ "XMemAlloc", @intFromPtr(&shim_XMemAlloc) },
        .{ "XMemAllocDefault", @intFromPtr(&shim_XMemAlloc) },
        .{ "XMemFree", @intFromPtr(&shim_XMemFree) },
        .{ "XMemFreeDefault", @intFromPtr(&shim_XMemFree) },
        .{ "XMemAllocatePhysicalPages", @intFromPtr(&shim_XMemAllocatePhysicalPages) },
        .{ "XMemMapPhysicalPages", @intFromPtr(&shim_XMemMapPhysicalPages) },
        .{ "XMemMapPhysicalPagesScatter", @intFromPtr(&shim_XMemMapPhysicalPagesScatter) },
        .{ "XMemFreePhysicalPages", @intFromPtr(&shim_XMemFreePhysicalPages) },
        .{ "XMemTransferMemory", @intFromPtr(&shim_XMemTransferMemory) },
        .{ "XMemGetWorkingSetStatistics", @intFromPtr(&shim_XMemGetWorkingSetStatistics) },
        .{ "XMemIsToolsMemAvailable", @intFromPtr(&shim_XMemIsToolsMemAvailable) },
        .{ "D3D12ConfigureVirtualMemoryX", @intFromPtr(&shim_D3D12ConfigureVirtualMemoryX) },
    };

    inline for (map) |entry| {
        if (std.mem.eql(u8, entry.@"0", sym_name)) {
            return entry.@"1";
        }
    }
    return null;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const test_mem_64k = MEM_RESERVE | MEM_64K_PAGES;
const test_prot = PAGE_READWRITE;

test "XMemVirtualAlloc reserves, commits at an address, decommits and releases" {
    const size: usize = 0x20000;
    const base = @intFromPtr(shim_XMemVirtualAlloc(null, size, test_mem_64k, 0x21, test_prot) orelse return error.OutOfMemory);
    defer _ = shim_VirtualFree(@ptrFromInt(base), 0, MEM_RELEASE);
    try std.testing.expectEqual(@as(usize, 0), base % PAGE_64K_SIZE);

    const reserved = debugVirtualInfo(base) orelse return error.TestUnexpectedResult;
    try std.testing.expect(!reserved.committed);
    try std.testing.expectEqual(PAGE_64K_SIZE, reserved.gran);
    try std.testing.expectEqual(test_prot, reserved.prot);

    // Commit-at-address must return the same address.
    const committed = shim_XMemVirtualAlloc(@ptrFromInt(base), size, MEM_COMMIT, 0, test_prot);
    try std.testing.expectEqual(@as(?*anyopaque, @ptrFromInt(base)), committed);
    const bytes: [*]u8 = @ptrFromInt(base);
    bytes[0] = 0x5A;
    bytes[0xFFFF] = 0xA5;
    try std.testing.expectEqual(@as(u8, 0x5A), bytes[0]);

    // Decommit the second page, recommit it, and verify it is zero-filled.
    bytes[PAGE_64K_SIZE] = 0x11;
    try std.testing.expectEqual(@as(i32, 1), shim_VirtualFree(@ptrFromInt(base + PAGE_64K_SIZE), PAGE_64K_SIZE, MEM_DECOMMIT));
    const recommitted = shim_XMemVirtualAlloc(@ptrFromInt(base + PAGE_64K_SIZE), PAGE_64K_SIZE, MEM_COMMIT, 0, test_prot);
    try std.testing.expectEqual(@as(?*anyopaque, @ptrFromInt(base + PAGE_64K_SIZE)), recommitted);
    try std.testing.expectEqual(@as(u8, 0), bytes[PAGE_64K_SIZE]);
    try std.testing.expectEqual(@as(u8, 0xA5), bytes[0xFFFF]);

    // Release requires dwSize == 0 and only accepts the reservation base.
    try std.testing.expectEqual(@as(i32, 0), shim_VirtualFree(@ptrFromInt(base), 1, MEM_RELEASE));
    try std.testing.expectEqual(@as(i32, 1), shim_VirtualFree(@ptrFromInt(base), 0, MEM_RELEASE));
    try std.testing.expectEqual(@as(i32, 0), shim_VirtualFree(@ptrFromInt(base), 0, MEM_RELEASE));
    try std.testing.expect(debugVirtualInfo(base) == null);
}

test "XMemVirtualAlloc rejects commit outside a reservation and honours 2 MiB pages" {
    try std.testing.expect(shim_XMemVirtualAlloc(@ptrFromInt(0x5000_0000_0000), 0x1000, MEM_COMMIT, 0, test_prot) == null);

    const base = @intFromPtr(shim_XMemVirtualAlloc(null, 0x100000, MEM_RESERVE | MEM_2MB_PAGES, 0x21, test_prot) orelse return error.OutOfMemory);
    defer _ = shim_VirtualFree(@ptrFromInt(base), 0, MEM_RELEASE);
    try std.testing.expectEqual(@as(usize, 0), base % PAGE_2MB_SIZE);
    const info = debugVirtualInfo(base) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(PAGE_2MB_SIZE, info.gran);
}

test "XMemAlloc returns 64 KiB-aligned memory and XMemFree releases it" {
    const ptr = shim_XMemAlloc(123, 0xF0814000) orelse return error.OutOfMemory;
    const addr = @intFromPtr(ptr);
    try std.testing.expectEqual(@as(usize, 0), addr % XMEM_ALLOC_ALIGN);
    const bytes: [*]u8 = @ptrFromInt(addr);
    bytes[0] = 1;
    bytes[122] = 2;
    try std.testing.expectEqual(@as(u8, 2), bytes[122]);
    shim_XMemFree(ptr, 0xF0814000);

    const tiny = shim_XMemAlloc(0, 0) orelse return error.OutOfMemory;
    try std.testing.expectEqual(@as(usize, 0), @intFromPtr(tiny) % XMEM_ALLOC_ALIGN);
    shim_XMemFree(tiny, 0);
}

test "physical arena alloc/free validates the whole arena" {
    var count: usize = 4;
    var pfns: [4]usize = undefined;
    try std.testing.expectEqual(@as(i32, 1), shim_XMemAllocatePhysicalPages(0, &count, pfns[0..].ptr));
    try std.testing.expectEqual(@as(usize, 4), count);
    try std.testing.expect(pfns[0] != 0);
    try std.testing.expectEqual(pfns[0] + 1, pfns[1]);
    try std.testing.expectEqual(@as(usize, 1), debugArenaCount());

    // Partial free and a corrupted token are rejected; the arena stays live.
    try std.testing.expectEqual(@as(i32, 0), shim_XMemFreePhysicalPages(2, pfns[0..].ptr));
    var bad = pfns;
    bad[2] += 1;
    try std.testing.expectEqual(@as(i32, 0), shim_XMemFreePhysicalPages(4, bad[0..].ptr));
    try std.testing.expectEqual(@as(usize, 1), debugArenaCount());

    try std.testing.expectEqual(@as(i32, 1), shim_XMemFreePhysicalPages(4, pfns[0..].ptr));
    try std.testing.expectEqual(@as(usize, 0), debugArenaCount());
    try std.testing.expectEqual(@as(i32, 0), shim_XMemFreePhysicalPages(4, pfns[0..].ptr));
}

test "XMemMapPhysicalPages creates real shared aliases" {
    var count: usize = 2;
    var pfns: [2]usize = undefined;
    try std.testing.expectEqual(@as(i32, 1), shim_XMemAllocatePhysicalPages(0, &count, pfns[0..].ptr));
    defer _ = shim_XMemFreePhysicalPages(2, pfns[0..].ptr);

    const va1 = @intFromPtr(shim_XMemVirtualAlloc(null, 0x20000, test_mem_64k, 0x21, test_prot) orelse return error.OutOfMemory);
    defer _ = shim_VirtualFree(@ptrFromInt(va1), 0, MEM_RELEASE);
    const va2 = @intFromPtr(shim_XMemVirtualAlloc(null, 0x20000, test_mem_64k, 0x21, test_prot) orelse return error.OutOfMemory);
    defer _ = shim_VirtualFree(@ptrFromInt(va2), 0, MEM_RELEASE);

    try std.testing.expectEqual(@as(?*anyopaque, @ptrFromInt(va1)), shim_XMemMapPhysicalPages(@ptrFromInt(va1), 2, pfns[0..].ptr));
    try std.testing.expectEqual(@as(?*anyopaque, @ptrFromInt(va2)), shim_XMemMapPhysicalPages(@ptrFromInt(va2), 2, pfns[0..].ptr));

    const a: [*]u8 = @ptrFromInt(va1);
    const b: [*]u8 = @ptrFromInt(va2);
    a[0] = 0x11;
    a[PAGE_64K_SIZE] = 0x22;
    try std.testing.expectEqual(@as(u8, 0x11), b[0]);
    try std.testing.expectEqual(@as(u8, 0x22), b[PAGE_64K_SIZE]);
    b[0] = 0x33;
    try std.testing.expectEqual(@as(u8, 0x33), a[0]);

    // A NULL page array decommits the range while keeping the reservation.
    try std.testing.expectEqual(@as(?*anyopaque, @ptrFromInt(va2)), shim_XMemMapPhysicalPages(@ptrFromInt(va2), 2, null));
    try std.testing.expect(debugVirtualInfo(va2) != null);
}

test "XMemMapPhysicalPagesScatter maps and unmaps individual pages" {
    var count: usize = 2;
    var pfns: [2]usize = undefined;
    try std.testing.expectEqual(@as(i32, 1), shim_XMemAllocatePhysicalPages(0, &count, pfns[0..].ptr));
    defer _ = shim_XMemFreePhysicalPages(2, pfns[0..].ptr);

    const va = @intFromPtr(shim_XMemVirtualAlloc(null, 0x20000, test_mem_64k, 0x21, test_prot) orelse return error.OutOfMemory);
    defer _ = shim_VirtualFree(@ptrFromInt(va), 0, MEM_RELEASE);
    var vas = [2]usize{ va, va + PAGE_64K_SIZE };
    try std.testing.expectEqual(@as(i32, 1), shim_XMemMapPhysicalPagesScatter(&vas, 2, pfns[0..].ptr));

    const p: [*]u8 = @ptrFromInt(va);
    p[0] = 0x77;
    p[PAGE_64K_SIZE] = 0x88;

    // Unmap the second VA by passing a NULL entry; the first stays mapped.
    var unmapped = [2]usize{ pfns[0], 0 };
    try std.testing.expectEqual(@as(i32, 1), shim_XMemMapPhysicalPagesScatter(&vas, 2, &unmapped));
    try std.testing.expectEqual(@as(u8, 0x77), p[0]);
}

test "XMemGetWorkingSetStatistics zeroes the 0x78-byte structure" {
    var buffer: [WORKING_SET_STATS_SIZE + 8]u8 = @splat(0xAA);
    try std.testing.expectEqual(@as(i32, 1), shim_XMemGetWorkingSetStatistics(0x2000000A, &buffer));
    try std.testing.expect(allBytesZero(&buffer, WORKING_SET_STATS_SIZE));
    try std.testing.expectEqual(@as(u8, 0xAA), buffer[WORKING_SET_STATS_SIZE]);
    try std.testing.expectEqual(@as(i32, 0), shim_XMemGetWorkingSetStatistics(0x2000000A, null));
    try std.testing.expectEqual(@as(i32, 1), shim_XMemTransferMemory(1, 0x100000));
}
