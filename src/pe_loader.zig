const std = @import("std");
const builtin = @import("builtin");
const module = @import("module.zig");
const host_imports = @import("host_imports.zig");
const stub_policy = @import("shims/stub_policy.zig");
const loader_lock = @import("loader_lock.zig");

const c = if (builtin.os.tag == .windows) struct {
    extern "kernel32" fn VirtualAlloc(lpAddress: ?*anyopaque, dwSize: usize, flAllocationType: u32, flProtect: u32) callconv(.{ .x86_64_win = .{} }) ?*anyopaque;
    extern "kernel32" fn VirtualFree(lpAddress: ?*anyopaque, dwSize: usize, dwFreeType: u32) callconv(.{ .x86_64_win = .{} }) i32;
} else struct {
    extern "c" fn mmap(addr: ?*anyopaque, len: usize, prot: i32, flags: i32, fd: i32, offset: i64) ?*anyopaque;
    extern "c" fn munmap(addr: ?*anyopaque, len: usize) i32;
};

pub const DataDirectory = extern struct {
    virtual_address: u32,
    size: u32,
};

pub const Export = struct {
    /// Null for ordinal-only exports.
    name: ?[]const u8,
    ordinal: u32,
    rva: u32,
    /// Non-null when the export is a forwarder ("DLL.Function").
    forwarder: ?[]const u8,
};

pub const MappedImage = struct {
    base_addr: usize,
    image_size: usize,
    entry_point: usize,
    trampoline_page: ?[*]u8,
    trampoline_page_size: usize,
    tls_block_addr: usize,
    tls_block_size: usize = 0,
    tls_index_va: usize,
    tls_callbacks: usize,
    preferred_base: u64,
    is_dll: bool,
    /// PE optional-header stack sizes (SizeOfStackReserve/SizeOfStackCommit).
    stack_reserve: u64 = 0,
    stack_commit: u64 = 0,
    import_dir: DataDirectory,
    export_dir: DataDirectory,
    pdata_rva: u32,
    pdata_size: u32,

    pub fn deinit(self: *MappedImage) void {
        const ptr: *anyopaque = @ptrFromInt(self.base_addr);
        if (builtin.os.tag == .windows) {
            const MEM_RELEASE: u32 = 0x00008000;
            _ = c.VirtualFree(ptr, 0, MEM_RELEASE);
            if (self.trampoline_page) |tramp| {
                _ = c.VirtualFree(@ptrCast(tramp), 0, MEM_RELEASE);
            }
        } else {
            _ = c.munmap(ptr, self.image_size);
            if (self.trampoline_page) |tramp| {
                _ = c.munmap(@ptrCast(tramp), self.trampoline_page_size);
            }
        }
    }
};

const FileHeader = extern struct {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
};

const SectionHeader = extern struct {
    name_lo: u32,
    name_hi: u32,
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_linenumbers: u32,
    number_of_relocations: u16,
    number_of_linenumbers: u16,
    characteristics: u32,
};

const ImportDescriptor = extern struct {
    original_first_thunk: u32,
    time_date_stamp: u32,
    forwarder_chain: u32,
    name: u32,
    first_thunk: u32,
};

const StubInfo = struct {
    dll: []const u8,
    name: []const u8,
};

fn simpleHostShim(name: ?[]const u8) bool {
    const n = name orelse return false;
    return std.mem.eql(u8, n, "GetSystemTimeAsFileTime") or
        std.mem.eql(u8, n, "GetCurrentThreadId") or
        std.mem.eql(u8, n, "GetCurrentProcessId") or
        std.mem.eql(u8, n, "QueryPerformanceCounter") or
        std.mem.eql(u8, n, "QueryPerformanceFrequency") or
        std.mem.eql(u8, n, "GetTickCount64") or
        std.mem.eql(u8, n, "InitializeSListHead") or
        std.mem.eql(u8, n, "GetCurrentProcess") or
        std.mem.eql(u8, n, "GetLastError") or
        std.mem.eql(u8, n, "SetLastError");
}

fn needsHostThunk(dll: []const u8) bool {
    if (host_imports.isHostDll(dll)) return true;
    const n = std.fs.path.basename(dll);
    return std.ascii.startsWithIgnoreCase(n, "api-ms-win-core-") or
        std.ascii.startsWithIgnoreCase(n, "kernel32") or
        std.ascii.startsWithIgnoreCase(n, "ntdll") or
        std.ascii.startsWithIgnoreCase(n, "ucrtbase") or
        std.ascii.startsWithIgnoreCase(n, "msvcp") or
        std.ascii.startsWithIgnoreCase(n, "vcruntime");
}

fn logUnimplementedCall(info: *const StubInfo, caller_ret: usize) callconv(.c) usize {
    // Formatting-only CRT exports are optional by design (see stub_policy).
    if (std.mem.startsWith(u8, info.name, "__stdio_common_")) return 0;
    std.log.err("[CALL] unimplemented {s}!{s} (from 0x{x}); failing closed", .{
        info.dll, info.name, caller_ret,
    });
    // Not a silent zero return: unknown imports abort through the same
    // fail-closed policy as the generated stubs (benign/optional APIs and
    // SCARLETT_STUB_POLICY=zero still return 0 there).
    return stub_policy.missing(info.dll, info.name);
}

pub const TrampolineArena = struct {
    base: [*]u8,
    capacity: usize,
    offset: usize = 0,
    /// Serializes slot allocation: stubs may be emitted from import patching
    /// (under the loader lock) and from guest `GetProcAddress` calls.
    lock: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    const slot_size = 128;

    fn lockSlot(self: *TrampolineArena) void {
        while (self.lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
            while (self.lock.load(.monotonic) != 0) std.atomic.spinLoopHint();
        }
    }

    fn unlockSlot(self: *TrampolineArena) void {
        self.lock.store(0, .release);
    }

    pub fn init(capacity: usize) !TrampolineArena {
        const ptr = try allocExecutableImage(0, capacity);
        return .{ .base = ptr, .capacity = capacity };
    }

    pub fn emitThunk(self: *TrampolineArena, target: usize) !usize {
        self.lockSlot();
        defer self.unlockSlot();
        if (self.offset + 128 > self.capacity) return error.OutOfMemory;
        const slot = self.base + self.offset;
        self.offset += 128;
        @memset(slot[0..128], 0x90);
        // Stack-saved guest TEB, host TEB switch, aligned host call.  The
        // guest TEB is saved on the stack so a callee cannot clobber it, and
        // RAX/XMM0 are left untouched on return.
        const template = [_]u8{
            0x65, 0x4c, 0x8b, 0x1c, 0x25, 0x30, 0x00, 0x00, 0x00, // mov r11, gs:[0x30]
            0x4d, 0x8b, 0x94, 0x24, 0xf8, 0x1f, 0x00, 0x00, // mov r10, [r11+0x1ff8]
            0x4d, 0x85, 0xd2, // test r10, r10
            0x74, 0x30, // jz no_host (0x46)
            0x4d, 0x89, 0xa3, 0xf0, 0x1f, 0x00, 0x00, // mov [r11+0x1ff0], r12
            0x4d, 0x89, 0x9a, 0xe0, 0x1f, 0x00, 0x00, // mov [r10+0x1fe0], r11
            0xf3, 0x49, 0x0f, 0xae, 0xda, // wrgsbase r10
            0xff, 0x15, 0x34, 0x00, 0x00, 0x00, // call [rip+0x34] -> 0x60
            0x65, 0x4c, 0x8b, 0x14, 0x25, 0x30, 0x00, 0x00, 0x00, // mov r10, gs:[0x30] (host)
            0x4d, 0x8b, 0x9a, 0xe0, 0x1f, 0x00, 0x00, // mov r11, [r10+0x1fe0]
            0x4d, 0x8b, 0xa3, 0xf0, 0x1f, 0x00, 0x00, // mov r12, [r11+0x1ff0]
            0xf3, 0x49, 0x0f, 0xae, 0xde, // wrgsbase r11
            0xc3, // ret
            0xff, 0x15, 0x14, 0x00, 0x00, 0x00, // no_host: call [rip+0x14] -> 0x60
            0xc3, // ret
        };
        @memcpy(slot[0..template.len], &template);
        std.mem.writeInt(u64, slot[0x60..0x68], target, .little);
        return @intFromPtr(slot);
    }

    fn emit(self: *TrampolineArena, allocator: std.mem.Allocator, dll: []const u8, name: []const u8) !usize {
        self.lockSlot();
        defer self.unlockSlot();
        if (self.offset + slot_size > self.capacity) return error.OutOfMemory;

        const info = try allocator.create(StubInfo);
        info.* = .{ .dll = dll, .name = name };

        const slot = self.base + self.offset;
        const addr = @intFromPtr(slot);
        self.offset += slot_size;

        const info_addr: u64 = @intFromPtr(info);
        const logger_addr: u64 = @intFromPtr(&logUnimplementedCall);

        @memset(slot[0..slot_size], 0x90);

        if (builtin.os.tag == .windows) {
            std.mem.writeInt(u32, slot[0..4], 0x28EC8348, .little);
            std.mem.writeInt(u16, slot[4..6], 0xB948, .little);
            std.mem.writeInt(u64, slot[6..14], info_addr, .little);
            std.mem.writeInt(u16, slot[14..16], 0xB848, .little);
            std.mem.writeInt(u64, slot[16..24], logger_addr, .little);
            std.mem.writeInt(u16, slot[24..26], 0xD0FF, .little);
            std.mem.writeInt(u32, slot[26..30], 0x28C48348, .little);
            std.mem.writeInt(u8, slot[30..31], 0xC3, .little);
        } else {
            var p: usize = 0;
            const emitBytes = struct {
                fn put(buf: [*]u8, idx: *usize, bytes: []const u8) void {
                    @memcpy(buf[idx.* .. idx.* + bytes.len], bytes);
                    idx.* += bytes.len;
                }
            }.put;

            emitBytes(slot, &p, &.{ 0x57, 0x56, 0x51, 0x52 });
            emitBytes(slot, &p, &.{ 0x41, 0x50, 0x41, 0x51 });
            emitBytes(slot, &p, &.{ 0x41, 0x52, 0x41, 0x53 });
            emitBytes(slot, &p, &.{ 0x4C, 0x8B, 0x5C, 0x24, 0x40 });
            emitBytes(slot, &p, &.{ 0x48, 0x83, 0xEC, 0x68 });
            emitBytes(slot, &p, &.{ 0x0F, 0x11, 0x44, 0x24, 0x00 });
            emitBytes(slot, &p, &.{ 0x0F, 0x11, 0x4C, 0x24, 0x10 });
            emitBytes(slot, &p, &.{ 0x0F, 0x11, 0x54, 0x24, 0x20 });
            emitBytes(slot, &p, &.{ 0x0F, 0x11, 0x5C, 0x24, 0x30 });
            emitBytes(slot, &p, &.{ 0x0F, 0x11, 0x64, 0x24, 0x40 });
            emitBytes(slot, &p, &.{ 0x0F, 0x11, 0x6C, 0x24, 0x50 });
            emitBytes(slot, &p, &.{ 0x48, 0xBF });
            std.mem.writeInt(u64, slot[p..][0..8], info_addr, .little);
            p += 8;
            // Second argument is the guest return address captured in r11.
            // (This used to be `mov r14, rbx`, which clobbered a callee-saved
            // register of the calling guest function and passed a bogus
            // caller_ret.)
            emitBytes(slot, &p, &.{ 0x4C, 0x89, 0xDE });
            emitBytes(slot, &p, &.{ 0x48, 0xB8 });
            std.mem.writeInt(u64, slot[p..][0..8], logger_addr, .little);
            p += 8;
            emitBytes(slot, &p, &.{ 0xFF, 0xD0 });
            emitBytes(slot, &p, &.{ 0x0F, 0x10, 0x44, 0x24, 0x00 });
            emitBytes(slot, &p, &.{ 0x0F, 0x10, 0x4C, 0x24, 0x10 });
            emitBytes(slot, &p, &.{ 0x0F, 0x10, 0x54, 0x24, 0x20 });
            emitBytes(slot, &p, &.{ 0x0F, 0x10, 0x5C, 0x24, 0x30 });
            emitBytes(slot, &p, &.{ 0x0F, 0x10, 0x64, 0x24, 0x40 });
            emitBytes(slot, &p, &.{ 0x0F, 0x10, 0x6C, 0x24, 0x50 });
            emitBytes(slot, &p, &.{ 0x48, 0x83, 0xC4, 0x68 });
            emitBytes(slot, &p, &.{ 0x41, 0x5B, 0x41, 0x5A });
            emitBytes(slot, &p, &.{ 0x41, 0x59, 0x41, 0x58 });
            emitBytes(slot, &p, &.{ 0x5A, 0x59, 0x5E, 0x5F });
            emitBytes(slot, &p, &.{0xC3});
        }

        return addr;
    }
};

const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;

pub const StackSizes = struct { reserve: u64, commit: u64 };

/// PE32+ optional-header SizeOfStackReserve/SizeOfStackCommit.
pub fn readStackSizes(opt_bytes: []const u8) StackSizes {
    if (opt_bytes.len < 0x58) return .{ .reserve = 0, .commit = 0 };
    return .{
        .reserve = std.mem.readInt(u64, opt_bytes[0x48..0x50], .little),
        .commit = std.mem.readInt(u64, opt_bytes[0x50..0x58], .little),
    };
}

fn readDataDir(opt_bytes: []const u8, index: usize) DataDirectory {
    const off = 112 + index * 8;
    return .{
        .virtual_address = std.mem.readInt(u32, opt_bytes[off..][0..4], .little),
        .size = std.mem.readInt(u32, opt_bytes[off + 4 ..][0..4], .little),
    };
}

/// Map a PE image and apply relocations/TLS, but do not touch imports yet.
pub fn mapImage(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !MappedImage {
    const file_bytes = try std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        allocator,
        .limited(1024 * 1024 * 1024),
    );
    defer allocator.free(file_bytes);

    if (file_bytes.len < 64) return error.InvalidPe;
    if (std.mem.readInt(u16, file_bytes[0..2], .little) != 0x5A4D) return error.InvalidDosMagic;

    const e_lfanew = std.mem.readInt(i32, file_bytes[60..64], .little);
    const nt_offset: usize = @intCast(e_lfanew);
    if (std.mem.readInt(u32, file_bytes[nt_offset..][0..4], .little) != 0x00004550) return error.InvalidPeSignature;

    const file_hdr: *const FileHeader = @ptrCast(@alignCast(file_bytes[nt_offset + 4 ..].ptr));
    const opt_offset = nt_offset + 4 + @sizeOf(FileHeader);
    const opt_bytes = file_bytes[opt_offset..];

    if (std.mem.readInt(u16, opt_bytes[0..2], .little) != 0x20B) return error.NotPe32Plus;

    const address_of_entry_point = std.mem.readInt(u32, opt_bytes[16..20], .little);
    const preferred_base = std.mem.readInt(u64, opt_bytes[24..32], .little);
    const size_of_image = std.mem.readInt(u32, opt_bytes[56..60], .little);
    const size_of_headers = std.mem.readInt(u32, opt_bytes[60..64], .little);
    const stack_sizes = readStackSizes(opt_bytes);
    const stack_reserve = stack_sizes.reserve;
    const stack_commit = stack_sizes.commit;

    if (size_of_image == 0 or size_of_image > 0x4000_0000) return error.InvalidImageSize;
    if (size_of_headers > size_of_image) return error.InvalidHeaders;

    const import_dir = readDataDir(opt_bytes, IMAGE_DIRECTORY_ENTRY_IMPORT);
    const reloc_dir = readDataDir(opt_bytes, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    const tls_dir = readDataDir(opt_bytes, IMAGE_DIRECTORY_ENTRY_TLS);
    const export_dir = readDataDir(opt_bytes, IMAGE_DIRECTORY_ENTRY_EXPORT);
    const pdata_dir = readDataDir(opt_bytes, IMAGE_DIRECTORY_ENTRY_EXCEPTION);

    const image_size: usize = size_of_image;
    const base_ptr = try allocExecutableImage(preferred_base, image_size);
    const base_addr = @intFromPtr(base_ptr);
    @memset(base_ptr[0..image_size], 0);

    @memcpy(base_ptr[0..size_of_headers], file_bytes[0..size_of_headers]);

    const sec_offset = opt_offset + file_hdr.size_of_optional_header;
    var s: usize = 0;
    while (s < file_hdr.number_of_sections) : (s += 1) {
        const cur_sec_off = sec_offset + s * @sizeOf(SectionHeader);
        if (cur_sec_off + @sizeOf(SectionHeader) > file_bytes.len) return error.InvalidSectionTable;
        const sec: *const SectionHeader = @ptrCast(@alignCast(file_bytes[cur_sec_off..].ptr));
        if (sec.size_of_raw_data == 0) continue;
        if (sec.virtual_address + sec.size_of_raw_data > image_size) return error.SectionOutOfBounds;
        if (sec.pointer_to_raw_data + sec.size_of_raw_data > file_bytes.len) return error.SectionOutOfBounds;
        const dst = base_ptr[sec.virtual_address..][0..sec.size_of_raw_data];
        const src = file_bytes[sec.pointer_to_raw_data..][0..sec.size_of_raw_data];
        @memcpy(dst, src);
    }

    const delta: i64 = @as(i64, @intCast(base_addr)) - @as(i64, @intCast(preferred_base));
    if (delta != 0) applyRelocations(base_ptr, reloc_dir, delta);

    var tls_block_addr: usize = 0;
    var tls_block_size: usize = 0;
    var tls_index_va: usize = 0;
    var tls_callbacks: usize = 0;
    if (tls_dir.virtual_address != 0 and tls_dir.size >= 40) {
        const tls_hdr = base_ptr + tls_dir.virtual_address;
        const start_va = std.mem.readInt(u64, tls_hdr[0..8], .little);
        const end_va = std.mem.readInt(u64, tls_hdr[8..16], .little);
        const index_va = std.mem.readInt(u64, tls_hdr[16..24], .little);
        const callbacks_va = std.mem.readInt(u64, tls_hdr[24..32], .little);
        const zero_fill = std.mem.readInt(u32, tls_hdr[32..36], .little);

        const raw_len: usize = if (end_va >= start_va) @intCast(end_va - start_va) else 0;
        // Exactly the module's declared TLS size (raw template + zero fill);
        // the old +0x1000 slack is gone.
        const total_tls_size: usize = raw_len + @as(usize, zero_fill);
        if (total_tls_size > 0) {
            const tls_mem = try allocator.alignedAlloc(u8, comptime std.mem.Alignment.fromByteUnits(64), total_tls_size);
            @memset(tls_mem, 0);
            if (raw_len > 0 and start_va != 0) {
                const src_ptr: [*]const u8 = @ptrFromInt(@as(usize, @intCast(start_va)));
                @memcpy(tls_mem[0..raw_len], src_ptr[0..raw_len]);
            }
            tls_block_addr = @intFromPtr(tls_mem.ptr);
            tls_block_size = total_tls_size;
        }
        tls_index_va = @intCast(index_va);
        tls_callbacks = @intCast(callbacks_va);
        std.log.info("TLS block: addr=0x{x}, raw={d}, zero_fill={d}, index_va=0x{x}", .{
            tls_block_addr, raw_len, zero_fill, tls_index_va,
        });
    }

    return MappedImage{
        .base_addr = base_addr,
        .image_size = image_size,
        .entry_point = base_addr + address_of_entry_point,
        .trampoline_page = null,
        .trampoline_page_size = 0,
        .tls_block_addr = tls_block_addr,
        .tls_block_size = tls_block_size,
        .tls_index_va = tls_index_va,
        .tls_callbacks = tls_callbacks,
        .preferred_base = preferred_base,
        .is_dll = (file_hdr.characteristics & 0x2000) != 0,
        .stack_reserve = stack_reserve,
        .stack_commit = stack_commit,
        .import_dir = import_dir,
        .export_dir = export_dir,
        .pdata_rva = pdata_dir.virtual_address,
        .pdata_size = pdata_dir.size,
    };
}

/// Parse the export directory. Names and forwarder strings point into the
/// mapped image, so the returned slice must not outlive it.
pub fn parseExports(allocator: std.mem.Allocator, image: *const MappedImage) ![]Export {
    if (image.export_dir.virtual_address == 0 or image.export_dir.size < 40) {
        return allocator.alloc(Export, 0);
    }
    const base: [*]u8 = @ptrFromInt(image.base_addr);
    const ed = base + image.export_dir.virtual_address;
    const ordinal_base = std.mem.readInt(u32, ed[16..20], .little);
    const number_of_functions = std.mem.readInt(u32, ed[20..24], .little);
    const number_of_names = std.mem.readInt(u32, ed[24..28], .little);
    const address_of_functions = std.mem.readInt(u32, ed[28..32], .little);
    const address_of_names = std.mem.readInt(u32, ed[32..36], .little);
    const address_of_name_ordinals = std.mem.readInt(u32, ed[36..40], .little);

    if (number_of_functions > 65536 or number_of_names > 65536) return error.InvalidExportTable;

    const exports = try allocator.alloc(Export, number_of_functions);
    for (exports, 0..) |*e, i| {
        const rva = std.mem.readInt(u32, (base + address_of_functions + i * 4)[0..4], .little);
        e.* = .{
            .name = null,
            .ordinal = ordinal_base + @as(u32, @intCast(i)),
            .rva = rva,
            .forwarder = null,
        };
        if (rva >= image.export_dir.virtual_address and
            rva < image.export_dir.virtual_address + image.export_dir.size)
        {
            e.forwarder = std.mem.span(@as([*:0]const u8, @ptrCast(base + rva)));
        }
    }

    var i: usize = 0;
    while (i < number_of_names) : (i += 1) {
        const name_rva = std.mem.readInt(u32, (base + address_of_names + i * 4)[0..4], .little);
        const ord_index = std.mem.readInt(u16, (base + address_of_name_ordinals + i * 2)[0..2], .little);
        if (ord_index >= exports.len) continue;
        exports[ord_index].name = std.mem.span(@as([*:0]const u8, @ptrCast(base + name_rva)));
    }
    return exports;
}

pub const ImportResolver = struct {
    ctx: *anyopaque,
    resolve: *const fn (ctx: *anyopaque, dll: []const u8, name: ?[]const u8, ordinal: ?u16) ?usize,
    arena: ?*TrampolineArena = null,
    allocator: ?std.mem.Allocator = null,
};

pub const ImportStats = struct {
    total: usize = 0,
    resolved: usize = 0,
    trampolines: usize = 0,
    missing: usize = 0,
};

pub fn patchImports(image: *const MappedImage, resolver: ImportResolver) !ImportStats {
    if (image.import_dir.virtual_address == 0) return .{};
    // Import patching may load dependent modules (which patch their own
    // imports); the loader lock is recursive.
    loader_lock.lock();
    defer loader_lock.unlock();
    const base: [*]u8 = @ptrFromInt(image.base_addr);
    const import_dir = image.import_dir;
    var stats = ImportStats{};

    var idx: usize = 0;
    while (true) : (idx += 1) {
        const desc_off = import_dir.virtual_address + idx * @sizeOf(ImportDescriptor);
        const cur_desc: *const ImportDescriptor = @ptrCast(@alignCast(base + desc_off));
        if (cur_desc.name == 0) break;

        const dll_name = std.mem.span(@as([*:0]const u8, @ptrCast(base + cur_desc.name)));
        const lookup_rva = if (cur_desc.original_first_thunk != 0)
            cur_desc.original_first_thunk
        else
            cur_desc.first_thunk;

        var t: usize = 0;
        while (true) : (t += 1) {
            const thunk_byte_off = t * 8;
            const entry = std.mem.readInt(u64, (base + lookup_rva + thunk_byte_off)[0..8], .little);
            if (entry == 0) break;
            stats.total += 1;

            const iat_slot = (base + cur_desc.first_thunk + thunk_byte_off)[0..8];
            const is_ordinal = (entry & (@as(u64, 1) << 63)) != 0;
            var name_opt: ?[]const u8 = null;
            var ord_opt: ?u16 = null;
            if (is_ordinal) {
                ord_opt = @truncate(entry & 0xFFFF);
            } else {
                const hint_name_rva: usize = @truncate(entry & 0x7FFFFFFF);
                name_opt = std.mem.span(@as([*:0]const u8, @ptrCast(base + hint_name_rva + 2)));
            }

            if (resolver.resolve(resolver.ctx, dll_name, name_opt, ord_opt)) |ptr| {
                var target = ptr;
                if (builtin.os.tag == .windows and needsHostThunk(dll_name) and !simpleHostShim(name_opt)) {
                    if (resolver.arena) |arena| target = try arena.emitThunk(ptr);
                }
                std.mem.writeInt(u64, iat_slot, target, .little);
                if (target < 0x1_0000_0000) {
                    std.log.err("[IAT] LOW target {s}!{s} -> 0x{x}", .{ dll_name, name_opt orelse "ordinal", target });
                }
                stats.resolved += 1;
            } else if (resolver.arena) |arena| {
                const allocator = resolver.allocator orelse return error.ResolverHasNoAllocator;
                const label = if (name_opt) |n| n else try std.fmt.allocPrint(allocator, "Ordinal_{d}", .{ord_opt.?});
                const tramp = try arena.emit(allocator, dll_name, label);
                std.mem.writeInt(u64, iat_slot, tramp, .little);
                stats.trampolines += 1;
            } else {
                stats.missing += 1;
                if (name_opt) |n| {
                    std.log.err("[IAT] unresolved {s}!{s}", .{ dll_name, n });
                } else {
                    std.log.err("[IAT] unresolved {s}!Ordinal_{d}", .{ dll_name, ord_opt.? });
                }
            }
        }
    }

    std.log.info("[IAT] imports={d}, resolved={d}, trampolines={d}, missing={d}", .{
        stats.total, stats.resolved, stats.trampolines, stats.missing,
    });
    if (stats.missing != 0) return error.UnresolvedImports;
    return stats;
}

fn allocExecutableImage(preferred_base: u64, size: usize) ![*]u8 {
    if (builtin.os.tag == .windows) {
        const MEM_COMMIT: u32 = 0x00001000;
        const MEM_RESERVE: u32 = 0x00002000;
        const PAGE_EXECUTE_READWRITE: u32 = 0x40;
        const ptr = c.VirtualAlloc(
            @ptrFromInt(preferred_base),
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        ) orelse c.VirtualAlloc(
            null,
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        ) orelse return error.OutOfMemory;
        return @ptrCast(ptr);
    } else {
        const PROT_READ: i32 = 0x1;
        const PROT_WRITE: i32 = 0x2;
        const PROT_EXEC: i32 = 0x4;
        const MAP_PRIVATE: i32 = 0x02;
        const MAP_ANONYMOUS: i32 = 0x20;
        const MAP_FAILED: usize = @bitCast(@as(isize, -1));

        const ptr = c.mmap(
            @ptrFromInt(preferred_base),
            size,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        ) orelse return error.OutOfMemory;

        if (@intFromPtr(ptr) == MAP_FAILED) return error.OutOfMemory;
        return @ptrCast(ptr);
    }
}

fn applyRelocations(base: [*]u8, reloc_dir: DataDirectory, delta: i64) void {
    if (reloc_dir.virtual_address == 0 or reloc_dir.size == 0) return;
    var offset: usize = 0;
    while (offset < reloc_dir.size) {
        const block_ptr = base + reloc_dir.virtual_address + offset;
        const page_rva = std.mem.readInt(u32, block_ptr[0..4], .little);
        const block_size = std.mem.readInt(u32, block_ptr[4..8], .little);
        if (block_size == 0) break;

        const entry_count = (block_size - 8) / 2;
        var i: usize = 0;
        while (i < entry_count) : (i += 1) {
            const entry_off = 8 + i * 2;
            const entry = std.mem.readInt(u16, block_ptr[entry_off..][0..2], .little);
            const reloc_type = entry >> 12;
            const page_offset = entry & 0x0FFF;
            if (reloc_type == 10) {
                const target_ptr: *u64 = @ptrCast(@alignCast(base + page_rva + page_offset));
                const updated: i64 = @as(i64, @intCast(target_ptr.*)) + delta;
                target_ptr.* = @intCast(updated);
            }
        }
        offset += block_size;
    }
}
