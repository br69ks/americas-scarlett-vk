const std = @import("std");
const builtin = @import("builtin");
const registry = @import("shims/generated/registry.zig");

const c = if (builtin.os.tag == .windows) struct {
    extern "kernel32" fn VirtualAlloc(lpAddress: ?*anyopaque, dwSize: usize, flAllocationType: u32, flProtect: u32) callconv(.{ .x86_64_win = .{} }) ?*anyopaque;
    extern "kernel32" fn VirtualFree(lpAddress: ?*anyopaque, dwSize: usize, dwFreeType: u32) callconv(.{ .x86_64_win = .{} }) i32;
} else struct {
    extern "c" fn mmap(addr: ?*anyopaque, len: usize, prot: i32, flags: i32, fd: i32, offset: i64) ?*anyopaque;
    extern "c" fn munmap(addr: ?*anyopaque, len: usize) i32;
};

pub const MappedImage = struct {
    base_addr: usize,
    image_size: usize,
    entry_point: usize,
    trampoline_page: [*]u8,
    trampoline_page_size: usize,

    pub fn deinit(self: *MappedImage) void {
        const ptr: *anyopaque = @ptrFromInt(self.base_addr);
        const tramp_ptr: *anyopaque = @ptrCast(self.trampoline_page);
        if (builtin.os.tag == .windows) {
            const MEM_RELEASE: u32 = 0x00008000;
            _ = c.VirtualFree(ptr, 0, MEM_RELEASE);
            _ = c.VirtualFree(tramp_ptr, 0, MEM_RELEASE);
        } else {
            _ = c.munmap(ptr, self.image_size);
            _ = c.munmap(tramp_ptr, self.trampoline_page_size);
        }
    }
};

const DataDirectory = extern struct {
    virtual_address: u32,
    size: u32,
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

const TrampolineArena = struct {
    base: [*]u8,
    capacity: usize,
    offset: usize = 0,

    fn init(capacity: usize) !TrampolineArena {
        const ptr = try allocExecutableImage(0, capacity);
        return .{ .base = ptr, .capacity = capacity };
    }

    fn emit(self: *TrampolineArena, allocator: std.mem.Allocator, dll: []const u8, name: []const u8) !usize {
        if (self.offset + 32 > self.capacity) return error.OutOfMemory;

        const info = try allocator.create(StubInfo);
        info.* = .{ .dll = dll, .name = name };

        const slot = self.base + self.offset;
        const addr = @intFromPtr(slot);
        self.offset += 32;

        const info_addr: u64 = @intFromPtr(info);
        const logger_addr: u64 = @intFromPtr(&logUnimplementedCall);

        @memset(slot[0..32], 0x90);

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
            std.mem.writeInt(u32, slot[0..4], 0x08EC8348, .little);
            std.mem.writeInt(u16, slot[4..6], 0xBF48, .little);
            std.mem.writeInt(u64, slot[6..14], info_addr, .little);
            std.mem.writeInt(u16, slot[14..16], 0xB848, .little);
            std.mem.writeInt(u64, slot[16..24], logger_addr, .little);
            std.mem.writeInt(u16, slot[24..26], 0xD0FF, .little);
            std.mem.writeInt(u32, slot[26..30], 0x08C48348, .little);
            std.mem.writeInt(u8, slot[30..31], 0xC3, .little);
        }

        return addr;
    }
};

fn logUnimplementedCall(info: *const StubInfo) callconv(.c) usize {
    std.log.warn("[CALL] {s}!{s}", .{ info.dll, info.name });
    return 0;
}

const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;

fn readDataDir(opt_bytes: []const u8, index: usize) DataDirectory {
    const off = 112 + index * 8;
    return .{
        .virtual_address = std.mem.readInt(u32, opt_bytes[off..][0..4], .little),
        .size = std.mem.readInt(u32, opt_bytes[off + 4 ..][0..4], .little),
    };
}

pub fn loadAndPatch(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !MappedImage {
    const file_bytes = try std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        allocator,
        .limited(1024 * 1024 * 1024),
    );
    defer allocator.free(file_bytes);

    if (file_bytes.len < 64) return error.InvalidPe;
    const dos_magic = std.mem.readInt(u16, file_bytes[0..2], .little);
    if (dos_magic != 0x5A4D) return error.InvalidDosMagic;

    const e_lfanew = std.mem.readInt(i32, file_bytes[60..64], .little);
    const nt_offset: usize = @intCast(e_lfanew);
    const pe_sig = std.mem.readInt(u32, file_bytes[nt_offset..][0..4], .little);
    if (pe_sig != 0x00004550) return error.InvalidPeSignature;

    const file_hdr: *const FileHeader = @ptrCast(@alignCast(file_bytes[nt_offset + 4 ..].ptr));
    const opt_offset = nt_offset + 4 + @sizeOf(FileHeader);
    const opt_bytes = file_bytes[opt_offset..];

    const opt_magic = std.mem.readInt(u16, opt_bytes[0..2], .little);
    if (opt_magic != 0x20B) return error.NotPe32Plus;

    const address_of_entry_point = std.mem.readInt(u32, opt_bytes[16..20], .little);
    const image_base = std.mem.readInt(u64, opt_bytes[24..32], .little);
    const size_of_image = std.mem.readInt(u32, opt_bytes[56..60], .little);
    const size_of_headers = std.mem.readInt(u32, opt_bytes[60..64], .little);

    const import_dir = readDataDir(opt_bytes, IMAGE_DIRECTORY_ENTRY_IMPORT);
    const reloc_dir = readDataDir(opt_bytes, IMAGE_DIRECTORY_ENTRY_BASERELOC);

    const image_size: usize = size_of_image;
    const base_ptr = try allocExecutableImage(image_base, image_size);
    const base_addr = @intFromPtr(base_ptr);

    @memcpy(base_ptr[0..size_of_headers], file_bytes[0..size_of_headers]);

    const sec_offset = opt_offset + file_hdr.size_of_optional_header;
    var s: usize = 0;
    while (s < file_hdr.number_of_sections) : (s += 1) {
        const cur_sec_off = sec_offset + s * @sizeOf(SectionHeader);
        const sec: *const SectionHeader = @ptrCast(@alignCast(file_bytes[cur_sec_off..].ptr));
        if (sec.size_of_raw_data == 0) continue;
        const dst = base_ptr[sec.virtual_address..][0..sec.size_of_raw_data];
        const src = file_bytes[sec.pointer_to_raw_data..][0..sec.size_of_raw_data];
        @memcpy(dst, src);
    }

    const delta: i64 = @as(i64, @intCast(base_addr)) - @as(i64, @intCast(image_base));
    if (delta != 0) {
        applyRelocations(base_ptr, reloc_dir, delta);
    }

    const tramp_size: usize = 64 * 1024;
    var arena = try TrampolineArena.init(tramp_size);

    try patchImports(allocator, &arena, base_ptr, import_dir);

    return MappedImage{
        .base_addr = base_addr,
        .image_size = image_size,
        .entry_point = base_addr + address_of_entry_point,
        .trampoline_page = arena.base,
        .trampoline_page_size = tramp_size,
    };
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

fn patchImports(
    allocator: std.mem.Allocator,
    arena: *TrampolineArena,
    base: [*]u8,
    import_dir: DataDirectory,
) !void {
    if (import_dir.virtual_address == 0) return;

    var resolved_count: usize = 0;
    var trampoline_count: usize = 0;

    var idx: usize = 0;
    while (true) : (idx += 1) {
        const desc_off = import_dir.virtual_address + idx * @sizeOf(ImportDescriptor);
        const cur_desc: *const ImportDescriptor = @ptrCast(@alignCast(base + desc_off));
        if (cur_desc.name == 0) break;

        const dll_name_ptr: [*:0]const u8 = @ptrCast(base + cur_desc.name);
        const dll_name = std.mem.span(dll_name_ptr);

        const lookup_rva = if (cur_desc.original_first_thunk != 0)
        cur_desc.original_first_thunk
        else
            cur_desc.first_thunk;

        var t: usize = 0;
        while (true) : (t += 1) {
            const thunk_byte_off = t * 8;
            const entry = std.mem.readInt(u64, (base + lookup_rva + thunk_byte_off)[0..8], .little);
            if (entry == 0) break;

            const iat_slot = (base + cur_desc.first_thunk + thunk_byte_off)[0..8];
            const is_ordinal = (entry & (@as(u64, 1) << 63)) != 0;

            if (is_ordinal) {
                const ord: u16 = @truncate(entry & 0xFFFF);
                if (registry.resolve(dll_name, null, ord)) |ptr| {
                    std.mem.writeInt(u64, iat_slot, ptr, .little);
                    resolved_count += 1;
                } else {
                    const owned_name = try std.fmt.allocPrint(allocator, "Ordinal_{d}", .{ord});
                    const tramp = try arena.emit(allocator, dll_name, owned_name);
                    std.mem.writeInt(u64, iat_slot, tramp, .little);
                    trampoline_count += 1;
                }
            } else {
                const hint_name_rva: usize = @truncate(entry & 0x7FFFFFFF);
                const sym_name_ptr: [*:0]const u8 = @ptrCast(base + hint_name_rva + 2);
                const sym_name = std.mem.span(sym_name_ptr);
                if (registry.resolve(dll_name, sym_name, null)) |ptr| {
                    std.mem.writeInt(u64, iat_slot, ptr, .little);
                    resolved_count += 1;
                } else {
                    const tramp = try arena.emit(allocator, dll_name, sym_name);
                    std.mem.writeInt(u64, iat_slot, tramp, .little);
                    trampoline_count += 1;
                }
            }
        }
    }

    std.log.info("IAT patched: {d} resolved, {d} logging trampolines", .{ resolved_count, trampoline_count });
}
