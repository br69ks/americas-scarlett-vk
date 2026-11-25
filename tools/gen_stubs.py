#!/usr/bin/env python3
import re
import sys
from pathlib import Path
from collections import defaultdict


def _parse_decimal_or_prefixed_int(value: str) -> int | None:
    """Parse objdump's decimal ordinal, while tolerating an explicit 0x prefix."""
    try:
        return int(value, 0) if value.lower().startswith("0x") else int(value, 10)
    except ValueError:
        return None


def parse_imports(text: str) -> dict[str, list[tuple[str, int | None]]]:
    """
    Parse imports from GNU `objdump -p` and `llvm-readobj --coff-imports`.

    GNU objdump's normal PE import rows have these columns:
        VMA  Ordinal  Hint  Member-Name  Bound-To

    For a named import, the ordinal column is `<none>` and Member-Name is
    the imported symbol. The Hint is NOT an ordinal. For an ordinal import,
    the ordinal column contains the ordinal and Member-Name is `<none>`.

    llvm-readobj prints `Symbol: name (hint)` for named imports and an empty
    symbol name with the actual ordinal for ordinal imports. Its parenthetical
    number is a hint for named imports, not an ordinal.

    Returns {"dll_name.dll": [(symbol_name_or_Ordinal_N, ordinal_or_none), ...]}.
    """
    imports: dict[str, list[tuple[str, int | None]]] = defaultdict(list)
    current_dll: str | None = None

    llvm_dll_re = re.compile(r"^\s*Name:\s*(\S+\.dll)\s*$", re.IGNORECASE)
    llvm_sym_re = re.compile(r"^\s*Symbol:\s*(.*?)\s*\((\d+)\)\s*$")
    hex_vma_re = re.compile(r"^[0-9a-fA-F]+$")

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        # GNU objdump import-directory header.
        if stripped.lower().startswith("dll name:"):
            _, _, dll_part = stripped.partition(":")
            current_dll = dll_part.strip().lower()
            continue

        # llvm-readobj import-directory header.
        if m := llvm_dll_re.match(line):
            current_dll = m.group(1).lower()
            continue

        # Stop capturing after the import directory section in GNU objdump.
        if stripped.startswith((
            "The Export Tables",
            "The Exception Directory",
            "The Function Table",
            "The Attribute Certificate Table",
            "The Base Relocation",
            "The TLS Directory",
            "The Load Configuration",
            "The Debug Directory",
            "The Resource Directory",
            "PE File Base Relocations",
            "Dump of ",
            "Sections:",
        )):
            current_dll = None
            continue

        if not current_dll:
            continue

        # llvm-readobj --coff-imports:
        #   Symbol: CreateFileW (123)  -> named import, 123 is the hint
        #   Symbol:  (17)              -> ordinal import 17
        if m := llvm_sym_re.match(line):
            symbol = m.group(1).strip()
            value = int(m.group(2), 10)
            if symbol:
                imports[current_dll].append((symbol, None))
            else:
                imports[current_dll].append((f"Ordinal_{value}", value))
            continue

        parts = stripped.split()
        if not parts or not hex_vma_re.fullmatch(parts[0]):
            continue

        # GNU objdump also prints the terminating all-zero import descriptor
        # in this section. It is not a symbol row.
        if len(parts) >= 5 and all(
            re.fullmatch(r"0+", token) for token in parts[1:]
        ):
            continue

        # Current GNU objdump -p format:
        #   <vma> <ordinal|<none>> <hint|<none>> <member-name> [bound-to]
        # Crucially, for named imports the actual name is parts[3], not the
        # hint in parts[2].
        if len(parts) >= 4:
            ordinal_token = parts[1]
            member_name = parts[3]

            if ordinal_token.lower() != "<none>":
                ordinal = _parse_decimal_or_prefixed_int(ordinal_token)
                if ordinal is not None and 0 <= ordinal <= 0xFFFF:
                    imports[current_dll].append((f"Ordinal_{ordinal}", ordinal))
                continue

            if member_name.lower() != "<none>":
                imports[current_dll].append((member_name, None))
            continue

        # Older/compact objdump output accepted by the previous generator:
        #   <vma> <hint-or-ordinal> <symbol-name-or-<none>>
        if len(parts) >= 3:
            value_token, name = parts[1], parts[2]
            if name.lower() == "<none>":
                # In this compact representation the value is an ordinal.
                try:
                    ordinal = int(value_token, 16)
                except ValueError:
                    ordinal = _parse_decimal_or_prefixed_int(value_token)
                if ordinal is not None and 0 <= ordinal <= 0xFFFF:
                    imports[current_dll].append((f"Ordinal_{ordinal}", ordinal))
            elif name.lower() not in ("bound-to", "member-name"):
                imports[current_dll].append((name, None))

    # Deduplicate while preserving order.
    for dll in imports:
        seen = set()
        unique = []
        for entry in imports[dll]:
            if entry not in seen:
                seen.add(entry)
                unique.append(entry)
        imports[dll] = unique

    return dict(imports)


def sanitize_zig_ident(name: str) -> str:
    """Converts C++/mangled symbol names into valid Zig identifiers."""
    clean = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    if clean and clean.isdigit():
        clean = "_" + clean
    return clean


def generate_zig_files(imports: dict[str, list[tuple[str, int | None]]], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    registry_entries = []
    module_imports = []

    for dll, funcs in sorted(imports.items()):
        mod_base = sanitize_zig_ident(dll.removesuffix(".dll"))
        zig_file = out_dir / f"{mod_base}.zig"
        seen_fn_names: dict[str, int] = {}

        lines = [
            "// AUTO-GENERATED BY tools/gen_stubs.py — DO NOT EDIT MANUALLY",
            'const std = @import("std");',
            "",
        ]

        for orig_name, ordinal in funcs:
            base_fn = f"stub_{sanitize_zig_ident(orig_name)}"
            count = seen_fn_names.get(base_fn, 0)
            seen_fn_names[base_fn] = count + 1
            zig_fn = base_fn if count == 0 else f"{base_fn}_{count}"
            ord_str = str(ordinal) if ordinal is not None else "null"

            lines.extend([
                f"pub fn {zig_fn}() callconv(.{{ .x86_64_win = .{{}} }}) usize {{",
                f'    std.log.warn("[STUB] {dll}!{orig_name} (ord={ord_str})", .{{}});',
                "    return 0;",
                "}",
                "",
            ])

            registry_entries.append(
                f'    .{{ .dll = "{dll}", .name = "{orig_name}", .ordinal = {ord_str}, .ptr = @ptrCast(&{mod_base}.{zig_fn}) }},'
            )

        zig_file.write_text("\n".join(lines), encoding="utf-8")
        module_imports.append(f'pub const {mod_base} = @import("{mod_base}.zig");')

    # Write central IAT lookup registry.
    reg_lines = [
        "// AUTO-GENERATED CENTRAL IAT STUB REGISTRY",
        'const std = @import("std");',
        "",
        *module_imports,
        "",
        "pub const StubEntry = struct {",
        "    dll: []const u8,",
        "    name: []const u8,",
        "    ordinal: ?u16,",
        "    ptr: *const anyopaque,",
        "};",
        "",
        "pub const all_stubs = [_]StubEntry{",
        *registry_entries,
        "};",
        "",
        "pub fn resolve(dll_name: []const u8, func_name: ?[]const u8, ordinal: ?u16) ?usize {",
        "    for (all_stubs) |entry| {",
        "        if (!std.ascii.eqlIgnoreCase(entry.dll, dll_name)) continue;",
        "        if (func_name) |fname| {",
        "            if (std.mem.eql(u8, entry.name, fname)) return @intFromPtr(entry.ptr);",
        "        }",
        "        if (ordinal != null and entry.ordinal != null and entry.ordinal.? == ordinal.?) {",
        "            return @intFromPtr(entry.ptr);",
        "        }",
        "    }",
        "    return null;",
        "}",
        "",
    ]

    (out_dir / "registry.zig").write_text("\n".join(reg_lines), encoding="utf-8")


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python3 tools/gen_stubs.py <imports.txt> [output_dir]")
        sys.exit(1)

    imports_path = Path(sys.argv[1])
    out_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("src/shims/generated")

    raw_text = imports_path.read_text(encoding="utf-8", errors="replace")
    parsed = parse_imports(raw_text)

    if not parsed:
        print("Error: No DLL imports found. Check that imports.txt came from `objdump -p` or `llvm-readobj --coff-imports`.")
        sys.exit(1)

    generate_zig_files(parsed, out_dir)

    total_funcs = sum(len(v) for v in parsed.values())
    print(f"Generated {len(parsed)} DLL shim modules ({total_funcs} total stubs) in {out_dir}/")
    for dll, funcs in sorted(parsed.items()):
        print(f"  - {dll}: {len(funcs)} functions")


if __name__ == "__main__":
    main()
