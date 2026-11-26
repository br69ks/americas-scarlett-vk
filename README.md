# americas-scarlett-loader

Experimental cross-platform (Linux/Windows) x86-64 compatibility loader and Vulkan translation layer for Project Americas (`Scarlett`) binaries.

## Quick Start

1. **Generate IAT fallback stubs from an import dump:**
   ```bash
   python3 tools/gen_stubs.py imports.txt src/shims/generated
   ```

2. **Build the loader (Linux native):**
   ```bash
   zig build -Doptimize=ReleaseFast
   ```

3. **Cross-compile for Windows from Linux:**
   ```bash
   zig build -Dtarget=x86_64-windows -Doptimize=ReleaseFast
   ```

4. **Run against extracted executable:**
   ```bash
   ./zig-out/bin/americas-loader /path/to/game_scarlett_master.exe
   ```

5. **Run tests:**
   ```bash
   zig build test
   python3 -m unittest discover -s tools -p 'test_*.py' -v
   ```

Generated stubs fail closed: an unimplemented API aborts with `[STUB] ...`.
Set `SCARLETT_STUB_POLICY=zero` to restore the old zero-return behaviour when
debugging a specific path.

## Project Roadmap
See [docs/ROADMAP.md](docs/ROADMAP.md) for the milestone checklist and runtime loading pipeline.
