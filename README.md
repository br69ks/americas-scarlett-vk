# americas-scarlett-loader

Experimental x86-64 compatibility loader for Project Americas (`Scarlett`) on Linux and Windows.

**Status:** Linux runs the real guest UCRT/VCRUNTIME/MSVCP through the pre-graphics platform and stops at the first `D3D12XboxCreateDevice` call, 20/20 runs. D3D12 and graphics are not implemented. Windows cross-builds but is not yet validated.

## Build and test

```bash
zig build -Doptimize=ReleaseFast
zig build -Dtarget=x86_64-windows -Doptimize=ReleaseFast
zig build test
python3 -m unittest discover -s tools -p 'test_*.py' -v
```

## Run

```bash
./zig-out/bin/americas-loader --game-dir /path/to/game /path/to/game_scarlett_master.exe
```

Unimplemented imports fail closed. `SCARLETT_STUB_POLICY=zero` is a debug-only escape hatch.

See [docs/ROADMAP.md](docs/ROADMAP.md) for milestone status.
