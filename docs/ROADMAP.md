# Roadmap

Goal: run Project Americas natively on x86-64 Linux/Windows with Vulkan.

## Status

Linux reaches the first `D3D12XboxCreateDevice` call in 20/20 runs and stops there deliberately. Real guest UCRT/VCRUNTIME/MSVCP and the pre-graphics platform are working; D3D12/graphics are not implemented. Tests pass; Linux Debug/ReleaseFast and Windows cross-builds succeed. Windows runtime is unvalidated.

The boundary is an explicit log-and-exit, not a D3D12 implementation.

## Pre-graphics checkpoints

- [x] **Binary Loader:** PE/DLL mapping, exports/IAT, TLS/DllMain, loader lock, handles, virtual module paths.
- [x] **OS Kernel Shim:** TEB/PEB, per-thread TLS, threads/suspend, sync, SEH/unwind, signals, window/input, file I/O.
- [x] **Unified Memory (UMA):** reservations/commit/release, XMem alloc/free, physical pages, shared aliasing, stats hooks.
- [x] **Asset Streaming:** DStorage `IDStorageFileX`, queues/status/events, overlapped I/O; guest parses RPF9.

These are complete for the pre-`D3D12XboxCreateDevice` path. Compressed streaming, saves/DLC, full input, and audio remain fail-closed or disabled.

## Graphics milestones

- [ ] Offline shader lifter (RDNA 2 → SPIR-V).
- [ ] Pre-lifted shader pack + pipeline cache.
- [ ] D3D12 → Vulkan backend.
- [ ] PSO/display, swapchain, VRR/HDR.
- [ ] Audio and full input.
- [ ] QA/profiling.

## Known limits

- D3D12XboxCreateDevice is the deliberate stop.
- DStorage compression is rejected, not decompressed.
- XPackage saves/DLC are unimplemented.
- Real evdev input is unverified on this host; audio is cleanly disabled.
- Windows is not yet at Linux parity.
