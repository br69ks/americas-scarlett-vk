# Project Americas Compatibility Layer — Roadmap & Checklist

A cross-platform (Linux & Windows) High-Level Emulation (HLE) compatibility layer checklist for running `game_scarlett_master.exe` natively on x86-64 PCs using **Vulkan** and **SPIR-V**.

## Status (2026-11-25)

- Linux and Windows builds are green (Zig 0.17.1).
- The loader now maps the EXE, loads `vcruntime140`/`vcruntime140_1`/`msvcp140`, starts guest threads, and initializes XMem, GameInput, and DStorage.
- It reaches asset mounting, then dies because `fiDevice::Open` returns a null `RPF9` packfile handle (RVA `0x2237320`).
- Audit steps 2, 4, 6, and 7 are done; steps 3 and 5 are partial.
- Tests, the GPU/shader layer, and audio are still missing.

## Implementation Checklist

- [x] **Binary Loader (core):** Map the EXE and its DLLs, apply relocations, resolve the IAT, parse exports, run TLS callbacks and `DllMain`, and expose per-module `GetProcAddress`/`LoadLibrary`. **Remaining:** map all 16 shipped DLLs; GDK DLLs are still HLE shims.
- [x] **OS Kernel Shim (core):** TEB/PEB with `ProcessParameters`, stack bounds, TLS/FLS, futex-backed sync objects, thread creation, read-write file I/O, and `.pdata` lookup. **Remaining:** full `RtlVirtualUnwind`/SEH dispatch and many lower-level APIs.
- [ ] **Security & Auth:** **Out of scope.** Xbox hypervisor/XSP DRM/licensing checks are not stubbed; circumventing them is not part of this project.
- [ ] **Unified Memory (UMA) — partial:** `XMemAlloc`/`XMemVirtualAlloc` use host `mmap` with `MAP_NORESERVE`; `XMemAllocatePhysicalPages` is still a no-op and there is no dirty-page/VRAM tracking.
- [ ] **Asset Streaming — partial:** DStorage factory/file/queue shims and synchronous reads work; `RPF9` packfile parsing/decryption, BCPack/`chad`, and async queues are not implemented.
- [ ] **Offline Shader Lifter:** Not started (target: ~26,500 RDNA 2 shaders to SPIR-V).
- [ ] **Pre-Lifted Shader Pack:** Not started (Zstd `.spv` archive + `VkPipelineCache`).
- [ ] **Vulkan Backend:** Not started (D3D12→Vulkan, `xg_xs` layouts, mesh shaders, ray tracing).
- [ ] **PSO & Display:** Not started (async PSO compile, VRR/HDR swapchain).
- [ ] **Audio & Input — input skeleton only:** `IGameInput` COM singleton exists; XAudio2/FAudio and `xapu`/`AcpHal` are not implemented.
- [ ] **QA & Profiling:** Not started; no automated tests or CI yet.

## Audit Follow-ups (steps 2–7)

- [x] **2. Truthful crash handling:** `int3` reports RIP−1 and aborts; hard-coded RVA patches are gone.
- [ ] **3. Signature-aware / fail-safe stubs:** many handwritten shims added, but generated stubs still return `0` instead of failing.
- [x] **4. Recursive DLL loader:** exports, per-module `GetProcAddress`, TLS callbacks, and `DllMain`.
- [ ] **5. `.pdata` / SEH — partial:** registration, lookup, context capture, and filters exist; full unwind/EH dispatch is incomplete.
- [x] **6. Real TEB/PEB + sync:** `ProcessParameters`, TLS callbacks, futex-backed objects, and `clone`-based guest threads.
- [x] **7. Read-write file I/O:** configurable game/save directories; Linux implementation is complete, Windows path is guarded.

## Runtime Loading Pipeline

1. **Host Launcher (`americas-loader`):** Starts the native ELF (Linux) or PE (Windows) host wrapper.
2. **Pre-Lifted Shader Mount:** Loads the Zstd-compressed `.spv` shader pack and disk-cached `VkPipelineCache` (not implemented).
3. **Virtual Memory Mapping:** Allocates executable host pages (`mmap` / `VirtualAlloc`) and copies `.text` and `.data` sections into place for the executable and shipped DLLs.
4. **IAT & EAT Hooking:** Redirects `api-ms-win-*`, `XCRDAPI.dll`, `xmem.dll`, and `d3d12_xs.dll` imports to native compatibility shim functions (`.x86_64_win`) and logging trampolines.
5. **Context Initialization:** Initializes the Vulkan device, UMA dirty-page tracker, async I/O workers, and Xbox Thread/Process Environment Block (`GS` segment TEB/PEB) registers.
6. **Entry Point Jump:** Transfers execution to `AddressOfEntryPoint` for native x86-64 execution.
