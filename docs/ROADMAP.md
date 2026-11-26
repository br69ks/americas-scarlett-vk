# Project Americas Compatibility Layer — Roadmap & Checklist

A cross-platform (Linux & Windows) High-Level Emulation (HLE) compatibility layer checklist for running `game_scarlett_master.exe` natively on x86-64 PCs using **Vulkan** and **SPIR-V**.

## Status (2026-11-26)

- Linux and Windows builds are green (Zig 0.17.1) after the latest UCRT/unwind changes.
- **Linux:** the loader now maps and initializes the real guest `ucrtbase.dll` (TLS callbacks and `DllMain`), followed by VCRUNTIME140, VCRUNTIME140_1, and MSVCP140. The current stop is MSVCP140's `DllMain` C++ exception path: `RtlVirtualUnwind` decodes the UCRT/MSVCP frame correctly, but exception dispatch repeatedly unwinds the same frame and crashes. `srand` is not reached in the current build.
- **Audio/RPF:** the engine's `audio.rpf` file device is created, wrapped in a `9FPR` pack object, registered through the engine manager, and re-keyed to `audio:/`. The pack path reaches the engine audio path without the old helper NOP on the successful branch.
- **Windows:** the guest LastError state is now guest-TEB based, the host thunk is stack-neutral and preserves `r12`, and the VEH switches to the host TEB before writing. Windows now passes CPU topology, XMem, GDK initialization, and VCRUNTIME140 `DllMain`. Its next failure was a guest `memset` with a bad `0x1400000` pointer; this has not been revisited after the latest Linux changes.
- Audit steps 2, 4, 6, and 7 are complete; 3 and 5 remain partial.

## Windows Parity Blockers

- Host/guest TEB state is now separated for LastError and the VEH report path; the stack-neutral call gate preserves arguments and guest `r12`.
- Windows still needs validation after the latest UCRT/unwind work; the last verified stop was a bad guest `memset` pointer in the CRT DllMain path.
- Windows has not been revalidated with the current tree and matching PDB.

## Linux Runtime Blockers

- **CRT/UCRT:** real `ucrtbase.dll` now loads, but MSVCP140 `DllMain` raises a C++ exception. The unwind shim's bitfield order and opcode table were corrected (`SAVE_NONVOL`, `ALLOC_SMALL`, `PUSH_NONVOL`, XMM ops), but the exception-handler/`RtlUnwindEx` path repeatedly unwinds the same UCRT frame instead of dispatching.
- **Audio initialization:** pack mount and manager re-key are implemented; early manager initialization must not run before the guest CRT is ready (doing so corrupts the CRT allocator object).
- **Engineering patches:** the GDK supported-version byte at `0x143751f71` is still an engine input correction; it should be replaced by correct GDK version initialization.

## Implementation Checklist

- [x] **Binary Loader (core):** Map the EXE and its DLLs, apply relocations, resolve the IAT, parse exports, run TLS callbacks and `DllMain`, and expose per-module `GetProcAddress`/`LoadLibrary`. **Remaining:** map all 16 shipped DLLs; GDK DLLs are still HLE shims.
- [ ] **OS Kernel Shim (core):** TEB/PEB with `ProcessParameters`, stack bounds, TLS/FLS, futex-backed sync objects, thread creation, read-write file I/O, and `.pdata` lookup exist. **Remaining:** full `RtlVirtualUnwind`/SEH dispatch and many lower-level APIs.
- [ ] **Unified Memory (UMA) — partial:** `XMemAlloc`/`XMemVirtualAlloc` use host `mmap` with `MAP_NORESERVE`; `XMemAllocatePhysicalPages` is still a no-op and there is no dirty-page/VRAM tracking.
- [ ] **Asset Streaming — partial:** DStorage factory/file/queue shims and synchronous reads work; `RPF9` packfile parsing/decryption, BCPack/`chad`, and async queues are not implemented.
- [ ] **Offline Shader Lifter:** Not started (target: ~26,500 RDNA 2 shaders to SPIR-V).
- [ ] **Pre-Lifted Shader Pack:** Not started (Zstd `.spv` archive + `VkPipelineCache`).
- [ ] **Vulkan Backend:** Not started (D3D12→Vulkan, `xg_xs` layouts, mesh shaders, ray tracing).
- [ ] **PSO & Display:** Not started (async PSO compile, VRR/HDR swapchain).
- [ ] **Audio & Input — input skeleton only:** `IGameInput` COM singleton exists; XAudio2/FAudio and `xapu`/`AcpHal` are not implemented.
- [ ] **QA & Profiling:** Unit tests added; no CI, RenderDoc, or stress testing yet.

## Audit Follow-ups (steps 2–7)

- [ ] **2. Truthful crash handling — partial:** `int3` reports and aborts; a GDK version-field patch and pack re-key remain as engine-input corrections.
- [ ] **3. Signature-aware / fail-safe stubs — partial:** generated stubs now fail closed via `stub_policy.zig`; signature-aware generation is still missing.
- [x] **4. Recursive DLL loader:** exports, per-module `GetProcAddress`, TLS callbacks, and `DllMain`.
- [ ] **5. `.pdata` / SEH — partial:** registration, lookup, context capture, opcode/bitfield decoding, and filters exist; C++ exception dispatch/handler unwinding still loops on the MSVCP/UCRT frame.
- [x] **6. Real TEB/PEB + sync:** `ProcessParameters`, TLS callbacks, futex-backed objects, and `clone`-based guest threads.
- [x] **7. Read-write file I/O:** configurable game/save directories; Linux implementation is complete, Windows path is guarded.

## Runtime Loading Pipeline

1. **Host Launcher (`americas-loader`):** Starts the native ELF (Linux) or PE (Windows) host wrapper.
2. **Pre-Lifted Shader Mount:** Loads the Zstd-compressed `.spv` shader pack and disk-cached `VkPipelineCache` (not implemented).
3. **Virtual Memory Mapping:** Allocates executable host pages (`mmap` / `VirtualAlloc`) and copies `.text` and `.data` sections into place for the executable and shipped DLLs.
4. **IAT & EAT Hooking:** Redirects `api-ms-win-*`, `XCRDAPI.dll`, `xmem.dll`, and `d3d12_xs.dll` imports to native compatibility shim functions (`.x86_64_win`) and logging trampolines.
5. **Context Initialization:** Initializes the Vulkan device, UMA dirty-page tracker, async I/O workers, and Xbox Thread/Process Environment Block (`GS` segment TEB/PEB) registers.
6. **Entry Point Jump:** Transfers execution to `AddressOfEntryPoint` for native x86-64 execution.
