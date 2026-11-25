# Project Americas Compatibility Layer — Roadmap & Checklist

A cross-platform (Linux & Windows) High-Level Emulation (HLE) compatibility layer checklist for running `game_scarlett_master.exe` natively on x86-64 PCs using **Vulkan** and **SPIR-V**.

## Implementation Checklist

- [ ] **Binary Loader:** Map `game_scarlett_master.exe` and the 16 shipped game DLLs (`msvcp140`, `concrt140`, etc.) into host virtual memory with EAT/IAT resolution.
- [ ] **OS Kernel Shim:** Reimplement `pi-ms-win-core-`, `api-ms-win-crt-`, and `XCRDAPI.dll` threads, sync primitives, timers, and package mounts on Linux/Windows.
- [ ] **Security & Auth:** Stub out Xbox hypervisor calls, XSP DRM checks, and offline network clients (`libHttpClient.GDK.dll`, `XCurl.dll`, `WINHTTP.dll`).
- [ ] **Unified Memory (UMA):** Implement `xmem.dll` (`XMemAlloc`/`XMemFree`) to bridge shared allocations to discrete PC RAM and GPU VRAM with dirty-page tracking.
- [ ] **Asset Streaming:** Emulate `chad.dll` BCPack decompression and map async I/O queues to `io_uring` / Windows async I/O.
- [ ] **Offline Shader Lifter:** Batch-disassemble all ~26,500+ RDNA 2 shaders into portable **SPIR-V** modules ahead of time.
- [ ] **Pre-Lifted Shader Pack:** Bundle the lifted `.spv` blobs into a Zstd-compressed, hash-indexed archive with a JIT fallback lifter for edge cases.
- [ ] **Vulkan Backend:** Translate `d3d12_xs.dll` ring-buffer commands, `xg_xs.dll` texture layouts, mesh shaders, and `XboxBvhBuilder.dll` ray tracing to native Vulkan.
- [ ] **PSO & Display:** Async-compile the shader pack into a disk-cached `VkPipelineCache`, unlock frame rates, and configure VRR/HDR swapchains via SDL3 (`ext-ms-win-rtcore-ntuser-*`).
- [ ] **Audio & Input:** Route `XAudio2_9.dll` to FAudio, decode `xapu.dll`/`AcpHal.dll` audio on CPU threads, map `GameInput.dll` to SDL3, and redirect local saves.
- [ ] **QA & Profiling:** Fix rendering bugs in RenderDoc, minimize RAM-VRAM copies, and stress-test stability under heavy load.

## Runtime Loading Pipeline

1. **Host Launcher (`americas-loader`):** Starts the native ELF (Linux) or PE (Windows) host wrapper.
2. **Pre-Lifted Shader Mount:** Loads the Zstd-compressed `.spv` shader pack and disk-cached `VkPipelineCache`.
3. **Virtual Memory Mapping:** Allocates executable host pages (`mmap` / `VirtualAlloc`) and copies `.text` and `.data` sections into place for the executable and shipped DLLs.
4. **IAT & EAT Hooking:** Redirects `api-ms-win-*`, `XCRDAPI.dll`, `xmem.dll`, and `d3d12_xs.dll` imports to native compatibility shim functions (`.x86_64_win`) and logging trampolines.
5. **Context Initialization:** Initializes the Vulkan device, UMA dirty-page tracker, async I/O workers, and Xbox Thread/Process Environment Block (`GS` segment TEB/PEB) registers.
6. **Entry Point Jump:** Transfers execution to `AddressOfEntryPoint` for native x86-64 execution.
