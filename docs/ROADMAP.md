# Project Americas Compatibility Layer — Roadmap & Checklist

A cross-platform (Linux & Windows) High-Level Emulation (HLE) compatibility layer checklist for running `game_scarlett_master.exe` natively on x86-64 PCs using **Vulkan** and **SPIR-V**.

## Implementation Checklist

- [ ] **Binary Loader:** Map `game_scarlett_master.exe` and console DLLs into host virtual memory.
- [ ] **OS Kernel Shim:** Reimplement `kernelx.dll` and `xgameruntime.dll` threads, sync primitives, and timers on Linux/Windows.
- [ ] **Security & Auth:** Stub out Xbox hypervisor calls, XSP DRM checks, and Xbox Live authentication.
- [ ] **Unified Memory (UMA):** Bridge shared `XMemAlloc` allocations to discrete PC RAM and GPU VRAM with dirty-page tracking.
- [ ] **Asset Streaming:** Emulate BCPack decompression and map Velocity I/O queues to `io_uring` / Windows async I/O.
- [ ] **Offline Shader Lifter:** Batch-disassemble all ~26,500+ RDNA 2 shaders into portable **SPIR-V** modules ahead of time.
- [ ] **Pre-Lifted Shader Pack:** Bundle the lifted `.spv` blobs into a Zstd-compressed, hash-indexed archive with a JIT fallback lifter for edge cases.
- [ ] **Vulkan Backend:** Translate Direct3D 12.X ring-buffer commands, mesh shaders, and ray tracing to native **Vulkan**.
- [ ] **PSO & Display:** Async-compile the shader pack into a disk-cached `VkPipelineCache`, unlock frame rates, and configure VRR/HDR swapchains.
- [ ] **Audio & Input:** Decode XMA/Opus audio on CPU threads, map controllers/raw mouse-keyboard via SDL3, and redirect local saves.
- [ ] **QA & Profiling:** Fix rendering bugs in RenderDoc, minimize RAM-VRAM copies, and stress-test stability under heavy load.

## Runtime Loading Pipeline

1. **Host Launcher (`gta6_loader`):** Starts the native ELF (Linux) or PE (Windows) host wrapper.
2. **Pre-Lifted Shader Mount:** Loads the Zstd-compressed `.spv` shader pack and disk-cached `VkPipelineCache`.
3. **Virtual Memory Mapping:** Allocates executable host pages (`mmap` / `VirtualAlloc`) and copies `.text` and `.data` sections into place.
4. **IAT Hooking:** Redirects `kernelx.dll`, `xgameruntime.dll`, and `d3d12_x.dll` imports to native compatibility shim functions (`ms_abi` / `.win64`).
5. **Context Initialization:** Initializes the Vulkan device, UMA dirty-page tracker, async I/O workers, and Xbox Thread Environment Block (TEB) registers.
6. **Entry Point Jump:** Transfers execution to `AddressOfEntryPoint` for native x86-64 execution.
