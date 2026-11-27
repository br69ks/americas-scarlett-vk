# Linux Debug State — D3D12XboxCreateDevice boundary

Goal (current): correctness up to the **first `D3D12XboxCreateDevice` call only**.
`D3D12XboxCreateDevice` itself and everything after it (device objects, queues,
swapchain, PSOs) must **not** be implemented, emulated, or bypassed.

Build: `zig build -Doptimize=ReleaseFast`
Run: `./zig-out/bin/americas-loader --game-dir /home/brad/GTA6.Xbox.v1.0.2.1 /home/brad/GTA6.Xbox.v1.0.2.1/game_scarlett_master.exe`

## Result (2026-11-26): 20/20

Harness: run 20 times, require exactly one `[BOUNDARY] D3D12XboxCreateDevice`
line and loader exit code 0.

```
for i in $(seq 1 20); do
  out=$(./zig-out/bin/americas-loader --game-dir … game_scarlett_master.exe 2>&1); rc=$?
  printf '%s' "$out" | grep -c '\[BOUNDARY\] D3D12XboxCreateDevice'   # 1
  echo "rc=$rc"                                                       # 0
done
```

Result: **20/20 runs** reached the boundary (one boundary line each, exit code 0),
with no `[STUB]` aborts, no `[CALL]` zero-return trampolines and no `[SRAND]`
milestone line.

```
20x harness: boundary=1 rc=0 call=0 stub=0 fatal=0  ->  pass=20 fail=0
zig build test -> 48/48 tests passed
zig build -Dtarget=x86_64-windows -Doptimize=ReleaseFast -> OK
```

Boundary tail of a run:

```
info: [WINDOW] RegisterClassExA("sgaWindowClass") -> atom 0xc000
info: [WINDOW] CreateWindowExA(class="sgaWindowClass", title="Americas") -> hwnd 0x10001
info: [BOUNDARY] D3D12XboxCreateDevice(rcx=0x0, rdx=0x7f9f8afbc8c0, r8=0x1461e0638, r9=0x1475df048)
info: [BOUNDARY] caller g:\game_scarlett_master.exe+0x24785bc
info: [BOUNDARY] stopping before D3D12 device creation (no D3D12 implementation); exit code 0
```

The guest call site is exe RVA `0x24785b7`
(`D3D12XboxCreateDevice(NULL adapter, params*, riid*, ppDevice*)`), so the raw
arguments above are: `rcx` = adapter = NULL, `rdx` = parameters on the guest
stack, `r8` = REFIID data pointer, `r9` = `ppDevice`.

## Exit behaviour

The boundary is a deliberate clean stop: `src/shims/d3d12_xs.zig` logs the call
and calls `std.process.exit(0)`. There is no generic fail-closed `[STUB]` abort
and no partial D3D12 stub.

## Pre-graphics correction batch (2026-11-26)

Live/correctness fixes before any D3D12 work. No engine/GDK/IAT byte patches.

1. **Unknown imports fail closed.** `pe_loader.logUnimplementedCall` no longer
   returns 0: it logs `[CALL] unimplemented ...; failing closed` and delegates to
   `stub_policy.missing`, so an unexpected import aborts like the
   generated stubs (benign/optional APIs and `SCARLETT_STUB_POLICY=zero` keep
   their documented zero-return behaviour). The 20 boundary runs call none of
   the remaining dormant trampolines (ucrtbase still has 44 patched-but-unused
   imports; each now aborts if called).
2. **Real core APIs** (`src/shims/crt_core.zig`, `src/shims/win32_fs.zig`,
   `src/shims/crt_extra.zig`): `GetCurrentThreadStackLimits` (guest TEB
   StackBase/StackLimit), `GetCurrentThread` (`(HANDLE)-2`), `GetProcessId`,
   `GetACP` = 1252, `GetOEMCP` = 437, `IsValidCodePage` (needed once GetACP
   returns 1252), `GetStdHandle`/`SetStdHandle`/`GetFileType` backed by the host
   std fds through the file handle table, and `GetSystemTimePreciseAsFileTime`
   aliased to the existing `GetSystemTimeAsFileTime` (both write a FILETIME).
3. **File API LastError contracts** (`src/shims/win32_fs.zig`): host errno is
   translated per Win32: `CreateDirectoryW` EEXIST -> FALSE +
   ERROR_ALREADY_EXISTS (183), `GetFileAttributesW/A`/`GetFileAttributesExW`/
   `SetFileAttributesW` ENOENT -> INVALID/FALSE + ERROR_FILE_NOT_FOUND (2) and
   EACCES/EPERM -> ERROR_ACCESS_DENIED (5), `RemoveDirectoryW` (2/145/5),
   `DeleteFileW` (2/5), `MoveFileExW` (2/5/17/183) and related attribute calls.
   Attribute queries now use `statx` so "missing" and "denied" are distinguishable.
4. **Per-thread exit** (`src/thread_exit.zig`, `src/teb.zig`, `src/sync.zig`):
   `ExitThread`, `RtlExitUserThread` and `_endthreadex` (and a normal return
   from a guest thread entry) now terminate only the calling thread: they run
   DLL_THREAD_DETACH + module TLS callbacks, then the FLS destructors (after the
   UCRT has freed its PTD and cleared its FLS slot in its own DllMain), publish
   the exit code and wake waiters, switch off the guest TEB on Windows, release
   the guest TEB/TLS allocations, and finally use `SYS_exit` (never
   `exit_group`). `ExitProcess`/`TerminateProcess` remain process-wide.
5. **GetExitCodeThread** returns the stored exit code (`sync.ThreadObj.code`)
   and accepts the `GetCurrentThread` pseudo handle; invalid handles report
   ERROR_INVALID_HANDLE. Threads report STILL_ACTIVE until they exit.

The boundary run does not exit any engine thread before the D3D12 call, so the
per-thread-exit path is covered by unit tests (exit codes, waiters, FLS
allocation bookkeeping) plus review, not by the 20x boundary harness.

## Loader checkpoint hardening (2026-11-26)

Pre-thread audit M1–M3, H4, M11–M13, L5/L6. Boundary/exit behaviour unchanged.

1. **Loader serialization.** New `src/loader_lock.zig` is a process-wide
   *recursive* lock. It is held across `loadLibrary*`, `loadModulePath`,
   `patchImports`, `loadExecutable`, `freeLibrary`, TLS callback/`DllMain`
   thread attach-detach and process detach, so module registry entries and TLS
   publishes are atomic with respect to other guest threads.
   `TrampolineArena.emit`/`emitThunk` now allocate slots under their own lock
   (stubs can be emitted by guest `GetProcAddress` after startup).
2. **Handles and thread IDs.** Guest handles and thread IDs come from atomic
   counters (`crt_core`), and `sync` handle-table entries are reference
   counted: `lookup` acquires, `releaseRef` drops, `CloseHandle` only drops the
   table reference. Waiters keep the object alive while blocked, and a slot
   recycled by `CloseHandle` can never be confused with the old object.
   Thread exit publishes its exit code through an acquired thread reference
   (`sync.acquireThreadRef` → `thread_exit` → `sync.markThreadExitedRef`), not
   through the guest handle value.
3. **Late-loaded module TLS.** `teb.zig` keeps a registry of every guest TEB.
   Allocating a module TLS slot (`allocModuleTls`) publishes the template and
   clones the block into every registered thread's own TEB (under the loader
   lock); later threads clone from the published template. The registry lives
   in `teb.zig` and is platform-neutral, so the Windows guest-TEB path behaves
   the same.
4. **Virtual guest paths.** `module.Module` now keeps the host path (`path`,
   internal) and the guest-visible `virtual_path` (`G:\<dll>`). PEB Ldr
   `FullDllName`, `GetModuleFileNameW` (via Ldr) and `GetModuleFileNameA`
   report `G:\…`; `PEB.ProcessParameters.DllPath` is `G:\`. Loader logs keep
   host paths.
5. **PE stack sizes.** `pe_loader.readStackSizes` parses
   `SizeOfStackReserve`/`SizeOfStackCommit` into `MappedImage` and
   `teb.Process`. The main guest thread's `StackLimit` becomes
   `StackBase - SizeOfStackReserve` (clamped to the real host stack), and
   `CreateThread(0)` uses the executable's reserve as the process default.
   Thread TEB bounds still reflect the requested size; the Clamp is
   `teb.guestStackLimit`.
6. **Cleanups.** Removed 33 dead duplicate/no-op sync resolve entries from
   `crt_core` (every resolve chain consults `sync_shims` first), guarded the
   `_tls_index` write to an in-image, aligned VA, removed the `+0x1000` TLS
   overallocation (blocks are exactly raw template + zero fill, with a
   zero-size guard), and made the guest handle/tid counters atomic.
7. **Tests (48 total).** Added: recursive loader lock (recursion + cross-thread
   exclusion), handle reference kept across `CloseHandle` + slot reuse, late
   module TLS clone into every registered TEB, host/virtual module paths,
   PE stack-size parsing, guest stack-limit computation, plus the earlier
   thread-exit/FLS/core-API/FS-LastError tests.

## srand milestone removed

- `src/loader.zig` no longer routes `srand` to a loader shim; the guest's
  `api-ms-win-crt-utility-l1-1-0.dll!srand` import resolves through the normal
  Linux CRT path to the **real guest `ucrtbase.dll`** (`srand` at
  `ucrtbase+0x82960`).
- `src/shims/crt_core.zig`'s `shim_srand` no longer logs `[SRAND]` or exits; it
  is now just a correct seed setter and is unused while the guest UCRT exports
  `srand`.
- Verified the real implementation executes: a temporary trace showed
  `srand import resolved to guest ucrtbase … (rva 0x82960)` and
  `real guest ucrtbase srand called: seed=<time(NULL)>`, and execution then
  continued to the boundary. The trace instrumentation was removed afterwards.

## Boundary implementation

- **New** `src/shims/d3d12_xs.zig`: models only the first
  `D3D12XboxCreateDevice` call as a boundary — logs the raw Win64 register
  arguments and the guest caller (module + RVA), then exits 0. Nothing after the
  call is implemented.
- `src/loader.zig` wires that shim into `shimResolve` / `resolveShimByName` so
  it takes precedence over the generated `d3d12_xs.dll` stub.

## Retained fixes from the previous milestone (no byte patches/bypasses)

- UCRT TEB `ReservedForCrt` (0x1820), Windows 10 `VerifyVersionInfoW`, single TLS
  index allocator, real UCRT PTD, per-thread guest TEB.
- `CREATE_SUSPENDED` honoured (`ResumeThread`/`SuspendThread` gates).
- Guest threads via `pthread_create` (per-thread glibc TLS); guest `StackBase` =
  host stack top, `StackLimit` = `StackBase - requested_size`.
- Fixed Linux unimplemented-import trampoline register clobber (`mov rsi,r11`).
- `HeapSize`, `SystemFunction036`/`RtlGenRandom`, `XMemAllocatePhysicalPages` /
  `XMemFreePhysicalPages` (GDK BOOL contract, UMA page arena).
- Headless windowing HLE (`RegisterClassExA`, `CreateWindowExA`, `ShowWindow`,
  `DefWindowProcA`, `PeekMessageA`, `DispatchMessageA`, `TranslateMessage`).

## Next step (not implemented)

`D3D12XboxCreateDevice` onward: device creation, command queues, swapchain,
PSOs — i.e. the D3D12→Vulkan backend.

## Appendix: previous UCRT root cause (resolved)

`ucrtbase+0x23b54` was `__dcrt_initialize_narrow_environment` indexing
`_environ_table`; `ucrtbase+0x92fc` is the `__crt_state_management`
global-state-index getter. TEB+0x1820 is `ReservedForCrt`, not a PTD pointer:
the UCRT keeps the per-thread state index there (0 = normal, 1 = inside an OS
call) when `VerifyVersionInfoW` reports Windows 10+. Unimplemented
`VerifyVersionInfoW`/`VerSetConditionMask` pushed the UCRT onto the pre-Win10
FLS slot, and two independent TLS index allocators made that slot alias the
exe's image-TLS block. Fixed by modelling `ReservedForCrt`, reporting Windows
10, unifying TLS index allocation, and letting the UCRT own its PTD.
