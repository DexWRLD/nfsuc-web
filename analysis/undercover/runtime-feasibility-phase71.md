# Phase 71 — Runtime feasibility gate

Decision: NO-GO continued speculative provider-by-provider startup translation. GO one bounded hybrid execution-backend feasibility milestone. Keep the existing unified process authoritative. The native prototype passed, but no browser CPU engine was integrated and no original CRT provider executed.

## Evidence and actual prototype

The already installed Unicorn 2.0.1.post1 package contains a native DLL. Its Python wrapper cannot import on Python 3.12 because distutils is unavailable. tools/uc_x86_probe.py uses that installed DLL's documented C API through ctypes; nothing was installed, downloaded, redistributed or patched. The DLL SHA-256 is 5fa133c4b81f08042c3eeb93870333c91be9852932222dda16e72e35ee806b33.

Original authenticated code ranges are 0x009E7540–0x009E7597, 0x009E75A0–0x009E75CA and 0x009C1830–0x009C1893 (inclusive ends). Execution begins with a synthetic ECX receiver at 0x0189D0A0, an A5-filled 128-byte data fixture, bounded stack and explicit register sentinels. It follows the original nested calls: 138 original instruction tags, eight function entries across three bodies, 27 original data writes. This repeats already admitted constructor bodies; it adds no unique historical harness function and proves no startup reachability.

web/tools/uc-x86-reference.mjs executes the same fixture using the existing unified Wasm. General registers including final ESP/EIP, six arithmetic flags (mask 0x8D5), the complete instruction trace, nested entries, write journal and 128 data bytes match. System EFLAGS and full exception behavior were not compared. Another 105 synthetic ADD/SUB/NEG/DEC/SBB boundary cases match the Phase 67 Wasm flag implementation. Incoming carry is derived by executed subtraction. These are fixtures, not original game objects or provider executions.

Only reviewed function instruction starts may execute. A same-page attempt at 0x009E7000 is rejected. Source pages, bounded data and stack are mapped; no unavailable section is mapped. A 10,000-instruction budget bounds execution. This is an offline CPU oracle, not a second production game runtime.

Reproduce:

    python tools/uc_x86_probe.py "C:/Games/Need For Speed Undercover/nfs.exe" "C:/Users/999/.nfsuc-web/authorized-startup" --output analysis/undercover/x86-prototype-phase71.json

Timing uses 50 warmups and seven batches of 100 calls, keeping trace/write instrumentation enabled. Native median: 106.933 microseconds/call; current Wasm in Node: 30.174 microseconds/call. Python/C callbacks and Node checked-import overhead differ. These measurements do not compare browser engine cores or estimate gameplay FPS. An earlier timer-enabled trial incurred per-call timer-thread overhead; final evidence uses an instruction budget without that timer.

## A / B / C comparison

| Requirement | A: per-function RawLifter | B: general x86 + explicit Win32 services | C: hybrid with existing process |
|---|---|---|---|
| Instructions | Current fourteen reviewed bodies work; new semantics require implementation/admission | A reusable CPU covers many instructions; exact chosen backend coverage still needs tests | Retain known translations; route other admitted instructions through tested backend |
| EFLAGS | Existing explicit validity and Phase 67 arithmetic tests | CPU engine supplies architectural flags; undefined/system behavior still requires policy | Match validity and flags at every engine transition |
| FS/TLS/SEH | Explicit synthetic thread; normal prolog/epilog supported, exception dispatch incomplete | CPU segmentation is not Windows TLS or exception dispatch | Preserve one thread state and add real services only with contracts/provenance |
| PE layout | Authenticated ordinary section mappings and checked memory | Needs a PE loader and permission/address policy | Reuse existing descriptors, permissions and single authoritative memory |
| Indirect calls | Reviewed dispatcher rejects unknown targets | CPU can follow code addresses, but imported calls need verified binding | Shared dispatcher/import stop policy must stay enforced |
| CRT | Provider provenance unavailable; no resolved services | CPU alone does not implement or legitimately bind MSVCR80 | Same provenance blocker; no guessed pointer mapping |
| Win32 | Partial native harness contracts, not a complete browser OS | Large adapter surface: threads, synchronization, files, timing, exceptions | Reuse tested concepts incrementally, without generic success stubs |
| D3D9 | Existing inherited recording/WebGPU foundation; no authentic Undercover frame | CPU/Win32 execution does not supply D3D9 compatibility or GPU resources | Existing graphics bridge needs verified device/resource contracts |
| Browser | Current Wasm integration works | A native engine DLL is not browser-capable evidence | Browser adapter and shared memory are an unproved engineering gate |
| Performance | Current instrumented constructor baseline measured | Local native oracle measured; no browser backend benchmark | Benchmark equivalent real trace in the browser before adopting |
| Debugging | Original address tags, writes and fail-closed calls | CPU instruction hooks and budgets available in local probe | One comparable event schema and deterministic failure boundary |
| Testing | Existing constructor, flags, SEH, media and frontend regressions | Differential fixtures feasible, demonstrated locally | Require exact equivalence before replacing any production execution |
| Licensing | Repository MIT; original executable/assets excluded | Engine-specific license review needed; see primary sources below | Do not assume repository MIT applies to an integrated engine |
| Maintenance | Per-function work grows; unresolved providers stop progress | Reusable ISA support reduces translation work, OS/GPU work remains substantial | More transition complexity, potentially lower instruction-admission burden |
| Unavailable code | Cannot execute unavailable entry/dependencies | Emulation does not recover unavailable bytes or their behavior | No change to protected/unavailable boundaries |

## Concrete local components

- tools/lift.py and tools/uc_unified_build.py: translation/admission foundation; tools/uc_unified_flags.h: explicit flags.
- web/src/host/uc-process.ts and uc-unified.ts: checked guest memory, dispatcher and one WebAssembly.Memory. uc-thread.ts: explicit synthetic FS/thread fixtures, not original thread initialization.
- runtime/cpu.h and runtime/dispatch.c: native CPU-state and translated dispatch infrastructure; neither is a drop-in browser instruction emulator. runtime/web/gcpu.c records CPU timing; its name does not imply an emulator.
- runtime/uc_abi.h, uc_import.c and uc_import_table.inc: native HLE contracts. tools/uc_phase7_test.py replaces the original memset thunk; that test proves a host contract fixture, not original provider resolution.
- runtime/module.c: inherited SPEED2/server.dll assumptions and host import magic; not an authenticated Undercover loader. runtime/win32.c includes placeholder LoadLibrary/GetProcAddress behavior and cannot be admitted wholesale as proven Undercover behavior.
- runtime/heap.c: reusable allocation concepts, not evidence for the unavailable game allocator at 0x00686000.
- runtime/web/gpu_web.c, gpu_proto.h, host_abi.h and web/src/gpu/{encoder.ts,proto.ts,wgsl.ts}: D3D9/WebGPU transport and shader foundations; no original Undercover device publication or frame is proved.

No legacy code was deleted merely because of its origin.

## Primary-source engine assessment

[Unicorn source](https://github.com/unicorn-engine/unicorn) documents a CPU emulation framework. Its [2.0.1 API](https://raw.githubusercontent.com/unicorn-engine/unicorn/2.0.1/include/unicorn/unicorn.h) supplies memory, registers and hooks, used here. It supplies no Win32 service layer. The [core COPYING file](https://raw.githubusercontent.com/unicorn-engine/unicorn/2.0.1/COPYING) is GPLv2; the API header carries an LGPL notice. Installed metadata says UNKNOWN, so metadata alone is inadequate license clearance. No engine binary/source is redistributed in this phase. A browser build, footprint and redistribution compatibility were not established.

[v86](https://raw.githubusercontent.com/copy/v86/master/Readme.md) is a documented browser x86-to-Wasm PC emulator with x87/SSE support and documented instruction/platform limitations. Its [architecture](https://raw.githubusercontent.com/copy/v86/master/docs/how-it-works.md) combines interpretation and generated Wasm, including paging/TLB machinery. Its [license](https://raw.githubusercontent.com/copy/v86/master/LICENSE) is BSD-2-Clause. This makes it a browser-capable candidate for review, not a tested user-mode engine adapter. [Windows support](https://raw.githubusercontent.com/copy/v86/master/docs/windows-nt.md) involves an emulated PC and OS installation; it is not evidence of a drop-in Win32/D3D9 layer or shared-memory integration. Extracting/adapting its execution core is unproved. No v86 code was downloaded or integrated.

[Wine](https://raw.githubusercontent.com/wine-mirror/wine/master/README.md) provides Windows compatibility on supported host systems, with a loader and system integration. Its [license](https://raw.githubusercontent.com/wine-mirror/wine/master/LICENSE) is LGPL-2.1-or-later. It is not a demonstrated browser CPU backend. Porting it is a separate, substantial project. Neither Wine nor a full PC emulator solves this executable's unavailable entry/provider initialization.

## Measurable Phase 72 milestone: option 5

Implement only a reviewed browser-capable CPU adapter feasibility experiment. First establish a suitable available/approved dependency and its license/build; do not automatically install an unreviewed engine. Reuse the existing unified process and the Phase 69 connected root/constructor/wrapper/SEH/registrar prefix as the oracle.

Acceptance gates:

1. One authoritative guest memory and identical permission/range checks; no hidden second game state.
2. Actual original call edges, all registers and defined flags match; original FS normal-path state and stack behavior match. Preserve twelve entries, seven distinct bodies, nine callee returns and 27 PE-global writes for the control prefix.
3. Stop at the exact original 0x0087B5B3 call through unchanged [0x00B61398]=0x008AAC6A. Imported services executed stays zero. Reject unavailable code and unknown import dispatch, with an instruction budget.
4. Reduce the need for per-function instruction translation on this real chain. Count newly required adapters/semantics explicitly; reruns are not new unique functions.
5. All existing media, cache, flags, SEH, frontend and provider regressions pass. Record an equivalent instrumented browser benchmark against current Wasm; use a provisional engineering budget of at most 5x baseline for this diagnostic chain, not a gameplay performance claim.

If these gates cannot be met, stop browser CPU integration and document the specific failure. Do not resume bulk speculative helper translation. Even passing this milestone does not unlock original startup: effective provider binding, legitimate import execution, actual CRT/thread initialization, original-entry reachability, allocator/device/resource paths and D3D9 remain separate gates.
