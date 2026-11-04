# Phase 72 â€” Browser x86 backend feasibility

2026-11-04. Decision: **NO-GO adoption of the measured adapter; original-byte browser differential succeeded.** The new engine executes the complete existing connected control without new handwritten function translations, but exceeds the established <=5x performance gate. Production remains translated Wasm. No CRT/startup/menu/gameplay advancement is claimed.

## Baseline and evidence

Baseline HEAD 00dda382 follows Phase 71 implementation 58d29cfd. main was twenty ahead of local origin/main. All 22 pre-existing discord-bot deletions were preserved; no fetch/push.

Read Phase 71 runtime/handoff/feasibility, native prototype and ordinary-import evidence; reviewed the retained Phase 69/70/71 Edge traces, shared process/dispatcher/thread/registry, private delivery, Phase 60 nine-case revalidation and preflight. Source executable SHA remains 6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd; master SHA remains f293d93d31fcbf86ad9b9639f2cf10c34defe9c621cfe7f1a5e975f598ddf88a. Preflight validates both. Original executable is read as data, never launched or modified.

No legacy binding investigation was reopened. The original [0x00B61398]=0x008AAC6A remains unchanged; no image-base correction, identity decoder, entropy, cookie, encoded sentinel or successful provider result was supplied. Unavailable code and assets were not executed, reconstructed, decrypted or patched.

## Candidate review and selection

Selected **Unicorn.js x86 2.1.4**, an established Emscripten/Wasm port, as an opt-in browser experiment. Published package gitHead: 560284c59c11c8d6c94d537f4354339f069ddcdf; Unicorn core submodule: 8028ec436f2d9376525352dd38ed9ed6b9f6be10. API version reported in Edge is 0x020104FF. This differs from Phase 71's installed native 2.0.1.post1 oracle and is independently tested here.

Reviewed pinned package metadata, wrapper, x86 constants/tests, hooks, build script, TCI/helper-adapter patches and core COPYING before integration. Source [README/package](https://github.com/AlexAltea/unicorn.js/tree/560284c59c11c8d6c94d537f4354339f069ddcdf) documents the Wasm variant and build. Package/core are GPLv2; this is not absorbed into the repository's MIT license. Any future redistribution requires retaining applicable notices and GPL terms and supplying corresponding source/build materials as required; MIT application licensing alone does not clear a combined distributed product. No engine binary or third-party source is committed, no production dependency is installed, and no engine URL is added to the LAN manifest. The engine was served only to the isolated loopback Edge test.

The source build uses CMake/Emscripten, SINGLE_FILE/WASM_BIGINT, a restored TCG interpreter and uniform helper adapters. Published x86-only output is 915,283 bytes. The pinned tarball's registry SHA-512 integrity and extracted JS SHA-256 643adbbb0c77eadb71182f116c9da0860814221a25194dac3ed561589929ef6d are verified. tools/uc_browser_x86_prepare.py explicitly retrieves that reviewed artifact outside the repository without npm lifecycle scripts. A second retrieval was tested successfully. No local Emscripten source rebuild or bit-identical build attestation was performed; compiler versions are not pinned by this experiment. Reproducing the published bytes is established; reproducing them from source is not.

| Candidate | Browser/CPU/flags | Memory, segments, hooks and invalid behavior | Build, size, risk and decision |
|---|---|---|---|
| Unicorn.js pinned x86 2.1.4 | Wasm 32-bit execution actually tested; nested calls and six defined arithmetic flags match | Private page mapping; explicit flat segments/FS; code/read/write hooks tested; UD2 returns UC_ERR_INSN_INVALID | 915,283-byte single file; GPLv2 obligations; upstream TCI/adapters add maintenance risk. Selected test-only; measured adapter rejected for adoption |
| Native Unicorn 2.0.1.post1 | Native-only, retained differential oracle | C API mapping/registers/hooks; no Win32 services | Already installed; cannot satisfy browser gate by itself |
| v86 | [Documented browser x86-to-Wasm engine](https://raw.githubusercontent.com/copy/v86/master/Readme.md), including SSE and noted CPU limitations | Full PC CPU/MMU/device model; this phase did not prove a checked user-mode memory adapter, FS handoff, exact hook or invalid-instruction policy | [BSD-2-Clause](https://raw.githubusercontent.com/copy/v86/master/LICENSE); Rust/clang build and published artifacts exist. Not downloaded/integrated; version/size/performance for this project unmeasured |
| Existing RawLifter/Wasm | Fourteen reviewed bindings; flags and normal-path SEH already verified | Existing checked memory and explicit dispatcher admission remain control | No extra dependency; faster control. Retained production backend |

Unicorn supplies instruction execution, not a legitimate PE import binder, MSVCR80/Win32 services or D3D9. No candidate solves unavailable entry or provider provenance. v86 was not treated as a proven drop-in replacement; a new custom interpreter was not invented.

## Unified-memory experiment

web/tools/uc-browser-x86-adapter.mjs accepts the existing process and an injected reviewed engine. The existing address-space object is authoritative. Original section bytes/BSS come from the authenticated private descriptor and payload; original virtual addresses and existing access checks remain unchanged. The experiment resets the same process between the Wasm oracle and CPU engine, rather than creating a second simulated Undercover process.

The engine requires private Wasm memory. It lazily maps page mirrors from the canonical checked memory, verifies source-code bytes and every CPU data read, commits original-width writes through canonical permission checks, and discards the engine after each run. Full mapped address space from 0x00400000 through the end of diagnostic stacks/TEBs matches byte-for-byte. Low unmapped Wasm bookkeeping at 0x00010000 is excluded from guest comparison; it contains the translated module's private CPU state, not mapped game globals. Read-only and unavailable canonical regions retain their checks even though engine mirror pages permit hooked accesses.

Synthetic segment descriptors are engine infrastructure, not original loader output: flat 32-bit CS/data/SS and a bounded FS descriptor at the existing explicit thread fixture 0x03100000. The private GDT is at 0x03102000 and is not guest-admitted storage. Loading FS alone initially left inconsistent default stack segmentation; explicit flat descriptors resolved that fixture integration issue. Ring/descriptor setup is not a claim about authentic Windows initialization. Guest FS reads/writes still use the existing chain-validation rules; final head is 0x0300EFD4.

Instruction admission is generated from the seven already reviewed original ranges by tools/uc_browser_x86_metadata.py. Metadata contains addresses, lengths, generic CALL/RET classification and Capstone defined/undefined/tested flag effects, not instruction bytes or handwritten per-function semantics. Authenticated original bytes execute in the engine. Range digests are checked before execution; code hooks verify that only admitted starts execute. Definedness is tracked separately from CPU EFLAGS; undefined flag consumption rejects execution.

**Scope limit:** no in-flight switch between an engine frame and a translated frame is offered. CPU registers are synchronized at the terminal boundary, while engine flag-validity/journals are returned as experimental evidence. The production Wasm bridge's private flag state is not qualified for subsequent mixed-backend resume. Every benchmark resets the process before using the other backend. This and persistent segment/flag transition testing remain adoption blockers, not successful transitions.

## Actual Edge differential

A dedicated worker ran over temporary HTTPS using the existing LAN server, bind 127.0.0.1, ephemeral port and current authorized asset manifest. A main-thread watchdog terminates the worker after 30 seconds; the worker uses per-instruction execution and cooperative yields. No port/firewall/public-access change was made.

| Observation | Exact result |
|---|---|
| Engine code-hook instruction addresses | 173, identical to reference sequence |
| Entered functions | 12 entries, 7 distinct existing bodies |
| Callee returns | 9 |
| Original PE-global writes | 27, same addresses/values/instructions |
| All guest instruction writes | 82 including one FS write; reference ordinary journal is 81 plus separate FS event |
| Guest reads | 68; same addresses, widths, values and originating instructions |
| Per-instruction snapshots | Registers and defined flag bits/validity match at all 173 tags |
| Stack / mapped guest bytes / FS events | Exact matches |
| Final ESP / EBP / ESI | 0x0300EFA8 / 0x0300EFE4 / 0x008AAC6A |
| Exception-chain head | 0x0300EFD4 |
| Final stop | dispatch at 0x8aac6a: unavailable |

Root is host-entered 0x00B57DC0 with the existing explicit synthetic thread. Actual original calls enter 0x009E7540, six 0x009E75A0 children, 0x009C1830, 0x0087B640, 0x0087B59B and 0x0087BEB8. No receiver, callback array or game storage is fabricated by this adapter. Registrar/wrapper/root do not return.

The original CALL at 0x0087B5B3 writes its actual return address. Engine raw stop EIP is recorded separately as 0x008AAC6A when fetching the unavailable effective target is rejected. The adapter presents the dispatcher trap at original instruction 0x0087B5B3 to match the existing bridge convention; this is trap-state normalization, not execution or redirection of the target. No hook records 0x008AAC6A, and the instruction interior is never executed. Both raw and presented state are retained in browser-x86-differential-phase72.json.

All twelve differential categories pass with zero mismatches. That proves the bounded original-byte browser control, not original PE startup, cleanup registration, CRT completion, a menu or gameplay. New handwritten function translations: zero. New unique harness functions: zero. Historical ledger remains 84 unique, 50 enterable, 358 recorded runs.

## Budgets, timing and go/no-go

Default limits: 10,000 guest instructions, 64 call frames, 2,000 writes, 65,536 accessed bytes, 1,000 ms worker execution time, 100,000 counted instruction/hook transitions. Accesses must also lie in the existing checked canonical mappings; unknown instructions/targets reject. Source/mapping setup is bounded by reviewed ranges and page mappings; the outer 30-second worker watchdog covers setup/engine calls too. Six focused cases reduce each limit and observe the expected BUDGET_* stop. Timeout is never counted as return. A synthetic UD2 negative fixture independently returns UC_ERR_INSN_INVALID. No full Windows exception dispatch is implemented.

Final measured medians: current Wasm 0.400 ms, browser adapter 45.800 ms, **114.50x slower**; gate <=5x fails. Earlier development runs varied; only final recorded samples drive generated status. Two warm-up pairs and seven measured pairs, checked hooks and tracing enabled. See browser-x86-benchmark-phase72.md for all samples, overhead and limitations.

Canonical linear memory is 51,445,760 bytes; observed engine linear memory 41,418,752 bytes, with 40,960 mapped guest bytes plus private GDT. These are allocations, not peak browser RSS. Module factory initialization measured 14.700 ms; authenticated process creation including hashing/Wasm compilation measured 52.300 ms. Synchronization is included in adapter timing, not separately isolated. Native Phase 71 timings are a smaller fixture and are not a directly comparable third benchmark.

**NO-GO adoption.** The reusable engine reduces per-function translation work on this chain, but this adapter fails the performance gate, source-build reproducibility is not qualified and mixed-engine resume is untested. The production backend is not replaced. CPU/SIMD initializer 0x0087BFE4 was not tested; optional work was deferred after the adoption gate failed. No CPUID/host CPU capability claim is made.

## Inspector, readiness and regressions

The existing inspector now offers translated Wasm and a disabled browser-x86 option. It displays generated measured provenance/version/license, instruction/function/write counts, differential/CPU-FS status, stop, duration, allocations, fixture provenance and false startup readiness. A disabled option cannot load the engine. No third-party code enters main.js. Full-game Play remains disabled. Private JPEG/bumper, OPFS and existing previews remain intact.

Final checks all exit zero:

| Commands | Actual result |
|---|---|
| python tools/uc_browser_x86_prepare.py <outside-repo-directory> | Pinned package/extracted SHA verified; no npm install |
| python tools/uc_browser_x86_metadata.py <original-exe> --output analysis/undercover/browser-x86-admission-phase72.json | Seven reviewed body ranges, source digest checked |
| python tools/uc_browser_x86_report.py | Feasibility JSON, measured benchmark and descriptive inspector status generated |
| node web/node_modules/typescript/bin/tsc -p web | Passed |
| web: node build.mjs | Passed, including final regenerated status |
| python tools/uc_unified_build.py <original-exe> <authorized-root> | Same fourteen bindings and byte-identical Wasm |
| web: node tools/unit-tests.mjs --fast | 157 tests: 156 passed, 0 failed, 1 existing skip; browser x86 test actually ran |
| web: node --test test/uc-lan-https-browser.test.mjs | Final generated inspector/media check: 2 passed |
| python tools/uc_import_frontier_test.py / tools/uc_crt_evidence_test.py | 4 + 6 passed; no new provider search |
| python tools/uc_x86_probe.py <original-exe> <authorized-root> --output <workspace>/phase72-native-differential.json | Native constructor differential and 105 arithmetic cases passed |
| python tools/uc_phase43_test.py through uc_phase51_test.py individually | 121 passed (52/10/8/23/8/6/5/4/5) |
| python tools/uc_startup_preflight_test.py | 3 passed |
| python tools/uc_phase31_campaign.py | Expected successes/blocked cases retained |
| python tools/uc_startup_preflight.py <original-exe> --output analysis/undercover/startup-readiness.json | Source/master integrity passed; original startup blocked |
| python tools/progress.py / python tools/uc_progress_test.py | Dashboard consistency passed |

Browser environment: UC_BROWSER_CHANNEL=msedge, UC_BROWSER_INIT_TEST=1, UC_UNIFIED_TEST=1, UC_AUTHENTIC_ASSET_ROOT points to existing authorized-startup, UC_SEH_NODE_EVIDENCE points to seh-normal-path-phase69.json, UC_BROWSER_EVIDENCE writes edge-execution-phase72.json, UC_BROWSER_X86_ENGINE points to the reviewed outside-repo unicorn_x86.js, UC_BROWSER_X86_EVIDENCE writes browser-x86-differential-phase72.json. The optional x86 test skips only when its external engine is absent; it did not skip in this run. The one existing skip is the older synthetic Chromium-logo test. Existing Phase 49 ResourceWarning is nonfatal.

Phase 60 nine-case diagnostics, Phase 67 flags, Phase 69 SEH, Phase 70 import metadata, exact provider failure, constructor writes, private HTTPS/media/cache and full-game disabled state remain tested. Wasm SHA remains 8d1a62e0f1347d3698c9a011bf0da415291c6054c33c0b209652064da7b71c76, 14,981 bytes. Six-path private manifest version 69 is unchanged. No commercial payloads, original binaries or third-party engines are staged.

## Local delivery

Implementation: 7a94e6c4. Documentation/evidence follow in a second focused local commit; final hashes/status are in the delivery response. After both commits main is 22 ahead of unchanged local origin/main. Only the same 22 unrelated discord-bot deletions remain. No push.

Phase 73 recommendation: do not promote this adapter or expand CPU/SIMD/provider scope. If pursuing CPU execution, first isolate synchronization/step/map/yield costs on this same control and prove a <=5x bounded adapter without weakening checks. Persistent engine memory and mixed-backend transitions require explicit consistency, flag-validity, segment, trap and reset tests. Require a pinned reproducible source build and distribution plan before website delivery. Stop if those gates cannot be met; the original provider boundary remains independently blocked.
