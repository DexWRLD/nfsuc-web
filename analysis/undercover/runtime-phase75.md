# Phase 75 — Windows-compatible CRT bootstrap

2026-11-04. **Strong milestone achieved within the requested compatibility scope:** original security-cookie routine 0x0087C264 returns in Edge using five documented, exact-callsite host services. Its own instructions write cookie/complement; a separately labeled Windows-compatible NT_TIB32 prefix is prepared afterward. This is host-scheduled compatibility CRT execution, not original PE startup or loader resolution.

## Baseline and sources

Actual starting HEAD 2f02cce0 follows Phase 73 implementation 8faddbc1; main was 24 ahead of local origin/main. No Phase 74 implementation was present; phase74-handoff.md and the latest read-only research were reviewed. The same 22 unrelated discord-bot deletions were preserved. No fetch or push.

Reviewed runtime-phase73.md/final decision, Phase 74 handoff, external C:/Users/999/Documents/KTA/research/undercover-authentic-startup-crt-only.md, Phase 69 SEH, Phase 70 ordering, Phase 71 import provenance, unified process/registry/thread/preflight and existing private authorization. Fresh read-only Ghidra program identity and the 52-instruction cookie disassembly agree with the authenticated PE bytes. The research digest is recorded in crt-compatibility-contracts-phase75.json.

Original executable SHA-256 remains 6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd; canonical decompilation remains f293d93d31fcbf86ad9b9639f2cf10c34defe9c621cfe7f1a5e975f598ddf88a. Preflight verifies both. The original executable/assets were read only, never launched, modified, unpacked or reconstructed.

## Architecture and routing

The default fourteen-body module/descriptor/payload remain byte-identical. tools/uc_unified_build.py now optionally emits a separately pinned diagnostic variant with those same bodies plus one reviewed cookie body at [0x0087C264,0x0087C2F8). It uses the existing RawLifter, imported checked WebAssembly.Memory, CPU bridge, dispatcher, original addresses and stack contract. There is one authoritative guest memory per diagnostic process and one active module; no second engine, private game-memory mirror or mid-frame backend switching is introduced.

The diagnostic variant is 18,128 bytes, SHA-256 7859c00ff1145937b25076452ba5afc152171bccea95240b68b5a78c0bfe3cc1. Metadata contains original-body SHA-256 d0507c2f9c14d64b541022c69ce07f0709947437d4a350e5e47b98a91b92f910, exact instruction starts and five operand/name-record reviews. It is not automatically admitted by the ordinary registry. Loading requires this exact module digest and explicit diagnostic options. Ordinary image/module hashes are still validated before selecting the variant.

The existing checked arithmetic semantics support this bounded body. NOT and LEAVE reuse the existing lifter's flag-preserving operations, independently tested for unchanged flags and ABI preservation. The conditional SHL at 0x0087C2E0 is not admitted: the original branch reaches an instruction-tagged unsupported trap before any substitute shift result. A targeted low-upper-word fixture verifies that stop and unchanged cookie globals. No broad opcode expansion was made.

Compatibility import routing uses namespace compat.kernel32, never a fake callable address. At each service boundary it requires explicit compatibility mode, the pinned original function, exact original callsite/bytes, original operand cell and unchanged raw target, exact original null-terminated name record, expected original return address and documented ABI. The five raw values remain in their original read-only cells. No active IAT, legacy cell or CALL/JMP bytes are rewritten. Unknown callsites/targets use the normal unsupported dispatcher and cannot acquire a guessed provider.

Every host invocation records its namespace, original callsite/cell/raw target, arguments, returned value/output words, ESP before/after, return address, environment provenance and hostSubstitution=true / originalLoaderBindingObserved=false. Buffer faults and provider errors propagate as diagnostic traps. Eight-byte output ranges are validated in full before either dword is written; failed calls do not create successful returns.

## Smallest implemented service set

| Exact original callsite | Legacy cell | Explicit host service | Arguments / cleanup |
|---|---|---|---|
| 0x0087C299 | 0x00B611A0 | GetSystemTimeAsFileTime | FILETIME pointer; stdcall removes 4 argument bytes |
| 0x0087C2A5 | 0x00B610CC | GetCurrentProcessId | No arguments; DWORD EAX |
| 0x0087C2AD | 0x00B611E0 | GetCurrentThreadId | No arguments; DWORD EAX |
| 0x0087C2B5 | 0x00B611D0 | GetTickCount | No arguments; DWORD EAX |
| 0x0087C2C1 | 0x00B611F8 | QueryPerformanceCounter | LARGE_INTEGER pointer; stdcall removes 4 argument bytes; BOOL EAX |

The [FILETIME service](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtimeasfiletime) writes current UTC and has no return value; this implementation preserves EAX. [Process](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocessid) and [thread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentthreadid) IDs identify the calling virtual context, not the host OS. The [tick count](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount) is DWORD elapsed milliseconds, with wrap. [QPC](https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancecounter) writes a counter and returns success on valid supported inputs. [Win32 x86 stdcall](https://learn.microsoft.com/en-us/cpp/cpp/stdcall) establishes callee argument cleanup.

The defined browser environment uses Date.now converted to 100-nanosecond intervals since 1601 for FILETIME; performance.now as a monotonic counter at virtual frequency 1,000,000 and as elapsed milliseconds from compatibility-context creation for ticks. Browser precision applies; hardware precision is not invented. Page-runtime process/thread identities are allocated uniquely without reuse until exhaustion. QPC's epoch need not be UTC. All values are environmental inputs, not a selected cookie value or seeded game global. Live resets retain the context/clock model; deterministic replay tests use explicitly labeled constant service fixtures.

All eighteen requested candidate services have contract/ABI/state/error/provenance classifications in crt-compatibility-contracts-phase75.json. Only the five above are implemented. Interlocked operations, Sleep, _initterm/_initterm_e, app-type handling, pointer encoding/decoding, locks, callback-array storage and EH4 dispatch are not speculatively supplied. In particular modern single-underscore _set_app_type documentation does not establish the exact legacy double-underscore provider, and no encoder secret/identity transform is invented.

## Actual Edge milestone

Fresh evidence: crt-bootstrap-execution-phase75.json, Edge 156.0.4314.58, secure HTTPS context. The original-only test first stops at 0x0087C299 through raw 0x008AB0FE with zero host services and the file cookie intact. The compatibility test then manually enters 0x0087C264 in a fresh diagnostic process, starting from the authenticated default cookie 0xBB40E64E. It does not force the already-initialized branch.

- Original functions entered: one, 0x0087C264. Actual original instruction tags: 42.
- Host-provided services: five; the original XOR/comparison/normalization path computes the cookie.
- Original memory writes: 15, including cookie store 0x0087C2E5 -> 0x01285688 and complement store 0x0087C2ED -> 0x0128568C.
- Recorded cookie: 0x20C46B41; complement: 0xDF3B94BE. These are observations, not constants supplied to the runtime. Independent tests reconstruct the result from logged inputs.
- Last original instruction: RET 0x0087C2F7. Return EIP=0x00DEC0DE, ESP=0x0300F000, callee-saved registers/EBP preserved.
- Host environment writes: 9, separately logged: synthetic root return slot, four service-output dwords and four thread-prefix fields. No host write initializes the cookie, startup state/owner or cleanup globals.
- All five operand cells remain unchanged; cleanup provider remains [0x00B61398]=0x008AAC6A.

A diagnostic return sentinel is not an original caller address. The original static CALL at 0x0087BD95 is verified but was not executed in this bootstrap; the entry-to-CRT bridge remains unavailable. No original PE-entry execution or loader resolution occurred. Replays and service invocations are not new original guest functions. The historical native ledger remains 84 unique / 50 enterable / 358 runs; the opt-in reviewed browser variant adds one separately classified ordinary body.

## Windows-compatible thread prefix and stop

Only after cookie return, the host initializes a checked single-thread NT_TIB32 prefix at existing FS base 0x03100000: exception head FFFFFFFF at +0, StackBase=0x03010000 at +4, StackLimit=0x03000000 at +8, Self=0x03100000 at +0x18. This follows the [Microsoft NT_TIB32 layout](https://raw.githubusercontent.com/microsoft/win32metadata/main/generation/WinSDK/RecompiledIdlHeaders/um/winnt.h). In particular [FS:[0x18]+4] is StackBase, the original code's ownership token, not a slot for a thread ID. Explicit IDs remain in the compatibility context.

The old generic thread initializer still admits only FS:[0]. The new opt-in initializer permits the verified FS:[0x18] read, maintains existing checked SEH-chain validation and rejects other unverified fields, writes or thread switching. Reset clears its context and all original process data; deterministic tests reproduce the same computed cookie and context. This is a verified-access prefix, not a full Windows TEB/TLS/scheduler or original game thread producer.

Next unadmitted entry is 0x0087BB3D. The live bootstrap does not enter it. Original startup synchronization/owner transitions are therefore not claimed; 0x018B1E58/5C remain zero. The first C non-null initializer 0x0087BCB3 is not admitted, and its PE-header/provider/encoding prerequisites remain unsupported. C table [0x00B63DC4,0x00B63DD4) is authenticated as [0,0x0087BCB3,0x0087BFE4,0x0087C08B], not a completed traversal. No later entry is skipped, no C++ table is traversed and the Apt constructor is not host-scheduled as new startup progress. Both cleanup globals remain zero; zero is not an encoded sentinel.

The existing original-only 173-tag Apt/SEH control and 0x0087B5B3 trap remain unchanged. Even compatibility mode does not substitute its _decode_pointer call: that service is unimplemented, and earlier initialization gates have not passed.

## Inspector and distribution

The existing inspector has separate Original-only and Compatibility CRT controls. Both require a separately built, digest-checked local diagnostic module; original-only remains the default. Full-game Play is disabled. No second frontend architecture or browser x86 adoption was introduced. Existing asset downloads, hashes, allowlists, OPFS, authentic JPEG/silent bumper and synthetic previews remain intact.

Build locally:

    python tools/uc_unified_build.py "C:/Games/Need For Speed Undercover/nfs.exe" "C:/Users/999/.nfsuc-web/authorized-startup" --crt-cookie-output "C:/Users/999/Documents/Codex/2026-11-03/referenced-chatgpt-conversation-this-is-an-3/outputs/phase75-private"

Run the frontend build, open Play Development Preview -> Execution inspector, select uc-crt-cookie.wasm from that private directory, choose Compatibility CRT and Run CRT Bootstrap. The generated module stays outside Git and the original installation; the builder rejects those output destinations. It is not added to dist or the private six-path version-69 manifest. Other LAN devices do not automatically receive it. No new LAN distribution, port/firewall rule or public exposure was created.

## Validation

Final existing/new checks all exited zero. Raw commands/output are retained in phase75-validation.log and phase75-browser-tests.log; extra development reruns are not counted as unique tests.

| Actual command / group | Result |
|---|---|
| Unified Wasm build above with --crt-cookie-output | Ordinary module unchanged; pinned fifteen-body diagnostic variant built |
| node web/node_modules/typescript/bin/tsc -p web | Passed |
| web: node build.mjs | Passed |
| web: node tools/unit-tests.mjs --fast | 166 tests: 165 passed, 0 failed, one existing skip |
| New uc-crt-bootstrap.test.mjs | Seven tests passed: ABI/stack, real guest arithmetic/writes, NOT/LEAVE flags, reset, normal isolation, unrecognized operands/returns, buffers/errors, shift/budget stop, thread/owner and C-table ordering gates |
| New uc-crt-bootstrap-browser.test.mjs | Live Edge UI/file-selection/original-only/compatibility milestone passed |
| Existing Phase 72/73 browser x86/cost tests | Differential, budget/reset and decision-boundary regressions passed; no tuning performed |
| python tools/uc_import_frontier_test.py / tools/uc_crt_evidence_test.py | 4 + 6 passed; existing evidence checks, no speculative binding search |
| python tools/uc_x86_probe.py <same original executable> <authorized root> --output <workspace>/phase75-native-differential.json | Native comparison and 105 arithmetic fixtures passed |
| Python tools/uc_phase43_test.py through uc_phase51_test.py, individually | 121 passed: 52/10/8/23/8/6/5/4/5 |
| python tools/uc_startup_preflight_test.py | Three passed, including final metadata rerun |
| python tools/uc_startup_preflight.py <same executable> --output analysis/undercover/startup-readiness.json | Source/master verified; original startup blocked; distinct compatibility status |
| python tools/uc_phase31_campaign.py | Expected successes and blocked cases retained |
| python tools/progress.py / python tools/uc_progress_test.py | Dashboard consistency passed |

The Node suite includes Phase 60 nine cases, Phase 67 flags, Phase 69 SEH, Phase 70 metadata and private HTTPS/media/cache tests. UC_CRT_COOKIE_MODULE and UC_CRT_EVIDENCE select the external module and new browser report; retained x86/Edge evidence goes to separate Phase 75 regression files. No earlier Phase 72/73 report was overwritten. The one skip is the older synthetic Chromium-logo test. Existing Phase 49 ResourceWarning is nonfatal.

Normal Wasm remains 14,981 bytes, SHA-256 8d1a62e0f1347d3698c9a011bf0da415291c6054c33c0b209652064da7b71c76. No original commercial assets, generated payload/module binaries or third-party DLLs are committed. The 22 unrelated deletions remain untouched.

## Delivery and Phase 76

Implementation commit: 6ae0c3c6. Reports/evidence/dashboard follow in a focused local commit; final hashes/status are in the delivery response. After both commits main is 26 ahead of the unchanged local origin/main reference. Nothing pushed.

The next focused target is reviewing 0x0087BB3D's actual frame contract, verified FS access and documented synchronization calls before any startup-state or table execution. Preserve the distinction between host services and original loader resolution. Do not implement encoder/callback storage, skip the first initializer, revive x86 performance work or infer original boot from this cookie milestone.
