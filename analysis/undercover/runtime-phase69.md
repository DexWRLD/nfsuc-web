# Phase 69: original SEH normal path and exact cleanup registrar coverage

The unified browser process now enters original 0x0087B59B and executes original SEH prolog 0x0087BEB8 through the existing Apt constructor/wrapper chain, using an explicitly synthetic generic x86 thread fixture. Node and Edge stop precisely at 0x0087B5B3, rejecting the unchanged provider pointer 0x008AAC6A from 0x00B61398. **Cleanup registration, original thread startup, game boot, menu presentation and gameplay are not established.**

## Baseline and source verification

Baseline HEAD fef03629 included Phase 67 implementation 05a3cd7d and Phase 60 revalidation a7048d53. Main was fourteen ahead of the unchanged local origin/main reference. The 22 pre-existing discord-bot deletions and all unrelated work were preserved. No fetch or push.

Read runtime-phase67.md, phase68-handoff.md, the current Phase 60 revalidation, PE/recovery evidence, registry, RawLifter, shared process, inspector and tests. The external research file exists and was read in full:

    C:\Users\999\Documents\KTA\research\undercover-phase68-crt-seh-cleanup.md

tools/uc_seh_evidence.py verifies its 81 instruction-appendix encodings against the original PE and independently checks the four-instruction finally outline. cleanup-registrar-coverage-phase69.json records the research-file SHA, exact regions, instructions, source hashes, branches, fallthroughs and recovery override. Original executable SHA remains 6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd. Canonical master SHA remains f293d93d31fcbf86ad9b9639f2cf10c34defe9c621cfe7f1a5e975f598ddf88a. Neither master nor original executable/assets were modified. No installed game was launched.

## Exact translated membership

| Body | Original range, inclusive | Distinct instructions | Execution classification |
|---|---|---:|---|
| Cleanup registrar | 0x0087B59B–0x0087B636 | 49 | Prefix through first unresolved indirect call only |
| SEH prolog | 0x0087BEB8–0x0087BEFC | 21 | Entire normal helper executed in connected fixture trace |
| SEH epilog | 0x0087BEFD–0x0087BF10 | 11 | Executed only in separate normal-path helper fixtures |
| Finally outline | 0x0087B637–0x0087B63F | 4 | Translated/admitted, not entered |

Ghidra's registrar membership remains [0x0087B59B,0x0087B600] union [0x0087B631,0x0087B636], totaling 108 bytes. The independently verified missing continuation adds [0x0087B601,0x0087B630], 48 bytes and 14 instructions. The separate finally block is nine bytes. The canonical index/master remain unchanged; reviewed registry metadata and recovery-priority overrides explicitly cite the additional instruction evidence.

The builder checks exact body SHA, original call sets and equality between decoded instruction starts and translated instruction tags for all four new bodies. RawLifter emits the original continuation, not Ghidra's injected pseudocode. Duplicate C copies of the shared return block do not count as additional original instruction addresses: the four bodies contain 85 distinct original instructions in total.

Registrar control flow is recorded instruction by instruction in cleanup-registrar-coverage-phase69.json. Its first provider at 0x0087B5B3 is never allowed to return. Statically, the EAX=-1 branch calls the alternate cell at 0x0087B5C1 then joins 0x0087B631. The other branch calls 0x0087BFFE at 0x0087B5CC, processes both globals through indirect calls, and calls the callback transformation at 0x0087B5FF. The omitted continuation removes that argument, stages the transformed callback and calls three-argument registration helper 0x0087BFF8 at 0x0087B603. It saves the result, transforms local pointers and contains stores at 0x0087B610/0x0087B61D to 0x018B1E6C/68. It resets try level to -2, calls the finally outline at 0x0087B629, reloads saved EAX and joins the epilog call at 0x0087B631. The final RET is 0x0087B636. None of these post-provider operations is reported as runtime success.

The finally outline pushes 8, calls 0x0087BFF2 at 0x0087B639, removes its argument and returns. The scope-table record also names this outline. Scope-based exception invocation is unsupported. The exception wrapper 0x0087BF11 and dispatch helper 0x0087C304 have explicit unavailable bindings; no exception dispatch or unwind path is implemented.

## Normal-path frame semantics

Let S be ESP on registrar entry. The original registrar pushes 0x14 and scope pointer 0x00CA9380, then calls the prolog at 0x0087B5A2. The prolog creates the following original frame:

| Frame location | Proven value after prolog |
|---|---|
| EBP | S-4, with saved caller EBP at [EBP] |
| ESP | EBP-0x34 = S-56 |
| EBP+4 / +8 | Original registrar return / callback argument |
| EBP-4 | Try level -2 |
| EBP-8 | 0x00CA9380 XOR authenticated cookie |
| EBP-0x0C | Exception wrapper 0x0087BF11 |
| EBP-0x10 | Previous thread exception head |
| EBP-0x18 | Baseline ESP, EBP-0x34 |
| EBP-0x28/-0x2C/-0x30 | Saved EBX/ESI/EDI |
| EBP-0x34 | Cookie XOR EBP |

FS:[0] is read at 0x0087BEBD and linked to EBP-0x10 at 0x0087BEF6. These are dedicated checked FS imports, never flat reads/writes at guest address zero. All ordinary stack/scope/cookie accesses use the existing checked guest memory.

The prolog is not an ordinary cdecl return: helper-entry ESP changes by -44 bytes and EBP becomes helper-entry ESP+8. The paired epilog requires a matching balanced frame; it restores FS:[0] at 0x0087BF00, captures its own continuation in ECX, discards the frame-cookie slot, restores EDI/ESI/EBX and caller EBP, and returns to 0x0087B636 with ESP=old EBP+4. EAX is preserved. The original epilog has no cookie comparison; none was invented.

GuestDispatcher retains ordinary cdecl/stdcall/thiscall checks. Two address-specific frame contracts validate the SEH helpers' actual ESP/EBP and EAX behavior rather than disabling ABI verification. Admission requires the exact helper address and cdecl/zero conventional argument metadata. The prolog currently admits only the verified 0x14/0x00CA9380 setup; other frame sizes/scope inputs are explicitly unsupported. The bridge retains volatile registers, arithmetic flags/validity and original source-before-ESP PUSH ordering across nested imports.

## Thread infrastructure provenance and limits

GuestThreadFixtures is explicitly synthetic infrastructure, separate from original Undercover initialization. Two bounded TEB-like slots at 0x03100000 and 0x03101000 have independent exception heads, and separate fixture stack bounds at 0x03000000–0x0300FFFF and 0x03010000–0x0301FFFF. These addresses are assigned diagnostic mappings, not discovered original Windows addresses. The implementation supports only FS offset zero. TLS, other TEB fields, scheduling, real Windows thread creation, exception dispatch and unwinding remain unsupported.

Each fixture starts with exception-chain terminator 0xFFFFFFFF. It validates mapped/readable/writable TEB storage, active initialization, aligned bounded chain records, mapped executable handler addresses, loops/depth, and per-thread stack ownership. Uninitialized state, unsupported offsets, unmapped/read-only TEBs and cross-thread frame pointers are rejected. Process reset clears bytes, thread initialization/selection and logs. Selecting a fixture does not create a native thread or schedule CPU execution.

Independent platform references: Microsoft's [x86 TEB explanation](https://devblogs.microsoft.com/oldnewthing/20190203-00/?p=101028) identifies FS and its offset-zero exception chain. Microsoft's [!exchain documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exchain) describes the per-thread x86 handler chain. The [ReactOS NDK source](https://github.com/reactos/reactos/blob/master/sdk/include/ndk/rtltypes.h) defines EXCEPTION_CHAIN_END as pointer -1. These support the generic fixture representation; they do not establish the original game's thread-startup path.

No host code seeds an Undercover object, capacity, cleanup list, callback provider or transformed global. The only new initialized host infrastructure is the explicitly classified thread slot/empty chain and, in separate helper tests, synthetic call frames/register sentinels. Without a thread fixture, the connected root still rejects at original FS read 0x0087BEBD. Its constructor writes remain preserved; no default thread is silently supplied.

## Cookie and scope provenance

The authenticated ordinary image supplies [0x01285688]=0xBB40E64E and [0x0128568C]=0x44BF19B1. The prolog reads the file-backed cookie and scope table directly. The fixture does not change them. Original ___security_init_cookie at 0x0087C264 is not bound or executed; its five indirect entropy providers and original caller/order remain unverified. No entropy result was invented. Use of these authenticated initial bytes does not prove original CRT cookie initialization.

## Actual connected result

Original call path, with host diagnostic root and synthetic thread selection explicitly identified:

    host: initialize generic x86 thread fixture, enter 0x00B57DC0
      original 0x00B57DC8 → 0x009E7540 → header/child constructors
      original 0x00B57DD2 → 0x0087B640
        original 0x0087B644 → 0x0087B59B
          original 0x0087B5A2 → 0x0087BEB8 → returns to 0x0087B5A7
          original 0x0087B5B3 → raw [0x00B61398] = 0x008AAC6A [REJECTED]

The connected trace has twelve entries across seven distinct bodies and nine completed callee returns. Newly entered connected bodies are 0x0087B59B and 0x0087BEB8. The epilog is newly executed only in separate helper fixtures; the finally outline is not entered. All 27 earlier original PE-global writes are retained, with no new cleanup-global publication. FS linkage is recorded separately from PE-global writes.

At the stop:

- EIP/last tagged original instruction: 0x0087B5B3.
- EBP: 0x0300EFE4; ESP: 0x0300EFA8; ESI: 0x008AAC6A; EAX: 0x0300EFD4.
- [ESP]: original return 0x0087B5B5; [ESP+4]: zero read from original zero-filled global 0x018B1E6C.
- Fixture FS base: 0x03100000; exception head: 0x0300EFD4; previous head: 0xFFFFFFFF.
- Callback at EBP+8 remains 0x00B602E0.
- Root, wrapper and registrar have not returned. The linked frame has not been restored in this connected trace.

The MOV ESI at 0x0087B5AD completed. The next CALL's original return-address push occurs before dispatcher rejection. The target instruction stream is not entered. The callsite expects one caller-cleaned dword and an EAX result, but no result or provider ABI implementation is supplied.

The raw cell value lies inside the existing LEA at 0x008AAC69. It is not reinterpreted, redirected, decoded, replaced with a Windows API or automatically classified as protected. Alternate/transform/storage cells 0x00B61394/8C/88/90/84 remain unresolved. Later stores 0x0087B610/61D are static coverage only; both cleanup globals remain zero in actual execution. No callback array layout, encoding algorithm, capacity, lifetime or storage policy is claimed.

seh-normal-path-phase69.json is actual Node connected evidence. edge-execution-phase69.json is actual secure-context Edge evidence and includes the separate original prolog/epilog restoration fixture. Edge asserts exact equality of Node's original instruction sequence, dispatcher trace and final registers. The connected trace has 173 executed instruction tags/103 unique tagged original addresses, including the blocked CALL tag. These are diagnostic coverage counts, not new unique native-harness functions.

## Independent helper verification and browser inspector

Node tests verify every documented frame slot, nested normal frames, previous-head restoration, EAX and all preserved registers, failed inputs and unbalanced frames, per-thread FS/stack isolation, missing/read-only/unmapped thread storage, unsupported offsets, invalid chains and unsupported exception targets. Expected values come from original instructions and fixed source bytes; no callee returns are fabricated to continue the registrar.

The browser inspector shows thread provenance, FS base/head and accesses, cookie source, prolog entry, linked frame, exact provider cell/value/argument, original trace/instructions, last instruction, 27 original global writes, explicit nonreturns and unverified original startup reachability. After recording the blocked trace, it resets and runs a separate synthetic call-frame fixture through the original prolog and epilog, confirming restored chain end, register preservation and EAX 0x13572468. This does not resume the registrar or imply cleanup completion.

The Phase 60 nine-case frame revalidation, arithmetic validity tests and historical 0x009E4B49/0xFFFFFFFC failure remain intact. No frontend frame-work or authentic-screen milestone is promoted. No speculative FNG/BUN work or legacy-tool deletion was performed.

## Private module delivery

Same six authorized allowlisted paths; private manifest version 69. Ordinary payload remains 15,356,006 bytes, SHA 35bc6b5a51a82fa9fc0ea5be991e1f67a4bbcfa87f2cd529867e40ed7961fcfa. New module: 14,981 bytes, SHA 8d1a62e0f1347d3698c9a011bf0da415291c6054c33c0b209652064da7b71c76. Descriptor: 5,252 bytes, SHA 35c41157239d29538e70cce352338c6696acfc8bf9e36827c407d3d7040c2a93. Total manifest download bytes: 16,416,124.

Generated Wasm, PE payload, original JPEG and authentic silent bumper remain outside Git. No delivery paths, firewall rules or bind addresses were widened. Existing local preview remains https://localhost:8443/ with loopback bind; Wasm HEAD returned 200 with application/wasm, length 14,981 and range support. Authentic media, manifest digest checking, OPFS reload and one payload download per clean browser context passed. Full-game Play remains disabled; Undercover branding is unchanged.

## Commands and validation

All final checks exited 0:

| Command | Actual result |
|---|---|
| python tools/uc_seh_evidence.py "C:/Games/Need For Speed Undercover/nfs.exe" "C:/Users/999/Documents/KTA/research/undercover-phase68-crt-seh-cleanup.md" --output analysis/undercover/cleanup-registrar-coverage-phase69.json | 81 appendix instructions checked; 85 original instruction starts across four exact regions |
| python tools/uc_unified_build.py "C:/Games/Need For Speed Undercover/nfs.exe" "C:/Users/999/.nfsuc-web/authorized-startup" | One shared module; fourteen reviewed bindings, five ordinary/six unavailable PE sections |
| python tools/uc_unified_publish.py "C:/Users/999/.nfsuc-web/authorized-startup" --allowlist "C:/Users/999/.nfsuc-web/authorized-startup/phase52-allowlist.json" --manifest "C:/Users/999/.nfsuc-web/authorized-startup/phase52-manifest.json" --version 69 | Six assets, updated module/descriptor digests |
| web: node node_modules/typescript/bin/tsc -p . | Passed |
| web: node build.mjs | Passed |
| web: node tools/unit-tests.mjs --fast | 154 tests, 153 passed, zero failed, one skipped |
| web: node --test test/uc-seh.test.mjs | Five focused SEH/recovery tests passed |
| web: node --test test/uc-process.test.mjs test/uc-seh.test.mjs test/uc-unified-flags.test.mjs | Nineteen process/SEH/arithmetic tests passed |
| python tools/uc_phase43_test.py through tools/uc_phase51_test.py, individually | 121 passed: 52/10/8/23/8/6/5/4/5 |
| python tools/uc_startup_preflight_test.py | Three passed; original master and blocked PE entry retained |
| python tools/uc_phase31_campaign.py | Expected ordinary successes and unresolved-state/provider failures preserved |
| python tools/uc_startup_preflight.py "C:/Games/Need For Speed Undercover/nfs.exe" --output analysis/undercover/startup-readiness.json | Conditional fixture frontier updated; native startup still blocked |
| python tools/uc_recovery_inventory.py | 8,675 recovery records; exact overrides recorded separately; general candidate catalog remains noncallable |
| python tools/progress.py; python tools/uc_progress_test.py | Deterministic dashboard validation passed |

Browser environment: UC_BROWSER_CHANNEL=msedge, UC_BROWSER_INIT_TEST=1, UC_UNIFIED_TEST=1, UC_AUTHENTIC_ASSET_ROOT=C:/Users/999/.nfsuc-web/authorized-startup. UC_SEH_EVIDENCE writes the Node JSON; UC_SEH_NODE_EVIDENCE points Edge to it for trace/register equality; UC_BROWSER_EVIDENCE writes edge-execution-phase69.json. The single skip is the older synthetic-logo test requiring unavailable bundled Chromium; actual media and runtime tests ran in Edge. The pre-existing Phase 49 ResourceWarning remains nonfatal.

## Readiness and Phase 70 target

Verified: exact normal-path helper translation, explicit thread-fixture provenance and bounded FS operations, normal SEH link/restoration fixtures, complete static registrar continuation coverage, connected registrar/prolog execution, unchanged original constructor writes, strict provider rejection and Node/Edge agreement.

Unverified/blocked: original Windows/CRT thread initialization, original cookie initialization/order, exception dispatch/unwind, cleanup provider identity/initialization, successful registration, registrar/wrapper/root return, PE-entry continuation, original boot order, menu and gameplay. Historical native metrics stay 84 unique, 50 enterable, 358 runs. Browser repetitions and infrastructure fixtures do not increment that ledger.

Phase 70 should trace the original provenance of the unresolved provider cells, beginning with 0x00B61398, and establish a trustworthy original callable target and ABI before any continuation. Preserve raw file values and the current rejection. Do not assume an encoding algorithm, import identity, relocation fix or protected implementation from appearance. If no ordinary provider initializer is established, report the first exact unavailable boundary. Preserve current SEH/frame/media regressions and keep exception paths unsupported.

## Local commits and worktree

Implementation commit: 498a4535. Reports, captured evidence and dashboard updates follow in a separate local commit. After those commits main is sixteen ahead of the unchanged local origin/main reference; the remaining worktree changes are the same 22 pre-existing discord-bot deletions. No original commercial assets or generated PE/Wasm payloads were staged. No push.
