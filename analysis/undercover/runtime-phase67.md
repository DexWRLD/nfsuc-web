# Phase 67: verified flags and the ordinary cleanup-wrapper frontier

The unified browser process now enters original wrapper 0x0087B640 through the original call at 0x00B57DD2. It forwards callback 0x00B602E0 and stops at 0x0087B644 → 0x0087B59B. Cleanup registration has **not** completed. The arithmetic following that call is verified with isolated synthetic-callee fixtures; it is **not** reached in the original connected execution.

## Baseline and scope

Baseline HEAD was 40278dd8, with implementation 47865ed3 present; main was ten ahead of the local origin/main reference. The only pre-existing worktree changes were 22 discord-bot deletions, preserved and excluded from Phase 67 commits. No fetch or push.

Original nfs.exe SHA-256 was checked as 6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd. Canonical master SHA-256 remains f293d93d31fcbf86ad9b9639f2cf10c34defe9c621cfe7f1a5e975f598ddf88a, 54,494,254 bytes. Ghidra independently identified the same PE32 x86 program and image base 0x00400000. No original executable or asset was executed or modified. Opaque runtime boundaries and PE entry 0x01FCA510 remain untouched.

The supplied Phase 67 attachment was 6,171 bytes and ends mid-sentence in section 6. Work followed all available instructions and the Phase 66 handoff; missing later instructions were not invented.

Reviewed Phase 66 report, handoff, readiness and dependency graph, both recorded execution traces, canonical index, registry, RawLifter bridge, dispatcher, native CPU flag helpers and existing browser tests. ghidra-phase67.json captures fresh bounds, disassembly, decompilation warnings and relevant cross-references. pe-evidence-phase67.json is independently reproducible from the authenticated original file with tools/uc_phase67_evidence.py.

## Original wrapper and ABI

Ghidra and PE bytes agree on the complete contiguous 18-byte body 0x0087B640–0x0087B651, without decompiler warnings. Ghidra's calling convention is unknown; cdecl with one dword argument is inferred from original caller cleanup and the wrapper's plain RET, not from its generic signature.

| Address | Original instruction | Verified effect |
|---|---|---|
| 0x0087B640 | PUSH [ESP+4] | Read original callback argument before decrementing ESP |
| 0x0087B644 | CALL 0x0087B59B | Push original return 0x0087B649; unresolved ordinary callee |
| 0x0087B649 | NEG EAX | CF is one iff callee result is nonzero; updates arithmetic flags |
| 0x0087B64B | SBB EAX,EAX | Consume CF; yield zero or 0xFFFFFFFF, with unsigned borrow |
| 0x0087B64D | NEG EAX | Yield zero or one; update CF |
| 0x0087B64F | POP ECX | Remove forwarded dword; flags unchanged |
| 0x0087B650 | DEC EAX | Return -1 for zero callee result, otherwise zero; preserve CF |
| 0x0087B651 | RET | Pop caller return; original caller removes its own argument |

The wrapper itself uses EAX/ECX and stack only, with no global accesses or indirect calls. Its sole direct callee is 0x0087B59B. EBX/ESI/EDI/EBP preservation is conditional on the real callee's still-unverified behavior. Fixture tests prove wrapper preservation when that callee fixture preserves them, rather than claiming a complete downstream ABI.

The builder checks the wrapper's exact source bytes, canonical decompiled status, exact body range and recovered direct-call set. The registry now has ten callable bodies. The complete wrapper is admitted; its unavailable callee has no execute binding. Merely entering the wrapper does not establish its success path.

## Bridge changes and arithmetic evidence

tools/uc_unified_flags.h replaces approximate equal/less state with volatile CF/PF/AF/ZF/SF/OF and a validity mask. The bridge transfers arithmetic flag values and validity across nested imports, alongside the Phase 66 volatile CPU registers. Eager flag computation avoids stale flags from local liveness masks at function boundaries. Values in cpu.eflags represent only the six supported arithmetic bits; this is not general EFLAGS, DF, system-flag, TLS or SEH support. The validity mask uses CF/PF/AF/ZF/SF/OF as bits 0–5.

ADD/SUB/CMP, NEG, SBB, DEC and logical condition handling mask operands to 8/16/32 bits. Borrow uses widened unsigned comparisons, including b+carry crossing 32 bits. Signed overflow, auxiliary carry, low-byte parity, sign and zero are computed separately. DEC preserves both incoming CF and its validity. Logical AF is undefined and invalidated; an attempted read traps. Unknown incoming carry consumption traps. The builder rejects instruction mnemonics outside its explicit reviewed subset, so new flag/system operations cannot silently inherit approximate behavior.

The wrapper exposed a separate PUSH-order bug: the old macro decremented ESP before evaluating its operand. PUSH [ESP+4] would therefore forward the wrong stack word. It now evaluates the source first. POP similarly captures the old stack word before advancing ESP and assigning its destination.

Four independent Wasm tests cover 1,053 arithmetic boundary cases across three widths, all 16 condition codes for binary arithmetic, zero/underflow/signed overflow, unknown CF, undefined logical AF, invalid width, DEC carry preservation, re-entrant imports, and original lifted-wrapper stack/return behavior. Arithmetic expectations use independent BigInt range and nibble-borrow calculations, not the implementation formulas. Input CF is established by an executed SUB. The nested test establishes CF then clears it with a re-entrant executed SUB. Wrapper fixture callee returns 0, 1, 0x80000000 and 0xFFFFFFFF. Expected wrapper flags are 0x94 for a zero return and 0x45 otherwise.

These fixture functions and synthetic callee returns exist only in a temporary test module. They are not registered with the game process, counted as original game bodies, or used to create cleanup state.

## Why the callee is not admitted

0x0087B59B has Ghidra warnings for injected SEH prolog/epilog semantics. Its body is noncontiguous: the listing reaches an indirect call at 0x0087B5FF and later includes 0x0087B631 → 0x0087BEFD and RET at 0x0087B636. The 108-byte body membership is not the same as the whole bounding span. Flattening that interval or accepting the injected C pseudocode would omit relevant exception behavior.

Its verified first instructions push 0x14 and scope table 0x00CA9380, then call 0x0087BEB8 at 0x0087B5A2. The prolog reads FS:[0] at 0x0087BEBD, reads cookie cell 0x01285688, encodes frame data and writes FS:[0] at 0x0087BEF6. No thread environment, FS base, previous exception-chain head or supported exception-frame lifecycle exists in the browser process.

The prolog also has a nonstandard stack contract. If the original cleanup callee's entry ESP is S, the prolog receives ESP=S-12. It sets EBP=S-4, reserves 0x14 bytes and saves registers/cookie; its final RET resumes at 0x0087B5A7 with ESP=S-56. Treating it as an ordinary cdecl helper would be incorrect. This calculation comes from original instructions; it was not executed with a fabricated FS head. The existing native campaign independently remains blocked on its unmodeled address-zero access in related roots.

| State or provider | Fresh file-backed evidence | Remaining dependency |
|---|---|---|
| 0x018B1E6C / 0x018B1E68 | Zero-filled .data tails; no file-backed dword | Real CRT/global initialization and encoded-state meaning |
| 0x01285688 | .data dword 0xBB40E64E | Actual startup cookie initialization/lifecycle |
| 0x00B61398 | .rdata dword 0x008AAC6A; not an import-directory cell | At 0x0087B5B3, CALL ESI passes state from 0x018B1E6C; target boundary and ABI unresolved |
| 0x00B61394 | .rdata dword 0x008AAC60; not an import-directory cell | Conditional call at 0x0087B5C1 if prior EAX=-1; callback argument |
| 0x00B6138C | .rdata dword 0x008AAC46; not an import-directory cell | Three-argument indirect call at 0x0087B5FF; unresolved provider |

In the current Ghidra body, 0x008AAC69 is a four-byte LEA; 0x008AAC6A lies inside that instruction. Starting a different linear decode there does not establish a callable function. The function at 0x008AAC60 starts by reading [ESP+0xC0], inconsistent with assuming a simple one-argument import thunk without further evidence. No runtime rewrite, alternate entry, import identity or callable provider is inferred. Ghidra cross-references show reads of the relevant cells, not a proven writer establishing usable runtime providers. Static cross-reference coverage is not proof that no writer exists elsewhere.

No Windows API was reached. No platform adapter, allocation, success stub, exception-chain head or provider pointer was fabricated. 0x0087B59B and its helpers remain ordinary unresolved code, not automatically classified as protected.

## Actual connected execution and order

Original verified path:

    host diagnostic entry: 0x00B57DC0
      0x00B57DC3: original MOV ECX,0x0189D0A0
      0x00B57DC8 → 0x009E7540
        six original calls → 0x009E75A0
        one original call → 0x009C1830
      0x00B57DD2 → 0x0087B640
        0x0087B640: original forwarded-argument PUSH
        0x0087B644 → 0x0087B59B [blocked before callee entry]

Node and Edge observed ten entries across five distinct original bodies, eight completed callee returns and the same 27 original global writes. The root and wrapper do not return. The constructor's original receiver, six headers, +0x3C gap, child constants 0x32000/0x186A0, byte store and callback-table regression are preserved. The exact Phase 66 checkpoint remains recorded at wrapper entry: callsite 0x00B57DD2, return 0x00B57DD7, ESP=0x0300EFF0.

At the new stop: EIP/last tagged instruction=0x0087B644, ESP=0x0300EFE8, EAX=0x0189D0A0; stack top=0x0087B649, +4=0x00B602E0, +12=the original 0x00B602E0 argument. The PUSH at 0x0087B640 completed; the CALL's original return-address push completed before dispatcher rejection. The target body was never entered. No NEG/SBB/DEC instruction after that call ran in this real prefix.

Host scheduling of the independent callback-table initializer, callback diagnostic root and Apt root remains a diagnostic sequence. It is not original startup sequencing. No edge from PE entry to these roots, actual cleanup-registration completion, original game boot or gameplay frame has been established. The older 0x009E4B49 / 0xFFFFFFFC fault remains an exact separate regression.

## Browser preview and delivery

The existing Play Development Preview → initializer inspector → Run Shared Process Integration shows ten reviewed addresses, flags validity, the Phase 66 checkpoint, new stop and explicit difference from Phase 66. No redesign or second frontend. Node evidence is unified-execution-phase67.json; actual Edge HTTPS evidence is edge-execution-phase67.json.

Private manifest version 67 retains the same six allowlisted paths. PE payload SHA remains 35bc6b5a51a82fa9fc0ea5be991e1f67a4bbcfa87f2cd529867e40ed7961fcfa. The 10,710-byte module SHA is 8f92346a8de81c8ee6005b2ac01036e954b9e25585cd5c25ad1b515cd646cba5. Module, payload, JPEG and silent bumper stay outside Git under the previously authorized private asset root. No network exposure was widened. The existing server remains bound to 127.0.0.1:8443; this loopback address is for local testing, not a newly opened second-device LAN listener. HTTPS manifest and Wasm HEAD both returned 200. OPFS reload checks retain one payload download per clean test context.

## Validation and commands

Commands ran from the repository unless marked web. All successful commands below exited 0.

| Command | Result |
|---|---|
| python tools/uc_unified_build.py "C:/Games/Need For Speed Undercover/nfs.exe" "C:/Users/999/.nfsuc-web/authorized-startup" | One shared module; 11 section descriptors, ten bindings |
| python tools/uc_unified_publish.py ... --allowlist .../phase52-allowlist.json --manifest .../phase52-manifest.json --version 67 | Six paths; 16,411,023 total authorized bytes |
| web: node node_modules/typescript/bin/tsc -p . | Passed |
| web: node build.mjs | Passed |
| web: node tools/unit-tests.mjs --fast | 149 tests, 148 passed, zero failed, one skipped |
| web: node --test test/uc-unified-flags.test.mjs | Four independent fixture tests passed |
| web: node --test test/uc-unified-initialization.test.mjs test/uc-unified.test.mjs | Three real-source/registry regressions passed |
| python tools/uc_startup_preflight_test.py | Three passed; master and entry boundary preserved |
| python tools/uc_phase43_test.py through tools/uc_phase51_test.py, individually | 121 passed: 52/10/8/23/8/6/5/4/5 |
| python tools/uc_phase31_campaign.py | Expected successful chains and explicit state/boundary failures preserved |
| python tools/uc_phase67_evidence.py "C:/Games/Need For Speed Undercover/nfs.exe" --output analysis/undercover/pe-evidence-phase67.json | Read-only source/slot/instruction evidence |
| python tools/uc_startup_preflight.py ... --output analysis/undercover/startup-readiness.json | Updated frontier, startup still blocked |
| python tools/uc_recovery_inventory.py | 8,674 recovery records; candidates remain noncallable |
| python tools/progress.py; python tools/uc_progress_test.py | Dashboard regenerated and deterministic validation passed |

Browser environment: UC_BROWSER_CHANNEL=msedge, UC_BROWSER_INIT_TEST=1, UC_UNIFIED_TEST=1 and UC_AUTHENTIC_ASSET_ROOT=C:/Users/999/.nfsuc-web/authorized-startup. UC_BROWSER_EVIDENCE captured the Edge trace; UC_UNIFIED_EVIDENCE separately captured Node. The one skip is the old synthetic-logo test requiring unavailable bundled Chromium; actual logo/media and unified execution tests ran in Edge. A pre-existing Phase 49 ResourceWarning was emitted without a test failure.

During development, the standalone fixture initially needed adaptation of RawLifter's outside-text dispatch form. The first full batch also caught a text-encoding change to an existing arrow assertion; that unintended change was corrected. Neither failure was hidden or handled by weakening expected guest results. The final suites passed. An initial restricted temporary-directory build failed before compilation and succeeded with normal approved local build access.

## Readiness and next work

Verified: shared original memory, 27 constructor writes, original constructor returns, one additional connected wrapper entry, source-backed reviewed registry, correct arithmetic subset, checked stack forwarding, explicit unavailable target and private browser cache/media regressions.

Blocked: actual wrapper result/return, cleanup registration, SEH lifecycle, provider identities, initialization of 0x018B1E6C/68, PE-entry continuation, original full-game startup and authentic gameplay rendering. The full-game button remains disabled. No unique native-harness body count is increased for browser reruns or fixture arithmetic. Historical native ledger totals remain 84 unique, 50 enterable, 358 runs. No additional NFSU2-derived tool deletion is justified by this work.

Phase 68 should establish the ordinary CRT/SEH thread-state and provider initialization contracts before admitting 0x0087B59B. Keep unsupported FS accesses explicit; do not convert them to flat address zero or seed a fabricated chain. Verify 0x0087BEFD's paired restore behavior and actual body membership before implementing a specialized prolog contract. Keep the current ten-binding regression as the control.

## Local delivery

Implementation commit: 05a3cd7d. Documentation/evidence are in the following local Phase 67 commit. No push. After these two commits, main is twelve ahead of the unchanged local origin/main reference; the remaining worktree changes are the original 22 discord-bot deletions. No commercial asset or generated PE/Wasm payload is staged.

Exact private-manifest update command:

    python tools/uc_unified_publish.py "C:\Users\999\.nfsuc-web\authorized-startup" --allowlist "C:\Users\999\.nfsuc-web\authorized-startup\phase52-allowlist.json" --manifest "C:\Users\999\.nfsuc-web\authorized-startup\phase52-manifest.json" --version 67

Exact startup evidence command:

    python tools/uc_startup_preflight.py "C:\Games\Need For Speed Undercover\nfs.exe" --output analysis/undercover/startup-readiness.json
