# Phase 60 frontend frame frontier

Baseline main 9acf9d1, 24 ahead of local origin/main, with the earlier audit untracked. The installed executable was hash-verified by the builder. The original frame routine was lifted from the bounded text range 0x008096E0–0x00809731. Full-span lifting followed the unsupported tail target and failed on LES.

## Edge execution

The probe enters the original mid-function block at 0x00785CD9 with fixture EBX zero and a bounded stack. The block reads ECX from [0x01873134], compares it with EBX and executes its original call at 0x00785CE3 when different. The call pushes 0x00785CE8 and enters 0x008096E0, with no stack arguments. The second static caller uses the same pattern at 0x00786798–0x007867A2. Scheduler, containing frame entry ABI, thread ownership and authentic manager state remain unverified.

| Fixture | Last verified guest operation and stop |
|---|---|
| Gate zero, manager 0x0300EC00 | 0x00809730–31 restores ESI and returns. ESP is restored to 0x0300EFFC. The diagnostic stops at 0x00785CE8 before the next global read. |
| Gate one, manager +0x18 zero | 0x008096F2 computes ECX=0x0300EC08. Original call boundary 0x008096F5 targets unresolved 0x00548810. ESP 0x0300EFF0 includes the call return slot. |
| Gate one, +0x18 one, +0x34 zero | 0x00809727 computes the same receiver, 0x0080972A restores ESI, and tail boundary 0x0080972B targets 0x00548810. ESP 0x0300EFF8 retains the caller return slot. |
| Null manager global | Original caller skips the call and reaches 0x00785CE8. |
| Direct null receiver | Original byte read at 0x008096EC traps on 0x18. |
| Unmapped receiver | Same byte read traps on 0xDEAD0018. |
| Nonzero +0x34 and null +0x4C | Read at 0x00809703 traps on 0x1C while resolving the first virtual receiver. |

The enabled gate uses the reported original static value one. Gate zero and manager data are diagnostic fixtures. No original work-state writes or virtual dispatch returns occurred. No substitute implementations were provided.

## Work state

Original 0x0080970B calls through the child of manager.ptr(+0x4C) at +0x1C, with vtable slot +4. The next call at 0x00809717 reads manager.ptr(+0x34), uses vtable slot +0x10 and pushes -1. Only after these returns does 0x0080971C call 0x008082F0 with ECX=manager.ptr(+0x4C).

The helper saves ESI and reads receiver +8. A nonzero value triggers the six-argument dispatch at 0x00808318 through child at +0x1C and vtable slot +0x0C. The ordinary stores after return write +0x14=0, +0x18=2, +4=0, +8=0. The zero branch skips those stores but still reaches child slot +8 at the tail dispatch 0x00808340. Live child provenance, virtual return contracts and frame presentation are unresolved.

## Resource frontier

Read-only inventory and whole-file SHA-256:

| File | Bytes | SHA-256 |
|---|---:|---|
| FRONTEND/LOGOTEXTURES.BUN | 2178816 | 4822ff18c9810f7fbf7e9ad9a09bd5ee59745c86f5087b21cd8bb9538a686352 |
| FRONTEND/BOOTFLOWTEXTURES.BUN | 530176 | 3d188dbc4ded3237805fe04258d419bade3094ba3f80593345d325c0b7bd4925 |
| FRONTEND/FRONTB1.BUN | 450304 | e1b5ec6d759d7ad44268306f7d04bb2cb47a484a919987e771ba302b54893c00 |
| GLOBAL/UNIQUEBOOTTEXTURES.BIN | 118784 | 69bf7cde83c45f721b0d2891738f6691e61089149f2552ee7ec26956196d4f7e |

The existing intro report records no direct reference to the BOOTFLOWTEXTURES path or LoadUniqueBootflowTextures label. BootLoadingScreen and LS_EALOGO.FNG, LS_SPLASH.FNG and MC_MAIN.FNG remain string leads. The reviewed evidence supplies no ordinary directory reader mapping one identifier to a verified byte span and downstream decoder. No payload or decoded dimensions are claimed. The existing authentic JPEG and bumper remain independent previews.

## Validation and readiness

TypeScript, frontend and Wasm builds completed. The 53-test targeted Node and Edge HTTPS suite passed after correcting the expected trap stack depths. It repeats all seven frame cases and verifies authentic bumper playback and prior diagnostics. The Wasm build retains an unused linker-path warning. Python Phase 43–51 regressions, guest campaign and dashboard consistency checks were rerun.

FRONTEND_FRAME_PREFIX_BROWSER_VERIFIED and FRONTEND_FRAME_CALLER_EDGE_BROWSER_VERIFIED apply to synthetic state. FRONTEND_FRAME_WORK_STATE_VERIFIED, ORIGINAL_FRONTEND_RESOURCE_SPAN_VERIFIED, ORIGINAL_FRONTEND_SCREEN_DISPLAYED, ORIGINAL_BOOT_ORDER_VERIFIED and ORIGINAL_GAME_BOOT_EXECUTING remain unverified. FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND remains blocked. Historical harness totals are unchanged at 84 unique, 50 enterable and 358 runs.

## Revalidation and stronger frame evidence — 2026-11-04

The Phase 60 instructions were supplied again after Phase 67. Actual baseline was a63eb537, main twelve ahead of the unchanged local origin/main reference. Phase 67 implementation 05a3cd7d and its later initialization frontier were retained. The pre-existing 22 discord-bot deletions and earlier project audit were preserved. There was no rollback, fetch, game execution, asset modification or push.

Freshly checked the Phase 59 callback report, existing Phase 60 work/handoff, Phase 53–58 diagnostic reports, post-Phase-52 audit, startup resource evidence, current builder/inspector, HTTPS tests and private media infrastructure. Both installed executable and canonical master hashes remain as recorded. Ghidra confirmed the same original program SHA and instruction bodies.

### What changed

The existing bounded original frame/caller probe now records each original instruction address, all nine guest registers and fixture-integrity observations. Frontend Frame Processing shows structured per-case gate, manager, state bytes, selected branch, original callsite, last tagged instruction, stack, fault/boundary and evidence classification. It explicitly distinguishes synthetic field values from fields actually read before a stop. No homepage redesign or additional frontend architecture.

Two new negative cases distinguish a present null manager global from an absent mapping, and reject a truncated manager mapping. All 20 fixture words, including two distinct sentinels, are checked after each run. The real frame prefix performs no manager work-state writes before these boundaries. Original stack stores are not counted as manager writes.

An initial missing-global run exposed optimization of trace updates past a trapping read. The trace array/count and diagnostic CPU fields are now volatile, preserving pre-trap observation. The expected original address remained 0x00785CD9; it was not weakened to accept a missing trace. All cases now pass. The Phase 67 shared module rebuilt to its identical SHA, so that later runtime and private manifest remain unchanged.

### Fresh Edge HTTPS trace

edge-frame-phase60-revalidation.json is actual captured Edge output, not a reconstructed trace. The browser repeats the complete diagnostic and checks identical results while authentic media continues to play. Each case uses a fresh diagnostic instance and explicitly synthetic bounded state; these repetitions add no unique original functions to the native execution ledger.

| Case | Last tagged original instruction | Result / fault address | ESP |
|---|---|---|---|
| Gate zero | 0x00809731 RET | Returns to original 0x00785CE8 continuation boundary | 0x0300EFFC |
| Gate one, +0x18 zero | 0x008096F5 CALL | Unsupported 0x00548810; ECX=0x0300EC08 | 0x0300EFF0 |
| Gate one, +0x18 one, +0x34 null | 0x0080972B JMP | Unsupported 0x00548810; ECX=0x0300EC08 | 0x0300EFF8 |
| Present null manager global | 0x00785CE1 JE | Original caller skips callee; reaches boundary 0x00785CE8 | 0x0300EFFC |
| Direct null receiver | 0x008096EC CMP byte | Read rejected at 0x00000018 | 0x0300EFF8 |
| Unmapped receiver | 0x008096EC CMP byte | Read rejected at 0xDEAD0018 | 0x0300EFF4 |
| +0x34 nonzero, null +0x4C | 0x00809703 MOV | Virtual setup read rejected at 0x0000001C | 0x0300EFF4 |
| Manager global absent | 0x00785CD9 MOV | Original caller read rejected at 0x01873134; callee not entered | 0x0300EFFC |
| Truncated manager | 0x008096EC CMP byte | State read rejected at 0x0300EC60 | 0x0300EFF4 |

For faults, a tagged instruction is the attempted instruction, not a claim that its read completed. At unsupported calls the original return-address push is retained; no helper result is supplied. The gate-zero case preserves ESI=0x1234, EBP and the original return/stack contract. Register snapshots on blocked paths are partial-execution state, not completed callee-preservation guarantees.

Original 0x00785CE3 dispatches into 0x008096E0 in the appropriate cases. The null-global and absent-global controls do not enter the callee; direct-null mode intentionally has no original caller. The gate is freshly verified as static one in PE data. Gate-zero and receiver bytes are fixtures.

Ghidra identifies containing functions 0x007856F0–0x007866AA and 0x007866B0–0x00786855 with unknown calling conventions. Independent original-byte disassembly confirms both caller sequences, 0x00785CD9/0x00785CE3 and 0x00786798/0x007867A2. Only the first mid-function caller block is browser-entered. Its fixture supplies EBX=0 as the comparison sentinel. Full frame-loop entry ABI, actual manager construction, scheduler reachability, thread ownership and original boot order remain unverified.

Fresh 0x008082F0 disassembly confirms that its nonzero +8 path performs six-argument virtual dispatch at 0x00808318 before the four ordinary stores. The +8-zero branch skips those stores but still tail-dispatches via child slot +8 at 0x00808340. No branch shown establishes a complete return without resolving a virtual provider. The helper was not executed with fabricated virtual returns; its field stores remain static evidence only. No menu transition or frame presentation is inferred.

### Bounded resource-loader investigation

tools/uc_frame_evidence.py performs read-only SHA checking, original instruction disassembly and four-file header/hash inventory. frame-resource-revalidation.json records the exact lengths, hashes and first 32 bytes. All four match the historical table above. No source file or extracted payload was copied into Git or the delivery manifest. Raw outer-header bytes do not establish texture membership, compression, dimensions or a decoded screen.

Fresh PE string locations: BootLoadingScreen at 0x00B86370 and 0x00BBB9B3, LS_EALOGO.FNG at 0x00B74FA4, LS_SPLASH.FNG at 0x00B74F80, MC_MAIN.FNG at 0x00B74FD0. BootLoadingScreen has a DATA reference from 0x00CC5EE8; LOGOTEXTURES has the previously recorded DATA reference at 0x00CC5EAC. The queried table/path/name entries did not produce an ordinary function reader. A bounded direct-reference query cannot exclude aliased or computed readers. No adjacent-name or table-membership inference is promoted to a payload span.

Missing evidence remains an ordinary directory/index reader that ties a concrete resource identity to a bounds-checked offset/length and downstream decoder/consumer. No independently decoded BUN texture or FNG screen is established. Source/payload offsets and decoded dimensions therefore remain null in the machine-readable report. Authentic JPEG and silent bumper are independent previews, not original BUN loading or boot scheduling. No archive decryption, provider bypass or speculative extraction was attempted.

Fresh static evidence: ghidra-frame-revalidation.json and resource-name-xrefs-revalidation.json. A trustworthy next resource target is the original reader of the path/screen table, not more guessed archive scanning.

### Fresh validation

All final commands exited 0:

- `python tools/uc_browser_init.py "C:/Games/Need For Speed Undercover/nfs.exe" web/dist/uc-init-009e8ad0.wasm`: built diagnostic including frame/caller slices; retained unused linker-path warning. Module SHA-256 a134a0f42416924a37078e10f086e972008920608ed51c3a157183d8006e36c0. Generated module stays outside Git.
- From web: `node node_modules/typescript/bin/tsc -p .` and `node build.mjs`: passed.
- From web: `node tools/unit-tests.mjs --fast`: 149 tests, 148 passed, zero failures, one skip. Environment UC_BROWSER_CHANNEL=msedge, UC_BROWSER_INIT_TEST=1, UC_UNIFIED_TEST=1, UC_AUTHENTIC_ASSET_ROOT=C:/Users/999/.nfsuc-web/authorized-startup, UC_FRAME_EVIDENCE=analysis/undercover/edge-frame-phase60-revalidation.json (absolute output path in the actual invocation).
- Edge HTTPS tests capture all nine frame cases, exact callsite/last-address/stack behavior, repeated results, preserved manager sentinels, authentic JPEG/bumper, OPFS reload and the later Phase 67 unified execution. The skip is an older synthetic-logo test requiring missing bundled Chromium; real media tests ran in Edge.
- Python Phase 43–51 scripts, individually: 121 passed (52/10/8/23/8/6/5/4/5); startup preflight: three passed. The existing Phase 49 unclosed-file ResourceWarning does not fail its tests.
- `python tools/uc_phase31_campaign.py`: expected completed chains and explicit state/unsupported-boundary failures retained.
- `python tools/uc_frame_evidence.py "C:/Games/Need For Speed Undercover" --output analysis/undercover/frame-resource-revalidation.json`: source hashes and ordinary instruction evidence captured.
- `python tools/uc_unified_build.py "C:/Games/Need For Speed Undercover/nfs.exe" "C:/Users/999/.nfsuc-web/authorized-startup"`: ten bindings; shared module SHA unchanged at 8f92346a8de81c8ee6005b2ac01036e954b9e25585cd5c25ad1b515cd646cba5.
- `python tools/progress.py` and `python tools/uc_progress_test.py`: dashboard consistency passed. The project's current_phase remains 67; separate frontend_frame_revalidation classifications were added rather than rewinding progress.

Readiness remains: FRONTEND_FRAME_PREFIX_BROWSER_VERIFIED=true and FRONTEND_FRAME_CALLER_EDGE_BROWSER_VERIFIED=true for synthetic state. FRONTEND_FRAME_WORK_STATE_VERIFIED=false; ORIGINAL_FRONTEND_RESOURCE_SPAN_VERIFIED=false; ORIGINAL_FRONTEND_SCREEN_DISPLAYED=false; ORIGINAL_BOOT_ORDER_VERIFIED=false; ORIGINAL_GAME_BOOT_EXECUTING=false. FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND remains BLOCKED. These do not classify 0x00548810 itself as protected.

No full-game launch was enabled. Existing private HTTPS, six-path manifest, asset authorization, OPFS, Undercover-only branding and all prior diagnostics remain intact. No original commercial asset was committed. The pre-existing unrelated deletions remain outside the local commits. No push.

Local implementation commit a7048d53. The existing dashboard now shows the fixture-qualified frame prefix/caller milestones and keeps resource span, work state, screen, boot order and original game boot unverified. Its obsolete WASM/BROWSER not-started label is corrected to diagnostics verified, boot blocked. No historical native execution count changes. Reports and evidence are saved in the following local documentation commit.
