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
