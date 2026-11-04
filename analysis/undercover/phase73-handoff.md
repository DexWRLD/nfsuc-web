# Phase 73 handoff — browser backend adoption remains NO-GO

Baseline: Phase 72 actually executed Unicorn.js x86 2.1.4 in an Edge HTTPS worker. The same 173 original instruction tags, 12 function entries/seven bodies, nine returns, 27 PE-global writes, 68 reads, defined flags and per-tag registers, mapped memory/stack and FS events match existing Wasm. Provider stop stays 0x0087B5B3 through [0x00B61398]=0x008AAC6A. No CRT/startup advancement or new unique harness functions.

Read runtime-phase72.md, browser-x86-feasibility-phase72.json, browser-x86-differential-phase72.json and browser-x86-benchmark-phase72.md. Final measurements drive generated inspector status. The checked adapter fails the <=5x gate by a large margin. Browser x86 remains disabled; only translated Wasm is available on the site.

## Reproduce before changing scope

1. Verify HEAD/status. Preserve 22 unrelated discord-bot deletions. No fetch/push. Source SHA 6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd; canonical master f293d93d31fcbf86ad9b9639f2cf10c34defe9c621cfe7f1a5e975f598ddf88a.
2. If the outside-repo engine is unavailable, explicitly run tools/uc_browser_x86_prepare.py with an outside-repo destination. This retrieves only the already reviewed pinned GPLv2 package, verifies integrity, and runs no npm install scripts. Do not add the binary to Git or website manifest.
3. Set UC_BROWSER_X86_ENGINE and UC_AUTHENTIC_ASSET_ROOT. Run web/test/uc-browser-x86.test.mjs with UC_BROWSER_X86_EVIDENCE selecting a new evidence file. It must run in Edge, not skip. Keep the current reference and exact failure assertions.
4. Retain explicit synthetic thread/segment classification. Raw engine EIP at rejected target and original dispatcher callsite EIP are distinct recorded observations; do not hide this trap presentation difference.

## Highest-value bounded next target

Profile the existing 173-instruction control only. Separate digest/map/copy/read-hook/write-hook/single-step/register-snapshot/yield costs. Do not remove checks or claim a faster comparison from disabling instrumentation on only one side. First establish whether a reviewed persistent engine or shared-memory strategy can meet <=5x with identical semantics and bounded execution. A different candidate requires source/version/license/build review before download/integration.

No production mixed-backend resume exists. Terminal engine registers are copied to the process; experimental flag validity and journals are returned in evidence, not admitted into the production Wasm bridge's private CPU state. To change that, prove original CALL/RET, EIP/ESP/EBP/general registers, definedness, segments/FS, pending trap, journals and reset consistency across every transition. Keep one authoritative checked guest memory; test stale private-page rejection and writes across transitions. Never present reset-separated comparisons as mid-frame handoff proof.

GO adoption only after <=5x measured equivalent browser execution, full differential, resource/invalid/provider negatives, source-build reproducibility, applicable distribution obligations and all regressions pass. Otherwise stop. Do not broaden to the optional CPU/SIMD initializer or more helpers to inflate coverage. No native-only substitute.

The engine uses GPLv2 and is not part of the application's MIT license. Published package integrity is reproducible; rebuilding identical output from pinned source/toolchain has not been established. Future distribution needs the appropriate notices and corresponding source/build materials. No engine/commercial binary is currently committed or added to the private manifest.

## Boundaries and preserved behavior

Do not reopen legacy binding research without new independent writer/loader/copy evidence. Import-name RVAs are not callable pointers. No decoding identity, copied IAT, invented secret/entropy/sentinel/thread owner or successful callback registration. No unavailable code execution/reconstruction/bypass. Original PE entry, provider/CRT lifecycle, allocator/device/resource paths and D3D9 are still separate blockers. Original game remains read-only and unlaunched.

Keep authentic JPEG/silent bumper, OPFS/private HTTPS, synthetic previews, Phase 60 nine cases, flags/SEH/import tests and full-game Play disabled. Preserve the canonical export. Six private asset paths and version 69 remain unchanged. Existing historical ledger stays 84 unique/50 enterable/358 runs; this CPU rerun adds zero.

Phase 72 validation: 157 Node/Edge tests (156 passed, one existing skip), 134 Python unit tests, native comparison with 105 arithmetic cases, separate two-test inspector/media check, TypeScript/frontend/Wasm/campaign/dashboard pass. Record actual commands and outcomes for future changes; do not count benchmark reruns as unique functions.
