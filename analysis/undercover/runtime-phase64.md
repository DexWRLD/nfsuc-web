# Phase 64 recovery audit and unified runtime foundation

Baseline f9d574b4 on main, four ahead of local origin/main. Existing discord-bot deletions were preserved and excluded from this phase's commits. No fetch or push.

## Recovery findings

The master remains 54,494,254 bytes with SHA-256 f293d93d31fcbf86ad9b9639f2cf10c34defe9c621cfe7f1a5e975f598ddf88a. Its index records 200 unavailable Ghidra bodies, 921 unavailable/rejected additional candidates, 3,143 warned emitted Ghidra bodies and 308 warning-free bodies independently rejected by discovery. These populations overlap with the 14,846 computed-call occurrences. Executable gaps remain address coverage data, not a missing-function count.

tools/uc_recovery_inventory.py builds recovery-priority-index.json as a union by address with original classifications, reasons, callers, callees, computed callsites, uncertainty, relevance and recommended action. It prioritizes the PE entry and ordinary initialization/platform/resource/frame dependencies. dispatch-candidates.json contains only noncallable metadata. windows-service-inventory.json records signatures and name-based service categories with explicit ownership-review requirements.

Static alternative decodings and source bytes are recorded in entry-alternative-decodings.json. The 0x01FCA516 conditional branch depends on incoming carry. Jumps at 0x01FCA527 and 0x01FCA598 enter overlapping streams. The saved index provides no verified ordinary callee. No branch was chosen and no opaque entry code was executed. No speculative repair changed the master or index.

## Foundation

web/src/host/uc-process.ts implements checked mapping, zero fill, reset, original VA reads/writes, permissions, CPU state, bounded dispatch, vtable resolution and call-return trace. It uses WebAssembly.Memory and native uc_image.h permission semantics. The implementation is a reusable process foundation with synthetic tests, rather than an additional original-function demo. unified-runtime-readiness.md lists the supported and missing capabilities. Original translated diagnostics are not yet connected to this process memory.

## Cleanup

The active frontend cleanup from aff9c648 remains intact. Bounded inspection confirmed web/build.sh is an old SPEED2.EXE/server.dll pipeline and runtime/career.c implements former-game progression hooks. Those files are still referenced by the retained legacy native build/test graph. No new native deletion was made because the reusable portions and callers have not been disentangled. The previous automatic review rejection remains applicable to broad native deletion. The 998 investigation paths were not bulk deleted. This phase improves classification, with complete native cleanup still pending.

## Fresh validation

- New guest-process suite: 10 passed, zero failed. Includes the original static vtable bytes and synthetic ABI/memory tests.
- Maintained Node and Edge HTTPS batch: 142 tests, 141 passed, zero failed, one skipped. Includes synthetic foundation checks inside Edge and authentic EA bumper/cache/guest diagnostics.
- TypeScript, frontend build and existing Wasm diagnostic build exited 0. Clang retained the known unused linker-path warning.
- Master/startup preflight tests: three passed.
- PE preflight retained BLOCKED_UNVERIFIED_ENTRY_CONTROL_FLOW.
- Python Phase 43–51 regressions each exited 0.
- Guest campaign exited 0 with expected blocked cases.
- Dashboard test exited 0.

The infrastructure tests establish bounded contracts. No new original startup execution, native allocator, Windows threading, Direct3D device, screen display or gameplay was verified. Historical harness totals remain unchanged.
