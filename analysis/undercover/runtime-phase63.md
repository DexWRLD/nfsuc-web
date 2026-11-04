# Phase 63 startup readiness and cleanup

Baseline aff9c648, main two ahead of local origin/main. There were pre-existing deletions in discord-bot; these were not restored or included in Phase 63 commits. The earlier project audit is tracked at the current baseline. No remote fetch.

Master integrity passed: 54,494,254 bytes, SHA-256 f293d93d31fcbf86ad9b9639f2cf10c34defe9c621cfe7f1a5e975f598ddf88a. It contains 17,367 Ghidra inventory markers and 8,401 disjoint fallback-body markers. This includes unavailable Ghidra entries and thunks as inventory; 25,419 actual emitted bodies is the separate body tally.

The preceding cleanup commit aff9c648 removed 114 explicit legacy frontend/test/artwork paths, with per-path reasons. Phase 63 classified every one of the 1,400 tracked paths at inventory time: 366 Undercover, 30 reusable shared, six mixed build pipelines and 998 requiring investigation. These classifications express evidence scope. The last group is not proof of unused code. Native gameplay implementations and old build/test graph remain, so the complete legacy-native cleanup objective is still open. The active browser entry and homepage use Undercover branding and the validated preview infrastructure.

tools/uc_startup_preflight.py is new foundational tooling. It reads the source PE and canonical index, checks hashes and architecture, verifies the entry jump bytes and emits startup-readiness.json with an explicit blocked result. It does not execute the game. No new isolated Wasm demo was added. The ordinary startup path is not yet verified beyond 0x01FCA510. Independent static inspection confirms the overlap jump 0x01FCA527 → 0x01FCA523. The saved decompiler lists no ordinary callee. startup-dependency-graph.md records the unresolved entry, ordinary islands and missing platform/game providers.

## Fresh validation

- python tools/uc_startup_preflight_test.py: three passed, including master marker uniqueness, verified-entry blocked result and wrong-source rejection.
- python tools/uc_startup_preflight.py with the installed nfs.exe and --output analysis/undercover/startup-readiness.json: exit 0, reports BLOCKED_UNVERIFIED_ENTRY_CONTROL_FLOW.
- node node_modules/typescript/bin/tsc -p . from web: exit 0.
- node build.mjs from web: exit 0.
- python ../tools/uc_browser_init.py with installed nfs.exe and dist/uc-init-009e8ad0.wasm: exit 0, existing unused linker-path warning.
- node tools/unit-tests.mjs --fast with Edge channel and authorized-media/initializer options: 132 tests, 131 passed, zero failed, one skipped.
- Python Phase 43–51 test scripts: each exited 0.
- python tools/uc_phase31_campaign.py: exit 0, expected blocked cases retained.
- python tools/uc_progress_test.py: exit 0.

The actual EA bumper test passed in the maintained browser batch. No physical second-PC test was performed. Historical guest totals remain 84 unique, 50 enterable and 358 runs. UNDERCOVER_ORIGINAL_STARTUP_PREFIX_IN_BROWSER remains unverified; native screen presentation and gameplay remain blocked. The master export remains intact.
