# Underground 2 cleanup report

This commit removes 114 explicitly inventoried legacy frontend, multiplayer, game-session, artwork and associated test files. The active Undercover browser entry, low-level input, GPU/audio, workers, asset cache and translated-code diagnostics build and run. The broader native cleanup is incomplete because automatic approval review rejected the proposed native deletion group.

## Removed files and evidence

nfsu2-cleanup-deletions.json records every path, removal reason, dependency evidence and validation. The deletion group includes the inherited shell and settings/profile/save UI, multiplayer friends/crews/network protocol, game-specific session and radio adapters, old images/icons and the obsolete service worker. No game-installation files were touched.

The decision used the transitive imports from main.ts and retained host, GPU and audio entry points, followed by TypeScript dependency checks. Tests tied to removed interfaces were retired. Shared input code under web/src/input, generic host workers and renderer/audio modules remain. The generic hostcheck test was extracted from its obsolete multiplayer attachment.

## Build and naming

web/package.json and package-lock.json now identify nfsuc-web. The package description targets Undercover PC 1.1.2.1. The active capability error names the Undercover private HTTPS host. The CSS module declaration is retained separately. build.mjs no longer emits removed legacy game tests or the obsolete service worker and removes their stale output bundles and icons by explicit bounded paths. There are no wholesale directory deletes.

No on-disk files were renamed. Storage keys, environment variables and compatibility names inside reusable runtime modules retain their original spellings pending coordinated caller migration. Generic input support is preserved without presenting a working game runtime.

## Remaining legacy dependencies

nfsu2-cleanup-residuals.json contains 599 tracked text paths with residual search matches and their classifications. It scans NFSU2, nfsu2, Underground 2, Need for Speed Underground and UG2. Original executable-derived strings and historical research attribution are retained. Native gameplay enhancements, the older native Mac/Windows build chain, legacy server/service modules and tests still need exact dependency closure before removal.

Automatic approval review rejected deletion of the broader native runtime, generated code, platform/service directories, scripts and tests. Its reason was that filename/stem groups did not prove a safe dependency closure and could remove reusable Undercover infrastructure. That native deletion was not executed. Approval for a reviewed exact list or a further verified native dependency study is required to continue that portion.

## Validation

- TypeScript exited 0.
- node build.mjs exited 0.
- The hash-verified Wasm builder exited 0 with the existing unused linker-path warning.
- The targeted Undercover Node/Edge HTTPS batch passed 53/53 after frontend removal.
- The maintained runner, node tools/unit-tests.mjs --fast, ran 132 tests: 131 passed, zero failed, one skipped. UC_BROWSER_CHANNEL=msedge, UC_BROWSER_INIT_TEST=1 and the authorized media root were configured. This includes actual bumper playback, JPEG asset routing, cache reuse and all earlier guest inspectors.
- Before defining the maintained runner, the broad inherited test set ran 190 cases: 151 passed, 34 failed, five skipped. Failures included removed shell/catalog dependencies and old deployment/native module assumptions. Those results are not passing evidence. Unsupported inherited tests that remain are outside the maintained default set.
- Python phase regressions 43–51 each exited 0.
- The guest campaign exited 0 with its expected blocked cases.
- Dashboard consistency exited 0.
- The master decompilation assembler exited 0 and reproduced SHA-256 f293d93d31fcbf86ad9b9639f2cf10c34defe9c621cfe7f1a5e975f598ddf88a.

The active Undercover page and its metadata contain no Underground 2 branding. The repository still contains legacy implementation requiring native dependency investigation. This report does not mark the complete repository cleanup achieved.

## Git

Baseline dac65b08 on main, one ahead of local origin/main, with a clean working tree. No remote fetch. The decompilation commit is separate from this cleanup. Only paths listed in the removal inventory and the associated build/interface/report changes belong to this task. No push was performed.


## Phase 63 reconciliation

The preceding cleanup was committed as aff9c648. repository-classification-phase63.json now inventories all 1,400 tracked paths from the current baseline. It preserves 22 pre-existing discord-bot deletions as unrelated working-tree state. No native deletion was retried after the automatic rejection. The cleanup commit removes the old active frontend and its tests, while retained native/game build dependencies still need a verified closure.

Fresh Phase 63 validation passed the maintained browser, asset, cache and native harness suites. See runtime-phase63.md for exact commands and counts. The cleanup goal remains incomplete for the native legacy graph. The active preview remains Undercover-only.
