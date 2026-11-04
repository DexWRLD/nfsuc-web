# Phase 73 — X86 cost isolation and final adoption gate

2026-11-04. **NO-GO: close this checked Unicorn.js adapter approach for adoption.** Keep the existing translated Wasm production backend and Unicorn.js as an external test-only oracle. No new CPU/CRT/startup/graphics scope was added.

## Baseline and integrity

Actual baseline HEAD was 60d677ff following implementation 7a94e6c4. main was 22 ahead of unchanged local origin/main. Only the same 22 unrelated discord-bot deletions were present. No fetch/push or unrelated restoration/staging.

Reviewed runtime-phase72.md, phase73-handoff.md, Phase 72 benchmark/differential/feasibility JSON, the exact adapter and Edge harness, original process/dispatcher/admission metadata, Phase 71 native results and current preflight. Source executable SHA remains 6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd; canonical master remains f293d93d31fcbf86ad9b9639f2cf10c34defe9c621cfe7f1a5e975f598ddf88a. Both were verified by preflight. The original executable was read as data, never launched or patched.

Phase 72 files are retained unchanged, including 45.800 ms / 0.400 ms / 114.50x samples. Before optimization, a fresh isolated Phase 73 baseline measured 43.500 ms for the original adapter. The separate unprofiled cost adapter measured 44.700 ms; this 1.028x wrapper overhead is recorded. The production adapter file and runtime dispatcher are not modified.

## Baseline cost decomposition

web/tools/uc-browser-x86-cost-adapter.mjs is a separate costed copy of the frozen Phase 72 test adapter. A nested timer records inclusive and exclusive time, call counts and an independent wall total. Permission checks are instrumented on the experiment's process instance and restored afterward. No check is suppressed. Three profiled baseline runs take 64.0 / 61.9 / 60.5 ms, versus the unprofiled copy median 44.700 ms. Profiling overhead is 1.385x; gate decisions use unprofiled timings.

The table gives baseline median exclusive milliseconds, except the separately identified one-time/external measurements. Inclusive scopes are retained in JSON and must not be summed. Medians from different runs are not additive totals. Some very short scopes quantize to zero; zero is not proof of zero cost.

| Requested cost | Frequency / scope | Exclusive ms | Calls |
|---|---|---:|---:|
| Engine factory initialization | one time / worker | 15.100 | 1 |
| Engine instance creation | cold engine | 0.000 | 1 |
| Engine teardown | fresh run | 0.200 | 1 |
| Guest page allocation | cold mapping | 0.100 | 10 |
| Guest page mapping | cold mapping | 0.500 | 10 |
| Initial canonical copy | cold mapping | 10.000 | 10 |
| Initial engine copy | cold mapping | 0.100 | 10 |
| Original code digest checking | each run | 0.600 | 1 |
| General-register initialization | each run | 0.000 | 1 |
| FS/GDT and segment setup | cold engine; parent scope | 4.300 | 1 |
| Instruction execution / engine-start scope | each step, children excluded | 5.300 | 173 |
| Instruction hook | each instruction | 0.100 | 173 |
| Read hooks | each CPU read | 0.400 | 68 |
| Write hooks | each CPU write | 0.200 | 82 |
| Guest permission checks | setup and runtime | 12.700 | 43177 |
| Canonical read synchronization | instruction/data inspection | 0.400 | 420 |
| Register snapshots | each instruction | 0.900 | 173 |
| Defined-flag updates | completed step | 0.000 | 172 |
| Call/return journaling | completed step | 0.100 | 172 |
| Cooperative worker yields | five timer awaits | 25.100 | 5 |
| Terminal state comparison | outside execution; mean per comparison | 55.608 | 1 |
| Guest reset | outside execution; mean per reset | 7.614 | 1 |

Segment-register writes are separately nested under FS/GDT in the final representative profiles. Canonical writes, dirty-range restoration and flag prerequisite checks also have explicit categories there. Original before-optimization baseline factory timing initially included script load; the final report separates engineScriptLoad from engineFactoryInitialization, rather than treating their combined value as factory-only cost.

The five yields dominate baseline wall time at about 25 ms. Page preparation makes 43,177 permission checks; the representative unoptimized profile records 396 denied setup-padding probes at the last partial .data page (end 0x018B1E74). These are zero-fill setup probes, not failures among the 68 admitted CPU reads. Whole-page bulk copying preserves canonical range checks and falls back to the original byte checks for partial pages; it does not eliminate that fallback. Setup, hooks, memory copy and CPU costs are therefore kept separate.

Per-instruction and per-engine-start averages can be derived from the same totals/counts; engine-start scope excludes timed callback children and does not equal pure ISA cost. Per-access costs use the 68 read / 82 write counts. Per-callback and per-start transition costs are distinct; the existing guard-transition budget is not a census of every C API call. Nested source/memory checks and callbacks are not double-counted as additional wall time. Fine-grained timer costs are explanatory measurements, not a theoretical lower bound.

## Fair benchmark modes and bounded experiments

A retains full Phase 72 snapshots, read storage, journals, authentication, permission checks and all twelve differential categories. B removes only optional per-instruction snapshots and verbose read storage from both backends; the Wasm observer's optional functions are actually unset, avoiding its snapshot-building cost. Both retain mandatory journals, checked memory, original-byte authentication, instruction admission, flags/FS, budgets, target rejection and terminal consistency. B does not claim per-instruction snapshot equivalence when snapshots are absent; that claim is independently tested in A.

C changes one setting at a time: yield interval 32 to 173, checked bulk page copies, snapshots, persistent session, or batch size 1 to 16. Combined A/B settings are explicitly cumulative. No unchecked or unauthenticated mode is presented as production-equivalent. No new engine candidate is introduced.

Each matrix case records a first session/engine cold run, two warm-up pairs and nine measured pairs. Mode B additionally records seven groups of ten paired runs to reduce relative timer quantization on the short Wasm path. Pairs always run Wasm then x86, with reset outside execution timing; order is not randomized and no formal confidence interval is claimed. Raw per-run and group values, median/min/max/mean/standard deviation and cold results are in browser-x86-optimization-phase73.json. A separate full-suite campaign is preserved as browser-x86-optimization-phase73-regression.json, so concurrent and isolated observations are not silently mixed.

Final isolated results:

| Comparable mode | Browser x86 median | Wasm median | Ratio | <=5x |
|---|---:|---:|---:|---|
| A, full diagnostics / combined safe settings | 4.500 ms | 0.300 ms | 15.00x | FAIL |
| B, persistent checked / grouped means | 3.440 ms | 0.150 ms | 22.93x | FAIL |

The B group-mean x86 range is 3.260–4.340 ms, standard deviation 0.376 ms; Wasm range 0.120–0.180 ms. The independent concurrent campaign ratio is 21.50x. The threshold remains five times the comparable measured path, not a conveniently fixed 2 ms. Current Mode B target is approximately 0.750 ms. Both A and B fail comfortably despite timing variability.

Engine/module factory initialization excluding script loading is 15.100 ms; script fetch/evaluation 23.800 ms. Worker boot-plus-ping 11.400 ms, warm ping 0.100 ms. The 25492.793 ms whole-campaign round trip includes actual experiments, resets and comparisons and is not worker scheduling overhead alone.

Edge version: 156.0.4314.58; Unicorn.js 2.1.4 API version 0x020104FF, pinned source/core/package hashes unchanged from Phase 72. Engine download 915,283 bytes, reference Wasm 14,981 bytes, generated experiment worker 80,147 bytes. Canonical linear memory 51,445,760 bytes; observed engine allocation after the campaign 41,418,752 bytes. These are allocation observations, not RSS/peak resident memory. No browser portability, FPS or direct native-speed inference is made. The native comparison is a smaller constructor fixture, not this 173-instruction benchmark.

## Persistent reset and canonical memory

The engine factory initializes once per worker. Persistent sessions reuse mapped pages and save/restore a pristine CPU context after synthetic segment setup, including FS/GDT state. Registers are initialized per run. Call frames, local pending traps, hook state, budgets and flag metadata are recreated; hooks are removed in finally. Awaited runs are sequential, with no pending worker operation reused. A terminated worker/session is discarded.

Every attempted guest write is marked dirty before canonical policy can reject it. After the canonical process resets, dirty ranges are copied from canonical memory before CPU execution; the host root-return fixture slot is synchronized explicitly. The final warm profile maps 0 new pages and restores 46 ranges / 181 bytes instead of broadly recopying all mapped pages. Read hooks still compare every CPU read with the authoritative checked memory. Code digests and per-instruction byte/admission checks remain enabled.

Eight full-correctness cases pass: cold, warm, repeated same process, reset after provider, reset after budget, reset after invalid instruction, reset after permission failure, and reset after all six budget probes. The invalid-instruction test uses synthetic UD2 in a private temporary page, which is then unmapped. The permission test strengthens the host policy to reject the original first PUSH at 0x0300EFF8 without changing original bytes or original permissions. These probes and their failure reasons are recorded separately from successful recovery. This qualifies this fixture, not every Windows exception or malformed cross-page operation.

Every recovery compares complete mapped guest bytes from 0x00400000 through the diagnostic stacks/TEBs, including BSS, stack and FS storage. Low unmapped Wasm CPU bookkeeping is excluded as in Phase 72. The engine mirror is never promoted to canonical authority.

## Safe batching and frozen correctness

Batch size 16 reduces engine-start calls from 173 to 11. Before each next instruction executes, its hook finalizes the previous instruction, verifies return/target/flag state and admits the next original instruction boundary. Memory hooks remain active inside the batch. Unsupported calls reject at the hook or unmapped-fetch boundary; the engine never executes the effective provider. An instruction/resource budget still applies at every hook. Yield reduction is confined to the dedicated worker, with the 1,000 ms per-run wall budget and 60-second campaign watchdog retained.

The following remain exact in all full-correctness comparisons and eight recovery runs: 173 instruction tags, 12 entries/seven bodies/nine returns, 27 PE-global writes, 68 checked reads and 82 guest writes including FS; all original instruction addresses, registers and defined arithmetic flags, memory ordering, stack/FS and final stop match. No new handwritten function translation or new unique harness function is added. Historical ledger remains 84 unique, 50 enterable, 358 recorded runs.

Final ESP=0x0300EFA8, EBP=0x0300EFE4, ESI=0x008AAC6A and FS head=0x0300EFD4. The provider cell [0x00B61398] remains 0x008AAC6A. Raw engine stop EIP 0x008AAC6A is retained in each reset observation; normalized dispatcher EIP 0x0087B5B3 retains its original CALL-site provenance. No instruction at that unsupported target/interior executes. No cleanup, CRT, PE startup, menu or gameplay success is implied.

## Final decision and practical ceiling

Most of the original 45.8 ms was removable adapter overhead: timer yields, repeated segment/mapping setup and copying. Persistent checked batching reaches about 3.44 ms, but still needs another 78.2% reduction to meet the current equivalent Mode B target. Individual bulk-copy/snapshot/batching timing effects are noisy and are not claimed as standalone wins where the data do not support one. The remaining warm profile is concentrated in the checked engine/instruction boundary and callbacks, code authentication/admission and synchronization.

This is a measured practical limitation of this adapter configuration, not proof that x86 browser emulation is inherently impossible. Removing safety checks or predicting an unmeasured new architecture is not a valid improvement ceiling. The bounded eight-case matrix is complete; no further tuning or engine replacement is recommended. Source-build reproducibility and GPL redistribution/corresponding-source obligations remain independent unresolved deployment gates. Existing translated Wasm stays production; no mixed-backend resume or deployment is enabled.

## Validation and delivery

All final commands exited zero:

| Actual command / group | Result |
|---|---|
| node web/node_modules/typescript/bin/tsc -p web | Passed |
| web: node build.mjs | Passed; production main.js remains byte-identical |
| python tools/uc_unified_build.py "C:/Games/Need For Speed Undercover/nfs.exe" "C:/Users/999/.nfsuc-web/authorized-startup" | Fourteen bindings, identical 14,981-byte Wasm |
| web: node tools/unit-tests.mjs --fast | 158 tests: 157 passed, 0 failed, one existing skip |
| web: node --test test/uc-browser-x86-cost.test.mjs | Isolated cost qualification: one passed |
| python tools/uc_import_frontier_test.py / tools/uc_crt_evidence_test.py | 4 + 6 passed, no speculative search |
| python tools/uc_x86_probe.py <same executable> <same asset root> --output <workspace>/phase73-native-differential.json | Native constructor comparison + 105 arithmetic fixtures passed |
| Python tools/uc_phase43_test.py through uc_phase51_test.py, individually | 121 passed: 52/10/8/23/8/6/5/4/5 |
| python tools/uc_startup_preflight_test.py | Three passed, including final metadata rerun |
| python tools/uc_startup_preflight.py <same executable> --output analysis/undercover/startup-readiness.json | Source/master checks pass; original startup remains blocked |
| python tools/uc_phase31_campaign.py | Expected successes and explicit blockers retained |
| python tools/progress.py / python tools/uc_progress_test.py | Dashboard regenerated; consistency passed |
| python tools/uc_browser_x86_cost_report.py | Derived cost breakdown and final decision generated from recorded evidence |

The Node suite actually ran the existing Phase 72 browser differential, all twelve full categories, six original and six optimized budget probes, reset/invalid probes, Phase 60 nine cases, arithmetic/SEH/import tests and private HTTPS/JPEG/bumper/OPFS regressions. The existing skip is the old synthetic Chromium-logo test. Existing Phase 49 ResourceWarning is nonfatal. Repeated tests are not counted as new unique tests/functions.

Browser environment is recorded in logs: UC_BROWSER_CHANNEL=msedge, UC_BROWSER_INIT_TEST=1, UC_UNIFIED_TEST=1, existing UC_AUTHENTIC_ASSET_ROOT, reviewed outside-repo UC_BROWSER_X86_ENGINE, UC_BROWSER_X86_COST=1, and explicit evidence outputs. Original Phase 72 files were not overwritten; Phase 73 regression evidence has new names. No original assets, commercial payloads or third-party engine binaries are committed. Temporary HTTPS binds only 127.0.0.1; the version-69 six-path manifest is unchanged. Full-game Play remains disabled.

Production main.js SHA remains bf5cd044cc8cb55f98b59b3670222651c17c90f1820482808770c2bcefd78e36. Production Wasm SHA remains 8d1a62e0f1347d3698c9a011bf0da415291c6054c33c0b209652064da7b71c76. The existing inspector's Phase 72 benchmark remains historical; Phase 73 decision is recorded in readiness/dashboard analysis. No production execution implementation changed.

Implementation commit: 8faddbc1. Reports/evidence/dashboard follow in a second focused local commit; final hashes/status are in the delivery response. Expected final main is 24 ahead of unchanged local origin/main, with only the original 22 discord-bot deletions. Nothing pushed. Phase 74 should return to a single evidence-supported original-startup dependency, without reopening closed positional provider inference or continuing CPU tuning.
