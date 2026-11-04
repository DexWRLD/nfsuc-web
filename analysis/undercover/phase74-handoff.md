# Phase 74 handoff — return to original startup dependencies

Phase 73 decision: **NO-GO; close further adoption tuning of this browser x86 adapter.** Read runtime-phase73.md and browser-x86-decision-phase73.md. The checked Mode B ratio remains far above 5x after a bounded eight-case experiment matrix. browser-x86-cost-breakdown-phase73.json contains nested timings and browser-x86-optimization-phase73.json contains raw samples, cold/warm results and all reset qualification. The separate concurrent campaign and pre-optimization baseline are preserved.

Do not start another performance phase, introduce another CPU engine, expand CPU/SIMD/x87 coverage, translate helpers for counts or enable the browser engine in production. Unicorn.js remains a test-only oracle. Source-build reproducibility and GPL distribution obligations remain unresolved; no engine binary is committed or present in the private manifest.

## What is established

- Edge actually executes the same 173 original instruction tags, twelve entries/seven bodies/nine returns, 27 global writes, 68 reads and 82 writes including FS.
- Full twelve-category diagnostics pass. B omits optional snapshots/read storage on both sides and does not claim the omitted snapshot comparison.
- Persistent reuse/dirty restoration and batch size 16 pass this control's cold/warm/repeat/provider/budget/invalid/permission recovery cases. The permission probe uses a stronger host policy on the original first PUSH; it is not universal Win32 fault recovery.
- Every attempted write is dirty; warm reset restores 46 ranges / 181 bytes from canonical memory in the recorded run. Every data read remains checked against canonical memory. No unchecked mirror becomes authoritative.
- The provider stays [0x00B61398]=0x008AAC6A. Raw engine EIP and normalized CALL-site stop 0x0087B5B3 remain distinct recorded observations. The target interior is never executed.
- Production translated Wasm and main.js remain byte-identical. Original PE startup reachability, CRT completion, cleanup registration, menu/frame/gameplay remain unproved.

## Highest-value next work

Return to the existing original-startup dependency graph. Choose one real blocker that can advance through an independently supported ordinary caller edge or a documented external contract with actual binding provenance. Review existing Phase 70/71 conditional CRT graph and verified state producers before selecting a target. Separate original call order from host-driven fixtures.

Current graph boundaries to preserve:

| Node | Supported observation | Unresolved dependency |
|---|---|---|
| PE entry 0x01FCA510 | Recorded overlapping-control boundary | No verified ordinary continuation into the manually entered root |
| Conditional cookie routine 0x0087C264 | First provider use at 0x0087C299 through [0x00B611A0] | Legitimate live binding and original startup reachability |
| C initializer 0x0087BCB3 | Header checks, then 0x0087BD1A [0x00B613CC] before 0x0087BD22 [0x00B6138C] | Header mapping, providers and encoding context; no seeded sentinel |
| Connected registrar 0x0087B59B | Browser reaches 0x0087B5B3 using the synthetic thread | [0x00B61398] is not a resolved provider; no successful registration |

These are distinct static/diagnostic observations, not an executed original boot sequence. The current provider/loader mechanism is still unavailable. Do not reopen the same legacy table investigation unless new independent writer, loader/copy, binding and permission/order evidence appears. IMAGE_IMPORT_BY_NAME RVAs and positional correspondence are descriptive metadata, not live function addresses. A convenient Windows service stub is not an established import binding. Do not seed pointers, entropy, sentinels or successful CRT callback results.

If available evidence cannot establish a lawful next ordinary edge, report that precise prerequisite. Do not substitute more diagnostic helper executions, another emulator or guessed state for startup progress. Do not execute, decrypt, reconstruct or bypass unavailable/protected sections. Keep the original installation read-only and unlaunched.

## Baseline and reproduction

Check actual HEAD/status first. Preserve the same 22 unrelated discord-bot deletions. No fetch/push. Source SHA 6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd; canonical master f293d93d31fcbf86ad9b9639f2cf10c34defe9c621cfe7f1a5e975f598ddf88a. Existing fourteen production bindings and historical native ledger 84 unique/50 enterable/358 runs are unchanged.

The Phase 73 cost test is optional unless UC_BROWSER_X86_COST=1 and the reviewed external UC_BROWSER_X86_ENGINE/UC_AUTHENTIC_ASSET_ROOT are supplied. It actually ran in this phase, including an isolated repeat. No download occurs in tests. Keep generated payloads and engine binaries outside Git. Original Phase 72 evidence is preserved; do not overwrite it when reproducing measurements.

Validation: 158 Node/Edge tests, 157 passed and one existing skip; 134 Python unit tests; native comparison with 105 arithmetic fixtures; frontend/TypeScript/Wasm/campaign/dashboard pass. The isolated cost case also passed. Keep Phase 60 nine cases, flags, SEH, import evidence, exact provider failure, authentic media, OPFS/private HTTPS and disabled full-game Play intact. Do not count reruns as new unique functions.
