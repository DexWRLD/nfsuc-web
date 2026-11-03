# Phase 55 backing-storage provenance

Baseline main at 43d6421, 14 ahead of local origin/main. No fetch. The prior audit was untracked. The installed image was hash-verified by the Wasm builder. Ordinary code was inspected with RawLifter and comments enabled.

## Publisher and allocation contract

| Address | Verified behavior |
|---|---|
| 0x009B2D31 | Recorded predecessor supplies receiver VA 0x0189D0A0 to the helper reaching 0x009E4640. Native scheduling of this predecessor remains unverified. |
| 0x009E464A / 0x009E465C | Checks receiver +4 against zero and invokes diagnostic callback on the nonzero path. |
| 0x009E466B | Stores the stack argument at receiver +4. It supplies the requested dword capacity. |
| 0x009E466E / 0x009E4683 | Checks registered allocation slot 0x0189D198 and dispatches a diagnostic when absent. |
| 0x009E468C–0x009E4699 | Requests argument times four bytes using ECX from [0x0189BEEC]. Calls 0x009DC250. |
| 0x009DC259–0x009DC294 | Checks zero size via diagnostic, requests payload bytes plus four from 0x009DC310, writes the payload byte count at the returned block base, and returns base plus four. The lifted path assumes the lower helper returned writable storage before writing the header. |
| 0x009E469E–0x009E46A1 | Reloads original receiver and publishes EAX to [ECX+8], which is 0x0189D0A8 for this receiver. It directly publishes the interior payload pointer. |
| 0x009E46A7–0x009E46C5 | Tests the published pointer, issues a diagnostic if zero, and returns with RET 4. No payload element initialization occurs in this function. |

The ordinary allocation path is 0x009DC310 → 0x009DBE50 → [0x0189D198] → 0x009E77D0 → 0x009E9460. At 0x009E9460 ECX loads [0x0189DA88]. Zero takes the EAX=0 return, after which 0x009E77D0 expects a dereferenceable result. A nonzero factory uses the virtual slot at +0x1C with the stack argument forwarded. The recorded factory initialization depends on the result of the call at 0x00810259 to the unavailable allocator-shaped 0x00686000. The first unavailable production dependency is that factory provider. The producer also requires the state loaded from 0x0189BEEC. Exact object lifetime, release behavior and the startup capacity value remain unverified.

## Consumer and ordering

At 0x009E4B1C the code calculates count minus requested index, then TEST/JG interprets it as signed positive. A nonpositive value invokes the callback through 0x0189D1A4. The returning callback falls through. At 0x009E4B40 EAX is recalculated from receiver +0 minus the index. At 0x009E4B46 EDX loads receiver +8. At 0x009E4B49 the read uses (EDX + 4 * EAX - 4) modulo 2^32. A valid element requires count minus index greater than zero and count minus index minus one within the allocated dword capacity. Index zero selects the last occupied element when count is positive. In the observed zero-state case the offset is -4 and the computed address is 0xFFFFFFFC. A nonzero backing pointer alone would still leave a pre-payload read for this count.

The original local dependencies require callback registration and factory state before allocation, a successful publication plus valid count before consuming an element. 0x009E8AD0 writes both callback slots, while the factory pointer and receiver backing storage are separate. The ordinary direct caller at 0x009E9305 is recorded. A global startup schedule placing the producer before the consumer has not been demonstrated. The browser harness invokes the registration leaf first and then the root separately. Within the root the four guest bodies and five entries are the same connected trace as Phase 54. The final completed guest instruction is 0x009E4B46. No allocation or publication ran in the browser.

## Validation

The Wasm bridge captures EDX and the signed EAX delta at the original read and uses the same checked 32-bit effective address. Edge verified zero backing pointer, zero delta, bounds rejection at 0xFFFFFFFC, exact entry sequence, the initializer's 49 writes and stack return, plus authentic bumper playback and reload cache reuse.

- python tools/progress.py and python tools/uc_progress_test.py completed successfully.
- python tools/uc_phaseNN_test.py for NN 43 through 51 each exited 0.
- python tools/uc_phase31_campaign.py exited 0 with expected blocked cases.
- node node_modules/typescript/bin/tsc -p . and node build.mjs exited 0 from web.
- python ../tools/uc_browser_init.py with the installed nfs.exe and dist/uc-init-009e8ad0.wasm exited 0. Clang reported the existing unused linker-path warning.
- node --test test/uc-lan-https-browser.test.mjs test/uc-startup-preview.test.mjs test/uc-assets.test.mjs test/uc-lan-server.test.mjs test/uc-dxt1.test.mjs passed 53/53 with Edge, UC_BROWSER_INIT_TEST=1 and the authorized local media root.
- Positive producer execution, ownership, and continuation are unverified. Separate invalid ABI and arbitrary valid-pointer cases were not exercised.

The dashboard records the static publisher finding. Connected browser function count stays four, with three distinct guest callsites plus a second indirect callback callsite. Historical guest totals remain 84 unique, 50 enterable, 358 runs. Full boot and authentic first frame remain blocked.

