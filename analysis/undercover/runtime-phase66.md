# Phase 66 connected Apt initialization in the unified process

Baseline main 127c994e, eight ahead of local origin/main. The pre-existing discord-bot deletions were preserved. No fetch. The master remains 54,494,254 bytes with SHA-256 f293d93d31fcbf86ad9b9639f2cf10c34defe9c621cfe7f1a5e975f598ddf88a.

## New original connection

Independent static inspection found the direct call at 0x00B57DC8. Original instructions at 0x00B57DC3 load ECX=0x0189D0A0 before calling 0x009E7540. A file-backed .rdata cell at 0x00B6370C contains 0x00B57DC0. That pointer does not establish execution from the PE entry.

The root is entered manually with an infrastructure stack. No host code supplies an Apt object, receiver pointer, backing array, capacity or constructor fields. The original guest MOV supplies the static receiver. Complete Ghidra bodies for the four new bindings have no warnings and exact ranges checked by the builder against the canonical index.

| Original callsite | Callee | Observed contract |
|---|---|---|
| 0x00B57DC8 | 0x009E7540 | ECX=0x0189D0A0, no stack arguments; callee returns EAX=receiver |
| 0x009E754A | 0x009E75A0 | Receiver +0, plain RET |
| 0x009E7555 | 0x009E75A0 | Receiver +0x0C, plain RET |
| 0x009E7560 | 0x009E75A0 | Receiver +0x18, plain RET |
| 0x009E756B | 0x009E75A0 | Receiver +0x24, plain RET |
| 0x009E7576 | 0x009E75A0 | Receiver +0x30, plain RET |
| 0x009E7581 | 0x009E75A0 | Receiver +0x40, plain RET |
| 0x009E758C | 0x009C1830 | Receiver +0x4C, plain RET |

Edge observed nine function entries across four distinct bodies, eight callee returns and depth three. The six header constructors write 18 zero dwords. The child constructor adds eight dword writes and one byte write, for 27 writes to original PE global addresses. Nonzero values at 0x0189D0F8 and 0x0189D0FC are 0x32000 and 0x186A0. The gap at +0x3C is preserved. The constructor returns the original global receiver in EAX.

The next original call at 0x00B57DD2 pushes return address 0x00B57DD7 and attempts 0x0087B640 with argument 0x00B602E0. The process traps as unavailable. EAX is 0x0189D0A0, EIP is 0x00B57DD2 and ESP is 0x0300EFF0. The root has not returned, and cleanup registration has not completed.

## Registry and bridge correction

tools/uc_unified_registry.json is the reviewed source for nine explicit callable bindings and one unavailable helper. Metadata records original address, Wasm export, ABI and argument bytes, required registers/globals, caller instructions, verified callees, indirect slots, return contract, recovery confidence and unresolved dependencies. The builder emits uc-unified-registry.ts and descriptor bindings from that source. It checks original source hash, registry admission, exact new-body bounds and original direct call sets. The large candidate catalog remains noncallable.

The first constructor run exposed stale register values across re-entrant host dispatch under Clang optimization. CPU fields had been optimized across imports. The fix makes C CPU fields and condition-state storage volatile and retains checked synchronization at nested dispatch boundaries. The test expected the original ABI and failed before the fix. Exact original call/return addresses, stack depths and callee preservation now pass in Node and Edge.

GuestAddressSpace gained checked byte access for the original child byte store. The shared bridge logs original guest writes and records callsite plus return address for original calls. A snapshot API observes CPU state after mutating guest execution. Reset clears image state, CPU and logs, and both original paths rerun in the same memory instance.

## Stop condition and platform services

0x0087B640 is recovered ordinary code, not classified as protected. It calls 0x0087B59B at 0x0087B644, then uses NEG/SBB/DEC and carry semantics. The current bridge does not implement its CF contract. 0x0087B59B begins with a call to 0x0087BEB8 and reads state at 0x018B1E6C plus pointer cell 0x00B61398. The file values at 0x00B61398 and 0x00B61394 are 0x008AAC6A and 0x008AAC60. Their provider identities and callable boundaries are not established here. They must not be assumed to be Windows imports by resemblance.

No Windows API is reached by the supported constructor chain. No new platform service adapter was added. Existing import rejection tests and the unavailable-helper trap verify explicit failure rather than a success stub. The next dependency is verified CF/ABI support for the wrapper and the downstream cleanup-registration state/provider contract.

## Browser evidence and private delivery

Run Shared Process Integration now exercises the previous producer/consumer regression and, after a reset, the new original initialization root. It shows mapped sections, nine registered addresses, call/return records, 27 original global writes, CPU state, provenance, zero platform-service calls and the unsupported helper. Host ordering of the independent roots is diagnostic scheduling.

edge-execution-phase66.json is captured from Edge over HTTPS. unified-execution-phase66.json is the separate opt-in Node trace. Edge repeats the integration and reload cache check, with one PE-payload request per clean context. All six existing allowlisted paths are preserved. The ordinary payload SHA remains 35bc6b5a51a82fa9fc0ea5be991e1f67a4bbcfa87f2cd529867e40ed7961fcfa. The 7,730-byte module SHA is c93ce3485a54ca0ea17efe424d23ba67076c6f0dbce3f185b724b4b6cd766bb6. The private manifest is version 66. Generated module and PE payload stay outside Git.

## Fresh validation

- Unified Wasm build exited 0; registry source and generated metadata consistency are tested.
- TypeScript and frontend build exited 0 after correcting the snapshot typing.
- Maintained Node/Edge HTTPS batch: 145 tests, 144 passed, zero failed, one skipped. The skipped older synthetic-logo test requires missing bundled Chromium; actual media and unified integration run in Edge.
- Master/startup preflight: three tests passed.
- Python Phase 43–51 regressions each exited 0.
- Guest execution campaign exited 0 with expected blocked cases.
- Dashboard validation rerun.
- Wrong initialization order, unknown/import/unavailable targets, permissions, byte writes, guest reset, actual CALL/RET edges and shared state are covered by the retained and new suites.

## Readiness

| Classification | State |
|---|---|
| UNIFIED_PE_IMAGE_MAPPED | Verified for five ordinary and six unavailable section descriptors |
| UNIFIED_GUEST_MEMORY_BROWSER_VERIFIED | Verified |
| MULTI_FUNCTION_ORIGINAL_DISPATCH_VERIFIED | Verified for nine reviewed bindings |
| SHARED_ORIGINAL_STATE_PERSISTENCE_VERIFIED | Verified |
| CONNECTED_ORIGINAL_RUNTIME_PREFIX_VERIFIED | Verified for independently entered ordinary roots |
| ORIGINAL_PLATFORM_ADAPTER_VERIFIED | No new adapter; selected chain reaches no verified Windows import |
| ORIGINAL_PE_ENTRY_CONTINUATION_VERIFIED | Unverified |
| UNDERCOVER_ORIGINAL_STARTUP_PREFIX_IN_BROWSER | Unverified |
| ORIGINAL_GAME_BOOT_EXECUTING | Unverified |
| AUTHENTIC_FIRST_GAMEPLAY_FRAME | Blocked |
| FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND | Blocked |

Historical native ledger totals remain 84 unique, 50 enterable and 358 runs. Native cleanup remains open; no additional deletion was justified by this call-path work.

Local implementation commit 47865ed3. Pre-existing discord-bot deletions remain outside this phase. No push.
