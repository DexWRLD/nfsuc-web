# Phase 71 â€” CRT provenance and runtime feasibility

2026-11-04. Baseline HEAD 49b00f74 follows Phase 70 implementation 591bf1ee. main was eighteen ahead of the local origin/main reference; no fetch/push. The same 22 unrelated discord-bot deletions were preserved.

Outcome: no legitimate resolved ordinary import call or legacy binding writer was established. Original CRT execution did not advance. A real, native-only x86 differential prototype passed against existing Wasm. Further speculative provider translation is NO-GO; one bounded hybrid browser-backend experiment is recommended, with explicit acceptance gates in runtime-feasibility-phase71.md.

## Baseline and immutable boundary

Reviewed Phase 70 runtime/handoff, provider-binding and conditional-order JSON, Phase 69 Node/Edge SEH evidence, current process/dispatcher/thread/registry, imports, Phase 60 nine-case evidence and readiness. Also reviewed the supplied external research at C:/Users/999/Documents/KTA/research/undercover-phase70-legacy-crt-binding.md. Its digest is in ordinary-import-call-evidence-phase71.json.

Source executable SHA-256 remains 6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd. Canonical master SHA-256 remains f293d93d31fcbf86ad9b9639f2cf10c34defe9c621cfe7f1a5e975f598ddf88a. Preflight verifies both. No original assets were modified; the original executable was read as data, never launched. No unavailable code was executed, reconstructed or bypassed.

Connected browser control remains host entry 0x00B57DC0 â†’ original Apt constructors â†’ 0x0087B640 â†’ 0x0087B59B â†’ 0x0087BEB8 â†’ rejection at 0x0087B5B3. The host root and explicit synthetic thread are not original PE startup. The registrar reads unchanged [0x00B61398]=0x008AAC6A and cannot dispatch it. No redirect to _decode_pointer was added.

## Bounded import/provider attempt

New tool tools/uc_import_frontier.py verifies the source digest and examines all 625 advertised PE import slots. This is a different population from Ghidra's 622 external declarations. It scans ordinary .text for literal active-IAT addresses and absolute CALL/JMP operands. Result: zero active-IAT literal references and zero active-IAT absolute call/thunk candidates. Raw byte patterns include 3,808 FF15 and 464 FF25 candidates. Starts may overlap other instructions; they are not admitted functions or reachability proof.

Fresh read-only Ghidra queries are retained in ghidra-import-search-phase71.json. Queried active loader/resolver/protection-related cells yield only the recorded PE-header data reference or no incoming references. The legacy cookie cell has the expected read at 0x0087C299, with no new binding writer. The external report and prior indexed/literal writer searches also supply no proven copy/resolver/permission-change chain.

Limits: this is not exhaustive symbolic recovery of register-computed writes, computed import targets, table copies or startup sequencing. Such an operation was not established. Unavailable sections were not explored as executable mechanisms. No writer is inferred from positional table alignment, and no provider address is invented. The gate is BLOCKED_UNAVAILABLE_PROVIDER_PROVENANCE; repeat searches are closed until actual new writer/binding evidence appears.

### New independent name evidence, without execution authority

The original legacy dwords are valid IMAGE_IMPORT_BY_NAME RVAs when interpreted as metadata. At 0x00B61398 the raw value is 0x008AAC6A. Image-base-plus-RVA 0x00CAAC6A contains the hint record and the ASCII name _decode_pointer at +2. The CPU still reads raw 0x008AAC6A as its target; adding the image base is a metadata interpretation, not a correction to dispatch.

The same original-byte check establishes names for _unlock, __dllonexit, _encode_pointer, _lock, _onexit, _initterm, _initterm_e, __set_app_type, _except_handler4_common, GetSystemTimeAsFileTime and memset. None of these legacy cells is the current advertised descriptor's FirstThunk cell. Their .rdata storage is read-only in the mapped ordinary image; advertised active import storage is unavailable .securom. No legitimate writer/protection transition between these representations is proved. Active symbol names and original name records identify intent, not live provider addresses.

### Address-grounded ordinary call examples

| Original code | Bytes / operands | Caller contract | Result |
|---|---|---|---|
| 0x00739B9C | e835171400; CALL 0x0087B2D6, return 0x00739BA1 | Caller 0x00739B90 pushes 0x180, zero, caller destination; ADD ESP,0xC then RET | Verified ordinary edge, startup reachability unverified |
| 0x0087B2D6 | ff253c12b600; JMP [0x00B6123C] | Metadata name memset; needs writable 384-byte destination and genuine cdecl provider, expected EAX destination | Legacy binding unproved; not executed |
| 0x0087C299 | ff15a011b600; CALL [0x00B611A0] | Cookie default branch supplies pointer to two FILETIME dwords at EBP-8; one-pointer stdcall-shaped consumer | Metadata name GetSystemTimeAsFileTime; binding and startup reachability unproved |

The old native tools/uc_phase7_test.py replaces sub_0087b2d6 with uc_import_invoke using runtime/uc_import_table.inc. That is an explicitly host-supplied import contract fixture, not evidence that this executable's original provider table was initialized. It remains useful for its bounded native ABI purpose and was not deleted.

## Earliest CRT dependency graph

Conditional original order: wrapper call 0x0087BD95 â†’ cookie routine 0x0087C264, then 0x0087BD9A â†’ 0x0087BB3D. The default-cookie branch first requires 0x0087C299 â†’ [0x00B611A0]. The C initializer 0x0087BCB3 requires mapped PE-header checks, then 0x0087BD1A â†’ [0x00B613CC] (__set_app_type), before 0x0087BD22 â†’ [0x00B6138C] (_encode_pointer). Only after these operations can stores at 0x0087BD2A/2F publish sentinel globals.

Each edge remains conditional/static: original entry reachability, effective binding and provider-owned context are unproved. No entropy, thread-owner state, cookie, encoded sentinel or successful provider result was seeded. Constructor-table traversal, cleanup registration and frontend-manager reachability remain blocked. The known manager path still requires the unavailable allocation boundary 0x00686000 and unresolved constructor dependency; it was not forced through.

## Actual execution and feasibility

edge-execution-phase71.json is fresh Edge HTTPS evidence. It agrees with retained Phase 69 Node trace/state. Twelve entries across seven distinct bodies, nine callee returns and 27 original PE-global writes remain unchanged. Last tagged instruction 0x0087B5B3; ESP=0x0300EFA8, EBP=0x0300EFE4, ESI=0x008AAC6A. Synthetic FS head remains linked at 0x0300EFD4. Root, wrapper and registrar do not return; imported services, completed registrations and new CRT entries are zero.

The separate offline prototype used installed native Unicorn and actual three constructor bodies. It matched 138 original instruction tags, eight nested entries, 27 data writes, registers, defined arithmetic flags and bounded data against current Wasm. Another 105 arithmetic instruction fixtures matched. It is not browser execution, original boot, a resolved provider, or a new original-function milestone. Full technical comparison, local source audit, engine licenses, timings and go/no-go gates are in runtime-feasibility-phase71.md. Historical native ledger remains 84 unique, 50 enterable, 358 recorded runs.

## Validation

All following commands exited zero; full raw output is preserved in validation-phase71.log and browser-tests-phase71.log.

| Command | Actual result |
|---|---|
| python tools/uc_import_frontier.py <original-exe> <external-research> --output analysis/undercover/ordinary-import-call-evidence-phase71.json | 625 advertised slots; bounded negative; name metadata only |
| python tools/uc_import_frontier_test.py | 4 passed |
| python tools/uc_crt_evidence_test.py | 6 passed |
| python tools/uc_x86_probe.py <original-exe> <authorized-asset-root> --output analysis/undercover/x86-prototype-phase71.json | Real constructor differential passed; 105 synthetic arithmetic cases matched |
| python tools/uc_unified_build.py <original-exe> <authorized-asset-root> | Same 14 bindings and unchanged Wasm |
| node web/node_modules/typescript/bin/tsc -p web | Passed |
| web: node build.mjs | Passed |
| web: node tools/unit-tests.mjs --fast | 156 tests: 155 passed, 0 failed, 1 existing skip |
| python tools/uc_phase43_test.py through tools/uc_phase51_test.py, individually | 121 passed: 52/10/8/23/8/6/5/4/5 |
| python tools/uc_startup_preflight_test.py | 3 passed |
| python tools/uc_phase31_campaign.py | Expected successes and explicit blocked cases retained |
| python tools/uc_startup_preflight.py <original-exe> --output analysis/undercover/startup-readiness.json | Provenance closure/strategy added; startup still blocked |
| python tools/progress.py and python tools/uc_progress_test.py | Dashboard regenerated and consistency passed |

Browser environment: UC_BROWSER_CHANNEL=msedge, UC_BROWSER_INIT_TEST=1, UC_UNIFIED_TEST=1, UC_AUTHENTIC_ASSET_ROOT=C:/Users/999/.nfsuc-web/authorized-startup, UC_SEH_NODE_EVIDENCE points at seh-normal-path-phase69.json, UC_BROWSER_EVIDENCE writes edge-execution-phase71.json. All nine Phase 60 cases, flags, normal SEH, import metadata, original constructor writes, authentic JPEG/silent bumper, private manifest, secure-context and cache reload tests remain covered. The one existing skip is the old synthetic Chromium-logo test; actual media/runtime integration ran in Edge. Existing Phase 49 ResourceWarning is nonfatal.

Wasm stays 14,981 bytes, SHA-256 8d1a62e0f1347d3698c9a011bf0da415291c6054c33c0b209652064da7b71c76. Authorized private manifest remains version 69, six paths. No new network bind/firewall/public exposure. Full-game Play stays disabled. No commercial assets, executable sections, generated Wasm, DLL or third-party engine sources are committed.

## Delivery and next target

Implementation commit: 58d29cfd. Documentation/evidence/dashboard are recorded in a following focused local commit. Final local hashes/status are recorded in the delivery response. After two focused commits main is twenty ahead of unchanged local origin/main; only the same 22 discord-bot deletions remain. Nothing was pushed.

Phase 72 should attempt milestone 5: a reviewed browser-capable CPU adapter must handle the existing connected prefix with fewer per-function translations, identical checked memory/registers/defined flags/FS/writes and the same unsupported-provider stop. A native DLL result is not this browser milestone. Provider research must not restart without concrete new writer/binding evidence. See phase72-handoff.md for go/no-go criteria.
