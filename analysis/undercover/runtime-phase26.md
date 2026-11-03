# Undercover Phase 26 — `_CIsqrt` + ordinary execution campaign

Graphics remain **frozen**: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`.

## A. `_CIsqrt` metadata

| field | value |
| --- | --- |
| thunk | `0x00AE5116` |
| IAT | `0x00B61448` |
| DLL | `MSVCR80.dll` |
| call sites | 116 |
| HIGH callers | 55 |
| pre single-unlock | 88 |
| now import-ready (call-list) | 53 |

## B. ABI

Identical to Phase-9 `_CI*` family: **ST0 → ST0**, cdecl, **0** stack dwords,
EAX unchanged, TOP unchanged. Host math via `uc_host_sqrt`.

## C. Implementation

`UC_HLE_CISQRT` in `uc_abi.h` / `uc_import.c` using existing `x87_replace`.

## D. Numerical policy

Host double (ucrtbase `sqrt`). Not bit-exact MSVCR80/x87 80-bit.
No tag-word / FP-env / exception fidelity claims.
Negative inputs: host-dependent (typically NaN); guest integer/x87 TOP preserved.

## E–G. Tests / consumer

Unit+edge+ABI in `uc_phase26_test.py`. Real consumer **`0x00924D30`**:
before unbound host → reject; after → normalize (3,4)→(0.6,0.8,1.0).

## H. Unlock recompute

Phase-25 single_unlock[_CIsqrt]=88 counted otherwise-clean closures. Per-function call-list import-ready with _CIsqrt and no other missing imports is 53 HIGH functions. RUNTIME_READY closure sizes remain 19+35 because newly unlocked closures are smaller than the extreme.

## I. Runtime-ready definition

See `runtime-frontier.json` `definitions`. RUNTIME_READY stays closure-extreme based (**54**).

## J–M. Campaign

Attempted 10 roots. Outcomes: {'EXECUTED_CLEAN': 3, 'BLOCKED_REQUIRED_STATE': 5, 'BLOCKED_INDIRECT': 1, 'BLOCKED_IMPORT': 1}.
Most common next blocker: **BLOCKED_REQUIRED_STATE**.

## N. Frontier delta

- `_CIsqrt` removed from single-unlock ranking (was #1 @ 88).
- Next single-unlock leaders: `_wassert`/tolower/sprintf.
- UNIQUE executed: **6** (was audited 6 completed + new `0x00924D30` → see list).

## O. Executed-count audit

UNIQUE_UC_FUNCTIONS_EXECUTED = completed harness VAs:
`0x00721070`, `0x00739B90`, `0x0088390D`, `0x00924D30`, `0x009E78C0`, `0x009E8AD0`

Phase 25 said “6” while adding a consumer because the metric mixed
completed vs entered; Phase 26 uses completed-only unique VAs.

## P. Recommended Phase 27

Most common campaign next blocker is BLOCKED_REQUIRED_STATE (ordinary object/global contracts). Prefer documenting/entering proven ordinary initializers for import-ready math leaves, or implement next clean CRT HLE (tolower / floor cdecl — not _CI*) only if execution evidence elevates it. Do not implement _CIpow/_setjmp3 without real execution pressure. Graphics remain frozen.
