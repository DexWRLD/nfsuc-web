# Undercover Phase 25 — Ordinary runtime frontier

Graphics investigation remains **frozen**. `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`. No analysis of `0x007A51B0` / protected submit backend.

## Counts

| metric | value |
| --- | ---: |
| HIGH functions | 22779 |
| Generated | 22770 |
| Compiled | 22770 |
| RUNTIME_READY (READY + READY_WITH_IMPORTS closures) | 54 |
| EXECUTED (harness-logged) | 6 |
| BLOCKED_GRAPHICS (call-list) | 124 |
| BLOCKED_PROTECTED (call-list) | 585 |
| BLOCKED_STANDARD_RUNTIME | 733 |
| UNKNOWN | 79 |
| Execution islands | 7085 |
| Non-graphics islands | 6996 |

## Selected implementation

**`strncpy` CRT HLE** (`0x0087B6A0`, cdecl, 3 stack dwords).

Highest single-missing-import unlock in prior frontier (90 HIGH functions / 66 closures / 244 call sites); cdecl; standard public CRT semantics; no protected behavior.

Standard/public semantics: YES. Protected dependency: NO.

## Top blockers (non-graphics weighted)

- `BLOCKED_IMPORT` — ~495 HIGH fns / 63 components; largest 274 @ 0x009F0D20; recommend NO
- `BLOCKED_EXTERNAL` — ~316 HIGH fns / 22 components; largest 274 @ 0x009F0D20; recommend NO
- `IMPORT:_CIpow` — ~277 HIGH fns / 2 components; largest 274 @ 0x009F0D20; recommend CANDIDATE
- `IMPORT:_setjmp3` — ~274 HIGH fns / 1 components; largest 274 @ 0x009F0D20; recommend NO
- `IMPORT:floor` — ~274 HIGH fns / 1 components; largest 274 @ 0x009F0D20; recommend CANDIDATE
- `BLOCKED_PROTECTED` — ~249 HIGH fns / 188 components; largest 19 @ 0x0085AD60; recommend NO
- `BLOCKED_FILESYSTEM` — ~115 HIGH fns / 5 components; largest 111 @ 0x00883012; recommend NO
- `BLOCKED_TIMING` — ~113 HIGH fns / 3 components; largest 111 @ 0x00883012; recommend NO
- `IMPORT:_close` — ~111 HIGH fns / 1 components; largest 111 @ 0x00883012; recommend NO
- `IMPORT:_filelength` — ~111 HIGH fns / 1 components; largest 111 @ 0x00883012; recommend NO

## Top non-graphics execution islands

- root `0x009F0D20` — 274 fns, missing _CIpow, _setjmp3, floor, isalnum, isalpha, iscntrl, isdigit, isspace, blockers BLOCKED_EXTERNAL, BLOCKED_IMPORT
- root `0x0072EAE0` — 41 fns, missing none, blockers RUNTIME_READY
- root `0x00B182F0` — 21 fns, missing none, blockers RUNTIME_READY
- root `0x00721050` — 11 fns, missing none, blockers RUNTIME_READY
- root `0x00820E20` — 13 fns, missing none, blockers RUNTIME_READY
- root `0x00757B40` — 12 fns, missing none, blockers RUNTIME_READY
- root `0x009FF620` — 11 fns, missing none, blockers RUNTIME_READY
- root `0x008833FA` — 11 fns, missing none, blockers RUNTIME_READY
- root `0x00A07E00` — 11 fns, missing none, blockers RUNTIME_READY
- root `0x00A52A90` — 11 fns, missing none, blockers RUNTIME_READY

## Import frontier

Total thunks: 199. Implemented HLE: 11. Next unlock candidates after strncpy:

- `_CIsqrt` sites=116 prior_single_unlock=88 (KNOWN_ABI_UNIMPLEMENTED)
- `_wassert` sites=1 prior_single_unlock=22 (CONVENTION_KNOWN_NO_HLE)
- `sprintf` sites=430 prior_single_unlock=21 (KNOWN_ABI_UNIMPLEMENTED)
- `tolower` sites=10 prior_single_unlock=21 (KNOWN_ABI_UNIMPLEMENTED)
- `sscanf` sites=51 prior_single_unlock=15 (KNOWN_ABI_UNIMPLEMENTED)
- `strchr` sites=50 prior_single_unlock=13 (KNOWN_ABI_UNIMPLEMENTED)
- `_snprintf` sites=34 prior_single_unlock=13 (KNOWN_ABI_UNIMPLEMENTED)
- `strtok` sites=26 prior_single_unlock=12 (CONVENTION_KNOWN_NO_HLE)

## Frontiers (summary)

- **CRT**: continue string/math helpers with known cdecl; next after strncpy likely `_CIsqrt` / `tolower` / `sprintf` (format risk).
- **Allocation**: `malloc`/`free` present as MEMORY_BOUNDARY — do not substitute for protected helpers.
- **Filesystem**: CRT/Win32 file imports exist; leverage lower than strncpy this phase.
- **Timing / threading / TLS / SEH**: present as stubs or missing on UC import path; not selected.
- **Indirect calls**: still a major whole-program limiter (see prior frontier kinds).

## Harness capability

- mapped_ordinary_sections: **IMPLEMENTED**
- guest_stack: **IMPLEMENTED**
- direct_uc_calls: **IMPLEMENTED**
- nested_uc_calls: **IMPLEMENTED**
- imports_hle: **PARTIAL**
- x87: **PARTIAL**
- simd: **PARTIAL**
- atomics: **PARTIAL**
- memory_validation: **IMPLEMENTED**
- indirect_dispatch: **PARTIAL**
- tls: **STUB**
- filesystem: **MISSING**
- threads: **MISSING**
- timing: **MISSING**
- seh: **STUB**
- atomic_correctness: **SUFFICIENT_FOR_SINGLE_THREAD**

Native UC harness maps ordinary PE sections and runs lifted HIGH functions with import HLE for CRT mem/string and a few x87 helpers. NFSU2 win32/fileio/thread helpers exist in the broader tree but are not wired as the Undercover native UC import path. Atomics suffice for single-thread controlled execution.

## Dashboard fields

- `ORDINARY_RUNTIME_FRONTIER`: see `runtime-frontier.json`
- `TOP ORDINARY ISLAND`: see `execution-islands.json`
- Graphics badges stay frozen (FIRST FRAME blocked / D3D9 not justified / engine backend not justified).

## Consumer measurement

| | |
| --- | --- |
| Before | `strncpy` thunk `0x0087B6A0` was `UC_HLE_NONE` → import invoke fault (“no HLE implementation”) |
| After | `UC_HLE_STRNCPY`; consumer `0x0088390D` copies `"UNDERCOVER"` into `this+0xB4` (n=`0x1F`) and returns |
| Unit | phase6 covers short-src pad + long-src truncate |
| Newly runtime-ready (estimate) | 90 HIGH functions previously single-blocked by `strncpy` |
| Next blocker after improvement | `_CIsqrt` (88 single-unlock functions) |

## Recommended Phase 26

Implement **`_CIsqrt`** (x87 ST0, same pattern as `_CIsin`/`_CIcos`/`_CIacos`) unless a cleaner enterable island root is preferred. Do not reopen protected graphics.
