# Phase 76 — Bounded CRT startup prefix

2026-11-04. **Strong milestone within compatibility scope:** after the Phase 75 cookie return and NT_TIB32 prefix, Edge executes a host-scheduled bounded prefix of original CRT startup at `0x0087BB3D`, including SEH prolog frame `size=0x10` / `scope=0x00CA93F8`, `FS:[0x18]` Self read, StackBase ownership token, and exact-callsite `InterlockedCompareExchange`. Original code stores startup state `0x018B1E58 = 1`. Execution stops at `0x0087BBB4` → `0x0087C232` (`_initterm_e` stub). This is not original PE entry or loader binding.

## Baseline

HEAD before this phase: `c4563df0` (Phase 75 docs) on implementation `6ae0c3c6`. The 22 unrelated `discord-bot` deletions were preserved. No fetch or push.

Source SHA-256 remains `6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd`. Ordinary Wasm remains 14,981 bytes / `8d1a62e0…71c76`. Opt-in diagnostic module is now 22,070 bytes / `2efbe299…f82c` with 16 reviewed bodies (14 + cookie + startup prefix).

## Reviewed startup contract

Authenticated bytes for `[0x0087BB3D, 0x0087BBFA)` lift with exact instruction coverage. Key edges:

| Address | Role |
|---|---|
| `0x0087BB3D` | `push 0x10` / `push 0x00CA93F8` / `call 0x0087BEB8` |
| `0x0087BB4E` | `mov eax, fs:[0x18]` |
| `0x0087BB54` | `mov esi, [eax+4]` → StackBase ownership token |
| `0x0087BB62` | `call [0x00B611B4]` → `InterlockedCompareExchange` |
| `0x0087BBA4` | original `mov [0x018B1E58], esi` with `esi=1` |
| `0x0087BBB4` | `call 0x0087C232` → first unsupported `_initterm_e` |

Cleanup SEH frame (`0x14` / `0x00CA9380`) remains admitted. Startup frame (`0x10` / `0x00CA93F8`) is newly admitted with size-derived ESP expectations (`entry_esp - (24 + size)`). Epilog validation derives size from `[ebp-0x18]`.

## Compatibility services

Five Phase 75 cookie services unchanged. New exact callsite only:

| Callsite | Service | ABI |
|---|---|---|
| `0x0087BB62` | `InterlockedCompareExchange` | stdcall, 12 argument bytes; returns previous LONG |

Single-thread compare/store is documented; no fabricated multi-core barrier claim. Owner write is logged as a host environment write. State `1` is an original guest write. `Sleep` and `InterlockedExchange` are reviewed but unimplemented; foreign-owner tests stop at Sleep. `_initterm` / `_initterm_e` / encoding / app-type remain unimplemented.

## Edge evidence

Evidence: `crt-bootstrap-execution-phase76.json` (Edge 156.0.4314.58, HTTPS). Summary: `crt-startup-execution-phase76.json`.

Host schedule: cookie `0x0087C264` → NT_TIB32 prefix → startup `0x0087BB3D`.

Observed compatibility run:

- Original PE entry executed: **false**
- Original loader binding observed: **false**
- Startup state: **1**
- Startup owner: **0x03010000** (StackBase)
- Cleanup globals: still **0 / 0**
- Stop: `0x0087BBB4` / dependency `0x0087C232 → [0x00B613B4]`
- C/C++ initializer traversal: **not executed**

## Validation

| Check | Result |
|---|---|
| `tsc` / frontend build | Pass |
| `uc-crt-bootstrap.test.mjs` | 10 pass |
| `uc-seh.test.mjs` | 5 pass |
| Edge `uc-crt-bootstrap-browser.test.mjs` | Pass |
| `web/tools/unit-tests.mjs --fast` | 169 tests, 166 pass, 0 fail, 3 skip |
| Python Phase 43–51 | 121 pass |
| Startup preflight | Source/master verified; original startup still blocked |

## Phase 77

Review and, only if justified, implement `_initterm_e` / first C initializer `0x0087BCB3` contracts without inventing pointer encoding or skipping table entries. Keep Play disabled. Do not resume Unicorn adoption or graphics work.
