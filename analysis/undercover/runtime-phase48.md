# Undercover Phase 48 — Clean-PC validation & asset hardening

SHA-256: `6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd`

`GAME_CODE_TARGET=NFS_UNDERCOVER_PC`  `TOOLING_ORIGIN=NFSU2-WEB`

FIRST_FRAME: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`

## A. Toolchain / stray path

- Node: `v24.20.0`
- Stray `--help/`: Accidental copies of analysis/undercover/progress.* likely created when progress.py was invoked with a '--help' output path. Not source code; left untracked per Phase 48 (do not delete without user confirmation).

## B. Validation layers (do not merge)

- Node `uc-assets.test.mjs`: **PASS**
- Frontend build: **PASS**
- Browser clean profile: **PASS**
- Python asset mirror: retained as secondary
- Guest execution: see section D
- Synthetic graphics: clear smoke only
- Authentic gameplay: not ready

## C. Asset hardening

Path traversal / duplicate rejection, URL host restrictions, atomic staged cache publish, retry backoff, content-length checks, cache re-hash, retry/cancel UI. See `web/docs/uc-clean-pc-deploy.md`.

## D. New guest-executed functions

| Address | Function | ABI | Oracle | Result |
|---|---|---|---|---|
| `0x00A12800` | float_passthru | cdecl `float(float)` ST0 | ST0=arg0 (clean return) | EXECUTED_CLEAN |
| `0x00A12810` | finite_matrix_ok | thiscall ret4 `(*out)=1` | all 12 floats finite | EXECUTED_CLEAN |
| `0x00A12810` | finite_matrix_inf | thiscall ret4 `(*out)=0` | Inf present → 0 | EXECUTED_CLEAN |

Newly unique: ['0x00A12800', '0x00A12810']
Newly enterable: ['0x00A12800', '0x00A12810']

## E. Metrics

- Compiled functions: 22,770 (unchanged)
- UNIQUE: 82 → 84
- ENTERABLE: 48 → 50
- RUNS: 310 → 322
- RUNTIME_READY: 72
- BLOCKED_EXTERNAL: 74 (unchanged)
- Asset distribution: FIXTURE_PIPELINE_HARDENED
- Browser renderer: SYNTHETIC_CLEAR_SMOKE_ONLY
- First frame: BLOCKED

## F. Phase 49

Authorize and host real Undercover game data; map resource formats; recover scene scheduling edges; keep opaque draw backends untouched.
