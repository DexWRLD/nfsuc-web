# Undercover Phase 47 — Clean-PC asset downloads & runtime expansion

SHA-256 target: `6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd`

`GAME_CODE_TARGET=NFS_UNDERCOVER_PC`  `TOOLING_ORIGIN=NFSU2-WEB`

FIRST_FRAME: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`

## A. Asset distribution

- Readiness: **FIXTURE_PIPELINE_READY**
- Production Undercover assets: **UNAVAILABLE_PENDING_AUTHORIZED_SOURCE**
- Manifest mode: `fixtures` (authorized=False)
- Required fixture assets: 2
- Node uc-assets tests: **PASS**

Clean Windows PC path for fixtures: open site → check cache → download missing → verify SHA-256 → initialize FS bridge. No game install folder.

## B. Browser renderer

- Readiness: **SYNTHETIC_CLEAR_SMOKE_ONLY**
- Clear-only smoke mirrors BeginScene→Clear→EndScene→Present shape.
- Does **not** change first-frame blocked status.

## C. New guest-executed functions

| Address | Role | Clean | Oracle |
|---|---|---|---|
| `0x00A129B0` | near_eq_true | True | True |
| `0x00A129B0` | near_eq_false | True | True |
| `0x00A12A40` | from_vec | True | True |
| `0x00A12DE0` | mul_cdecl | True | True |

Newly unique: ['0x00A129B0', '0x00A12A40', '0x00A12DE0']
Newly enterable: ['0x00A129B0', '0x00A12A40', '0x00A12DE0']
Chain clean: True

## D. Metrics

- UNIQUE: 79 → 82
- ENTERABLE: 45 → 48
- EXECUTION_RUNS: 297 → 310
- RUNTIME_READY: 72
- BLOCKED_EXTERNAL: 74
- Asset distribution: FIXTURE_PIPELINE_READY
- Browser renderer: SYNTHETIC_CLEAR_SMOKE_ONLY
- Authentic first frame: BLOCKED

## E. Phase 48

Host rights-authorized Undercover game data; map real resource formats into the FS bridge; recover scheduling edges for authentic Present; expand guest execution; keep opaque draw backends untouched.
