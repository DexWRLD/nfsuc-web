# Undercover Phase 44 — External blocker attribution

Target SHA-256: `6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd`

`GAME_CODE_TARGET=NFS_UNDERCOVER_PC`  `TOOLING_ORIGIN=NFSU2-WEB`

FIRST_FRAME: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`

## A. What BLOCKED_EXTERNAL means here

progress.py: MUST_REACH_EXTERNAL_HELPER on allocator 0x00686000 (helper-cut). Not every protected-boundary caller.

The eight audited protected boundaries are **not** each a separate
`BLOCKED_EXTERNAL` class. Only the helper-cut **MUST** set (allocator)
is painted `BLOCKED_EXTERNAL` in `progress.json`.

## B. Counts

- BLOCKED_EXTERNAL before: **74**
- BLOCKED_EXTERNAL after: **74** (delta 0)
- With identified root blocker: **74**
- Direct: **62**
- Transitive/inherited: **12**
- Audit missing-caller gaps: **6**
- Callback registration edges: **2**
- BLOCKED_EXTERNAL affected by callback edges: **0**

## C. Root cause

Every `BLOCKED_EXTERNAL` function shares root **`0x00686000` (allocator)**.
No duplicate competing primary roots inside this class.

## D. Audit cross-check

- Audit defined alloc callers: 113
- Of those in BLOCKED_EXTERNAL: 56
- Of those in MAY (correctly not BLOCKED_EXTERNAL): 44
- Absent from progress: 13

Audit completeness issue:

Allocator root claims complete:true but omits >=6 verified ordinary direct callers present in project function-map and .text.

Verified omitted direct callers:

- `0x0071E6A0`
- `0x0071E730`
- `0x00779B30`
- `0x0077A4E0`
- `0x0077BF80`
- `0x00780180`

## E. Callback edges

| Registrar | Site | Callback | Kind | Execution modeled |
|---|---|---|---|---|
| `0x0072E340` | `0x0072E497` | `0x0072B170` | CALLBACK_REGISTRATION | False |
| `0x0076CA20` | `0x0076CB40` | `0x00766730` | CALLBACK_REGISTRATION | False |

Registration ≠ execution. Registrars were **not** reclassified to
`BLOCKED_EXTERNAL` because a DATA reference exists.

## F. Classification errors

- Status changes required: **0**
- Graph diagnostics added for audit caller gaps and callback registration.
- Do not reclassify solely because a Ghidra call site exists.

## G. Guest metrics (unchanged)

- ENTERABLE: 33 (Δ 0)
- UNIQUE executed: 67 (Δ 0)
- RUNTIME_READY: 72 (Δ 0)
- Newly classified without execution: 0

## H. Artifacts

- `blocked-external-attribution.json`
- `blocked-external-inventory.json`
- `callback-registration-edges.json`
- `blocker-audit-2026-11-03.json`

## I. Phase 45

See `phase45-handoff.md`.
