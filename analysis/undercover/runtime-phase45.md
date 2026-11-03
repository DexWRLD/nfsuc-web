# Undercover Phase 45 — Allocator-independent execution expansion

SHA-256 target: `6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd`

`GAME_CODE_TARGET=NFS_UNDERCOVER_PC`  `TOOLING_ORIGIN=NFSU2-WEB`

FIRST_FRAME: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`

## A. Helper-cut reconciliation

- Current MUST / MAY / INDEPENDENT: **74 / 139 / 22394** (reachable_high=22607)
- Dashboard BLOCKED_EXTERNAL: **74** ≡ current MUST: **True**
- Historical Phase-14 doc MUST/MAY/INDEP: 11 / 31 / 6456 — different population.

Different analysis stage and reachable-HIGH population. Phase-14 documented MUST=11/MAY=31/INDEP=6456 on ~6498 reachable HIGH. Current helper-cut.json (Phase 16+) has MUST=74/MAY=139/INDEP=22394 on reachable_high=22607. Dashboard BLOCKED_EXTERNAL=74 tracks current MUST, not the historical Phase-14 MUST=11.

See `helper-cut-reconciliation.json`.

## B. New guest-executed functions

| Address | Role | Clean | Oracle |
|---|---|---|---|
| `0x00A12850` | const_ptr | True | True |
| `0x00A130E0` | coalesce_passthrough | True | True |
| `0x00A130E0` | coalesce_default | True | True |
| `0x00A127E0` | fmax_2_5 | True | True |
| `0x00A128A0` | copy_transpose | True | True |
| `0x00A12860` | transpose_inplace | True | True |
| `0x00A12D10` | matrix_add | True | True |
| `0x00A12D50` | matrix_sub | True | True |
| `0x00A12D90` | matrix_scale | True | True |

Newly unique executed: ['0x00A127E0', '0x00A12850', '0x00A12860', '0x00A128A0', '0x00A12D10', '0x00A12D50', '0x00A12D90', '0x00A130E0']
Newly enterable: ['0x00A127E0', '0x00A12850', '0x00A12860', '0x00A128A0', '0x00A12D10', '0x00A12D50', '0x00A12D90', '0x00A130E0']
Matrix chain clean: True

## C. Metrics

- UNIQUE: 67 → 75
- ENTERABLE: 33 → 41
- EXECUTION_RUNS: 265 → 282
- RUNTIME_READY: 72 (unchanged policy)
- BLOCKED_EXTERNAL: 74 (unchanged)

## D. Regressions

- Family A getter 0x5A: True
- Family B export: True
- Family C field: True

## E. Allocator / protected

No injected allocator substitution. MUST set untouched. Backends opaque.

## F. Phase 46

Expand the 0x00A12xxx matrix island (more leaf ops / short chains); recover ordinary contracts for remaining RUNTIME_READY_NOT_EXECUTED math leaves; continue Family C/+0x14 interface work only with proven providers. Keep 0x00686000 opaque.
