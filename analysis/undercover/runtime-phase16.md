# Phase 16 — CFG discovery repair

Ordinary `.text` and existing analysis only. Protected sections were not
read. Direct3D9, TLS, Win32, and `0x00686000` were not implemented.

## A. Old walker defect

`tools/uc_funcmap.py` scored uncovered padding/prologue candidates with a
**24-instruction linear sketch** (`_window`). That sketch never followed
conditional branches, never reached many ordinary returns, and therefore
blocked HIGH even when score ≥ 60.

Of **1,782** functions that previously appeared as `MEDIUM_CONFIDENCE` with
`insns == 24` (almost all unreachable sketches), Phase 15 already showed that
real CFG walks of `0x00766730` and `0x0072E340` found ordinary returns. That
was a general discovery defect, not a graphics special case.

The primary seed BFS walker already used a large CFG budget. The defect was
the unreachable-candidate sketch and the missing enrollment of CFG-complete
strong entries into the ordinary graph.

## B. New CFG walker design

`Walker.walk` is now the single fact walk:

- worklist of basic-block starts
- decode only on linear-sweep instruction boundaries
- follow ordinary direct conditional / unconditional branches
- stop at near ret; record multiple returns
- treat jmp-to-strong-entry as a tail transfer (do not absorb callees)
- record direct calls without absorbing callee bodies
- stop / conflict when falling into another known strong entry
- recognize switch tables via the existing lifter helpers

Every walk records a termination reason.

## C. Safety budgets

| Budget | Value |
| --- | --- |
| Instructions | 16,384 |
| Blocks | 4,096 |
| Byte span | 262,144 |

Hitting a budget sets `CFG_BUDGET_EXCEEDED` and prevents HIGH. This is not a
tiny linear discovery cap.

## D. Old 24-instruction cohort outcome

Cohort size: **1,782**

| Outcome | Count |
| --- | --- |
| PROMOTED_HIGH | 1,769 |
| REMAINS_MEDIUM | 5 |
| DEMOTED_LOW | 2 |
| REJECTED_DATA | 3 |
| CFG_BUDGET_EXCEEDED | 3 |

## E. Confidence-map before/after

| Label | Before (reachable) | After (reachable) |
| --- | ---: | ---: |
| HIGH_CONFIDENCE | 6,597 | 22,779 |
| MEDIUM_CONFIDENCE | 50 | 165 |
| LOW_CONFIDENCE | 20 | 54 |
| REJECTED_DATA_LIKE | 514 | 1,454 |

Strong CFG candidates enrolled: **14,868**.
Newly HIGH vs prior reachable HIGH: **16,202**. Lost HIGH: **20**.

## F. CFG coverage before/after

| | Bytes | % of ordinary `.text` |
| --- | ---: | ---: |
| Before | 1,851,810 | 23.96% |
| After | 3,864,703 | 50.00% |

Text size: 7,730,171 bytes.

CFG-budget exceeded among walked entries: **72**.

## G. Translation results

HIGH attempted: **22,779**  
Generated: **22,770**  
Generation failures: **9** (`int`×7, `fbstp`×2)

## H. Compilation results

Compiled: **22,770 / 22,770**  
Compiler failures: **0**

Phase 5's compiler closure still holds on the repaired discovery set.

## I. Newly promoted functions

Newly HIGH: **16,202**  
Generated among attempted HIGH: **22,770**  
Compiled: **22,770**  
Unsupported among failures: `int`, `fbstp`  
Indirect call sites recorded in generation: **20,969**  
External direct edges: **37**

## J. Call-graph changes

Reachable HIGH: **22,779** (frontier scan used 22,607 after thunk filter).  
Direct call / tail edges expanded with the enrolled strong entries.  
Largest protected-reaching closure root: `0x009EA130` size **794**.

## K. `0x00686000` cut recomputation

| Class | Count |
| --- | ---: |
| MUST_REACH_EXTERNAL_HELPER | 74 |
| MAY_REACH_EXTERNAL_HELPER | 139 |
| NO_PATH_TO_EXTERNAL_HELPER | 22,394 |

Direct helper-touching HIGH functions: **110**. Direct CFG sites: rebuilt with the new map.

**Still a narrow cut** relative to the HIGH set (~0.3% MUST). Absolute MUST/MAY grew because the HIGH set grew; the independent majority remains.

## L. `0x0055FF30`

Still **UNKNOWN**. Four ordinary call sites. Body is still not a function. Not implemented.

## M. READY closure changes

From `runtime-frontier.json` after rebuild:

| Closure | Root | Size |
| --- | --- | ---: |
| READY | `0x00B01EB0` | 19 |
| READY_WITH_IMPLEMENTED_IMPORTS | `0x0096CED0` | 35 |
| PROTECTED_BOUNDARY (largest) | `0x009EA130` | 794 |

## N. Graphics-function confidence changes

| VA | Confidence | Insns | Blocks | Termination | Reachable |
| --- | --- | ---: | ---: | --- | --- |
| `0x00766730` | HIGH | 227 | 25 | RET_REACHED | yes |
| `0x0072E5D0` | HIGH | 130 | 16 | MULTIPLE_RETURNS | yes |
| `0x0072E340` | HIGH | 351 | 12 | MULTIPLE_RETURNS | yes |
| `0x0072DD00` | HIGH | 33 | 4 | RET_REACHED | yes |

No address-specific promotion rules. General CFG enrollment + scoring only.
`0x00766730` / `0x0072E5D0` are MAY for the helper cut; `0x0072E340` is independent.

## O. Direct3DCreate9 predecessor graph

Shortest ordinary predecessor chain:

`0x0072E340` → `0x0087A79C` (Direct3DCreate9 thunk)

Highest-confidence chain: same (create is HIGH).  
Independent-of-`0x00686000` chain: same (`0x0072E340` is NO_PATH).  
Longer provenance chain still exists: `0x00766730` → `0x0072E5D0` → `0x0072E340` → thunk.

## P. Flag=1 writer reachability

`0x00722D60` is now **HIGH** and reachable in the ordinary graph, but still has:

- 0 ordinary `E8` callers
- 0 absolute pointer refs in allowed sections
- 0 call-graph predecessors

Disconnected from ordinary direct call flow.

## Q. Graphics callback-slot classifications

| Slot | PE value | Class |
| --- | --- | --- |
| `0x00B611D4` | `0x008A9F58` | INVALID_INSTRUCTION_BOUNDARY |
| `0x00B61188` | `0x008AB180` | INVALID_INSTRUCTION_BOUNDARY |
| `0x00B615C4` | `0x008AA3AE` | INVALID_INSTRUCTION_BOUNDARY |

Corrected CFG discovery did not turn these into valid entries.

## R. TLS provenance changes

`0x01882C34`: still **0** absolute ordinary writers. No newly promoted writer found.

## S. Graphics-object provenance changes

`0x01318170`: PE zeroed. Phase 16 refs are **ADDRESS_TAKEN** only (123). No new constructor/zeroing writer proven.

## T. Dashboard changes

`tools/progress.py` now exposes a discovery-quality panel (HIGH/MEDIUM/LOW/REJECTED,
CFG-complete, CFG-budget, translation/compilation success) and regenerates maps from
the corrected counts (no frozen 6,604/6,598).

## U. Recommended Phase 17

Expand ordinary graphics initialization provenance for the still-blocked inputs:

- how `0x00722D60` is reached without an ordinary direct caller
- legitimate publication of the callback slots
- object `0x01318170` field writers
- TLS index provenance

Do not implement Direct3D9 yet. The factory is on a reachable HIGH path but is
not enterable with proven state.

## First-frame estimate

| | Phase 15 | Phase 16 |
| --- | ---: | ---: |
| BEST_CASE_FIRST_FRAME_PHASE | 21 | 20 |
| LIKELY_FIRST_FRAME_PHASE_RANGE | 24–32 | 23–31 |

The discovery repair removed one structural blocker (MEDIUM/cap). Runtime
blockers (flag, slots, TLS, zero object) remain, so the estimate moves only one
phase.
