# Phase 17 — Graphics factory initialization provenance

Ordinary sections only. Phase 16 discovery rules unchanged. Direct3D9, TLS,
Win32, and `0x00686000` were not implemented. No graphics function was executed.
No flag, slot, object, or TLS state was synthesized.

## Terminology

In `function-map.json`, `reachable: true` means the entry was **enrolled in the
Phase 16 ordinary discovery graph** (seed BFS or CFG-complete strong-entry
enrollment). It does **not** mean a proven call-graph path from a live root.

## A. `0x00722D60` entry provenance

| Fact | Value |
| --- | --- |
| Label | HIGH_CONFIDENCE (score 105) |
| Map `reachable` | true (enrollment) |
| Termination | RET_REACHED (24 instructions, 5 blocks) |
| After int3 | yes |
| Frame prologue | no |
| Call/tail predecessors | **none** |
| `E8`/`E9` sites | **0** |
| Absolute dword in `.text/.rdata/.data/.tls/.rsrc` | **0** |
| Immediate refs in `.text` | **0** |

Enrollment reason: CFG-complete int3-padded strong entry under Phase 16 rules.

Body (abbreviated):

1. `call 0x0071EB40`
2. `mov eax, 1` / `mov ecx, 0x01311E1C` / `xchg dword ptr [ecx], eax`
3. loop: wait via `call 0x009773B0` until `[0x01311E1C] == 2` or `[0x012C9148] == 1`
4. `ret`

## B. Flag state machine (`0x01311E1C`)

PE value: **0**.

| Transition | Writer entry | Site | Mechanism |
| --- | --- | --- | --- |
| ANY → 1 | `0x00722D60` | `0x00722D70` | `xchg [ecx], eax` with EAX=1 |
| ANY → 2 | `0x007297D0` (contains site) | `0x00729977` | `xchg [ecx], eax` with EAX=2 |
| ANY → 0 | `0x00B4F990` | `0x00B4F997` | `xchg [ecx], eax` with EAX=0 |

Observed uses:

| Value | Ordinary use |
| --- | --- |
| 0 | image / clearer leaf |
| 1 | gate in `0x0072E5D0`: `cmp [flag], 1` / `je` before `call 0x0072E340` |
| 2 | wait exit in `0x00722D60`; stored by post-factory-ish path in `0x007297D0` |

Meaning is **not** established beyond these compares. Do not equate `1` with
“initialized” except as the gate value `0x0072E5D0` requires.

## C. XCHG semantics

Lifter (`tools/lift.py`): unlocked `xchg` swaps both operands through a temp.
For `xchg dword ptr [ecx], eax` that yields old memory in EAX and new EAX in
memory. Flag writers have **no LOCK prefix**. Single-threaded model is
consistent; atomicity is not claimed. No lowering change in this phase.

## D–G. Callback slots

All three live in `.rdata`. PE consumers call through them. **No absolute writers.**

| Slot | PE value | On linear-sweep boundary | Consumers | Final class |
| --- | --- | --- | --- | --- |
| `0x00B611D4` | `0x008A9F58` | no | load in `0x00766730`; several `call dword ptr [slot]` | RUNTIME_REPLACEMENT_REQUIRED |
| `0x00B61188` | `0x008AB180` | no | `0x009773B0` wait helper; other indirect calls | RUNTIME_REPLACEMENT_REQUIRED |
| `0x00B615C4` | `0x008AA3AE` | no | `mov esi,[slot]` then **three `call esi`** in `0x0072E340` before Direct3DCreate9 | RUNTIME_REPLACEMENT_REQUIRED |

Interior class for each PE target: **INVALID_INTERIOR_ENTRY** (not a linear-sweep
instruction start; Capstone mid-stream decode is rejected).

Not PE IAT entries. No ordinary replacement writers found. Import-like only as
a descriptive analogy: static placeholders that must be replaced before use,
without PE import evidence.

## H–I. Graphics object `0x01318170`

Still PE-zeroed `.data` virtual tail. Address-taken widely among HIGH functions.
Top address-taken roots include `0x007540E0`, `0x0071E9A0`, `0x00787D40`,
`0x00766730`, …

Key offsets relative to the factory path:

| Offset | Role |
| --- | --- |
| `+0x10` | WRITTEN_BY_FACTORY_PATH (Direct3DCreate9 result) |
| `+0x54` | ONLY_USED_AFTER_FACTORY (optional write before factory if `+0x4B8` nonzero) |
| `+0x4C0`, `+0x4C8`, `+0x4D0` | lea’d as callback buffer args on the pre-factory path; zero may be intentional; UNKNOWN as hard prerequisite |
| `+0x534` | UNKNOWN |

No single proven constructor. Staged / lazy thiscall methods on the static object.

## J. TLS index `0x01882C34`

PE value 0. Absolute WRITE count: **0**. Used with `fs:[0x2C]` in outer
`0x00766730` only among the three prefixes.

| Prefix | Uses TLS index | Uses flag | Uses slots | Calls helper |
| --- | --- | --- | --- | --- |
| `0x00766730` | yes | no | `0x00B611D4` | no |
| `0x0072E5D0` | no | yes | — | no |
| `0x0072E340` | no | no | `0x00B615C4` | no |

TLS is an **outer orchestration** dependency, not inherent to the factory function.

## K. Outer vs inner requirements

- Enter `0x00766730`: TLS index + slot `0x00B611D4` + object as ECX for callee.
- Enter `0x0072E5D0`: flag must already be 1 (else wait loop); then `call 0x0072E340`.
- Enter `0x0072E340`: ECX = object; ESI from `0x00B615C4` must be a valid callee.

## L. Shortest pre-factory path (`0x0072E340` → site)

```
sub esp, 0x4C
push ebx / ebp / esi
mov esi, dword ptr [0x00B615C4]      ; REQUIRED load
mov ebx, ecx                         ; this = object
xor ebp, ebp
; three times: push 0 / lea [ebx+4C0|4C8|4D0] / push sizes / call esi
cmp dword ptr [ebx+0x4B8], ebp
je skip
mov eax, [ebx+0x54] ; mov [eax+0x78], 1
skip:
lea / push stack args; mov immediates 0x00CE69F8, 0x00CC5B44
call 0x0072DD00
call 0x0072DCA0
push 0x20
call 0x0087A79C                      ; Direct3DCreate9 thunk
```

## M. Branch / path conditions

One conditional before the factory call: `cmp [ebx+0x4B8], 0` / `je`.
Fall-through writes through `[ebx+0x54]`. Factory call is reached on **both** arms.
No hard branch prerequisite beyond surviving the three `call esi`.

## N. Minimum factory prerequisites

1. `0x0072E340` HIGH (satisfied)
2. Direct callees `0x0072DD00`, `0x0072DCA0` HIGH/compiled (satisfied)
3. `[0x00B615C4]` valid callable target (**not satisfied** — INVALID / replacement required)
4. ECX = `0x01318170` (caller-supplied; object may be zero)
5. Direct3DCreate9 may remain unimplemented; stop immediately before it

Flag=1 is required only when entering via `0x0072E5D0`, not by the create body itself.

## O. FACTORY_FRONTIER_READY

**FALSE**

Primary blocker on the create prefix: three `call esi` through
`RUNTIME_REPLACEMENT_REQUIRED` slot `0x00B615C4`.

Static Direct3DCreate9 frontier: **REACHABLE** (HIGH create calls the thunk).
Runtime factory frontier: **NOT ENTERABLE**.

## P. Controlled execution

Not run. No legitimate ordinary initializer sequence closes the ESI slot or
publishes `0x00722D60`.

## Q. Remaining dependencies

| Item | Class |
| --- | --- |
| `0x00B615C4` valid target | UNKNOWN (replacement required; not proven protected) |
| `0x00B611D4` / `0x00B61188` | UNKNOWN (same) |
| `0x01311E1C = 1` invocation | UNKNOWN (`0x00722D60` enrolled HIGH, no invocation path) |
| `0x01882C34` TLS (outer only) | TLS_RUNTIME |
| `0x01318170` fields | UNKNOWN / ORDINARY address-taken methods |
| Direct3DCreate9 | IMPORT_RUNTIME |
| `0x00686000` on create path | **no** (create is NO_PATH in helper cut) |

## R. First-frame estimate

| | Value |
| --- | ---: |
| BEST_CASE_FIRST_FRAME_PHASE | 20 |
| LIKELY_FIRST_FRAME_PHASE_RANGE | 23–31 |

Unchanged: static reachability was already known after Phase 16; runtime
provenance did not close the slot/flag blockers.

## S. Recommended Phase 18

Continue ordinary provenance for how `.rdata` graphics callback slots become
valid callables (or prove they are protected/external). Do **not** implement
Direct3D9 until FACTORY_FRONTIER_READY.
