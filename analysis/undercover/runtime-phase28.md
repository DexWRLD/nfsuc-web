# Undercover Phase 28 — Ordinary initialization depth

Graphics frozen: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`.

## A. Baseline

ENTERABLE 6; UNIQUE executed 8; deepest chain 2; largest closure 2.
IMPORT_READY unchanged (~737). Dominant blocker: BLOCKED_REQUIRED_STATE.

## B. Track A — `0x00A52DF0`

No E8, no function-map preds, no absolute imm32 refs in mapped image. Do not synthesize +0x140/+0x150. Stop Track A.

Layout proven from ops: xmmword reads at +0x140/+0x150; writes +0x100/+0x120;
float arg; `_CIsin` then `_CIsqrt`. Not labeled matrix beyond SIMD vectors.

## C. Non-E8 references

- E8 callers: **0**
- imm32 sites: **0**
- function-map preds: **0**

## D. Field provenance

No ordinary writer cluster uniquely tied to this type. Classification:
`NO_ORDINARY_INIT_PATH_FOUND`.

## E. Constructor/init candidates

- PROVEN: `0x009E9160` (vtable 0xC30E68)
- STRONG base: `0x009E7710`
- ORDINARY_INITIALIZER: `0x009E9990`

## F. Reverse-call frontier

Seeds: 0x00721070, 0x00739B90, 0x0088390D, 0x00924D30, 0x00929972, 0x00949920, 0x009E78C0, 0x009E8AD0
Top reverse callers scored in `reverse-execution-frontier.json`.

## G–I. Census / POD

See census in reverse-execution-frontier.json. POD builders preserved from Phase 27.

## J. Ranked depth-3 candidates

- `0x009E9160` kind=ENTERABLE_AFTER_ORDINARY_CTOR cost=3 pot=90 — ctor nests base initializer; harness allocates guest this + POD source
- `0x0072D640` kind=ENTERABLE_DIRECT cost=1 pot=70 — uses BSS object 0xCEA3B8 via 0x00721050; stops before protected 0x0072C190
- `0x0072DCA0` kind=ENTERABLE_DIRECT cost=1 pot=80 — PE-zero BSS 0xCEA3F0/0xCEA3F4 selects jmp → 0x0072D640. Lifter may merge tail into one frame; nesting depth depends on lift shape.

## K. Initialization graphs

`0x009E9160` ← POD/this ← harness; nested `0x009E9990` ← `0x009E7710` ← STATIC vtable.
`0x0072D640` ← primitives ← BSS `0xCEA3B8` ← PROTECTED `0x0072C190`.

## L. Execution campaign

Outcomes: `{'EXECUTED_TO_NEXT_BLOCKER': 2, 'BLOCKED_REQUIRED_STATE': 6, 'BLOCKED_PROTECTED': 1}`

## M. Deepest successful run

`0x009E9160` → `0x009E9990` → `0x009E7710` (depth **3**).
Constructor→initializer chain: **YES**.
POD grandparent→parent→child: **NO** (`0x00947790` still UNKNOWN).

## N. Actual runtime blockers

- After depth-3 ctor: Win32 IAT dispatch at `0x009777D0` / `[0x00B61138]`
- After BSS parent chain: PROTECTED `0x0072C190`
- Campaign majority: BLOCKED_REQUIRED_STATE (large islands)

## O. Frontier delta

- ENTERABLE: 6 → **12**
- UNIQUE executed: 8 → **15**
- DEEPEST chain: 2 → **3**
- LARGEST closure: 2 → **4**
- ENTERABLE_WITH_DEPTH_3_POTENTIAL: **1**

## P. Phase 29

Depth 3 achieved via ordinary ctor nesting. Next: either (1) resolve/stub-classify the Win32 IAT at 0x00B61138 blocking completion of 0x009E9160→0x009E8AD0, or (2) recover a lower-cost POD grandparent for the 0x00929900 math island (0x00947790 still UNKNOWN). Do not reopen Track A 0x00A52DF0 without new refs. No CRT HLE until a chain reaches it.
