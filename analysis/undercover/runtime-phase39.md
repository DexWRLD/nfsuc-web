# Undercover Phase 39 — object lifecycle + global publication

Graphics frozen: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`.

## A. Baseline

Phase 38: UNIQUE 53, ENTERABLE 25, SEQ_LEN 3, SEQ_COV 20, 6 clean stateful sequences.

## B. Proven object state

Ctor `0x009E9160` extent `0x248`; vtables `0x00C30E68` / `0x00C30F2C`; +0xBC/+0xC0 list heads; +0xDC flag; +0xE0 null.

## C. Vtable/method census

Main table slots 0–16 classified; dtor/allocator/unknown rejected.

## D. Consumer prerequisites

List methods need +0xBC/+0xC0 (constructor-produced). Embed clear needs +0xE0 null. Setter/getter need +0xDC.

## E. Executed object methods

setter/getter/rtti/list_a/list_b/embed_clr — see sequences.

## F. Embedded-object consumers

`0x009E9980` (pod +4); `0x009E83D0` (this+0xE0 clear early-exit).

## G. Global publication provenance

`0x0189D1A4←0x009E78C0`, `0x0189D198←0x009E77D0` via `0x009E8AD0`.

## H. Global reader census

D1A4: 906 CALL_THROUGH_POINTER sites. D198: allocator callback path.

## I. Callable-target validation

Both immediates are ordinary executable targets. D1A4 early-exit clean when `[0x0189DA84]==0`. D198 hits allocator.

## J. Stateful execution campaign

Sequences 12; clean 11; longest 5; coverage 22.

## K. New ordinary functions

['0x009E77D0', '0x009E83D0', '0x009E8460']

## L. New actual blockers

D198 → allocator/protected init. Meaningful D1A4 path needs factory publish of object pointer.

## M. Frontier delta

UNIQUE **56**; ENTERABLE **29**; SEQ_LEN **5**; SEQ_COV **22**; CLEAN_SEQ **11**; RUNS **137**.

## N. Phase-40 recommendation

Object method frontier and published-callback early-exit are proven. Meaningful work through 0x0189D1A4 still needs factory publication of 0x0189DA84 (allocator-blocked). Phase 40: EXPAND REAL UC EXECUTION on other ordinary object families / POD constructors without allocator dependence, or deepen same-vtable methods that only need constructor-produced fields. Graphics frozen.
