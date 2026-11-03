# Undercover Phase 40 — independent object family + vtable dispatch

Graphics frozen: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`.

## A. Baseline

Phase 39: UNIQUE 56, ENTERABLE 29, SEQ_LEN 5, SEQ_COV 22, CLEAN_SEQ 11, RUNS 137.

## B. Second-family search method

Bounded census of IMPORT_READY / proven constructors / POD builders / caller-storage initializers; scored for ordinary evidence, small extent, static vtable, low deps; penalized allocator/protected/destructor.

## C. Ranked constructor candidates

Top: `0x009E98F0` (POD), `0x009E9160` (regression), `0x009E9990` (copy), `0x0097BB30`, `0x009E0880`, `0x009E7710`, `0x009EB350`, `0x009EBC70`, … See `object-family-frontier.json`.

## D. Object contracts

Family B: CALLER_STORAGE extent `0x54`; vtable `0x00C30F2C` at +0; nested `0x009E7710` + `0x009E0880`; ABI thiscall ret 0.

## E. Constructor executions

`0x009E98F0` EXECUTED_CLEAN; installs POD vtable; fields +0x2C/+0x30=0x10, +0x34=1; returns this.

## F. Consumer discovery

`0x009E9980` pure RTTI getter (vt slot 2) → `0x00C30F38`. `0x009E9990` copy-initializer ret 4.

## G. Independent lifecycle results

Clean: `0x009E98F0` → `0x009E9980` (EAX=`0x00C30F38`). Also `ctor → copy → rtti` on distinct buffers.

## H. Vtable call candidates

Sampled ordinary `call [reg+disp]` sites; none previously enterable with full object contract. Probe `0x0090749E` skips when `[obj+0x14]!=0x54`.

## I. Real virtual dispatch evidence

EXECUTED_VTABLE_DISPATCH

0x009E8E00 performs call [vt+0x14]; with arg==constructed Family-A object, slot5 resolves to 0x009E8E00 and sparse DISPATCH_CALL entered it. Continuation hits allocator 0x009E9460 (not counted as clean lifecycle).

Harness: sparse UC registration for DISPATCH_CALL beyond NFSU2 g_dtab size.

## J. Execution campaign

Sequences 9; clean 8; independent families executed 2; clean independent lifecycles 2; REAL_VTABLE_DISPATCHES 1.

## K. New ordinary bodies

(coverage within prior unique set)

## L. Genuine blockers

Allocator/factory (`0x0189DA84` / `0x009E9460`) unchanged. Virtual callers need object field contracts not produced by current ctors without fabrication.

## M. Frontier delta

UNIQUE **61**; ENTERABLE **29**; FAMILIES **2**; CLEAN_LIFECYCLES **2**; VTABLE_DISPATCH **1**; RUNS **179**.

## N. Phase 41 recommendation

Independent POD family 0x009E98F0→0x009E9980 is clean. Real vtable dispatch: EXECUTED_VTABLE_DISPATCH. Phase 41: EXPAND REAL UC EXECUTION on additional independent families with non-trivial stateful consumers, or find an enterable virtual caller whose object contract is fully constructor-produced without allocator dependence. Graphics frozen.
