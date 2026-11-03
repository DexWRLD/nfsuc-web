# Undercover Phase 36 — deterministic SleepEx timeout

Graphics frozen: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`.
D3D9 / ENGINE BACKEND: **NOT JUSTIFIED**.

## A. Phase-35 baseline

UNIQUE 44, ENTERABLE 21, DEEPEST 4, CLOSURE 11, RUNTIME_READY 71, RUNS 71. Constructor stopped on alertable SleepEx(50, TRUE).

## B. SleepEx identity and ABI

- IAT `0x00B61188` KERNEL32!SleepEx hint 855
- stdcall, 2 stack dwords → DWORD; **PROVEN**
- sites 6; HIGH 6

## C. Real constructor call contract

`SleepEx(0x32, TRUE)` at `0x0097F8D6` in `0x0097F790`. Return **ignored**.

## D. APC/completion provenance

{
  "imported": {
    "CreateWaitableTimerA": "0x00B61194",
    "SetWaitableTimer": "0x00B6119C"
  },
  "in_ctor_closure": {},
  "QueueUserAPC": "NOT_IMPORTED",
  "ReadFileEx": "NOT_IMPORTED",
  "WriteFileEx": "NOT_IMPORTED",
  "SetWaitableTimer_on_ctor_path": false,
  "CreateWaitableTimerA_on_ctor_path": false,
  "pending_apc_classification": "PROVEN_NO_PENDING_APC_IN_SUPPORTED_MODEL",
  "note": "SetWaitableTimer/CreateWaitableTimerA are imported but not called on the ordinary constructor closure path that reaches SleepEx. No APC queue exists in the guest runtime. Guest APC pending flag defaults false."
}

## E. Timeout-only eligibility

**YES** — PROVEN_NO_PENDING_APC_IN_SUPPORTED_MODEL on the ctor path; finite timeout; coherent guest clock; return 0 = timeout.

## F. Guest wait representation

last-wait descriptor: ms, alertable, start_ticks, deadline_ticks; completion counter; pending-APC flag

## G. Virtual-time advancement

50 ms → 50,000,000 ns → 500,000 QPC ticks. Synchronous HLE advances the Phase-35 clock to the deadline. Not host sleep. Not a scheduler.

## H. Tests

`uc_phase36_test.py` — ABI, finite alertable/non-alertable, repeated, zero, infinite reject, pending-APC guard, QPC integration.

## I. Constructor before/after

Before: BLOCKED_ALERTABLE_WAIT. After: **EXECUTED_TO_NEXT_BLOCKER** / **switch/jump-table or unresolved ordinary target 0x0097FA08** (clean=False). SleepEx completions=5; virtual ticks=2500000 (~25 ms).

## J. Subsequent ordinary execution

New bodies: 0x0087B4F6, 0x0097FAE0, 0x0087B880, 0x0097F9E0. Depth **4**, closure **15**.

## K. Next real blockers

- Constructor: **BLOCKED_INDIRECT** (MSVC jump table in `0x0097F9E0`)
- CRT: BLOCKED_CRT_INITIALIZATION

## L. Frontier delta

UNIQUE **48**; ENTERABLE **21**; DEEPEST **4**; CLOSURE **15**; CLEAN **12**; RUNTIME_READY **72**; RUNS **83**.

## M. Phase-37 recommendation

SleepEx timeout-only HLE cleared the alertable finite wait. Constructor now stops on an unresolved ordinary jump-table / switch dispatch inside 0x0097F9E0 (BLOCKED_INDIRECT). Phase 37: EXPAND INDIRECT DISPATCH — enable/verify JTSWITCH recognition for this MSVC switch so ordinary case handlers execute without DISPATCH_TAIL. Do not invent APC delivery. Graphics frozen.
