# Undercover Phase 34 — guest thread identity + priority continuation

Graphics frozen: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`.
D3D9 / ENGINE BACKEND: **NOT JUSTIFIED**.

## A. Phase-33 baseline

UNIQUE 44, ENTERABLE 21, DEEPEST 4, CLOSURE 11, RUNTIME_READY 65, RUNS 47, CLEAN 12, CTORS 9. Constructor stopped on GetCurrentThread. Semaphore root 0x0097BB30 clean at depth 4.

## B. GetCurrentThread import identity

- IAT `0x00B611DC` KERNEL32!GetCurrentThread hint 325; thunk/unbound `0x008A9F2E`
- stdcall, 0 stack dwords, HANDLE in EAX; **PROVEN**
- call sites 7; HIGH callers 7: 0x0087C5DD, 0x0087C672, 0x0087C714, 0x0087C781, 0x00977300, 0x0097F790, 0x00A07A7A
- real reached caller: `0x0097F790`

## C. Pseudo-handle model

`GetCurrentThread` → **0xFFFFFFFE**. Distinct from process `GetCurrentProcess` → **0xFFFFFFFF**. Not a thread ID. Not a host HANDLE.

## D. Guest thread context

One active guest-thread context: identity via pseudo-handle, dynamic TLS (existing), relative thread priority, sync ownership identity. Lifetime: guest process. Scheduler: **NONE**.

## E. Implementation and tests

`UC_HLE_GETCURRENTTHREAD` / `GETTHREADPRIORITY` / `SETPRIORITYCLASS` / `SETTHREADPRIORITY`. Guest-only mutable priority state. Host scheduling unchanged even for REALTIME / TIME_CRITICAL. Tests: `uc_phase34_test.py`.

## F. Constructor continuation

Before: stop on GetCurrentThread. After: **EXECUTED_TO_NEXT_BLOCKER** / **QueryPerformanceCounter** (clean=False). Observed mid-path: process class 0x100, thread priority 15.

## G. SetPriorityClass provenance

IAT `0x00B610E8`; reached YES with handle=process pseudo, class=**0x100 REALTIME_PRIORITY_CLASS** (not HIGH=0x80). Implemented YES; guest mutable YES.

## H. GetThreadPriority / SetThreadPriority

Both imported, reached on ctor path, implemented. Default NORMAL(0). Invalid handle → THREAD_PRIORITY_ERROR_RETURN. STP observed arg 0xF = TIME_CRITICAL.

## I. Affinity status

Not reached on the ordinary constructor path. Not implemented. No coherent guest processor topology — future dependency.

## J. Timing reach

QueryPerformanceCounter **reached** (next blocker). QPF / SleepEx(0x32) present statically after QPC on the same block. Timing **not** implemented.

## K. No-stub campaign

- `0x009E9160` → **EXECUTED_TO_NEXT_BLOCKER** (d=3 u=11) QueryPerformanceCounter
- `0x009E98F0` → **EXECUTED_CHAIN** (d=2 u=3) 
- `0x00B57CD0` → **EXECUTED_CHAIN** (d=2 u=2) 
- `0x00B52140` → **BLOCKED_REQUIRED_STATE** (d=4 u=6) access 0x00000000 unmapped guest access
- `0x009EBC70` → **EXECUTED_CHAIN** (d=3 u=5) 
- `0x009EB350` → **EXECUTED_CHAIN** (d=2 u=2) 
- `0x0097BB30` → **EXECUTED_CHAIN** (d=4 u=8) 
- `0x009D9310` → **UNKNOWN** (d=1 u=1) callee 0x004026F0 (REJECTED_DATA_LIKE); callee not ordinary-decodable
- `0x00808770` → **EXECUTED_CHAIN** (d=2 u=2) 
- `0x009EB870` → **BLOCKED_REQUIRED_STATE** (d=2 u=2) access 0x00000000 unmapped guest access
- `0x009EB980` → **EXECUTED_CHAIN** (d=2 u=2) 
- `0x00B57CF0` → **BLOCKED_REQUIRED_STATE** (d=4 u=6) access 0x00000000 unmapped guest access

## L. Next real blockers

- Constructor: **QueryPerformanceCounter** (BLOCKED_TIMING)
- CRT static-init: BLOCKED_CRT_INITIALIZATION
- Affinity: not reached

## M. Frontier delta

UNIQUE **44**; ENTERABLE **21**; DEEPEST **4**; CLOSURE **11**; CLEAN **12**; RUNTIME_READY **69**; RUNS **59**.

## N. Phase-35 recommendation

GetCurrentThread, GetThreadPriority, SetPriorityClass, and SetThreadPriority are implemented with guest-only state (no host scheduling changes). Constructor 0x009E9160 advances past the priority block and stops on QueryPerformanceCounter. Phase 35: EXPAND TIMING RUNTIME — coherent deterministic guest QPC/QPF (+ SleepEx policy) without wall-clock substitution. Affinity remains a future dependency (no guest processor topology). CRT atexit stays BLOCKED_CRT_INITIALIZATION. Graphics frozen. No scheduler.
