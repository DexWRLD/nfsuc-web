# Undercover Phase 33 — process priority + semaphore creation

Graphics frozen: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`.

## A. Phase-32 baseline

UNIQUE 43, ENTERABLE 20, DEEPEST 4, CLOSURE 11, RUNTIME_READY 61.

## B. GetPriorityClass

- IAT `0x00B610E4` KERNEL32!GetPriorityClass; stdcall 1 dword → DWORD; **PROVEN**
- Sites 1; HIGH 1

## C. Pseudo-handle provenance

EDI = GetCurrentProcess() result (pseudo-handle 0xFFFFFFFF)

## D. Guest priority model

Initial **NORMAL_PRIORITY_CLASS (0x20)**; immutable until SetPriorityClass exists.

## E. Implementation

`UC_HLE_GETPRIORITYCLASS`. Invalid handle → EAX=0. Last-error not modeled.

## F. Constructor before/after

Before: stop on GetPriorityClass. After: **EXECUTED_TO_NEXT_BLOCKER** / **GetCurrentThread** (not clean).

## G. CreateSemaphoreA

- IAT `0x00B6112C`; stdcall 4 dwords → HANDLE; **PROVEN**

## H. Observed contract

{"lpSemaphoreAttributes": "NULL (0)", "lInitialCount": "0", "lMaximumCount": "0x3FFFFFFF", "lpName": "NULL"}

## I. Implementation

Typed guest handles (MUTEX vs SEMAPHORE). Count validation. Named reuse. No wait/release/scheduler.

## J. Semaphore path before/after

Before: CreateSemaphoreA @ depth 4. After: **EXECUTED_CHAIN** clean=True depth=4.

## K. CRT atexit NULL

**BLOCKED_CRT_INITIALIZATION** — CRT atexit/registration path requires initialized CRT lock/heap state and import helpers; PE-zero BSS / unbound CRT IATs are not a defensible ordinary init substitute. NULL callback is not invoked.

## L. Campaign

- `0x009E9160` → **EXECUTED_TO_NEXT_BLOCKER** (d=3 u=11) GetCurrentThread
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

## M. Next blockers

- Constructor: **GetCurrentThread**
- CRT static-init: BLOCKED_CRT_INITIALIZATION
- SetPriorityClass inventoried on same affinity block (not reached until GCT)

## N. Frontier delta

UNIQUE **44**; ENTERABLE **21**; DEEPEST **4**; CLOSURE **11**; CLEAN **12**; RUNTIME_READY **65**.

## O. Phase 34

GetPriorityClass and CreateSemaphoreA are implemented. Semaphore root 0x0097BB30 now RETURNS CLEAN at depth 4. Constructor advances to GetCurrentThread (pseudo-handle). Phase 34: implement GetCurrentThread (+ optionally SetPriorityClass/GetThreadPriority on the same 0x97F790 affinity block) under EXPAND THREADING/TLS RUNTIME, or harvest more ordinary roots under EXPAND REAL UC EXECUTION. CRT atexit remains BLOCKED_CRT_INITIALIZATION — do not fabricate registration tables. Graphics frozen.
