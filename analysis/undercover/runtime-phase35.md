# Undercover Phase 35 — deterministic guest performance clock

Graphics frozen: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`.
D3D9 / ENGINE BACKEND: **NOT JUSTIFIED**.

## A. Phase-34 baseline

UNIQUE 44, ENTERABLE 21, DEEPEST 4, CLOSURE 11, RUNTIME_READY 69, RUNS 59. Constructor stopped on QueryPerformanceCounter.

## B. QPC identity and ABI

- IAT `0x00B611F8` KERNEL32!QueryPerformanceCounter hint 675; unbound `0x008A9E84`
- stdcall, 1 stack dword, BOOL in EAX + 64-bit LE store; **PROVEN**
- HIGH callers include `0x0097F790`

## C. Real output-buffer provenance

lea eax, [esp+0x30]; stack LARGE_INTEGER (STACK). Call site `0x0097F7F8`.

## D. Clock design and frequency

Virtual frequency **10000000** ticks/s. Initial counter **0**. Not host uptime. Not host QPC.

## E. Deterministic advancement policy

`uc_guest_clock_advance_ns(delta)` only. Equal QPC at equal virtual time. Virtual TSC = qpc_ticks × 300 (3 GHz coherent).

## F. QPC implementation/tests

`UC_HLE_QUERYPERFORMANCECOUNTER`. Full 8-byte guest write via checked stores. Invalid buffer → HLE reject. Tests: `uc_phase35_test.py`.

## G. QPF identity and actual reach

- IAT `0x00B611FC`; stdcall 1 dword; **PROVEN**
- Legitimately reached on ctor path after QPC calibration retries (observed qpf_calls=1).

## H. QPF implementation/tests

`UC_HLE_QUERYPERFORMANCEFREQUENCY` writes stable `10000000`. Same timebase as QPC.

## I. Timing consistency

Unit tests cover advance_ns → ΔQPC / QPF == elapsed seconds (integer). Low-word rollover and reset covered.

## J. Constructor before/after

Before: stop on QPC. After: **EXECUTED_TO_NEXT_BLOCKER** / **SleepEx** (clean=False). Observed qpc_calls=6 qpf_calls=1.

## K. SleepEx and wait semantics

Reached with args **(0x32, alertable=1)**. Not implemented. **BLOCKED_ALERTABLE_WAIT** — no APC delivery / no scheduler.

## L. No-stub campaign

- `0x009E9160` → **EXECUTED_TO_NEXT_BLOCKER** (d=3 u=11) SleepEx
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

## M. Next genuine blocker

- Constructor: **SleepEx** (`BLOCKED_ALERTABLE_WAIT`)
- CRT static-init: BLOCKED_CRT_INITIALIZATION

## N. Frontier delta

UNIQUE **44**; ENTERABLE **21**; DEEPEST **4**; CLOSURE **11**; CLEAN **12**; RUNTIME_READY **71**; RUNS **71**.

## O. Phase-36 recommendation

QPC/QPF guest clock is live; constructor advances to alertable SleepEx(50ms, TRUE). Phase 36: either EXPAND THREADING/TLS RUNTIME for a narrowly justified non-alertable sleep/virtual-wait policy (without APC/scheduler fiction), or EXPAND REAL UC EXECUTION on other ordinary roots while leaving alertable waits classified. CRT atexit remains BLOCKED_CRT_INITIALIZATION. Graphics frozen.
