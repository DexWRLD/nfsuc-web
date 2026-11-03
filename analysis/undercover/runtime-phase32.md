# Undercover Phase 32 — Win32 synchronization runtime

Graphics frozen: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`.

## A. Phase 31 baseline

UNIQUE 34, ENTERABLE 19, DEEPEST 3, CLOSURE 7 (no-stub). Ctor stopped on InitializeCriticalSection. Phase-30 clean was RETURNED_CLEAN_WITH_STUBS.

## B. InitializeCriticalSection

- IAT `0x00B611F0`: KERNEL32!InitializeCriticalSection (hint 547)
- stdcall, **1** stack dword, VOID; confidence **PROVEN**
- Call sites: 10; HIGH callers: 9

## C. Guest CRITICAL_SECTION

0x18-byte x86 RTL_CRITICAL_SECTION in guest memory; side table for runtime state; no host pointers.

## D. Implementation

`UC_HLE_INITCRITSEC`. NULL/unmapped → fail. Re-init rewrites fields. Reset via `uc_sync_reset` each harness run.

## E. Four ICS consumer paths

0x009E9160, 0x00B52140, 0x009EBC70, 0x0097BB30

## F. CreateMutexA

- IAT `0x00B61140`; stdcall **3** args; HANDLE return; PROVEN
- Observed args: (NULL, FALSE, name|NULL) from `0x00977420`

## G. Named mutex / handles

Opaque guest handles `0xCD010001+`; named reuse; attrs must be NULL.

## H. Implementation decision

CreateMutexA **implemented** (reached + defensible handle model). Wait/Release **not** implemented.

## I. GetCurrentProcess

Legitimately reached after ICS on ctor path. Implemented as pseudo-handle `0xFFFFFFFF`. Next blocker: **GetPriorityClass**.

## J. No-stub campaign

- `0x009E9160` → **EXECUTED_TO_NEXT_BLOCKER** (d=3 u=11) GetPriorityClass
- `0x009E98F0` → **EXECUTED_CHAIN** (d=2 u=3) 
- `0x00B57CD0` → **EXECUTED_CHAIN** (d=2 u=2) 
- `0x00B52140` → **BLOCKED_REQUIRED_STATE** (d=4 u=6) access 0x00000000 unmapped guest access
- `0x009EBC70` → **EXECUTED_CHAIN** (d=3 u=5) 
- `0x009EB350` → **EXECUTED_CHAIN** (d=2 u=2) 
- `0x0097BB30` → **EXECUTED_TO_NEXT_BLOCKER** (d=4 u=7) CreateSemaphoreA
- `0x009D9310` → **UNKNOWN** (d=1 u=1) callee 0x004026F0 (REJECTED_DATA_LIKE); callee not ordinary-decodable
- `0x00808770` → **EXECUTED_CHAIN** (d=2 u=2) 
- `0x009EB870` → **BLOCKED_REQUIRED_STATE** (d=2 u=2) access 0x00000000 unmapped guest access
- `0x009EB980` → **EXECUTED_CHAIN** (d=2 u=2) 
- `0x00B57CF0` → **BLOCKED_REQUIRED_STATE** (d=4 u=6) access 0x00000000 unmapped guest access

## K. Constructor status

Not RETURNED_CLEAN. After ICS+GCP: stops on **GetPriorityClass**. Entered 11 frames (no stubs).

## L. New real blockers

- GetPriorityClass (ctor)
- CreateSemaphoreA (`0x0097BB30`, proven depth 4)
- CRT atexit null-deref on some static-init roots

## M. Frontier delta

UNIQUE **43**; ENTERABLE **20**; DEEPEST **4**; CLOSURE **11**; CLEAN **11**; CTORS **9**.

## N. Phase 33

InitializeCriticalSection, CreateMutexA, and GetCurrentProcess are implemented for the single-guest-thread model. Constructor 0x009E9160 now reaches GetPriorityClass (process affinity/priority family) after real sync+GCP. Independent root 0x0097BB30 reaches CreateSemaphoreA at proven depth 4. Phase 33: either EXPAND THREADING/TLS RUNTIME for GetPriorityClass / CreateSemaphoreA if those stay on ordinary paths, or EXPAND REAL UC EXECUTION on newly cleaned sync consumers. Do not open graphics/allocator. Enter/Leave/Delete remain unimplemented until legitimately required.
