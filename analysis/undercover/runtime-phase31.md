# Undercover Phase 31 — Expand ordinary initialization

Graphics frozen: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`. D3D9 NOT JUSTIFIED. ENGINE BACKEND NOT JUSTIFIED.

## A. Baseline (honest)

- Prior UNIQUE inflated by 4 stub-only visits; real P30 baseline **17**.
- Phase 30 ctor `RETURNED_CLEAN` reclassified → **RETURNED_CLEAN_WITH_STUBS**.
- Live no-stub ctor stops on **InitializeCriticalSection** (depth 3, 7 entered).

## B. Allocator provenance `[0x0189DA88]`

- Section: `.data` BSS tail; PE initial **0**.
- Single absolute writer: setter `0x009E9410` ← `0x008101B0`.
- Value source: **PROTECTED_BOUNDARY_CALL** `0x00686000` (then ordinary base ctor `0x009E7710` + vtable `0x00BBB460`).
- Classification: **PROTECTED_INITIALIZED_ALLOCATOR**
- ALLOCATOR_TARGET_RESOLVED: **NO** (vtable+8 → `0x004A9FF0` undecodable)
- ALLOCATOR_INIT_PATH_ORDINARY: **NO**
- `0x009E9340` ENTERABLE: **NO**. Implementation attempted: **NO**. Track A **stopped**.

## C. Wrapper `0x009E9460`

if [0x189DA88]==0 return 0, else this=[0x189DA88]; call vtable[+0x1C](id) and return its EAX. A manager-object method dispatcher: NOT malloc; no size/header/alignment semantics.

## D. Wrapper `0x009EB870`

(size, type_name_ptr, heap_id, _unused): heap = 0x9E9460(heap_id); return heap->vtable[+8](this=heap, size, type_name, heap_id). Dereferences heap without a NULL check; return = guest pointer or 0.

## E. Classification decision

Exactly one class applied: **PROTECTED_INITIALIZED_ALLOCATOR**. Not invoked, not emulated, not malloc-substituted.

## F. `0x009E9160` caller inventory

- E8 sites: **1**; data pointers: **0**
- Sole caller `0x009E9340`; this-source **ALLOCATOR_RESULT**.
- by_this_source: {"STACK_STORAGE": 0, "EMBEDDED_SUBOBJECT": 0, "CALLER_ARGUMENT": 0, "GLOBAL_STORAGE": 0, "ALLOCATOR_RESULT": 1, "UNKNOWN": 0}

## G. Non-allocating ctor parents

**None.** No STACK_STORAGE / EMBEDDED_SUBOBJECT / CALLER_ARGUMENT / GLOBAL_STORAGE caller.

## H. Reverse execution frontier

- Seeds: 34 executed HIGH functions (incl. POD `0x929972→0x924D30`, seed `0x949920`).
- Level-1/2 callers scored with PROVEN_DEPTH weighting; allocator parent deprioritized.

## I. Depth-4 / Depth-5

- ENTERABLE_WITH_DEPTH_4_POTENTIAL: **0** []
- ENTERABLE_WITH_DEPTH_5_POTENTIAL: **0** []
- Strict rule rejects candidates with pending imports (CS/mutex) even when static frames ≥4.

## J. Campaign (12 HIGH roots)

- `0x009E9160` ORDINARY_CONSTRUCTOR → **EXECUTED_TO_NEXT_BLOCKER** (d=3, u=7) InitializeCriticalSection
- `0x009E98F0` ORDINARY_CONSTRUCTOR → **EXECUTED_CHAIN** (d=2, u=3) 
- `0x00B57CD0` STATIC_INITIALIZER → **EXECUTED_CHAIN** (d=2, u=2) 
- `0x00B52140` STATIC_INITIALIZER → **EXECUTED_TO_NEXT_BLOCKER** (d=3, u=3) InitializeCriticalSection
- `0x009EBC70` ORDINARY_CONSTRUCTOR → **EXECUTED_TO_NEXT_BLOCKER** (d=3, u=5) InitializeCriticalSection
- `0x009EB350` ORDINARY_CONSTRUCTOR → **EXECUTED_CHAIN** (d=2, u=2) 
- `0x0097BB30` ORDINARY_CONSTRUCTOR → **EXECUTED_TO_NEXT_BLOCKER** (d=3, u=3) InitializeCriticalSection
- `0x009D9310` ORDINARY_CONSTRUCTOR → **UNKNOWN** (d=1, u=1) callee 0x004026F0 (REJECTED_DATA_LIKE); callee not ordinary-decodable
- `0x00808770` ORDINARY_CONSTRUCTOR → **EXECUTED_CHAIN** (d=2, u=2) 
- `0x009EB870` ALLOCATOR_NEGATIVE_CONTROL → **BLOCKED_REQUIRED_STATE** (d=2, u=2) access 0x00000000 unmapped guest access
- `0x009EB980` STATIC_INITIALIZER → **EXECUTED_CHAIN** (d=2, u=2) 
- `0x00B57CF0` STATIC_INITIALIZER → **EXECUTED_TO_NEXT_BLOCKER** (d=3, u=3) CreateMutexA

## K. Actual blockers

- Histogram: {"REQUIRED_STATE": 2, "IMPORT": 5, "INDIRECT": 0, "MEMORY": 0, "TLS": 0, "FILESYSTEM": 0, "TIMING": 0, "EXTERNAL": 0, "PROTECTED": 0, "CLEAN_RETURN": 5}
- REQUIRED_STATE subclasses: {"UNKNOWN_OBJECT": 0, "UNKNOWN_PARENT": 0, "UNKNOWN_GLOBAL": 0, "UNKNOWN_BUFFER": 0, "UNKNOWN_CALLBACK": 0, "UNKNOWN_VTABLE": 0, "ALLOCATOR_REQUIRED": 1, "OTHER": 1}
- Most common real blocker: **InitializeCriticalSection** ×4
- Diagnostic (uncounted) CS no-op → next **GetCurrentProcess**

## L. Clean roots / constructors

- CLEAN_ORDINARY_ROOTS: **10** ['0x00721070', '0x00808770', '0x0088390D', '0x00924D30', '0x00929972', '0x00949920', '0x009E98F0', '0x009EB350', '0x009EB980', '0x00B57CD0']
- EXECUTED_ORDINARY_CONSTRUCTORS: **9** ['0x00808770', '0x0097BB30', '0x009D9310', '0x009E0880', '0x009E7710', '0x009E9160', '0x009E98F0', '0x009EB350', '0x009EBC70']

## M. Frontier delta

- UNIQUE: **34** (honest; stubs excluded unless body entered)
- ENTERABLE: **19**
- EXECUTION_RUNS: **23**
- DEEPEST: **3**; LARGEST_CLOSURE: **7** (no-stub)
- DEPTH_4/5 potential: **0 / 0**

## N. Phase 32 recommendation

Allocator at [0x0189DA88] is PROTECTED_INITIALIZED_ALLOCATOR (value from 0x00686000); Track A stopped — do not implement/emulate. 0x009E9160 has no non-allocating callers. Live no-stub campaign: deepest remains 3; most common real blocker is KERNEL32!InitializeCriticalSection (and CreateMutexA) via 0x00977420 across independent ctor/static-init chains. Diagnostic (uncounted) CS no-op next hits GetCurrentProcess. Phase 32: EXPAND THREADING/TLS RUNTIME for sync primitives reached on ordinary paths. Do not reopen graphics/A52DF0. TlsGetValue still NOT REACHED.
