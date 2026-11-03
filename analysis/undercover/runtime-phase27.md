# Undercover Phase 27 — Ordinary initialization

Graphics frozen: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`.
D3D9 / engine backend: **NOT JUSTIFIED**. No new CRT/FS/timing/TLS implemented.

## A. Phase 26 BLOCKED_REQUIRED_STATE revisited

### `0x0096CED0`

Reads [esi+0xb28] count/flag early via object at ESI from stack arg; needs object+0x24/+0x30/+0xb28. Multi-callee READY island. No ordinary ctor recovered in Phase 27 bound search.

- enterability: `BLOCKED_UNKNOWN_STATE`

- required `esi/object` class=`THIS_POINTER` prov=`CALLER_ARGUMENT`
- required `+0xb28` class=`COUNT` prov=`UNKNOWN`
- required `+0x30` class=`OBJECT_FIELD` prov=`UNKNOWN`
- required `+0x24` class=`OBJECT_FIELD` prov=`UNKNOWN`

### `0x00B01EB0`

stdcall-like multi-arg; stack [ebp+8..+20]; this-relative fields before call 0x00AFF2E0. Large READY root; init unknown.

- enterability: `BLOCKED_UNKNOWN_STATE`

- required `stack+8` class=`STACK_ARGUMENT` prov=`CALLER_ARGUMENT`
- required `stack+0x14 struct` class=`BUFFER` prov=`UNKNOWN`

### `0x00A52DF0`

Pre-entry: stack float [ebp+8] then _CIsin. Post-import reads this+0x140/+0x150 SIMD mats. No E8 callers; likely vtable method. Ctor not found; zero matrices are not claimed valid.

- enterability: `BLOCKED_UNKNOWN_STATE`

- required `ecx/this` class=`THIS_POINTER` prov=`CALLER_ARGUMENT`
- required `stack float` class=`STACK_ARGUMENT` prov=`CALLER_ARGUMENT`
- required `+0x140/+0x150` class=`OBJECT_FIELD` prov=`UNKNOWN`

### `0x00949920`

Pre-entry: this + stack floats; first import _CIcos. Writes this+0xa4. Caller 0x00950190 exists. Primitive float args OK; object fields beyond write sink not required pre-entry.

- enterability: `ENTERABLE_DIRECT`

- required `ecx/this` class=`THIS_POINTER` prov=`CALLER_ARGUMENT`
- required `stack floats` class=`STACK_ARGUMENT` prov=`CALLER_ARGUMENT`

### `0x00A28720`

Pre-entry reads stack+8/+0xc and statics 0x00B71CF0 / 0x0129FC24 before _CIsqrt. Packed word-stream semantics UNKNOWN.

- enterability: `BLOCKED_UNKNOWN_STATE`

- required `stack+8 stream` class=`BUFFER` prov=`UNKNOWN`
- required `0x00B71CF0` class=`STATIC_DATA` prov=`STATIC_DATA`

## B. Pre-entry contracts

See `object-contracts.json` → `pre_entry` for bounded read sets
(stop at first ordinary call / import / indirect / return).

## C. Object contracts

### `vec3_normalize_pod` → `0x00924D30`

- enterability: `ENTERABLE_DIRECT` confidence=`PROVEN`
- constructor: `none`
- initializer: `none required pre-entry; method writes outputs`
- vtable: `none`
- allocation: `harness guest buffer OK (not ownership-sensitive)`

### `parent_of_vec3_at_7c` → `0x00929900`

- enterability: `ENTERABLE_DIRECT` confidence=`STRONG`
- constructor: `none`
- initializer: `zero buffer + primitive stack args (case edi=1)`
- vtable: `none on selected path`
- allocation: `harness guest buffer`

### `iface_holder_72eae0` → `0x0072EAE0`

- enterability: `BLOCKED_PROTECTED_INIT` confidence=`PROVEN`
- constructor: `0x007306C0 (PROTECTED jump)`
- initializer: `none`
- vtable: `PROTECTED_VTABLE / unknown iface`
- allocation: `blocked`

### `math_a52df0` → `0x00A52DF0`

- enterability: `BLOCKED_UNKNOWN_STATE` confidence=`WEAK`
- constructor: `none`
- initializer: `none`
- vtable: `UNKNOWN_VTABLE (no absolute E8 callers)`
- allocation: `unknown`

### `math_949920` → `0x00949920`

- enterability: `ENTERABLE_DIRECT` confidence=`STRONG`
- constructor: `none`
- initializer: `zero buffer sufficient for write sink`
- vtable: `none observed pre-entry`
- allocation: `harness guest buffer`

## D. Constructors

- No new PROVEN ordinary constructors for the five Phase-26 required-state roots.
- `0x007306C0` is a factory for `0x0072EAE0` objects but ends in `.securom` jmp — not ordinary.
- Math leaves (`0x00924D30`, `0x00949920`, parent `0x00929900`) use harness POD `this` (caller-provided storage); ctor not required on selected paths.

## E. Initializers

- Recovered as ENTERABLE_DIRECT (depth 0): `0x00924D30`, `0x00929900`, `0x00929972`, `0x00949920`.
- Zeroed guest buffer + primitive float/stack args establish pre-entry state (write-sink fields only).
- Large islands remain WITHOUT ordinary init: `0x0096CED0`, `0x00B01EB0`, `0x00A52DF0`, `0x00A28720`.

## F. Vtable provenance

- `0x0072EAE0`: iface at this+0x18 → PROTECTED_VTABLE / PROTECTED_INITIALIZED_CALLBACK via slot `0x023AF9C8` (.securom).
- `0x00A52DF0`: no absolute E8 callers → likely virtual; UNKNOWN_VTABLE; not invented.
- Math POD roots: no vtable on selected paths.

## G. Initialization graphs

Documented in `initialization-frontier.json`.
Counts: recovered=4 external=0 protected=1 unknown=4.

## H. `0x0072EAE0`

Reads this+0x18 as interface pointer; call [ [*+0x18] + 0x18 ]. Caller 0x00731320 obtains object via 0x007306C0 which does jmp dword ptr [0x023AF9C8] located in .securom.

- indirect call: `[ [*this+0x18] + 0x18 ]`
- writer/factory: `0x007306C0` → `jmp dword ptr [0x023AF9C8]`
- slot section: `.securom`
- classification: **PROTECTED_INITIALIZED_CALLBACK**
- enterable: **NO** (diagnostic only; not forced)

## I. Import-ready root ranking

Top scored IMPORT_READY (depth/island weight; non-graphics preferred):

- `0x0099FE50` score=729 callees=65 insns=794 imports=—
- `0x009B97E0` score=715 callees=60 insns=1156 imports=—
- `0x009BE240` score=642 callees=56 insns=824 imports=—
- `0x0075A840` score=628 callees=55 insns=780 imports=—
- `0x00AD6900` score=614 callees=41 insns=2043 imports=—
- `0x009CD390` score=535 callees=48 insns=550 imports=—
- `0x007E9080` score=521 callees=32 insns=2016 imports=memset
- `0x00A4BC30` score=489 callees=29 insns=1996 imports=—
- `0x00ABD490` score=484 callees=19 insns=2948 imports=—
- `0x009D2470` score=483 callees=43 insns=539 imports=—
- `0x00AC9770` score=482 callees=32 insns=1621 imports=—
- `0x009A39A0` score=431 callees=37 insns=612 imports=—

## J. Execution campaign

Attempted Phase-27 roots (≤12, high-confidence / diagnostic):
`0x00929972`, `0x00949920`, `0x0072EAE0`, plus remaining P26 required-state.

Outcomes: `{'EXECUTED_CHAIN': 1, 'EXECUTED_CLEAN': 1, 'BLOCKED_PROTECTED': 1, 'BLOCKED_REQUIRED_STATE': 4}`.

## K. Successful initialization→execution chains

1. **POD parent case body** `0x00929972` → `0x00924D30` (+ `_CIsqrt`): EXECUTED_CHAIN, depth **2**, closure **2**.
2. **Math leaf** `0x00949920` (+ `_CIcos`/`_CIsin`/`_CIsqrt`): EXECUTED_CLEAN, depth 1.
No fabricated object fields; harness allocated mapped guest buffers only.

## L. Real blockers

Most common immediate: **BLOCKED_REQUIRED_STATE**.
Protected diagnostic: `0x0072EAE0`. No FS/timing/TLS/import CRT beyond existing HLE in successful runs.

## M. Frontier delta

- ENTERABLE: 3 → **6**
- UNIQUE_UC_FUNCTIONS_EXECUTED: 6 → **8**
- DEEPEST_ORDINARY_EXECUTION_CHAIN: 1 → **2**
- LARGEST_EXECUTED_ORDINARY_CLOSURE: 1 → **2**
- ORDINARY_INIT_RECOVERED: **4**
- INIT_BLOCKED_PROTECTED: **1**; INIT_BLOCKED_UNKNOWN: **4**

## N. Phase 28

Most common remaining blocker is still BLOCKED_REQUIRED_STATE / UNKNOWN object provenance for large islands. Next: recover ordinary ctors for matrix/math objects (0x00A52DF0 family) or expand the 0x00929900-style POD parent chains. Do not implement CRT/FS/timing until an ENTERABLE chain reaches them. 0x0072EAE0 stays protected.
