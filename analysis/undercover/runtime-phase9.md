# Phase 9 — x87 CRT math for `0x00A124B0`

The game executable was not started. Protected sections stayed unmapped. The call-site contract is in `analysis/undercover/x87-ci-abi.md`. This note records the runtime that implements that contract and the executions that checked it.

## A. Actual `_CI*` call-site ABI

All four calls in the closure use the same contract. It was read from the instructions, not from the import names.

| | |
| --- | --- |
| Argument | already in ST(0) |
| Result | replaces ST(0) |
| Extra live x87 value | none |
| Depth change | none |
| Integer arguments | none |
| ESP | cdecl with zero stack dwords: the dispatcher pops only the return address |
| EAX | not an argument and not the result |

`_CIsin` is called at `0x00A11C6D` and `_CIcos` at `0x00A11C9B`, both in `0x00A11C50`. Each is preceded by `fld dword` of the same spilled angle and followed by `fstp dword`. The angle was multiplied by the `.rdata` qword at `0x00B71CF0`, which is `0.5`.

`_CIacos` is called at `0x00A11B2B` in `0x00A11AF0` and at `0x00A11C25` in `0x00A11BD0`. Both calls are on the `|value| < 1` side of an `fcompi` / `jb`. The other side does not call the import. For a positive out-of-range value, `0x00A11AF0` returns `0`. For a negative out-of-range value it returns the float at `0x00B6DCF0`, which is `3.141592741`.

## B. Existing x87 representation

`runtime/cpu.h` already had what this closure needs for ordinary x87 traffic:

- ST(0) through ST(7) are `double st[8]`, indexed by `top`. There is no tag word.
- `FPUSH` decrements `top` and stores. `FPOP` increments `top` and leaves the slot.
- `fcw` is a stored control word. The rounding helpers read bits 10–11. The lifter's `fstp dword` is a C float cast, not a full x87 store.
- `fsw` holds the compare condition codes. `fsw_get` overlays TOP into bits 11–13. The HLE does not set exception flags.
- Loads, stores, `fabs`, `fadd`, `fmul`, `fcompi`, and `fld1` were already lowered. This phase did not change `tools/lift.py`.

The model is 64-bit `double`, not 80-bit extended precision. That limitation was already documented on the CPU struct.

## C. Changes required

The integer helpers were already enough for Phase 8. This closure needed three additions:

- A descriptor field that says the result lives in ST(0), so a successful import does not write EAX.
- HLE bodies that read ST(0), call a host double function, and write ST(0) without moving TOP.
- A fault record for an x87 state the runtime refuses to invent: guest function when the harness supplies it, EIP, TOP, ST(0), ST(1), FCW, and FSW.

An unbound host function fails before the write. ESP is restored to the thunk entry, EAX and ST(0) stay as they were, and the fault record is filled. A call is not keyed by the thunk address. The descriptor's HLE id and location fields select the operation.

The freestanding link has no libm. The harness binds `sin`, `cos`, `acos`, `fabs`, and `sqrtf` from `ucrtbase.dll`. Those pointers are the mathematical operation. They are not an MSVCR80 emulator.

## D. Import metadata

`UcImport` gained `arg_loc` and `ret_loc`.

| symbol | convention | stack dwords | argument | result | HLE |
| --- | --- | --- | --- | --- | --- |
| `_CIsin` | cdecl | 0 | ST(0) | ST(0) | `UC_HLE_CISIN` |
| `_CIcos` | cdecl | 0 | ST(0) | ST(0) | `UC_HLE_CICOS` |
| `_CIacos` | cdecl | 0 | ST(0) | ST(0) | `UC_HLE_CIACOS` |

Every previous row stays `UC_LOC_STACK` / `UC_LOC_EAX` with its old stack count. `_CIasin` is still unrecorded and fails closed. `tools/uc_abi_table.py` regenerates `runtime/uc_import_table.inc`.

## E. `_CIsin` tests

Direct calls, with `1.25` live in ST(1), compared as exact host-double bits:

| input | ST(0) |
| --- | --- |
| `0` | `0` |
| `0.5` | `0.479425538604203` |
| `-0.3` | `-0.29552020666133955` |
| `1.5707963267948966` | `1` |
| `10` | `-0.5440211108893698` |

TOP was unchanged. ST(1) stayed `1.25`. ESP returned to the value before the call. EAX, EBX, ECX, EDX, ESI, EDI, and EBP were unchanged. A following `FPOP` exposed the saved `1.25`.

## F. `_CIcos` tests

Same stack and register checks.

| input | ST(0) |
| --- | --- |
| `0` | `1` |
| `0.5` | `0.8775825618903728` |
| `-0.3` | `0.955336489125606` |
| `1` | `0.5403023058681398` |

## G. `_CIacos` tests

| input | ST(0) |
| --- | --- |
| `-1` | `3.141592653589793` |
| `-0.5` | `2.0943951023931957` |
| `0` | `1.5707963267948966` |
| `0.5` | `1.0471975511965979` |
| `1` | `0` |

`acos(2)` stores a NaN in the same slot. TOP is unchanged, EAX is unchanged, and `fsw` gains no exception bits. The runtime does not model the x87 invalid-operation exception. The Undercover callers do not rely on one: `|x| >= 1` branches away before the import. `0x00A11AF0` with `2.0` made no import call and returned `0`. With `-1.0` it made no import call and returned the float `3.141592741`.

## H. Smallest real callers

`0x00A11AF0` is the smallest `_CIacos` caller. Entry ESP `0x0300F000`, argument `0.5`. The import saw ST(0) `0.5` at TOP 7. After the import TOP was still 7 and ESP had moved by the popped return address only. The function then stored the float `1.0471975803375244`, which is `(float)acos(0.5)`, both in ST(0) and in the caller's stack slot. Final EIP `0x00DEC0DE`, final ESP `0x0300EFFC`, EAX unchanged. `push ecx` in this function is a spill slot: `fstp dword [esp]` overwrites it, so ECX returns as the bits of `0.5`, not as the entry value.

`0x00A11C50` is the smallest caller of both `_CIsin` and `_CIcos`. Angle `1.0` is scaled by `0.5`. The sine import received `0.5` and returned `0.479425538604203`. The cosine import received the same `0.5` and returned `0.8775825618903728`. TOP stayed 7 across both. The stored lanes were `0.4794255495071411`, `0.9588510990142822`, `1.4382766485214233`, and `0.8775825500488281`. The last lane is the cosine; the first three are the input vector times the sine. Final ESP `0x0300F000`, EIP `0x00DEC0DE`. EBX, ECX, ESI, and EBP were preserved. EAX became the vector pointer the function loaded. A second angle of `0` stored `0, 0, 0, 1`.

## I. `0x00A124B0` closure

Inputs were the 16-byte values `(0, 0, 0, 1)` and `(0.6, 0.3, 0.1, 0.7)`, plus a scratch vector and an output float. Entry ESP `0x0300F000`.

Functions reached, in first-entry order:

1. `0x00A124B0`
2. `0x00A12280`
3. `0x00A11AF0`
4. `0x00A11C50`
5. `0x00A11B40`
6. `0x00A11BD0`

Maximum call depth was 3. Termination was the function's own `ret 0xc`: EIP `0x00DEC0DE`, ESP `0x0300F000`, TOP `0`. EBX, ESI, EDI, and EBP were restored.

`_CI*` calls:

| import | ST(0) in | ST(0) out |
| --- | --- | --- |
| `_CIacos` | `0.46000000834465027` | `1.0928011188779574` |
| `_CIsin` | `0.5464005470275879` | `0.5196152276515444` |
| `_CIcos` | `0.5464005470275879` | `0.8544003834225694` |
| `_CIacos` | NaN | NaN |

The cosine is visible in the scratch vector written by `0x00A11C50`: lanes `NaN, NaN, NaN, 0.8544003963470459`. The last lane is the host cosine stored by the lifted `fstp`. The first three lanes were already NaN in the SSE value that sine scaled. The second `_CIacos` therefore received a NaN from `0x00A11BD0` and returned a NaN. The stored output float is that NaN. No exception flag was invented.

Checked guest traffic included reads of `.rdata` `0x00C34428`, `0x00BDDBE0`, `0x00B6DCF0`, and `0x00B71CF0`, and writes to the harness stack. No protected section was touched.

## J. Repeatability

The same inputs were run again. The function count, maximum depth, import order, ST(0) bit patterns, output bits, register mix, and termination matched. The NaN bits matched as well.

## K. Second input

The second pair was `(1, 0, 0, 0)` and `(1, 0, 0, 1)`. The import log changed from four calls to one: `_CIacos(0) = 1.5707963267948966`. Sine and cosine were not called. The stored float was `3.1415927410125732`. ESP, EIP, and the callee-saved registers still returned cleanly.

## L. Numerical compatibility

Three different claims:

- ABI correctness: established for these call sites. ST(0) in, ST(0) out, TOP unchanged, EAX untouched, cdecl with no stack arguments.
- Numerical compatibility: the value written to ST(0) is the `ucrtbase` double of the same input. Caller `fstp dword` results match the C float cast of that double on the tested inputs.
- Bit-exact CRT compatibility: not claimed. Host `sin`, `cos`, and `acos` are not MSVCR80, and the register file is not 80-bit.

Direct comparisons in the harness are exact against the bound host functions. That checks the handoff. It is not a claim that every input matches the original game runtime.

## M. x87 state limitations

- No tag word. An empty register cannot be distinguished from a stored value. These call sites always have a value in ST(0).
- No x87 exception flags. Out-of-range `acos` becomes a NaN in ST(0) and does not raise a modeled invalid operation.
- `double` is not 80-bit extended precision.
- The lifter's `fstp m32` is a C float cast. The HLE does not pre-round.
- A ninth push still wraps TOP. This closure does not do that.

## N. Runtime failures discovered

- Calling `_CIsin` with no host function bound fails closed. The probed case kept ST(0) at `0.25`, kept EAX, restored ESP to the thunk entry, and reported TOP 7, FCW `0x037F`, and FSW `0x3800` (TOP in bits 11–13). That failure is the intended policy.
- The six-function path stores NaN in three lanes of the vector `0x00A11C50` scales, so the closure's final float is NaN for the inputs that reach all six functions. The cosine lane and the first three import results are finite. The NaN is produced by the surrounding SSE sequence, including `rsqrtss` lowered as `1/sqrt`, and is deterministic. It was not patched away.
- `uc_import.c` now references `_fltused`. The Phase 6 and Phase 8 harnesses define it, as Phase 7 already did. After that, Phase 6, Phase 7, and Phase 8 passed, as did `tools/uc_isa_test.py` and `tools/uc_isa_phase5.py`. The lifter was not changed. The high-confidence map was not changed.

An intentional read of `Sitext` at `0x01FC7000` still faults with that section name. Unknown import `0x0087A7AE` still fails without moving ESP or EAX.
