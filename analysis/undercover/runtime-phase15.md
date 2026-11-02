# Runtime phase 15

Graphics-frontier provenance only. `0x00686000` was not revisited as an implementation target. Direct3D, TLS, windowing, and the filesystem were not implemented. No graphics function was executed. Medium-confidence functions were not promoted.

## A. `0x01311E1C` provenance

Section: `.data` virtual tail. Mapped value: **0**.

Absolute encodings in ordinary `.text`:

| kind | count |
| --- | --- |
| READ | 4 |
| ADDRESS_TAKEN | 3 |
| WRITE (`mov [abs]`) | 0 |

Address-taken sites all use `mov ecx, 0x01311E1C` and then `xchg dword ptr [ecx], eax`:

| site | EAX before xchg | effect | containing function |
| --- | --- | --- | --- |
| `0x00722D70` | `1` | store 1, old value in EAX | `0x00722D60` HIGH, unreachable |
| `0x00729977` | `2` | store 2 | inside `0x00729750` MEDIUM |
| `0x00B4F997` | `0` | store 0 | leaf `0x00B4F990` |

## B. Alias-writer results

| candidate | class | notes |
| --- | --- | --- |
| `0x00722D70` | `DEFINITE_WRITER` | `xchg` of immediate 1 |
| `0x00729977` | `DEFINITE_WRITER` | `xchg` of immediate 2 |
| `0x00B4F997` | `DEFINITE_WRITER` | `xchg` of 0 |
| other absolute stores | `NO_WRITER` | none found |

Phase 11's absolute-`WRITE` classifier does not see `xchg`-through-register. That is why Phase 14 reported "no absolute write."

## C. Variable behavior

Observable compared values: `0`, `1`, `2`.

| value | ordinary use |
| --- | --- |
| `0` | image / clearer leaf |
| `1` | gate in `0x0072E5D0` before `call 0x0072E340` |
| `2` | exit condition in `0x00722D60` after it has stored `1` |

Role: multi-state synchronization dword, not a one-bit boolean. No invented name.

## D. `0x009773B0`

HIGH, reachable, 6 instructions. Body:

1. `mov eax, [esp+4]`
2. `mov ecx, [eax]`
3. `push 1` / `push ecx`
4. `call dword ptr [0x00B61188]`
5. `ret`

It is not itself a wait loop. Callers (including `0x0072E5D0`) loop by re-reading the flag and calling this between attempts. Imports: one indirect through `.rdata`. No write of the flag.

## E. Graphics object field map

Static object address used as `ECX` at `0x00766773`: **`0x01318170`** (`.data` virtual tail, mapped zeros).

On `0x0072E340` / `0x0072E5D0` (this in `ECX`/`ESI`/`EBX`):

| offset | ops | note |
| --- | --- | --- |
| `+0x00` | READ | |
| `+0x10` | WRITE | `Direct3DCreate9` result |
| `+0x14` | READ | |
| `+0x18` / `+0x1C` | READ/WRITE | |
| `+0x54` | READ | subobject used heavily after the factory |
| `+0x4B8` | READ | |
| `+0x4C0`, `+0x4C8`, `+0x4D0` | READ | targets of the three `call esi` argument leas |
| `+0x4F8` | WRITE | `fstp` after later method |
| through `+0x534` | READ/WRITE | seen on `0x0072E5D0` |

## F. Object construction provenance

- Address: static global `0x01318170`, 123 `ADDRESS_TAKEN`, **0** absolute `WRITE`.
- Size: at least **0x534** bytes of observed field traffic; exact heap/global size not closed.
- Construction: thiscall methods on that address; not a `0x00686000` allocation path.
- Image state: zero. Field values are missing until ordinary methods run.

## G. `0x00766730`

MEDIUM, score 80, unreachable. It is the ordinary outer function that loads TLS state and then calls `0x0072E5D0` with `ECX = 0x01318170`.

Actual head:

- loads `[0x01385FA0]`, `call [0x00B611D4]`
- reads TLS index `[0x01882C34]` and `fs:[0x2C]`
- writes TLS object fields
- `mov ecx, 0x01318170` then `call 0x0072E5D0`

CFG walk beyond the map's 24 instructions: **180** instructions, returns at `0x00766946`, next map entry `0x00766950`. Coherent function with a real epilogue.

## H. `0x0072E340`

MEDIUM, score 80. thiscall (`ECX` saved in `EBX`). Loads ESI from `[0x00B615C4]`, three `call esi` (callee cleanup, four stack dwords), then `0x0072DD00` / `0x0072DCA0`, then `push 0x20` / `call Direct3DCreate9`, stores EAX at `[ebx+0x10]`, continues with more setup, later `call 0x00729750`.

CFG walk: **207** instructions, returns at `0x0072E408` and `0x0072E5B2`, next map entry `0x0072E5C0`.

## I. Medium-confidence extent findings

`tools/uc_funcmap.py` uses a **24-instruction** linear fact walk for scoring. Truncation sets `truncated` and blocks HIGH even when score ≥ 60.

Of 1,832 `MEDIUM_CONFIDENCE` functions, **1,782** have `insns == 24`. This is a **general discovery limitation**, not a property unique to the graphics addresses.

A full CFG walk finds ordinary returns for both `0x00766730` and `0x0072E340` before the next map symbol. They were **not** promoted in Phase 15. A general cap fix belongs in a dedicated discovery phase with map regeneration and tests.

## J. Three `call esi` targets

ESI comes from one load: `mov esi, dword ptr [0x00B615C4]`. All three calls use that same ESI.

PE value: `0x008AA3AE`. That address is the **displacement byte of a `je`**, not an instruction boundary in the owner CFG of `0x008A9480`. It was not dispatched.

## K. `0x00B611D4`

`.rdata`, PE value `0x008A9F58`, not a function-map entry. 7 indirect calls, 3 reads, **0** writers. Used by `0x00766730` before TLS work. Not dispatched.

## L. `0x00B61188`

`.rdata`, PE value `0x008AB180`, not a map entry. 6 indirect calls, **0** writers. Callee of `0x009773B0`. Not dispatched.

## M. `0x00B615C4`

`.rdata`, PE value `0x008AA3AE`. Classification: **initial PE function-pointer table slot whose value is not a valid ordinary entry**. No ordinary writer. Do not treat as `0x008A9480` and do not execute at `0x008AA3AE`.

## N. `0x00CEA3F0`

`.data`, PE value **0**. Two reads in `0x0072DD00` / `0x0072DCA0`. No writers. When zero, those helpers return without the indirect call. The zero path remains useful; a nonzero callback is not required before `Direct3DCreate9`.

## O. TLS index `0x01882C34`

`.data` virtual tail, mapped **0**. **605** absolute reads, **0** absolute writes. `0x00766730` uses it with `fs:[0x2C]` exactly as a TLS index into the TEB array.

Classification for the factory prefix:

- via `0x00766730`: `TLS_REQUIRED_BEFORE_FACTORY`
- via `0x0072E5D0` alone: `TLS_OPTIONAL_ON_PREFIX` (that function does not read the index before `Direct3DCreate9`)

## P. Direct3DCreate9 ABI confirmation

| item | value |
| --- | --- |
| thunk | `0x0087A79C` |
| IAT slot | `0x00B616CC` |
| DLL | `d3d9.dll` |
| convention | stdcall, high confidence |
| site | `0x0072E3B9` |
| stack argument | immediate `0x20` (`push 0x20`) |
| EAX | stored to `[ebx+0x10]` |
| failure | later path can return `al = 0` without assuming a non-null factory |

Not implemented.

## Q. Graphics initializer roots

| root | what it initializes | blockers |
| --- | --- | --- |
| `0x00722D60` | sets flag to 1 | no ordinary caller or data pointer |
| `0x00729750` | sets flag to 2 | called from inside create, after the factory |
| `0x00B4F990` | clears flag to 0 | table leaf |
| `0x00766730` | TLS slot fields, ECX object address, enters `0x0072E5D0` | medium, TLS index 0, bad indirect slots |
| static `0x01318170` | object storage | zero-filled; methods not run |

Best structural root for the high-confidence prefix: **`0x0072E5D0`**, once the flag and object fields are legitimate. No root currently establishes all prerequisites.

## R. Exact enterability requirements

To call `0x0072E5D0` and reach `Direct3DCreate9` without synthesizing state:

| piece | class |
| --- | --- |
| `[0x01311E1C] == 1` | `EXTERNAL_DEPENDENCY` / `UNKNOWN` entry to its definite writer |
| `ECX` → object at `0x01318170` (address) | `PE_INITIALIZED` |
| object fields used before the factory | `MISSING` / `ORDINARY_INITIALIZER` methods not yet ranked as runnable |
| `[0x00B615C4]` valid callee | `UNKNOWN` |
| `Direct3DCreate9` HLE | `IMPORT` (after enterability) |
| TLS for this entry | not required |
| `0x00686000` | not on this path |
| protected section bytes | not read; may still own the missing flag publication |

## S. Optional execution

None. Required state is not established.

## T. First-frame estimate

Phase 14: best 20, likely 22–28.

Phase 15 adds: the flag has definite writers, but the value-`1` writer is unreachable from the ordinary call/data graph; the ESI slot is not a valid entry; the object is a zero static. That is stricter than "missing absolute write."

| | |
| --- | --- |
| `BEST_CASE_FIRST_FRAME_PHASE` | 21 |
| `LIKELY_FIRST_FRAME_PHASE_RANGE` | 24–32 |
| reason | flag publication and callback-slot validity look external or undiscovered; discovery-cap fix helps confidence but does not fill those slots |

## U. Recommended Phase 16

1. Fix the **general** 24-instruction fact walk in function discovery, regenerate the map under the same ordinary-only rules, and re-score medium functions with tests. Do not special-case graphics addresses.
2. Continue searching for any ordinary or import-based publication of flag value `1` and for writers of the `.rdata` callback slots. Do not implement Direct3D until enterability is real.
