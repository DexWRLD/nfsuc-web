# Phase 18 — Runtime callback/dispatch table provenance

Ordinary `.text` / `.rdata` / `.data` / `.tls` / `.rsrc` and PE headers only.
Did not execute `nfs.exe`, patch `.rdata`, implement Direct3D9/TLS/Win32, unpack
protected sections, or invent callback bodies.

Primary question: **what structure contains `0x00B615C4`, and how is that
structure expected to become callable at runtime?**

## A. Candidate table layout

Three nearby pointer-dense dword runs in ordinary `.rdata`:

| Run | Bounds | Entries | Role |
| --- | --- | --- | --- |
| A | `0x00B61100`–`0x00B61214` | ~70 | Win32-ish dispatch; includes named `GetTickCount` IAT at `0x00B611D0` |
| B | `0x00B61230`–`0x00B614D8` | ~171 | Mostly named CRT IAT (e.g. `memcpy` at `0x00B61270`) |
| C (home) | `0x00B61528`–`0x00B615E4` | **48** | Graphics/system callback table containing `0x00B615C4` |

`0x00B615C4` belongs to **run C**. Immediately after a zero gap, named
`VERSION.dll` IAT slots begin at `0x00B615EC`.

The three watched slots are **not** one contiguous table:

| Slot | Run |
| --- | --- |
| `0x00B61188` | A |
| `0x00B611D4` | A (dword after `GetTickCount`) |
| `0x00B615C4` | C |

## B. Slot classifications

| Slot | PE value | Class | Named ordinary IAT | PE FirstThunk member |
| --- | --- | --- | --- | --- |
| `0x00B61188` | `0x008AB180` | INVALID / RUNTIME_REPLACEMENT_REQUIRED | no | no |
| `0x00B611D4` | `0x008A9F58` | INVALID / RUNTIME_REPLACEMENT_REQUIRED | no | no |
| `0x00B615C4` | `0x008AA3AE` | INVALID / RUNTIME_REPLACEMENT_REQUIRED | no | no |

Home run C: **48** callable-looking dwords; **25** invalid initial targets; **17**
linear-sweep-valid; **6** interior.

## C. Slot consumers

### `0x00B615C4` (3 consumers)

| Owner | Load | Call shape |
| --- | --- | --- |
| `0x0072E340` (HIGH, create) | `mov esi,[slot]` | three `call esi` |
| `0x00727F40` (HIGH) | `mov edi,[slot]` | three `call edi` with codes `0x3B`/`0x35`/`0x33` |
| `0x0071EA40` (HIGH) | `mov edi,[slot]` | three `call edi` into object `+0x4C0/+0x4C8/+0x4D0` |

All are **4-stack-dword**, callee-cleanup patterns (no `add esp` after the call).

### `0x00B61188` / `0x00B611D4`

Multiple HIGH consumers. `0x00B61188` sites push `(1, delay)` — SleepEx-like.
`0x00B611D4` sites are 0–1 arg cleanup helpers. Different ABI from `0x00B615C4`.

## D. `0x00B615C4` ABI

Inferred: **stdcall-like 4-arg** (or custom equivalent with callee cleaning 16 bytes).

Argument order (stdcall): `(code, size, buffer, flags)`.

Not named: no ordinary binding evidence assigns a Win32/API symbol.

## E. Three-call argument / dataflow (`0x0072E340`)

`ESI = [0x00B615C4]`; `EBX = ECX` (graphics object); `EBP = 0`.

| # | EIP | code | size | buffer | flags |
| --- | --- | --- | --- | --- | --- |
| 1 | `0x0072E35C` | `0x3A` | `8` | `[ebx+0x4C0]` | `0` |
| 2 | `0x0072E36A` | `0x34` | `8` | `[ebx+0x4C8]` | `0` |
| 3 | `0x0072E378` | `0x32` | `0x18` | `[ebx+0x4D0]` | `0` |

Returns unused. After #3: `cmp [ebx+0x4B8], 0` then helpers, then
`call 0x0087A79C` (Direct3DCreate9 thunk).

Pattern: **same callback, three parallel buffer fills** (not independent APIs,
not synchronization). Expected effect: mutate the three object regions before
the factory path. No substitute body implemented.

## F. Table-base references

Ordinary immediates hit home bounds and slots as **consumers**
(`call dword ptr [0x00B61528]`, `mov ebp,[0x00B61528]`, `call [0x00B615E4]`, …
plus the three `0x00B615C4` loads). No ordinary instruction takes the table as a
writable base for a fill loop.

Run B start `0x00B61230` appears in the `jmp dword ptr [iat]` thunk slab
(`0x00AE50xx`) — import-thunk style, not a publisher of run C.

## G. Alias writers

| Class | Count |
| --- | --- |
| DEFINITE_WRITER | **0** |
| POSSIBLE_WRITER (lea/address-taken + store) | **0** |
| READ_ONLY_CONSUMER | many |

Re-scanned with the Phase-16 HIGH map. No ordinary `lea reg,[table]` /
`mov [reg+disp],val` publisher of the home run or watched slots.

## H. Bulk-copy candidates

`memcpy` / `memmove` ordinary call sites: **no destination immediate overlapping**
`0x00B61100`–`0x00B61640`.

## I. Shadow-table candidates

`.data` copies of the three initial PE values: **none**. Shadow table: **no**.

## J. Memory-protection evidence

| Fact | Value |
| --- | --- |
| `VirtualProtect` in ordinary import-abi | no |
| `VirtualProtect` in PE import (SecuROM IAT) | yes (`~0x22CD0907`) |
| Ordinary `.text` immediates to that IAT | **0** |
| Dataflow linking protect → table | **none** |

Existence of the API in the protected import set is **not** evidence of ordinary
patching of `0x00B615C4`.

## K. Import-resolution evidence

| Fact | Value |
| --- | --- |
| PE Import Directory section | **`.securom`** |
| PE IAT Data Directory section | **`.securom`** |
| Descriptors overlapping `0x00B61000`–`0x00B61780` | **none** |
| Watched slots in any FirstThunk range | **none** |
| Ordinary `GetProcAddress` / `LoadLibrary*` ABI rows | none |
| Same APIs in SecuROM IAT | present; **0** ordinary `.text` imm refs |

Ordinary `.rdata` `0x00B610xx`–`0x00B617xx` is a **parallel dispatch/IAT-shaped
window** consumed by ordinary code. Official PE binding targets the protected
IAT (`~0x22CD****`), not these watched slots.

## L. Module / DLL evidence

- `d3d9.dll` is in the SecuROM-hosted PE import directory (separate from run C).
- `VERSION.dll` named slots sit just after run C.
- No ordinary DLL/module string path was tied to publishing `0x00B615C4`.

## M. Initial `0x008AA3AE`

Class: **DELIBERATELY_INVALID_SENTINEL_OR_PLACEHOLDER**.

Not a linear-sweep instruction boundary. Capstone mid-stream decode is rejected.
Same shape as nearby named import PE placeholders (e.g. `VERSION.dll` at
`0x00B615EC`). No ordinary XOR/add transform observed. Treat as
unbound/runtime-filled placeholder — not a recoverable ordinary code entry.

## N. Relationship among the three slots

| Property | Shared? |
| --- | --- |
| Same dense run | **no** |
| Same invalid PE placeholder format | **yes** |
| Same consumer ABI | **no** (`B615C4` 4-arg fill vs SleepEx-like / cleanup) |
| Same ordinary writer | none found for any |
| Same publication **class** | **yes** — external/protected placeholder binding |

`0x00B615C4` remains highest priority.

## O. Newly promoted Phase-16 HIGH findings

Re-ran publication/writer/alias/bulk/base-ref scans against the corrected map
(HIGH ≈ 22 779). **No new definite publisher** of `0x00B615C4` or home-run base.
Consumers of the slot are HIGH as before (`0x0072E340`, `0x00727F40`, `0x0071EA40`).

## P. Publisher candidates

| Candidate | Rank |
| --- | --- |
| Ordinary absolute / alias / memcpy writers | eliminated (0 definite) |
| Ordinary GetProcAddress fill | eliminated (no ordinary path) |
| Standard OS IAT bind of `0x00B615C4` | eliminated (slot not in PE FirstThunk) |
| **Protected/SecuROM binding of ordinary `.rdata` dispatch window** | **best remaining class** |

Best candidate label: PE/SecuROM import-binding of the ordinary `.rdata`
dispatch window (external/protected). This is a **dependency class**, not an
implementable ordinary initializer recovered here.

## Q. Publisher call-graph provenance

No ordinary publisher root. Protected import directory / IAT live outside
ordinary sections. **Not CALL_GRAPH_REACHABLE** from ordinary HIGH code.
Does not require TLS or `0x00686000` on the short create prefix; requires
**protected/external** execution to populate the slot.

## R. Flag=1 indirect-entry findings (`0x00722D60`)

| Check | Result |
| --- | --- |
| Call/tail predecessors | none |
| Ordinary `.rdata/.data` dword == `0x00722D60` | **none** |
| Indirect table candidate | **NONE_OBSERVED** |

Still DISCOVERED_HIGH (enrollment only), not CALL_GRAPH_REACHABLE.

## S. Corrected reachability terminology

| Term | Meaning |
| --- | --- |
| DISCOVERED_HIGH | HIGH + enrolled in discovery graph |
| DIRECTLY_REFERENCED | E8/E9 or absolute immediate exists |
| CALL_GRAPH_REACHABLE | ordinary HIGH predecessor via calls/tails |
| INDIRECT_CANDIDATE | only via unresolved table/register |
| RUNTIME_ENTERABLE | FACTORY_FRONTIER_READY + legitimate state |

Map field `reachable` = **discovery enrollment only**.

## T. FACTORY_FRONTIER_READY

**NO / FALSE**

| Requirement | Status |
| --- | --- |
| `0x0072E340` HIGH | yes |
| Pre-factory direct callees available | yes on selected path |
| `[0x00B615C4]` legitimate callable | **no** |
| Three ESI calls can execute legitimately | **no** |
| STATIC FACTORY | REACHABLE |
| PRE-FACTORY CALLBACK | UNRESOLVED |
| DIRECT3D9 IMPLEMENTED | NO |

## U. Optional execution

**Not run.** No legitimate ordinary publication mechanism to execute. Slot not
changed; graphics prefix not entered; immediately-before-Direct3DCreate9 not
reached.

## V. Recommended Phase 19

**GRAPHICS FRONTIER REQUIRES EXTERNAL INITIALIZATION**

1. Keep `0x00B615C4` classified as external/protected publication — do not
   invent a callback body or manually patch `.rdata`.
2. Search for an independent ordinary graphics initialization route that does
   not consume this slot.
3. Leave Direct3D9 unimplemented until a legitimate callable target exists
   without reconstructing protected code.

Artifacts: `phase18-raw.json`, `callback-table-map.json`, this report.
