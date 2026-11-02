# Phase 12

Ordinary provenance for `0x0189DA84` and `0x0189D0A0`. No value was written into either global by the harness. Protected sections were not read. The game was not started.

## A. `0x0189DA84`

Three ordinary writes: `0x009E9396` stores EAX, and `0x009E939D` and `0x009E7CCE` store 0. At `0x009E9396` the previous instruction is `call 0x009E9160`. `0x009E9160` ends with `mov eax, esi` / `ret 8`, and ESI is the ECX it received. That ECX is the return value of `0x009EB870`, called as `0x009EB870(0x248, 0x00C30EAC, 0, 0)`. `0x00C30EAC` points at the bytes `CoreImpl`. `0x009EB870` calls `0x009E9460`, which reads `0x0189DA88` and, when that dword is 0, returns 0. The next instruction in `0x009EB870` then reads `[eax]`.

The block is 0x248 bytes. `0x009E9160` writes through offsets up to `+0x240`, which matches that size. The pointer is not an address in `.data` and not a harness address. It is whatever `0x009EB870` returns. That return was not produced, because `0x0189DA88` is still 0 and its only writer is behind `call 0x00686000`.

## B. `0x009E9160`

Thiscall, two stack arguments, `ret 8`. ECX is the object. It does not allocate. It stores `0x00C30E68` at offset 0. That `.rdata` address begins a run of `.text` pointers, so offset 0 is a pointer table. It stores the second argument at `+0x58`. It calls `0x009E8AD0` at `0x009E9305` and then returns the same pointer in EAX. It also calls `0x009E7710`, `0x009E9990`, `0x009E9460`, `0x009773C0`, `0x00977E20`, `0x009EB980`, `0x0097FCD0`, `0x009777D0`, and `0x00977800`. Several of those are not discovered function entries. It cannot run on the current runtime: the block has to come from `0x009EB870`, and `0x009E9460` needs `0x0189DA88`.

## C. `0x009E9340`

If `[0x0189DA84]` is already nonzero it skips allocation and returns that pointer. Otherwise it calls `0x009EB870`, and on a nonzero return it calls `0x009E9160` with that pointer in ECX and then stores EAX. On a zero return it stores 0. It cannot run independently. The allocation call is the dependency, not a missing import inside `0x009E9340` itself.

## D. `0x009E9420`

Three stack arguments are forwarded, except the third is replaced by `[0x0189DA88]` before `call 0x009E9340`, then `add esp, 0x0C`. One caller in the walked chain is `0x008104E9`. The first function in this chain that cannot execute is `0x008101B0`, because it calls `0x0055FF30` and `0x00686000` before `0x009E9410`. Neither target disassembles as a function. `0x009E9410` is the only writer of `0x0189DA88`, and its only caller is `0x00810291`.

## E. `0x008101B0`

Medium confidence, score 80, not reachable, 24 instructions in the map. The score passes the numeric high-confidence bar. The label stays medium because the recorded walk does not end in `ret`, a tail, an import jump, or a switch, which `tools/uc_funcmap.py` requires. The bytes continue well past those 24 instructions and include `call 0x0055FF30` (`inc esi` and then bytes that are not a function) and `call 0x00686000` (`E8` to an address outside the image; low confidence, "branch misses the instruction stream"). It was not promoted and not executed.

## F. `0x0189D0A0`

In-place object and the base of a larger structure. The first 12 bytes are a count at `+0`, a second dword at `+4`, and a pointer at `+8`. The same 12-byte record is visited at `+0x0C`, `+0x18`, `+0x24`, and `+0x30`. See `object-0189d0a0.md`.

## G. Field required by the Phase 11 fault

`[0x0189D0A0+8]`. The instruction at `0x009E4B49` reads `[pointer + (count - argument) * 4 - 4]`. Count and argument were both 0, so this is `[pointer - 4]`. `0x009DC250` places a size dword in front of the pointer it returns. The address `0xFFFFFFFC` is that header while the pointer is 0.

## H. Ordinary writer of that field

`0x009E46A1` in `0x009E4640`: `mov dword ptr [ecx+8], eax` after `call 0x009DC250`. `0x009B67C0` calls `0x009E4640` with ECX equal to `0x0189D0A0` from `0x009B2D31`. `0x009E4C03` is the same kind of store for a different entry, `0x009E4BB0`, whose only caller initializes a different object's `+0x14`.

## I. Pointer-table chain for `0x009E78C0`

The outer target remains `0x009E78C0`, stored by the Phase 11 leaf. When `[0x0189DA84]` is nonzero, `0x009E78C0` loads `[object+0x58]`. `0x009E9160` stores its second argument there, and `0x009E9420` passes `[0x0189DA88]` as that argument. `0x008101B0` sets the dword at offset 0 of the 4-byte block to `0x00BBB460` before publishing it. Dword `+0x0C` of that table is `0x00564C20`, whose bytes are `int3` / `ret` with an immediate. It is not a generated entry. It was not dispatched. Ten slots in the Phase 11 table still hold `0x00695490`; those bytes are still not a function and were not called.

## J. Allocation

`0x009DBE50` passes one cdecl size to `[0x0189D198]`. The leaf sets that slot to `0x009E77D0`. `0x009E77D0` needs `[0x0189DA88]`. Creating `0x0189DA88` calls `0x00686000`, which is not `malloc` (`malloc` is the thunk `0x0087B6F8`) and is not code. A guest heap was not implemented. Substituting `malloc` for that call would invent the callee. Classification of this path: the next required call is not an ordinary function.

## K. Graph

`object-init-graph.md`.

## L. Order

`0x009E8AD0` runs during `0x009E9160`, after offset 0 and offset `0x58` are stored, and before `0x009E9340` publishes `0x0189DA84`. Allocation in `0x009EB870` is before that call.

## M. Controlled execution

No new function was executed. `0x009E9160`, `0x009E9340`, and `0x009E9420` were not run. A harness object was not supplied. `0x009E75A0` only writes zeros that are already present.

## N. Globals

`0x0189DA84`, `0x0189DA88`, `0x0189D0A0`, and `0x0189BEEC` were not changed. No new `.data` ranges.

## O. Retry of `0x0099DCD0`

Not repeated. Phase 11 already entered `0x009E78C0`, `0x009B6290`, and `0x009E4B10` and stopped at `0x009E4B49`. Phase 12 did not produce the pointer that instruction reads.

## P. Frontier

| | EIP | Reason |
| --- | --- | --- |
| Phase 10 | `0x0099DCEB` | `[0x0189D1A4]` is 0 |
| Phase 11 | `0x009E4B49` | `[0x0189D0A0+8]` is 0, address `0xFFFFFFFC` |
| Phase 12 | `0x009E4B49` | same instruction; the writer is known and was not run |

No additional functions, depth, imports, or indirect calls. The new dependency is the call at `0x00686000` on the way to `0x0189DA88`.

## Q. Still unknown

What would have to be true of the bytes at `0x00686000` for the factory pointer to appear. No ordinary store of those bytes was found. The pointer table at `0x00BBB460` has at least one slot, `0x00564C20`, that is not code.

## R. Phase 13

Do not implement a heap in place of `0x00686000`. Do not promote `0x008101B0`. Treat `0x00686000` and `0x0055FF30` as calls whose targets are not ordinary functions, and decide that boundary explicitly before any further object execution.

## Snapshot

No initialization snapshot was written. The changed-range record from Phase 11 remains the only executed initializer diff.
