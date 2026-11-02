# Phase 13

What the ordinary calls to `0x00686000` and `0x0055FF30` are. Protected sections were not read. The game was not started. Neither address was replaced with an allocator or any other function. Neither was executed.

## A. Address mapping

Two independent parses of the PE header agree. Image base `0x00400000`. Ordinary `.text` VA `0x00401000`, file pointer `0x1000`. File offset is `raw_ptr + (VA - text VA)`.

| VA | RVA | File offset | Check |
| --- | --- | --- | --- |
| `0x00401000` | `0x00001000` | `0x00001000` | section start |
| `0x008101B0` | `0x004101B0` | `0x004101B0` | bytes `6A FF 68`, `push -1` / `push imm32` |
| `0x009E4640` | `0x005E4640` | `0x005E4640` | bytes `55 8B EC`, `push ebp` / `mov ebp, esp` |
| `0x009E8AD0` | `0x005E8AD0` | `0x005E8AD0` | bytes `C7 05`, the Phase 11 leaf |
| `0x00686000` | `0x00286000` | `0x00286000` | same eight bytes from the file and from the `.text` buffer |
| `0x0055FF30` | `0x0015FF30` | `0x0015FF30` | same eight bytes from the file and from the `.text` buffer |

The image is 22,320,400 bytes and `SizeOfImage` is `0x020A5000`. Mapping is not off by one, and it is not the wrong base. SHA-256/80 of the 32 bytes before each target through the 48 bytes after: `0x00686000` is `0c9c12ab52214354`, `0x0055FF30` is `cc4cceb22a825823`.

## B. Bytes

Both addresses are inside ordinary `.text`. Neither is preceded by `int3` padding. Sixteen bytes ending at the address, then sixteen at the address:

`0x00686000`: `c8 56 52 bc 0f 7f 49 97` then `e8 f6 3f 2f ae 48 e2 6b f0 3d b5 5c cd 26 f0 f8`.

`0x0055FF30`: the byte at the address is `46`, then `c6 4e e5 96 94 07 7c 74 75 6e e6 a4 42 d4 eb`.

## C. Callers of `0x00686000`

249 direct `E8` calls. No direct `E9`. Not an import thunk. The map already contains the address as low confidence, score 35, 3 instructions, reachable, because a branch leaves the instruction stream.

| Caller label | Sites | Reachable from the high-confidence graph |
| --- | --- | --- |
| HIGH_CONFIDENCE | 88 | 44 |
| MEDIUM_CONFIDENCE | 159 | 0 |
| LOW_CONFIDENCE | 1 | 1 |
| REJECTED_DATA_LIKE | 1 | 1 |

`0x0071E6B0` is high confidence. Its bytes are `E8 4B 79 F6 FF`, and `0x0071E6B5 + 0xFFF6794B = 0x00686000`. The function begins `0x0071E6A0` after `int3` padding, so the call is not a misaligned immediate. Reachable high-confidence `0x00772413` is the same instruction form.

## D. Arguments

The repeated shape is three stack arguments and `add esp, 0x0C`. 163 sites have that `add esp` as the next instruction. 62 sites first copy EAX into EDI, ESI, EBX, or EBP. Checked sites:

| EIP | Pushes, last is the first argument | After the call |
| --- | --- | --- |
| `0x0071E6B0` | `0`, `0x00BAAE10`, `0x400` | `mov esi, eax` / `add esp, 0x0C` / compare with zero |
| `0x00772413` | `0`, `0x00BAEA38`, `0x9C6C` | `mov esi, eax` / `add esp, 0x0C` / `test esi, esi` |
| `0x0074D4D6` | `[0x00CD3A58]`, `0x00BADDBC`, `4` | `add esp, 0x18` / compare EAX / store through EAX |
| `0x00810259` | `[0x00CD3A54]`, `0x00BBBFC8`, `4` | `mov edi, eax` / `add esp, 0x0C` / compare with zero |

The integer is sometimes the first argument and sometimes a later one. One of the other arguments is often a `.rdata` address. The 0x248 count on the `0x009EB870` path is not one of these arguments.

Name used here: UNKNOWN_HELPER_A. It is not the `malloc` thunk.

## E. Return value

EAX is consumed as a pointer: copied into a register, compared with zero, or stored through. Sites that ignore EAX are not the pattern. Flags are not the result. EDX is not the result.

## F. Bytes at the target

Starting at `0x00686000`, the first instruction is `call 0xAE979FFB`. That address is outside the image (`SizeOfImage` ends at `0x024A5000`). The next bytes decode as `dec eax` / `loop`, which is not a return path. Shifts from -8 to +8 are `enter`, `mov esp, imm32`, `idiv`, `aas`, `das`, `scasb`, and `imul`. None is a prologue, and none ends in `ret` inside the first instructions. There is no `int3` run in the preceding 64 bytes.

## G. Nearby map entries

Within `0x180` bytes the map has `0x00685FC0` rejected, `0x00686000` low, `0x00686010` rejected, `0x00686030` medium (`or eax, 0xC7136FBB`), and `0x006860F0` rejected. None of those entries is the address the 249 calls use. They were not substituted.

## H. `0x0055FF30`

Four direct calls. Two high confidence (`0x0079478A`, `0x00794CA0`) and two medium (`0x00793AFA`, `0x008101E6`). No direct jump. Not an import thunk. Not in the function map. No map entry within `0x180` bytes.

The coherent sites set ECX and do not clean a stack argument:

```
00794782 lea ecx, [esi + 0x68]
0079478A call 0x55ff30
0079478F mov dword ptr [esi + 0x64], 0xb7e05c
```

`0x00793AFA` uses `lea ecx, [esp+0x34]`. `0x008101E6` uses `lea ecx, [esi+4]` when decoded from the `0x008101B0` prologue. The return value is not read. Name: UNKNOWN_HELPER_B. The byte at the address is `46` (`inc esi`). Shifts around it decode as `lodsd`, `in`, `pop es`, `xchg`, and `ret imm16` into data. No alignment in -8..+8 is a function.

## I. Comparison

Both are exact direct-call targets in ordinary `.text`, with high-confidence callers, no `.rdata` or `.data` pointer, and no import thunk. Both sit in stretches the map does not treat as high-confidence code. They are not the same helper. `0x00686000` is a three-argument caller-cleaned call whose EAX is a pointer, and its first decoded instruction leaves the image. `0x0055FF30` is a thiscall on ECX with no stack cleanup and no used return, and its first decoded instruction is `inc esi`.

## J. Caller confidence

See the table in C. Forty-four high-confidence callers of `0x00686000` are reachable in the ordinary graph. The calls are not an artifact of medium-confidence discovery alone.

## K. Ordinary data

No dword `0x00686000` or `0x0055FF30` in ordinary `.rdata`, `.data`, `.tls`, or `.rsrc`. They are not present as table entries in those sections.

## L. Writers

The absolute address does not occur as an immediate in ordinary `.text`, so there is no `mov [0x00686000], ...` and no `mov reg, 0x00686000`. Same for `0x0055FF30`. Classification of writers: NO_ORDINARY_WRITER. Alias stores that never materialize the address cannot be shown, and none were assumed.

## M. Discovery

`0x00686000` was discovered. The scorer recorded the bad branch and left it low confidence. Promoting every heavily called target would mark this body high confidence. That rule was not added. `0x0055FF30` was not given a function entry. Its bytes fail the ordinary-entry checks. No special case was added. The confidence map was not regenerated. Newly discovered functions: 0.

## N. `0x009EB870`

See `00686000-provenance.md`. The boundary is `call 0x00686000` inside `0x008101B0`, which is what produces the pointer later read from `0x0189DA88`. `0x009EB870` itself was not executed.

## O. `[0x0189D0A0+8]`

See `0189d0a0-field8-provenance.md`. The store is ordinary and was not run. Its pointer source also requires `0x0189DA88`, so it stops on the same call.

## P. Classification

`0x00686000`: PROTECTED_OR_EXTERNAL_DEPENDENCY.

Rejected: valid ordinary function (no alignment is one); missed discovery (it is already low confidence for a bad branch); ordinary runtime stub (the bytes are not a `jmp [slot]` or a short `call`/`ret`); runtime-modified ordinary code (no ordinary writer); embedded data as the whole explanation (44 reachable high-confidence functions call this exact entry); invalid call decoding (the `E8` displacement and the prologue at `0x0071E6A0` agree).

The positive evidence is the call itself: the entry those calls use begins with `call 0xAE979FFB`, which is outside the image. Protected sections were not opened to chase that address.

`0x0055FF30`: UNKNOWN.

The four calls are real thiscalls, and the bytes are not a function. The first instruction does not leave the image, so the external-call evidence used for `0x00686000` is absent. Calling the bytes data would ignore the calls. Neither label is forced.

## Q. Initialization

No initializer was run. `0x009E9160`, `0x009E9340`, and the store at `0x009E46A1` still depend on a pointer this helper has not returned. `0x0099DCD0` was not retried. `0x00695490` was not called.

## R. Phase 14

Do not lift `0x00686000` or `0x0055FF30`. Do not substitute `malloc`. Do not open a protected section to recover a body. Ordinary object initialization that needs `0x0189DA88` cannot go further until that call has an ordinary implementation, and this phase did not find one.
