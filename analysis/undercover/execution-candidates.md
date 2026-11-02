# Undercover execution candidates

These addresses are from the 6,598 high-confidence functions that generated and compiled in Phase 5. Nothing here is a name for what the function does. The notes come from the bytes in ordinary `.text`. `nfs.exe` was not executed. Protected sections were not read.

The first native harness runs `0x00721070`. `execution-candidates.json` is an unreviewed mechanical ranking; the table below is the one that was checked.

| Address | Insns | Calls | Imports | Memory outside the stack | Indirect control | Verdict |
| --- | --- | --- | --- | --- | --- | --- |
| `0x00721070` | 3 | none | none | none | none | suitable, selected |
| `0x00A03510` | 2 | none | none | none | none | suitable |
| `0x00721050` | 2 | none | none | none | none | suitable |
| `0x00893E50` | 2 | none | none | none | none | suitable |
| `0x009EE7B0` | 3 | none | none | none | none | suitable |
| `0x009B6190` | 4 | none | none | none | none | suitable, little to check |
| `0x0045F160` | 1 | none | none | none | none | unsuitable as a first target |
| `0x00739E20` | 2 | none | none | absolute dword | none | unsuitable |
| `0x007409C0` | 2 | none | none | absolute dword | none | unsuitable |
| `0x00789620` | 2 | none | none | absolute dword | none | unsuitable |
| `0x00803FE0` | 3 | none | none | stack float only | none | unsuitable for the first run |
| `0x0071B850` | 8 | `0x0087A7AE` | `D3DXMatrixMultiply`, convention unknown | stack only | none | unsuitable |

## `0x00721070`

```
8B 44 24 04    mov eax, dword ptr [esp+4]
33 44 24 08    xor eax, dword ptr [esp+8]
C2 08 00       ret 8
```

The following bytes are `int3` padding. Both reads are stack arguments. There is no call, no absolute address, and no indirect branch. `ret 8` pops the return address and then 8 more bytes. The result in `EAX` is the first stack dword XOR the second. That is enough to check the return without guessing a role for the function.

## Other suitable leaves

`0x00A03510` is `mov al, 1` / `ret`. It writes only the low byte of `EAX` and pops only the return address.

`0x00721050` is `mov eax, 0xCEA3B8` / `ret`. The immediate is not a memory operand.

`0x00893E50` is `mov eax, ecx` / `ret 4`. The result is the incoming `ECX`, and the callee pops one stack dword after the return address.

`0x009EE7B0` is `mov eax, dword ptr [esp+4]` / `add eax, 0x10` / `ret`. One stack argument, and the plain `ret` does not pop it.

`0x009B6190` is `push ebp` / `mov ebp, esp` / `pop ebp` / `ret`. It restores `EBP` and the stack and produces no other result.

## Unsuitable for the first run

`0x0045F160` is the single instruction `ret 0xCE4D`. That pops 52,813 extra bytes. The bytes after it are not `int3` padding. It is a poor first guest.

`0x00739E20` is `sub dword ptr [0x013C6444], 1` / `ret`. It writes a fixed global.

`0x007409C0` is `mov eax, dword ptr [0x013C65D4]` / `ret`. The result depends on a global that this harness does not define.

`0x00789620` is `fld dword ptr [0x0179F41C]` / `ret`. It reads a global into the x87 stack.

`0x00803FE0` is `fld dword ptr [esp+4]` / `fcos` / `ret`. The input is a stack float, but the result depends on the host cosine and is the wrong first check.

`0x0071B850` loads three stack dwords, pushes them, calls `0x0087A7AE`, and returns with a plain `ret`. That thunk is `d3dx9_34.dll` `D3DXMatrixMultiply`, whose convention is unknown. The three pushes are only balanced if that callee pops 12 bytes. The metadata stays unknown; this pattern is not treated as proof, and the function is not the first guest.

## Phase 7 chains

These are ordinary `.text` call chains reviewed for the native harness. "Reachable" counts high-confidence Undercover functions reached by direct calls or direct tail jumps, including the root. Import thunks are listed separately and are not counted as Undercover functions. Nothing here was given a purpose name.

| Root | Direct Undercover callees | Reachable | Imports | Indirect | `.rdata` | `.data` | Runtime need | Rank |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `0x009B3910` | `0x009CF900` | 2 | none | none | none | none | stack only | executed |
| `0x00AEC8E0` | `0x00983AB0`, `0x009EE750` | 3 | none | none | none | none | an object pointer in `ECX`; `0x009EE750` is `lock xadd` | executed |
| `0x00739B90` | none | 1 | `memset` cdecl, thunk `0x0087B2D6` | none | none | none | a writable destination pointer | executed |
| `0x009D9150` | none | 1 | `memset` cdecl, thunk `0x0087B2D6` | none | none | writes `0x0189CDF4` for `0x28` bytes, then dwords at `0x0189CE1C` and `0x0129729C` | mapped writable `.data` | executed |
| `0x009AE260` | `0x009DDA50` | 3, through `0x009DDA70` | none | none | none | none | an object pointer in `ECX`; the leaf returns the dword at `[ecx] + 8` | suitable, not run |
| `0x009CAE50` | `0x009CB9F0`, `0x009E1F20` | 3 | none | none | none | none | an object whose dword at `+4` is itself a pointer | suitable, not run |
| `0x009D2C30` | `0x009E1F20` | 2 | none | none | none | none | one stack argument used as an object pointer | suitable, not run |
| `0x009DD280` | `0x009E43B0` | 3, through `0x009DD240` | none | none | the immediates `0x00C2F8D0` and `0x00C2F8C8` are stored, not loaded | none | a writable object; two dwords are replaced with those immediates | suitable, not run |
| `0x009B6200` | `0x009E0DA0` | 2 | none | none | none | `ECX` is the immediate `0x0189D0EC`; the callee reads the byte at `+0x20` | mapped `.data` | suitable, not run |
| `0x00AD1BD0` | `0x00A0B810` | 2 | none | none | none | none | an object table and two stack dwords; the callee is 28 instructions and returns with `ret 4` | suitable, not run |
| `0x00A46D40` | `0x00AEE150` | 3, through `0x00A12580` | none | none | `0x00AEE150` loads xmm constants, including `0x00BD1F10` and `0x00B6A8A8` | none | mapped `.rdata`, x87, and SSE; the middle function is 83 instructions | lower, not run |

`0x0071C7C0` calls `0x00744360` and `0x00755DC0` and reads the dword at `.data` `0x013C64E4`. It is not on the list above. `0x00755DC0` contains `jmp dword ptr [0x023ABC58]`. That address is inside `.securom`. The chain was not executed, and `.securom` was not mapped.
