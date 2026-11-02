# Undercover `_CI*` call-site ABI

The contract below is taken from the ordinary `.text` instructions around the four calls inside the `0x00A124B0` closure. It is not inferred from the import names. The game executable was only read. Nothing here executes `nfs.exe` or maps a protected section.

Thunks, from `analysis/undercover/import-abi.json`:

| symbol | thunk | slot | DLL | recorded convention |
| --- | --- | --- | --- | --- |
| `_CIsin` | `0x00AE5140` | `0x00B61464` | MSVCR80.dll | cdecl |
| `_CIcos` | `0x00AE5110` | `0x00B61444` | MSVCR80.dll | cdecl |
| `_CIacos` | `0x0087B2E0` | `0x00B61240` | MSVCR80.dll | cdecl |

`_CIasin` (`0x0087B2E6`) is not called by this closure and is not part of the contract below.

## Shared contract

Every call in this closure has the same shape:

- The value to transform is already in ST(0).
- No integer argument is pushed for the import.
- The instruction after the call is an `fstp` of ST(0). That is how the result is consumed.
- No other x87 register is live across the call.
- The call is a direct `E8` to the thunk. The thunk is `jmp dword ptr [slot]` inside ordinary `.text`.
- There is no `add esp` after the call. The callee therefore removes no stack arguments. The dispatcher pops only the return address. ESP after the import equals ESP before the `call`.
- The result is not returned in EAX. The instructions that follow read ST(0), not EAX.

Depth across the call is unchanged: one value in, that same slot replaced, one value out.

## `0x00A11C50` — `_CIsin` at `0x00A11C6D`

This is the only `_CIsin` caller in the closure, and the smallest one. It also makes the `_CIcos` call below. `ECX` is a destination object. `[ebp+8]` is a pointer to 16 bytes. `[ebp+0xc]` is a float. The function ends with `ret 8`.

Bytes immediately before the call, with the x87 depth that follows from an empty stack at function entry:

| address | instruction | depth after | integer stack |
| --- | --- | --- | --- |
| `0x00A11C50` | `push ebp` / `mov ebp, esp` | 0 | frame |
| `0x00A11C53` | `and esp, -16` / `sub esp, 0xc` | 0 | aligned frame |
| `0x00A11C59` | `fld dword [ebp+0xc]` | 1 | |
| `0x00A11C5C` | `push esi` | 1 | callee-saved, not an import argument |
| `0x00A11C5D` | `fmul qword [0x00B71CF0]` | 1 | ST(0) scaled in place |
| `0x00A11C65` | `fstp dword [esp+8]` | 0 | scaled value spilled |
| `0x00A11C69` | `fld dword [esp+8]` | 1 | ST(0) reloaded; nothing else live |
| `0x00A11C6D` | `call 0x00AE5140` | 1 | return address only |

`0x00B71CF0` is the qword `0.5` in `.rdata`. The import therefore sees `(float)(argument * 0.5)` promoted back to the x87 register.

Immediately after return:

```
0x00A11C72  fstp dword [esp+0xc]
0x00A11C76  fld dword [esp+0xc]
0x00A11C7D  fstp dword [esp+0xc]
0x00A11C81  movss xmm0, dword [esp+0xc]
```

`fstp` consumes ST(0). The following `fld`/`fstp`/`movss` move that stored float into XMM. Depth is 0 once the `fstp` completes. The `push esi` is balanced later by `pop esi`. It is not an import argument.

## `0x00A11C50` — `_CIcos` at `0x00A11C9B`

The sine result has already been stored and popped. The same spilled scaled angle is loaded again:

```
0x00A11C87  fld dword [esp+8]     ; depth 1, ST(0) = scaled argument
0x00A11C9B  call 0x00AE5110
0x00A11CA0  fstp dword [esp+0xc]  ; consumes ST(0)
0x00A11CA4  fld dword [esp+0xc]
0x00A11CA8  fstp dword [esi+0xc]  ; store, then depth 0
```

No other x87 value is live across this call. No integer argument is pushed. The next use of the cosine is the memory store at `[esi+0xc]`, which overlaps the last lane of the 16-byte XMM store that happened just before the call.

## `0x00A11AF0` — `_CIacos` at `0x00A11B2B`

Smallest `_CIacos` caller. One stack float at `[esp+4]` on entry. The import is reached only on the `|argument| < 1` path.

```
0x00A11AF0  push ecx
0x00A11AF1  fld dword [esp+8]     ; depth 1, original signed value
0x00A11AF5  fld st(0)             ; depth 2
0x00A11AF7  fabs
0x00A11AF9  fstp dword [esp]      ; depth 1, ST(0) still the signed value
0x00A11AFC  fld1                  ; depth 2
0x00A11AFE  fld dword [esp]       ; depth 3, ST(0) = |argument|
0x00A11B01  fcompi st(1)          ; depth 2, pops the absolute value
0x00A11B03  fstp st(0)            ; depth 1, pops the 1.0
0x00A11B05  jb 0x00A11B2B         ; taken when |argument| < 1
0x00A11B2B  call 0x0087B2E0
0x00A11B30  fstp dword [esp+8]    ; consumes ST(0) into the argument slot
0x00A11B34  fld dword [esp+8]     ; depth 1 again, returned to the caller
0x00A11B38  pop ecx
0x00A11B39  ret
```

At the call, depth is 1 and ST(0) is the original signed argument. The absolute value was only a temporary used for the compare. Nothing else is live. `push ecx` is a saved register, not an import argument. `ret` has no immediate, so the caller's stack slot remains and now holds the stored float. ST(0) also holds that float-rounded result, because of the reload.

The fall-through at `0x00A11B07` does not call the import. `comiss` against zero selects either `0.0` (argument `>= 1`) or the float at `.rdata` `0x00B6DCF0` (argument `<= -1`). That constant is the float `3.141592741`. The selected Undercover path therefore does not ask the runtime to raise an x87 exception for an out-of-domain arccosine. It branches away before the call.

## `0x00A11BD0` — `_CIacos` at `0x00A11C25`

Second caller. The input is the float at `[ecx+0xc]`. `fld` then `fabs` replaces ST(0) with the absolute value, so the value that reaches the import is already non-negative.

```
0x00A11BD0  sub esp, 8
0x00A11BD3  fld dword [ecx+0xc]
...         fabs, compare |value| with 1.0
0x00A11BF6  jb 0x00A11C25         ; |value| < 1
0x00A11C25  call 0x0087B2E0       ; depth 1, ST(0) = |value|
0x00A11C2A  fstp dword [esp+4]    ; consumes ST(0)
0x00A11C32  fstp dword [esp]
0x00A11C35  fld dword [esp]
0x00A11C38  fadd st(0), st(0)     ; doubles the result
0x00A11C3A  fstp dword [esp+4]
0x00A11C42  add esp, 8
0x00A11C45  ret
```

`add esp, 8` balances the function's own allocation. It is not import cleanup. The out-of-domain side again uses `0x00B6DCF0` and does not call the import.

A linear scan that adds both sides of the `jb` reports depth 2 at this call. That count is wrong. Each path ends the compare sequence at depth 1.

## Runtime contract used by the dispatcher

| question | answer from these call sites |
| --- | --- |
| Where is the argument? | already in ST(0) |
| Where is the result? | replaces ST(0) |
| Does the result push a new slot? | no |
| Is the input popped? | no; it is overwritten in place |
| Does x87 depth change? | no |
| Does ESP change beyond popping the return address? | no |
| Integer convention | cdecl, zero stack dwords |
| EAX | not used for the argument or the result |

The integer/stack convention and the x87 convention are separate. A cdecl return that writes EAX would not match these `fstp` consumers.
