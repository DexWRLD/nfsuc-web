# Phase 8 cluster execution

The subsystem was not chosen in advance. `tools/uc_phase8_test.py` runs the cluster that the high-confidence graph actually closed.

Closures of two to twelve high-confidence functions were grouped by the imports they reach. A closure was executable only when every import has a recorded convention, no instruction is an indirect call or jump, and no operand lands in `Stext`, `Sitext`, `Srdata`, `Sdata`, `Sidata`, or `.securom`.

| Imports reached | Why it was not the first run |
| --- | --- |
| Winsock ordinals, `WSAIoctl`, `Netbios` | Unknown conventions and indirect calls. Those calls stay fatal. |
| `malloc`, `free`, `printf` | Indirect calls, and the result depends on the allocator. |
| `_CIacos`, `_CIcos`, `_CIsin` | Closed and direct. Six functions, `.rdata` constants, no `.data`. The results come back on the x87 stack, and the bodies are long SSE sequences. Left as the next candidate. |
| `memcpy` or `memset` alone | Already executed in Phase 7. The new samples are two-function tails, smaller than the chain below. |

The closure that satisfied the filter and adds more than one import is the set of functions that share `0x009AE140`, `0x009AE2A0`, and `0x009DDA70`.

| Root | Direct callees | Import |
| --- | --- | --- |
| `0x009B0490` | `0x009AE2A0`, `0x009DDA50` | `strlen`, thunk `0x00AE52EC`, cdecl, one stack dword |
| `0x009AEBD0` | `0x009AE2A0`, `0x009DDA70` | `memcmp`, thunk `0x00AE52D4`, cdecl, three stack dwords |
| `0x009AF0B0` | `0x009DDA70` | `strcmp`, thunk `0x00AE52C8`, cdecl, two stack dwords |

`0x009AE2A0` calls `0x009AE140`. `0x009DDA50` calls `0x009DDA70`. No new HLE was added. All three imports were already implemented. `nfs.exe` was not started.

The instructions use this layout. It is not a name for the object.

- The dword at the object is a pointer.
- The word at that pointer plus 2 is read by `0x009AE140`.
- The bytes at that pointer plus 8 are read by `0x009DDA70`.

The guest image is the Phase 7 ordinary image. The object bytes live in the private stack at `0x03000000`, not in a PE section.

## `0x009B0490`

Entry `ESP` was `0x0300F000`. The planted return was `0x00DEC0DE`. `ECX` was the object. The two stack arguments were a guest string and the dword `100`.

With the word equal to 4 and an empty string, `EAX` was 4. With the word equal to 5, bytes `a b c X Y` at the character pointer, and the string `XY`, `EAX` was 3. With the word equal to 4, bytes `a b c d`, and the string `zz`, `EAX` was `0xFFFFFFFF`. Each return left `ESP` at `0x0300F00C` and `EIP` at `0x00DEC0DE`. `EBX`, `ESI`, `EDI`, and `EBP` were unchanged.

The `strlen` call inside the first of those runs:

| Point | ESP |
| --- | --- |
| before the generated `CALL` | `0x0300EFE4` |
| inside the dispatcher | `0x0300EFE0` |
| after the import returned | `0x0300EFE4` |
| after the generated `add esp, 4` | `0x0300EFE8` |

The dword above the return address, captured inside the thunk, was the empty-string pointer `0x03001000`. The dispatcher popped only that return address. The lifted `add esp, 4` removed the argument. The harness did not write `ESP` after entry.

The first call's trace:

| Event | Function | Target |
| --- | --- | --- |
| `FUNCTION_ENTER` | `0x009B0490` | `0x009B0490` |
| `DIRECT_CALL` | `0x009B0490` | `0x009AE2A0` |
| `FUNCTION_ENTER` | `0x009AE2A0` | `0x009AE2A0` |
| `DIRECT_CALL` | `0x009AE2A0` | `0x009AE140` |
| `FUNCTION_ENTER` | `0x009AE140` | `0x009AE140` |
| `FUNCTION_RETURN` | `0x009AE140` | `0x009AE140` |
| `FUNCTION_RETURN` | `0x009AE2A0` | `0x009AE2A0` |
| `IMPORT_CALL` | `0x009B0490` | `0x00AE52EC` |
| `IMPORT_RETURN` | `0x009B0490` | `0x00AE52EC` |
| `DIRECT_CALL` | `0x009B0490` | `0x009DDA50` |
| `FUNCTION_ENTER` | `0x009DDA50` | `0x009DDA50` |
| `DIRECT_CALL` | `0x009DDA50` | `0x009DDA70` |
| `FUNCTION_ENTER` | `0x009DDA70` | `0x009DDA70` |
| `FUNCTION_RETURN` | `0x009DDA70` | `0x009DDA70` |
| `FUNCTION_RETURN` | `0x009DDA50` | `0x009DDA50` |
| `FUNCTION_RETURN` | `0x009B0490` | `0x009B0490` |

That is five Undercover functions plus `strlen`. The trace buffer holds 64 events, so later calls are checked by their register results rather than by another full listing.

## `0x009AEBD0`

Two objects, both with the word equal to 3 and the same three bytes, produced `AL = 1` and one `memcmp` call. The same word with a different third byte produced `AL = 0`. Different words produced `AL = 0` and did not call `memcmp`. `ESP` finished at `0x0300F008`.

| Point | ESP |
| --- | --- |
| before the generated `CALL` | `0x0300EFE8` |
| inside the dispatcher | `0x0300EFE4` |
| after the import returned | `0x0300EFE8` |
| after the generated `add esp, 0xc` | `0x0300EFF4` |

Inside the thunk the three stack dwords were the first character pointer `0x03002108`, the second character pointer `0x03002308`, and the length `3`.

## `0x009AF0B0`

Character bytes `abc` against `abd` produced `AL = 1` and one `strcmp` call. The same object pointer in `ECX` and on the stack produced `AL = 0` and did not call `strcmp`. Bytes `abd` against `abc` produced `AL = 0`. `ESP` finished at `0x0300F008`. `ESI` and `EBP` stayed `0x51515151` and `0xEBEBEBEB`.

| Point | ESP |
| --- | --- |
| before the generated `CALL` | `0x0300EFF0` |
| inside the dispatcher | `0x0300EFEC` |
| after the import returned | `0x0300EFF0` |
| after the generated `add esp, 8` | `0x0300EFF8` |

The two stack dwords were `0x03002108` and `0x03002308`.

## What this phase did not do

No protected section was read by these functions. A separate checked read of `Sitext` at `0x01FC7000` faulted with section `Sitext` and did not crash the host. No graphics, audio, input, file, or thread import was added. Unknown imports still fail closed. The game does not run.

The next closed candidate is `0x00A124B0` and the five functions it reaches, which call `_CIacos`, `_CIcos`, and `_CIsin`. Those results use the x87 stack. They are not implemented.
