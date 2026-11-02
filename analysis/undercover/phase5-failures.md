# Phase 5 remaining high-confidence failures

The generation pass used the exact Phase 4 HIGH_CONFIDENCE list: 6,604 addresses.
6,598 generated and 6,598 compiled. These six did not generate.
None of them is a missing compiler opcode. The lifter was not taught `aad`, `aaa`, `salc`, `ljmp`, or `fstpnce`.

| Function | First bad mnemonic | Class | Why |
| --- | --- | --- | --- |
| 0x00401DC0 | `salc` | FALSE_POSITIVE_DATA | The bytes at the candidate are `cmp dh, dh`, then `salc`, `ret`, `inc ebp`, and a `call` to `0xD6E93654`, which is outside `.text`. That is not a compiler function. |
| 0x00780150 | `aad 0x3e` | FUNCTION_BOUNDARY_PROBLEM | The entry is real (`mov eax, [esp+4]` / `test` / `je`). Following a jump reaches `aad` at `0x00527EB7`, inside bytes that are not an instruction stream. |
| 0x007C8350 | `aaa` | FUNCTION_BOUNDARY_PROBLEM | The entry is real (`mov eax, [esp+4]` and a byte test). The walk then reaches `aaa`, `salc`, and `aad` around `0x005092B1`. |
| 0x007C9010 | `fstpnce` | FUNCTION_BOUNDARY_PROBLEM | The entry is real. `discover()` follows a jump into `0x00463F74`, where the bytes `D9 DB` sit in a data block. See below. |
| 0x00841BF0 | `ljmp` | FUNCTION_BOUNDARY_PROBLEM | The entry is a real stack frame (`sub esp, 0xc`). A jump reaches `ljmp 0x7c4:0xa1538f2f` at `0x006954B6`, then `les`. |
| 0x00A945E0 | `aad 0x4a` | FUNCTION_BOUNDARY_PROBLEM | The function is `mov ecx, [ecx+0x10]` and `jmp 0x006BAEB0`, then `int3` padding. The jump target is data (`aad`, `lcall`, `ljmp`). |

No remaining failure is GENUINE_UNSUPPORTED_CODE, CONTROL_FLOW_LIMITATION beyond the boundary problem above, EXTERNAL_EDGE, or UNKNOWN.

`0x004A7520` did generate. Its bytes are `inc edi`, `std`, `and eax, imm32`, `wait`, `into`. The lifter emits `into` as a comment, so compilation succeeded. The map now rejects it as FALSE_POSITIVE_DATA. It stays inside the 6,598 generated count because that count is the Phase 4 list.

The same check rejected 29 MEDIUM functions. A sample (`0x00760950`, `0x0077D860`) starts with a real `55 8B EC` and then jumps into data. Those are boundary problems. They were not part of the high-confidence generation.

## `fstpnce`

Capstone decodes `D9 DB` as `fstpnce st(3), st(0)`. Intel leaves `D9 D8+i` reserved. The documented `FSTP ST(i)` encoding is `DD D8+i`, and `fst` / `fstp` are already implemented. The bytes around `0x00463F74` are not an x87 sequence. `fstpnce` is not implemented.

## Classifier

`tools/uc_funcmap.py` now runs the lifter's control-flow walk on every HIGH or MEDIUM function. If that walk reaches one of these opcodes, the function is reclassified `REJECTED_DATA_LIKE`. The Phase 4 generation numbers above are not recomputed from the smaller set.
