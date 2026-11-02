# Phase 7 runtime validation

The harness is `tools/uc_phase7_test.py`. It compiles the lifted functions with clang and runs them through a native DLL. `nfs.exe` was not started. The lifter was not changed. `win32_call` was not changed. Protected sections were not read.

Phase 6 ran `0x00721070`. That function is `mov eax, [esp+4]` / `xor eax, [esp+8]` / `ret 8`. It does not call an import. The Phase 6 import tests called the dispatcher from the harness, not from recompiled Undercover code. The real import path starts in this phase.

## A. Undercover function to import

`0x00739B90` is the first recompiled function that called an import and returned.

```
mov eax, dword ptr [esp+4]
push 0x180
push 0
push eax
call 0x0087B2D6
add esp, 0xc
ret
```

`0x0087B2D6` is the `MSVCR80.dll` `memset` thunk. The descriptor says cdecl and three stack dwords. The HLE is the existing `memset` body. The lifted caller was not replaced. The thunk is a runtime function that calls `uc_import_invoke` on that descriptor.

The destination was guest `0x03002000`, filled with `0xA5` for `0x181` bytes. The planted return address was `0x00DEC0DE`. Entry `ESP` was `0x0300F000`.

| Point | ESP | What it means |
| --- | --- | --- |
| function entry | `0x0300F000` | return address already on the stack |
| before the generated `CALL` | `0x0300EFF4` | three pushes, 12 bytes |
| inside import dispatch | `0x0300EFF0` | the generated `PUSH32` of `0x00739BA1` |
| immediately after import return | `0x0300EFF4` | cdecl popped only that return address |
| after the generated cleanup | `0x0300F000` | the lifted `add esp, 0xc` |
| after the function returns | `0x0300F004` | the function's own `ret` |

`EAX` was `0x03002000`. `EIP` was `0x00DEC0DE`. The first `0x180` bytes were zero and the following byte was still `0xA5`. `ECX`, `EDX`, `EBX`, `ESI`, `EDI`, and `EBP` were unchanged. The import trace recorded the same inside and after values, with symbol `memset` and a successful return.

`0x009D9150` is a second call of the same thunk. It passes the constant destination `0x0189CDF4`, length `0x28`, and fill `0`. After the call it stores `0` at `0x0189CE1C` and `4` at `0x0129729C`. Entry `ESP` was again `0x0300F000`.

| Point | ESP |
| --- | --- |
| before the generated `CALL` | `0x0300EFF0` |
| inside import dispatch | `0x0300EFEC` |
| after import return | `0x0300EFF0` |
| after `add esp, 0xc` | `0x0300EFFC` |
| after the function returns | `0x0300F004` |

The four-byte difference between the cleanup value and the entry value is the saved `EBP`. The final `pop` and `ret` remove it. `EAX` was `0x0189CDF4`. `EBP` was restored. The `0x28` bytes at `0x0189CDF4` were zero. The dword at `0x0189CE1C` was `0` and the dword at `0x0129729C` was `4`. The byte at `0x0189CDF3` and the byte at `0x0189CE20` were left as `0xA5`.

The first version of that last check used `0x0189CE1C` as the untouched byte. That address is the next store, so the byte correctly became `0`. The check was moved. This was a bad assertion, not an ESP repair and not a change to the generated cleanup.

## B. Cdecl stack ownership

For both calls the dispatcher popped one dword, the return address pushed by the lifted `CALL`. It did not add `4 * 3`. The lifted `add esp, 0xc` ran as generated and returned `ESP` to the pre-call value, plus the caller's own frame in `0x009D9150`. The harness did not write `ESP` after entry.

The stack slot at the inside-dispatch `ESP` was the lifted return constant: `0x00739BA1` for the first function and `0x009D9161` for the second.

## C. Ordinary image

`runtime/uc_image.c` places caller-supplied section bytes at their guest virtual addresses. It zeros the virtual size first, then copies `min(raw size, virtual size)`. The virtual tail stays zero. The loader refuses the protected names even if a caller passes bytes for them. The Phase 7 driver reads raw bytes only for `.text`, `.rdata`, `.data`, `.tls`, and `.rsrc`.

| Section | Guest VA | Virtual size | Access | Mapped |
| --- | --- | --- | --- | --- |
| `.text` | `0x00401000` | 7,730,171 | read, execute | yes |
| `.rdata` | `0x00B61000` | 1,354,302 | read | yes |
| `.data` | `0x00CAC000` | 12,607,092 | read, write | yes |
| `.tls` | `0x018B2000` | 25 | read, write | yes |
| `.rsrc` | `0x018B3000` | 4,628 | read | yes |
| `Stext` | `0x018B5000` | 7,412,768 | none | no |
| `Sitext` | `0x01FC7000` | 26,896 | none | no |
| `Srdata` | `0x01FCE000` | 437,924 | none | no |
| `Sdata` | `0x02039000` | 2,639,608 | none | no |
| `Sidata` | `0x022BE000` | 21,432 | none | no |
| `.securom` | `0x022C4000` | 1,966,294 | none | no |

The harness stack is a private region at `0x03000000` for `0x10000` bytes. It is not a PE section. `.data`'s file bytes end at `0x012A6000`. A checked read there returned zero.

The first dword of `.text` and the first dword of `.rdata` matched the file. No selected function reads `.tls` or `.rsrc`.

## D. Two Undercover functions

`0x009B3910` calls `0x009CF900`. Both are recompiled ordinary `.text` functions. Neither has an import or a global operand.

Entry `ESP` was `0x0300F000` and the planted return was `0x00DEC0DE`. After the return, `ESP` was `0x0300F004` and `EIP` was `0x00DEC0DE`. `EAX` stayed `0xA5A5A5A5`. `EBX`, `ECX`, `EDX`, `ESI`, `EDI`, and `EBP` stayed at the values planted before the call.

The trace for this pair, in order:

| Event | Function | Target |
| --- | --- | --- |
| `FUNCTION_ENTER` | `0x009B3910` | `0x009B3910` |
| `DIRECT_CALL` | `0x009B3910` | `0x009CF900` |
| `FUNCTION_ENTER` | `0x009CF900` | `0x009CF900` |
| `FUNCTION_RETURN` | `0x009CF900` | `0x009CF900` |
| `FUNCTION_RETURN` | `0x009B3910` | `0x009B3910` |

`DIRECT_CALL` goes through a switch on the guest address from the lifted call. The only callee for that address is the lifted body of `0x009CF900`.

## E. Three-function chain

`0x00AEC8E0` calls `0x00983AB0` and then `0x009EE750`.

`0x00983AB0` reads the dword at `[ecx+4]`. The caller sets `ECX` to the object plus `0xD0`, so the read is the object dword at `0xD4`. That dword was `1`, so the following compare does not skip the second call. `0x009EE750` is `lock xadd dword ptr [eax], ecx` with `ECX` set to `-1` by the function itself, then a decrement. The pointer at object `+0x30` was guest `0x03005000`, whose dword was `5`.

After the chain, `EAX` was `4` and that dword was `4`. `ESP` was `0x0300F004`. `EIP` was `0x00DEC0DE`. `ESI`, `EBX`, `EDI`, and `EBP` were restored. `ECX` is the xadd register and is not preserved.

The trace continued:

| Event | Function | Target |
| --- | --- | --- |
| `FUNCTION_ENTER` | `0x00AEC8E0` | `0x00AEC8E0` |
| `DIRECT_CALL` | `0x00AEC8E0` | `0x00983AB0` |
| `FUNCTION_ENTER` | `0x00983AB0` | `0x00983AB0` |
| `FUNCTION_RETURN` | `0x00983AB0` | `0x00983AB0` |
| `DIRECT_CALL` | `0x00AEC8E0` | `0x009EE750` |
| `FUNCTION_ENTER` | `0x009EE750` | `0x009EE750` |
| `FUNCTION_RETURN` | `0x009EE750` | `0x009EE750` |
| `FUNCTION_RETURN` | `0x00AEC8E0` | `0x00AEC8E0` |

No larger chain was executed. The next clean shapes need an object graph or a long body. `0x00A46D40` reaches three functions, and the middle one is 83 instructions with `.rdata` xmm loads. It was left unrun. Chains that need an unknown import or a protected address were not used to stretch the count.

## F. Memory checks

Checked builds resolve `MR*` and the atomic helpers through `uc_guest_ptr`. A miss, or a write to a region without the write flag, records the current function, the recorded guest `EIP`, the address, the access kind, and the section name, and returns a sink so the host does not crash. Lifted stores of the form `MR32(...) = ...` in this harness call `uc_guest_store32`, which uses the write flag. `PUSH32` still uses the load-checked lvalue, because the stack region is writable and the push is not a store to a PE section.

The negative checks, after the successful runs:

| Access | Address | Result |
| --- | --- | --- |
| read | `0x00B613FC`, the hole after `.text` | fault, section `unmapped` |
| read | `0x01FC7000`, `Sitext` | fault, section `Sitext`, kind read |
| write | `0x00B61000`, `.rdata` | fault, section `.rdata`, kind write; the dword was unchanged |
| execute | `0x01FC7000`, `Sitext` | fault, section `Sitext`, kind execute |
| read | `0x024A5000`, one past the image | fault, unmapped |

The following read of the first `.rdata` dword still matched the file. The process did not crash.

`0x00816E50` is `fld dword ptr [ecx+0x130]` / `fmul dword ptr [0x00B69278]` / `ret`. With `2.0` at the object slot, `ST(0)` matched the double product of that value and the mapped `.rdata` float. The read of `0x00B69278` is span 10 below.

Spans recorded while tracing was on:

| Kind | Range | Section | Source |
| --- | --- | --- | --- |
| read | `0x0300EFEC` .. `0x0300F008` | harness stack | stack operands |
| read | `0x0300EFF0` .. `0x0300F000` | harness stack | stack operands; overlaps the range above |
| write | `0x03002000` .. `0x03002180` | harness stack | `memset` of the pointer argument, `0x180` bytes |
| read | `0x030040D4` .. `0x030040D8` | harness stack | object field used by `0x00983AB0` |
| read | `0x03004030` .. `0x03004034` | harness stack | pointer loaded by `0x00AEC8E0` |
| read and write | `0x03005000` .. `0x03005004` | harness stack | `lock xadd` dword, `5` became `4` |
| write | `0x0189CDF4` .. `0x0189CE20` | `.data` | `memset` of `0x28` bytes plus the dword store at `0x0189CE1C` |
| write | `0x0129729C` .. `0x012972A0` | `.data` | the dword store of `4` |
| read | `0x03006130` .. `0x03006134` | harness stack | the float argument of `0x00816E50` |
| read | `0x00B69278` .. `0x00B6927C` | `.rdata` | `fmul dword ptr [0x00B69278]` |
| read | `0x012A6000` .. `0x012A6004` | `.data` | the harness check of the zero-filled virtual tail, not a game instruction |

`.data` bytes in the written ranges changed as the tests required. The `.rdata` float was read and not written.

## G. Imports added in this phase

None. `memset` was already implemented. The selected functions do not call the other six CRT helpers. Those helpers stay covered by `tools/uc_phase6_test.py`, which still passes. Unknown imports still fail without moving `ESP`.

## H. Unresolved runtime limits

- The executed import is cdecl `memset` only. Stdcall, thiscall, and fastcall were not entered from a recompiled Undercover function in this phase. Their Phase 6 synthetic checks still pass.
- Guest `EIP` in the fault record is the `CPU.eip` value last written by the lifter, plus the function address the harness publishes at entry. The lifter does not update `EIP` on every instruction.
- Two stack-read spans overlap. The bytes are right; the merger did not collapse them.
- `0x00755DC0` was not executed. Its fourth instruction is `jmp dword ptr [0x023ABC58]`, and `0x023ABC58` is in `.securom`. A direct call to an unknown address, including the harness call of `dispatch_indirect` with target `0x0087A7AE`, records `INDIRECT_CALL` and does not choose a callee. `EIP` and `ESP` stayed where the caller left them.
- `guest_atomic_xadd` is still one load and one store. The chain that uses it is single-threaded. This is not a multiprocessor atomic.
- No thread is created. No Direct3D, DirectSound, DirectInput, or XInput function is implemented.
- The game does not boot. The PE entry in `Sitext` is not called.

## I. Protected sections

None of the executed functions read, wrote, or executed a protected section. The `Sitext` and `.securom` results above are the explicit fault checks and the static rejection of `0x00755DC0`. Those sections were not mapped in order to continue.
