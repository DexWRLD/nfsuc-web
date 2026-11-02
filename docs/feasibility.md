# Feasibility

This is a summary. The measurements are in `analysis/undercover/`. The game executable is not in the repository.

## PE

Need for Speed Undercover's `nfs.exe` is PE32 / x86, image base `0x00400000`, linked with MSVC 8 (MSVCR80 / MSVCP80). The image is about 34 MB (`SizeOfImage` `0x020A5000`). There is no base-relocation directory, and `IMAGE_FILE_RELOCS_STRIPPED` is set. The PE entry point is `0x01FCA510`, in `Sitext`, not in ordinary `.text`.

Sections named `Stext`, `Sitext`, `Srdata`, `Sdata`, `Sidata`, and `.securom` are the protected layout. They were not disassembled.

Details: `analysis/undercover/nfs-pe.md`.

## Ordinary .text

`.text` is `0x00401000` .. `0x00B603FB` (7,730,171 bytes). Capstone decoded 99.5% of those bytes: 2,771,110 instructions. Direct calls inside the section produce 13,090 targets that land on a decoded instruction. A walk from those targets reaches 874,653 instructions.

The existing NFSU2 lifter accepts 99.9% of that reached set. `jmp`, in-range conditional branches, and `loop` / `jecxz` are handled in `lift()` before `insn()`. 328 switch tables match `Lifter._jt_bound` / `Lifter._jt_table`, and none of their entries leave `.text`.

From the call-target graph, one direct edge enters a protected section (a `jmp` into `.securom`). The body is otherwise self-contained. The linear sweep reports more outward branches; those are not on the call-target graph and are decoded data.

`.text` contains no absolute `call` or `jmp` through the PE import-address table. Import thunks that do appear are `jmp dword ptr [slot]` with the slot in `.rdata`.

Details: `analysis/undercover/code-analysis.md`.

## Phase 3 sample

`tools/uc_gen.py` lifts with `RawLifter`, so only `.text` is in memory. The PE entry was not a root. Unsupported instructions were not replaced with NOPs. Generated C was compiled with clang against `runtime/cpu.h` and was not committed.

| | Count |
| --- | --- |
| Functions attempted | 100 |
| Generated | 83 |
| Compiled | 83 |
| Compiler failures | 0 |
| Direct calls that stay in `.text` | 1,703 |
| Direct edges into a protected section | 0 |
| Unresolved indirect calls | 230 |
| Recognized switch tables | 20 |
| Rejected `[reg*4]` jumps | 1 |
| Generated source | 3,507,975 bytes |

The required roots `0x00A0AF20` and `0x00686030` generated and compiled. `0x0087B350` is a real four-instruction function (`cmp`, `jne`, `repz ret`, `jmp`) and the phase 3 lifter stopped on `repz ret` (`F3 C3`). The linear sweep finds 46 `repz ret` instructions and 43,759 plain `ret` instructions.

`movmskps` (`0F 50`) stopped `0x00B02690` and `0x00B070C0`, both of which begin with `push ebp; mov ebp, esp`. The other 14 refusals are `aaa`, `das`, `les`, `lcall`, `ljmp`, `iretd`, and `aad` in targets whose first bytes are not compiler output. The baseline is kept in `analysis/undercover/phase3-baseline.md`.

## Phase 4

`F3 C3` is lowered as a near return. Intel ignores a `REP` prefix on near `RET`; MSVC emits the two bytes as an AMD branch-prediction hint. It pops one return address, the same as `C3`. It is not a repeated string operation. `F2 C3` is a different encoding and is not accepted as this form. `movmskps r32, xmm` writes the four lane sign bits into bits 0..3 of the destination and clears the rest. The bits are taken from the integer view of the existing XMM union, so `+0.0` and `-0.0` stay distinct. `tools/uc_isa_test.py` runs both forms.

The same 100 addresses were lifted again. Nothing was added to make the count reach 100.

| | Phase 3 | Phase 4 |
| --- | --- | --- |
| Attempted | 100 | 100 |
| Generated | 83 | 86 |
| Compiled | 83 | 86 |
| Compiler failures | 0 | 0 |
| Genuine unsupported instructions | `repz ret`, `movmskps` | none in this sample |
| Rejected likely-data roots | 14 | 14 |

`0x0087B350`, `0x00B02690`, and `0x00B070C0` now generate and compile. The 14 data-like roots still fail, on `aaa`, `das`, `les`, `lcall`, `ljmp`, `iretd`, and `aad`.

Function discovery for Undercover is separate from `tools/genall.py`. Seeds are the phase 3 functions that compiled, plus boundary `55 8B EC` prologues after `int3`. A frame pointer is evidence, not a requirement. The walk follows direct calls, direct jumps that land on an entry, and recognized switch targets. It does not start from every `CALL` the linear sweep can decode.

| | Count |
| --- | --- |
| HIGH_CONFIDENCE | 6,604 |
| MEDIUM_CONFIDENCE | 79 |
| LOW_CONFIDENCE | 20 |
| REJECTED_DATA_LIKE among walked entries | 478 |
| Reachable entries | 7,181 |
| Unreachable padding or prologue candidates | 15,755 |
| CFG coverage of `.text` | 1,853,801 / 7,730,171 bytes (24.0%) |

Only the high-confidence set was generated. Medium and low roots were not. `0x00686030` is medium (two instructions, score 45), so it is not in that set; it did compile in the phase 3 sample.

| | Count |
| --- | --- |
| High-confidence functions attempted | 6,604 |
| Generated | 6,532 (98.9%) |
| Compiled | 6,532 |
| Compilation of generated functions | 100% |
| Compiler failures | 0 |
| Unresolved indirect calls | 6,875 |
| Unresolved external direct edges | 11 |
| Recognized switches | 142 |
| Rejected switches | 53 |
| Generated source | 46,994,153 bytes |
| Translation units | 6,532 |
| Compile time | 114s |

The 72 generation failures are not hidden. 67 are real opcodes in compiler-shaped functions: `lock xadd` (41), `psrldq` (7), `lock cmpxchg` (6), `lock cmpxchg8b` (5), `pslldq` (4), `punpcklqdq` (2), `pshufd` (1), `fstpnce` (1). Five are still data-like (`aad` twice, `salc`, `aaa`, `ljmp`) and were admitted by the confidence model.

199 `.rdata` thunks resolve to an import symbol. 137 undecorated MSVCR80 exports are cdecl, and one MSVCR80 method is thiscall. 19 Win32 exports are stdcall, including `Direct3DCreate9` and `DirectInput8Create`. 42 stay unknown, mostly ordinals and DirectX helpers whose decoration does not say. No MSVCP80 thunk appeared in this set. The runtime is not implemented. `win32_call` still pops arguments as stdcall.

The game does not boot or run. Protected startup remains outside this work.

Details: `analysis/undercover/recompilation-feasibility.md`, `function-map.md`, `high-confidence.md`, `import-thunks.md`.

## Phase 5

The same 6,604 Phase 4 addresses were generated again after the remaining compiler opcodes were lowered. Classification was not edited to raise the percentage. `tools/uc_isa_phase5.py` checks the new forms on integer lanes and on guest memory bytes.

`psrldq` and `pslldq` shift the 16 raw XMM bytes and fill with zero. Counts of 0, 1, 4, 8, 15, 16, and greater than 16 are tested. `pshufd` copies 32-bit lanes, including a memory source. `pshuflw` copies 16-bit lanes in the low qword and leaves the high qword unchanged. `punpcklqdq` keeps the destination low qword and inserts the source low qword above it. `punpckhqdq` moves the destination high qword down and inserts the source high qword above it. `pshuflw` and `punpckhqdq` were hidden in Phase 4 because an earlier instruction in the same function failed first.

Locked `xadd`, `cmpxchg`, and `cmpxchg8b` call `guest_atomic_*` in `runtime/cpu.h`. Unlocked `xadd` and `cmpxchg` do not. The helper body is a single-threaded load and store for the compile harness. It is not a multiprocessor atomic and it is not a WebAssembly shared-memory atomic. `cmpxchg8b` compares `EDX:EAX` with two little-endian 32-bit halves, writes `ECX:EBX` on a match, and updates `EDX:EAX` and ZF on a miss. It does not cast the guest address to `uint64_t*`. Every Undercover site is `lock xadd dword ptr [reg], reg32`, `lock cmpxchg dword ptr [reg], reg32`, or `lock cmpxchg8b qword ptr [reg]`.

`fstpnce` is Capstone's name for the reserved bytes `D9 DB`. It is not `fstp`, which the lifter already implements. It is not implemented.

| | Phase 4 list |
| --- | --- |
| Functions attempted | 6,604 |
| Generated | 6,598 (99.9%) |
| Compiled | 6,598 |
| Compilation of generated functions | 100% |
| Compiler failures | 0 |
| Generated source | 48,306,062 bytes |
| Translation units | 6,598 |
| Compile time | 144s |

The six failures are not missing compiler opcodes. Five real-looking entries reach `aad`, `aaa`, `ljmp`, or `fstpnce` by following a jump into data. `0x00401DC0` is data (`salc` and a call outside `.text`). Details are in `analysis/undercover/phase5-failures.md`.

The map then rejects any HIGH or MEDIUM function whose lifter walk reaches that data class. HIGH moves from 6,604 to 6,597, MEDIUM from 79 to 50, and REJECTED_DATA_LIKE from 478 to 514. LOW stays 20. Reachable entries stay 7,181. CFG coverage moves from 1,853,801 to 1,851,810 of 7,730,171 bytes (24.0%). The extra former HIGH function is `0x004A7520`, which is data the lifter compiled only because `into` is emitted as a comment. It remains inside the 6,598 generated count.

`analysis/undercover/import-abi.json` lists the 199 thunks: 137 cdecl, 19 stdcall, 1 thiscall, 42 unknown. 157 have high confidence. 31 ordinals and the undecorated DirectX helpers stay unknown. 3,404 direct calls and 2,604 tail jumps are counted separately. `win32_call` is unchanged.

## Phase 6

The lifter was not changed. `runtime/uc_import.c` dispatches Undercover imports by the convention in `import-abi.json`. Cdecl and stdcall were checked with the same argument block: after a cdecl return, guest ESP has moved by 4, and the caller must add the argument bytes; after a stdcall return, guest ESP has moved by 4 plus `4 * n`. That stdcall distance is the same `4 * n` still used by `win32_call`. A synthetic thiscall keeps `this` in `ECX` and pops one recorded stack dword. A synthetic fastcall reads `ECX` and `EDX` plus one stack dword. `D3DXMatrixMultiply` stays unknown and the call fails without moving ESP, even if a handler is supplied.

Seven CRT imports have HLE bodies: `memcpy`, `memmove`, `memset`, `memcmp`, `strlen`, `strcmp`, `strncmp`. Overlapping `memcpy` is rejected. The other 192 imports have no HLE and fail if called.

`tools/uc_phase6_test.py` translates `0x00721070` and runs that C in a native harness. The body is `mov eax, [esp+4]` / `xor eax, [esp+8]` / `ret 8`. With stack arguments `0x11111111` and `0x01010101` and return address `0x00DEC0DE`, the result is `EAX = 0x10101010`, `EIP` is the planted return address, and `ESP` is 12 bytes above the entry value. A second call with both arguments `0xFFFFFFFF` returns 0. No other register changes. This is not execution of `nfs.exe`. That function does not call an import.

## Phase 7

`tools/uc_phase7_test.py` runs lifted functions against a guest image of the ordinary sections. `0x00739B90` calls `memset` through `uc_import_invoke` and the generated caller removes the 12 argument bytes. `0x009B3910` calls `0x009CF900` and both return. `0x00AEC8E0` calls `0x00983AB0` and `0x009EE750`. `0x009D9150` calls the same `memset` and then writes two `.data` dwords. `0x00816E50` reads the float at `.rdata` `0x00B69278`. The details and the ESP trace are in `analysis/undercover/runtime-phase7.md`.

A read of `Sitext`, a write of `.rdata`, and an execute of `Sitext` fault with the section name. The host process continues. No protected section is mapped. No new import was added. The game is not executed.

## Phase 8

The next cluster was taken from the high-confidence graph, not from a preselected subsystem. Closures that reach unknown Winsock ordinals were left unrun. The executed cluster shares `0x009AE140`, `0x009AE2A0`, and `0x009DDA70`. `0x009B0490` calls `strlen`, `0x009AEBD0` calls `memcmp`, and `0x009AF0B0` calls `strcmp`. All three are existing cdecl helpers. A five-function chain through `strlen` returns the expected dwords, and the generated `add esp` removes one, three, or two arguments. Details are in `analysis/undercover/runtime-phase8.md`. The next closed candidate calls `_CIacos`, `_CIcos`, and `_CIsin`.

## Phase 9

`tools/uc_phase9_test.py` executes that candidate. The call sites pass the argument in ST(0) and consume the result with `fstp`. `_CIsin`, `_CIcos`, and `_CIacos` replace ST(0) and do not write EAX. `0x00A11C50` and `0x00A11AF0` consume those results. The six functions under `0x00A124B0` return deterministically. A second input drops the sine and cosine calls and stores a different float. Host `sin`, `cos`, and `acos` are not claimed to match MSVCR80 bits. Details are in `analysis/undercover/runtime-phase9.md`.

## Phase 10

`tools/uc_frontier.py` classifies the high-confidence call graph. The largest closure with no missing import and no indirect call is 19 functions at `0x00B01EB0`. The largest whose only import is already implemented is 31 functions at `0x00968D10`. Both were executed. Each completing input entered 6 functions. A second input for each root takes a different path. The 102-function closure at `0x0099DCD0` is the largest set blocked only by indirect calls, and running it stops at `0x0099DCEB` on a zero `.data` slot. Filesystem, heap, timing, and `Direct3DCreate9` are not the next gate. Details are in `analysis/undercover/runtime-phase10.md`.

## Phase 11

`tools/uc_initprov.py` searches ordinary `.text` for absolute and simple register-relative writers of a global. `0x0189D1A4` has 906 indirect calls, all followed by `add esp, 0x0C`, and one writer: `0x009E8AD0` at `0x009E8B16` stores `0x009E78C0`. That leaf writes 48 other dwords the same way. Running it fills the slot. Retrying `0x0099DCD0` enters the callback and stops later at `0x009E4B49` on a zero object field (`0xFFFFFFFC`). `0x0188DAFC` was not written. `_CIsqrt` was not implemented. Details are in `analysis/undercover/runtime-phase11.md`.

## Phase 12

`0x0189DA84` is the pointer returned by `0x009E9160`, which returns the block it was given. That block is the return of `0x009EB870` and is 0x248 bytes. The call is reached only after `[0x0189DA88]` is nonzero. The only writer of `0x0189DA88` is `0x009E9410`, and its only caller is `0x00810291` inside medium-confidence `0x008101B0`, after `call 0x00686000`. That address does not disassemble as code. `0x0189D0A0` is an in-place object. The Phase 11 fault reads `[object+8] - 4` while `+8` is 0. `0x009E4640` is the ordinary store of that pointer, and the value comes from `0x009DC250`, which ends up calling `[0x0189D198]`. The Phase 11 leaf sets that slot to `0x009E77D0`, and `0x009E77D0` again needs `0x0189DA88`. Neither global was written by the harness, and `0x0099DCD0` was not retried. Details are in `analysis/undercover/runtime-phase12.md`.

## Phase 13

`0x00686000` is the target of 249 ordinary direct calls, 44 of them from high-confidence functions that the graph can reach. The calls take three stack arguments, the caller removes 12 bytes, and EAX is used as a pointer. The bytes at the address are not a function: the first instruction is `call 0xAE979FFB`, outside the image. Shifting the start by a few bytes does not find a prologue. The address is not an import thunk, not a data-table entry, and no ordinary instruction writes it. It was not replaced with `malloc`. `0x0055FF30` has four thiscall sites and the same kind of non-function bytes, without an out-of-image first instruction, so that one stays unclassified. Both object paths still stop on `0x00686000`. Details are in `analysis/undercover/runtime-phase13.md`.

## Phase 14

`0x00686000` remains unavailable and was not substituted. Of 6,498 reachable high-confidence functions, 11 must reach it, 31 can reach it, and 6,456 have no call-graph path. The 102 functions at `0x0099DCD0` are in the last set. Their executed prefix still needs an object field whose writer follows that call, so the closure stays retired as a primary frontier. `Direct3DCreate9` is one call inside medium-confidence `0x0072E340`. The span does not call the helper. The high-confidence caller `0x0072E5D0` is unreachable and only reaches the method when `[0x01311E1C]` is already 1. That dword has no absolute writer. The `.rdata` slot used before the import holds `0x008AA3AE`, an address inside `0x008A9480` rather than its entry. D3D9, TLS, and the filesystem were not implemented. Details are in `analysis/undercover/runtime-phase14.md`.

## Phase 15

`[0x01311E1C]` is a 0/1/2 synchronization dword. Absolute `mov` writers are still absent; three `xchg`-through-`ECX` sites are definite writers for values 1, 2, and 0. The value-`1` writer `0x00722D60` has no ordinary `E8` caller and no absolute pointer in allowed sections. The graphics object is the static zeroed global `0x01318170`. `[0x00B615C4]` holds `0x008AA3AE`, which is mid-instruction. `0x00766730` and `0x0072E340` grow past the function-map's 24-instruction fact walk to ordinary returns; they were not promoted. Direct3D was not implemented. Details are in `analysis/undercover/runtime-phase15.md`.

## Phase 16

The 24-instruction unreachable-candidate sketch was replaced by a CFG-aware fact walk with explicit safety budgets and termination reasons. Strong CFG-complete padding/prologue candidates were enrolled into the ordinary graph. Reachable HIGH rose from 6,597 to 22,779; CFG coverage of ordinary `.text` rose from 24% to 50%. Of the old 1,782 `insns==24` MEDIUM cohort, 1,769 promoted to HIGH. Generation 22,770/22,779, compile 22,770/22,770. The helper cut remains narrow (74 must / 139 may / 22,394 independent). `0x0072E340` is now reachable HIGH and independent of `0x00686000`, but Direct3DCreate9 is still not enterable: flag=1 writer disconnected, callback slots invalid, TLS unwitten, object zeroed. Details are in `analysis/undercover/runtime-phase16.md`.

## Status

STATIC CODE READINESS: established for the repaired ordinary high-confidence `.text` list. 22,770 of 22,779 generate, and every generated function compiles. The old 24-instruction discovery cap is gone.

RUNTIME INITIALIZATION READINESS: partial. One ordinary leaf initializes the callback slot that blocked `0x0099DCD0`. The object pointer `0x0189DA84` and the field `[0x0189D0A0+8]` have ordinary writers, and both writers depend on `0x0189DA88`. The only store to that global is after `call 0x00686000`. Phase 16 kept that call unimplemented. It is a must-hit for 74 reachable HIGH functions and a possible hit for 139 more. The other 22,394 reachable high-confidence functions do not call it.

INTEGER/STACK ABI: established for the tested paths. Cdecl `memset`, `strlen`, `memcmp`, and `strcmp` run from lifted callers, and the generated `add esp` removes the arguments. Unknown imports fail closed.

X87 CRT ABI: established in Phase 9 for `_CIsin`, `_CIcos`, and `_CIacos` as used by `0x00A124B0`. The argument and the result are ST(0). This is not bit-exact MSVCR80 math, and x87 exceptions are not modeled.

DETERMINISTIC CLUSTER EXECUTION: established. Phase 8 ran the five-function string chain. Phase 9 ran the six-function `0x00A124B0` closure twice from the same state, then once with a second input. Phase 10 ran two larger static closures; the completing paths enter 6 functions and repeat.

MAJOR NATIVE SUBSYSTEMS: future. Phase 16 puts `Direct3DCreate9` on a reachable HIGH path outside the helper cut, but it is still not enterable: the flag's value-`1` writer remains without an ordinary caller, and the pre-create callback slots are not valid entries. Filesystem, timing, TLS, and Direct3D were not implemented.

PROTECTED STARTUP: unresolved and outside this work. `Sitext` and the other protected sections are not read, executed, or rewritten.

BROWSER/WASM: future work. The Undercover image above is a native test image. It is not a browser build.

The atomic helpers remain a single-threaded stand-in. The game does not boot or run.

## Verdict

The `0x00A124B0` closure runs, and Phase 10 can enter larger ordinary closures until a zero indirect slot or a null pointer. Phase 11 shows that slot has an ordinary writer and that executing the writer moves `0x0099DCD0` past it, onto another zero object field. Phase 12 finds the ordinary store for that field and stops at `call 0x00686000`, which is not an ordinary function and is not substituted. Phase 14–16 show that call remains a narrow cut. Phase 16 repaired function discovery and put `Direct3DCreate9` on a reachable HIGH path that is still not enterable: the gate flag's value-`1` writer is ordinary code with no ordinary caller. The game is not ready to boot.
