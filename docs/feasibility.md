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

## Verdict

ADAPT LIFTER FURTHER
