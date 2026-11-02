# Undercover recompilation feasibility

Sample of `.text` roots taken from the phase 3 address list. The PE entry point was not used. Protected sections were not disassembled or followed. This is the phase 4 rerun of the same 100 addresses. `repz ret` and `movmskps` are lowered. The linear-sweep list of 13,090 roots is not generated from this mode. Generated C was compiled and was not committed.

- Input: `C:\Games\Need For Speed Undercover\nfs.exe`
- `.text`: 0x00401000 .. 0x00B603FA (7730171 bytes)
- Clang: `C:\Program Files\Unity\Hub\Editor\6000.6.7f1\Editor\Data\PlaybackEngines\WebGLSupport\BuildTools\Emscripten\llvm\clang.exe`
- Elapsed: 20s

## Sample

- Functions attempted: 100
- Functions generated: 86
- Generation failures: 14
- Functions compiled: 86
- Compiler failures: 0
- Generated source size: 3954090 bytes
- Unresolved direct edges leaving `.text`: 15
- Of those, into a protected section: 0
- Unresolved indirect calls: 230
- Recognized switch tables: 20
- Rejected `[reg*4]` jumps: 1
- Direct calls that stay in `.text`: 1703
- Privileged instructions inside these CFGs (the lifter comments them out; they are not counted as translated): 110
- Return forms in the linear sweep of `.text`: not re-counted on this rerun. The phase 3 sweep counted `ret` 43759 and `repz ret` 46 (`phase3-baseline.md`)

Categories (a function may be in more than one):

- fill: 9
- highly-called: 15
- indirect: 12
- large: 12
- medium: 12
- required: 3
- small: 12
- sse: 12
- switch: 12
- x87: 12

| Function | Insns | In | Categories | Generated | Compiled |
| --- | --- | --- | --- | --- | --- |
| 0x00401030 | 47 | 5 | fill | yes | yes |
| 0x004010A0 | 75 | 2 | medium, fill | yes | yes |
| 0x004010D0 | 7 | 2 | small | yes | yes |
| 0x00401110 | 45 | 4 | fill | yes | yes |
| 0x00401250 | 41 | 2 | fill | no | no |
| 0x004012A0 | 33 | 1 | fill | no | no |
| 0x004014E0 | 108 | 1 | fill | no | no |
| 0x00401510 | 79 | 8 | fill | no | no |
| 0x00401570 | 117 | 1 | fill | no | no |
| 0x00401FD0 | 29 | 4 | fill | no | no |
| 0x004A91F0 | 213 | 6 | indirect | no | no |
| 0x005DAAB0 | 94 | 403 | highly-called | no | no |
| 0x0065AA30 | 161 | 560 | highly-called | no | no |
| 0x00686030 | 2 | 799 | required, highly-called | yes | yes |
| 0x00695490 | 139 | 580 | highly-called | no | no |
| 0x006962A0 | 93 | 462 | highly-called | no | no |
| 0x006DFE00 | 42 | 2 | switch | yes | yes |
| 0x006E0010 | 16 | 5 | small | yes | yes |
| 0x006E4560 | 1197 | 1 | sse | yes | yes |
| 0x006ED410 | 1832 | 1 | sse | yes | yes |
| 0x006F7040 | 1502 | 2 | sse | yes | yes |
| 0x007286C0 | 56 | 1 | medium | yes | yes |
| 0x00732B70 | 74 | 2 | indirect | yes | yes |
| 0x00772800 | 77 | 4 | medium | no | no |
| 0x00777B20 | 45 | 1 | switch | yes | yes |
| 0x00783BB0 | 15 | 3 | small | no | no |
| 0x007A6B50 | 212 | 1 | indirect | yes | yes |
| 0x007BEB80 | 32 | 491 | highly-called | yes | yes |
| 0x007C6C90 | 56 | 6 | medium | no | no |
| 0x007D5AE0 | 88 | 2 | switch | yes | yes |
| 0x007EF1D0 | 6097 | 1 | large | yes | yes |
| 0x00813B90 | 13 | 1 | small | yes | yes |
| 0x0081A840 | 63 | 1 | switch | yes | yes |
| 0x00828A70 | 1918 | 1 | sse | yes | yes |
| 0x0082CEC0 | 127 | 4 | medium | yes | yes |
| 0x0082E2F0 | 1350 | 1 | sse | yes | yes |
| 0x00839D00 | 2215 | 3 | large, sse | yes | yes |
| 0x008433C0 | 2073 | 4 | large | yes | yes |
| 0x0084B050 | 2232 | 2 | large | yes | yes |
| 0x0085FFE0 | 271 | 1 | switch | yes | yes |
| 0x00875110 | 57 | 1 | indirect | yes | yes |
| 0x0087B2D6 | 1 | 597 | highly-called | yes | yes |
| 0x0087B350 | 63 | 3208 | required, highly-called | yes | yes |
| 0x0087B640 | 8 | 624 | highly-called | yes | yes |
| 0x0087B6CA | 1 | 430 | highly-called | yes | yes |
| 0x00880EC1 | 12 | 5 | small | yes | yes |
| 0x0088F4F0 | 128 | 3 | medium | yes | yes |
| 0x0089F1F0 | 163 | 446 | highly-called | yes | yes |
| 0x008B2D30 | 80 | 3 | indirect | yes | yes |
| 0x008D18D0 | 67 | 3 | medium | yes | yes |
| 0x008E6D70 | 280 | 1 | switch | yes | yes |
| 0x008E7490 | 103 | 1 | indirect | yes | yes |
| 0x009035B2 | 2 | 13 | small | yes | yes |
| 0x00907D17 | 73 | 10 | medium | yes | yes |
| 0x00913470 | 355 | 2 | indirect | yes | yes |
| 0x0091B870 | 1294 | 3 | x87 | yes | yes |
| 0x0091CD10 | 4161 | 1 | large, x87 | yes | yes |
| 0x0091EC60 | 1259 | 3 | x87 | yes | yes |
| 0x00921500 | 1261 | 1 | x87 | yes | yes |
| 0x00921DF0 | 1303 | 1 | x87 | yes | yes |
| 0x00927330 | 2123 | 1 | large, sse | yes | yes |
| 0x009282A0 | 2142 | 1 | large, sse | yes | yes |
| 0x009327C0 | 973 | 1 | x87 | yes | yes |
| 0x00936F30 | 658 | 3 | x87 | yes | yes |
| 0x00938980 | 1000 | 4 | x87 | yes | yes |
| 0x00947B10 | 801 | 2 | x87 | yes | yes |
| 0x0095AAF0 | 974 | 1 | x87 | yes | yes |
| 0x00965B30 | 974 | 1 | x87 | yes | yes |
| 0x00973D30 | 63 | 1 | medium | yes | yes |
| 0x0097B290 | 3 | 8 | small | yes | yes |
| 0x009829D0 | 8 | 1 | switch | yes | yes |
| 0x0099C7B0 | 24 | 1 | indirect | yes | yes |
| 0x009CE0F0 | 136 | 1 | medium | yes | yes |
| 0x009CF020 | 210 | 2 | indirect | yes | yes |
| 0x009D0E90 | 14 | 1 | small | yes | yes |
| 0x009E1960 | 14 | 1 | small | yes | yes |
| 0x009F9550 | 680 | 2 | switch | yes | yes |
| 0x009FDDD0 | 14 | 3 | small | yes | yes |
| 0x00A071F0 | 74 | 1 | indirect | yes | yes |
| 0x00A0AEC0 | 35 | 372 | highly-called | yes | yes |
| 0x00A0AF20 | 44 | 926 | required, highly-called | yes | yes |
| 0x00A0BFB0 | 97 | 1 | medium | yes | yes |
| 0x00A0E260 | 58 | 402 | highly-called | yes | yes |
| 0x00A0E2E0 | 87 | 428 | highly-called | yes | yes |
| 0x00A16F40 | 63 | 13 | switch | yes | yes |
| 0x00A23B60 | 2234 | 3 | large, x87 | yes | yes |
| 0x00A3D120 | 6 | 2 | small | yes | yes |
| 0x00A50D10 | 15 | 3 | indirect | yes | yes |
| 0x00A7C1D0 | 1211 | 4 | switch | yes | yes |
| 0x00A92B20 | 2075 | 3 | large | yes | yes |
| 0x00AA3420 | 248 | 6 | switch | yes | yes |
| 0x00AA4950 | 78 | 3 | medium | yes | yes |
| 0x00ABCED0 | 44 | 2 | indirect | yes | yes |
| 0x00ABD490 | 2948 | 7 | large | yes | yes |
| 0x00AC6D60 | 2 | 1 | small | yes | yes |
| 0x00AD1D70 | 47 | 2 | switch | yes | yes |
| 0x00B02690 | 2945 | 3 | large, sse | yes | yes |
| 0x00B070C0 | 2990 | 1 | large, sse | yes | yes |
| 0x00B09310 | 1568 | 15 | sse | yes | yes |
| 0x00B13EF0 | 1855 | 3 | sse | yes | yes |

## Unsupported instructions

- `aaa`: 3
- `das`: 3
- `lcall`: 3
- `les`: 2
- `iretd`: 1
- `aad`: 1
- `ljmp`: 1

Instruction-level records are in `generation-failures.md`.

Genuine unsupported instructions in compiler-shaped functions: 0. Rejected likely-data roots: 14. Other generation failures: 0.

Likely-data roots (the failing opcode is not treated as a missing lifter feature):

- 0x00401250: `aaa`
- 0x004012A0: `les`
- 0x004014E0: `das`
- 0x00401510: `das`
- 0x00401570: `iretd`
- 0x00401FD0: `aad`
- 0x004A91F0: `aaa`
- 0x005DAAB0: `lcall`
- 0x0065AA30: `lcall`
- 0x00695490: `ljmp`
- 0x006962A0: `lcall`
- 0x00772800: `das`
- 0x00783BB0: `aaa`
- 0x007C6C90: `les`

`aaa`, `das`, `les`, `lcall`, `ljmp`, `iretd`, and `aad` occur in targets whose first bytes are not a compiler prologue. Those targets stay generation failures. They are not evidence that the lifter lacks those opcodes.

## Calling conventions

Sites are classified from the instruction shape only. A direct call inside `.text` has no symbol, so its convention stays unknown. `likely-thiscall` means a vtable-shaped `call [reg+4*n]` or a `call reg` whose preceding instructions write `ecx`. `possible-fastcall` means the preceding instructions write both `ecx` and `edx`. Neither is proof. No absolute call through the PE IAT was required for this classification.

- import-thunk: 101
- likely-thiscall: 8
- possible-fastcall: 134
- unknown: 1690

The NFSU2 runtime's `win32_call` always pops `4 * nargs` after an import, which is stdcall. Undercover imports MSVCR80 and MSVCP80, which are cdecl. This `.text` sample does not contain the absolute `call [IAT]` form that runtime rewrites, so that mismatch is not yet attached to a concrete call site. It still has to be fixed before any import in those DLLs can be called. `cpu.h` sizes its fast dispatch table for the NFSU2 `.text` span (`DISPATCH_TEXT_SIZE`), which ends before this image's `.text`.

## Control flow outside .text

| Section | Kind | Edges |
| --- | --- | --- |
| unmapped | jmp | 15 |

These were emitted as an indirect dispatch or as `unsupported_insn(..., "branch-out")` for a conditional branch. They were not followed.
## Verdict

The phase 3 sample addresses that failed on `repz ret` or `movmskps` are no longer refused for those opcodes. Remaining refusals, if any, are recorded above and are not rewritten into successes. A full translation uses the validated function graph, not every linear-sweep call target.

SAMPLE UNBLOCKED
