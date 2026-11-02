# Undercover validated function map

This map is Undercover-specific. `tools/genall.py` and the NFSU2 root list were not changed.
Protected sections were not disassembled. The PE entry point was not used.

## How a function is scored

A candidate starts at an instruction boundary from a linear sweep of `.text`. That boundary is required. Missing it rejects the candidate.

Seeds are not every direct CALL the sweep can decode. They are:

- phase 3 functions that generated and compiled
- `55 8B EC` at a boundary whose preceding byte is `int3`

From a function classified HIGH or MEDIUM the walk follows a CFG worklist:

- ordinary direct conditional branches
- ordinary direct unconditional branches that stay inside the function
- a direct `jmp` whose target already looks like an entry becomes a tail transfer
- a direct `call` is recorded; the callee is not absorbed
- targets of a switch table recognized by the same bounds the lifter uses

Function termination is decided from control flow (ret, tail transfer, import jump), not from a tiny linear instruction count. Safety budgets still exist (16384 instructions / 4096 blocks / 262144 byte span) and report `CFG_BUDGET_EXCEEDED` instead of silently truncating.

Optimized MSVC code often omits `55 8B EC`. A frame pointer adds points. It is not required.

| Evidence | Points |
| --- | --- |
| On a linear-sweep instruction boundary | +20, required |
| Called or tail-called from a HIGH or MEDIUM function | +25 |
| MSVC frame prologue | +25 |
| Stack setup without a frame pointer | +12 |
| Preceded by int3 padding | +15 |
| Internal branches stay on boundaries | +15 |
| Ends in near ret (including `repz ret`), a tail jmp, or `jmp [abs]` | +15 |
| Stack traffic | +8 |
| Calls another HIGH or MEDIUM function | +10 |
| Recognized switch table | +10 |
| Decoded bytes cover at least 85% of the span | +10 |
| A branch leaves the instruction stream | -20 |
| Privileged opcodes are common in the body | -40 |
| Far call or jump | -35 |
| BCD opcode | -30 |
| `les` or `lds` | -30 |
| Repeated rare legacy opcodes | -25 |
| Three or more undecodable gaps | -25 |
| CFG safety budget exceeded | -10 |

Labels: HIGH at 60 or more with a terminator and no bad branch; MEDIUM at 40 or more; LOW at 20 or more; otherwise REJECTED_DATA_LIKE. An illegal first instruction is rejected before the points are added. Tail transfers and multiple returns are valid terminators.

After scoring, HIGH and MEDIUM functions are checked with the lifter's own control-flow walk. If that walk reaches `aad`, `aaa`, `salc`, `ljmp`, `fstpnce`, or another opcode in the same data class, the function is reclassified REJECTED_DATA_LIKE. The opcode is not added to the lifter. Phase 5 rejected 344 functions this way.

## Phase 16 discovery repair

Phase 15 found that unreachable candidates were scored with a 24-instruction linear sketch. Phase 16 replaces that with the CFG walker above, then enrolls CFG-complete strong entries (14868 enrolled this run) into the ordinary graph.

| | Prior map | Phase 16 |
| --- | --- | --- |
| HIGH_CONFIDENCE | 6,597 | 22779 |
| MEDIUM_CONFIDENCE | 50 | 165 |
| LOW_CONFIDENCE | 20 | 54 |
| REJECTED_DATA_LIKE | 514 | 1454 |
| CFG-covered bytes | 1,851,810 | 3864703 |

## Counts

- Seeds: 3751
- Reachable entries walked: 24452
- HIGH_CONFIDENCE: 22779
- MEDIUM_CONFIDENCE: 165
- LOW_CONFIDENCE: 54
- REJECTED_DATA_LIKE among walked entries: 1454
- CFG budget exceeded among walked entries: 72
- Strong CFG candidates enrolled: 14868
- Unreachable prologue or padding candidates: 998
- CFG sketch of those candidates, not generated: 0 score like HIGH, 511 like MEDIUM, 452 like LOW, 35 like REJECTED_DATA_LIKE
- CFG coverage of `.text`: 3864703 / 7730171 bytes (50.0%)

Coverage counts bytes of instructions that belong to a reachable HIGH or MEDIUM function, including its switch targets. LOW and rejected entries do not add coverage.

An unreachable candidate is a frame prologue, or the first instruction after a run of at least four `int3` bytes, that the ordinary graph never entered and that is not already inside a walked body. Those remaining addresses were not enrolled. `function-map.json` stores the first 5000 of them.

## Termination

| Termination | Count |
| --- | --- |
| `RET_REACHED` | 16415 |
| `MULTIPLE_RETURNS` | 4489 |
| `TAIL_TRANSFER` | 2200 |
| `DECODE_FAILURE` | 685 |
| `EXTERNAL_BOUNDARY` | 26 |
| `OVERLAP_CONFLICT` | 40 |
| `CFG_BUDGET_EXCEEDED` | 72 |
| `NO_TERMINATOR` | 206 |
| `UNKNOWN` | 319 |

## Examples

### HIGH_CONFIDENCE

| Function | Score | Insns | Termination | Why |
| --- | --- | --- | --- | --- |
| 0x004072B0 | 85 | 7 | RET_REACHED | instruction boundary; referenced from a validated function; internal branches land on instruction boundaries |
| 0x0045D5E0 | 105 | 13 | RET_REACHED | instruction boundary; referenced from a validated function; stack operation without requiring a frame pointer |
| 0x0045F160 | 85 | 1 | RET_REACHED | instruction boundary; referenced from a validated function; internal branches land on instruction boundaries |
| 0x005472F0 | 85 | 1 | RET_REACHED | instruction boundary; referenced from a validated function; internal branches land on instruction boundaries |
| 0x005CAED0 | 105 | 9 | RET_REACHED | instruction boundary; referenced from a validated function; stack operation without requiring a frame pointer |
| 0x005D87E0 | 105 | 9 | RET_REACHED | instruction boundary; referenced from a validated function; stack operation without requiring a frame pointer |
| 0x005E8BF0 | 85 | 1 | RET_REACHED | instruction boundary; referenced from a validated function; internal branches land on instruction boundaries |
| 0x00625E20 | 85 | 3 | RET_REACHED | instruction boundary; referenced from a validated function; internal branches land on instruction boundaries |
| 0x0064B910 | 105 | 3 | RET_REACHED | instruction boundary; referenced from a validated function; stack operation without requiring a frame pointer |
| 0x0064D000 | 105 | 3 | RET_REACHED | instruction boundary; referenced from a validated function; stack operation without requiring a frame pointer |
| 0x0064D900 | 105 | 3 | RET_REACHED | instruction boundary; referenced from a validated function; stack operation without requiring a frame pointer |
| 0x0064DA80 | 105 | 3 | RET_REACHED | instruction boundary; referenced from a validated function; stack operation without requiring a frame pointer |

22767 more are in `function-map.json`.

### MEDIUM_CONFIDENCE

| Function | Score | Insns | Termination | Why |
| --- | --- | --- | --- | --- |
| 0x0040D910 | 70 | 1 | DECODE_FAILURE | instruction boundary; referenced from a validated function; internal branches land on instruction boundaries |
| 0x004503A0 | 70 | 1 | DECODE_FAILURE | instruction boundary; referenced from a validated function; internal branches land on instruction boundaries |
| 0x00451CB0 | 90 | 2 | DECODE_FAILURE | instruction boundary; referenced from a validated function; stack operation without requiring a frame pointer |
| 0x00453EF0 | 70 | 3 | DECODE_FAILURE | instruction boundary; referenced from a validated function; internal branches land on instruction boundaries |
| 0x0045B370 | 50 | 4 | DECODE_FAILURE | instruction boundary; referenced from a validated function; stack operation without requiring a frame pointer |
| 0x0045CC30 | 70 | 4 | DECODE_FAILURE | instruction boundary; referenced from a validated function; internal branches land on instruction boundaries |
| 0x00499AE0 | 70 | 5 | DECODE_FAILURE | instruction boundary; referenced from a validated function; internal branches land on instruction boundaries |
| 0x004A2C20 | 55 | 4 | DECODE_FAILURE | instruction boundary; referenced from a validated function; stack operation without requiring a frame pointer |
| 0x004A9310 | 60 | 7 | RET_REACHED | instruction boundary; referenced from a validated function; stack operation without requiring a frame pointer |
| 0x004A9590 | 70 | 2 | DECODE_FAILURE | instruction boundary; referenced from a validated function; internal branches land on instruction boundaries |
| 0x004AA3F0 | 90 | 7 | DECODE_FAILURE | instruction boundary; referenced from a validated function; stack operation without requiring a frame pointer |
| 0x004AA690 | 70 | 3 | DECODE_FAILURE | instruction boundary; referenced from a validated function; internal branches land on instruction boundaries |

153 more are in `function-map.json`.

### LOW_CONFIDENCE

| Function | Score | Insns | Termination | Why |
| --- | --- | --- | --- | --- |
| 0x004014E0 | 55 | 16 | OVERLAP_CONFLICT | instruction boundary; referenced from a validated function; stack operation without requiring a frame pointer |
| 0x0045AAD0 | 35 | 3 | DECODE_FAILURE | instruction boundary; referenced from a validated function; branch misses the instruction stream or enters embedded data |
| 0x0045B440 | 35 | 1 | EXTERNAL_BOUNDARY | instruction boundary; referenced from a validated function; branch misses the instruction stream or enters embedded data |
| 0x0045E220 | 30 | 3 | NO_TERMINATOR | instruction boundary; referenced from a validated function; internal branches land on instruction boundaries |
| 0x00487600 | 35 | 1 | NO_TERMINATOR | instruction boundary; referenced from a validated function; branch misses the instruction stream or enters embedded data |
| 0x00499CA0 | 35 | 1 | EXTERNAL_BOUNDARY | instruction boundary; referenced from a validated function; branch misses the instruction stream or enters embedded data |
| 0x004A87D0 | 55 | 13 | NO_TERMINATOR | instruction boundary; referenced from a validated function; stack operation without requiring a frame pointer |
| 0x004ACEB0 | 35 | 1 | EXTERNAL_BOUNDARY | instruction boundary; referenced from a validated function; branch misses the instruction stream or enters embedded data |
| 0x004B5040 | 35 | 1 | EXTERNAL_BOUNDARY | instruction boundary; referenced from a validated function; branch misses the instruction stream or enters embedded data |
| 0x004DA940 | 30 | 3 | DECODE_FAILURE | instruction boundary; referenced from a validated function; internal branches land on instruction boundaries |
| 0x00502250 | 30 | 2 | NO_TERMINATOR | instruction boundary; referenced from a validated function; internal branches land on instruction boundaries |
| 0x0050EE40 | 50 | 15 | RET_REACHED | instruction boundary; referenced from a validated function; branch misses the instruction stream or enters embedded data |

42 more are in `function-map.json`.

### REJECTED_DATA_LIKE

| Function | Score | Insns | Termination | Why |
| --- | --- | --- | --- | --- |
| 0x00401030 | -10 | 33 | NO_TERMINATOR | instruction boundary; stack operation without requiring a frame pointer; branch misses the instruction stream or enters embedded data |
| 0x00401070 | 0 | 0 | DECODE_FAILURE | call or jump target is not on an instruction boundary |
| 0x00401090 | 0 | 0 |  | call or jump target is not on an instruction boundary |
| 0x004010A0 | 10 | 14 | OVERLAP_CONFLICT | instruction boundary; branch misses the instruction stream or enters embedded data; high density of decoded bytes |
| 0x004010B0 | 0 | 0 | DECODE_FAILURE | call or jump target is not on an instruction boundary |
| 0x004010C0 | 0 | 0 | DECODE_FAILURE | call or jump target is not on an instruction boundary |
| 0x004010D0 | 0 | 1 | DECODE_FAILURE | first instruction is not ordinary application code |
| 0x004010F0 | 0 | 0 | DECODE_FAILURE | call or jump target is not on an instruction boundary |
| 0x00401100 | 0 | 0 |  | call or jump target is not on an instruction boundary |
| 0x00401110 | -10 | 26 | DECODE_FAILURE | instruction boundary; stack operation without requiring a frame pointer; branch misses the instruction stream or enters embedded data |
| 0x00401160 | 0 | 0 |  | call or jump target is not on an instruction boundary |
| 0x00401230 | 0 | 0 | DECODE_FAILURE | call or jump target is not on an instruction boundary |

1442 more are in `function-map.json`.
