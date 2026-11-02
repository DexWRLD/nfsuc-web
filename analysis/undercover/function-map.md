# Undercover validated function map

This map is Undercover-specific. `tools/genall.py` and the NFSU2 root list were not changed.
Protected sections were not disassembled. The PE entry point was not used.

## How a function is scored

A candidate starts at an instruction boundary from a linear sweep of `.text`. That boundary is required. Missing it rejects the candidate.

Seeds are not every direct CALL the sweep can decode. They are:

- phase 3 functions that generated and compiled
- `55 8B EC` at a boundary whose preceding byte is `int3`

From a function classified HIGH or MEDIUM the walk follows:

- a direct `call` whose target is inside `.text`
- a direct `jmp` whose target already looks like an entry (frame prologue, int3 padding, or an existing entry)
- targets of a switch table recognized by the same bounds the lifter uses

A direct `jmp` to any other in-range address stays inside the function. Switch targets stay inside the function. A call into a target whose first instruction is privileged, far, BCD, `les`/`lds`, or another rare legacy opcode is rejected and is not expanded.

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

Labels: HIGH at 60 or more with a terminator and no bad branch; MEDIUM at 40 or more; LOW at 20 or more; otherwise REJECTED_DATA_LIKE. An illegal first instruction is rejected before the points are added.

## Counts

- Seeds: 3751
- Reachable entries walked: 7181
- HIGH_CONFIDENCE: 6604
- MEDIUM_CONFIDENCE: 79
- LOW_CONFIDENCE: 20
- REJECTED_DATA_LIKE among walked entries: 478
- Unreachable prologue or padding candidates: 15755
- Short-window sketch of those candidates, not a second graph and not generated: 11710 score like HIGH, 4045 like MEDIUM, 0 like LOW, 0 like REJECTED_DATA_LIKE
- CFG coverage of `.text`: 1853801 / 7730171 bytes (24.0%)

Coverage counts bytes of instructions that belong to a reachable HIGH or MEDIUM function, including its switch targets. LOW and rejected entries do not add coverage.

An unreachable candidate is a frame prologue, or the first instruction after a run of at least four `int3` bytes, that the direct-call walk never entered and that is not already inside a walked body. The short window is only a sketch. Those addresses were not generated. `function-map.json` stores the first 5000 of them.

## Examples

### HIGH_CONFIDENCE

| Function | Score | Insns | Why |
| --- | --- | --- | --- |
| 0x00401DC0 | 85 | 3 | instruction boundary; referenced from a validated function; internal branches land on instruction boundaries |
| 0x0045D5E0 | 105 | 13 | instruction boundary; referenced from a validated function; stack operation without requiring a frame pointer |
| 0x0045F160 | 85 | 1 | instruction boundary; referenced from a validated function; internal branches land on instruction boundaries |
| 0x004A7520 | 80 | 16 | instruction boundary; referenced from a validated function; stack operation without requiring a frame pointer |
| 0x005CAED0 | 105 | 9 | instruction boundary; referenced from a validated function; stack operation without requiring a frame pointer |
| 0x005D87E0 | 105 | 9 | instruction boundary; referenced from a validated function; stack operation without requiring a frame pointer |
| 0x0065BF10 | 85 | 2 | instruction boundary; referenced from a validated function; internal branches land on instruction boundaries |
| 0x006B07F0 | 85 | 6 | instruction boundary; referenced from a validated function; internal branches land on instruction boundaries |
| 0x006B0A80 | 85 | 1 | instruction boundary; referenced from a validated function; internal branches land on instruction boundaries |
| 0x006DD7C0 | 118 | 61 | instruction boundary; MSVC frame prologue; preceded by int3 padding |
| 0x006DE410 | 118 | 98 | instruction boundary; MSVC frame prologue; preceded by int3 padding |
| 0x006DFE00 | 85 | 42 | instruction boundary; preceded by int3 padding; internal branches land on instruction boundaries |

6592 more are in `function-map.json`.

### MEDIUM_CONFIDENCE

| Function | Score | Insns | Why |
| --- | --- | --- | --- |
| 0x00451CB0 | 90 | 2 | instruction boundary; referenced from a validated function; stack operation without requiring a frame pointer |
| 0x00453EF0 | 70 | 3 | instruction boundary; referenced from a validated function; internal branches land on instruction boundaries |
| 0x0045CC30 | 70 | 4 | instruction boundary; referenced from a validated function; internal branches land on instruction boundaries |
| 0x004A2C20 | 55 | 4 | instruction boundary; referenced from a validated function; stack operation without requiring a frame pointer |
| 0x004A9010 | 55 | 29 | instruction boundary; referenced from a validated function; stack operation without requiring a frame pointer |
| 0x004A9310 | 60 | 7 | instruction boundary; referenced from a validated function; stack operation without requiring a frame pointer |
| 0x004AA3F0 | 90 | 7 | instruction boundary; referenced from a validated function; stack operation without requiring a frame pointer |
| 0x004AA690 | 70 | 3 | instruction boundary; referenced from a validated function; internal branches land on instruction boundaries |
| 0x00521410 | 55 | 4 | instruction boundary; referenced from a validated function; stack operation without requiring a frame pointer |
| 0x005217A0 | 90 | 7 | instruction boundary; referenced from a validated function; stack operation without requiring a frame pointer |
| 0x005247B0 | 55 | 38 | instruction boundary; referenced from a validated function; stack operation without requiring a frame pointer |
| 0x005258D0 | 50 | 2 | instruction boundary; referenced from a validated function; stack operation without requiring a frame pointer |

67 more are in `function-map.json`.

### LOW_CONFIDENCE

| Function | Score | Insns | Why |
| --- | --- | --- | --- |
| 0x004A87D0 | 55 | 13 | instruction boundary; referenced from a validated function; stack operation without requiring a frame pointer |
| 0x004ACEB0 | 35 | 1 | instruction boundary; referenced from a validated function; branch misses the instruction stream or enters embedded data |
| 0x00502250 | 30 | 2 | instruction boundary; referenced from a validated function; internal branches land on instruction boundaries |
| 0x00521080 | 35 | 5 | instruction boundary; referenced from a validated function; branch misses the instruction stream or enters embedded data |
| 0x00523C80 | 45 | 34 | instruction boundary; referenced from a validated function; stack operation without requiring a frame pointer |
| 0x005D8DD0 | 35 | 6 | instruction boundary; referenced from a validated function; branch misses the instruction stream or enters embedded data |
| 0x005DAAB0 | 35 | 5 | instruction boundary; referenced from a validated function; branch misses the instruction stream or enters embedded data |
| 0x005DBB60 | 70 | 70 | instruction boundary; referenced from a validated function; stack operation without requiring a frame pointer |
| 0x005DBBB0 | 70 | 41 | instruction boundary; referenced from a validated function; stack operation without requiring a frame pointer |
| 0x00682E00 | 35 | 10 | instruction boundary; referenced from a validated function; branch misses the instruction stream or enters embedded data |
| 0x00686000 | 35 | 3 | instruction boundary; referenced from a validated function; branch misses the instruction stream or enters embedded data |
| 0x00686EB0 | 35 | 1 | instruction boundary; referenced from a validated function; branch misses the instruction stream or enters embedded data |

8 more are in `function-map.json`.

### REJECTED_DATA_LIKE

| Function | Score | Insns | Why |
| --- | --- | --- | --- |
| 0x00401030 | -10 | 33 | instruction boundary; stack operation without requiring a frame pointer; branch misses the instruction stream or enters embedded data |
| 0x00401090 | 0 | 0 | call or jump target is not on an instruction boundary |
| 0x004010A0 | -30 | 21 | instruction boundary; branch misses the instruction stream or enters embedded data; high density of decoded bytes |
| 0x004010D0 | 0 | 1 | first instruction is not ordinary application code |
| 0x00401100 | 0 | 0 | call or jump target is not on an instruction boundary |
| 0x00401110 | -10 | 26 | instruction boundary; stack operation without requiring a frame pointer; branch misses the instruction stream or enters embedded data |
| 0x00401160 | 0 | 0 | call or jump target is not on an instruction boundary |
| 0x004012A0 | 10 | 11 | instruction boundary; referenced from a validated function; branch misses the instruction stream or enters embedded data |
| 0x004012C0 | 0 | 0 | call or jump target is not on an instruction boundary |
| 0x004013A0 | 0 | 0 | call or jump target is not on an instruction boundary |
| 0x004013D0 | 0 | 0 | call or jump target is not on an instruction boundary |
| 0x00401440 | 0 | 0 | call or jump target is not on an instruction boundary |

466 more are in `function-map.json`.
