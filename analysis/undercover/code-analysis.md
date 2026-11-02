# Undercover .text static analysis

Only the ordinary `.text` section was read. Stext, Sitext, Srdata, Sdata, Sidata, and `.securom` were not disassembled, unpacked, or followed. `tools/lift.py` was not modified. No C was written. `tools/genall.py` was not run.

- File: `C:\Games\Need For Speed Undercover\nfs.exe`
- File size: 22320400 bytes
- SHA-256 of the analyzed `.text` bytes: `5109e439e823bd3aac93bdf27f132af69b7cfef0b015f11c2f14ad9e5f4f5650`
- Range: 0x00401000 .. 0x00B603FB (7730171 bytes)
- PE entry: 0x01FCA510 in Sitext; inside `.text`: False
- IAT virtual range, from the data directory: ['0x022CD82F', '0x022CE257']
- Elapsed: 68.3 s

## 1. Linear disassembly

- Decoded instructions: 2771110
- Decoded bytes: 7693780 (99.5% of `.text`)
- Undecodable bytes: 36391 in 33497 regions
- `int3` instructions: 201104
- Instructions with an fs: or gs: memory operand: 6748

Longest undecodable regions:

- 0x009FB772: 161 bytes
- 0x00ABAC54: 79 bytes
- 0x007A91FC: 54 bytes
- 0x009A2734: 53 bytes
- 0x009FB752: 30 bytes
- 0x009FB815: 12 bytes
- 0x009FB744: 10 bytes
- 0x007B8746: 7 bytes
- 0x009A3903: 7 bytes
- 0x009FB823: 6 bytes

Instruction groups, from Capstone, over the linear sweep. A linear sweep also decodes bytes that are data, so these counts are an upper bound on real instructions.

- x87: 100385
- mmx: 8029
- sse: 112851
- sse2: 6145
- sse3_or_later: 0
- avx: 163
- 3dnow: 25

Mnemonic frequency:

| Mnemonic | Count |
| --- | --- |
| mov | 531129 |
| push | 259761 |
| int3 | 201104 |
| pop | 110858 |
| add | 104989 |
| call | 100153 |
| cmp | 83853 |
| lea | 62048 |
| test | 53805 |
| xor | 53070 |
| sub | 51998 |
| ret | 43759 |
| xchg | 43644 |
| je | 41999 |
| jmp | 40774 |
| movss | 39997 |
| dec | 39718 |
| and | 39280 |
| inc | 38150 |
| or | 37786 |
| sbb | 33550 |
| adc | 31371 |
| jne | 29914 |
| movaps | 27831 |
| fld | 23627 |
| fstp | 22157 |
| out | 19281 |
| in | 19013 |
| imul | 13809 |
| movzx | 13560 |
| jbe | 10708 |
| jl | 10626 |
| retf | 10044 |
| jle | 9836 |
| movq | 8633 |
| jge | 8538 |
| shl | 8301 |
| enter | 7752 |
| jae | 7529 |
| mulss | 7441 |

The JSON file lists all 625 mnemonics.

Privileged mnemonics (the lifter treats these as data and emits a no-op):

- out: 19281
- in: 19013
- insb: 6694
- hlt: 4957
- cli: 4932
- arpl: 4827
- sti: 4770
- iretd: 4698
- outsb: 4678
- into: 4668
- insd: 4573
- outsd: 4485
- bound: 3355
- rep insb: 30
- iret: 25
- rep outsd: 23
- sysexit: 23
- repne insd: 21
- rep insd: 20
- repne outsd: 19
- rdmsr: 19
- wbinvd: 18
- sysret: 18
- insw: 18
- invd: 17
- wrmsr: 17
- ud1: 16
- syscall: 16
- repne outsb: 15
- sysenter: 15
- outsw: 15
- rdpmc: 13
- clts: 13
- ud2: 12
- ud0: 11
- rep outsb: 11
- repne insb: 8
- lmsw: 4
- lgdt: 3
- invlpg: 2
- lidt: 2
- ltr: 2
- lldt: 2
- smsw: 1

Unusual mnemonics other than `int3` padding (`int`, `cpuid`, `rdtsc`, and the privileged set):

- out: 19281
- in: 19013
- insb: 6694
- hlt: 4957
- cli: 4932
- arpl: 4827
- sti: 4770
- int: 4742
- iretd: 4698
- outsb: 4678
- into: 4668
- insd: 4573
- outsd: 4485
- bound: 3355
- rdtsc: 691
- rep insb: 30
- cpuid: 27
- iret: 25
- rep outsd: 23
- sysexit: 23
- repne insd: 21
- rep insd: 20
- repne outsd: 19
- rdmsr: 19
- wbinvd: 18
- sysret: 18
- insw: 18
- invd: 17
- wrmsr: 17
- ud1: 16
- syscall: 16
- repne outsb: 15
- sysenter: 15
- outsw: 15
- rdpmc: 13
- clts: 13
- ud2: 12
- ud0: 11
- rep outsb: 11
- repne insb: 8
- lmsw: 4
- lgdt: 3
- invlpg: 2
- lidt: 2
- ltr: 2
- lldt: 2
- smsw: 1

## 2. Direct calls inside .text

- CALL instructions: 80889
- Target inside `.text`: 76385
- Target outside `.text`: 4504
- Unique in-`.text` targets: 13885
- Of those, on a decoded instruction boundary: 13090
- Off a boundary, not used as entries: 795

Highest incoming call counts. The full ranking is in the JSON file.

| Target | Incoming calls |
| --- | --- |
| 0x0087B350 | 3208 |
| 0x00A0AF20 | 926 |
| 0x00686030 | 799 |
| 0x0087B640 | 624 |
| 0x0087B2D6 | 597 |
| 0x00695490 | 580 |
| 0x0065AA30 | 560 |
| 0x0045E590 | 502 |
| 0x007BEB80 | 491 |
| 0x006962A0 | 462 |
| 0x0089F1F0 | 446 |
| 0x0087B6CA | 430 |
| 0x005DB160 | 429 |
| 0x00A0E2E0 | 428 |
| 0x005DAAB0 | 403 |
| 0x00A0E260 | 402 |
| 0x00A0AEC0 | 372 |
| 0x00462440 | 368 |
| 0x008040B0 | 358 |
| 0x0087B44C | 357 |
| 0x005DBB60 | 356 |
| 0x004AA010 | 353 |
| 0x0089F0B0 | 350 |
| 0x00893EA0 | 344 |
| 0x00902FFC | 321 |
| 0x00897D90 | 304 |
| 0x009B6290 | 296 |
| 0x009DD940 | 282 |
| 0x0087B6F2 | 277 |
| 0x00A11740 | 270 |
| 0x00682E00 | 260 |
| 0x00401790 | 259 |
| 0x00686000 | 249 |
| 0x0087B6A0 | 244 |
| 0x00973C70 | 244 |
| 0x009E12F0 | 233 |
| 0x0087B3E2 | 226 |
| 0x009B64E0 | 226 |
| 0x005DB940 | 222 |
| 0x00893E50 | 220 |

## 3. Direct jumps inside .text

- Direct JMP instructions: 38676
- Target inside `.text`: 34094
- Target outside `.text`: 4582
- Unique in-`.text` JMP targets: 22174
- Conditional branches and loop instructions: 191417

| JMP target | Incoming jumps |
| --- | --- |
| 0x0087B34A | 2579 |
| 0x0073B310 | 726 |
| 0x009730B0 | 278 |
| 0x00695490 | 163 |
| 0x007EDBD9 | 138 |
| 0x00401500 | 126 |
| 0x00560450 | 111 |
| 0x009B73F5 | 109 |
| 0x007F32E7 | 105 |
| 0x00463620 | 103 |
| 0x0069EDA0 | 102 |
| 0x005F8150 | 81 |
| 0x00462440 | 77 |
| 0x00520770 | 75 |
| 0x00501E80 | 68 |
| 0x009A25CD | 66 |
| 0x009ADC50 | 65 |
| 0x0064D710 | 64 |
| 0x0040E560 | 59 |
| 0x009A25B8 | 54 |

## 4. Candidate functions

A strong entry is a direct CALL target that lands on a byte the linear sweep decoded as an instruction. A `55 8B EC` sequence is recorded, and it is not an entry by itself.

- Raw `55 8B EC` occurrences: 4637
- Of those, at an instruction boundary: 4621
- Boundary prologues immediately after one or more decoded `int3` bytes: 3683
- Those padding prologues that are not direct call targets: 1238
- Strong call-target entries: 13090
- Strong entries that also begin with the MSVC prologue: 3069
- Strong entries immediately after `int3`: 10823
- `jmp [IAT]` thunks in `.text`: 0
- Of those thunks, how many are themselves direct call targets: 0

## 5. Control-flow graph from strong entries

Roots are the strong call targets only. Direct jumps and conditional branches are followed when the target is inside `.text` and on an instruction boundary. Calls do not recurse; their targets are roots of their own when they qualify. A run of three `int3` bytes ends a walk, matching `Lifter.discover`. Indirect targets are not guessed. Protected sections are not entered.

- Roots: 13090
- Roots entered: 13090
- Instructions reached: 874653
- Bytes reached: 2789584
- Direct calls that stay in `.text`: 42505
- Direct jumps that stay in `.text`: 12540
- Conditional branches that stay in `.text`: 62762
- Branches that landed off an instruction boundary: 882
- x87 / MMX / SSE-family instructions reached: 43750 / 2741 / 74706

## 6. Direct edges that leave .text

From the call-target graph. `call [IAT]` and `jmp [IAT]` are not in this table; they are imports and are counted in section 7.

| Destination | Kind | Edges |
| --- | --- | --- |
| unmapped | jmp | 52 |
| unmapped | call | 49 |
| unmapped | jcc | 2 |
| .securom | jmp | 1 |

Direct edges into Stext, Sitext, Srdata, Sdata, Sidata, or `.securom`: 1.

The same classification over the linear sweep, which also counts branches decoded from data:

| Destination | Kind | Edges |
| --- | --- | --- |
| unmapped | jmp | 4551 |
| unmapped | call | 4472 |
| unmapped | jcc | 300 |
| .data | call | 25 |
| .data | jmp | 17 |
| Stext | jmp | 8 |
| Sdata | jmp | 5 |
| Stext | call | 4 |
| .securom | call | 1 |
| .rdata | call | 1 |
| Sdata | call | 1 |
| .securom | jmp | 1 |

## 7. Indirect calls and jumps

Counts are from the linear sweep. Examples are the first few of each shape, not a listing of every site. A `base+disp` call is the shape of an MSVC vtable call when the register holds an object or a vtable; the target is not known statically. A `[index*4]` jump is the shape of a jump table; targets are recorded only when `Lifter._jt_table` accepts the block.

| Form | Count |
| --- | --- |
| call reg | 14238 |
| call [abs] | 3795 |
| call [base+disp] | 851 |
| jmp [base+disp] | 485 |
| jmp [abs] | 454 |
| jmp reg | 419 |
| jmp [index*4] | 401 |
| call [base] | 267 |
| jmp [base] | 217 |
| jmp [scaled] | 122 |
| call [scaled] | 112 |
| call [index*4] | 1 |

Calls through `[reg+disp]` whose displacement is a positive multiple of 4 and at most 0x400: 319. That is the usual shape of an MSVC vtable slot. The count is from the linear sweep, so it includes anything the sweep decoded, and it does not prove the register holds a vtable.

Reached from strong entries:

- indirect calls: 10365
- indirect jumps: 741
- `call [IAT]`: 0
- `jmp [IAT]`: 0

Examples:

- jmp reg
  - `0x004017AE: jmp ecx`
  - `0x0040456C: jmp esp`
  - `0x0041180A: jmp esi`
  - `0x0041CD9C: jmp ecx`
- call [base+disp]
  - `0x00401EEA: call dword ptr [ecx + 0x31]`
  - `0x00402306: call ptr [ecx - 0x54]`
  - `0x004052D1: call dword ptr [ebx - 0x16]`
  - `0x00405B31: call dword ptr [ebp + 0x4d]`
- call [base]
  - `0x00404439: call ptr [eax]`
  - `0x0040899E: call ptr [esi]`
  - `0x0040B440: call dword ptr [eax]`
  - `0x0040D569: call dword ptr [ebx]`
- jmp [base+disp]
  - `0x00404B16: jmp ptr [esi + 0x59a3064c]`
  - `0x00405EBA: jmp dword ptr [edx - 0x1a]`
  - `0x00406C47: jmp dword ptr [ebx + 0x2d]`
  - `0x0040739F: jmp ptr [edi + 0x4bb78c33]`
- call reg
  - `0x00406303: call ebp`
  - `0x0040B50C: call ebx`
  - `0x0040F4EA: call esi`
  - `0x004170E1: call esp`
- jmp [base]
  - `0x0040A98F: jmp dword ptr [ebx]`
  - `0x0040D5EA: jmp ptr [edi]`
  - `0x0040F717: jmp dword ptr [eax]`
  - `0x0040F9B0: jmp dword ptr [edx]`
- call [abs]
  - `0x0040D313: call ptr [0x5c313601]`
  - `0x0041D9DE: call ptr [0x782e4dc9]`
  - `0x004231B7: call dword ptr [0xbadea313]`
  - `0x00470F9F: call dword ptr [0x1013ced1]`
- call [scaled]
  - `0x004102C5: call dword ptr [edx + eax*8 + 0x3368df44]`
  - `0x0041129D: call ptr [esp + eax*4]`
  - `0x0042139D: call dword ptr [esi + ecx - 0x1b]`
  - `0x004242C9: call dword ptr [edi + edx + 0x1571dfe2]`
- jmp [scaled]
  - `0x00413021: jmp ptr [ebp + ebp*4 + 0x5d]`
  - `0x0041B4DD: jmp ptr [bp + si]`
  - `0x0042AB61: jmp ptr [esp + edx*8 - 0x55]`
  - `0x00433720: jmp dword ptr [esp + ecx*2 + 2]`
- jmp [abs]
  - `0x0041CE4F: jmp ptr [0xbeb6fb3a]`
  - `0x0042ED71: jmp ptr [0xc31a38da]`
  - `0x004495BA: jmp dword ptr [0x85f9dbd1]`
  - `0x004549AD: jmp ptr [0x6c30f32a]`
- call [index*4]
  - `0x00586514: call ptr [ecx*4 + 0x3c618538]`
- jmp [index*4]
  - `0x006DFE53: jmp dword ptr [eax*4 + 0x6dfe98]`
  - `0x006E1769: jmp dword ptr [eax*4 + 0x6e1870]`
  - `0x006E1AFC: jmp dword ptr [eax*4 + 0x6e1b28]`
  - `0x006E200A: jmp dword ptr [eax*4 + 0x6e20f8]`

## 8. Lifter coverage

lift() accepts jmp, in-range conditional branches, and loop/jecxz before insn(); other forms are decided by Lifter.insn on one instruction of each operand form. Strings are discarded.

- Distinct operand forms: 4560
- Forms accepted: 3987
- Forms rejected: 573
- Linear-sweep instructions accepted: 2697239
- Linear-sweep instructions rejected: 73871
- Reached instructions accepted: 873389
- Reached instructions rejected: 1264

Rejected mnemonics on the linear sweep:

- das: 5775
- aas: 5223
- salc: 5185
- aam: 5003
- lcall: 4954
- aad: 4926
- int1: 4857
- ljmp: 4852
- int: 4742
- iretd: 4698
- daa: 4608
- aaa: 4607
- les: 4390
- lds: 3499
- fbstp: 463
- fbld: 462
- fnstenv: 437
- fnsave: 435
- fldenv: 423
- frstor: 414
- add: 202
- sub: 194
- movmskps: 166
- mov: 161
- lock xadd: 157
- fstpnce: 122
- cmp: 111
- sbb: 97
- and: 93
- lock or: 88
- lock xor: 71
- lock add: 68
- bnd jno: 63
- lock sub: 62
- lock and: 60
- lock adc: 59
- repz ret: 46
- je: 45
- vorps: 45
- notrack jmp: 42
- pshuflw: 41
- bnd retf: 40
- lock xchg: 39
- lock sbb: 36
- bnd ret: 36
- ja: 31
- psrldq: 31
- rep insb: 30
- fyl2xp1: 29
- pmuludq: 29
- rol: 28
- bnd jmp: 27
- bnd jl: 27
- jp: 26
- iret: 25
- pshufw: 24
- bnd call: 24
- jnp: 24
- vdivps: 24
- fimul: 23
- rep outsd: 23
- sal: 22
- js: 22
- repne insd: 21
- bnd jo: 21
- bnd jb: 21
- rep insd: 20
- bnd ja: 20
- bnd jp: 20
- pslldq: 20
- repne outsd: 19
- fdisi8087_nop: 19
- bnd je: 19
- xabort: 19
- jge: 19
- cmpps: 19
- lss: 19
- bnd jns: 19
- xacquire xchg: 18
- bnd jg: 18
- sysret: 18
- cwd: 18
- psubq: 17
- bnd jne: 17
- lar: 17
- jae: 16
- bnd jbe: 16
- xrelease xchg: 16
- ud1: 16
- xbegin: 16
- rcr: 16
- jo: 16
- bnd jle: 16
- inc: 16
- bnd jnp: 16
- jbe: 16
- syscall: 16
- getsec: 16
- feni8087_nop: 15
- paddq: 15
- repne outsb: 15
- vmread: 15
- fxtract: 15
- rsm: 15
- fcom: 15
- div: 15
- jno: 15
- jg: 14
- pushaw: 14
- popaw: 14
- fsetpm: 14
- lsl: 13
- jns: 13
- bnd jecxz: 13
- jl: 13
- ud2: 12
- fmul: 12
- notrack call: 12
- jne: 12
- lock cmpxchg: 12
- ud0: 11
- bnd js: 11
- rep outsb: 11
- lfs: 10
- jb: 10
- bnd jae: 10
- bnd jge: 10
- vmwrite: 9
- punpcklqdq: 9
- movnti: 8
- lgs: 8
- repne insb: 8
- dec: 8
- lock neg: 8
- jle: 8
- punpckhqdq: 8
- lock cmpxchg8b: 8
- vcmpps: 6
- vmptrst: 6
- bndstx: 5
- vpsubsw: 5
- sldt: 5
- vsubsd: 4
- imul: 4
- bndldx: 4
- lmsw: 4
- vsqrtsd: 4
- xsaveopt: 4
- pshufd: 4
- verr: 3
- vmaxss: 3
- xor: 3
- lock dec: 3
- vsubss: 3
- vpaddq: 3
- fxsave: 3
- xrstors: 3
- vminps: 3
- maskmovq: 3
- vpminub: 3
- xchg: 2
- invlpg: 2
- rdseed: 2
- vmovntpd: 2
- vdivsd: 2
- vpavgw: 2
- vdivpd: 2
- neg: 2
- vpaddsw: 2
- prefetchwt1: 2
- vsqrtss: 2
- vpsubd: 2
- vcmpsd: 2
- andps: 2
- vmulpd: 2
- vshufps: 2
- vpunpcklqdq: 2
- sidt: 2
- vpmaddwd: 2
- vpcmpeqd: 2
- vpmulhw: 2
- vpsubq: 2
- vmaxps: 2
- fxrstor: 2
- xsaves: 2
- vpcmov: 1
- vshufpd: 1
- vfmadd231ss: 1
- fild: 1
- vpunpckhbw: 1
- vaddss: 1
- clac: 1
- vunpcklps: 1
- vunpckhpd: 1
- sha256msg2: 1
- vcmppd: 1
- xsavec: 1
- setb: 1
- vpsubusw: 1
- sha1msg2: 1
- call: 1
- bndcn: 1
- vpcmpgtw: 1
- vdivss: 1
- vpunpcklwd: 1
- vunpckhps: 1
- cmpxchg8b: 1
- vshufi32x4: 1
- vpsllq: 1
- vaddsubps: 1
- vpaddusb: 1
- kandnb: 1
- vunpcklpd: 1
- vaddpd: 1
- vpand: 1
- xacquire lock adc: 1
- vpackssdw: 1
- vpaddusw: 1
- pf2iw: 1
- vpcmpgtd: 1
- vpslld: 1
- smsw: 1
- vmptrld: 1
- vcmpgesd: 1
- vpsrld: 1
- phsubd: 1
- vsubpd: 1
- xacquire lock add: 1
- vhaddps: 1
- vpunpckhqdq: 1
- vpshldq: 1
- tzcnt: 1
- xsave: 1
- vpunpckhwd: 1
- vcvtsi2ss: 1
- vpmulhuw: 1
- vpsubsb: 1
- vhsubpd: 1
- vsqrtpd: 1
- vxorps: 1
- fistp: 1
- fadd: 1
- vsubps: 1
- vpsrad: 1
- shr: 1
- vpsrlq: 1
- vandps: 1
- vminsd: 1
- vpsraw: 1
- vmulsd: 1
- vcvtss2sd: 1
- vpinsrw: 1
- vaddps: 1
- vmulss: 1
- vpaddsb: 1
- kxnorb: 1
- vpsubb: 1
- verw: 1
- vxorpd: 1
- vpmaxsw: 1
- pmulhrw: 1
- vpmuldq: 1
- vandnps: 1
- vpavgb: 1
- vroundsd: 1
- vpermilpd: 1
- vmovlpd: 1
- sgdt: 1

Rejected mnemonics among instructions reached from strong entries:

- lock xadd: 111
- salc: 90
- lcall: 72
- aas: 67
- iretd: 66
- mov: 64
- ljmp: 62
- movmskps: 61
- aaa: 59
- das: 59
- aad: 58
- int1: 54
- int: 51
- daa: 50
- aam: 50
- les: 49
- lds: 42
- pshuflw: 40
- psrldq: 31
- pslldq: 20
- cmp: 12
- lock cmpxchg: 10
- add: 8
- fnsave: 6
- frstor: 6
- fmul: 6
- lock cmpxchg8b: 6
- fnstenv: 5
- fbstp: 4
- fbld: 4
- pshufd: 4
- sub: 4
- fstpnce: 3
- rsm: 2
- lock adc: 2
- fldenv: 2
- bnd jg: 2
- sbb: 2
- psubq: 1
- ud1: 1
- bnd jecxz: 1
- repz ret: 1
- fsetpm: 1
- bnd jno: 1
- vpaddsw: 1
- bnd jl: 1
- xrelease xchg: 1
- div: 1
- rep outsb: 1
- jae: 1
- lsl: 1
- bnd je: 1
- getsec: 1
- jnp: 1
- lock or: 1
- notrack jmp: 1
- pmulhrw: 1
- lock and: 1

## 9. NFSU2 switch patterns

`Lifter._jt_bound` looks for a block ending in `cmp r32, imm` / `ja` or `jbe`. `Lifter._jt_table` looks for `jmp dword ptr [r*4 + table]`, optionally after `movzx` from a byte table. Both were called on blocks collected from `.text`. A table is accepted only when every dword target is inside `.text`. No other targets were invented.

- `[reg*4+disp]` jumps: 401
- cmp/ja or cmp/jbe bounds: 840
- Short blocks ending in an indirect jump: 1646
- Tables the lifter accepts: 328
- Of those, two-level `movzx` tables: 122
- Bounds whose jump block was rejected: 8
- Accepted-table entries that point outside `.text`: 0

| Jump | Table | Entries | Two-level |
| --- | --- | --- | --- |
| 0x006DFE53 | 0x006DFE98 | 4 | False |
| 0x006E1769 | 0x006E1870 | 4 | False |
| 0x006E1AFC | 0x006E1B28 | 5 | False |
| 0x006E200A | 0x006E20F8 | 5 | False |
| 0x006EA078 | 0x006EA5A4 | 6 | False |
| 0x006F47E4 | 0x006F4918 | 5 | False |
| 0x006F4B97 | 0x006F4EE4 | 5 | False |
| 0x006FADA9 | 0x006FB1FC | 10 | False |
| 0x006FAE35 | 0x006FB224 | 3 | True |
| 0x006FB087 | 0x006FB23C | 3 | True |
| 0x0071A165 | 0x0071A54C | 4 | False |
| 0x0071D902 | 0x0071DA08 | 30 | False |

## 10. Feasibility

**A.** Capstone decoded 99.5% of `.text`. Of the 874653 instructions reached from strong call targets, 99.9% are accepted by the current lifter: `lift()` handles `jmp`, in-range conditional branches, and `loop`/`jecxz`, and `Lifter.insn` handles the rest. The linear sweep accepts 2697239 of 2771110 decoded instructions. The reached-code figure is the one that answers this question, because the sweep also decodes data.

**B.** 13090 high-confidence entries, with no relocation information. 3069 of them begin with `push ebp; mov ebp, esp`. 4637 raw prologue byte sequences were not treated as entries.

**C.** The graph has 42505 direct calls that stay in `.text` and 1 direct edges into protected-layout sections. Import calls are separate: 0 `call [IAT]` and 0 `jmp [IAT]` on that graph.

**D.** The concrete gaps before any code generation:

1. **The PE entry point is outside .text.** Entry 0x01FCA510 is in Sitext. tools/genall.py seeds discovery there and then stops, because the walk is limited to .text. This run did not disassemble that section.

2. **Direct edges from reached .text into protected-layout sections.** 1 direct call/jmp/jcc edges. .securom jmp: 1

3. **Lifter.insn rejects some reached instructions.** 1264 of 874653 reached instructions are unsupported. lock xadd x111, salc x90, lcall x72, aas x67, iretd x66, mov x64, ljmp x62, movmskps x61, aaa x59, das x59, aad x58, int1 x54

4. **MSVC switch pattern from tools/lift.py.** 328 jump tables match _jt_bound/_jt_table (122 of them use the movzx byte table). 401 indirect jumps have the [reg*4+disp] shape, 840 cmp/ja bounds were recorded, and 8 jmp blocks sat on a bound but were rejected. Targets were not guessed when the pattern did not match.

5. **Indirect calls and jumps have no proven targets.** Reached code has 10365 register/memory indirect calls, 741 indirect jumps, 0 call [IAT], and 0 jmp [IAT]. The lifter already lowers an indirect call to DISPATCH_CALL. It does not recover a vtable target, and a jmp [reg*4+disp] that fails the switch matcher stays indirect.

6. **.text has no absolute call or jump through the PE IAT.** The IAT directory is ['0x022CD82F', '0x022CE257'], inside the .securom address range. Absolute indirect branches at that range in the linear sweep: 0. Reached code contains 0 call [IAT] and 0 jmp [IAT]. NFSU2's import path is an absolute call or jump through an IAT slot, which runtime/win32.c rewrites. Reached indirect calls are call reg or call [mem], with no static target. If those ever reach MSVCR80 or MSVCP80, win32_call still pops nargs as if the callee were stdcall.

7. **Function discovery has call targets but no relocations.** 13090 direct-call targets land on a decoded instruction. 795 call targets are not on an instruction boundary and were not used. tools/reloc2.py still has no unnamed reloc section to read, and IMAGE_FILE_RELOCS_STRIPPED is set. Call edges replace that seed only for functions that are called directly.

8. **Prologues are evidence, not entries.** The byte sequence 55 8B EC occurs 4637 times. 4621 of those are at an instruction boundary, and 3069 of the strong call targets begin with it. 1238 boundary prologues sit after int3 padding and are not direct call targets, so they were not used as roots.

9. **The image does not fit the NFSU2 guest map.** Image base 0x00400000 matches, but SizeOfImage is 0x020A5000 (0x024A5000). runtime/heap.c treats 0x00400000..0x00932000 as the image. The .text end 0x00B603FB is already past that window.

10. **Stack commit is 4 MB.** The PE optional header, measured by tools/uc_analyze.py, asks for 0x400000 bytes of stack commit and 0x800000 reserved. The web worker stack is about 1 MB.

**E. PROTECTED STARTUP IS A FUNDAMENTAL BLOCKER**

.text is largely ordinary MSVC code and the reached body is mostly self-contained, so instruction coverage is not what blocks a port. The PE entry point 0x01FCA510 is not in .text. Adapting the lifter would translate a body the PE header does not enter. Reaching that body from the real entry means following the protected startup, which this analysis does not do.
