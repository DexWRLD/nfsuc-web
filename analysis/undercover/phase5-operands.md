# Phase 5 operand catalog

Every site below is inside the lifter control flow of a Phase 4 HIGH_CONFIDENCE function that failed to generate. The bytes are ordinary `.text`. Protected sections were not read.

`lock xadd`, `lock cmpxchg`, and `lock cmpxchg8b` occur only as 32-bit memory destinations, or as `qword ptr` for `cmpxchg8b`. The LOCK prefix is present on every one of them. No 8-bit or 16-bit form appears in this set. The lifter still accepts those widths so the implementation is not tied to these addresses.

`psrldq` and `pslldq` are immediate byte shifts of one XMM register. `punpcklqdq` and `punpckhqdq` are register, register. The `pshufd` sites read memory and use immediate `0xE4`. `pshuflw` is register, register, immediate `0xF9`. Those two showed up only after the earlier instruction in the same function could be lifted.

`aad`, `aaa`, `salc`, `ljmp`, and `fstpnce` are not implemented. See the decision at the end.

## Forms

| Count | Instruction | Operand size | Operands | LOCK |
| --- | --- | --- | --- | --- |
| 48 | `lock xadd` | 4 | `dword ptr [ecx], eax` | yes |
| 32 | `lock xadd` | 4 | `dword ptr [edx], eax` | yes |
| 24 | `pshuflw` | 16 | `xmm5, xmm5, 0xf9` | no |
| 15 | `pslldq` | 16 | `xmm5, 2` | no |
| 11 | `lock xadd` | 4 | `dword ptr [esi], eax` | yes |
| 11 | `psrldq` | 16 | `xmm5, 2` | no |
| 10 | `lock cmpxchg8b` | 8 | `qword ptr [esi]` | yes |
| 8 | `psrldq` | 16 | `xmm4, 1` | no |
| 7 | `lock xadd` | 4 | `dword ptr [eax], ecx` | yes |
| 5 | `lock xadd` | 4 | `dword ptr [ecx], edx` | yes |
| 4 | `psrldq` | 16 | `xmm5, 1` | no |
| 4 | `psrldq` | 16 | `xmm3, 2` | no |
| 4 | `psrldq` | 16 | `xmm4, 2` | no |
| 4 | `pslldq` | 16 | `xmm6, 2` | no |
| 4 | `pshuflw` | 16 | `xmm4, xmm4, 0xf9` | no |
| 4 | `pshuflw` | 16 | `xmm6, xmm6, 0xf9` | no |
| 3 | `salc` | 0 | `` | no |
| 3 | `lock xadd` | 4 | `dword ptr [eax], ebp` | yes |
| 3 | `ljmp` | 2 | `0x7c4:0xa1538f2f` | no |
| 3 | `lock xadd` | 4 | `dword ptr [edx], ecx` | yes |
| 3 | `lock cmpxchg` | 4 | `dword ptr [edi], esi` | yes |
| 3 | `lock cmpxchg` | 4 | `dword ptr [edx], ecx` | yes |
| 3 | `pshuflw` | 16 | `xmm3, xmm3, 0xf9` | no |
| 2 | `lock xadd` | 4 | `dword ptr [esi], edx` | yes |
| 2 | `lock xadd` | 4 | `dword ptr [eax], esi` | yes |
| 2 | `aaa` | 0 | `` | no |
| 2 | `pshufd` | 16 | `xmm0, xmmword ptr [esi], 0xe4` | no |
| 2 | `pshufd` | 16 | `xmm3, xmmword ptr [esi + 0x10], 0xe4` | no |
| 2 | `pshufd` | 16 | `xmm2, xmmword ptr [esi + 0x900], 0xe4` | no |
| 2 | `pshufd` | 16 | `xmm5, xmmword ptr [esi + 0x910], 0xe4` | no |
| 2 | `lock xadd` | 4 | `dword ptr [eax], edx` | yes |
| 2 | `lock cmpxchg` | 4 | `dword ptr [ebx], edi` | yes |
| 2 | `psrldq` | 16 | `xmm4, 3` | no |
| 2 | `punpcklqdq` | 16 | `xmm0, xmm4` | no |
| 2 | `punpcklqdq` | 16 | `xmm1, xmm0` | no |
| 2 | `punpcklqdq` | 16 | `xmm4, xmm5` | no |
| 2 | `punpcklqdq` | 16 | `xmm5, xmm6` | no |
| 2 | `ljmp` | 2 | `0xea89:0xaea44ed0` | no |
| 2 | `punpckhqdq` | 16 | `xmm1, xmm4` | no |
| 2 | `punpckhqdq` | 16 | `xmm3, xmm0` | no |
| 2 | `punpckhqdq` | 16 | `xmm2, xmm5` | no |
| 2 | `punpckhqdq` | 16 | `xmm7, xmm6` | no |
| 2 | `pshuflw` | 16 | `xmm0, xmm5, 0xf9` | no |
| 1 | `aad` | 1 | `0x3e` | no |
| 1 | `aad` | 1 | `0xb8` | no |
| 1 | `aad` | 1 | `0xb2` | no |
| 1 | `fstpnce` | 10 | `st(3), st(0)` | no |
| 1 | `lock cmpxchg` | 4 | `dword ptr [edi], edx` | yes |
| 1 | `lock cmpxchg` | 4 | `dword ptr [esi], edx` | yes |
| 1 | `psrldq` | 16 | `xmm1, 4` | no |
| 1 | `psrldq` | 16 | `xmm1, 8` | no |
| 1 | `psrldq` | 16 | `xmm1, 0xc` | no |
| 1 | `pslldq` | 16 | `xmm4, 2` | no |
| 1 | `psrldq` | 16 | `xmm2, 2` | no |
| 1 | `aad` | 1 | `0x4a` | no |
| 1 | `aad` | 1 | `0x88` | no |
| 1 | `pshuflw` | 16 | `xmm0, xmm2, 0xf9` | no |
| 1 | `pshuflw` | 16 | `xmm0, xmm3, 0xf9` | no |
| 1 | `pshuflw` | 16 | `xmm0, xmm4, 0xf9` | no |

## `lock xadd`

| Function | Address | Size | Operands | LOCK | Bytes |
| --- | --- | --- | --- | --- | --- |
| 0x00725580 | 0x0072562A | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x007377E0 | 0x007377E3 | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x0073A440 | 0x0073A44A | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x0073AAB0 | 0x0073AAEE | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x0073BE00 | 0x0073BE40 | 4 | `dword ptr [esi], edx` | yes | `f00fc116` |
| 0x0073BE00 | 0x0073BE40 | 4 | `dword ptr [esi], edx` | yes | `f00fc116` |
| 0x00747830 | 0x00747859 | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x00747830 | 0x007478A2 | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x00747830 | 0x007478A2 | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x00747830 | 0x007478DC | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x00747830 | 0x007478FB | 4 | `dword ptr [eax], ebp` | yes | `f00fc128` |
| 0x00747830 | 0x007478DC | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x00747830 | 0x007478FB | 4 | `dword ptr [eax], ebp` | yes | `f00fc128` |
| 0x00747830 | 0x00747B3F | 4 | `dword ptr [edx], eax` | yes | `f00fc102` |
| 0x00747830 | 0x00747B98 | 4 | `dword ptr [edx], eax` | yes | `f00fc102` |
| 0x00747830 | 0x00747B3F | 4 | `dword ptr [edx], eax` | yes | `f00fc102` |
| 0x00747830 | 0x00747B98 | 4 | `dword ptr [edx], eax` | yes | `f00fc102` |
| 0x00747C00 | 0x00747CB4 | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x00747C00 | 0x00747CB4 | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x00747D20 | 0x00747DD4 | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x00747D20 | 0x00747DD4 | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x0075CB50 | 0x0075CB64 | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x0075CB50 | 0x0075CB9A | 4 | `dword ptr [edx], eax` | yes | `f00fc102` |
| 0x0075CB50 | 0x0075CB9A | 4 | `dword ptr [edx], eax` | yes | `f00fc102` |
| 0x00760B20 | 0x00760B54 | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x00760B20 | 0x00760BC1 | 4 | `dword ptr [esi], eax` | yes | `f00fc106` |
| 0x00760B20 | 0x00760BC1 | 4 | `dword ptr [esi], eax` | yes | `f00fc106` |
| 0x00760B20 | 0x00760C60 | 4 | `dword ptr [esi], eax` | yes | `f00fc106` |
| 0x00760B20 | 0x00760CA2 | 4 | `dword ptr [esi], eax` | yes | `f00fc106` |
| 0x00760B20 | 0x00760CA2 | 4 | `dword ptr [esi], eax` | yes | `f00fc106` |
| 0x00760B20 | 0x00760DB9 | 4 | `dword ptr [edx], eax` | yes | `f00fc102` |
| 0x00760B20 | 0x00760F3B | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x00760B20 | 0x00760F3B | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x00760B20 | 0x00760F3B | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x00760B20 | 0x00760FE2 | 4 | `dword ptr [edx], eax` | yes | `f00fc102` |
| 0x00760B20 | 0x00760FE2 | 4 | `dword ptr [edx], eax` | yes | `f00fc102` |
| 0x00760B20 | 0x007613E1 | 4 | `dword ptr [edx], eax` | yes | `f00fc102` |
| 0x00760B20 | 0x00761428 | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x00760B20 | 0x00761428 | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x00760B20 | 0x00761428 | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x007614C0 | 0x00761588 | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x007614C0 | 0x00761588 | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x00761BE0 | 0x00761CCA | 4 | `dword ptr [eax], esi` | yes | `f00fc130` |
| 0x00761BE0 | 0x00761D4B | 4 | `dword ptr [edx], eax` | yes | `f00fc102` |
| 0x007620A0 | 0x0076218A | 4 | `dword ptr [eax], esi` | yes | `f00fc130` |
| 0x007620A0 | 0x0076220B | 4 | `dword ptr [edx], eax` | yes | `f00fc102` |
| 0x00764B40 | 0x00764BA4 | 4 | `dword ptr [edx], eax` | yes | `f00fc102` |
| 0x00764B40 | 0x00764C2F | 4 | `dword ptr [edx], eax` | yes | `f00fc102` |
| 0x00764B40 | 0x00764C62 | 4 | `dword ptr [eax], ebp` | yes | `f00fc128` |
| 0x00764B40 | 0x00764DE0 | 4 | `dword ptr [edx], eax` | yes | `f00fc102` |
| 0x00764B40 | 0x00764E7D | 4 | `dword ptr [edx], eax` | yes | `f00fc102` |
| 0x00764F70 | 0x00765074 | 4 | `dword ptr [edx], eax` | yes | `f00fc102` |
| 0x00764F70 | 0x007651DA | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x00764F70 | 0x007651DA | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x00767BC0 | 0x00767C7E | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x0076B3D0 | 0x0076B415 | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x0076B3D0 | 0x0076B471 | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x0076B3D0 | 0x0076B471 | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x00777D60 | 0x00777DAA | 4 | `dword ptr [esi], eax` | yes | `f00fc106` |
| 0x00779690 | 0x0077982F | 4 | `dword ptr [esi], eax` | yes | `f00fc106` |
| 0x00779690 | 0x0077982F | 4 | `dword ptr [esi], eax` | yes | `f00fc106` |
| 0x00779690 | 0x00779874 | 4 | `dword ptr [edx], eax` | yes | `f00fc102` |
| 0x007F9A30 | 0x007F9D46 | 4 | `dword ptr [edx], eax` | yes | `f00fc102` |
| 0x00804070 | 0x00804075 | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x00814A40 | 0x00814AFB | 4 | `dword ptr [edx], eax` | yes | `f00fc102` |
| 0x00814B90 | 0x00814B9E | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x0081A3A0 | 0x0081A404 | 4 | `dword ptr [edx], eax` | yes | `f00fc102` |
| 0x00823660 | 0x0082369C | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x00823E10 | 0x00823E45 | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x00823E10 | 0x00823E45 | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x00824100 | 0x0082412A | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x00824100 | 0x0082412A | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x008241E0 | 0x0082424A | 4 | `dword ptr [esi], eax` | yes | `f00fc106` |
| 0x008241E0 | 0x00824748 | 4 | `dword ptr [edx], eax` | yes | `f00fc102` |
| 0x008241E0 | 0x00824D14 | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x008241E0 | 0x00824D5A | 4 | `dword ptr [edx], eax` | yes | `f00fc102` |
| 0x008241E0 | 0x00824D5A | 4 | `dword ptr [edx], eax` | yes | `f00fc102` |
| 0x008241E0 | 0x00824DA0 | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x008241E0 | 0x00824DA0 | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x008241E0 | 0x00824DF0 | 4 | `dword ptr [esi], eax` | yes | `f00fc106` |
| 0x008241E0 | 0x00824DF0 | 4 | `dword ptr [esi], eax` | yes | `f00fc106` |
| 0x00836170 | 0x008363AB | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x00837410 | 0x0083748C | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x00838A90 | 0x00838AA6 | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x0084C950 | 0x0084C993 | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x0084C950 | 0x0084C9AF | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x0084C950 | 0x0084C9E7 | 4 | `dword ptr [edx], eax` | yes | `f00fc102` |
| 0x0084C950 | 0x0084C9E7 | 4 | `dword ptr [edx], eax` | yes | `f00fc102` |
| 0x0084C950 | 0x0084CA1F | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x0084C950 | 0x0084CA1F | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x0084C950 | 0x0084CDFE | 4 | `dword ptr [edx], eax` | yes | `f00fc102` |
| 0x00977BE0 | 0x00977BEC | 4 | `dword ptr [eax], ecx` | yes | `f00fc108` |
| 0x00977BE0 | 0x00977C76 | 4 | `dword ptr [eax], edx` | yes | `f00fc110` |
| 0x00977CE0 | 0x00977D7D | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x00977CE0 | 0x00977DAB | 4 | `dword ptr [eax], ecx` | yes | `f00fc108` |
| 0x00977CE0 | 0x00977DAB | 4 | `dword ptr [eax], ecx` | yes | `f00fc108` |
| 0x00978180 | 0x009782A5 | 4 | `dword ptr [edx], eax` | yes | `f00fc102` |
| 0x00978180 | 0x009782A5 | 4 | `dword ptr [edx], eax` | yes | `f00fc102` |
| 0x009782D0 | 0x009782E3 | 4 | `dword ptr [ecx], edx` | yes | `f00fc111` |
| 0x009782D0 | 0x0097831E | 4 | `dword ptr [eax], ecx` | yes | `f00fc108` |
| 0x009782D0 | 0x0097832C | 4 | `dword ptr [edx], eax` | yes | `f00fc102` |
| 0x009782D0 | 0x0097831E | 4 | `dword ptr [eax], ecx` | yes | `f00fc108` |
| 0x009782D0 | 0x0097832C | 4 | `dword ptr [edx], eax` | yes | `f00fc102` |
| 0x009782D0 | 0x009783C4 | 4 | `dword ptr [ecx], edx` | yes | `f00fc111` |
| 0x009782D0 | 0x009783DD | 4 | `dword ptr [ecx], eax` | yes | `f00fc101` |
| 0x009782D0 | 0x00978405 | 4 | `dword ptr [edx], ecx` | yes | `f00fc10a` |
| 0x009782D0 | 0x0097841C | 4 | `dword ptr [edx], ecx` | yes | `f00fc10a` |
| 0x009782D0 | 0x0097841C | 4 | `dword ptr [edx], ecx` | yes | `f00fc10a` |
| 0x00978440 | 0x0097856C | 4 | `dword ptr [ecx], edx` | yes | `f00fc111` |
| 0x00978440 | 0x0097856C | 4 | `dword ptr [ecx], edx` | yes | `f00fc111` |
| 0x009EBFE0 | 0x009EBFF3 | 4 | `dword ptr [eax], edx` | yes | `f00fc110` |
| 0x009EDCF0 | 0x009EDD80 | 4 | `dword ptr [ecx], edx` | yes | `f00fc111` |
| 0x009EE730 | 0x009EE739 | 4 | `dword ptr [eax], ecx` | yes | `f00fc108` |
| 0x009EE750 | 0x009EE757 | 4 | `dword ptr [eax], ecx` | yes | `f00fc108` |
| 0x009EE760 | 0x009EE76A | 4 | `dword ptr [edx], eax` | yes | `f00fc102` |

## `lock cmpxchg`

| Function | Address | Size | Operands | LOCK | Bytes |
| --- | --- | --- | --- | --- | --- |
| 0x00978080 | 0x00978099 | 4 | `dword ptr [ebx], edi` | yes | `f00fb13b` |
| 0x00978080 | 0x00978099 | 4 | `dword ptr [ebx], edi` | yes | `f00fb13b` |
| 0x009ECAA0 | 0x009ECAB1 | 4 | `dword ptr [edi], esi` | yes | `f00fb137` |
| 0x009ECAD0 | 0x009ECAE9 | 4 | `dword ptr [edi], esi` | yes | `f00fb137` |
| 0x009ECAD0 | 0x009ECAE9 | 4 | `dword ptr [edi], esi` | yes | `f00fb137` |
| 0x009ECDF0 | 0x009ECE09 | 4 | `dword ptr [edx], ecx` | yes | `f00fb10a` |
| 0x009ED7B0 | 0x009ED905 | 4 | `dword ptr [edx], ecx` | yes | `f00fb10a` |
| 0x009EDCF0 | 0x009EDD09 | 4 | `dword ptr [edx], ecx` | yes | `f00fb10a` |
| 0x009EDCF0 | 0x009EDD3B | 4 | `dword ptr [edi], edx` | yes | `f00fb117` |
| 0x009EE710 | 0x009EE71F | 4 | `dword ptr [esi], edx` | yes | `f00fb116` |

## `lock cmpxchg8b`

| Function | Address | Size | Operands | LOCK | Bytes |
| --- | --- | --- | --- | --- | --- |
| 0x009EBEC0 | 0x009EBF0D | 8 | `qword ptr [esi]` | yes | `f00fc70e` |
| 0x009EBEC0 | 0x009EBF0D | 8 | `qword ptr [esi]` | yes | `f00fc70e` |
| 0x009EC240 | 0x009EC280 | 8 | `qword ptr [esi]` | yes | `f00fc70e` |
| 0x009ED7B0 | 0x009ED8C4 | 8 | `qword ptr [esi]` | yes | `f00fc70e` |
| 0x009ED7B0 | 0x009ED8C4 | 8 | `qword ptr [esi]` | yes | `f00fc70e` |
| 0x009ED7B0 | 0x009ED948 | 8 | `qword ptr [esi]` | yes | `f00fc70e` |
| 0x009ED7B0 | 0x009EDA6C | 8 | `qword ptr [esi]` | yes | `f00fc70e` |
| 0x009ED7B0 | 0x009EDA6C | 8 | `qword ptr [esi]` | yes | `f00fc70e` |
| 0x009EE100 | 0x009EE1BA | 8 | `qword ptr [esi]` | yes | `f00fc70e` |
| 0x009EE520 | 0x009EE61B | 8 | `qword ptr [esi]` | yes | `f00fc70e` |

## `psrldq`

| Function | Address | Size | Operands | LOCK | Bytes |
| --- | --- | --- | --- | --- | --- |
| 0x0098D9C0 | 0x0098D9FC | 16 | `xmm4, 3` | no | `660f73dc03` |
| 0x0098D9C0 | 0x0098DA26 | 16 | `xmm4, 1` | no | `660f73dc01` |
| 0x0098D9C0 | 0x0098D9FC | 16 | `xmm4, 3` | no | `660f73dc03` |
| 0x0098D9C0 | 0x0098DA26 | 16 | `xmm4, 1` | no | `660f73dc01` |
| 0x0098DB00 | 0x0098DB31 | 16 | `xmm5, 1` | no | `660f73dd01` |
| 0x0098DB00 | 0x0098DB31 | 16 | `xmm5, 1` | no | `660f73dd01` |
| 0x0098DBE0 | 0x0098DC10 | 16 | `xmm4, 1` | no | `660f73dc01` |
| 0x0098DBE0 | 0x0098DC48 | 16 | `xmm4, 1` | no | `660f73dc01` |
| 0x0098DBE0 | 0x0098DC48 | 16 | `xmm4, 1` | no | `660f73dc01` |
| 0x0098DCA0 | 0x0098DCD3 | 16 | `xmm4, 1` | no | `660f73dc01` |
| 0x0098DCA0 | 0x0098DD0B | 16 | `xmm4, 1` | no | `660f73dc01` |
| 0x0098DCA0 | 0x0098DD0B | 16 | `xmm4, 1` | no | `660f73dc01` |
| 0x0098DD60 | 0x0098DD91 | 16 | `xmm5, 1` | no | `660f73dd01` |
| 0x0098DD60 | 0x0098DD91 | 16 | `xmm5, 1` | no | `660f73dd01` |
| 0x00A07E00 | 0x00A07E2C | 16 | `xmm1, 4` | no | `660f73d904` |
| 0x00A07E00 | 0x00A07E46 | 16 | `xmm1, 8` | no | `660f73d908` |
| 0x00A07E00 | 0x00A07E5D | 16 | `xmm1, 0xc` | no | `660f73d90c` |
| 0x00A07E80 | 0x00A0806C | 16 | `xmm3, 2` | no | `660f73db02` |
| 0x00A07E80 | 0x00A080F5 | 16 | `xmm3, 2` | no | `660f73db02` |
| 0x00A07E80 | 0x00A081DD | 16 | `xmm2, 2` | no | `660f73da02` |
| 0x00A07E80 | 0x00A08213 | 16 | `xmm3, 2` | no | `660f73db02` |
| 0x00A08230 | 0x00A08533 | 16 | `xmm4, 2` | no | `660f73dc02` |
| 0x00A08230 | 0x00A085EF | 16 | `xmm4, 2` | no | `660f73dc02` |
| 0x00A08230 | 0x00A08712 | 16 | `xmm3, 2` | no | `660f73db02` |
| 0x00A08230 | 0x00A08757 | 16 | `xmm4, 2` | no | `660f73dc02` |
| 0x00A08770 | 0x00A08B63 | 16 | `xmm5, 2` | no | `660f73dd02` |
| 0x00A08770 | 0x00A08C78 | 16 | `xmm5, 2` | no | `660f73dd02` |
| 0x00A08770 | 0x00A08D80 | 16 | `xmm5, 2` | no | `660f73dd02` |
| 0x00A08770 | 0x00A08E11 | 16 | `xmm4, 2` | no | `660f73dc02` |
| 0x00A08E70 | 0x00A0933E | 16 | `xmm5, 2` | no | `660f73dd02` |
| 0x00A08E70 | 0x00A09461 | 16 | `xmm5, 2` | no | `660f73dd02` |
| 0x00A08E70 | 0x00A0955C | 16 | `xmm5, 2` | no | `660f73dd02` |
| 0x00A08E70 | 0x00A0960B | 16 | `xmm5, 2` | no | `660f73dd02` |
| 0x00A09670 | 0x00A09C87 | 16 | `xmm5, 2` | no | `660f73dd02` |
| 0x00A09670 | 0x00A09DFB | 16 | `xmm5, 2` | no | `660f73dd02` |
| 0x00A09670 | 0x00A09F6F | 16 | `xmm5, 2` | no | `660f73dd02` |
| 0x00A09670 | 0x00A0A051 | 16 | `xmm5, 2` | no | `660f73dd02` |

## `pslldq`

| Function | Address | Size | Operands | LOCK | Bytes |
| --- | --- | --- | --- | --- | --- |
| 0x00A07E80 | 0x00A080BB | 16 | `xmm5, 2` | no | `660f73fd02` |
| 0x00A07E80 | 0x00A0810B | 16 | `xmm4, 2` | no | `660f73fc02` |
| 0x00A07E80 | 0x00A08169 | 16 | `xmm5, 2` | no | `660f73fd02` |
| 0x00A07E80 | 0x00A081D8 | 16 | `xmm5, 2` | no | `660f73fd02` |
| 0x00A08230 | 0x00A084DE | 16 | `xmm5, 2` | no | `660f73fd02` |
| 0x00A08230 | 0x00A085A7 | 16 | `xmm5, 2` | no | `660f73fd02` |
| 0x00A08230 | 0x00A0866B | 16 | `xmm5, 2` | no | `660f73fd02` |
| 0x00A08230 | 0x00A0870D | 16 | `xmm5, 2` | no | `660f73fd02` |
| 0x00A08770 | 0x00A08B0A | 16 | `xmm5, 2` | no | `660f73fd02` |
| 0x00A08770 | 0x00A08C1A | 16 | `xmm5, 2` | no | `660f73fd02` |
| 0x00A08770 | 0x00A08D1F | 16 | `xmm5, 2` | no | `660f73fd02` |
| 0x00A08770 | 0x00A08E0C | 16 | `xmm5, 2` | no | `660f73fd02` |
| 0x00A08E70 | 0x00A092D8 | 16 | `xmm5, 2` | no | `660f73fd02` |
| 0x00A08E70 | 0x00A093F3 | 16 | `xmm6, 2` | no | `660f73fe02` |
| 0x00A08E70 | 0x00A094FE | 16 | `xmm6, 2` | no | `660f73fe02` |
| 0x00A08E70 | 0x00A09606 | 16 | `xmm6, 2` | no | `660f73fe02` |
| 0x00A09670 | 0x00A09C02 | 16 | `xmm5, 2` | no | `660f73fd02` |
| 0x00A09670 | 0x00A09D76 | 16 | `xmm5, 2` | no | `660f73fd02` |
| 0x00A09670 | 0x00A09EEA | 16 | `xmm5, 2` | no | `660f73fd02` |
| 0x00A09670 | 0x00A0A016 | 16 | `xmm6, 2` | no | `660f73fe02` |

## `punpcklqdq`

| Function | Address | Size | Operands | LOCK | Bytes |
| --- | --- | --- | --- | --- | --- |
| 0x0098E150 | 0x0098E407 | 16 | `xmm0, xmm4` | no | `660f6cc4` |
| 0x0098E150 | 0x0098E421 | 16 | `xmm1, xmm0` | no | `660f6cc8` |
| 0x0098E150 | 0x0098E42D | 16 | `xmm4, xmm5` | no | `660f6ce5` |
| 0x0098E150 | 0x0098E44D | 16 | `xmm5, xmm6` | no | `660f6cee` |
| 0x0098E650 | 0x0098E86D | 16 | `xmm0, xmm4` | no | `660f6cc4` |
| 0x0098E650 | 0x0098E887 | 16 | `xmm1, xmm0` | no | `660f6cc8` |
| 0x0098E650 | 0x0098E893 | 16 | `xmm4, xmm5` | no | `660f6ce5` |
| 0x0098E650 | 0x0098E8B3 | 16 | `xmm5, xmm6` | no | `660f6cee` |

## `punpckhqdq`

| Function | Address | Size | Operands | LOCK | Bytes |
| --- | --- | --- | --- | --- | --- |
| 0x0098E150 | 0x0098E40B | 16 | `xmm1, xmm4` | no | `660f6dcc` |
| 0x0098E150 | 0x0098E425 | 16 | `xmm3, xmm0` | no | `660f6dd8` |
| 0x0098E150 | 0x0098E431 | 16 | `xmm2, xmm5` | no | `660f6dd5` |
| 0x0098E150 | 0x0098E451 | 16 | `xmm7, xmm6` | no | `660f6dfe` |
| 0x0098E650 | 0x0098E871 | 16 | `xmm1, xmm4` | no | `660f6dcc` |
| 0x0098E650 | 0x0098E88B | 16 | `xmm3, xmm0` | no | `660f6dd8` |
| 0x0098E650 | 0x0098E897 | 16 | `xmm2, xmm5` | no | `660f6dd5` |
| 0x0098E650 | 0x0098E8B7 | 16 | `xmm7, xmm6` | no | `660f6dfe` |

## `pshufd`

| Function | Address | Size | Operands | LOCK | Bytes |
| --- | --- | --- | --- | --- | --- |
| 0x0095E670 | 0x0095E6BD | 16 | `xmm0, xmmword ptr [esi], 0xe4` | no | `660f7006e4` |
| 0x0095E670 | 0x0095E6C2 | 16 | `xmm3, xmmword ptr [esi + 0x10], 0xe4` | no | `660f705e10e4` |
| 0x0095E670 | 0x0095E6CE | 16 | `xmm2, xmmword ptr [esi + 0x900], 0xe4` | no | `660f709600090000e4` |
| 0x0095E670 | 0x0095E6D7 | 16 | `xmm5, xmmword ptr [esi + 0x910], 0xe4` | no | `660f70ae10090000e4` |
| 0x0095E670 | 0x0095E6BD | 16 | `xmm0, xmmword ptr [esi], 0xe4` | no | `660f7006e4` |
| 0x0095E670 | 0x0095E6C2 | 16 | `xmm3, xmmword ptr [esi + 0x10], 0xe4` | no | `660f705e10e4` |
| 0x0095E670 | 0x0095E6CE | 16 | `xmm2, xmmword ptr [esi + 0x900], 0xe4` | no | `660f709600090000e4` |
| 0x0095E670 | 0x0095E6D7 | 16 | `xmm5, xmmword ptr [esi + 0x910], 0xe4` | no | `660f70ae10090000e4` |

## `pshuflw`

| Function | Address | Size | Operands | LOCK | Bytes |
| --- | --- | --- | --- | --- | --- |
| 0x00A07E80 | 0x00A08071 | 16 | `xmm3, xmm3, 0xf9` | no | `f20f70dbf9` |
| 0x00A07E80 | 0x00A080C0 | 16 | `xmm5, xmm5, 0xf9` | no | `f20f70edf9` |
| 0x00A07E80 | 0x00A080FA | 16 | `xmm3, xmm3, 0xf9` | no | `f20f70dbf9` |
| 0x00A07E80 | 0x00A0811A | 16 | `xmm4, xmm4, 0xf9` | no | `f20f70e4f9` |
| 0x00A07E80 | 0x00A0816E | 16 | `xmm5, xmm5, 0xf9` | no | `f20f70edf9` |
| 0x00A07E80 | 0x00A081E2 | 16 | `xmm0, xmm2, 0xf9` | no | `f20f70c2f9` |
| 0x00A07E80 | 0x00A081E7 | 16 | `xmm5, xmm5, 0xf9` | no | `f20f70edf9` |
| 0x00A07E80 | 0x00A08218 | 16 | `xmm3, xmm3, 0xf9` | no | `f20f70dbf9` |
| 0x00A08230 | 0x00A084E3 | 16 | `xmm5, xmm5, 0xf9` | no | `f20f70edf9` |
| 0x00A08230 | 0x00A08538 | 16 | `xmm4, xmm4, 0xf9` | no | `f20f70e4f9` |
| 0x00A08230 | 0x00A085AC | 16 | `xmm5, xmm5, 0xf9` | no | `f20f70edf9` |
| 0x00A08230 | 0x00A085F4 | 16 | `xmm4, xmm4, 0xf9` | no | `f20f70e4f9` |
| 0x00A08230 | 0x00A08670 | 16 | `xmm5, xmm5, 0xf9` | no | `f20f70edf9` |
| 0x00A08230 | 0x00A08717 | 16 | `xmm0, xmm3, 0xf9` | no | `f20f70c3f9` |
| 0x00A08230 | 0x00A0871C | 16 | `xmm5, xmm5, 0xf9` | no | `f20f70edf9` |
| 0x00A08230 | 0x00A0875C | 16 | `xmm4, xmm4, 0xf9` | no | `f20f70e4f9` |
| 0x00A08770 | 0x00A08B0F | 16 | `xmm5, xmm5, 0xf9` | no | `f20f70edf9` |
| 0x00A08770 | 0x00A08B68 | 16 | `xmm5, xmm5, 0xf9` | no | `f20f70edf9` |
| 0x00A08770 | 0x00A08C1F | 16 | `xmm5, xmm5, 0xf9` | no | `f20f70edf9` |
| 0x00A08770 | 0x00A08C7D | 16 | `xmm5, xmm5, 0xf9` | no | `f20f70edf9` |
| 0x00A08770 | 0x00A08D24 | 16 | `xmm5, xmm5, 0xf9` | no | `f20f70edf9` |
| 0x00A08770 | 0x00A08D85 | 16 | `xmm5, xmm5, 0xf9` | no | `f20f70edf9` |
| 0x00A08770 | 0x00A08E16 | 16 | `xmm0, xmm4, 0xf9` | no | `f20f70c4f9` |
| 0x00A08770 | 0x00A08E1B | 16 | `xmm5, xmm5, 0xf9` | no | `f20f70edf9` |
| 0x00A08E70 | 0x00A092DD | 16 | `xmm5, xmm5, 0xf9` | no | `f20f70edf9` |
| 0x00A08E70 | 0x00A09343 | 16 | `xmm5, xmm5, 0xf9` | no | `f20f70edf9` |
| 0x00A08E70 | 0x00A093F8 | 16 | `xmm6, xmm6, 0xf9` | no | `f20f70f6f9` |
| 0x00A08E70 | 0x00A09466 | 16 | `xmm5, xmm5, 0xf9` | no | `f20f70edf9` |
| 0x00A08E70 | 0x00A09503 | 16 | `xmm6, xmm6, 0xf9` | no | `f20f70f6f9` |
| 0x00A08E70 | 0x00A09561 | 16 | `xmm5, xmm5, 0xf9` | no | `f20f70edf9` |
| 0x00A08E70 | 0x00A09610 | 16 | `xmm0, xmm5, 0xf9` | no | `f20f70c5f9` |
| 0x00A08E70 | 0x00A09615 | 16 | `xmm6, xmm6, 0xf9` | no | `f20f70f6f9` |
| 0x00A09670 | 0x00A09C07 | 16 | `xmm5, xmm5, 0xf9` | no | `f20f70edf9` |
| 0x00A09670 | 0x00A09C8C | 16 | `xmm5, xmm5, 0xf9` | no | `f20f70edf9` |
| 0x00A09670 | 0x00A09D7B | 16 | `xmm5, xmm5, 0xf9` | no | `f20f70edf9` |
| 0x00A09670 | 0x00A09E00 | 16 | `xmm5, xmm5, 0xf9` | no | `f20f70edf9` |
| 0x00A09670 | 0x00A09EEF | 16 | `xmm5, xmm5, 0xf9` | no | `f20f70edf9` |
| 0x00A09670 | 0x00A09F74 | 16 | `xmm5, xmm5, 0xf9` | no | `f20f70edf9` |
| 0x00A09670 | 0x00A0A01B | 16 | `xmm6, xmm6, 0xf9` | no | `f20f70f6f9` |
| 0x00A09670 | 0x00A0A056 | 16 | `xmm0, xmm5, 0xf9` | no | `f20f70c5f9` |

## `fstpnce`

| Function | Address | Size | Operands | LOCK | Bytes |
| --- | --- | --- | --- | --- | --- |
| 0x007C9010 | 0x00463F74 | 10 | `st(3), st(0)` | no | `d9db` |

## `aad`

| Function | Address | Size | Operands | LOCK | Bytes |
| --- | --- | --- | --- | --- | --- |
| 0x00780150 | 0x00527EB7 | 1 | `0x3e` | no | `d53e` |
| 0x007C8350 | 0x00509355 | 1 | `0xb8` | no | `d5b8` |
| 0x007C8350 | 0x005093C8 | 1 | `0xb2` | no | `d5b2` |
| 0x00A945E0 | 0x006BAF94 | 1 | `0x4a` | no | `d54a` |
| 0x00A945E0 | 0x006BAFAE | 1 | `0x88` | no | `d588` |

## `aaa`

| Function | Address | Size | Operands | LOCK | Bytes |
| --- | --- | --- | --- | --- | --- |
| 0x007C8350 | 0x005092B1 | 0 | `` | no | `37` |
| 0x007C8350 | 0x0050936F | 0 | `` | no | `37` |

## `salc`

| Function | Address | Size | Operands | LOCK | Bytes |
| --- | --- | --- | --- | --- | --- |
| 0x00401DC0 | 0x00401DC2 | 0 | `` | no | `d6` |
| 0x007C8350 | 0x005092D3 | 0 | `` | no | `d6` |
| 0x007C8350 | 0x0050949A | 0 | `` | no | `d6` |

## `ljmp`

| Function | Address | Size | Operands | LOCK | Bytes |
| --- | --- | --- | --- | --- | --- |
| 0x00841BF0 | 0x006954B6 | 2 | `0x7c4:0xa1538f2f` | no | `ea2f8f53a1c407` |
| 0x00841BF0 | 0x006954B6 | 2 | `0x7c4:0xa1538f2f` | no | `ea2f8f53a1c407` |
| 0x00841BF0 | 0x006954B6 | 2 | `0x7c4:0xa1538f2f` | no | `ea2f8f53a1c407` |
| 0x00A945E0 | 0x006BB093 | 2 | `0xea89:0xaea44ed0` | no | `ead04ea4ae89ea` |
| 0x00A945E0 | 0x006BB093 | 2 | `0xea89:0xaea44ed0` | no | `ead04ea4ae89ea` |

## `fstpnce` decision

Capstone decodes `d9db` at 0x00463F74 in function 0x007C9010 as `fstpnce st(3), st(0)`. Intel leaves `D9 D8+i` reserved. The documented `FSTP ST(i)` encoding is `DD D8+i`, and the lifter already implements `fst` and `fstp`. The surrounding block is not x87 compiler output. The function entry looks like a short compiler function, and `discover()` reaches this block by following a jump. `fstpnce` is not implemented. The function is reclassified as data reached through a bad edge.
