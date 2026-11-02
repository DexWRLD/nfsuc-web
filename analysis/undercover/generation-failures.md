# Undercover generation failures

Genuine failures are instructions `Lifter.lift` refused. Unsupported opcodes were not replaced with NOPs. The existing lifter already emits a comment for privileged instructions; those are counted in the feasibility report and are not listed here as successes of translation.

Failed functions: 14

| Function | Instruction | Bytes | Mnemonic | Operands | Reason |
| --- | --- | --- | --- | --- | --- |
| 0x00401250 | 0x00401262 | `37` | `aaa` | `` | aaa |
| 0x004012A0 | 0x0040127E | `c4b66f85abcf` | `les` | `esi, ptr [esi - 0x30547a91]` | les |
| 0x004014E0 | 0x004015BE | `2f` | `das` | `` | das |
| 0x00401510 | 0x004015BE | `2f` | `das` | `` | das |
| 0x00401570 | 0x0040158D | `cf` | `iretd` | `` | iretd |
| 0x00401FD0 | 0x00401FD5 | `d59f` | `aad` | `0x9f` | aad |
| 0x004A91F0 | 0x004A90E6 | `37` | `aaa` | `` | aaa |
| 0x005DAAB0 | 0x005DAAFB | `9ad5dac1f36453` | `lcall` | `0x5364, 0xf3c1dad5` | lcall |
| 0x0065AA30 | 0x0065A991 | `9a70ef99d1b24b` | `lcall` | `0x4bb2, 0xd199ef70` | lcall |
| 0x00695490 | 0x006954B6 | `ea2f8f53a1c407` | `ljmp` | `0x7c4:0xa1538f2f` | ljmp |
| 0x006962A0 | 0x006962E2 | `9a4362296a847c` | `lcall` | `0x7c84, 0x6a296243` | lcall |
| 0x00772800 | 0x00403076 | `2f` | `das` | `` | das |
| 0x00783BB0 | 0x00533065 | `37` | `aaa` | `` | aaa |
| 0x007C6C90 | 0x0047C57E | `c4b6d7591dbb` | `les` | `esi, ptr [esi - 0x44e2a629]` | les |

## Watchlist instructions inside functions the lifter accepted

| Function | Instruction | Mnemonic | Operands |
| --- | --- | --- | --- |
| 0x00B02690 | 0x00B02AA1 | `movmskps` | `eax, xmm0` |
| 0x00B02690 | 0x00B02BB1 | `movmskps` | `edx, xmm0` |
| 0x00B070C0 | 0x00B0750E | `movmskps` | `edx, xmm0` |
| 0x00B070C0 | 0x00B07615 | `movmskps` | `eax, xmm0` |
