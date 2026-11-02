# High-confidence generation

Only HIGH_CONFIDENCE functions were translated. MEDIUM and LOW roots were not.
Generated C is under `generated/undercover/high/` and is not committed.
The game was not executed.

- Functions attempted: 6604
- Functions generated: 6532
- Generation success: 98.9%
- Functions compiled: 6532
- Compilation success: 100.0%
- Compiler failures: 0
- Unresolved indirect calls: 6875
- Unresolved external direct edges: 11
- Recognized switches: 142
- Rejected switches: 53
- Generated source size: 46994153 bytes
- Translation units: 6532
- Compile time: 114s

## Generation failures

- `lock xadd`: 41
- `psrldq`: 7
- `lock cmpxchg`: 6
- `lock cmpxchg8b`: 5
- `pslldq`: 4
- `aad`: 2
- `punpcklqdq`: 2
- `salc`: 1
- `aaa`: 1
- `fstpnce`: 1
- `ljmp`: 1
- `pshufd`: 1

| Function | Mnemonic | Reason |
| --- | --- | --- |
| 0x00401DC0 | `salc` | salc |
| 0x00725580 | `lock xadd` | lock xadd |
| 0x007377E0 | `lock xadd` | lock xadd |
| 0x0073A440 | `lock xadd` | lock xadd |
| 0x0073AAB0 | `lock xadd` | lock xadd |
| 0x0073BE00 | `lock xadd` | lock xadd |
| 0x00747830 | `lock xadd` | lock xadd |
| 0x00747C00 | `lock xadd` | lock xadd |
| 0x00747D20 | `lock xadd` | lock xadd |
| 0x0075CB50 | `lock xadd` | lock xadd |
| 0x00760B20 | `lock xadd` | lock xadd |
| 0x007614C0 | `lock xadd` | lock xadd |
| 0x00761BE0 | `lock xadd` | lock xadd |
| 0x007620A0 | `lock xadd` | lock xadd |
| 0x00764B40 | `lock xadd` | lock xadd |
| 0x00764F70 | `lock xadd` | lock xadd |
| 0x00767BC0 | `lock xadd` | lock xadd |
| 0x0076B3D0 | `lock xadd` | lock xadd |
| 0x00777D60 | `lock xadd` | lock xadd |
| 0x00779690 | `lock xadd` | lock xadd |
| 0x00780150 | `aad` | aad |
| 0x007C8350 | `aaa` | aaa |
| 0x007C9010 | `fstpnce` | fstpnce |
| 0x007F9A30 | `lock xadd` | lock xadd |
| 0x00804070 | `lock xadd` | lock xadd |
| 0x00814A40 | `lock xadd` | lock xadd |
| 0x00814B90 | `lock xadd` | lock xadd |
| 0x0081A3A0 | `lock xadd` | lock xadd |
| 0x00823660 | `lock xadd` | lock xadd |
| 0x00823E10 | `lock xadd` | lock xadd |
| 0x00824100 | `lock xadd` | lock xadd |
| 0x008241E0 | `lock xadd` | lock xadd |
| 0x00836170 | `lock xadd` | lock xadd |
| 0x00837410 | `lock xadd` | lock xadd |
| 0x00838A90 | `lock xadd` | lock xadd |
| 0x00841BF0 | `ljmp` | ljmp |
| 0x0084C950 | `lock xadd` | lock xadd |
| 0x0095E670 | `pshufd` | pshufd |
| 0x00977BE0 | `lock xadd` | lock xadd |
| 0x00977CE0 | `lock xadd` | lock xadd |
| 0x00978080 | `lock cmpxchg` | lock cmpxchg |
| 0x00978180 | `lock xadd` | lock xadd |
| 0x009782D0 | `lock xadd` | lock xadd |
| 0x00978440 | `lock xadd` | lock xadd |
| 0x0098D9C0 | `psrldq` | psrldq |
| 0x0098DB00 | `psrldq` | psrldq |
| 0x0098DBE0 | `psrldq` | psrldq |
| 0x0098DCA0 | `psrldq` | psrldq |
| 0x0098DD60 | `psrldq` | psrldq |
| 0x0098E150 | `punpcklqdq` | punpcklqdq |
| 0x0098E650 | `punpcklqdq` | punpcklqdq |
| 0x009EBEC0 | `lock cmpxchg8b` | lock cmpxchg8b |
| 0x009EBFE0 | `lock xadd` | lock xadd |
| 0x009EC240 | `lock cmpxchg8b` | lock cmpxchg8b |
| 0x009ECAA0 | `lock cmpxchg` | lock cmpxchg |
| 0x009ECAD0 | `lock cmpxchg` | lock cmpxchg |
| 0x009ECDF0 | `lock cmpxchg` | lock cmpxchg |
| 0x009ED7B0 | `lock cmpxchg8b` | lock cmpxchg8b |
| 0x009EDCF0 | `lock cmpxchg` | lock cmpxchg |
| 0x009EE100 | `lock cmpxchg8b` | lock cmpxchg8b |
| 0x009EE520 | `lock cmpxchg8b` | lock cmpxchg8b |
| 0x009EE710 | `lock cmpxchg` | lock cmpxchg |
| 0x009EE730 | `lock xadd` | lock xadd |
| 0x009EE750 | `lock xadd` | lock xadd |
| 0x009EE760 | `lock xadd` | lock xadd |
| 0x00A07E00 | `psrldq` | psrldq |
| 0x00A07E80 | `psrldq` | psrldq |
| 0x00A08230 | `pslldq` | pslldq |
| 0x00A08770 | `pslldq` | pslldq |
| 0x00A08E70 | `pslldq` | pslldq |
| 0x00A09670 | `pslldq` | pslldq |
| 0x00A945E0 | `aad` | aad |

## Compiler failures

None.
