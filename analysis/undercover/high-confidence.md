# High-confidence generation

This is the exact Phase 4 HIGH_CONFIDENCE address list (6,604 functions). MEDIUM and LOW roots were not translated. The six failures below stay in this list; the later map reclassifies them and does not drop them from this percentage.
Generated C is under `generated/undercover/high/` and is not committed.
The game was not executed.

- Functions attempted: 6604
- Functions generated: 6598
- Generation success: 99.9%
- Functions compiled: 6598
- Compilation success: 100.0%
- Compiler failures: 0
- Unresolved indirect calls: 6875
- Unresolved external direct edges: 11
- Recognized switches: 142
- Rejected switches: 53
- Generated source size: 48306062 bytes
- Translation units: 6598
- Compile time: 144s

## Generation failures

- `aad`: 2
- `salc`: 1
- `aaa`: 1
- `fstpnce`: 1
- `ljmp`: 1

| Function | Mnemonic | Reason |
| --- | --- | --- |
| 0x00401DC0 | `salc` | salc |
| 0x00780150 | `aad` | aad |
| 0x007C8350 | `aaa` | aaa |
| 0x007C9010 | `fstpnce` | fstpnce |
| 0x00841BF0 | `ljmp` | ljmp |
| 0x00A945E0 | `aad` | aad |

## Compiler failures

None.
