# Undercover native runtime frontier

Ordinary high-confidence functions only. Import thunks are edges, not functions in a closure. Protected sections were not read. The game was not started.

A closure follows direct calls and tail jumps through reachable `HIGH_CONFIDENCE` functions. Import and indirect counts are the union of the functions in the set, each function counted once. The label is the first boundary that stops the current runtime from executing the whole set. A function that is not a source can head a larger closure than any source, so the last section is the one to use for size.

Executed paths are smaller than these static closures. `analysis/undercover/runtime-phase10.md` records which functions actually ran.

## Source closures by boundary

| boundary | source closures |
| --- | --- |
| UNRESOLVED_INDIRECT_CALL | 3622 |
| READY | 3524 |
| UNKNOWN_RUNTIME_DEPENDENCY | 1862 |
| TLS_BOUNDARY | 1383 |
| PROTECTED_BOUNDARY | 585 |
| READY_WITH_IMPLEMENTED_IMPORTS | 76 |
| KNOWN_IMPORT_MISSING_HLE | 71 |
| RESOLVABLE_INDIRECT_CALL | 36 |
| UNKNOWN_IMPORT_ABI | 5 |
| FILESYSTEM_BOUNDARY | 5 |
| MEMORY_BOUNDARY | 3 |
| TIMING_BOUNDARY | 2 |

Reachable high-confidence functions, excluding import thunks: 22607.

## Indirect sites

| kind | sites |
| --- | --- |
| D_REGISTER | 30614 |
| D_UNKNOWN | 8972 |
| E_PROTECTED_SLOT | 241 |
| B_IMPORT_SLOT | 110 |
| B_GENERATED_TARGET | 50 |

Examples are guest addresses, not names invented for the code.

- D_REGISTER: fn 0x006DD7C0 at 0x006DD7D5 edx; fn 0x006DD7C0 at 0x006DD7E1 edx; fn 0x006DD860 at 0x006DD86B edx; fn 0x006DD860 at 0x006DD8D5 edx
- D_UNKNOWN: fn 0x006DFE00 at 0x006DFE53 dword ptr [eax*4 + 0x6dfe98]; fn 0x006DFE00 at 0x006DFE53 dword ptr [eax*4 + 0x6dfe98]; fn 0x006DFE00 at 0x006DFE53 dword ptr [eax*4 + 0x6dfe98]; fn 0x006E1AF0 at 0x006E1AFC dword ptr [eax*4 + 0x6e1b28]
- E_PROTECTED_SLOT: fn 0x006DFEF0 at 0x006DFEF1 0x23ab900; fn 0x006E55D0 at 0x006E55E3 0x23af6c4; fn 0x006FACF0 at 0x006FB1E7 0x23af408; fn 0x006FACF0 at 0x006FB1E7 0x23af408
- B_GENERATED_TARGET: fn 0x0071DE60 at 0x0071DE81 0x8aa690; fn 0x00722DB0 at 0x00722DDB 0x8aa690; fn 0x0072E340 at 0x0072E547 0x8aa530; fn 0x0072E340 at 0x0072E547 0x8aa530
- B_IMPORT_SLOT: fn 0x00902DF8 at 0x00902E56 malloc; fn 0x00902EFA at 0x00902F83 free; fn 0x00902EFA at 0x00902F83 free; fn 0x0090361A at 0x00903643 malloc

## Largest distinct source closures

| root | functions | depth | boundary | imports | indirect | other edges |
| --- | --- | --- | --- | --- | --- | --- |
| `0x009EA130` | 794 | 37 | PROTECTED_BOUNDARY | memset:9, memcpy:8, memmove:5, strlen:4, strcmp:4, strcpy:2 | 1037 | unknown 21, data 122 |
| `0x009BBEC0` | 479 | 31 | PROTECTED_BOUNDARY | memset:6, memcpy:4, strcmp:3, memmove:2, strlen:2, strcpy:1 | 555 | unknown 5, data 62 |
| `0x0099E270` | 478 | 31 | PROTECTED_BOUNDARY | memset:6, memcpy:4, strcmp:3, memmove:2, strlen:2, strcpy:1 | 555 | unknown 5, data 62 |
| `0x0099DE70` | 476 | 30 | PROTECTED_BOUNDARY | memset:6, memcpy:4, strcmp:3, memmove:2, strlen:2, strcpy:1 | 552 | unknown 5, data 62 |
| `0x009BFF30` | 467 | 28 | PROTECTED_BOUNDARY | memset:6, memcpy:4, strcmp:3, memmove:2, strlen:2, strcpy:1 | 541 | unknown 5, data 62 |
| `0x0099DE30` | 465 | 29 | PROTECTED_BOUNDARY | memset:6, memcpy:4, strcmp:3, memmove:2, strlen:2, strcpy:1 | 539 | unknown 5, data 62 |
| `0x0099DE50` | 465 | 29 | PROTECTED_BOUNDARY | memset:6, memcpy:4, strcmp:3, memmove:2, strlen:2, strcpy:1 | 539 | unknown 5, data 62 |
| `0x009BF760` | 463 | 28 | PROTECTED_BOUNDARY | memset:6, memcpy:4, strcmp:3, memmove:2, strlen:2, strcpy:1 | 539 | unknown 5, data 62 |
| `0x009BF360` | 462 | 28 | PROTECTED_BOUNDARY | memset:6, memcpy:4, strcmp:3, memmove:2, strlen:2, strcpy:1 | 539 | unknown 5, data 62 |
| `0x0099F120` | 461 | 28 | PROTECTED_BOUNDARY | memset:6, memcpy:4, strcmp:3, memmove:2, strlen:2, strcpy:1 | 538 | unknown 5, data 62 |
| `0x0099F170` | 461 | 28 | PROTECTED_BOUNDARY | memset:6, memcpy:4, strcmp:3, memmove:2, strlen:2, strcpy:1 | 538 | unknown 5, data 62 |
| `0x009BAC90` | 461 | 28 | PROTECTED_BOUNDARY | memset:6, memcpy:4, strcmp:3, memmove:2, strlen:2, strcpy:1 | 538 | unknown 5, data 62 |
| `0x009BACD0` | 461 | 28 | PROTECTED_BOUNDARY | memset:6, memcpy:4, strcmp:3, memmove:2, strlen:2, strcpy:1 | 538 | unknown 5, data 62 |
| `0x0099E410` | 437 | 23 | PROTECTED_BOUNDARY | memset:7, memcpy:4, memmove:2, strcmp:2, strlen:2, strcpy:1 | 515 | unknown 4, data 61 |
| `0x009A0730` | 436 | 23 | PROTECTED_BOUNDARY | memset:7, memcpy:4, memmove:4, strlen:3, strcpy:1, strcmp:1 | 646 | unknown 3, data 77 |
| `0x009B3C00` | 433 | 24 | PROTECTED_BOUNDARY | memset:6, memcpy:4, memmove:2, strcmp:2, strlen:2, strcpy:1 | 526 | unknown 4, data 60 |
| `0x0099EF00` | 430 | 23 | PROTECTED_BOUNDARY | memset:7, memcpy:4, memmove:2, strcmp:2, strlen:2, strcpy:1 | 517 | unknown 4, data 61 |
| `0x009CDD30` | 428 | 23 | PROTECTED_BOUNDARY | memset:6, memcpy:4, memmove:2, strcmp:2, strlen:2, strcpy:1 | 519 | unknown 4, data 60 |
| `0x009B2F50` | 413 | 24 | PROTECTED_BOUNDARY | memset:8, memcpy:4, strlen:3, memmove:3, memcmp:1, vsprintf:1 | 1348 | unknown 17, data 212 |
| `0x0099F9F0` | 399 | 21 | PROTECTED_BOUNDARY | memset:5, memcpy:4, memmove:4, strlen:3, strcpy:1, strcmp:1 | 556 | unknown 3, data 70 |
| `0x009BF990` | 386 | 24 | PROTECTED_BOUNDARY | strlen:8, memcpy:7, memset:5, sprintf:2, strcmp:2, strcpy:1 | 364 | unknown 6, data 62 |
| `0x0099E050` | 357 | 24 | PROTECTED_BOUNDARY | memcpy:7, memset:5, strlen:5, sprintf:2, strcpy:1, strcmp:1 | 331 | unknown 6, data 57 |
| `0x0099E1D0` | 351 | 24 | PROTECTED_BOUNDARY | memcpy:6, memset:5, strlen:5, strcpy:1, sprintf:1, strcmp:1 | 327 | unknown 6, data 56 |
| `0x0080E770` | 340 | 31 | TLS_BOUNDARY | memcpy:3, strlen:3, memset:3, memmove:2, vsprintf:1, _crt_debugger_hook:1 | 1321 | unknown 15, data 224 |
| `0x009E9AC0` | 334 | 26 | PROTECTED_BOUNDARY | memcpy:4, memset:4, strlen:4, strcpy:1, strcmp:1, vsprintf:1 | 280 | unknown 6, data 59 |

## Extremes

- READY: largest source closure is `10` functions at `0x00950A00` (depth 4).
- READY_WITH_IMPLEMENTED_IMPORTS: largest source closure is `35` functions at `0x0096CED0` (depth 5).
- KNOWN_IMPORT_MISSING_HLE: largest source closure is `25` functions at `0x0094FFD0` (depth 6).
- MEMORY_BOUNDARY: largest source closure is `1` functions at `0x00893DF0` (depth 1).
- FILESYSTEM_BOUNDARY: largest source closure is `2` functions at `0x00945130` (depth 2).
- GRAPHICS_BOUNDARY: none
- PROTECTED_BOUNDARY: largest source closure is `794` functions at `0x009EA130` (depth 37).
- UNRESOLVED_INDIRECT_CALL: largest source closure is `288` functions at `0x00AAEF20` (depth 17).
- TIMING_BOUNDARY: largest source closure is `1` functions at `0x00895650` (depth 1).

## Largest closure of each label, any high-confidence root

- PROTECTED_BOUNDARY: `794` functions at `0x009EA130` (depth 37, missing imports strcpy, sprintf, _wassert, _snprintf, vsprintf, _crt_debugger_hook).
- TLS_BOUNDARY: `340` functions at `0x0080E770` (depth 31, missing imports vsprintf, _crt_debugger_hook).
- UNRESOLVED_INDIRECT_CALL: `334` functions at `0x009E9440` (depth 29, missing imports vsprintf, _crt_debugger_hook).
- READY_WITH_IMPLEMENTED_IMPORTS: `35` functions at `0x0096CED0` (depth 5, missing imports none).
- KNOWN_IMPORT_MISSING_HLE: `25` functions at `0x0094FFD0` (depth 6, missing imports _CItan, floor, _CIsqrt).
- READY: `19` functions at `0x00B01EB0` (depth 5, missing imports none).
- RESOLVABLE_INDIRECT_CALL: `18` functions at `0x00906973` (depth 7, missing imports strnlen).
- UNKNOWN_RUNTIME_DEPENDENCY: `16` functions at `0x009D0EE0` (depth 6, missing imports _wassert).
- NETWORK_BOUNDARY: `7` functions at `0x0088B7E0` (depth 4, missing imports ordinal 111, WSASetEvent, ordinal 4, ordinal 3, ordinal 22, ordinal 2).
- FILESYSTEM_BOUNDARY: `5` functions at `0x00944EC0` (depth 4, missing imports fclose, fwrite, fseek).
- UNKNOWN_IMPORT_ABI: `3` functions at `0x0074D3B0` (depth 3, missing imports D3DXVec4Transform).
- MEMORY_BOUNDARY: `1` functions at `0x00A07C50` (depth 1, missing imports free).
- TIMING_BOUNDARY: `1` functions at `0x00883718` (depth 1, missing imports _localtime32).
