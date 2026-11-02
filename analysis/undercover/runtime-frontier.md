# Undercover native runtime frontier

Ordinary high-confidence functions only. Import thunks are edges, not functions in a closure. Protected sections were not read. The game was not started.

A closure follows direct calls and tail jumps through reachable `HIGH_CONFIDENCE` functions. Import and indirect counts are the union of the functions in the set, each function counted once. The label is the first boundary that stops the current runtime from executing the whole set. A function that is not a source can head a larger closure than any source, so the last section is the one to use for size.

Executed paths are smaller than these static closures. `analysis/undercover/runtime-phase10.md` records which functions actually ran.

## Source closures by boundary

| boundary | source closures |
| --- | --- |
| UNRESOLVED_INDIRECT_CALL | 903 |
| READY | 394 |
| PROTECTED_BOUNDARY | 203 |
| TLS_BOUNDARY | 80 |
| UNKNOWN_RUNTIME_DEPENDENCY | 56 |
| KNOWN_IMPORT_MISSING_HLE | 26 |
| READY_WITH_IMPLEMENTED_IMPORTS | 14 |
| UNKNOWN_IMPORT_ABI | 3 |

Reachable high-confidence functions, excluding import thunks: 6498.

## Indirect sites

| kind | sites |
| --- | --- |
| D_REGISTER | 9812 |
| D_UNKNOWN | 5183 |
| E_PROTECTED_SLOT | 86 |
| B_IMPORT_SLOT | 13 |

Examples are guest addresses, not names invented for the code.

- D_REGISTER: fn 0x006DD7C0 at 0x006DD7D5 edx; fn 0x006DD7C0 at 0x006DD7E1 edx; fn 0x006DE410 at 0x006DE4AD edx; fn 0x006DE410 at 0x006DE576 eax
- D_UNKNOWN: fn 0x006DFE00 at 0x006DFE53 dword ptr [eax*4 + 0x6dfe98]; fn 0x006DFE00 at 0x006DFE53 dword ptr [eax*4 + 0x6dfe98]; fn 0x006DFE00 at 0x006DFE53 dword ptr [eax*4 + 0x6dfe98]; fn 0x006FCAA0 at 0x006FCB09 0x8a9f74
- E_PROTECTED_SLOT: fn 0x00700BB0 at 0x00700BBF 0x23afa1c; fn 0x0070B310 at 0x0070B314 0x23af1cc; fn 0x0070E370 at 0x0070E370 0x23aba54; fn 0x0071B5B0 at 0x0071B5D0 0x23abb7c
- B_IMPORT_SLOT: fn 0x00908168 at 0x0090816C malloc; fn 0x00908172 at 0x009081AB malloc; fn 0x00908172 at 0x009081DF malloc; fn 0x009086E2 at 0x0090870B malloc

## Largest distinct source closures

| root | functions | depth | boundary | imports | indirect | other edges |
| --- | --- | --- | --- | --- | --- | --- |
| `0x009DA970` | 755 | 36 | PROTECTED_BOUNDARY | memset:9, memcpy:8, memmove:5, strlen:4, strcmp:4, strcpy:2 | 995 | unknown 15, data 119 |
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
| `0x009C87D0` | 432 | 23 | PROTECTED_BOUNDARY | memset:6, memcpy:4, memmove:2, strcmp:2, strlen:2, strcpy:1 | 526 | unknown 4, data 60 |
| `0x0099EF00` | 430 | 23 | PROTECTED_BOUNDARY | memset:7, memcpy:4, memmove:2, strcmp:2, strlen:2, strcpy:1 | 517 | unknown 4, data 61 |
| `0x009B2F50` | 413 | 24 | PROTECTED_BOUNDARY | memset:8, memcpy:4, strlen:3, memmove:3, memcmp:1, vsprintf:1 | 1348 | unknown 17, data 212 |
| `0x0099F9F0` | 399 | 21 | PROTECTED_BOUNDARY | memset:5, memcpy:4, memmove:4, strlen:3, strcpy:1, strcmp:1 | 556 | unknown 3, data 70 |
| `0x009BF990` | 389 | 24 | PROTECTED_BOUNDARY | strlen:8, memcpy:7, memset:5, sprintf:2, strcmp:2, strcpy:1 | 364 | unknown 4, data 62 |
| `0x0099E050` | 360 | 24 | PROTECTED_BOUNDARY | memcpy:7, memset:5, strlen:5, sprintf:2, strcpy:1, strcmp:1 | 331 | unknown 4, data 57 |
| `0x0099E1D0` | 354 | 24 | PROTECTED_BOUNDARY | memcpy:6, memset:5, strlen:5, strcpy:1, sprintf:1, strcmp:1 | 327 | unknown 4, data 56 |
| `0x009BF440` | 336 | 24 | PROTECTED_BOUNDARY | strlen:6, memcpy:4, memset:4, strcpy:1, strcmp:1, vsprintf:1 | 279 | unknown 4, data 58 |
| `0x009DA820` | 336 | 25 | PROTECTED_BOUNDARY | memcpy:4, memset:4, strlen:4, strcpy:1, strcmp:1, vsprintf:1 | 280 | unknown 4, data 59 |
| `0x009B3110` | 320 | 27 | UNRESOLVED_INDIRECT_CALL | memcpy:3, strlen:3, memset:3, memmove:2, vsprintf:1, _crt_debugger_hook:1 | 1206 | unknown 9, data 214 |

## Extremes

- READY: largest source closure is `7` functions at `0x0098DF30` (depth 3).
- READY_WITH_IMPLEMENTED_IMPORTS: largest source closure is `31` functions at `0x00968D10` (depth 4).
- KNOWN_IMPORT_MISSING_HLE: largest source closure is `6` functions at `0x0097C4E0` (depth 4).
- MEMORY_BOUNDARY: none
- FILESYSTEM_BOUNDARY: none
- GRAPHICS_BOUNDARY: none
- PROTECTED_BOUNDARY: largest source closure is `755` functions at `0x009DA970` (depth 36).
- UNRESOLVED_INDIRECT_CALL: largest source closure is `320` functions at `0x009B3110` (depth 27).
- TIMING_BOUNDARY: none

## Largest closure of each label, any high-confidence root

- PROTECTED_BOUNDARY: `755` functions at `0x009DA970` (depth 36, missing imports strcpy, sprintf, _wassert, strncpy, _snprintf, vsprintf, _crt_debugger_hook).
- UNRESOLVED_INDIRECT_CALL: `320` functions at `0x009B3110` (depth 27, missing imports vsprintf, _crt_debugger_hook).
- TLS_BOUNDARY: `174` functions at `0x00864E20` (depth 17, missing imports _crt_debugger_hook).
- READY_WITH_IMPLEMENTED_IMPORTS: `31` functions at `0x00968D10` (depth 4, missing imports none).
- READY: `19` functions at `0x00B01EB0` (depth 5, missing imports none).
- UNKNOWN_RUNTIME_DEPENDENCY: `16` functions at `0x009D0EE0` (depth 6, missing imports _wassert).
- KNOWN_IMPORT_MISSING_HLE: `8` functions at `0x009C58E0` (depth 4, missing imports atoi, isdigit).
- RESOLVABLE_INDIRECT_CALL: `8` functions at `0x00908D42` (depth 3, missing imports none).
- NETWORK_BOUNDARY: `5` functions at `0x00895D70` (depth 4, missing imports ordinal 111, ordinal 23, ordinal 3, ordinal 4, ordinal 6, ordinal 52, ordinal 57, WSAIoctl).
- UNKNOWN_IMPORT_ABI: `3` functions at `0x0074D3B0` (depth 3, missing imports D3DXVec4Transform).
- FILESYSTEM_BOUNDARY: `2` functions at `0x00A07D60` (depth 2, missing imports fwrite, _vsnprintf).
- TIMING_BOUNDARY: `1` functions at `0x00B0C040` (depth 1, missing imports _time64).
- MEMORY_BOUNDARY: `1` functions at `0x00A07C50` (depth 1, missing imports free).
