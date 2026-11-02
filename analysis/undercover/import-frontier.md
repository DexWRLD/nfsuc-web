# Undercover import frontier

Counts use the reachable high-confidence graph. A function is unlocked by one missing import when its closure has no indirect call, no protected edge, no unknown callee, and that import is the only unimplemented one. That column is the unlock count. The last column counts high-confidence roots whose closure contains the import along with whatever else blocks them. It is not an unlock count. `sprintf` and `printf` are counted, and they are not small helpers. No new helper was added in Phase 10: the largest otherwise-clean closure blocked by one missing import is 16 functions (`_wassert`), and `_CIsqrt` accounts for 62 functions spread across 41 closures, none of which is a single large closure.

## Single missing import

| symbol | DLL | convention | direct sites | closures blocked only by it | functions in those closures | high roots whose closure also contains it |
| --- | --- | --- | --- | --- | --- | --- |
| `_CIsqrt` | MSVCR80.dll | cdecl | 116 | 41 | 62 | 142 |
| `_wassert` | MSVCR80.dll | cdecl | 1 | 13 | 22 | 46 |
| `sprintf` | MSVCR80.dll | cdecl | 430 | 2 | 6 | 199 |
| `D3DXVec4Transform` | d3dx9_34.dll | unknown | 2 | 6 | 6 | 62 |
| `strchr` | MSVCR80.dll | cdecl | 50 | 1 | 5 | 59 |
| `strncpy` | MSVCR80.dll | cdecl | 244 | 3 | 3 | 153 |
| `_CIpow` | MSVCR80.dll | cdecl | 18 | 1 | 3 | 1 |
| `D3DXMatrixMultiply` | d3dx9_34.dll | unknown | 9 | 2 | 2 | 56 |
| `D3DXVec3Transform` | d3dx9_34.dll | unknown | 1 | 2 | 2 | 30 |
| `__libm_sse2_exp` | MSVCR80.dll | cdecl | 4 | 2 | 2 | 9 |
| `vsprintf` | MSVCR80.dll | cdecl | 4 | 1 | 1 | 193 |
| `_vsnprintf` | MSVCR80.dll | cdecl | 7 | 1 | 1 | 92 |
| `_unlock` | MSVCR80.dll | cdecl | 1 | 1 | 1 | 60 |
| `_time64` | MSVCR80.dll | cdecl | 8 | 1 | 1 | 50 |
| `printf` | MSVCR80.dll | cdecl | 277 | 1 | 1 | 48 |
| `free` | MSVCR80.dll | cdecl | 106 | 1 | 1 | 43 |
| `strnlen` | MSVCR80.dll | cdecl | 41 | 1 | 1 | 10 |
| `atoi` | MSVCR80.dll | cdecl | 15 | 1 | 1 | 8 |
| `Netbios` | NETAPI32.dll | unknown | 2 | 1 | 1 | 5 |
| `atof` | MSVCR80.dll | cdecl | 5 | 1 | 1 | 1 |
| `atan` | MSVCR80.dll | cdecl | 1 | 1 | 1 | 1 |
| `_crt_debugger_hook` | MSVCR80.dll | cdecl | 2 | 0 | 0 | 581 |
| `strcpy` | MSVCR80.dll | cdecl | 6 | 0 | 0 | 148 |
| `__dllonexit` | MSVCR80.dll | cdecl | 1 | 0 | 0 | 59 |
| `_lock` | MSVCR80.dll | cdecl | 1 | 0 | 0 | 59 |
| `strncat` | MSVCR80.dll | cdecl | 10 | 0 | 0 | 56 |
| `ceil` | MSVCR80.dll | cdecl | 7 | 0 | 0 | 52 |
| `malloc` | MSVCR80.dll | cdecl | 66 | 0 | 0 | 50 |
| `strstr` | MSVCR80.dll | cdecl | 16 | 0 | 0 | 37 |
| `longjmp` | MSVCR80.dll | cdecl | 2 | 0 | 0 | 29 |
| `strcspn` | MSVCR80.dll | cdecl | 1 | 0 | 0 | 26 |
| `_snprintf` | MSVCR80.dll | cdecl | 34 | 0 | 0 | 25 |
| `ordinal 111` | WS2_32.dll / WSOCK32.dll | unknown | 14 | 0 | 0 | 22 |
| `fwrite` | MSVCR80.dll | cdecl | 13 | 0 | 0 | 21 |
| `fclose` | MSVCR80.dll | cdecl | 5 | 0 | 0 | 20 |
| `fopen` | MSVCR80.dll | cdecl | 5 | 0 | 0 | 19 |
| `_localtime64` | MSVCR80.dll | cdecl | 4 | 0 | 0 | 19 |
| `asctime` | MSVCR80.dll | cdecl | 2 | 0 | 0 | 19 |
| `setvbuf` | MSVCR80.dll | cdecl | 2 | 0 | 0 | 19 |
| `ordinal 3` | WS2_32.dll / WSOCK32.dll | unknown | 4 | 0 | 0 | 18 |
| `__libm_sse2_sin` | MSVCR80.dll | cdecl | 34 | 0 | 0 | 14 |
| `ordinal 23` | WS2_32.dll | unknown | 4 | 0 | 0 | 14 |
| `ordinal 6` | OLEAUT32.dll / WS2_32.dll | unknown | 2 | 0 | 0 | 14 |
| `ordinal 21` | WS2_32.dll | unknown | 7 | 0 | 0 | 13 |
| `strtoul` | MSVCR80.dll | cdecl | 4 | 0 | 0 | 13 |
| `ordinal 4` | WS2_32.dll / XINPUT1_3.dll | unknown | 3 | 0 | 0 | 13 |
| `ordinal 52` | WS2_32.dll | unknown | 3 | 0 | 0 | 13 |
| `ordinal 57` | WS2_32.dll | unknown | 2 | 0 | 0 | 13 |
| `WSAIoctl` | WS2_32.dll | stdcall | 1 | 0 | 0 | 13 |
| `isdigit` | MSVCR80.dll | cdecl | 13 | 0 | 0 | 12 |
| `WSASetEvent` | WS2_32.dll | stdcall | 5 | 0 | 0 | 12 |
| `ordinal 22` | WS2_32.dll / WSOCK32.dll | unknown | 2 | 0 | 0 | 12 |
| `iscntrl` | MSVCR80.dll | cdecl | 2 | 0 | 0 | 11 |
| `WSACloseEvent` | WS2_32.dll | stdcall | 1 | 0 | 0 | 11 |
| `__libm_sse2_cos` | MSVCR80.dll | cdecl | 19 | 0 | 0 | 10 |
| `__libm_sse2_pow` | MSVCR80.dll | cdecl | 13 | 0 | 0 | 10 |
| `ordinal 19` | WS2_32.dll / WSOCK32.dll | unknown | 2 | 0 | 0 | 10 |
| `ordinal 20` | WS2_32.dll | unknown | 1 | 0 | 0 | 10 |
| `__libm_sse2_atan2` | MSVCR80.dll | cdecl | 21 | 0 | 0 | 9 |
| `ordinal 18` | WS2_32.dll | unknown | 3 | 0 | 0 | 9 |
| `ordinal 5` | WS2_32.dll / XINPUT1_3.dll | unknown | 2 | 0 | 0 | 9 |
| `isxdigit` | MSVCR80.dll | cdecl | 2 | 0 | 0 | 9 |
| `strtol` | MSVCR80.dll | cdecl | 6 | 0 | 0 | 7 |
| `abs` | MSVCR80.dll | cdecl | 5 | 0 | 0 | 7 |
| `_beginthreadex` | MSVCR80.dll | cdecl | 3 | 0 | 0 | 7 |
| `ordinal 2` | OLEAUT32.dll / WS2_32.dll / XINPUT1_3.dll | unknown | 2 | 0 | 0 | 7 |
| `_CIasin` | MSVCR80.dll | cdecl | 2 | 0 | 0 | 6 |
| `WSACreateEvent` | WS2_32.dll | stdcall | 2 | 0 | 0 | 6 |
| `ordinal 10` | WS2_32.dll | unknown | 2 | 0 | 0 | 6 |
| `__libm_sse2_acos` | MSVCR80.dll | cdecl | 8 | 0 | 0 | 5 |
| `GetTickCount` | KERNEL32.dll | stdcall | 2 | 0 | 0 | 5 |
| `__libm_sse2_asin` | MSVCR80.dll | cdecl | 5 | 0 | 0 | 4 |
| `isspace` | MSVCR80.dll | cdecl | 5 | 0 | 0 | 4 |
| `_CxxThrowException` | MSVCR80.dll | cdecl | 4 | 0 | 0 | 4 |
| `isalnum` | MSVCR80.dll | cdecl | 3 | 0 | 0 | 4 |
| `_CIfmod` | MSVCR80.dll | cdecl | 1 | 0 | 0 | 4 |
| `tolower` | MSVCR80.dll | cdecl | 10 | 0 | 0 | 3 |
| `toupper` | MSVCR80.dll | cdecl | 3 | 0 | 0 | 3 |
| `localeconv` | MSVCR80.dll | cdecl | 1 | 0 | 0 | 3 |
| `sscanf` | MSVCR80.dll | cdecl | 51 | 0 | 0 | 2 |
| `strtok` | MSVCR80.dll | cdecl | 26 | 0 | 0 | 2 |
| `floor` | MSVCR80.dll | cdecl | 9 | 0 | 0 | 2 |
| `qsort` | MSVCR80.dll | cdecl | 4 | 0 | 0 | 2 |
| `__libm_sse2_log` | MSVCR80.dll | cdecl | 1 | 0 | 0 | 1 |
| `_strupr` | MSVCR80.dll | cdecl | 1 | 0 | 0 | 1 |
| `strcat` | MSVCR80.dll | cdecl | 1 | 0 | 0 | 1 |
| `_setjmp3` | MSVCR80.dll | cdecl | 1 | 0 | 0 | 1 |
| `isalpha` | MSVCR80.dll | cdecl | 1 | 0 | 0 | 1 |
| `_strlwr` | MSVCR80.dll | cdecl | 1 | 0 | 0 | 1 |

## Otherwise-clean closures by their missing-import set

Only sets that account for a closure of at least 8 functions are listed.

| missing imports | largest such closure |
| --- | --- |
| `_wassert` | 16 |
| `atoi`, `isdigit` | 8 |
