# Undercover import frontier

Counts use the reachable high-confidence graph. A function is unlocked by one missing import when its closure has no indirect call, no protected edge, no unknown callee, and that import is the only unimplemented one. That column is the unlock count. The last column counts high-confidence roots whose closure contains the import along with whatever else blocks them. It is not an unlock count. `sprintf` and `printf` are counted, and they are not small helpers.

## Single missing import

| symbol | DLL | convention | direct sites | closures blocked only by it | functions in those closures | high roots whose closure also contains it |
| --- | --- | --- | --- | --- | --- | --- |
| `strncpy` | MSVCR80.dll | cdecl | 244 | 66 | 90 | 1026 |
| `_CIsqrt` | MSVCR80.dll | cdecl | 116 | 55 | 88 | 191 |
| `_wassert` | MSVCR80.dll | cdecl | 1 | 13 | 22 | 48 |
| `sprintf` | MSVCR80.dll | cdecl | 430 | 14 | 19 | 662 |
| `tolower` | MSVCR80.dll | cdecl | 10 | 11 | 16 | 67 |
| `_snprintf` | MSVCR80.dll | cdecl | 34 | 7 | 13 | 169 |
| `sscanf` | MSVCR80.dll | cdecl | 51 | 6 | 12 | 103 |
| `_CIpow` | MSVCR80.dll | cdecl | 18 | 6 | 11 | 16 |
| `_stricmp` | MSVCR80.dll | cdecl | 65 | 10 | 10 | 95 |
| `floor` | MSVCR80.dll | cdecl | 9 | 4 | 9 | 13 |
| `ldexp` | MSVCR80.dll | cdecl | 4 | 7 | 9 | 8 |
| `_vsnprintf` | MSVCR80.dll | cdecl | 7 | 7 | 8 | 316 |
| `strchr` | MSVCR80.dll | cdecl | 50 | 3 | 7 | 476 |
| `strtok` | MSVCR80.dll | cdecl | 26 | 2 | 7 | 61 |
| `D3DXVec4Transform` | d3dx9_34.dll | unknown | 2 | 6 | 6 | 71 |
| `fopen` | MSVCR80.dll | cdecl | 5 | 4 | 5 | 141 |
| `printf` | MSVCR80.dll | cdecl | 277 | 3 | 4 | 1478 |
| `fwrite` | MSVCR80.dll | cdecl | 13 | 2 | 4 | 155 |
| `_time64` | MSVCR80.dll | cdecl | 8 | 3 | 3 | 171 |
| `strnlen` | MSVCR80.dll | cdecl | 41 | 2 | 3 | 155 |
| `D3DXMatrixMultiply` | d3dx9_34.dll | unknown | 9 | 3 | 3 | 73 |
| `strtoul` | MSVCR80.dll | cdecl | 4 | 2 | 3 | 65 |
| `fclose` | MSVCR80.dll | cdecl | 5 | 2 | 2 | 143 |
| `ordinal 3` | WS2_32.dll / WSOCK32.dll | unknown | 4 | 2 | 2 | 143 |
| `D3DXVec3Transform` | d3dx9_34.dll | unknown | 1 | 2 | 2 | 31 |
| `__libm_sse2_exp` | MSVCR80.dll | cdecl | 4 | 2 | 2 | 12 |
| `_CItan` | MSVCR80.dll | cdecl | 5 | 2 | 2 | 10 |
| `bsearch` | MSVCR80.dll | cdecl | 3 | 2 | 2 | 5 |
| `fseek` | MSVCR80.dll | cdecl | 3 | 2 | 2 | 4 |
| `_fullpath` | MSVCR80.dll | cdecl | 1 | 2 | 2 | 4 |
| `_CIlog10` | MSVCR80.dll | cdecl | 3 | 2 | 2 | 2 |
| `free` | MSVCR80.dll | cdecl | 106 | 1 | 1 | 1057 |
| `malloc` | MSVCR80.dll | cdecl | 66 | 1 | 1 | 945 |
| `_unlock` | MSVCR80.dll | cdecl | 1 | 1 | 1 | 747 |
| `vsprintf` | MSVCR80.dll | cdecl | 4 | 1 | 1 | 225 |
| `strncat` | MSVCR80.dll | cdecl | 10 | 1 | 1 | 165 |
| `ordinal 2` | OLEAUT32.dll / WS2_32.dll / XINPUT1_3.dll | unknown | 2 | 1 | 1 | 77 |
| `ordinal 4` | WS2_32.dll / XINPUT1_3.dll | unknown | 3 | 1 | 1 | 76 |
| `atoi` | MSVCR80.dll | cdecl | 15 | 1 | 1 | 59 |
| `Netbios` | NETAPI32.dll | unknown | 2 | 1 | 1 | 30 |
| `__libm_sse2_pow` | MSVCR80.dll | cdecl | 13 | 1 | 1 | 23 |
| `strtol` | MSVCR80.dll | cdecl | 6 | 1 | 1 | 20 |
| `strtod` | MSVCR80.dll | cdecl | 3 | 1 | 1 | 12 |
| `atof` | MSVCR80.dll | cdecl | 5 | 1 | 1 | 9 |
| `_localtime32` | MSVCR80.dll | cdecl | 1 | 1 | 1 | 7 |
| `strcat_s` | MSVCR80.dll | cdecl | 1 | 1 | 1 | 6 |
| `strrchr` | MSVCR80.dll | cdecl | 1 | 1 | 1 | 5 |
| `_mkdir` | MSVCR80.dll | cdecl | 1 | 1 | 1 | 4 |
| `strcoll` | MSVCR80.dll | cdecl | 2 | 1 | 1 | 3 |
| `fflush` | MSVCR80.dll | cdecl | 1 | 1 | 1 | 3 |
| `_mkgmtime64` | MSVCR80.dll | cdecl | 1 | 1 | 1 | 3 |
| `_CIlog` | MSVCR80.dll | cdecl | 2 | 1 | 1 | 2 |
| `_aligned_malloc` | MSVCR80.dll | cdecl | 2 | 1 | 1 | 2 |
| `_aligned_free` | MSVCR80.dll | cdecl | 1 | 1 | 1 | 2 |
| `atan` | MSVCR80.dll | cdecl | 1 | 1 | 1 | 2 |
| `_crt_debugger_hook` | MSVCR80.dll | cdecl | 2 | 0 | 0 | 1165 |
| `__dllonexit` | MSVCR80.dll | cdecl | 1 | 0 | 0 | 746 |
| `_lock` | MSVCR80.dll | cdecl | 1 | 0 | 0 | 746 |
| `longjmp` | MSVCR80.dll | cdecl | 2 | 0 | 0 | 193 |
| `strcpy` | MSVCR80.dll | cdecl | 6 | 0 | 0 | 173 |
| `ordinal 111` | WS2_32.dll / WSOCK32.dll | unknown | 14 | 0 | 0 | 172 |
| `_beginthreadex` | MSVCR80.dll | cdecl | 3 | 0 | 0 | 166 |
| `_localtime64` | MSVCR80.dll | cdecl | 4 | 0 | 0 | 141 |
| `ordinal 21` | WS2_32.dll | unknown | 7 | 0 | 0 | 139 |
| `setvbuf` | MSVCR80.dll | cdecl | 2 | 0 | 0 | 134 |
| `WSASetEvent` | WS2_32.dll | stdcall | 5 | 0 | 0 | 133 |
| `asctime` | MSVCR80.dll | cdecl | 2 | 0 | 0 | 132 |
| `strcspn` | MSVCR80.dll | cdecl | 1 | 0 | 0 | 131 |
| `ceil` | MSVCR80.dll | cdecl | 7 | 0 | 0 | 126 |
| `ordinal 22` | WS2_32.dll / WSOCK32.dll | unknown | 2 | 0 | 0 | 125 |
| `WSACloseEvent` | WS2_32.dll | stdcall | 1 | 0 | 0 | 120 |
| `ordinal 19` | WS2_32.dll / WSOCK32.dll | unknown | 2 | 0 | 0 | 108 |
| `ordinal 20` | WS2_32.dll | unknown | 1 | 0 | 0 | 107 |
| `ordinal 23` | WS2_32.dll | unknown | 4 | 0 | 0 | 93 |
| `ordinal 6` | OLEAUT32.dll / WS2_32.dll | unknown | 2 | 0 | 0 | 92 |
| `ordinal 18` | WS2_32.dll | unknown | 3 | 0 | 0 | 86 |
| `iscntrl` | MSVCR80.dll | cdecl | 2 | 0 | 0 | 80 |
| `GetTickCount` | KERNEL32.dll | stdcall | 2 | 0 | 0 | 78 |
| `ordinal 5` | WS2_32.dll / XINPUT1_3.dll | unknown | 2 | 0 | 0 | 76 |
| `WSACreateEvent` | WS2_32.dll | stdcall | 2 | 0 | 0 | 73 |
| `ordinal 10` | WS2_32.dll | unknown | 2 | 0 | 0 | 73 |
| `isspace` | MSVCR80.dll | cdecl | 5 | 0 | 0 | 59 |
| `strstr` | MSVCR80.dll | cdecl | 16 | 0 | 0 | 54 |
| `ordinal 16` | WS2_32.dll / WSOCK32.dll | unknown | 2 | 0 | 0 | 53 |
| `ordinal 17` | WS2_32.dll | unknown | 1 | 0 | 0 | 52 |
| `isdigit` | MSVCR80.dll | cdecl | 13 | 0 | 0 | 46 |
| `ordinal 52` | WS2_32.dll | unknown | 3 | 0 | 0 | 43 |
| `ordinal 57` | WS2_32.dll | unknown | 2 | 0 | 0 | 42 |
| `WSAIoctl` | WS2_32.dll | stdcall | 1 | 0 | 0 | 41 |
| `__libm_sse2_sin` | MSVCR80.dll | cdecl | 34 | 0 | 0 | 39 |
| `__libm_sse2_atan2` | MSVCR80.dll | cdecl | 21 | 0 | 0 | 36 |
| `isalnum` | MSVCR80.dll | cdecl | 3 | 0 | 0 | 36 |
| `localeconv` | MSVCR80.dll | cdecl | 1 | 0 | 0 | 35 |
| `isalpha` | MSVCR80.dll | cdecl | 1 | 0 | 0 | 33 |
| `_snprintf_s` | MSVCR80.dll | cdecl | 8 | 0 | 0 | 32 |
| `ordinal 1` | DSOUND.dll / WS2_32.dll | unknown | 2 | 0 | 0 | 26 |
| `__libm_sse2_cos` | MSVCR80.dll | cdecl | 19 | 0 | 0 | 21 |
| `_CxxThrowException` | MSVCR80.dll | cdecl | 4 | 0 | 0 | 15 |
| `isprint` | MSVCR80.dll | cdecl | 4 | 0 | 0 | 11 |
| `_itoa_s` | MSVCR80.dll | cdecl | 4 | 0 | 0 | 9 |
| `isxdigit` | MSVCR80.dll | cdecl | 2 | 0 | 0 | 9 |
| `__libm_sse2_acos` | MSVCR80.dll | cdecl | 8 | 0 | 0 | 7 |
| `abs` | MSVCR80.dll | cdecl | 5 | 0 | 0 | 7 |
| `_CIasin` | MSVCR80.dll | cdecl | 2 | 0 | 0 | 7 |
| `__libm_sse2_asin` | MSVCR80.dll | cdecl | 5 | 0 | 0 | 6 |
| `DirectInput8Create` | DINPUT8.dll | stdcall | 3 | 0 | 0 | 6 |
| `_findclose` | MSVCR80.dll | cdecl | 3 | 0 | 0 | 6 |
| `strpbrk` | MSVCR80.dll | cdecl | 1 | 0 | 0 | 6 |
| `_setjmp3` | MSVCR80.dll | cdecl | 1 | 0 | 0 | 6 |
| `_findnext32` | MSVCR80.dll | cdecl | 1 | 0 | 0 | 6 |
| `_findfirst32` | MSVCR80.dll | cdecl | 1 | 0 | 0 | 6 |
| `sscanf_s` | MSVCR80.dll | cdecl | 3 | 0 | 0 | 5 |
| `D3DXGetPixelShaderProfile` | d3dx9_34.dll | unknown | 1 | 0 | 0 | 5 |
| `D3DXGetVertexShaderProfile` | d3dx9_34.dll | unknown | 1 | 0 | 0 | 5 |
| `VerQueryValueA` | VERSION.dll | stdcall | 1 | 0 | 0 | 5 |
| `GetFileVersionInfoA` | VERSION.dll | stdcall | 1 | 0 | 0 | 5 |
| `GetFileVersionInfoSizeA` | VERSION.dll | stdcall | 1 | 0 | 0 | 5 |
| `qsort` | MSVCR80.dll | cdecl | 4 | 0 | 0 | 4 |
| `getenv` | MSVCR80.dll | cdecl | 4 | 0 | 0 | 4 |
| `toupper` | MSVCR80.dll | cdecl | 3 | 0 | 0 | 4 |
| `D3DXGetShaderConstantTable` | d3dx9_34.dll | unknown | 2 | 0 | 0 | 4 |
| `_gmtime64` | MSVCR80.dll | cdecl | 2 | 0 | 0 | 4 |
| `_close` | MSVCR80.dll | cdecl | 2 | 0 | 0 | 4 |
| `_open` | MSVCR80.dll | cdecl | 2 | 0 | 0 | 4 |
| `_CIfmod` | MSVCR80.dll | cdecl | 1 | 0 | 0 | 4 |
| `_strnicmp` | MSVCR80.dll | cdecl | 1 | 0 | 0 | 4 |
| `_read` | MSVCR80.dll | cdecl | 4 | 0 | 0 | 3 |
| `_write` | MSVCR80.dll | cdecl | 3 | 0 | 0 | 3 |
| `Direct3DCreate9` | d3d9.dll | stdcall | 1 | 0 | 0 | 3 |
| `rand` | MSVCR80.dll | cdecl | 1 | 0 | 0 | 3 |
| `remove` | MSVCR80.dll | cdecl | 1 | 0 | 0 | 3 |
| `_getdiskfree` | MSVCR80.dll | cdecl | 1 | 0 | 0 | 3 |
| `_getdrive` | MSVCR80.dll | cdecl | 1 | 0 | 0 | 3 |
| `_lseek` | MSVCR80.dll | cdecl | 1 | 0 | 0 | 3 |
| `_filelength` | MSVCR80.dll | cdecl | 1 | 0 | 0 | 3 |
| `_rmdir` | MSVCR80.dll | cdecl | 1 | 0 | 0 | 3 |
| `srand` | MSVCR80.dll | cdecl | 1 | 0 | 0 | 3 |
| `D3DXFillVolumeTexture` | d3dx9_34.dll | unknown | 2 | 0 | 0 | 2 |
| `ordinal 9` | WS2_32.dll | unknown | 2 | 0 | 0 | 2 |
| `ordinal 115` | WS2_32.dll | unknown | 2 | 0 | 0 | 2 |
| `__libm_sse2_log` | MSVCR80.dll | cdecl | 1 | 0 | 0 | 2 |
| `WSARecv` | WS2_32.dll | stdcall | 1 | 0 | 0 | 2 |
| `WSARecvFrom` | WS2_32.dll | stdcall | 1 | 0 | 0 | 2 |
| `ordinal 116` | WS2_32.dll | unknown | 1 | 0 | 0 | 2 |
| `_control87` | MSVCR80.dll | cdecl | 3 | 0 | 0 | 1 |
| `D3DXCreateVolumeTextureFromFileInMemory` | d3dx9_34.dll | unknown | 1 | 0 | 0 | 1 |
| `D3DXCreateCubeTextureFromFileInMemory` | d3dx9_34.dll | unknown | 1 | 0 | 0 | 1 |
| `ordinal 11` | WS2_32.dll | unknown | 1 | 0 | 0 | 1 |
| `_strupr` | MSVCR80.dll | cdecl | 1 | 0 | 0 | 1 |
| `?_type_info_dtor_internal_method@type_info@@QAEXXZ` | MSVCR80.dll | thiscall | 1 | 0 | 0 | 1 |
| `WSAResetEvent` | WS2_32.dll | stdcall | 1 | 0 | 0 | 1 |
| `WSAWaitForMultipleEvents` | WS2_32.dll | stdcall | 1 | 0 | 0 | 1 |
| `WSAGetOverlappedResult` | WS2_32.dll | stdcall | 1 | 0 | 0 | 1 |
| `ordinal 13` | WS2_32.dll | unknown | 1 | 0 | 0 | 1 |
| `_vsnwprintf` | MSVCR80.dll | cdecl | 1 | 0 | 0 | 1 |
| `strcat` | MSVCR80.dll | cdecl | 1 | 0 | 0 | 1 |
| `_strlwr` | MSVCR80.dll | cdecl | 1 | 0 | 0 | 1 |
| `__CxxFrameHandler3` | MSVCR80.dll | cdecl | 0 | 0 | 0 | 1 |

## Otherwise-clean closures by their missing-import set

Only sets that account for a closure of at least 8 functions are listed.

| missing imports | largest such closure |
| --- | --- |
| `_CIsqrt`, `_CItan`, `floor` | 25 |
| `_wassert` | 16 |
| `_vsnprintf`, `strncpy`, `tolower` | 14 |
| `strchr`, `tolower` | 10 |
| `tolower` | 9 |
| `_CIsqrt` | 8 |
| `_CIpow` | 8 |
| `atoi`, `isdigit` | 8 |
| `atof`, `sprintf`, `strncpy` | 8 |
| `floor` | 8 |
| `sscanf` | 8 |
