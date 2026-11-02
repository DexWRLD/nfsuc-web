# Undercover import thunks

`.text` calls a small stub, and the stub is `jmp dword ptr [slot]` with `slot` in `.rdata`. The PE import address table in the data directory sits in `.securom` and was not read. The slot's on-disk dword is the unbound import entry already stored in `.rdata`: an ordinal with the high bit set, or the RVA of a hint followed by the symbol name.

The DLL is the one `nfs-pe.json` lists for that symbol. A symbol listed for more than one DLL stays unresolved rather than being assigned. This file does not implement the Win32 or CRT runtime.

## Calling convention

The convention comes from the symbol and the DLL, not from a guess about the call site.

- `@@QAE`, `@@UAE`, and `@@QBE` are thiscall. `@@YA` is cdecl. `@@YG` and `@@SG` are stdcall.
- A C++ name with some other mangling stays unknown.
- `_name@N` is stdcall. `@name@N` is fastcall.
- An undecorated MSVCR80 or MSVCP80 export is cdecl.
- An undecorated KERNEL32, USER32, GDI32, ADVAPI32, SHELL32, OLE32, OLEAUT32, SHLWAPI, SETUPAPI, VERSION, WINTRUST, CRYPT32, imagehlp, WS2_32, or WSOCK32 export is stdcall.
- `wsprintfA` and `wsprintfW` are cdecl even though they live in USER32.
- `Direct3DCreate9` and `DirectInput8Create` are stdcall. Other DirectX names stay unknown.
- An ordinal (`#N`) stays unknown. The number alone does not say how the callee pops arguments.

## Counts

- Thunks whose slot is in `.rdata`: 199
- Resolved to a symbol: 199
- Slots that are not an import entry: 0
- Direct calls to resolved thunks: 3404
- Direct tail jumps to resolved thunks: 2604

Call and tail counts are from a linear sweep, so a CALL decoded out of embedded data can add to them.

### By convention

- cdecl: 137
- stdcall: 19
- thiscall: 1
- unknown: 42

### By DLL

- MSVCR80.dll: 138
- WS2_32.dll: 26
- d3dx9_34.dll: 10
- WS2_32.dll / WSOCK32.dll: 5
- KERNEL32.dll: 4
- WS2_32.dll / XINPUT1_3.dll: 4
- VERSION.dll: 3
- OLEAUT32.dll / WS2_32.dll / XINPUT1_3.dll: 2
- DSOUND.dll / WS2_32.dll: 2
- d3d9.dll: 1
- DINPUT8.dll: 1
- WINTRUST.dll: 1
- NETAPI32.dll: 1
- OLEAUT32.dll / WS2_32.dll: 1

## Thunks

| Thunk | Slot | DLL | Symbol | Calls | Tail jmps | Convention |
| --- | --- | --- | --- | --- | --- | --- |
| 0x0087A78A | 0x00B610A8 | KERNEL32.dll | `Process32Next` | 1 | 0 | stdcall |
| 0x0087A790 | 0x00B610AC | KERNEL32.dll | `Process32First` | 1 | 0 | stdcall |
| 0x0087A796 | 0x00B610B0 | KERNEL32.dll | `CreateToolhelp32Snapshot` | 2 | 0 | stdcall |
| 0x0087A79C | 0x00B616CC | d3d9.dll | `Direct3DCreate9` | 1 | 0 | stdcall |
| 0x0087A7AE | 0x00B616D4 | d3dx9_34.dll | `D3DXMatrixMultiply` | 9 | 0 | unknown |
| 0x0087A7B4 | 0x00B616D8 | d3dx9_34.dll | `D3DXVec4Transform` | 2 | 0 | unknown |
| 0x0087A7BA | 0x00B61700 | d3dx9_34.dll | `D3DXVec3Transform` | 1 | 0 | unknown |
| 0x0087A7C0 | 0x00B616DC | d3dx9_34.dll | `D3DXGetPixelShaderProfile` | 1 | 0 | unknown |
| 0x0087A7C6 | 0x00B616F4 | d3dx9_34.dll | `D3DXGetVertexShaderProfile` | 1 | 0 | unknown |
| 0x0087A7CC | 0x00B616FC | d3dx9_34.dll | `D3DXFillVolumeTexture` | 2 | 0 | unknown |
| 0x0087A7D2 | 0x00B616F8 | d3dx9_34.dll | `D3DXCreateVolumeTextureFromFileInMemory` | 1 | 0 | unknown |
| 0x0087A7D8 | 0x00B616E8 | d3dx9_34.dll | `D3DXCreateCubeTextureFromFileInMemory` | 1 | 0 | unknown |
| 0x0087A7DE | 0x00B616F0 | d3dx9_34.dll | `D3DXGetShaderConstantTable` | 2 | 0 | unknown |
| 0x0087A7E4 | 0x00B616EC | d3dx9_34.dll | `D3DXSaveSurfaceToFileInMemory` | 1 | 0 | unknown |
| 0x0087B2A0 | 0x00B6105C | DINPUT8.dll | `DirectInput8Create` | 3 | 0 | stdcall |
| 0x0087B2A6 | 0x00B616BC | OLEAUT32.dll / WS2_32.dll / XINPUT1_3.dll | `#2` | 2 | 0 | unknown |
| 0x0087B2AC | 0x00B616C4 | WS2_32.dll / XINPUT1_3.dll | `#4` | 1 | 0 | unknown |
| 0x0087B2B2 | 0x00B616C0 | WS2_32.dll / XINPUT1_3.dll | `#5` | 2 | 0 | unknown |
| 0x0087B2B8 | 0x00B61620 | WS2_32.dll | `#11` | 1 | 0 | unknown |
| 0x0087B2BE | 0x00B6161C | WS2_32.dll | `#9` | 2 | 0 | unknown |
| 0x0087B2C4 | 0x00B615EC | VERSION.dll | `VerQueryValueA` | 1 | 0 | stdcall |
| 0x0087B2CA | 0x00B615F4 | VERSION.dll | `GetFileVersionInfoA` | 1 | 0 | stdcall |
| 0x0087B2D0 | 0x00B615F0 | VERSION.dll | `GetFileVersionInfoSizeA` | 1 | 0 | stdcall |
| 0x0087B2D6 | 0x00B6123C | MSVCR80.dll | `memset` | 597 | 2 | cdecl |
| 0x0087B2E0 | 0x00B61240 | MSVCR80.dll | `_CIacos` | 4 | 0 | cdecl |
| 0x0087B2E6 | 0x00B61244 | MSVCR80.dll | `_CIasin` | 2 | 0 | cdecl |
| 0x0087B2EC | 0x00B61248 | MSVCR80.dll | `floor` | 9 | 0 | cdecl |
| 0x0087B2F2 | 0x00B6124C | MSVCR80.dll | `_CIpow` | 18 | 0 | cdecl |
| 0x0087B34A | 0x00B61250 | MSVCR80.dll | `__CxxFrameHandler3` | 0 | 2579 | cdecl |
| 0x0087B366 | 0x00B61258 | MSVCR80.dll | `__libm_sse2_sin` | 34 | 0 | cdecl |
| 0x0087B36C | 0x00B6125C | MSVCR80.dll | `__libm_sse2_cos` | 19 | 0 | cdecl |
| 0x0087B372 | 0x00B61260 | MSVCR80.dll | `__libm_sse2_asin` | 5 | 0 | cdecl |
| 0x0087B378 | 0x00B61264 | MSVCR80.dll | `__libm_sse2_acos` | 8 | 0 | cdecl |
| 0x0087B37E | 0x00B61268 | MSVCR80.dll | `__libm_sse2_atan2` | 21 | 0 | cdecl |
| 0x0087B446 | 0x00B6126C | MSVCR80.dll | `__libm_sse2_pow` | 13 | 0 | cdecl |
| 0x0087B44C | 0x00B61270 | MSVCR80.dll | `memcpy` | 357 | 4 | cdecl |
| 0x0087B4B8 | 0x00B61274 | MSVCR80.dll | `memmove` | 98 | 1 | cdecl |
| 0x0087B694 | 0x00B61284 | MSVCR80.dll | `tolower` | 10 | 0 | cdecl |
| 0x0087B69A | 0x00B614D4 | MSVCR80.dll | `atoi` | 15 | 0 | cdecl |
| 0x0087B6A0 | 0x00B6128C | MSVCR80.dll | `strncpy` | 244 | 2 | cdecl |
| 0x0087B6A6 | 0x00B61290 | MSVCR80.dll | `strstr` | 16 | 1 | cdecl |
| 0x0087B6AC | 0x00B61294 | MSVCR80.dll | `_CxxThrowException` | 4 | 0 | cdecl |
| 0x0087B6B8 | 0x00B6129C | MSVCR80.dll | `rand` | 1 | 0 | cdecl |
| 0x0087B6BE | 0x00B612A0 | MSVCR80.dll | `_CIfmod` | 1 | 0 | cdecl |
| 0x0087B6C4 | 0x00B612A4 | MSVCR80.dll | `strrchr` | 1 | 1 | cdecl |
| 0x0087B6CA | 0x00B612A8 | MSVCR80.dll | `sprintf` | 430 | 0 | cdecl |
| 0x0087B6F2 | 0x00B612AC | MSVCR80.dll | `printf` | 277 | 0 | cdecl |
| 0x0087B6F8 | 0x00B612B0 | MSVCR80.dll | `malloc` | 66 | 2 | cdecl |
| 0x0087B6FE | 0x00B612B4 | MSVCR80.dll | `free` | 106 | 1 | cdecl |
| 0x0087B7F0 | 0x00B612B8 | MSVCR80.dll | `__libm_sse2_exp` | 4 | 0 | cdecl |
| 0x0087B7F6 | 0x00B612BC | MSVCR80.dll | `strchr` | 50 | 1 | cdecl |
| 0x0087B7FC | 0x00B612C0 | MSVCR80.dll | `isspace` | 5 | 0 | cdecl |
| 0x0087B802 | 0x00B612C4 | MSVCR80.dll | `atof` | 5 | 0 | cdecl |
| 0x0087B808 | 0x00B612C8 | MSVCR80.dll | `sscanf` | 51 | 0 | cdecl |
| 0x0087B80E | 0x00B612CC | MSVCR80.dll | `strncat` | 10 | 0 | cdecl |
| 0x0087B814 | 0x00B612D0 | MSVCR80.dll | `qsort` | 4 | 0 | cdecl |
| 0x0087B81A | 0x00B612D4 | MSVCR80.dll | `ceil` | 7 | 0 | cdecl |
| 0x0087B820 | 0x00B612D8 | MSVCR80.dll | `fclose` | 5 | 1 | cdecl |
| 0x0087B826 | 0x00B612DC | MSVCR80.dll | `fopen` | 5 | 0 | cdecl |
| 0x0087B82C | 0x00B612E0 | MSVCR80.dll | `_time64` | 8 | 0 | cdecl |
| 0x0087B832 | 0x00B612E4 | MSVCR80.dll | `strtok` | 26 | 0 | cdecl |
| 0x0087B838 | 0x00B612E8 | MSVCR80.dll | `_isnan` | 24 | 0 | cdecl |
| 0x0087B83E | 0x00B612EC | MSVCR80.dll | `exit` | 1 | 0 | cdecl |
| 0x0087B844 | 0x00B612F0 | MSVCR80.dll | `vsprintf` | 4 | 0 | cdecl |
| 0x0087B8E8 | 0x00B612F8 | MSVCR80.dll | `__iob_func` | 1 | 0 | cdecl |
| 0x0087B8EE | 0x00B61300 | MSVCR80.dll | `_controlfp_s` | 1 | 0 | cdecl |
| 0x0087B9DA | 0x00B61310 | MSVCR80.dll | `__libm_sse2_log` | 1 | 0 | cdecl |
| 0x0087B9E0 | 0x00B61314 | MSVCR80.dll | `fwrite` | 13 | 0 | cdecl |
| 0x0087B9E6 | 0x00B61318 | MSVCR80.dll | `_strupr` | 1 | 0 | cdecl |
| 0x0087B9EC | 0x00B61320 | MSVCR80.dll | `toupper` | 3 | 0 | cdecl |
| 0x0087B9F2 | 0x00B61324 | MSVCR80.dll | `fread` | 1 | 0 | cdecl |
| 0x0087B9F8 | 0x00B61328 | MSVCR80.dll | `ftell` | 2 | 0 | cdecl |
| 0x0087B9FE | 0x00B6132C | MSVCR80.dll | `fseek` | 3 | 0 | cdecl |
| 0x0087BA04 | 0x00B61338 | MSVCR80.dll | `remove` | 1 | 0 | cdecl |
| 0x0087BA0A | 0x00B6133C | MSVCR80.dll | `strncmp` | 8 | 1 | cdecl |
| 0x0087BA10 | 0x00B61350 | MSVCR80.dll | `strcat_s` | 1 | 0 | cdecl |
| 0x0087BA16 | 0x00B61354 | MSVCR80.dll | `_stricmp` | 65 | 1 | cdecl |
| 0x0087BA1C | 0x00B61358 | MSVCR80.dll | `fflush` | 1 | 2 | cdecl |
| 0x0087BA22 | 0x00B61360 | MSVCR80.dll | `_gmtime64` | 2 | 0 | cdecl |
| 0x0087BA28 | 0x00B61364 | MSVCR80.dll | `isdigit` | 13 | 0 | cdecl |
| 0x0087BA2E | 0x00B61368 | MSVCR80.dll | `isxdigit` | 2 | 0 | cdecl |
| 0x0087BA34 | 0x00B6136C | MSVCR80.dll | `isalnum` | 3 | 0 | cdecl |
| 0x0087BDA0 | 0x00B61374 | MSVCR80.dll | `_strnicmp` | 1 | 0 | cdecl |
| 0x0087BDA6 | 0x00B61378 | MSVCR80.dll | `_mkdir` | 1 | 0 | cdecl |
| 0x0087BEB0 | 0x00B61380 | MSVCR80.dll | `?terminate@@YAXXZ` | 2 | 0 | cdecl |
| 0x0087BFF2 | 0x00B61384 | MSVCR80.dll | `_unlock` | 1 | 0 | cdecl |
| 0x0087BFF8 | 0x00B61388 | MSVCR80.dll | `__dllonexit` | 1 | 0 | cdecl |
| 0x0087BFFE | 0x00B61390 | MSVCR80.dll | `_lock` | 1 | 0 | cdecl |
| 0x0087C09A | 0x00B6139C | MSVCR80.dll | `_amsg_exit` | 2 | 0 | cdecl |
| 0x0087C0E8 | 0x00B613A8 | MSVCR80.dll | `_XcptFilter` | 1 | 0 | cdecl |
| 0x0087C22C | 0x00B613B0 | MSVCR80.dll | `_initterm` | 1 | 0 | cdecl |
| 0x0087C232 | 0x00B613B4 | MSVCR80.dll | `_initterm_e` | 1 | 0 | cdecl |
| 0x0087C2F8 | 0x00B613D0 | MSVCR80.dll | `?_type_info_dtor_internal_method@type_info@@QAEXXZ` | 1 | 0 | thiscall |
| 0x0087C2FE | 0x00B613D4 | MSVCR80.dll | `_crt_debugger_hook` | 2 | 0 | cdecl |
| 0x0087C304 | 0x00B613D8 | MSVCR80.dll | `_except_handler4_common` | 1 | 0 | cdecl |
| 0x0087C30A | 0x00B613DC | MSVCR80.dll | `_invoke_watson` | 1 | 0 | cdecl |
| 0x00887700 | 0x00B6160C | WINTRUST.dll | `WinVerifyTrust` | 1 | 0 | stdcall |
| 0x00889450 | 0x00B611D0 | KERNEL32.dll | `GetTickCount` | 2 | 0 | stdcall |
| 0x00AE3ED2 | 0x00B61064 | DSOUND.dll / WS2_32.dll | `#1` | 2 | 0 | unknown |
| 0x00AE4F90 | 0x00B614E0 | NETAPI32.dll | `Netbios` | 2 | 0 | unknown |
| 0x00AE4F96 | 0x00B616A0 | WS2_32.dll / WSOCK32.dll | `#111` | 14 | 0 | unknown |
| 0x00AE4F9C | 0x00B6169C | WS2_32.dll | `WSACreateEvent` | 2 | 0 | stdcall |
| 0x00AE4FA2 | 0x00B61698 | WS2_32.dll | `#21` | 7 | 0 | unknown |
| 0x00AE4FA8 | 0x00B61694 | WS2_32.dll | `#10` | 2 | 0 | unknown |
| 0x00AE4FAE | 0x00B616B4 | WS2_32.dll | `#23` | 4 | 0 | unknown |
| 0x00AE4FB4 | 0x00B61690 | WS2_32.dll / WSOCK32.dll | `#3` | 4 | 0 | unknown |
| 0x00AE4FBA | 0x00B6168C | WS2_32.dll / WSOCK32.dll | `#22` | 2 | 0 | unknown |
| 0x00AE4FC0 | 0x00B61688 | WS2_32.dll | `WSACloseEvent` | 1 | 0 | stdcall |
| 0x00AE4FC6 | 0x00B61684 | WS2_32.dll | `WSASetEvent` | 5 | 0 | stdcall |
| 0x00AE4FCC | 0x00B61680 | WS2_32.dll | `WSARecv` | 1 | 0 | stdcall |
| 0x00AE4FD2 | 0x00B6167C | WS2_32.dll | `WSARecvFrom` | 1 | 0 | stdcall |
| 0x00AE4FD8 | 0x00B61678 | WS2_32.dll | `WSAResetEvent` | 1 | 0 | stdcall |
| 0x00AE4FDE | 0x00B61674 | WS2_32.dll | `WSAWaitForMultipleEvents` | 1 | 0 | stdcall |
| 0x00AE4FE4 | 0x00B61670 | WS2_32.dll | `WSAGetOverlappedResult` | 1 | 0 | stdcall |
| 0x00AE4FEA | 0x00B6166C | WS2_32.dll | `#115` | 2 | 0 | unknown |
| 0x00AE4FF0 | 0x00B61668 | OLEAUT32.dll / WS2_32.dll / XINPUT1_3.dll | `#2` | 2 | 0 | unknown |
| 0x00AE4FF6 | 0x00B61664 | WS2_32.dll / XINPUT1_3.dll | `#4` | 3 | 0 | unknown |
| 0x00AE4FFC | 0x00B61660 | WS2_32.dll | `#13` | 1 | 0 | unknown |
| 0x00AE5002 | 0x00B6165C | DSOUND.dll / WS2_32.dll | `#1` | 2 | 0 | unknown |
| 0x00AE5008 | 0x00B61658 | WS2_32.dll | `#20` | 1 | 0 | unknown |
| 0x00AE500E | 0x00B61654 | WS2_32.dll / WSOCK32.dll | `#19` | 2 | 0 | unknown |
| 0x00AE5014 | 0x00B616B0 | WS2_32.dll / WSOCK32.dll | `#16` | 2 | 0 | unknown |
| 0x00AE501A | 0x00B6164C | WS2_32.dll | `#17` | 1 | 0 | unknown |
| 0x00AE5020 | 0x00B61648 | WS2_32.dll / XINPUT1_3.dll | `#5` | 2 | 0 | unknown |
| 0x00AE5026 | 0x00B61644 | WS2_32.dll | `#18` | 3 | 0 | unknown |
| 0x00AE502C | 0x00B61640 | OLEAUT32.dll / WS2_32.dll | `#6` | 2 | 0 | unknown |
| 0x00AE5032 | 0x00B6163C | WS2_32.dll | `#52` | 3 | 0 | unknown |
| 0x00AE5038 | 0x00B61638 | WS2_32.dll | `#57` | 2 | 0 | unknown |
| 0x00AE503E | 0x00B61634 | WS2_32.dll | `WSAIoctl` | 1 | 0 | stdcall |
| 0x00AE5044 | 0x00B61630 | WS2_32.dll | `#116` | 1 | 0 | unknown |
| 0x00AE504A | 0x00B61624 | WS2_32.dll | `#15` | 1 | 0 | unknown |
| 0x00AE5050 | 0x00B616A4 | WS2_32.dll | `#101` | 1 | 0 | unknown |
| 0x00AE5056 | 0x00B616A8 | WS2_32.dll | `#12` | 1 | 0 | unknown |
| 0x00AE505C | 0x00B616AC | WS2_32.dll | `#151` | 1 | 0 | unknown |
| 0x00AE5062 | 0x00B613FC | MSVCR80.dll | `_endthreadex` | 1 | 0 | cdecl |
| 0x00AE5068 | 0x00B61238 | MSVCR80.dll | `_beginthreadex` | 3 | 0 | cdecl |
| 0x00AE506E | 0x00B61234 | MSVCR80.dll | `bsearch` | 3 | 0 | cdecl |
| 0x00AE5074 | 0x00B61230 | MSVCR80.dll | `_vsnprintf` | 7 | 1 | cdecl |
| 0x00AE507A | 0x00B61308 | MSVCR80.dll | `_vsnwprintf` | 1 | 0 | cdecl |
| 0x00AE5080 | 0x00B613E0 | MSVCR80.dll | `getenv` | 4 | 0 | cdecl |
| 0x00AE5086 | 0x00B613E4 | MSVCR80.dll | `_findclose` | 3 | 0 | cdecl |
| 0x00AE508C | 0x00B613E8 | MSVCR80.dll | `_getdiskfree` | 1 | 0 | cdecl |
| 0x00AE5092 | 0x00B613F0 | MSVCR80.dll | `_getdrive` | 1 | 0 | cdecl |
| 0x00AE5098 | 0x00B61288 | MSVCR80.dll | `_fullpath` | 1 | 0 | cdecl |
| 0x00AE509E | 0x00B613F4 | MSVCR80.dll | `_close` | 2 | 0 | cdecl |
| 0x00AE50A4 | 0x00B613F8 | MSVCR80.dll | `_write` | 3 | 0 | cdecl |
| 0x00AE50AA | 0x00B61400 | MSVCR80.dll | `_open` | 2 | 0 | cdecl |
| 0x00AE50B0 | 0x00B61404 | MSVCR80.dll | `_lseek` | 1 | 0 | cdecl |
| 0x00AE50B6 | 0x00B61408 | MSVCR80.dll | `_read` | 4 | 0 | cdecl |
| 0x00AE50BC | 0x00B6140C | MSVCR80.dll | `_filelength` | 1 | 0 | cdecl |
| 0x00AE50C2 | 0x00B61410 | MSVCR80.dll | `_rmdir` | 1 | 0 | cdecl |
| 0x00AE50C8 | 0x00B61414 | MSVCR80.dll | `__CxxFrameHandler` | 0 | 2 | cdecl |
| 0x00AE50CE | 0x00B61418 | MSVCR80.dll | `strtol` | 6 | 0 | cdecl |
| 0x00AE50D4 | 0x00B6141C | MSVCR80.dll | `_mktime64` | 1 | 0 | cdecl |
| 0x00AE50DA | 0x00B61420 | MSVCR80.dll | `_localtime64` | 4 | 0 | cdecl |
| 0x00AE50E0 | 0x00B61424 | MSVCR80.dll | `_snprintf` | 34 | 0 | cdecl |
| 0x00AE50E6 | 0x00B61428 | MSVCR80.dll | `_mkgmtime64` | 1 | 0 | cdecl |
| 0x00AE50EC | 0x00B6142C | MSVCR80.dll | `asctime` | 2 | 0 | cdecl |
| 0x00AE50F2 | 0x00B61430 | MSVCR80.dll | `strpbrk` | 1 | 0 | cdecl |
| 0x00AE50F8 | 0x00B61434 | MSVCR80.dll | `isprint` | 4 | 0 | cdecl |
| 0x00AE50FE | 0x00B61438 | MSVCR80.dll | `_difftime64` | 1 | 0 | cdecl |
| 0x00AE5104 | 0x00B6143C | MSVCR80.dll | `strnlen` | 41 | 0 | cdecl |
| 0x00AE510A | 0x00B61440 | MSVCR80.dll | `_snprintf_s` | 8 | 0 | cdecl |
| 0x00AE5110 | 0x00B61444 | MSVCR80.dll | `_CIcos` | 38 | 0 | cdecl |
| 0x00AE5116 | 0x00B61448 | MSVCR80.dll | `_CIsqrt` | 116 | 0 | cdecl |
| 0x00AE511C | 0x00B6144C | MSVCR80.dll | `srand` | 1 | 0 | cdecl |
| 0x00AE5122 | 0x00B61450 | MSVCR80.dll | `sscanf_s` | 3 | 0 | cdecl |
| 0x00AE5128 | 0x00B61454 | MSVCR80.dll | `_itoa_s` | 4 | 0 | cdecl |
| 0x00AE512E | 0x00B61458 | MSVCR80.dll | `_CIatan2` | 9 | 0 | cdecl |
| 0x00AE5134 | 0x00B6145C | MSVCR80.dll | `_CIlog` | 2 | 0 | cdecl |
| 0x00AE513A | 0x00B61460 | MSVCR80.dll | `_CIlog10` | 3 | 0 | cdecl |
| 0x00AE5140 | 0x00B61464 | MSVCR80.dll | `_CIsin` | 39 | 0 | cdecl |
| 0x00AE5146 | 0x00B61468 | MSVCR80.dll | `_CItan` | 5 | 0 | cdecl |
| 0x00AE514C | 0x00B6146C | MSVCR80.dll | `ldexp` | 4 | 0 | cdecl |
| 0x00AE52B6 | 0x00B61474 | MSVCR80.dll | `_aligned_malloc` | 2 | 1 | cdecl |
| 0x00AE52BC | 0x00B61478 | MSVCR80.dll | `_aligned_free` | 1 | 1 | cdecl |
| 0x00AE52C2 | 0x00B6147C | MSVCR80.dll | `_control87` | 3 | 0 | cdecl |
| 0x00AE52C8 | 0x00B61480 | MSVCR80.dll | `strcmp` | 33 | 0 | cdecl |
| 0x00AE52CE | 0x00B61484 | MSVCR80.dll | `abs` | 5 | 0 | cdecl |
| 0x00AE52D4 | 0x00B61488 | MSVCR80.dll | `memcmp` | 8 | 0 | cdecl |
| 0x00AE52DA | 0x00B6148C | MSVCR80.dll | `atan` | 1 | 0 | cdecl |
| 0x00AE52E0 | 0x00B61490 | MSVCR80.dll | `strcpy` | 6 | 0 | cdecl |
| 0x00AE52E6 | 0x00B61494 | MSVCR80.dll | `strcat` | 1 | 0 | cdecl |
| 0x00AE52EC | 0x00B61498 | MSVCR80.dll | `strlen` | 123 | 0 | cdecl |
| 0x00AE52F2 | 0x00B6149C | MSVCR80.dll | `strtoul` | 4 | 0 | cdecl |
| 0x00AE52F8 | 0x00B614A0 | MSVCR80.dll | `_wassert` | 1 | 0 | cdecl |
| 0x00AE52FE | 0x00B614A4 | MSVCR80.dll | `strcspn` | 1 | 0 | cdecl |
| 0x00AE5304 | 0x00B614A8 | MSVCR80.dll | `_setjmp3` | 1 | 0 | cdecl |
| 0x00AE530A | 0x00B614AC | MSVCR80.dll | `longjmp` | 2 | 0 | cdecl |
| 0x00AE5310 | 0x00B614B0 | MSVCR80.dll | `strcoll` | 2 | 0 | cdecl |
| 0x00AE5316 | 0x00B614B4 | MSVCR80.dll | `iscntrl` | 2 | 0 | cdecl |
| 0x00AE531C | 0x00B614B8 | MSVCR80.dll | `localeconv` | 1 | 0 | cdecl |
| 0x00AE5322 | 0x00B614BC | MSVCR80.dll | `isalpha` | 1 | 0 | cdecl |
| 0x00AE5328 | 0x00B614C0 | MSVCR80.dll | `strtod` | 3 | 0 | cdecl |
| 0x00AE532E | 0x00B614C4 | MSVCR80.dll | `setvbuf` | 2 | 0 | cdecl |
| 0x00AE5334 | 0x00B614C8 | MSVCR80.dll | `_strlwr` | 1 | 0 | cdecl |
| 0x00AE533A | 0x00B614CC | MSVCR80.dll | `_localtime32` | 1 | 0 | cdecl |
| 0x00AE5340 | 0x00B614D0 | MSVCR80.dll | `_findnext32` | 1 | 0 | cdecl |
| 0x00AE5346 | 0x00B614D8 | MSVCR80.dll | `_findfirst32` | 1 | 0 | cdecl |
