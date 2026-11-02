# Need for Speed Undercover — nfs.exe PE report

Read-only structural report. The game directory was not modified. Protected sections were not unpacked or emulated. The NFSU2 lifter, reloc parser, and runtime were not changed and were not run on this file.

- File: `C:\Games\Need For Speed Undercover\nfs.exe`
- Size: 22320400 bytes
- SHA-256: `6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd`

## PE architecture

- Machine: IMAGE_FILE_MACHINE_I386 (0x014c)
- Format: PE32 (optional-header magic 0x10B)
- File characteristics: RELOCS_STRIPPED, EXECUTABLE_IMAGE, 32BIT_MACHINE
- DllCharacteristics: 0x0
- Subsystem: WINDOWS_CUI (3)
- Linker version: 8.0
- OS / image / subsystem versions: 4.0 / 0.0 / 4.0
- TimeDateStamp: 0x49f90641 (2009-04-30 02:00:33 UTC)
- Alignment: section 0x1000, file 0x1000
- SizeOfHeaders: 0x1000
- CheckSum: 0x154d5a1
- Stack reserve / commit: 0x800000 / 0x400000
- Heap reserve / commit: 0x200000 / 0x1000

## Image base

- ImageBase: 0x00400000
- SizeOfImage: 0x020A5000 (34230272 bytes)
- Mapped span at the preferred base: 0x00400000 .. 0x024A5000

## Entry point

- AddressOfEntryPoint: 0x01BCA510
- Virtual address: 0x01FCA510
- Section: Sitext
- Inside the lifter's .text range: False

## Sections and permissions

| Section | VA | Virtual size | End | Raw size | Perm | Entropy | MSVC frames | int3 pads |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| .text | 0x00401000 | 0x0075F3FB | 0x00B603FB | 7733248 | R-X | 7.44 | 4637 | 39463 |
| .rdata | 0x00B61000 | 0x0014AA3E | 0x00CABA3E | 1355776 | R-- | 5.69 | 0 | 1 |
| .data | 0x00CAC000 | 0x00C05E74 | 0x018B1E74 | 6266880 | RW- | 4.63 | 0 | 0 |
| .tls | 0x018B2000 | 0x00000019 | 0x018B2019 | 4096 | RW- | 0.02 | 0 | 0 |
| .rsrc | 0x018B3000 | 0x00001214 | 0x018B4214 | 8192 | R-- | 4.12 | 0 | 0 |
| Stext | 0x018B5000 | 0x00711C20 | 0x01FC6C20 | 3776512 | RWX | 8.00 | 0 | 0 |
| Sitext | 0x01FC7000 | 0x00006910 | 0x01FCD910 | 28672 | R-X | 6.44 | 7 | 6 |
| Srdata | 0x01FCE000 | 0x0006AEA4 | 0x02038EA4 | 438272 | R-X | 5.60 | 0 | 4 |
| Sdata | 0x02039000 | 0x002846F8 | 0x022BD6F8 | 704512 | RWX | 8.00 | 0 | 0 |
| Sidata | 0x022BE000 | 0x000053B8 | 0x022C33B8 | 24576 | RW- | 5.63 | 0 | 0 |
| .securom | 0x022C4000 | 0x001E00D6 | 0x024A40D6 | 1970176 | RWX | 6.89 | 4 | 0 |

Permissions are read, write, execute from the section characteristics. MSVC frames are the byte sequence `55 8B EC` (`push ebp; mov ebp, esp`). int3 pads are runs of four `CC` bytes. Both counts are over the section's raw bytes.

Data directories that are present:

- IMPORT: RVA 0x01ECEC7F, size 0x00000208
- RESOURCE: RVA 0x014B3000, size 0x00001214
- SECURITY: RVA 0x01548000, size 0x00001510
- DEBUG: RVA 0x01ECB000, size 0x0000001C
- TLS: RVA 0x00849E60, size 0x00000018
- IAT: RVA 0x01ECD82F, size 0x00000A28

## Imported DLLs

- KERNEL32.dll: 208 functions, IAT RVA 0x01ECD82F
- d3d9.dll: 1 functions, IAT RVA 0x01ECDB73
- d3dx9_34.dll: 12 functions, IAT RVA 0x01ECDB7B
- DINPUT8.dll: 1 functions, IAT RVA 0x01ECDBAF
- XINPUT1_3.dll: 3 functions, IAT RVA 0x01ECDBB7
- USER32.dll: 90 functions, IAT RVA 0x01ECDBC7
- ADVAPI32.dll: 47 functions, IAT RVA 0x01ECDD33
- SHFOLDER.dll: 1 functions, IAT RVA 0x01ECDDF3
- WS2_32.dll: 41 functions, IAT RVA 0x01ECDDFB
- SETUPAPI.dll: 4 functions, IAT RVA 0x01ECDEA3
- VERSION.dll: 3 functions, IAT RVA 0x01ECDEB7
- SHLWAPI.dll: 8 functions, IAT RVA 0x01ECDEC7
- OLEAUT32.dll: 2 functions, IAT RVA 0x01ECDEEB
- MSVCR80.dll: 171 functions, IAT RVA 0x01ECDEF7
- MSVCP80.dll: 4 functions, IAT RVA 0x01ECE1A7
- CRYPT32.dll: 3 functions, IAT RVA 0x01ECE1BB
- imagehlp.dll: 3 functions, IAT RVA 0x01ECE1CB
- WINTRUST.dll: 1 functions, IAT RVA 0x01ECE1DB
- ole32.dll: 5 functions, IAT RVA 0x01ECE1E3
- RPCRT4.dll: 2 functions, IAT RVA 0x01ECE1FB
- DSOUND.dll: 1 functions, IAT RVA 0x01ECE207
- WINMM.dll: 3 functions, IAT RVA 0x01ECE20F
- NETAPI32.dll: 1 functions, IAT RVA 0x01ECE21F
- SHELL32.dll: 4 functions, IAT RVA 0x01ECE227
- WSOCK32.dll: 6 functions, IAT RVA 0x01ECE23B

Total: 625 functions from 25 DLLs.

## Imported functions

### KERNEL32.dll

- LoadLibraryA
- GetVersionExA
- GetLongPathNameA
- GetDriveTypeA
- GetLogicalDrives
- GetSystemTime
- FindClose
- FindNextFileA
- FindFirstFileA
- FreeLibrary
- GetSystemInfo
- CreateDirectoryA
- GetModuleHandleA
- Sleep
- CloseHandle
- Process32Next
- Process32First
- CreateToolhelp32Snapshot
- GetConsoleTitleA — not in tools/argcount.py KNOWN
- SetErrorMode
- HeapFree
- HeapAlloc
- GetProcessHeap
- OpenEventA — not in tools/argcount.py KNOWN
- GetCurrentProcessId
- LoadLibraryW
- CreateEventA
- VirtualQuery
- VirtualAlloc
- VirtualFree
- GetPriorityClass
- SetPriorityClass
- RemoveDirectoryW — not in tools/argcount.py KNOWN
- CreateDirectoryW — not in tools/argcount.py KNOWN
- FindNextFileW — not in tools/argcount.py KNOWN
- FindFirstFileW — not in tools/argcount.py KNOWN
- WideCharToMultiByte
- MoveFileW — not in tools/argcount.py KNOWN
- DeleteFileW — not in tools/argcount.py KNOWN
- SetEndOfFile
- GetProcAddress
- GetFileSizeEx — not in tools/argcount.py KNOWN
- ResumeThread
- SetFilePointerEx — not in tools/argcount.py KNOWN
- RaiseException
- TlsFree
- ReleaseSemaphore
- InterlockedDecrement
- CreateSemaphoreA
- InterlockedExchangeAdd
- SetThreadIdealProcessor — not in tools/argcount.py KNOWN
- TlsAlloc
- ReleaseMutex
- CreateMutexA
- VirtualProtect
- FlushFileBuffers
- CreateThread
- GetModuleFileNameA
- GetDiskFreeSpaceExA
- GetCurrentDirectoryA
- ResetEvent
- CreateFileA
- GetFileSize
- ReadFile
- MoveFileA
- DeleteFileA
- SetFilePointer
- WriteFile
- GetExitCodeThread
- SetThreadPriority
- GetThreadPriority
- SleepEx
- TerminateThread
- DuplicateHandle
- CreateWaitableTimerA — not in tools/argcount.py KNOWN
- SystemTimeToFileTime
- SetWaitableTimer — not in tools/argcount.py KNOWN
- GetSystemTimeAsFileTime
- SetUnhandledExceptionFilter
- UnhandledExceptionFilter
- GetCurrentProcess
- TerminateProcess
- InterlockedCompareExchange
- InterlockedExchange
- GetFileAttributesA
- TryEnterCriticalSection
- InitializeCriticalSectionAndSpinCount
- TlsSetValue
- TlsGetValue
- GetTickCount
- SetEvent
- WaitForSingleObject
- GetCurrentThread
- GetCurrentThreadId
- LeaveCriticalSection
- EnterCriticalSection
- DeleteCriticalSection
- InitializeCriticalSection
- MultiByteToWideChar
- QueryPerformanceCounter
- QueryPerformanceFrequency
- CreateProcessA — not in tools/argcount.py KNOWN
- GetLastError
- IsBadReadPtr
- IsDebuggerPresent
- CreateFileW
- OutputDebugStringA
- SetNamedPipeHandleState — not in tools/argcount.py KNOWN
- WaitNamedPipeA — not in tools/argcount.py KNOWN
- ExitProcess
- SuspendThread
- SetThreadAffinityMask
- GetProcessAffinityMask
- GetOverlappedResult
- GetEnvironmentVariableA
- GetVersion
- GetLocalTime
- DeviceIoControl — not in tools/argcount.py KNOWN
- GetThreadContext — not in tools/argcount.py KNOWN
- GetCommandLineA
- lstrlenW — not in tools/argcount.py KNOWN
- OpenProcess — not in tools/argcount.py KNOWN
- FlushInstructionCache
- lstrlenA
- IsBadWritePtr
- GetSystemDirectoryA
- GetVolumeInformationA — not in tools/argcount.py KNOWN
- GetStartupInfoA
- GetLocaleInfoA
- GetWindowsDirectoryA
- FileTimeToSystemTime
- GlobalMemoryStatus
- CreateFileMappingA
- SetCurrentDirectoryA
- lstrcmpA
- OpenMutexA — not in tools/argcount.py KNOWN
- QueryDosDeviceA — not in tools/argcount.py KNOWN
- MapViewOfFile
- UnmapViewOfFile
- WaitForMultipleObjects
- GetFileTime
- CompareFileTime — not in tools/argcount.py KNOWN
- GetTempPathA
- GetTempPathW — not in tools/argcount.py KNOWN
- GetModuleFileNameW
- ReadProcessMemory — not in tools/argcount.py KNOWN
- WriteProcessMemory — not in tools/argcount.py KNOWN
- GetComputerNameA
- GetExitCodeProcess
- SetLastError
- GetShortPathNameA
- lstrcmpiA
- GetFullPathNameW — not in tools/argcount.py KNOWN
- GetFullPathNameA
- GetDiskFreeSpaceW — not in tools/argcount.py KNOWN
- GetDiskFreeSpaceA
- FlushConsoleInputBuffer — not in tools/argcount.py KNOWN
- SetFileAttributesA
- GetConsoleMode — not in tools/argcount.py KNOWN
- GetFileType
- RemoveDirectoryA
- LocalFree
- LocalUnlock — not in tools/argcount.py KNOWN
- GlobalUnlock
- LocalLock — not in tools/argcount.py KNOWN
- LocalAlloc
- GlobalLock
- GlobalAlloc
- GlobalFree
- SetEnvironmentVariableA
- CompareStringW
- CompareStringA
- SetConsoleCtrlHandler
- SetStdHandle
- IsBadCodePtr
- GetStringTypeW
- GetStringTypeA
- GetCPInfo
- GetOEMCP
- GetACP
- GetTimeZoneInformation
- LCMapStringW
- LCMapStringA
- SetHandleCount
- GetEnvironmentStringsW
- FreeEnvironmentStringsW
- GetEnvironmentStrings
- FreeEnvironmentStringsA
- GetStdHandle
- HeapSize
- FileTimeToLocalFileTime
- ReadConsoleInputA — not in tools/argcount.py KNOWN
- SetConsoleMode — not in tools/argcount.py KNOWN
- HeapCreate
- HeapDestroy
- LoadLibraryExA — not in tools/argcount.py KNOWN
- LoadLibraryExW — not in tools/argcount.py KNOWN
- FormatMessageA — not in tools/argcount.py KNOWN
- CopyFileA
- GetTempFileNameA — not in tools/argcount.py KNOWN
- MoveFileExA — not in tools/argcount.py KNOWN
- GetUserDefaultLangID — not in tools/argcount.py KNOWN
- LockResource
- LoadResource
- FindResourceA
- WritePrivateProfileStringA
- RtlUnwind
- HeapReAlloc

### d3d9.dll

- Direct3DCreate9

### d3dx9_34.dll

- D3DXMatrixMultiply — not in tools/argcount.py KNOWN
- D3DXVec4Transform — not in tools/argcount.py KNOWN
- D3DXGetPixelShaderProfile — not in tools/argcount.py KNOWN
- D3DXVec3Normalize — not in tools/argcount.py KNOWN
- D3DXMatrixTranspose — not in tools/argcount.py KNOWN
- D3DXCreateCubeTextureFromFileInMemory — not in tools/argcount.py KNOWN
- D3DXSaveSurfaceToFileInMemory — not in tools/argcount.py KNOWN
- D3DXGetShaderConstantTable — not in tools/argcount.py KNOWN
- D3DXGetVertexShaderProfile — not in tools/argcount.py KNOWN
- D3DXCreateVolumeTextureFromFileInMemory — not in tools/argcount.py KNOWN
- D3DXFillVolumeTexture — not in tools/argcount.py KNOWN
- D3DXVec3Transform — not in tools/argcount.py KNOWN

### DINPUT8.dll

- DirectInput8Create

### XINPUT1_3.dll

- #2 — not in tools/argcount.py KNOWN
- #5 — not in tools/argcount.py KNOWN
- #4 — not in tools/argcount.py KNOWN

### USER32.dll

- DispatchMessageA
- TranslateMessage
- GetMessageA
- DestroyWindow
- ReleaseCapture
- GetDesktopWindow
- SetCapture
- EndPaint
- BeginPaint
- PostQuitMessage
- IsIconic
- PostMessageA
- DefWindowProcA
- AdjustWindowRect
- SetWindowPos
- GetClientRect
- GetWindowRect
- SetForegroundWindow
- SetFocus
- ShowCursor
- UpdateWindow
- CreateWindowExA
- RegisterClassExA
- LoadCursorA
- LoadIconA
- GetCursorPos
- FindWindowA — not in tools/argcount.py KNOWN
- CallWindowProcA — not in tools/argcount.py KNOWN
- MessageBoxA
- SetWindowLongA
- GetWindowLongA
- wsprintfA
- SetTimer — not in tools/argcount.py KNOWN
- KillTimer — not in tools/argcount.py KNOWN
- RegisterDeviceNotificationA — not in tools/argcount.py KNOWN
- PeekMessageA
- SendInput — not in tools/argcount.py KNOWN
- GetForegroundWindow
- ShowWindow
- SystemParametersInfoA — not in tools/argcount.py KNOWN
- EnumDisplaySettingsA — not in tools/argcount.py KNOWN
- MapVirtualKeyA
- ToUnicode — not in tools/argcount.py KNOWN
- SendMessageA
- GetKeyboardLayout — not in tools/argcount.py KNOWN
- MapVirtualKeyExA — not in tools/argcount.py KNOWN
- GetKeyState — not in tools/argcount.py KNOWN
- SetCursor
- GetDlgItem — not in tools/argcount.py KNOWN
- EndDialog — not in tools/argcount.py KNOWN
- SetDlgItemTextW — not in tools/argcount.py KNOWN
- SetDlgItemTextA — not in tools/argcount.py KNOWN
- GetSysColor — not in tools/argcount.py KNOWN
- SetWindowTextA
- SetWindowTextW — not in tools/argcount.py KNOWN
- EnableWindow — not in tools/argcount.py KNOWN
- FlashWindow — not in tools/argcount.py KNOWN
- wsprintfW — not in tools/argcount.py KNOWN
- CharLowerA — not in tools/argcount.py KNOWN
- UnregisterHotKey — not in tools/argcount.py KNOWN
- RegisterHotKey — not in tools/argcount.py KNOWN
- UnregisterClassA
- GetSubMenu — not in tools/argcount.py KNOWN
- GetMenuState — not in tools/argcount.py KNOWN
- GetMenu — not in tools/argcount.py KNOWN
- EnableMenuItem — not in tools/argcount.py KNOWN
- CheckMenuItem — not in tools/argcount.py KNOWN
- GetWindowTextA — not in tools/argcount.py KNOWN
- GetParent — not in tools/argcount.py KNOWN
- GetClassNameA — not in tools/argcount.py KNOWN
- CopyImage — not in tools/argcount.py KNOWN
- LoadImageA — not in tools/argcount.py KNOWN
- SetSystemCursor — not in tools/argcount.py KNOWN
- LoadCursorFromFileA — not in tools/argcount.py KNOWN
- GetClassLongA — not in tools/argcount.py KNOWN
- EnumChildWindows — not in tools/argcount.py KNOWN
- DestroyCursor — not in tools/argcount.py KNOWN
- GetCursor — not in tools/argcount.py KNOWN
- FindWindowExA — not in tools/argcount.py KNOWN
- EnumWindows — not in tools/argcount.py KNOWN
- DialogBoxIndirectParamA — not in tools/argcount.py KNOWN
- GetUserObjectInformationW — not in tools/argcount.py KNOWN
- GetProcessWindowStation — not in tools/argcount.py KNOWN
- SendDlgItemMessageA — not in tools/argcount.py KNOWN
- GetSysColorBrush — not in tools/argcount.py KNOWN
- LoadStringA — not in tools/argcount.py KNOWN
- GetKeyboardType — not in tools/argcount.py KNOWN
- GetSystemMetrics
- GetWindowThreadProcessId — not in tools/argcount.py KNOWN
- CharLowerBuffA — not in tools/argcount.py KNOWN

### ADVAPI32.dll

- RegCreateKeyA
- CryptGenRandom — not in tools/argcount.py KNOWN
- CryptImportKey — not in tools/argcount.py KNOWN
- CryptEncrypt — not in tools/argcount.py KNOWN
- CryptDestroyHash — not in tools/argcount.py KNOWN
- CryptGetHashParam — not in tools/argcount.py KNOWN
- CryptDestroyKey — not in tools/argcount.py KNOWN
- CryptAcquireContextA — not in tools/argcount.py KNOWN
- CryptCreateHash — not in tools/argcount.py KNOWN
- CryptHashData — not in tools/argcount.py KNOWN
- CryptReleaseContext — not in tools/argcount.py KNOWN
- RegSetValueExA
- RegOpenKeyExA
- RegQueryValueExA
- RegCloseKey
- AllocateAndInitializeSid — not in tools/argcount.py KNOWN
- CheckTokenMembership — not in tools/argcount.py KNOWN
- FreeSid — not in tools/argcount.py KNOWN
- ControlService — not in tools/argcount.py KNOWN
- GetUserNameA
- RegDeleteValueA
- GetSidSubAuthorityCount — not in tools/argcount.py KNOWN
- GetSidSubAuthority — not in tools/argcount.py KNOWN
- GetSidIdentifierAuthority — not in tools/argcount.py KNOWN
- IsValidSid — not in tools/argcount.py KNOWN
- RegOpenKeyA
- RegQueryInfoKeyA
- RegEnumKeyExA
- RegCreateKeyExA
- RegDeleteKeyA
- RegEnumKeyA
- DeregisterEventSource — not in tools/argcount.py KNOWN
- ReportEventA — not in tools/argcount.py KNOWN
- RegisterEventSourceA — not in tools/argcount.py KNOWN
- CreateServiceA — not in tools/argcount.py KNOWN
- StartServiceA — not in tools/argcount.py KNOWN
- DeleteService — not in tools/argcount.py KNOWN
- OpenSCManagerA — not in tools/argcount.py KNOWN
- OpenServiceA — not in tools/argcount.py KNOWN
- CloseServiceHandle — not in tools/argcount.py KNOWN
- QueryServiceStatus — not in tools/argcount.py KNOWN
- RevertToSelf — not in tools/argcount.py KNOWN
- OpenThreadToken — not in tools/argcount.py KNOWN
- OpenProcessToken — not in tools/argcount.py KNOWN
- GetTokenInformation — not in tools/argcount.py KNOWN
- EqualSid — not in tools/argcount.py KNOWN
- RegEnumValueA

### SHFOLDER.dll

- SHGetFolderPathA

### WS2_32.dll

- freeaddrinfo — not in tools/argcount.py KNOWN
- #14 — not in tools/argcount.py KNOWN
- #9 — not in tools/argcount.py KNOWN
- #11 — not in tools/argcount.py KNOWN
- #15 — not in tools/argcount.py KNOWN
- #8 — not in tools/argcount.py KNOWN
- #7 — not in tools/argcount.py KNOWN
- #116 — not in tools/argcount.py KNOWN
- WSAIoctl
- #57 — not in tools/argcount.py KNOWN
- #52 — not in tools/argcount.py KNOWN
- #6 — not in tools/argcount.py KNOWN
- #18 — not in tools/argcount.py KNOWN
- #5 — not in tools/argcount.py KNOWN
- #17 — not in tools/argcount.py KNOWN
- getaddrinfo — not in tools/argcount.py KNOWN
- #19 — not in tools/argcount.py KNOWN
- #20 — not in tools/argcount.py KNOWN
- #1
- #13 — not in tools/argcount.py KNOWN
- #4 — not in tools/argcount.py KNOWN
- #2 — not in tools/argcount.py KNOWN
- #115 — not in tools/argcount.py KNOWN
- WSAGetOverlappedResult — not in tools/argcount.py KNOWN
- WSAWaitForMultipleEvents — not in tools/argcount.py KNOWN
- WSAResetEvent — not in tools/argcount.py KNOWN
- WSARecvFrom — not in tools/argcount.py KNOWN
- WSARecv — not in tools/argcount.py KNOWN
- WSASetEvent — not in tools/argcount.py KNOWN
- WSACloseEvent — not in tools/argcount.py KNOWN
- #22 — not in tools/argcount.py KNOWN
- #3 — not in tools/argcount.py KNOWN
- #10 — not in tools/argcount.py KNOWN
- #21 — not in tools/argcount.py KNOWN
- WSACreateEvent — not in tools/argcount.py KNOWN
- #111 — not in tools/argcount.py KNOWN
- #101 — not in tools/argcount.py KNOWN
- #12 — not in tools/argcount.py KNOWN
- #151 — not in tools/argcount.py KNOWN
- #16 — not in tools/argcount.py KNOWN
- #23 — not in tools/argcount.py KNOWN

### SETUPAPI.dll

- SetupDiGetClassDevsA — not in tools/argcount.py KNOWN
- SetupDiDestroyDeviceInfoList — not in tools/argcount.py KNOWN
- SetupDiGetDeviceInstanceIdA — not in tools/argcount.py KNOWN
- SetupDiEnumDeviceInfo — not in tools/argcount.py KNOWN

### VERSION.dll

- VerQueryValueA — not in tools/argcount.py KNOWN
- GetFileVersionInfoSizeA — not in tools/argcount.py KNOWN
- GetFileVersionInfoA — not in tools/argcount.py KNOWN

### SHLWAPI.dll

- PathQuoteSpacesA — not in tools/argcount.py KNOWN
- SHGetValueA — not in tools/argcount.py KNOWN
- PathCombineW — not in tools/argcount.py KNOWN
- PathStripPathW — not in tools/argcount.py KNOWN
- PathRemoveExtensionW — not in tools/argcount.py KNOWN
- PathFileExistsA — not in tools/argcount.py KNOWN
- PathRemoveFileSpecW — not in tools/argcount.py KNOWN
- PathFileExistsW — not in tools/argcount.py KNOWN

### OLEAUT32.dll

- #2 — not in tools/argcount.py KNOWN
- #6 — not in tools/argcount.py KNOWN

### MSVCR80.dll

- _vsnprintf — not in tools/argcount.py KNOWN
- bsearch — not in tools/argcount.py KNOWN
- _beginthreadex — not in tools/argcount.py KNOWN
- memset — not in tools/argcount.py KNOWN
- _CIacos — not in tools/argcount.py KNOWN
- _CIasin — not in tools/argcount.py KNOWN
- floor — not in tools/argcount.py KNOWN
- _CIpow — not in tools/argcount.py KNOWN
- __CxxFrameHandler3 — not in tools/argcount.py KNOWN
- _purecall — not in tools/argcount.py KNOWN
- __libm_sse2_sin — not in tools/argcount.py KNOWN
- __libm_sse2_cos — not in tools/argcount.py KNOWN
- __libm_sse2_asin — not in tools/argcount.py KNOWN
- __libm_sse2_acos — not in tools/argcount.py KNOWN
- __libm_sse2_atan2 — not in tools/argcount.py KNOWN
- __libm_sse2_pow — not in tools/argcount.py KNOWN
- memcpy — not in tools/argcount.py KNOWN
- memmove — not in tools/argcount.py KNOWN
- ??1exception@std@@UAE@XZ — not in tools/argcount.py KNOWN
- ??0exception@std@@QAE@XZ — not in tools/argcount.py KNOWN
- _invalid_parameter_noinfo — not in tools/argcount.py KNOWN
- tolower — not in tools/argcount.py KNOWN
- _fullpath — not in tools/argcount.py KNOWN
- strncpy — not in tools/argcount.py KNOWN
- strstr — not in tools/argcount.py KNOWN
- _CxxThrowException — not in tools/argcount.py KNOWN
- ??0exception@std@@QAE@ABV01@@Z — not in tools/argcount.py KNOWN
- rand — not in tools/argcount.py KNOWN
- _CIfmod — not in tools/argcount.py KNOWN
- strrchr — not in tools/argcount.py KNOWN
- sprintf — not in tools/argcount.py KNOWN
- printf — not in tools/argcount.py KNOWN
- malloc — not in tools/argcount.py KNOWN
- free — not in tools/argcount.py KNOWN
- __libm_sse2_exp — not in tools/argcount.py KNOWN
- strchr — not in tools/argcount.py KNOWN
- isspace — not in tools/argcount.py KNOWN
- atof — not in tools/argcount.py KNOWN
- sscanf — not in tools/argcount.py KNOWN
- strncat — not in tools/argcount.py KNOWN
- qsort — not in tools/argcount.py KNOWN
- ceil — not in tools/argcount.py KNOWN
- fclose — not in tools/argcount.py KNOWN
- fopen — not in tools/argcount.py KNOWN
- _time64 — not in tools/argcount.py KNOWN
- strtok — not in tools/argcount.py KNOWN
- _isnan — not in tools/argcount.py KNOWN
- exit — not in tools/argcount.py KNOWN
- vsprintf — not in tools/argcount.py KNOWN
- fprintf — not in tools/argcount.py KNOWN
- __iob_func — not in tools/argcount.py KNOWN
- _exit — not in tools/argcount.py KNOWN
- _controlfp_s — not in tools/argcount.py KNOWN
- ??0exception@std@@QAE@ABQBD@Z — not in tools/argcount.py KNOWN
- _vsnwprintf — not in tools/argcount.py KNOWN
- memmove_s — not in tools/argcount.py KNOWN
- __libm_sse2_log — not in tools/argcount.py KNOWN
- fwrite — not in tools/argcount.py KNOWN
- _strupr — not in tools/argcount.py KNOWN
- _getcwd — not in tools/argcount.py KNOWN
- toupper — not in tools/argcount.py KNOWN
- fread — not in tools/argcount.py KNOWN
- ftell — not in tools/argcount.py KNOWN
- fseek — not in tools/argcount.py KNOWN
- _chmod — not in tools/argcount.py KNOWN
- rename — not in tools/argcount.py KNOWN
- remove — not in tools/argcount.py KNOWN
- strncmp — not in tools/argcount.py KNOWN
- wcsstr — not in tools/argcount.py KNOWN
- _mbscmp — not in tools/argcount.py KNOWN
- swscanf_s — not in tools/argcount.py KNOWN
- strcpy_s — not in tools/argcount.py KNOWN
- strcat_s — not in tools/argcount.py KNOWN
- _stricmp — not in tools/argcount.py KNOWN
- fflush — not in tools/argcount.py KNOWN
- _sprintf_p — not in tools/argcount.py KNOWN
- _gmtime64 — not in tools/argcount.py KNOWN
- isdigit — not in tools/argcount.py KNOWN
- isxdigit — not in tools/argcount.py KNOWN
- isalnum — not in tools/argcount.py KNOWN
- strftime — not in tools/argcount.py KNOWN
- _strnicmp — not in tools/argcount.py KNOWN
- _mkdir — not in tools/argcount.py KNOWN
- _ltoa — not in tools/argcount.py KNOWN
- ?terminate@@YAXXZ — not in tools/argcount.py KNOWN
- _unlock — not in tools/argcount.py KNOWN
- __dllonexit — not in tools/argcount.py KNOWN
- _encode_pointer — not in tools/argcount.py KNOWN
- _lock — not in tools/argcount.py KNOWN
- _onexit — not in tools/argcount.py KNOWN
- _decode_pointer — not in tools/argcount.py KNOWN
- _amsg_exit — not in tools/argcount.py KNOWN
- __getmainargs — not in tools/argcount.py KNOWN
- _cexit — not in tools/argcount.py KNOWN
- _XcptFilter — not in tools/argcount.py KNOWN
- __initenv — not in tools/argcount.py KNOWN
- _initterm — not in tools/argcount.py KNOWN
- _initterm_e — not in tools/argcount.py KNOWN
- _configthreadlocale — not in tools/argcount.py KNOWN
- __setusermatherr — not in tools/argcount.py KNOWN
- _adjust_fdiv — not in tools/argcount.py KNOWN
- __p__commode — not in tools/argcount.py KNOWN
- __p__fmode — not in tools/argcount.py KNOWN
- __set_app_type — not in tools/argcount.py KNOWN
- ?_type_info_dtor_internal_method@type_info@@QAEXXZ — not in tools/argcount.py KNOWN
- _crt_debugger_hook — not in tools/argcount.py KNOWN
- _except_handler4_common — not in tools/argcount.py KNOWN
- _invoke_watson — not in tools/argcount.py KNOWN
- getenv — not in tools/argcount.py KNOWN
- _findclose — not in tools/argcount.py KNOWN
- _getdiskfree — not in tools/argcount.py KNOWN
- ?what@exception@std@@UBEPBDXZ — not in tools/argcount.py KNOWN
- _getdrive — not in tools/argcount.py KNOWN
- _close — not in tools/argcount.py KNOWN
- _write — not in tools/argcount.py KNOWN
- _endthreadex — not in tools/argcount.py KNOWN
- _open — not in tools/argcount.py KNOWN
- _lseek — not in tools/argcount.py KNOWN
- _read — not in tools/argcount.py KNOWN
- _filelength — not in tools/argcount.py KNOWN
- _rmdir — not in tools/argcount.py KNOWN
- __CxxFrameHandler — not in tools/argcount.py KNOWN
- strtol — not in tools/argcount.py KNOWN
- _mktime64 — not in tools/argcount.py KNOWN
- _localtime64 — not in tools/argcount.py KNOWN
- _snprintf — not in tools/argcount.py KNOWN
- _mkgmtime64 — not in tools/argcount.py KNOWN
- asctime — not in tools/argcount.py KNOWN
- strpbrk — not in tools/argcount.py KNOWN
- isprint — not in tools/argcount.py KNOWN
- _difftime64 — not in tools/argcount.py KNOWN
- strnlen — not in tools/argcount.py KNOWN
- _snprintf_s — not in tools/argcount.py KNOWN
- _CIcos — not in tools/argcount.py KNOWN
- _CIsqrt — not in tools/argcount.py KNOWN
- srand — not in tools/argcount.py KNOWN
- sscanf_s — not in tools/argcount.py KNOWN
- _itoa_s — not in tools/argcount.py KNOWN
- _CIatan2 — not in tools/argcount.py KNOWN
- _CIlog — not in tools/argcount.py KNOWN
- _CIlog10 — not in tools/argcount.py KNOWN
- _CIsin — not in tools/argcount.py KNOWN
- _CItan — not in tools/argcount.py KNOWN
- ldexp — not in tools/argcount.py KNOWN
- _except_handler3 — not in tools/argcount.py KNOWN
- _aligned_malloc — not in tools/argcount.py KNOWN
- _aligned_free — not in tools/argcount.py KNOWN
- _control87 — not in tools/argcount.py KNOWN
- strcmp — not in tools/argcount.py KNOWN
- abs — not in tools/argcount.py KNOWN
- memcmp — not in tools/argcount.py KNOWN
- atan — not in tools/argcount.py KNOWN
- strcpy — not in tools/argcount.py KNOWN
- strcat — not in tools/argcount.py KNOWN
- strlen — not in tools/argcount.py KNOWN
- strtoul — not in tools/argcount.py KNOWN
- _wassert — not in tools/argcount.py KNOWN
- strcspn — not in tools/argcount.py KNOWN
- _setjmp3 — not in tools/argcount.py KNOWN
- longjmp — not in tools/argcount.py KNOWN
- strcoll — not in tools/argcount.py KNOWN
- iscntrl — not in tools/argcount.py KNOWN
- localeconv — not in tools/argcount.py KNOWN
- isalpha — not in tools/argcount.py KNOWN
- strtod — not in tools/argcount.py KNOWN
- setvbuf — not in tools/argcount.py KNOWN
- _strlwr — not in tools/argcount.py KNOWN
- _localtime32 — not in tools/argcount.py KNOWN
- _findnext32 — not in tools/argcount.py KNOWN
- atoi — not in tools/argcount.py KNOWN
- _findfirst32 — not in tools/argcount.py KNOWN

### MSVCP80.dll

- ??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@PBD@Z — not in tools/argcount.py KNOWN
- ??1?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@XZ — not in tools/argcount.py KNOWN
- ??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@ABV01@@Z — not in tools/argcount.py KNOWN
- ??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@XZ — not in tools/argcount.py KNOWN

### CRYPT32.dll

- CertFreeCertificateContext — not in tools/argcount.py KNOWN
- CertGetNameStringA — not in tools/argcount.py KNOWN
- CryptVerifyMessageSignature — not in tools/argcount.py KNOWN

### imagehlp.dll

- ImageGetCertificateHeader — not in tools/argcount.py KNOWN
- ImageEnumerateCertificates — not in tools/argcount.py KNOWN
- ImageGetCertificateData — not in tools/argcount.py KNOWN

### WINTRUST.dll

- WinVerifyTrust — not in tools/argcount.py KNOWN

### ole32.dll

- CoCreateInstance — not in tools/argcount.py KNOWN
- CoSetProxyBlanket — not in tools/argcount.py KNOWN
- CoUninitialize — not in tools/argcount.py KNOWN
- CoInitialize — not in tools/argcount.py KNOWN
- CoCreateGuid — not in tools/argcount.py KNOWN

### RPCRT4.dll

- UuidToStringA — not in tools/argcount.py KNOWN
- RpcStringFreeA — not in tools/argcount.py KNOWN

### DSOUND.dll

- #1

### WINMM.dll

- timeGetTime
- timeEndPeriod
- timeBeginPeriod

### NETAPI32.dll

- Netbios

### SHELL32.dll

- SHFileOperationA — not in tools/argcount.py KNOWN
- ShellExecuteExA — not in tools/argcount.py KNOWN
- ShellExecuteA
- SHGetSpecialFolderPathA — not in tools/argcount.py KNOWN

### WSOCK32.dll

- #3 — not in tools/argcount.py KNOWN
- #16 — not in tools/argcount.py KNOWN
- #112 — not in tools/argcount.py KNOWN
- #19 — not in tools/argcount.py KNOWN
- #22 — not in tools/argcount.py KNOWN
- #111 — not in tools/argcount.py KNOWN

## Relocation information

- Base relocation directory: RVA 0x00000000, size 0x00000000
- IMAGE_FILE_RELOCS_STRIPPED: True
- Unnamed sections (the input tools/reloc2.py parses): 0
- Relocation types present: none
- HIGHLOW fixup slots: 0

tools/prepare_module.py refuses a module with no base-relocation directory, and it only accepts relocation types ABSOLUTE (0) and HIGHLOW (3). This file has neither a directory nor an unnamed reloc section.

## Executable code ranges

- .text R-X 0x00401000 .. 0x00B603FB (7730171 bytes), entropy 7.44, MSVC frames 4637. clear enough to contain MSVC frame prologues.
- Stext RWX 0x018B5000 .. 0x01FC6C20 (7412768 bytes), entropy 8.00, MSVC frames 0. executable bytes are not clear x86 (entropy at the ceiling, no MSVC frames).
- Sitext R-X 0x01FC7000 .. 0x01FCD910 (26896 bytes), entropy 6.44, MSVC frames 7. executable, with few or no MSVC frame prologues.
- Srdata R-X 0x01FCE000 .. 0x02038EA4 (437924 bytes), entropy 5.60, MSVC frames 0. executable, with few or no MSVC frame prologues.
- Sdata RWX 0x02039000 .. 0x022BD6F8 (2639608 bytes), entropy 8.00, MSVC frames 0. executable bytes are not clear x86 (entropy at the ceiling, no MSVC frames).
- .securom RWX 0x022C4000 .. 0x024A40D6 (1966294 bytes), entropy 6.89, MSVC frames 4. executable, with few or no MSVC frame prologues.

The lifter's code range is .text only: 0x00401000 .. 0x00B603FB.

## Compiler and runtime patterns

- Linker version field: 8.0.
- Rich header present: False. Standard MSVC DOS stub present: False.
- Version resource file_version: 1.1.2.1
- Version resource product_version: 1.1.2.1
- Version resource FileVersion: 1.1.2.1
- Version resource ProductVersion: 1.1.2.1
- Version resource ProductName: Need for Speed Undercover
- Version resource OriginalFilename: Nfs.exe
- Version resource FileDescription: Need for Speed Undercover
- Version resource CompanyName: Electronic Arts
- CodeView PDB path: `E:\generate-pc-PCFinal\MW2\Branches\PCFinal\Speed\Pc\Obj\ReleaseOpt\xxEU\SpeedReleaseOpt-xxEU.pdb` (age 3, directory in section .securom)
- Dynamic CRT: MSVCR80.dll and MSVCP80.dll are Visual C++ 2005 (VC8). The C++ imports are decorated names.
- Decorated C++ import names: 11.
- .text holds 4637 MSVC frame prologues, 39463 int3 padding runs, and 1125 `mov eax, fs:[0]` SEH reads.
- TLS directory in .rdata: raw data 0x018B2000..0x018B2018, index 0x01882C34, callbacks 0x00B63DDC, zerofill 0.
- Load-config directory: absent.
- Marker strings, counted per section and not quoted beyond the marker itself:
  - .rdata: _except_handler4 x1, _CxxThrowException x1, d3dx9_34 x1
  - Srdata: Microsoft Visual C++ x1, Runtime Error x1, R6002 x1
  - .securom: _except_handler4 x1, _CxxThrowException x1, d3dx9_34 x1

## What the existing pipeline would see

- pefile machine 0x14c, magic 0x10b, image base 0x00400000.
- Section names: .text, .rdata, .data, .tls, .rsrc, Stext, Sitext, Srdata, Sdata, Sidata, .securom.
- Lifter .text selection: 0x00401000 .. 0x00B603FB.
- Entry in that range: False.
- Unnamed section for tools/reloc2.py: none.
- DIRECTORY_ENTRY_BASERELOC: False.

## Incompatibilities with the NFSU2 static recompiler

### 1. Entry point is outside .text

Severity: blocker.

tools/lift.py keeps only the section named .text (0x00401000..0x00B603FB). The entry point 0x01FCA510 is in Sitext. tools/genall.py seeds discovery at that address and then stops, because the walk leaves .text immediately.

### 2. No base relocations

Severity: blocker.

IMAGE_FILE_RELOCS_STRIPPED is set and the base-relocation directory is empty. tools/reloc2.py reads an unnamed section, and this file has 0 unnamed sections, so it cannot write out/relocs.txt. tools/genall.py discovers functions from those fixup slots. With none, the only seed is the entry point.

### 3. More than one executable section

Severity: blocker.

The lifter never reads these executable ranges: Stext RWX 0x018B5000..0x01FC6C20, Sitext R-X 0x01FC7000..0x01FCD910, Srdata R-X 0x01FCE000..0x02038EA4, Sdata RWX 0x02039000..0x022BD6F8, .securom RWX 0x022C4000..0x024A40D6. Stext and Sdata have entropy 8.00 and no MSVC frame prologues, so their bytes are not an x86 image the lifter can translate. A section is named .securom. This report does not unpack or emulate it.

### 4. Image does not fit the guest map

Severity: blocker.

Image base 0x00400000 matches SPEED2.EXE, but the image runs 0x00400000..0x024A5000 (32.6 MB). The runtime treats 0x00400000..0x00932000 as the image and places other regions on top of the rest. NFSU2 image window (runtime/heap.c) overlaps 0x00400000..0x00932000; server.dll (docs/web/DESIGN.md) overlaps 0x00A00000..0x00A58000; module heaps overlaps 0x01000000..0x024A5000. Also inside the image: 0x00BE0000 (Winsock hostent buffers), 0x00C00000 (thread environment blocks). The image ends at 0x024A5000, before the main stack at 0x05000000, the thread stacks, and the guest heap at 0x08000000.

### 5. Dynamic Visual C++ 2005 runtime

Severity: gap.

The import table binds MSVCR80.dll, MSVCP80.dll. SPEED2.EXE links its CRT into the exe. runtime/win32.c pops nargs for every import (`c->esp += 4 * nargs`, the stdcall convention). A cdecl CRT call cleans the stack in the caller, so a non-zero nargs here would pop twice. tools/argcount.py's KNOWN table has no CRT exports.

### 6. Import set is not the SPEED2 set

Severity: gap.

394 imported functions are absent from tools/argcount.py KNOWN (356 names). DLLs with no name in that table: d3dx9_34.dll, XINPUT1_3.dll, SETUPAPI.dll, VERSION.dll, SHLWAPI.dll, OLEAUT32.dll, MSVCR80.dll, MSVCP80.dll, CRYPT32.dll, imagehlp.dll, WINTRUST.dll, ole32.dll, RPCRT4.dll, WSOCK32.dll. gen.sh runs argcount.py with STRICT=1 for a second module and exits on an unknown name.

### 7. TLS directory is not loaded

Severity: gap.

A TLS directory is present. runtime/mem.c mem_load_pe copies sections and does not walk TLS callbacks.

### 8. Stack commit is larger than a browser worker stack

Severity: gap.

The optional header asks for 4096 KB of stack commit and 8192 KB reserved. docs/web/DESIGN.md records that a Chrome worker stack is about 1 MB and cannot be raised.

### 9. Subsystem is not WINDOWS_GUI

Severity: note.

Subsystem is WINDOWS_CUI (3).

### 10. No Rich header and no standard DOS stub

Severity: note.

The MSVC linker product stamp is absent, and the DOS stub is not the usual "This program cannot be run in DOS mode" stub. Compiler identity comes from the import DLLs, the frame prologues in .text, and the debug path instead.

## What still matches

- PE32, Intel 386. The lifter is Capstone `CS_ARCH_X86` / `CS_MODE_32`.
- Preferred image base 0x00400000, the same base the runtime maps SPEED2.EXE at.
- A section named .text exists, so Lifter.__init__ can select it.
- .text contains MSVC frame prologues and int3 padding, which is the compiler family tools/lift.py's switch patterns were written for.
- Direct3DCreate9, DirectInput8Create, and DirectSoundCreate are imports the current HLE already names.

No generated C was produced. tools/genall.py was not run.
