# Undercover Phase 30 — TlsSetValue / dynamic guest TLS

Graphics frozen: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`.

## A. TlsSetValue identity

- Slot `0x00B611C8`: **KERNEL32.dll!TlsSetValue** (hint 870)
- Classification: **STANDARD_WIN32_IMPORT**
- Call sites: **8**

## B. ABI

stdcall, **2** stack dwords, return BOOL in EAX. Confidence: **PROVEN**.

## C. Real call contract (`0x00977800`)

stdcall wrapper ret 4; ECX=pointer to TLS index dword; [esp+4]=value

- Index: `[ECX]` at object+0x240 (from TlsAlloc)
- Value: caller `push ebx` after `xor ebx,ebx` → **0** (`INTEGER_VALUE` / NULL)
- Wrapper `ret 4`; import stdcall cleans 8

## D. Guest TLS architecture

Per-guest-thread value table × allocated index bitmask. Single active guest-thread context today; host OS TLS unused.

## E. Implementation

`UC_HLE_TLSSETVALUE` in `runtime/uc_import.c`. Invalid index → EAX=0. GetLastError not modeled.

## F. Unit tests

Alloc, set, multi-index, invalid, NULL, stdcall ESP cleanup — `uc_phase30_test.py`.

## G. Real before/after

- Before (HLE disabled): stop at `0x00977800` → `[0x00B611C8]`
- After: TlsSetValue; ctor **RETURNED_CLEAN** (`ret 8`)

## H. Next blocker

Parent `0x009E9340`: vtable-mediated game allocator via global object from 0x009E9460 / 0x0189DA88 (ORDINARY_GAME_ALLOCATOR). Not implemented.

## I. TlsGetValue / TlsFree discovery

- TlsGetValue `@ 0x00B611CC`: 1354 sites, **not reached**, not implemented
- TlsFree `@ 0x00B61120`: 4 sites, **not reached**, not implemented

## J. Dynamic vs static TLS

DYNAMIC_WIN32_TLS only this phase. PE_STATIC_TLS and SEH_FS kept separate.

## K. `0x009E9340` allocator

{
  "parent": "0x009E9340",
  "allocator_helper": "0x009EB870",
  "mechanism": "0x009EB870 calls 0x009E9460 for allocator object, then virtual call [vtable+8] (edx) with size/args \u2014 runtime-initialized vtable.",
  "identity": "vtable-mediated game allocator via global object from 0x009E9460 / 0x0189DA88",
  "classification": "ORDINARY_GAME_ALLOCATOR",
  "sub_class": "RUNTIME_INITIALIZED_CALLBACK",
  "standard_crt": false,
  "implementation_attempted": false,
  "note": "Do not substitute malloc. Not Phase-30 scope."
}

## L. Frontier delta

TlsSetValue IMPLEMENTED; ctor CLEAN; UNIQUE/CLOSURE up via `0x00977800`; depth still 3.

## M. Phase 31

Ctor 0x009E9160 now RETURNED_CLEAN after TlsSetValue. Depth-4 needs parent 0x009E9340 (ORDINARY_GAME_ALLOCATOR via vtable — do not malloc-substitute). TlsGetValue is heavily imported but not on this path — implement only if a related ordinary reader is reached. Prefer EXPAND ORDINARY INITIALIZATION / REAL UC EXECUTION for next ENTERABLE roots, or EXPAND THREADING/TLS RUNTIME if a TlsGetValue consumer on the same object family is selected. Do not reopen A52DF0/graphics.
