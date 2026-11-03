# Undercover Phase 29 — TlsAlloc boundary

Graphics frozen: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`.

## A. Baseline

Depth 3 ctor chain blocked at `0x009777D0` / `[0x00B61138]`.

## B. `0x00B61138` identity

- DLL: **KERNEL32.dll**
- Symbol: **TlsAlloc** (hint 867)
- Classification: **STANDARD_WIN32_IMPORT**
- Initial PE dword: `0x008AB2CE` (unbound IMAGE_IMPORT_BY_NAME RVA)
- Section: `.rdata`

## C. `0x009777D0` call contract

thiscall-like wrapper; ret 0; ECX=this storage for TLS index

- Import args: **0** (CONSTANT empty)
- Return: store EAX TLS index to `[this]`, return this
- ABI confidence: **PROVEN**

## D. Implementation decision

HLE justified and implemented: public KERNEL32!TlsAlloc, stdcall/0, guest index abstraction.

## E. Runtime

`UC_HLE_TLSALLOC` in `runtime/uc_import.c`; IAT bind via `uc_import_bind_hle_iats`.

## F. Before/after

- Before: stop at stubbed `0x009777D0`
- After: TlsAlloc + wrapper + `0x009E8AD0` entered; next blocker `0x00977800`

## G–H. Constructor continuation / ownership

Chain continued. Object ownership: CALLER_STORAGE; parent `0x009E9340` not enterable.

## I. Fallback `0x00947790`

Not executed; still UNKNOWN required state.

## J–N. Depth-4 / campaign / delta / Phase 30

ENTERABLE_WITH_DEPTH_4_POTENTIAL: 0.
Largest closure: **10**. Depth: **3**.

TlsAlloc unblocked 0x009777D0→0x009E8AD0. Next on the same chain: 0x00977800 calls IAT 0x00B611C8 = KERNEL32!TlsSetValue (classify ABI/args before HLE). Depth stays 3 until parent 0x009E9340 is ENTERABLE. 0x00947790 still UNKNOWN. Do not reopen A52DF0/graphics.
