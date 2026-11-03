# Undercover Phase 41 — nontrivial lifecycles + virtual continuation

Graphics frozen: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`.

## A. Phase-40 baseline

UNIQUE 61, ENTERABLE 29, families 2, VT_DISP 1, RUNS 179.

## B. Undercover target provenance

TOOLING_ORIGIN=`NFSU2-WEB`. GAME_CODE_TARGET=`NFS_UNDERCOVER_PC`.
Status: **VERIFIED_UNDERCOVER_1_1_2_1**. SHA-256 match=True. Ordinary `.text` samples verified for Phase-40/41 VAs.

## C. Family B nontrivial consumer search

Standalone: `0x009E9980` RTTI, `0x009E9990` copy, **`0x009E9A30` export**.
Embedded-only: `0x009E9CD0` / `0x009E9DB0` (need parent `this+4`).

## D. Standalone versus embedded contracts

Export/copy/RTTI are STANDALONE_FAMILY_B. `9E9CD0`/`9E9DB0` are EMBEDDED_FAMILY_B.

## E. New lifecycle execution

B: `9E98F0`→`9E9A30` exports +0x38..+0x4C (match ctor fields). C: `9EB350`→`9EB310` RTTI `EAX=0x00C31168`.

## F. Virtual-call site provenance

Caller `0x009E8E00` site `0x009E8E15` `call edx` with edx=`[vt+0x14]`. Family-A object → target `0x009E8E00` (same function). `uc_indirect_enters≥1` proves nested DISPATCH_CALL activation.

## G. Virtual continuation diagnosis

**INCORRECT_VTABLE_SLOT**: Call site 0x009E8E15 invokes [vt+0x14] as thiscall with 0 stack args, expecting EAX string. Family-A slot5 resolves to 0x009E8E00 itself (ret 4). Nested activation therefore lacks the stack arg its prologue reads at [esp+0x20], loads EBP≈0/garbage, then faults on `mov eax, dword ptr [ebp]` (unmapped guest access at 0). Not a clean virtual-method completion.

## H. Additional independent family search

Family C `0x009EB350` (vt `0x00C31180`) entered with null-safe arg2.

## I. Real execution campaign

Sequences 10; clean 8; families 3; nontrivial 2; VT_DISP 1; CLEAN_VT 0; VT_FAULTS 1.

## J. Actual blockers

Virtual continuation INCORRECT_VTABLE_SLOT. Family C nontrivial consumers allocator/protected-adjacent. Embedded B methods need parent.

## K. Frontier delta

UNIQUE **64**; FAMILIES **3**; NONTRIVIAL **2**; CLEAN_LIFE **3**; RUNS **243**.

## L. Phase-42 recommendation

Family B nontrivial export (`0x009E9A30`) and Family C RTTI lifecycle are proven. Virtual self-dispatch at `0x009E8E00` remains a continuation fault (INCORRECT_VTABLE_SLOT / ABI mismatch). Phase 42: EXPAND REAL UC EXECUTION on Family C nontrivial consumers or a correctly typed string-provider object for the 0x009E8E00 virtual call site. Graphics frozen.
