# Undercover Phase 42 — Family C consumers + typed virtual provenance

Graphics frozen: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`.

## A. Baseline

Phase 41: UNIQUE 64, ENTERABLE 31, families 3, nontrivial 2, VT_DISP 1 / fault 1.

## B. Family C object contract

Ctor `0x009EB350` thiscall ret `0x10`; extent `0x1C`; vt `0x00C31180`; fields +0/+4/+8/+C/+10/+14/+18 as in `object-family-frontier.json`.

## C. Family C consumer census

Safe standalone: `0x009EB310` RTTI, **`0x009EB2B0` field-slot**, `0x009EB2D0` clear-+8 early-exit. Unsafe: slot3/`9EB280` need interface at +0x14; dtor protected.

## D. Nontrivial lifecycle results

`0x009EB350`→`0x009EB2B0` clean; EAX=`this+0xC`; payload dword matches ctor.

## E. Virtual-call receiver identification

Receiver is **SEPARATE_INTERFACE_ARGUMENT** (stack arg0 / ebp), not Family A this.

## F. Interface provider candidates

Static POSSIBLE_INTERFACE vtables with `mov eax,[ecx+disp]; ret` at slot5 exist; no proven ordinary ctor→`9E8E00` arg producer enterable without fabrication.

## G. Virtual-call ABI / continuation

Site pushes 0 args; expects string in EAX / ret 0. Family A slot5 self-target is ret 4 → nested activation missing stack arg → INCORRECT_VTABLE_SLOT. Missing stack argument on nested self-call: YES.

## H. Sparse dispatch verification

sparse ok=True; protected registered=[]; lifted=123.

## I. Alternate-family campaign

`0x009EBC70`, `0x00808770` regressions; Family A/B mandatory paths clean.

## J. Next genuine blockers

Family C +0x14 interface object; typed string-provider for `0x009E8E15`.

## K. Audited metric delta

UNIQUE **67**; ENTERABLE **33**; NONTRIVIAL **3**; RUNS **265**.

## L. Phase-43 recommendation

Family C field-slot getter `0x009EB2B0` validates constructor payload layout beyond RTTI; vt-slot3/interface consumers remain blocked without a real interface at +0x14. Virtual call at `0x009E8E15` needs a proven ordinary producer of a ret0 string/field getter at slot+0x14 — none enterable without fabrication. Phase 43: EXPAND REAL UC EXECUTION on proven interface producers for typed virtual calls, or deeper Family C when +0x14 interface objects are ordinarily constructed. Graphics frozen.
