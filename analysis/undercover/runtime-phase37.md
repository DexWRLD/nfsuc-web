# Undercover Phase 37 — MSVC absolute dword jump-table dispatch

Graphics frozen: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`.
D3D9 / ENGINE BACKEND: **NOT JUSTIFIED**.

## A. Phase-36 baseline

UNIQUE 48, ENTERABLE 21, DEEPEST 4, CLOSURE 15, RUNTIME_READY 72, RUNS 83. Ctor stopped on BLOCKED_INDIRECT at case body `0x0097FA08`.

## B. Actual indirect instruction

`jmp dword ptr [eax*4 + 0x0097FA40]` bytes `ff248540fa9700` at `0x0097F9F5` in `0x0097F9E0`.

## C. Discriminator provenance

thiscall 0x0097F9E0: EAX = dword [esp+4] after stdcall arg; caller 0x0097FCD0 pushes [esp+0x14] (ctor first stack arg) then call

## D. Switch/table classification

**ABSOLUTE_DWORD_JUMP_TABLE** / **PROVEN_JUMP_TABLE**.

## E. Table location and targets

Base `0x0097FA40` (.text), width 4, count 7, formula absolute VA. Bounds: `cmp eax,6; ja` default `0x0097FA3D`; special `eax==1000`.

## F. Original runtime-selected target

Index **3** → `0x0097FA08` (Phase-36 blocked_va evidence).

## G. JTSWITCH audit

Harness Phase 31–36 lifted without JTSWITCH=1, so the absolute dword table became DISPATCH_TAIL → dispatch_indirect → BLOCKED_INDIRECT. uc_gen/genall already set JTSWITCH=1 for full builds.

## H. Diagnosis of failure

A. jump table not recognized

## I. Lifter/dispatcher fix

Enable os.environ['JTSWITCH']='1' in uc_harness31.Harness before lift; no address-hardcoded bypass; reusable MSVC pattern.

## J. Tests

`uc_phase37_test.py` — table form, lifter emission, harness case-3, invalid selector, ctor clean regression.

## K. Constructor before/after

Before: BLOCKED_INDIRECT. After: **EXECUTED_CHAIN** clean=True depth=4 closure=18 SleepEx=5 ticks=2500000.

## L. Next blocker

None on ctor — **RETURNED_CLEAN**. Campaign still has CRT atexit / required-state roots.

## M. Broader switch impact

Harness now matches uc_gen JTSWITCH policy. Sample census: 6.

## N. Frontier delta

UNIQUE **48**; ENTERABLE **21**; DEEPEST **4**; CLOSURE **18**; CLEAN **13**; RUNTIME_READY **72**; RUNS **95**.

## O. Phase-38 recommendation

Constructor 0x009E9160 RETURNED CLEAN (EXECUTED_CHAIN) after JTSWITCH harness enablement. Phase 38: EXPAND REAL UC EXECUTION — harvest additional ordinary roots that benefit from jump-table lowering, or deepen post-ctor consumers now that the timing/priority/TLS init object constructs successfully. Graphics remain frozen.
