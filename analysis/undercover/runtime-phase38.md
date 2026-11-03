# Undercover Phase 38 — post-constructor ordinary execution

Graphics frozen: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`.
D3D9 / ENGINE BACKEND: **NOT JUSTIFIED**.

## A. Phase-37 baseline

Ctor `0x009E9160` RETURNED_CLEAN; UNIQUE 48; CLOSURE 18; CLEAN 13; JTSWITCH enabled.

## B. Constructor state contract

Extent `0x248`; thiscall `(SRC_POD, 0)`; ret 8; no stubs.

## C. Object fields and write provenance

Non-zero dwords after clean ctor: **34**. Highlights: {"vtable_plus0": "0x00C30E68", "embedded_pod_vtable_plus4": "0x00C30F2C", "arg2_plus58": "0x00000000", "tls_index_plus240": "0x00000000", "flag_plus_dc": "0x00000000"}.

## D. Guest runtime side effects

TLS alloc/set, ICS/mutex, priorities, SleepEx×5, QPC ticks 2500000.

## E. Candidate consumer search

Vtable `0x00C30E68` slots inspected; dtor/allocator paths rejected.

## F. Static vtable relationship

Main `0x00C30E68` @+0; pod `0x00C30F2C` @+4; base family `0x00C30D5C`.

## G. Consumer ranking

Strongest: setter/getter `0x009E9140`/`0x009E9150` (+0xDC). Also rtti-like `0x009E7780`, pod `0x009E9980`.

## H. Multi-step harness architecture

`uc_p31_step` + `Harness.begin_sequence`/`step(continue_state=True)` preserve guest runtime + object; independent `run()` still full-resets.

## I. Stateful execution campaign

Sequences tested: 6; clean: 6; longest length: 3; largest coverage: 20.

## J. New ordinary bodies reached

New unique vs Phase 37 prior list: ['0x009E7780', '0x009E8400', '0x009E9140', '0x009E9150', '0x009E9980'].

## K. Next genuine blockers

List-walk `0x009E8400` may need +0xBC/+0xC0 state; campaign REQUIRED_STATE remains common. Factory `0x009E9340` still allocator-blocked.

## L. Frontier delta

UNIQUE **53**; ENTERABLE **25**; DEEPEST **4**; CLOSURE **18**; SEQ_LEN **3**; SEQ_COV **20**; CLEAN **13**; RUNS **113**.

## M. Phase-39 recommendation

Stateful ctor→setter→getter and vtable leaf methods execute cleanly. Phase 39: EXPAND REAL UC EXECUTION — pursue additional SAME_VTABLE_FAMILY methods with proven field prerequisites (avoid dtors/allocator), or ordinary global consumers of 0x0189D1A4/0x0189D198 published during ctor. Do not reopen protected allocator/factory. Graphics frozen.
