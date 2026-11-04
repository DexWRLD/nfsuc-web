# Phase 72 browser backend benchmark

Decision: NO-GO adoption; successful browser instruction differential remains a test-only result.

Engine: Unicorn.js x86 2.1.4, GPL-2.0, pinned source 560284c59c11c8d6c94d537f4354339f069ddcdf. Published single-file module: 915,283 bytes. No third-party binary is committed or added to the private LAN manifest.

| Measurement | Actual value |
|---|---:|
| Original instructions per connected run | 173 |
| Function entries / distinct bodies / callee returns | 12 / 7 / 9 |
| Original PE-global writes | 27 |
| Authenticated process creation, including checks and Wasm compile/instantiate | 52.300 ms |
| Engine initialization, excluding script fetch/evaluation | 14.700 ms |
| Current Wasm median | 0.400 ms |
| Browser x86 median | 45.800 ms |
| Measured slowdown | 114.50x |
| Adoption gate | <=5x |
| Reset median, excluded from execution samples | 6.600 ms |
| Canonical process linear-memory allocation | 51445760 bytes |
| Engine Wasm linear-memory allocation | 41418752 bytes |
| Engine mapped guest pages, excluding synthetic GDT | 40960 bytes |

Two warm-up pairs, seven measured pairs, one local headless Edge worker over temporary loopback HTTPS. Same canonical process, authenticated payload and synthetic thread are reset between backends. Wasm module/process are already compiled; each x86 run creates/maps/checks/closes a private engine. Instruction/write/read/snapshot tracing remains enabled. X86 timing includes digest checking, mapping, synchronization and cooperative yields; Wasm timing includes observer tracing. Reset, asset download and source-module compile/instantiate are outside execution samples. Total browser RSS/peak memory and full load/compile decomposition were not measured; linear-memory allocations are not RSS. No compression assumption, mobile/other-browser result, native-vs-browser speed claim or gameplay FPS estimate.

Raw Wasm samples (ms): [0.5, 0.4000000022351742, 0.8000000007450581, 0.30000000074505806, 0.4000000022351742, 0.29999999701976776, 0.19999999925494194]

Raw x86 samples (ms): [42.099999997764826, 52.79999999701977, 46.19999999925494, 52.399999998509884, 45.80000000074506, 44, 39.80000000074506]

Synchronization is performed within the timed x86 adapter and is not isolated as a separate benchmark. Native Phase 71 uses a smaller 138-instruction constructor fixture, so its timings are not directly comparable with this connected chain. No new handwritten function translation was needed; generic CPU integration, segment setup, checked hooks and metadata admission were required.

All twelve differential categories match, including per-instruction registers/defined flags, reads, writes, call/return trace, final memory, FS and the exact provider stop. Six budget cases pass. This proves browser CPU feasibility on this control chain, but the measured adapter fails the performance gate. No production switch, mixed-backend resume or CPU/SIMD follow-up is justified in this phase.
