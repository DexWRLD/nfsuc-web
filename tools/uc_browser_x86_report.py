"""Generate descriptive Phase 72 backend status from measured browser evidence."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def generate():
 directory=ROOT/'analysis/undercover';d=json.loads((directory/'browser-x86-differential-phase72.json').read_text());b=d['benchmark'];a=d['actual']
 if not all(d['comparison'].values()) or not all(t['passed'] for t in d['budgetCases']):raise ValueError('Differential failed')
 engine=dict(name='Unicorn.js x86',package='@alexaltea/unicorn-js',version='2.1.4',sourceCommit='560284c59c11c8d6c94d537f4354339f069ddcdf',coreCommit='8028ec436f2d9376525352dd38ed9ed6b9f6be10',license='GPL-2.0',sha256='643adbbb0c77eadb71182f116c9da0860814221a25194dac3ed561589929ef6d',downloadBytes=915283,source='https://github.com/AlexAltea/unicorn.js/tree/560284c59c11c8d6c94d537f4354339f069ddcdf',packageUrl='https://registry.npmjs.org/@alexaltea/unicorn-js/-/unicorn-js-2.1.4.tgz',packageIntegrity='sha512-UAml23tgHyXEuP2A7Y50qDCNYMIRHJobsjlhetPRrtH+PXg0+BNAyvPQEKoCd+VHAF1nDfPHE4yJCqSLVtOrXA==',build='Published single-file Wasm/JS, verified integrity. Source/Emscripten build recipe reviewed; no local rebuild or bit-identical source-build attestation.')
 report=dict(phase=72,decision='NO_GO_ADOPTION',technicalBrowserDifferentialPassed=True,engine=engine,browser='Edge HTTPS dedicated worker',browserExecution=True,productionAvailable=False,originalInstructions=len(a['instructions']),originalEntries=len([e for e in a['trace'] if e['kind']=='enter']),distinctOriginalBodies=len({e['address'] for e in a['trace'] if e['kind']=='enter'}),calleeReturns=len([e for e in a['trace'] if e['kind']=='return']),originalGlobalWrites=len([w for w in a['writes'] if 0x400000<=w['address']<0x3000000]),differential=d['comparison'],memoryMethod='One existing process; private engine pages checked on every read and write; canonical writes immediate; private engine discarded per run',cpuFsConsistency='MATCHED_EXPLICIT_SYNTHETIC_THREAD',fixtureProvenance=a['classification'],stop=a['stop'],eip=a['registers']['eip'],flagsKnown=a['flagsKnown'],runtimeMedianMs=b['x86MedianMs'],wasmMedianMs=b['wasmMedianMs'],slowdown=b['ratio'],performanceGateMaximumRatio=5,performanceGatePassed=b['ratio']<=5,canonicalMemoryBytes=d['memoryBytes'],engineMemoryBytes=a['engineMemoryBytes'],engineMappedBytes=a['mappedBytes'],budgetCases=d['budgetCases'],newHandwrittenFunctionTranslations=0,unsupportedCpuSemanticsInControl=0,mixedBackendTransitionsVerified=False,cpuSimdInitializerTested=False,originalStartupReachability='UNVERIFIED',startupReady=False,fullGamePlayEnabled=False,providerSearchReopened=False,importsExecuted=[],newUniqueHarnessFunctions=0,reason='Measured per-instruction checked adapter exceeds 5x gate; mixed-engine resume/segment/flag-validity handoff and source-build reproducibility not production-qualified. Retain as test-only oracle.')
 (directory/'browser-x86-feasibility-phase72.json').write_text(json.dumps(report,indent=2)+'\n')
 (ROOT/'web/src/app/uc-backend-status.ts').write_text('// Generated from measured Phase 72 evidence; descriptive only, never dispatch authority.\nexport const BROWSER_X86_STATUS = '+json.dumps(report,indent=2)+' as const;\n')
 (directory/'browser-x86-benchmark-phase72.md').write_text(f'''# Phase 72 browser backend benchmark

Decision: NO-GO adoption; successful browser instruction differential remains a test-only result.

Engine: Unicorn.js x86 2.1.4, GPL-2.0, pinned source 560284c59c11c8d6c94d537f4354339f069ddcdf. Published single-file module: 915,283 bytes. No third-party binary is committed or added to the private LAN manifest.

| Measurement | Actual value |
|---|---:|
| Original instructions per connected run | 173 |
| Function entries / distinct bodies / callee returns | 12 / 7 / 9 |
| Original PE-global writes | 27 |
| Authenticated process creation, including checks and Wasm compile/instantiate | {d['processCreateMs']:.3f} ms |
| Engine initialization, excluding script fetch/evaluation | {d['engineInitMs']:.3f} ms |
| Current Wasm median | {b['wasmMedianMs']:.3f} ms |
| Browser x86 median | {b['x86MedianMs']:.3f} ms |
| Measured slowdown | {b['ratio']:.2f}x |
| Adoption gate | <=5x |
| Reset median, excluded from execution samples | {b['resetMedianMs']:.3f} ms |
| Canonical process linear-memory allocation | {d['memoryBytes']} bytes |
| Engine Wasm linear-memory allocation | {a['engineMemoryBytes']} bytes |
| Engine mapped guest pages, excluding synthetic GDT | {a['mappedBytes']} bytes |

Two warm-up pairs, seven measured pairs, one local headless Edge worker over temporary loopback HTTPS. Same canonical process, authenticated payload and synthetic thread are reset between backends. Wasm module/process are already compiled; each x86 run creates/maps/checks/closes a private engine. Instruction/write/read/snapshot tracing remains enabled. X86 timing includes digest checking, mapping, synchronization and cooperative yields; Wasm timing includes observer tracing. Reset, asset download and source-module compile/instantiate are outside execution samples. Total browser RSS/peak memory and full load/compile decomposition were not measured; linear-memory allocations are not RSS. No compression assumption, mobile/other-browser result, native-vs-browser speed claim or gameplay FPS estimate.

Raw Wasm samples (ms): {b['wasmMs']}

Raw x86 samples (ms): {b['x86Ms']}

Synchronization is performed within the timed x86 adapter and is not isolated as a separate benchmark. Native Phase 71 uses a smaller 138-instruction constructor fixture, so its timings are not directly comparable with this connected chain. No new handwritten function translation was needed; generic CPU integration, segment setup, checked hooks and metadata admission were required.

All twelve differential categories match, including per-instruction registers/defined flags, reads, writes, call/return trace, final memory, FS and the exact provider stop. Six budget cases pass. This proves browser CPU feasibility on this control chain, but the measured adapter fails the performance gate. No production switch, mixed-backend resume or CPU/SIMD follow-up is justified in this phase.
''')
 return report
if __name__=='__main__':generate()
