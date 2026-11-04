// Generated from measured Phase 72 evidence; descriptive only, never dispatch authority.
export const BROWSER_X86_STATUS = {
  "phase": 72,
  "decision": "NO_GO_ADOPTION",
  "technicalBrowserDifferentialPassed": true,
  "engine": {
    "name": "Unicorn.js x86",
    "package": "@alexaltea/unicorn-js",
    "version": "2.1.4",
    "sourceCommit": "560284c59c11c8d6c94d537f4354339f069ddcdf",
    "coreCommit": "8028ec436f2d9376525352dd38ed9ed6b9f6be10",
    "license": "GPL-2.0",
    "sha256": "643adbbb0c77eadb71182f116c9da0860814221a25194dac3ed561589929ef6d",
    "downloadBytes": 915283,
    "source": "https://github.com/AlexAltea/unicorn.js/tree/560284c59c11c8d6c94d537f4354339f069ddcdf",
    "packageUrl": "https://registry.npmjs.org/@alexaltea/unicorn-js/-/unicorn-js-2.1.4.tgz",
    "packageIntegrity": "sha512-UAml23tgHyXEuP2A7Y50qDCNYMIRHJobsjlhetPRrtH+PXg0+BNAyvPQEKoCd+VHAF1nDfPHE4yJCqSLVtOrXA==",
    "build": "Published single-file Wasm/JS, verified integrity. Source/Emscripten build recipe reviewed; no local rebuild or bit-identical source-build attestation."
  },
  "browser": "Edge HTTPS dedicated worker",
  "browserExecution": true,
  "productionAvailable": false,
  "originalInstructions": 173,
  "originalEntries": 12,
  "distinctOriginalBodies": 7,
  "calleeReturns": 9,
  "originalGlobalWrites": 27,
  "differential": {
    "engineHooks": true,
    "instructions": true,
    "registers": true,
    "writes": true,
    "trace": true,
    "fs": true,
    "fsAccesses": true,
    "reads": true,
    "flagsKnown": true,
    "states": true,
    "memory": true,
    "stop": true
  },
  "memoryMethod": "One existing process; private engine pages checked on every read and write; canonical writes immediate; private engine discarded per run",
  "cpuFsConsistency": "MATCHED_EXPLICIT_SYNTHETIC_THREAD",
  "fixtureProvenance": "ORIGINAL_BYTES_EXPLICIT_SYNTHETIC_THREAD_NOT_STARTUP",
  "stop": "dispatch at 0x8aac6a: unavailable",
  "eip": 8893875,
  "flagsKnown": 59,
  "runtimeMedianMs": 45.80000000074506,
  "wasmMedianMs": 0.4000000022351742,
  "slowdown": 114.49999936204404,
  "performanceGateMaximumRatio": 5,
  "performanceGatePassed": false,
  "canonicalMemoryBytes": 51445760,
  "engineMemoryBytes": 41418752,
  "engineMappedBytes": 40960,
  "budgetCases": [
    {
      "name": "instructions",
      "expectedStop": "BUDGET_INSTRUCTIONS",
      "actualStop": "BUDGET_INSTRUCTIONS",
      "passed": true,
      "instructions": 3
    },
    {
      "name": "depth",
      "expectedStop": "BUDGET_CALL_DEPTH",
      "actualStop": "BUDGET_CALL_DEPTH",
      "passed": true,
      "instructions": 4
    },
    {
      "name": "writes",
      "expectedStop": "BUDGET_WRITES",
      "actualStop": "BUDGET_WRITES",
      "passed": true,
      "instructions": 4
    },
    {
      "name": "accessBytes",
      "expectedStop": "BUDGET_ACCESS_BYTES",
      "actualStop": "BUDGET_ACCESS_BYTES",
      "passed": true,
      "instructions": 4
    },
    {
      "name": "wall",
      "expectedStop": "BUDGET_WALL",
      "actualStop": "BUDGET_WALL",
      "passed": true,
      "instructions": 0
    },
    {
      "name": "transitions",
      "expectedStop": "BUDGET_TRANSITIONS",
      "actualStop": "BUDGET_TRANSITIONS",
      "passed": true,
      "instructions": 1
    }
  ],
  "newHandwrittenFunctionTranslations": 0,
  "unsupportedCpuSemanticsInControl": 0,
  "mixedBackendTransitionsVerified": false,
  "cpuSimdInitializerTested": false,
  "originalStartupReachability": "UNVERIFIED",
  "startupReady": false,
  "fullGamePlayEnabled": false,
  "providerSearchReopened": false,
  "importsExecuted": [],
  "newUniqueHarnessFunctions": 0,
  "reason": "Measured per-instruction checked adapter exceeds 5x gate; mixed-engine resume/segment/flag-validity handoff and source-build reproducibility not production-qualified. Retain as test-only oracle."
} as const;
