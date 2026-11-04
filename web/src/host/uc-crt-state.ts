import { CRT_IMPORT_EVIDENCE } from './uc-crt-imports';
import type { GuestAddressSpace } from './uc-process';

/** Inspection only. Import identity never authorizes dispatch or cell writes. */
export function describeCrtState(memory: GuestAddressSpace) {
  const providers = CRT_IMPORT_EVIDENCE.providers.map(entry => {
    const actualLegacyValue = memory.read32(entry.legacyCell);
    if (actualLegacyValue !== entry.legacyFileValue) throw new Error('Unexpected CRT legacy-cell mutation');
    return { ...entry, actualLegacyValue, activeImportIdentityVerified: true,
      activeImportStorage: 'UNAVAILABLE_PE_SECTION', effectiveTarget: actualLegacyValue,
      runtimeBindingVerified: false, importedServiceExecuted: false };
  });
  return { sourceSha256: CRT_IMPORT_EVIDENCE.sourceSha256, providers,
    runtimeBindingVerified: false, loaderCopyVerified: false, importedServicesExecuted: [],
    conditionalInitialization: { classification: CRT_IMPORT_EVIDENCE.crtOrderClassification,
      edges: CRT_IMPORT_EVIDENCE.edges, branchConditions: CRT_IMPORT_EVIDENCE.branchConditions,
      firstDependencies: CRT_IMPORT_EVIDENCE.firstDependencies, traversalExecuted: false },
    cookie: { value: memory.read32(0x01285688), complement: memory.read32(0x0128568c),
      provenance: 'AUTHENTICATED_FILE_BYTES_ONLY', initializerExecuted: false },
    cleanupGlobals: { start: memory.read32(0x018b1e68), end: memory.read32(0x018b1e6c),
      originalSentinelInitializerExecuted: false, encodedSentinelValue: null },
    callbackRegistrationCompleted: false, originalStartupReachability: 'UNVERIFIED' };
}
