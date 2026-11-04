import { createUndercoverProcess } from '../host/uc-unified';
import { UcDownloadManager } from './uc-download-manager';
import { MemoryAssetStore, openOpfsAssetStore } from './uc-asset-cache';

export async function runUnifiedIntegration(signal: AbortSignal) {
  const store = await openOpfsAssetStore().catch(() => new MemoryAssetStore());
  const manager = new UcDownloadManager({ store, pageOrigin: location.origin });
  const manifest = await manager.loadManifest('/uc-asset-manifest.json');
  const files: Uint8Array[] = [];
  for (const name of ['uc-unified-image.json', 'uc-unified-image.bin', 'uc-unified.wasm']) {
    signal.throwIfAborted();
    const entry = manifest.assets.find(candidate => candidate.path === name);
    if (!entry) throw new Error('Private unified-process asset unavailable: ' + name);
    const bytes = await manager.ensureAsset(manifest, entry, signal);
    signal.throwIfAborted();
    if (!bytes) throw new Error('Unified asset missing after verification');
    files.push(bytes);
  }
  const descriptor = JSON.parse(new TextDecoder().decode(files[0]));
  const process = await createUndercoverProcess(descriptor, files[1], files[2]);
  const before = process.memory.read32(0x0189d1a4);
  const staticCell = process.memory.read32(0x00bbb2bc);
  if (before !== 0 || staticCell !== 0x0080d090) throw new Error('Unexpected original PE state');
  process.call(0x009e8ad0);
  const after = process.memory.read32(0x0189d1a4);
  const initializer = { writes: process.writes, eip: process.cpu.eip, esp: process.cpu.esp };
  if (after !== 0x009e78c0 || initializer.writes !== 49 || initializer.eip !== 0x00dec0de
      || initializer.esp !== 0x0300f000) throw new Error('Unexpected unified initializer result');
  process.dispatcher.trace.length = 0;
  let fault = '';
  try { process.call(0x0099dcd0, [0, 2]); }
  catch (error) { fault = error instanceof Error ? error.message : String(error); }
  const entered = process.dispatcher.trace.filter(event => event.kind === 'enter').map(event => event.address);
  if (!fault.includes('read at 0xfffffffc') || process.lastInstruction !== 0x009e4b49
      || process.cpu.edx !== 0 || process.cpu.eax !== 0
      || entered.join(',') !== [0x0099dcd0, 0x009e78c0, 0x009b6290, 0x009e4b10, 0x009e78c0].join(',')) {
    throw new Error('Unexpected unified callback-prefix result');
  }
  const registers = { ...process.cpu };
  process.reset();
  if (process.memory.read32(0x0189d1a4) !== before || process.memory.read32(0x00bbb2bc) !== staticCell) {
    throw new Error('Unified reset failed');
  }
  const globalBefore = process.memory.read32(0x0189d0f8);
  if (process.memory.read32(0x00b6370c) !== 0x00b57dc0) throw new Error('Original initializer pointer mismatch');
  let initializationFault = '';
  try { process.call(0x00b57dc0); }
  catch (error) { initializationFault = error instanceof Error ? error.message : String(error); }
  const observed = process.snapshot();
  const initializationTrace = process.dispatcher.trace.map(event => ({ ...event }));
  const initializationEntered = initializationTrace.filter(event => event.kind === 'enter').map(event => event.address);
  const initializationWrites = process.writeLog.filter(write => write.address >= 0x00400000 && write.address < 0x03000000);
  if (!initializationFault.includes('dispatch at 0x87b59b: unavailable')
      || observed.lastInstruction !== 0x0087b644 || observed.cpu.eax !== 0x0189d0a0
      || observed.cpu.esp !== 0x0300efe8
      || initializationEntered.join(',') !== [0x00b57dc0, 0x009e7540,
        0x009e75a0, 0x009e75a0, 0x009e75a0, 0x009e75a0, 0x009e75a0, 0x009e75a0, 0x009c1830, 0x0087b640].join(',')
      || initializationTrace.filter(event => event.kind === 'return').length !== 8
      || initializationWrites.length !== 27
      || process.memory.read32(0x0189d0f8) !== 0x32000 || process.memory.read32(0x0189d0fc) !== 0x186a0) {
    throw new Error('Unexpected connected Apt initialization result');
  }
  const initialization = {
    root: '0x00B57DC0', staticPointerCell: '0x00B6370C', receiverSource: 'Original MOV ECX,0x0189D0A0 at 0x00B57DC3',
    entered: initializationEntered, trace: initializationTrace, globalWrites: initializationWrites,
    registers: observed.cpu, lastInstruction: observed.lastInstruction, flagsKnown: observed.flagsKnown,
    phase66Checkpoint: initializationTrace.find(event => event.kind === 'enter' && event.address === 0x0087b640),
    differenceFromPhase66: 'Original wrapper entered; callee blocked before SEH. Cleanup not registered.',
    firstUnsupportedDependency: initializationFault, originalStartupReachability: 'UNVERIFIED',
  };
  process.reset();
  if (process.memory.read32(0x0189d0f8) !== globalBefore || process.memory.read32(0x0189d1a4) !== before) {
    throw new Error('Initialization-state reset failed');
  }
  return {
    mappedSections: descriptor.segments.map((segment: { name: string; address: number; size: number; unavailable: boolean }) => ({
      name: segment.name, address: '0x' + segment.address.toString(16), size: segment.size, unavailable: segment.unavailable,
    })),
    registeredAddresses: process.registry.bindings.map(binding => '0x' + binding.address.toString(16)),
    currentEip: initialization.registers.eip, platformServiceCalls: [],
    initialization,
    evidence: 'Shared memory verified. Host orders initializer and root as a diagnostic fixture.',
    sourceSha256: descriptor.sourceSha256, before, after, staticCell, initializer, entered,
    lastInstruction: 0x009e4b49, fault, registers,
    reset: 'Original PE bytes and zero-filled state restored',
  };
}

