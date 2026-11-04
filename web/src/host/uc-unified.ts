import { UNIFIED_BINDINGS as bindings, UNIFIED_REGISTRY } from './uc-unified-registry';
import { GuestThreadFixtures, THREAD_BASES } from './uc-thread';
import { GuestAddressSpace, GuestDispatcher, READ, WRITE, type GuestCpu, type GuestSegment } from './uc-process';

export const UNDERCOVER_SHA = '6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd';
const registers = ['esp', 'eip', 'eax', 'ebp', 'ecx', 'edx', 'esi', 'edi', 'ebx'] as const;
interface ImageSegment {
  name: string; address: number; size: number; permissions: number;
  offset: number; length: number; sha256: string; unavailable: boolean;
}
interface ImageDescriptor {
  version: number; imageBase: number; sourceSha256: string; payloadSha256: string;
  moduleSha256: string; payloadSize: number; segments: ImageSegment[]; bindings: unknown;
}
interface UnifiedExports {
  execute(address: number): void;
  set_register(index: number, value: number): void;
  get_register(index: number): number;
  get_flags(): number;
  get_flags_known(): number;
  set_flags(value: number, known: number): void;
}
async function sha(bytes: Uint8Array): Promise<string> {
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes.slice())))
    .map(value => value.toString(16).padStart(2, '0')).join('');
}

export interface UnifiedExecutionObserver {
  instruction?(cpu: GuestCpu, flagsKnown: number): void;
  read?(address: number, size: number, instruction: number, value: number): void;
}
export async function createUndercoverProcess(description: unknown, payload: Uint8Array, code: Uint8Array, observer?: UnifiedExecutionObserver) {
  const image = description as ImageDescriptor;
  if (!image || image.version !== 1 || image.imageBase !== 0x00400000
      || image.sourceSha256 !== UNDERCOVER_SHA || image.payloadSize !== payload.length
      || await sha(payload) !== image.payloadSha256 || !Array.isArray(image.segments)
      || await sha(code) !== image.moduleSha256 || !Array.isArray(image.bindings)
      || image.bindings.length !== bindings.length
      || !image.bindings.every((binding, index) => binding
        && binding.address === bindings[index].address && binding.convention === bindings[index].convention
        && binding.argumentBytes === bindings[index].argumentBytes && binding.frameContract === bindings[index].frameContract)) {
    throw new Error('Invalid authenticated Undercover image descriptor');
  }
  const allowed = new Set(['.text', '.rdata', '.data', '.tls', '.rsrc']);
  const segments: GuestSegment[] = [];
  let nextOffset = 0;
  for (const segment of image.segments) {
    if (!segment || typeof segment.name !== 'string' || typeof segment.unavailable !== 'boolean'
        || !Number.isSafeInteger(segment.offset) || !Number.isSafeInteger(segment.length)
        || segment.offset !== nextOffset || segment.length < 0 || segment.length > payload.length - segment.offset
        || segment.address % 0x1000 !== 0 || segment.address < image.imageBase || !Number.isInteger(segment.permissions)
        || segment.permissions < 0 || segment.permissions > 7
        || segment.unavailable && segment.length !== 0
        || !segment.unavailable && !allowed.has(segment.name)) {
      throw new Error('Invalid PE section descriptor');
    }
    const bytes = payload.slice(segment.offset, segment.offset + segment.length);
    if (await sha(bytes) !== segment.sha256) throw new Error('PE section digest mismatch');
    nextOffset += segment.length;
    segments.push({
      name: segment.name, address: segment.address, size: segment.size,
      permissions: segment.permissions, unavailable: segment.unavailable, bytes,
    });
  }
  if (nextOffset !== payload.length) throw new Error('Unreferenced image payload');
  segments.push({ name: 'diagnostic stack', address: 0x03000000, size: 0x10000, permissions: READ | WRITE });
  segments.push({ name: 'second thread fixture stack', address: 0x03010000, size: 0x10000, permissions: READ | WRITE });
  THREAD_BASES.forEach(address => segments.push({ name: 'synthetic thread fixture', address, size: 0x1000, permissions: READ | WRITE }));
  const memory = new GuestAddressSpace(segments, image.imageBase);
  const threads = new GuestThreadFixtures(memory);
  const module = await WebAssembly.compile(code.slice());
  const requiredImports = new Set(['env.memory:memory', 'guest.read32:function', 'guest.write32:function',
    'guest.dispatch:function', 'guest.instruction:function', 'guest.write8:function', 'guest.readFs32:function', 'guest.writeFs32:function']);
  const imports = WebAssembly.Module.imports(module).map(entry => entry.module + '.' + entry.name + ':' + entry.kind);
  if (imports.length !== requiredImports.size || imports.some(entry => !requiredImports.has(entry))) {
    throw new Error('Unexpected unified module imports');
  }
  const cpu: GuestCpu = { eax: 0, ebx: 0, ecx: 0, edx: 0, esi: 0, edi: 0, ebp: 0, esp: 0x0300f000, eip: 0, eflags: 0 };
  let exports: UnifiedExports;
  let dispatcher: GuestDispatcher;
  let flagsKnown = 0;
  let lastInstruction = 0;
  let writes = 0;
  const writeLog: { address: number; size: number; value: number; instruction: number }[] = [];
  const instructions: number[] = [];
  const readCpu = () => {
    registers.forEach((name, index) => { cpu[name] = exports.get_register(index) >>> 0; });
    cpu.eflags = exports.get_flags() >>> 0;
    flagsKnown = exports.get_flags_known() >>> 0;
  };
  const writeCpu = () => {
    registers.forEach((name, index) => exports.set_register(index, cpu[name]));
    exports.set_flags(cpu.eflags, flagsKnown);
  };
  const instance = await WebAssembly.instantiate(module, {
    env: { memory: memory.memory },
    guest: {
      readFs32: (offset: number) => {
        const value = threads.read(offset >>> 0);
        observer?.read?.(threads.snapshot().fsBase! + (offset >>> 0), 4, lastInstruction, value);
        return value;
      },
      writeFs32: (offset: number, value: number) => threads.write(offset >>> 0, value >>> 0),
      read32: (address: number) => {
        const value = memory.read32(address >>> 0);
        observer?.read?.(address >>> 0, 4, lastInstruction, value);
        return value;
      },
      write32: (address: number, value: number) => {
        memory.write32(address >>> 0, value);
        writes++;
        writeLog.push({ address: address >>> 0, size: 4, value: value >>> 0, instruction: lastInstruction });
      },
      write8: (address: number, value: number) => {
        memory.write8(address >>> 0, value);
        writes++;
        writeLog.push({ address: address >>> 0, size: 1, value: value & 0xff, instruction: lastInstruction });
      },
      instruction: (address: number) => {
        lastInstruction = address >>> 0;
        instructions.push(lastInstruction);
        exports.set_register(1, lastInstruction);
        if (observer?.instruction) {
          const observed = Object.fromEntries(registers.map((name, index) => [name, exports.get_register(index) >>> 0])) as unknown as GuestCpu;
          observed.eflags = exports.get_flags() >>> 0;
          observer.instruction(observed, exports.get_flags_known() >>> 0);
        }
      },
      dispatch: (address: number) => {
        readCpu();
        try { dispatcher.callFromGuest(cpu, address >>> 0); }
        finally { writeCpu(); }
      },
    },
  });
  exports = instance.exports as unknown as UnifiedExports;
  if (typeof exports.execute !== 'function' || typeof exports.set_register !== 'function'
      || typeof exports.get_register !== 'function' || typeof exports.get_flags !== 'function'
      || typeof exports.get_flags_known !== 'function' || typeof exports.set_flags !== 'function') throw new Error('Unified module exports missing');
  dispatcher = new GuestDispatcher(memory, [...bindings.map(binding => ({
    address: binding.address,
    abi: { convention: binding.convention, argumentBytes: binding.argumentBytes },
    frameContract: binding.frameContract,
    sourceSha256: UNDERCOVER_SHA,
    evidence: 'tools/uc_unified_registry.json binding 0x' + binding.address.toString(16),
    classification: 'verified' as const,
    execute: () => {
      writeCpu();
      try { exports.execute(binding.address); }
      finally { readCpu(); }
    },
  })), ...UNIFIED_REGISTRY.unavailable.map(entry => ({
    address: entry.address,
    abi: { convention: entry.convention, argumentBytes: entry.argumentBytes },
    sourceSha256: UNDERCOVER_SHA, evidence: entry.callsite + ': ' + entry.classification,
    classification: 'unavailable' as const,
  }))]);

  return {
    memory, cpu, dispatcher, instructions, writeLog, threads, registry: UNIFIED_REGISTRY,
    get lastInstruction() { return lastInstruction; },
    snapshot() { return { cpu: { ...cpu }, flagsKnown, lastInstruction }; },
    get writes() { return writes; },
    call(address: number, args: number[] = []) {
      cpu.esp = 0x0300f000;
      for (const argument of [...args].reverse()) {
        cpu.esp -= 4;
        memory.write32(cpu.esp, argument);
      }
      dispatcher.call(cpu, address, 0x00dec0de);
    },
    reset() {
      memory.reset();
      threads.reset();
      for (const name of registers) cpu[name] = 0;
      cpu.esp = 0x0300f000;
      cpu.eflags = 0;
      flagsKnown = 0;
      writeCpu();
      dispatcher.trace.length = 0;
      instructions.length = 0;
      writeLog.length = 0;
      writes = 0;
      lastInstruction = 0;
    },
  };
}

