// Mirrors uc_image.h permission bits and original guest virtual addresses.
export const READ = 1, WRITE = 2, EXECUTE = 4;
const ADDRESS_LIMIT = 0x1_0000_0000;

export interface GuestSegment {
  name: string;
  address: number;
  size: number;
  permissions: number;
  bytes?: Uint8Array;
  unavailable?: boolean;
}

export class GuestFault extends Error {
  constructor(public readonly address: number, public readonly operation: string, reason: string) {
    super(operation + ' at 0x' + address.toString(16) + ': ' + reason);
  }
}

function validRange(address: number, size: number): boolean {
  return Number.isSafeInteger(address) && Number.isSafeInteger(size)
    && address >= 0 && size > 0 && address < ADDRESS_LIMIT && size <= ADDRESS_LIMIT - address;
}

/** One memory per process. Addresses stay at PE32 VAs. Relocation is unsupported. */
export class GuestAddressSpace {
  readonly memory: WebAssembly.Memory;
  private readonly segments: GuestSegment[];

  constructor(segments: GuestSegment[], imageBase = 0x00400000) {
    if (imageBase !== 0x00400000) throw new Error('Unsupported image relocation');
    this.segments = segments.map(segment => ({ ...segment, bytes: segment.bytes?.slice() }))
      .sort((a, b) => a.address - b.address);
    let end = 0;
    for (const segment of this.segments) {
      if (!validRange(segment.address, segment.size) || segment.address < end
          || !Number.isInteger(segment.permissions) || segment.permissions < 0 || segment.permissions > 7
          || (segment.bytes?.length ?? 0) > segment.size
          || segment.unavailable && segment.bytes?.length) {
        throw new Error('Invalid guest mapping: ' + segment.name);
      }
      end = segment.address + segment.size;
    }
    // Limit initial process size explicitly. Huge malformed PE mappings fail before allocation.
    if (end > 0x10000000) throw new Error('Guest image exceeds configured 256 MiB limit');
    const pages = Math.max(1, Math.ceil(end / 65536));
    this.memory = new WebAssembly.Memory({ initial: pages, maximum: pages });
    this.reset();
  }

  private check(address: number, size: number, permission: number, operation: string) {
    if (!validRange(address, size)) throw new GuestFault(address, operation, 'invalid range');
    const segment = this.segments.find(candidate =>
      address >= candidate.address && address + size <= candidate.address + candidate.size);
    if (!segment || segment.unavailable || !(segment.permissions & permission)) {
      throw new GuestFault(address, operation, 'unmapped, unavailable or permission denied');
    }
  }

  read8(address: number): number {
    this.check(address, 1, READ, 'read');
    return new DataView(this.memory.buffer).getUint8(address);
  }

  write8(address: number, value: number) {
    this.check(address, 1, WRITE, 'write');
    new DataView(this.memory.buffer).setUint8(address, value & 0xff);
  }

  read32(address: number): number {
    this.check(address, 4, READ, 'read');
    return new DataView(this.memory.buffer).getUint32(address, true);
  }

  write32(address: number, value: number) {
    this.check(address, 4, WRITE, 'write');
    new DataView(this.memory.buffer).setUint32(address, value >>> 0, true);
  }

  assertExecutable(address: number) { this.check(address, 1, EXECUTE, 'execute'); }

  reset() {
    const memory = new Uint8Array(this.memory.buffer);
    memory.fill(0);
    for (const segment of this.segments) {
      if (!segment.unavailable && segment.bytes) memory.set(segment.bytes, segment.address);
    }
  }
}

export interface GuestCpu {
  eax: number; ebx: number; ecx: number; edx: number; esi: number; edi: number;
  ebp: number; esp: number; eip: number; eflags: number;
}
export type GuestAbi = { convention: 'cdecl' | 'stdcall' | 'thiscall'; argumentBytes: number };
export interface DispatchTarget {
  address: number;
  abi: GuestAbi;
  sourceSha256: string;
  evidence: string;
  classification: 'candidate' | 'verified' | 'unavailable' | 'import';
  execute?: (cpu: GuestCpu, memory: GuestAddressSpace) => void;
}

/** Dispatch admits explicit verified bindings, never the whole pseudocode index. */
export class GuestDispatcher {
  private readonly targets = new Map<number, DispatchTarget>();
  readonly trace: { kind: string; address: number; esp: number; callsite?: number; returnAddress?: number }[] = [];
  constructor(private readonly memory: GuestAddressSpace, targets: DispatchTarget[]) {
    for (const target of targets) {
      if (!validRange(target.address, 1) || this.targets.has(target.address)
          || !/^[0-9a-f]{64}$/.test(target.sourceSha256) || !target.evidence.trim()
          || !['cdecl', 'stdcall', 'thiscall'].includes(target.abi.convention)
          || !Number.isInteger(target.abi.argumentBytes) || target.abi.argumentBytes < 0
          || target.abi.argumentBytes % 4 !== 0
          || target.execute && target.classification !== 'verified') {
        throw new Error('Invalid dispatch mapping');
      }
      this.targets.set(target.address, { ...target, abi: { ...target.abi } });
    }
  }

  call(cpu: GuestCpu, address: number, returnAddress: number) {
    const target = this.targets.get(address);
    if (!target || target.classification !== 'verified' || !target.execute) {
      throw new GuestFault(address, 'dispatch', target?.classification ?? 'unknown function or import');
    }
    this.memory.assertExecutable(address);
    if (!validRange(returnAddress, 1) || !Number.isInteger(cpu.esp) || cpu.esp < 4 || cpu.esp % 4) {
      throw new GuestFault(cpu.esp, 'call', 'invalid stack or return address');
    }
    const expectedEsp = cpu.esp + (target.abi.convention === 'cdecl' ? 0 : target.abi.argumentBytes);
    this.memory.write32(cpu.esp - 4, returnAddress);
    cpu.esp -= 4;
    cpu.eip = address;
    this.trace.push({ kind: 'enter', address, esp: cpu.esp });
    try {
      target.execute(cpu, this.memory);
      if (cpu.eip !== returnAddress || cpu.esp !== expectedEsp) {
        throw new GuestFault(address, 'return', 'ABI mismatch');
      }
      this.trace.push({ kind: 'return', address, esp: cpu.esp });
    } catch (error) {
      this.trace.push({ kind: 'fault', address, esp: cpu.esp });
      throw error;
    }
  }

  /** A lifted CALL already pushed its original return address. */
  callFromGuest(cpu: GuestCpu, address: number) {
    const target = this.targets.get(address);
    if (!target || target.classification !== 'verified' || !target.execute) {
      throw new GuestFault(address, 'dispatch', target?.classification ?? 'unknown function or import');
    }
    this.memory.assertExecutable(address);
    if (!Number.isInteger(cpu.esp) || cpu.esp % 4) throw new GuestFault(cpu.esp, 'call', 'unaligned stack');
    const returnAddress = this.memory.read32(cpu.esp);
    const expectedEsp = cpu.esp + 4 + (target.abi.convention === 'cdecl' ? 0 : target.abi.argumentBytes);
    this.trace.push({ kind: 'enter', address, esp: cpu.esp, callsite: cpu.eip, returnAddress });
    try {
      target.execute(cpu, this.memory);
      if (cpu.eip !== returnAddress || cpu.esp !== expectedEsp) {
        throw new GuestFault(address, 'return', 'ABI mismatch');
      }
      this.trace.push({ kind: 'return', address, esp: cpu.esp });
    } catch (error) {
      this.trace.push({ kind: 'fault', address, esp: cpu.esp });
      throw error;
    }
  }

  resolveVtable(object: number, slotOffset: number): number {
    if (!Number.isInteger(slotOffset) || slotOffset < 0 || slotOffset % 4) {
      throw new GuestFault(object, 'vtable', 'invalid slot');
    }
    const table = this.memory.read32(object);
    return this.memory.read32(table + slotOffset);
  }
}

