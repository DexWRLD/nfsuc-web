import { GuestAddressSpace, GuestFault } from './uc-process';

export const THREAD_BASES = [0x03100000, 0x03101000] as const;
export const CHAIN_END = 0xffffffff;
/** Synthetic generic x86 thread infrastructure. No Undercover startup/TLS claim. */
export class GuestThreadFixtures {
  private initialized = new Set<number>();
  private active: number | undefined;
  private windowsContext: {processId:number;threadId:number;ownerToken:number}|null=null;
  readonly accesses: { operation: string; base: number; offset: number; value: number }[] = [];
  constructor(private readonly memory: GuestAddressSpace) {}
  initialize(index = 0) {
    if(this.windowsContext)throw new Error("Compatibility thread requires reset before another initialization");
    if (!Number.isInteger(index) || index < 0 || index >= THREAD_BASES.length) throw new Error('Invalid thread fixture');
    const base = THREAD_BASES[index];
    if (this.initialized.has(base)) throw new Error('Thread already initialized; reset required');
    this.memory.write32(base, CHAIN_END);
    this.initialized.add(base);
    this.active = base;
    return this.snapshot();
  }
  initializeWindowsCompatible(processId:number,threadId:number) {
    if(this.active!==undefined)throw new Error('Reset required before compatibility thread initialization');
    for(const id of [processId,threadId])if(!Number.isInteger(id)||id<1||id>0xffffffff)throw new Error('Invalid compatibility identity');
    this.initialize(0);
    const base=THREAD_BASES[0], stackBase=0x03010000;
    // NT_TIB32: +4 StackBase, +8 StackLimit, +0x18 Self. IDs remain host context.
    this.memory.write32(base+4,stackBase);this.memory.write32(base+8,0x03000000);this.memory.write32(base+0x18,base);
    this.windowsContext={processId,threadId,ownerToken:stackBase};
    return this.snapshot();
  }
  select(index: number) {
    if(this.windowsContext&&index!==0)throw new Error("Compatibility bootstrap supports one thread only");
    const base = THREAD_BASES[index];
    if (!this.initialized.has(base)) throw new Error('Uninitialized thread fixture');
    this.active = base;
    this.read(0);
  }
  private chain(head: number) {
    const seen = new Set<number>();
    const low = this.active === THREAD_BASES[1] ? 0x03010000 : 0x03000000;
    while (head !== CHAIN_END) {
      if (head % 4 || head < low || head > low + 0xfff8 || seen.has(head) || seen.size >= 64) {
        throw new GuestFault(head, 'FS', 'invalid exception-chain record');
      }
      seen.add(head);
      this.memory.assertExecutable(this.memory.read32(head + 4));
      head = this.memory.read32(head);
    }
  }
  private base(offset: number) {
    if (this.active === undefined || !this.initialized.has(this.active)) throw new GuestFault(0, 'FS', 'uninitialized guest thread');
    if (offset !== 0 && !(offset===0x18&&this.windowsContext&&this.active===THREAD_BASES[0])) throw new GuestFault(offset, 'FS', 'unsupported thread field');
    return this.active;
  }
  read(offset: number) {
    const base = this.base(offset), value = this.memory.read32(base+offset);
    if(offset===0)this.chain(value);
    this.accesses.push({ operation: 'read', base, offset, value });
    return value;
  }
  write(offset: number, value: number) {
    if(offset!==0)throw new GuestFault(offset,'FS','unsupported thread write');
    const base = this.base(offset);
    this.chain(this.memory.read32(base));
    this.chain(value);
    this.memory.write32(base, value);
    this.accesses.push({ operation: 'write', base, offset, value });
  }
  snapshot() {
    return { provenance: this.windowsContext?'HOST_WINDOWS_COMPATIBLE_NT_TIB32':'SYNTHETIC_GENERIC_X86_THREAD_FIXTURE',
      ...(this.windowsContext?{compatibilityContext:{...this.windowsContext}}:{}), fsBase: this.active ?? null,
      exceptionHead: this.active === undefined ? null : this.memory.read32(this.active),
      originalThreadInitialization: false, exceptionDispatchSupported: false };
  }
  reset() { this.windowsContext=null;this.initialized.clear(); this.active = undefined; this.accesses.length = 0; }
}
