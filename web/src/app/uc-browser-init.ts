interface InitializerExports {
  run_init(): number;
  frontend_lookup(length: number): number;
  frontend_stop(): number;
  frontend_native_id(): number;
  run_apt_constructor(): number;
  run_apt_fixture(): number;
  read_slot(address: number): number;
  write_count(): number;
  guest_esp(): number;
  guest_eax(): number;
  run_prefix(): number;
  prefix_fault(): number;
  prefix_read_base(): number;
  prefix_read_delta(): number;
  prefix_entry(index: number): number;
}

async function loadInitializer() {
  const response = await fetch('/uc-init-009e8ad0.wasm');
  if (!response.ok) throw new Error('Local initializer module unavailable (HTTP ' + response.status + ')');
  const module = await WebAssembly.compile(await response.arrayBuffer());
  if (WebAssembly.Module.imports(module).length) throw new Error('Unsupported initializer imports');
  const instance = await WebAssembly.instantiate(module);
  return instance.exports as unknown as InitializerExports;
}

export async function runAptDiagnostic(mode: 'constructor' | 'fixture') {
  const guest = await loadInitializer();
  if (mode === 'constructor') {
    if (guest.run_apt_constructor() !== 6) throw new Error('Unexpected Apt constructor trace');
    return 'Original 0x009E7540 → 0x009E75A0 ×6. Verified 18 zeroed header words. Stopped before 0x009E758C.';
  }
  if (guest.run_apt_fixture() !== 0x0300ee04) throw new Error('Unexpected Apt fixture result');
  return 'Synthetic storage: push 0x009E47D0 stored 0x0300EE04 and incremented count. Depth-zero read 0x009B6290 → 0x009E4B10 returned the same value. Both calls restored ESP.';
}

export async function runUndercoverInitializer() {
  const guest = await loadInitializer();
  const slot = 0x0189d1a4;
  const before = guest.read_slot(slot);
  const eip = guest.run_init();
  const result = {
    entry: 0x009e8ad0, slot, before, after: guest.read_slot(slot),
    writes: guest.write_count(), eip, esp: guest.guest_esp(), eax: guest.guest_eax(),
  };
  if (result.before !== 0 || result.after !== 0x009e78c0 || result.writes !== 49
      || result.eip !== 0x00dec0de || result.esp !== 0x0300f000 || result.eax !== 0) {
    throw new Error('Unexpected translated initializer state');
  }
  try {
    guest.run_prefix();
  } catch (error) {
    if (!(error instanceof WebAssembly.RuntimeError) || guest.prefix_fault() >>> 0 !== 0xfffffffc) throw error;
    const entered = Array.from({ length: 5 }, (_, index) => guest.prefix_entry(index));
    const expected = [0x0099dcd0, 0x009e78c0, 0x009b6290, 0x009e4b10, 0x009e78c0];
    if (entered.some((address, index) => address !== expected[index]) || guest.prefix_entry(5)) {
      throw new Error('Unexpected startup prefix trace');
    }
    const backingPointer = guest.prefix_read_base() >>> 0;
    const countMinusIndex = guest.prefix_read_delta() | 0;
    if (backingPointer !== 0 || countMinusIndex !== 0) throw new Error('Unexpected fault operands');
    return { ...result, prefix: { entered, backingPointer, countMinusIndex, faultAddress: guest.prefix_fault() >>> 0 } };
  }
  throw new Error('Startup prefix returned unexpectedly');
}

export async function runFrontendLookup() {
  const guest = await loadInitializer();
  for (const length of [1, 21]) {
    if (guest.frontend_lookup(length) || guest.frontend_stop()) throw new Error('Unexpected lookup length result');
  }
  const index = guest.frontend_lookup(13);
  const nativeId = guest.frontend_native_id();
  const stop = guest.frontend_stop();
  if (index !== 118 || nativeId !== 0x7f || stop !== 0x00998241) {
    throw new Error('Unexpected original frontend lookup trace');
  }
  return { index, nativeId, stop };
}
