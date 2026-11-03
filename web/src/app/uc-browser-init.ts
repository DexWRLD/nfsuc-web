interface InitializerExports {
  run_init(): number;
  read_slot(address: number): number;
  write_count(): number;
  guest_esp(): number;
  guest_eax(): number;
  run_prefix(): number;
  prefix_fault(): number;
  prefix_entry(index: number): number;
}

export async function runUndercoverInitializer() {
  const response = await fetch('/uc-init-009e8ad0.wasm');
  if (!response.ok) throw new Error('Local initializer module unavailable (HTTP ' + response.status + ')');
  const module = await WebAssembly.compile(await response.arrayBuffer());
  if (WebAssembly.Module.imports(module).length) throw new Error('Unsupported initializer imports');
  const instance = await WebAssembly.instantiate(module);
  const guest = instance.exports as unknown as InitializerExports;
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
    return { ...result, prefix: { entered, faultAddress: guest.prefix_fault() >>> 0 } };
  }
  throw new Error('Startup prefix returned unexpectedly');
}
