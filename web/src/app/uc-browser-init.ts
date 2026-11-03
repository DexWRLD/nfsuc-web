interface InitializerExports {
  run_init(): number;
  run_boot_callback(mode: number): number;
  boot_flag_value(mode: number): number;
  run_queue(mode: number): number;
  queue_word(address: number): number;
  queue_stop(): number;
  queue_value(): number;
  prefix_fault(): number;
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

const queueCases = [
  'Append to empty vector', 'Append after existing entry', 'Full vector',
  'Processing disabled', 'Empty scan', 'No pending entry', 'Pending entry',
  'Null entry', 'Unmapped entry',
];

export async function runFrontendQueue() {
  const results: string[] = [];
  for (const [mode, label] of queueCases.entries()) {
    const guest = await loadInitializer();
    const boundary = mode === 2 ? 0x005d6b20 : mode === 6 ? 0x0055feb0 : 0;
    const fault = mode === 7 ? 4 : mode === 8 ? 0xdead0004 : 0;
    let trapped = false;
    try {
      if (guest.run_queue(mode) !== 0x00dec0de) throw new Error('Wrong guest return');
    } catch (error) {
      if (!(error instanceof WebAssembly.RuntimeError) || !(boundary || fault)) throw error;
      trapped = true;
    }
    const word = (address: number) => guest.queue_word(address) >>> 0;
    const begin = word(0x0300ed10);
    const end = word(0x0300ed14);
    const entry = 0x0300ed60;
    const expectedEnd = mode === 1 ? 0x0300ed50 : mode === 4 ? 0x0300ed48 : 0x0300ed4c;
    const first = mode === 7 ? 0 : mode === 8 ? 0xdead0000 : entry;
    if (trapped !== Boolean(boundary || fault) || guest.queue_stop() !== boundary
        || (guest.prefix_fault() >>> 0) !== fault || begin !== 0x0300ed48 || end !== expectedEnd
        || word(begin) !== first || word(begin + 4) !== (mode === 1 ? entry : 0xaabbccdd)
        || word(begin - 4) !== 0x11223344 || word(begin + 8) !== 0x55667788
        || word(entry + 4) !== (mode === 5 ? 2 : 1) || word(entry + 12) !== 7
        || guest.queue_value() !== (mode === 6 ? 900 : 0)) {
      throw new Error('Unexpected queue trace: ' + label);
    }
    const hex = (value: number) => '0x' + value.toString(16).toUpperCase().padStart(8, '0');
    const outcome = boundary ? 'blocked at ' + hex(boundary) : fault ? 'rejected read ' + hex(fault) : 'returned with stack restored';
    results.push(label + ' · ' + (mode < 3 ? '0x0080F4F0' : '0x008091E0') + ' · '
      + hex(begin) + '–' + hex(end) + ' · ' + (end - begin) / 4 + ' entries · ' + outcome
      + (mode === 6 ? ' · entry ' + hex(entry) + ', state 1, selected index 7, fixture numeric field 900' : ''));
  }
  return results;
}

export async function runBootCallbacks() {
  const guest = await loadInitializer();
  for (const mode of [0, 1]) {
    if (guest.boot_flag_value(mode) !== 0) throw new Error('Unexpected initial callback flag');
    for (let run = 0; run < 2; run++) {
      if (guest.run_boot_callback(mode) !== 0x13572468 || guest.boot_flag_value(mode) !== 1
          || guest.boot_flag_value(1 - mode) !== mode) {
        throw new Error('Unexpected callback state or return value');
      }
    }
  }
  const invalid = await loadInitializer();
  for (const [mode, address] of [[2, 0x6c], [3, 0xdead006c]]) {
    let trapped = false;
    try {
      invalid.run_boot_callback(mode);
    } catch (error) {
      if (!(error instanceof WebAssembly.RuntimeError)) throw error;
      trapped = true;
    }
    if (!trapped || (invalid.prefix_fault() >>> 0) !== address || invalid.boot_flag_value(1) !== 0) {
      throw new Error('Unexpected invalid manager behavior');
    }
  }
  return [
    'BootLoadScreenLoaded 0x008062A0: [0x01873177] 0 → 1; repeat remains 1.',
    'MainScreenLoaded 0x00806290: fixture manager +0x6C 0 → 1 at 0x00806295; repeat remains 1.',
    'Both tail paths reached 0x009ADC50 and returned fixture EAX 0x13572468 at 0x009ADC59.',
    'Two caller-cleaned arguments preserved. Null and unmapped manager writes rejected.',
    'Fixture entry only. Original CmdUtil registration and Apt dispatch remain unverified.',
  ];
}
