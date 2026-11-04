import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as esbuild from 'esbuild';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const build = await esbuild.build({
  entryPoints: [path.join(root, 'src/host/uc-process.ts')],
  bundle: true, write: false, format: 'esm', platform: 'neutral',
});
const { GuestAddressSpace, GuestDispatcher, GuestFault, READ, WRITE, EXECUTE } =
  await import('data:text/javascript;base64,' + Buffer.from(build.outputFiles[0].text).toString('base64'));

function memory() {
  return new GuestAddressSpace([
    { name: 'code', address: 0x1000, size: 16, permissions: READ | EXECUTE },
    { name: 'data', address: 0x2000, size: 16, permissions: READ | WRITE, bytes: Uint8Array.of(1, 2, 3, 4) },
    { name: 'vtable-fixture', address: 0x3000, size: 4, permissions: READ, bytes: Uint8Array.of(0, 0x10, 0, 0) },
    { name: 'unavailable', address: 0x4000, size: 16, permissions: READ, unavailable: true },
    { name: 'stack', address: 0x5000, size: 64, permissions: READ | WRITE },
  ]);
}
const cpu = () => ({ eax: 0, ebx: 0, ecx: 0x2000, edx: 0, esi: 0, edi: 0, ebp: 0, esp: 0x5020, eip: 0, eflags: 0x202 });
const target = (execute, convention = 'cdecl') => ({
  address: 0x1000, abi: { convention, argumentBytes: 4 },
  sourceSha256: '0'.repeat(64), evidence: 'Synthetic platform contract fixture',
  classification: 'verified', execute,
});

test('one Wasm memory maps initialized bytes and zero-fill deterministically', () => {
  const guest = memory();
  assert.ok(guest.memory instanceof WebAssembly.Memory);
  assert.equal(guest.read32(0x2000), 0x04030201);
  assert.equal(guest.read32(0x2004), 0);
  guest.write32(0x2000, 7);
  guest.reset();
  assert.equal(guest.read32(0x2000), 0x04030201);
  assert.equal(guest.read32(0x5000), 0);
});

test('segment permissions, cross-boundary, unknown and wrapped addresses fail', () => {
  const guest = memory();
  for (const address of [0x4000, 0x200e, 0xffff_fffe, -1, 1.5]) {
    assert.throws(() => guest.read32(address), GuestFault);
  }
  assert.throws(() => guest.write32(0x3000, 1), GuestFault);
  assert.throws(() => guest.assertExecutable(0x2000), GuestFault);
});

test('invalid image layouts and relocation are rejected', () => {
  const segment = { name: 'x', address: 0x1000, size: 4, permissions: READ };
  assert.throws(() => new GuestAddressSpace([segment, segment]), /Invalid guest mapping/);
  assert.throws(() => new GuestAddressSpace([{ ...segment, size: 2, bytes: new Uint8Array(3) }]), /Invalid/);
  assert.throws(() => new GuestAddressSpace([], 0x500000), /relocation/);
});

for (const convention of ['cdecl', 'stdcall', 'thiscall']) {
  test('synthetic dispatch preserves ' + convention + ' return contract', () => {
    const guest = memory(), state = cpu();
    const dispatch = new GuestDispatcher(guest, [target((c, m) => {
      c.eax = c.ecx;
      c.eip = m.read32(c.esp);
      c.esp += 4 + (convention === 'cdecl' ? 0 : 4);
    }, convention)]);
    dispatch.call(state, 0x1000, 0x1004);
    assert.equal(state.eax, 0x2000);
    assert.equal(state.esp, convention === 'cdecl' ? 0x5020 : 0x5024);
    assert.deepEqual(dispatch.trace.map(event => event.kind), ['enter', 'return']);
  });
}

test('unknown functions, candidates and imports trap before mutating the stack', () => {
  for (const classification of ['candidate', 'unavailable', 'import']) {
    const guest = memory(), state = cpu();
    const dispatch = new GuestDispatcher(guest, [{ ...target(undefined), classification }]);
    assert.throws(() => dispatch.call(state, 0x1000, 0x1004), GuestFault);
    assert.equal(state.esp, 0x5020);
    assert.equal(guest.read32(0x501c), 0);
    assert.throws(() => dispatch.call(state, 0x1008, 0x1004), GuestFault);
  }
});

test('vtable resolution reads a checked slot, without admitting its target', () => {
  const guest = memory();
  guest.write32(0x2000, 0x3000);
  const dispatch = new GuestDispatcher(guest, []);
  assert.equal(dispatch.resolveVtable(0x2000, 0), 0x1000);
  assert.throws(() => dispatch.resolveVtable(0x2000, 4), GuestFault);
  assert.throws(() => dispatch.resolveVtable(0x2000, -4), GuestFault);
});

test('bad ABI or provenance is rejected and a bad runtime return records a fault', () => {
  const guest = memory();
  assert.throws(() => new GuestDispatcher(guest, [{ ...target(undefined), evidence: '' }]), /Invalid/);
  assert.throws(() => new GuestDispatcher(guest, [{ ...target(undefined), abi: { convention: 'unknown', argumentBytes: 0 } }]), /Invalid/);
  const dispatch = new GuestDispatcher(guest, [target(() => {})]);
  assert.throws(() => dispatch.call(cpu(), 0x1000, 0x1004), /ABI mismatch/);
  assert.equal(dispatch.trace.at(-1).kind, 'fault');
});


test('recorded original CmdUtil vtable cell maps at its original VA', async () => {
  const { readFile } = await import('node:fs/promises');
  const recorded = JSON.parse(await readFile(path.join(root, '../analysis/undercover/static-vtable-evidence.json'), 'utf8'));
  assert.equal(recorded.address, '0x00BBB2BC');
  const guest = new GuestAddressSpace([{
    name: 'verified PE static cell', address: 0x00bbb2bc, size: 4, permissions: READ,
    bytes: Uint8Array.from(Buffer.from(recorded.bytes, 'hex')),
  }]);
  assert.equal(guest.read32(0x00bbb2bc), 0x0080d090);
  assert.throws(() => guest.write32(0x00bbb2bc, 0), GuestFault);
});
