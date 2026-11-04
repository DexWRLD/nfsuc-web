import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as esbuild from 'esbuild';

const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const js = (await esbuild.build({ entryPoints: [path.join(web, 'src/host/uc-unified.ts')],
  bundle: true, format: 'esm', platform: 'neutral', write: false })).outputFiles[0].text;
const { createUndercoverProcess } = await import('data:text/javascript;base64,' + Buffer.from(js).toString('base64'));

test('original static initializer supplies the receiver and completes its constructor chain', {
  skip: !process.env.UC_AUTHENTIC_ASSET_ROOT,
}, async () => {
  const root = process.env.UC_AUTHENTIC_ASSET_ROOT;
  const description = JSON.parse(await fs.readFile(path.join(root, 'uc-unified-image.json'), 'utf8'));
  const payload = new Uint8Array(await fs.readFile(path.join(root, 'uc-unified-image.bin')));
  const code = new Uint8Array(await fs.readFile(path.join(root, 'uc-unified.wasm')));
  const guest = await createUndercoverProcess(description, payload, code);
  for (let attempt = 0; attempt < 2; attempt++) {
    assert.equal(guest.memory.read32(0x00b6370c), 0x00b57dc0);
    const gap = guest.memory.read32(0x0189d0dc);
    assert.equal(guest.memory.read32(0x0189d0f8), 0);
    // No host writes a receiver, object, factory, capacity or backing pointer.
    assert.throws(() => guest.call(0x00b57dc0), /dispatch at 0x87b640: unavailable/);
    assert.equal(guest.lastInstruction, 0x00b57dd2);
    assert.equal(guest.cpu.eip, 0x00b57dd2);
    assert.equal(guest.cpu.eax, 0x0189d0a0);
    assert.equal(guest.cpu.esp, 0x0300eff0);
    assert.equal(guest.memory.read32(guest.cpu.esp), 0x00b57dd7);
    assert.equal(guest.memory.read32(guest.cpu.esp + 4), 0x00b602e0);
    const entering = guest.dispatcher.trace.filter(event => event.kind === 'enter');
    assert.deepEqual(entering.map(event => event.address), [
      0x00b57dc0, 0x009e7540,
      0x009e75a0, 0x009e75a0, 0x009e75a0, 0x009e75a0, 0x009e75a0, 0x009e75a0,
      0x009c1830,
    ]);
    assert.equal(entering[1].callsite, 0x00b57dc8);
    assert.equal(entering[1].returnAddress, 0x00b57dcd);
    assert.deepEqual(entering.slice(2).map(event => event.callsite),
      [0x009e754a, 0x009e7555, 0x009e7560, 0x009e756b, 0x009e7576, 0x009e7581, 0x009e758c]);
    assert.equal(guest.dispatcher.trace.filter(event => event.kind === 'return').length, 8);
    assert.ok(guest.dispatcher.trace.some(event => event.address === 0x009e7540 && event.kind === 'return'));
    const globals = guest.writeLog.filter(write => write.address >= 0x00400000 && write.address < 0x03000000);
    assert.equal(globals.length, 27);
    assert.equal(globals.filter(write => write.size === 1).length, 1);
    for (const offset of [0, 0xc, 0x18, 0x24, 0x30, 0x40]) {
      for (const field of [0, 4, 8]) assert.equal(guest.memory.read32(0x0189d0a0 + offset + field), 0);
    }
    assert.equal(guest.memory.read32(0x0189d0f8), 0x32000);
    assert.equal(guest.memory.read32(0x0189d0fc), 0x186a0);
    assert.equal(guest.memory.read8(0x0189d10c), 0);
    assert.equal(guest.memory.read32(0x0189d0dc), gap);
    assert.equal(guest.memory.read32(0x0189d1a4), 0);
    if (process.env.UC_UNIFIED_EVIDENCE && attempt === 0) {
      await fs.writeFile(process.env.UC_UNIFIED_EVIDENCE, JSON.stringify({
        sourceSha256: description.sourceSha256, moduleSha256: description.moduleSha256,
        root: '0x00B57DC0', receiverSource: 'Original MOV ECX,0x0189D0A0 at 0x00B57DC3',
        trace: guest.dispatcher.trace, globalWrites: globals, registers: guest.cpu,
        blockedCallsite: '0x00B57DD2', unavailableTarget: '0x0087B640',
        cleanupArgument: '0x00B602E0', originalStartupReachability: 'UNVERIFIED',
      }, null, 2) + '\n');
    }
    guest.reset();
    assert.equal(guest.writeLog.length, 0);
    assert.equal(guest.memory.read32(0x0189d0f8), 0);
  }
});



test('generated unified registry stays consistent with its reviewed source', async () => {
  const document = JSON.parse(await fs.readFile(path.join(web, '../tools/uc_unified_registry.json'), 'utf8'));
  const built = await esbuild.build({ entryPoints: [path.join(web, 'src/host/uc-unified-registry.ts')],
    bundle: true, format: 'esm', write: false, platform: 'neutral' });
  const generated = await import('data:text/javascript;base64,' + Buffer.from(built.outputFiles[0].text).toString('base64'));
  assert.deepEqual(generated.UNIFIED_REGISTRY, document);
  assert.equal(new Set(document.bindings.map(binding => binding.address)).size, document.bindings.length);
  assert.equal(document.bindings.length, 9);
  for (const binding of document.bindings) {
    assert.equal(binding.sourceSha256, document.sourceSha256);
    assert.ok(binding.recoveryConfidence);
    assert.ok(binding.returnBehavior);
  }
  assert.deepEqual(document.unavailable.map(entry => [entry.address, entry.callable]), [[0x0087b640, false]]);
});
