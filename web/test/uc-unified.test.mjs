import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as esbuild from 'esbuild';
const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const js = (await esbuild.build({
  entryPoints: [path.join(web, 'src/host/uc-unified.ts')],
  bundle: true, format: 'esm', platform: 'neutral', write: false,
})).outputFiles[0].text;
const { createUndercoverProcess } = await import('data:text/javascript;base64,' + Buffer.from(js).toString('base64'));
const root = process.env.UC_AUTHENTIC_ASSET_ROOT;
test('real translated producer and connected consumer use one authenticated guest image', { skip: !root }, async () => {
  const descriptor = JSON.parse(await fs.readFile(path.join(root, 'uc-unified-image.json'), 'utf8'));
  const payload = new Uint8Array(await fs.readFile(path.join(root, 'uc-unified-image.bin')));
  const wasm = new Uint8Array(await fs.readFile(path.join(root, 'uc-unified.wasm')));
  const process = await createUndercoverProcess(descriptor, payload, wasm);
  for (let run = 0; run < 2; run++) {
    assert.equal(process.memory.read32(0x0189d1a4), 0);
    for (const segment of descriptor.segments) {
      if (segment.unavailable) {
        assert.throws(() => process.memory.read32(segment.address), /unavailable/);
      } else if (segment.permissions & 1) {
        if (segment.length >= 4) assert.equal(process.memory.read32(segment.address),
          new DataView(payload.buffer, payload.byteOffset).getUint32(segment.offset, true));
        if (segment.size - segment.length >= 4) assert.equal(process.memory.read32(segment.address + segment.size - 4), 0);
      }
    }
    assert.equal(process.memory.read32(0x00bbb2bc), 0x0080d090);
    assert.throws(() => process.memory.write32(0x00bbb2bc, 0), /permission denied/);
    process.call(0x009e8ad0);
    assert.equal(process.memory.read32(0x0189d1a4), 0x009e78c0);
    assert.equal(process.cpu.eip, 0x00dec0de);
    assert.equal(process.cpu.esp, 0x0300f000);
    assert.equal(process.writes, 49);
    process.dispatcher.trace.length = 0;
    assert.throws(() => process.call(0x0099dcd0, [0, 2]), /read at 0xfffffffc/);
    assert.equal(process.lastInstruction, 0x009e4b49);
    assert.equal(process.cpu.edx, 0);
    assert.equal(process.cpu.eax, 0);
    assert.deepEqual(process.dispatcher.trace.filter(event => event.kind === 'enter').map(event => event.address),
      [0x0099dcd0, 0x009e78c0, 0x009b6290, 0x009e4b10, 0x009e78c0]);
    assert.equal(process.memory.read32(0x0189d1a4), 0x009e78c0);
    if (globalThis.process.env.UC_UNIFIED_EVIDENCE && run === 0) {
      await fs.writeFile(globalThis.process.env.UC_UNIFIED_EVIDENCE, JSON.stringify({
        sourceSha256: descriptor.sourceSha256, moduleSha256: descriptor.moduleSha256,
        memoryBytes: process.memory.memory.buffer.byteLength,
        initializationWrites: 49, callbackSlot: '0x0189D1A4', callbackTarget: '0x009E78C0',
        provenance: 'Original ordinary PE sections; host orders registration and root with historical fixture arguments',
        trace: process.dispatcher.trace, faultInstruction: process.lastInstruction, registers: process.cpu,
        startupOrderVerified: false,
      }, null, 2) + '\n');
    }
    process.reset();
  }
  assert.throws(() => process.call(0x0099dcd0, [0, 2]), /dispatch at 0x0/);
  process.reset();
  await assert.rejects(createUndercoverProcess({ ...descriptor, imageBase: 0x500000 }, payload, wasm), /Invalid authenticated/);
  const changedCode = wasm.slice(); changedCode[changedCode.length - 1] ^= 1;
  await assert.rejects(createUndercoverProcess(descriptor, payload, changedCode), /Invalid authenticated/);
  const changed = payload.slice(); changed[0] ^= 1;
  await assert.rejects(createUndercoverProcess(descriptor, changed, wasm), /Invalid authenticated/);
});

