import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import * as esbuild from 'esbuild';
const web=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
async function load(name){const result=await esbuild.build({entryPoints:[path.join(web,name)],bundle:true,format:'esm',platform:'neutral',write:false});return import('data:text/javascript;base64,'+Buffer.from(result.outputFiles[0].text).toString('base64'));}
const {CRT_IMPORT_EVIDENCE}=await load('src/host/uc-crt-imports.ts');
const {describeCrtState}=await load('src/host/uc-crt-state.ts');
const {createUndercoverProcess}=await load('src/host/uc-unified.ts');
const root=process.env.UC_AUTHENTIC_ASSET_ROOT;
test('generated active-import identities retain their nonbinding classification',async()=>{
  const report=JSON.parse(await fs.readFile(path.join(web,'../analysis/undercover/crt-provider-binding-phase70.json'),'utf8'));
  assert.deepEqual(CRT_IMPORT_EVIDENCE.providers,report.providers);
  assert.equal(CRT_IMPORT_EVIDENCE.runtimeBindingVerified,false);
  assert.equal(CRT_IMPORT_EVIDENCE.activeImportsExecutableInBrowser,false);
  for(const row of report.providers){assert.equal(row.adapterImplemented,false);assert.equal(row.runtimeBindingVerified,false);assert.equal(row.loaderResolvedExternalService,null);}
});
test('original legacy cells, sentinel state and exact blocked registrar remain unchanged',{skip:!root},async()=>{
  const description=JSON.parse(await fs.readFile(path.join(root,'uc-unified-image.json'),'utf8'));
  const g=await createUndercoverProcess(description,new Uint8Array(await fs.readFile(path.join(root,'uc-unified-image.bin'))),new Uint8Array(await fs.readFile(path.join(root,'uc-unified.wasm'))));
  for(let repeat=0;repeat<2;repeat++){
    const before=describeCrtState(g.memory);g.threads.initialize();
    assert.throws(()=>g.call(0xb57dc0),/0x8aac6a: unavailable/);
    assert.equal(g.lastInstruction,0x87b5b3);
    const after=describeCrtState(g.memory);assert.deepEqual(after,before);
    assert.equal(g.dispatcher.trace.filter(e=>e.kind==='return').length,9);
    assert.equal(after.cleanupGlobals.originalSentinelInitializerExecuted,false);
    for(const row of after.providers){
      assert.throws(()=>g.memory.write32(row.legacyCell,0x22ce05f),/permission denied/);
      assert.throws(()=>g.memory.read32(row.activeImportCell),/unavailable/);
      assert.throws(()=>g.dispatcher.callFromGuest(g.cpu,row.activeImportCell),/unknown function or import/);
    }
    assert.equal(g.memory.read32(0x18b1e68),0);assert.equal(g.memory.read32(0x18b1e6c),0);
    g.reset();assert.deepEqual(describeCrtState(g.memory),before);assert.equal(g.threads.snapshot().fsBase,null);
  }
});
