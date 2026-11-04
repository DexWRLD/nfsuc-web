import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as esbuild from 'esbuild';
const web=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const built=await esbuild.build({entryPoints:[path.join(web,'src/host/uc-unified.ts')],bundle:true,format:'esm',platform:'neutral',write:false});
const {createUndercoverProcess}=await import('data:text/javascript;base64,'+Buffer.from(built.outputFiles[0].text).toString('base64'));
const root=process.env.UC_AUTHENTIC_ASSET_ROOT;
async function create(){return createUndercoverProcess(JSON.parse(await fs.readFile(path.join(root,'uc-unified-image.json'),'utf8')),new Uint8Array(await fs.readFile(path.join(root,'uc-unified-image.bin'))),new Uint8Array(await fs.readFile(path.join(root,'uc-unified.wasm'))));}
function startFrame(g,S){
  // Synthetic registrar call frame, not Undercover initialization or a provider.
  const saved={ebp:g.cpu.ebp,ebx:g.cpu.ebx,esi:g.cpu.esi,edi:g.cpu.edi};
  g.memory.write32(S,0xdec0de);g.memory.write32(S+4,0xb602e0);
  g.memory.write32(S-4,0x14);g.memory.write32(S-8,0xca9380);
  g.cpu.esp=S-8;
  g.dispatcher.call(g.cpu,0x87beb8,0x87b5a7);
  assert.equal(g.cpu.ebp,S-4);assert.equal(g.cpu.esp,S-56);
  const b=g.cpu.ebp,cookie=g.memory.read32(0x1285688);
  for(const [offset,value] of [[8,0xb602e0],[4,0xdec0de],[0,saved.ebp],[-4,0xfffffffe],[-8,(0xca9380^cookie)>>>0],[-12,0x87bf11],[-24,b-52],[-40,saved.ebx],[-44,saved.esi],[-48,saved.edi],[-52,(cookie^b)>>>0]]) assert.equal(g.memory.read32(b+offset),value);
  assert.equal(g.threads.read(0),b-16);
  return saved;
}
function finishFrame(g,saved){
  const b=g.cpu.ebp;g.cpu.eax=0x13572468;
  g.dispatcher.call(g.cpu,0x87befd,0x87b636);
  assert.equal(g.cpu.esp,b+4);assert.equal(g.cpu.eip,0x87b636);assert.equal(g.cpu.eax,0x13572468);
  for(const [name,value]of Object.entries(saved))assert.equal(g.cpu[name],value);
}
test('original SEH prolog/epilog layout, nested frames, EAX and register restoration',{skip:!root},async()=>{
  const g=await create();g.threads.initialize();Object.assign(g.cpu,{ebp:0x11111111,ebx:0x22222222,esi:0x33333333,edi:0x44444444});
  const outer=startFrame(g,0x300ef00),head=g.threads.read(0);
  const nested=startFrame(g,g.cpu.esp-4);
  assert.equal(g.memory.read32(g.cpu.ebp-16),head);
  finishFrame(g,nested);assert.equal(g.threads.read(0),head);
  // Synthetic caller removes its nested frame/argument, restoring original baseline.
  g.cpu.esp=g.cpu.ebp-52;
  finishFrame(g,outer);assert.equal(g.threads.read(0),0xffffffff);
  assert.ok(g.instructions.includes(0x87bf00));assert.ok(g.instructions.includes(0x87bf10));
});
test('thread FS isolation, invalid state, unsupported fields and exception dispatch',{skip:!root},async()=>{
  const g=await create();assert.throws(()=>g.threads.read(0),/uninitialized/);
  assert.throws(()=>g.call(0x87befd),/unbalanced SEH frame/);
  assert.throws(()=>g.call(0x87beb8,[0,0x14]),/unsupported SEH frame inputs/);
  g.reset();
  assert.throws(()=>g.threads.select(0),/Uninitialized/);
  assert.throws(()=>g.threads.initialize(2),/Invalid/);
  g.threads.initialize(0);const saved=startFrame(g,0x300ef00),first=g.threads.read(0);
  g.threads.initialize(1);assert.equal(g.threads.read(0),0xffffffff);g.threads.select(0);assert.equal(g.threads.read(0),first);
  g.threads.select(1);assert.throws(()=>g.threads.write(0,first),/invalid exception-chain/);g.threads.select(0);
  assert.throws(()=>g.threads.write(0,0),/invalid exception-chain/);
  assert.throws(()=>g.threads.read(0x2c),/unsupported thread field/);
  g.memory.write32(0x3100000,0xdead0000);assert.throws(()=>g.threads.read(0),/invalid exception-chain/);
  g.memory.write32(0x3100000,first);finishFrame(g,saved);
  assert.throws(()=>g.call(0x87bf11),/unavailable/);assert.throws(()=>g.call(0x87c304),/unavailable/);
  g.reset();assert.equal(g.threads.snapshot().fsBase,null);assert.throws(()=>g.threads.read(0),/uninitialized/);
});

test('recovery override includes omitted normal continuation and keeps exception dispatch unsupported',async()=>{
  const coverage=JSON.parse(await fs.readFile(path.join(web,'../analysis/undercover/cleanup-registrar-coverage-phase69.json'),'utf8'));
  const addresses=new Set(coverage.regions[0].instructions.map(i=>i.address));
  for(const address of ['0x0087B601','0x0087B603','0x0087B610','0x0087B61D','0x0087B629','0x0087B631','0x0087B636'])assert.ok(addresses.has(address));
  assert.equal(coverage.canonicalMasterModified,false);assert.equal(coverage.exceptionDispatchSupported,false);
  assert.ok(coverage.laterGlobalStores.every(store=>!store.runtimeObserved));
  const registry=JSON.parse(await fs.readFile(path.join(web,'../tools/uc_unified_registry.json'),'utf8'));
  assert.ok(!registry.bindings.some(entry=>entry.address===0x87c264));
});

test('thread initialization rejects an unmapped or read-only synthetic TEB',async()=>{
  const module=await esbuild.build({entryPoints:[path.join(web,'src/host/uc-thread.ts')],bundle:true,format:'esm',platform:'neutral',write:false});
  const {GuestThreadFixtures}=await import('data:text/javascript;base64,'+Buffer.from(module.outputFiles[0].text).toString('base64'));
  const processModule=await esbuild.build({entryPoints:[path.join(web,'src/host/uc-process.ts')],bundle:true,format:'esm',platform:'neutral',write:false});
  const {GuestAddressSpace,READ}=await import('data:text/javascript;base64,'+Buffer.from(processModule.outputFiles[0].text).toString('base64'));
  for(const segments of [[],[{name:'read-only TEB',address:0x03100000,size:0x1000,permissions:READ}]]) {
    const threads=new GuestThreadFixtures(new GuestAddressSpace(segments));
    assert.throws(()=>threads.initialize(),/unmapped, unavailable or permission denied/);
    assert.equal(threads.snapshot().fsBase,null);
  }
});
test('connected original registrar links fixture FS frame and rejects exact unaligned provider',{skip:!root},async()=>{
  const g=await create();
  for(let repeat=0;repeat<2;repeat++){
    g.threads.initialize();
    assert.throws(()=>g.call(0xb57dc0),/dispatch at 0x8aac6a: unavailable/);
    assert.equal(g.lastInstruction,0x87b5b3);assert.equal(g.cpu.eip,0x87b5b3);
    assert.equal(g.cpu.ebp,0x300efe4);assert.equal(g.cpu.esp,0x300efa8);
    assert.equal(g.memory.read32(g.cpu.esp),0x87b5b5);assert.equal(g.memory.read32(g.cpu.esp+4),0);
    assert.equal(g.cpu.esi,0x8aac6a);assert.equal(g.memory.read32(0xb61398),0x8aac6a);
    assert.equal(g.threads.read(0),0x300efd4);assert.equal(g.memory.read32(0x300efd4),0xffffffff);
    assert.equal(g.memory.read32(0x189d0f8),0x32000);assert.equal(g.memory.read32(0x189d0fc),0x186a0);
    const writes=g.writeLog.filter(w=>w.address>=0x400000&&w.address<0x3000000);
    assert.equal(writes.length,27);assert.equal(g.memory.read32(0x18b1e6c),0);assert.equal(g.memory.read32(0x18b1e68),0);
    assert.equal(g.memory.read32(0x1285688),0xbb40e64e);assert.equal(g.memory.read32(0x128568c),0x44bf19b1);
    assert.equal(g.dispatcher.trace.filter(e=>e.kind==='return').length,9);
    for(const a of [0xb57dc0,0x87b640,0x87b59b])assert.ok(!g.dispatcher.trace.some(e=>e.kind==='return'&&e.address===a));
    if(process.env.UC_SEH_EVIDENCE&&repeat===0)await fs.writeFile(process.env.UC_SEH_EVIDENCE,JSON.stringify({classification:'ORIGINAL_CONNECTED_CODE_SYNTHETIC_THREAD',thread:g.threads.snapshot(),fsAccesses:g.threads.accesses,trace:g.dispatcher.trace,instructions:g.instructions,registers:g.cpu,globalWrites:writes,blockedProvider:{callsite:0x87b5b3,cell:0xb61398,value:0x8aac6a,argument:g.memory.read32(g.cpu.esp+4),returnAddress:g.memory.read32(g.cpu.esp)},restorationExercisedInConnectedTrace:false,originalStartupReachability:'UNVERIFIED'},null,2)+'\n');
    g.reset();assert.equal(g.threads.snapshot().fsBase,null);
  }
});
