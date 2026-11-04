import {test} from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs/promises';import path from 'node:path';import {fileURLToPath} from 'node:url';import * as esbuild from 'esbuild';
const web=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const code=(await esbuild.build({entryPoints:[path.join(web,'src/host/uc-unified.ts')],bundle:true,format:'esm',platform:'neutral',write:false})).outputFiles[0].text;
const {createUndercoverProcess}=await import('data:text/javascript;base64,'+Buffer.from(code).toString('base64'));
const root=process.env.UC_AUTHENTIC_ASSET_ROOT,modulePath=process.env.UC_CRT_COOKIE_MODULE;
const fixture={provenance:'DETERMINISTIC_SERVICE_FIXTURE',processId:123,threadId:456,fileTime:()=>133000000000000000n,tickCount:()=>9876,performanceCounter:()=>12345678901n};
async function create(mode='compatibility-crt',env=fixture,maxInstructions,observer,moduleOverride){return createUndercoverProcess(JSON.parse(await fs.readFile(path.join(root,'uc-unified-image.json'),'utf8')),new Uint8Array(await fs.readFile(path.join(root,'uc-unified-image.bin'))),new Uint8Array(await fs.readFile(path.join(root,'uc-unified.wasm'))),observer,{module:moduleOverride??new Uint8Array(await fs.readFile(modulePath)),mode,environment:env,maxInstructions});}
const skip=!root||!modulePath;
test('compatibility cookie computes and stores original cookie/complement with five exact host ABI calls',{skip},async()=>{
 const observed=[];const g=await create('compatibility-crt',fixture,undefined,{instruction:(cpu,known)=>observed.push({cpu,known})});for(let run=0;run<2;run++){
  assert.equal(g.memory.read32(0x1285688),0xbb40e64e);Object.assign(g.cpu,{ebx:0x11223344,esi:0x55667788,edi:0x99112233,ebp:0x44556677});g.call(0x87c264);
  assert.equal(g.cpu.ebx,0x11223344);assert.equal(g.cpu.esi,0x55667788);assert.equal(g.cpu.edi,0x99112233);assert.equal(g.cpu.ebp,0x44556677);assert.equal(g.cpu.eip,0xdec0de);assert.equal(g.cpu.esp,0x300f000);
  let expected=(Number(fixture.fileTime()&0xffffffffn)^Number(fixture.fileTime()>>32n)^123^456^9876^Number(fixture.performanceCounter()&0xffffffffn)^Number(fixture.performanceCounter()>>32n))>>>0;
  if(expected===0xbb40e64e)expected=0xbb40e64f;
  assert.notEqual(expected&0xffff0000,0);assert.equal(g.memory.read32(0x1285688),expected);assert.equal(g.memory.read32(0x128568c),(~expected)>>>0);
  assert.deepEqual(g.writeLog.filter(w=>w.address===0x1285688||w.address===0x128568c).map(w=>w.instruction),[0x87c2e5,0x87c2ed]);
  assert.equal(g.compatibility.calls.length,5);assert.equal(g.compatibility.hostWrites.length,4);
  for(const [a,b] of [[0x87c2eb,0x87c2ed],[0x87c2f6,0x87c2f7]]){const before=observed.find(v=>v.cpu.eip===a),after=observed.find(v=>v.cpu.eip===b);assert.equal(before.cpu.eflags,after.cpu.eflags);assert.equal(before.known,after.known);}
  for(const c of g.compatibility.calls){assert.equal(c.status,'RETURNED');assert.equal(c.hostSubstitution,true);assert.equal(c.originalLoaderBindingObserved,false);assert.equal(c.espAfter-c.espBefore,4+(c.arguments.length*4));}
  assert.equal(g.memory.read32(0xb61398),0x8aac6a);g.reset();
 }
});
test('original-only cookie and original constructor control retain unresolved traps',{skip},async()=>{
 const bad=new Uint8Array(await fs.readFile(modulePath));bad[bad.length-1]^=1;await assert.rejects(create('compatibility-crt',fixture,undefined,undefined,bad),/Invalid reviewed CRT/);
 const g=await create('original-only');assert.throws(()=>g.call(0x87c264),/dispatch at 0x8ab0fe/);assert.equal(g.lastInstruction,0x87c299);assert.equal(g.compatibility,null);assert.equal(g.memory.read32(0x1285688),0xbb40e64e);
 g.reset();g.threads.initialize();assert.throws(()=>g.call(0xb57dc0),/dispatch at 0x8aac6a/);assert.equal(g.lastInstruction,0x87b5b3);
 const c=await create();c.threads.initialize();assert.throws(()=>c.call(0xb57dc0),/dispatch at 0x8aac6a/);assert.equal(c.compatibility.calls.length,0);
});
test('cookie unsupported shift and execution budgets stop without fabricated global results',{skip},async()=>{
 const low={...fixture,fileTime:()=>0n,performanceCounter:()=>0n,processId:1,threadId:2,tickCount:()=>0};const g=await create('compatibility-crt',low);
 assert.throws(()=>g.call(0x87c264),/Unsupported checked SHL/);assert.equal(g.lastInstruction,0x87c2e0);assert.equal(g.memory.read32(0x1285688),0xbb40e64e);assert.equal(g.compatibility.calls.length,5);
 const b=await create('compatibility-crt',fixture,3);assert.throws(()=>b.call(0x87c264),/budget/);assert.equal(b.compatibility.calls.length,0);
});
test('compatibility output buffers reject before partial writes, exact callsites and return ABI are mandatory',{skip},async()=>{
 const g=await create(),cpu=g.cpu,s=0x300ef00;g.memory.write32(s,0x87c29f);g.memory.write32(s+4,0xb61398);Object.assign(cpu,{eip:0x87c299,esp:s});
 assert.throws(()=>g.compatibility.invoke(cpu,0x8ab0fe),/permission/);assert.equal(g.memory.read32(0xb61398),0x8aac6a);assert.equal(cpu.esp,s);
 cpu.eip=0x87c298;assert.equal(g.compatibility.invoke(cpu,0x8ab0fe),false);
 cpu.eip=0x87c299;assert.throws(()=>g.compatibility.invoke(cpu,0x8ab0ff),/target mismatch/);
 g.memory.write32(s,0x87c2a0);assert.throws(()=>g.compatibility.invoke(cpu,0x8ab0fe),/return address/);
});
test('Windows-compatible NT_TIB context preserves ownership fields and resets without startup-global transitions',{skip},async()=>{
 const g=await create();g.call(0x87c264);const t=g.threads.initializeWindowsCompatible(123,456);
 assert.equal(g.threads.read(0),0xffffffff);assert.equal(g.threads.read(0x18),0x3100000);assert.equal(g.memory.read32(g.threads.read(0x18)+4),0x3010000);
 assert.equal(t.compatibilityContext.threadId,456);assert.equal(g.memory.read32(0x18b1e58),0);assert.equal(g.memory.read32(0x18b1e5c),0);
 assert.throws(()=>g.threads.initializeWindowsCompatible(123,456),/Reset required/);assert.throws(()=>g.threads.read(0x24),/unsupported/);
 assert.throws(()=>g.call(0x87bb3d),/dispatch at 0x87c232/);
 assert.equal(g.memory.read32(0x18b1e58),1);assert.equal(g.memory.read32(0x18b1e5c),0x3010000);
 assert.equal(g.compatibility.calls.filter(c=>c.name==='InterlockedCompareExchange').length,1);
 assert.equal(g.lastInstruction,0x87bbb4);g.reset();assert.equal(g.threads.snapshot().fsBase,null);assert.throws(()=>g.threads.read(0x18),/uninitialized/);
});
test('initializer order stays blocked before the first non-null unreviewed C entry',{skip},async()=>{
 const g=await create();const values=[0,1,2,3].map(i=>g.memory.read32(0xb63dc4+i*4));assert.deepEqual(values,[0,0x87bcb3,0x87bfe4,0x87c08b]);
 assert.throws(()=>g.call(0x87c232),/dispatch/);assert.throws(()=>g.call(0x87bcb3),/dispatch/);assert.equal(g.memory.read32(0x18b1e68),0);assert.equal(g.memory.read32(0x18b1e6c),0);assert.equal(g.compatibility.calls.length,0);
});
test('bounded CRT startup prefix uses SEH 0x10/CA93F8, FS owner token, ICE and stops at _initterm_e',{skip},async()=>{
 const g=await create();g.call(0x87c264);g.threads.initializeWindowsCompatible(123,456);
 assert.throws(()=>g.call(0x87bb3d),/dispatch at 0x87c232/);
 assert.equal(g.lastInstruction,0x87bbb4);assert.equal(g.cpu.eip,0x87bbb4);
 assert.ok(g.instructions.includes(0x87bb44));assert.ok(g.instructions.includes(0x87bb4e));assert.ok(g.instructions.includes(0x87bb62));
 assert.equal(g.memory.read32(0x18b1e58),1);assert.equal(g.memory.read32(0x18b1e5c),0x3010000);
 assert.equal(g.memory.read32(0x18b1e68),0);assert.equal(g.memory.read32(0x18b1e6c),0);
 const ice=g.compatibility.calls.find(c=>c.name==='InterlockedCompareExchange');
 assert.equal(ice.status,'RETURNED');assert.equal(ice.hostSubstitution,true);assert.equal(ice.originalLoaderBindingObserved,false);
 assert.equal(ice.espAfter-ice.espBefore,16);assert.deepEqual(ice.arguments,[0x18b1e5c,0x3010000,0]);assert.equal(ice.eax,0);assert.equal(ice.exchanged,true);
 assert.ok(g.compatibility.hostWrites.some(w=>w.address===0x18b1e5c&&w.value===0x3010000&&w.service==='InterlockedCompareExchange'));
 assert.ok(g.writeLog.some(w=>w.address===0x18b1e58&&w.value===1&&w.instruction===0x87bba4));
 assert.equal(g.memory.read32(0xb611b4),0x8ab07e);assert.equal(g.memory.read32(0xb613b4),0x8aacca);
});
test('startup SEH frame rejects unknown size/scope and original-only still refuses host ICE',{skip},async()=>{
 const g=await create('original-only');g.threads.initializeWindowsCompatible(1,2);
 assert.throws(()=>g.call(0x87bb3d),/dispatch at 0x8ab07e/);assert.equal(g.lastInstruction,0x87bb62);
 assert.equal(g.memory.read32(0x18b1e58),0);assert.equal(g.memory.read32(0x18b1e5c),0);assert.equal(g.compatibility,null);
 const h=await create();h.threads.initialize();
 assert.throws(()=>h.call(0x87beb8,[0x14,0xca93f8]),/unsupported SEH frame inputs/);
 assert.throws(()=>h.call(0x87beb8,[0x10,0xca9380]),/unsupported SEH frame inputs/);
 const S=0x300ef00;h.memory.write32(S,0xdec0de);h.memory.write32(S+4,0xb602e0);h.memory.write32(S-4,0x10);h.memory.write32(S-8,0xca93f8);h.cpu.esp=S-8;
 h.dispatcher.call(h.cpu,0x87beb8,0x87bb49);assert.equal(h.cpu.ebp,S-4);assert.equal(h.cpu.esp,S-52);
});
test('foreign owner forces Sleep path; Sleep remains unimplemented',{skip},async()=>{
 const g=await create();g.call(0x87c264);g.threads.initializeWindowsCompatible(123,456);
 g.memory.write32(0x18b1e5c,0xdead0001); // other owner token
 assert.throws(()=>g.call(0x87bb3d),/dispatch at 0x8aa0d0/); // Sleep raw target
 assert.equal(g.lastInstruction,0x87bb7d);assert.equal(g.memory.read32(0x18b1e58),0);assert.equal(g.memory.read32(0x18b1e5c),0xdead0001);
 const ice=g.compatibility.calls.filter(c=>c.name==='InterlockedCompareExchange');
 assert.ok(ice.length>=1);assert.equal(ice[0].exchanged,false);assert.equal(ice[0].eax,0xdead0001);
 assert.ok(!g.compatibility.calls.some(c=>c.name==='Sleep'));
});

test('clock errors and truncated output ranges propagate without partial host writes',{skip},async()=>{
 const g=await create('compatibility-crt',{...fixture,fileTime:()=>{throw new Error('clock-failure');}});assert.throws(()=>g.call(0x87c264),/clock-failure/);assert.equal(g.compatibility.calls[0].status,'FAULT');assert.equal(g.compatibility.hostWrites.length,0);assert.equal(g.memory.read32(0x1285688),0xbb40e64e);
 const h=await create(),s=0x300ef00,p=0x3101ffc;h.memory.write32(s,0x87c29f);h.memory.write32(s+4,p);h.memory.write32(p,0x11223344);Object.assign(h.cpu,{eip:0x87c299,esp:s});assert.throws(()=>h.compatibility.invoke(h.cpu,0x8ab0fe),/permission/);assert.equal(h.memory.read32(p),0x11223344);assert.equal(h.compatibility.hostWrites.length,0);
});
