// Offline feasibility reference only. Never used by the website/game process.
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {spawnSync} from 'node:child_process';
import {performance} from 'node:perf_hooks';
import * as esbuild from 'esbuild';
const [incoming,assetRoot,output]=process.argv.slice(2);
const native=JSON.parse(await fs.readFile(incoming,'utf8'));
const js=await esbuild.build({entryPoints:['src/host/uc-unified.ts'],bundle:true,write:false,format:'esm',platform:'neutral'});
const {createUndercoverProcess}=await import('data:text/javascript;base64,'+Buffer.from(js.outputFiles[0].text).toString('base64'));
const descriptor=JSON.parse(await fs.readFile(path.join(assetRoot,'uc-unified-image.json'),'utf8'));
const g=await createUndercoverProcess(descriptor,new Uint8Array(await fs.readFile(path.join(assetRoot,'uc-unified-image.bin'))),new Uint8Array(await fs.readFile(path.join(assetRoot,'uc-unified.wasm'))));
const base=0x0189d0a0;
for(let a=base;a<base+128;a+=4)g.memory.write32(a,0xa5a5a5a5);
Object.assign(g.cpu,native.initialRegisters);g.call(0x009e7540);
for(const key of ['eax','ebx','ecx','edx','esi','edi','ebp','esp','eip'])if(g.cpu[key]!==native.cold.registers[key])throw new Error('Register mismatch: '+key);
if(g.cpu.eflags!==(native.cold.registers.eflags&0x8d5))throw new Error('Arithmetic flags mismatch');
if(JSON.stringify(g.instructions)!==JSON.stringify(native.cold.instructions))throw new Error('Original instruction trace mismatch');
if(JSON.stringify(g.dispatcher.trace.filter(event=>event.kind==='enter').map(event=>event.address))!==JSON.stringify(native.cold.functionEntries))throw new Error('Nested original entry sequence mismatch');
const data=Buffer.from(Array.from({length:128},(_,i)=>g.memory.read8(base+i))).toString('hex');
if(data!==native.cold.dataHex)throw new Error('Guest data mismatch');
const writes=g.writeLog.filter(w=>w.address>=base&&w.address<base+128);
if(JSON.stringify(writes)!==JSON.stringify(native.cold.globalWrites))throw new Error('Original guest write journal mismatch');
const temp=await fs.mkdtemp(path.join(os.tmpdir(),'uc-engine-flags-'));
try{
  const build=spawnSync('python',['../tools/uc_unified_flags_fixture.py',path.join(temp,'flags.wasm')],{encoding:'utf8'});
  if(build.status!==0)throw new Error(build.stderr);
  const module=await WebAssembly.instantiate(await fs.readFile(path.join(temp,'flags.wasm')),{
    env:{memory:new WebAssembly.Memory({initial:2})},guest:{read32:()=>{throw new Error('Unexpected fixture read');},write32:()=>{throw new Error('Unexpected fixture write');},dispatch:()=>{throw new Error('Unexpected fixture provider');},write8:()=>{},instruction:()=>{}}});
  const f=module.instance.exports;
  for(const row of native.arithmetic){f.arithmetic(1,0,row.carry,32);const result=f.arithmetic(row.op,row.a,row.b,32)>>>0;if(result!==row.result||f.flags()!==row.flags)throw new Error('Engine/RawLifter arithmetic mismatch: '+JSON.stringify(row));}
}finally{await fs.rm(temp,{recursive:true,force:true});}
function invoke(){g.cpu.ecx=base;g.instructions.length=0;g.writeLog.length=0;g.dispatcher.trace.length=0;g.call(0x009e7540);}
for(let i=0;i<50;i++)invoke();
const batches=[];
for(let batch=0;batch<7;batch++){const start=performance.now();for(let i=0;i<100;i++)invoke();batches.push((performance.now()-start)*1000/100);}
const sorted=[...batches].sort((a,b)=>a-b);
const wasmTiming={unit:'microseconds_per_instrumented_call',batchMeans:batches,median:sorted[3],minimum:sorted[0],maximum:sorted.at(-1),iterationsPerBatch:100,warmup:50};
await fs.writeFile(output,JSON.stringify({...native,comparison:{generalRegistersEqual:true,arithmeticFlagsEqual:true,comparedFlagMask:0x8d5,systemFlagsCompared:false,nestedFunctionEntriesEqual:true,originalInstructionTraceEqual:true,originalWriteJournalEqual:true,boundedGuestBytesEqual:true,syntheticArithmeticCasesEqual:native.arithmetic.length,wasmFlagsKnown:g.snapshot().flagsKnown},wasmTiming,
performanceLimit:'Native Unicorn via Python/C callbacks versus existing Wasm via Node checked imports. Instrumented hot constructor timings include different host boundaries; not a browser engine benchmark or FPS estimate.'},null,2)+'\n');
