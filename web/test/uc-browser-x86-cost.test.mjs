import {test} from 'node:test';import assert from 'node:assert/strict';
import fs from 'node:fs/promises';import path from 'node:path';import os from 'node:os';import {fileURLToPath} from 'node:url';import {execFile} from 'node:child_process';import {promisify} from 'node:util';
const web=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
test('browser x86 cost modes retain checked bytes, persistent reset and bounded batch traps',{skip:!process.env.UC_BROWSER_X86_COST,timeout:110000},async()=>{
 assert.ok(process.env.UC_BROWSER_X86_ENGINE);assert.ok(process.env.UC_AUTHENTIC_ASSET_ROOT);
 const temp=await fs.mkdtemp(path.join(os.tmpdir(),'uc-cost-test-'));
 try{
  const output=process.env.UC_BROWSER_X86_COST_EVIDENCE||path.join(temp,'costs.json');
  await promisify(execFile)(process.execPath,['tools/uc-browser-x86-cost-experiment.mjs',process.env.UC_BROWSER_X86_ENGINE,process.env.UC_AUTHENTIC_ASSET_ROOT,output,'optimized'],{cwd:web,timeout:100000,maxBuffer:1024*1024});
  const d=JSON.parse(await fs.readFile(output,'utf8'));assert.equal(d.secureContext,true);assert.equal(d.reference.instructionCount,173);assert.equal(d.reference.entries,12);assert.equal(d.reference.distinctBodies,7);assert.equal(d.reference.calleeReturns,9);assert.equal(d.reference.globalWrites,27);assert.equal(d.reference.guestWrites,82);assert.equal(d.reference.checkedReads,68);
  assert.equal(d.experiments.length,8);for(const r of d.experiments){assert.equal(r.allRepeatedComparisonsPassed,true);assert.ok(Object.values(r.comparisons).every(v=>v!==false));assert.equal(r.warm.samples.length,9);if(r.mode==='B'){assert.equal(r.fair.wasmRawMs.length,70);assert.equal(r.fair.x86RawMs.length,70);assert.equal(r.comparisons.states,null);assert.equal(r.comparisons.reads,null);}}
  assert.equal(d.resetTests.length,8);for(const r of d.resetTests){assert.ok(Object.values(r.comparison).every(Boolean));assert.equal(r.rawEngineStopEip,0x8aac6a);assert.equal(r.stop,'dispatch at 0x8aac6a: unavailable');}
  assert.equal(d.resetProbes.length,3);assert.equal(d.optimizedBudgets.length,6);assert.ok(d.optimizedBudgets.every(r=>r.passed));
  const p=d.experiments.find(r=>r.name==='B_persistent_checked');assert.equal(p.synchronization.pagesMappedThisRun,0);assert.ok(p.synchronization.restoredRanges>0);assert.ok(p.reused.every(Boolean));
 }finally{await fs.rm(temp,{recursive:true,force:true});}
});
