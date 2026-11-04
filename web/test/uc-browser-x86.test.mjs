import {test} from 'node:test';
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import fs from 'node:fs/promises';import os from 'node:os';import path from 'node:path';import {fileURLToPath} from 'node:url';
const web=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
test('reviewed browser x86 engine matches original connected bytes and rejects budgets/providers', {skip:!process.env.UC_BROWSER_X86_ENGINE,timeout:60000},async()=>{
 assert.ok(process.env.UC_AUTHENTIC_ASSET_ROOT,'private original asset root required');
 const temp=await fs.mkdtemp(path.join(os.tmpdir(),'uc-x86-evidence-'));
 try{
  const output=process.env.UC_BROWSER_X86_EVIDENCE||path.join(temp,'result.json');
  await promisify(execFile)(process.execPath,['tools/uc-browser-x86-experiment.mjs',process.env.UC_BROWSER_X86_ENGINE,process.env.UC_AUTHENTIC_ASSET_ROOT,'../analysis/undercover/browser-x86-admission-phase72.json',output],{cwd:web,timeout:55000,maxBuffer:1024*1024});
  const d=JSON.parse(await fs.readFile(output,'utf8'));assert.equal(d.secureContext,true);assert.equal(d.actual.instructions.length,173);
  assert.ok(Object.values(d.comparison).every(Boolean));assert.equal(d.actual.trace.filter(e=>e.kind==='enter').length,12);
  assert.equal(d.actual.trace.filter(e=>e.kind==='return').length,9);assert.equal(d.actual.writes.filter(w=>w.address>=0x400000&&w.address<0x3000000).length,27);
  assert.equal(d.actual.stop,'dispatch at 0x8aac6a: unavailable');assert.equal(d.actual.registers.eip,0x87b5b3);
  assert.ok(!d.actual.instructions.includes(0x8aac6a));assert.equal(d.actual.fs.exceptionHead,0x300efd4);
  assert.equal(d.budgetCases.length,6);assert.ok(d.budgetCases.every(c=>c.passed));assert.equal(d.negativeTests.invalidInstructionRejected,true);
  assert.equal(d.benchmark.measuredPairs,7);assert.equal(d.originalStartupReachability,'UNVERIFIED');
 }finally{await fs.rm(temp,{recursive:true,force:true});}
});
