import {createUndercoverProcess} from '../src/host/uc-unified.ts';
import {runBrowserX86} from './uc-browser-x86-adapter.mjs';
import {runCostedBrowserX86,createPersistentSession} from './uc-browser-x86-cost-adapter.mjs';
import {createCostMeter} from './uc-browser-x86-cost-meter.mjs';
const norm=v=>Array.isArray(v)?v.map(norm):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,norm(v[k])])):v;
const eq=(a,b)=>JSON.stringify(norm(a))===JSON.stringify(norm(b));
const events=t=>t.filter(e=>e.kind==='enter'||e.kind==='return');
export function statistics(samples){const a=[...samples].sort((a,b)=>a-b),mean=samples.reduce((s,v)=>s+v,0)/samples.length;return{samples,median:a[Math.floor(a.length/2)],min:a[0],max:a.at(-1),mean,standardDeviation:Math.sqrt(samples.reduce((s,v)=>s+(v-mean)**2,0)/samples.length)};}
self.onmessage=async(event)=>{
 if(event.data.ping){self.postMessage({ping:true});return;}
 try{
  const meter=createCostMeter();meter.measure('engineScriptLoad',()=>importScripts('/engine.js'));const factoryDone=meter.enter('engineFactoryInitialization');
  const instantiate=WebAssembly.instantiate;let engineMemory;
  WebAssembly.instantiate=async(...args)=>{const result=await instantiate(...args);for(const v of Object.values((result.instance??result).exports))if(v instanceof WebAssembly.Memory)engineMemory=v;return result;};
  let uc;try{uc=await MUnicorn();}finally{WebAssembly.instantiate=instantiate;}factoryDone();
  const load=async name=>{const r=await fetch('/uc-assets/'+name);if(!r.ok)throw new Error('Private asset unavailable: '+name);return new Uint8Array(await r.arrayBuffer());};
  const [description,payload,wasm]=await Promise.all(['uc-unified-image.json','uc-unified-image.bin','uc-unified.wasm'].map(load));
  const descriptor=JSON.parse(new TextDecoder().decode(description)),admission=await(await fetch('/admission.json')).json();
  let full=true;const referenceStates=[],referenceReads=[];
  const onInstruction=(cpu,flagsKnown)=>referenceStates.push({cpu,flagsKnown}),onRead=(address,size,instruction,value)=>referenceReads.push({address,size,instruction,value});const observer={instruction:onInstruction,read:onRead};const g=await createUndercoverProcess(descriptor,payload,wasm,observer);function setFull(value){full=value;observer.instruction=value?onInstruction:undefined;observer.read=value?onRead:undefined;}
  function reset(){return meter.measure('guestReset',()=>{g.reset();g.threads.initialize();referenceStates.length=0;referenceReads.length=0;});}
  function runWasm(){let stop='';const start=performance.now();try{g.call(0xb57dc0);}catch(error){stop=error.message;}return{durationMs:performance.now()-start,instructions:[...g.instructions],writes:g.writeLog.map(w=>({...w})),registers:{...g.cpu},trace:g.dispatcher.trace.map(e=>({...e})),fs:g.threads.snapshot(),flagsKnown:g.snapshot().flagsKnown,states:[...referenceStates],reads:[...referenceReads],fsAccesses:[...g.threads.accesses],stop};}
  reset();const reference=runWasm(),expectedMemory=new Uint8Array(g.memory.memory.buffer).slice();
  function compare(actual,withSnapshots=true){return meter.measure('terminalStateComparison',()=>{
   const memory=new Uint8Array(g.memory.memory.buffer);let mismatches=0;for(let i=0x400000;i<memory.length;i++)if(memory[i]!==expectedMemory[i])mismatches++;
   const c={engineHooks:eq(actual.executedInstructionAddresses,actual.instructions),instructions:eq(reference.instructions,actual.instructions),registers:eq(reference.registers,actual.registers),writes:eq(reference.writes,actual.writes.filter(w=>w.address!==reference.fs.fsBase)),trace:eq(events(reference.trace),events(actual.trace)),fs:eq(reference.fs,actual.fs),fsAccesses:eq(reference.fsAccesses,actual.fsAccesses),reads:actual.settings?.verboseReads===false?null:eq(reference.reads,actual.reads),flagsKnown:eq(reference.flagsKnown,actual.flagsKnown),states:withSnapshots?actual.states.length===reference.states.length&&reference.states.every((s,i)=>{const a=actual.states[i];if(!a||s.flagsKnown!==a.flagsKnown)return false;const mask=[1,4,16,64,128,2048].reduce((m,b,j)=>m|((s.flagsKnown&(1<<j))?b:0),0);return eq({...s.cpu,eflags:s.cpu.eflags&mask},{...a.cpu,eflags:a.cpu.eflags&mask});}):null,memory:mismatches===0,stop:eq(reference.stop,actual.stop)};
   if(Object.values(c).some(v=>v===false))throw new Error('Differential mismatch: '+JSON.stringify(c));return c;
  });}
  const legacy={wasm:[],x86:[]};
  for(let i=0;i<11;i++){reset();const a=runWasm();reset();const b=await runBrowserX86(g,uc,admission);compare(b);if(i>=2){legacy.wasm.push(a.durationMs);legacy.x86.push(b.durationMs);}}
  const profiles=[];
  for(let i=0;i<3;i++){reset();const costs=createCostMeter();const a=await runCostedBrowserX86(g,uc,admission,{}, {meter:costs});const comparison=compare(a);profiles.push({durationMs:a.durationMs,costs:a.costs,comparison});}
  const unprofiled=[];for(let i=0;i<9;i++){reset();const a=await runCostedBrowserX86(g,uc,admission);compare(a);unprofiled.push(a.durationMs);}
  const experiments=[],resetTests=[],resetProbes=[],optimizedBudgets=[];
  if(event.data.stage==='optimized'){
   const cases=[
    ['C_yield_only','C',{yieldEvery:173}],
    ['C_bulk_page_copy_only','C',{bulkPages:true}],
    ['C_snapshot_only','C',{snapshots:false}],
    ['C_persistent_only','C',{session:createPersistentSession()}],
    ['C_batch16_only','C',{batchSize:16}],
    ['A_combined_full','A',{bulkPages:true,yieldEvery:0,batchSize:16,session:createPersistentSession()}],
    ['B_fresh_checked','B',{snapshots:false,verboseReads:false,bulkPages:true,yieldEvery:0,batchSize:16}],
    ['B_persistent_checked','B',{snapshots:false,verboseReads:false,bulkPages:true,yieldEvery:0,batchSize:16,session:createPersistentSession()}],
   ];
   for(const [name,mode,settings] of cases){
    setFull(mode!=='B');const measurements=[],wasmSamples=[],comparisons=[],reused=[];
    reset();let a=runWasm();reset();let cold=await runCostedBrowserX86(g,uc,admission,{},settings);comparisons.push(compare(cold,settings.snapshots!==false));
    for(let i=0;i<11;i++){
     reset();const w=runWasm();reset();const x=await runCostedBrowserX86(g,uc,admission,{},settings);
     comparisons.push(compare(x,settings.snapshots!==false));reused.push(x.reused);
     if(i>=2){measurements.push(x.durationMs);wasmSamples.push(w.durationMs);}
    }
    // Group means improve resolution for the short production-equivalent Wasm path.
    let fair=null;
    if(mode==='B'){
     const xGroups=[],wGroups=[],xRaw=[],wRaw=[];
     for(let group=0;group<7;group++){
      let wt=0,xt=0;
      for(let j=0;j<10;j++){
       reset();const w=runWasm();wt+=w.durationMs;wRaw.push(w.durationMs);
       reset();const x=await runCostedBrowserX86(g,uc,admission,{},settings);xt+=x.durationMs;xRaw.push(x.durationMs);compare(x,false);
      }
      wGroups.push(wt/10);xGroups.push(xt/10);
     }
     fair={wasm:statistics(wGroups),x86:statistics(xGroups),wasmRawMs:wRaw,x86RawMs:xRaw,groupCount:7,runsPerGroup:10,ratio:statistics(xGroups).median/statistics(wGroups).median};
    }
    const prof=createCostMeter();reset();const detailed=await runCostedBrowserX86(g,uc,admission,{}, {...settings,meter:prof});compare(detailed,settings.snapshots!==false);
    experiments.push({name,mode,settings:{...settings,session:!!settings.session},coldMs:cold.durationMs,warm:statistics(measurements),wasm:statistics(wasmSamples),ratio:statistics(measurements).median/statistics(wasmSamples).median,fair,comparisons:comparisons[0],allRepeatedComparisonsPassed:true,reused,profile:detailed.costs,synchronization:detailed.synchronization});
    settings.session?.close();
   }
   // Persistent reset qualification uses complete correctness diagnostics, never reduced checks.
   setFull(true);const session=createPersistentSession(),settings={session,bulkPages:true,yieldEvery:0,batchSize:16};
   const good=async label=>{reset();const x=await runCostedBrowserX86(g,uc,admission,{},settings);const comparison=compare(x);resetTests.push({label,reused:x.reused,comparison,stop:x.stop,rawEngineStopEip:x.rawEngineStopEip});};
   await good('cold');await good('warm');await good('same-process-repeat');await good('reset-after-provider');
   reset();let x=await runCostedBrowserX86(g,uc,admission,{instructions:3},settings);resetProbes.push({label:'budget',stop:x.stop});if(x.stop!=='BUDGET_INSTRUCTIONS')throw new Error(x.stop);await good('reset-after-budget');
   let invalid='';try{session.invalidInstructionFixture(uc);}catch(error){invalid=String(error);}resetProbes.push({label:'invalid-instruction',stop:invalid,fixture:'Synthetic UD2 outside original code; private page unmapped before reuse'});if(!invalid.includes('UC_ERR_INSN_INVALID'))throw new Error('Invalid-instruction reset fixture failed');await good('reset-after-invalid-instruction');
   reset();const write=g.memory.write32;g.memory.write32=function(address,value){if(address===0x0300eff8)throw new Error('PERMISSION_FAILURE_FIXTURE');return write.call(this,address,value);};
   try{x=await runCostedBrowserX86(g,uc,admission,{},settings);}finally{g.memory.write32=write;}
   resetProbes.push({label:'permission-failure',stop:x.stop,fixture:'Stronger host permission policy rejects original first PUSH to 0x0300EFF8; original bytes and permissions not patched'});if(x.stop!=='PERMISSION_FAILURE_FIXTURE')throw new Error('Permission-failure reset fixture failed: '+x.stop);await good('reset-after-permission-failure');
   for(const [name,options,expected] of [['instructions',{instructions:3},'BUDGET_INSTRUCTIONS'],['depth',{depth:1},'BUDGET_CALL_DEPTH'],['writes',{writes:1},'BUDGET_WRITES'],['accessBytes',{accessBytes:4},'BUDGET_ACCESS_BYTES'],['wall',{wallMs:1},'BUDGET_WALL'],['transitions',{transitions:1},'BUDGET_TRANSITIONS']]){
    reset();const x=await runCostedBrowserX86(g,uc,admission,options,settings);optimizedBudgets.push({name,expected,stop:x.stop,passed:x.stop===expected});if(x.stop!==expected)throw new Error('Optimized budget failed '+name+': '+x.stop);
   }
   await good('reset-after-all-budget-cases');meter.measure('persistentEngineFinalTeardown',()=>session.close());
  }
  self.postMessage({experiments,resetTests,resetProbes,optimizedBudgets,phase:73,stage:event.data.stage==='optimized'?'BOUNDED_OPTIMIZATION':'BASELINE_BEFORE_OPTIMIZATION',secureContext:isSecureContext,engineVersion:uc.version(),memoryBytes:g.memory.memory.buffer.byteLength,engineMemoryBytes:engineMemory?.buffer.byteLength,baseline:{wasm:statistics(legacy.wasm),originalAdapter:statistics(legacy.x86),costAdapterUnprofiled:statistics(unprofiled)},profiles,externalCosts:meter.result(),reference:{instructionCount:reference.instructions.length,entries:events(reference.trace).filter(e=>e.kind==='enter').length,distinctBodies:new Set(events(reference.trace).filter(e=>e.kind==='enter').map(e=>e.address)).size,calleeReturns:events(reference.trace).filter(e=>e.kind==='return').length,globalWrites:reference.writes.filter(w=>w.address>=0x400000&&w.address<0x3000000).length,guestWrites:reference.writes.length+reference.fsAccesses.filter(a=>a.operation==='write').length,checkedReads:reference.reads.length,stop:reference.stop,registers:reference.registers},sourceSha256:descriptor.sourceSha256});
 }catch(error){self.postMessage({error:error.stack??String(error)});}
};
