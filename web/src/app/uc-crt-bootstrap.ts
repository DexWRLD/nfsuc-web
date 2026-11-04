import {createUndercoverProcess, type CrtDiagnosticOptions} from '../host/uc-unified';
import {createBrowserCrtEnvironment} from '../host/uc-crt-services';
import {CRT_COOKIE_REGISTRY} from '../host/uc-crt-cookie-registry';
import {UcDownloadManager} from './uc-download-manager';
import {MemoryAssetStore,openOpfsAssetStore} from './uc-asset-cache';

export async function runCrtBootstrap(module:Uint8Array,mode:CrtDiagnosticOptions['mode'],signal:AbortSignal){
 const store=await openOpfsAssetStore().catch(()=>new MemoryAssetStore()),manager=new UcDownloadManager({store,pageOrigin:location.origin});
 const manifest=await manager.loadManifest('/uc-asset-manifest.json'),files:Uint8Array[]=[];
 for(const path of ['uc-unified-image.json','uc-unified-image.bin','uc-unified.wasm']){
  signal.throwIfAborted();const entry=manifest.assets.find(e=>e.path===path);if(!entry)throw new Error('Existing private asset unavailable: '+path);
  const bytes=await manager.ensureAsset(manifest,entry,signal);if(!bytes)throw new Error('Verified asset missing');files.push(bytes);
 }
 const environment=createBrowserCrtEnvironment(),description=JSON.parse(new TextDecoder().decode(files[0]));
 const g=await createUndercoverProcess(description,files[1],files[2],undefined,{module,mode,environment});
 const before={cookie:g.memory.read32(0x1285688),complement:g.memory.read32(0x128568c)};
 const importBefore=CRT_COOKIE_REGISTRY.services.map(s=>({cell:s.cell,value:g.memory.read32(s.cell)}));
 const started=performance.now();let error='',cookieReturned=false,startupEntered=false,startupStopped=false;
 try{g.call(CRT_COOKIE_REGISTRY.entry);cookieReturned=true;}catch(e){error=e instanceof Error?e.message:String(e);}
 let thread=null;
 const threadWrites:{address:number;value:number;source:string}[]=[];
 if(cookieReturned&&mode==='compatibility-crt'){
  thread=g.threads.initializeWindowsCompatible(environment.processId,environment.threadId);
  for(const offset of [0,4,8,0x18])threadWrites.push({address:0x03100000+offset,value:g.memory.read32(0x03100000+offset),source:'HOST_WINDOWS_COMPATIBLE_NT_TIB32'});
  const cookieServices=(g.compatibility?.calls.length)??0;
  try{
   startupEntered=true;
   g.call(CRT_COOKIE_REGISTRY.startup.entry);
   startupStopped=false;
  }catch(e){
   startupStopped=true;
   error=e instanceof Error?e.message:String(e);
  }
  // Preserve cookie-service count for reporting; startup may add ICE.
  void cookieServices;
 }
 const startupState=g.memory.read32(0x018b1e58),startupOwner=g.memory.read32(0x018b1e5c);
 const ice=g.compatibility?.calls.filter(c=>c.name==='InterlockedCompareExchange')??[];
 const reachedInitterm=startupEntered&&/0x8aac|0x87c232|0xb613b4|initterm|dispatch/i.test(error);
 return {mode,classification:mode==='compatibility-crt'?'COMPATIBILITY_HOSTED_CRT_BOOTSTRAP':'ORIGINAL_ONLY_DIAGNOSTIC',
  entry:startupEntered?CRT_COOKIE_REGISTRY.startup.entry:CRT_COOKIE_REGISTRY.entry,hostScheduled:true,
  cookieEntry:CRT_COOKIE_REGISTRY.entry,startupEntry:CRT_COOKIE_REGISTRY.startup.entry,
  sourceSha256:description.sourceSha256,diagnosticModuleSha256:CRT_COOKIE_REGISTRY.moduleSha256,originalPeEntryExecuted:false,originalLoaderBindingObserved:false,
  before,after:{cookie:g.memory.read32(0x1285688),complement:g.memory.read32(0x128568c)},cookieReturned,cookieComputedByOriginalCode:cookieReturned&&!!g.compatibility?.calls.some(c=>c.name==='GetSystemTimeAsFileTime'),
  startupPrefixEntered:startupEntered,startupPrefixStoppedAtUnsupported:startupStopped,
  originalInstructions:[...g.instructions],originalFunctionsEntered:g.dispatcher.trace.filter(e=>e.kind==='enter').map(e=>e.address),trace:[...g.dispatcher.trace],registers:{...g.cpu},flagsKnown:g.snapshot().flagsKnown,
  hostServices:g.compatibility?.calls??[],originalMemoryWrites:[...g.writeLog],hostEnvironmentWrites:[{address:0x0300effc,value:0x00dec0de,source:'HOST_DIAGNOSTIC_RETURN_FRAME'},...(g.compatibility?.hostWrites??[]),...threadWrites],
  syntheticThreadDependencies:thread,virtualProcess:{processId:environment.processId,threadId:environment.threadId,provenance:environment.provenance,bootEpoch:'Compatibility environment creation',qpcFrequency:1000000},
  importValuesUnchanged:importBefore.every(s=>g.memory.read32(s.cell)===s.value),cleanupProvider:g.memory.read32(0x00b61398),
  startupState,startupOwner,cleanupGlobals:[g.memory.read32(0x018b1e68),g.memory.read32(0x018b1e6c)],
  cInitializerCells:[0,1,2,3].map(i=>({cell:0x00b63dc4+i*4,value:g.memory.read32(0x00b63dc4+i*4)})),
  interlockedCompareExchange:ice,
  milestones:{securityCookie:cookieReturned,compatibilityThread:thread!==null,crtStartupRoutine:startupEntered&&startupState===1&&startupOwner===0x03010000,cInitializers:false,cppConstructors:false,cleanupRegistration:false,fullGameBoot:false},
  lastInstruction:g.lastInstruction,exactStopAddress:g.lastInstruction||g.cpu.eip,
  firstUnsupportedDependency:reachedInitterm
   ? '0x0087C232 -> legacy [0x00B613B4] (_initterm_e); C initializer walker not implemented'
   : (cookieReturned&&!startupEntered?'0x0087BB3D not entered':error),
  stopReason:reachedInitterm?'CRT_STARTUP_PREFIX_STOP_AT_INITTERM_E':(cookieReturned&&!startupEntered?'COOKIE_ROUTINE_RETURNED':error),
  nextUnadmittedEntry:reachedInitterm?0x0087bcb3:null,
  durationMs:performance.now()-started,distribution:'User-selected local diagnostic module; existing private asset manifest unchanged'};
}
