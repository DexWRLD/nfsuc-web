import { CRT_COOKIE_REGISTRY } from './uc-crt-cookie-registry';
import { GuestFault, type GuestAddressSpace, type GuestCpu } from './uc-process';
export interface CrtEnvironment {
  readonly provenance: 'BROWSER_COMPATIBILITY_ENVIRONMENT' | 'DETERMINISTIC_SERVICE_FIXTURE';
  readonly processId: number; readonly threadId: number;
  fileTime(): bigint; tickCount(): number; performanceCounter(): bigint;
}
let nextVirtualIdentity=1;
export function createBrowserCrtEnvironment(): CrtEnvironment {
  if(nextVirtualIdentity>0xfffffffe)throw new Error("Compatibility identity namespace exhausted");
  const processId=nextVirtualIdentity++,threadId=nextVirtualIdentity++;
  const origin=performance.now();
  return {provenance:'BROWSER_COMPATIBILITY_ENVIRONMENT',processId,threadId,
    fileTime:()=>BigInt(Date.now())*10000n+116444736000000000n,
    tickCount:()=>Math.floor(performance.now()-origin)>>>0,
    performanceCounter:()=>BigInt(Math.floor(performance.now()*1000))};
}
export class CrtCompatibilityNamespace {
  readonly calls: Record<string,unknown>[]=[];
  readonly hostWrites: {address:number;value:number;service:string}[]=[];
  constructor(readonly memory:GuestAddressSpace,readonly environment:CrtEnvironment) {
    for(const id of [environment.processId,environment.threadId])if(!Number.isInteger(id)||id<1||id>0xffffffff)throw new Error('Invalid virtual process/thread identity');
  }
  invoke(cpu:GuestCpu,target:number):boolean {
    const site=CRT_COOKIE_REGISTRY.services.find(row=>row.callsite===cpu.eip);
    if(!site)return false;
    if(target!==site.rawValue||this.memory.read32(site.cell)!==site.rawValue)throw new GuestFault(target,'compatibility','operand/target mismatch');
    for(let i=0;i<6;i++)if(this.memory.read8(site.callsite+i)!==parseInt(site.bytes.slice(i*2,i*2+2),16))throw new Error('Compatibility callsite bytes changed');
    for(let i=0;i<=site.name.length;i++)if(this.memory.read8(site.record+2+i)!==(i===site.name.length?0:site.name.charCodeAt(i)))throw new Error('Compatibility import-name record changed');
    const before=cpu.esp,ret=this.memory.read32(before);
    if(ret!==site.callsite+6)throw new GuestFault(ret,'compatibility','original return address mismatch');
    const args=site.argumentBytes?[this.memory.read32(before+4)]:[];
    const event:Record<string,unknown>={namespace:'compat.kernel32',name:site.name,callsite:site.callsite,cell:site.cell,rawEffectiveTarget:target,arguments:args,espBefore:before,returnAddress:ret,hostSubstitution:true,originalLoaderBindingObserved:false,environment:this.environment.provenance,status:'ENTERED'};
    this.calls.push(event);
    try {
      let output:bigint|undefined;
      if(site.name==='GetSystemTimeAsFileTime')output=this.environment.fileTime();
      else if(site.name==='QueryPerformanceCounter')output=this.environment.performanceCounter();
      if(output!==undefined){
        if(output<0n||output>(site.name==='GetSystemTimeAsFileTime'?0xffffffffffffffffn:0x7fffffffffffffffn))throw new Error('Invalid compatibility clock output');
        this.memory.assertWritable(args[0],8);
        const low=Number(output&0xffffffffn),high=Number(output>>32n);
        this.memory.write32(args[0],low);this.memory.write32(args[0]+4,high);
        this.hostWrites.push({address:args[0],value:low,service:site.name},{address:args[0]+4,value:high,service:site.name});
        event.output64=output.toString();event.outputWords=[low,high];
        if(site.name==='QueryPerformanceCounter')cpu.eax=1;
      }else if(site.name==='GetCurrentProcessId')cpu.eax=this.environment.processId;
      else if(site.name==='GetCurrentThreadId')cpu.eax=this.environment.threadId;
      else if(site.name==='GetTickCount'){
        const tick=this.environment.tickCount();if(!Number.isInteger(tick)||tick<0||tick>0xffffffff)throw new Error('Invalid tick count');cpu.eax=tick;
      }else throw new Error('Unsupported compatibility service');
      cpu.esp=(before+4+site.argumentBytes)>>>0;cpu.eip=ret;
      event.eax=cpu.eax;event.espAfter=cpu.esp;event.status='RETURNED';return true;
    }catch(error){event.status='FAULT';event.error=error instanceof Error?error.message:String(error);throw error;}
  }
  reset(){this.calls.length=0;this.hostWrites.length=0;}
}
