// Opt-in Phase 72 experiment. Engine is injected; no third-party code in the app bundle.
// One canonical guest process. Private CPU pages are synchronized and checked per instruction.
export async function runBrowserX86(g, uc, admission, options={}) {
 const limits={instructions:10000,depth:64,writes:2000,accessBytes:65536,wallMs:1000,transitions:100000,...options};
 for(const value of Object.values(limits))if(!Number.isSafeInteger(value)||value<1)throw new Error('Invalid execution budget');
 const started=performance.now();
 if(admission.sourceSha256!==g.registry.sourceSha256)throw new Error('Admission source mismatch');
 for(const row of admission.ranges){
  const bytes=new Uint8Array(row.end-row.start+1);for(let i=0;i<bytes.length;i++)bytes[i]=g.memory.read8(row.start+i);
  const hash=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))).map(b=>b.toString(16).padStart(2,'0')).join('');
  if(hash!==row.sha256)throw new Error('Admission code digest mismatch');
 }
 const e=new uc.Unicorn(uc.ARCH_X86,uc.MODE_32);
 const regs=['eax','ebx','ecx','edx','esi','edi','ebp','esp','eip'];
 const get=name=>e.reg_read_i32(uc['X86_REG_'+name.toUpperCase()])>>>0;
 const put=(name,value)=>e.reg_write_i32(uc['X86_REG_'+name.toUpperCase()],value);
 const allowed=new Map(admission.instructions.map(i=>[i.address,i]));
 const entries=new Set(admission.ranges.map(r=>r.start));
 const mapped=new Set(),executedInstructionAddresses=[],instructions=[],writes=[],reads=[],trace=[],states=[];
 let flagsKnown=g.snapshot().flagsKnown,transitions=0,accessBytes=0,current=0,pending=null,rawEngineStopEip=null,stop='',fsConfigured=false;
 const frames=[], hooks=[];
 function budget(){if(++transitions>limits.transitions)throw new Error('BUDGET_TRANSITIONS');if(performance.now()-started>limits.wallMs)throw new Error('BUDGET_WALL');}
 function range(address,size){if(!Number.isSafeInteger(address)||address<0||!Number.isSafeInteger(size)||size<1||address+size>0x100000000)throw new Error('INVALID_ACCESS_RANGE');if((accessBytes+=size)>limits.accessBytes)throw new Error('BUDGET_ACCESS_BYTES');}
 function canonical(address,size){const bytes=new Uint8Array(size);for(let i=0;i<size;i++)bytes[i]=g.memory.read8(address+i);return bytes;}
 function map(address){const page=address&~4095;if(mapped.has(page))return;const data=new Uint8Array(4096);for(let i=0;i<4096;i++){try{data[i]=g.memory.read8(page+i);}catch{}}
  e.mem_map(page,4096,uc.PROT_ALL);e.mem_write(page,data);mapped.add(page);
 }
 function fail(error){pending=error instanceof Error?error:new Error(String(error));e.emu_stop();}
 function readState(address){const cpu=Object.fromEntries(regs.map(n=>[n,get(n)]));cpu.eip=address;cpu.eflags=get('eflags')&0x8d5;return cpu;}
 try {
  // Load a synthetic GDT solely for the explicit existing generic FS fixture.
  // This page is engine infrastructure; game access remains denied by canonical checks.
  const base=g.threads.snapshot().fsBase;
  if(base!==null){
   const table=0x03102000, bytes=new Uint8Array(4096),v=new DataView(bytes.buffer),descriptor=8;
   v.setUint16(descriptor,0xfff,true);v.setUint16(descriptor+2,base&65535,true);bytes[descriptor+4]=(base>>>16)&255;bytes[descriptor+5]=0x93;bytes[descriptor+6]=0x40;bytes[descriptor+7]=base>>>24;
   for(const [offset,access] of [[16,0x93],[24,0x9b]]){v.setUint16(offset,0xffff,true);bytes[offset+5]=access;bytes[offset+6]=0xcf;}
   e.mem_map(table,4096,uc.PROT_READ);e.mem_write(table,bytes);
   const gdtr=new Uint8Array(24),dv=new DataView(gdtr.buffer);dv.setBigUint64(8,BigInt(table),true);dv.setUint32(16,31,true);
   e.reg_write(uc.X86_REG_GDTR,gdtr);for(const name of ['DS','ES','SS'])e.reg_write_i32(uc['X86_REG_'+name],0x10);e.reg_write_i32(uc.X86_REG_CS,0x18);e.reg_write_i32(uc.X86_REG_FS,0x08);fsConfigured=true;
  }
  for(const row of admission.instructions)map(row.address);
  for(const name of regs)put(name,g.cpu[name]);put('eflags',g.cpu.eflags|2);
  // Same synthetic root call contract as GuestDispatcher.call, without calling translated code.
  g.cpu.esp=0x0300effc;g.memory.write32(g.cpu.esp,0x00dec0de);put('esp',g.cpu.esp);put('eip',0x00b57dc0);
  frames.push({address:0x00b57dc0,returnAddress:0x00dec0de});trace.push({kind:'enter',address:0x00b57dc0,esp:get('esp')});
  hooks.push(e.hook_add(uc.HOOK_CODE,(_,address)=>{try{budget();const pc=Number(address);if(pc!==current||!allowed.has(pc))throw new Error('UNSUPPORTED_EXECUTION');executedInstructionAddresses.push(pc);}catch(error){fail(error);}}));
  hooks.push(e.hook_add(uc.HOOK_MEM_READ,(_,kind,raw,size)=>{try{budget();const address=Number(raw);range(address,size);const expected=canonical(address,size);if(address===base&&size===4)g.threads.read(0);const actual=e.mem_read(address,size);if(actual.some((b,i)=>b!==expected[i]))throw new Error('DIVERGING_GUEST_READ');reads.push({address,size,instruction:current,value:size===4?new DataView(expected.buffer).getUint32(0,true):Number(BigInt('0x'+Array.from(expected).reverse().map(b=>b.toString(16).padStart(2,'0')).join('')))});}catch(error){fail(error);}}));
  hooks.push(e.hook_add(uc.HOOK_MEM_WRITE,(_,kind,raw,size,rawValue)=>{try{budget();const address=Number(raw);range(address,size);if(writes.length>=limits.writes)throw new Error('BUDGET_WRITES');const value=Number(BigInt.asUintN(size*8,BigInt(rawValue)));
   // Validate full original-width access before changing canonical state.
   if(size!==1&&size!==4)throw new Error('UNSUPPORTED_WRITE_WIDTH');
   if(address===base&&size===4)g.threads.write(0,value);
   else if(size===4)g.memory.write32(address,value);else g.memory.write8(address,value);
   writes.push({address,size,value,instruction:current});
  }catch(error){fail(error);}}));
  hooks.push(e.hook_add(uc.HOOK_MEM_READ_UNMAPPED|uc.HOOK_MEM_WRITE_UNMAPPED,(_,kind,raw,size)=>{try{budget();const address=Number(raw);canonical(address,size);map(address);if((address&4095)+size>4096)map(address+size-1);return true;}catch(error){fail(error);return false;}}));
  while(true){
   budget();if(instructions.length>=limits.instructions)throw new Error('BUDGET_INSTRUCTIONS');
   const pc=get('eip'),ins=allowed.get(pc);if(!ins)throw new Error('UNSUPPORTED_INSTRUCTION_ADDRESS 0x'+pc.toString(16));
   g.memory.assertExecutable(pc);canonical(pc,ins.size);map(pc);if((pc&4095)+ins.size>4096)map(pc+ins.size-1);
   const source=canonical(pc,ins.size),mirror=e.mem_read(pc,ins.size);if(mirror.some((b,i)=>b!==source[i]))throw new Error('DIVERGING_CODE_BYTES');
   if((flagsKnown&ins.flagsRequired)!==ins.flagsRequired)throw new Error('UNDEFINED_FLAGS_CONSUMED');
   current=pc;states.push({cpu:readState(pc),flagsKnown});instructions.push(pc);
   try{e.emu_start(pc,0xffffffff,0,1);}catch(error){const target=get('eip');if(!pending&&ins.flow==='call'&&target!==pc&&!entries.has(target)){rawEngineStopEip=target;put('eip',pc);throw new Error('dispatch at 0x'+target.toString(16)+': unavailable');}throw pending??error;}
   if(pending)throw pending;
   flagsKnown=(flagsKnown|ins.flagsDefined)&~ins.flagsUndefined;
   const next=get('eip');
   if(ins.flow==='call'){
    const returnAddress=pc+ins.size;
    if(!entries.has(next)){rawEngineStopEip=next;put('eip',pc);throw new Error('dispatch at 0x'+next.toString(16)+': unavailable');}
    if(frames.length>=limits.depth)throw new Error('BUDGET_CALL_DEPTH');
    if(g.memory.read32(get('esp'))!==returnAddress)throw new Error('CALL_RETURN_ADDRESS_MISMATCH');
    frames.push({address:next,returnAddress});trace.push({kind:'enter',address:next,esp:get('esp'),callsite:pc,returnAddress});
   } else if(next===frames.at(-1)?.returnAddress){
    const frame=frames.pop();trace.push({kind:'return',address:frame.address,esp:get('esp')});
    if(!frames.length){stop='RETURNED';break;}
   }
   // Cooperative yielding bounds the normal main-thread slice if used without a worker.
   if(instructions.length%32===0)await new Promise(resolve=>setTimeout(resolve,0));
  }
 }catch(error){stop=error instanceof Error?error.message:String(error);}
 finally{
  for(const name of regs)g.cpu[name]=get(name);g.cpu.eflags=get('eflags')&0x8d5;
  for(const hook of hooks)e.hook_del(hook);
  e.close();
 }
 return {rawEngineStopEip,executedInstructionAddresses,flagsKnown,instructions,states,reads,writes,trace,registers:{...g.cpu},stop,fs:g.threads.snapshot(),fsAccesses:[...g.threads.accesses],fsConfigured,transitions,accessBytes,mappedBytes:mapped.size*4096,durationMs:performance.now()-started,engineMemoryBytes:uc.HEAPU8?.buffer.byteLength??null,limits,classification:'ORIGINAL_BYTES_EXPLICIT_SYNTHETIC_THREAD_NOT_STARTUP'};
}
