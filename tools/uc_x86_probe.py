"""Native-only bounded Unicorn/RawLifter differential feasibility experiment.

Uses an already installed DLL through its documented C API. It does not import
the incompatible Python wrapper, install packages, register a game backend,
execute unavailable sections, or resolve any imported game provider.
"""
import argparse,ctypes as C,hashlib,importlib.metadata,json,statistics,struct,subprocess,tempfile,time
from pathlib import Path
import pefile
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
from uc_browser_init import SOURCE_SHA

ROOT=Path(__file__).resolve().parents[1]
REGS={'eax':19,'ebp':20,'ebx':21,'ecx':22,'edi':23,'edx':24,'eflags':25,'eip':26,'esi':29,'esp':30}
BASE=0x0189d0a0
INITIAL=dict(eax=0xa5a5a5a5,ebx=0xb0b0b0b0,ecx=BASE,edx=0xd0d0d0d0,esi=0x51515151,edi=0xd1d1d1d1,ebp=0xebebebeb,esp=0x0300effc,eflags=0x202)
STOP=0x00dec0de

class Engine:
    def __init__(self):
        distribution=importlib.metadata.distribution('unicorn')
        self.dllPath=Path(distribution.locate_file('unicorn/lib/unicorn.dll'))
        self.version=distribution.version;self.lib=C.CDLL(str(self.dllPath));self.handle=C.c_void_p()
        definitions={'uc_open':([C.c_int,C.c_int,C.POINTER(C.c_void_p)],C.c_int),'uc_close':([C.c_void_p],C.c_int),
            'uc_mem_map':([C.c_void_p,C.c_uint64,C.c_size_t,C.c_uint32],C.c_int),
            'uc_mem_write':([C.c_void_p,C.c_uint64,C.c_void_p,C.c_size_t],C.c_int),
            'uc_mem_read':([C.c_void_p,C.c_uint64,C.c_void_p,C.c_size_t],C.c_int),
            'uc_reg_write':([C.c_void_p,C.c_int,C.c_void_p],C.c_int),'uc_reg_read':([C.c_void_p,C.c_int,C.c_void_p],C.c_int),
            'uc_emu_start':([C.c_void_p,C.c_uint64,C.c_uint64,C.c_uint64,C.c_size_t],C.c_int),
            'uc_emu_stop':([C.c_void_p],C.c_int),
            'uc_hook_add':([C.c_void_p,C.POINTER(C.c_size_t),C.c_int,C.c_void_p,C.c_void_p,C.c_uint64,C.c_uint64],C.c_int),
            'uc_strerror':([C.c_int],C.c_char_p)}
        for name,(args,result) in definitions.items():
            f=getattr(self.lib,name);f.argtypes=args;f.restype=result
        self.check(self.lib.uc_open(4,4,C.byref(self.handle)))
        self.callbacks=[];self.trace=[];self.writes=[];self.violation=None;self.allowed=set()
        callback=C.CFUNCTYPE(None,C.c_void_p,C.c_uint64,C.c_uint32,C.c_void_p)
        def instruction(_,address,size,user):
            if address not in self.allowed:
                self.violation='Instruction outside reviewed probe ranges: 0x%x'%address
                self.lib.uc_emu_stop(self.handle);return
            self.trace.append(address)
        self.callbacks.append(callback(instruction))
        self.hook(4,self.callbacks[-1])
        memcallback=C.CFUNCTYPE(None,C.c_void_p,C.c_int,C.c_uint64,C.c_int,C.c_int64,C.c_void_p)
        def write(_,kind,address,size,value,user):
            self.writes.append(dict(address=address,size=size,value=value&((1<<(size*8))-1),instruction=self.trace[-1] if self.trace else None))
        self.callbacks.append(memcallback(write));self.hook(2048,self.callbacks[-1])

    def check(self,error):
        if error:raise RuntimeError('Unicorn: '+self.lib.uc_strerror(error).decode())
    def hook(self,kind,callback):
        handle=C.c_size_t();self.check(self.lib.uc_hook_add(self.handle,C.byref(handle),kind,C.cast(callback,C.c_void_p),None,1,0))
    def map(self,address,size,permissions):self.check(self.lib.uc_mem_map(self.handle,address,size,permissions))
    def write(self,address,data):
        buffer=C.create_string_buffer(data);self.check(self.lib.uc_mem_write(self.handle,address,buffer,len(data)))
    def read(self,address,size):
        buffer=C.create_string_buffer(size);self.check(self.lib.uc_mem_read(self.handle,address,buffer,size));return buffer.raw
    def reg(self,name,value=None):
        result=C.c_uint32(value or 0)
        if value is None:self.check(self.lib.uc_reg_read(self.handle,REGS[name],C.byref(result)));return result.value
        self.check(self.lib.uc_reg_write(self.handle,REGS[name],C.byref(result)))
    def run(self,entry):
        self.trace.clear();self.writes.clear();self.violation=None
        # A fixed instruction budget avoids the native API's per-run timeout
        # thread/timer overhead dominating this tiny deterministic experiment.
        self.check(self.lib.uc_emu_start(self.handle,entry,STOP,0,10000))
        if self.violation:raise RuntimeError(self.violation)
        if self.reg('eip')!=STOP:raise RuntimeError('Probe did not return within instruction budget')
    def close(self):self.check(self.lib.uc_close(self.handle))

def prototype(image,assetRoot,output):
    raw=image.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SOURCE_SHA:raise ValueError('Original executable SHA mismatch')
    pe=pefile.PE(data=raw)
    registry=json.loads((ROOT/'tools/uc_unified_registry.json').read_text(encoding='utf-8'))
    entries=[e for e in registry['bindings'] if e['address'] in [0x9e7540,0x9e75a0,0x9c1830]]
    if len(entries)!=3:raise ValueError('Reviewed constructor bodies missing')
    engine=Engine();ranges=[];mapped=set()
    try:
        for entry in entries:
            start,last=[int(v,16) for v in entry['verifiedBodyRange']];data=pe.get_data(start-0x400000,last-start+1)
            if not data or last>=0x00b61000 or start<0x00401000:raise ValueError('Probe outside ordinary text')
            page=start&~0xfff
            if page not in mapped:engine.map(page,0x1000,5);mapped.add(page)
            engine.write(start,data)
            engine.allowed.update(i.address for i in Cs(CS_ARCH_X86,CS_MODE_32).disasm(data,start))
            ranges.append(dict(start=start,end=last,sha256=hashlib.sha256(data).hexdigest()))
        engine.map(BASE&~0xfff,0x1000,3);engine.map(0x0300e000,0x2000,3)
        engine.write(BASE,b'\xa5'*128);engine.write(INITIAL['esp'],struct.pack('<I',STOP))
        for name,value in INITIAL.items():engine.reg(name,value)
        engine.run(0x9e7540)
        cold=dict(registers={name:engine.reg(name) for name in REGS},dataHex=engine.read(BASE,128).hex(),
            instructions=list(engine.trace),globalWrites=[w for w in engine.writes if BASE<=w['address']<BASE+128])
        cold['functionEntries']=[address for address in engine.trace if address in [0x9e7540,0x9e75a0,0x9c1830]]
        if len(cold['globalWrites'])!=27:raise ValueError('Original write count mismatch')
        # Both sides retain instruction/write instrumentation. These are host-
        # boundary-inclusive fixture timings, not comparative browser FPS.
        def invoke():
            engine.reg('esp',INITIAL['esp']);engine.reg('ecx',BASE);engine.run(0x9e7540)
        for _ in range(50):invoke()
        batches=[]
        for _ in range(7):
            before=time.perf_counter_ns()
            for _ in range(100):invoke()
            batches.append((time.perf_counter_ns()-before)/100/1000)
        nativeTiming=dict(unit='microseconds_per_instrumented_call',batchMeans=batches,median=statistics.median(batches),minimum=min(batches),maximum=max(batches),iterationsPerBatch=100,warmup=50)
        # Fail closed on same-page bytes outside the exact reviewed functions.
        engine.reg('esp',INITIAL['esp'])
        try:engine.run(0x9e7000)
        except RuntimeError as error:codeGuard=str(error)
        else:raise ValueError('Instruction-range guard failed')
        dll=dict(path=str(engine.dllPath),packageVersion=engine.version,sha256=hashlib.sha256(engine.dllPath.read_bytes()).hexdigest(),api='installed native C API; Python wrapper incompatible with Python 3.12',license='Upstream Unicorn 2.0.1 GPL-2.0; API headers/bindings have separate LGPL notices; no engine redistributed')
    finally:engine.close()
    arithmetic=[]
    for op,encoding in [(0,b'\x01\xd8'),(1,b'\x29\xd8'),(2,b'\xf7\xd8'),(3,b'\x48'),(4,b'\x19\xd8')]:
        for a in [0,1,0x7fffffff,0x80000000,0xffffffff]:
            for b in [0,1,0xffffffff]:
                for carry in ([0,1] if op in [3,4] else [0]):
                    e=Engine()
                    try:
                        # SUB ECX,EDX derives incoming carry. No host flag injection.
                        code=b'\xb9'+struct.pack('<I',0)+b'\xba'+struct.pack('<I',carry)+b'\x29\xd1'+b'\xb8'+struct.pack('<I',a)+b'\xbb'+struct.pack('<I',b)+encoding+b'\xc3'
                        e.map(0x01000000,0x1000,5);e.write(0x01000000,code);e.allowed={i.address for i in Cs(CS_ARCH_X86,CS_MODE_32).disasm(code,0x01000000)}
                        e.map(0x0300e000,0x2000,3);e.write(INITIAL['esp'],struct.pack('<I',STOP));e.reg('esp',INITIAL['esp']);e.reg('eflags',0x202);e.run(0x01000000)
                        arithmetic.append(dict(op=op,a=a,b=b,carry=carry,result=e.reg('eax'),flags=e.reg('eflags')&0x8d5,classification='SYNTHETIC_ARITHMETIC_INSTRUCTIONS'))
                    finally:e.close()
    native=dict(sourceSha256=SOURCE_SHA,engine=dll,originalRanges=ranges,initialRegisters=INITIAL,cold=cold,arithmetic=arithmetic,nativeTiming=nativeTiming,codeGuard=codeGuard,
        classification='NATIVE_ONLY_DIFFERENTIAL_CONSTRUCTOR_FIXTURE_NOT_STARTUP',browserBackendInstalled=False,importsExecuted=[],protectedRegionsMapped=False)
    with tempfile.TemporaryDirectory() as temp:
        incoming=Path(temp)/'native.json';result=Path(temp)/'compared.json'
        incoming.write_text(json.dumps(native),encoding='utf-8')
        subprocess.run(['node',str(ROOT/'web/tools/uc-x86-reference.mjs'),str(incoming),str(assetRoot),str(result)],check=True,cwd=ROOT/'web')
        comparison=json.loads(result.read_text(encoding='utf-8'))
    output.write_text(json.dumps(comparison,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(originalInstructions=len(cold['instructions']),originalWrites=len(cold['globalWrites']),arithmeticCases=len(arithmetic),comparison=comparison['comparison'])))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('image',type=Path);p.add_argument('asset_root',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args();prototype(a.image,a.asset_root,a.output)
