"""Reviewed CRT diagnostic extension: cookie body plus bounded startup prefix.

No original import cells or source bytes are changed. Startup admission ends at the
exclusive bound before post-call continuation so coverage stays exact; the first
unsupported dependency on the zero-state path is the _initterm_e stub at 0x0087C232.
"""
import hashlib,json,re,struct
from pathlib import Path
import pefile
import lift
ROOT=Path(__file__).resolve().parents[1]
COOKIE_ENTRY=0x87c264;COOKIE_END=0x87c2f8
STARTUP_ENTRY=0x87bb3d;STARTUP_END=0x87bbfa  # exclusive; covers zero-state path through initterm call and internal joins
COOKIE_SITES=[(0x87c299,0xb611a0,'GetSystemTimeAsFileTime',4),(0x87c2a5,0xb610cc,'GetCurrentProcessId',0),(0x87c2ad,0xb611e0,'GetCurrentThreadId',0),(0x87c2b5,0xb611d0,'GetTickCount',0),(0x87c2c1,0xb611f8,'QueryPerformanceCounter',4)]
STARTUP_SITES=[(0x87bb62,0xb611b4,'InterlockedCompareExchange',12)]
ADMITTED={'mov','lea','push','pop','call','ret','jmp','add','sub','cmp','test','xor','and','or','neg','sbb','inc','dec','not','leave','shl'}|{'j'+c for c in lift.CC}

def _name_sites(pe,sites):
 names=[]
 for site,cell,name,args in sites:
  code=pe.get_data(site-0x400000,6)
  if code!=b'\xff\x15'+struct.pack('<I',cell):raise ValueError(f'{name} callsite mismatch')
  value=struct.unpack('<I',pe.get_data(cell-0x400000,4))[0]
  if pe.get_string_at_rva(value+2).decode()!=name:raise ValueError(f'{name} name record mismatch')
  providers=[g.dll.decode() for g in pe.DIRECTORY_ENTRY_IMPORT for i in g.imports if i.name and i.name.decode()==name]
  names.append(dict(callsite=site,cell=cell,rawValue=value,name=name,record=0x400000+value,argumentBytes=args,convention='stdcall',bytes=code.hex(),advertisedProviders=providers,originalEffectiveBindingVerified=False))
 return names

def _lift_window(pe,entry,end,label):
 data=pe.get_data(entry-0x400000,end-entry)
 body,calls=lift.RawLifter(data,entry,comments=True).lift(entry)
 starts={i.address for i in lift.Cs(lift.CS_ARCH_X86,lift.CS_MODE_32).disasm(data,entry)}
 translated={int(a,16) for a in re.findall(r'/\* ([0-9a-f]{8})  ',body)}
 if starts!=translated:raise ValueError(f'{label} body coverage mismatch')
 ops=set(re.findall(r'/\* [0-9a-f]{8}  (\S+)',body))
 if ops-ADMITTED:raise ValueError(f'{label} unsupported instruction {ops-ADMITTED}')
 return data,body,calls,sorted(starts)

def source(raw,info):
 pe=pefile.PE(data=raw)
 cookie_data,cookie_body,cookie_calls,cookie_starts=_lift_window(pe,COOKIE_ENTRY,COOKIE_END,'cookie')
 if cookie_calls or len(cookie_starts)!=52:raise ValueError('Cookie body coverage mismatch')
 # Keep the first unsupported shift as an instruction-tagged trap, on its original branch.
 cookie_body=re.sub(r'(/\* 0087c2e0  shl eax, 0x10 \*/\n)[^\n]+',r'\1    __builtin_trap(); /* unsupported checked shift flags; no replacement result */',cookie_body)
 if 'SETZSP' in cookie_body:raise ValueError('Shift must remain trapped')
 startup_data,startup_body,startup_calls,startup_starts=_lift_window(pe,STARTUP_ENTRY,STARTUP_END,'startup')
 if set(startup_calls)!={0x87beb8,0x87c09a,0x87c22c,0x87c232}:raise ValueError(f'Unexpected startup calls {startup_calls}')
 if 'fs_base+0x18' not in startup_body:raise ValueError('Startup FS:[0x18] access missing')
 startup_body=startup_body.replace('MR32(c->fs_base+0x18u)','readFs32(0x18u)')
 if 'fs_base' in startup_body:raise ValueError('Unreviewed startup segment access')
 bodies=[]
 for body in (cookie_body,startup_body):
  body=re.sub(r'dispatch_indirect\(c, ([^;]+?)\)',r'dispatch(\1)',body)
  body=re.sub(r'DISPATCH_TAIL\(c, ([^;]+?)\)',r'dispatch(\1)',body)
  body=re.sub(r'unsupported_insn\(c, ([^;]+?), "[^"]*"\)',r'__builtin_trap()',body)
  body=re.sub(r'MR32\(([^;\n]+?)\) = \(([^;\n]+?)\);',r'write32(\1, \2);',body)
  body=re.sub(r'(/\* ([0-9a-f]{8})  .*?\*/)',lambda m:m[1]+f'\n    instruction(0x{m[2]}u);',body)
  if 'dispatch_indirect' in body or 'DISPATCH_TAIL' in body or 'unsupported_insn' in body:
   raise ValueError('Untransformed startup/cookie dispatch helper remains')
  bodies.append(body)
 services=_name_sites(pe,COOKIE_SITES)+_name_sites(pe,STARTUP_SITES)
 meta=dict(
  entry=COOKIE_ENTRY,end=COOKIE_END,
  bodySha256=hashlib.sha256(cookie_data).hexdigest(),
  instructionStarts=cookie_starts,instructionCount=len(cookie_starts),
  startup=dict(
   entry=STARTUP_ENTRY,endExclusive=STARTUP_END,
   bodySha256=hashlib.sha256(startup_data).hexdigest(),
   instructionStarts=startup_starts,instructionCount=len(startup_starts),
   sehProlog=dict(size=0x10,scope=0x00ca93f8,callsite=0x87bb44,target=0x87beb8),
   fsSelfRead=0x87bb4e,ownerTokenRead=0x87bb54,
   firstSynchronization=dict(callsite=0x87bb62,cell=0xb611b4,name='InterlockedCompareExchange'),
   firstUnsupportedDependency=dict(callsite=0x87bbb4,target=0x87c232,name='_initterm_e stub via legacy 0x00B613B4'),
   classification='HOST_SCHEDULED_BOUNDED_CRT_STARTUP_PREFIX'),
  services=services,unsupportedInstruction=0x87c2e0,
  classification='HOST_SCHEDULED_DIAGNOSTIC_NOT_ORIGINAL_PE_STARTUP')
 return ''.join(bodies),meta

def metadata(meta,module):
 meta['moduleSha256']=hashlib.sha256(module.read_bytes()).hexdigest()
 meta['sourceSha256']='6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd'
 meta['normalBindingsUnchanged']=14
 meta['diagnosticBodies']=16
 (ROOT/'web/src/host/uc-crt-cookie-registry.ts').write_text(
  '// Generated reviewed diagnostic metadata only. No callable import targets.\n'
  'export const CRT_COOKIE_REGISTRY = '+json.dumps(meta,indent=2)+' as const;\n',encoding='utf-8')
 retained={k:meta[k] for k in (
  'entry','end','bodySha256','instructionStarts','instructionCount',
  'unsupportedInstruction','classification','moduleSha256','sourceSha256','normalBindingsUnchanged'
 ) if k in meta}
 retained['services']=[s for s in meta['services'] if s['name']!='InterlockedCompareExchange']
 retained['note']='Phase 75 cookie subset retained; startup fields live in crt-startup-contract-phase76.json'
 (ROOT/'analysis/undercover/crt-cookie-evidence-phase75.json').write_text(json.dumps(retained,indent=2)+'\n',encoding='utf-8')
