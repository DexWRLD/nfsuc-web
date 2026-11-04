"""Reviewed cookie-only extension. No original import cells or source bytes are changed."""
import hashlib,json,re,struct
from pathlib import Path
import pefile
import lift
ROOT=Path(__file__).resolve().parents[1]
ENTRY=0x87c264;END=0x87c2f8
SITES=[(0x87c299,0xb611a0,'GetSystemTimeAsFileTime',4),(0x87c2a5,0xb610cc,'GetCurrentProcessId',0),(0x87c2ad,0xb611e0,'GetCurrentThreadId',0),(0x87c2b5,0xb611d0,'GetTickCount',0),(0x87c2c1,0xb611f8,'QueryPerformanceCounter',4)]
def source(raw,info):
 pe=pefile.PE(data=raw);data=pe.get_data(ENTRY-0x400000,END-ENTRY)
 body,calls=lift.RawLifter(data,ENTRY,comments=True).lift(ENTRY)
 starts={i.address for i in lift.Cs(lift.CS_ARCH_X86,lift.CS_MODE_32).disasm(data,ENTRY)}
 if len(starts)!=52 or calls or starts!={int(a,16) for a in re.findall(r'/\* ([0-9a-f]{8})  ',body)}:raise ValueError('Cookie body coverage mismatch')
 names=[]
 for site,cell,name,args in SITES:
  code=pe.get_data(site-0x400000,6)
  if code!=b'\xff\x15'+struct.pack('<I',cell):raise ValueError('Cookie callsite mismatch')
  value=struct.unpack('<I',pe.get_data(cell-0x400000,4))[0]
  if pe.get_string_at_rva(value+2).decode()!=name:raise ValueError('Cookie name record mismatch')
  providers=[g.dll.decode() for g in pe.DIRECTORY_ENTRY_IMPORT for i in g.imports if i.name and i.name.decode()==name]
  names.append(dict(callsite=site,cell=cell,rawValue=value,name=name,record=0x400000+value,argumentBytes=args,convention='stdcall',bytes=code.hex(),advertisedProviders=providers,originalEffectiveBindingVerified=False))
 # Keep the first unsupported shift as an instruction-tagged trap, on its original branch.
 body=re.sub(r'(/\* 0087c2e0  shl eax, 0x10 \*/\n)[^\n]+',r'\1    __builtin_trap(); /* unsupported checked shift flags; no replacement result */',body)
 admitted={'mov','lea','push','pop','call','ret','jmp','add','sub','cmp','test','xor','and','or','neg','sbb','inc','dec','not','leave','shl'}|{'j'+c for c in lift.CC}
 if set(re.findall(r'/\* [0-9a-f]{8}  (\S+)',body))-admitted:raise ValueError('Unsupported cookie instruction')
 if 'SETZSP' in body:raise ValueError('Shift must remain trapped')
 body=re.sub(r'MR32\(([^;\n]+?)\) = \(([^;\n]+?)\);',r'write32(\1, \2);',body)
 body=re.sub(r'(/\* ([0-9a-f]{8})  .*?\*/)',lambda m:m[1]+f'\n    instruction(0x{m[2]}u);',body)
 return body,dict(entry=ENTRY,end=END,bodySha256=hashlib.sha256(data).hexdigest(),instructionStarts=sorted(starts),instructionCount=52,services=names,unsupportedInstruction=0x87c2e0,classification='HOST_SCHEDULED_DIAGNOSTIC_NOT_ORIGINAL_PE_STARTUP')
def metadata(meta,module):
 meta['moduleSha256']=hashlib.sha256(module.read_bytes()).hexdigest();meta['sourceSha256']='6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd';meta['normalBindingsUnchanged']=14
 (ROOT/'web/src/host/uc-crt-cookie-registry.ts').write_text('// Generated reviewed diagnostic metadata only. No callable import targets.\nexport const CRT_COOKIE_REGISTRY = '+json.dumps(meta,indent=2)+' as const;\n',encoding='utf-8')
 (ROOT/'analysis/undercover/crt-cookie-evidence-phase75.json').write_text(json.dumps(meta,indent=2)+'\n',encoding='utf-8')
