"""Emit instruction-admission metadata, never commercial instruction bytes."""
import json,hashlib,argparse
from pathlib import Path
import pefile
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
from capstone import x86_const as xc
ROOT=Path(__file__).resolve().parents[1]
SHA='6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd'
def generate(image):
 raw=image.read_bytes()
 if hashlib.sha256(raw).hexdigest()!=SHA:raise ValueError('Source SHA mismatch')
 pe=pefile.PE(data=raw);registry=json.loads((ROOT/'tools/uc_unified_registry.json').read_text())
 selected={0xb57dc0,0x9e7540,0x9e75a0,0x9c1830,0x87b640,0x87b59b,0x87beb8};rows=[];ranges=[]
 for b in registry['bindings']:
  if b['address'] not in selected:continue
  start,last=[int(x,16) for x in b['verifiedBodyRange']];data=pe.get_data(start-0x400000,last-start+1)
  ranges.append(dict(start=start,end=last,sha256=hashlib.sha256(data).hexdigest()))
  decoder=Cs(CS_ARCH_X86,CS_MODE_32);decoder.detail=True
  for i in decoder.disasm(data,start):
   defined=undefined=required=0
   for bit,flag in enumerate(['CF','PF','AF','ZF','SF','OF']):
    for effect in ['MODIFY','RESET','SET']:
     if i.eflags & getattr(xc,'X86_EFLAGS_'+effect+'_'+flag,0):defined|=1<<bit
    if i.eflags & getattr(xc,'X86_EFLAGS_UNDEFINED_'+flag,0):undefined|=1<<bit
    if i.eflags & getattr(xc,'X86_EFLAGS_TEST_'+flag,0):required|=1<<bit
   rows.append(dict(address=i.address,size=i.size,flagsDefined=defined,flagsUndefined=undefined,flagsRequired=required,flow='call' if i.mnemonic=='call' else 'ret' if i.mnemonic.startswith('ret') else 'other',function=b['address']))
 return dict(sourceSha256=SHA,classification='REVIEWED_RANGES_NOT_STARTUP_REACHABILITY',ranges=ranges,instructions=rows)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('image',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.write_text(json.dumps(generate(a.image),indent=2)+'\n')
