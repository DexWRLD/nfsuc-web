"""Verify independent SEH instruction appendix and record exact recovery overrides."""
import argparse,hashlib,json,re
from pathlib import Path
import pefile
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
from uc_browser_init import SOURCE_SHA

def inspect(image,research):
    raw=image.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SOURCE_SHA:raise ValueError('Original SHA mismatch')
    pe=pefile.PE(data=raw)
    read=lambda a,n:pe.get_data(a-pe.OPTIONAL_HEADER.ImageBase,n)
    appendix=research.read_text(encoding='utf-8')
    verified={}
    for addr,encoding in re.findall(r'^\| ([0-9a-f]{8}) \| ([0-9a-f]+) \|',appendix,re.M):
        address=int(addr,16);expected=bytes.fromhex(encoding)
        if read(address,len(expected))!=expected:raise ValueError('Research byte mismatch at '+addr)
        verified[address]=encoding
    regions=[]
    for start,end,name in [(0x87b59b,0x87b637,'registrar normal flow'),(0x87beb8,0x87befd,'SEH prolog'),(0x87befd,0x87bf11,'SEH epilog'),(0x87b637,0x87b640,'separate finally outline')]:
        data=read(start,end-start)
        instructions=[]
        for i in Cs(CS_ARCH_X86,CS_MODE_32).disasm(data,start):
            if start!=0x87b637 and i.address not in verified:raise ValueError('Missing independent instruction evidence')
            instructions.append(dict(address=f'0x{i.address:08X}',bytes=i.bytes.hex(),instruction=i.mnemonic+' '+i.op_str,
                fallthrough=f'0x{i.address+i.size:08X}' if i.mnemonic not in ('ret','jmp') else None,
                directTarget=i.op_str if i.mnemonic in ('call','jmp','jne') and i.op_str.startswith('0x') else None))
        if sum(len(bytes.fromhex(i['bytes'])) for i in instructions)!=len(data):raise ValueError('Instruction coverage gap')
        if start==0x87b637 and data.hex()!='6a08e8b409000059c3':raise ValueError('Finally outline mismatch')
        regions.append(dict(name=name,start=f'0x{start:08X}',endExclusive=f'0x{end:08X}',bodySha256=hashlib.sha256(data).hexdigest(),instructions=instructions))
    return dict(sourceSha256=SOURCE_SHA,researchPath=str(research),researchSha256=hashlib.sha256(research.read_bytes()).hexdigest(),
        independentInstructionsChecked=len(verified),canonicalMasterModified=False,
        ghidraRegistrarMembership=[['0x0087B59B','0x0087B600'],['0x0087B631','0x0087B636']],
        independentlyRecoveredNormalContinuation=['0x0087B601','0x0087B630'],finallyOutline=['0x0087B637','0x0087B63F'],
        regions=regions,scopeDwords=[f'0x{int.from_bytes(read(0xca9380+4*i,4),"little"):08X}' for i in range(7)],
        cookie=f'0x{int.from_bytes(read(0x1285688,4),"little"):08X}',complement=f'0x{int.from_bytes(read(0x128568c,4),"little"):08X}',
        firstUnsupportedProvider=dict(callsite='0x0087B5B3',cell='0x00B61398',fileValue='0x008AAC6A',classification='inside LEA at 0x008AAC69; not callable'),
        laterGlobalStores=[dict(instruction='0x0087B610',destination='0x018B1E6C',runtimeObserved=False),dict(instruction='0x0087B61D',destination='0x018B1E68',runtimeObserved=False)],
        exceptionDispatchSupported=False,originalStartupReachability='UNVERIFIED')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('image',type=Path);p.add_argument('research',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    a.output.write_text(json.dumps(inspect(a.image,a.research),indent=2)+'\n',encoding='utf-8')
