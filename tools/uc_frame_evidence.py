"""Read-only frame-call and frontend container evidence; no archive extraction."""
import argparse
import hashlib
import json
from pathlib import Path
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from uc_browser_init import SOURCE_SHA

def inspect(installation):
    executable=installation/'nfs.exe'
    raw=executable.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SOURCE_SHA:
        raise ValueError('Original executable SHA mismatch')
    pe=pefile.PE(data=raw)
    instructions={}
    for address,length in [(0x785cd9,15),(0x786798,15),(0x8096e0,82),(0x8082f0,82)]:
        data=pe.get_data(address-pe.OPTIONAL_HEADER.ImageBase,length)
        instructions[f'0x{address:08X}']=[dict(address=f'0x{i.address:08X}',bytes=i.bytes.hex(),instruction=i.mnemonic+' '+i.op_str)
            for i in Cs(CS_ARCH_X86,CS_MODE_32).disasm(data,address)]
    names=['BootLoadingScreen','LS_EALOGO.FNG','LS_SPLASH.FNG','MC_MAIN.FNG','UNIQUEBOOTTEXTURES']
    strings={}
    for name in names:
        offsets=[]; start=0
        while (offset:=raw.find(name.encode(),start))>=0:
            offsets.append(dict(fileOffset=offset,address=f'0x{pe.OPTIONAL_HEADER.ImageBase+pe.get_rva_from_offset(offset):08X}'))
            start=offset+1
        strings[name]=dict(occurrences=offsets,classification='STATIC_STRING_ONLY')
    containers=[]
    for relative in ['FRONTEND/LOGOTEXTURES.BUN','FRONTEND/BOOTFLOWTEXTURES.BUN','FRONTEND/FRONTB1.BUN','GLOBAL/UNIQUEBOOTTEXTURES.BIN']:
        data=(installation/relative).read_bytes()
        containers.append(dict(path=relative,length=len(data),sha256=hashlib.sha256(data).hexdigest(),
            first32Bytes=data[:32].hex(),verifiedPayloadSpan=None,decodedDimensions=None,
            ordinaryConsumer=None,authorization='original installation read-only; not exported or committed'))
    return dict(sourceSha256=SOURCE_SHA,imageBase='0x00400000',
        staticGate=int.from_bytes(pe.get_data(0xcbf590-pe.OPTIONAL_HEADER.ImageBase,4),'little'),
        instructions=instructions,resourceNames=strings,containers=containers,
        frontendResourceSpanVerified=False,
        missingEvidence='Ordinary directory/index reader mapping a named resource to offset/length, bounds and decoder/consumer; string adjacency is not membership proof.',
        originalSchedulerVerified=False,originalFrontendScreenDisplayed=False)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('installation',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    args.output.write_text(json.dumps(inspect(args.installation),indent=2)+'\n',encoding='utf-8')
