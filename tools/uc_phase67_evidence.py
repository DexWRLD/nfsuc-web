"""Read-only PE checks for the Phase 67 cleanup frontier. Never executes game code."""
import argparse
import hashlib
import json
from pathlib import Path
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from uc_browser_init import SOURCE_SHA

def inspect(path):
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_SHA:
        raise ValueError('Source executable SHA mismatch')
    pe = pefile.PE(data=raw)
    base = pe.OPTIONAL_HEADER.ImageBase
    imports = {entry.address: {'dll': group.dll.decode(), 'name': entry.name.decode() if entry.name else entry.ordinal}
               for group in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []) for entry in group.imports}
    def read(address, length):
        for section in pe.sections:
            start = base + section.VirtualAddress
            if start <= address and address + length <= start + section.Misc_VirtualSize:
                displacement = address - start
                available = max(0, min(length, section.SizeOfRawData - displacement))
                offset = section.PointerToRawData + displacement
                return raw[offset:offset+available] + bytes(length-available), section.Name.rstrip(b'\0').decode(), available
        raise ValueError('Unmapped address')
    cells = []
    for address in [0x018b1e6c,0x018b1e68,0x00b61398,0x00b61394,0x00b6138c,0x01285688]:
        value, section, available = read(address,4)
        cells.append(dict(address=f'0x{address:08X}',value=f'0x{int.from_bytes(value,"little"):08X}',
                          section=section,fileBackedBytes=available,importDirectoryEntry=imports.get(address)))
    code = {}
    for start, length in [(0x87b640,18),(0x87b59b,0x9c),(0x87beb8,69),(0x8aac60,24),(0x8aac6a,16)]:
        data, section, _ = read(start,length)
        code[f'0x{start:08X}'] = dict(section=section, bytes=data.hex(),
            linearDisassembly=[dict(address=f'0x{i.address:08X}',bytes=i.bytes.hex(),mnemonic=i.mnemonic,operands=i.op_str)
                               for i in Cs(CS_ARCH_X86,CS_MODE_32).disasm(data,start)])
    return dict(sourceSha256=SOURCE_SHA, cells=cells, code=code,
        caution='Linear disassembly does not establish function membership or callable boundaries. 0x008AAC6A lies inside LEA at 0x008AAC69 in the current Ghidra body.',
        runtimeProviderIdentity='UNRESOLVED', nativeStartupReachability='UNVERIFIED')

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    args.output.write_text(json.dumps(inspect(args.image),indent=2)+'\n',encoding='utf-8')
