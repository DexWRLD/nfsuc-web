from pathlib import Path
import sys,json,struct,hashlib
r=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(r/'tools'))
import uc_phase7_test as p7,capstone
image=Path(r'C:\Games\Need For Speed Undercover\nfs.exe')
sections=p7.read_sections(str(image))['sections']
raw=image.read_bytes()
if hashlib.sha256(raw).hexdigest() != '6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd': raise ValueError('Source SHA mismatch')
def read(a,n):
 for s in sections:
  off=a-s['va']
  if 0<=off and off+n<=s['raw_size']:
   return raw[s['raw_ptr']+off:s['raw_ptr']+off+n]
 raise ValueError(hex(a))
m=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
result={}
for address in [0x1fca510,0x1fca520,0x1fca523,0x1fca52a,0x1fca58c,0x1fca58f]:
 result[f'0x{address:08X}']=[dict(address=f'0x{i.address:08X}',bytes=i.bytes.hex(),instruction=i.mnemonic+' '+i.op_str) for i in m.disasm(read(address,24),address)]
out=r/'analysis/undercover'
(out/'entry-alternative-decodings.json').write_text(json.dumps(dict(classification='Static alternative decodings; no branch selected or executed',decodings=result),indent=2)+'\n')
value=int.from_bytes(read(0xBBB2BC,4),'little')
assert value==0x80D090
(out/'static-vtable-evidence.json').write_text(json.dumps(dict(source_sha256='6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd',address='0x00BBB2BC',bytes=read(0xBBB2BC,4).hex(),target='0x0080D090',classification='Static original PE bytes only; no live receiver established'),indent=2)+'\n')
print('Static alternative decodings and vtable verified')
