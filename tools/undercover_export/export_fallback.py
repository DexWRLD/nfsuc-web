"""Export RawLifter fallback bodies for discovery entries absent from Ghidra."""
from pathlib import Path
import sys,json,hashlib
sys.path.insert(0,str(Path(sys.argv[2])/'tools'))
import lift,uc_code_analyze as uca
image=Path(r'C:\Games\Need For Speed Undercover\nfs.exe')
assert hashlib.sha256(image.read_bytes()).hexdigest()=='6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd'
work=Path(sys.argv[1]); repo=Path(sys.argv[2])
known={int(line.split('\t')[0],16) for line in (work/'functions.tsv').read_text().splitlines()}
fmap=json.loads((repo/'analysis/undercover/function-map.json').read_text())['functions']
info=uca.read_inputs(str(image)); lifter=lift.RawLifter(info['bytes'],info['text_va'],comments=True)
result=[]
with (work/'fallback.c').open('w',encoding='utf-8',newline='\n') as out:
 for f in fmap:
  addr=int(f['va'],16)
  if addr in known: continue
  entry=dict(address=f['va'],status='unavailable',reason='',calls=[])
  if f['label']=='REJECTED_DATA_LIKE':
   entry['reason']='Existing discovery rejected this candidate as data-like'
  else:
   try:
    body,calls=lifter.lift(addr)
    entry.update(status='raw_lifter_fallback',calls=sorted(calls))
    out.write(f"\n/* RAW_LIFTER_FUNCTION {addr:08x} | CPU/register-level translation, semantic validity unverified */\n"+body+'\n')
   except Exception as e: entry['reason']=str(e)
  result.append(entry)
(work/'fallback.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
print(json.dumps(dict(attempt_population=len(result),emitted=sum(e['status']=='raw_lifter_fallback' for e in result))))

