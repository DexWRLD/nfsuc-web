from pathlib import Path
import json,re,hashlib,collections,sys
work=Path(sys.argv[1]); repo=Path(sys.argv[2]); out=repo/'analysis/undercover'
raw=(work/'nfs_undercover_full_decompile.c').read_text(encoding='utf-8')
rows=[line.split('\t') for line in (work/'functions.tsv').read_text().splitlines()]
parts=re.split(r'(?=/\* UC_FUNCTION )',raw)
chunks={re.match(r'/\* UC_FUNCTION ([0-9a-f]+)',part)[1]:part for part in parts[1:]}
assert len(chunks)==len(rows)==17367
fmap=json.loads((out/'function-map.json').read_text())['functions']
candidates={int(f['va'],16):f for f in fmap}
metadata=[line.split('\t') for line in (work/'metadata.txt').read_text().splitlines()]
warnings=collections.Counter()
functions=[]
bodies=[]
decls=[]
for row in rows:
 a,name,status,start,end,abi,callers,callees,reason,indirect,imports,size=row
 body=chunks[a]
 ws=re.findall(r'/\* WARNING:(.*?)\*/',body,re.S)
 ws=[' '.join(w.split()) for w in ws]
 discovery=candidates.get(int(a,16))
 if status=='decompiled' and ws: status='emitted_with_warnings'
 if discovery and discovery['label']=='REJECTED_DATA_LIKE': status='discovery_rejected_'+status
 warnings.update(ws)
 body=body.replace(' | decompiled */',' | '+status+' */',1)
 signature=None
 if '{' in body and 'Body unavailable:' not in body:
  prefix=re.sub(r'/\*.*?\*/','',body.split('{',1)[0],flags=re.S).strip()
  signature=' '.join(prefix.split())
  decls.append(signature+';')
 functions.append(dict(address='0x'+a.upper(),name=name,decompilation_status=status,
  address_range=[start,end],body_bytes=int(size),calling_convention=abi,signature=signature,
  known_callers=callers.split(',') if callers else [],known_callees=callees.split(',') if callees else [],
  unresolved_dependencies=dict(error=reason,indirect_callsites=indirect.split(',') if indirect else [],
   external_references=imports.split(',') if imports else []),warnings=ws,
  discovery_classification=discovery['label'] if discovery else None,
  browser_execution_status='unknown; see browser builder and phase reports'))
 bodies.append(body)
ghidra_addresses={int(r[0],16) for r in rows}
missing=[dict(address=f['va'],status='not_recognized_in_saved_ghidra_project',
  discovery_classification=f['label'],termination=f.get('termination'),
  known_callees=f.get('calls',[]),reasons=f.get('reasons',[])) for f in fmap if int(f['va'],16) not in ghidra_addresses]
fallback=json.loads((work/'fallback.json').read_text())
fallback_by={int(e['address'],16):e for e in fallback}
for candidate in missing:
 entry=fallback_by[int(candidate['address'],16)]
 candidate.update(status=entry['status'],failure_reason=entry['reason'],raw_lifter_callees=entry['calls'])
counts=collections.Counter(f['decompilation_status'] for f in functions)
unassigned=[m for m in metadata if m[0]=='unassigned_exec']
overlaps=[m for m in metadata if m[0]=='overlap']
import_rows=[m for m in metadata if m[0]=='import']
manifest=dict(executable_sha256='6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd',
 project='UndercoverResearch:/nfs.exe',ghidra_version='12.2',functions=len(functions),statuses=dict(counts),
 candidate_addresses_not_in_project=len(missing),unassigned_executable_ranges=len(unassigned),
 unassigned_executable_bytes=sum(int(x[3]) for x in unassigned),overlapping_function_entries=len(overlaps),
 computed_callsite_occurrences=sum(len(f['unresolved_dependencies']['indirect_callsites']) for f in functions),
 external_function_declarations=len(import_rows),entry_addresses=[m[1] for m in metadata if m[0]=='entry'],
 raw_lifter_additional_bodies=sum(e['status']=='raw_lifter_fallback' for e in fallback),
 unavailable_additional_candidates=sum(e['status']!='raw_lifter_fallback' for e in fallback),
 standalone_compilable=False,semantic_correctness='not established by decompiler completion')
header='/* SOURCE MANIFEST\n'+json.dumps(manifest,indent=2)+'\n*/\n'
header+='/* Recovered signatures and imported declarations. Definitions of unresolved Ghidra types remain external. */\n'
header+='\n'.join(m[3]+';' for m in import_rows if len(m)>3)+'\n'
header+='\n'.join(decls)+'\n/* Address-sorted bodies. Domain grouping is unverified. */\n'
master=header+''.join(bodies)+'\\n/* Additional original-address CPU/register-level translations from RawLifter. These require the repository runtime. */\\n'+(work/'fallback.c').read_text(encoding='utf-8')+'\n/* UNRESOLVED DISCOVERY INVENTORY\n'
master+='\n'.join(f"{m['address']} {m['discovery_classification']} {m['termination']} {m['status']} {m.get('failure_reason','')}" for m in missing)
master+='\n*/\n/* SAVED PROJECT DATA AND EXECUTABLE COVERAGE INVENTORY\n'
master+='\n'.join(' | '.join(m).replace('*/','* /') for m in metadata if m[0] in ('data','block','overlap','unassigned_exec'))
master+='\n*/\n'
target=out/'nfs_undercover_full_decompile.c'
target.write_text(master,encoding='utf-8',newline='\n')
manifest['master_sha256']=hashlib.sha256(target.read_bytes()).hexdigest()
index=dict(source_manifest=manifest,functions=functions,additional_discovery_candidates=missing,
 executable_ranges_outside_function_bodies=unassigned,function_body_overlaps=overlaps,external_functions=import_rows)
(out/'nfs_undercover_function_index.json').write_text(json.dumps(index,indent=2)+'\n',encoding='utf-8')
assert re.findall(r'/\* UC_FUNCTION ([0-9a-f]+)',master)==[r[0] for r in rows]
assert len(set(r[0] for r in rows))==len(rows)
assert all(len(r)==12 for r in rows)
print(json.dumps(manifest,indent=2))

