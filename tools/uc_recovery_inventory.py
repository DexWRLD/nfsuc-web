"""Build recovery and dispatch inventories from the canonical Undercover index."""
from pathlib import Path
import json,re,collections
ROOT=Path(__file__).resolve().parents[1]
A=ROOT/"analysis"/"undercover"
SOURCE="6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd"
PRIORITIES={
 0x00B57DC0:("ordinary static Apt initialization","Constructor and wrapper entry verified; cleanup stops at 0x0087B59B",1),
 0x009E7540:("Apt header-group constructor","Preserve complete unified caller/return regression",1),
 0x009E75A0:("Apt header initializer","Verified leaf; no separate function-count work needed",3),
 0x009C1830:("Apt work-state initializer","Verified field writes and return; find next genuine consumer",2),
 0x0087B640:("cleanup-registration wrapper","Admitted; result semantics tested only with isolated callee fixtures",2),
 0x0087B59B:("ordinary cleanup callee","Resolve SEH injection, noncontiguous body and provider boundaries before admission",1),
 0x0087BEB8:("SEH frame prolog","Prove FS thread state and nonstandard stack contract without flat-address substitution",1),
 0x008AAC60:("file-backed provider candidate","Verify function entry and high stack-offset inputs; not an import declaration",2),
 0x01FCA510:("PE entry","Entry control flow unresolved; preserve boundary",0),
 0x008101B0:("ordinary manager constructor","Verify ordinary callers and required factory state",1),
 0x009E12F0:("native function allocation","Recover caller contract without substituting allocator",1),
 0x009E4640:("Apt storage publication","Verify capacity, context and factory dependencies",1),
 0x009E9460:("Apt object factory","Trace ordinary vtable provider",1),
 0x00548810:("frontend frame helper","No trustworthy callable implementation; stop",1),
 0x008096E0:("frontend frame update","Compare bounded browser prefix with complete CFG",1),
 0x0072E340:("device initialization","Resolve callback state and reached Windows API contract",2),
 0x006860F0:("indexed scene submission","Preserve unresolved implementation; inspect ordinary caller ABI",2),
 0x00686290:("user-memory scene submission","Preserve distinct unresolved implementation",2),
}
def main():
 index=json.loads((A/"nfs_undercover_function_index.json").read_text())
 queue=[]
 registries=[]
 for f in index["functions"]:
  addr=int(f["address"],16)
  status=f["decompilation_status"]
  reasons=[]
  if "unavailable" in status:reasons.append("decompilation unavailable")
  if f["warnings"]:reasons.append("decompiler warnings")
  if f.get("discovery_classification")=="REJECTED_DATA_LIKE":reasons.append("independently rejected discovery")
  indirect=f["unresolved_dependencies"]["indirect_callsites"]
  if indirect:reasons.append("computed callsites require target proof")
  priority=PRIORITIES.get(addr,("unestablished runtime relevance","Inspect original instructions and caller contracts",4))
  if reasons or addr in PRIORITIES:
   queue.append(dict(address=f["address"],classification=status,reasons=reasons,
    warning_details=f["warnings"],failure_reason=f["unresolved_dependencies"]["error"],
    known_callers=f["known_callers"],known_callees=f["known_callees"],
    computed_callsites=indirect,runtime_relevance=priority[0],priority=priority[2],
    overlap_risk=any("overlap" in w.lower() for w in f["warnings"]),
    confidence="recovery outcome only; runtime semantics unverified",
    recovery_feasibility="requires static boundary review" if f["warnings"] else "requires ABI and target validation",
    recommended_next_action=priority[1]))
  registries.append(dict(address=f["address"],name=f["name"],
   classification="unavailable" if "unavailable" in status else "candidate",
   recovered_calling_convention=f["calling_convention"],callable=False,
   sourceSha256=SOURCE,evidence="nfs_undercover_function_index.json",
   body_status=status,argument_bytes=None))
 for f in index["additional_discovery_candidates"]:
  if f["status"]!="raw_lifter_fallback":
   queue.append(dict(address=f["address"],classification=f["status"],priority=4,
    reasons=[f["failure_reason"],f["discovery_classification"],f["termination"]],
    known_callers=[],known_callees=f["known_callees"],
    runtime_relevance="unestablished",recovery_feasibility="inspect original CFG before retry",
    overlap_risk=f["termination"]=="OVERLAP_CONFLICT",confidence="candidate only",
    recommended_next_action="Resolve classification using caller and boundary evidence"))
 present={int(f["address"],16) for f in queue}
 for address,(relevance,action,priority) in PRIORITIES.items():
  if address not in present:
   candidate=next((f for f in index["additional_discovery_candidates"] if int(f["address"],16)==address),None)
   queue.append(dict(address=f"0x{address:08X}",classification="not_recognized_in_ghidra",
    priority=priority,reasons=["Runtime-relevant research address requires explicit recovery review"],
    known_callers=[],known_callees=candidate.get("known_callees",[]) if candidate else [],
    runtime_relevance=relevance,recovery_feasibility="verify exact original bounds",
    overlap_risk="unknown",confidence="existing research lead",
    recommended_next_action=action))
 queue.sort(key=lambda f:(f["priority"],int(f["address"],16)))
 payload=dict(source_sha256=SOURCE,populations=index["source_manifest"],
  note="Warning, rejection, computed-call and failure populations overlap. Queue is a union by address.",
  functions=queue)
 (A/"recovery-priority-index.json").write_text(json.dumps(payload,indent=2)+"\n")
 (A/"dispatch-candidates.json").write_text(json.dumps(dict(source_sha256=SOURCE,
  note="No callable bindings are inferred from decompiler output",targets=registries),indent=2)+"\n")
 imports=index["external_functions"]
 groups=collections.defaultdict(list)
 for row in imports:
  name=row[2]
  group="unclassified"
  for category,pattern in [
   ("graphics",r"Direct3D|D3DX|CreateWindow|GetDC|Gdi|Display"),
   ("audio",r"DirectSound|wave|midi|Audio"),
   ("input",r"DirectInput|Keyboard|Cursor|RawInput|GetKey"),
   ("tls",r"Tls|Fls"),
   ("threading",r"Thread|Process|Sleep"),
   ("synchronization",r"CriticalSection|Mutex|Semaphore|Event|WaitFor|Interlocked"),
   ("memory",r"Heap|VirtualAlloc|VirtualFree|VirtualProtect|MapView|UnmapView|LocalAlloc|GlobalAlloc"),
   ("filesystem",r"File|Directory|Path|Drive|Volume|FindFirst|FindNext|ReadFile|WriteFile"),
   ("time",r"Time|Tick|Performance"),
   ("exceptions",r"Exception|Unwind|Error|Debug|Terminate")]:
   if re.search(pattern,name,re.I):group=category;break
  groups[group].append(dict(name=name,address=row[1],signature=row[3] if len(row)>3 else None,
   ownership="requires API contract review; no generic success stub",
   adapter_status="candidate platform API; not verified by this inventory"))
 (A/"windows-service-inventory.json").write_text(json.dumps(dict(
  note="Name-based triage only. Signatures are recovered Ghidra metadata, not proven ABI.",
  groups=dict(sorted(groups.items()))),indent=2)+"\n")
 print("Recovery union",len(queue),"dispatch candidates",len(registries),"external declarations",len(imports))
if __name__=="__main__": main()

