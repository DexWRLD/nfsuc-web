"""One bounded ordinary-code import/provenance search; never executes game code."""
import argparse,hashlib,json,struct
from pathlib import Path
import pefile
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
from uc_browser_init import SOURCE_SHA

ROOT=Path(__file__).resolve().parents[1]
def inspect(image,research):
    raw=image.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SOURCE_SHA:raise ValueError('Original executable SHA mismatch')
    pe=pefile.PE(data=raw);base=pe.OPTIONAL_HEADER.ImageBase
    imports={entry.address:dict(dll=g.dll.decode(),symbol=entry.name.decode() if entry.name else '#'+str(entry.ordinal)) for g in pe.DIRECTORY_ENTRY_IMPORT for entry in g.imports}
    def word(address):return struct.unpack('<I',pe.get_data(address-base,4))[0]
    def section(address):
        s=next(s for s in pe.sections if base+s.VirtualAddress<=address<base+s.VirtualAddress+s.Misc_VirtualSize)
        return s.Name.rstrip(b'\0').decode()
    text=next(s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text');textva=base+text.VirtualAddress
    code=raw[text.PointerToRawData:text.PointerToRawData+text.SizeOfRawData]
    # Every advertised active IAT address has upper word 0x022C in this image.
    if {a>>16 for a in imports}!={0x22c}:raise ValueError('Search mask no longer covers active IAT')
    active_hits=[];cursor=0
    while (offset:=code.find(b'\x2c\x02',cursor))>=0:
        cursor=offset+1
        if offset>=2:
            value=struct.unpack('<I',code[offset-2:offset+2])[0]
            if value in imports:active_hits.append(dict(operandAddress=textva+offset-2,cell=value,identity=imports[value]))
    stubs=[];calls=[]
    for opcode,label in [(b'\xff\x15','CALL'),(b'\xff\x25','JMP')]:
        cursor=0
        while (offset:=code.find(opcode,cursor))>=0:
            cursor=offset+1
            if offset+6>len(code):continue
            cell=struct.unpack('<I',code[offset+2:offset+6])[0]
            record=dict(address=textva+offset,bytes=code[offset:offset+6].hex(),instruction=label+' [0x%08X]'%cell,cell=cell,
                        activeImportIdentity=imports.get(cell),classification='RAW_CANDIDATE_NOT_REACHABILITY_PROOF')
            if label=='CALL':calls.append(record)
            else:stubs.append(record)
    legacy=[]
    for cell in [0xb61384,0xb61388,0xb6138c,0xb61390,0xb61394,0xb61398,0xb613b0,0xb613b4,0xb613cc,0xb613d8,0xb611a0,0xb6123c]:
        value=word(cell);name=pe.get_string_at_rva(value+2).decode('ascii')
        owners=[dict(cell=a,**identity) for a,identity in imports.items() if identity['symbol']==name]
        legacy.append(dict(cell=cell,rawValue=value,section=section(cell),
            originalImportNameRva=value,importNameAddress=base+value,importNameSection=section(base+value),importName=name,
            nameIdentityVerifiedFromOriginalBytes=True,matchingActiveSymbols=owners,
            advertisedImportDescriptorOwnsLegacyCell=cell in imports,runtimeBindingVerified=False,
            warning='RVA interpretation proves a name record, not a callable target or live IAT binding. CPU still sees the raw dword.'))
    if word(0xb61398)!=0x8aac6a:raise ValueError('Original rejection changed')
    example=next(row for row in stubs if row['address']==0x87b2d6)
    if example['cell']!=0xb6123c:raise ValueError('memset thunk source mismatch')
    earliest=dict(cookie=dict(callsite=0x87c299,cell=0xb611a0,rawValue=word(0xb611a0),importName='GetSystemTimeAsFileTime',bindingVerified=False),
        preC=dict(callsite=0x87bd1a,cell=0xb613cc,rawValue=word(0xb613cc),importName='__set_app_type',bindingVerified=False),
        sentinel=dict(callsite=0x87bd22,cell=0xb6138c,rawValue=word(0xb6138c),importName='_encode_pointer',bindingVerified=False))
    return dict(sourceSha256=SOURCE_SHA,researchPath=str(research),researchSha256=hashlib.sha256(research.read_bytes()).hexdigest(),
        scannedOrdinarySection='.text',scannedBytes=len(code),advertisedImportCount=len(imports),
        advertisedActiveIatLiteralReferences=active_hits,activeIatCallOrThunkCandidates=[r for r in calls+stubs if r['cell'] in imports],
        absoluteCallCandidateCount=len(calls),absoluteJumpThunkCandidateCount=len(stubs),legacyNameRecords=legacy,
        rawLegacyCallCandidates=[r for r in calls if r['cell'] in {x['cell'] for x in legacy}],
        rawLegacyThunkCandidates=[r for r in stubs if r['cell'] in {x['cell'] for x in legacy}],
        ordinaryLegacyExamples=[dict(caller=0x739b90,callsite=0x739b9c,callBytes=pe.get_data(0x739b9c-base,5).hex(),originalReturn=0x739ba1,thunk=0x87b2d6,cell=0xb6123c,
            importedName='memset',expectedArguments=['writable destination from caller [ESP+4]','zero','0x180 bytes'],expectedAbi='cdecl; original caller ADD ESP,0xC at 0x00739BA1',expectedReturn='EAX destination if genuine memset provider returns',requiredState='bounded source stack and 0x180 writable bytes; effective import binding',ordinaryEdgeVerified=True,startupReachability='UNVERIFIED',providerBindingVerified=False),
            dict(caller=0x87c264,callsite=0x87c299,callBytes=pe.get_data(0x87c299-base,6).hex(),cell=0xb611a0,importedName='GetSystemTimeAsFileTime',
            expectedArguments=['pointer to two writable FILETIME dwords at EBP-8'],expectedAbi='stdcall-shaped one-pointer Win32 call; no caller cleanup at this edge',requiredState='original cookie frame, default-cookie branch, effective import binding',ordinaryEdgeVerified=True,startupReachability='UNVERIFIED',providerBindingVerified=False)],
        existingMemsetHarness=dict(originalThunk=example,source='tools/uc_phase7_test.py: sub_0087b2d6 replacement + runtime/uc_import_table.inc',
            classification='HOST_IMPORT_CONTRACT_FIXTURE_NOT_PROOF_OF_ORIGINAL_RUNTIME_BINDING',newlyExecuted=False),
        earliestCrtDependencies=earliest,
        priorWriterSearch='crt-provider-binding-phase70.json and fresh external research: no proven writer/copy; literal/indexed scope only',
        legitimateOrdinaryImportExecutionEstablished=False,legacyRuntimeBindingVerified=False,provenBindingWriter=None,
        importedServicesExecuted=[],crtExecutionAdvanced=False,
        gate='BLOCKED_UNAVAILABLE_PROVIDER_PROVENANCE',
        repeatSearchPolicy='CLOSED_UNTIL_NEW_WRITER_OR_BINDING_EVIDENCE; no further positional-correspondence phases',
        limits='Ordinary .text absolute literals/opcodes only. Register-computed targets/copies, dataflow and unavailable sections are not exhaustively covered. Raw opcode starts may be inside other instructions; no candidate is automatically admitted.',
        protectedCodeExecuted=False,legacyCellsChanged=False)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('image',type=Path);p.add_argument('research',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    result=inspect(a.image,a.research);a.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:result[k] for k in ['advertisedImportCount','absoluteCallCandidateCount','absoluteJumpThunkCandidateCount','gate']}))
