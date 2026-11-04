"""Read-only Phase 70 PE import identities and conditional CRT dependency graph.

Does not resolve imports, change legacy cells, execute providers or traverse
initializer tables as code. All table correspondence remains explicitly inferred.
"""
import argparse,hashlib,json,struct
from pathlib import Path
import pefile
from capstone import Cs,CS_ARCH_X86,CS_MODE_32,CS_AC_WRITE
from capstone.x86 import X86_OP_MEM
from uc_browser_init import SOURCE_SHA

ROOT=Path(__file__).resolve().parents[1]
PAIRS=[(0xb61384,0x8aac2e,0x22ce04b,'_unlock',4),(0xb61388,0x8aac38,0x22ce04f,'__dllonexit',12),
       (0xb6138c,0x8aac46,0x22ce053,'_encode_pointer',4),(0xb61390,0x8aac58,0x22ce057,'_lock',4),
       (0xb61394,0x8aac60,0x22ce05b,'_onexit',4),(0xb61398,0x8aac6a,0x22ce05f,'_decode_pointer',4),
       (0xb613d8,0x8aad8e,0x22ce09f,'_except_handler4_common',24),
       (0xb613b0,None,0x22ce077,'_initterm',8),(0xb613b4,None,0x22ce07b,'_initterm_e',8),
       (0xb613cc,None,0x22ce093,'__set_app_type',4)]
CONTRACTS={
 '_encode_pointer':dict(arguments='one pointer-sized dword',result='EAX transformed pointer; exact MSVCR80 algorithm/error/lifetime unverified',requiredState='matching CRT encoding state; no secret or encoded sentinel supplied',reference='https://learn.microsoft.com/en-us/previous-versions/bb432254(v=vs.85)',limit='Kernel32 EncodePointer documentation is not proof of this CRT implementation or binding'),
 '_decode_pointer':dict(arguments='one pointer-sized dword',result='EAX decoded value expected by original caller; exact provider semantics unverified',requiredState='same encoding context and valid encoded data; zero-filled globals are not a proven encoded sentinel',reference=None,limit='No standalone ABI is established for 0x008AAC6A'),
 '_onexit':dict(arguments='no-argument callback pointer',result='documented callback pointer on success, null on storage failure',requiredState='owned CRT exit-registration state and lifetime',reference='https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/onexit-onexit-m',limit='documented LIFO registration does not authorize an invented guest array'),
 '__dllonexit':dict(arguments='callback, address of begin-pointer variable, address of end-pointer variable',result='documented callback pointer or null on failure',requiredState='owned mutable list pointers, allocation and teardown policy',reference='https://learn.microsoft.com/en-us/cpp/c-runtime-library/dllonexit',limit='provider array capacity/allocation/encoding implementation not established'),
 '_lock':dict(arguments='int lock number; original registrar passes 8',result='documented void; lock acquisition failure can be fatal',requiredState='CRT lock table and ownership/concurrency policy',reference='https://learn.microsoft.com/en-us/cpp/c-runtime-library/lock',limit='not a success no-op; exact target CRT state unavailable'),
 '_unlock':dict(arguments='int lock number; original finally passes 8',result='documented void',requiredState='matching CRT lock ownership',reference='https://learn.microsoft.com/en-us/cpp/c-runtime-library/unlock',limit='unentered original finally; no lock implementation admitted'),
 '_except_handler4_common':dict(arguments='six original caller-cleaned dwords: cookie/checker and four handler arguments',result='exception disposition/provider-dependent behavior unverified',requiredState='validated SEH/EH4 scopes, cookie checker and unwind contracts',reference=None,limit='unsupported exception path; no no-op adapter'),
 '_initterm':dict(arguments='two function-pointer table bounds',result='documented void; skips null entries',requiredState='effective walker binding and valid earlier CRT initialization',reference='https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/initterm-initterm-e',limit='table catalog is not observed traversal'),
 '_initterm_e':dict(arguments='two int-returning initializer table bounds',result='documented zero on success, nonzero on initializer failure',requiredState='effective walker binding and caller error gating',reference='https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/initterm-initterm-e',limit='conditional original order only; no browser walker executed')}

def inspect(image,research):
    raw=image.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SOURCE_SHA:raise ValueError('Original executable SHA mismatch')
    pe=pefile.PE(data=raw);base=pe.OPTIONAL_HEADER.ImageBase
    def data(address,n):
        result=pe.get_data(address-base,n)
        if len(result)!=n:raise ValueError('Truncated PE evidence')
        return result
    word=lambda address:struct.unpack('<I',data(address,4))[0]
    def section(address):
        s=next(s for s in pe.sections if base+s.VirtualAddress<=address<base+s.VirtualAddress+s.Misc_VirtualSize)
        return dict(name=s.Name.rstrip(b'\0').decode(),readable=bool(s.Characteristics&0x40000000),writable=bool(s.Characteristics&0x80000000),executable=bool(s.Characteristics&0x20000000))
    group=next(g for g in pe.DIRECTORY_ENTRY_IMPORT if g.dll.lower()==b'msvcr80.dll')
    index=pe.DIRECTORY_ENTRY_IMPORT.index(group)
    directory=pe.OPTIONAL_HEADER.DATA_DIRECTORY[1]
    descriptor=base+directory.VirtualAddress+20*index
    fields=struct.unpack('<5I',data(descriptor,20))
    if fields[0]!=0x1ece91f or fields[3]!=0x1eccc62 or fields[4]!=0x1ecdef7:raise ValueError('MSVCR descriptor mismatch')
    if pe.get_string_at_rva(fields[3])!=b'MSVCR80.dll':raise ValueError('Original DLL name mismatch')
    # Independently decode ILT/IMAGE_IMPORT_BY_NAME and compare the PE parser.
    identities={}
    for i,entry in enumerate(group.imports):
        thunk=word(base+fields[0]+4*i)
        if thunk&0x80000000:raise ValueError('Unexpected MSVCR ordinal')
        name=pe.get_string_at_rva(thunk+2).decode()
        if name!=entry.name.decode() or entry.address!=base+fields[4]+4*i:raise ValueError('Import identity mismatch')
        identities[entry.address]=dict(symbol=name,hintNameRva=thunk,hint=struct.unpack('<H',pe.get_data(thunk,2))[0],index=i,fileIatValue=word(entry.address))
    if word(base+fields[4]+4*len(group.imports))!=0:raise ValueError('IAT terminator mismatch')
    providers=[]
    for legacy,expected,active,symbol,args in PAIRS:
        identity=identities[active]
        if identity['symbol']!=symbol or expected is not None and word(legacy)!=expected:raise ValueError('Provider source mismatch')
        providers.append(dict(legacyCell=legacy,legacyFileValue=word(legacy),legacySection=section(legacy),
            activeImportCell=active,activeSection=section(active),dll='MSVCR80.dll',**identity,
            tableIndex=(legacy-0xb61230)//4,positionalDelta=active-legacy,
            correspondence='POSITIONAL_AND_CALLSITE_ROLE_ONLY',runtimeBindingVerified=False,loaderResolvedExternalService=None,
            adapterImplemented=False,expectedLegacyAbi=dict(convention='cdecl',argumentBytes=args,provenance='original consuming stack cleanup; not ABI of overlapping file target')))
    if any(p['index']!=p['tableIndex'] or p['positionalDelta']!=0x176ccc7 for p in providers):raise ValueError('Positional relationship mismatch')
    text=next(s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text');code=raw[text.PointerToRawData:text.PointerToRawData+text.SizeOfRawData];textva=base+text.VirtualAddress
    # Absolute-operand candidate search, not whole-program dataflow. Computed
    # writes and unknown instruction boundaries cannot be excluded by this scan.
    decoder=Cs(CS_ARCH_X86,CS_MODE_32);decoder.detail=True
    scans=[]
    targets={p['legacyCell'] for p in providers}|{p['activeImportCell'] for p in providers}|{0xb61230,0x22cdef7,0x176ccc7}
    for target in sorted(targets):
        hits=[];cursor=0;enc=struct.pack('<I',target)
        while (offset:=code.find(enc,cursor))>=0:
            cursor=offset+1
            candidates={}
            for start in range(max(0,offset-15),offset+1):
                ins=next(decoder.disasm(code[start:start+15],textva+start,count=1),None)
                if not ins or not (ins.address<=textva+offset and ins.address+ins.size>=textva+offset+4):continue
                operands=[o for o in ins.operands if o.type==X86_OP_MEM and o.mem.base==0 and o.mem.index==0 and o.mem.disp&0xffffffff==target]
                if operands:candidates[ins.address]=dict(address=ins.address,bytes=ins.bytes.hex(),instruction=ins.mnemonic+' '+ins.op_str,writeCandidate=any(o.access&CS_AC_WRITE for o in operands),boundaryConfidence='CANDIDATE_UNLESS_IN_INDEPENDENT_DECODE_OR_GHIDRA')
            hits.append(dict(operandAddress=textva+offset,candidates=list(candidates.values())))
        scans.append(dict(value=target,rawOccurrences=hits))
    binding=dict(sourceSha256=SOURCE_SHA,researchPath=str(research),researchSha256=hashlib.sha256(research.read_bytes()).hexdigest(),
        descriptor=dict(index=index,address=descriptor,originalFirstThunkRva=fields[0],dllNameRva=fields[3],firstThunkRva=fields[4],importCount=len(group.imports),section=section(descriptor)),
        directories={str(i):dict(rva=pe.OPTIONAL_HEADER.DATA_DIRECTORY[i].VirtualAddress,size=pe.OPTIONAL_HEADER.DATA_DIRECTORY[i].Size) for i in [1,5,11,12,13]},
        characteristics=pe.FILE_HEADER.Characteristics,relocationsStripped=bool(pe.FILE_HEADER.Characteristics&1),
        legacyBlock=dict(start=0xb61230,endTerminator=0xb614dc,prefixTerminator=word(0xb6122c),terminator=word(0xb614dc)),
        providers=providers,absoluteOperandScan=scans,provenLegacyWriter=None,provenLoaderCopy=None,
        runtimeBindingVerified=False,adaptersImplemented=[],importedServicesExecuted=[],
        scanLimits='Only .text literal operands and read-only indexed xrefs reviewed. Computed/unindexed writes or opaque loader behavior remain unverified; no absence proof.',
        activeImportCellsMappedInBrowser=False,activeImportStorage='.securom; remains unavailable',legacyCellsChanged=False,
        serviceContracts={name:dict(**contract,legacyCallerConvention='cdecl',activeDllImplementationAbiVerified=False,adapterImplemented=False) for name,contract in CONTRACTS.items()})
    regions={}
    for start,length,label in [(0x87bd95,10,'cookie_then_startup'),(0x87c264,0x94,'cookie_initializer'),(0x87bb3d,0xc3,'bounded_startup_window'),(0x87bcb3,0x90,'bounded_pre_c_window'),(0x87c22c,12,'initializer_walker_stubs'),(0x87baf2,20,'first_cpp_entry'),(0x810920,0x82,'frontend_manager_producer')]:
        regions[label]=[dict(address=i.address,bytes=i.bytes.hex(),mnemonic=i.mnemonic,operands=i.op_str) for i in decoder.disasm(data(start,length),start)]
    instruction={i['address']:i for region in regions.values() for i in region}
    expected={0x87bd95:'call',0x87bd9a:'jmp',0x87bbb4:'call',0x87bbe9:'call',0x87bd22:'call',0x87bd2a:'mov',0x87bd2f:'mov',0x810971:'call',0x810976:'mov'}
    if any(instruction[a]['mnemonic']!=m for a,m in expected.items()):raise ValueError('Original order instruction mismatch')
    c=[dict(cell=a,value=word(a)) for a in range(0xb63dc4,0xb63dd4,4)]
    cpp=[dict(cell=a,value=word(a)) for a in range(0xb61730,0xb63dc0,4)]
    if word(0xb63dc8)!=0x87bcb3 or word(0xb6370c)!=0xb57dc0:raise ValueError('Initializer table mismatch')
    manager_branches=[]
    for opcode in [0xe8,0xe9]:
        cursor=0
        while (offset:=code.find(bytes([opcode]),cursor))>=0:
            cursor=offset+1
            if offset+5<=len(code) and (textva+offset+5+struct.unpack('<i',code[offset+1:offset+5])[0])&0xffffffff==0x810920:
                manager_branches.append(dict(address=textva+offset,opcode=opcode,classification='raw relative branch candidate; boundary validation required'))
    manager_literals=[]
    for s in pe.sections:
        if s.Name.rstrip(b'\0') not in (b'.text',b'.rdata',b'.data'):continue
        content=raw[s.PointerToRawData:s.PointerToRawData+s.SizeOfRawData];cursor=0
        while (offset:=content.find(struct.pack('<I',0x810920),cursor))>=0:
            cursor=offset+1;manager_literals.append(base+s.VirtualAddress+offset)
    order=dict(sourceSha256=SOURCE_SHA,classification='STATIC_CONDITIONAL_ORIGINAL_ORDER_NOT_EXECUTION',regions=regions,
        cInitializers=dict(start=0xb63dc4,endExclusive=0xb63dd4,entries=c,endWord=word(0xb63dd4),walkerStub=0x87c232,legacyCell=0xb613b4,activeCounterpart=0x22ce07b,traversalExecuted=False),
        cppInitializers=dict(start=0xb61730,endExclusive=0xb63dc0,entryCount=len(cpp),nonNullCount=sum(bool(e['value']) for e in cpp),entries=cpp,walkerStub=0x87c22c,legacyCell=0xb613b0,activeCounterpart=0x22ce077,traversalExecuted=False),
        edges=[dict(source=0x87bd95,target=0x87c264,kind='original direct CALL'),dict(source=0x87bd9a,target=0x87bb3d,kind='original tail transfer'),dict(source=0x87bbb4,target=0x87c232,kind='conditional C walker'),dict(source=0xb63dc8,target=0x87bcb3,kind='table pointer; requires unavailable walker'),dict(source=0x87bd22,target=0xb6138c,kind='legacy indirect transform of -1'),dict(source=0x87bbe9,target=0x87c22c,kind='conditional C++ walker'),dict(source=0xb6370c,target=0xb57dc0,kind='table pointer; requires unavailable walker')],
        branchConditions=dict(cInitialization='startup state zero sets state one before C walker; EAX=0 from walker reaches continuation, nonzero exits error path',cppInitialization='at 0x0087BBDD, startup state must equal one; otherwise skip constructor walker',stateTwoWrite=0x87bbf0),
        cleanupSentinel=dict(argument=0xffffffff,providerCell=0xb6138c,priorProviderCall=0x87bd1a,priorProviderCell=0xb613cc,writes=[dict(instruction=0x87bd2a,address=0x18b1e68),dict(instruction=0x87bd2f,address=0x18b1e6c)],runtimeExecuted=False,encodedValue=None,currentGuestValues=[0,0]),
        firstDependencies=dict(cookie=dict(callsite=0x87c299,cell=0xb611a0),startup=dict(prologSize=0x10,scope=0xca93f8,fsSelfRead=0x87bb4e,fsOffset=0x18,synchronizationCall=0x87bb62,cell=0xb611b4),cWalker=0xb613b4,preC=dict(headerRead=0x400000,priorProvider=0xb613cc,encodingProvider=0xb6138c),cppWalker=0xb613b0,aptRegistrar=dict(callsite=0x87b5b3,cell=0xb61398)),
        frontend=dict(producer=0x810920,allocationCall=0x810957,allocationTarget=0x686000,constructorCall=0x810971,constructor=0x8101b0,publication=0x810976,globalAddress=0x1873134,constructorFirstUnsupported=0x55ff30,initializerTableMatches=[e for e in c+cpp if e['value']==0x810920],incomingRelativeBranchCandidates=manager_branches,ordinaryAbsoluteAddressOccurrences=manager_literals,incomingCallerVerified=False,searchLimit='Bounded ordinary sections only; computed/unindexed or unavailable-region callers not excluded'),
        crtInstructionsNewlyExecuted=[],cleanupGlobalRuntimeWrites=[],cookieInitializerExecuted=False,peEntryToWrapperVerified=False,providerBindingRequired=True)
    return binding,order

def write(image,research):
    binding,order=inspect(image,research);analysis=ROOT/'analysis/undercover'
    (analysis/'crt-provider-binding-phase70.json').write_text(json.dumps(binding,indent=2)+'\n',encoding='utf-8')
    (analysis/'crt-initialization-order-phase70.json').write_text(json.dumps(order,indent=2)+'\n',encoding='utf-8')
    public=dict(sourceSha256=SOURCE_SHA,providers=binding['providers'],runtimeBindingVerified=False,loaderCopyVerified=False,
        activeImportsExecutableInBrowser=False,crtOrderClassification=order['classification'],edges=order['edges'],branchConditions=order['branchConditions'],firstDependencies=order['firstDependencies'],cookieInitializerExecuted=False,cleanupGlobalInitializerExecuted=False)
    (ROOT/'web/src/host/uc-crt-imports.ts').write_text('/* Generated by tools/uc_crt_evidence.py; static identity is not a runtime binding. */\nexport const CRT_IMPORT_EVIDENCE = '+json.dumps(public,indent=2)+' as const;\n',encoding='utf-8')
    print(json.dumps(dict(verifiedImports=len(binding['providers']),runtimeBindingVerified=False,cTableEntries=len(order['cInitializers']['entries']),cppTableEntries=order['cppInitializers']['entryCount'])))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('image',type=Path);p.add_argument('research',type=Path);a=p.parse_args();write(a.image,a.research)
