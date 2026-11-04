"""Build the existing Undercover prefix with imported checked memory and address dispatch."""
import argparse, hashlib, json, re, subprocess, tempfile
from pathlib import Path
import uc_browser_init as legacy
import uc_phase7_test as p7
import uc_code_analyze as uca
import lift

REPOSITORY = Path(__file__).resolve().parents[1]
REGISTRY = json.loads((REPOSITORY/"tools/uc_unified_registry.json").read_text(encoding="utf-8"))
ADDRESSES = [entry["address"] for entry in REGISTRY["bindings"]]
BINDINGS = [dict(**{key: entry[key] for key in ("address", "convention", "argumentBytes")}, frameContract=entry.get("frameContract")) for entry in REGISTRY["bindings"]]

HEADER = r"""
typedef unsigned u32;
typedef u32 uint32_t;
typedef struct { volatile u32 esp,eip,eax,ebp,ecx,edx,esi,edi,ebx,cf,pf,af,zf,sf,of,flags_known; } CPU;
static CPU cpu;
__attribute__((import_module("guest"),import_name("read32"))) u32 read32(u32);
__attribute__((import_module("guest"),import_name("write32"))) void write32(u32,u32);
__attribute__((import_module("guest"),import_name("dispatch"))) void dispatch(u32);
__attribute__((import_module("guest"),import_name("instruction"))) void instruction(u32);
__attribute__((import_module("guest"),import_name("write8"))) void write8(u32,u32);
__attribute__((import_module("guest"),import_name("readFs32"))) u32 readFs32(u32);
__attribute__((import_module("guest"),import_name("writeFs32"))) void writeFs32(u32,u32);
#define MR32(a) read32(a)
#define PUSH32(v) do { u32 pushed=(v); c->esp -= 4; write32(c->esp,pushed); } while (0)
#define POP32(v) do { u32 popped=read32(c->esp); c->esp += 4; (v)=popped; } while (0)
#define DISPATCH_CALL(c,target) dispatch(target)
"""

HEADER += (REPOSITORY/"tools/uc_unified_flags.h").read_text(encoding="utf-8")

def transform_flags(bodies):
    # SBB/ADC consume actual incoming CF. INC/DEC preserve CF validity too.
    bodies = bodies.replace("_ci=c->cf&1u", "_ci=flag_read(c,F_CF)")
    bodies = bodies.replace("_cf=c->cf;", "_cf=c->cf,_ck=c->flags_known&F_CF;")
    return bodies.replace("c->cf=_cf;", "c->cf=_cf;c->flags_known=(c->flags_known&~F_CF)|_ck;")

def validate_instruction_subset(bodies):
    # Admission is explicit. New flag/system operations need semantics and tests;
    # compiler acceptance alone does not make an instruction supported.
    admitted = {'mov','lea','push','pop','call','ret','jmp','add','sub','cmp',
                'test','xor','and','or','neg','sbb','inc','dec'}
    admitted.update('j'+condition for condition in lift.CC)
    mnemonics = set(re.findall(r'/\* [0-9a-f]{8}  (\S+)', bodies))
    if mnemonics - admitted:
        raise ValueError('Unreviewed unified instruction: '+','.join(sorted(mnemonics-admitted)))

def build(image, output):
    raw=image.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=legacy.SOURCE_SHA:
        raise ValueError("Original executable SHA mismatch")
    if (REGISTRY["sourceSha256"] != legacy.SOURCE_SHA or len(ADDRESSES) != len(set(ADDRESSES))
            or any(entry.get("callable") is not True or entry["sourceSha256"] != legacy.SOURCE_SHA
                   or entry["convention"] not in ("cdecl", "stdcall", "thiscall")
                   or not isinstance(entry["argumentBytes"], int) or entry["argumentBytes"] < 0
                   or entry["argumentBytes"] % 4 for entry in REGISTRY["bindings"])):
        raise ValueError("Invalid reviewed dispatch registry")
    info=uca.read_inputs(str(image))
    wrapper = bytes.fromhex("ff742404e852fffffff7d81bc0f7d85948c3")
    offset=0x0087B640-info["text_va"]
    if info["bytes"][offset:offset+len(wrapper)] != wrapper:
        raise ValueError("Cleanup wrapper original instruction bytes mismatch")
    lifter=lift.RawLifter(info["bytes"],info["text_va"],comments=True)
    initializer,_=lifter.lift(0x009E8AD0)
    bodies=initializer+"\n"+legacy.build_prefix(lifter)
    expected_calls = {
        0x00B57DC0: {0x009E7540, 0x0087B640},
        0x0087B640: {0x0087B59B},
        0x009E7540: {0x009E75A0, 0x009C1830},
        0x009E75A0: set(),
        0x009C1830: set(),
    }
    index = json.loads((REPOSITORY/"analysis/undercover/nfs_undercover_function_index.json").read_text(encoding="utf-8"))
    indexed = {int(entry["address"], 16): entry for entry in index["functions"]}
    registry_entries = {entry["address"]: entry for entry in REGISTRY["bindings"]}
    for address in expected_calls:
        recovered = indexed.get(address)
        if (not recovered or recovered["decompilation_status"] != "decompiled"
                or recovered["address_range"] != registry_entries[address]["verifiedBodyRange"]):
            raise ValueError("Constructor boundary lacks the required recovery evidence")
    for address, expected in expected_calls.items():
        body, calls = lifter.lift(address)
        if calls != expected:
            raise ValueError("Registry call edges differ from original code")
        bodies += "\n" + body
    # Independent exact-byte override; canonical master/index stay untouched.
    seh_calls = {0x87b59b:{0x87beb8,0x87befd,0x87bffe,0x87bff8,0x87b637},0x87beb8:set(),0x87befd:set(),0x87b637:{0x87bff2}}
    for address, expected in seh_calls.items():
        entry=registry_entries[address]
        start,end=[int(value,16) for value in entry["verifiedBodyRange"]]
        data=info["bytes"][start-info["text_va"]:end-info["text_va"]+1]
        if hashlib.sha256(data).hexdigest()!=entry["bodySha256"]:
            raise ValueError("SEH source bytes mismatch")
        bounded=lift.RawLifter(data,start,comments=True)
        body,calls=bounded.lift(address)
        if calls!=expected:raise ValueError("SEH original call set mismatch")
        starts={i.address for i in lift.Cs(lift.CS_ARCH_X86,lift.CS_MODE_32).disasm(data,start)}
        translated={int(value,16) for value in re.findall(r'/\* ([0-9a-f]{8})  ',body)}
        if translated!=starts:raise ValueError("Incomplete original SEH instruction coverage")
        body=body.replace("MR32(c->fs_base) = (c->eax);","writeFs32(0u,c->eax);")
        body=body.replace("MR32(c->fs_base) = (c->ecx);","writeFs32(0u,c->ecx);")
        body=body.replace("MR32(c->fs_base)","readFs32(0u)")
        if "fs_base" in body:raise ValueError("Unreviewed segment access")
        bodies+="\n"+body
    registry_ts = "/* Generated by uc_unified_build.py from tools/uc_unified_registry.json. */\n"
    registry_ts += "export const UNIFIED_BINDINGS = " + json.dumps(BINDINGS, indent=2) + " as const;\n"
    registry_ts += "export const UNIFIED_REGISTRY = " + json.dumps(REGISTRY, indent=2) + " as const;\n"
    (REPOSITORY/"web/src/host/uc-unified-registry.ts").write_text(registry_ts, encoding="utf-8")

    validate_instruction_subset(bodies)
    bodies=transform_flags(bodies)
    bodies=re.sub(r"    if \(entered >= 8\) __builtin_trap\(\); trace\[entered\+\+\] = \d+u;\n","",bodies)
    bodies=bodies.replace("(*indexed_read(c->edx, c->eax))","MR32(c->edx+c->eax*4+0xfffffffcu)")
    bodies=re.sub(r"MR8\(([^;\n]+?)\) = \(([^;\n]+?)\);",r"write8(\1, \2);",bodies)
    bodies=re.sub(r"MR32\(([^;\n]+?)\) = \(([^;\n]+?)\);",r"write32(\1, \2);",bodies)
    bodies=re.sub(r"dispatch_indirect\(c, ([^;]+?)\)",r"dispatch(\1)",bodies)
    bodies=re.sub(r"sub_([0-9a-f]+)\(c\)",lambda m:f"dispatch(0x{m[1]}u)",bodies)
    bodies=re.sub(r"(/\* ([0-9a-f]{8})  .*?\*/)",lambda m:m[1]+f"\n    instruction(0x{m[2]}u);",bodies)
    if any(word in bodies for word in ("indexed_read", "trace[", "entered", "MR8", "MRF32")):
        raise ValueError("Unsupported unified prefix operation")
    exports="""
void set_register(u32 i,u32 v) { if(i>=9)__builtin_trap(); ((volatile u32*)&cpu)[i]=v; }
u32 get_register(u32 i) { if(i>=9)__builtin_trap(); return ((volatile u32*)&cpu)[i]; }
u32 get_flags(void) { return flags_value(&cpu); }
u32 get_flags_known(void) { return cpu.flags_known; }
void set_flags(u32 value,u32 known) { flags_restore(&cpu,value,known); }
void execute(u32 address) { switch(address) {
"""
    exports+="\n".join(f"case 0x{a:08x}u: sub_{a:08x}(&cpu); return;" for a in ADDRESSES)
    exports+="\ndefault: __builtin_trap(); } }\n"
    output.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory() as temp:
        source=Path(temp)/"unified.c"
        source.write_text(HEADER+bodies+exports)
        subprocess.run([p7.clang(),"--target=wasm32-unknown-unknown","-O2","-ffreestanding",
            "-nostdlib","-Wl,--no-entry","-Wl,--import-memory","-Wl,--initial-memory=131072",
            "-Wl,--export=execute","-Wl,--export=set_register","-Wl,--export=get_register","-Wl,--export=get_flags","-Wl,--export=get_flags_known","-Wl,--export=set_flags",
            str(source),"-o",str(output/"uc-unified.wasm")],check=True)
    sections=p7.read_sections(str(image))["sections"]
    payload=bytearray()
    mapped=[]
    allowed={".text",".rdata",".data",".tls",".rsrc"}
    for section in sections:
        size=section["vsize"]
        if not size:continue
        ordinary=section["name"] in allowed
        offset=len(payload)
        data=b""
        if ordinary:
            length=min(section["raw_size"],size)
            data=raw[section["raw_ptr"]:section["raw_ptr"]+length]
            if len(data)!=length:raise ValueError("Truncated PE section")
            payload.extend(data)
        chars=section["chars"]
        permissions=(1 if chars&0x40000000 else 0)|(2 if chars&0x80000000 else 0)|(4 if chars&0x20000000 else 0)
        mapped.append(dict(name=section["name"],address=section["va"],size=size,permissions=permissions,
            offset=offset,length=len(data),sha256=hashlib.sha256(data).hexdigest(),unavailable=not ordinary))
    (output/"uc-unified-image.bin").write_bytes(payload)
    descriptor=dict(version=1,imageBase=0x400000,sourceSha256=legacy.SOURCE_SHA,
        payloadSha256=hashlib.sha256(payload).hexdigest(),payloadSize=len(payload),moduleSha256=hashlib.sha256((output/"uc-unified.wasm").read_bytes()).hexdigest(),
        segments=mapped,bindings=BINDINGS)
    (output/"uc-unified-image.json").write_text(json.dumps(descriptor,indent=2)+"\n")
    print(json.dumps(dict(segments=len(mapped),ordinaryBytes=len(payload),bindings=len(ADDRESSES))))

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("output",type=Path)
    args=p.parse_args()
    build(args.image,args.output)

