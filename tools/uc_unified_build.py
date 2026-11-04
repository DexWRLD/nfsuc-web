"""Build the existing Undercover prefix with imported checked memory and address dispatch."""
import argparse, hashlib, json, re, subprocess, tempfile
from pathlib import Path
import uc_browser_init as legacy
import uc_phase7_test as p7
import uc_code_analyze as uca
import lift

ADDRESSES = [0x009E8AD0,0x0099DCD0,0x009E78C0,0x009B6290,0x009E4B10]
HEADER = r"""
typedef unsigned u32;
typedef u32 uint32_t;
typedef struct { u32 esp,eip,eax,ebp,ecx,edx,esi,edi,ebx; } CPU;
static CPU cpu;
__attribute__((import_module("guest"),import_name("read32"))) u32 read32(u32);
__attribute__((import_module("guest"),import_name("write32"))) void write32(u32,u32);
__attribute__((import_module("guest"),import_name("dispatch"))) void dispatch(u32);
__attribute__((import_module("guest"),import_name("instruction"))) void instruction(u32);
static int equal, less;
#define MR32(a) read32(a)
#define PUSH32(v) do { c->esp -= 4; write32(c->esp,(v)); } while (0)
#define POP32(v) do { (v)=read32(c->esp); c->esp += 4; } while (0)
#define FLAGS_SUB_M(a,b,r,n,m) do { if(m){equal=!(r);less=(int)(a)<(int)(b);} } while(0)
#define FLAGS_ADD_M(a,b,r,n,m) do { if(m){equal=!(r);less=(int)(r)<0;} } while(0)
#define FLAGS_LOG_M(r,n,m) do { equal=!(r);less=(int)(r)<0; } while(0)
#define CC_E equal
#define CC_NE (!equal)
#define CC_L less
#define CC_G (!equal && !less)
#define DISPATCH_CALL(c,target) dispatch(target)
"""

def build(image, output):
    raw=image.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=legacy.SOURCE_SHA:
        raise ValueError("Original executable SHA mismatch")
    info=uca.read_inputs(str(image))
    lifter=lift.RawLifter(info["bytes"],info["text_va"],comments=True)
    initializer,_=lifter.lift(0x009E8AD0)
    bodies=initializer+"\n"+legacy.build_prefix(lifter)
    bodies=re.sub(r"    if \(entered >= 8\) __builtin_trap\(\); trace\[entered\+\+\] = \d+u;\n","",bodies)
    bodies=bodies.replace("(*indexed_read(c->edx, c->eax))","MR32(c->edx+c->eax*4+0xfffffffcu)")
    bodies=re.sub(r"MR32\(([^;\n]+?)\) = \(([^;\n]+?)\);",r"write32(\1, \2);",bodies)
    bodies=re.sub(r"sub_([0-9a-f]+)\(c\)",lambda m:f"dispatch(0x{m[1]}u)",bodies)
    bodies=re.sub(r"(/\* ([0-9a-f]{8})  .*?\*/)",lambda m:m[1]+f"\n    instruction(0x{m[2]}u);",bodies)
    if any(word in bodies for word in ("indexed_read", "trace[", "entered", "MR8", "MRF32")):
        raise ValueError("Unsupported unified prefix operation")
    exports="""
void set_register(u32 i,u32 v) { if(i>=9)__builtin_trap(); ((u32*)&cpu)[i]=v; }
u32 get_register(u32 i) { if(i>=9)__builtin_trap(); return ((u32*)&cpu)[i]; }
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
            "-Wl,--export=execute","-Wl,--export=set_register","-Wl,--export=get_register",
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
        segments=mapped,bindings=[dict(address=a,convention="thiscall" if a in (0x9b6290,0x9e4b10) else "cdecl",
        argumentBytes=4 if a in (0x9b6290,0x9e4b10) else 8 if a==0x99dcd0 else 12 if a==0x9e78c0 else 0) for a in ADDRESSES])
    (output/"uc-unified-image.json").write_text(json.dumps(descriptor,indent=2)+"\n")
    print(json.dumps(dict(segments=len(mapped),ordinaryBytes=len(payload),bindings=len(ADDRESSES))))

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("output",type=Path)
    args=p.parse_args()
    build(args.image,args.output)

