"""Build infrastructure-only arithmetic tests, including a lifted wrapper fixture.

The fixture's callee return is synthetic and is never registered in the game
process. This does not establish cleanup registration or callee execution.
"""
import re
import subprocess
import sys
from pathlib import Path
import lift
import uc_unified_build as unified
import uc_phase7_test as p7


def build(output):
    # Exact wrapper bytes are separately checked against the authenticated PE.
    body, _ = lift.RawLifter(bytes.fromhex('ff742404e852fffffff7d81bc0f7d85948c3'),
                            0x87b640, comments=True).lift(0x87b640)
    body = re.sub(r'sub_([0-9a-f]+)\(c\)', lambda m: 'dispatch(0x'+m[1]+'u)', body)
    body = body.replace('dispatch_indirect(c, 0x87b59bu)', 'dispatch(0x87b59bu)')
    body = unified.transform_flags(body)
    source = unified.HEADER + body + r'''
u32 arithmetic(u32 op,u32 a,u32 b,u32 n) {
    CPU *c=&cpu; u32 mask=width_mask(n),ci=0,result;
    a&=mask;b&=mask;
    if(op==4)ci=flag_read(c,F_CF);
    if(op==0) {result=a+b;FLAGS_ADD_M(a,b,result,n,0);}
    else if(op==1) {result=a-b;FLAGS_SUB_M(a,b,result,n,0);}
    else if(op==2) {result=0-a;FLAGS_SUB_M(0,a,result,n,0);}
    else if(op==3) {
        u32 old=c->cf,known=c->flags_known&F_CF;result=a-1;
        FLAGS_SUB_M(a,1,result,n,0);c->cf=old;
        c->flags_known=(c->flags_known&~F_CF)|known;
    }
    else if(op==4) {result=a-b-ci;FLAGS_SBB_M(a,b,ci,result,n,0);}
    else if(op==5) {result=a&b;FLAGS_LOG_M(result,n,0);}
    else __builtin_trap();
    return result&mask;
}
u32 flags(void) {return flags_value(&cpu);}
u32 known(void) {return cpu.flags_known;}
u32 condition(u32 which) {
    CPU *c=&cpu;
    switch(which) {
    case 0:return CC_O;case 1:return CC_NO;case 2:return CC_B;case 3:return CC_AE;
    case 4:return CC_E;case 5:return CC_NE;case 6:return CC_BE;case 7:return CC_A;
    case 8:return CC_S;case 9:return CC_NS;case 10:return CC_P;case 11:return CC_NP;
    case 12:return CC_L;case 13:return CC_GE;case 14:return CC_LE;case 15:return CC_G;
    case 16:return flag_read(c,F_AF);default:__builtin_trap();
    }
}
u32 nested(void) {
    CPU *c=&cpu;
    FLAGS_SUB_M(0,1,0xffffffffu,32,0); /* Actual instruction establishes CF. */
    dispatch(0xf17u); /* Re-entrant infrastructure test, no game binding. */
    u32 ci=flag_read(c,F_CF),result=0-ci;
    FLAGS_SBB_M(0,0,ci,result,32,0);
    return result;
}
u32 wrapper_fixture(void) {
    cpu.esp=0x10000u;cpu.ebp=0x1234u;cpu.ebx=0x5678u;
    cpu.esi=0xabcdu;cpu.edi=0xef01u;
    write32(cpu.esp,0xdec0deu);write32(cpu.esp+4,0xb602e0u);
    sub_0087b640(&cpu);return cpu.eax;
}
void fixture_return(u32 value) {
    /* Explicit synthetic unavailable-callee result for wrapper ABI tests only. */
    cpu.eax=value;cpu.eip=read32(cpu.esp);cpu.esp+=4;
}
u32 register_value(u32 i) {if(i>=9)__builtin_trap();return ((volatile u32*)&cpu)[i];}
'''
    output = Path(output)
    cfile = output.with_suffix('.c')
    cfile.write_text(source, encoding='utf-8')
    exports = ['arithmetic','flags','known','condition','nested','wrapper_fixture','fixture_return','register_value']
    subprocess.run([p7.clang(),'--target=wasm32-unknown-unknown','-O2','-ffreestanding','-nostdlib',
                    '-Wl,--no-entry','-Wl,--import-memory','-Wl,--initial-memory=131072',
                    *['-Wl,--export='+name for name in exports],str(cfile),'-o',str(output)],check=True)

if __name__ == '__main__':
    build(sys.argv[1])
