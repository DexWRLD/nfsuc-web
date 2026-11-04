/* Checked arithmetic flags for the admitted ordinary x86 subset.
 * Eager calculation deliberately ignores RawLifter liveness masks. Undefined
 * AF after logical instructions is marked unknown; a later consumer traps.
 * All CPU fields remain volatile across re-entrant Wasm imports. */
#define F_CF 1u
#define F_PF 2u
#define F_AF 4u
#define F_ZF 8u
#define F_SF 16u
#define F_OF 32u
#define F_ALL 63u
static u32 flag_read(CPU *c,u32 bit) {
    if (!(c->flags_known & bit)) __builtin_trap();
    switch(bit) {
    case F_CF:return c->cf; case F_PF:return c->pf; case F_AF:return c->af;
    case F_ZF:return c->zf; case F_SF:return c->sf; case F_OF:return c->of;
    default:__builtin_trap();
    }
}
static u32 width_mask(u32 n) {
    if(n!=8 && n!=16 && n!=32) __builtin_trap();
    return n==32?0xffffffffu:((1u<<n)-1u);
}
static void arithmetic_flags(CPU *c,u32 a,u32 b,u32 ci,u32 result,u32 n,u32 sub) {
    u32 mask=width_mask(n), sign=1u<<(n-1);
    a&=mask;b&=mask;result&=mask;
    unsigned long long rhs=(unsigned long long)b+ci;
    c->cf=sub?((unsigned long long)a<rhs):((unsigned long long)a+rhs>mask);
    c->of=((sub?(a^b):~(a^b))&(a^result)&sign)!=0;
    c->af=((a^b^result)&16u)!=0;
    c->zf=result==0;c->sf=(result&sign)!=0;
    u32 p=result&255u;p^=p>>4;p^=p>>2;p^=p>>1;c->pf=(~p)&1u;
    c->flags_known=F_ALL;
}
static void logical_flags(CPU *c,u32 result,u32 n) {
    arithmetic_flags(c,result&width_mask(n),0,0,result,n,0);
    c->cf=0;c->of=0;c->flags_known=F_ALL&~F_AF;
}
#define FLAGS_SUB_M(a,b,r,n,m) arithmetic_flags(c,a,b,0,r,n,1)
#define FLAGS_ADD_M(a,b,r,n,m) arithmetic_flags(c,a,b,0,r,n,0)
#define FLAGS_SBB_M(a,b,ci,r,n,m) arithmetic_flags(c,a,b,ci,r,n,1)
#define FLAGS_ADC_M(a,b,ci,r,n,m) arithmetic_flags(c,a,b,ci,r,n,0)
#define FLAGS_LOG_M(r,n,m) logical_flags(c,r,n)
#define CC_O flag_read(c,F_OF)
#define CC_NO (!CC_O)
#define CC_B flag_read(c,F_CF)
#define CC_AE (!CC_B)
#define CC_E flag_read(c,F_ZF)
#define CC_NE (!CC_E)
#define CC_BE (CC_B || CC_E)
#define CC_A (!CC_B && !CC_E)
#define CC_S flag_read(c,F_SF)
#define CC_NS (!CC_S)
#define CC_P flag_read(c,F_PF)
#define CC_NP (!CC_P)
#define CC_L (flag_read(c,F_SF)!=flag_read(c,F_OF))
#define CC_GE (!CC_L)
#define CC_LE (CC_E || CC_L)
#define CC_G (!CC_E && !CC_L)
static u32 flags_value(CPU *c) {
    return c->cf|(c->pf<<2)|(c->af<<4)|(c->zf<<6)|(c->sf<<7)|(c->of<<11);
}
static void flags_restore(CPU *c,u32 v,u32 known) {
    c->cf=v&1;c->pf=(v>>2)&1;c->af=(v>>4)&1;c->zf=(v>>6)&1;
    c->sf=(v>>7)&1;c->of=(v>>11)&1;c->flags_known=known&F_ALL;
}
