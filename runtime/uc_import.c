#include "cpu.h"
#include "uc_abi.h"

#if defined(UC_GUEST_CHECKED)
extern void uc_guest_store8(uint32_t addr, uint8_t value);
#define UC_ST8(addr, value) uc_guest_store8((uint32_t)(addr), (uint8_t)(value))
#else
#define UC_ST8(addr, value) (MR8(addr) = (uint8_t)(value))
#endif

uint32_t uc_guest_limit;
int uc_import_trace;
uint32_t uc_import_trace_count;
UcImportFault uc_import_fault;
UcImportTrace uc_import_trace_last;
UcX87Fault uc_x87_fault;
UcHostUnary uc_host_sin;
UcHostUnary uc_host_cos;
UcHostUnary uc_host_acos;

/* The image tracer owns uc_current_fn. This unit does not link it.
 * A harness that has the tracer installs a reader; otherwise the
 * fault still reports EIP, TOP, ST(0), ST(1), FCW, and FSW. */
uint32_t (*uc_x87_current_fn)(void);

static void x87_fail(struct CPU *c, const char *why) {
    uc_x87_fault.active = 1;
    uc_x87_fault.function_va = uc_x87_current_fn ? uc_x87_current_fn() : 0;
    uc_x87_fault.eip = c->eip;
    uc_x87_fault.top = c->top;
    uc_x87_fault.st0 = ST(0);
    uc_x87_fault.st1 = ST(1);
    uc_x87_fault.fcw = c->fcw;
    uc_x87_fault.fsw = fsw_get(c);
    uc_x87_fault.why = why;
}

/* Replace ST(0). TOP is not moved. The host function is only the
 * mathematical operation; it does not see the guest stack. */
static int x87_replace(struct CPU *c, UcHostUnary fn, const char *missing) {
    double in, out;
    if (!fn) {
        x87_fail(c, missing);
        return 0;
    }
    in = ST(0);
    out = fn(in);
    ST(0) = out;
    return 1;
}

#include "uc_import_table.inc"

int uc_abi_callee_bytes(UcAbi abi, int stack_dwords) {
    if (stack_dwords < 0) return -1;
    if (abi == UC_ABI_CDECL) return 0;
    /* Same 4 * n that runtime/win32.c applies for an NFSU2 stdcall import.
     * thiscall and fastcall pop only their stack arguments; ECX and EDX
     * are not stack slots. */
    if (abi == UC_ABI_STDCALL || abi == UC_ABI_THISCALL || abi == UC_ABI_FASTCALL)
        return stack_dwords * 4;
    return -1;
}

unsigned uc_import_count(void) {
    return (unsigned)(sizeof uc_import_table / sizeof uc_import_table[0]);
}

const UcImport *uc_import_find(uint32_t thunk) {
    unsigned n = uc_import_count();
    unsigned lo = 0, hi = n;
    while (lo < hi) {
        unsigned mid = lo + (hi - lo) / 2;
        uint32_t key = uc_import_table[mid].thunk;
        if (key == thunk) return &uc_import_table[mid];
        if (key < thunk) lo = mid + 1;
        else hi = mid;
    }
    return 0;
}

static int range_ok(uint32_t addr, uint32_t len) {
    if (addr >= uc_guest_limit) return 0;
    if (len > uc_guest_limit - addr) return 0;
    return 1;
}

static void copy_bytes(uint32_t dst, uint32_t src, uint32_t n, int backward) {
    uint32_t i;
    if (!n || dst == src) return;
    if (!backward) {
        for (i = 0; i < n; i++) UC_ST8(dst + i, MR8(src + i));
    } else {
        i = n;
        while (i) {
            i--;
            UC_ST8(dst + i, MR8(src + i));
        }
    }
}

static int ranges_overlap(uint32_t a, uint32_t b, uint32_t n) {
    if (!n) return 0;
    if (a + n <= b) return 0;
    if (b + n <= a) return 0;
    return 1;
}

static uint32_t hle_run(struct CPU *c, const UcImport *imp, const UcDecoded *in, int *ok) {
    uint32_t a, b, n, i;
    int diff;
    *ok = 0;
    if (imp->arg_loc == UC_LOC_ST0 || imp->ret_loc == UC_LOC_ST0) {
        if (imp->arg_loc != UC_LOC_ST0 || imp->ret_loc != UC_LOC_ST0) {
            x87_fail(c, "x87 import must read and write ST(0)");
            return 0;
        }
        if (imp->hle == UC_HLE_CISIN)
            *ok = x87_replace(c, uc_host_sin, "host sin is not bound");
        else if (imp->hle == UC_HLE_CICOS)
            *ok = x87_replace(c, uc_host_cos, "host cos is not bound");
        else if (imp->hle == UC_HLE_CIACOS)
            *ok = x87_replace(c, uc_host_acos, "host acos is not bound");
        else
            x87_fail(c, "ST0 import has no x87 HLE");
        return 0;
    }
    if (in->stack_dwords < 1) return 0;
    a = in->stack[0];
    switch (imp->hle) {
    case UC_HLE_STRLEN:
        if (!range_ok(a, 1)) return 0;
        for (i = 0; range_ok(a + i, 1); i++)
            if (MR8(a + i) == 0) { *ok = 1; return i; }
        return 0;
    case UC_HLE_STRCMP:
        if (in->stack_dwords < 2) return 0;
        b = in->stack[1];
        for (i = 0;; i++) {
            if (!range_ok(a + i, 1) || !range_ok(b + i, 1)) return 0;
            if (MR8(a + i) != MR8(b + i) || MR8(a + i) == 0) break;
        }
        diff = (int)MR8(a + i) - (int)MR8(b + i);
        *ok = 1;
        return (uint32_t)diff;
    case UC_HLE_STRNCMP:
        if (in->stack_dwords < 3) return 0;
        b = in->stack[1];
        n = in->stack[2];
        for (i = 0; i < n; i++) {
            if (!range_ok(a + i, 1) || !range_ok(b + i, 1)) return 0;
            if (MR8(a + i) != MR8(b + i) || MR8(a + i) == 0) break;
        }
        if (i == n) { *ok = 1; return 0; }
        diff = (int)MR8(a + i) - (int)MR8(b + i);
        *ok = 1;
        return (uint32_t)diff;
    default:
        break;
    }
    if (in->stack_dwords < 3) return 0;
    b = in->stack[1];
    n = in->stack[2];
    if (!range_ok(a, n) || (imp->hle != UC_HLE_MEMSET && !range_ok(b, n))) return 0;
    switch (imp->hle) {
    case UC_HLE_MEMCPY:
        if (ranges_overlap(a, b, n)) return 0;
        copy_bytes(a, b, n, 0);
        *ok = 1;
        return a;
    case UC_HLE_MEMMOVE:
        copy_bytes(a, b, n, b < a);
        *ok = 1;
        return a;
    case UC_HLE_MEMSET:
        for (i = 0; i < n; i++) UC_ST8(a + i, (uint8_t)b);
        *ok = 1;
        return a;
    case UC_HLE_MEMCMP:
        diff = 0;
        for (i = 0; i < n; i++) {
            if (MR8(a + i) != MR8(b + i)) {
                diff = (int)MR8(a + i) - (int)MR8(b + i);
                break;
            }
        }
        *ok = 1;
        return (uint32_t)diff;
    default:
        return 0;
    }
}

static void fill_fault(struct CPU *c, const UcImport *imp, uint32_t esp, uint32_t ret, const char *why) {
    uc_import_fault.active = 1;
    uc_import_fault.call_site = c->eip;
    uc_import_fault.return_address = ret;
    uc_import_fault.thunk = imp ? imp->thunk : 0;
    uc_import_fault.dll = imp ? imp->dll : "";
    uc_import_fault.symbol = imp ? imp->symbol : "";
    uc_import_fault.ordinal = imp ? imp->ordinal : -1;
    uc_import_fault.esp = esp;
    uc_import_fault.eax = c->eax;
    uc_import_fault.ecx = c->ecx;
    uc_import_fault.edx = c->edx;
    uc_import_fault.ebx = c->ebx;
    uc_import_fault.esi = c->esi;
    uc_import_fault.edi = c->edi;
    uc_import_fault.ebp = c->ebp;
    uc_import_fault.why = why;
}

static void fill_trace(struct CPU *c, const UcImport *imp, uint32_t site, uint32_t esp0, uint32_t eax, int ok) {
    if (!uc_import_trace) return;
    uc_import_trace_count++;
    uc_import_trace_last.call_site = site;
    uc_import_trace_last.thunk = imp ? imp->thunk : 0;
    uc_import_trace_last.dll = imp ? imp->dll : "";
    uc_import_trace_last.symbol = imp ? imp->symbol : "";
    uc_import_trace_last.ordinal = imp ? imp->ordinal : -1;
    uc_import_trace_last.abi = imp ? imp->abi : UC_ABI_UNKNOWN;
    uc_import_trace_last.stack_dwords = imp ? imp->stack_dwords : -1;
    uc_import_trace_last.esp_before = esp0;
    uc_import_trace_last.esp_after = c->esp;
    uc_import_trace_last.eax = eax;
    uc_import_trace_last.ok = ok;
}

static void decode(struct CPU *c, const UcImport *imp, UcDecoded *out) {
    int i, n;
    out->abi = imp->abi;
    out->ecx = c->ecx;
    out->edx = c->edx;
    out->esp = c->esp;
    out->stack_dwords = imp->stack_dwords;
    n = imp->stack_dwords;
    if (n > 8) n = 8;
    for (i = 0; i < 8; i++) out->stack[i] = 0;
    for (i = 0; i < n; i++) out->stack[i] = MR32(c->esp + (uint32_t)(4 * i));
}

int uc_import_invoke(struct CPU *c, const UcImport *imp, UcHleFn override) {
    uint32_t esp0, eax0, ret, eax, site;
    int ok, extra;
    esp0 = c->esp;
    eax0 = c->eax;
    site = c->eip;
    uc_import_fault.active = 0;
    if (!imp || imp->abi == UC_ABI_UNKNOWN) {
        fill_fault(c, imp, esp0, 0, "unknown calling convention");
        fill_trace(c, imp, site, esp0, eax0, 0);
        return 0;
    }
    if (imp->stack_dwords < 0) {
        fill_fault(c, imp, esp0, 0, "argument layout is not recorded");
        fill_trace(c, imp, site, esp0, eax0, 0);
        return 0;
    }
    if (!override && imp->hle == UC_HLE_NONE) {
        fill_fault(c, imp, esp0, 0, "no HLE implementation");
        fill_trace(c, imp, site, esp0, eax0, 0);
        return 0;
    }
    {
        uint32_t popped;
        POP32(popped);
        ret = popped;
    }
    {
        UcDecoded decoded;
        decode(c, imp, &decoded);
        ok = 1;
        if (override) eax = override(c, &decoded, &ok);
        else eax = hle_run(c, imp, &decoded, &ok);
        if (!ok) {
            c->esp = esp0;
            c->eax = eax0;
            fill_fault(c, imp, esp0, ret, "HLE rejected the guest arguments");
            fill_trace(c, imp, site, esp0, eax0, 0);
            return 0;
        }
    }
    extra = uc_abi_callee_bytes(imp->abi, imp->stack_dwords);
    /* An ST0 result stays in the x87 register. EAX is the integer return. */
    if (imp->ret_loc == UC_LOC_ST0) c->eax = eax0;
    else c->eax = eax;
    c->eip = ret;
    if (extra > 0) c->esp += (uint32_t)extra;
    fill_trace(c, imp, site, esp0, c->eax, 1);
    return 1;
}
