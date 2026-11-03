#include "cpu.h"
#include "uc_abi.h"

#if defined(UC_GUEST_CHECKED)
extern void uc_guest_store8(uint32_t addr, uint8_t value);
extern void uc_guest_store32(uint32_t addr, uint32_t value, int *ok);
#define UC_ST8(addr, value) uc_guest_store8((uint32_t)(addr), (uint8_t)(value))
#define UC_ST32(addr, value) do { int _ok = 0; uc_guest_store32((uint32_t)(addr), (uint32_t)(value), &_ok); (void)_ok; } while (0)
#else
#define UC_ST8(addr, value) (MR8(addr) = (uint8_t)(value))
#define UC_ST32(addr, value) (MR32(addr) = (uint32_t)(value))
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
UcHostUnary uc_host_sqrt;

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

static int range_ok(uint32_t addr, uint32_t len);

/* Dynamic Win32 TLS — guest-managed indices/values, not host OS TLS.
 * Today: one active guest-thread context (single-thread harness).
 * Layout keeps a thread axis so multi-thread can be added later. */
enum { UC_TLS_INDEX_MAX = 128, UC_TLS_THREAD_MAX = 1 };
#define UC_TLS_OUT_OF_INDEXES 0xffffffffu
static uint32_t uc_tls_next;
static uint32_t uc_tls_free_stack[UC_TLS_INDEX_MAX];
static int uc_tls_nfree;
static uint8_t uc_tls_allocated[UC_TLS_INDEX_MAX];
static uint32_t uc_tls_values[UC_TLS_THREAD_MAX][UC_TLS_INDEX_MAX];
static unsigned uc_tls_active_thread; /* always 0 for current harness */

void uc_tls_reset(void) {
    unsigned t, i;
    uc_tls_next = 0;
    uc_tls_nfree = 0;
    uc_tls_active_thread = 0;
    for (i = 0; i < UC_TLS_INDEX_MAX; i++) {
        uc_tls_allocated[i] = 0;
        uc_tls_free_stack[i] = 0;
        for (t = 0; t < UC_TLS_THREAD_MAX; t++)
            uc_tls_values[t][i] = 0;
    }
}

unsigned uc_tls_thread_context_count(void) {
    return UC_TLS_THREAD_MAX;
}

int uc_tls_slot_allocated(uint32_t index) {
    return index < UC_TLS_INDEX_MAX && uc_tls_allocated[index];
}

uint32_t uc_tls_get_value(uint32_t index) {
    if (!uc_tls_slot_allocated(index)) return 0;
    if (uc_tls_active_thread >= UC_TLS_THREAD_MAX) return 0;
    return uc_tls_values[uc_tls_active_thread][index];
}

static uint32_t uc_tls_alloc_index(void) {
    uint32_t idx;
    if (uc_tls_nfree > 0)
        idx = uc_tls_free_stack[--uc_tls_nfree];
    else if (uc_tls_next < UC_TLS_INDEX_MAX)
        idx = uc_tls_next++;
    else
        return UC_TLS_OUT_OF_INDEXES;
    uc_tls_allocated[idx] = 1;
    if (uc_tls_active_thread < UC_TLS_THREAD_MAX)
        uc_tls_values[uc_tls_active_thread][idx] = 0;
    return idx;
}

static uint32_t uc_tls_set_value(uint32_t index, uint32_t value) {
    /* Public BOOL: nonzero success. NULL value is valid for an allocated index.
     * GetLastError is not modeled yet. */
    if (!uc_tls_slot_allocated(index)) return 0;
    if (uc_tls_active_thread >= UC_TLS_THREAD_MAX) return 0;
    uc_tls_values[uc_tls_active_thread][index] = value;
    return 1;
}

/* Guest Win32 synchronization — single guest-thread context, no scheduler.
 *
 * CRITICAL_SECTION is the 32-bit Windows layout written into guest memory.
 * Runtime ownership/recursion lives in a side table keyed by guest VA so no
 * host pointer is ever stored in the guest image.
 *
 * Mutexes are opaque guest handles (not host HANDLEs, not guest pointers). */
enum {
    UC_CS_SIZE = 0x18,          /* sizeof(RTL_CRITICAL_SECTION) on x86 */
    UC_CS_CAP = 64,
    UC_MUTEX_CAP = 32,
    UC_MUTEX_NAME_MAX = 64,
    UC_MUTEX_HANDLE_BASE = 0xCD010001u
};

typedef struct UcCritSec {
    uint32_t guest_cs;
    uint8_t initialized;
    uint8_t owned;
    uint32_t owner_thread; /* index into guest-thread contexts; 0 today */
    uint32_t recursion;
} UcCritSec;

typedef struct UcMutex {
    uint8_t active;
    uint8_t named;
    uint8_t owned;
    uint32_t owner_thread;
    char name[UC_MUTEX_NAME_MAX];
} UcMutex;

static UcCritSec uc_cs_tab[UC_CS_CAP];
static unsigned uc_cs_n;
static UcMutex uc_mutex_tab[UC_MUTEX_CAP];
static unsigned uc_mutex_n;

void uc_sync_reset(void) {
    unsigned i;
    uc_cs_n = 0;
    uc_mutex_n = 0;
    for (i = 0; i < UC_CS_CAP; i++) {
        uc_cs_tab[i].guest_cs = 0;
        uc_cs_tab[i].initialized = 0;
        uc_cs_tab[i].owned = 0;
        uc_cs_tab[i].owner_thread = 0;
        uc_cs_tab[i].recursion = 0;
    }
    for (i = 0; i < UC_MUTEX_CAP; i++) {
        uc_mutex_tab[i].active = 0;
        uc_mutex_tab[i].named = 0;
        uc_mutex_tab[i].owned = 0;
        uc_mutex_tab[i].owner_thread = 0;
        uc_mutex_tab[i].name[0] = 0;
    }
}

unsigned uc_sync_critsec_count(void) {
    unsigned i, n = 0;
    for (i = 0; i < uc_cs_n; i++)
        if (uc_cs_tab[i].initialized) n++;
    return n;
}

unsigned uc_sync_mutex_count(void) {
    unsigned i, n = 0;
    for (i = 0; i < UC_MUTEX_CAP; i++)
        if (uc_mutex_tab[i].active) n++;
    return n;
}

int uc_sync_critsec_initialized(uint32_t guest_cs) {
    unsigned i;
    for (i = 0; i < uc_cs_n; i++)
        if (uc_cs_tab[i].guest_cs == guest_cs && uc_cs_tab[i].initialized)
            return 1;
    return 0;
}

int uc_sync_mutex_valid(uint32_t guest_handle) {
    unsigned idx;
    if (guest_handle < UC_MUTEX_HANDLE_BASE) return 0;
    idx = guest_handle - UC_MUTEX_HANDLE_BASE;
    return idx < UC_MUTEX_CAP && uc_mutex_tab[idx].active;
}

static UcCritSec *uc_cs_find(uint32_t guest_cs) {
    unsigned i;
    for (i = 0; i < uc_cs_n; i++)
        if (uc_cs_tab[i].guest_cs == guest_cs)
            return &uc_cs_tab[i];
    return 0;
}

static UcCritSec *uc_cs_alloc(uint32_t guest_cs) {
    UcCritSec *row = uc_cs_find(guest_cs);
    if (row) return row;
    if (uc_cs_n >= UC_CS_CAP) return 0;
    row = &uc_cs_tab[uc_cs_n++];
    row->guest_cs = guest_cs;
    row->initialized = 0;
    row->owned = 0;
    row->owner_thread = 0;
    row->recursion = 0;
    return row;
}

/* 32-bit RTL_CRITICAL_SECTION field stores. DebugInfo is NULL — never a host
 * pointer. LockCount = -1 means unlocked (Windows convention). */
static int uc_cs_write_guest(uint32_t cs) {
    if (!range_ok(cs, UC_CS_SIZE)) return 0;
    UC_ST32(cs + 0x00, 0);          /* DebugInfo */
    UC_ST32(cs + 0x04, 0xffffffffu); /* LockCount = -1 */
    UC_ST32(cs + 0x08, 0);          /* RecursionCount */
    UC_ST32(cs + 0x0c, 0);          /* OwningThread */
    UC_ST32(cs + 0x10, 0);          /* LockSemaphore */
    UC_ST32(cs + 0x14, 0);          /* SpinCount */
    return 1;
}

static uint32_t uc_hle_init_critsec(uint32_t cs, int *ok) {
    UcCritSec *row;
    *ok = 0;
    if (!cs) return 0; /* NULL → fail; do not claim success */
    if (!range_ok(cs, UC_CS_SIZE)) return 0;
    row = uc_cs_alloc(cs);
    if (!row) return 0;
    if (!uc_cs_write_guest(cs)) return 0;
    /* Re-init of an existing CS: Windows documents this as undefined.
     * We reset runtime ownership and rewrite the guest fields. */
    row->initialized = 1;
    row->owned = 0;
    row->owner_thread = 0;
    row->recursion = 0;
    *ok = 1;
    return 0; /* VOID API; EAX unused by observed callers */
}

static int uc_mutex_name_eq(const UcMutex *m, uint32_t name_va) {
    unsigned i;
    if (!m->named) return 0;
    if (!name_va) return 0;
    for (i = 0; i < UC_MUTEX_NAME_MAX; i++) {
        uint8_t ch;
        if (!range_ok(name_va + i, 1)) return 0;
        ch = MR8(name_va + i);
        if ((uint8_t)m->name[i] != ch) return 0;
        if (ch == 0) return 1;
    }
    return 0;
}

static int uc_mutex_copy_name(UcMutex *m, uint32_t name_va) {
    unsigned i;
    m->named = 1;
    for (i = 0; i < UC_MUTEX_NAME_MAX - 1; i++) {
        uint8_t ch;
        if (!range_ok(name_va + i, 1)) return 0;
        ch = MR8(name_va + i);
        m->name[i] = (char)ch;
        if (ch == 0) return 1;
    }
    m->name[UC_MUTEX_NAME_MAX - 1] = 0;
    return 1;
}

static uint32_t uc_hle_create_mutex_a(uint32_t attrs, uint32_t initial_owner,
                                     uint32_t name_va, int *ok) {
    unsigned i;
    UcMutex *slot;
    *ok = 0;
    /* lpMutexAttributes: only NULL is supported (observed UC path pushes 0). */
    if (attrs != 0) return 0;
    if (name_va) {
        for (i = 0; i < UC_MUTEX_CAP; i++) {
            if (uc_mutex_tab[i].active && uc_mutex_name_eq(&uc_mutex_tab[i], name_va)) {
                /* Existing named mutex: return same guest handle.
                 * GetLastError ERROR_ALREADY_EXISTS is not modeled. */
                *ok = 1;
                if (initial_owner) {
                    /* Cannot steal ownership without a scheduler when already owned
                     * by another context; single-thread: allow if unowned or self. */
                    if (!uc_mutex_tab[i].owned ||
                        uc_mutex_tab[i].owner_thread == uc_tls_active_thread) {
                        uc_mutex_tab[i].owned = 1;
                        uc_mutex_tab[i].owner_thread = uc_tls_active_thread;
                    }
                }
                return UC_MUTEX_HANDLE_BASE + i;
            }
        }
    }
    slot = 0;
    for (i = 0; i < UC_MUTEX_CAP; i++) {
        if (!uc_mutex_tab[i].active) { slot = &uc_mutex_tab[i]; break; }
    }
    if (!slot) return 0;
    slot->active = 1;
    slot->named = 0;
    slot->name[0] = 0;
    slot->owned = initial_owner ? 1 : 0;
    slot->owner_thread = initial_owner ? uc_tls_active_thread : 0;
    if (name_va) {
        if (!uc_mutex_copy_name(slot, name_va)) {
            slot->active = 0;
            return 0;
        }
    }
    if (uc_mutex_n < UC_MUTEX_CAP) uc_mutex_n++;
    *ok = 1;
    return UC_MUTEX_HANDLE_BASE + (unsigned)(slot - uc_mutex_tab);
}

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

const UcImport *uc_import_find_by_iat(uint32_t iat_slot) {
    unsigned i, n = uc_import_count();
    for (i = 0; i < n; i++)
        if (uc_import_table[i].iat_slot == iat_slot)
            return &uc_import_table[i];
    return 0;
}

const UcImport *uc_import_find_dispatch_target(uint32_t target) {
    const UcImport *imp = uc_import_find(target);
    unsigned i, n;
    if (imp) return imp;
    n = uc_import_count();
    for (i = 0; i < n; i++) {
        imp = &uc_import_table[i];
        if (imp->hle == UC_HLE_NONE || !imp->iat_slot) continue;
        if (MR32(imp->iat_slot) == target) return imp;
    }
    return 0;
}

unsigned uc_import_bind_hle_iats(void) {
    unsigned i, n = uc_import_count(), bound = 0;
    for (i = 0; i < n; i++) {
        const UcImport *imp = &uc_import_table[i];
        if (imp->hle == UC_HLE_NONE || !imp->iat_slot)
            continue;
#if defined(UC_GUEST_CHECKED)
        {
            int ok = 0;
            uc_guest_store32(imp->iat_slot, imp->thunk, &ok);
            if (!ok) continue;
        }
#else
        MR32(imp->iat_slot) = imp->thunk;
#endif
        bound++;
    }
    return bound;
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
    if (imp->hle == UC_HLE_TLSALLOC) {
        /* KERNEL32!TlsAlloc: stdcall, 0 stack args; EAX = index or 0xFFFFFFFF. */
        (void)in;
        *ok = 1;
        return uc_tls_alloc_index();
    }
    if (imp->hle == UC_HLE_TLSSETVALUE) {
        /* KERNEL32!TlsSetValue(index, value): stdcall, 2 stack dwords; EAX BOOL. */
        if (in->stack_dwords < 2) return 0;
        *ok = 1;
        return uc_tls_set_value(in->stack[0], in->stack[1]);
    }
    if (imp->hle == UC_HLE_INITCRITSEC) {
        /* KERNEL32!InitializeCriticalSection(lpCriticalSection): stdcall, 1 arg; VOID. */
        if (in->stack_dwords < 1) return 0;
        return uc_hle_init_critsec(in->stack[0], ok);
    }
    if (imp->hle == UC_HLE_CREATEMUTEXA) {
        /* KERNEL32!CreateMutexA(attrs, initialOwner, name): stdcall, 3 args; HANDLE. */
        if (in->stack_dwords < 3) return 0;
        return uc_hle_create_mutex_a(in->stack[0], in->stack[1], in->stack[2], ok);
    }
    if (imp->hle == UC_HLE_GETCURRENTPROCESS) {
        /* KERNEL32!GetCurrentProcess(): stdcall, 0 args; returns pseudo-handle -1.
         * Not a host HANDLE and not a guest pointer. */
        (void)in;
        *ok = 1;
        return 0xffffffffu;
    }
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
        else if (imp->hle == UC_HLE_CISQRT)
            *ok = x87_replace(c, uc_host_sqrt, "host sqrt is not bound");
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
    case UC_HLE_STRNCPY:
        /* Standard CRT: copy at most n bytes; pad with NULs when src is shorter.
         * Dest need not be NUL-terminated when src length >= n. */
        if (in->stack_dwords < 3) return 0;
        b = in->stack[1];
        n = in->stack[2];
        if (!range_ok(a, n)) return 0;
        for (i = 0; i < n; i++) {
            uint8_t ch;
            if (!range_ok(b + i, 1)) return 0;
            ch = MR8(b + i);
            UC_ST8(a + i, ch);
            if (ch == 0) {
                for (i++; i < n; i++) UC_ST8(a + i, 0);
                break;
            }
        }
        *ok = 1;
        return a;
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
