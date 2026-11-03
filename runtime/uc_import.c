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

/* Guest Win32 synchronization / process — single guest-thread, no scheduler.
 *
 * CRITICAL_SECTION: 32-bit layout in guest memory + VA-keyed side table.
 * Kernel objects (MUTEX / SEMAPHORE): opaque guest handles 0xCD010001+idx.
 * Process: one logical guest process; pseudo-handle 0xFFFFFFFF.
 * Never store host HANDLEs or host pointers in guest memory. */
enum {
    UC_CS_SIZE = 0x18,
    UC_CS_CAP = 64,
    UC_OBJ_CAP = 64,
    UC_OBJ_NAME_MAX = 64,
    UC_HANDLE_BASE = 0xCD010001u,
    UC_OBJ_NONE = 0,
    UC_OBJ_MUTEX = 1,
    UC_OBJ_SEMAPHORE = 2,
    UC_PROCESS_PSEUDO = 0xffffffffu,
    UC_THREAD_PSEUDO = 0xfffffffeu,
    UC_NORMAL_PRIORITY_CLASS = 0x00000020u,
    UC_IDLE_PRIORITY_CLASS = 0x00000040u,
    UC_HIGH_PRIORITY_CLASS = 0x00000080u,
    UC_REALTIME_PRIORITY_CLASS = 0x00000100u,
    UC_BELOW_NORMAL_PRIORITY_CLASS = 0x00004000u,
    UC_ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000u,
    UC_THREAD_PRIORITY_NORMAL = 0,
    UC_THREAD_PRIORITY_ERROR_RETURN = 0x7fffffff
};

typedef struct UcCritSec {
    uint32_t guest_cs;
    uint8_t initialized;
    uint8_t owned;
    uint32_t owner_thread;
    uint32_t recursion;
} UcCritSec;

typedef struct UcKernelObj {
    uint8_t active;
    uint8_t type;          /* UC_OBJ_MUTEX or UC_OBJ_SEMAPHORE */
    uint8_t named;
    uint8_t owned;         /* mutex */
    uint32_t owner_thread; /* mutex */
    int32_t count;         /* semaphore current */
    int32_t max_count;     /* semaphore maximum */
    char name[UC_OBJ_NAME_MAX];
} UcKernelObj;

static UcCritSec uc_cs_tab[UC_CS_CAP];
static unsigned uc_cs_n;
static UcKernelObj uc_obj_tab[UC_OBJ_CAP];
static uint32_t uc_guest_priority_class;
static int32_t uc_guest_thread_priority;
/* One active guest thread context (index 0). Not a scheduler. */
static unsigned uc_guest_thread_active = 1;

void uc_process_reset(void) {
    /* Documented initial policy: NORMAL_PRIORITY_CLASS. */
    uc_guest_priority_class = UC_NORMAL_PRIORITY_CLASS;
}

void uc_thread_reset(void) {
    /* Relative thread priority independent of process priority class. */
    uc_guest_thread_priority = UC_THREAD_PRIORITY_NORMAL;
    uc_guest_thread_active = 1;
}

/*
 * Deterministic guest monotonic performance clock.
 * Frequency: 10,000,000 ticks/second (virtual; not host hardware).
 * Epoch: zero at each harness/runtime reset.
 * Advancement: only via uc_guest_clock_advance_ns — never host wall-clock.
 * Virtual TSC: 3.0 GHz coherent with the same timebase (300 cycles/QPC tick).
 */
#define UC_QPF_HZ            10000000ull
#define UC_NS_PER_QPC_TICK   100ull      /* 1e9 / 1e7 */
#define UC_TSC_PER_QPC_TICK  300ull      /* 3e9 / 1e7 */
static uint64_t uc_guest_qpc_ticks;

void uc_guest_clock_reset(void) {
    uc_guest_qpc_ticks = 0;
}

uint64_t uc_guest_clock_qpc(void) {
    return uc_guest_qpc_ticks;
}

uint64_t uc_guest_clock_qpf(void) {
    return UC_QPF_HZ;
}

uint64_t uc_guest_clock_tsc(void) {
    return uc_guest_qpc_ticks * UC_TSC_PER_QPC_TICK;
}

int uc_guest_clock_advance_ns(uint64_t delta_ns) {
    uint64_t ticks, room;
    ticks = delta_ns / UC_NS_PER_QPC_TICK;
    if (!ticks && delta_ns) {
        /* Sub-tick deltas do not move the counter (documented rounding). */
        return 1;
    }
    room = ~uc_guest_qpc_ticks;
    if (ticks > room) return 0;
    uc_guest_qpc_ticks += ticks;
    return 1;
}

/*
 * Deterministic guest wait (SleepEx timeout-only).
 * Single guest thread. No scheduler. No APC delivery.
 * Alertable finite waits may complete by timeout only when no pending APC
 * exists in the supported guest model.
 */
#define UC_WAIT_INFINITE 0xffffffffu
#define UC_NS_PER_MS     1000000ull
static int uc_wait_apc_pending;
static unsigned uc_wait_sleepex_done;
/* Last completed wait descriptor (diagnostic / tests). */
static uint32_t uc_wait_last_ms;
static int uc_wait_last_alertable;
static uint64_t uc_wait_last_start_ticks;
static uint64_t uc_wait_last_deadline_ticks;

void uc_wait_reset(void) {
    uc_wait_apc_pending = 0;
    uc_wait_sleepex_done = 0;
    uc_wait_last_ms = 0;
    uc_wait_last_alertable = 0;
    uc_wait_last_start_ticks = 0;
    uc_wait_last_deadline_ticks = 0;
}

void uc_wait_set_pending_apc(int pending) {
    uc_wait_apc_pending = pending ? 1 : 0;
}

int uc_wait_pending_apc(void) {
    return uc_wait_apc_pending;
}

unsigned uc_wait_sleepex_completions(void) {
    return uc_wait_sleepex_done;
}

static uint32_t uc_hle_sleep_ex(uint32_t ms, uint32_t alertable, int *ok) {
    uint64_t start, need_ns, need_ticks, room;
    int alert = alertable != 0;
    /* Infinite wait: no wake source in the single-thread model. */
    if (ms == UC_WAIT_INFINITE) {
        *ok = 0;
        return 0;
    }
    /* Known pending APC: timeout-only path must not ignore it. */
    if (alert && uc_wait_apc_pending) {
        *ok = 0;
        return 0;
    }
    start = uc_guest_qpc_ticks;
    if (ms == 0) {
        /* Zero timeout: complete immediately; no invented elapsed time. */
        uc_wait_last_ms = 0;
        uc_wait_last_alertable = alert;
        uc_wait_last_start_ticks = start;
        uc_wait_last_deadline_ticks = start;
        uc_wait_sleepex_done++;
        *ok = 1;
        return 0; /* timeout */
    }
    /* Finite timeout: advance virtual time by exactly ms milliseconds. */
    need_ns = (uint64_t)ms * UC_NS_PER_MS;
    need_ticks = need_ns / UC_NS_PER_QPC_TICK;
    room = ~uc_guest_qpc_ticks;
    if (need_ticks > room) {
        *ok = 0;
        return 0;
    }
    uc_guest_qpc_ticks += need_ticks;
    uc_wait_last_ms = ms;
    uc_wait_last_alertable = alert;
    uc_wait_last_start_ticks = start;
    uc_wait_last_deadline_ticks = uc_guest_qpc_ticks;
    uc_wait_sleepex_done++;
    *ok = 1;
    return 0; /* WAIT_OBJECT_0 / timeout; never WAIT_IO_COMPLETION here */
}

static int uc_store_u64_le(uint32_t addr, uint64_t value) {
    int ok_lo = 1, ok_hi = 1;
    if (!range_ok(addr, 8)) return 0;
#if defined(UC_GUEST_CHECKED)
    uc_guest_store32(addr, (uint32_t)value, &ok_lo);
    uc_guest_store32(addr + 4u, (uint32_t)(value >> 32), &ok_hi);
    return ok_lo && ok_hi;
#else
    UC_ST32(addr, (uint32_t)value);
    UC_ST32(addr + 4u, (uint32_t)(value >> 32));
    (void)ok_lo; (void)ok_hi;
    return 1;
#endif
}

uint32_t uc_process_priority_class(void) {
    return uc_guest_priority_class;
}

int32_t uc_thread_priority(void) {
    return uc_guest_thread_priority;
}

unsigned uc_active_guest_threads(void) {
    return uc_guest_thread_active;
}

int uc_process_pseudo_handle(uint32_t handle) {
    return handle == UC_PROCESS_PSEUDO;
}

int uc_thread_pseudo_handle(uint32_t handle) {
    return handle == UC_THREAD_PSEUDO;
}

static int uc_priority_class_valid(uint32_t cls) {
    return cls == UC_IDLE_PRIORITY_CLASS
        || cls == UC_BELOW_NORMAL_PRIORITY_CLASS
        || cls == UC_NORMAL_PRIORITY_CLASS
        || cls == UC_ABOVE_NORMAL_PRIORITY_CLASS
        || cls == UC_HIGH_PRIORITY_CLASS
        || cls == UC_REALTIME_PRIORITY_CLASS;
}

static int uc_thread_priority_valid(int32_t p) {
    /* Documented Win32 relative priorities (incl. TIME_CRITICAL=15, IDLE=-15). */
    return p == -15 || p == -2 || p == -1 || p == 0 || p == 1 || p == 2 || p == 15;
}

void uc_sync_reset(void) {
    unsigned i;
    uc_cs_n = 0;
    for (i = 0; i < UC_CS_CAP; i++) {
        uc_cs_tab[i].guest_cs = 0;
        uc_cs_tab[i].initialized = 0;
        uc_cs_tab[i].owned = 0;
        uc_cs_tab[i].owner_thread = 0;
        uc_cs_tab[i].recursion = 0;
    }
    for (i = 0; i < UC_OBJ_CAP; i++) {
        uc_obj_tab[i].active = 0;
        uc_obj_tab[i].type = UC_OBJ_NONE;
        uc_obj_tab[i].named = 0;
        uc_obj_tab[i].owned = 0;
        uc_obj_tab[i].owner_thread = 0;
        uc_obj_tab[i].count = 0;
        uc_obj_tab[i].max_count = 0;
        uc_obj_tab[i].name[0] = 0;
    }
    uc_process_reset();
    uc_thread_reset();
    uc_guest_clock_reset();
    uc_wait_reset();
}

unsigned uc_sync_critsec_count(void) {
    unsigned i, n = 0;
    for (i = 0; i < uc_cs_n; i++)
        if (uc_cs_tab[i].initialized) n++;
    return n;
}

unsigned uc_sync_mutex_count(void) {
    unsigned i, n = 0;
    for (i = 0; i < UC_OBJ_CAP; i++)
        if (uc_obj_tab[i].active && uc_obj_tab[i].type == UC_OBJ_MUTEX) n++;
    return n;
}

unsigned uc_sync_semaphore_count(void) {
    unsigned i, n = 0;
    for (i = 0; i < UC_OBJ_CAP; i++)
        if (uc_obj_tab[i].active && uc_obj_tab[i].type == UC_OBJ_SEMAPHORE) n++;
    return n;
}

int uc_sync_critsec_initialized(uint32_t guest_cs) {
    unsigned i;
    for (i = 0; i < uc_cs_n; i++)
        if (uc_cs_tab[i].guest_cs == guest_cs && uc_cs_tab[i].initialized)
            return 1;
    return 0;
}

static UcKernelObj *uc_obj_from_handle(uint32_t handle) {
    unsigned idx;
    if (handle < UC_HANDLE_BASE) return 0;
    idx = handle - UC_HANDLE_BASE;
    if (idx >= UC_OBJ_CAP || !uc_obj_tab[idx].active) return 0;
    return &uc_obj_tab[idx];
}

int uc_sync_mutex_valid(uint32_t guest_handle) {
    UcKernelObj *o = uc_obj_from_handle(guest_handle);
    return o && o->type == UC_OBJ_MUTEX;
}

int uc_sync_semaphore_valid(uint32_t guest_handle) {
    UcKernelObj *o = uc_obj_from_handle(guest_handle);
    return o && o->type == UC_OBJ_SEMAPHORE;
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

static int uc_obj_name_eq(const UcKernelObj *o, uint32_t name_va) {
    unsigned i;
    if (!o->named || !name_va) return 0;
    for (i = 0; i < UC_OBJ_NAME_MAX; i++) {
        uint8_t ch;
        if (!range_ok(name_va + i, 1)) return 0;
        ch = MR8(name_va + i);
        if ((uint8_t)o->name[i] != ch) return 0;
        if (ch == 0) return 1;
    }
    return 0;
}

static int uc_obj_copy_name(UcKernelObj *o, uint32_t name_va) {
    unsigned i;
    o->named = 1;
    for (i = 0; i < UC_OBJ_NAME_MAX - 1; i++) {
        uint8_t ch;
        if (!range_ok(name_va + i, 1)) return 0;
        ch = MR8(name_va + i);
        o->name[i] = (char)ch;
        if (ch == 0) return 1;
    }
    o->name[UC_OBJ_NAME_MAX - 1] = 0;
    return 1;
}

static UcKernelObj *uc_obj_alloc_slot(void) {
    unsigned i;
    for (i = 0; i < UC_OBJ_CAP; i++)
        if (!uc_obj_tab[i].active) return &uc_obj_tab[i];
    return 0;
}

static uint32_t uc_obj_handle(const UcKernelObj *o) {
    return UC_HANDLE_BASE + (unsigned)(o - uc_obj_tab);
}

static UcKernelObj *uc_obj_find_named(uint8_t type, uint32_t name_va) {
    unsigned i;
    if (!name_va) return 0;
    for (i = 0; i < UC_OBJ_CAP; i++) {
        if (uc_obj_tab[i].active && uc_obj_tab[i].type == type &&
            uc_obj_name_eq(&uc_obj_tab[i], name_va))
            return &uc_obj_tab[i];
    }
    return 0;
}

static uint32_t uc_hle_create_mutex_a(uint32_t attrs, uint32_t initial_owner,
                                     uint32_t name_va, int *ok) {
    UcKernelObj *slot;
    *ok = 0;
    if (attrs != 0) return 0;
    if (name_va) {
        slot = uc_obj_find_named(UC_OBJ_MUTEX, name_va);
        if (slot) {
            /* GetLastError ERROR_ALREADY_EXISTS not modeled. */
            *ok = 1;
            if (initial_owner &&
                (!slot->owned || slot->owner_thread == uc_tls_active_thread)) {
                slot->owned = 1;
                slot->owner_thread = uc_tls_active_thread;
            }
            return uc_obj_handle(slot);
        }
        /* Named object of another type → fail rather than overwrite. */
        if (uc_obj_find_named(UC_OBJ_SEMAPHORE, name_va)) return 0;
    }
    slot = uc_obj_alloc_slot();
    if (!slot) return 0;
    slot->active = 1;
    slot->type = UC_OBJ_MUTEX;
    slot->named = 0;
    slot->name[0] = 0;
    slot->owned = initial_owner ? 1 : 0;
    slot->owner_thread = initial_owner ? uc_tls_active_thread : 0;
    slot->count = 0;
    slot->max_count = 0;
    if (name_va && !uc_obj_copy_name(slot, name_va)) {
        slot->active = 0;
        slot->type = UC_OBJ_NONE;
        return 0;
    }
    *ok = 1;
    return uc_obj_handle(slot);
}

static uint32_t uc_hle_create_semaphore_a(uint32_t attrs, uint32_t initial,
                                         uint32_t maximum, uint32_t name_va,
                                         int *ok) {
    UcKernelObj *slot;
    int32_t init = (int32_t)initial;
    int32_t maxc = (int32_t)maximum;
    *ok = 0;
    if (attrs != 0) return 0;
    /* Standard constraints: max > 0; initial >= 0; initial <= max. */
    if (maxc <= 0 || init < 0 || init > maxc) return 0;
    if (name_va) {
        slot = uc_obj_find_named(UC_OBJ_SEMAPHORE, name_va);
        if (slot) {
            /* Existing named semaphore: return same handle; do not rewrite counts.
             * ERROR_ALREADY_EXISTS not modeled (no guest last-error yet). */
            *ok = 1;
            return uc_obj_handle(slot);
        }
        if (uc_obj_find_named(UC_OBJ_MUTEX, name_va)) return 0;
    }
    slot = uc_obj_alloc_slot();
    if (!slot) return 0;
    slot->active = 1;
    slot->type = UC_OBJ_SEMAPHORE;
    slot->named = 0;
    slot->name[0] = 0;
    slot->owned = 0;
    slot->owner_thread = 0;
    slot->count = init;
    slot->max_count = maxc;
    if (name_va && !uc_obj_copy_name(slot, name_va)) {
        slot->active = 0;
        slot->type = UC_OBJ_NONE;
        return 0;
    }
    *ok = 1;
    return uc_obj_handle(slot);
}

static uint32_t uc_hle_get_priority_class(uint32_t handle, int *ok) {
    /* stdcall GetPriorityClass(hProcess) → DWORD. Failure returns 0.
     * Call completes either way (*ok=1); GetLastError not modeled. */
    *ok = 1;
    if (!uc_process_pseudo_handle(handle)) return 0;
    return uc_guest_priority_class;
}

static uint32_t uc_hle_set_priority_class(uint32_t handle, uint32_t cls, int *ok) {
    /* SetPriorityClass(hProcess, dwPriorityClass) → BOOL.
     * Updates guest-visible process priority only — never host scheduling. */
    *ok = 1;
    if (!uc_process_pseudo_handle(handle) || !uc_priority_class_valid(cls))
        return 0;
    uc_guest_priority_class = cls;
    return 1;
}

static uint32_t uc_hle_get_thread_priority(uint32_t handle, int *ok) {
    /* GetThreadPriority(hThread) → int; invalid → THREAD_PRIORITY_ERROR_RETURN. */
    *ok = 1;
    if (!uc_thread_pseudo_handle(handle))
        return (uint32_t)UC_THREAD_PRIORITY_ERROR_RETURN;
    return (uint32_t)uc_guest_thread_priority;
}

static uint32_t uc_hle_set_thread_priority(uint32_t handle, uint32_t prio, int *ok) {
    /* SetThreadPriority(hThread, nPriority) → BOOL; guest state only. */
    int32_t p = (int32_t)prio;
    *ok = 1;
    if (!uc_thread_pseudo_handle(handle) || !uc_thread_priority_valid(p))
        return 0;
    uc_guest_thread_priority = p;
    return 1;
}

static uint32_t uc_hle_query_performance_counter(uint32_t out, int *ok) {
    /* QueryPerformanceCounter(LARGE_INTEGER*): stdcall 1 arg → BOOL.
     * Writes little-endian 64-bit guest counter. Invalid buffer → reject. */
    if (!uc_store_u64_le(out, uc_guest_clock_qpc())) {
        *ok = 0;
        return 0;
    }
    *ok = 1;
    return 1;
}

static uint32_t uc_hle_query_performance_frequency(uint32_t out, int *ok) {
    /* QueryPerformanceFrequency(LARGE_INTEGER*): same timebase as QPC. */
    if (!uc_store_u64_le(out, uc_guest_clock_qpf())) {
        *ok = 0;
        return 0;
    }
    *ok = 1;
    return 1;
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
        return UC_PROCESS_PSEUDO;
    }
    if (imp->hle == UC_HLE_GETCURRENTTHREAD) {
        /* GetCurrentThread(): stdcall, 0 args; pseudo-handle 0xFFFFFFFE.
         * Resolves to the single active guest-thread context; not a host handle. */
        (void)in;
        *ok = 1;
        return UC_THREAD_PSEUDO;
    }
    if (imp->hle == UC_HLE_GETPRIORITYCLASS) {
        /* KERNEL32!GetPriorityClass(hProcess): stdcall, 1 arg; DWORD in EAX. */
        if (in->stack_dwords < 1) return 0;
        return uc_hle_get_priority_class(in->stack[0], ok);
    }
    if (imp->hle == UC_HLE_SETPRIORITYCLASS) {
        if (in->stack_dwords < 2) return 0;
        return uc_hle_set_priority_class(in->stack[0], in->stack[1], ok);
    }
    if (imp->hle == UC_HLE_GETTHREADPRIORITY) {
        if (in->stack_dwords < 1) return 0;
        return uc_hle_get_thread_priority(in->stack[0], ok);
    }
    if (imp->hle == UC_HLE_SETTHREADPRIORITY) {
        if (in->stack_dwords < 2) return 0;
        return uc_hle_set_thread_priority(in->stack[0], in->stack[1], ok);
    }
    if (imp->hle == UC_HLE_QUERYPERFORMANCECOUNTER) {
        if (in->stack_dwords < 1) return 0;
        return uc_hle_query_performance_counter(in->stack[0], ok);
    }
    if (imp->hle == UC_HLE_QUERYPERFORMANCEFREQUENCY) {
        if (in->stack_dwords < 1) return 0;
        return uc_hle_query_performance_frequency(in->stack[0], ok);
    }
    if (imp->hle == UC_HLE_SLEEPEX) {
        /* SleepEx(dwMilliseconds, bAlertable): stdcall 2 args → DWORD. */
        if (in->stack_dwords < 2) return 0;
        return uc_hle_sleep_ex(in->stack[0], in->stack[1], ok);
    }
    if (imp->hle == UC_HLE_CREATESEMAPHOREA) {
        /* CreateSemaphoreA(attrs, initial, maximum, name): stdcall, 4 args; HANDLE. */
        if (in->stack_dwords < 4) return 0;
        return uc_hle_create_semaphore_a(in->stack[0], in->stack[1], in->stack[2],
                                         in->stack[3], ok);
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
