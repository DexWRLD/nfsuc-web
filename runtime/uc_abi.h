/* Undercover import ABI.
 *
 * A guest import call names a descriptor. The descriptor carries the DLL,
 * the symbol or ordinal, the calling convention, and how many stack dwords
 * are known. An ABI decoder reads the guest registers and the guest stack.
 * An HLE implementation then performs the operation. The descriptor, not
 * the HLE function, decides who removes stack arguments.
 *
 * CDECL: the caller removes arguments. This dispatcher pops only the return
 * address. STDCALL, THISCALL, and FASTCALL: the callee removes the recorded
 * stack arguments. UNKNOWN is not treated as stdcall and is not called.
 *
 * arg_loc and ret_loc are separate from that integer convention. An import
 * whose result is UC_LOC_ST0 replaces ST(0) and does not write EAX.
 *
 * NFSU2's win32_call is unchanged. It still executes
 * `c->esp += 4u * (uint32_t)e->nargs` after popping the return address.
 * uc_abi_callee_bytes(UC_ABI_STDCALL, n) is that same `4 * n`. Undercover
 * metadata does not rewrite the NFSU2 import table.
 *
 * The bodies here are a native test harness. They are not a claim that the
 * game boots, and they do not cover protected startup.
 */
#ifndef UC_ABI_H
#define UC_ABI_H
#include <stdint.h>

struct CPU;

typedef enum UcAbi {
    UC_ABI_CDECL = 1,
    UC_ABI_STDCALL = 2,
    UC_ABI_THISCALL = 3,
    UC_ABI_FASTCALL = 4,
    UC_ABI_UNKNOWN = 5
} UcAbi;

typedef enum UcHle {
    UC_HLE_NONE = 0,
    UC_HLE_MEMCPY,
    UC_HLE_MEMMOVE,
    UC_HLE_MEMSET,
    UC_HLE_MEMCMP,
    UC_HLE_STRLEN,
    UC_HLE_STRCMP,
    UC_HLE_STRNCMP,
    UC_HLE_STRNCPY,
    UC_HLE_CISIN,
    UC_HLE_CICOS,
    UC_HLE_CIACOS,
    UC_HLE_CISQRT,
    UC_HLE_TLSALLOC,
    UC_HLE_TLSSETVALUE,
    UC_HLE_INITCRITSEC,
    UC_HLE_CREATEMUTEXA,
    UC_HLE_GETCURRENTPROCESS,
    UC_HLE_GETPRIORITYCLASS,
    UC_HLE_CREATESEMAPHOREA,
    UC_HLE_GETCURRENTTHREAD,
    UC_HLE_GETTHREADPRIORITY,
    UC_HLE_SETPRIORITYCLASS,
    UC_HLE_SETTHREADPRIORITY
} UcHle;

/* Where an import argument is read, and where its result is written.
 * STACK means the integer stack already described by stack_dwords.
 * ST0 means the x87 register ST(0). EAX is the integer return used by
 * the CRT memory helpers. A descriptor selects one; the dispatcher does
 * not turn an ST0 result into an EAX result. */
typedef enum UcLoc {
    UC_LOC_NONE = 0,
    UC_LOC_EAX = 1,
    UC_LOC_ST0 = 2,
    UC_LOC_STACK = 3
} UcLoc;

typedef double (*UcHostUnary)(double);

typedef struct UcImport {
    uint32_t thunk;
    uint32_t iat_slot;
    const char *dll;
    const char *symbol;
    int ordinal;       /* -1 when the import is by name */
    UcAbi abi;
    int stack_dwords;  /* -1 when the layout has not been recorded */
    UcHle hle;
    uint8_t arg_loc;   /* UC_LOC_STACK or UC_LOC_ST0 */
    uint8_t ret_loc;   /* UC_LOC_EAX or UC_LOC_ST0 */
} UcImport;

typedef struct UcDecoded {
    UcAbi abi;
    uint32_t ecx;          /* thiscall this, or fastcall argument 0 */
    uint32_t edx;          /* fastcall argument 1 */
    uint32_t esp;          /* first stack argument, after the return address */
    int stack_dwords;
    uint32_t stack[8];
} UcDecoded;

typedef struct UcImportFault {
    int active;
    uint32_t call_site;
    uint32_t return_address;
    uint32_t thunk;
    const char *dll;
    const char *symbol;
    int ordinal;
    uint32_t esp;
    uint32_t eax, ecx, edx, ebx, esi, edi, ebp;
    const char *why;
} UcImportFault;

typedef struct UcImportTrace {
    uint32_t call_site;
    uint32_t thunk;
    const char *dll;
    const char *symbol;
    int ordinal;
    UcAbi abi;
    int stack_dwords;
    uint32_t esp_before;
    uint32_t esp_after;
    uint32_t eax;
    int ok;
} UcImportTrace;

/* Bytes the callee removes, not counting the return address.
 * STDCALL/THISCALL/FASTCALL: 4 * stack_dwords. CDECL: 0. Unknown: -1. */
int uc_abi_callee_bytes(UcAbi abi, int stack_dwords);

/* x87 state the runtime actually keeps. There is no tag word. */
typedef struct UcX87Fault {
    int active;
    uint32_t function_va;
    uint32_t eip;
    int32_t top;
    double st0;
    double st1;
    uint16_t fcw;
    uint16_t fsw;
    const char *why;
} UcX87Fault;

extern uint32_t uc_guest_limit;
extern int uc_import_trace;                 /* 0 unless a host turns it on */
extern uint32_t uc_import_trace_count;
extern UcImportFault uc_import_fault;
extern UcImportTrace uc_import_trace_last;
extern UcX87Fault uc_x87_fault;
extern uint32_t (*uc_x87_current_fn)(void);
extern UcHostUnary uc_host_sin;
extern UcHostUnary uc_host_cos;
extern UcHostUnary uc_host_acos;
extern UcHostUnary uc_host_sqrt;

const UcImport *uc_import_find(uint32_t thunk);
const UcImport *uc_import_find_by_iat(uint32_t iat_slot);
/* Resolve a `call dword ptr [iat]` target: bound thunk, or unbound
 * PE name-RVA still sitting in an HLE-ready IAT slot. */
const UcImport *uc_import_find_dispatch_target(uint32_t target);
unsigned uc_import_count(void);
/* Optional: write thunk into guest IAT when the slot is writable. */
unsigned uc_import_bind_hle_iats(void);

/* Dynamic Win32 TLS (guest-managed; not host OS TLS). */
void uc_tls_reset(void);
uint32_t uc_tls_get_value(uint32_t index);
int uc_tls_slot_allocated(uint32_t index);
unsigned uc_tls_thread_context_count(void);

/* Guest Win32 synchronization / process / thread (single guest-thread; no scheduler). */
void uc_sync_reset(void);
void uc_process_reset(void);
void uc_thread_reset(void);
unsigned uc_sync_critsec_count(void);
unsigned uc_sync_mutex_count(void);
unsigned uc_sync_semaphore_count(void);
int uc_sync_critsec_initialized(uint32_t guest_cs);
int uc_sync_mutex_valid(uint32_t guest_handle);
int uc_sync_semaphore_valid(uint32_t guest_handle);
uint32_t uc_process_priority_class(void);
int uc_process_pseudo_handle(uint32_t handle);
int uc_thread_pseudo_handle(uint32_t handle);
int32_t uc_thread_priority(void);
unsigned uc_active_guest_threads(void);

typedef uint32_t (*UcHleFn)(struct CPU *c, const UcDecoded *in, int *ok);

/* override is optional and is ignored when the convention is unknown.
 * A null override uses the descriptor's HLE id. No HLE and an unknown
 * layout both fail without changing guest registers. */
int uc_import_invoke(struct CPU *c, const UcImport *imp, UcHleFn override);
#endif
