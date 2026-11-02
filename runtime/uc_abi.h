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
    UC_HLE_STRNCMP
} UcHle;

typedef struct UcImport {
    uint32_t thunk;
    uint32_t iat_slot;
    const char *dll;
    const char *symbol;
    int ordinal;       /* -1 when the import is by name */
    UcAbi abi;
    int stack_dwords;  /* -1 when the layout has not been recorded */
    UcHle hle;
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

extern uint32_t uc_guest_limit;
extern int uc_import_trace;                 /* 0 unless a host turns it on */
extern uint32_t uc_import_trace_count;
extern UcImportFault uc_import_fault;
extern UcImportTrace uc_import_trace_last;

const UcImport *uc_import_find(uint32_t thunk);
unsigned uc_import_count(void);

typedef uint32_t (*UcHleFn)(struct CPU *c, const UcDecoded *in, int *ok);

/* override is optional and is ignored when the convention is unknown.
 * A null override uses the descriptor's HLE id. No HLE and an unknown
 * layout both fail without changing guest registers. */
int uc_import_invoke(struct CPU *c, const UcImport *imp, UcHleFn override);
#endif
