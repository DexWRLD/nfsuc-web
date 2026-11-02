/* Undercover ordinary-section guest image.
 *
 * The loader copies only sections the caller marks as ordinary. Protected
 * names are recorded as address ranges and are never copied. A later access
 * to one of those ranges fails with the section name. Nothing here starts
 * a thread, calls the PE entry, or executes the image.
 *
 * UC_GUEST_CHECKED builds route MR* and the atomic helpers through
 * uc_guest_ptr. The NFSU2 default memory path does not.
 */
#ifndef UC_IMAGE_H
#define UC_IMAGE_H
#include <stdint.h>

struct CPU;

#define UC_MEM_READ  1u
#define UC_MEM_WRITE 2u
#define UC_MEM_EXEC  4u

enum {
    UC_EV_FUNCTION_ENTER = 1,
    UC_EV_DIRECT_CALL,
    UC_EV_FUNCTION_RETURN,
    UC_EV_IMPORT_CALL,
    UC_EV_IMPORT_RETURN,
    UC_EV_UNMAPPED_ACCESS,
    UC_EV_UNKNOWN_IMPORT,
    UC_EV_INDIRECT_CALL
};

enum {
    UC_ACCESS_READ = 0,
    UC_ACCESS_WRITE = 1,
    UC_ACCESS_EXECUTE = 2
};

typedef struct UcSectionIn {
    uint32_t va;
    uint32_t vsize;
    uint32_t raw_len;
    uint32_t flags;          /* UC_MEM_* plus UC_SECTION_PROTECTED */
    const uint8_t *raw;      /* unused when the section is protected */
    char name[16];
} UcSectionIn;

#define UC_SECTION_PROTECTED 0x80000000u

typedef struct UcSpan {
    uint32_t lo;
    uint32_t hi;
    int write;
    char section[16];
} UcSpan;

typedef struct UcTraceEvent {
    int kind;
    uint32_t fn;
    uint32_t eip;
    uint32_t target;
    uint32_t esp;
    uint32_t eax, ecx, edx, ebx, esi, edi, ebp;
} UcTraceEvent;

typedef struct UcAccessFault {
    int active;
    uint32_t function_va;
    uint32_t eip;
    uint32_t address;
    unsigned size;
    int kind;
    char section[16];
    char why[48];
} UcAccessFault;

#define UC_TRACE_CAP 64
#define UC_SPAN_CAP 32
#define UC_REGION_CAP 24

/* Limits are off when the matching value is 0. The trace log is a ring:
 * uc_trace_total counts every event, and the last UC_TRACE_CAP events are
 * kept. uc_trace_count stays the number of events still sitting in order at
 * the front of the log, which is the whole log until it wraps. */
extern int uc_exec_trace;
extern uint32_t uc_current_fn;
extern uint32_t uc_fault_eip;
extern UcAccessFault uc_access_fault;
extern UcSpan uc_spans[UC_SPAN_CAP];
extern int uc_span_count;
extern UcTraceEvent uc_trace_log[UC_TRACE_CAP];
extern int uc_trace_count;
extern int uc_trace_total;
extern uint32_t uc_esp_mark[8];

extern uint32_t uc_limit_calls;
extern uint32_t uc_limit_depth;
extern uint32_t uc_limit_imports;
extern uint32_t uc_limit_indirect;
extern uint32_t uc_limit_ms;
extern uint64_t (*uc_host_ms)(void);
extern int (*uc_limit_hook)(void);
extern uint32_t uc_stat_calls;
extern uint32_t uc_stat_imports;
extern uint32_t uc_stat_indirect;
extern int uc_stat_depth;
extern int uc_stat_max_depth;

typedef struct UcLimitStop {
    int active;
    int code; /* 1 calls, 2 depth, 3 imports, 4 indirect, 5 timeout */
    uint32_t fn;
    uint32_t eip;
    uint32_t target;
    char why[48];
} UcLimitStop;

extern UcLimitStop uc_limit_stop;

void uc_limits_clear(void);
int uc_limit_note_import(struct CPU *c, uint32_t thunk);
int uc_limit_note_indirect(struct CPU *c, uint32_t target);

int uc_image_reset(uint8_t *mem, uint32_t mem_size);
int uc_image_map(const UcSectionIn *section);
int uc_image_add_private(const char *name, uint32_t va, uint32_t size, uint32_t flags);

uint8_t *uc_guest_ptr(uint32_t addr, unsigned n, int write);
uint32_t uc_guest_load32(uint32_t addr, int *ok);
void uc_guest_store8(uint32_t addr, uint8_t value);
void uc_guest_store32(uint32_t addr, uint32_t value, int *ok);
int uc_guest_execute(uint32_t addr);

void uc_access_clear(void);
void uc_trace(int kind, uint32_t fn, uint32_t eip, uint32_t target, struct CPU *c);
void uc_fn_enter(uint32_t va, struct CPU *c);
void uc_fn_leave(uint32_t va, struct CPU *c);
void uc_esp_mark_at(int slot, struct CPU *c);

int uc_section_is_protected(const char *name);
#endif
