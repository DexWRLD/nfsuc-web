#include "cpu.h"
#include "uc_abi.h"
#include "uc_image.h"

int uc_exec_trace;
uint32_t uc_current_fn;
uint32_t uc_fault_eip;
UcAccessFault uc_access_fault;
UcSpan uc_spans[UC_SPAN_CAP];
int uc_span_count;
UcTraceEvent uc_trace_log[UC_TRACE_CAP];
int uc_trace_count;
uint32_t uc_esp_mark[8];

static uint8_t *image_mem;
static uint32_t image_size;
static uint8_t sink[16];

typedef struct UcRegion {
    uint32_t va;
    uint32_t size;
    uint32_t flags;
    int mapped;
    char name[16];
} UcRegion;

static UcRegion regions[UC_REGION_CAP];
static int region_count;

static void copy_text(char *dst, const char *src, unsigned cap) {
    unsigned i;
    if (!cap) return;
    for (i = 0; i + 1 < cap && src && src[i]; i++) dst[i] = src[i];
    dst[i] = 0;
}

static void copy_name(char *dst, const char *src) {
    copy_text(dst, src, 16);
}

static int name_eq(const char *a, const char *b) {
    unsigned i;
    for (i = 0; i < 16; i++) {
        if (a[i] != b[i]) return 0;
        if (a[i] == 0) return 1;
    }
    return 1;
}

int uc_section_is_protected(const char *name) {
    static const char *names[] = {
        "Stext", "Sitext", "Srdata", "Sdata", "Sidata", ".securom"
    };
    unsigned i;
    for (i = 0; i < 6; i++)
        if (name_eq(name, names[i])) return 1;
    return 0;
}

static int range_inside(uint32_t va, uint32_t size) {
    if (!size) return 0;
    if (va + size < va) return 0;
    if (va + size > image_size) return 0;
    return 1;
}

int uc_image_reset(uint8_t *mem, uint32_t mem_size) {
    unsigned i;
    image_mem = mem;
    image_size = mem_size;
    g_mem = mem;
    uc_guest_limit = mem_size;
    region_count = 0;
    uc_span_count = 0;
    uc_trace_count = 0;
    uc_current_fn = 0;
    uc_access_fault.active = 0;
    for (i = 0; i < 16; i++) sink[i] = 0;
    for (i = 0; i < 8; i++) uc_esp_mark[i] = 0;
    return mem && mem_size ? 0 : -1;
}

static int add_region(const char *name, uint32_t va, uint32_t size, uint32_t flags, int mapped) {
    UcRegion *r;
    if (region_count >= UC_REGION_CAP) return -1;
    if (!range_inside(va, size)) return -1;
    r = &regions[region_count++];
    r->va = va;
    r->size = size;
    r->flags = flags;
    r->mapped = mapped;
    copy_name(r->name, name);
    return 0;
}

int uc_image_map(const UcSectionIn *section) {
    uint32_t n, i;
    int protect;
    if (!section || !image_mem) return -1;
    protect = uc_section_is_protected(section->name) || (section->flags & UC_SECTION_PROTECTED);
    if (protect) {
        if (!section->vsize) return 0;
        return add_region(section->name, section->va, section->vsize, 0, 0);
    }
    if (!section->vsize) return 0;
    if (add_region(section->name, section->va, section->vsize, section->flags & 7u, 1))
        return -1;
    for (i = 0; i < section->vsize; i++) image_mem[section->va + i] = 0;
    n = section->raw_len;
    if (n > section->vsize) n = section->vsize;
    if (n && !section->raw) return -1;
    for (i = 0; i < n; i++) image_mem[section->va + i] = section->raw[i];
    return 0;
}

int uc_image_add_private(const char *name, uint32_t va, uint32_t size, uint32_t flags) {
    uint32_t i;
    if (uc_section_is_protected(name)) return -1;
    if (add_region(name, va, size, flags, 1)) return -1;
    for (i = 0; i < size; i++) image_mem[va + i] = 0;
    return 0;
}

static UcRegion *find_region(uint32_t addr, unsigned n, int mapped_only) {
    int i;
    if (!n || addr + n < addr) return 0;
    for (i = 0; i < region_count; i++) {
        UcRegion *r = &regions[i];
        if (mapped_only && !r->mapped) continue;
        if (addr < r->va) continue;
        if (addr + n > r->va + r->size) continue;
        return r;
    }
    return 0;
}

static void note_span(uint32_t addr, unsigned n, int write, const char *section) {
    uint32_t hi = addr + n;
    int i;
    for (i = 0; i < uc_span_count; i++) {
        UcSpan *s = &uc_spans[i];
        if (s->write != write) continue;
        if (!name_eq(s->section, section)) continue;
        if (hi < s->lo || addr > s->hi) continue;
        if (addr < s->lo) s->lo = addr;
        if (hi > s->hi) s->hi = hi;
        return;
    }
    if (uc_span_count >= UC_SPAN_CAP) return;
    uc_spans[uc_span_count].lo = addr;
    uc_spans[uc_span_count].hi = hi;
    uc_spans[uc_span_count].write = write;
    copy_name(uc_spans[uc_span_count].section, section);
    uc_span_count++;
}

static void note_fault(uint32_t addr, unsigned n, int kind, const char *section, const char *why) {
    if (uc_access_fault.active) return;
    uc_access_fault.active = 1;
    uc_access_fault.function_va = uc_current_fn;
    uc_access_fault.eip = uc_fault_eip;
    uc_access_fault.address = addr;
    uc_access_fault.size = n;
    uc_access_fault.kind = kind;
    copy_name(uc_access_fault.section, section ? section : "unmapped");
    copy_text(uc_access_fault.why, why, 48);
    if (uc_exec_trace && uc_trace_count < UC_TRACE_CAP) {
        UcTraceEvent *e = &uc_trace_log[uc_trace_count++];
        e->kind = UC_EV_UNMAPPED_ACCESS;
        e->fn = uc_current_fn;
        e->eip = 0;
        e->target = addr;
        e->esp = e->eax = e->ecx = e->edx = e->ebx = e->esi = e->edi = e->ebp = 0;
    }
}

void uc_access_clear(void) {
    uc_access_fault.active = 0;
    uc_access_fault.section[0] = 0;
    uc_access_fault.why[0] = 0;
}

uint8_t *uc_guest_ptr(uint32_t addr, unsigned n, int write) {
    UcRegion *r = find_region(addr, n, 1);
    UcRegion *named;
    if (!r) {
        named = find_region(addr, n ? n : 1, 0);
        note_fault(addr, n, write ? UC_ACCESS_WRITE : UC_ACCESS_READ,
                   named ? named->name : "unmapped",
                   named && !named->mapped ? "protected section is not mapped" : "unmapped guest access");
        return sink;
    }
    if (write && !(r->flags & UC_MEM_WRITE)) {
        note_fault(addr, n, UC_ACCESS_WRITE, r->name, "write to read-only guest data");
        return sink;
    }
    if (!write && !(r->flags & UC_MEM_READ) && !(r->flags & UC_MEM_EXEC)) {
        note_fault(addr, n, UC_ACCESS_READ, r->name, "region is not readable");
        return sink;
    }
    note_span(addr, n, write, r->name);
    return image_mem + addr;
}

uint32_t uc_guest_load32(uint32_t addr, int *ok) {
    uint8_t *p = uc_guest_ptr(addr, 4, 0);
    if (uc_access_fault.active && p == sink) {
        if (ok) *ok = 0;
        return 0;
    }
    if (ok) *ok = 1;
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

void uc_guest_store8(uint32_t addr, uint8_t value) {
    uint8_t *p = uc_guest_ptr(addr, 1, 1);
    if (p == sink) return;
    *p = value;
}

void uc_guest_store32(uint32_t addr, uint32_t value, int *ok) {
    uint8_t *p = uc_guest_ptr(addr, 4, 1);
    if (p == sink) {
        if (ok) *ok = 0;
        return;
    }
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
    p[3] = (uint8_t)(value >> 24);
    if (ok) *ok = 1;
}

int uc_guest_execute(uint32_t addr) {
    UcRegion *r = find_region(addr, 1, 1);
    UcRegion *named;
    if (!r || !(r->flags & UC_MEM_EXEC)) {
        named = r ? r : find_region(addr, 1, 0);
        note_fault(addr, 1, UC_ACCESS_EXECUTE, named ? named->name : "unmapped",
                   r ? "region is not executable" : "unmapped execute");
        if (uc_exec_trace && uc_trace_count < UC_TRACE_CAP) {
            UcTraceEvent *e = &uc_trace_log[uc_trace_count++];
            e->kind = UC_EV_INDIRECT_CALL;
            e->fn = uc_current_fn;
            e->target = addr;
            e->eip = uc_fault_eip;
            e->esp = e->eax = e->ecx = e->edx = e->ebx = e->esi = e->edi = e->ebp = 0;
        }
        return 0;
    }
    return 1;
}

void uc_trace(int kind, uint32_t fn, uint32_t eip, uint32_t target, struct CPU *c) {
    UcTraceEvent *e;
    if (!uc_exec_trace || uc_trace_count >= UC_TRACE_CAP) return;
    e = &uc_trace_log[uc_trace_count++];
    e->kind = kind;
    e->fn = fn;
    e->eip = eip;
    e->target = target;
    if (c) {
        e->esp = c->esp;
        e->eax = c->eax;
        e->ecx = c->ecx;
        e->edx = c->edx;
        e->ebx = c->ebx;
        e->esi = c->esi;
        e->edi = c->edi;
        e->ebp = c->ebp;
    } else {
        e->esp = e->eax = e->ecx = e->edx = e->ebx = e->esi = e->edi = e->ebp = 0;
    }
}

void uc_fn_enter(uint32_t va, struct CPU *c) {
    uc_current_fn = va;
    uc_fault_eip = c->eip;
    uc_trace(UC_EV_FUNCTION_ENTER, va, c->eip, va, c);
}

void uc_fn_leave(uint32_t va, struct CPU *c) {
    uc_trace(UC_EV_FUNCTION_RETURN, va, c->eip, va, c);
}

void uc_esp_mark_at(int slot, struct CPU *c) {
    if (slot >= 0 && slot < 8) uc_esp_mark[slot] = c->esp;
}
