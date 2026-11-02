/* Compile-only harness for C emitted by tools/uc_gen.py.
 *
 * It includes the NFSU2 CPU header so a generated function is checked
 * against the same macros the lifter writes. tests/uc_host supplies the
 * libc headers this compiler does not ship. Nothing in this header runs
 * Need for Speed Undercover, binds its imports, or executes Sitext.
 */
#ifndef UC_HARNESS_H
#define UC_HARNESS_H
#include "cpu.h"

void unsupported_insn(CPU *c, uint32_t addr, const char *why);
void cpuid_shim(CPU *c);
uint64_t rdtsc_shim(void);
#endif
