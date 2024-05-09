#ifndef NATIVE_UTIL_H
#define NATIVE_UTIL_H

#include "unicorn.h"

#define min(a, b) (a < b ? a : b)

#ifdef __GNUC__
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#else
#define likely(x)       (x)
#define unlikely(x)     (x)
#endif

void print_state(uc_engine *uc);
int get_instruction_size(uint64_t insn, bool is_thumb);

#endif