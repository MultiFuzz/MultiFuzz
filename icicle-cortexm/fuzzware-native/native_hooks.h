#ifndef NATIVE_HOOKS_H
#define NATIVE_HOOKS_H

#include "unicorn.h"

#define DEBUG_TIMER_TIMEOUT 100

void do_exit(uc_engine * uc, uc_err err);
void force_crash(uc_engine *uc, uc_err error);

void reload_fuzz_consumption_timer(uc_engine *uc);

uc_err init(uc_engine *uc, int p_do_print_exit_info, uint64_t fuzz_consumption_timeout, uint64_t p_instr_limit, uint32_t global_timer_scale);

#endif
