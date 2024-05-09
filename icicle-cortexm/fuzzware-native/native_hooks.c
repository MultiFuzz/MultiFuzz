/* Low level unicorn hooks for fuzzing */

/* Porting Considerations
- Memory handlers currently assume shared endianness between host and emulated target (uc_mem_write)
- ARM thumb instruction set
- System peripherals written for Cortex-M3
*/

#include "native_hooks.h"
#include "util.h"
#include "timer.h"
#include "core_peripherals/cortexm_nvic.h"
#include "interrupt_triggers.h"

#include "unicorn.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

#define CPUID_ADDR 0xE000ED00
const int CPUID_CORTEX_M4=0x410fc240;
const int CPUID_CORTEX_M3=0x410fc230;

const uc_err mem_errors[] = {
    UC_ERR_READ_UNMAPPED,
    UC_ERR_READ_PROT,
    UC_ERR_READ_UNALIGNED,
    UC_ERR_WRITE_UNMAPPED,
    UC_ERR_WRITE_PROT,
    UC_ERR_WRITE_UNALIGNED,
    UC_ERR_FETCH_UNMAPPED,
    UC_ERR_FETCH_PROT,
    UC_ERR_FETCH_UNALIGNED,
};


void do_exit(uc_engine *uc, uc_err err) {
    if(uc->fw->config.do_print_exit_info) {
        fflush(stdout);
    }
    uc->emu_stop(uc->ctx, err);
}

void force_crash(uc_engine *uc, uc_err error) {
    do_exit(uc, error);
}

void reload_fuzz_consumption_timer(uc_engine* uc) {
    reload_timer(uc, uc->fw->fuzz_consumption_timer_id);
}

void fuzz_consumption_timeout_cb(uc_engine *uc, uint32_t id, void *user_data) {
    if(uc->fw->config.do_print_exit_info) {
        printf("Fuzzing input not consumed for %ld basic blocks, exiting\n",
            uc->fw->config.fuzz_consumption_timeout);
    }
    do_exit(uc, UC_ERR_NO_FUZZ_CONSUMPTION);
}

#ifdef DEBUG_INJECT_TIMER
void test_timeout_cb(uc_engine *uc, uint32_t id, void *user_data) {
    if(!is_discovery_child) {
        uint32_t pc;
        uc->reg_read(uc->ctx, UC_ARM_REG_PC, &pc);
        printf("Test timer triggered at pc 0x%08x\n", pc);
        fflush(NULL);
    }
}
#endif

void instr_limit_timeout_cb(uc_engine *uc, uint32_t id, void *user_data) {
    if(uc->fw->config.do_print_exit_info) {
        uint32_t pc;
        uc->reg_read(uc->ctx, UC_ARM_REG_PC, &pc);
        printf("Ran into instruction limit of %lu at 0x%08x - exiting\n",
            get_timer_reload_val(&uc->fw->timers, uc->fw->instr_limit_timer_id), pc);
    }
    do_exit(uc, UC_ERR_BLOCK_LIMIT);
}

uc_err init(uc_engine *uc, int p_do_print_exit_info, uint64_t p_fuzz_consumption_timeout, uint64_t p_instr_limit, uint32_t global_timer_scale) {
    // TODO: assumes shared endianness
    // uc->mem_write(uc->ctx, CPUID_ADDR, &CPUID_CORTEX_M4, sizeof(CPUID_CORTEX_M4));

    // Allocate memory for data managed by Fuzzware.
    struct FwContext *ctx = malloc(sizeof(struct FwContext));
    memset(ctx, 0, sizeof(struct FwContext));
    uc->fw = ctx;

    // Configure default timer state.
    ctx->config.timer_scale = global_timer_scale;
    ctx->timers.end_ind = 0;
    ctx->timers.num_inuse = 0;
    ctx->timers.cur_interval = MAX_RELOAD_VAL;
    ctx->timers.cur_countdown = MAX_RELOAD_VAL;
    ctx->timers.global_ticker = 0;

    ctx->config.do_print_exit_info = p_do_print_exit_info;

    // Add fuzz consumption timeout as timer
    ctx->config.fuzz_consumption_timeout = p_fuzz_consumption_timeout;
    ctx->fuzz_consumption_timer_id = add_timer(&uc->fw->timers, p_fuzz_consumption_timeout, fuzz_consumption_timeout_cb, NULL, TIMER_IRQ_NOT_USED);
    if(p_fuzz_consumption_timeout) {
        start_timer(uc, ctx->fuzz_consumption_timer_id);
    }

    #ifdef DEBUG_INJECT_TIMER
    // debug timer to debug precise timing consistencies
    start_timer(uc, add_timer(&uc->fw->timers, DEBUG_TIMER_TIMEOUT, test_timeout_cb, NULL, TIMER_IRQ_NOT_USED));
    #endif

    ctx->config.instr_limit = p_instr_limit;
    ctx->instr_limit_timer_id = add_timer(&uc->fw->timers, p_instr_limit, instr_limit_timeout_cb, NULL, TIMER_IRQ_NOT_USED);
    if(p_instr_limit) {
        start_timer(uc, ctx->instr_limit_timer_id);
    }

    return UC_ERR_OK;
}
