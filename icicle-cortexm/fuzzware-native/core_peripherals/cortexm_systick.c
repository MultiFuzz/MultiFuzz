#include "cortexm_systick.h"
#include <stdlib.h>

// 0. Constants
const uint32_t calibration_val = SYSTICK_TICKS_10_MS;

uint64_t handle_syst_mmio_read(uc_engine *uc, uint64_t addr, int size) {
    struct CortexmSysTick* systick = &uc->fw->systick;
    uint32_t access_offset = addr - SysTick_BASE;
    uint32_t out_val = 0;

    // SysTick register read
    switch (access_offset) {
        case REG_OFF_SYST_CSR:
            // Simply return value here
            // uc->mem_write(uc->ctx, addr, &systick.csr, sizeof(systick.csr));
            out_val = systick->csr;
            /*
                * HACK (non-standard behavior):
                * In case firmware explicitly asks whether time has passed
                * multiple times within one systick period, indicate that it has.
                * This makes time go faster for firmware waiting in busy loops via
                * a SysTick polling mechanism (which we want it to get out of).
                */
            systick->csr |= SYST_CSR_COUNTFLAG;
            break;
        case REG_OFF_SYST_RVR:
            // Strictly speaking only 24 bits are used for the reload val
            out_val = get_timer_reload_val(&uc->fw->timers, systick->timer_ind) & SYST_RELOAD_VAL_MASK;
            // uc->mem_write(uc->ctx, addr, &out_val, sizeof(out_val));
            break;
        case REG_OFF_SYST_CVR:
            // Strictly speaking only 24 bits are used for the reload val
            out_val = get_timer_ticker_val(uc, systick->timer_ind) & SYST_RELOAD_VAL_MASK;
            // uc->mem_write(uc->ctx, addr, &out_val, sizeof(out_val));
            break;
        case REG_OFF_SYST_CALIB:
            out_val = calibration_val;
            // uc->mem_write(uc->ctx, addr, &calibration_val, sizeof(calibration_val));
            break;
        default:
            break;
    }

    return out_val;
}


void hook_syst_mmio_write(uc_engine *uc, uc_mem_type type,
                      uint64_t addr, int size, int64_t value, void *user_data) {
    struct CortexmSysTick* systick = &uc->fw->systick;
    uint32_t access_offset = addr - SysTick_BASE;

    #ifdef DEBUG_SYSTICK
    printf("[SysTick] hook_syst_mmio_write: Write to %08lx, value: %08lx\n", addr, value);
    fflush(stdout);
    #endif

    // SysTick register write
    switch (access_offset) {
        case REG_OFF_SYST_CSR:
            // SysTick is only concerned with writing the 3 lowest bits
            // ENABLE, TICKINT, CLKSOURCE

            // Did the enable status change?
            if((systick->csr & SYST_CSR_ENABLE) != (value & SYST_CSR_ENABLE)) {
                if(value & SYST_CSR_ENABLE) {
                    reload_timer(uc, systick->timer_ind);
                    start_timer(uc, systick->timer_ind);
                } else {
                    stop_timer(uc, systick->timer_ind);
                }
            } else {
                // Did the clock source change?
                if ((systick->csr ^ value) & SYST_CSR_CLKSOURCE) {
                    reload_timer(uc, systick->timer_ind);
                }
            }

            // Clear the respective flags
            systick->csr &= ~(SYST_CSR_ENABLE | SYST_CSR_TICKINT | SYST_CSR_CLKSOURCE);
            // And now set them
            systick->csr |= (value & (SYST_CSR_ENABLE | SYST_CSR_TICKINT | SYST_CSR_CLKSOURCE));
            // We will react to TICKINT as soon as the timer expires
            break;
        case REG_OFF_SYST_RVR:
            // restrict the value to something that makes sense to the emulator
            if(uc->fw->config.user_configured_reload_val != SYSTICK_RELOAD_VAL_NONE) {
                value = uc->fw->config.user_configured_reload_val;
            } else if(value < SYSTICK_TICKS_10_MS) {
                value = SYSTICK_TICKS_10_MS;
            } else if (value > 3*SYSTICK_TICKS_10_MS) {
                value = 3 * SYSTICK_TICKS_10_MS;
            }

            // The timer will handle the invalid case 0 by itself
            set_timer_reload_val(uc, systick->timer_ind, value & SYST_RELOAD_VAL_MASK);
            break;
        case REG_OFF_SYST_CVR:
            // Clear COUNTFLAG
            systick->csr &= (~SYST_CSR_COUNTFLAG);
            // Clear current value to 0, meaning a timer reset
            reload_timer(uc, systick->timer_ind);
            break;
        default:
            break;
    }
}

/*
 * https://developer.arm.com/documentation/dui0552/a/cortex-m3-peripherals/system-timer--systick/systick-control-and-status-register?lang=en
 *
 * When ENABLE is set to 1, the counter loads the RELOAD value from the SYST_RVR register and then counts down.
 * On reaching 0, it sets the COUNTFLAG to 1 and optionally asserts the SysTick depending on the value of TICKINT.
 * It then loads the RELOAD value again, and begins counting.
 **/
static void systick_trigger_callback (uc_engine *uc, uint32_t id, void *user_data) {
    #ifdef DEBUG_SYSTICK
    printf("[SYSTICK] trigger callback called for timer id=%d\n", id);
    #endif

    if ((uc->fw->systick.csr |= SYST_CSR_COUNTFLAG) & SYST_CSR_TICKINT)
    {
        #ifdef DEBUG_SYSTICK
        printf("[SYSTICK] pending interrupt...\n");
        #endif
        // TODO FIXME: use pend_interrupt as soon as we are done with the compatibility impl
        // pend_interrupt(uc, EXCEPTION_NO_SYSTICK);
        nvic_set_pending(uc, EXCEPTION_NO_SYSTICK, false);
    }

    // Reloading is done implicitly by the underlying timer
}

void *systick_take_snapshot(uc_engine *uc) {
    size_t size = sizeof(struct CortexmSysTick);
    void *result = malloc(size);
    memcpy(result, &uc->fw->systick, size);
    return result;
}

void systick_restore_snapshot(uc_engine *uc, void *snapshot) {
    memcpy(&uc->fw->systick, snapshot, sizeof(struct CortexmSysTick));
}

void systick_discard_snapshot(uc_engine *uc, void *snapshot) {
    free(snapshot);
}

uc_err init_systick(uc_engine *uc, uint32_t reload_val) {
    struct CortexmSysTick* systick = &uc->fw->systick;

    systick->csr = SYST_CSR_RESET_VAL;

    systick->timer_ind = add_timer(&uc->fw->timers, 0, systick_trigger_callback, NULL, TIMER_IRQ_NOT_USED);

    uc->fw->config.user_configured_reload_val = reload_val;
    #ifdef DEBUG_SYSTICK
    printf("[SYSTICK] Added timer with id %d\n", systick->timer_ind);
    #endif
    stop_timer(uc, systick->timer_ind);

    return UC_ERR_OK;
}