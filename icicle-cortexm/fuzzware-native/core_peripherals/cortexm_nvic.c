#include "cortexm_nvic.h"
#include <stdio.h>
#include <stdlib.h>

// We implement recalculating states lazily, but can disable that behavior
// #define DISABLE_LAZY_RECALCS

// We can react to interrupt-related MMIO writes from the access handler
#define DISABLE_IMMEDIATE_MMIOWRITE_RESPONSE

// We are allowing SVC to be activated more leniently
#define FORCE_SVC_ACTIVATION
#define SKIP_CHECK_SVC_ACTIVE_INTERRUPT_PRIO

// 0. Constants
// Some Cortex M3 specific constants
#define NVIC_VTOR_NONE 0xffffffff
#define NVIC_NONE_ACTIVE 0

#define FRAME_SIZE 0x20

const uint8_t nvic_id[] = {
    0x00, 0xb0, 0x1b, 0x00, 0x0d, 0xe0, 0x05, 0xb1
};
int saved_reg_ids[NUM_SAVED_REGS] = {
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_R12, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_XPSR,
    UC_ARM_REG_SP
};

uint64_t get_timer_ticker_val(uc_engine *uc, uint32_t id) {
#ifdef DEBUG_TIMER
    if(id >= MAX_TIMERS) {
        perror("[TIMER ERROR] get_timer_ticker_val: Too high id passed\n");
        exit(-1);
    }
#endif
    uc->get_timer_countdown(uc->ctx, &uc->fw->timers.cur_countdown);
    struct TimerState* timers = &uc->fw->timers;
    return timers->timers[id].ticker_val - (timers->cur_interval-timers->cur_countdown);
}


uint64_t get_timer_reload_val(struct TimerState* timers, uint32_t id) {
#ifdef DEBUG_TIMER
    if(id >= MAX_TIMERS) {
        perror("[TIMER ERROR] get_timer_reload_val: Too high id passed\n");
        exit(-1);
    }
#endif
    return timers->timers[id].reload_val;
}


// Versions of the above that assume an existing NVIC pointer
static inline uint8_t GET_PRIMASK_NVIC(struct FwContext *ctx) {
    return *ctx->reg_daif_ptr & CPSR_IRQ_MASK_BIT;
}

static inline int32_t GET_BASEPRI_NVIC(struct FwContext *ctx) {
    return *ctx->reg_basepri_ptr;
}

static inline uint32_t GET_CURR_SP_MODE_IS_PSP (struct FwContext *ctx) {
    return *ctx->reg_curr_sp_mode_is_psp_ptr;
}

#define is_exception_ret(pc) ((pc & EXC_RETURN_MASK) == EXC_RETURN_MASK)


// Forward declarations
static void ExceptionEntry(uc_engine *uc, bool is_tail_chained, bool skip_instruction);

// Armv7-M ARM B1.5.8
static int get_group_prio(struct FwContext *ctx, int raw_prio) {
    return raw_prio & ctx->nvic.group_prio_mask;
}

// B1.5.4
static int get_boosted_prio(struct FwContext *ctx, int raw_prio) {
    if(GET_PRIMASK_NVIC(ctx)
    #ifdef FORCE_SVC_ACTIVATION
        && ctx->nvic.pending_irq != EXCEPTION_NO_SVC
    #endif
    ) {
        return 0;
    }

    int basepri = GET_BASEPRI_NVIC(ctx);
    if(basepri != 0) {
        basepri = get_group_prio(ctx, basepri);
        return min(basepri, raw_prio);
    } else {
        return raw_prio;
    }
}

static bool pending_exception_can_be_activated(struct FwContext *ctx) {
    #ifdef DEBUG_NVIC
    fprintf(stderr, "[NVIC] pending_exception_can_be_activated: nvic.pending_prio < get_boosted_prio(nvic.active_group_prio)? %d < %d ? -> %d\n",
        ctx->nvic.pending_prio, get_boosted_prio(ctx, ctx->nvic.active_group_prio), ctx->nvic.pending_prio < get_boosted_prio(ctx, ctx->nvic.active_group_prio)); fflush(stderr);
    #endif

    if(ctx->nvic.active_irq != NVIC_NONE_ACTIVE && !ctx->config.enable_nested_interrupts) {
        #ifdef DEBUG_NVIC
        fprintf(stderr, "Already in handler, short-cutting exec prio to 0 to disable nesting/preemption.\n"); fflush(stderr);
        #endif
        return 0;
    }

    return ctx->nvic.pending_prio < get_boosted_prio(ctx, ctx->nvic.active_group_prio);
}

/*
 * Re-calculate nvic interrupt prios and indicate whether
 * things have changed (i.e., a higher-prio interrupt is now pending).
 */
static bool recalc_prios(struct FwContext *ctx) {
    int highest_pending_prio = 256;
    int num_active = 0;

    // Track the raw active prio before priority boosting (masking / basepri)
    int highest_active_group_prio = 256;
    int highest_pending_irq = EXCEPTION_NONE_ACTIVE;

    for(int i = EXCEPTION_NO_SVC; i <= ctx->nvic.highest_ever_enabled_exception_no; ++i) {
        int curr_prio = ctx->nvic.ExceptionPriority[i];

        // IPSR values of the exception handlers
        if(ctx->nvic.ExceptionActive[i]) {
            ++num_active;
            if (curr_prio < highest_active_group_prio) {
                // Increase to flag group prio (highest subprio)
                highest_active_group_prio = get_group_prio(ctx, curr_prio);
            }
        }

        if(ctx->nvic.ExceptionPending[i]) {
            if (curr_prio < highest_pending_prio) {
                #ifdef DEBUG_NVIC
                fprintf(stderr, "[recalc_prios] curr_prio < highest_pending_prio for irq %d: curr: %d < new highest: %d\n", i, curr_prio, highest_pending_prio);
                #endif

                // We are tracking the full pending prio here to be able to
                // check whether we actually need updates elsewhere
                highest_pending_prio = curr_prio;
                highest_pending_irq = i;
            }
        }
    }

    ctx->nvic.num_active = num_active;

    bool pending_prio_now_surpasses_active =
        // Pending previously not higher prio
        !(ctx->nvic.pending_prio < ctx->nvic.active_group_prio) &&
        // But now higher prio
        highest_pending_prio < highest_active_group_prio;

    // Now update the prio info
    ctx->nvic.active_group_prio = highest_active_group_prio;
    ctx->nvic.pending_prio = highest_pending_prio;
    ctx->nvic.pending_irq = highest_pending_irq;

    /* HACK: We are abusing the prev_basepri field here to make
     * the unconditional block hook hot path aware of changes.
     */
    if(pending_prio_now_surpasses_active) {
        ctx->nvic.prev_basepri = -1;
    }

    return pending_prio_now_surpasses_active;
}

bool is_disabled_by_config(struct FwContext *ctx, uint32_t exception_no) {
    for(uint32_t i = 0; i < ctx->config.num_disabled_interrupts; ++i) {
        if(ctx->config.disabled_interrupts[i] == exception_no) {
            return true;
        }
    }

    return false;
}

void pend_interrupt(struct FwContext *ctx, int exception_no) {
    #ifdef DEBUG_NVIC
    fprintf(stderr, "[pend_interrupt] exception_no=%d\n", exception_no);
    fflush(stderr);
    #endif
    if(ctx->nvic.ExceptionPending[exception_no] == 0) {
        ctx->nvic.ExceptionPending[exception_no] = 1;

        #ifndef DISABLE_LAZY_RECALCS
        // we only need to update if we pend a high-prio or a lower same-prio interrupt
        if(exception_no < ctx->nvic.pending_irq ||
            ctx->nvic.ExceptionPriority[exception_no] < ctx->nvic.pending_prio) {
        #endif
            recalc_prios(ctx);
        #ifndef DISABLE_LAZY_RECALCS
        }
        #endif
    }
}

static void maybe_activate(uc_engine *uc, bool skip_instruction) {
    #ifdef DEBUG_NVIC
    fprintf(stderr, "[maybe_activate] skip_instruction: %d\n", skip_instruction);
    #endif

    /*
     * We only activate an exception (preempt running exception or freshly activate)
     * in case we have a higher-prio exception (post boosting) pended.
     */
    if(pending_exception_can_be_activated(uc->fw)) {
        ExceptionEntry(uc, false, skip_instruction);
    }
}

void clear_pend_interrupt(struct FwContext *ctx, int exception_no) {
    if(ctx->nvic.ExceptionPending[exception_no] == 1) {
        ctx->nvic.ExceptionPending[exception_no] = 0;

        #ifndef DISABLE_LAZY_RECALCS
        // We only need to update if we clear the currently pending interrupt
        if(ctx->nvic.pending_irq == exception_no) {
        #endif
            recalc_prios(ctx);
        #ifndef DISABLE_LAZY_RECALCS
        }
        #endif
    }
}

// Armv7-M ARM B3.4.3
uint64_t handle_nvic_mmio_read(uc_engine *uc, uint64_t addr, int size) {
    struct FwContext *ctx = uc->fw;

    uint32_t access_offset = (uint32_t)addr - NVIC_BASE;
    // Caution: Implicit bounds check here
    uint32_t base_ind = EXCEPTION_NO_EXTERNAL_START + ((access_offset & NVIC_REGISTER_OFFSET_MASK) * 8);
    uint32_t out_val = 0;

    // Interrupt Set-Enable Registers
    // NVIC register read
    uint32_t x = access_offset & 0x780;
    if ((NVIC_IREG_START(NVIC_ISER) <= x && x < NVIC_IREG_END(NVIC_ISER)) || // Interrupt Set-Enable Registers
        // Both NVIC_ISER and NVIC_ICER reads yield enabled flags.
        (NVIC_IREG_START(NVIC_ICER) <= x && x < NVIC_IREG_END(NVIC_ICER))) { // Interrupt Clear-Enable Registers
        for(int i = size * 8 - 1; i >= 0; --i) {
            out_val <<= 1;
            out_val |= ctx->nvic.ExceptionEnabled[base_ind + i];
        }
    }
    else if ((NVIC_IREG_START(NVIC_ISPR) <= x && x < NVIC_IREG_END(NVIC_ISPR)) || // Interrupt Set-Pending Registers
        // Both NVIC_ISPR and NVIC_ICPR reads yield pending flags.
            (NVIC_IREG_START(NVIC_ICPR) <= x && x < NVIC_IREG_END(NVIC_ICPR))) { // Interrupt Clear-Pending Registers
        for(int i = size * 8 - 1; i >= 0 && base_ind + i < NVIC_NUM_SUPPORTED_INTERRUPTS; --i) {
            out_val <<= 1;
            out_val |= ctx->nvic.ExceptionPending[base_ind + i];
        }
        #ifdef DEBUG_NVIC
        fprintf(stderr, "[NVIC] hook_nvic_mmio_read: NVIC_ISPR: %08lx, value: %08x\n", addr, out_val); fflush(stderr);
        #endif
    }
    else if (NVIC_IREG_START(NVIC_IABR) <= x && x < NVIC_IREG_END(NVIC_IABR)) { // Interrupt Active Bit Registers+
        for(int i = size * 8 - 1; i >= 0; --i) {
            out_val <<= 1;
            out_val |= ctx->nvic.ExceptionActive[base_ind * 4 + i];
        }
    }
    else if (NVIC_IPR_START(NVIC_IPR) <= x && x < NVIC_IPR_END(NVIC_IPR)) { // Interrupt Priority Registers
        base_ind = EXCEPTION_NO_EXTERNAL_START + ((access_offset - NVIC_IPR) & 0x1ff);
        if(base_ind <= NVIC_NUM_SUPPORTED_INTERRUPTS - 4) {
            for(int i = size-1; i >= 0; --i) {
                out_val <<= 8;
                out_val |= ctx->nvic.ExceptionPriority[base_ind + i];
            }
        }
    }

    return out_val;
}

static bool enable_irq(uc_engine *uc, int to_be_enabled) {
    struct FwContext *ctx = uc->fw;
    /*
     * Enable an irq and return whether an nvic prio recalc is required.
     *
     * Assumes that to_be_enabled is a valid exception index.
     */
    if(ctx->nvic.ExceptionEnabled[to_be_enabled] != 1 && !is_disabled_by_config(ctx, to_be_enabled)) {
        uc->notify_irq_enable_state(uc->ctx, to_be_enabled, true);
        ctx->nvic.ExceptionEnabled[to_be_enabled] = 1;

        if(to_be_enabled > ctx->nvic.highest_ever_enabled_exception_no) {
            ctx->nvic.highest_ever_enabled_exception_no = (uint8_t)to_be_enabled;
        }

        // Take note of the interrupt number choice for fuzzing
        if(to_be_enabled >= EXCEPTION_NO_EXTERNAL_START) {
            int i = 0;
            // Add it in in a sorted manner in case we preserve previous behavior
            for(; i < ctx->nvic.num_enabled; ++i) {
                if(ctx->nvic.enabled_irqs[i] > to_be_enabled) {
                    memmove(&ctx->nvic.enabled_irqs[i+1], &ctx->nvic.enabled_irqs[i], (ctx->nvic.num_enabled-i) * sizeof(ctx->nvic.enabled_irqs[0]));
                    break;
                }
            }
            ctx->nvic.enabled_irqs[i] = (uint8_t)to_be_enabled;
            ++ctx->nvic.num_enabled;

            // The alternative implementation which does not preserve ordering would be:
            // Add at the end of the list
            // nvic.enabled_irqs[nvic.num_enabled++] = to_be_enabled;
        }

        #ifdef DISABLE_LAZY_RECALCS
        return true;
        #else
        // We need to update in case we enabled a pending, high-prio exception
        return ctx->nvic.ExceptionPending[to_be_enabled] &&
            ctx->nvic.ExceptionPriority[to_be_enabled] < ctx->nvic.pending_irq;
        #endif
    }
    return false;
}

static void remove_fuzzable_interrupt_no(struct FwContext *ctx, int to_be_removed) {
    /*
     * Remove the an irq from the ones available to fuzzing
     */
    for(int i = 0; i < ctx->nvic.num_enabled; ++i) {
        if(ctx->nvic.enabled_irqs[i] == to_be_removed) {
            // Remove it while maintaining a sorted list if we are backward compatible
            memmove(&ctx->nvic.enabled_irqs[i], &ctx->nvic.enabled_irqs[i+1], (ctx->nvic.num_enabled-i-1) * sizeof(ctx->nvic.enabled_irqs[0]));

            // The alternative implementation which does not preserve ordering would be:
            // Copy the end of the list into the blank space and shrink the list.
            // nvic.enabled_irqs[i] = nvic.enabled_irqs[nvic.num_enabled];

            --ctx->nvic.num_enabled;
            return;
        }
    }

    /*
     * We assume that we are only removing one which is actually present.
     * If not, we need to know about it.
     */
    assert(false);
}

static bool disable_irq(uc_engine *uc, int to_be_disabled) {
    struct FwContext *ctx = uc->fw;
    /*
     * Disable an irq and return whether an nvic prio recalc is required.
     *
     * Assumes that to_be_enabled is a valid exception index.
     */
    if(ctx->nvic.ExceptionEnabled[to_be_disabled] != 0) {
        uc->notify_irq_enable_state(uc->ctx, to_be_disabled, false);
        ctx->nvic.ExceptionEnabled[to_be_disabled] = 0;

        // Unregister the interrupt number choice from fuzzing
        remove_fuzzable_interrupt_no(ctx, to_be_disabled);

        #ifdef DISABLE_LAZY_RECALCS
        return true;
        #else
        // We only need to update if we disable the pending interrupt
        return to_be_disabled == ctx->nvic.pending_irq;
        #endif
    }
    return false;
}

/*
 * Sets the prigroup fields from a given prigroup value.
 * prigroup itself is a shift amount which determines
 * group prio and sub prio masks.
 */
static void set_prigroup(struct FwContext *ctx, uint8_t new_prigroup) {
    ctx->nvic.prigroup_shift = new_prigroup;
    ctx->nvic.sub_prio_mask = (2 << new_prigroup) - 1;
    ctx->nvic.group_prio_mask = ~ctx->nvic.sub_prio_mask;
}

static bool set_prio(struct FwContext *ctx, int to_be_prio_changed, int new_prio) {
    /*
     * Set priority and return whether an nvic prio recalc is required.
     */

    if(new_prio != ctx->nvic.ExceptionPriority[to_be_prio_changed] && !is_disabled_by_config(ctx, to_be_prio_changed)) {
        #ifdef DEBUG_NVIC
        fprintf(stderr, "[NVIC] set priority for %d -> %d\n", to_be_prio_changed, new_prio); fflush(stderr);
        #endif
        ctx->nvic.ExceptionPriority[to_be_prio_changed] = new_prio;

        // We have to update in different cases here, so just do it in any case
        // Cases to update:
        // 1. active and changing active group prio
        // 2. enabled && pending && changing pending prio ()
        // 3. ?
        return true;
    }
    return false;
}

void hook_nvic_mmio_write(uc_engine *uc, uc_mem_type type,
                      uint64_t addr, int size, int64_t value, void *user_data) {
    struct FwContext *ctx = uc->fw;
    uint32_t access_offset = (uint32_t)addr - NVIC_BASE;
    // Caution: Implicit bounds check here
    uint32_t base_ind = EXCEPTION_NO_EXTERNAL_START + ((access_offset & NVIC_REGISTER_OFFSET_MASK) * 8);
    bool need_update = false;

    #ifdef DEBUG_NVIC
    fprintf(stderr, "[NVIC] hook_nvic_mmio_write: Write to %08lx, value: %08lx\n", addr, value);
    fflush(stderr);
    #endif

    // NVIC register write
    uint32_t x = access_offset & 0x780;
    if (NVIC_IREG_START(NVIC_ISER) <= x && x < NVIC_IREG_END(NVIC_ISER)) { // Interrupt Set-Enable Registers
        #ifdef DEBUG_NVIC
        fprintf(stderr, "[NVIC] hook_nvic_mmio_write: NVIC_ISER\n"); fflush(stderr);
        #endif
        for(int i = 0; i < size * 8; ++i) {
            if((value & 1)) {
                int to_be_enabled = base_ind + i;
                #ifdef DEBUG_NVIC
                fprintf(stderr, "[NVIC] NVIC_ISER: got enabled bit at i=%d. to_be_enabled = %d\n", i, to_be_enabled); fflush(stderr);
                #endif

                need_update |= enable_irq(uc, to_be_enabled);
            }
            value >>= 1;
        }

        if(need_update) {
            recalc_prios(ctx);
        }
    }
    else if (NVIC_IREG_START(NVIC_ICER) <= x && x < NVIC_IREG_END(NVIC_ICER)) { // Interrupt Clear-Enable Registers
        #ifdef DEBUG_NVIC
        fprintf(stderr, "[NVIC] hook_nvic_mmio_write: NVIC_ICER\n"); fflush(stderr);
        #endif
        for(int i = 0; i < size * 8; ++i) {
            if((value & 1)) {
                int to_be_disabled = base_ind + i;
                need_update |= disable_irq(uc, to_be_disabled);
            }
            value >>= 1;
        }

        if(need_update) {
            recalc_prios(ctx);
        }
    }
    else if (NVIC_IREG_START(NVIC_ISPR) <= x && x < NVIC_IREG_END(NVIC_ISPR)) { // Interrupt Set-Pending Registers
        #ifdef DEBUG_NVIC
        fprintf(stderr, "[NVIC] hook_nvic_mmio_write: NVIC_ISPR\n"); fflush(stderr);
        #endif
        for(int i = 0; i < size * 8; ++i) {
            if((value & 1)) {
                uint32_t to_pend = base_ind + i;
                if(!is_disabled_by_config(ctx, to_pend)) {
                    // We may want to directly react to such writes.
                    #ifdef DISABLE_IMMEDIATE_MMIOWRITE_RESPONSE
                    pend_interrupt(ctx, to_pend);
                    #else
                    pend_from_mem_write(uc, to_pend);
                    #endif
                }
            }
            value >>= 1;
        }
    }
    else if (NVIC_IREG_START(NVIC_ICPR) <= x && x < NVIC_IREG_END(NVIC_ICPR)) { // Interrupt Clear-Pending Registers
        #ifdef DEBUG_NVIC
        fprintf(stderr, "[NVIC] hook_nvic_mmio_write: NVIC_ICPR\n"); fflush(stderr);
        #endif
        for(int i = 0; i < size * 8; ++i) {
            if((value & 1)) {
                clear_pend_interrupt(ctx, base_ind + i);
            }
            value >>= 1;
        }
    }
    else if (NVIC_IREG_START(NVIC_IABR) <= x && x < NVIC_IREG_END(NVIC_IABR)) { // Interrupt Active Bit Registers
        // Read-only register: ignore
    }
    else if (NVIC_IPR_START(NVIC_IPR) <= x && x < NVIC_IPR_END(NVIC_IPR)) { // Interrupt Priority Registers
        #ifdef DEBUG_NVIC
        fprintf(stderr, "[NVIC] hook_nvic_mmio_write: NVIC_IPR\n"); fflush(stderr);
        #endif
        base_ind = EXCEPTION_NO_EXTERNAL_START + ((access_offset - NVIC_IPR) & 0x1ff);

        if(base_ind <= NVIC_NUM_SUPPORTED_INTERRUPTS - 4) {
            for(int i = 0; i < size; ++i) {
                uint8_t new_prio = value & 0xff;
                uint8_t to_be_prio_changed = (uint8_t)(base_ind + i);

                need_update |= set_prio(ctx, to_be_prio_changed, new_prio);
                value >>= 8;
            }

            if(need_update) {
                recalc_prios(ctx);
            }
        }
    }
}

static uint32_t calc_icsr(struct FwContext *ctx) {
    uint32_t res = 0;

    // ISRPREEMPT
    // debug state register, which we don't support

    // ISRPENDING
    // this is not the exact semantic, but we give some indication
    // (highest irq does not need to be external, could be SYSTICK / PENDSV)
    res |= (ctx->nvic.pending_irq > EXCEPTION_NO_SYSTICK) << SCB_ICSR_ISRPENDING_Pos;

    // VECTPENDING
    res |= (ctx->nvic.pending_irq << SCB_ICSR_VECTPENDING_Pos) & SCB_ICSR_VECTPENDING_Msk;

    // RETTOBASE
    res |= (ctx->nvic.num_active <= 1) << SCB_ICSR_RETTOBASE_Pos;

    // VECTACTIVE
    res |= ctx->nvic.active_irq & SCB_ICSR_VECTACTIVE_Msk;
    return res;
}


uint64_t handle_sysctl_mmio_read(uc_engine *uc, uint64_t addr, int size) {
    if(addr >= SYSTICK_BASE && addr <= SYSTICK_END) {
        return handle_syst_mmio_read(uc, addr, size);
    } else if (addr >= NVIC_MMIO_BASE && addr <= NVIC_MMIO_END) {
        return handle_nvic_mmio_read(uc, addr, size);
    }

    struct FwContext *ctx = uc->fw;
    uint32_t out_val = 0, base_ind;

    switch(addr & ~3) {
        case SYSCTL_ICTR: // Interrupt Controller Type Register
            // number of supported interrupts
            out_val = ctx->config.intlinesnum;
            break;
        case SYSCTL_ICSR: // Interrupt Control and State Register
            out_val = calc_icsr(ctx);
            break;
        case SYSCTL_VTOR: // Vector Table Offset Register
            out_val = ctx->nvic.vtor;
            break;
        case SYSCTL_AIRCR: // Application Interrupt and Reset Control Register.
            out_val = VECTKEY_HIWORD_MAGIC_READ;
            // Implicit: little endian
            // out_val |= 0 << SCB_AIRCR_ENDIANESS_Pos;
            out_val |= ctx->nvic.prigroup_shift << SCB_AIRCR_PRIGROUP_Pos;
            #ifdef DEBUG_NVIC
            fprintf(stderr, "Generated out_val for SYSCTL_AIRCR: %#010x\n", out_val); fflush(stderr);
            #endif
            break;
        case SYSCTL_STIR: // Software Triggered Interrupt Register
            // Ignore, write-only
            break;
        case SYSCTL_SHCSR: // System Handler Control and State Register
            // NOT IMPLEMENTED
            break;
        case SYSCTL_SHPR1: // System Handler Priority Register 1
        case SYSCTL_SHPR2:
        case SYSCTL_SHPR3:
            if (addr + size > SYSCTL_SHPR3+4)
                break;

            // Handle priorities for exceptions 4-15
            base_ind = 4 + (uint32_t)(addr - SYSCTL_SHPR1);

            for(int i = size-1; i >= 0; --i) {
                out_val <<= 8;
                out_val |= ctx->nvic.ExceptionPriority[base_ind + i];
            }
            break;
        default:
            // uc->backtrace(uc->ctx);
            break;

    }

    return out_val;
}

static void pend_from_mem_write(uc_engine *uc, int exception_no) {
    /*
    * For write-based register pends, we need an immediate activation
    * We also need to skip the currently executing write
    * instruction, as we would return to another write
    * otherwise
    */
    pend_interrupt(uc->fw, exception_no);
    maybe_activate(uc, true);
}

static void handle_icsr_write(uc_engine *uc, uint32_t value) {
    struct FwContext *ctx = uc->fw;

    if(value & SCB_ICSR_PENDSVSET_Msk) {
        pend_from_mem_write(uc, EXCEPTION_NO_PENDSV);
    }

    if(value & SCB_ICSR_PENDSVCLR_Msk) {
        clear_pend_interrupt(ctx, EXCEPTION_NO_PENDSV);
    }

    if(value & SCB_ICSR_PENDSTSET_Msk) {
        pend_from_mem_write(uc, EXCEPTION_NO_SYSTICK);
    }

    if(value & SCB_ICSR_PENDSTCLR_Msk) {
        clear_pend_interrupt(ctx, EXCEPTION_NO_SYSTICK);
    }

    if(value & SCB_ICSR_NMIPENDSET_Msk) {
        pend_interrupt(ctx, EXCEPTION_NO_NMI);
    }
}

static void handle_aircr_write(uc_engine *uc, uint32_t value) {
    struct FwContext *ctx = uc->fw;

    // VECTCLRACTIVE: Only valid in debug state, which we don't support
    // VECTRESET: Only valid in debug state, which we don't support
    if(value & SCB_AIRCR_SYSRESETREQ_Msk) {
        if(ctx->config.do_print_exit_info) {
            fprintf(stderr, "SYSCTL_AIRCR write indicated system reset, stopping emulation\n");
        }
        // do_exit(uc, UC_ERR_EXCEPTION);
        do_exit(uc, UC_ERR_OK);
    }

    // PRIGROUP
    uint32_t new_prigroup = (value & SCB_AIRCR_PRIGROUP_Msk) >> SCB_AIRCR_PRIGROUP_Pos;
    if(new_prigroup != ctx->nvic.prigroup_shift) {
        #ifdef DEBUG_NVIC
        fprintf(stderr, "[NVIC] SYSCTL_AIRCR write: Setting prigroup to new value. Old value: %#04x, new value: %#04x\n", ctx->nvic.prigroup_shift, new_prigroup);
        fflush(stderr);
        #endif
        set_prigroup(ctx, (uint8_t)new_prigroup);

        recalc_prios(ctx);
    }
    #ifdef DEBUG_NVIC
    else {
        fprintf(stderr, "[NVIC] SYSCTL_AIRCR write: extracted prigroup %x from value %08x. It stayed the same.\n", new_prigroup, value); fflush(stderr);
    }
    #endif
}

void hook_sysctl_mmio_write(uc_engine *uc, uc_mem_type type,
                      uint64_t addr, int size, int64_t value, void *user_data) {
    #ifdef DEBUG_NVIC
    uint32_t pc = 0;
    uc->reg_read(uc->ctx, UC_ARM_REG_PC, &pc);
    fprintf(stderr, "[NVIC] hook_sysctl_mmio_write: 0x%x Write to %08lx, value: %08lx\n", pc, addr, value);
    fflush(stderr);
    #endif

    if(addr >= SYSTICK_BASE && addr <= SYSTICK_END) {
        hook_syst_mmio_write(uc, type, addr, size, value, user_data);
        return;
    } else if (addr >= NVIC_MMIO_BASE && addr <= NVIC_MMIO_END) {
        hook_nvic_mmio_write(uc, type, addr, size, value, user_data);
        return;
    }

    struct FwContext *ctx = uc->fw;
    uint32_t to_pend, base_ind;

    switch(addr & ~3) {
        case SYSCTL_ICTR: // Interrupt Controller Type Register
            // Ignore, read-only
            break;
        case SYSCTL_ICSR: // Interrupt Control and State Register
            handle_icsr_write(uc, value);
            break;
        case SYSCTL_VTOR: // Vector Table Offset Register
            ctx->nvic.vtor = value;
            break;
        case SYSCTL_AIRCR: // Application Interrupt and Reset Control Register.
            if((value & 0xffff0000u) == VECTKEY_HIWORD_MAGIC_WRITE) {
                // Valid key, process write
                handle_aircr_write(uc, value);
            }
            #ifdef NVIC_ASSERTIONS
            nvic_assert((value & 0xffff0000u) == VECTKEY_HIWORD_MAGIC_WRITE, "Expected SYSCTL_AIRCR write key to be correct, but it is not equal to VECTKEY_HIWORD_MAGIC_WRITE");
            #endif
            break;
        case SYSCTL_CCR: // Configuration and Control Register
            break;
        case SYSCTL_STIR: // Software Triggered Interrupt Register
            to_pend = EXCEPTION_NO_EXTERNAL_START + (value & 0xff);
            if(to_pend < EXCEPTION_NO_MAX && !is_disabled_by_config(ctx, to_pend)) {
                pend_from_mem_write(uc, to_pend);
            }
            break;
        case SYSCTL_SHCSR: // System Handler Control and State Register
            break;
        case SYSCTL_SHPR1: // System Handler Priority Register 1-3
        case SYSCTL_SHPR2:
        case SYSCTL_SHPR3:
            if(addr + size > SYSCTL_SHPR3+4)
                break;

            bool need_update = false;
            // Handle priorities for exceptions 4-15
            base_ind = 4 + (addr - SYSCTL_SHPR1);

            for(int i = 0; i < size; ++i) {
                uint8_t new_prio = value & 0xff;
                uint8_t to_be_prio_changed = base_ind + i;

                need_update |= set_prio(ctx, to_be_prio_changed, new_prio);
                value >>= 8;
            }

            if(need_update) {
                recalc_prios(ctx);
            }
            break;
        default:
            break;
    }
}

void handle_sysctl_mmio_write(uc_engine *uc, uint64_t addr, int size, int64_t value) {
    hook_sysctl_mmio_write(uc, UC_MEM_WRITE, addr, size, value, NULL);
}

// Armv7-M ARM B1.5.8
void PopStack(uc_engine *uc) {
    uint32_t frameptr;
    uc->reg_read(uc->ctx, UC_ARM_REG_SP, &frameptr);
    uc_err err;

    #ifdef DEBUG_NVIC
    fprintf(stderr, "************ PRE PopStack\n");
    print_state(uc);
    #endif

    struct FwContext *ctx = uc->fw;

    if((err = uc->mem_read(uc->ctx, frameptr, &ctx->saved_regs, FRAME_SIZE)) != UC_ERR_OK) {
        if(ctx->config.do_print_exit_info) {
            fprintf(stderr, "[NVIC] PopStack: reading saved context frame during interrupt exit failed for frameptr= 0x%08x: (%s)\n", frameptr, uc_strerror(err));
            fflush(stderr);
        }
        force_crash(uc, err);
    }

    // Align stack
    ctx->saved_regs.sp = frameptr + FRAME_SIZE;
    if ((ctx->saved_regs.xpsr_retspr & (1 << 9)) != 0) {
        ctx->saved_regs.sp += 4;
    }
    // Clear saved alignment bit.
    ctx->saved_regs.xpsr_retspr &= ~(1 << 9);

    // Here we restore all registers in one go, including sp
    if((err = uc->reg_write_batch(uc->ctx, &saved_reg_ids[0], (void **)(&ctx->saved_reg_ptrs[0]), NUM_SAVED_REGS)) != UC_ERR_OK){
        if(ctx->config.do_print_exit_info) {
            fprintf(stderr, "[NVIC ERROR] PopStack: restoring registers failed\n\n");
            print_state(uc);
            fflush(stderr);
        }
        force_crash(uc, err);
    }

    // Restore the stored active irq
    ctx->nvic.active_irq = ctx->saved_regs.xpsr_retspr & xPSR_ISR_Msk;

    #ifdef DEBUG_NVIC
    fprintf(stderr, "************ POST PopStack\n");
    print_state(uc);
    #endif
}

// B1.5.6
void PushStack(uc_engine *uc, bool skip_instruction) {
    uc_err err;

    #ifdef DEBUG_NVIC
    fprintf(stderr, "************ PRE PushStack\n");
    print_state(uc);
    #endif

    /*
     * Push the pre-exception register stack to the stack.
     * We do not deal with SP_process vs. SP_main here, though.
     * Instead, we use the current SP (which will return whatever
     * the correct value is) and push to that.
     * We assume that the calling function rotates out SP_process
     * when coming from thread mode and SP_process is used.
     */

    // The standard mentions (but deprecates) only guarateeing a
    // 4-byte alignment. We force a 8-byte stack alignment
    uint32_t frameptr, frameptralign;
    uint32_t spmask = ~(1 << 2);

    struct FwContext *ctx = uc->fw;

    // Read the registers which are to be pushed afterwards
    if((err = uc->reg_read_batch(uc->ctx, &saved_reg_ids[0], (void **)(&ctx->saved_reg_ptrs[0]), NUM_SAVED_REGS)) != UC_ERR_OK) {
        if(ctx->config.do_print_exit_info) {
            fprintf(stderr, "[NVIC ERROR] PushStack: Failed reading registers\n\n");
            fflush(stderr);
        }
        force_crash(uc, err);
    }

    if(skip_instruction) {
        uint64_t insn = 0;
        #ifdef DEBUG_NVIC
        uint32_t prev_pc = ctx->saved_regs.pc_retaddr;
        #endif
        if ((err = uc->mem_read(uc->ctx, ctx->saved_regs.pc_retaddr, &insn, 2)) != UC_ERR_OK) {
            if (ctx->config.do_print_exit_info) {
                fprintf(stderr, "[NVIC ERROR] PushStack: error reading 0x%x\n", ctx->saved_regs.pc_retaddr);
                fflush(stderr);
            }
            force_crash(uc, err);
        }
        ctx->saved_regs.pc_retaddr += get_instruction_size(insn, true);
        #ifdef DEBUG_NVIC
        fprintf(stderr, "[PushStack, skip_curr_instruction] adjusted pc from 0x%x to 0x%x\n", prev_pc, ctx->saved_regs.pc_retaddr); fflush(stderr);
        #endif
    }

    // We are always working on the current stack pointer, given the mode
    frameptralign = (ctx->saved_regs.sp & ~spmask) >> 2;
    frameptr = (ctx->saved_regs.sp - FRAME_SIZE) & spmask;

    // Save the stack pointer with additional space
    uc->reg_write(uc->ctx, UC_ARM_REG_SP, &frameptr);
    #ifdef DEBUG_NVIC
    fprintf(stderr, "[PushStack] adjusted sp from 0x%x to 0x%x\n", ctx->saved_regs.sp, frameptr); fflush(stderr);
    #endif

    // Adjust xpsr with alignment info
    ctx->saved_regs.xpsr_retspr &= ~(1 << 9);
    ctx->saved_regs.xpsr_retspr |= (frameptralign << 9);

    // Push the context frame itself
    if((err = uc->mem_write(uc->ctx, frameptr, &ctx->saved_regs, (NUM_SAVED_REGS - 1)*sizeof(ctx->saved_regs.r0))) != UC_ERR_OK){
        if(ctx->config.do_print_exit_info) {
            fprintf(stderr, "[NVIC] PopStack: writing saved context frame during interrupt entry failed (INVALID WRITE, frameptr= 0x%08x)\n", frameptr);
            print_state(uc);
            fflush(stderr);
        }
        force_crash(uc, err);
    }

    #ifdef DEBUG_NVIC
    fprintf(stderr, "************ POST PushStack\n");
    print_state(uc);
    #endif
}

// B1.5.8
void ExceptionReturn(uc_engine *uc, uint32_t ret_pc) {
    struct FwContext *ctx = uc->fw;
    uint32_t ReturningExceptionNumber = ctx->nvic.active_irq;

    // DeActivate(ReturningExceptionNumber)
    ctx->nvic.ExceptionActive[ReturningExceptionNumber] = 0;
    // Unicorn does not seem to handle faultmask
    // unset_faultmask();

    if(ReturningExceptionNumber == NVIC_NONE_ACTIVE) {
        if(ctx->config.do_print_exit_info) {
            fprintf(stderr, "[NVIC ERROR] ExceptionReturn: Inconsistent state: no exception is active. This probably means we got here via a corrupted pc...\n");
            print_state(uc);
            fflush(stderr);
        }

        force_crash(uc, UC_ERR_FETCH_PROT);
        return;
    }

    #ifdef DEBUG_NVIC
    uint32_t sp_mode, other_sp, sp, lr;
    sp_mode = GET_CURR_SP_MODE_IS_PSP(ctx);
    uc->reg_read(uc->ctx, UC_ARM_REG_OTHER_SP, &other_sp);
    uc->reg_read(uc->ctx, UC_ARM_REG_SP, &sp);
    uc->reg_read(uc->ctx, UC_ARM_REG_LR, &lr);
    fprintf(stderr, "[ExceptionReturn] UC_ARM_REG_CURR_SP_MODE_IS_PSP=%d, UC_ARM_REG_OTHER_SP=%08x, UC_ARM_REG_SP=%08x, lr=%08x\n", sp_mode, other_sp, sp, lr); fflush(stderr);
    #endif

    /*
     * After deactivating the exception, re-calc to see if a
     * pending exception can now be taken.
     */
    recalc_prios(ctx);

    // Unset the active interrupt to allow active prio to drop
    ctx->nvic.active_irq = NVIC_NONE_ACTIVE;
    if(pending_exception_can_be_activated(ctx)) {
        // Can we tail-chain?
        ExceptionEntry(uc, true, false);
        return;
    }

    // If we don't tail-chain, we need to pop the current stack state

    // Are we returning to thread mode?
    if(ret_pc & NVIC_INTERRUPT_ENTRY_LR_THREADMODE_FLAG) {
        // Need to change stack to SP_process
        if(ret_pc & NVIC_INTERRUPT_ENTRY_LR_PSPSWITCH_FLAG) {
            // We are coming from Handler Mode (which always uses SP_main) and
            // return to Thread Mode which uses SP_process. Switch to SP_process
            uint32_t new_SPSEL_now_psp = 1;
            uint32_t SP_process, SP_main;
            uc->reg_read(uc->ctx, UC_ARM_REG_SP, &SP_main);
            uc->reg_read(uc->ctx, UC_ARM_REG_OTHER_SP, &SP_process);

            // Back up SP_main
            uc->reg_write(uc->ctx, UC_ARM_REG_OTHER_SP, &SP_main);
            uc->reg_write(uc->ctx, UC_ARM_REG_SP, &SP_process);

            // Switch the CPU state to indicate the new SPSEL state
            // 1. In pstate register
            uc->reg_write(uc->ctx, UC_ARM_REG_SPSEL, &new_SPSEL_now_psp);
            // 2. In cached spsel field
            uc->reg_write(uc->ctx, UC_ARM_REG_CURR_SP_MODE_IS_PSP, &new_SPSEL_now_psp);
        }
    }

    PopStack(uc);
    uc->pop_stack(uc->ctx);

    nvic_assert(
        (((ret_pc & NVIC_INTERRUPT_ENTRY_LR_THREADMODE_FLAG) != 0) == (ctx->nvic.active_irq == NVIC_NONE_ACTIVE)),
        "[ExceptionReturn] expected thread mode return to end up with nvic.active_irq == NVIC_NONE_ACTIVE and vice versa."
    );
}

void handler_svc(uc_engine *uc, uint32_t intno, void *user_data) {
    #ifdef DEBUG_NVIC
    uint32_t pc;
    uc->reg_read(uc->ctx, UC_ARM_REG_PC, &pc);
    fprintf(stderr, "[SVC HOOK %08x] native SVC hook called, intno: %d\n", pc, intno); fflush(stderr);
    #endif

    struct FwContext *ctx = uc->fw;

    // Make sure we are actually asked to perform a syscall
    if(intno == 2) {
        #ifndef SKIP_CHECK_SVC_ACTIVE_INTERRUPT_PRIO
        if(ctx->nvic.active_group_prio <= ctx->nvic.ExceptionPriority[EXCEPTION_NO_SVC]) {
            if(ctx->config.do_print_exit_info) {
                uint32_t pc;
                uc->reg_read(uc->ctx, UC_ARM_REG_PC, &pc);
                fprintf(stderr, "[SVC HOOK %08x] primask is set, so interrupts are masked. SVC prio: %d. As this would escalate to hardfault, exiting\n", pc, ctx->nvic.ExceptionPriority[EXCEPTION_NO_SVC]); fflush(stderr);
            }
            do_exit(uc, UC_ERR_EXCEPTION);
            return;
        }
        #endif
        // SVCs are enabled by default. Just pend the SVC exception here
        pend_interrupt(ctx, EXCEPTION_NO_SVC);
        maybe_activate(uc, false);
    } else {
        // Alternatives could be breakpoints and the like, which we do not handle.
        if(ctx->config.do_print_exit_info) {
            uint32_t pc;
            uc->reg_read(uc->ctx, UC_ARM_REG_PC, &pc);
            fprintf(stderr, "[SVC HOOK %08x] %d is NOT an SVC, exiting\n", pc, intno); fflush(stderr);
        }
        do_exit(uc, UC_ERR_OK);
    }
}

// B1.5.6
static void ExceptionEntry(uc_engine *uc, bool is_tail_chained, bool skip_instruction) {
    uint32_t new_lr = NVIC_INTERRUPT_ENTRY_LR_BASE;

    #ifdef DEBUG_NVIC
    fprintf(stderr, "[NVIC] ExceptionEntry(is_tail_chained=%d, skip_instruction=%d)\n", is_tail_chained, skip_instruction); fflush(stderr);
    #endif

    struct FwContext *ctx = uc->fw;

    // Bookkeep number of interrupts except SysTick
    if (ctx->nvic.pending_irq != EXCEPTION_NO_SYSTICK) {
        if (++ctx->nvic.interrupt_count >= ctx->config.interrupt_limit) {
            if(ctx->config.do_print_exit_info) {
                fprintf(stderr, "Interrupt activation limit of %d reached, exiting\n", ctx->config.interrupt_limit); fflush(stderr);
            }

            do_exit(uc, UC_ERR_INTERRUPT_LIMIT);
            return;
        }
    }

    if(!is_tail_chained) {
        /*
         * We are interrupting execution. We are either preempting an existing interrupt
         * (Handler Mode) or coming from normal execution (Thread Mode). So save frame.
         */
        PushStack(uc, skip_instruction);
        uc->push_stack(uc->ctx);

        /*
        * Figure out stack pointer to push exception context to:
        * We need to handle the situation where we come from thread mode (no exception being handled),
        * and use the SP_process stack instead of the SP_main stack (which is always used in handler mode).
        */
        if(ctx->nvic.active_irq == NVIC_NONE_ACTIVE) {
            // We are coming from Thread mode in case we are not tail-chained and had no previously active IRQ
            new_lr |= NVIC_INTERRUPT_ENTRY_LR_THREADMODE_FLAG;

            if(GET_CURR_SP_MODE_IS_PSP(ctx)) {
                // We are coming from Thread Mode which uses SP_process. Switch it to SP_main
                uint32_t new_SPSEL_not_psp = 0;
                uint32_t SP_process, SP_main;
                uc->reg_read(uc->ctx, UC_ARM_REG_SP, &SP_process);
                uc->reg_read(uc->ctx, UC_ARM_REG_OTHER_SP, &SP_main);

                #ifdef DEBUG_NVIC
                fprintf(stderr, "[NVIC] switching from SP_process: %x to SP_main: %x\n", SP_process, SP_main); fflush(stderr);
                #endif

                // Back up SP_process
                uc->reg_write(uc->ctx, UC_ARM_REG_OTHER_SP, &SP_process);
                uc->reg_write(uc->ctx, UC_ARM_REG_SP, &SP_main);

                // Switch the CPU state to indicate the new SPSEL state
                // 1. In pstate register
                uc->reg_write(uc->ctx, UC_ARM_REG_SPSEL, &new_SPSEL_not_psp);
                // 2. In cached spsel field
                uc->reg_write(uc->ctx, UC_ARM_REG_CURR_SP_MODE_IS_PSP, &new_SPSEL_not_psp);

                // Finally: Indicate that we switched in the LR value
                new_lr |= NVIC_INTERRUPT_ENTRY_LR_PSPSWITCH_FLAG;
            }
        }
    } else {
        // Tail Chaining: going from handler mode to handler mode. No stack switching required
        uint32_t prev_lr;
        // If we are chained, maintain the previous lr's SP switch and thread mode bits
        uc->reg_read(uc->ctx, UC_ARM_REG_PC, &prev_lr);
        new_lr |= (prev_lr & (NVIC_INTERRUPT_ENTRY_LR_PSPSWITCH_FLAG | NVIC_INTERRUPT_ENTRY_LR_THREADMODE_FLAG));
    }

    // In any case we need to set our new LR
    uc->reg_write(uc->ctx, UC_ARM_REG_LR, &new_lr);

    // We inline ExceptionTaken here

    // Find the ISR entry point and set it
    uint32_t ExceptionNumber = ctx->nvic.pending_irq;
    uint32_t isr_entry;
    uc_err err;
    if ((err = uc->mem_read(uc->ctx, ctx->nvic.vtor + 4 * ExceptionNumber, &isr_entry, sizeof(isr_entry))) != UC_ERR_OK) {
        if(uc->fw->config.do_print_exit_info) {
            fprintf(stderr, "[NVIC ERROR] ExceptionEntry: error reading ISR entry: 0x%x\n", ctx->nvic.vtor + 4 * ExceptionNumber);
        }
        force_crash(uc, err);
    }
    uc->reg_write(uc->ctx, UC_ARM_REG_PC, &isr_entry);

    #ifdef DEBUG_NVIC
    fprintf(stderr, "Redirecting irq %d to isr: %08x lr: %08x\n", ExceptionNumber, isr_entry, new_lr);
    #endif

    // Prepare new XPSR state
    uint32_t isr_xpsr = ctx->saved_regs.xpsr_retspr;
    // Reset ITSTATE bits
    isr_xpsr &= ~(xPSR_ICI_IT_2_Msk | xPSR_ICI_IT_1_Msk);
    // Set active interrupt
    isr_xpsr &= ~xPSR_ISR_Msk;
    isr_xpsr |= ExceptionNumber;
    uc->reg_write(uc->ctx, UC_ARM_REG_XPSR, &isr_xpsr);

    // Update nvic state with new active interrupt
    ctx->nvic.ExceptionActive[ExceptionNumber] = 1;
    ctx->nvic.ExceptionPending[ExceptionNumber] = 0;
    ctx->nvic.active_irq = ExceptionNumber;

    // We need to re-calculate the pending priority state
    recalc_prios(ctx);

    #ifdef DEBUG_NVIC
    fprintf(stderr, "************ POST ExceptionEntry\n");
    print_state(uc);
    #endif
}

// #define NVIC_BLOCK_HOOK_SIMPLE
#ifndef NVIC_BLOCK_HOOK_SIMPLE
ATTRIBUTE_HOT
void nvic_block_hook(uc_engine *uc, uint64_t address, uint32_t size) {
    struct FwContext *ctx = uc->fw;
    struct CortexmNVIC *arg_nvic = &ctx->nvic;
    /*
     * This implementation takes the more complex approach of trying to exit early in the common
     * case: If nothing changed on the enabling / base priority sides, just exit.
     */

    /*
     * CAUTION: This runs for every block - so we are on a performance-critical path
     *
     * We first need to check registers which can change without us seeing these changes:
     * 1. primask: Interrupts disabled (interrupts could have been re-enabled)
     * 2. basepri: The base active priority (base priority could have been lowered, such that another interrupt now takes precedence)
     *
     * We also consider whether previous updates are now pending a higher-prio interrupt
     **/

    // 1. Interrupts disabled?
    if (likely(GET_PRIMASK_NVIC(ctx) == 0)) {
        // Interrupts are not disabled
        uint32_t basepri = GET_BASEPRI_NVIC(ctx);

        #ifdef DEBUG_NVIC
        // fprintf(stderr, "basepri == %d, primask == 0\n", basepri); fflush(stderr);
        #endif

        // Interrupts have previously been entirely disabled
        if(unlikely(arg_nvic->prev_primask))
        {
            #ifdef DEBUG_NVIC
            fprintf(stderr, "[NVIC] [tick %lu] Detected change in interrupt enable (new 0x%x vs old 0x%x), calling maybe_activate(uc);\n", get_global_ticker(), GET_PRIMASK_NVIC(ctx), arg_nvic->prev_primask);
            fflush(stderr);
            #endif

            // We went from interrupts masked to interrupts not masked
            arg_nvic->prev_primask = 0;
            // We need to check actual pending priorities
        } else if (likely(basepri == arg_nvic->prev_basepri) || (basepri != 0 && basepri < arg_nvic->prev_basepri)) {
            arg_nvic->prev_basepri = basepri;

            /*
             * This is the early exit which we expect to take most of the time
             * Not landing here would mean either
             * a) having newly enabled interupts again
             * b) or having lowered the base priority
             */
            return;
        } else {
            // Interrupts are still enabled, and we lowered basepri
            // We need to check actual pending priorities
        }

        #ifdef DEBUG_NVIC
        if(basepri > arg_nvic->prev_basepri) {
            fprintf(stderr, "[NVIC] [tick %lu] Detected change in interrupt base priority (new 0x%x vs old 0x%x), calling maybe_activate(uc);\n", get_global_ticker(), basepri, arg_nvic->prev_basepri);
            fflush(stderr);
        }
        #endif
        arg_nvic->prev_basepri = basepri;

        // We know interrupts are still enabled here and we already queried the basepri value.
        // This means we don't need to update prev_primask, it stayed at 0
        // arg_nvic->prev_primask = 0;

        // We are inlining primask/basepri knowledge instead of calling the full maybe_activate
        // maybe_activate(uc, false);

        if(arg_nvic->active_irq == NVIC_NONE_ACTIVE || ctx->config.enable_nested_interrupts) {
            int active_group_prio = arg_nvic->active_group_prio;
            if(basepri != 0 && basepri < active_group_prio) {
                active_group_prio = basepri & arg_nvic->group_prio_mask;
            }

            if(arg_nvic->pending_prio < active_group_prio) {
                ExceptionEntry(uc, false, false);
            }
        }
    } else {
        // primask is set / interrupts are disabled now
        arg_nvic->prev_primask = 1;
    }
}
#else
ATTRIBUTE_HOT
static void nvic_block_hook(uc_engine *uc, uint64_t address, uint32_t size, struct CortexmNVIC *arg_nvic) {
    /*
     * This implementation takes the simple approach of always re-calculating the current
     * active prio and checking it against the pending prio in case interrupts are enabled.
     */

    int32_t basepri;

    if (likely(GET_PRIMASK_NVIC(arg_nvic) == 0)) {
        if(likely(arg_nvic->active_irq == NVIC_NONE_ACTIVE || ctx->config.enable_nested_interrupts)) {
            basepri = GET_BASEPRI_NVIC(arg_nvic);

            int active_group_prio = arg_nvic->active_group_prio;
            if(basepri != 0 && basepri < active_group_prio) {
                active_group_prio = basepri & arg_nvic->group_prio_mask;
            }

            if(unlikely(arg_nvic->pending_prio < active_group_prio)) {
                ExceptionEntry(uc, false, false);
            }

        }
    }
}
#endif

void *nvic_take_snapshot(uc_engine *uc) {
    struct CortexmNVIC *nvic_ptr = &uc->fw->nvic;
    size_t size = sizeof(struct CortexmNVIC);

    // NVIC snapshot: save the sysreg mem page
    char *result = malloc(size);
    memcpy(result, nvic_ptr, size);

    return result;
}

void nvic_restore_snapshot(uc_engine *uc, void *snapshot) {
    // Restore the nvic
    struct CortexmNVIC * arg_nvic = &uc->fw->nvic;
    memcpy(arg_nvic, snapshot, sizeof(struct CortexmNVIC));
}

void nvic_discard_snapshot(uc_engine *uc, void *snapshot) {
    free(snapshot);
}

uc_err init_nvic(uc_engine *uc,
    uint32_t vtor,
    uint32_t num_irq,
    uint32_t interrupt_limit,
    uint32_t num_disabled_interrupts,
    uint32_t *disabled_interrupts,
    bool enable_nested_interrupts,
    bool allow_active_interrupt_pending) {
    #ifdef DEBUG_NVIC
    fprintf(stderr, "[NVIC] init_nvic called with vtor: %x, num_irq: %d\n", vtor, num_irq); fflush(stderr);
    #endif

    if(num_irq > EXCEPTION_NO_MAX) {
        num_irq = EXCEPTION_NO_MAX;
    }

    struct FwContext* ctx = uc->fw;
    struct saved_regs* saved_regs = &ctx->saved_regs;
    ctx->saved_reg_ptrs[0] = &saved_regs->r0;
    ctx->saved_reg_ptrs[1] = &saved_regs->r1;
    ctx->saved_reg_ptrs[2] = &saved_regs->r2;
    ctx->saved_reg_ptrs[3] = &saved_regs->r3;
    ctx->saved_reg_ptrs[4] = &saved_regs->r12;
    ctx->saved_reg_ptrs[5] = &saved_regs->lr;
    ctx->saved_reg_ptrs[6] = &saved_regs->pc_retaddr;
    ctx->saved_reg_ptrs[7] = &saved_regs->xpsr_retspr;
    ctx->saved_reg_ptrs[8] = &saved_regs->sp;

    struct CortexmNVIC *nvic_ptr = &ctx->nvic;
    nvic_ptr->prev_basepri = -1;

    // Make sure SVC is enabled
    nvic_ptr->ExceptionEnabled[EXCEPTION_NO_SVC] = 1;
    nvic_ptr->ExceptionEnabled[EXCEPTION_NO_PENDSV] = 1;
    nvic_ptr->ExceptionEnabled[EXCEPTION_NO_SYSTICK] = 1;

    nvic_ptr->ExceptionPriority[EXCEPTION_NO_NMI] = -2;
    nvic_ptr->highest_ever_enabled_exception_no = EXCEPTION_NO_SYSTICK;

    nvic_ptr->active_irq = NVIC_NONE_ACTIVE;
    nvic_ptr->pending_irq = NVIC_NONE_ACTIVE;
    nvic_ptr->active_group_prio = NVIC_LOWEST_PRIO;
    nvic_ptr->pending_prio = NVIC_LOWEST_PRIO;
    set_prigroup(ctx, NVIC_RESET_VAL_PRIGROUP);

    // B1.5.5 Reset Behavior
    // Unicorn CPU reset will reset PRIMASK / FAULTMASK, SP, ...
    // Priorities default to 0, so nothing to be done

    nvic_ptr->interrupt_count = 0;

    struct FwConfig *config = &ctx->config;
    config->interrupt_limit = interrupt_limit;
    config->num_disabled_interrupts = num_disabled_interrupts;
    config->disabled_interrupts = calloc(num_disabled_interrupts, sizeof(*disabled_interrupts));
    config->intlinesnum = INTLINESNUM;
    config->enable_nested_interrupts = enable_nested_interrupts;
    config->allow_active_interrupt_pending = allow_active_interrupt_pending;

    for(uint32_t i = 0; i < num_disabled_interrupts; ++i)
        config->disabled_interrupts[i] = EXCEPTION_NO_EXTERNAL_START + disabled_interrupts[i];

    // Get pointers to commonly used registers
    uc_err err;
    if((err = uc->reg_ptr(uc->ctx, UC_ARM_REG_PRIMASK, (void **) &ctx->reg_daif_ptr)) != UC_ERR_OK) {
        fprintf(stderr, "[init_nvic] ERROR: uc_reg_tr\n");
        return err;
    }
    if((err = uc->reg_ptr(uc->ctx, UC_ARM_REG_BASEPRI, (void **) &ctx->reg_basepri_ptr)) != UC_ERR_OK) {
        fprintf(stderr, "[init_nvic] ERROR: uc_reg_tr\n");
        return err;
    }
    if((err = uc->reg_ptr(uc->ctx, UC_ARM_REG_CURR_SP_MODE_IS_PSP, (void **) &ctx->reg_curr_sp_mode_is_psp_ptr)) != UC_ERR_OK) {
        fprintf(stderr, "[init_nvic] ERROR: uc_reg_tr\n");
        return err;
    }

    // Set the vtor. If it is uninitialized, read it from actual (restored) process memory
    if(vtor == NVIC_VTOR_NONE) {
        if ((err = uc->mem_read(uc->ctx, SYSCTL_VTOR, &nvic_ptr->vtor, sizeof(nvic_ptr->vtor))) != UC_ERR_OK) {
            fprintf(stderr, "[init_nvic] ERROR: SYSCTL_VTOR\n");
            return err;
        }
        fprintf(stderr, "[NVIC] Recovered vtor base: %x\n", nvic_ptr->vtor); fflush(stderr);
    } else {
        // We have MMIO vtor read fall through, so put vtor value in emulated memory
        // uc->mem_write(uc->ctx, SYSCTL_VTOR, &nvic_ptr->vtor, sizeof(nvic_ptr->vtor));
        nvic_ptr->vtor = vtor;
    }

    // 3. nvic MMIO range read/write handler
    // uc->mem_hook_add(uc->ctx, &hook_mmio_write_handle, UC_HOOK_MEM_WRITE, hook_sysctl_mmio_write, NULL, SYSCTL_MMIO_BASE, SYSCTL_MMIO_END);
    // uc->mem_hook_add(uc->ctx, &hook_mmio_read_handle, UC_HOOK_MEM_READ, hook_sysctl_mmio_read, NULL, SYSCTL_MMIO_BASE, SY

    recalc_prios(ctx);

    return UC_ERR_OK;
}

uint16_t get_num_enabled(struct CortexmNVIC * nvic_ptr) {
    return nvic_ptr->num_enabled;
}

uint8_t nth_enabled_irq_num(struct CortexmNVIC * nvic_ptr, uint8_t n) {
    return nvic_ptr->enabled_irqs[n % nvic_ptr->num_enabled];
}

void nvic_set_pending(uc_engine *uc, uint32_t num, int delay_activation) {
    pend_interrupt(uc->fw, num);
    maybe_activate(uc, false);
}
