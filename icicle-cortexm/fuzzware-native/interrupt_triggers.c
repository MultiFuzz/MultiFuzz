#include "interrupt_triggers.h"
#include "native_hooks.h"
#include "core_peripherals/cortexm_nvic.h"
#include "timer.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// 0. Constants

#define FUZZER_TIME_RELOAD_CHOICES 8
const int64_t FUZZER_TIME_RELOAD_VALS[FUZZER_TIME_RELOAD_CHOICES] = {
    // Due to fuzzer's biased random use, put regular values to front and end
    IRQ_DEFAULT_TIMER_INTERVAL,
    IRQ_DEFAULT_TIMER_INTERVAL >> 1,
    IRQ_DEFAULT_TIMER_INTERVAL >> 2,
    1,
    IRQ_DEFAULT_TIMER_INTERVAL << 2,
    IRQ_DEFAULT_TIMER_INTERVAL << 3,
    IRQ_DEFAULT_TIMER_INTERVAL << 4,
    IRQ_DEFAULT_TIMER_INTERVAL << 1,
};

static void interrupt_trigger_tick_block_hook(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    InterruptTrigger *trigger = (InterruptTrigger *) user_data;

    #ifdef DEBUG_INTERRUPT_TRIGGERS
    printf("[INTERRUPT TRIGGER] Trigger callback called at address 0x%lx\n", address); fflush(NULL);
    #endif

    if(trigger->skip_next) {
        // We are coming from where we triggered the interrupt
        trigger->skip_next = 0;
        return;
    } else if (trigger->curr_pends)
    {
        // Already on the pending train, follow it
        nvic_set_pending(uc, trigger->irq, false);
        ++trigger->curr_pends;
        #ifdef DEBUG_INTERRUPT_TRIGGERS
        printf("[INTERRUPT TRIGGER] On pending train: %d/%d\n", trigger->curr_pends, trigger->times_to_pend);
        #endif
    } else if(trigger->curr_skips < trigger->times_to_skip) {
        // We need to wait for a bit longer
        ++trigger->curr_skips;
        #ifdef DEBUG_INTERRUPT_TRIGGERS
        printf("[INTERRUPT TRIGGER] Trigger skipping %d/%d\n", trigger->curr_skips, trigger->times_to_skip);
        #endif
    } else {
        uint16_t num_enabled;
        // Waiting is over, check whether to do anything
        switch(trigger->fuzz_mode) {
            case IRQ_FUZZ_MODE_FIXED:
                #ifdef DEBUG_INTERRUPT_TRIGGERS
                printf("[INTERRUPT TRIGGER] Pending fixed interrupt automatically: %d\n", trigger->irq);
                #endif
                // Pend in all cases, fall through
                break;

            case IRQ_FUZZ_MODE_FUZZ_ENABLED_IRQ_INDEX:
                // Pend the irq which the fuzzer decides which irq to pend based on the currently enabled ones
                num_enabled = get_num_enabled(&uc->fw->nvic);
                if (num_enabled)
                {
                    uint8_t irq_ind = 0; // default: we choose the first one without consuming fuzzing input if we only have one enabled irq anyways
                    if (num_enabled != 1) {
                        if (!uc->get_next_irq_number(uc->ctx, &irq_ind)) {
                            return;
                        }
                    }
                    trigger->irq = nth_enabled_irq_num(&uc->fw->nvic, irq_ind);

                    #ifdef DEBUG_INTERRUPT_TRIGGERS
                    printf("[INTERRUPT TRIGGER] Fuzzer index choice: Pending nth (%d) interrupt: %d\n", irq_ind, trigger->irq);
                    #endif
                } else {
                    #ifdef DEBUG_INTERRUPT_TRIGGERS
                    printf("[INTERRUPT TRIGGER] Fuzzer index choice to be made, but no interrupts enabled \n");
                    #endif
                    // No irqs are enabled
                    trigger->irq = 0;
                }
                break;

            case IRQ_FUZZ_MODE_ROUND_ROBIN:
                if (get_num_enabled(&uc->fw->nvic)) {
                    trigger->irq = nth_enabled_irq_num(&uc->fw->nvic, trigger->round_robin_index++);
                    #ifdef DEBUG_INTERRUPT_TRIGGERS
                    printf("[INTERRUPT TRIGGER] Round robin: Pending nth (%d) interrupt: %d\n", trigger->round_robin_index, trigger->irq);
                    #endif
                } else {
                    #ifdef DEBUG_INTERRUPT_TRIGGERS
                    puts("[INTERRUPT TRIGGER] Round robin: No interrupts are currently enabled...");
                    #endif
                    // No irqs are enabled
                    trigger->irq = 0;
                }
                break;
            default:
                trigger->irq = 0;
            }

        if(trigger->trigger_mode == IRQ_TRIGGER_MODE_TIME_FUZZED) {
            uint8_t time_fuzzer_choice;
            if (!uc->get_next_timer_choice(uc->ctx, &time_fuzzer_choice)) {
                return;
            }
            set_timer_reload_val(uc, trigger->timer_id, FUZZER_TIME_RELOAD_VALS[time_fuzzer_choice % FUZZER_TIME_RELOAD_CHOICES]);
        }

        // Perform the actual pending
        if(trigger->irq && (uc->fw->config.allow_active_interrupt_pending || uc->fw->nvic.active_irq != trigger->irq)) {
            nvic_set_pending(uc, trigger->irq, false);
            ++trigger->curr_pends;
        }
    }

    if (trigger->curr_pends == trigger->times_to_pend)
    {
        trigger->curr_pends = 0;
        trigger->curr_skips = 0;
        trigger->skip_next = 1;

        #ifdef DEBUG_INTERRUPT_TRIGGERS
        puts("[INTERRUPT TRIGGER] Resetting interrupt curr_pends and skips");
        #endif
    }
}

void interrupt_trigger_timer_cb(uc_engine *uc, uint32_t timer_id, void *user_data) {
    InterruptTrigger *trigger = (InterruptTrigger *) user_data;
    interrupt_trigger_tick_block_hook(uc, 0, 0, trigger);
    trigger->skip_next = 0;
}

uc_hook add_interrupt_trigger(uc_engine *uc, uint64_t addr, uint32_t irq, uint32_t num_skips, uint32_t num_pends, uint32_t fuzz_mode, uint32_t trigger_mode, uint64_t every_nth_tick) {
    if(uc->fw->num_triggers_inuse >= MAX_INTERRUPT_TRIGGERS) {
        perror("[INTERRUPT_TRIGGERS ERROR] register_interrupt_trigger: Maxmimum number of interrupt triggers exhausted.\n");
        exit(-1);
    }

    #ifdef DEBUG_INTERRUPT_TRIGGERS
    printf("[add_interrupt_trigger] for addr=0x%lx irq=%d, fuzz_mode=%d\n", addr, irq, fuzz_mode);
    #endif

    InterruptTrigger *trigger = &uc->fw->triggers[uc->fw->num_triggers_inuse++];

    trigger->irq = irq;
    trigger->curr_pends = 0;
    // don't skip for the very first invocation
    trigger->curr_skips = num_skips;
    trigger->times_to_pend = num_pends;
    trigger->times_to_skip = num_skips;
    trigger->fuzz_mode = fuzz_mode;
    trigger->round_robin_index = 0;
    trigger->trigger_mode = trigger_mode;

    if(trigger_mode == IRQ_TRIGGER_MODE_ADDRESS) {
        if (uc->block_hook_add(uc->ctx, &trigger->hook_handle, (void *)interrupt_trigger_tick_block_hook, trigger, addr) != UC_ERR_OK) {
            perror("[INTERRUPT_TRIGGERS ERROR] Failed adding block hook.\n");
            exit(-1);
        }
    } else if (trigger_mode == IRQ_TRIGGER_MODE_TIME || trigger_mode == IRQ_TRIGGER_MODE_TIME_FUZZED) {
        if(every_nth_tick == 0) {
            every_nth_tick = IRQ_DEFAULT_TIMER_INTERVAL;
        }

        trigger->timer_id = add_timer(&uc->fw->timers, get_timer_scale(uc->fw)*every_nth_tick, interrupt_trigger_timer_cb, trigger, TIMER_IRQ_NOT_USED);
        start_timer(uc, trigger->timer_id);
    } else {
        return -1;
    }

    return UC_ERR_OK;
}

void *interrupt_trigger_take_snapshot(uc_engine *uc) {
    size_t size = uc->fw->num_triggers_inuse * sizeof(struct InterruptTrigger);
    InterruptTrigger *result = malloc(size);
    memcpy(result, &uc->fw->triggers[0], size);
    return result;
}

void interrupt_trigger_restore_snapshot(uc_engine *uc, void *snapshot) {
    memcpy(&uc->fw->triggers[0], snapshot, uc->fw->num_triggers_inuse * sizeof(struct InterruptTrigger));
}

void interrupt_trigger_discard_snapshot(uc_engine *uc, void *snapshot) {
    free(snapshot);
}

