#ifndef INTERRUPT_TRIGGERS_H
#define INTERRUPT_TRIGGERS_H

#include "unicorn.h"

#define IRQ_FUZZ_MODE_FIXED 0
#define IRQ_FUZZ_MODE_FUZZ_ENABLED_IRQ_INDEX 1
#define IRQ_FUZZ_MODE_ROUND_ROBIN 2

#define IRQ_TRIGGER_MODE_ADDRESS 0
#define IRQ_TRIGGER_MODE_TIME 1
#define IRQ_TRIGGER_MODE_TIME_FUZZED 2

#define IRQ_DEFAULT_TIMER_INTERVAL 1000

typedef struct InterruptTrigger {
    uc_hook hook_handle;
    uint32_t irq;
    uint16_t fuzz_mode;
    uint8_t round_robin_index;
    uint16_t skip_next;
    uint32_t times_to_skip; /* Number of times to skip the basic block before triggering? */
    uint32_t times_to_pend; /* Number of times to pend at a time */
    uint32_t curr_skips; /* Currently already skipped */
    uint32_t curr_pends; /* Currently already pended */
    uint32_t trigger_mode; /* Mode of deriving interrupt trigger timings */
    uint32_t timer_id; /* The timer associated with the trigger */
} InterruptTrigger;

uc_hook add_interrupt_trigger(uc_engine *uc, uint64_t addr, uint32_t irq, uint32_t num_skips, uint32_t num_pends, uint32_t fuzz_mode, uint32_t trigger_mode, uint64_t every_nth_tick);
void init_interrupt_triggering(uc_engine *uc);


void *interrupt_trigger_take_snapshot(uc_engine *uc);
void interrupt_trigger_restore_snapshot(uc_engine *uc, void *snapshot);
void interrupt_trigger_discard_snapshot(uc_engine *uc, void *snapshot);

void interrupt_trigger_timer_cb(uc_engine *uc, uint32_t timer_id, void *user_data);

#endif