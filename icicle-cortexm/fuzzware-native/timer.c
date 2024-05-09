#include "unicorn.h"
#include "timer.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "native_hooks.h"
#include "core_peripherals/cortexm_nvic.h"
#include "util.h"

/*
    We use an array of timers with an in_use flag for every timer.
    We keep track of the number of indices touched so far (timers.end_ind)
    as well as the number of currently used timers (in_use).

    When adding a timer, we either use the next unused timer or re-use
    released timer slots.

    To keep track of timer expiries, we use a sorted singly-linked list, updating
    expiries in batches.
*/


static inline int get_timer_id(struct TimerState* timers, struct Timer *tim) {
    return (uint32_t) (tim - &timers->timers[0]);
}

void print_timer(struct TimerState* timers, uint32_t id) {
    struct Timer *t = &timers->timers[id];
    printf("=== TIMER %d ===\nticker_val=%ld\nreload_val=%ld\nin_use=%d\nis_active=%d\n=============\n", id, t->ticker_val, t->reload_val, t->in_use, t->is_active);
}

void print_timer_state(struct TimerState* timers) {
    int i;
    struct Timer *cursor;
    printf("=== Timer State Dump ===\nglobal_ticker: %ld | cur_interval: %ld | cur_countdown: %ld | elapsed: %ld\n", timers->global_ticker, timers->cur_interval, timers->cur_countdown, timers->cur_interval-timers->cur_countdown);
    for(i = 0, cursor=timers->active_head; cursor; ++i, cursor=cursor->next) {
        if(i) {
            printf("-> ");
        }
        printf("timer [%d]. ticker_val: %ld, reload_val: %ld\n", get_timer_id(timers, cursor), cursor->ticker_val, cursor->reload_val);
    }
    puts("========================\n");
    fflush(stdout);
}

uint32_t add_timer(struct TimerState* timers, int64_t reload_val, timer_cb trigger_callback, void *trigger_cb_user_data, uint32_t isr_num) {
    if(timers->num_inuse == MAX_TIMERS) {
        perror("[TIMER ERROR] add_timer: Maximum number of timers is already used\n");
        exit(-1);
    }
    if(trigger_callback == NULL && isr_num == TIMER_IRQ_NOT_USED) {
        perror("[TIMER ERROR] add_timer: No callback or irq passed to newly created timer\n");
        exit(-1);
    }

    uint32_t ind;
    if (timers->num_inuse == timers->end_ind)
    {
        // Insert new at the end
        ind = timers->end_ind++;
    }
    else
    {
        // Find a gap
        for (ind = 0; ind < timers->end_ind; ++ind) {
            if(timers->timers[ind].in_use) {
                break;
            }
        }
    }
    ++timers->num_inuse;

    if(reload_val == 0) {
        reload_val = MAX_RELOAD_VAL;
    }

    timers->timers[ind].in_use = 1;
    timers->timers[ind].irq_num = isr_num;
    timers->timers[ind].ticker_val = reload_val;
    timers->timers[ind].reload_val = reload_val;
    timers->timers[ind].trigger_callback = trigger_callback;
    timers->timers[ind].trigger_cb_user_data = trigger_cb_user_data;
    timers->timers[ind].is_active = 0;

    #ifdef DEBUG_TIMER
    printf("[TIMER] Added timer with id %d, Now: num_inuse=%u\n", ind, (int) timers->num_inuse);
    print_timer(ind);
    #endif

    return ind;
}

static inline void sync_timers(uc_engine *uc) {
    uc->get_timer_countdown(uc->ctx, &uc->fw->timers.cur_countdown);

    // This does not perform reloading as syncing is assumed to only occur and to be handled
    // within the timer callback. All manual timer syncs are on a non-elapsed state

    // In case the countdown is 0, we are currently handling timer timer callbacks
    struct TimerState* timers = &uc->fw->timers;
    if(timers->cur_countdown != 0) {
        int64_t elapsed = timers->cur_interval - timers->cur_countdown;

        #ifdef DEBUG_TIMER
        printf("[sync_timers] timers.cur_interval: %lu, timers.cur_countdown: %lu -> elapsed: %ld\n", timers->cur_interval, timers->cur_countdown, elapsed); fflush(NULL);
        #endif

        timers->global_ticker += elapsed;
        timers->cur_interval = timers->cur_countdown;

        for(struct Timer *cursor=timers->active_head; cursor; cursor = cursor->next) {
            cursor->ticker_val -= elapsed;
        }
    }
}

uc_err rem_timer(uc_engine *uc, uint32_t id) {
    struct TimerState* timers = &uc->fw->timers;

    // Catch bugs from the other side
    if(id >= MAX_TIMERS) {
        perror("[TIMER ERROR] rem_timer: Too high id passed\n");
        exit(-1);
    } else if(!timers->timers[id].in_use) {
        perror("[TIMER ERROR] rem_timer: Unused timer to be removed\n");
        exit(-1);
    }

    #ifdef DEBUG_TIMER
    printf("[TIMER] rem_timer(%d)\n", id); fflush(stdout);
    #endif

    if(timers->timers[id].is_active) {
        stop_timer(uc, id);
    }

    memset(&timers->timers[id], 0, sizeof(timers->timers[id]));

    // Delete tail entries if we can
    while(id != -1 && id == timers->end_ind-1) {
        if(timers->timers[id].in_use) {
            break;
        } else {
            --id;
            --timers->end_ind;
        }
    }

    --timers->num_inuse;

    return UC_ERR_OK;
}

static void insert_active_timer(uc_engine *uc, struct Timer *tim) {
    struct TimerState* timers = &uc->fw->timers;
    struct Timer *cursor = timers->active_head;
    int64_t ticker_val;

    // Reset intermediate elapsed time
    sync_timers(uc);

    if(!cursor) {
        // First entry
        timers->active_head = tim;
        timers->cur_countdown = tim->ticker_val;
        uc->set_timer_countdown(uc->ctx, uc->fw->timers.cur_countdown);
        timers->cur_interval = tim->ticker_val;
    } else if ((ticker_val = tim->ticker_val) <= cursor->ticker_val) {
        // New first entry
        tim->next = cursor;
        timers->active_head = tim;
        timers->cur_countdown = tim->ticker_val;
        uc->set_timer_countdown(uc->ctx, uc->fw->timers.cur_countdown);
        timers->cur_interval = tim->ticker_val;
    } else {
        // Find the entry after which to insert the timer
        for(;cursor->next && (ticker_val > cursor->next->ticker_val); cursor = cursor->next);
        tim->next = cursor->next;
        cursor->next = tim;
    }
}

static inline void remove_active_timer(uc_engine *uc, struct Timer *tim) {
    struct TimerState* timers = &uc->fw->timers;
    struct Timer *cursor = timers->active_head;

    sync_timers(uc);

    if(cursor == tim ) {
        // We are changing the front, so also the intermediate ticks
        timers->active_head = tim->next;
        timers->cur_countdown = timers->cur_interval = timers->active_head->ticker_val;
        uc->set_timer_countdown(uc->ctx, uc->fw->timers.cur_countdown);
    } else {
        // We are changing something in the middle, we can just unlink it
        for(; cursor->next != tim; cursor = cursor->next);
        cursor->next = tim->next;
    }
}

static inline void sort_timer_back(struct TimerState* timers, struct Timer *tim) {
    struct Timer *cursor;
    int64_t ticker_val;
    struct Timer *pred;

    if(!tim->next || ((ticker_val = tim->ticker_val) <= tim->next->ticker_val)) {
        // Already last entry or already correctly sorted
    } else {
        // Sorting changed
        cursor = tim->next;

        // Find the entry after which to insert the timer
        for(;cursor->next && ticker_val > cursor->next->ticker_val; cursor = cursor->next);

        // Update reference to tim
        if(likely(tim == timers->active_head)) {
            // Timer was at the front
            timers->active_head = tim->next;
        } else {
            // Timer in the middle, find it's predecessor
            for(pred = timers->active_head; pred->next != tim; pred = pred->next);
            pred->next = tim->next;
        }

        // Move timer to right place
        tim->next = cursor->next;
        cursor->next = tim;
    }
}

uc_err reload_timer(uc_engine *uc, uint32_t id) {
    struct TimerState* timers = &uc->fw->timers;
    #ifdef DEBUG_TIMER
    // This is a rather hot path due to input consumption timeouts, so skip checks outside debugging
    if(id >= MAX_TIMERS) {
        perror("[TIMER ERROR] reload_timer: Too high id passed\n");
        exit(-1);
    } else if(!timers->timers[id].in_use) {
        printf("[TIMER ERROR] reload_timer: Unused timer to be reset (id=%u)\n", id);
        print_timer(id);
        exit(-1);
    }

    printf("[TIMER] reload_timer(%d)\n", id); fflush(stdout);
    #endif

    struct Timer *tim = &timers->timers[id];

    if(tim->is_active) {
        uc->get_timer_countdown(uc->ctx, &uc->fw->timers.cur_countdown);
        tim->ticker_val = tim->reload_val + (timers->cur_interval-timers->cur_countdown);
        sort_timer_back(timers, tim);
    } else {
        tim->ticker_val = tim->reload_val;
    }

    return UC_ERR_OK;
}

uc_err set_timer_reload_val(uc_engine *uc, uint32_t id, uint64_t reload_val) {
    struct TimerState* timers = &uc->fw->timers;
    #ifdef DEBUG_TIMER
    printf("[TIMER] set_timer_reload_val(id = %d, reload_val=%ld)\n", id, reload_val); fflush(stdout);
    #endif

    if(id >= MAX_TIMERS) {
        perror("[TIMER ERROR] set_timer_reload_val: Too high id passed\n");
        exit(-1);
    }

    if(reload_val == 0) {
        reload_val = MAX_RELOAD_VAL;
    }

    struct Timer *tim = &timers->timers[id];
    if(tim->reload_val == reload_val) {
        return UC_ERR_OK;
    }

    if (tim->is_active) {
        // For active timers, we remove and re-insert to maintain fast-path sorting logic
        remove_active_timer(uc, tim);
        tim->reload_val = reload_val;
        tim->ticker_val = reload_val;
        insert_active_timer(uc, tim);
    } else {
        tim->reload_val = reload_val;
        tim->ticker_val = reload_val;
    }

    return UC_ERR_OK;
}

uint32_t get_timer_scale(struct FwContext* fw) {
    return fw->config.timer_scale;
}

uint32_t is_running(struct TimerState* timers, uint32_t id) {
    if(id >= MAX_TIMERS) {
        perror("[TIMER ERROR] is_running: Too high id passed\n");
        exit(-1);
    }
    return timers->timers[id].is_active;
}

uint64_t curr_val(struct TimerState* timers, uint32_t id) {
    if(id >= MAX_TIMERS) {
        perror("[TIMER ERROR] curr_val: Too high id passed\n");
        exit(-1);
    }
    return timers->timers[id].ticker_val;
}

uint64_t get_global_ticker(uc_engine *uc) {
    sync_timers(uc);
    return uc->fw->timers.global_ticker;
}

ATTRIBUTE_NO_INLINE
void timer_countdown_expired(uc_engine *uc) {
    #ifdef DEBUG_TIMER
    puts("======= Timer state PRE ======= ");
    print_timer_state();
    fflush(stdout);
    #endif
    struct TimerState* timers = &uc->fw->timers;
    struct Timer *initial_head = timers->active_head;
    struct Timer *cursor;
    if(initial_head) {
        // Sync timers
        uint64_t elapsed = timers->cur_interval;
        timers->global_ticker += elapsed;
        for(cursor = initial_head; cursor; cursor = cursor->next) {
            cursor->ticker_val -= elapsed;
        }

        // Trigger and reload the timers which timeouted
        for (cursor = initial_head; cursor->ticker_val == 0; cursor = timers->active_head) {
            cursor->ticker_val = cursor->reload_val;
            sort_timer_back(timers, cursor);

            // Ding!
            #ifdef DEBUG_TIMER
            uc->timer_expired(uc->ctx, get_timer_id(timers, cursor), cursor);
            printf("[TIMER] Ding! Timer %d is going off. Reloading to %ld\n", get_timer_id(timers, cursor), cursor->reload_val);
            #endif
            if(cursor->irq_num != TIMER_IRQ_NOT_USED) {
                // pend interrupt
                #ifdef DEBUG_TIMER
                printf("[TIMER] Pending irq %d\n", cursor->irq_num);
                #endif
                nvic_set_pending(uc, cursor->irq_num, false);
            }
            if(cursor->trigger_callback != NULL) {
                // call timer callback
                #ifdef DEBUG_TIMER
                puts("[TIMER] Calling timer callback");
                #endif
                cursor->trigger_callback(uc, get_timer_id(timers, cursor), cursor->trigger_cb_user_data);
            }
        }

        // Set interval to the front's ticker
        timers->cur_interval = cursor->ticker_val;
    }

    timers->cur_countdown = timers->cur_interval;
    uc->set_timer_countdown(uc->ctx, uc->fw->timers.cur_countdown);

    #ifdef DEBUG_TIMER
    puts("======= Timer state POST ======= ");
    print_timer_state();
    fflush(stdout);
    #endif
}

uc_err start_timer(uc_engine *uc, uint32_t id) {
    struct TimerState* timers = &uc->fw->timers;
    if(id >= MAX_TIMERS) {
        perror("[TIMER ERROR] start_timer: Too high id passed\n");
        exit(-1);
    } else if(!timers->timers[id].in_use) {
        perror("[TIMER ERROR] start_timer: Unused timer to be started\n");
        exit(-1);
    } else if(timers->timers[id].reload_val == 0) {
        perror("[TIMER ERROR] start_timer: Invalid reload value 0\n");
        exit(-1);
    } else if(timers->timers[id].reload_val > MAX_RELOAD_VAL) {
        perror("[TIMER ERROR] start_timer: Invalid, too large reload value\n");
        exit(-1);
    }

    #ifdef DEBUG_TIMER
    printf("[TIMER] start_timer(%d)\n", id);
    puts("======= Timer state PRE ======= ");
    print_timer_state();
    fflush(stdout);
    #endif

    struct Timer *tim = &timers->timers[id];
    if (!tim->is_active) {
        tim->is_active = 1;

        insert_active_timer(uc, tim);
    }

    #ifdef DEBUG_TIMER
    puts("======= Timer state POST ======= ");
    print_timer_state();
    fflush(stdout);
    #endif

    return UC_ERR_OK;
}

uc_err stop_timer(uc_engine *uc, uint32_t id) {
    struct TimerState* timers = &uc->fw->timers;

    if(id >= MAX_TIMERS) {
        perror("[TIMER ERROR] stop_timer: Too high id passed\n");
        exit(-1);
    } else if(!timers->timers[id].in_use) {
        perror("[TIMER ERROR] stop_timer: Unused timer to be started\n");
        exit(-1);
    }

    struct Timer *tim = &timers->timers[id];
    if(tim->is_active) {
        tim->is_active = 0;

        remove_active_timer(uc, tim);
    }

    return UC_ERR_OK;
}

void *timers_take_snapshot(uc_engine *uc) {
    size_t size = sizeof(struct TimerState);
    void *result = malloc(size);
    memcpy(result, &uc->fw->timers, size);
    return result;
}

void timers_restore_snapshot(uc_engine *uc, void *snapshot) {
    memcpy(&uc->fw->timers, snapshot, sizeof(struct TimerState));
}

void timers_discard_snapshot(uc_engine *uc, void *snapshot) {
    free(snapshot);
}
