#ifndef NATIVE_TIMER_H
#define NATIVE_TIMER_H

#include "unicorn.h"
typedef void (*timer_cb)(uc_engine *uc, uint32_t id, void *user_data);

#define MAX_TIMERS 32
#define TIMER_IRQ_NOT_USED 0

struct Timer {
    struct Timer *next;
    uint64_t ticker_val;
    uint64_t reload_val;
    timer_cb trigger_callback;
    void *trigger_cb_user_data;
    uint32_t irq_num;
    uint8_t in_use;
    uint8_t is_active;
};

struct TimerState {
    struct Timer *active_head;
    uint64_t cur_interval;
    uint64_t cur_countdown;
    uint64_t global_ticker;
    struct Timer timers[MAX_TIMERS];
    uint32_t end_ind;
    uint32_t num_inuse;
};

uc_err init_timer_hook(uc_engine *uc, uint32_t global_timer_scale);
uint32_t add_timer(struct TimerState* timers, int64_t reload_val, timer_cb trigger_callback, void *user_data, uint32_t isr_num);

uc_err reload_timer(uc_engine *uc, uint32_t id);
void adjust_timers_for_unicorn_exit();
uc_err set_timer_reload_val(uc_engine *uc, uint32_t id, uint64_t reload_val);
uint32_t get_timer_scale(struct FwContext* fw);
uint64_t get_global_ticker();

uc_err rem_timer(uc_engine *uc, uint32_t id);
uc_err start_timer(uc_engine *uc, uint32_t id);
uc_err stop_timer(uc_engine *uc, uint32_t id);
uint32_t is_running(struct TimerState* timers, uint32_t id);

void *timers_take_snapshot(uc_engine *uc);
void timers_restore_snapshot(uc_engine *uc, void *snapshot);
void timers_discard_snapshot(uc_engine *uc, void *snapshot);

void timer_countdown_expired(uc_engine *uc);

void print_timer(struct TimerState* timers, uint32_t id);
void print_timer_state(struct TimerState* timers);

#endif