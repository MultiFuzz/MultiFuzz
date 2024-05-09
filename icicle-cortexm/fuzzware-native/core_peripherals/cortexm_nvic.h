#ifndef CORTEXM_NVIC_H
#define CORTEXM_NVIC_H

#include <string.h>
#include <assert.h>

#include "../unicorn.h"
#include "cortexm_exception_nums.h"
#include "cortexm_systick.h"

#include "../util.h"
#include "../timer.h"
#include "../native_hooks.h"
#include "../interrupt_triggers.h"

#define NVIC_ASSERTIONS

#ifdef NVIC_ASSERTIONS
#define nvic_assert(cond, msg)                  \
    if(!(cond)) {                               \
        fprintf(stderr, "ASSERTION ERROR: '%s'\n", msg); \
        fflush(stderr);                         \
        print_state(uc);                        \
        force_crash(uc, UC_ERR_NVIC_ASSERTION); \
    }
#else
#define nvic_assert(condition, msg) ((void)0)
#endif



#define CPSR_FAULT_MASK_BIT (1 << 6)
#define CPSR_IRQ_MASK_BIT (1 << 7)

#define NVIC_ISER 0x00
#define NVIC_ICER 0x80
#define NVIC_ISPR 0x100
#define NVIC_ICPR 0x180
#define NVIC_IABR 0x200
#define NVIC_IPR  0x300

// Register offset range for MMIO access (this is based on the number of supported interrupts)
// We need 1 bit per interrupt, and pack 8 bits per address -> 1:8
#define NVIC_IREG_RANGE(reg_base) \
    (reg_base) ... (((reg_base) + ((NVIC_NUM_SUPPORTED_INTERRUPTS-EXCEPTION_NO_EXTERNAL_START) / 8)) & (~3))

#define NVIC_IREG_START(reg_base) (reg_base)
#define NVIC_IREG_END(reg_base) (((reg_base) + ((NVIC_NUM_SUPPORTED_INTERRUPTS-EXCEPTION_NO_EXTERNAL_START) / 8)) & (~3))

// We need 8 bits per interrupt to express the priority -> 1:1
#define NVIC_IPR_RANGE(reg_base) \
    (reg_base) ... ((reg_base) + (NVIC_NUM_SUPPORTED_INTERRUPTS-EXCEPTION_NO_EXTERNAL_START))

#define NVIC_IPR_START(reg_base) (reg_base)
#define NVIC_IPR_END(reg_base) ((reg_base) + (NVIC_NUM_SUPPORTED_INTERRUPTS-EXCEPTION_NO_EXTERNAL_START))


#define SYSCTL_START 0xE000E000
#define SYSCTL_CPUID 0xE000ED00
#define SYSCTL_ICSR  0xE000ED04
#define SYSCTL_VTOR  0xE000ED08
#define SYSCTL_AIRCR 0xE000ED0C
#define SYSCTL_ICTR  0xE000E004
#define SYSCTL_CCR   0xE000ED14
#define SYSCTL_SHPR1 0xE000ED18
#define SYSCTL_SHPR2 0xE000ED1C
#define SYSCTL_SHPR3 0xE000ED20
#define SYSCTL_SHCSR 0xE000ED24
#define SYSCTL_STIR  0xE000EF00

#define SYSCTL_MMIO_BASE SCS_BASE
#define SYSCTL_MMIO_END (SYSCTL_MMIO_BASE + 0xf04)
#define NVIC_MMIO_BASE NVIC_BASE
#define NVIC_MMIO_END (NVIC_MMIO_BASE + 0x600)

#define VECTKEY_HIWORD_MAGIC_READ 0xFA050000u
#define VECTKEY_HIWORD_MAGIC_WRITE 0x05FA0000u
#define NVIC_RESET_VAL_PRIGROUP 0
#define NVIC_INTERRUPT_ENTRY_LR_BASE 0xfffffff1u
#define NVIC_INTERRUPT_ENTRY_LR_PSPSWITCH_FLAG 4
#define NVIC_INTERRUPT_ENTRY_LR_THREADMODE_FLAG 8

#define NVIC_LOWEST_PRIO 256

// Technically, only the top two bytes need to be 0xff, but by making the mask larger, it reduces
// the risk that this value
//
// Note: for compatibility with ARMv8m we don't use the original mask used by fuzzware (0xfffffff0).
#define EXC_RETURN_MASK 0xffffff80

struct CortexmNVIC {
    // State for the basic block hook to detect differences
    uint8_t prev_primask;
    int32_t prev_basepri;
    uint8_t group_prio_mask;
    uint8_t prigroup_shift;
    uint8_t sub_prio_mask;
    uint8_t highest_ever_enabled_exception_no;

    // dynamic state which we re-calculate upon changes
    int active_group_prio;
    int active_irq;
    int pending_prio;
    int pending_irq;
    int num_active;

    // Vector table base address
    uint32_t vtor;

    uint32_t interrupt_count;
    bool force_stack_align;

    uint8_t ExceptionEnabled[NVIC_NUM_SUPPORTED_INTERRUPTS];
    uint8_t ExceptionActive[NVIC_NUM_SUPPORTED_INTERRUPTS];
    uint8_t ExceptionPending[NVIC_NUM_SUPPORTED_INTERRUPTS];
    int ExceptionPriority[NVIC_NUM_SUPPORTED_INTERRUPTS];

    // We keep track of enabled interrupts for fuzzing
    int num_enabled;
    uint8_t enabled_irqs[NVIC_NUM_SUPPORTED_INTERRUPTS];
};

struct CortexmSysTick {
    /*
     * We treat SysTick as a timer. From that abstraction we will also query
     * data such as reload values.
     */
    int timer_ind;
    // We have some extra information that is SysTick specific
    int csr;
};

struct FwConfig {
    uint32_t interrupt_limit;
    uint32_t num_disabled_interrupts;
    uint32_t* disabled_interrupts;
    uint32_t intlinesnum;

    bool do_print_exit_info;

    // Hang heuristics
    uint64_t instr_limit;
    uint64_t fuzz_consumption_timeout;

    // Configures whether we allow nested interrupts to be triggered.
    bool enable_nested_interrupts;
    // Controls whether an interrupt can be set to pending while it is active.
    bool allow_active_interrupt_pending;

    // Systick config
    uint32_t user_configured_reload_val;

    // Timer config
    uint32_t timer_scale;
};

struct saved_regs {
    uint32_t r0, r1, r2, r3, r12, lr, pc_retaddr, xpsr_retspr, sp;
};
#define NUM_SAVED_REGS 9
#define MAX_INTERRUPT_TRIGGERS 256

struct FwContext {
    // We put some members to the front as they are required in the basic block hot path
    // Direct access pointers for interrupt disable / base priority flags
    uint8_t *reg_daif_ptr;
    int32_t *reg_basepri_ptr;

    struct CortexmNVIC nvic;
    struct CortexmSysTick systick;

    // State for interrupt triggers.
    int num_triggers_inuse;
    InterruptTrigger triggers[MAX_INTERRUPT_TRIGGERS];

    // State for native hooks
    uint32_t fuzz_consumption_timer_id;
    uint32_t instr_limit_timer_id;

    // State for timers
    struct TimerState timers;

    // Precomputed storage for reg_read_batch, and reg_write_batch.
    struct saved_regs saved_regs;
    uint32_t *saved_reg_ptrs[NUM_SAVED_REGS];

    // Other configuration.
    uint32_t *reg_curr_sp_mode_is_psp_ptr;
    struct FwConfig config;
};

void pend_interrupt(struct FwContext *ctx, int exception_no);

uc_err init_nvic(
    uc_engine *uc,
    uint32_t vtor,
    uint32_t num_irq,
    uint32_t interrupt_limit,
    uint32_t num_disabled_interrupts,
    uint32_t *disabled_interrupts,
    bool enable_nested_interrupts,
    bool allow_active_interrupt_pending
);

// Added for fuzzing purposes
uint16_t get_num_enabled(struct CortexmNVIC * nvic_ptr);
uint8_t nth_enabled_irq_num(struct CortexmNVIC * nvic_ptr, uint8_t n);

extern struct CortexmNVIC nvic;
void nvic_block_hook(uc_engine *uc, uint64_t address, uint32_t size);
extern void ExceptionReturn(uc_engine *uc, uint32_t ret_pc);
extern void handler_svc(uc_engine *uc, uint32_t intno, void *user_data);

// TODO: remove backward-compatible interface
void nvic_set_pending(uc_engine *uc, uint32_t num, int skip_current_instruction);

void *nvic_take_snapshot(uc_engine *uc);
void nvic_restore_snapshot(uc_engine *uc, void *snapshot);
void nvic_discard_snapshot(uc_engine *uc, void *snapshot);

void handle_sysctl_mmio_write(uc_engine *uc, uint64_t addr, int size, int64_t value);
uint64_t handle_sysctl_mmio_read(uc_engine *uc, uint64_t addr, int size);

uint64_t get_timer_ticker_val(uc_engine *uc, uint32_t id);
uint64_t get_timer_reload_val(struct TimerState* timers, uint32_t id);

#endif