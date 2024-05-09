#ifndef ICICLE_H
#define ICICLE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "arm.h"

#if (defined(__GNUC__) && !defined(__clang__))
#define ATTRIBUTE_HOT __attribute__((hot))
#else
#define ATTRIBUTE_HOT
#endif

#if defined(_MSC_VER)
#define ATTRIBUTE_NO_INLINE __declspec(noinline)
#else
#define ATTRIBUTE_NO_INLINE __attribute__((noinline))
#endif

#if defined(_MSC_VER)
#define ATTRIBUTE_ALIGN(x) __declspec(align(x))
#else
#define ATTRIBUTE_ALIGN(x) __attribute__((aligned (x)))
#endif

#if defined(__GNUC__) || defined(__clang__)
#define ATTRIBUTE_DEPRECATED __attribute__((deprecated))
#elif defined(_MSC_VER)
#define ATTRIBUTE_DEPRECATED __declspec(deprecated)
#endif

typedef size_t uc_hook;

typedef enum uc_err {
    UC_ERR_OK = 0,   // No error: everything was fine
    UC_ERR_NOMEM,      // Out-Of-Memory error: uc_open(), uc_emulate()
    UC_ERR_ARCH,     // Unsupported architecture: uc_open()
    UC_ERR_HANDLE,   // Invalid handle
    UC_ERR_MODE,     // Invalid/unsupported mode: uc_open()
    UC_ERR_VERSION,  // Unsupported version (bindings)
    UC_ERR_READ_UNMAPPED, // Quit emulation due to READ on unmapped memory: uc_emu_start()
    UC_ERR_WRITE_UNMAPPED, // Quit emulation due to WRITE on unmapped memory: uc_emu_start()
    UC_ERR_FETCH_UNMAPPED, // Quit emulation due to FETCH on unmapped memory: uc_emu_start()
    UC_ERR_HOOK,    // Invalid hook type: uc_hook_add()
    UC_ERR_INSN_INVALID, // Quit emulation due to invalid instruction: uc_emu_start()
    UC_ERR_MAP, // Invalid memory mapping: uc_mem_map()
    UC_ERR_WRITE_PROT, // Quit emulation due to UC_MEM_WRITE_PROT violation: uc_emu_start()
    UC_ERR_READ_PROT, // Quit emulation due to UC_MEM_READ_PROT violation: uc_emu_start()
    UC_ERR_FETCH_PROT, // Quit emulation due to UC_MEM_FETCH_PROT violation: uc_emu_start()
    UC_ERR_ARG,     // Inavalid argument provided to uc_xxx function (See specific function API)
    UC_ERR_READ_UNALIGNED,  // Unaligned read
    UC_ERR_WRITE_UNALIGNED,  // Unaligned write
    UC_ERR_FETCH_UNALIGNED,  // Unaligned fetch
    UC_ERR_HOOK_EXIST,  // hook for this event already existed
    UC_ERR_RESOURCE,    // Insufficient resource: uc_emu_start()
    UC_ERR_EXCEPTION, // Unhandled CPU exception

    // Custom errors
    UC_ERR_BLOCK_LIMIT, // Hit block count limit
    UC_ERR_NO_FUZZ_CONSUMPTION, // Exceeded limit for the number of blocks without consuming fuzzer input
    UC_ERR_INTERRUPT_LIMIT, // Exceeded maximum number of interrupts triggered
    UC_ERR_NVIC_ASSERTION, // Hit an NVIC assertion
} uc_err;

extern const char *uc_strerror(uc_err code);

// All type of memory accesses for UC_HOOK_MEM_*
typedef enum uc_mem_type {
    UC_MEM_READ = 16,   // Memory is read from
    UC_MEM_WRITE,       // Memory is written to
    UC_MEM_FETCH,       // Memory is fetched
    UC_MEM_READ_UNMAPPED,    // Unmapped memory is read from
    UC_MEM_WRITE_UNMAPPED,   // Unmapped memory is written to
    UC_MEM_FETCH_UNMAPPED,   // Unmapped memory is fetched
    UC_MEM_WRITE_PROT,  // Write to write protected, but mapped, memory
    UC_MEM_READ_PROT,   // Read from read protected, but mapped, memory
    UC_MEM_FETCH_PROT,  // Fetch from non-executable, but mapped, memory
    UC_MEM_READ_AFTER,   // Memory is read from (successful access)
} uc_mem_type;

typedef enum uc_prot {
   UC_PROT_NONE = 0,
   UC_PROT_READ = 1,
   UC_PROT_WRITE = 2,
   UC_PROT_EXEC = 4,
   UC_PROT_ALL = 7,
} uc_prot;

// All type of hooks for uc_hook_add() API.
typedef enum uc_hook_type {
    // Hook all interrupt/syscall events
    UC_HOOK_INTR = 1 << 0,
    // Hook a particular instruction - only a very small subset of instructions supported here
    UC_HOOK_INSN = 1 << 1,
    // Hook a range of code
    UC_HOOK_CODE = 1 << 2,
    // Hook basic blocks
    UC_HOOK_BLOCK = 1 << 3,
    // Hook for memory read on unmapped memory
    UC_HOOK_MEM_READ_UNMAPPED = 1 << 4,
    // Hook for invalid memory write events
    UC_HOOK_MEM_WRITE_UNMAPPED = 1 << 5,
    // Hook for invalid memory fetch for execution events
    UC_HOOK_MEM_FETCH_UNMAPPED = 1 << 6,
    // Hook for memory read on read-protected memory
    UC_HOOK_MEM_READ_PROT = 1 << 7,
    // Hook for memory write on write-protected memory
    UC_HOOK_MEM_WRITE_PROT = 1 << 8,
    // Hook for memory fetch on non-executable memory
    UC_HOOK_MEM_FETCH_PROT = 1 << 9,
    // Hook memory read events.
    UC_HOOK_MEM_READ = 1 << 10,
    // Hook memory write events.
    UC_HOOK_MEM_WRITE = 1 << 11,
    // Hook memory fetch for execution events
    UC_HOOK_MEM_FETCH = 1 << 12,
    // Hook memory read events, but only successful access.
    // The callback will be triggered after successful read.
    UC_HOOK_MEM_READ_AFTER = 1 << 13,
    // Hook invalid instructions exceptions.
    UC_HOOK_INSN_INVALID = 1 << 14,
    // Hook blocks unconditionally, ignoring the range modifier. Used to optimize hook invocation
    UC_HOOK_BLOCK_UNCONDITIONAL = 1 << 15,
} uc_hook_type;

// Hook type for all events of unmapped memory access
#define UC_HOOK_MEM_UNMAPPED (UC_HOOK_MEM_READ_UNMAPPED + UC_HOOK_MEM_WRITE_UNMAPPED + UC_HOOK_MEM_FETCH_UNMAPPED)
// Hook type for all events of illegal protected memory access
#define UC_HOOK_MEM_PROT (UC_HOOK_MEM_READ_PROT + UC_HOOK_MEM_WRITE_PROT + UC_HOOK_MEM_FETCH_PROT)
// Hook type for all events of illegal read memory access
#define UC_HOOK_MEM_READ_INVALID (UC_HOOK_MEM_READ_PROT + UC_HOOK_MEM_READ_UNMAPPED)
// Hook type for all events of illegal write memory access
#define UC_HOOK_MEM_WRITE_INVALID (UC_HOOK_MEM_WRITE_PROT + UC_HOOK_MEM_WRITE_UNMAPPED)
// Hook type for all events of illegal fetch memory access
#define UC_HOOK_MEM_FETCH_INVALID (UC_HOOK_MEM_FETCH_PROT + UC_HOOK_MEM_FETCH_UNMAPPED)
// Hook type for all events of illegal memory access
#define UC_HOOK_MEM_INVALID (UC_HOOK_MEM_UNMAPPED + UC_HOOK_MEM_PROT)
// Hook type for all events of valid memory access
// NOTE: UC_HOOK_MEM_READ is triggered before UC_HOOK_MEM_READ_PROT and UC_HOOK_MEM_READ_UNMAPPED, so
//       this hook may technically trigger on some invalid reads.
#define UC_HOOK_MEM_VALID (UC_HOOK_MEM_READ + UC_HOOK_MEM_WRITE + UC_HOOK_MEM_FETCH)

typedef struct uc_mem_region {
    uint64_t begin; // begin address of the region (inclusive)
    uint64_t end;   // end address of the region (inclusive)
    uint32_t perms; // memory permissions of the region
} uc_mem_region;


struct uc_context;
typedef struct uc_context uc_context;

typedef struct {
    void* ctx; // Pointer to Rust managed context.
    struct FwContext* fw; // Pointer to context for Fuzzwre.

    uc_err (*emu_stop)(void*, uc_err);
    uc_err (*reg_read)(void*, int, void*);
    uc_err (*reg_read_batch)(void*, int*, void**, int);
    uc_err (*reg_write)(void*, int, const void*);
    uc_err (*reg_write_batch)(void*, int*, void* const*, int);
    uc_err (*reg_ptr)(void*, int, void**);

    uc_err (*mem_read)(void*, uint64_t, void*, size_t);
    uc_err (*mem_write)(void*, uint64_t, const void*, size_t);

    // New Icicle APIs
    uc_err (*set_timer_countdown)(void*, uint64_t);
    uc_err (*get_timer_countdown)(void*, uint64_t*);
    uc_err (*block_hook_add)(void*, uc_hook*, void*, void*, uint64_t);
    void (*push_stack)(void*);
    void (*pop_stack)(void*);
    void (*backtrace)(void*);

    bool (*get_next_irq_number)(void*, uint8_t*);
    bool (*get_next_timer_choice)(void*, uint8_t*);

    // APIs added for debugging
    void (*notify_irq_enable_state)(void*, int, bool);
    void (*timer_expired)(void*, int, void*);
} uc_engine;


typedef void (*uc_cb_hookcode_t)(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
typedef void (*uc_cb_hookintr_t)(uc_engine *uc, uint32_t intno, void *user_data);
typedef bool (*uc_cb_hookinsn_invalid_t)(uc_engine *uc, void *user_data);
typedef uint32_t (*uc_cb_insn_in_t)(uc_engine *uc, uint32_t port, int size, void *user_data);


typedef void (*uc_cb_hookmem_t)(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, int64_t value, void *user_data);


#define DEFAULT_GLOBAL_TIMER_SCALE 1
#define MAX_RELOAD_VAL 0xffffffffffffLL

#endif