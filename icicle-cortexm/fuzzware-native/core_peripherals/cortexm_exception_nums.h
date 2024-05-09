#ifndef CORTEXM_EXCEPTION_NUMS
#define CORTEXM_EXCEPTION_NUMS

#define EXCEPTION_NONE_ACTIVE 0
#define EXCEPTION_NO_NMI     0x2
#define EXCEPTION_NO_SVC     0xb
#define EXCEPTION_NO_PENDSV  0xe
#define EXCEPTION_NO_SYSTICK 0xf

#define EXCEPTION_NO_EXTERNAL_START 0x10

// We support 256 interrupts
#define NVIC_NUM_SUPPORTED_INTERRUPTS 256
#define INTLINESNUM ((NVIC_NUM_SUPPORTED_INTERRUPTS / 32) - 1)

#define EXCEPTION_NO_MAX (NVIC_NUM_SUPPORTED_INTERRUPTS-1)
// NVIC registers are queried by dwords, so 32 interrupt status in one access
// The following computation is commented out as it relies on all 1-bits to be set in the result
// This works out for 256 -> 0x7 mask like here, bit is not guaranteed to work for all numbers
// of total supported interrupts
// #define NVIC_REGISTER_OFFSET_MASK ((EXCEPTION_NO_MAX / 32)-1)
#define NVIC_REGISTER_OFFSET_MASK 0x3f

// 0xff

#endif