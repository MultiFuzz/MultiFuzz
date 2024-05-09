#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case, dead_code, clippy::all)]
include!(concat!(env!("OUT_DIR"), "/fuzzware_bindings.rs"));

pub const ANY_MEM_HOOK: uc_hook_type::Type = uc_hook_type::UC_HOOK_MEM_WRITE
    | uc_hook_type::UC_HOOK_MEM_READ
    | uc_hook_type::UC_HOOK_MEM_READ_AFTER
    | uc_hook_type::UC_HOOK_MEM_WRITE_PROT
    | uc_hook_type::UC_HOOK_MEM_READ_PROT;

pub const ANY_BLOCK_HOOK: uc_hook_type::Type =
    uc_hook_type::UC_HOOK_BLOCK | uc_hook_type::UC_HOOK_BLOCK_UNCONDITIONAL;

pub fn uc_error_str(err: uc_err::Type) -> &'static str {
    use uc_err::*;

    match err {
        UC_ERR_OK => "UC_ERR_OK",
        UC_ERR_ARCH => "UC_ERR_ARCH",
        UC_ERR_ARG => "UC_ERR_ARG",
        UC_ERR_EXCEPTION => "UC_ERR_EXCEPTION",
        UC_ERR_FETCH_PROT => "UC_ERR_FETCH_PROT",
        UC_ERR_FETCH_UNALIGNED => "UC_ERR_FETCH_UNALIGNED",
        UC_ERR_FETCH_UNMAPPED => "UC_ERR_FETCH_UNMAPPED",
        UC_ERR_HANDLE => "UC_ERR_HANDLE",
        UC_ERR_HOOK => "UC_ERR_HOOK",
        UC_ERR_HOOK_EXIST => "UC_ERR_HOOK_EXIST",
        UC_ERR_INSN_INVALID => "UC_ERR_INSN_INVALID",
        UC_ERR_MAP => "UC_ERR_MAP",
        UC_ERR_MODE => "UC_ERR_MODE",
        UC_ERR_NOMEM => "UC_ERR_NOMEM",
        UC_ERR_READ_PROT => "UC_ERR_READ_PROT",
        UC_ERR_READ_UNALIGNED => "UC_ERR_READ_UNALIGNED",
        UC_ERR_READ_UNMAPPED => "UC_ERR_READ_UNMAPPED",
        UC_ERR_RESOURCE => "UC_ERR_RESOURCE",
        UC_ERR_VERSION => "UC_ERR_VERSION",
        UC_ERR_WRITE_PROT => "UC_ERR_WRITE_PROT",
        UC_ERR_WRITE_UNALIGNED => "UC_ERR_WRITE_UNALIGNED",
        UC_ERR_WRITE_UNMAPPED => "UC_ERR_WRITE_UNMAPPED",
        UC_ERR_BLOCK_LIMIT => "UC_ERR_BLOCK_LIMIT",
        UC_ERR_NO_FUZZ_CONSUMPTION => "UC_ERR_NO_FUZZ_CONSUMPTION",
        UC_ERR_INTERRUPT_LIMIT => "UC_ERR_INTERRUPT_LIMIT",
        UC_ERR_NVIC_ASSERTION => "UC_ERR_NVIC_ASSERTION",
        _ => "UNKNOWN_ERROR",
    }
}
