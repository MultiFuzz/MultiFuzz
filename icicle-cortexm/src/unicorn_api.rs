use std::os::raw::{c_int, c_void};

use icicle_fuzzing::timer::BlockTimerRef;
use icicle_vm::{
    cpu::{
        mem::{perm, IoHandler},
        Exception, ExceptionCode,
    },
    Vm,
};

use crate::{
    fuzzware::{self, uc_err::*, *},
    FuzzwareEnvironment,
};

#[allow(non_camel_case_types)]
type uc_err = fuzzware::uc_err::Type;

pub struct Context {
    /// Pointer to the VM, can be null.
    pub vm: *mut Vm,

    /// The vtable passed to C code to allow it to call emulator APIs.
    pub vtable: Option<Box<fuzzware::uc_engine>>,

    /// A reference to the block based timer.
    pub timer: Option<BlockTimerRef>,

    /// A handle to the input handler.
    pub io_handle: Option<IoHandler>,

    /// A mapping from Unicorn register indices to VarNodes allocated the associated registers.
    pub uc_vars: Vec<pcode::VarNode>,
}

impl Context {
    pub fn new(vm: &mut Vm) -> anyhow::Result<Self> {
        Ok(Self { vm: vm as *mut Vm, io_handle: None, uc_vars: vec![], vtable: None, timer: None })
    }

    pub(crate) unsafe fn uc_ptr(&mut self) -> *mut fuzzware::uc_engine {
        match self.vtable.as_mut() {
            Some(vtable) => vtable.as_mut(),
            None => {
                self.build_vtable();
                self.vtable.as_mut().unwrap().as_mut()
            }
        }
    }

    fn get_reg_slice(&mut self, regid: i32) -> Option<&mut [u8]> {
        let var = *self.uc_vars.get(regid as usize).unwrap_or(&pcode::VarNode::NONE);
        if var.is_invalid() {
            return None;
        }
        let vm = unsafe { &mut *self.vm };
        vm.cpu.regs.get_mut(var)
    }

    // Super unsafe: creates a self referencing struct.
    unsafe fn build_vtable(&mut self) {
        let vtable = Box::new(fuzzware::uc_engine {
            ctx: (self as *mut Context).cast(),
            // Initialized as part of fuzzware::init
            // @FIXME: currently this gets leaked.
            fw: std::ptr::null_mut(),
            emu_stop: Some(emu_stop),
            reg_read: Some(reg_read),
            reg_read_batch: Some(reg_read_batch),
            reg_write: Some(reg_write),
            reg_write_batch: Some(reg_write_batch),
            reg_ptr: Some(reg_ptr),
            mem_read: Some(mem_read),
            mem_write: Some(mem_write),
            set_timer_countdown: Some(set_timer_countdown),
            get_timer_countdown: Some(get_timer_countdown),
            block_hook_add: Some(block_hook_add),
            backtrace: Some(backtrace),
            push_stack: Some(push_stack),
            pop_stack: Some(pop_stack),
            notify_irq_enable_state: Some(notify_irq_enable_state),
            timer_expired: Some(timer_expired),
            get_next_irq_number: Some(get_next_irq_number),
            get_next_timer_choice: Some(get_next_timer_choice),
        });
        self.vtable = Some(vtable);
    }
}

pub(crate) const DEBUG: bool = false;

macro_rules! debug {
    ($($arg:tt)*) => {{
        if DEBUG {
            eprintln!($($arg)*)
        }
    }}
}

pub fn map_uc_err(err: uc_err) -> anyhow::Result<()> {
    if err == UC_ERR_OK {
        return Ok(());
    }
    Err(anyhow::format_err!("{}", fuzzware::uc_error_str(err)))
}

fn read_err_to_uc_err(err: icicle_vm::cpu::mem::MemError) -> uc_err {
    match err {
        icicle_vm::cpu::mem::MemError::Unmapped => UC_ERR_READ_UNMAPPED,
        icicle_vm::cpu::mem::MemError::ReadViolation => UC_ERR_READ_PROT,
        icicle_vm::cpu::mem::MemError::Unaligned => UC_ERR_READ_UNALIGNED,
        icicle_vm::cpu::mem::MemError::OutOfMemory => UC_ERR_NOMEM,
        _ => UC_ERR_EXCEPTION,
    }
}

fn write_err_to_uc_err(err: icicle_vm::cpu::mem::MemError) -> uc_err {
    match err {
        icicle_vm::cpu::mem::MemError::Unmapped => UC_ERR_WRITE_UNMAPPED,
        icicle_vm::cpu::mem::MemError::WriteViolation => UC_ERR_WRITE_PROT,
        icicle_vm::cpu::mem::MemError::Unaligned => UC_ERR_WRITE_UNALIGNED,
        icicle_vm::cpu::mem::MemError::OutOfMemory => UC_ERR_NOMEM,
        _ => UC_ERR_EXCEPTION,
    }
}

pub unsafe extern "C" fn emu_stop(ctx: *mut c_void, exit: uc_err) -> uc_err {
    tracing::debug!("icicle_unicorn_api::emu_stop");
    let ctx = &mut *ctx.cast::<Context>();
    let vm = unsafe { &mut *ctx.vm };

    // We might end up with an "uninitalized read" if this stop was requested as part of handling a
    // MMIO access, so instead we store the exit code in `fuzzware_exit`.
    vm.cpu.exception.code = ExceptionCode::Environment as u32;
    vm.cpu.exception.value = 1;

    if vm.env_mut::<FuzzwareEnvironment>().unwrap().fuzzware_exit.is_some() {
        // Avoid handling duplicate calls to emu_stop.
        return UC_ERR_OK;
    }
    vm.env_mut::<FuzzwareEnvironment>().unwrap().fuzzware_exit = Some(exit);

    UC_ERR_OK
}

#[cold]
#[inline(never)]
fn invalid_reg(id: c_int) -> ! {
    panic!("Read to invalid register regid={id}");
}

#[inline]
pub unsafe extern "C" fn reg_read(ctx: *mut c_void, regid: c_int, value: *mut c_void) -> uc_err {
    let ctx = &mut *ctx.cast::<Context>();

    match regid as uc_arm_reg::Type {
        uc_arm_reg::UC_ARM_REG_XPSR => {
            let xpsr_reg = *ctx.uc_vars.get(regid as usize).unwrap_or_else(|| invalid_reg(regid));
            let vm = unsafe { &mut *ctx.vm };
            *value.cast::<u32>() = vm.cpu.read_reg(xpsr_reg) as u32;
        }
        uc_arm_reg::UC_ARM_REG_PC => {
            let vm = unsafe { &mut *ctx.vm };
            *value.cast::<u32>() = vm.cpu.read_pc() as u32;
        }
        _ => {
            let data = ctx.get_reg_slice(regid).unwrap_or_else(|| invalid_reg(regid));
            match data.try_into().ok() {
                Some(data) => *value.cast::<u32>() = u32::from_ne_bytes(data),
                None => copy_data_cold(data, value),
            }
        }
    };
    UC_ERR_OK
}

#[cold]
unsafe fn copy_data_cold(data: &[u8], value: *mut std::ffi::c_void) {
    std::ptr::copy_nonoverlapping(data.as_ptr(), value.cast(), data.len());
}

pub unsafe extern "C" fn reg_read_batch(
    ctx: *mut c_void,
    regs: *mut c_int,
    vals: *mut *mut c_void,
    count: c_int,
) -> uc_err {
    let regs = std::slice::from_raw_parts(regs, count as usize);
    let vals = std::slice::from_raw_parts_mut(vals, count as usize);

    for (regid, val) in regs.iter().zip(vals) {
        let result = reg_read(ctx, *regid, *val);
        if result != UC_ERR_OK {
            return result;
        }
    }

    UC_ERR_OK
}

pub unsafe extern "C" fn reg_write(ctx: *mut c_void, regid: c_int, value: *const c_void) -> uc_err {
    debug!("icicle_unicorn_api::reg_write({regid})");
    let ctx = &mut *ctx.cast::<Context>();
    let vm = unsafe { &mut *ctx.vm };

    match regid as uc_arm_reg::Type {
        uc_arm_reg::UC_ARM_REG_PC => {
            let new_pc = (*value.cast::<u32>() & !0b1) as u64;
            vm.cpu.set_isa_mode(1);
            vm.cpu.exception.code = ExceptionCode::ExternalAddr as u32;
            vm.cpu.exception.value = new_pc;

            // @fixme: this is part of the API for interrupt frames, so should be part of the code
            // there instead changing things here.
            vm.lifter.set_context(vm.cpu.arch.isa_mode_context[1]);
            vm.cpu.write_pc(new_pc);
        }
        uc_arm_reg::UC_ARM_REG_XPSR => {
            let xpsr_reg = ctx.uc_vars[regid as usize];
            let vm = unsafe { &mut *ctx.vm };
            vm.cpu.write_reg(xpsr_reg, *value.cast::<u32>() as u64);
        }
        _ => {
            let data = ctx.get_reg_slice(regid).unwrap_or_else(|| invalid_reg(regid));
            if data.len() == 4 {
                *data.as_mut_ptr().cast::<u32>() = *value.cast::<u32>();
            }
            else {
                copy_value_cold(value, data);
            }
        }
    }

    UC_ERR_OK
}

#[cold]
unsafe fn copy_value_cold(value: *const std::ffi::c_void, data: &mut [u8]) {
    std::ptr::copy_nonoverlapping(value.cast(), data.as_mut_ptr(), data.len());
}

pub unsafe extern "C" fn reg_write_batch(
    ctx: *mut c_void,
    regs: *mut c_int,
    vals: *const *mut c_void,
    count: c_int,
) -> uc_err {
    let regs = std::slice::from_raw_parts(regs, count as usize);
    let vals = std::slice::from_raw_parts(vals, count as usize);
    debug!("icicle_unicorn_api::reg_write_batch({regs:?})");

    for (regid, val) in regs.iter().zip(vals) {
        let result = reg_write(ctx, *regid, *val);
        if result != UC_ERR_OK {
            return result;
        }
    }

    UC_ERR_OK
}

pub unsafe extern "C" fn reg_ptr(
    ctx: *mut c_void,
    regid: c_int,
    value: *mut *mut c_void,
) -> uc_err {
    debug!("icicle_unicorn_api::reg_ptr({regid})");
    let ctx = &mut *ctx.cast::<Context>();
    let data = match ctx.get_reg_slice(regid) {
        Some(slice) => slice,
        None => return UC_ERR_ARG,
    };
    *value = data.as_mut_ptr().cast();
    UC_ERR_OK
}

pub unsafe extern "C" fn mem_read(
    ctx: *mut c_void,
    address: u64,
    buf: *mut c_void,
    count: usize,
) -> uc_err {
    debug!("icicle_unicorn_api::mem_read");

    let ctx = &mut *ctx.cast::<Context>();
    let vm = unsafe { &mut *ctx.vm };

    if !vm.cpu.mem.is_regular_region(address, count as u64) {
        return UC_ERR_READ_PROT;
    }

    match count {
        1 => match vm.cpu.mem.read_u8(address, perm::NONE) {
            Ok(x) => *buf.cast() = x,
            Err(e) => return read_err_to_uc_err(e),
        },
        2 => match vm.cpu.mem.read_u16(address, perm::NONE) {
            Ok(x) => *buf.cast() = x,
            Err(e) => return read_err_to_uc_err(e),
        },
        4 => match vm.cpu.mem.read_u32(address, perm::NONE) {
            Ok(x) => *buf.cast() = x,
            Err(e) => return read_err_to_uc_err(e),
        },
        8 => match vm.cpu.mem.read_u64(address, perm::NONE) {
            Ok(x) => *buf.cast() = x,
            Err(e) => return read_err_to_uc_err(e),
        },
        _ => {
            let buf = std::slice::from_raw_parts_mut(buf.cast::<u8>(), count);
            if let Err(e) = vm.cpu.mem.read_bytes(address, buf, perm::NONE) {
                return read_err_to_uc_err(e);
            }
        }
    }
    UC_ERR_OK
}

pub unsafe extern "C" fn mem_write(
    ctx: *mut c_void,
    address: u64,
    buf: *const c_void,
    count: usize,
) -> uc_err {
    let ctx = &mut *ctx.cast::<Context>();
    let vm = unsafe { &mut *ctx.vm };

    let result = match count {
        1 => vm.cpu.mem.write_u8(address, *buf.cast(), perm::NONE),
        2 => vm.cpu.mem.write_u16(address, *buf.cast(), perm::NONE),
        4 => vm.cpu.mem.write_u32(address, *buf.cast(), perm::NONE),
        8 => vm.cpu.mem.write_u64(address, *buf.cast(), perm::NONE),
        _ => {
            let buf = std::slice::from_raw_parts(buf.cast::<u8>(), count);
            vm.cpu.mem.write_bytes(address, buf, perm::NONE)
        }
    };
    match result {
        Ok(_) => UC_ERR_OK,
        Err(err) => write_err_to_uc_err(err),
    }
}

pub unsafe extern "C" fn set_timer_countdown(ctx: *mut c_void, value: u64) -> uc_err {
    let ctx = &mut *ctx.cast::<Context>();
    let timer = ctx.timer.as_ref().unwrap_unchecked();
    timer.set_countdown(&mut (*ctx.vm).cpu, value);
    UC_ERR_OK
}

pub unsafe extern "C" fn get_timer_countdown(ctx: *mut c_void, value: *mut u64) -> uc_err {
    let ctx = &mut *ctx.cast::<Context>();
    let timer = ctx.timer.as_ref().unwrap_unchecked();
    *value = timer.get_countdown(&mut (*ctx.vm).cpu);
    UC_ERR_OK
}

pub unsafe extern "C" fn block_hook_add(
    ctx: *mut c_void,
    hook_handle: *mut uc_hook,
    callback: *mut c_void,
    user_data: *mut c_void,
    address: u64,
) -> uc_err {
    tracing::debug!("icicle_unicorn_api::block_hook_add");
    let ctx = &mut *ctx.cast::<Context>();

    let vm = unsafe { &mut *ctx.vm };
    let vtable = ctx.vtable.as_mut().unwrap().as_mut() as *mut uc_engine;

    vm.hook_address(address, move |_cpu, addr| {
        let func_ptr: fuzzware::uc_cb_hookcode_t = std::mem::transmute(callback);
        func_ptr.unwrap()(vtable, addr, 0, user_data);
    });
    *hook_handle = 0;

    UC_ERR_OK
}

pub unsafe extern "C" fn backtrace(ctx: *mut c_void) {
    let vm = unsafe { &mut *(*ctx.cast::<Context>()).vm };
    let guest_bt = icicle_vm::debug::backtrace(vm);
    let host_bt = std::backtrace::Backtrace::force_capture();
    eprintln!("{host_bt}{guest_bt}");
}

pub unsafe extern "C" fn push_stack(ctx: *mut c_void) {
    let vm = unsafe { &mut *(*ctx.cast::<Context>()).vm };
    vm.env.as_mut_any().downcast_mut::<FuzzwareEnvironment>().unwrap().push_stack(&mut vm.cpu);
}

pub unsafe extern "C" fn pop_stack(ctx: *mut c_void) {
    let vm = unsafe { &mut *(*ctx.cast::<Context>()).vm };
    vm.env.as_mut_any().downcast_mut::<FuzzwareEnvironment>().unwrap().pop_stack(&mut vm.cpu);
}

pub unsafe extern "C" fn notify_irq_enable_state(ctx: *mut c_void, irq: i32, is_enabled: bool) {
    let vm = unsafe { &mut *(*ctx.cast::<Context>()).vm };
    tracing::debug!(
        "[{:#x}:{}] IRQ: {irq} enable state -> {is_enabled}",
        vm.cpu.read_pc(),
        vm.cpu.icount()
    );
}

pub unsafe extern "C" fn timer_expired(ctx: *mut c_void, number: i32, timer: *mut c_void) {
    let vm = unsafe { &mut *(*ctx.cast::<Context>()).vm };
    let timer = timer.cast::<fuzzware::Timer>();
    tracing::debug!(
        "[{:#x}:{}] Timer: {number} expired. Reloading to {}",
        vm.cpu.read_pc(),
        vm.cpu.icount(),
        (*timer).reload_val
    );
}

/// A magic location used for reading other data from the fuzzer (that is not a valid MMIO address).
const IRQ_NUMBER_ADDR: u64 = 0xaaaa_aaa0;

pub unsafe extern "C" fn get_next_irq_number(ctx: *mut c_void, number: *mut u8) -> bool {
    let ctx = &mut *ctx.cast::<Context>();
    let vm = unsafe { &mut *ctx.vm };

    let mut buf = [0];
    if vm.cpu.mem.get_io_memory_mut(ctx.io_handle.unwrap()).read(IRQ_NUMBER_ADDR, &mut buf).is_err()
    {
        vm.cpu.exception = Exception::new(ExceptionCode::ReadWatch, IRQ_NUMBER_ADDR);
        return false;
    }
    *number = buf[0];
    true
}

/// The location to read timer choices from
const TIMER_CHOICE_ADDR: u64 = IRQ_NUMBER_ADDR + 4;

pub unsafe extern "C" fn get_next_timer_choice(ctx: *mut c_void, choice: *mut u8) -> bool {
    let ctx = &mut *ctx.cast::<Context>();
    let vm = unsafe { &mut *ctx.vm };

    let mut buf = [0];
    if vm
        .cpu
        .mem
        .get_io_memory_mut(ctx.io_handle.unwrap())
        .read(TIMER_CHOICE_ADDR, &mut buf)
        .is_err()
    {
        vm.cpu.exception = Exception::new(ExceptionCode::ReadWatch, TIMER_CHOICE_ADDR);
        return false;
    }
    *choice = buf[0];
    true
}
