pub mod config;
pub mod fuzzware;
pub mod genconfig;
pub mod mmio;

mod arm;
mod unicorn_api;

use std::{cell::UnsafeCell, os::raw::c_void, path::PathBuf};

use anyhow::Context as _;
use icicle_fuzzing::parse_addr_or_symbol;
use icicle_vm::{
    cpu::{
        debug_info::{DebugInfo, SourceLocation, SymbolKind},
        mem::{perm, IoHandler, IoMemory, Mapping},
        utils::get_u64,
        Cpu, Exception, ExceptionCode, ValueSource,
    },
    VmExit,
};

use crate::{
    fuzzware::uc_engine,
    mmio::FuzzwareMmioHandler,
    unicorn_api::{map_uc_err, Context},
};
pub use unicorn_api::{IRQ_NUMBER_ADDR, TIMER_CHOICE_ADDR};

pub struct CortexmTarget<T> {
    pub mmio_handler: Option<IoHandler>,
    pub ctx: Option<UnsafeCell<Box<Context>>>,
    fuzzware_exit: fuzzware::uc_err::Type,
    mmio_type: std::marker::PhantomData<T>,
}

impl<T> CortexmTarget<T> {
    pub fn new() -> Self {
        Self {
            ctx: None,
            mmio_handler: None,
            fuzzware_exit: fuzzware::uc_err::UC_ERR_OK,
            mmio_type: std::marker::PhantomData::default(),
        }
    }

    fn with_uc_ptr<R>(
        &mut self,
        vm: &mut icicle_vm::Vm,
        handler: impl FnOnce(*mut uc_engine) -> R,
    ) -> R {
        self.ctx.as_mut().unwrap().get_mut().vm = vm;

        let result = unsafe {
            let uc_ptr = self.ctx.as_mut().unwrap().get_mut().uc_ptr();
            handler(uc_ptr)
        };

        result
    }

    pub fn get_mmio_handler<'a>(&self, vm: &'a mut icicle_vm::Vm) -> Option<&'a mut T>
    where
        T: 'static,
    {
        vm.cpu.mem.get_io_memory_mut(self.mmio_handler?).as_mut_any().downcast_mut::<T>()
    }
}

impl<I: IoMemory + 'static> CortexmTarget<FuzzwareMmioHandler<I>> {
    pub fn fuzzware_init(
        &mut self,
        config: &config::FirmwareConfig,
        vm: &mut icicle_vm::Vm,
        mmio_handler: I,
    ) -> anyhow::Result<()> {
        self.ctx = Some(UnsafeCell::new(Box::new(Context::new(vm)?)));
        let uc_ptr = unsafe { self.ctx.as_mut().unwrap().get_mut().uc_ptr() };

        let mut vtor = None;
        let mut entry_image_base = None;

        let mmio_handler = vm.cpu.mem.register_io_handler(FuzzwareMmioHandler::new(
            &config.mmio_models,
            uc_ptr,
            config.use_access_contexts,
            mmio_handler,
        ));

        self.mmio_handler = Some(mmio_handler);

        let nvic_enabled = config.use_systick || config.use_nvic;
        let nvic_handler = vm.cpu.mem.register_io_handler(FuzzwareNvicHandler { uc: uc_ptr });

        // Keeps track of best file to use for loading debug info from. Note: currently we only
        // support loading debug info from a single ELF file.
        let mut debug_info_path = None;

        for (name, region) in &config.memory_map {
            tracing::info!(
                "mapping {name} at {:#x} (size: {:#x}) perms: {:?}",
                region.base_addr,
                region.size,
                region.permissions
            );

            if name == "nvic" && nvic_enabled {
                // Handle special case for NVIC region (note: if NVIC emulation is disabled then it
                // will be treated as a regular region).
                anyhow::ensure!(
                    vm.cpu.mem.map_memory_len(region.base_addr, region.size, nvic_handler),
                    "failed to map NVIC memory"
                );
                continue;
            }
            else if name.starts_with("mmio") {
                // Handle special case for MMIO regions.
                anyhow::ensure!(
                    vm.cpu.mem.map_memory_len(region.base_addr, region.size, mmio_handler),
                    "failed to map MMIO memory"
                );
                continue;
            }

            let mut size = region.size;

            // Make memory allocations aligned to 4KB, if they don't overlap with any other region.
            // This is required for compatibility with some config files from Fuzzware.
            //
            // For example, in the `p2im_unittests/K64F-RIOT-PWM` binary, `heap_top` points to
            // 0x1fff0a74 which is outside of any of the declared memory regions. However, since the
            // size of the memory region assigned for `.stack` is adjusted upwards to 0x1000,
            // accesses to this region still succeed.
            let aligned_size = pcode::align_up(size, 0x1000);
            let padding_start = region.base_addr + size;
            let padding_end = region.base_addr + aligned_size;
            if size != aligned_size && !config.is_mapped(padding_start, padding_end) {
                size = aligned_size;
            }

            if !(vm.cpu.mem.map_memory_len(region.base_addr, size, Mapping {
                perm: region.permissions.0 | perm::INIT,
                value: region.fill.unwrap_or(0x0),
            })) {
                anyhow::bail!("failed to map: {name} at {:#x}", region.base_addr);
            }

            if let Some(file) = region.file.as_ref() {
                let mut path = std::path::PathBuf::from(file);
                if !path.exists() {
                    path = config.relative_path(&path);
                }

                let data = std::fs::read(&path)
                    .with_context(|| format!("failed to read {file} ({})", path.display()))?;
                match path.extension().map_or(false, |x| x == "hex") {
                    true => write_ihex_bytes(vm, region, &data),
                    false => write_raw_bytes(vm, region, &data),
                }
                .with_context(|| format!("error writing {file}"))?;

                if debug_info_path.is_none() || region.is_entry {
                    debug_info_path = find_elf_for_path(path);
                }
            }

            if region.is_entry {
                vtor = Some(region.base_addr);
                entry_image_base = Some(region.base_addr + region.ivt_offset.unwrap_or(0));
            }
        }

        if let Some(path) = debug_info_path {
            vm.env_mut::<FuzzwareEnvironment>().unwrap().set_debug_info(path)?;
        }
        else {
            // If there was no ELF file to use for debug info, then use any symbols provided
            // directly in the config file.
            let debug_info = &mut vm.env_mut::<FuzzwareEnvironment>().unwrap().debug_info;
            let symbols = std::rc::Rc::make_mut(&mut debug_info.symbols);
            for (addr, name) in &config.symbols {
                symbols.insert(name.into(), *addr & !1, 1, SymbolKind::Function);
            }
        }

        let (vtor, base_addr) = match (vtor, entry_image_base) {
            (Some(vtor), Some(base_addr)) => (vtor, base_addr),
            _ => anyhow::bail!("Failed to resolve entrypoint"),
        };

        const SP_MASK_ON_RESET: u32 = 0xfffffffc;
        let initial_sp = vm
            .cpu
            .mem
            .read_u32(base_addr, perm::NONE)
            .map_err(|e| anyhow::format_err!("error reading SP from IVT: {e}"))?
            & SP_MASK_ON_RESET;

        let initial_pc = match config.entry_point {
            Some(pc) => pc,
            None => vm
                .cpu
                .mem
                .read_u32(base_addr + 4, perm::NONE)
                .map_err(|e| anyhow::format_err!("error reading PC from IVT: {e}"))?,
        };

        tracing::info!("initial_sp={initial_sp:#x}, initial_pc={initial_pc:#x}");
        vm.cpu.write_reg(vm.cpu.arch.reg_sp, initial_sp as u64);
        vm.cpu.write_pc(initial_pc as u64);

        // Fuzzware integration.
        unsafe {
            let uc_ptr = self.ctx.as_mut().unwrap().get_mut().uc_ptr();
            vm.env_mut::<FuzzwareEnvironment>().unwrap().uc_ptr = uc_ptr;

            let nvic_hook = vm.cpu.add_hook(move |_cpu: &mut Cpu, addr: u64| {
                fuzzware::nvic_block_hook(uc_ptr, addr, 4)
            });
            arm::add_arm_extras(vm, nvic_hook);

            let vars = crate::arm::map_uc_to_varnodes(&vm.cpu);

            // Update context to include references to all of the data needed to handle calls from
            // fuzzware.
            {
                let ctx = (*uc_ptr).ctx.cast::<Context>().as_mut().unwrap();

                ctx.uc_vars = vars;
                ctx.io_handle = Some(mmio_handler);

                ctx.timer =
                    Some(icicle_fuzzing::timer::add_block_timer(&mut *ctx.vm, move |_, _| {
                        fuzzware::timer_countdown_expired(uc_ptr)
                    }));
            };

            // Execute Fuzzware's native hooks initialization.
            let print_exit_info =
                icicle_fuzzing::parse_bool_env("FUZZWARE_PRINT_EXIT_INFO")?.unwrap_or(false);
            map_uc_err(fuzzware::init(
                uc_ptr,
                print_exit_info as i32,
                config.fuzz_consumption_timeout,
                config.instr_limit,
                config.global_timer_scale,
            ))
            .context("error in fuzzware::init")?;

            for (name, trigger) in config.interrupt_triggers.iter() {
                tracing::info!("adding trigger {name}: {trigger:x?}");
                let addr = match trigger.addr() {
                    Some(addr) => get_symbol(vm, addr)?,
                    None => 0,
                };
                let num_skips = 0;
                let num_pends = 1;
                map_uc_err(fuzzware::add_interrupt_trigger(
                    uc_ptr,
                    addr,
                    trigger.irq(),
                    num_skips,
                    num_pends,
                    trigger.fuzz_mode(),
                    trigger.trigger_mode(),
                    trigger.every_nth_tick(),
                ) as fuzzware::uc_err::Type)
                .with_context(|| format!("error adding trigger: {name}"))?;
            }

            let reload_val = 0;
            if config.use_systick {
                map_uc_err(fuzzware::init_systick(uc_ptr, reload_val))
                    .context("error in fuzzware::init_systick")?;
            }

            if nvic_enabled {
                let mut disabled_interrupts = match config.nvic.enabled_irqs.as_ref() {
                    Some(enabled) => (0..crate::fuzzware::NVIC_NUM_SUPPORTED_INTERRUPTS)
                        .filter(|i| !enabled.contains(i))
                        .collect(),
                    None => config.nvic.disabled_irqs.clone(),
                };
                tracing::info!("Disabled interrupts = {disabled_interrupts:?}");
                tracing::info!(
                    "Nested interrupts = {}, Pend interrupts while in IRQ = {}",
                    config.nvic.enable_nested_interrupts,
                    config.nvic.allow_active_interrupt_pending
                );
                map_uc_err(fuzzware::init_nvic(
                    uc_ptr,
                    vtor as u32,
                    config.nvic.num_vecs,
                    config.nvic.interrupt_limit,
                    disabled_interrupts.len() as u32,
                    disabled_interrupts.as_mut_ptr(),
                    config.nvic.enable_nested_interrupts,
                    config.nvic.allow_active_interrupt_pending,
                ))
                .context("error in fuzzware::init_nvic")?;
            }
        }

        // Register handlers for functions if enabled.
        let mut ignore: Vec<u64> = vec![];
        let mut crash_at: Vec<u64> = vec![];
        if let Ok(entry) = std::env::var("REMOVE_DELAYS") {
            ignore.extend(entry.split(',').filter_map(|x| parse_addr_or_symbol(x, vm)));
        }
        for (symbol, handler) in &config.handlers {
            let addr = get_symbol(vm, &symbol)?;
            match handler.as_deref() {
                Some("ignore") | None => ignore.push(addr),
                Some("crash") => crash_at.push(addr),
                Some(unknown) => anyhow::bail!("unsupported handler type for {symbol}: {unknown}"),
            }
        }

        tracing::info!("Crashing at: {crash_at:x?}");
        vm.hook_many_addresses(&crash_at, |cpu, addr| {
            cpu.exception = Exception::new(ExceptionCode::InvalidInstruction, addr);
        });

        let lr = vm.cpu.arch.sleigh.get_reg("lr").unwrap().var;
        tracing::info!("Ignoring functions at: {ignore:x?}");
        icicle_vm::cpu::lifter::register_experimental_instant_return(&mut vm.lifter, lr, ignore);

        // Register functions that the fuzzer should exit at.
        let mut exit_at = vec![];
        let mut hang_at = vec![];
        for (symbol, handler) in &config.exit_at {
            let addr = get_symbol(vm, &symbol)?;

            match handler.as_ref().map(|x| x.as_str()) {
                Some("hang") => hang_at.push(addr),
                Some(unknown) => anyhow::bail!("Unknown handler for exit_at {symbol}: {unknown}"),
                None => exit_at.push(addr),
            }
        }

        if !exit_at.is_empty() {
            tracing::info!("Halting at: {exit_at:x?}");
            vm.hook_many_addresses(&exit_at, |cpu, addr| {
                cpu.exception = Exception::new(ExceptionCode::Halt, addr);
            });
        }

        if !hang_at.is_empty() {
            tracing::info!("Hanging at: {hang_at:x?}");
            vm.hook_many_addresses(&hang_at, |cpu, addr| {
                cpu.exception = Exception::new(ExceptionCode::Halt, addr);
            });
        }

        for (addr, patch) in &config.patch {
            let addr = get_symbol(vm, addr)?;
            let reg = vm.cpu.arch.sleigh.get_reg(&patch.register).ok_or_else(|| {
                anyhow::format_err!("Unknown register in `patch` for {addr:#x}: {}", patch.register)
            })?;
            icicle_vm::cpu::lifter::register_value_patcher(
                &mut vm.lifter,
                addr,
                reg.var,
                patch.value,
            );
        }

        for (addr, value) in &config.mem_patch {
            let addr = get_symbol(vm, addr)?;
            vm.cpu.mem.write_bytes(addr, &value, perm::NONE)?;
        }

        Ok(())
    }
}

fn get_symbol(vm: &mut icicle_vm::Vm, symbol: &str) -> anyhow::Result<u64> {
    parse_addr_or_symbol(symbol, vm)
        .ok_or_else(|| anyhow::format_err!("Failed to resolve symbol: {symbol}"))
}

/// Attempts to find an ELF binary with the same base name as target path to load debug info from.
fn find_elf_for_path(path: PathBuf) -> Option<PathBuf> {
    let elf_path = path.with_extension("elf");
    if elf_path.exists() {
        return Some(elf_path);
    }
    let out_path = path.with_extension("out");
    if out_path.exists() {
        return Some(out_path);
    }
    None
}

fn write_raw_bytes(
    vm: &mut icicle_vm::Vm,
    region: &config::Memory,
    data: &[u8],
) -> anyhow::Result<()> {
    let bytes = &data[region.file_offset as usize..];

    // If file size was not specified, assume it matches the size of the full region.
    let file_size = region.file_size.unwrap_or(region.size) as usize;
    let len = usize::min(bytes.len(), file_size);
    vm.cpu.mem.write_bytes_large(region.base_addr, &bytes[..len], perm::NONE).map_err(|e| {
        anyhow::format_err!(
            "failed to write {len:#x} bytes (offset = {:#x}) to {:#x}: {e}",
            region.file_offset,
            region.base_addr
        )
    })
}

fn write_ihex_bytes(
    vm: &mut icicle_vm::Vm,
    region: &config::Memory,
    data: &[u8],
) -> anyhow::Result<()> {
    let input =
        std::str::from_utf8(&data).map_err(|e| anyhow::format_err!("invalid ihex file: {e}"))?;

    let reader = ihex::Reader::new(input);
    let mut base_addr = region.base_addr;
    for entry in reader {
        match entry.map_err(|e| anyhow::format_err!("invalid ihex file: {e}"))? {
            ihex::Record::Data { offset, value } => {
                let addr = base_addr + offset as u64;
                vm.cpu.mem.write_bytes(addr, &value, perm::NONE).map_err(|e| {
                    anyhow::format_err!("failed to write to memory at {addr:#0x}: {e}")
                })?;
                let perm = region.permissions.0;
                vm.cpu.mem.update_perm(addr, value.len() as u64, perm).map_err(|e| {
                    anyhow::format_err!("failed to update permissions at {addr:#0x}: {e}")
                })?;
            }
            ihex::Record::StartLinearAddress(addr) => base_addr = addr as u64,
            ihex::Record::ExtendedLinearAddress(upper_addr) => {
                base_addr = (base_addr & 0xffff) | ((upper_addr as u64) << 16);
            }
            ihex::Record::EndOfFile => break,
            other => anyhow::bail!("Unsupported ihex record: {other:x?}"),
        }
    }

    Ok(())
}

impl<T> icicle_fuzzing::Runnable for CortexmTarget<T> {
    fn set_input(&mut self, _vm: &mut icicle_vm::Vm, _input: &[u8]) -> anyhow::Result<()> {
        anyhow::bail!("input must be set directly");
    }

    fn run(&mut self, vm: &mut icicle_vm::Vm) -> anyhow::Result<VmExit> {
        let (icicle_exit, fuzzware_exit) = self.with_uc_ptr(vm, |uc| {
            let ctx = unsafe { &mut *(*uc).ctx.cast::<Context>() };
            let vm = unsafe { &mut *ctx.vm };

            let exit = vm.run();

            if let Some(fuzzware_exit) =
                vm.env_mut::<FuzzwareEnvironment>().unwrap().fuzzware_exit.take()
            {
                let icicle_exit = match fuzzware_exit {
                    fuzzware::uc_err::UC_ERR_OK => VmExit::Halt,

                    fuzzware::uc_err::UC_ERR_BLOCK_LIMIT
                    | fuzzware::uc_err::UC_ERR_NO_FUZZ_CONSUMPTION
                    | fuzzware::uc_err::UC_ERR_INTERRUPT_LIMIT => VmExit::InstructionLimit,

                    fuzzware::uc_err::UC_ERR_NVIC_ASSERTION => {
                        VmExit::UnhandledException((ExceptionCode::InternalError, 0))
                    }

                    fuzzware::uc_err::UC_ERR_NVIC_RESET => VmExit::Killed,

                    fuzzware::uc_err::UC_ERR_FETCH_PROT => VmExit::UnhandledException((
                        ExceptionCode::InvalidInstruction,
                        vm.cpu.read_pc(),
                    )),

                    x => VmExit::UnhandledException((ExceptionCode::UnknownError, x as u64)),
                };
                return (icicle_exit, fuzzware_exit);
            }
            (exit, fuzzware::uc_err::UC_ERR_OK)
        });

        self.fuzzware_exit = fuzzware_exit;
        Ok(icicle_exit)
    }
}

impl<T> icicle_fuzzing::FuzzTarget for CortexmTarget<T> {
    fn create_vm(
        &mut self,
        config: &mut icicle_fuzzing::FuzzConfig,
    ) -> anyhow::Result<icicle_vm::Vm> {
        let mut cpu_config = config.cpu_config();
        cpu_config.triple = "arm-none".parse().unwrap();

        let mut vm = icicle_vm::build(&cpu_config)?;
        vm.set_env(FuzzwareEnvironment::new());

        Ok(vm)
    }

    fn initialize_vm(
        &mut self,
        _config: &icicle_fuzzing::FuzzConfig,
        vm: &mut icicle_vm::Vm,
    ) -> anyhow::Result<()> {
        // @fixme: this is needed to set the `vm` ptr inside of the `uc_engine` struct that is used
        // in the C APIs. This usage breaks Rust's aliasing rules, so should be fixed.
        self.ctx.as_mut().unwrap().get_mut().vm = vm;

        // Force thumb mode.
        let pc = vm.cpu.read_pc();
        vm.cpu.write_pc(pc & !0b1);
        vm.cpu.set_isa_mode(1);
        vm.cpu.exception.clear();

        vm.env.as_mut_any().downcast_mut::<FuzzwareEnvironment>().unwrap().init(&mut vm.cpu);

        if icicle_fuzzing::parse_bool_env("USE_HALT_PATCHER")?.unwrap_or(false) {
            icicle_vm::cpu::lifter::register_halt_patcher(&mut vm.lifter);
        }

        // @todo? run until the first time the input is read
        Ok(())
    }

    fn exit_string(&self, exit: VmExit) -> String {
        if self.fuzzware_exit == fuzzware::uc_err::UC_ERR_OK {
            return format!("{exit:?}");
        }
        format!("{exit:?}: {}", fuzzware::uc_error_str(self.fuzzware_exit))
    }
}

pub struct FuzzwareEnvironment {
    uc_ptr: *mut uc_engine,

    /// Debug info loaded into the environment.
    debug_info: DebugInfo,

    /// The path to the ELF binary for the currently configured target.
    pub elf_path: Option<PathBuf>,

    /// The value saved value used for restoring coverage information after masking.
    saved_prev: Option<u64>,

    /// Handles fixing coverage state between interrupts.
    masking: CovMasking,

    /// Controls whether interrupts should be triggered by halts.
    trigger_interrupt_on_halt: bool,

    /// The varnode associated with the XPSR register.
    xpsr: pcode::VarNode,

    /// A custom exit condition requested by Fuzzware code.
    fuzzware_exit: Option<fuzzware::uc_err::Type>,
}

impl Default for FuzzwareEnvironment {
    fn default() -> Self {
        Self::new()
    }
}

impl FuzzwareEnvironment {
    pub fn new() -> Self {
        Self {
            debug_info: DebugInfo::default(),
            elf_path: None,
            uc_ptr: std::ptr::null_mut(),
            saved_prev: None,
            masking: CovMasking::None,
            trigger_interrupt_on_halt: false,
            xpsr: pcode::VarNode::NONE,
            fuzzware_exit: None,
        }
    }

    pub fn init(&mut self, cpu: &mut Cpu) {
        if let Some(reg) = cpu.arch.sleigh.get_reg("afl.prev_pc") {
            tracing::info!("Edge hit counts (afl.prev_pc) masking enabled for interrupts");
            self.masking = CovMasking::HitCounts { prev_pc_var: reg.var };
        }
        self.xpsr =
            cpu.arch.sleigh.get_reg("xpsr").expect("xpsr must be configured before init").var;

        if let Some(hook) = cpu
            .get_hooks()
            .iter_mut()
            .position(|x| x.data_mut::<icicle_fuzzing::coverage::EdgeHookData>().is_some())
        {
            self.masking = CovMasking::ExactEdgeCov { hook: hook as pcode::HookId }
        }
    }

    /// Handles code associated with pushing the stack frame associated with an interrupt entry.
    ///
    /// Note: Currently most of the code is implemented by Fuzzware.
    pub fn push_stack(&mut self, cpu: &mut Cpu) {
        self.masking.mask_entry(self, cpu)
    }

    /// Handles code associated with poping the stack frame after returning from an interrupt.
    ///
    /// Note: Currently most of the code is implemented by Fuzzware.
    pub fn pop_stack(&mut self, cpu: &mut Cpu) {
        self.masking.mask_return(self, cpu)
    }

    pub fn set_debug_info(&mut self, path: PathBuf) -> anyhow::Result<()> {
        tracing::info!("Using debug info from: {}", path.display());
        let file =
            std::fs::read(&path).with_context(|| format!("failed to read `{}`", path.display()))?;
        self.debug_info.add_file(&file, 0).map_err(|e| {
            anyhow::format_err!("error setting debug info for `{}`: {e}", path.display())
        })?;
        self.elf_path = Some(path);
        Ok(())
    }

    fn get_active_exception(&mut self, cpu: &mut Cpu) -> u64 {
        cpu.read_reg(self.xpsr) & 0x1ff
    }

    /// Triggers the next time based interrupt to occur (if time-based interrupts are enabled).
    fn trigger_next_time_based_interrupt(&mut self) {
        /// Configures whether interrupts are triggered directly when a sleep event is triggered,
        /// instead of simply adjusting timers.
        ///
        /// This is disabled by default to maintain backwards compatibility with previous traces.
        const IMPROVED_SLEEP_INTERRUPT_TRIGGERING: bool = false;

        if IMPROVED_SLEEP_INTERRUPT_TRIGGERING {
            self.force_trigger_next_time_based_interrupt();
        }
        else {
            // Warp time forward until the next timer event.
            unsafe { unicorn_api::set_timer_countdown((*self.uc_ptr).ctx, 1) };
        }
    }

    /// Triggers the next time based interrupt to occur (if time-based interrupts are enabled).
    fn force_trigger_next_time_based_interrupt(&mut self) {
        unsafe {
            let fw = unsafe { &mut *(*self.uc_ptr).fw };
            let num_triggers = fw.num_triggers_inuse as usize;
            let triggers = &mut fw.triggers[..num_triggers];
            if let Some(trigger) = triggers
                .iter_mut()
                .find(|trigger| trigger.fuzz_mode == fuzzware::IRQ_TRIGGER_MODE_TIME as u16)
            {
                fuzzware::interrupt_trigger_timer_cb(
                    self.uc_ptr,
                    0,
                    (trigger as *mut fuzzware::InterruptTrigger).cast(),
                );
            }
        }
    }
}

impl icicle_vm::cpu::elf::ElfLoader for FuzzwareEnvironment {
    const DYNAMIC_MEMORY: bool = true;
    const LOAD_AT_PHYSICAL_ADDRESS: bool = false;
}

impl icicle_vm::cpu::Environment for FuzzwareEnvironment {
    fn load(&mut self, cpu: &mut Cpu, path: &[u8]) -> Result<(), String> {
        use icicle_vm::cpu::elf::ElfLoader;
        let metadata = self.load_elf(cpu, path)?;
        self.debug_info = metadata.debug_info;
        Ok(())
    }

    fn handle_exception(&mut self, cpu: &mut Cpu) -> Option<VmExit> {
        match ExceptionCode::from_u32(cpu.exception.code) {
            ExceptionCode::Syscall => {
                // Update PC to point to the next pc value (this is not done inside of the SVC
                // handler).
                cpu.resume_next();
                unsafe {
                    fuzzware::handler_svc(self.uc_ptr, crate::arm::EXCP_SWI, std::ptr::null_mut());
                }
            }
            ExceptionCode::SoftwareBreakpoint => {
                // Ignore software breakpoints while fuzzing (these sometimes occur during panic
                // handlers).
                cpu.exception.clear();
                cpu.resume_next();
            }
            ExceptionCode::Sleep => {
                self.trigger_next_time_based_interrupt();
                cpu.exception.clear();
                cpu.resume_next();
            }
            ExceptionCode::Halt => {
                // Report as a deadlock if halt occurs inside of a IRQ
                let exception_number = self.get_active_exception(cpu);
                if exception_number != 0 {
                    // @todo: allow this if nested interrupts are enabled?.
                    tracing::debug!("Deadlock in IRQ: {exception_number}");
                    return Some(VmExit::Deadlock);
                }

                if self.trigger_interrupt_on_halt {
                    self.force_trigger_next_time_based_interrupt();
                    cpu.exception.clear();
                }
                else {
                    return Some(VmExit::InstructionLimit);
                }
            }
            ExceptionCode::CodeNotTranslated
            | ExceptionCode::InvalidInstruction
            | ExceptionCode::ShadowStackInvalid => {
                let value = cpu.exception.value as u32;
                if is_arm_exception_return(value) {
                    cpu.exception.clear();
                    unsafe { fuzzware::ExceptionReturn(self.uc_ptr, value) }
                }
            }
            _ => {
                // Any other exceptions are left for the emulator to handle.
            }
        }

        None
    }

    fn snapshot(&mut self) -> Box<dyn std::any::Any> {
        Box::new((self.saved_prev, FuzzwareSnapshot::take(self.uc_ptr)))
    }

    fn restore(&mut self, snapshot: &Box<dyn std::any::Any>) {
        let (saved_prev, fuzzware) =
            snapshot.downcast_ref::<(Option<u64>, FuzzwareSnapshot)>().unwrap();
        fuzzware.restore(self.uc_ptr);
        self.saved_prev = *saved_prev;
    }

    fn symbolize_addr(&mut self, _cpu: &mut Cpu, addr: u64) -> Option<SourceLocation> {
        if is_arm_exception_return(addr as u32) {
            let mut location = SourceLocation::default();
            location.function = Some(("<signal handler>".into(), addr));
            return Some(location);
        }
        self.debug_info.symbolize_addr(addr)
    }

    fn lookup_symbol(&mut self, symbol: &str) -> Option<u64> {
        // Note: we clear the thumb bit because the SLEIGH spec normalizes jumps to thumb addresses.
        self.debug_info.symbols.resolve_sym(symbol).map(|x| x & !0b1)
    }

    fn debug_info(&self) -> Option<&DebugInfo> {
        Some(&self.debug_info)
    }
}

#[inline(always)]
pub fn is_arm_exception_return(value: u32) -> bool {
    (value & fuzzware::EXC_RETURN_MASK) == fuzzware::EXC_RETURN_MASK
}

#[derive(Copy, Clone)]
pub(crate) enum CovMasking {
    HitCounts { prev_pc_var: pcode::VarNode },
    ExactEdgeCov { hook: pcode::HookId },
    None,
}

impl CovMasking {
    pub fn mask_entry(self, env: &mut FuzzwareEnvironment, cpu: &mut Cpu) {
        match self {
            Self::HitCounts { prev_pc_var } => {
                let prev_pc = cpu.read_var::<u16>(prev_pc_var);
                env.saved_prev = Some(prev_pc as u64);
                cpu.write_var(prev_pc_var, 0_u16);
            }
            Self::ExactEdgeCov { hook } => {
                let hook = cpu
                    .get_hook_mut(hook)
                    .data_mut::<icicle_fuzzing::coverage::EdgeHookData>()
                    .unwrap();
                env.saved_prev = Some(hook.prev);
                hook.prev = 0;
            }
            Self::None => {}
        }
    }

    pub fn mask_return(self, env: &mut FuzzwareEnvironment, cpu: &mut Cpu) {
        match self {
            Self::HitCounts { prev_pc_var } => {
                let value = env
                    .saved_prev
                    .take()
                    .expect("returned from interrupt without setting previous interrupt value");
                cpu.write_var(prev_pc_var, value as u16);
            }
            Self::ExactEdgeCov { hook } => {
                let hook = cpu
                    .get_hook_mut(hook)
                    .data_mut::<icicle_fuzzing::coverage::EdgeHookData>()
                    .unwrap();
                hook.prev = env
                    .saved_prev
                    .take()
                    .expect("returned from interrupt without setting previous interrupt value");
            }
            Self::None => {}
        }
    }
}

struct FuzzwareNvicHandler {
    uc: *mut uc_engine,
}

impl IoMemory for FuzzwareNvicHandler {
    fn read(&mut self, addr: u64, buf: &mut [u8]) -> icicle_vm::cpu::mem::MemResult<()> {
        let value = unsafe { fuzzware::handle_sysctl_mmio_read(self.uc, addr, buf.len() as i32) };
        // This function is extremly hot so we specialize common output sizes, with the most common
        // (4 byte access) first.
        match buf.len() {
            4 => buf.copy_from_slice(&value.to_le_bytes()[..4]),
            1 => buf.copy_from_slice(&value.to_le_bytes()[..1]),
            2 => buf.copy_from_slice(&value.to_le_bytes()[..2]),
            _ => buf.copy_from_slice(&value.to_le_bytes()[..buf.len()]),
        }
        Ok(())
    }

    fn write(&mut self, addr: u64, value: &[u8]) -> icicle_vm::cpu::mem::MemResult<()> {
        // @fixme? Unlike fuzzware we don't passthrough writes.
        unsafe {
            fuzzware::handle_sysctl_mmio_write(
                self.uc,
                addr,
                value.len() as i32,
                get_u64(value) as i64,
            )
        };
        Ok(())
    }
}

struct FuzzwareSnapshot {
    interrupt_trigger: *mut c_void,
    timers: *mut c_void,
    nvic: *mut c_void,
    systick: *mut c_void,
}

impl Drop for FuzzwareSnapshot {
    fn drop(&mut self) {
        self.discard();
    }
}

impl FuzzwareSnapshot {
    fn take(uc: *mut uc_engine) -> Self {
        unsafe {
            Self {
                interrupt_trigger: fuzzware::interrupt_trigger_take_snapshot(uc),
                timers: fuzzware::timers_take_snapshot(uc),
                nvic: fuzzware::nvic_take_snapshot(uc),
                systick: fuzzware::systick_take_snapshot(uc),
            }
        }
    }

    fn restore(&self, uc: *mut uc_engine) {
        unsafe {
            fuzzware::interrupt_trigger_restore_snapshot(uc, self.interrupt_trigger);
            fuzzware::timers_restore_snapshot(uc, self.timers);
            fuzzware::nvic_restore_snapshot(uc, self.nvic);
            fuzzware::systick_restore_snapshot(uc, self.systick);
        }
    }

    fn discard(&mut self) {
        if self.interrupt_trigger.is_null() {
            // Snapshot has already been discarded.
            tracing::error!("Attempted to discard a snapshot multiple times");
            return;
        }

        unsafe {
            let uc: *mut uc_engine = std::ptr::null_mut();
            fuzzware::interrupt_trigger_discard_snapshot(uc, self.interrupt_trigger);
            self.interrupt_trigger = std::ptr::null_mut();

            fuzzware::timers_discard_snapshot(uc, self.timers);
            self.timers = std::ptr::null_mut();

            fuzzware::nvic_discard_snapshot(uc, self.nvic);
            self.nvic = std::ptr::null_mut();

            fuzzware::systick_discard_snapshot(uc, self.systick);
            self.systick = std::ptr::null_mut();
        }
    }
}
