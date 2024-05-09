use std::{io::Write, path::Path};

use anyhow::Context;
use hashbrown::HashMap;

use icicle_fuzzing::{FuzzTarget, Runnable};
use icicle_vm::{cpu::ExceptionCode, Vm, VmExit};

use crate::{
    config,
    coverage::Coverage,
    debugging::{modify_input, trace},
    i2s::log_cmplog_data,
    input::{CortexmMultiStream, MultiStream},
    queue::InputMetadata,
    setup_vm,
    utils::load_json,
    Config,
};

pub enum SaveMode {
    Full,
    BlocksOnly,
}

impl std::str::FromStr for SaveMode {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "full" => Self::Full,
            "blocks" => Self::BlocksOnly,
            _ => Self::BlocksOnly,
        })
    }
}

pub fn save_block_coverage(mut config: Config, mode: SaveMode) -> anyhow::Result<()> {
    let mut testcases: Vec<InputMetadata> = load_json(&config.workdir.join("testcases.json"))?;
    testcases.sort_by_key(|x| x.found_at);

    let features = config::EnabledFeatures::from_env()?;
    let (mut target, mut vm) = setup_vm(&mut config, &features)?;
    target.initialize_vm(&config.fuzzer, &mut vm)?;

    let mut coverage =
        crate::coverage::BlockCoverage::init(&mut vm, crate::coverage::BucketStrategy::Any, true);

    let snapshot = vm.snapshot();

    let mut all_blocks = vec![];
    let mut block_map = HashMap::new();
    let mut output = vec![];
    for case in testcases {
        vm.restore(&snapshot);
        coverage.reset(&mut vm);

        let input = MultiStream::from_path(&config.workdir.join(format!("queue/{}.bin", case.id)))?;
        target.get_mmio_handler(&mut vm).unwrap().clone_from(&input);

        target.run(&mut vm)?;

        let blocks = coverage.get_blocks(&mut vm);
        let hits = blocks
            .into_iter()
            .map(|addr| {
                *block_map.entry(addr).or_insert_with(|| {
                    let id = all_blocks.len();
                    all_blocks.push((addr, case.found_at, case.id));
                    id
                })
            })
            .collect::<Vec<_>>();

        output.push(serde_json::json!({
            "id": case.id,
            "time_ms": case.found_at,
            "hits": hits,
        }));
    }

    let out = match mode {
        SaveMode::Full => serde_json::json!({ "blocks": all_blocks, "inputs": output }),
        SaveMode::BlocksOnly => serde_json::json!(all_blocks),
    };
    write!(std::io::stdout(), "{out}")?;

    Ok(())
}

pub fn replay(mut config: Config, input_path: &Path) -> anyhow::Result<()> {
    let features = config::EnabledFeatures::from_env()?;
    let (mut target, mut vm) = setup_vm(&mut config, &features)?;
    target.initialize_vm(&config.fuzzer, &mut vm)?;

    let mut input = MultiStream::from_path(input_path)?;
    modify_input(&mut input);
    target.get_mmio_handler(&mut vm).unwrap().clone_from(&input);

    //
    // Now we launch in one of three modes depending on what environment variables are configured:
    //

    // GDB mode.
    if let Ok(addr) = std::env::var("GDB_BIND") {
        return icicle_gdb::listen_auto(&addr, vm);
    }

    // Benchmarking mode.
    if let Ok(trials_str) = std::env::var("TRIALS") {
        let trials = trials_str
            .parse::<u64>()
            .with_context(|| format!("failed to parse TRIALS={trials_str}"))?;
        return replay_bench(vm, target, trials);
    }

    // Tracing dumping mode.
    replay_trace(vm, target)
}

fn replay_bench(mut vm: Vm, mut target: CortexmMultiStream, trials: u64) -> anyhow::Result<()> {
    let core_ids = core_affinity::get_core_ids().unwrap_or(vec![]);
    if let Some(core_id) = core_ids.first() {
        eprintln!("pinning active thread to core: {core_id:?}");
        core_affinity::set_for_current(*core_id);
    }

    let snapshot = vm.snapshot();

    // Perform a dry run of the input to warm up the VM.
    let exit = target.run(&mut vm);
    vm.recompile();

    // Dump JIT function ID -> guest address mapping for analysis.
    vm.jit
        .dump_jit_mapping("jit_table.txt".as_ref())
        .context("failed to save JIT mapping table")?;

    let expected_icount = vm.cpu.icount();
    eprintln!("[icicle] exited with: {exit:?} (icount = {expected_icount})");

    let start = std::time::Instant::now();

    for _ in 0..trials {
        vm.restore(&snapshot);
        target.get_mmio_handler(&mut vm).unwrap().source.seek_to_start();
        let _ = target.run(&mut vm);

        // Ensure execution doesn't diverge.
        let icount = vm.cpu.icount();
        anyhow::ensure!(
            icount == expected_icount,
            "Execution diverged during benchmarking:\n\
            expected execution to end at icount={expected_icount}, but ended at icount={icount} instead."
        )
    }

    let elapsed = start.elapsed().as_secs_f64();
    eprintln!("{trials} trials executed in {elapsed:.2} seconds");
    eprintln!("{:.2} trials/second", trials as f64 / elapsed);
    eprintln!("{:.2} ms per trial", (elapsed / trials as f64) * 1000.0);

    Ok(())
}

fn replay_trace(mut vm: Vm, mut target: CortexmMultiStream) -> anyhow::Result<()> {
    let path_tracer = trace::add_path_tracer(&mut vm, target.mmio_handler.unwrap())?;

    let mut cmplog = None;
    if icicle_fuzzing::parse_bool_env("REPLAY_CMPLOG")?.unwrap_or(false) {
        let cmplog_ref =
            icicle_fuzzing::cmplog2::CmpLog2Builder::new().instrument_calls(true).finish(&mut vm);
        cmplog_ref.set_enabled(&mut vm.cpu, true);
        cmplog = Some(cmplog_ref);
    }

    icicle_fuzzing::add_debug_instrumentation(&mut vm);

    let exit = target.run(&mut vm)?;

    let xpsr = vm.cpu.arch.sleigh.get_reg("xpsr").unwrap().var;
    let active_irq = vm.cpu.read_reg(xpsr) & 0x1ff;
    eprintln!(
        "\n[icicle] exited with: {} (icount = {}), active_irq = {active_irq}",
        target.exit_string(exit),
        vm.cpu.icount()
    );
    eprintln!("[icicle] callstack:\n{}", icicle_vm::debug::backtrace(&mut vm));

    let print_count = match std::env::var("PRINT_LAST_BLOCKS").ok() {
        Some(c) => c.parse().context("Failed to parse `PRINT_LAST_BLOCKS` environment variable")?,
        None => 10,
    };
    eprintln!("[icicle] last blocks:\n{}", path_tracer.print_last_blocks(&mut vm, print_count));

    let reglist = icicle_vm::debug::get_debug_regs(&vm.cpu);
    eprintln!("registers:\n{}", icicle_vm::debug::print_regs(&vm, &reglist));

    if let Some(cmplog) = cmplog {
        log_cmplog_data(&mut vm, cmplog, "cmplog.txt".as_ref())?;
    }
    if icicle_fuzzing::parse_bool_env("SAVE_TRACE")?.unwrap_or(true) {
        let symbolize = icicle_fuzzing::parse_bool_env("SYMBOLIZE_TRACE")?.unwrap_or(false);
        path_tracer.save_trace(&mut vm, "trace.txt".as_ref(), symbolize);
    }
    if icicle_fuzzing::parse_bool_env("SAVE_MMIO_READS")?.unwrap_or(false) {
        trace::save_mmio_reads("mmio_reads.txt".as_ref(), &path_tracer.get_mmio_reads(&mut vm));
    }
    if icicle_fuzzing::parse_bool_env("DEBUG_IL")?.unwrap_or(false) {
        std::fs::write("il.pcode", icicle_vm::debug::dump_semantics(&vm)?)?;
    }

    Ok(())
}

pub fn analyze_crashes(mut config: Config, path: &Path) -> anyhow::Result<()> {
    let features = config::EnabledFeatures::from_env()?;
    let (mut target, mut vm) = setup_vm(&mut config, &features)?;
    target.initialize_vm(&config.fuzzer, &mut vm)?;

    let path_tracer = trace::add_path_tracer(&mut vm, target.mmio_handler.unwrap())?;
    let xpsr_reg = vm.cpu.arch.sleigh.get_reg("xpsr").unwrap().var;

    let snapshot = vm.snapshot();
    for entry in
        std::fs::read_dir(path).with_context(|| format!("failed to read: {}", path.display()))?
    {
        let path = entry?.path();
        vm.restore(&snapshot);
        path_tracer.clear(&mut vm);

        let input = MultiStream::from_path(&path)
            .with_context(|| format!("failed to read: {}", path.display()))?;
        target.get_mmio_handler(&mut vm).unwrap().clone_from(&input);

        eprintln!("-------------------\n{}", path.display());
        let exit = target.run(&mut vm)?;
        let active_irq = vm.cpu.read_reg(xpsr_reg) & 0x1ff;
        eprintln!(
            "\n[icicle] exited with: {} (icount = {}), active_irq = {active_irq}",
            target.exit_string(exit),
            vm.cpu.icount()
        );

        if !matches!(exit, VmExit::UnhandledException((ExceptionCode::Environment, _))) {
            // Print additional information for unknown crashes.
            eprintln!("[icicle] callstack:\n{}", icicle_vm::debug::backtrace(&mut vm));
            eprintln!("[icicle] last blocks:\n{}", path_tracer.print_last_blocks(&mut vm, 10));
        }

        eprintln!("-------------------\n");
    }

    Ok(())
}
