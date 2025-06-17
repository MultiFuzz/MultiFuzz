use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::Context;
use hashbrown::HashMap;

use icicle_fuzzing::{FuzzTarget, Runnable, parse_addr_or_symbol};
use icicle_vm::{Vm, VmExit, cpu::ExceptionCode};

use crate::{
    Config, config,
    coverage::Coverage,
    debugging::{modify_input, trace},
    i2s::log_cmplog_data,
    input::{CortexmMultiStream, MultiStream},
    queue::InputMetadata,
    setup_vm,
    utils::load_json,
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

pub fn replay(mut config: Config, path: &str) -> anyhow::Result<()> {
    let features = config::EnabledFeatures::from_env()?;
    let (mut target, mut vm) = setup_vm(&mut config, &features)?;
    target.initialize_vm(&config.fuzzer, &mut vm)?;

    let mut input = MultiStream::from_bytes(&InputSource::from_str(path).read()?)
        .with_context(|| format!("Invalid file format: {path}"))?;
    modify_input(&mut input);
    target.get_mmio_handler(&mut vm).unwrap().clone_from(&input);

    //
    // Now we launch in one of three modes depending on what environment variables are configured:
    //

    // GDB mode.
    if let Ok(addr) = std::env::var("GDB_BIND") {
        let elf_path = vm
            .env
            .as_any()
            .downcast_ref::<icicle_cortexm::FuzzwareEnvironment>()
            .unwrap()
            .elf_path
            .clone();
        let mut state = icicle_gdb::ArmStub::new(&mut vm);
        if let Some(elf_path) = elf_path {
            let is_loopback =
                addr.parse::<std::net::SocketAddr>().map_or(false, |x| x.ip().is_loopback());
            // If we are running on a loopback address, assume that GDB will be executed locally
            // and we can use the local ELF path (greatly improves performance).
            let path = match is_loopback {
                false => icicle_gdb::ExePath::Remote(elf_path),
                true => icicle_gdb::ExePath::Local(elf_path),
            };
            tracing::info!("Setting executable path: {path:?}");
            state.set_exe_path(path);
        }
        return icicle_gdb::listen(&addr, state, icicle_gdb::CustomCommands::default());
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

    let mut snapshot = vm.snapshot();
    let mut cursor_snapshot = target.get_mmio_handler(&mut vm).unwrap().source.snapshot_cursors();

    // Perform a dry run of the input to warm up the VM.
    let exit = target.run(&mut vm);
    vm.recompile();

    // Dump JIT function ID -> guest address mapping for analysis.
    if let Err(e) = vm.jit.dump_jit_mapping("jit_table.txt".as_ref(), vm.env.debug_info().unwrap())
    {
        tracing::warn!("Failed to dump JIT table: {e}")
    }

    let expected_icount = vm.cpu.icount();
    eprintln!("[icicle] exited with: {exit:?} (icount = {expected_icount})");

    // We allow replaying from part way through the input if provided from an environment variable.
    if let Some(bp) =
        std::env::var("REPLAY_FROM").ok().and_then(|addr| parse_addr_or_symbol(&addr, &mut vm))
    {
        vm.restore(&snapshot);
        target.get_mmio_handler(&mut vm).unwrap().source.restore_cursors(&cursor_snapshot);

        vm.add_breakpoint(bp);
        let exit = target.run(&mut vm);
        anyhow::ensure!(
            matches!(exit, Ok(VmExit::Breakpoint)),
            "Failed to hit breakpoint at: {bp:#x} when `REPLAY_FROM` is set (exited with: {exit:?} at: {:#x})",
            vm.cpu.read_pc()
        );
        vm.remove_breakpoint(bp);

        eprintln!("[icicle] hit break: {exit:?} (icount = {expected_icount})");

        snapshot = vm.snapshot();
        cursor_snapshot = target.get_mmio_handler(&mut vm).unwrap().source.snapshot_cursors();
    }

    vm.recompile();

    // Dump JIT function ID -> guest address mapping for analysis.
    if let Err(e) = vm.jit.dump_jit_mapping("jit_table.txt".as_ref(), vm.env.debug_info().unwrap())
    {
        tracing::warn!("Failed to dump JIT table: {e}")
    }

    let start = std::time::Instant::now();

    for _ in 0..trials {
        vm.restore(&snapshot);
        // Restoring currently triggers a lookup flush, but we know the code will not change between
        // execs so we can skip it here.
        vm.cpu.mem.mapping_changed = false;
        target.get_mmio_handler(&mut vm).unwrap().source.restore_cursors(&cursor_snapshot);
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

    let xpsr = vm.cpu.arch.sleigh.get_varnode("xpsr").unwrap();
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

pub fn analyze_crashes(mut config: Config, path: &str) -> anyhow::Result<()> {
    let features = config::EnabledFeatures::from_env()?;
    let (mut target, mut vm) = setup_vm(&mut config, &features)?;
    target.initialize_vm(&config.fuzzer, &mut vm)?;

    let path_tracer = trace::add_path_tracer(&mut vm, target.mmio_handler.unwrap())?;
    let xpsr_reg = vm.cpu.arch.sleigh.get_varnode("xpsr").unwrap();

    let input_src = InputSource::from_str(path);

    let snapshot = vm.snapshot();
    for entry in input_src.list_files().with_context(|| format!("failed list files in: {path}"))? {
        vm.restore(&snapshot);
        path_tracer.clear(&mut vm);

        let input = MultiStream::from_bytes(&input_src.read_child(&entry)?)
            .with_context(|| format!("Invalid file format: {}", entry.display()))?;
        target.get_mmio_handler(&mut vm).unwrap().clone_from(&input);

        eprintln!("-------------------\n{}", entry.display());
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

#[derive(Debug, Clone, Copy)]
enum Compression {
    None,
    Gz,
}

impl Compression {
    fn open_reader(&self, path: &Path) -> std::io::Result<Box<dyn std::io::Read>> {
        let file = std::fs::File::open(path)?;
        match self {
            Self::None => Ok(Box::new(std::io::BufReader::new(file))),
            Self::Gz => Ok(Box::new(flate2::read::GzDecoder::new(file))),
        }
    }
}

enum PathKind {
    Path,
    Tar { subpath: Option<PathBuf> },
}

struct InputSource {
    path: PathBuf,
    kind: PathKind,
    compression: Compression,
}

impl InputSource {
    pub fn from_str(path: &str) -> Self {
        let (file_path, subpath) = match path.rsplit_once(":") {
            Some((file_path, subpath)) => (file_path, Some(PathBuf::from(subpath))),
            None => (path, None),
        };

        let (stem, compression) =
            match file_path.strip_suffix(".gz").or_else(|| file_path.strip_suffix(".gzip")) {
                Some(stem) => (stem, Compression::Gz),
                None if file_path.ends_with(".tgz") => (file_path, Compression::None),
                None => (file_path, Compression::None),
            };

        if stem.ends_with(".tgz") || stem.ends_with(".tar") {
            Self { path: PathBuf::from(file_path), kind: PathKind::Tar { subpath }, compression }
        }
        else {
            Self { path: PathBuf::from(file_path), kind: PathKind::Path, compression }
        }
    }

    pub fn list_files(&self) -> anyhow::Result<Vec<PathBuf>> {
        match &self.kind {
            PathKind::Path => {
                anyhow::ensure!(
                    matches!(self.compression, Compression::None),
                    "attempted to read compressed file as a directory: {}",
                    self.path.display()
                );

                let mut entries = vec![];
                for entry in std::fs::read_dir(&self.path)
                    .with_context(|| format!("failed to read: {}", self.path.display()))?
                {
                    entries.push(
                        entry?
                            .path()
                            .file_name()
                            .ok_or_else(|| anyhow::format_err!("invalid file name"))?
                            .into(),
                    );
                }

                Ok(entries)
            }
            PathKind::Tar { subpath } => {
                let subpath = subpath.as_deref().unwrap_or(Path::new(""));
                let mut archive = tar::Archive::new(self.compression.open_reader(&self.path)?);
                Ok(archive
                    .entries()?
                    .flat_map(|x| x)
                    .filter(|x| x.header().entry_type().is_file())
                    .flat_map(|x| Some(x.path().ok()?.into_owned()))
                    .filter(|x| x.parent().unwrap_or(Path::new("")) == subpath)
                    .flat_map(|x| Some(x.file_name()?.into()))
                    .collect())
            }
        }
    }

    pub fn read(&self) -> anyhow::Result<Vec<u8>> {
        match &self.kind {
            PathKind::Path => {
                let mut out = vec![];
                self.compression
                    .open_reader(&self.path)
                    .with_context(|| format!("failed to read: {}", self.path.display()))?
                    .read_to_end(&mut out)?;
                Ok(out)
            }
            PathKind::Tar { subpath } => {
                let file_path = subpath.as_deref().ok_or_else(|| {
                    anyhow::format_err!(
                        "expected subpath for .tar archive: {}",
                        self.path.display()
                    )
                })?;
                read_within(&self.path, file_path, &self.compression)
            }
        }
    }

    pub fn read_child(&self, file: &Path) -> anyhow::Result<Vec<u8>> {
        match &self.kind {
            PathKind::Path => {
                anyhow::ensure!(
                    matches!(self.compression, Compression::None),
                    "attempted to read compressed file as a directory: {}",
                    self.path.display()
                );

                let file_path = self.path.join(file);
                std::fs::read(&file_path)
                    .with_context(|| format!("failed to read: {}", file_path.display()))
            }
            PathKind::Tar { subpath } => {
                let file_path = subpath.as_deref().unwrap_or(Path::new("")).join(file);
                read_within(&self.path, &file_path, &self.compression)
            }
        }
    }
}

fn read_within(
    tar_path: &Path,
    file_path: &Path,
    compression: &Compression,
) -> anyhow::Result<Vec<u8>> {
    let mut archive = tar::Archive::new(compression.open_reader(tar_path)?);
    let Some(mut entry) =
        archive.entries()?.flatten().find(|x| x.path().map_or(false, |path| path == file_path))
    else {
        anyhow::bail!("failed to find {} in {}", file_path.display(), tar_path.display());
    };
    let mut buf = vec![];
    entry.read_to_end(&mut buf).with_context(|| {
        format!("error reading: {} from {}", file_path.display(), tar_path.display())
    })?;
    Ok(buf)
}
