use std::{
    path::PathBuf,
    sync::{atomic::AtomicBool, Arc},
};

use anyhow::Context;
use icicle_cortexm::config::FirmwareConfig;
use icicle_fuzzing::{parse_bool_env, FuzzConfig};
use icicle_vm::Vm;

use crate::coverage::{BlockCoverage, BucketStrategy, CoverageAny, EdgeCountMap};

/// Configures whether to validate that an execution was reproducable whenever a new path is found.
/// This will significantly slow down execution speed.
pub(crate) const VALIDATE: bool = false;

/// Configures whether to validate that crashes/hangs are reproducable when they are found.
pub(crate) const VALIDATE_CRASHES: bool = false;

/// Configures the absolute maximum size (in bytes) allow for a stream. If this is set too high, the
/// fuzzer may consume a lot of memory.
pub(crate) const MAX_STREAM_LEN: usize = 0x50_000;

/// The first time we try to extend an input make more attempts. Extensions will be short (so
/// execution should be fast) and we are more likely to find a useful extension.
///
/// Currrently we do not use this feature.
pub(crate) const INCREASE_EXTENSIONS_ON_FIRST_EXEC_FACTOR: usize = 1;

/// Configures the CmpLog stage to skip comparisons involving `<`, `>`, overflow or floating point
/// operations.
pub(crate) const SKIP_COMPLEX_COMPARISIONS: bool = true;

#[derive(Clone)]
pub struct Config {
    pub fuzzer: FuzzConfig,
    pub workdir: PathBuf,
    pub firmware: FirmwareConfig,
    pub interrupt_flag: Arc<AtomicBool>,
}

/// Controls which features are enabled or not.
pub struct EnabledFeatures {
    /// Use access contexts for multi-stream inputs.
    pub access_contexts: bool,
    /// A lightweight static analysis feature that attempts to scan for cases where some bits for a
    /// load are immediately discarded. Typically level 3 is always the best option. The other
    /// options are mostly provided for compatibility with old traces.
    pub resize_load_level: usize,
    /// Whether havoc should be used for mutation as well as length extension. Should almost always
    /// be enabled (toggleable for ablation study).
    pub havoc: bool,
    /// Whether the input-to-state stage should be enabled.
    pub cmplog: bool,
    /// Whether the input-to-state stage should automatically add values to the dictionary.
    pub auto_dict: bool,
    /// Whether we should automatically attempt to trim inputs after each execution.
    pub auto_trim: bool,
    /// Whether the smart trim stage should be enabled.
    pub smart_trim: bool,
    /// Controls whether the fuzzer will use a simplified energy assignment algorithm. Currently we
    /// do not believe that this makes a significant difference to the fuzzer's performance,
    /// however 'false' is default since the old algorithm was more thoroughly tested.
    pub simple_energy_assignment: bool,
    /// Whether to occasionally check if newly generated inputs are favored (i.e. smaller) compared
    /// to previous entries.
    pub add_favored_inputs: bool,
    /// Whether to increase extensions if we repeatedly reach the end of a stream.
    pub extension_factor: bool,
}

impl EnabledFeatures {
    pub fn from_env() -> anyhow::Result<Self> {
        let simple_energy_assignment = parse_bool_env("SIMPLE_ENERGY_ASSIGNMENT")?.unwrap_or(false);
        let access_contexts =
            icicle_fuzzing::parse_bool_env("USE_ACCESS_CONTEXTS")?.unwrap_or(false);
        let extension_factor =
            icicle_fuzzing::parse_bool_env("USE_EXTENSION_FACTOR")?.unwrap_or(true);
        let add_favored_inputs = parse_bool_env("ADD_FAVORED_INPUTS")?.unwrap_or(false);

        let resize_load_level = match std::env::var("ICICLE_RESIZE_LOADS").as_deref() {
            Ok("0") => 0,
            Ok("1") => 1,
            Ok("2") => 2,
            Ok("3") | Ok("true") | Err(std::env::VarError::NotPresent) => 3,
            Ok(other) => anyhow::bail!("unknown level for resize loads: {other}"),
            Err(e) => anyhow::bail!("error reading environment variable: {e}"),
        };

        if icicle_fuzzing::parse_bool_env("LENGTH_EXTENSION_ONLY")?.unwrap_or(false) {
            return Ok(Self {
                access_contexts,
                resize_load_level,
                havoc: false,
                cmplog: false,
                auto_trim: false,
                smart_trim: false,
                auto_dict: false,
                simple_energy_assignment,
                extension_factor,
                add_favored_inputs,
            });
        }

        // Enabled by default
        let cmplog = parse_bool_env("ENABLE_CMPLOG")?.unwrap_or(true);
        let havoc = parse_bool_env("ENABLE_HAVOC")?.unwrap_or(true);
        let auto_trim = parse_bool_env("ENABLE_AUTO_TRIM")?.unwrap_or(true);
        let smart_trim = parse_bool_env("ENABLE_TRIM")?.unwrap_or(true);
        let auto_dict = parse_bool_env("ENABLE_AUTO_DICT")?.unwrap_or(true);

        Ok(Self {
            access_contexts,
            resize_load_level,
            havoc,
            cmplog,
            auto_trim,
            smart_trim,
            auto_dict,
            simple_energy_assignment,
            extension_factor,
            add_favored_inputs,
        })
    }
}

pub struct DebugSettings {
    /// Enable debugging for CmpLog stage
    pub cmplog: bool,
    /// Enable debugging for the Havoc stage
    pub havoc: bool,
    /// Whether we should save debug info for length extensions.
    pub save_length_extension_metadata: bool,
    /// Save block coverage for each input (useful for monitoring).
    pub save_input_coverage: bool,
}

impl DebugSettings {
    pub fn from_env() -> anyhow::Result<Self> {
        let cmplog = parse_bool_env("DEBUG_CMPLOG")?.unwrap_or(false);
        let havoc = parse_bool_env("DEBUG_HAVOC")?.unwrap_or(false);
        let save_input_coverage = parse_bool_env("SAVE_INPUT_COVERAGE")?.unwrap_or(false);
        let save_length_extension_metadata =
            parse_bool_env("SAVE_EXTENSION_METADATA")?.unwrap_or(false);
        Ok(Self { cmplog, havoc, save_length_extension_metadata, save_input_coverage })
    }
}

pub(crate) fn configure_coverage(config: &FuzzConfig, vm: &mut Vm) -> Box<dyn CoverageAny> {
    tracing::info!("Using: {:?} for coverage", config.coverage_mode);
    match config.coverage_mode {
        icicle_fuzzing::CoverageMode::Blocks => {
            Box::new(BlockCoverage::init(vm, BucketStrategy::Any, true))
        }
        icicle_fuzzing::CoverageMode::BlockCounts => {
            Box::new(BlockCoverage::init(vm, BucketStrategy::AflFirst, false))
        }
        icicle_fuzzing::CoverageMode::EdgeCounts => Box::new(EdgeCountMap::hit_counts(vm, config)),
        icicle_fuzzing::CoverageMode::Edges => {
            Box::new(EdgeCountMap::with_strategy(vm, config, BucketStrategy::Any))
        }
    }
}

pub(crate) struct WorkdirLock {
    file: Option<std::fs::File>,
    path: std::path::PathBuf,
}

impl WorkdirLock {
    fn new(path: std::path::PathBuf) -> anyhow::Result<Self> {
        let file = std::fs::File::options().write(true).create_new(true).open(&path).with_context(
            || format!("Failed to obtain lock for working directory ({})", path.display()),
        )?;
        Ok(Self { file: Some(file), path })
    }
}

impl Drop for WorkdirLock {
    fn drop(&mut self) {
        drop(self.file.take());
        let _ = std::fs::remove_file(&self.path);
    }
}

#[derive(serde::Serialize)]
struct HailFuzzSettings {
    firmware_config: PathBuf,
    fuzzer_path: PathBuf,
}

pub(crate) fn init_workdir(config: &Config) -> anyhow::Result<WorkdirLock> {
    let workdir = &config.workdir;

    std::fs::create_dir_all(workdir.join("crashes")).context("Error creating crash directory")?;
    std::fs::create_dir_all(workdir.join("hangs")).context("Error creating hang directory.")?;

    let lock = WorkdirLock::new(workdir.join(".lock"))?;

    std::fs::write(
        workdir.join("settings.json"),
        &serde_json::to_vec_pretty(&HailFuzzSettings {
            firmware_config: config.firmware.path.canonicalize()?,
            fuzzer_path: std::env::current_exe()?,
        })?,
    )?;

    if !config.fuzzer.resume {
        let _ = std::fs::remove_dir_all(workdir.join("queue"));

        let stats_path = workdir.join("stats.csv");
        let _ = std::fs::remove_file(&stats_path);
        if parse_bool_env("ENABLE_STATS_HEADER")?.unwrap_or(false) {
            std::fs::write(&stats_path, b"time,execs,crashes,unique_crashes,hangs,unique_hangs,coverage,blocks,inputs,total_input_bytes,total_instructions,dictionary_items\n").context("Failed to write to stats file")?;
        }
    }
    else {
        // Try to move old queue directory in place of imports.
        let _ = std::fs::remove_dir_all(workdir.join("imports"));
        let _ = std::fs::rename(workdir.join("queue"), workdir.join("imports"));
    }

    let _ = std::fs::create_dir_all(workdir.join("cmplog"));

    std::fs::create_dir_all(workdir.join("queue"))
        .context("Error creating directory for input queue.")?;

    Ok(lock)
}

pub fn add_ctrlc_handler() -> Arc<AtomicBool> {
    let flag = Arc::new(AtomicBool::new(false));
    {
        let flag = flag.clone();
        ctrlc::set_handler(move || {
            if flag.swap(true, std::sync::atomic::Ordering::Relaxed) {
                eprintln!("ctrl+c: cancel already attempted, exiting now...");
                std::process::exit(-1);
            }
        })
        .unwrap();
    }
    flag
}
