use std::{
    io::Write,
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::Context;
use hashbrown::HashMap;
use icicle_fuzzing::CrashKind;
use icicle_vm::{Vm, VmExit};

use crate::{
    dictionary::DictionaryItem,
    input::{CortexmMultiStream, StreamKey},
    Fuzzer, Stage, State,
};

#[derive(Copy, Clone)]
pub(crate) struct Monitor {
    /// The total number of executions that the fuzzer has done
    pub total_executions: u64,

    /// The number of crashes that the fuzzer has seen
    pub crashes: u64,

    /// The number of times a timeout has been hit
    pub timeouts: u64,

    /// The number of unique blocks that the fuzzer has seen with any input
    pub blocks_seen: u64,

    /// An instant that keeps track of when the fuzzer start.
    pub start_time: Instant,

    /// The last time we wrote the stats to a file.
    pub last_log_time: Instant,

    /// The amount of time to wait before writing current stats to a file.
    pub log_rate: Duration,

    /// The time it took to execute the slowest input.
    pub max_duration: Duration,

    /// The maximum number of instructions executed by a single test case.
    pub max_instructions: u64,

    /// The last point in time that we got new coverage
    pub last_coverage_increase: Instant,

    /// The last time that we displayed output.
    pub last_report: Instant,

    /// The total executions the last time we displayed output.
    pub last_exec_count: u64,

    /// The total number of dictionary items the last time we saved the fuzzer dictionary.
    pub last_dict_items: usize,

    /// The ID of the current input.
    pub input_id: usize,

    /// The current stage.
    pub stage: Stage,
}

impl Monitor {
    pub fn new() -> Self {
        let log_rate = match std::env::var("STATS_LOG_RATE") {
            Ok(time) => Duration::from_secs_f64(time.parse::<f64>().unwrap()),
            Err(_) => Duration::from_secs(1),
        };

        Self {
            total_executions: 0,
            crashes: 0,
            timeouts: 0,
            blocks_seen: 0,
            start_time: Instant::now(),
            log_rate,
            last_log_time: Instant::now(),
            last_coverage_increase: Instant::now(),
            last_report: Instant::now(),
            max_duration: Duration::ZERO,
            max_instructions: 0,
            last_exec_count: 0,
            last_dict_items: 0,
            input_id: 0,
            stage: Stage::Import,
        }
    }

    pub fn update(&mut self, fuzzer: &Fuzzer) {
        let blocks_seen = fuzzer.vm.code.blocks.len() as u64;
        if blocks_seen != self.blocks_seen {
            self.blocks_seen = blocks_seen;
            self.last_coverage_increase = Instant::now();
        }
        else {
            // Note: we only update the max time if the number of blocks seen doesn't increase to
            // avoid counting the JIT compilation time.
            self.max_duration = fuzzer.state.exec_time.max(self.max_duration);
        }

        self.max_instructions = fuzzer.state.instructions.max(self.max_instructions);
        self.input_id = fuzzer.input_id.unwrap_or(0);
        self.stage = fuzzer.stage;

        self.log(fuzzer);
    }

    pub fn log(&mut self, fuzzer: &Fuzzer) {
        let elapsed_time = self.last_report.elapsed();

        let total_time = self.start_time.elapsed();
        let rate =
            (self.total_executions - self.last_exec_count) as f64 / elapsed_time.as_secs_f64();

        eprintln!(
            "[{:6} s] {:6.1}k rate= {:5.0}/s {}:{:<4} crash= {:<6} ({} unq)  hang= {:<3} ({} unq)  cov= {:<5} ({:<4} TB)  in= {:<3} ({} new)  cycle= {} (find @{})",
            total_time.as_secs(),
            self.total_executions as f64 / 1000.0,
            rate,
            self.stage.short_name(),
            self.input_id,
            self.crashes,
            fuzzer.global.crashes.lock().unwrap().len(),
            self.timeouts,
            fuzzer.global.hangs.lock().unwrap().len(),
            fuzzer.coverage.count(),
            fuzzer.seen_blocks.total_seen(),
            fuzzer.corpus.inputs(),
            fuzzer.queue.new_inputs(),
            fuzzer.queue.cycles,
            fuzzer.queue.found_input_at_cycle
        );

        if self.last_log_time.elapsed() > self.log_rate {
            self.last_log_time = Instant::now();
            if let Ok(mut monitor_file) = std::fs::File::options()
                .append(true)
                .create(true)
                .open(fuzzer.workdir.join("stats.csv"))
            {
                let _ = monitor_file.write_all(
                    format!(
                        "{},{},{},{},{},{},{},{},{},{},{},{}\n",
                        total_time.as_millis(),
                        self.total_executions,
                        self.crashes,
                        fuzzer.global.crashes.lock().unwrap().len(),
                        self.timeouts,
                        fuzzer.global.hangs.lock().unwrap().len(),
                        fuzzer.coverage.count(),
                        fuzzer.seen_blocks.total_seen(),
                        fuzzer.corpus.inputs(),
                        fuzzer.corpus.metadata.total_input_bytes,
                        fuzzer.corpus.metadata.total_instructions,
                        fuzzer.dict_items,
                    )
                    .as_bytes(),
                );
            }
        }

        if self.last_dict_items != fuzzer.dict_items {
            self.last_dict_items = fuzzer.dict_items;
            let mut dict: Vec<(StreamKey, Vec<&DictionaryItem>)> =
                fuzzer.dict.iter().map(|(addr, x)| (*addr, x.entries.values().collect())).collect();
            dict.sort_by_key(|(addr, _)| *addr);
            let dict = serde_json::ser::to_vec(&dict).unwrap();
            std::fs::write(fuzzer.workdir.join("dict.json"), dict).unwrap();
        }

        self.last_report = Instant::now();
        self.last_exec_count = self.total_executions;
    }

    pub fn sync(&mut self, stats: LocalStats) {
        self.total_executions += stats.execs;
        self.crashes += stats.crashes;
        self.timeouts += stats.timeouts;
    }
}

struct DisplayBytes(usize);

impl std::fmt::Display for DisplayBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const KB: usize = 1024;
        const MB: usize = 1024 * 1024;

        match self.0 {
            x if x < KB => write!(f, "{x} B"),
            x if x < MB => write!(f, "{:.2} KB", x as f64 / KB as f64),
            x => write!(f, "{:.2} MB", x as f64 / MB as f64),
        }
    }
}

#[derive(Copy, Clone)]
pub(crate) struct LocalStats {
    /// The total executions the last time stats were synced.
    pub execs: u64,

    /// The number of crashes since last sync.
    pub crashes: u64,

    /// The number of timeouts since last sync.
    pub timeouts: u64,

    /// The last time the fuzzer was syncronized.
    pub last_sync: Instant,
}

impl Default for LocalStats {
    fn default() -> Self {
        Self { execs: 0, crashes: 0, timeouts: 0, last_sync: Instant::now() }
    }
}

impl LocalStats {
    pub fn update(&mut self, fuzzer: &Fuzzer) {
        self.execs += 1;
        if fuzzer.state.was_crash {
            self.crashes += 1;
        }
        if fuzzer.state.was_hang {
            self.timeouts += 1;
        }
        self.maybe_sync(fuzzer);
    }

    pub fn maybe_sync(&mut self, fuzzer: &Fuzzer) {
        let elapsed_time = self.last_sync.elapsed();
        if elapsed_time < std::time::Duration::from_secs(1) {
            return;
        }

        if let Some(mut monitor) = fuzzer.global.monitor.as_ref().and_then(|x| x.lock().ok()) {
            monitor.sync(*self);
            if fuzzer.global.is_main_instance() {
                monitor.update(fuzzer);
            }
            *self = Self::default();
        }
    }
}

#[derive(serde::Serialize)]
struct CrashEntry {
    id: usize,
    count: usize,
    exit: String,
    callstack: Vec<u64>,
}

#[derive(Default)]
pub struct CrashLogger {
    crashes: HashMap<String, CrashEntry>,
    hangs: HashMap<String, CrashEntry>,
    metadata_path: PathBuf,
    crash_dir: Option<PathBuf>,
    hang_dir: Option<PathBuf>,
    /// A limit on the total number of crashes/hangs to save.
    save_limit: usize,
    print_crashes: bool,
}

impl CrashLogger {
    pub fn new(config: &crate::Config) -> anyhow::Result<Self> {
        Ok(Self {
            metadata_path: config.workdir.join("crashes.json"),
            crash_dir: config.fuzzer.save_crashes.then(|| config.workdir.join("crashes")),
            hang_dir: config.fuzzer.save_hangs.then(|| config.workdir.join("hangs")),
            save_limit: std::env::var("SAVE_CRASH_LIMIT")
                .ok()
                .and_then(|x| x.parse().ok())
                .unwrap_or(usize::MAX),
            print_crashes: icicle_fuzzing::parse_bool_env("PRINT_CRASHES")?.unwrap_or(true),
            ..Self::default()
        })
    }

    pub fn is_new(&mut self, vm: &mut Vm, exit: VmExit) -> bool {
        let dst = match CrashKind::from(exit) {
            CrashKind::Hang => &mut self.hangs,
            _ => &mut self.crashes,
        };

        let id = dst.len();
        let mut is_new = false;
        let entry = dst.entry(icicle_fuzzing::gen_crash_key(vm, exit)).or_insert_with(|| {
            is_new = true;
            // @todo: consider truncating to handle unbounded recursion?
            let callstack = vm.get_debug_callstack();
            CrashEntry { id, count: 0, exit: format!("{exit:?}"), callstack }
        });
        entry.count += 1;

        is_new
    }

    pub fn save(
        &mut self,
        state: &State,
        vm: &mut Vm,
        target: &CortexmMultiStream,
        exit: VmExit,
    ) -> anyhow::Result<()> {
        let save_dir = match CrashKind::from(exit) {
            CrashKind::Hang => {
                self.print_crash_or_hang(vm, target, exit, "hang");
                match self.hangs.len() < self.save_limit {
                    true => self.hang_dir.as_ref(),
                    false => None,
                }
            }
            _ => {
                self.print_crash_or_hang(vm, target, exit, "crash");
                match self.crashes.len() < self.save_limit {
                    true => self.crash_dir.as_ref(),
                    false => None,
                }
            }
        };

        if let Some(dir) = save_dir {
            let path = dir.join(format!("{}", icicle_fuzzing::gen_crash_key(vm, exit)));
            std::fs::write(&path, state.input.to_bytes())
                .with_context(|| format!("failed to save to {}", path.display()))?;
        }

        #[derive(serde::Serialize)]
        struct CrashMetadata<'a> {
            crashes: Vec<(&'a String, &'a CrashEntry)>,
            hangs: Vec<(&'a String, &'a CrashEntry)>,
        }
        let mut metadata = CrashMetadata {
            crashes: self.crashes.iter().collect(),
            hangs: self.hangs.iter().collect(),
        };
        metadata.crashes.sort_by_key(|(_, entry)| entry.callstack.last());
        metadata.hangs.sort_by_key(|(_, entry)| entry.callstack.last());
        std::fs::write(&self.metadata_path, serde_json::ser::to_vec(&metadata)?)?;

        Ok(())
    }

    fn print_crash_or_hang(
        &self,
        vm: &mut Vm,
        target: &CortexmMultiStream,
        exit: VmExit,
        kind: &str,
    ) {
        use icicle_fuzzing::FuzzTarget;

        if self.print_crashes {
            let backtrace = icicle_vm::debug::backtrace(vm);
            let exit = target.exit_string(exit);
            eprintln!("New {kind} ({exit}): \n{backtrace}");
            tracing::error!("New {kind} ({exit}): \n{backtrace}");
        }
    }
}
