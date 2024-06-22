//! Script for running P2IM unit tests.

use std::{
    collections::HashMap,
    io::BufRead,
    path::{Path, PathBuf},
    sync::Mutex,
};

use anyhow::Context;
use icicle_fuzzing::{CoverageMode, FuzzConfig, FuzzTarget, Runnable};

use crate::{
    config,
    debugging::trace,
    fuzzing_loop,
    input::MultiStream,
    queue::{GlobalQueue, GlobalRef, InputMetadata},
    setup_vm,
    utils::load_json,
    Fuzzer,
};

pub fn run(
    mut fuzz_config: FuzzConfig,
    unit_test_dir: &Path,
    interrupt_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> anyhow::Result<()> {
    let groundtruth = parse_groundtruth_csv(unit_test_dir.join("groundtruth.csv"))?;

    let mut binaries: Vec<PathBuf> = glob::glob(&format!("{}/*/*/*.elf", unit_test_dir.display()))
        .with_context(|| format!("error finding binaries in: {}", unit_test_dir.display()))?
        .collect::<Result<_, _>>()
        .context("error walking file system to find ELF files")?;
    // Reverse the order of binaries so that when we pop from the vector we end up in the correct
    // order.
    binaries.reverse();

    tracing::info!("{} binaries found in {}", binaries.len(), unit_test_dir.display());
    anyhow::ensure!(
        !binaries.is_empty(),
        "No binaries found in subdirectories of: {}",
        unit_test_dir.display()
    );

    // Set coverage mode block-counts to ensure that inputs that hit edges multiple times are
    // considered "interesting". This is required since we only check whether the saved inputs reach
    // the target locations. However, some of the test cases directly check that target locations
    // are hit multiple times.
    //
    // @fixme? Consider performing 'live' checks of the objectives as inputs are generated. Length
    // extension should be able to trigger multiple iterations even if they are not saved.
    fuzz_config.coverage_mode = CoverageMode::BlockCounts;

    // The shadow-stack debugging feature does not work for binaries that use premptive scheduling.
    // It shouldn't have any impact on actually fuzzing, so it is save to disable here.
    fuzz_config.enable_shadow_stack = false;

    let n_workers = fuzz_config.workers.min(binaries.len() as u16);
    let input_queue = Mutex::new(binaries);
    let output_queue = Mutex::new(Vec::<TestResult>::new());

    let shared_workdir = Path::new("./workdir-p2im-unittests");

    std::thread::scope(|s| -> anyhow::Result<()> {
        for id in 0..n_workers {
            let input_queue = &input_queue;
            let output_queue = &output_queue;
            let interrupt_flag = &interrupt_flag;
            let fuzz_config = &fuzz_config;
            let groundtruth = &groundtruth;
            s.spawn(move || {
                while let Some(binary) = {
                    let mut lock = input_queue.lock().unwrap();
                    lock.pop()
                } {
                    if interrupt_flag.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }

                    // Try to find the fuzzware config in the same directory as the file.
                    let Some(parent_dir) = binary.parent()
                    else {
                        tracing::warn!("Skipping: {}. Failed to get parent dir", binary.display());
                        continue;
                    };
                    let config_path = parent_dir.join("config.yml");
                    let fuzzware =
                        match icicle_cortexm::config::FirmwareConfig::from_path(&config_path) {
                            Ok(config) => config,
                            Err(e) => {
                                tracing::warn!(
                                    "Skipping: {}. Error parsing config: {e:#}",
                                    binary.display(),
                                );
                                continue;
                            }
                        };

                    // Use name of parent directory as name of workdir.
                    let workdir = shared_workdir.join(
                        parent_dir.file_name().expect("invalid file name for parent directory"),
                    );
                    let config = crate::Config {
                        fuzzer: fuzz_config.clone(),
                        workdir,
                        firmware: fuzzware,
                        interrupt_flag: interrupt_flag.clone(),
                    };

                    // Run the fuzzer for a bit if this test-case has yet to be run before.
                    if !config.workdir.join("testcases.json").exists() {
                        tracing::info!(
                            "worker {id}: attempting to fuzz: {} for 10 minutes",
                            binary.display()
                        );

                        let _workdir_lock = match config::init_workdir(&config.workdir, false) {
                            Ok(lock) => lock,
                            Err(e) => {
                                tracing::warn!(
                                    "Skipping: {}. Error initializing workdir {}: {e}",
                                    binary.display(),
                                    config.workdir.display()
                                );
                                continue;
                            }
                        };

                        let global =
                            GlobalRef::new(0, std::sync::Arc::new(GlobalQueue::init(1)), None);

                        if let Err(e) = Fuzzer::new(config.clone(), global).and_then(|fuzzer| {
                            fuzzing_loop(fuzzer, Some(std::time::Duration::from_secs(60 * 10)))
                        }) {
                            tracing::error!(
                                "Error starting fuzzer for {}: {e:?}",
                                binary.display()
                            );
                            continue;
                        }
                    }

                    if interrupt_flag.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }

                    let Some(key) = get_groundtruth_key(&binary)
                    else {
                        tracing::error!("error resolving groundtruth key for {}", binary.display());
                        continue;
                    };

                    tracing::info!("worker {id}: analyzing results for: {key}");

                    let tests = groundtruth.get(&key).map_or(&[][..], Vec::as_slice);
                    if tests.is_empty() {
                        tracing::warn!("No tests for {}", binary.display());
                        continue;
                    }

                    let mut output = output_queue.lock().unwrap();
                    match find_input_for_tests(config, tests) {
                        Ok(mut results) => {
                            for test in tests {
                                output.push(results.remove(&test.line).unwrap_or_else(|| {
                                    TestResult::error(
                                        test.line,
                                        format!("no matching input: {}", test.comment),
                                    )
                                }));
                            }
                        }
                        Err(e) => output.extend(
                            tests.iter().map(|x| TestResult::error(x.line, format!("{e}"))),
                        ),
                    }
                }
            });
        }

        Ok(())
    })?;

    let mut output_queue = output_queue.into_inner().unwrap();
    output_queue.sort_by_key(|x| x.line);
    let successes = output_queue.iter().filter(|x| x.result.is_ok()).count();
    let errors = output_queue.iter().filter(|x| x.result.is_err()).count();

    eprintln!("{successes} successes, {errors} errors");
    for result in output_queue {
        let binary = groundtruth
            .iter()
            .find(|(_, entries)| entries.iter().find(|x| x.line == result.line).is_some())
            .map_or("<unknown>", |(k, _)| k.as_str());

        match result.result {
            Ok(info) => {
                tracing::info!(
                    "{} satisfies input for {binary} on line {}",
                    info.display(),
                    result.line
                );
            }
            Err(e) => {
                eprintln!("Failed test for {binary} on line {}: {e}", result.line);
            }
        }
    }

    Ok(())
}

fn find_input_for_tests(
    mut config: crate::Config,
    tests: &[GroundTruthEntry],
) -> anyhow::Result<HashMap<usize, TestResult>> {
    let mut testcases: Vec<InputMetadata> = load_json(&config.workdir.join("testcases.json"))?;
    testcases.sort_by_key(|x| x.found_at);

    let features = config::EnabledFeatures::from_env()?;
    let (mut target, mut vm) = setup_vm(&mut config, &features)?;
    target.initialize_vm(&config.fuzzer, &mut vm)?;

    let path_tracer = trace::add_path_tracer(&mut vm, target.mmio_handler.unwrap())?;
    let snapshot = vm.snapshot();

    let mut checkers = vec![];
    for case in tests {
        checkers.push((
            case,
            RequirementsChecker::from_testcase(&mut vm, case).ok_or_else(|| {
                anyhow::format_err!("error resolving symbols in testcase: {case:#?}")
            })?,
        ));
    }

    let mut results = HashMap::new();

    for input in testcases {
        vm.restore(&snapshot);
        path_tracer.clear(&mut vm);
        checkers.iter_mut().for_each(|(_, checker)| checker.reset());

        let input_path = config.workdir.join(format!("queue/{}.bin", input.id));
        let input = MultiStream::from_path(&input_path)?;
        target.get_mmio_handler(&mut vm).unwrap().clone_from(&input);

        target.run(&mut vm)?;
        for entry in path_tracer.get_last_blocks(&mut vm) {
            checkers.retain_mut(|(case, checker)| {
                if checker.check(entry.pc) {
                    results.insert(case.line, TestResult::success(case.line, input_path.clone()));
                    return false;
                }
                true
            })
        }
    }

    Ok(results)
}

struct RequirementsChecker {
    addresses: Vec<Vec<u64>>,
    positions: Vec<usize>,
    found: bool,
}

impl RequirementsChecker {
    fn from_testcase(vm: &mut icicle_vm::Vm, case: &GroundTruthEntry) -> Option<Self> {
        let mut addresses = vec![];
        for requirement in &case.requirements {
            addresses.push(
                requirement
                    .iter()
                    .map(|x| icicle_fuzzing::parse_addr_or_symbol(&x, vm))
                    .collect::<Option<_>>()?,
            );
        }
        Some(Self { positions: vec![0; addresses.len()], addresses, found: false })
    }

    fn reset(&mut self) {
        self.found = false;
        self.positions.iter_mut().for_each(|p| *p = 0);
    }

    fn check(&mut self, address: u64) -> bool {
        if self.found {
            return true;
        }

        for (pos, group) in self.positions.iter_mut().zip(&self.addresses) {
            if group[*pos] == address {
                *pos += 1;
            }
            if *pos >= group.len() {
                self.found = true;
                return true;
            }
        }
        false
    }
}

/// Determine the key to use for the groundtruth file.
fn get_groundtruth_key(elf_path: &Path) -> Option<String> {
    let group = elf_path.parent()?.parent()?.file_name()?.to_str()?;
    let elf = elf_path.file_name()?.to_str()?;
    Some(format!("{group}/{elf}"))
}

#[derive(Debug)]
struct TestResult {
    /// The line number of the testcase in the `groundtruth.csv` test file.
    line: usize,
    /// The path to the input that solves the test on success, or an error message if the test test
    /// was failed.
    result: Result<PathBuf, String>,
}

impl TestResult {
    fn error(line: usize, msg: impl Into<String>) -> Self {
        Self { line, result: Err(msg.into()) }
    }

    fn success(line: usize, input_path: PathBuf) -> TestResult {
        Self { line, result: Ok(input_path) }
    }
}

#[derive(Debug)]
struct GroundTruthEntry {
    line: usize,
    #[allow(unused)]
    testcase: String,
    requirements: Vec<Vec<String>>,
    comment: String,
}

impl GroundTruthEntry {
    fn from_line(fragment: &str, line_number: usize) -> Option<GroundTruthEntry> {
        let mut fields = fragment.split('\t');

        let testcase = fields.next()?;
        let raw_requirements = fields.next()?;
        let comment = fields.next()?;

        let mut requirements = vec![];
        for group in raw_requirements.split("||") {
            requirements.push(group.trim().split("->").map(|x| x.trim().to_string()).collect());
        }

        Some(GroundTruthEntry {
            line: line_number,
            testcase: testcase.to_string(),
            requirements,
            comment: comment.to_string(),
        })
    }
}

fn parse_groundtruth_csv(
    path: std::path::PathBuf,
) -> anyhow::Result<HashMap<String, Vec<GroundTruthEntry>>> {
    // Keep track of all the tests by filename so we can
    let mut tests = HashMap::new();
    let mut add_test = |name: String, entries: Vec<GroundTruthEntry>| {
        if tests.insert(name.clone(), entries).is_some() {
            anyhow::bail!("Duplicate entry for: {}", name)
        }
        Ok(())
    };

    let reader = std::io::BufReader::new(
        std::fs::File::open(&path)
            .with_context(|| format!("failed to open: {}", path.display()))?,
    );

    let mut current_file = None;
    let mut entries_for_file = vec![];
    // Iterate through all lines the csv file, skipping the header field.
    for (i, line) in reader.lines().enumerate().skip(1) {
        let line = line?;
        let line_num = i + 1;
        let mut fragment = line.as_str();

        // Check whether the current line is the start of a new file or a continuation of the
        // previous file.
        if !line.starts_with('\t') {
            let Some((filename, rest)) = line.split_once('\t')
            else {
                anyhow::bail!("Expected \\t character after filename on line: {line_num}");
            };
            fragment = rest;

            // Add all tests for the previous file to the map and start record for the current file.
            if let Some(name) = current_file.replace(filename.to_string()) {
                add_test(name, std::mem::take(&mut entries_for_file))?;
            }
        }
        else {
            anyhow::ensure!(current_file.is_some(), "File missing on line: {line_num}");
            fragment = fragment.trim_start();
        }

        // Parse the testcase for the current line.
        match GroundTruthEntry::from_line(fragment, line_num) {
            Some(entry) => entries_for_file.push(entry),
            None => anyhow::bail!("Invalid entry on line: {line_num}"),
        }
    }

    // Add final test.
    if let Some(name) = current_file {
        add_test(name, entries_for_file)?;
    }

    Ok(tests)
}
