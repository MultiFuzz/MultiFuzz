use std::collections::VecDeque;

use hashbrown::{HashMap, HashSet};
use icicle_vm::{cpu::ExceptionCode, VmExit};
use rand::Rng;

use crate::{
    calculate_energy, config, i2s,
    input::{MultiStream, StreamKey},
    monitor,
    mutations::extend_input_by_rand,
    DictionaryRef, Fuzzer, FuzzerStage, Snapshot, Stage, StageExit,
};

pub(crate) struct MultiStreamExtendStage {
    /// The different addresses that the program has finished executing at, used for discovering
    /// new inputs for further mutations.
    end_addrs: HashSet<u64>,

    /// The rarest ending address seen for the current input.
    rare_input: Option<(u64, MultiStream)>,

    /// Inputs that we found that end with new mmio address.
    new_starting_inputs: VecDeque<(u32, MultiStream)>,

    /// The input we are extending.
    current_input: MultiStream,

    /// The number of inputs that we fuzzed in order to reach `current_input`.
    local_depth: u32,

    /// The maximum number of extensions to apply per stream.
    log2_max_extensions: u32,

    /// The set of streams that have been observed to be read after `current_input`
    streams_to_mutate: HashMap<StreamKey, f64>,

    /// Data used for input-to-state random replacement.
    i2s_data: Option<i2s::I2SRandomReplacement>,

    /// The number of remaining attempts when to try i2s random replacement for.
    i2s_replacement_attempts: i32,

    /// The amount of energy assigned to this input.
    energy: usize,

    /// The remaining attempts to try for the current input.
    attempts: usize,
    extension_limit: usize,
}

impl MultiStreamExtendStage {
    fn start(fuzzer: &mut Fuzzer) -> Result<Self, StageExit> {
        fuzzer.copy_current_input();

        let mut attempts = calculate_energy(fuzzer) as usize;

        let last_read = Self::crate_snapshot_after(fuzzer, 0)?;
        let mut end_addrs = HashSet::new();
        end_addrs.insert(fuzzer.vm.cpu.read_pc());

        let mut streams_to_mutate = hashbrown::HashMap::new();

        let factor = fuzzer.get_extension_factor(last_read);
        streams_to_mutate.insert(last_read, factor);

        // @todo: consider adjusting the energy for inputs with a long initial execution time,
        // reducing the amount of times this input is scheduled proportionally.

        let log2_max_extensions = log2_max_extensions(fuzzer);
        let extension_limit = extension_limit(fuzzer);

        let is_first_attempt = fuzzer
            .input_id
            .map(|id| fuzzer.corpus[id].metadata.length_extension_rounds == 0)
            .unwrap_or(true);
        if is_first_attempt {
            attempts *= config::INCREASE_EXTENSIONS_ON_FIRST_EXEC_FACTOR;
        }

        tracing::debug!(
            "[{}] {last_read:#x}@{:#x} (factor={factor}, max extensions={}, limit={extension_limit}) len={}, attempts={attempts}, icount={}",
            fuzzer.input_id.unwrap_or(0),
            fuzzer.vm.cpu.read_pc(),
            2_u32.pow(log2_max_extensions),
            fuzzer.state.input.total_bytes(),
            fuzzer.state.instructions,
        );
        if let Some(id) = fuzzer.input_id {
            fuzzer.corpus[id].metadata.length_extension_rounds += 1;
        }

        Ok(Self {
            current_input: fuzzer.state.input.clone(),
            local_depth: 1,
            log2_max_extensions,
            extension_limit,
            new_starting_inputs: VecDeque::new(),
            rare_input: None,
            i2s_data: None,
            i2s_replacement_attempts: 0,
            end_addrs,
            streams_to_mutate,
            energy: attempts,
            attempts,
        })
    }

    fn exec_one(&mut self, fuzzer: &mut Fuzzer) -> Option<VmExit> {
        Snapshot::restore_prefix(fuzzer);
        fuzzer.state.input.clone_from(&self.current_input);

        match self.i2s_data.as_mut() {
            Some(data) => {
                fuzzer.stage = Stage::MultiStreamExtendI2S;
                Snapshot::restore_initial(fuzzer);
                fuzzer.state.input.seek_to_start();
                let _ = data.random_replace(fuzzer);
                match self.i2s_replacement_attempts.checked_sub(1) {
                    Some(new) => self.i2s_replacement_attempts = new,
                    None => self.i2s_data = None,
                }
            }
            None => {
                fuzzer.stage = Stage::MultiStreamExtend;
                self.extend_current_input(fuzzer)
            }
        }

        fuzzer.write_input_to_target().unwrap();
        let exit = fuzzer.execute()?;
        fuzzer.auto_trim_input().ok()?;

        Some(exit)
    }

    fn extend_current_input(&mut self, fuzzer: &mut Fuzzer) {
        let num_extensions = crate::utils::rand_pow2(&mut fuzzer.rng, self.log2_max_extensions);
        let input = &mut fuzzer.state.input;
        let before_len = input.total_bytes();
        for (&addr, &factor) in &self.streams_to_mutate {
            let stream = &mut input.streams.entry(addr).or_default();

            let local_dict = fuzzer.dict.entry(addr).or_default();
            local_dict.compute_weights();
            let dict = DictionaryRef { local: local_dict, global: &fuzzer.global_dict };

            // We extend all streams we end at the same number of times. This may result in some
            // streams ending up oversized, however this will be fixed by the auto-trim step.
            for _ in 0..num_extensions {
                if stream.bytes.len() >= config::MAX_STREAM_LEN {
                    continue;
                }
                let kind = extend_input_by_rand(
                    &mut fuzzer.rng,
                    factor,
                    dict,
                    &mut stream.bytes,
                    self.extension_limit,
                );
                fuzzer.state.mutation_kinds.push((addr, kind).into());
            }
        }

        if input.total_bytes() <= before_len {
            tracing::warn!(
                "[{}] input length ({before_len} bytes) did not increase after applying extensions ({num_extensions} extensions of {} streams)\nmutations: {:x?}",
                fuzzer.input_id.unwrap_or(0),
                self.streams_to_mutate.len(),
                fuzzer.state.mutation_kinds
            );
        }
    }

    fn prepare_new_input(&mut self, fuzzer: &mut Fuzzer) -> Result<(), StageExit> {
        const RARE_EXTENSIONS: bool = true;
        if !RARE_EXTENSIONS {
            return Err(StageExit::Skip);
        }

        if let Some((_, input)) = self.rare_input.take() {
            fuzzer.state.input.clone_from(&input);
            Self::crate_snapshot_after(fuzzer, self.local_depth)?;
            self.current_input.clone_from(&fuzzer.state.input);

            // Occasionally decide to switch to input-to-state mode during length extension.
            const MULTI_STREAM_EXTEND_I2S_STAGE: bool = true;
            if fuzzer.features.cmplog
                && MULTI_STREAM_EXTEND_I2S_STAGE
                && fuzzer.rng.gen_ratio(1, 20)
            {
                self.i2s_data =
                    Some(i2s::I2SRandomReplacement::init(fuzzer).ok_or(StageExit::Skip)?);
                self.i2s_replacement_attempts = 1000;
            }

            // Refresh the attempt count.
            self.attempts = self.energy;
            return Ok(());
        }

        if let Some((depth, input)) = self.new_starting_inputs.pop_back() {
            fuzzer.state.input.clone_from(&input);
            Self::crate_snapshot_after(fuzzer, self.local_depth)?;
            self.current_input.clone_from(&fuzzer.state.input);
            self.local_depth = depth + 1;
            self.attempts = (self.energy / 100).max(1);
            return Ok(());
        }

        Err(StageExit::Skip)
    }

    /// Creates a new snapshot after executing the current input.
    fn crate_snapshot_after(fuzzer: &mut Fuzzer, depth: u32) -> Result<u64, StageExit> {
        // Perform initial execution of current input to obtain a snapshot.
        Snapshot::restore_initial(fuzzer);
        fuzzer.state.input.seek_to_start();
        fuzzer.write_input_to_target().unwrap();
        let exit = fuzzer.execute().ok_or(StageExit::Interrupted)?;

        let VmExit::UnhandledException((ExceptionCode::ReadWatch, exit_address)) = exit
        else {
            // Never attempt to extend inputs that do not end with input exhaustion.
            tracing::trace!("attempted to extend hanging input");
            return Err(StageExit::Skip);
        };
        fuzzer.auto_trim_input()?;

        // Currently we are unable to resume the emulator at the point an interrupt is injected, so
        // rerun the input stopping one instruction early.
        if crate::utils::is_interrupt_stream(exit_address) {
            let until_icount = fuzzer.vm.cpu.icount() - 1;
            tracing::trace!(
                "extending snapshot on interrupt stream, adjusting snapshot to start at: {until_icount}"
            );

            Snapshot::restore_initial(fuzzer);
            fuzzer.state.input.seek_to_start();
            fuzzer.write_input_to_target().unwrap();
            let exit = fuzzer.execute_with_limit(until_icount).ok_or(StageExit::Interrupted)?;

            assert!(matches!(exit, VmExit::InstructionLimit));
            fuzzer.auto_trim_input()?;
        }

        tracing::debug!(
            "[{}] Extension (depth={depth}) starting at: {exit:?}@{:#x}, len={}, icount={}",
            fuzzer.input_id.unwrap_or(0),
            fuzzer.vm.cpu.read_pc(),
            fuzzer.state.input.total_bytes(),
            fuzzer.state.instructions,
        );

        fuzzer.vm.cpu.exception.clear();
        fuzzer.prefix_snapshot = Some(Snapshot::capture(fuzzer));

        Ok(exit_address)
    }
}

impl FuzzerStage for MultiStreamExtendStage {
    fn run(fuzzer: &mut Fuzzer, stats: &mut monitor::LocalStats) -> anyhow::Result<StageExit> {
        let mut state = match MultiStreamExtendStage::start(fuzzer) {
            Ok(data) => data,
            Err(err) => return Ok(err.into()),
        };

        loop {
            if state.attempts == 0 {
                // Check if there any pending partial extensions to try.
                if let Err(exit) = state.prepare_new_input(fuzzer) {
                    // Done with this stage.
                    fuzzer.prefix_snapshot = None;
                    return Ok(exit);
                }
            }
            state.attempts -= 1;

            let Some(exit) = state.exec_one(fuzzer)
            else {
                return Ok(StageExit::Interrupted);
            };

            let mut new_mmio_addr = false;
            if matches!(exit, VmExit::UnhandledException((ExceptionCode::ReadWatch, _))) {
                // If the mutated input ends at a new location then consider saving it, for a second
                // multi-stream extension stage.
                let end_addr = fuzzer.vm.cpu.read_pc();
                if state.end_addrs.insert(end_addr) {
                    state.rare_input = Some((end_addr, fuzzer.state.input.clone()));
                }
                else if state.rare_input.as_ref().map_or(false, |(addr, _)| *addr == end_addr) {
                    // We found the same ending point again (meaning this was not a rare input).
                    state.rare_input = None;
                }

                // If fuzzing stops because a different stream was read from, added to the list of
                // streams we are extending.
                if let Some(addr) = fuzzer.state.input.last_read {
                    // Record metadata for the input causing the exit. This is used to increase
                    // the size of extensions on inputs with a large number of exits.
                    let metadata = fuzzer.corpus.metadata.streams.entry(addr).or_default();
                    metadata.reached_end_of_stream += 1;

                    if let Some(id) = fuzzer.input_id {
                        *fuzzer.corpus[id]
                            .stage_data::<LengthExtData>(Stage::MultiStreamExtend)
                            .stream_exits
                            .entry(addr)
                            .or_default() += 1;
                    }

                    state.streams_to_mutate.entry(addr).or_insert_with(|| {
                        new_mmio_addr = true;
                        fuzzer.get_extension_factor(addr)
                    });
                };
            }

            const DEFER_INPUT_CHECK_ON_LENGTH_EXTENSION: bool = false;
            if new_mmio_addr && DEFER_INPUT_CHECK_ON_LENGTH_EXTENSION {
                // We defer checking the exit status of inputs that hit new MMIO addresses because
                // just extending the stream with anything will hit additional blocks.
                state
                    .new_starting_inputs
                    .push_front((state.local_depth, fuzzer.state.input.clone()));
            }
            else {
                fuzzer.check_exit_state(exit)?;
            }

            save_metadata(fuzzer, &state);
            fuzzer.update_stats(stats);
        }
    }
}

#[derive(Default)]
pub struct LengthExtData {
    stream_exits: HashMap<StreamKey, usize>,
}

impl LengthExtData {
    /// Returns the average (across streams) number of times that we end execution due to reaching
    /// the end of a particular stream.
    pub(crate) fn average_stream_end_execs(&self) -> f64 {
        if self.stream_exits.is_empty() {
            return 1.0;
        }

        let total_stream_exits: usize = self.stream_exits.values().sum();
        total_stream_exits as f64 / self.stream_exits.len() as f64
    }

    /// Returns a factor to use for length extension that attempts to increase the size of inputs
    /// that regularly cause execution to stop.
    pub(crate) fn extension_factor(&self, key: StreamKey) -> f64 {
        let average = self.average_stream_end_execs();
        let stream_exits = self.stream_exits.get(&key).copied().unwrap_or(0) as f64;
        if stream_exits <= average {
            return 1.0;
        }
        let factor = 1.0 + (stream_exits - average).log2().max(0.0);
        debug_assert!(
            !factor.is_nan(),
            "factor={factor} (exits={stream_exits}, average={average})"
        );
        factor
    }
}

fn save_metadata(fuzzer: &mut Fuzzer, state: &MultiStreamExtendStage) {
    if !fuzzer.debug.save_length_extension_metadata {
        return;
    }

    for (addr, _) in &state.streams_to_mutate {
        let prev_size = state.current_input.streams.get(addr).map_or(0, |x| x.bytes.len());
        let size = fuzzer.state.input.streams.get(addr).map_or(0, |x| x.bytes.len());

        let diff = size.saturating_sub(prev_size);

        let metadata = fuzzer.corpus.metadata.streams.entry(*addr).or_default();
        if fuzzer.state.new_coverage {
            *metadata.successful_extensions.entry(diff).or_default() += 1;
        }
        else {
            *metadata.failed_extensions.entry(diff).or_default() += 1;
        }
    }
}

/// Determine the maximum number of length extensions to apply to try.
fn log2_max_extensions(fuzzer: &Fuzzer) -> u32 {
    let max_find_gap =
        fuzzer.input_id.map(|id| fuzzer.corpus[id].metadata.max_find_gap).unwrap_or(0);
    match max_find_gap {
        ..=1000 => 2,
        ..=10000 => 3,
        ..=100000 => 4,
        ..=1000000 => 5,
        _ => 6,
    }
}

/// Determine the maximum size of a single extension to try. The idea is to try small extensions
/// first to avoid inputs becoming too large. This number increases the longer it takes to find
/// new inputs.
fn extension_limit(fuzzer: &Fuzzer) -> usize {
    let max_find_gap =
        fuzzer.input_id.map(|id| fuzzer.corpus[id].metadata.max_find_gap).unwrap_or(0);
    if max_find_gap < 0x1000 {
        return 32;
    }
    max_find_gap.next_power_of_two().min(0x10000) as usize
}
