use anyhow::Context;
use bstr::ByteSlice;
use hashbrown::HashMap;
use icicle_vm::cpu::utils::get_u64;
use rand::Rng;
use rand_distr::Distribution;

use crate::{
    i2s::{
        finder::{self, CmpCursor, Comparisons, ReplacementFinder},
        log_cmplog_data, MAX_ONE_BYTE_MATCHES, MAX_ONE_BYTE_REPLACEMENTS, MAX_STREAM_LEN,
    },
    input::{MultiStream, StreamKey},
    utils::{get_non_empty_streams, get_stream_weights, insert_slice, replace_slice_strided},
    Fuzzer, FuzzerStage, Snapshot, StageExit, StageStartError,
};

pub(crate) struct I2SRandomReplacement {
    comparisons: Comparisons,
    finder: ReplacementFinder,
    streams: Vec<(StreamKey, usize)>,
    stream_distr: rand_distr::WeightedAliasIndex<f64>,
}

impl I2SRandomReplacement {
    pub fn init(fuzzer: &mut Fuzzer) -> Option<Self> {
        let input_id = fuzzer.input_id?;
        tracing::debug!("[{input_id}] multi-stream extend input-to-state stage");

        Snapshot::restore_initial(fuzzer);
        fuzzer.state.input.seek_to_start();

        let (_, comparisons) = finder::capture_comparisons(fuzzer)?;
        if fuzzer.debug.cmplog && fuzzer.global.is_main_instance() {
            if let Some(cmplog) = fuzzer.cmplog {
                let _ = log_cmplog_data(
                    &mut fuzzer.vm,
                    cmplog,
                    &fuzzer.workdir.join(format!("cmplog/{input_id}.ext.cmplog.txt")),
                );
            }
        }

        let streams = get_non_empty_streams(&fuzzer.state.input);
        let stream_distr = get_stream_weights(fuzzer, input_id, &streams);

        Some(Self { comparisons, finder: ReplacementFinder::default(), streams, stream_distr })
    }

    pub fn random_replace(&mut self, fuzzer: &mut Fuzzer) -> Option<()> {
        const MAX_REPLACEMENT_ATTEMPTS: usize = 100;

        let mut num_mutations: u32 = fuzzer.rng.gen_range(1..32);
        for _ in 0..MAX_REPLACEMENT_ATTEMPTS {
            let cmp = self.comparisons.select_random(&mut fuzzer.rng);
            let (_, operands) = self.comparisons.get(cmp)?;

            let (stream_addr, _) = self.streams[self.stream_distr.sample(&mut fuzzer.rng)];
            let stream = fuzzer.state.input.streams.get_mut(&stream_addr)?;

            if stream.cursor as usize == stream.bytes.len() {
                continue;
            }
            let offset = fuzzer.rng.gen_range(stream.cursor as usize..stream.bytes.len());
            self.finder.reset(offset);

            if self.finder.find_match(stream, operands) {
                self.finder.apply_replacement(&mut stream.bytes);
                num_mutations = match num_mutations.checked_sub(1) {
                    Some(x) => x,
                    None => break,
                }
            }
        }

        Some(())
    }
}

pub(crate) struct I2SReplaceStage {
    /// The input we extracted comparisons from.
    base_input: MultiStream,
    /// All the comparisons found in `base_input`.
    comparisons: Comparisons,
    /// The current position in the input we are attempting to find the next replacement from
    cursor: Position,

    /// The number of times a certain value has been matched.
    tried_matches: HashMap<u64, usize>,
    /// The number of times are particular replacement has be used for the current stream.
    tried_replacements: HashMap<u64, usize>,

    /// The total number of replacements that have been attempted.
    total_execs: usize,
    /// The replacement that we are currently trying.
    replacement: Replacement,
    /// The final PC of the initial execution. Used for filtering tokens to insert into the
    /// dictionary.
    end_icount: u64,
    /// All the replacements that were attempted (for debugging).
    attempted: Vec<Replacement>,
}

impl FuzzerStage for I2SReplaceStage {
    fn run(
        fuzzer: &mut Fuzzer,
        stats: &mut crate::monitor::LocalStats,
    ) -> anyhow::Result<StageExit> {
        let mut state = match I2SReplaceStage::start(fuzzer) {
            Ok(data) => data,
            Err(err) => return Ok(err.into()),
        };

        fuzzer.state.reset();
        fuzzer.state.parent = fuzzer.input_id;

        loop {
            Snapshot::restore_initial(fuzzer);
            fuzzer.state.input.clone_from(&state.base_input);
            if state.next_replacement(fuzzer).is_none() {
                break;
            }

            // Try basic replacement:
            state.replacement.apply_simple(&mut fuzzer.state.input);
            if !state.try_exec(fuzzer, stats)? {
                return Ok(StageExit::Interrupted);
            }

            // Try extended replacement:
            if !state.replacement.extended.is_empty() {
                Snapshot::restore_initial(fuzzer);
                fuzzer.state.input.clone_from(&state.base_input);
                state.replacement.apply_extended(&mut fuzzer.state.input);
                state.try_exec(fuzzer, stats)?;
            }
        }

        tracing::debug!("I2S stage complete: {} replacements attempted", state.total_execs);
        if fuzzer.debug.cmplog && fuzzer.global.is_main_instance() {
            let input_id = fuzzer.input_id.unwrap_or(0);
            log_attempted_replacements(
                &state.attempted,
                &fuzzer.workdir.join(format!("cmplog/{input_id}.replacements.csv")),
            )
            .unwrap();
        }

        Ok(StageExit::Finished)
    }
}

impl I2SReplaceStage {
    fn start(fuzzer: &mut Fuzzer) -> Result<Self, StageStartError> {
        // Colorization would have just run before this stage, so the current input is the colorized
        // input.
        fuzzer.state.input.seek_to_start();
        let mut base_input = fuzzer.state.input.clone();

        Snapshot::restore_initial(fuzzer);
        let (_, comparisons) = finder::capture_comparisons(fuzzer).ok_or(StageStartError::Skip)?;

        if fuzzer.debug.cmplog && fuzzer.global.is_main_instance() {
            let input_id = fuzzer.input_id.unwrap_or(0);
            comparisons
                .save_to_file(&fuzzer.workdir.join(format!("cmplog/{input_id}.cmplog.txt")))
                .unwrap();
            if let Some(cmplog) = fuzzer.cmplog {
                log_cmplog_data(
                    &mut fuzzer.vm,
                    cmplog,
                    &fuzzer.workdir.join(format!("cmplog/{input_id}.cmplog_raw.txt")),
                )
                .unwrap();
            }
        }

        // For all non-empty streams, extend them a bit to avoid cases where changes that we make
        // exit due to reaching the end of the input.
        for (_, stream) in &mut base_input.streams {
            if stream.bytes.len() > 8 {
                let start: usize = fuzzer.rng.gen_range(0..stream.bytes.len());
                let len: usize = fuzzer.rng.gen_range(1..=(stream.bytes.len() - start).min(32));
                stream.bytes.extend_from_within(start..start + len);
            }
        }

        Ok(I2SReplaceStage {
            comparisons,
            cursor: Position::default(),
            base_input,
            tried_matches: HashMap::new(),
            tried_replacements: HashMap::new(),
            replacement: Replacement::default(),
            total_execs: 0,
            end_icount: fuzzer.vm.cpu.icount(),
            attempted: vec![],
        })
    }

    fn next_replacement(&mut self, fuzzer: &Fuzzer) -> Option<()> {
        loop {
            if self.cursor.stream >= self.base_input.streams.len() {
                return None;
            }

            let (stream_key, dst) =
                fuzzer.state.input.streams.iter().nth(self.cursor.stream).unwrap();

            self.cursor.finder.offset =
                self.cursor.finder.offset.max(dst.bytes.len().saturating_sub(MAX_STREAM_LEN));

            loop {
                let found = match self.comparisons.get(self.cursor.cmp) {
                    Some((addr, operands)) => match self.cursor.finder.find_match(dst, operands) {
                        true => Some(addr),
                        false => None,
                    },
                    None => {
                        self.cursor.cmp.array += 1;
                        if self.cursor.cmp.array > 4 {
                            break;
                        }
                        self.cursor.cmp.offset = 0;
                        continue;
                    }
                };

                if let Some(addr) = found {
                    if self.hit_replacement_limit(&dst.bytes) {
                        self.cursor.finder.offset += 1;
                        continue;
                    }

                    let offset = self.cursor.finder.offset;
                    self.cursor.finder.offset += 1;

                    self.replacement.cmp_addr = addr;
                    self.replacement.cmp_array = self.cursor.cmp.array;
                    self.replacement.cmp_offset = self.cursor.cmp.offset;
                    self.replacement.stream_key = *stream_key;
                    self.replacement.stream_offset = offset;
                    self.replacement.bytes.clone_from(&self.cursor.finder.replacement);
                    self.replacement.extended.clone_from(&self.cursor.finder.extended_replacement);
                    self.replacement.stride = self.cursor.finder.stride as usize;

                    if fuzzer.debug.cmplog {
                        self.attempted.push(self.replacement.clone());
                    }

                    return Some(());
                }

                self.cursor.cmp.offset += 1;

                let start_offset = dst.bytes.len().saturating_sub(MAX_STREAM_LEN);
                self.cursor.finder.reset(start_offset);
            }

            self.cursor.cmp = CmpCursor::default();
            self.cursor.stream += 1;
            self.tried_matches.clear();
            self.tried_replacements.clear();
        }
    }

    /// Checks if we have hit the replacement limit for the current stream/comparison.
    fn hit_replacement_limit(&mut self, dst: &[u8]) -> bool {
        if self.cursor.finder.replacement.len() > 1 {
            // Multi-byte replacements are sufficiently rare that we can try all of them.
            return false;
        }

        let matching_value = get_u64(self.cursor.finder.get_value_to_replace(dst));
        let tried_match = self.tried_matches.entry(matching_value).or_default();
        let replacement = get_u64(&self.cursor.finder.replacement);
        let tried_replacement = self.tried_replacements.entry(replacement).or_default();

        if *tried_match > MAX_ONE_BYTE_MATCHES || *tried_replacement > MAX_ONE_BYTE_REPLACEMENTS {
            return true;
        }
        *tried_match += 1;
        *tried_replacement += 1;
        false
    }

    fn try_exec(
        &mut self,
        fuzzer: &mut Fuzzer,
        stats: &mut crate::monitor::LocalStats,
    ) -> anyhow::Result<bool> {
        fuzzer.reset_input_cursor().unwrap();
        fuzzer.write_input_to_target().unwrap();
        let Some(exit) = fuzzer.execute()
        else {
            return Ok(false);
        };
        fuzzer.auto_trim_input().unwrap();
        self.total_execs += 1;

        let path_changed = fuzzer.vm.cpu.icount() != self.end_icount;
        // If we executed a different amount of instructions then the replacement we just made had
        // an impact, so store it in the dictionary for future mutations.
        if path_changed && fuzzer.features.auto_dict {
            let item_to_add = self.replacement.get_value_for_dictionary();
            let key = self.replacement.stream_key;
            let dict = fuzzer.dict.entry(key).or_default();
            let sizes = fuzzer.state.input.streams[&key].sizes;
            if dict.add_item(item_to_add, sizes as u8) {
                fuzzer.dict_items += 1;
            }
        }

        fuzzer.check_exit_state(exit)?;
        fuzzer.update_stats(stats);

        Ok(true)
    }
}

#[derive(Default, Debug)]
struct Position {
    /// The stream we are in the middle of mutating.
    stream: usize,
    /// The comparison operands that we are trying to replace.
    cmp: CmpCursor,
    /// The offset within the stream.
    finder: ReplacementFinder,
}

#[derive(Clone, Default)]
struct Replacement {
    cmp_addr: u64,
    cmp_array: u8,
    cmp_offset: usize,
    stream_key: StreamKey,
    stream_offset: usize,
    bytes: Vec<u8>,
    extended: Vec<u8>,
    tmp: Vec<u8>,
    stride: usize,
}

impl Replacement {
    pub(crate) fn apply_simple(&mut self, input: &mut MultiStream) {
        let dst = &mut input.streams.get_mut(&self.stream_key).unwrap().bytes;
        replace_slice_strided(dst, &self.bytes, self.stream_offset, self.stride);
    }

    pub(crate) fn apply_extended(&mut self, input: &mut MultiStream) {
        if self.extended.len() <= self.bytes.len() {
            tracing::error!(
                "expected extended replacement ({} bytes) to be larger than normal replacement ({} bytes)",
                self.extended.len(),
                self.bytes.len()
            );
        }

        let dst = &mut input.streams.get_mut(&self.stream_key).unwrap().bytes;

        // Apply stride to `extended`
        self.tmp.clear();
        self.tmp.extend(
            self.extended.iter().flat_map(|&byte| std::iter::repeat(byte).take(self.stride)),
        );

        // Find the part of the input that overlaps with the replacement
        let len = usize::min(
            self.bytes.len() * self.stride,
            dst.len().saturating_sub(self.stream_offset),
        );
        dst[self.stream_offset..self.stream_offset + len].copy_from_slice(&self.tmp[..len]);
        // Insert the bytes after the replacement.
        insert_slice(dst, &self.tmp[len..], self.stream_offset + len);
    }

    fn get_value_for_dictionary(&self) -> &[u8] {
        // Use extended value for dictionary if we have good value for it, otherwise just use the
        // replacement value.
        match self.extended.len() > self.bytes.len() || self.extended.len() > 4 {
            true => &self.extended,
            false => &self.bytes,
        }
    }
}

fn log_attempted_replacements(
    replacements: &[Replacement],
    path: &std::path::Path,
) -> anyhow::Result<()> {
    use std::io::Write;

    let mut log = std::io::BufWriter::new(
        std::fs::File::create(path)
            .with_context(|| format!("failed to create `{}.txt`", path.display()))?,
    );

    for Replacement {
        cmp_addr,
        cmp_array,
        cmp_offset,
        stream_key,
        stream_offset,
        bytes,
        extended,
        stride,
        ..
    } in replacements
    {
        if *stride != 1 {
            writeln!(
                log,
                "Cmp@{cmp_addr:#x}: cmp[{cmp_array}][{cmp_offset}]: {stream_key:#x}@{stream_offset} ({:?}, {:?}) stride={stride}",
                bytes.as_bstr(),
                extended.as_bstr()
            )?;
        }
        else {
            writeln!(
                log,
                "Cmp@{cmp_addr:#x}: cmp[{cmp_array}][{cmp_offset}]: {stream_key:#x}@{stream_offset} ({:?}, {:?})",
                bytes.as_bstr(),
                extended.as_bstr()
            )?;
        }
    }

    Ok(())
}
