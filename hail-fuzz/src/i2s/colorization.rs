use std::collections::BinaryHeap;

use hashbrown::HashMap;
use icicle_fuzzing::CrashKind;

use crate::{
    i2s::MAX_STREAM_LEN,
    input::{MultiStream, StreamKey},
    queue::InputId,
    utils::randomize_input,
    Fuzzer, FuzzerStage, Snapshot, Stage, StageExit, StageStartError,
};

pub(crate) struct ColorizationStage {
    input_id: InputId,
    mutated_input: MultiStream,

    attempts: usize,
    remaining_streams: Vec<(StreamKey, u32)>,
    ranges: BinaryHeap<SortByLen>,

    untainted_ranges: Vec<Range>,
    colorized_bytes: HashMap<StreamKey, usize>,
    original_icount: u64,

    total_execs: usize,
}

impl FuzzerStage for ColorizationStage {
    fn run(
        fuzzer: &mut Fuzzer,
        stats: &mut crate::monitor::LocalStats,
    ) -> anyhow::Result<StageExit> {
        let mut state = match Self::start(fuzzer) {
            Ok(state) => state,
            Err(err) => match err {
                StageStartError::Unsupported => return Ok(StageExit::Unsupported),
                StageStartError::Skip => return Ok(StageExit::Finished),
                StageStartError::Interrupted => return Ok(StageExit::Interrupted),
                StageStartError::Unknown(err) => return Err(err),
            },
        };

        while state.fuzz_one(fuzzer).is_some() {
            fuzzer.update_stats(stats);
        }

        state.end(fuzzer);
        Ok(StageExit::Finished)
    }
}

impl ColorizationStage {
    fn next_range(&mut self) -> Option<Range> {
        let current_stream_range = (|| {
            let next = self.ranges.pop()?.0;
            self.attempts = match self.attempts.checked_sub(1) {
                Some(attempts) => attempts,
                None => {
                    tracing::debug!(
                        "exceeded max colorization attempts for {:#x} ({} ranges remaining)",
                        next.stream,
                        self.ranges.len()
                    );
                    return None;
                }
            };
            Some(next)
        })();

        if let Some(range) = current_stream_range {
            return Some(range);
        }

        self.ranges.clear();
        let (stream, len) = self.remaining_streams.pop()?;
        self.attempts = (len as usize * 2).min(MAX_STREAM_LEN);

        Some(Range { stream, start: len.saturating_sub(MAX_STREAM_LEN as u32), end: len })
    }

    pub fn start(fuzzer: &mut Fuzzer) -> Result<Self, StageStartError>
    where
        Self: Sized,
    {
        let input_id = fuzzer.input_id.ok_or(StageStartError::Skip)?;

        fuzzer.copy_current_input();
        fuzzer.reset_input_cursor().unwrap();
        let mut mutated_input = fuzzer.state.input.clone();
        randomize_input(&mut fuzzer.rng, &mut mutated_input);

        Snapshot::restore_initial(fuzzer);
        fuzzer.write_input_to_target().unwrap();
        fuzzer.execute().ok_or(StageStartError::Interrupted)?;
        let original_icount = fuzzer.vm.cpu.icount();

        let mut remaining_streams = vec![];
        for (addr, stream) in &fuzzer.state.input.streams {
            if !stream.bytes.is_empty() {
                remaining_streams.push((*addr, stream.bytes.len() as u32));
            }
        }

        Ok(Self {
            input_id,
            attempts: 0,
            mutated_input,
            remaining_streams,
            ranges: std::collections::BinaryHeap::default(),
            untainted_ranges: vec![],
            colorized_bytes: HashMap::default(),
            original_icount,
            total_execs: 0,
        })
    }

    fn fuzz_one(&mut self, fuzzer: &mut Fuzzer) -> Option<()> {
        let range = self.next_range()?;

        // Copy random bytes from the mutated input for the current range.
        let input = &mut fuzzer.state.input;
        range.get_mut(input).copy_from_slice(range.get(&self.mutated_input));

        // Execute the modified input in the fuzzer.
        Snapshot::restore_initial(fuzzer);
        fuzzer.reset_input_cursor().unwrap();
        fuzzer.write_input_to_target().unwrap();
        let exit = fuzzer.execute()?;
        self.total_execs += 1;

        let diverged =
            CrashKind::from(exit).is_crash() || fuzzer.vm.cpu.icount != self.original_icount;

        // Check if the fuzzer thinks the input is interesting, Note: this needs to be done now,
        // since the code below may modify the input.
        let _ = fuzzer.check_exit_state(exit);

        // Check that the input executes the same path as before.
        let original_input = &mut fuzzer.corpus[self.input_id];
        if diverged {
            // Input trace no longer matches, so restore the mutated bytes and split the range.
            range.get_mut(&mut fuzzer.state.input).copy_from_slice(range.get(&original_input.data));

            if range.len() > 1 {
                // Split the range in half and push the two halves onto the heap.
                let mid = range.start + (range.len() / 2);
                self.ranges.push(SortByLen(Range {
                    stream: range.stream,
                    start: range.start,
                    end: mid,
                }));
                self.ranges.push(SortByLen(Range {
                    stream: range.stream,
                    start: mid,
                    end: range.end,
                }));
            }
        }
        else {
            *self.colorized_bytes.entry(range.stream).or_default() +=
                (range.end - range.start) as usize;
            self.untainted_ranges.push(range);
        }

        Some(())
    }

    fn end(&mut self, fuzzer: &mut Fuzzer) {
        if fuzzer.debug.cmplog && fuzzer.global.is_main_instance() {
            let _ = std::fs::write(
                &fuzzer.workdir.join(&format!("queue/{}.colorized.bin", self.input_id)),
                &fuzzer.state.input.to_bytes(),
            );
        }

        let mut total_colorized = 0;
        let mut total_attempted = 0;
        for (&addr, &count) in &self.colorized_bytes {
            let attempted = fuzzer.state.input.streams[&addr].bytes.len().min(MAX_STREAM_LEN);

            let metadata = fuzzer.corpus.metadata.streams.entry(addr).or_default();
            metadata.colorized_bytes.0 += count;
            metadata.colorized_bytes.1 += attempted;

            total_colorized += count;
            total_attempted += attempted;
        }
        fuzzer.corpus[self.input_id]
            .stage_data
            .insert(Stage::Colorization, Box::new(self.colorized_bytes.clone()));

        tracing::debug!(
            "{total_colorized} of {} bytes colorized ({:.2}%) in {} attempts",
            fuzzer.state.input.total_bytes(),
            (total_colorized as f64 / total_attempted as f64) * 100.0,
            self.total_execs,
        )
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct Range {
    pub stream: StreamKey,
    pub start: u32,
    pub end: u32,
}

impl Range {
    pub fn len(self) -> u32 {
        self.end - self.start
    }

    pub fn get<'a>(&self, data: &'a MultiStream) -> &'a [u8] {
        &data.streams.get(&self.stream).unwrap().bytes[self.start as usize..self.end as usize]
    }

    pub fn get_mut<'a>(&self, data: &'a mut MultiStream) -> &'a mut [u8] {
        &mut data.streams.get_mut(&self.stream).unwrap().bytes
            [self.start as usize..self.end as usize]
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
struct SortByLen(Range);

impl Ord for SortByLen {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.len().cmp(&other.0.len())
    }
}

impl Eq for SortByLen {}

impl PartialEq for SortByLen {
    fn eq(&self, other: &Self) -> bool {
        self.0.len() == other.0.len()
    }
}

impl PartialOrd for SortByLen {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.len().partial_cmp(&other.0.len())
    }
}
