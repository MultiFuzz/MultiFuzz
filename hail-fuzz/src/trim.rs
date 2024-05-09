use icicle_fuzzing::CrashKind;
use rand::{seq::SliceRandom, Rng};

use crate::{
    coverage::{is_bit_set, BlockCoverage},
    input::{MultiStream, StreamKey},
    monitor::LocalStats,
    queue::InputId,
    Fuzzer, FuzzerStage, Snapshot, StageExit,
};

pub(crate) struct TrimStage;

impl FuzzerStage for TrimStage {
    fn run(fuzzer: &mut Fuzzer, stats: &mut LocalStats) -> anyhow::Result<StageExit> {
        let Some(input_id) = fuzzer.input_id
        else {
            return Ok(StageExit::Finished);
        };
        fuzzer.copy_current_input();
        let initial_len = fuzzer.corpus[input_id].data.total_bytes();

        // The bits that we want to ensure that the input still reaches after trimming.
        let bits_to_keep = fuzzer.corpus[input_id].metadata.new_bits.clone();
        tracing::debug!("[{input_id}] attempting to trim keeping {bits_to_keep:?}");

        let mut trim_log = TrimLogger::new(input_id, &fuzzer.workdir);

        // Keeps track of the location to trim next.
        let Some(mut cursor) = MultiStreamTrimCursor::new(&fuzzer.state.input)
        else {
            return Ok(StageExit::Finished);
        };

        // The order we trim things in sometimes matter (e.g., one stream might be unable to be
        // trimmed before another stream). We randomize the order here to ensure that the chosen
        // order is less dependent on the ordering of the stream HashMap to avoid cases where a bad
        // order is always chosen.
        cursor.randomize_trim_order(&mut fuzzer.rng);

        // Keep track best input we have found so far that still hits the target bits.
        let mut attempts = 0;
        let mut saved_input = fuzzer.state.input.clone();
        while let Some((stream_key, offset, len)) = cursor.get(&fuzzer.state.input) {
            // Remove part of the input
            let stream_bytes = &mut fuzzer.state.input.streams.get_mut(&stream_key).unwrap().bytes;
            stream_bytes.drain(offset..offset + len);

            // Run the modifed input in the emulator.
            Snapshot::restore_initial(fuzzer);
            fuzzer.reset_input_cursor().unwrap();
            fuzzer.write_input_to_target().unwrap();
            let Some(exit) = fuzzer.execute()
            else {
                return Ok(StageExit::Interrupted);
            };
            attempts += 1;
            fuzzer.auto_trim_input().unwrap();

            // Check if the input finds a new path or is a crash, and update the monitor.
            fuzzer.check_exit_state(exit)?;
            fuzzer.update_stats(stats);

            // Check whether we still hit all the target bits, and we still exit in the same way.
            let current_bits = fuzzer.coverage.get_bits(&mut fuzzer.vm);
            let diverges = CrashKind::from(exit).is_crash()
                || !bits_to_keep.iter().all(|bit| is_bit_set(current_bits, *bit));
            if diverges {
                // Input no longer hits the target bits skip past this chunk and restore the input.
                fuzzer.state.input.clone_from(&saved_input);
                cursor.skip_current();
                trim_log.log(fuzzer, stream_key, offset, len, &bits_to_keep, false);
            }
            else {
                saved_input.clone_from(&fuzzer.state.input);
                cursor.remove_current();
                trim_log.log(fuzzer, stream_key, offset, len, &bits_to_keep, true);
            }
        }

        // The final execution may have corresponed to an input that reaches a different path, so we
        // do an extra execution here to make sure that the final state matches the target input.
        Snapshot::restore_initial(fuzzer);
        fuzzer.reset_input_cursor().unwrap();
        fuzzer.write_input_to_target().unwrap();
        let _ = fuzzer.execute();

        let final_len = fuzzer.state.input.total_bytes();
        if initial_len != final_len {
            tracing::debug!(
                "trimed input: {initial_len} -> {final_len} bytes ({:.2}%) ({attempts} attempts)",
                (final_len as f64 / initial_len as f64) * 100.0
            );
            fuzzer.state.hit_coverage =
                crate::coverage::bit_iter(fuzzer.coverage.get_bits(&mut fuzzer.vm))
                    .map(|x| x as u32)
                    .collect();
            fuzzer.corpus.replace_input(input_id, &fuzzer.state);
        }
        else {
            tracing::debug!("input not trimmed ({attempts} attempts)");
        }

        Ok(StageExit::Finished)
    }
}

const TRIM_MIN_BYTES: usize = 1;
// const TRIM_START_STEPS: usize = 16;
const TRIM_END_STEPS: usize = 1024;
const MAX_FAILED_ATTEMPTS_FOR_STREAM: usize = 512;

struct MultiStreamTrimCursor {
    streams: Vec<StreamKey>,
    current_stream: usize,
    remove_offset: usize,
    remove_len: usize,
    attempts: usize,
}

impl MultiStreamTrimCursor {
    fn new(input: &MultiStream) -> Option<Self> {
        let streams = input.streams.keys().cloned().collect::<Vec<_>>();
        let stream_addr = streams.first()?;

        let stream_len = input.streams[stream_addr].bytes.len();
        let remove_len = usize::max(stream_len.next_power_of_two() / 2, TRIM_MIN_BYTES);
        let remove_offset = 0;

        Some(Self {
            streams,
            current_stream: 0,
            remove_offset,
            remove_len,
            attempts: MAX_FAILED_ATTEMPTS_FOR_STREAM,
        })
    }

    fn randomize_trim_order<R: Rng>(&mut self, rng: &mut R) {
        self.streams.shuffle(rng)
    }

    fn get(&mut self, input: &MultiStream) -> Option<(StreamKey, usize, usize)> {
        while self.current_stream < self.streams.len() {
            let stream_key = self.streams[self.current_stream];
            let stream_len = input.streams[&stream_key].bytes.len();

            if self.remove_offset < stream_len {
                self.attempts = self.attempts.saturating_sub(1);
                // Adjust the ending length to handle removal at the end of the stream.
                let remove_len = self.remove_len.min(stream_len - self.remove_offset);
                return Some((stream_key, self.remove_offset, remove_len));
            }

            // Check if we should attempt removing smaller chunks of the same stream.
            let min_remove_size =
                usize::max(stream_len.next_power_of_two() / TRIM_END_STEPS, TRIM_MIN_BYTES);
            if self.remove_len > min_remove_size && self.attempts > 0 {
                self.remove_offset = 0; // @todo: adjust the removal location to start at the cursor position.
                self.remove_len /= 2;
                continue;
            }

            // Move to the next stream.
            self.current_stream += 1;
            if self.current_stream >= self.streams.len() {
                break;
            }

            self.attempts = MAX_FAILED_ATTEMPTS_FOR_STREAM;
            let stream_addr = self.streams[self.current_stream];
            let stream_len = input.streams[&stream_addr].bytes.len();
            self.remove_len = usize::max(stream_len.next_power_of_two() / 2, TRIM_MIN_BYTES);
            self.remove_offset = 0;
        }

        None
    }

    /// Update the cursor assuming that the current location has been removed.
    fn remove_current(&mut self) {
        self.attempts = MAX_FAILED_ATTEMPTS_FOR_STREAM;
        // The next location has been shifted forward as a result of the removal, so there is no
        // need to update the cursor.
    }

    /// Update the cursor assuming that the current location has been removed.
    fn skip_current(&mut self) {
        self.remove_offset += self.remove_len;
    }
}

/// A logging mechanism that keeps track of what causes trim to fail when removing subslices.
struct TrimLogger {
    out: Option<std::io::BufWriter<std::fs::File>>,
}

impl TrimLogger {
    fn new(input_id: InputId, workdir: &std::path::Path) -> Self {
        if icicle_fuzzing::parse_bool_env("LOG_TRIM").unwrap().unwrap_or(false) {
            Self {
                out: Some(std::io::BufWriter::new(
                    std::fs::File::create(workdir.join(format!("queue/{input_id}_trim.txt")))
                        .unwrap(),
                )),
            }
        }
        else {
            Self { out: None }
        }
    }

    fn log(
        &mut self,
        fuzzer: &mut Fuzzer,
        stream: StreamKey,
        offset: usize,
        len: usize,
        bits_to_keep: &[u32],
        success: bool,
    ) {
        use std::io::Write;
        if let Some(out) = self.out.as_mut() {
            if success {
                writeln!(out, "{stream:#x} trim({offset},{len}) success").unwrap();
            }
            else if let Some(cov) = fuzzer.coverage.as_any().downcast_ref::<BlockCoverage>() {
                let unreached = cov.get_unreached_blocks(&mut fuzzer.vm, bits_to_keep);
                writeln!(out, "{stream:#x} trim({offset},{len}) fail: {unreached:x?}").unwrap();
            }
        }
    }
}
