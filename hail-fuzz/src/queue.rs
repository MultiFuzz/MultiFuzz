use std::{
    any::Any,
    collections::{BinaryHeap, HashMap, HashSet, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::Context;
use icicle_fuzzing::CrashKind;
use rand::seq::SliceRandom;

use crate::{
    input::{MultiStream, StreamKey},
    monitor::Monitor,
    MutationKind, Stage, State,
};

pub type InputId = usize;

#[derive(Default, serde::Serialize)]
pub struct StreamMetadata {
    /// The total number of bytes across _all_ executions.
    pub total_bytes: usize,
    /// The number of colorized bytes out of the total bytes that we tried to colorize.
    pub colorized_bytes: (usize, usize),
    /// The number of inputs in the queue that contain this stream
    pub num_inputs: usize,
    /// The number of times this stream cause the fuzzer to stop execution during length extension.
    pub reached_end_of_stream: usize,
    /// Bit flags that capture the sizes of the data read from each peripheral.
    pub seen_sizes: u8,
    /// The number of times a length extension of a particular size has resulted in new coverage.
    #[serde(serialize_with = "serialize_as_vec")]
    pub successful_extensions: HashMap<usize, u64>,
    /// The number of times a length extension of a particular size has failed to discover new
    /// coverage.
    #[serde(serialize_with = "serialize_as_vec")]
    pub failed_extensions: HashMap<usize, u64>,
}

#[derive(Default, serde::Serialize)]
pub struct CorpusMetadata {
    /// The total size (in bytes) of all the inputs in the input queue.
    pub total_input_bytes: usize,
    /// The total number of instructions across any input.
    pub total_instructions: u64,
    /// Metadata collected for each input stream.
    #[serde(serialize_with = "serialize_as_vec")]
    pub streams: HashMap<StreamKey, StreamMetadata>,
}

pub fn serialize_as_vec<S, K, V>(map: &HashMap<K, V>, serializer: S) -> Result<S::Ok, S::Error>
where
    K: serde::Serialize,
    V: serde::Serialize,
    S: serde::Serializer,
{
    serializer.collect_seq(map.iter())
}

pub(crate) struct CorpusStore<D> {
    test_cases: Vec<TestCase<D>>,
    /// The number of testcases that we had the last time the corpus was saved.
    last_save_cases: usize,
    /// When we last saved the input corpus. Used to ensure that the input metadata is saved
    /// occasionally even when no new inputs have been found.
    last_save_time: Instant,
    /// The IDs of inputs that have been replaced in the corpus since last save.
    replaced: Vec<InputId>,
    /// Keeps track of the inputs that hit each block, this is used for input prioritization.
    coverage_hits: HashMap<u32, Vec<InputId>>,
    /// Metadata collected about the corpus
    pub metadata: CorpusMetadata,
    /// The time the corpus was created at.
    start_time: Instant,
}

impl<D> Default for CorpusStore<D> {
    fn default() -> Self {
        Self {
            test_cases: Default::default(),
            last_save_cases: Default::default(),
            last_save_time: Instant::now(),
            replaced: vec![],
            coverage_hits: HashMap::default(),
            metadata: Default::default(),
            start_time: Instant::now(),
        }
    }
}

impl<D> CorpusStore<D> {
    fn add_data(&mut self, data: D) -> InputId {
        let id = self.test_cases.len();
        self.test_cases.push(TestCase {
            data,
            stage_data: HashMap::new(),
            metadata: InputMetadata {
                id,
                found_at: self.start_time.elapsed().as_millis() as u64,
                ..Default::default()
            },
            blocks: None,
            // Inputs are added when they cover new coverage bits, so they are always favoured
            // initially.
            favored: true,
            has_unique_edge: false,
            is_import: false,
        });
        id
    }

    /// Returns the total number of test cases in the corpus
    pub fn inputs(&self) -> usize {
        self.test_cases.len()
    }

    /// Returns a random input from the corpus.
    pub fn random<R: rand::Rng>(&self, rng: &mut R) -> &TestCase<D> {
        self.test_cases.choose(rng).unwrap()
    }

    /// Recomputes the inputs in the corpus that should be favored.
    pub fn recompute_input_prioritization(&mut self) {
        tracing::debug!("recomputing input prioritization");

        self.test_cases.iter_mut().for_each(|x| {
            x.favored = false;
            x.has_unique_edge = false;
        });

        for group in self.coverage_hits.values().filter(|x| !x.is_empty()) {
            let Some(&min) = group.iter().min_by_key(|id| self.test_cases[**id].favored_metric())
            else {
                continue;
            };
            self.test_cases[min].favored = true;
            if group.len() == 1 {
                self.test_cases[min].has_unique_edge = true;
            }
        }
    }

    fn is_favored(&self, id: usize) -> bool {
        self.test_cases[id].favored
    }
}

impl CorpusStore<MultiStream> {
    pub fn maybe_save(&mut self, workdir: &std::path::Path) -> anyhow::Result<()> {
        if self.last_save_cases == self.test_cases.len()
            && self.replaced.is_empty()
            && self.last_save_time.elapsed().as_secs() < 60
        {
            return Ok(());
        }

        if self.last_save_time.elapsed().as_secs() <= 2 {
            return Ok(());
        }

        // Save any new testcases
        for test_case in self.test_cases[self.last_save_cases..]
            .iter()
            .chain(self.replaced.drain(..).map(|id| &self.test_cases[id]))
        {
            std::fs::write(
                workdir.join(format!("queue/{}.bin", test_case.metadata.id)),
                &test_case.data.to_bytes(),
            )?;

            if let Some(blocks) = test_case.blocks.as_ref() {
                use std::io::Write;

                let path = workdir.join(format!("queue/{}.coverage.txt", test_case.metadata.id));
                let mut output = std::io::BufWriter::new(
                    std::fs::File::create(&path)
                        .with_context(|| format!("failed to create: {}", path.display()))?,
                );
                for addr in blocks {
                    writeln!(output, "{addr:#x}")?;
                }
            }
        }

        // Save metadata
        let testcases: Vec<_> = self.test_cases.iter().map(|x| x.metadata.clone()).collect();
        std::fs::write(workdir.join("testcases.json"), serde_json::ser::to_vec(&testcases)?)?;
        std::fs::write(workdir.join("metadata.json"), serde_json::ser::to_vec(&self.metadata)?)?;

        self.last_save_cases = self.test_cases.len();
        self.last_save_time = Instant::now();
        Ok(())
    }

    /// Replace an input in the input corpus with a new version.
    pub fn replace_input(&mut self, id: InputId, state: &State) {
        self.remove_global_metadata(id);
        self.add_to_global_metadata(id, state);

        let entry = &mut self.test_cases[id];
        entry.data.clone_from(&state.input);
        entry.metadata.untrimed_len = entry.metadata.len;
        entry.metadata.len = state.input.total_bytes() as u64;
        entry.metadata.streams = entry.data.count_non_empty_streams() as u64;
        entry.metadata.instructions = state.instructions;

        self.replaced.push(id);
    }

    pub fn add(&mut self, state: &State) -> InputId {
        let id = self.add_data(state.input.clone());
        self.test_cases[id].is_import = state.is_import;
        self.add_to_global_metadata(id, state);
        id
    }

    fn add_to_global_metadata(&mut self, id: InputId, state: &State) {
        self.metadata.total_input_bytes += state.input.total_bytes();
        self.metadata.total_instructions += state.instructions;

        // Ignore crashing inputs from global coverage to avoid them being selected during input
        // prioritization.
        if !state.was_crash() {
            for cov in &state.hit_coverage {
                self.coverage_hits.entry(*cov).or_default().push(id);
            }
        }

        for (addr, entry) in &state.input.streams {
            if entry.bytes.is_empty() {
                continue;
            }
            let stream_metadata = self.metadata.streams.entry(*addr).or_default();
            stream_metadata.num_inputs += 1;
            stream_metadata.total_bytes += entry.bytes.len();
            stream_metadata.seen_sizes |= entry.sizes as u8;
        }
    }

    fn remove_global_metadata(&mut self, id: InputId) {
        let entry = &mut self.test_cases[id];
        self.metadata.total_input_bytes -= entry.data.total_bytes();
        self.metadata.total_instructions -= entry.metadata.instructions;

        // @fixme: avoid this expensive loop
        for entry in self.coverage_hits.values_mut() {
            entry.retain(|x| *x != id);
        }

        for (key, entry) in &entry.data.streams {
            if entry.bytes.is_empty() {
                continue;
            }
            let Some(stream_metadata) = self.metadata.streams.get_mut(key)
            else {
                continue;
            };
            stream_metadata.num_inputs -= 1;
            stream_metadata.total_bytes -= entry.bytes.len();
        }
    }
}

impl<D> std::ops::Index<InputId> for CorpusStore<D> {
    type Output = TestCase<D>;

    fn index(&self, index: InputId) -> &Self::Output {
        &self.test_cases[index]
    }
}

impl<D> std::ops::IndexMut<InputId> for CorpusStore<D> {
    fn index_mut(&mut self, index: InputId) -> &mut Self::Output {
        &mut self.test_cases[index]
    }
}

pub(crate) struct TestCase<D> {
    /// The bytes in memory.
    pub data: D,
    /// Manages stats for individual stages.
    pub stage_data: HashMap<Stage, Box<dyn Any>>,
    /// Metadata stored about this testcase.
    pub metadata: InputMetadata,
    /// The cached block coverage data for this input.
    pub blocks: Option<Vec<u64>>,
    /// Whether this input is prioritized for future mutations, currently set for the smallest
    /// input for each coverage location.
    pub favored: bool,
    /// Set if this testcase reaches a unique edge. Further increased mutation prioritization.
    pub has_unique_edge: bool,
    /// Set when this input was imported from an external source
    pub is_import: bool,
}

impl<D> TestCase<D> {
    pub fn stage_data<T: Default + 'static>(&mut self, stage: Stage) -> &mut T {
        self.stage_data.entry(stage).or_insert_with(|| Box::<T>::default()).downcast_mut().unwrap()
    }

    /// Prefer smaller inputs, but maximize the number of streams that have been found.
    fn favored_metric(&self) -> impl Ord {
        (std::cmp::Reverse(self.metadata.streams), self.metadata.len)
    }

    /// Computes the ratio to use for length extension compared to havoc style mutations for this
    /// input.
    pub fn length_extension_prob(&self) -> f64 {
        if self.metadata.rounds == 0 {
            // First time executing the input prefer length extension.
            return 0.9;
        }

        const ADAPTIVE_EXTENSION_PROB: bool = true;
        if !ADAPTIVE_EXTENSION_PROB {
            return 0.5;
        }

        if self.metadata.finds > 2 || self.is_import {
            // If there multiple finds already for this input then it is likely one of them is a
            // better length extension candidate than this input.
            return 0.1;
        }

        // Otherwise, slighly prefer length extension (because it generally is faster).
        0.6
    }
}

#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub(crate) struct InputMetadata {
    /// A unique identifier assigned to this test case.
    pub id: InputId,
    /// The ID of the parent input that discovered this test-case
    pub parent_id: Option<InputId>,
    /// The length of the input chain required to reach this input.
    pub depth: u64,
    /// The cached length (in bytes) of the input.
    pub len: u64,
    /// The length of the input (in bytes) before the input was trimmed.
    pub untrimed_len: u64,
    /// The number of non-empty streams.
    pub streams: u64,
    /// The number of instructions executed by the VM when running the test case.
    pub instructions: u64,
    /// The number of coverage bits set for this input.
    pub coverage_bits: u64,
    /// The time (since the fuzzer started) in milliseconds that we found this input at.
    pub found_at: u64,
    /// The total time spent executing mutated versions of this input.
    pub time: Duration,
    /// The total number of times a mutated version of this input was mutated.
    pub execs: u64,
    /// The number of times a new path was found by mutating this input.
    pub finds: u64,
    /// The number of times the input has resulted in a hang after mutation.
    pub hangs: u64,
    /// The total number of times the input has resulted in a crash after mutation.
    pub crashes: u64,
    /// The number of executions that were made the last time we saved a mutated input.
    pub last_find: u64,
    /// The largest gap (in executions) since we found a new input. This is used for scalling the
    /// mutation rate during Havoc.
    pub max_find_gap: u64,
    /// The new bits discovered by this input.
    pub new_bits: Vec<u32>,
    /// The stage that the input was discovered in.
    pub stage: Stage,
    /// The mutations that were performed to find this input.
    pub mutation_kinds: Vec<MutationKind>,
    /// The number of times this input as been chosen by the fuzzer.
    pub rounds: u64,
    /// The number of length extensions rounds applied to this input.
    pub length_extension_rounds: u64,
    /// The number of havoc rounds applied to this input.
    pub havoc_rounds: u64,
    /// Whether this was a crashing input.
    pub is_crashing: bool,
}

pub(crate) trait InputSource {
    /// Get the next input the input queue. Returns `None` if the queue is empty.
    fn next_input(&mut self, store: &CorpusStore<MultiStream>) -> Option<InputId>;
}

pub(crate) trait InputQueue: InputSource {
    /// Adds the current fuzzing input from `state` if this queue thinks it is interesting.
    fn add_if_interesting(
        &mut self,
        store: &mut CorpusStore<MultiStream>,
        state: &State,
    ) -> Option<InputId>;
}

#[derive(PartialEq, Eq)]
struct NewInput {
    id: InputId,
    len: usize,
    streams: usize,
    icount: u64,
    new_bits: usize,
}

impl NewInput {
    /// Assigns a weight to the input which is used to determine which of the new inputs we should
    /// try fuzzing first.
    fn weight(&self) -> impl Ord {
        // Fuzz smaller inputs first, but maximize the number of streams that have been found.
        // (std::cmp::Reverse(self.streams), self.len)

        // Fuzz faster inputs that hit more new bits.
        std::cmp::Reverse((self.icount as f64 / self.new_bits as f64).round() as u64)
    }
}

impl PartialOrd for NewInput {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NewInput {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.weight().cmp(&other.weight())
    }
}

/// An input queue that attempts to maximize code coverage
pub(crate) struct CoverageQueue {
    /// A queue of inputs that have previously increased coverage.
    queue: VecDeque<InputId>,

    /// A queue of inputs that have yet to be fuzzed a single time. These are always processed
    /// before existing entries in `queue`.
    new: BinaryHeap<NewInput>,

    /// Approximate number of full iterations of the queue that have been performed.
    pub cycles: usize,

    /// The cycle count that we last found an input at.
    pub found_input_at_cycle: usize,
}

impl CoverageQueue {
    pub fn new() -> Self {
        Self { queue: VecDeque::new(), new: BinaryHeap::new(), cycles: 0, found_input_at_cycle: 0 }
    }

    pub fn new_inputs(&self) -> usize {
        self.new.len()
    }
}

impl InputSource for CoverageQueue {
    fn next_input(&mut self, corpus: &CorpusStore<MultiStream>) -> Option<InputId> {
        let id = match self.new.pop() {
            // Fuzz small, new entries first, but ensure we haven't already found a better input.
            Some(entry) => {
                if corpus.is_favored(entry.id) {
                    entry.id
                }
                else {
                    self.queue.push_back(entry.id);
                    self.queue.pop_front()?
                }
            }
            // Fallback to the next scheduled input,
            None => self.queue.pop_front()?,
        };

        if id == 0 {
            self.cycles += 1;
        }

        self.queue.push_back(id);
        Some(id)
    }
}

impl InputQueue for CoverageQueue {
    fn add_if_interesting(
        &mut self,
        store: &mut CorpusStore<MultiStream>,
        state: &State,
    ) -> Option<InputId> {
        if !state.new_coverage {
            return None;
        }

        self.found_input_at_cycle = self.cycles;
        let id = store.add(state);
        self.new.push(NewInput {
            id,
            streams: state.input.streams.len(),
            len: state.input.total_bytes(),
            icount: state.instructions,
            new_bits: state.new_bits.len(),
        });
        Some(id)
    }
}

/// Determine whether the current input is smaller than an existing entry in the queue that is
/// favored for a particular bit.
pub(crate) fn current_state_is_favored(
    state: &mut State,
    store: &mut CorpusStore<MultiStream>,
) -> bool {
    let len = state.input.total_bytes();
    let mut improvement = false;
    for idx in &state.hit_coverage {
        let best = store.coverage_hits[idx]
            .iter()
            .map(|id| (id, &store.test_cases[*id].metadata))
            .min_by_key(|(_, metadata)| metadata.len);

        let Some((id, metadata)) = best
        else {
            tracing::warn!("No existing input for {idx:#x} but input was not considered new");
            return true;
        };

        if len as f32 * 1.1f32 < metadata.len as f32 {
            tracing::debug!(
                "new input length {len} is better than existing best input id={id}, len={}, for bit={idx:#x}",
                metadata.len
            );
            state.new_bits.push(*idx);
            improvement = true;
        }
    }
    improvement
}

static GLOBAL_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub struct GlobalQueue<D> {
    new: Vec<std::sync::Mutex<Vec<(u64, Arc<D>)>>>,
}

impl<D> GlobalQueue<D> {
    pub fn init(workers: usize) -> Self {
        let new = (0..workers).map(|_| Default::default()).collect();
        Self { new }
    }

    pub fn add_new(&self, from_id: usize, input: D) -> u64 {
        let id = GLOBAL_ID.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        let input = Arc::new(input);
        for (i, entry) in self.new.iter().enumerate() {
            if i != from_id {
                entry.lock().unwrap().push((id, input.clone()));
            }
        }
        id
    }

    pub fn add_for_main(&self, _from_id: usize, input: D) -> u64 {
        let id = GLOBAL_ID.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        self.new[0].lock().unwrap().push((id, Arc::new(input)));
        id
    }

    pub fn take_all(&self, id: usize) -> Vec<(u64, Arc<D>)> {
        self.new[id].lock().unwrap().drain(..).collect()
    }
}

#[derive(Clone)]
pub(crate) struct GlobalRef {
    pub id: usize,
    pub queue: Arc<GlobalQueue<MultiStream>>,
    pub monitor: Option<Arc<Mutex<Monitor>>>,
    pub crashes: Arc<Mutex<HashSet<String>>>,
    pub hangs: Arc<Mutex<HashSet<String>>>,
}

impl GlobalRef {
    pub fn new(
        id: usize,
        queue: Arc<GlobalQueue<MultiStream>>,
        monitor: Option<Arc<Mutex<Monitor>>>,
    ) -> Self {
        Self { id, queue, monitor, crashes: Arc::default(), hangs: Arc::default() }
    }

    pub fn clone_with_id(&self, id: usize) -> Self {
        let mut new = self.clone();
        new.id = id;
        new
    }

    /// Returns whether the fuzzing instance with this reference corresponds to the main fuzzing
    /// instance (which takes care of logging, debugging other additional tasks).
    pub fn is_main_instance(&self) -> bool {
        self.id == 0
    }

    /// Returns whether the fuzzing instance with this reference corresponds any instance except the
    /// main instance.
    pub fn is_worker_instance(&self) -> bool {
        !self.is_main_instance()
    }

    pub fn add_new(&self, input: MultiStream) -> u64 {
        self.queue.add_new(self.id, input.into())
    }

    pub fn add_for_main(&self, input: MultiStream) -> u64 {
        self.queue.add_for_main(self.id, input.into())
    }

    pub fn take_all(&self) -> Vec<(u64, Arc<MultiStream>)> {
        self.queue.take_all(self.id)
    }

    pub fn add_crash_or_hang(&self, key: String, kind: CrashKind) -> bool {
        match kind {
            CrashKind::Hang => self.hangs.lock().unwrap().insert(key),
            _ => self.crashes.lock().unwrap().insert(key),
        }
    }
}
