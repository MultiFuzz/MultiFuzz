use hashbrown::HashMap;
use icicle_vm::VmExit;
use rand::Rng;
use rand_distr::{Distribution, WeightedAliasIndex};

use crate::{
    calculate_energy, config,
    input::{MultiStream, StreamKey},
    mutations::{self, Mutation, ALL_MUTATIONS},
    queue::CorpusStore,
    utils::{get_non_empty_streams, get_stream_weights, random_bytes},
    DictionaryRef, Fuzzer, Snapshot, StageData, StageExit,
};

/// A fuzzing stage that applies random mutations to the input.
pub(crate) struct HavocStage {
    attempts: u32,
    mutator: HavocMutator,

    streams: Vec<(StreamKey, usize)>,
    stream_distr: WeightedAliasIndex<f64>,
    streams_to_extend: HashMap<StreamKey, usize>,

    log2_max_mutations: u32,
    max_mutations: u32,
    saved: bool,
}

impl StageData for HavocStage {
    fn start(fuzzer: &mut Fuzzer) -> Result<Self, StageExit> {
        fuzzer.copy_current_input();

        let (Some(id), data) = (fuzzer.input_id, &fuzzer.state.input)
        else {
            return Err(StageExit::Unsupported);
        };

        let streams = get_non_empty_streams(data);
        if streams.is_empty() {
            // Must have at least one non-empty stream.
            return Err(StageExit::Skip);
        }

        let stream_distr = get_stream_weights(fuzzer, id, &streams);
        let mutator = HavocMutator::new();
        let attempts = calculate_energy(fuzzer) as u32;
        let log2_max_mutations = log2_max_mutations(fuzzer);
        let max_mutations = max_mutations(fuzzer);

        fuzzer.corpus[id].metadata.havoc_rounds += 1;

        tracing::trace!(
            "[{id}] havoc for {attempts} attempts with {} max mutations",
            2_u64.pow(log2_max_mutations)
        );
        Ok(Self {
            attempts,
            streams,
            stream_distr,
            mutator,
            log2_max_mutations,
            max_mutations,
            streams_to_extend: HashMap::new(),
            saved: false,
        })
    }

    fn fuzz_one(&mut self, fuzzer: &mut Fuzzer) -> Option<VmExit> {
        self.attempts = self.attempts.checked_sub(1)?;

        Snapshot::restore_initial(fuzzer);
        fuzzer.copy_current_input();
        fuzzer.reset_input_cursor().unwrap();

        self.havoc_v1(fuzzer);

        // Also extend any streams that have caused us to exit because there were too small, these
        // streams will be trimmed back to the correct length as part of `auto_trim_input` if the
        // extension was unnecessary
        let data = &mut fuzzer.state.input;
        for (key, count) in &self.streams_to_extend {
            let bytes = &mut data.streams.entry(*key).or_default().bytes;
            if bytes.len() >= config::MAX_STREAM_LEN {
                continue;
            }

            let local_dict = fuzzer.dict.entry(*key).or_default();
            local_dict.compute_weights();
            let dict = DictionaryRef { local: local_dict, global: &fuzzer.global_dict };
            mutations::extend_input_by(&mut fuzzer.rng, dict, bytes, 4 * count);
        }

        fuzzer.write_input_to_target().unwrap();
        let exit = fuzzer.execute()?;

        // Keep track of the streams that cause us to exit because they are too small.
        if let Some(key) = fuzzer.state.input.last_read {
            *self.streams_to_extend.entry(key).or_default() += 1;
        }

        fuzzer.auto_trim_input().ok()?;

        if fuzzer.debug.havoc && !self.saved {
            let _ = std::fs::write(
                fuzzer.workdir.join(format!("queue/{}.havoc.bin", fuzzer.input_id.unwrap_or(0))),
                fuzzer.state.input.to_bytes(),
            );
            self.saved = true;
        }

        Some(exit)
    }
}

impl HavocStage {
    #[allow(unused)]
    fn havoc_v1(&mut self, fuzzer: &mut Fuzzer) {
        let data = &mut fuzzer.state.input;

        let mut mutations = crate::utils::rand_pow2(&mut fuzzer.rng, self.log2_max_mutations);
        let mut mutations = fuzzer.rng.gen_range(1..=self.max_mutations);
        while mutations > 0 {
            // Select a random stream to mutate.
            let (key, _) = self.streams[self.stream_distr.sample(&mut fuzzer.rng)];
            let bytes = &mut data.streams.get_mut(&key).unwrap().bytes;

            let local_dict = fuzzer.dict.entry(key).or_default();
            local_dict.compute_weights();
            let dict = DictionaryRef { local: local_dict, global: &fuzzer.global_dict };

            // Avoid excess mutations for small streams.
            // let max_mutations_for_stream = match bytes.len() {
            //     ..=8 => 8,
            //     ..=128 => 32,
            //     _ => 64,
            // };
            let max_mutations_for_stream = mutations;
            // Consume some propotion of the total number of mutations on the current stream.
            let num_mutations = fuzzer.rng.gen_range(1..=mutations.min(max_mutations_for_stream));
            mutations -= num_mutations;
            for _ in 0..num_mutations {
                let mutation =
                    self.mutator.havoc_bytes(&mut fuzzer.rng, dict, bytes, key, &fuzzer.corpus, 0);
                if let Some(mutation) = mutation {
                    fuzzer.state.mutation_kinds.push((key, mutation).into());
                }
            }
        }
    }

    #[allow(unused)]
    fn havoc_v2(&mut self, fuzzer: &mut Fuzzer) {
        let Some(input_id) = fuzzer.input_id
        else {
            return;
        };
        let max_find_gap = fuzzer.corpus[input_id].metadata.max_find_gap;

        let data = &mut fuzzer.state.input;
        for &(key, _) in &self.streams {
            // Decided whether this stream should be mutated.
            if fuzzer.rng.gen_bool(0.5) {
                continue;
            }

            let bytes = &mut data.streams.get_mut(&key).unwrap().bytes;
            let local_dict = fuzzer.dict.entry(key).or_default();
            local_dict.compute_weights();
            let dict = DictionaryRef { local: local_dict, global: &fuzzer.global_dict };

            let mutations = fuzzer.rng.gen_range(1..=self.log2_max_mutations);
            for _ in 0..mutations {
                self.mutator.havoc_bytes(&mut fuzzer.rng, dict, bytes, key, &fuzzer.corpus, 0);
            }
        }
    }
}

/// Determine the maximum number of mutations to try. This number increases the longer it takes to
/// find new inputs.
///
/// @todo: these ranges were selected to be similar the havoc stacking factor used by AFL++, but it
/// is possible that there are better values.
fn log2_max_mutations(fuzzer: &Fuzzer) -> u32 {
    let max_find_gap =
        fuzzer.input_id.map(|id| fuzzer.corpus[id].metadata.max_find_gap).unwrap_or(0);
    match max_find_gap {
        ..=1000 => 3,
        ..=10000 => 4,
        ..=100000 => 5,
        ..=1000000 => 6,
        ..=10000000 => 7,
        _ => 8,
    }
}

fn max_mutations(fuzzer: &Fuzzer) -> u32 {
    let max_find_gap =
        fuzzer.input_id.map(|id| fuzzer.corpus[id].metadata.max_find_gap).unwrap_or(0);
    match max_find_gap {
        ..=100 => 4,
        ..=1000 => 8,
        ..=10000 => 16,
        ..=100000 => 32,
        _ => 64,
    }
}

fn mutation_weight(mutation: &Mutation) -> u32 {
    return match mutation {
        Mutation::BitFlip => 20,
        Mutation::ReplaceByte => 40,
        Mutation::IncDec => 10,
        Mutation::InsertByte => 10,
        Mutation::Insert4 => 10,
        Mutation::RemoveByte => 5,
        Mutation::Remove4 => 5,
        Mutation::InterestingValue => 10,
        Mutation::DictReplace => 20,
        Mutation::DictInsert => 20,
        Mutation::StreamSplice => 5,
        Mutation::InnerSplice => 5,
        Mutation::RandomSplice => 5,
        Mutation::RemoveRegion => 1,
    };
    // match mutation {
    //     Mutation::BitFlip => 1,
    //     Mutation::IncDec => 1,

    //     Mutation::ReplaceByte => 4,
    //     Mutation::InsertByte => 4,
    //     Mutation::Insert4 => 4,

    //     Mutation::InterestingValue => 2,
    //     Mutation::DictReplace => 4,
    //     Mutation::DictInsert => 4,

    //     Mutation::StreamSplice => 4,
    //     Mutation::InnerSplice => 4,
    //     Mutation::RandomSplice => 1,

    //     Mutation::RemoveByte => 2,
    //     Mutation::Remove4 => 1,
    //     Mutation::RemoveRegion => 1,
    // }
}

pub struct HavocMutator {
    mutation_distr: WeightedAliasIndex<u32>,
}

impl HavocMutator {
    pub(crate) fn new() -> Self {
        let weights = ALL_MUTATIONS.iter().map(mutation_weight).collect();
        Self { mutation_distr: WeightedAliasIndex::new(weights).unwrap() }
    }

    #[allow(unused)]
    fn random_weights<R: Rng>(rng: &mut R) -> Self {
        let weights = ALL_MUTATIONS.iter().map(|_| rng.gen_range(0..100)).collect();
        let Ok(mutation_distr) = WeightedAliasIndex::new(weights)
        else {
            return HavocMutator::new();
        };
        Self { mutation_distr }
    }

    pub(crate) fn havoc_bytes<R>(
        &self,
        rng: &mut R,
        dict: DictionaryRef,
        input: &mut Vec<u8>,
        key: StreamKey,
        corpus: &CorpusStore<MultiStream>,
        offset: usize,
    ) -> Option<Mutation>
    where
        R: Rng,
    {
        if input.is_empty() {
            random_bytes(rng, input);
            return None;
        }

        let mutation = ALL_MUTATIONS[self.mutation_distr.sample(rng)];
        mutations::apply_mutation(mutation, rng, dict, input, key, corpus, offset);

        if input.is_empty() {
            random_bytes(rng, input);
            return None;
        }

        Some(mutation)
    }
}
