use rand::{prelude::SliceRandom, Rng};
use rand_distr::Distribution;

use crate::{
    input::{MultiStream, StreamKey},
    queue::CorpusStore,
    utils::{
        insert_slice, insert_slice_strided, rand_range, random_bytes, random_stride,
        replace_slice_strided, select_random_non_empty_stream, INTERESTING_VALUES,
    },
    DictionaryRef, Fuzzer,
};

/// Generate a completely random input
pub(crate) fn random_input(fuzzer: &mut Fuzzer) {
    let stream = &mut fuzzer.state.input;
    if let Some(key) = stream.last_read {
        let bytes = &mut stream.streams.entry(key).or_default().bytes;
        random_bytes(&mut fuzzer.rng, bytes);
    }
}

/// A limit that controls the amount small streams are allowed to be extended by.
const MIN_EXTENSION_LIMIT: usize = 256;

/// Controls the lambda factor for the exponential distribution used for length extension.
/// (1 / factor) corresponds to the mean value of the distribution.
const LENGTH_EXTENSION_LAMBDA: f64 = 1.0 / 16.0;

/// Extend an input by a random number of bytes exponentially distributed.
pub(crate) fn extend_input_by_rand<R: Rng>(
    rng: &mut R,
    factor: f64,
    dict: DictionaryRef,
    input: &mut Vec<u8>,
    extension_limit: usize,
) -> Extension {
    // Small chance try a large extension up to the maximum limit.
    if rng.gen_bool(0.001) {
        return extend_input_by(rng, dict, input, extension_limit);
    }

    let dist = rand_distr::Exp::<f64>::new(LENGTH_EXTENSION_LAMBDA).unwrap();
    let base = (1 + (factor * dist.sample(rng).floor()) as usize).max(4);

    // Unless the input is small, avoid the extension from being more than twice the input length.
    let max_extension = (2 * input.len()).max(MIN_EXTENSION_LIMIT * (factor.floor() as usize));
    let amount = base.min(max_extension).min(extension_limit);
    extend_input_by(rng, dict, input, amount)
}

#[derive(Copy, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum Extension {
    Interesting,
    Prev,
    PrevRepeat,
    Dict,
    DictRepeat,
    Random,
}

static ALL_EXTENSIONS: &[Extension] = &[
    Extension::Interesting,
    Extension::Prev,
    Extension::PrevRepeat,
    Extension::Dict,
    Extension::DictRepeat,
    Extension::Random,
];

pub(crate) fn extend_input_by<R: Rng>(
    rng: &mut R,
    dict: DictionaryRef,
    bytes: &mut Vec<u8>,
    amount: usize,
) -> Extension {
    let new_len = bytes.len() + amount;
    let kind = *ALL_EXTENSIONS.choose(rng).unwrap();
    match kind {
        Extension::Interesting => {
            let value = INTERESTING_VALUES.choose(rng).unwrap();
            while bytes.len() < new_len {
                bytes.extend_from_slice(value);
            }
        }
        Extension::Prev if bytes.len() > 2 => {
            while bytes.len() < new_len {
                bytes.extend_from_within(rand_range(rng, 0, bytes.len(), amount));
            }
        }
        Extension::PrevRepeat if bytes.len() > 2 => {
            let range = rand_range(rng, 0, bytes.len(), amount);
            while bytes.len() < new_len {
                bytes.extend_from_within(range.clone());
            }
        }
        Extension::Dict => {
            while bytes.len() < new_len {
                let (value, strides) = dict.choose(rng);
                let stride = random_stride(rng, strides);
                bytes.extend(value.iter().flat_map(|x| std::iter::repeat(x).take(stride)));
            }
        }
        Extension::DictRepeat => {
            let (value, strides) = dict.choose(rng);
            let stride = random_stride(rng, strides);
            while bytes.len() < new_len {
                bytes.extend(value.iter().flat_map(|x| std::iter::repeat(x).take(stride)));
            }
        }
        Extension::Random | _ => {
            for _ in 0..amount {
                bytes.push(rng.gen());
            }
        }
    }
    kind
}

#[derive(Copy, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum Mutation {
    // Bit manipulation.
    BitFlip,
    IncDec,

    // Byte operations.
    ReplaceByte,
    InsertByte,
    Insert4,

    // Dictionary / interesting value replacements.
    InterestingValue,
    DictReplace,
    DictInsert,

    // Splice operations
    StreamSplice,
    InnerSplice,
    RandomSplice,

    // Removal operations
    RemoveByte,
    Remove4,
    RemoveRegion,
}

pub static ALL_MUTATIONS: &[Mutation] = &[
    Mutation::BitFlip,
    Mutation::IncDec,
    Mutation::ReplaceByte,
    Mutation::InsertByte,
    Mutation::Insert4,
    Mutation::InterestingValue,
    Mutation::DictReplace,
    Mutation::DictInsert,
    Mutation::StreamSplice,
    Mutation::InnerSplice,
    Mutation::RandomSplice,
    Mutation::RemoveByte,
    Mutation::Remove4,
    Mutation::RemoveRegion,
];

pub trait InputSource {
    fn count(&self) -> usize;
    fn choose_random<R: Rng>(&self, rng: &mut R) -> &MultiStream;
}

impl InputSource for CorpusStore<MultiStream> {
    fn count(&self) -> usize {
        self.inputs()
    }

    fn choose_random<R: Rng>(&self, rng: &mut R) -> &MultiStream {
        &self.random(rng).data
    }
}

pub(crate) fn apply_mutation<R, S>(
    mutation: Mutation,
    rng: &mut R,
    dict: DictionaryRef,
    input: &mut Vec<u8>,
    key: StreamKey,
    corpus: &S,
    offset: usize,
) where
    R: Rng,
    S: InputSource,
{
    let len = input.len();
    match mutation {
        Mutation::BitFlip => {
            let bit_offset: usize = rng.gen_range(offset * 8..len * 8);
            let mask = 1 << (bit_offset % 8);
            input[bit_offset / 8] ^= input[bit_offset / 8] & mask;
        }
        Mutation::IncDec => {
            let offset: usize = rng.gen_range(offset..len);
            input[offset] = match rng.gen_bool(0.5) {
                true => input[offset].wrapping_add(1),
                false => input[offset].wrapping_sub(1),
            };
        }

        Mutation::ReplaceByte => {
            let offset: usize = rng.gen_range(offset..len);
            input[offset] = rng.gen();
        }
        Mutation::InsertByte => {
            let offset: usize = rng.gen_range(offset..len + 1);
            input.insert(offset, rng.gen())
        }
        Mutation::Insert4 => {
            let offset: usize = rng.gen_range(offset..len + 1);
            insert_slice(input, &rng.gen::<[u8; 4]>(), offset);
        }

        Mutation::InterestingValue => {
            let offset: usize = rng.gen_range(offset..len);
            let x = INTERESTING_VALUES.choose(rng).unwrap();
            let stride = random_stride(rng, 1 | 2 | 4);
            replace_slice_strided(input, x, offset, stride);
        }
        Mutation::DictReplace => {
            let (x, strides) = dict.choose(rng);
            let x = if rng.gen() { x } else { random_subslice(rng, x) };

            let stride = random_stride(rng, strides);
            replace_slice_strided(input, x, offset, stride);
        }
        Mutation::DictInsert => {
            let (x, strides) = dict.choose(rng);
            let x = if rng.gen() { x } else { random_subslice(rng, x) };
            let stride = random_stride(rng, strides);
            insert_slice_strided(input, x, offset, stride);
        }

        Mutation::StreamSplice => {
            if corpus.count() == 0 {
                // Unable to perform a splice operation without other inputs.
                return;
            }

            // Try up to 10 times to find another input with data for the same stream.
            let other = 'found: {
                for _ in 0..10 {
                    let data = corpus.choose_random(rng);
                    if let Some(stream) = data.streams.get(&key) {
                        if !stream.bytes.is_empty() {
                            break 'found stream;
                        }
                    }
                }
                return;
            };

            splice_input(rng, input, offset, &other.bytes);
        }
        Mutation::InnerSplice => {
            if len < 3 {
                return;
            }
            let range = rand_range(rng, 0, len, 16);
            let bytes = input[range].to_vec();
            let offset: usize = rng.gen_range(offset..len);
            replace_slice_strided(input, &bytes, offset, 1);
        }
        Mutation::RandomSplice => {
            if corpus.count() == 0 {
                return;
            }
            let data = corpus.choose_random(rng);
            let other = match select_random_non_empty_stream(rng, data) {
                Some((_, bytes)) => bytes,
                None => return,
            };
            splice_input(rng, input, offset, other);
        }

        Mutation::RemoveByte => {
            input.remove(rng.gen_range(offset..len));
        }
        Mutation::Remove4 => {
            if len > 3 && len - 3 > offset {
                let start = rng.gen_range(offset..len - 3);
                input.drain(start..start + 4);
            }
        }
        Mutation::RemoveRegion => {
            let start: usize = rng.gen_range(offset..len);
            let end: usize = rng.gen_range(start..len + 1);
            input.drain(start..end);
        }
    }
}

fn random_subslice<'a, R: Rng>(rng: &mut R, slice: &'a [u8]) -> &'a [u8] {
    let start: usize = rng.gen_range(0..slice.len());
    let end: usize = rng.gen_range(start..slice.len());
    &slice[start..=end]
}

fn splice_input<R: Rng>(rng: &mut R, input: &mut Vec<u8>, offset: usize, other: &[u8]) {
    if other.is_empty() {
        return;
    }

    let start: usize = rng.gen_range(0..other.len());
    let end: usize = rng.gen_range(start + 1..other.len() + 1);
    let position: usize = rng.gen_range(offset..input.len());

    let mut result = vec![];
    result.extend_from_slice(&input[..position]);
    result.extend_from_slice(&other[start..end]);
    result.extend_from_slice(&input[position..]);
}
