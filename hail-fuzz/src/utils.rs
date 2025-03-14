use std::time::Duration;

use anyhow::Context;
use hashbrown::HashMap;
use rand::{Rng, seq::SliceRandom};

use crate::{Fuzzer, Stage, StreamKey, input::MultiStream};

/// The maximum number of random bytes to generate for a completely random input.
const RANDOM_MAX: usize = 1024;

pub(crate) fn parse_duration_str(name: &str) -> Option<Duration> {
    if let Some(hours) = name
        .strip_suffix("hours")
        .or_else(|| name.strip_suffix("hour"))
        .or_else(|| name.strip_suffix("hrs"))
        .or_else(|| name.strip_suffix("hr"))
        .or_else(|| name.strip_suffix("h"))
    {
        return Some(Duration::from_secs_f64(hours.parse::<f64>().ok()? * 60.0 * 60.0));
    }
    else if let Some(mins) = name
        .strip_suffix("minutes")
        .or_else(|| name.strip_suffix("minute"))
        .or_else(|| name.strip_suffix("mins"))
        .or_else(|| name.strip_suffix("min"))
        .or_else(|| name.strip_suffix("m"))
    {
        return Some(Duration::from_secs_f64(mins.parse::<f64>().ok()? * 60.0));
    }
    else if let Some(seconds) = name
        .strip_suffix("seconds")
        .or_else(|| name.strip_suffix("second"))
        .or_else(|| name.strip_suffix("secs"))
        .or_else(|| name.strip_suffix("sec"))
        .or_else(|| name.strip_suffix("s"))
    {
        return Some(Duration::from_secs_f64(seconds.parse::<f64>().ok()?));
    }
    None
}

/// Fill `buf` with random bytes.
pub(crate) fn random_bytes<R: Rng>(rng: &mut R, buf: &mut Vec<u8>) {
    let len: usize = rng.gen_range(1..RANDOM_MAX);
    buf.truncate(0);
    buf.resize_with(len, || rng.gen())
}

/// Replace all bytes in the slice different values.
pub fn randomize_input<R: Rng>(rng: &mut R, input: &mut MultiStream) {
    for stream in input.streams.values_mut() {
        stream.bytes.iter_mut().for_each(|b| *b = rng.gen::<u8>())
    }
}

pub const INTERESTING_VALUES: &[&[u8]] = &[
    &[0x00], // 0
    &[0x01], // 1
    &[0x10], // 16
    &[0x20], // 64
    &[0x7f], // 127
    &[0x80], // -128
    &[0xff], // -1
    &[b' '],
    &[b'\n'],
    &[b'\r'],
    &[b'\t'],
    &[0x00, 0x00],
    &[0x00, 0x10],
    &[0x10, 0x00],
    &[0xff, 0x7f],
    &[0x00, 0x80],
    &[0xff, 0xff],
    &[0x00, 0x00, 0x00, 0x00],
    &[0x00, 0x00, 0x00, 0x10],
    &[0xff, 0xff, 0xff, 0x7f],
    &[0x00, 0x00, 0x00, 0x80],
    &[0xff, 0xff, 0xff, 0xff],
];

pub fn random_stride<R: Rng>(rng: &mut R, stride_bitmask: u8) -> usize {
    let choices: &[usize] = match stride_bitmask {
        7 => &[1, 2, 4],
        6 => &[2, 4],
        5 => &[1, 4],
        4 => &[4],
        3 => &[1, 2],
        2 => &[2],
        1 => &[1],
        _ => &[1],
    };
    *choices.choose(rng).unwrap_or(&1)
}

/// Generate a random range between `start..=end` with a maximum size of `max_size`.
pub fn rand_range<R: Rng>(
    rng: &mut R,
    start: usize,
    end: usize,
    max_size: usize,
) -> std::ops::Range<usize> {
    let start: usize = rng.gen_range(start..end);
    let len: usize = rng.gen_range(1..=(end - start).min(max_size));
    start..(start + len)
}

pub fn insert_slice(input: &mut Vec<u8>, x: &[u8], offset: usize) {
    let position = offset..((offset + x.len()).min(input.len()));
    input.resize(input.len() + x.len(), 0);
    input.copy_within(position, offset + x.len());
    input[offset..offset + x.len()].copy_from_slice(x);
}

pub fn insert_slice_strided(input: &mut Vec<u8>, x: &[u8], offset: usize, stride: usize) {
    let len = x.len() * stride;

    let position = offset..((offset + len).min(input.len()));
    input.resize(input.len() + len, 0);
    input.copy_within(position, offset + len);

    for (chunk, byte) in input[offset..offset + len].chunks_exact_mut(stride).zip(x) {
        chunk.fill(*byte);
    }
}

pub fn replace_slice_strided(input: &mut Vec<u8>, x: &[u8], offset: usize, stride: usize) {
    let len = x.len() * stride;

    input.resize(usize::max(offset + x.len() * stride, input.len()), 0);
    for (chunk, byte) in input[offset..offset + len].chunks_exact_mut(stride).zip(x) {
        chunk.fill(*byte);
    }
}

pub fn select_random_non_empty_stream<'a, R>(
    rng: &mut R,
    data: &'a MultiStream,
) -> Option<(StreamKey, &'a Vec<u8>)>
where
    R: Rng,
{
    let non_empty_streams = data.streams.iter().filter(|(_, data)| !data.bytes.is_empty()).count();
    if non_empty_streams == 0 {
        return None;
    }
    let stream = rng.gen_range(0..non_empty_streams);
    data.streams
        .iter()
        .filter(|(_, data)| !data.bytes.is_empty())
        .nth(stream)
        .map(|(addr, data)| (*addr, &data.bytes))
}

pub fn load_json<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> anyhow::Result<T> {
    serde_json::from_slice(
        &std::fs::read(path).with_context(|| format!("failed to read: {}", path.display()))?,
    )
    .with_context(|| format!("failed to parse: {}", path.display()))
}

/// Retrivies the address and size of all streams in `data` with an non-zero length.
pub(crate) fn get_non_empty_streams(data: &MultiStream) -> Vec<(StreamKey, usize)> {
    data.streams
        .iter()
        .filter(|(_, data)| !data.bytes.is_empty())
        .map(|(key, data)| (*key, data.bytes.len()))
        .collect()
}

/// Assign weights that control often each stream is mutated based on on the colorization rate.
/// This avoids spending effort on mutating streams that have little to zero impact on the path of
/// the input.
pub(crate) fn get_stream_weights(
    fuzzer: &mut Fuzzer,
    id: usize,
    streams: &[(StreamKey, usize)],
) -> rand_distr::WeightedAliasIndex<f64> {
    // Currently even streams that are impactful often have a very high colorization rate, this can
    // occur when a 32-bit read performed but only the low 8 are used. Currently we only adjust
    // the mutation probability of fully colorized streams.
    const COLORIZATION_THRESHOLD: f64 = 0.99;

    let color =
        fuzzer.corpus[id].stage_data::<hashbrown::HashMap<StreamKey, usize>>(Stage::Colorization);
    let colorization_rates: Vec<_> = streams
        .iter()
        .map(|(key, len)| {
            color
                .get(key)
                .map_or(1.0, |x| *x as f64 / *len.min(&fuzzer.features.max_i2s_bytes) as f64)
        })
        .collect();
    let weights = colorization_rates
        .into_iter()
        .map(|x| if x > COLORIZATION_THRESHOLD { 0.01 } else { 1.0 })
        .collect();

    // We could adjust the weights such that streams with higher colorization rates are
    // mutated more often, however because of oversized reads, interesting data often has a higher
    // than expected colorization rate.
    //
    // let min_rate = *colorization_rates.iter().min_by(|a, b| a.total_cmp(b)).unwrap_or(&0.0);
    // let weights = colorization_rates
    //     .into_iter()
    //     .map(|x| (1.0 - (x - min_rate) / (1.0 - min_rate)).max(0.01))
    //     .collect();

    rand_distr::WeightedAliasIndex::new(weights).unwrap()
}

pub fn rand_pow2<R: Rng>(mut rng: R, log2_max: u32) -> u64 {
    2_f32.powf(1.0 + (rng.gen::<f32>() * (log2_max as f32 - 1.0))).floor() as u64
}

/// Returns a count of the number of bytes within each stream shared with the parent input.
pub fn count_parent_prefix(
    fuzzer: &Fuzzer,
    input_id: usize,
    extension_only: bool,
) -> HashMap<u64, usize> {
    let input = &fuzzer.corpus[input_id];

    if !input.metadata.stage.is_extension() && extension_only {
        return HashMap::new();
    }
    let Some(parent) = input.metadata.parent_id
    else {
        return HashMap::new();
    };
    let parent_data = &fuzzer.corpus[parent].data;

    let mut extensions = HashMap::new();
    for (addr, stream) in &input.data.streams {
        let Some(parent_stream) = parent_data.streams.get(addr)
        else {
            continue;
        };

        let shared_prefix =
            stream.bytes.iter().zip(&parent_stream.bytes).take_while(|(a, b)| a == b).count();
        extensions.insert(*addr, shared_prefix);
    }

    extensions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_slice_empty() {
        let mut input = vec![];
        insert_slice(&mut input, &[1, 2, 3], 0);
        assert_eq!(input, vec![1, 2, 3]);
    }

    #[test]
    fn insert_slice_middle() {
        let mut input = vec![1, 2, 3];
        insert_slice(&mut input, &[4, 5, 6], 2);
        assert_eq!(input, vec![1, 2, 4, 5, 6, 3]);
    }

    #[test]
    fn insert_slice_end() {
        let mut input = vec![1, 2, 3];
        insert_slice(&mut input, &[4, 5, 6], 3);
        assert_eq!(input, vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn insert_strided_empty() {
        let mut input = vec![];
        insert_slice_strided(&mut input, &[1, 2, 3], 0, 2);
        assert_eq!(input, vec![1, 1, 2, 2, 3, 3]);
    }

    #[test]
    fn insert_strided_middle() {
        let mut input = vec![1, 2, 3, 4];
        insert_slice_strided(&mut input, &[5, 6], 2, 2);
        assert_eq!(input, vec![1, 2, 5, 5, 6, 6, 3, 4]);
    }

    #[test]
    fn insert_strided_end() {
        let mut input = vec![1, 2, 3, 4];
        insert_slice_strided(&mut input, &[5, 6], 4, 4);
        assert_eq!(input, vec![1, 2, 3, 4, 5, 5, 5, 5, 6, 6, 6, 6]);
    }

    #[test]
    fn replace_strided() {
        let mut input = vec![1, 2, 3, 4];
        replace_slice_strided(&mut input, &[5, 6], 0, 2);
        assert_eq!(input, vec![5, 5, 6, 6]);
    }

    #[test]
    fn replace_strided_middle() {
        let mut input = vec![1, 2, 3, 4];
        replace_slice_strided(&mut input, &[5, 6], 3, 4);
        assert_eq!(input, vec![1, 2, 3, 5, 5, 5, 5, 6, 6, 6, 6]);
    }

    #[test]
    fn replace_strided_end() {
        let mut input = vec![1, 2, 3, 4];
        replace_slice_strided(&mut input, &[5, 6], 4, 1);
        assert_eq!(input, vec![1, 2, 3, 4, 5, 6]);
    }
}

/// Streams related to interrupts should not be used for i2s replacement.
pub fn is_interrupt_stream(addr: u64) -> bool {
    addr == icicle_cortexm::IRQ_NUMBER_ADDR || addr == icicle_cortexm::TIMER_CHOICE_ADDR
}
