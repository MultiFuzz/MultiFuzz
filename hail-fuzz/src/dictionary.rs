use hashbrown::HashMap;
use rand::{seq::SliceRandom, Rng};
use rand_distr::Distribution;

use crate::input::StreamKey;

#[derive(serde::Serialize)]
pub struct DictionaryItem {
    /// The value in the dictionary.
    pub value: Vec<u8>,
    /// The number of times the fuzzer attempted to add this value to the dictionary.
    pub count: usize,
    /// Bit flags corresponding the strides seen for this value.
    pub strides: u8,
}

#[derive(Default)]
pub struct Dictionary {
    pub entries: HashMap<u64, DictionaryItem>,
    weights: Option<rand_distr::WeightedAliasIndex<f32>>,
}

/// EXPERIMENT: try to avoid rarely seen comparison operands (which could be dumped from invalid
/// pointers) so that interesting comparisons are tried more frequently.
///
/// Currently disabled. This did not seem to meaningfully change the results.
const ENABLE_DICTIONARY_WEIGHTS: bool = false;

impl Dictionary {
    pub fn compute_weights(&mut self) {
        if self.weights.is_some() || self.entries.is_empty() || !ENABLE_DICTIONARY_WEIGHTS {
            return;
        }
        self.weights = weight_dictionary_by_frequent_items(&self.entries);
    }

    pub fn choose<R: Rng>(&self, rng: &mut R) -> Option<(&[u8], u8)> {
        let index = match ENABLE_DICTIONARY_WEIGHTS {
            true => self.weights.as_ref()?.sample(rng),
            false => rng.gen_range(0..self.entries.len()),
        };
        self.entries.iter().nth(index).map(|(_, item)| (item.value.as_slice(), item.strides))
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() || (ENABLE_DICTIONARY_WEIGHTS && self.weights.is_none())
    }

    pub fn add_item(&mut self, item_to_add: &[u8], stride: u8) -> bool {
        // Skip dictionary entries that are all zeroes, these are already part of the global
        // `INTERESTING_VALUES` dictionary.
        if item_to_add.iter().all(|x| *x == 0) {
            return false;
        }

        // Create a key from the first 8 bytes of the input padded with zeroes.
        let key = {
            let mut tmp = [0; 8];
            let len = item_to_add.len().min(8);
            tmp[..len].copy_from_slice(&item_to_add[..len]);
            u64::from_le_bytes(tmp)
        };
        let mut new = false;
        self.weights = None; // Dictionary weights now need to be recomputed.
        let entry = self.entries.entry(key).or_insert_with(|| {
            new = true;
            DictionaryItem { value: item_to_add.to_vec(), count: 0, strides: 0 }
        });

        entry.count += 1;
        entry.strides |= stride;
        if item_to_add.len() > entry.value.len() {
            entry.value.clear();
            entry.value.extend_from_slice(item_to_add);
        }

        new
    }
}

/// Attempts to avoid spending too much effort on dictionary entries that were rarely seen, since
/// these are likely just noise.
fn weight_dictionary_by_frequent_items(
    entries: &HashMap<u64, DictionaryItem>,
) -> Option<rand_distr::WeightedAliasIndex<f32>> {
    let mut counts: Vec<_> = entries.iter().map(|(_, entry)| entry.count).collect();
    counts.sort_unstable();
    let threshold = if counts.len() > 10 {
        let median = counts[counts.len() / 2];
        median / 2
    }
    else {
        0
    };
    rand_distr::WeightedAliasIndex::new(
        counts.into_iter().map(|x| if x >= threshold { 10.0 } else { 1.0 }).collect(),
    )
    .ok()
}

pub type MultiStreamDict = HashMap<StreamKey, Dictionary>;

#[derive(Copy, Clone)]
pub struct DictionaryRef<'a> {
    pub local: &'a Dictionary,
    pub global: &'a Dictionary,
}

impl<'a> DictionaryRef<'a> {
    pub fn choose<R: Rng>(&self, rng: &mut R) -> (&'a [u8], u8) {
        let dict = match (self.local.is_empty(), self.global.is_empty()) {
            (true, true) => return (*crate::utils::INTERESTING_VALUES.choose(rng).unwrap(), 1),
            (true, false) => self.global,
            (false, true) => self.local,
            (false, false) => match rng.gen_bool(0.8) {
                true => self.local,
                false => self.global,
            },
        };
        dict.choose(rng).unwrap_or((&[], 1))
    }
}
