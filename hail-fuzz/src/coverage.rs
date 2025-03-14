use std::{any::Any, cell::RefCell};

use icicle_fuzzing::{
    FuzzConfig,
    coverage::{ExactBlockCountCoverageInjector, ExactBlockCoverageInjector},
};
use icicle_vm::{InjectorRef, Vm, cpu::StoreRef};

pub const MAP_SIZE: usize = 0x10000;

/// Keeps track of the global coverage seen across the input corpus.
pub trait Coverage {
    /// Get a estimate of the global coverage.
    fn count(&self) -> u64;

    /// Return a reference to the bits in the coverage map.
    fn get_bits<'a>(&self, vm: &'a mut Vm) -> &'a [u64];

    /// Return the the index of any newly hit bits in the current coverage map.
    fn new_bits(&mut self, vm: &mut Vm) -> Vec<u32>;

    /// Merge the local coverage state with the global state, returning true if coverage increased.
    fn merge(&mut self, vm: &mut Vm) -> bool;

    fn serialize(&self, _vm: &mut Vm, _out: &mut String) {}

    /// Called at the very start of execution. Note: typically `restore_local` is used for
    /// resetting testcases between testcase executions.
    fn reset(&mut self, vm: &mut Vm);

    /// Create a snapshot of the (local) coverage state that can be later restored.
    fn snapshot_local(&mut self, vm: &mut Vm) -> Box<dyn Any>;

    /// Restore the (local) coverage state to a previously saved snapshot.
    fn restore_local(&mut self, vm: &mut Vm, snapshot: &Box<dyn Any>);
}

pub trait CoverageAny: Coverage {
    fn as_any(&self) -> &dyn std::any::Any;
}

impl<T: Coverage + 'static> CoverageAny for T {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Count all bits (i.e. ones) within an array
#[must_use]
pub(crate) fn count_all_bits(array: &[u64]) -> u64 {
    array.iter().map(|x| x.count_ones() as u64).sum()
}

/// Returns an iterator of the bit index of all the bits in `array)
pub(crate) fn bit_iter(array: &[u64]) -> impl Iterator<Item = usize> + '_ {
    array.iter().enumerate().flat_map(move |(byte_offset, &byte)| {
        (0..u64::BITS)
            .filter(move |bit| (byte & (1 << bit)) != 0)
            .map(move |bit| byte_offset * 64 + (bit as usize))
    })
}

/// Check whether `new` contains any bits not set in `existing`.
#[inline]
pub fn has_new_bits(existing: &[u64], new: &[u64]) -> bool {
    assert_eq!(existing.len(), new.len());

    // This is done in chunks to aid auto-vectorization.
    //
    // We expect this to (roughly) correspond to a loop with body:
    //
    // ```
    //      vmovdqu ymm0, ymmword ptr [rax + rcx]
    //      vptest  ymm0, ymmword ptr [rsi + rcx]
    //      lea     rcx, [rcx + 32]
    // ```
    for (new, existing) in new.chunks_exact(4).zip(existing.chunks_exact(4)) {
        let change = (!existing[0] & new[0])
            | (!existing[1] & new[1])
            | (!existing[2] & new[2])
            | (!existing[3] & new[3]);
        if change != 0 {
            return true;
        }
    }
    false
}

/// Return the index of any bits within `new` not set in `existing`.
pub fn get_new_bits(existing: &[u64], new: &[u64]) -> Vec<u32> {
    let mut new_bits = vec![];
    for (i, (&old, &new)) in existing.iter().zip(new).enumerate() {
        if old | new == old {
            continue;
        }

        for j in 0..64 {
            if ((old & (1 << j)) == 0) && ((new & (1 << j)) != 0) {
                new_bits.push((i * 64 + j).try_into().unwrap());
            }
        }
    }
    new_bits
}

/// Or the bits from `new` with `old` returning the total number of bits set.
#[cold]
pub fn or_bits(existing: &mut [u64], new: &[u64]) -> usize {
    for (new, existing) in new[..].iter().zip(existing.iter_mut()) {
        *existing |= *new;
    }
    count_all_bits(existing) as usize
}

/// Create a zero initialized coverage array on the heap (note: we do this instead of directly
/// initializing the value [0; _], to avoid excess stack usage in debug mode).
fn init_coverage_array() -> Box<[u64; MAP_SIZE / 8]> {
    let layout = std::alloc::Layout::new::<[u64; MAP_SIZE / 8]>();
    // Safety: `layout` has a non-zero size and `[u64; _]` is valid when zero initializated.
    unsafe {
        let ptr: *mut [u64; MAP_SIZE / 8] = std::alloc::alloc_zeroed(layout).cast();
        if ptr.is_null() {
            panic!("failed to allocate {} bytes for coverage array.", layout.size())
        }
        Box::from_raw(ptr)
    }
}

type EdgeCountSnapshot = Vec<u8>;

pub struct EdgeCountMap {
    hit: Box<[u64; MAP_SIZE / 8]>,
    count: usize,
    storage: StoreRef,
    strategy: BucketStrategy,
}

impl EdgeCountMap {
    pub fn hit_counts(vm: &mut Vm, config: &FuzzConfig) -> Self {
        Self::with_strategy(vm, config, BucketStrategy::Afl)
    }

    pub fn with_strategy(vm: &mut Vm, config: &FuzzConfig, strategy: BucketStrategy) -> Self {
        let bitmap = Box::leak(init_coverage_array());

        let (start_addr, end_addr) = config.get_instrumentation_range(vm).unwrap_or((0, u64::MAX));
        let storage = icicle_fuzzing::coverage::AFLHitCountsBuilder::new()
            .filter(move |block| start_addr <= block.start && block.start <= end_addr)
            .finish(vm, bitmap as *mut u64 as *mut u8, MAP_SIZE as u32);

        if let Some(level) = config.compcov_level {
            icicle_fuzzing::compcov::CompCovBuilder::new()
                .filter(move |block| start_addr <= block.start && block.start <= end_addr)
                .level(level)
                .finish(vm, storage);
        }

        Self { hit: init_coverage_array(), count: 0, storage, strategy }
    }
}

impl Coverage for EdgeCountMap {
    fn count(&self) -> u64 {
        self.count as u64
    }

    fn get_bits<'a>(&self, vm: &'a mut Vm) -> &'a [u64] {
        bytemuck::cast_slice(vm.cpu.trace[self.storage].data())
    }

    fn new_bits(&mut self, vm: &mut Vm) -> Vec<u32> {
        // Calculate coverage buckets.
        let coverage: &mut [u64] = bytemuck::cast_slice_mut(vm.cpu.trace[self.storage].data_mut());
        classify_counts(coverage, self.strategy);

        // Bail early if there are no new bits.
        if !has_new_bits(&self.hit[..], coverage) {
            return vec![];
        }
        // Find which bits are new.
        get_new_bits(&self.hit[..], coverage)
    }

    fn merge(&mut self, vm: &mut Vm) -> bool {
        let coverage: &[u64] = bytemuck::cast_slice(vm.cpu.trace[self.storage].data_mut());

        if has_new_bits(&self.hit[..], coverage) {
            self.count = or_bits(&mut self.hit[..], coverage);
            return true;
        }

        false
    }

    fn serialize(&self, _: &mut Vm, out: &mut String) {
        use std::fmt::Write;
        for (i, entry) in self.hit.iter().enumerate() {
            let bytes = entry.to_le_bytes();
            for (j, byte) in bytes.iter().enumerate().filter(|(_, byte)| **byte != 0) {
                writeln!(out, "{:#06x} = {:#04x}", i * 8 + j, *byte).unwrap();
            }
        }
    }

    fn reset(&mut self, vm: &mut Vm) {
        vm.cpu.trace[self.storage].data_mut().fill(0);
    }

    fn snapshot_local(&mut self, vm: &mut Vm) -> Box<dyn Any> {
        let snapshot: EdgeCountSnapshot = vm.cpu.trace[self.storage].data().to_owned();
        Box::new(snapshot)
    }

    fn restore_local(&mut self, vm: &mut Vm, snapshot: &Box<dyn Any>) {
        let snapshot = snapshot.as_ref().downcast_ref::<EdgeCountSnapshot>().unwrap();
        vm.cpu.trace[self.storage].data_mut().copy_from_slice(snapshot);
    }
}

#[derive(Debug, Copy, Clone)]
pub enum BucketStrategy {
    Afl,
    AflFirst,
    #[allow(unused)]
    SmallCounts,
    Any,
}

#[inline(always)]
fn classify_counts(counts: &mut [u64], strategy: BucketStrategy) {
    let lut = match strategy {
        BucketStrategy::Any => &ANY_BIT,
        BucketStrategy::Afl => &AFL_COUNT_LOOKUP_16,
        BucketStrategy::AflFirst => &AFL_FIRST_COUNT_LOOKUP_16,
        BucketStrategy::SmallCounts => &SMALL_COUNT_LOOKUP_16,
    };

    // Manually unrolling the loop to operate in chunks of 4 results in minor (but measurable) speed
    // improvements
    for entry in counts.chunks_exact_mut(4) {
        // The `counts` array is generally sparse, so most entries will be zero and we can exit
        // early if this condition is true
        if *entry == [0; 4] {
            continue;
        }

        for word in bytemuck::cast_slice_mut(entry) {
            *word = lut[*word as usize];
        }
    }
}

/// Buckets inputs into either hit or not hit.
#[rustfmt::skip]
const fn bucket_any(count: u8) -> u8 {
    match count {
        0 => 0,
        _ => 1,
    }
}

/// An implementation of the count classification scheme from AFL. Each edge count is bucketed such
/// that each bit in the output byte corresponds to a range of counts.
#[rustfmt::skip]
const fn bucket_count_afl(count: u8) -> u8 {
    match count {
        0         => 0b0000_0000,
        1         => 0b0000_0001,
        2         => 0b0000_0010,
        3         => 0b0000_0100,
        4..=7     => 0b0000_1000,
        8..=15    => 0b0001_0000,
        16..=31   => 0b0010_0000,
        32..=127  => 0b0100_0000,
        128..=255 => 0b1000_0000,
    }
}

/// Modified that avoids treating smaller counts as interesting if we already have inputs that reach
/// larger counts.
///
/// EXPERIMENT: Try to avoid saving excess inputs to avoid saving inputs with low numbers of edge
/// hits when a deeper input has already been saved (unused - block hits still appears to perform
/// better).
#[rustfmt::skip]
const fn bucket_count_afl_first(count: u8) -> u8 {
    match count {
        0         => 0b0000_0000,
        1         => 0b0000_0001,
        2         => 0b0000_0011,
        3         => 0b0000_0111,
        4..=7     => 0b0000_1111,
        8..=15    => 0b0001_1111,
        16..=31   => 0b0011_1111,
        32..=127  => 0b0111_1111,
        128..=255 => 0b1111_1111,
    }
}

/// Buckets counts such that entries that are hit a small number of times are consider interesting.
///
/// EXPERIMENT: Alternative bucketing strategy to try to get coverage for individual edges to
/// saturate earlier, (unused - block hits still appears to perform better).
const fn bucket_count_small(count: u8) -> u8 {
    match count {
        0 => 0b0000_0000,
        1 => 0b0000_0001,
        2 => 0b0000_0011,
        3 => 0b0000_0111,
        4 => 0b0000_1111,
        5 => 0b0001_1111,
        6 => 0b0011_1111,
        7 => 0b0111_1111,
        _ => 0b1111_1111,
    }
}

macro_rules! gen_count_lookup_table {
    ($name:ident, $map_count:expr) => {
        static $name: [u16; 0x10000] = {
            const fn gen_count_lookup_16() -> [u16; 0x10000] {
                let mut table8: [u8; 0x100] = [0; 0x100];
                let mut i = 0;
                while i < 0x100 {
                    table8[i] = $map_count(i as u8);
                    i += 1;
                }

                let mut table16: [u16; 0x10000] = [0; 0x10000];
                let mut i = 0;
                while i < 0x10000 {
                    let hi = table8[(i >> 8) & 0xFF] as u16;
                    let lo = table8[i & 0xFF] as u16;
                    table16[i] = (hi << 8) | lo;
                    i += 1;
                }

                table16
            }

            gen_count_lookup_16()
        };
    };
}

gen_count_lookup_table!(ANY_BIT, bucket_any);
gen_count_lookup_table!(AFL_COUNT_LOOKUP_16, bucket_count_afl);
gen_count_lookup_table!(AFL_FIRST_COUNT_LOOKUP_16, bucket_count_afl_first);
gen_count_lookup_table!(SMALL_COUNT_LOOKUP_16, bucket_count_small);

pub fn is_bit_set(cov: &[u64], bit: u32) -> bool {
    let (index, bit) = (bit / 64, bit % 64);
    match cov.get(index as usize) {
        Some(entry) => (entry & (1 << bit)) != 0,
        None => false,
    }
}

type BlockCoverageSnapshot = Vec<u8>;

pub struct BlockCoverage {
    injector: InjectorRef,
    storage: StoreRef,
    count: usize,
    hit: Vec<u64>,
    mapping_cache: RefCell<Vec<(u64, usize)>>,
    bucket_strategy: BucketStrategy,
    pack_bits: bool,
}

impl BlockCoverage {
    pub fn init(vm: &mut Vm, bucket_strategy: BucketStrategy, pack_bits: bool) -> Self {
        if pack_bits && !matches!(bucket_strategy, BucketStrategy::Any) {
            panic!("cannot use bit packed with bucket strategy of: {bucket_strategy:?}");
        }

        let (injector, storage) = match bucket_strategy {
            BucketStrategy::Any if pack_bits => ExactBlockCoverageInjector::register(vm),
            _ => ExactBlockCountCoverageInjector::register(vm),
        };
        Self {
            injector,
            storage,
            count: 0,
            hit: vec![0; 128],
            mapping_cache: RefCell::new(vec![]),
            bucket_strategy,
            pack_bits,
        }
    }

    pub fn get_blocks(&self, vm: &mut Vm) -> Vec<u64> {
        self.update_mapping_cache(vm);
        let mapping = self.mapping_cache.borrow();
        let bitmap: &[u64] = bytemuck::cast_slice(vm.cpu.trace[self.storage].data());

        if self.pack_bits {
            bit_iter(bitmap).map(|x| mapping.get(x).map_or(0, |(addr, _)| *addr)).collect()
        }
        else {
            bitmap
                .iter()
                .enumerate()
                .filter(|(_, entry)| **entry != 0)
                .map(|(i, _)| mapping.get(i).map_or(0, |(addr, _)| *addr))
                .collect()
        }
    }

    /// Returns the blocks corresponding to the bits indexed by `target` that are not set.
    pub fn get_unreached_blocks(&self, vm: &mut Vm, target: &[u32]) -> Vec<u64> {
        self.update_mapping_cache(vm);
        let mapping = self.mapping_cache.borrow();

        let cov: &[u64] = bytemuck::cast_slice(vm.cpu.trace[self.storage].data());
        if self.pack_bits {
            target
                .iter()
                .copied()
                .filter(|bit| !is_bit_set(cov, *bit))
                .map(|bit| mapping.get(bit as usize).map_or(0, |(addr, _)| *addr))
                .collect()
        }
        else {
            target
                .iter()
                .enumerate()
                .filter(|(_, entry)| **entry == 0)
                .map(|(i, _)| mapping.get(i).map_or(0, |(addr, _)| *addr))
                .collect()
        }
    }

    /// Update the mapping of blocks IDs to addresses if the mapping has changed.
    fn update_mapping_cache(&self, vm: &mut Vm) {
        let injector_mapping = match self.pack_bits {
            true => {
                &vm.get_injector_mut::<ExactBlockCoverageInjector>(self.injector).unwrap().mapping
            }
            false => {
                &vm.get_injector_mut::<ExactBlockCountCoverageInjector>(self.injector)
                    .unwrap()
                    .mapping
            }
        };
        if self.mapping_cache.borrow().len() != injector_mapping.len() {
            let mut mapping = self.mapping_cache.borrow_mut();
            mapping.clear();
            mapping.extend(injector_mapping.iter().map(|(addr, idx)| (*addr, *idx)));
            mapping.sort_by_key(|(_, index)| *index);
        }
    }

    /// Translate coverage bits to real blocks.
    pub fn blocks_for(&self, vm: &mut Vm, bits: &[u32]) -> Vec<u64> {
        self.update_mapping_cache(vm);
        let mapping = self.mapping_cache.borrow();
        bits.iter().map(|x| mapping.get(*x as usize).map_or(0, |(addr, _)| *addr)).collect()
    }
}

impl Coverage for BlockCoverage {
    fn count(&self) -> u64 {
        self.count as u64
    }

    fn get_bits<'a>(&self, vm: &'a mut Vm) -> &'a [u64] {
        bytemuck::cast_slice(vm.cpu.trace[self.storage].data())
    }

    fn new_bits(&mut self, vm: &mut Vm) -> Vec<u32> {
        let coverage: &mut [u64] = bytemuck::cast_slice_mut(vm.cpu.trace[self.storage].data_mut());
        if !self.pack_bits {
            classify_counts(coverage, self.bucket_strategy);
        }

        if self.hit.len() != coverage.len() {
            self.hit.resize(coverage.len(), 0);
        }
        assert!(coverage.len() % 4 == 0);

        if !has_new_bits(&self.hit, coverage) {
            return vec![];
        }
        get_new_bits(&self.hit, coverage)
    }

    fn merge(&mut self, vm: &mut Vm) -> bool {
        let coverage: &[u64] = bytemuck::cast_slice(vm.cpu.trace[self.storage].data());
        if self.hit.len() != coverage.len() {
            self.hit.resize(coverage.len(), 0);
        }
        assert!(coverage.len() % 4 == 0);
        self.count = or_bits(&mut self.hit[..], coverage);
        true
    }

    fn reset(&mut self, vm: &mut Vm) {
        vm.cpu.trace[self.storage].data_mut().fill(0);
    }

    fn snapshot_local(&mut self, vm: &mut Vm) -> Box<dyn Any> {
        let snapshot: BlockCoverageSnapshot = vm.cpu.trace[self.storage].data().to_owned();
        Box::new(snapshot)
    }

    fn restore_local(&mut self, vm: &mut Vm, snapshot: &Box<dyn Any>) {
        let snapshot = snapshot.as_ref().downcast_ref::<BlockCoverageSnapshot>().unwrap();
        let dst = vm.cpu.trace[self.storage].data_mut();
        if dst.len() == snapshot.len() {
            dst.copy_from_slice(snapshot);
            return;
        }
        dst[..snapshot.len()].copy_from_slice(snapshot);
        dst[snapshot.len()..].fill(0);
    }

    fn serialize(&self, vm: &mut Vm, out: &mut String) {
        self.update_mapping_cache(vm);

        if self.pack_bits {
            let data: Vec<_> = self
                .mapping_cache
                .borrow()
                .iter()
                .copied()
                .map(|(addr, idx)| CoverageEntry { idx, addr, count: 1 })
                .collect();
            *out = serde_json::to_string(&data).unwrap();
        }
        else {
            let mapping = self.mapping_cache.borrow();
            let mut data = vec![];
            for (i, byte) in self.hit.iter().flat_map(|x| x.to_le_bytes()).enumerate() {
                let Some((addr, idx)) = mapping.get(i)
                else {
                    continue;
                };
                data.push(CoverageEntry { idx: *idx, addr: *addr, count: byte });
            }
            *out = serde_json::to_string(&data).unwrap();
        }
    }
}

#[derive(serde::Serialize)]
struct CoverageEntry {
    idx: usize,
    addr: u64,
    count: u8,
}
