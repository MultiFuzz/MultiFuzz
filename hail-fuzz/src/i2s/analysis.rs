use icicle_fuzzing::cmplog2::{CmpAttr, CmpCallData, CmpInstData};

use crate::{config::SKIP_COMPLEX_COMPARISIONS, i2s::Comparisons};

pub(crate) fn analyse_comparisons(entry: &CmpInstData) -> (ValueKind, ValueKind) {
    let a_kind = match entry.op.arg1 {
        pcode::Value::Var(_) => ValueKind::from_sequence(entry.values.iter().map(|(a, _)| *a)),
        pcode::Value::Const(x, sz) => ValueKind::AlwaysConst(pcode::sxt64(x, sz as u64 * 8) as i64),
    };
    let b_kind = match entry.op.arg2 {
        pcode::Value::Var(_) => ValueKind::from_sequence(entry.values.iter().map(|(_, b)| *b)),
        pcode::Value::Const(x, sz) => ValueKind::AlwaysConst(pcode::sxt64(x, sz as u64 * 8) as i64),
    };
    (a_kind, b_kind)
}

pub(crate) fn add_interesting_inst_cmps(entry: &CmpInstData, output: &mut Comparisons) {
    if SKIP_COMPLEX_COMPARISIONS
        && (entry.op.kind.intersects(
            CmpAttr::IS_LESSER | CmpAttr::IS_GREATER | CmpAttr::IS_OVERFLOW | CmpAttr::IS_FLOAT,
        ))
    {
        // Skip more complex comparison operations.
        return;
    }

    let mut unique_cases = entry.values.clone();
    unique_cases.sort_unstable();
    unique_cases.dedup();

    let (a_kind, b_kind) = analyse_comparisons(entry);
    let size = u8::max(a_kind.min_max().required_bytes(), b_kind.min_max().required_bytes());

    // If there are too many unique cases for this comparison then skip it
    if unique_cases.len() > (1 << size) / 2 {
        return;
    }

    match (a_kind, b_kind) {
        // No data recorded for this comparison
        (ValueKind::Unknown, _) | (_, ValueKind::Unknown) => {}
        // Ignore comparisons between counters and constants (these are typically loop variables).
        (ValueKind::Counter(_), ValueKind::Const(_) | ValueKind::AlwaysConst(_))
        | (ValueKind::Const(_) | ValueKind::AlwaysConst(_), ValueKind::Counter(_)) => {}
        // If one of the comparison values is always const then just add one copy of the operands to
        // the CmpMap.
        (_, ValueKind::AlwaysConst(x)) => {
            for &(a, _) in &entry.values {
                output.add_i64_with_size(entry.addr, (a, x), size);
            }
        }
        (ValueKind::AlwaysConst(x), _) => {
            for &(_, b) in &entry.values {
                output.add_i64_with_size(entry.addr, (b, x), size);
            }
        }
        // Otherwise try to add both
        _ => {
            for &(a, b) in &entry.values {
                output.add_i64_with_size(entry.addr, (a, b), size);
                output.add_i64_with_size(entry.addr, (b, a), size);
            }
        }
    }
}

pub(crate) fn analyse_call_parameters(entry: &CmpCallData) -> (ArrayInfo, ArrayInfo) {
    let a_kind = ArrayInfo::from_sequence(entry.values.iter().map(|(a, _)| a.as_slice()));
    let b_kind = ArrayInfo::from_sequence(entry.values.iter().map(|(_, b)| b.as_slice()));
    (a_kind, b_kind)
}

pub(crate) fn add_interesting_call_cmps(entry: &CmpCallData, output: &mut Comparisons) {
    if entry.has_invalid {
        // This call location was passed non-pointer values, so we ignore comparison values found
        // at this location since the are likely caused
        return;
    }
    let (a_info, b_info) = analyse_call_parameters(entry);
    for &(a, b) in &entry.values {
        if a.starts_with([0; 8].as_slice()) || b.starts_with([0; 8].as_slice()) {
            // Skip cases where the comparison values are all zeroes.
            continue;
        }

        output.call.push((entry.addr, (a, b)));
        if usize::min(a_info.prefix_match, b_info.prefix_match) >= 8 {
            // Avoid excess duplicates if a significant amount of both strings inputs remain the
            // same.
            break;
        }
    }
}

#[derive(Default)]
struct StrideEstimator {
    /// The value the current stride started at.
    start: i64,
    /// The value the current stride ended at.
    end: i64,
    /// The different between the current and previous element.
    stride: Option<i64>,
    /// The number of times we have had the same stride in a row.
    stride_count: usize,
    /// The best estimate we have had of the stride.
    best: Option<Counter>,
    /// The amount of strides that matches with best.
    best_stride_count: usize,
    /// The number of values that did not match the current stride count.
    miss_count: usize,
}

impl StrideEstimator {
    fn update(&mut self, prev: i64, next: i64) {
        if prev == next {
            return;
        }

        let prev_stride = match self.stride {
            Some(stride) => stride,
            None => return self.start_stride(prev, next),
        };

        if prev_stride == next.wrapping_sub(prev) {
            self.stride_count += 1;
            // Keep track of the furthest away we have reached from the current stride.
            self.end = match prev_stride > 0 {
                true => self.end.max(next),
                false => self.end.min(next),
            };
            return;
        }

        if next == self.start {
            // We returned to the start of the stride.
            return;
        }

        // Stride does not match, update the best stride and reset.
        self.finalize_stride(prev_stride);
        self.start_stride(prev, next);
    }

    fn finalize_stride(&mut self, prev_stride: i64) {
        let new = Counter { start: self.start, stride: prev_stride, end: self.end };
        let is_better = self.best.map_or(true, |old| old.steps() < new.steps());
        if is_better {
            self.miss_count += self.best_stride_count;
            self.best = Some(new);
            self.best_stride_count = self.stride_count;
        }
        else {
            self.miss_count += self.stride_count;
        }
    }

    fn start_stride(&mut self, prev: i64, next: i64) {
        self.start = prev;
        self.end = next;
        self.stride = Some(next.wrapping_sub(prev));
        self.stride_count = 1;
    }

    fn finalize(&mut self) -> Option<Counter> {
        if let Some(stride) = self.stride {
            self.finalize_stride(stride);
        }
        self.best
    }

    #[cfg(test)]
    fn from_sequence(items: impl Iterator<Item = i64> + Clone) -> Self {
        let mut estimator = Self::default();
        for (prev, next) in items.clone().zip(items.skip(1)) {
            estimator.update(prev, next);
        }
        estimator
    }
}

#[derive(Debug)]
pub enum ValueKind {
    /// It is impossible for the data to change.
    AlwaysConst(i64),

    /// All data seen is the same value.
    Const(i64),

    /// The data is a counter that increments/decrements at a fixed rate.
    Counter(Counter),

    /// The value at this is a random value within a range.
    Range(MinMax),

    /// We currently know nothing about the value at this data.
    Unknown,
}

impl ValueKind {
    pub fn from_sequence(values: impl Iterator<Item = i64> + Clone) -> Self {
        let mut next_iter = values.clone();

        let start = match next_iter.next() {
            Some(value) => value,
            None => return ValueKind::Unknown,
        };

        let mut min = start;
        let mut max = start;
        let mut count = 0;
        let mut stride_estimator = StrideEstimator::default();

        for (prev, next) in values.zip(next_iter) {
            min = i64::min(min, next);
            max = i64::max(max, next);
            stride_estimator.update(prev, next);
            count += 1;
        }

        // If the value never changes then classifiy it as a constant constant.
        if min == max {
            return Self::Const(min);
        }

        // If we find a stride estimate that matches at least half of the values classify it as a
        // counter.
        if let Some(counter) = stride_estimator.finalize() {
            if count > 3 && counter.steps() > 1 && stride_estimator.miss_count < count / 2 {
                return Self::Counter(counter);
            }
        }

        // Otherwise just report the min and max values in the sequence.
        Self::Range(MinMax { min, max })
    }

    /// Gets the minimum and maximum value of the data.
    pub fn min_max(&self) -> MinMax {
        match self {
            &Self::AlwaysConst(x) | &Self::Const(x) => MinMax { min: x, max: x },
            Self::Counter(counter) => counter.min_max(),
            Self::Range(x) => *x,
            Self::Unknown => MinMax { min: i64::MIN, max: i64::MAX },
        }
    }
}

/// Represents a set of values that increment/decrement at a fixed rate.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Counter {
    /// The initial value of the counter.
    pub start: i64,

    /// The amount the counter increments/decrements each step.
    pub stride: i64,

    /// The final value of the counter.
    pub end: i64,
}

impl Counter {
    /// Return the number of steps between the start and end of the counter.
    fn steps(&self) -> usize {
        if self.stride == 0 {
            return 0;
        }
        (self.end.wrapping_sub(self.start) / self.stride) as usize
    }

    /// Gets the minimum and maximum value of the counter.
    fn min_max(&self) -> MinMax {
        match self.stride > 0 {
            true => MinMax { min: self.start, max: self.end },
            false => MinMax { min: self.end, max: self.start },
        }
    }
}

/// Represents a value that we only know the minimum and maximum of.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct MinMax {
    pub min: i64,
    pub max: i64,
}

impl MinMax {
    /// Returns the number of bytes required to store the range.
    pub fn required_bytes(&self) -> u8 {
        match self.min.abs_diff(0).max(self.max.abs_diff(0)) {
            x if x <= u8::MAX as u64 => 1,
            x if x <= u16::MAX as u64 => 2,
            x if x <= u32::MAX as u64 => 4,
            _ => 8,
        }
    }
}

#[derive(Debug)]
pub struct ArrayInfo {
    pub incrementing: Option<usize>,
    pub is_ascii: bool,
    pub null_terminated: bool,
    pub prefix_match: usize,
}

impl ArrayInfo {
    pub fn new() -> Self {
        Self { incrementing: None, is_ascii: true, null_terminated: true, prefix_match: 0 }
    }

    pub fn from_sequence<'a>(sequence: impl Iterator<Item = &'a [u8]> + Clone) -> Self {
        let mut info = ArrayInfo::new();

        let first = match sequence.clone().next() {
            Some(entry) => entry,
            None => return info,
        };
        info.prefix_match = first.len();

        for array in sequence {
            // @todo: consider optimizing?
            info.prefix_match = first[..info.prefix_match]
                .iter()
                .zip(&array[..info.prefix_match])
                .take_while(|(a, b)| a == b)
                .count();

            let mut is_ascii = true;
            let mut has_null_terminator = false;
            for &byte in array {
                if is_ascii {
                    if byte == 0x00 {
                        has_null_terminator = true;
                        break;
                    }
                    is_ascii = byte.is_ascii();
                }
            }
            info.is_ascii &= is_ascii;
            info.null_terminated &= has_null_terminator;
        }

        info
    }
}

#[test]
fn test_stride_estimator() {
    let values: &[u8] = &[
        0x0, 0x1, 0x2, 0x2, 0x2, 0x2, 0x3, 0x3, 0x3, 0x4, 0x4, 0x4, 0x5, 0x5, 0x5, 0x6, 0x6, 0x6,
        0x7, 0x7, 0x7, 0x8,
    ];
    let mut estimator = StrideEstimator::from_sequence(values.iter().map(|&x| x as i64));
    assert_eq!(estimator.finalize(), Some(Counter { start: 0, stride: 1, end: 8 }));

    let values: &[u32] = &[
        0xffffffff, 0xfffffffe, 0xffffffff, 0xfffffffe, 0xfffffffd, 0xfffffffc, 0xfffffffb,
        0xfffffffa, 0xfffffff9, 0xfffffff8, 0xfffffff7, 0xfffffff6,
    ];
    let mut estimator = StrideEstimator::from_sequence(values.iter().map(|&x| x as i64));
    assert_eq!(
        estimator.finalize(),
        Some(Counter { start: 0xffffffff, stride: -1, end: 0xfffffff6 })
    );
}

#[test]
fn value_size() {
    let values: &[u8] = &[
        0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3c, 0x3d, 0x3e, 0xff,
    ];
    let kind = ValueKind::from_sequence(values.iter().map(|&x| x as i64));
    assert_eq!(kind.min_max().required_bytes(), 1);
}
