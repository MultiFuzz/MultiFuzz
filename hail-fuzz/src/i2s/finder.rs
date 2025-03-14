use icicle_vm::VmExit;
use rand::{Rng, seq::SliceRandom};

use crate::{
    Fuzzer,
    i2s::analysis::{add_interesting_call_cmps, add_interesting_inst_cmps},
    input::StreamData,
    utils::insert_slice,
};

/// Capture all the comparisons discovered by executing the current input.
///
/// Note: This function does not reset the fuzzer's state to the original snapshot.
pub(crate) fn capture_comparisons(fuzzer: &mut Fuzzer) -> Option<(VmExit, Comparisons)> {
    fuzzer.write_input_to_target().unwrap();

    let Some(cmplog) = fuzzer.cmplog
    else {
        return None;
    };
    cmplog.set_enabled(&mut fuzzer.vm.cpu, true);
    let exit = fuzzer.execute()?;
    cmplog.set_enabled(&mut fuzzer.vm.cpu, false);

    let mut comparisons = Comparisons::default();
    for entry in cmplog.get_inst_log(&mut fuzzer.vm.cpu) {
        add_interesting_inst_cmps(entry, &mut comparisons);
    }
    for entry in cmplog.get_call_log(&mut fuzzer.vm.cpu) {
        add_interesting_call_cmps(entry, &mut comparisons);
    }
    comparisons.dedup();

    Some((exit, comparisons))
}

#[derive(Default)]
pub(crate) struct Comparisons {
    pub u8: Vec<(u64, (u8, u8))>,
    pub u16: Vec<(u64, (u16, u16))>,
    pub u32: Vec<(u64, (u32, u32))>,
    pub u64: Vec<(u64, (u64, u64))>,
    pub call: Vec<(u64, ([u8; 64], [u8; 64]))>,
}

impl Comparisons {
    pub fn add_i64_with_size(&mut self, addr: u64, (a, b): (i64, i64), size: u8) {
        if a == b {
            // Don't add equal values
            return;
        }
        if let (0, 1) | (1, 0) = (a, b) {
            // Avoid comparisons that look like booleans.
            return;
        }

        match size {
            1 => self.u8.push((addr, (a as u8, b as u8))),
            2 => self.u16.push((addr, (a as u16, b as u16))),
            4 => self.u32.push((addr, (a as u32, b as u32))),
            8 => self.u64.push((addr, (a as u64, b as u64))),
            _ => panic!("invalid size of value: {size}"),
        }
    }

    fn dedup(&mut self) {
        macro_rules! sort_and_dedup {
            ($arr:expr) => {{
                $arr.sort_unstable_by_key(|(_, k)| *k);
                $arr.dedup_by_key(|(_, k)| *k);
                $arr.sort_unstable();
            }};
        }

        sort_and_dedup!(self.u8);
        sort_and_dedup!(self.u16);
        sort_and_dedup!(self.u32);
        sort_and_dedup!(self.u64);
        sort_and_dedup!(self.call);
    }

    pub fn save_to_file(&self, path: &std::path::Path) -> anyhow::Result<()> {
        use std::io::Write;

        let mut writer = std::io::BufWriter::new(std::fs::File::create(path)?);
        for (addr, (a, b)) in &self.u8 {
            writeln!(writer, "0x{addr:04x}: ({a:02x}, {b:02x})")?;
        }
        for (addr, (a, b)) in &self.u16 {
            writeln!(writer, "0x{addr:04x}: ({a:04x}, {b:04x})")?;
        }
        for (addr, (a, b)) in &self.u32 {
            writeln!(writer, "0x{addr:04x}: ({a:08x}, {b:08x})")?;
        }
        for (addr, (a, b)) in &self.u64 {
            writeln!(writer, "0x{addr:04x}: ({a:016x}, {b:016x})")?;
        }

        for (addr, (a, b)) in &self.call {
            writeln!(
                writer,
                "0x{addr:04x}: ({}, {})",
                icicle_vm::cpu::utils::hex(a.as_slice()),
                icicle_vm::cpu::utils::hex(b.as_slice())
            )?;
        }

        Ok(())
    }

    pub fn len(&self) -> usize {
        self.u8.len() + self.u16.len() + self.u32.len() + self.u64.len() + self.call.len()
    }

    pub(crate) fn get(&self, cursor: CmpCursor) -> Option<(u64, Operands)> {
        match cursor.array {
            0 => self.u8.get(cursor.offset).map(|&(addr, operands)| (addr, operands.into())),
            1 => self.u16.get(cursor.offset).map(|&(addr, operands)| (addr, operands.into())),
            2 => self.u32.get(cursor.offset).map(|&(addr, operands)| (addr, operands.into())),
            3 => self.u64.get(cursor.offset).map(|&(addr, operands)| (addr, operands.into())),
            4 => self.call.get(cursor.offset).map(|(addr, (a, b))| (*addr, Operands::Bytes(a, b))),
            _ => None,
        }
    }

    #[allow(unused)]
    pub(crate) fn shuffle_entries<R: Rng>(&mut self, rng: &mut R) {
        self.u8.shuffle(rng);
        self.u16.shuffle(rng);
        self.u32.shuffle(rng);
        self.u64.shuffle(rng);
        self.call.shuffle(rng);
    }

    pub(crate) fn select_random<R: Rng>(&self, rng: &mut R) -> CmpCursor {
        let total = self.len();
        if total == 0 {
            return CmpCursor { array: 0, offset: 0 };
        }
        self.cursor_from_offset(rng.gen_range(0..total))
    }

    fn cursor_from_offset(&self, mut offset: usize) -> CmpCursor {
        let mut array = 0;

        if offset < self.u8.len() {
            return CmpCursor { array, offset };
        }
        offset -= self.u8.len();
        array += 1;

        if offset < self.u16.len() {
            return CmpCursor { array, offset };
        }
        offset -= self.u16.len();
        array += 1;

        if offset < self.u32.len() {
            return CmpCursor { array, offset };
        }
        offset -= self.u32.len();
        array += 1;

        if offset < self.u64.len() {
            return CmpCursor { array, offset };
        }
        offset -= self.u64.len();
        array += 1;

        CmpCursor { array, offset }
    }
}

pub(crate) enum Operands<'a> {
    U8(u8, u8),
    U16(u16, u16),
    U32(u32, u32),
    U64(u64, u64),
    Bytes(&'a [u8; 64], &'a [u8; 64]),
}

macro_rules! impl_operands_from_tuple {
    ($ty:ty, $name:ident) => {
        impl From<($ty, $ty)> for Operands<'static> {
            fn from((a, b): ($ty, $ty)) -> Self {
                Self::$name(a, b)
            }
        }
    };
}

impl_operands_from_tuple!(u8, U8);
impl_operands_from_tuple!(u16, U16);
impl_operands_from_tuple!(u32, U32);
impl_operands_from_tuple!(u64, U64);

#[derive(Default, Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub(crate) struct CmpCursor {
    pub array: u8,
    pub offset: usize,
}

#[derive(Debug)]
pub(crate) struct ReplacementFinder {
    pub offset: usize,
    pub replacement: Vec<u8>,
    pub extended_replacement: Vec<u8>,
    pub stride: u8,
    match_strided_ints: bool,
}

impl ReplacementFinder {
    pub(crate) fn new(match_strided_ints: bool) -> Self {
        Self {
            match_strided_ints,
            offset: 0,
            replacement: Vec::new(),
            extended_replacement: Vec::new(),
            stride: 1,
        }
    }

    pub(crate) fn reset(&mut self, offset: usize) {
        self.offset = offset;
        self.replacement.clear();
        self.extended_replacement.clear();
    }

    /// Returns the value that we will replace in `dst`
    pub(crate) fn get_value_to_replace<'a>(&self, dst: &'a [u8]) -> &'a [u8] {
        let len = self.replacement.len().min(dst.len().saturating_sub(self.offset));
        &dst[self.offset..self.offset + len]
    }

    /// Apply the current replacement to `dst` adjusting the current offset.
    pub(crate) fn apply_replacement_simple(&mut self, dst: &mut Vec<u8>) {
        let len = self.replacement.len().min(dst.len().saturating_sub(self.offset));
        dst[self.offset..self.offset + len].copy_from_slice(&self.replacement[..len]);
    }

    pub(crate) fn apply_replacement_extended(&mut self, dst: &mut Vec<u8>) {
        if self.extended_replacement.len() < self.replacement.len()
            && self.extended_replacement.len() <= 2
        {
            return;
        }

        let len = self.replacement.len().min(dst.len().saturating_sub(self.offset));
        dst[self.offset..self.offset + len].copy_from_slice(&self.extended_replacement[..len]);
        insert_slice(dst, &self.extended_replacement[len..], self.offset + len);
    }

    pub(crate) fn apply_replacement(&mut self, dst: &mut Vec<u8>) {
        if self.extended_replacement.len() <= self.replacement.len() {
            self.apply_replacement_simple(dst)
        }
        self.apply_replacement_extended(dst)
    }

    pub fn find_match(&mut self, target: &StreamData, operands: Operands) -> bool {
        self.replacement.clear();
        self.extended_replacement.clear();
        self.stride = 1;
        match operands {
            Operands::U8(a, b) => self.find_int_match(target, a.to_ne_bytes(), b.to_ne_bytes()),
            Operands::U16(a, b) => self.find_int_match(target, a.to_ne_bytes(), b.to_ne_bytes()),
            Operands::U32(a, b) => self.find_int_match(target, a.to_ne_bytes(), b.to_ne_bytes()),
            Operands::U64(a, b) => self.find_int_match(target, a.to_ne_bytes(), b.to_ne_bytes()),
            Operands::Bytes(a, b) => self.find_prefix_match(target, a, b),
        }
    }

    fn find_int_match<const N: usize>(
        &mut self,
        target: &StreamData,
        v0: [u8; N],
        v1: [u8; N],
    ) -> bool {
        let start = self.offset;
        if self.find_full_match(&target.bytes, v0, v1) {
            return true;
        }
        if N > 1 && self.match_strided_ints {
            self.offset = start;
            return self.find_prefix_match(target, &v0, &v1);
        }
        false
    }

    /// Starting from the current offset find the next loction in `dst` that matches one of the
    /// operands in `v`. If a match is found, `true` is returned and the other operand can be
    /// applied using [Self::apply_replacement].
    fn find_full_match<const N: usize>(&mut self, target: &[u8], v0: [u8; N], v1: [u8; N]) -> bool {
        if target.len() < N {
            return false;
        }

        let mut rev_v0 = v0;
        rev_v0.reverse();
        let mut rev_v1 = v1;
        rev_v1.reverse();
        let get_match = |target: [u8; N]| -> Option<[u8; N]> {
            if target == v0 {
                return Some(v1);
            }

            if N > 1 && target == rev_v0 {
                return Some(rev_v1);
            }

            None
        };

        let len = target.len() - N + 1;
        while self.offset < len {
            if let Some(replacement) =
                get_match(target[self.offset..self.offset + N].try_into().unwrap())
            {
                self.replacement.extend_from_slice(&replacement);
                return true;
            }
            self.offset += 1;
        }

        false
    }

    /// Starting from the current offset, find the next location in `dst` where prefix matches
    /// either of the operands in, storing the other in `replacement`.
    fn find_prefix_match<const N: usize>(
        &mut self,
        target: &StreamData,
        v0: &[u8; N],
        v1: &[u8; N],
    ) -> bool {
        // @todo: this could be significantly more optimized.
        while self.offset < target.bytes.len() {
            self.find_best_prefix_match(target, v0, v1);

            // Avoid trying single byte replacements, unless there is a chance we can do better
            // using an expanded replacement.
            if self.replacement.len() > 1 || !self.extended_replacement.is_empty() {
                return true;
            }

            self.replacement.clear();
            self.extended_replacement.clear();
            self.offset += 1;
        }

        false
    }

    fn find_best_prefix_match<const N: usize>(
        &mut self,
        target: &StreamData,
        v0: &[u8; N],
        v1: &[u8; N],
    ) {
        let (stride1_prefix, stride1_size) =
            find_prefix_match(&target.bytes[self.offset..], v0, v1).unwrap_or((&[], 0));

        let (stride2_prefix, stride2_size) =
            find_strided_prefix_match::<N, 2>(target, self.offset, v0, v1).unwrap_or((&[], 0));

        let (stride4_prefix, stride4_size) =
            find_strided_prefix_match::<N, 4>(target, self.offset, v0, v1).unwrap_or((&[], 0));

        let (prefix, size, stride) = if stride4_size > stride2_size && stride4_size > stride1_size {
            (stride4_prefix, stride4_size, 4)
        }
        else if stride2_size > stride1_size {
            (stride2_prefix, stride2_size, 2)
        }
        else {
            (stride1_prefix, stride1_size, 1)
        };

        self.stride = stride;
        self.prefix_match(prefix, size);
    }

    fn prefix_match(&mut self, prefix: &[u8], size: usize) {
        self.replacement.extend_from_slice(&prefix[..size]);

        if let Some(null_terminator) = prefix.iter().position(|x| *x == 0) {
            if null_terminator > size && prefix[..null_terminator].is_ascii() {
                self.extended_replacement.extend_from_slice(&prefix[..null_terminator]);
            }
        }
    }
}

fn all_zero(arr: &[u8]) -> bool {
    arr.iter().all(|&x| x == 0)
}

fn find_prefix_match<'a, const N: usize>(
    target: &[u8],
    v0: &'a [u8; N],
    v1: &'a [u8; N],
) -> Option<(&'a [u8], usize)> {
    let (prefix, size) = match either_prefix_match(target, v0, v1) {
        PrefixMatch::A(size) => (v1, size),
        PrefixMatch::B(size) => (v0, size),
        PrefixMatch::None => return None,
    };
    if target[..size] == prefix[..size] || all_zero(&prefix[..size]) {
        return None;
    }
    Some((prefix, size))
}

fn find_strided_prefix_match<'a, const N: usize, const S: usize>(
    target: &StreamData,
    offset: usize,
    v0: &'a [u8; N],
    v1: &'a [u8; N],
) -> Option<(&'a [u8], usize)> {
    if !target.read_as(S as u32) || ((offset & (target.min_alignment() - 1)) != 0) {
        // Avoid looking for strided matches if the stream has never been read at the target size or
        // the offset is unaligned.
        return None;
    }

    let bytes = &target.bytes[offset..];
    let (prefix, size) = match either_strided_prefix_match::<S>(bytes, v0, v1) {
        PrefixMatch::A(size) => (v1, size),
        PrefixMatch::B(size) => (v0, size),
        PrefixMatch::None => return None,
    };
    if size < 2 || all_zero(&prefix[..size]) {
        return None;
    }
    Some((prefix, size))
}

/// Returns the number of prefix bytes shared between `a` and `b`.
fn prefix_match(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b).take_while(|(a, b)| *a == *b).count()
}

enum PrefixMatch {
    None,
    A(usize),
    B(usize),
}

/// Checks whether `target` shares a common prefix with either `a` or `b`. Returns the length of the
/// largest match if so.
fn either_prefix_match(target: &[u8], a: &[u8], b: &[u8]) -> PrefixMatch {
    match (prefix_match(target, a), prefix_match(target, b)) {
        (0, 0) => PrefixMatch::None,
        (a, b) if a > b => PrefixMatch::A(a),
        (_, b) => PrefixMatch::B(b),
    }
}

fn strided_prefix_match<const S: usize>(target: &[u8], x: &[u8]) -> usize {
    target.chunks_exact(S).zip(x).take_while(|(target, x)| target[0] == **x).count()
}

/// Checks whether `target` shares a common prefix with either `a` or `b`. Returns the length of the
/// largest match if so.
fn either_strided_prefix_match<const N: usize>(target: &[u8], a: &[u8], b: &[u8]) -> PrefixMatch {
    match (strided_prefix_match::<N>(target, a), strided_prefix_match::<N>(target, b)) {
        (0, 0) => PrefixMatch::None,
        (a, b) if a > b => PrefixMatch::A(a),
        (_, b) => PrefixMatch::B(b),
    }
}

#[test]
fn test_strided_prefix_match() {
    let a = b"a   b   c   d   ";
    let b = b"abcd";
    assert_eq!(strided_prefix_match::<4>(a, b), 4);

    let a = [
        0x41, 0xd8, 0x0c, 0xd8, 0xef, 0x5a, 0xee, 0x5d, 0x28, 0xe5, 0x8b, 0x0e, 0xc7, 0x0a, 0xfe,
        0x94, 0x96, 0x59, 0xe8, 0xdc, 0xe6, 0xd7, 0x1d, 0x5d, 0x31, 0x76, 0x47, 0x3d, 0x1c, 0xf5,
        0xcc, 0x7b, 0xc1, 0x32, 0x60, 0x77, 0x59, 0x01, 0xb6, 0xed, 0x30, 0x2b, 0x87, 0x82, 0x53,
        0x56, 0x6d, 0x5d, 0xdd, 0xc8, 0x5f, 0x84, 0xaa, 0xc6, 0xb5, 0xfb, 0xf9, 0x9b, 0xc9, 0xac,
        0x70, 0x6f, 0xf5, 0xf7, 0x0a, 0xec, 0xf5, 0xb0,
    ];
    let b = [
        0x41, 0xef, 0x28, 0xc7, 0x96, 0xe6, 0x31, 0x1c, 0xc1, 0x59, 0x30, 0x53, 0xdd, 0xaa, 0xf9,
        0x70, 0x0a, 0x00,
    ];
    assert_eq!(strided_prefix_match::<4>(&a[..], &b[..]), 17);
}

#[test]
fn test_stride_on_u16() {
    let bytes = &[
        0x00, 0x89, 0xb0, 0x33, 0x14, 0x98, 0x38, 0x44, 0x0e, 0xfe, 0xf3, 0x4a, 0x38, 0x5c, 0x3d,
        0xa5, 0xea, 0xd9, 0x15, 0xf2, 0x8f, 0xde, 0xd7, 0xeb, 0x24, 0x91, 0xcb, 0x9e, 0x2d, 0xbe,
        0xfe, 0x81,
    ];
    let stream_data = StreamData { bytes: bytes.to_vec(), cursor: 0, sizes: 2 | 4 };

    let v0 = 0xea38_u16;
    let v1 = 0x000a_u16;

    let mut finder = ReplacementFinder::new(true);
    assert!(finder.find_prefix_match::<2>(&stream_data, &v0.to_le_bytes(), &v1.to_le_bytes()));
    eprintln!("replacement: {:?}, stride={}\n\n", finder.replacement, finder.stride);

    finder.reset(0);
    finder.find_best_prefix_match::<2>(&stream_data, &v0.to_le_bytes(), &v1.to_le_bytes());
    eprintln!("replacement: {:?}, stride={}\n\n", finder.replacement, finder.stride);

    finder.reset(0);
    assert!(finder.find_match(&stream_data, Operands::U16(v0, v1)));
}

#[test]
fn test_stride_on_u32_underaligned() {
    #[rustfmt::skip]
    let bytes = &[
        0xf8, 0x0d, 0x1b, 0xa4,
        0xed, 0xec, 0x1e, 0x5c,
        0xa5, 0xf6, 0x05, 0x20,
        0xdb, 0x04, 0x00, 0x80,

        0x6f, 0xcd, 0x13, 0x81,
        0x3d, 0xec, 0x9d, 0xf7,
        0x1c, 0x53, 0x4c, 0x6b, // (0x4c) first byte of target
        0x38, 0x45, 0xdf, 0xf2, // (0xdf) second byte of target
        0x43, 0x0d
    ];

    let stream_data = StreamData { bytes: bytes.to_vec(), cursor: 0, sizes: 2 | 4 };
    let v0 = 0xdf4c_u16;
    let v1 = 0x0002_u16;

    let mut finder = ReplacementFinder::new(true);
    assert!(finder.find_int_match(&stream_data, v0.to_ne_bytes(), v1.to_ne_bytes()));

    assert!(finder.stride == 4);
    assert_eq!(finder.offset, 26);
    assert_eq!(finder.replacement, [0x02, 0x00])
}
