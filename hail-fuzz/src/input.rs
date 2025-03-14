use std::io::Read;

use anyhow::Context;
use hashbrown::HashMap;

use icicle_cortexm::{mmio::FuzzwareMmioHandler, CortexmTarget};
use icicle_vm::cpu::mem::{IoMemory, MemError, MemResult};

use crate::debugging::trace::IoTracerAny;

pub type MultiStreamMmio = FuzzwareMmioHandler<MultiStream>;
pub type CortexmMultiStream = CortexmTarget<MultiStreamMmio>;

#[derive(Debug, Default)]
pub struct StreamData {
    pub bytes: Vec<u8>,
    pub cursor: u32,
    pub sizes: u32,
}

impl Clone for StreamData {
    fn clone(&self) -> Self {
        Self { bytes: self.bytes.clone(), cursor: self.cursor, sizes: self.sizes }
    }

    fn clone_from(&mut self, source: &Self) {
        self.bytes.clone_from(&source.bytes);
        self.cursor = source.cursor;
        self.sizes = source.sizes;
    }
}

impl StreamData {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, cursor: 0, sizes: 0 }
    }

    pub fn clear(&mut self) {
        self.bytes.clear();
        self.cursor = 0;
        self.sizes = 0;
    }

    /// Returns whether the stream has been read as a certain sized value.
    pub fn read_as(&self, size: u32) -> bool {
        self.sizes & size != 0
    }

    /// Returns the minimum alignment of the stream, given the reads we have seen for this stream.
    pub fn min_alignment(&self) -> usize {
        1 << self.sizes.trailing_zeros()
    }
}

pub type StreamKey = u64;

const VERSION: u8 = 1;
const FILE_HEADER: [u8; 4] = [b'm', b'u', b'l', VERSION];

/// Represents an input source where every MMIO access is read from a global input stream.
#[derive(Default)]
pub struct MultiStream {
    /// A mapping from MMIO address to the target input stream.
    pub streams: HashMap<StreamKey, StreamData>,
    pub last_read: Option<StreamKey>,
    pub tracer: Option<Box<dyn IoTracerAny>>,
}

impl std::fmt::Debug for MultiStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiStream")
            .field("streams", &self.streams)
            .field("last_read", &self.last_read)
            .field("tracer", &self.tracer.is_some())
            .finish()
    }
}

impl Clone for MultiStream {
    fn clone(&self) -> Self {
        Self {
            streams: self.streams.clone(),
            last_read: self.last_read,
            tracer: self.tracer.as_ref().map(|x| x.dyn_clone()),
        }
    }

    fn clone_from(&mut self, source: &Self) {
        // Clear all the streams that are not in `source`.
        for (addr, stream) in &mut self.streams {
            if !source.streams.contains_key(addr) {
                stream.clear();
            }
        }

        // Clone or insert new streams.
        for (addr, stream) in &source.streams {
            let dst = self.streams.entry(*addr).or_default();
            dst.clone_from(stream);
        }

        self.last_read = source.last_read;
    }
}

impl MultiStream {
    pub fn new(streams: HashMap<StreamKey, StreamData>) -> Self {
        Self { streams, last_read: None, tracer: None }
    }

    pub fn next_bytes(&mut self, addr: StreamKey, size: usize) -> Option<&[u8]> {
        self.last_read = Some(addr);
        let stream = self.streams.get_mut(&addr)?;
        let buf = stream.bytes.get(stream.cursor as usize..stream.cursor as usize + size)?;
        if let Some(tracer) = self.tracer.as_mut() {
            tracer.read(addr, buf);
        }
        stream.sizes |= size as u32;
        stream.cursor += size as u32;
        Some(buf)
    }

    pub fn clear(&mut self) {
        self.streams.values_mut().for_each(|x| x.clear());
    }

    pub fn total_bytes(&self) -> usize {
        self.streams.values().map(|x| x.bytes.len()).sum()
    }

    pub fn count_non_empty_streams(&self) -> usize {
        self.streams.iter().filter(|(_, data)| !data.bytes.is_empty()).count()
    }

    pub fn bytes_read(&self) -> usize {
        self.streams.values().map(|x| x.cursor as usize).sum()
    }

    pub fn from_path(path: &std::path::Path) -> anyhow::Result<Self> {
        let buf =
            std::fs::read(path).with_context(|| format!("error reading: {}", path.display()))?;

        // Try parsing using the latest format.
        if let Some(data) = Self::from_bytes(&buf) {
            return Ok(data);
        }
        // Fallback to legacy format.
        legacy::multi_stream_from_bytes_v0(&buf).ok_or_else(|| {
            anyhow::format_err!("error parsing {} as multistream data", path.display())
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut headers: Vec<_> = self
            .streams
            .iter()
            .filter(|(_, data)| !data.bytes.is_empty())
            .map(|(addr, data)| (*addr, data.bytes.len() as u64))
            .collect();
        headers.sort_unstable();

        // Output format:
        //
        // FILE_HEADER
        // number of mmio addresses: u32le,
        // [(mmio1.address: u64le, mmio1.len: u64le), ...],
        // [mmio1.bytes...]
        let mut out = FILE_HEADER.to_vec();
        out.extend_from_slice(&(headers.len() as u32).to_le_bytes());
        for (addr, len) in &headers {
            out.extend_from_slice(&addr.to_le_bytes());
            out.extend_from_slice(&len.to_le_bytes());
        }

        for (addr, _) in headers {
            out.extend_from_slice(&self.streams[&addr].bytes);
        }
        out
    }

    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        use byteorder::{ReadBytesExt, LE};

        let mut reader = std::io::Cursor::new(buf);

        let mut magic_with_version = [0; 4];
        reader.read_exact(&mut magic_with_version).ok()?;
        if !matches!(magic_with_version, FILE_HEADER) {
            return None;
        }

        let num_mmio = reader.read_u32::<LE>().ok()?;

        if num_mmio > 0x10000 {
            // Too many MMIO peripherals.
            tracing::error!("Too many MMIO peripherals {num_mmio}");
            return None;
        }

        let mut headers = Vec::with_capacity(num_mmio as usize);
        for _ in 0..num_mmio {
            let addr = reader.read_u64::<LE>().ok()?;
            let len = reader.read_u64::<LE>().ok()?;
            headers.push((addr, len));
        }

        let mut streams = HashMap::default();
        streams.reserve(headers.len());
        for (addr, len) in headers {
            if len > 0x100000 {
                // Data too long.
                tracing::error!("{addr:#x} contains too many bytes: {len}");
                return None;
            }
            let mut buf = vec![0; len as usize];
            reader.read_exact(&mut buf).ok()?;
            streams.insert(addr, StreamData::new(buf));
        }
        Some(MultiStream { streams, last_read: None, tracer: None })
    }

    pub fn seek_to_start(&mut self) {
        self.streams.values_mut().for_each(|x| x.cursor = 0);
    }

    pub fn trim(&mut self) {
        self.streams.values_mut().for_each(|x| x.bytes.truncate(x.cursor as usize));
    }

    pub fn snapshot_cursors(&self) -> Vec<(u64, u32)> {
        self.streams.iter().map(|(key, value)| (*key, value.cursor)).collect()
    }

    pub fn restore_cursors(&mut self, snapshot: &Vec<(u64, u32)>) {
        snapshot
            .iter()
            .for_each(|(key, cursor)| self.streams.get_mut(key).unwrap().cursor = *cursor);
    }
}

// pub fn multi_stream(
//     models: &icicle_cortexm::config::MmioModels,
//     access_contexts: bool,
//     uc_ptr: *mut icicle_cortexm::uc_engine,
// ) -> FuzzwareMmioHandler<MultiStream> {
//     let (models, passthrough) = build_models(models);
//     FuzzwareMmioHandler {
//         source: MultiStream::default(),
//         models,
//         passthrough,
//         uc_ptr,
//         access_contexts,
//     }
// }

mod legacy {
    use std::io::Read;

    use hashbrown::HashMap;

    #[allow(unused)]
    pub fn multi_stream_to_bytes_v0(data: &super::MultiStream) -> Vec<u8> {
        let mut headers: Vec<_> = data
            .streams
            .iter()
            .filter(|(_, data)| !data.bytes.is_empty())
            .map(|(addr, data)| (*addr as u32, data.bytes.len() as u32))
            .collect();
        headers.sort_unstable();

        // Output format:
        // number of mmio addresses: u32le,
        // [(mmio1.address: u32le, mmio1.len: u32le), ...],
        // [mmio1.bytes...]
        let mut out = vec![];
        out.extend_from_slice(&(headers.len() as u32).to_le_bytes());
        for (addr, len) in &headers {
            out.extend_from_slice(&addr.to_le_bytes());
            out.extend_from_slice(&len.to_le_bytes());
        }

        for (addr, _) in headers {
            out.extend_from_slice(&data.streams[&(addr as u64)].bytes);
        }
        out
    }

    pub fn multi_stream_from_bytes_v0(buf: &[u8]) -> Option<super::MultiStream> {
        use byteorder::{ReadBytesExt, LE};

        let mut reader = std::io::Cursor::new(buf);
        let num_mmio = reader.read_u32::<LE>().ok()?;

        if num_mmio > 0x10000 {
            // Too many MMIO peripherals.
            tracing::error!("Too many MMIO peripherals {num_mmio}");
            return None;
        }

        let mut headers = Vec::with_capacity(num_mmio as usize);
        for _ in 0..num_mmio {
            let addr = reader.read_u32::<LE>().ok()?;
            let len = reader.read_u32::<LE>().ok()?;
            headers.push((addr, len));
        }

        let mut streams = HashMap::default();
        streams.reserve(headers.len());
        for (addr, len) in headers {
            if len > 0x100000 {
                // Data too long.
                tracing::error!("{addr:#x} contains too many bytes: {len}");
                return None;
            }
            let mut buf = vec![0; len as usize];
            reader.read_exact(&mut buf).ok()?;
            streams.insert(addr as u64, super::StreamData::new(buf));
        }
        Some(super::MultiStream { streams, last_read: None, tracer: None })
    }
}

struct MultiStreamSnapshot {
    cursors: Vec<(StreamKey, u32)>,
    tracer: Option<Box<dyn std::any::Any>>,
}

impl IoMemory for MultiStream {
    fn read(&mut self, addr: u64, buf: &mut [u8]) -> MemResult<()> {
        let data = self.next_bytes(addr, buf.len()).ok_or(MemError::ReadWatch)?;
        buf.copy_from_slice(data);
        Ok(())
    }

    fn write(&mut self, _addr: u64, _value: &[u8]) -> MemResult<()> {
        Ok(())
    }

    fn snapshot(&mut self) -> Box<dyn std::any::Any> {
        let cursors: Vec<_> = self.streams.iter().map(|(k, v)| (*k, v.cursor)).collect();
        let tracer = self.tracer.as_ref().map(|x| x.snapshot());
        Box::new(MultiStreamSnapshot { cursors, tracer })
    }

    fn restore(&mut self, snapshot: &Box<dyn std::any::Any>) {
        let snapshot = snapshot.downcast_ref::<MultiStreamSnapshot>().unwrap();
        for (addr, cursor) in &snapshot.cursors {
            self.streams.get_mut(addr).unwrap().cursor = *cursor;
        }
        if let Some(tracer) = self.tracer.as_mut() {
            tracer.restore(snapshot.tracer.as_ref().unwrap());
        }
    }
}
