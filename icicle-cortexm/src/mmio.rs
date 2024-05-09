use icicle_vm::cpu::mem::{IoMemory, MemError, MemResult};

use crate::{config, fuzzware};

pub struct Model {
    pub pc: u32,
    pub addr: u32,
    pub kind: ModelKind,
}

impl Model {
    fn matches_context(&self, pc: u64, mem_addr: u64) -> bool {
        (self.pc == u32::MAX || self.pc as u64 == pc)
            && (self.addr == u32::MAX || self.addr as u64 == mem_addr)
    }
}

pub enum ModelKind {
    Bitextract { size: u8, left_shift: u8, mask: u32 },
    Constant { val: u32 },
    Passthrough { id: usize },
    Set { values: Vec<u32> },
}

fn build_models(models: &config::MmioModels) -> (Vec<Model>, Vec<u32>) {
    let bitextract = models.bitextract.values().map(|x| Model {
        pc: x.pc,
        addr: x.addr as u32,
        kind: ModelKind::Bitextract { size: x.size, left_shift: x.left_shift, mask: x.mask },
    });
    let constant = models.constant.values().map(|x| Model {
        pc: x.pc,
        addr: x.addr as u32,
        kind: ModelKind::Constant { val: x.val },
    });
    let mut passthrough_id = 0;
    let passthrough = models.passthrough.values().map(|x| {
        let id = passthrough_id;
        passthrough_id += 1;
        Model { pc: x.pc, addr: x.addr as u32, kind: ModelKind::Passthrough { id } }
    });
    let passthrough_data = models.passthrough.values().map(|x| x.init_val).collect();

    let set = models.set.values().map(|x| Model {
        pc: x.pc,
        addr: x.addr as u32,
        kind: ModelKind::Set { values: x.vals.clone() },
    });
    (bitextract.chain(constant).chain(passthrough).chain(set).collect(), passthrough_data)
}

/// A re-implemented fuzzware MMIO handler
pub struct FuzzwareMmioHandler<I> {
    pub source: I,
    pub models: Vec<Model>,
    pub passthrough: Vec<u32>,
    access_contexts: bool,
    uc_ptr: *mut crate::uc_engine,
}

impl<I> std::ops::DerefMut for FuzzwareMmioHandler<I> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.source
    }
}

impl<I> std::ops::Deref for FuzzwareMmioHandler<I> {
    type Target = I;

    fn deref(&self) -> &Self::Target {
        &self.source
    }
}

impl<I> FuzzwareMmioHandler<I> {
    pub fn add_extract_model(&mut self, pc: u64, min_bit: u8, max_bit: u8) {
        let kind = if max_bit < min_bit {
            // No bits are used (zero-sized load).
            tracing::warn!("[{pc:#x}] removed zero sized load");
            ModelKind::Constant { val: 0 }
        }
        else {
            let required_bits = max_bit - min_bit + 1;
            let size = required_bits.next_multiple_of(8) / 8;
            let mask = (pcode::mask(required_bits as u64) as u32) << min_bit;
            tracing::info!("adjusting load [{pc:#x}] size={size}, shift={min_bit}, mask={mask:#b}");
            ModelKind::Bitextract { size, left_shift: min_bit, mask }
        };
        self.models.push(Model { pc: pc as u32, addr: u32::MAX, kind })
    }

    pub fn new(
        models: &config::MmioModels,
        uc_ptr: *mut crate::uc_engine,
        access_contexts: bool,
        source: I,
    ) -> Self {
        let (models, passthrough) = build_models(models);
        Self { source, models, passthrough, uc_ptr, access_contexts }
    }
}

impl<I: IoMemory> IoMemory for FuzzwareMmioHandler<I> {
    fn read(&mut self, addr: u64, buf: &mut [u8]) -> MemResult<()> {
        unsafe { fuzzware::reload_fuzz_consumption_timer(self.uc_ptr) };

        let pc = unsafe {
            let ctx = (*self.uc_ptr).ctx.cast::<crate::unicorn_api::Context>().as_mut().unwrap();
            let vm = &mut *ctx.vm;
            vm.cpu.read_pc() as u32
        };

        let key = if self.access_contexts { ((pc as u64) << 32) | addr } else { addr };
        if self.models.is_empty() {
            // Avoid doing any extra work if models are not enabled.
            return self.source.read(key, buf);
        }

        if let Some(model) = self.models.iter().find(|x| x.matches_context(pc as u64, addr)) {
            let value = match &model.kind {
                &ModelKind::Bitextract { size, left_shift, mask } => {
                    let mut buf = [0; 4];
                    self.source.read(key, &mut buf[..size as usize])?;
                    (u32::from_le_bytes(buf) << left_shift) & mask
                }
                ModelKind::Constant { val } => *val,
                ModelKind::Set { values } => match values.len() {
                    0 => 0,
                    1 => values[0],
                    n => {
                        let mut buf = [0; 1];
                        self.source.read(key, &mut buf)?;
                        values[buf[0] as usize % n]
                    }
                },
                ModelKind::Passthrough { id } => self.passthrough[*id],
            };
            buf.copy_from_slice(&value.to_le_bytes()[..buf.len()]);
            return Ok(());
        }

        // Fallback to unmodeled.
        self.source.read(key, buf)
    }

    fn write(&mut self, addr: u64, value: &[u8]) -> MemResult<()> {
        if self.models.is_empty() {
            return Ok(());
        }

        let pc = unsafe {
            let ctx = (*self.uc_ptr).ctx.cast::<crate::unicorn_api::Context>().as_mut().unwrap();
            let vm = &mut *ctx.vm;
            vm.cpu.read_pc() as u32
        };

        if let Some(model) =
            self.models.iter().find(|x| x.addr == addr as u32 && (x.pc == pc || x.pc == 0xffffffff))
        {
            if let ModelKind::Passthrough { id } = model.kind {
                let len = value.len().min(4);
                let mut buf = [0; 4];
                buf[..len].copy_from_slice(&value[..len]);
                self.passthrough[id] = u32::from_le_bytes(buf);
            }
        }
        Ok(())
    }

    fn snapshot(&mut self) -> Box<dyn std::any::Any> {
        Box::new((self.passthrough.clone(), self.source.snapshot()))
    }

    fn restore(&mut self, snapshot: &Box<dyn std::any::Any>) {
        let (passthrough, source) =
            snapshot.downcast_ref::<(Vec<u32>, Box<dyn std::any::Any>)>().unwrap();
        self.passthrough.clone_from(passthrough);
        self.source.restore(source)
    }
}

/// Represents an input source where every MMIO access is read from a global input stream.
#[derive(Clone)]
pub struct GlobalMmioSource {
    /// The input bytes provided by the fuzzer.
    pub data: Vec<u8>,
    /// The offset within `data` to read the next peripheral read from.
    pub offset: usize,
    /// (address, len) pairs used to reconstruct which peripheral accesses which input byte.
    pub(crate) mmio_accesses: Option<Vec<(u32, u32)>>,
}

impl GlobalMmioSource {
    pub fn empty() -> Self {
        Self { data: vec![], offset: 0, mmio_accesses: None }
    }

    pub fn next_bytes(&mut self, size: usize) -> Option<&[u8]> {
        let buf = self.data.get(self.offset..self.offset + size)?;
        self.offset += size;
        Some(buf)
    }

    pub fn set_input(&mut self, data: &[u8]) {
        self.data.clear();
        self.data.extend_from_slice(data);
        self.offset = 0;
    }

    pub fn update_input(&mut self, offset: usize, data: &[u8]) {
        self.data.clear();
        self.data.extend_from_slice(data);
        self.offset = offset;
    }
}

impl IoMemory for GlobalMmioSource {
    fn read(&mut self, addr: u64, buf: &mut [u8]) -> MemResult<()> {
        let data = self.next_bytes(buf.len()).ok_or(MemError::ReadWatch)?;
        buf.copy_from_slice(data);

        if let Some(monitor) = self.mmio_accesses.as_mut() {
            monitor.push((addr as u32, buf.len() as u32));
        }

        Ok(())
    }

    fn write(&mut self, _addr: u64, _value: &[u8]) -> MemResult<()> {
        Ok(())
    }

    fn snapshot(&mut self) -> Box<dyn std::any::Any> {
        Box::new(self.offset)
    }

    fn restore(&mut self, snapshot: &Box<dyn std::any::Any>) {
        self.offset = *snapshot.downcast_ref::<usize>().unwrap();
    }
}
