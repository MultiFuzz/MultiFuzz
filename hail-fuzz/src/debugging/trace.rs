use icicle_vm::cpu::{mem::IoHandler, Cpu, HookHandler};

use icicle_cortexm::mmio::{FuzzwareMmioHandler, GlobalMmioSource};

use crate::input::{MultiStream, StreamKey};

#[derive(Copy, Clone)]
pub struct TraceEntry {
    pub pc: u64,
    pub sp: u64,
    pub icount: u64,
    pub fuzz_offset: u32,
    pub last_read: u32,
    pub last_value: u32,
}

pub trait IoTracer {
    fn read(&mut self, addr: StreamKey, value: &[u8]);
    fn snapshot(&self) -> Box<dyn std::any::Any>;
    fn restore(&mut self, snapshot: &Box<dyn std::any::Any>);
}

pub trait IoTracerAny: IoTracer + Send + Sync + 'static {
    fn as_any(&self) -> &dyn std::any::Any;
    fn as_mut_any(&mut self) -> &mut dyn std::any::Any;
    fn dyn_clone(&self) -> Box<dyn IoTracerAny>;
}

impl<T: IoTracer + Send + Sync + 'static + Clone> IoTracerAny for T {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn as_mut_any(&mut self) -> &mut dyn std::any::Any {
        self
    }
    fn dyn_clone(&self) -> Box<dyn IoTracerAny> {
        Box::new(self.clone())
    }
}

#[derive(Clone)]
struct MultiStreamTracer {
    /// The (key, value, size) of all the reads made to the IO region.
    reads: Vec<(StreamKey, u64, u8)>,
}

impl IoTracer for MultiStreamTracer {
    fn read(&mut self, addr: StreamKey, value: &[u8]) {
        let x = icicle_vm::cpu::utils::get_u64(value);
        self.reads.push((addr, x, value.len() as u8));
    }

    fn snapshot(&self) -> Box<dyn std::any::Any> {
        Box::new(self.clone())
    }

    fn restore(&mut self, snapshot: &Box<dyn std::any::Any>) {
        self.clone_from(snapshot.downcast_ref().unwrap());
    }
}

pub type PathTracerSnapshot = Vec<TraceEntry>;

struct PathTracer {
    /// A list of trace entries for each basic block hit by the emulator.
    blocks: Vec<TraceEntry>,
    /// A reference to the IO handler for the mmio region for offset tracking.
    mmio_handler: IoHandler,
}

impl PathTracer {
    fn new(cpu: &mut Cpu, mmio_handler: IoHandler) -> Self {
        let handler = cpu.mem.get_io_memory_mut(mmio_handler).as_mut_any();
        if let Some(handler) = handler.downcast_mut::<FuzzwareMmioHandler<MultiStream>>() {
            handler.source.tracer = Some(Box::new(MultiStreamTracer { reads: vec![] }));
        }
        Self { blocks: vec![], mmio_handler }
    }
}

impl HookHandler for PathTracer {
    fn call(data: &mut Self, cpu: &mut Cpu, addr: u64) {
        // Avoid using up too much memory if we end up with an extremely long execution.
        if data.blocks.len() > 0x100_0000 {
            data.blocks.truncate(0);
        }

        let handler = cpu.mem.get_io_memory_mut(data.mmio_handler).as_any();

        let mut offset = 0;
        let mut last_read = 0;
        let mut last_value = 0;
        if let Some(handler) = handler.downcast_ref::<FuzzwareMmioHandler<GlobalMmioSource>>() {
            offset = handler.source.offset;
        }
        if let Some(handler) = handler.downcast_ref::<FuzzwareMmioHandler<MultiStream>>() {
            offset = handler.source.bytes_read();
            if let Some(tracer) = handler
                .source
                .tracer
                .as_ref()
                .and_then(|x| x.as_any().downcast_ref::<MultiStreamTracer>())
            {
                (last_read, last_value) =
                    tracer.reads.last().map_or((0, 0), |(addr, value, _)| (*addr, *value))
            }
        }

        let icount = cpu.icount();
        if let Some(prev) = data.blocks.last().map(|prev| prev.icount) {
            debug_assert!(icount >= prev, "icount went backwards! (was: {prev}, now: {icount})");
        }
        data.blocks.push(TraceEntry {
            pc: addr,
            sp: cpu.read_reg(cpu.arch.reg_sp),
            icount,
            fuzz_offset: offset as u32,
            last_read: last_read as u32,
            last_value: last_value as u32,
        })
    }
}

pub fn add_path_tracer(vm: &mut icicle_vm::Vm, mmio: IoHandler) -> anyhow::Result<PathTracerRef> {
    let tracer = PathTracer::new(&mut vm.cpu, mmio);
    let hook = vm.cpu.add_hook(tracer);
    icicle_vm::injector::register_block_hook_injector(vm, 0, u64::MAX, hook);
    Ok(PathTracerRef(hook))
}

#[derive(Copy, Clone)]
pub struct PathTracerRef(pcode::HookId);

impl PathTracerRef {
    pub fn get_last_blocks(&self, vm: &mut icicle_vm::Vm) -> Vec<TraceEntry> {
        let path_tracer = vm.cpu.get_hook_mut(self.0);
        path_tracer.data_mut::<PathTracer>().unwrap().blocks.clone()
    }

    pub fn get_mmio_reads(&self, vm: &mut icicle_vm::Vm) -> Vec<(StreamKey, u64, u8)> {
        let path_tracer = vm.cpu.get_hook_mut(self.0);
        let mmio_handle = path_tracer.data_mut::<PathTracer>().unwrap().mmio_handler;
        let handler = vm.cpu.mem.get_io_memory_mut(mmio_handle).as_any();

        let mut mmio_reads = vec![];
        if let Some(handler) = handler.downcast_ref::<FuzzwareMmioHandler<MultiStream>>() {
            if let Some(tracer) = handler
                .source
                .tracer
                .as_ref()
                .and_then(|x| x.as_any().downcast_ref::<MultiStreamTracer>())
            {
                mmio_reads = tracer.reads.clone();
            }
        }

        mmio_reads
    }

    pub fn clear(&self, vm: &mut icicle_vm::Vm) {
        let path_tracer = vm.cpu.get_hook_mut(self.0);
        path_tracer.data_mut::<PathTracer>().unwrap().blocks.clear();
    }

    pub fn print_last_blocks(&self, vm: &mut icicle_vm::Vm, count: usize) -> String {
        use std::fmt::Write;

        let mut output = String::new();

        for entry in self.get_last_blocks(vm).iter().rev().take(count) {
            let location = vm
                .env
                .symbolize_addr(&mut vm.cpu, entry.pc)
                .unwrap_or(icicle_vm::cpu::debug_info::SourceLocation::default());
            writeln!(output, "{:#x}: {location}", entry.pc).unwrap();
        }

        output
    }

    pub fn snapshot(&self, vm: &mut icicle_vm::Vm) -> PathTracerSnapshot {
        let path_tracer = vm.cpu.get_hook_mut(self.0);
        path_tracer.data_mut::<PathTracer>().unwrap().blocks.clone()
    }

    pub fn restore(&self, vm: &mut icicle_vm::Vm, snapshot: &PathTracerSnapshot) {
        let path_tracer = vm.cpu.get_hook_mut(self.0);
        let blocks = &mut path_tracer.data_mut::<PathTracer>().unwrap().blocks;
        blocks.clear();
        blocks.extend_from_slice(snapshot)
    }

    pub fn save_trace(&self, vm: &mut icicle_vm::Vm, path: &std::path::Path, symbolize: bool) {
        use std::io::Write;

        if symbolize {
            let mut output = std::io::BufWriter::new(std::fs::File::create(path).unwrap());
            for entry in self.get_last_blocks(vm) {
                let location = vm
                    .env
                    .symbolize_addr(&mut vm.cpu, entry.pc)
                    .unwrap_or(icicle_vm::cpu::debug_info::SourceLocation::default());
                writeln!(output, "{:#08x},sp={:#08x},location={location}", entry.pc, entry.sp)
                    .unwrap();
            }
        }
        else {
            save_path_trace(path, &self.get_last_blocks(vm))
        }
    }
}

pub fn save_path_trace(path: &std::path::Path, blocks: &Vec<TraceEntry>) {
    use std::io::Write;

    let mut output = std::io::BufWriter::new(std::fs::File::create(path).unwrap());
    writeln!(output, "pc,sp,icount,fuzz_offset,last_read,last_value").unwrap();
    for TraceEntry { pc, sp, icount, fuzz_offset, last_read, last_value } in blocks {
        writeln!(output, "{pc:#x},{sp:#x},{icount},{fuzz_offset},{last_read:#x},{last_value:#x}")
            .unwrap();
    }
}

pub fn save_mmio_reads(path: &std::path::Path, reads: &Vec<(u64, u64, u8)>) {
    use std::io::Write;

    if reads.is_empty() {
        return;
    }

    let mut output = std::io::BufWriter::new(std::fs::File::create(path).unwrap());
    for (addr, value, size) in reads {
        writeln!(output, "{addr:#x},{size:#x},{value:#x}").unwrap();
    }
}
