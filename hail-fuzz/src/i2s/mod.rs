pub(crate) use colorization::ColorizationStage;
pub(crate) use finder::Comparisons;
pub(crate) use replacement::{I2SRandomReplacement, I2SReplaceStage};

mod analysis;
mod colorization;
mod finder;
mod replacement;

use anyhow::Context;
use icicle_fuzzing::cmplog2::CmpLog2Ref;
use icicle_vm::Vm;

/// The maximum number of bytes (taken from the end of the stream) that the I2S stage will try to
/// perform I2S replacements within.
pub const MAX_STREAM_LEN: usize = 512;

/// The maximum number of times (per-stream) the I2S stage will attempt to replace a target
/// destination value.
const MAX_ONE_BYTE_MATCHES: usize = 16;

/// The maximum number of times (per-stream) the I2S stage will attempt to use a target source
/// value.
const MAX_ONE_BYTE_REPLACEMENTS: usize = 16;

pub fn log_cmplog_data(
    vm: &mut Vm,
    cmplog: CmpLog2Ref,
    path: &std::path::Path,
) -> anyhow::Result<()> {
    use pcode::PcodeDisplay;
    use std::io::Write;

    // @debugging: save CmpLog data
    let mut log = std::io::BufWriter::new(
        std::fs::File::create(path)
            .with_context(|| format!("failed to create `{}.txt`", path.display()))?,
    );
    for location in cmplog.get_inst_log(&mut vm.cpu).to_vec() {
        writeln!(log, "{:#x}: {}", location.addr, location.op.display(&vm.cpu.arch.sleigh))?;
        let (a_kind, b_kind) = analysis::analyse_comparisons(&location);
        writeln!(log, "\t{a_kind:x?},{b_kind:x?}")?;

        for (a, b) in location.values {
            writeln!(log, "\t{a:#x}, {b:#x}")?;
        }
    }
    for location in cmplog.get_call_log(&mut vm.cpu) {
        writeln!(
            log,
            "{:#x}, has_invalid={}, is_indirect={}",
            location.addr, location.has_invalid, location.is_indirect
        )?;
        let (a_kind, b_kind) = analysis::analyse_call_parameters(location);
        writeln!(log, "\t{a_kind:x?}\n\t{b_kind:x?}")?;
        for (a, b) in &location.values {
            writeln!(log, "\t{}, {}", a.escape_ascii(), b.escape_ascii())?;
        }
    }

    Ok(())
}
