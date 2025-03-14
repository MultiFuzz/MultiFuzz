mod check;
mod replay;
pub mod stage;
pub mod trace;

pub use check::init as enable_checks;
pub use replay::{analyze_crashes, replay, save_block_coverage};

use crate::{input::MultiStream, utils};

pub(crate) fn validate_last_exec(fuzzer: &mut crate::Fuzzer, exit: crate::VmExit) -> Option<()> {
    tracing::info!("validating input with new coverage: {:?}", fuzzer.state.new_bits);
    let expected_new_bits = fuzzer.state.new_bits.clone();

    let icount = fuzzer.vm.cpu.icount;
    let pc = fuzzer.vm.cpu.read_pc();
    let trace = fuzzer.path_tracer.map(|x| x.get_last_blocks(&mut fuzzer.vm));
    tracing::info!(
        "[{}] validating exit @ {pc:#x} {exit:?}",
        fuzzer.input_id.unwrap_or(usize::MAX)
    );

    crate::Snapshot::restore_initial(fuzzer);
    fuzzer.reset_input_cursor().unwrap();
    fuzzer.write_input_to_target().unwrap();
    tracing::info!("PC reset to: {:#x}", fuzzer.vm.cpu.read_pc());
    let root_exit = fuzzer.execute()?;
    tracing::info!("Ended with exit: {root_exit:?}");

    if !(icount == fuzzer.vm.cpu.icount && pc == fuzzer.vm.cpu.read_pc() && exit == root_exit) {
        eprintln!(
            "Execution diverged when executing from snapshot (starting at icount={}):
    snapshot: icount={icount}, pc={pc:#x}, exit={exit:?}, input_bytes={} (read={}),
    root    : icount={}, pc={:#x}, exit={root_exit:?}",
            fuzzer.prefix_snapshot.as_ref().map_or(0, |x| x.vm.cpu.icount),
            fuzzer.state.input.total_bytes(),
            fuzzer.state.input.bytes_read(),
            fuzzer.vm.cpu.icount,
            fuzzer.vm.cpu.read_pc(),
        );

        let root_trace = fuzzer.path_tracer.map(|x| x.get_last_blocks(&mut fuzzer.vm));
        if let (Some(snapshot), Some(root)) = (trace, root_trace) {
            if let Some((a, b)) = snapshot.iter().zip(&root).find(|(a, b)| a != b) {
                eprintln!("Diverged at:\n    snapshot: {a:x?}\n    root    : {b:x?}");
            }
            else {
                eprintln!("No divergance? One of the traces was shorter.");
            }

            trace::save_path_trace(&fuzzer.workdir.join("snapshot_trace.txt"), &snapshot);
            trace::save_path_trace(&fuzzer.workdir.join("root_trace.txt"), &root);
        }
        else {
            eprintln!("Missing traces for executions (run with `ICICLE_TRACK_PATH=1` to obtain)");
        }

        let _ = std::fs::write(
            fuzzer.workdir.join("disasm.asm"),
            icicle_vm::debug::dump_disasm(&fuzzer.vm).unwrap(),
        );

        let _ = std::fs::write(
            fuzzer.workdir.join("diverging_input.bin"),
            fuzzer.state.input.to_bytes(),
        );
        panic!();
    }

    let new_bits = fuzzer.coverage.new_bits(&mut fuzzer.vm);
    if new_bits != expected_new_bits {
        eprintln!("coverage bit map diverged! expected: {expected_new_bits:?}, got {new_bits:?}");
    }

    Some(())
}

/// Performs dynamic modifications of `input` based on environment variables
pub fn modify_input(input: &mut MultiStream) {
    let mut modified = false;

    if let Ok(trim) = std::env::var("TRIM") {
        modified = true;
        if let Some((stream, offset, size)) = parse_trim(&trim) {
            input.streams.get_mut(&stream).unwrap().bytes.drain(offset..offset + size);
        }
    }

    if let Ok(insert) = std::env::var("INSERT") {
        modified = true;
        for insert in insert.split(';') {
            if let Some((stream, offset, bytes)) = parse_modification(insert) {
                utils::insert_slice(
                    &mut input.streams.get_mut(&stream).unwrap().bytes,
                    &bytes,
                    offset,
                );
            }
        }
    }

    if let Ok(insert) = std::env::var("REPLACE") {
        modified = true;
        for insert in insert.split(';') {
            if let Some((stream, offset, bytes)) = parse_modification(insert) {
                tracing::info!("{stream:#x}@{offset} replacing {} bytes", bytes.len());
                let dst = &mut input.streams.get_mut(&stream).unwrap().bytes;
                dst[offset..offset + bytes.len()].copy_from_slice(&bytes);
            }
            else {
                tracing::warn!("invalid modification: {insert}");
            }
        }
    }

    if modified {
        // Save a copy of the modified version of the input for debugging and analysis.
        let _ = std::fs::write("workdir/modified_input", input.to_bytes());
    }
}

/// Parses a trim expression of the form: "<stream addr>,<stream offset>,<size>"
fn parse_trim(trim: &str) -> Option<(u64, usize, usize)> {
    use icicle_fuzzing::parse_u64_with_prefix;

    let mut parts = trim.split(',');
    let stream = parse_u64_with_prefix(parts.next()?)?;
    let offset = parse_u64_with_prefix(parts.next()?)?;
    let size = parse_u64_with_prefix(parts.next()?)?;

    Some((stream, offset as usize, size as usize))
}

/// Parses an insertion/replacement expression of the form:
///
/// "<stream addr>,<stream offset>,<hex bytes>"
///
/// e.g. 0x40000418,0,0a0b0c0d
fn parse_modification(insert: &str) -> Option<(u64, usize, Vec<u8>)> {
    use icicle_fuzzing::parse_u64_with_prefix;
    use icicle_vm::cpu::utils::bytes_from_hex;

    let mut parts = insert.split(',');
    let stream = parse_u64_with_prefix(parts.next()?)?;
    let offset = parse_u64_with_prefix(parts.next()?)?;
    let bytes = bytes_from_hex(parts.next()?)?;

    Some((stream, offset as usize, bytes))
}
