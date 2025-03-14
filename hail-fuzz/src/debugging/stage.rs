//! Utilities for testing individual stages.

use std::path::Path;

use crate::{
    Fuzzer, FuzzerStage, Stage, config::Config, debugging::modify_input, i2s, input::MultiStream,
    monitor::LocalStats,
};

pub fn run_stage(config: Config, input_path: &Path, stage: Stage) -> anyhow::Result<()> {
    let mut fuzzer = Fuzzer::new_debug(config)?;
    fuzzer.workdir = "workdir".into();

    let mut input = MultiStream::from_path(input_path)?;
    modify_input(&mut input);

    tracing::info!(
        "Loaded input with {} streams, {} bytes",
        input.count_non_empty_streams(),
        input.total_bytes(),
    );

    fuzzer.state.input = input;
    fuzzer.input_id = Some(fuzzer.corpus.add(&fuzzer.state));

    run_once(&mut fuzzer)?;

    let mut stats = LocalStats::default();

    match stage {
        Stage::InputToState => {
            tracing::info!("Running Colorization");
            i2s::ColorizationStage::run(&mut fuzzer, &mut stats)?;
            tracing::info!("Running I2S");
            i2s::I2SReplaceStage::run(&mut fuzzer, &mut stats)?;
        }
        _ => anyhow::bail!("Unsupported test"),
    }

    Ok(())
}

fn run_once(fuzzer: &mut Fuzzer) -> anyhow::Result<()> {
    fuzzer.reset_input_cursor().unwrap();
    fuzzer.write_input_to_target().unwrap();

    let exit = fuzzer.execute().ok_or_else(|| anyhow::format_err!("Failed to execute"))?;

    fuzzer.auto_trim_input().unwrap();
    fuzzer.check_exit_state(exit)?;

    Ok(())
}
