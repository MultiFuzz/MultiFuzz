//! Utilities for testing individual stages.

use std::path::Path;

use anyhow::Context;

use crate::{
    config::{self, Config},
    debugging::modify_input,
    i2s,
    input::MultiStream,
    monitor::LocalStats,
    Fuzzer, FuzzerStage, Stage,
};

pub fn run_stage(config: Config, input_path: &Path, stage: Stage) -> anyhow::Result<()> {
    let _workdir_lock = config::init_workdir(&config).with_context(|| {
        format!("Failed to initialize working directory at: {}", config.workdir.display())
    })?;

    let mut fuzzer = Fuzzer::new_debug(config)?;

    let mut input = MultiStream::from_path(input_path)?;
    modify_input(&mut input);

    fuzzer.state.input = input;
    let mut stats = LocalStats::default();

    match stage {
        Stage::InputToState => {
            i2s::ColorizationStage::run(&mut fuzzer, &mut stats)?;
            i2s::I2SReplaceStage::run(&mut fuzzer, &mut stats)?;
        }
        _ => anyhow::bail!("Unsupported test"),
    }

    Ok(())
}
