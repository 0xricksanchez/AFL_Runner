use crate::{cli::TuiArgs, commands::Command, session::CampaignData, tui::Tui};
use anyhow::{bail, Context, Result};
use std::path::Path;

pub struct RenderCommand<'a> {
    args: &'a TuiArgs,
}

impl<'a> RenderCommand<'a> {
    pub fn new(args: &'a TuiArgs) -> Self {
        Self { args }
    }

    fn validate_output_dir(output_dir: &Path) -> Result<()> {
        for entry in output_dir.read_dir()? {
            let path = entry?.path();
            if path.is_dir() {
                let fuzzer_stats = path.join("fuzzer_stats");
                if !fuzzer_stats.exists() {
                    bail!(
                        "Invalid output directory: {} is missing 'fuzzer_stats' file",
                        path.display()
                    );
                }
            }
        }
        Ok(())
    }
}

impl Command for RenderCommand<'_> {
    fn execute(&self) -> Result<()> {
        if !self.args.afl_output.exists() {
            bail!("Output directory is required for TUI mode");
        }

        Self::validate_output_dir(&self.args.afl_output)?;

        let mut cdata = CampaignData::default();
        Tui::run(&self.args.afl_output, None, &mut cdata).context("Failed to run TUI")
    }
}
