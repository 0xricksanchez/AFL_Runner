use anyhow::{Context, Result};
use std::path::Path;
use std::path::PathBuf;
use std::process;
use tempfile::TempDir;

use crate::{argument_aggregator::ArgumentAggregator, cli::AddSeedArgs, commands::Command};

pub struct AddSeedCommand<'a> {
    args: &'a AddSeedArgs,
    arg_aggregator: &'a ArgumentAggregator,
}

impl<'a> AddSeedCommand<'a> {
    pub fn new(args: &'a AddSeedArgs, arg_aggregator: &'a ArgumentAggregator) -> Self {
        Self {
            args,
            arg_aggregator,
        }
    }

    fn execute_add_seed_afl(
        seed: &Path,
        corpus_dir: &Path,
        target: &Path,
        target_args: &[String],
    ) -> Result<()> {
        let target = if target.starts_with("./") || target.starts_with("/") {
            target.to_path_buf()
        } else {
            Path::new("./").join(target)
        };

        let status = process::Command::new("afl-fuzz")
            .env("AFL_BENCH_JUST_ONE", "1")
            .env("AFL_FAST_CAL", "1")
            .env("AFL_IGNORE_SEED_PROBLEMS", "1")
            .env("AFL_AUTORESUME", "1")
            .arg("-i")
            .arg(seed)
            .arg("-o")
            .arg(corpus_dir)
            .arg("-S")
            .arg(&uuid::Uuid::new_v4().simple().to_string()[..8])
            .arg("--")
            .arg(target)
            .args(target_args)
            .stdout(process::Stdio::null())
            .stderr(process::Stdio::null())
            .status()
            .context("Failed to execute afl-fuzz")?;

        if !status.success() {
            return Err(anyhow::anyhow!(
                "afl-fuzz failed with exit code: {}",
                status.code().unwrap_or(-1),
            ));
        }

        Ok(())
    }

    fn add_seed(
        seed: &PathBuf,
        target: &Path,
        target_args: &[String],
        output_dir: &Path,
    ) -> Result<()> {
        if !seed.exists() {
            return Err(anyhow::anyhow!("Seed file does not exist: {:?}", seed));
        }

        if seed.is_file() {
            let tmpdir = TempDir::new().context("Failed to create temporary directory")?;
            let new_seed_dir = tmpdir.path();
            std::fs::copy(seed, new_seed_dir.join(seed.file_name().unwrap()))?;

            Self::execute_add_seed_afl(new_seed_dir, output_dir, target, target_args)
        } else {
            Self::execute_add_seed_afl(seed, output_dir, target, target_args)
        }
    }
}

impl Command for AddSeedCommand<'_> {
    fn execute(&self) -> Result<()> {
        let merged_args = self.arg_aggregator.merge_add_seed_args(self.args)?;

        let target = merged_args.target.as_ref().context("Target is required")?;
        let target_args = merged_args
            .target_args
            .as_ref()
            .context("Target arguments are required")?;
        let output_dir = merged_args
            .output_dir
            .as_ref()
            .context("Output directory is required")?;

        Self::add_seed(&merged_args.seed, target, target_args, output_dir)?;
        println!("[+] Seeds added successfully");
        Ok(())
    }
}
