use crate::{
    afl::{base_cfg::Bcfg, cmd::Printable, cmd_gen::AFLCmdGenerator},
    argument_aggregator::ArgumentAggregator,
    cli::GenArgs,
    commands::Command,
    harness::Harness,
};
use anyhow::{Context, Result};
use std::path::Path;

pub struct GenCommand<'a> {
    args: &'a GenArgs,
    arg_aggregator: &'a ArgumentAggregator,
}

impl<'a> GenCommand<'a> {
    pub fn new(args: &'a GenArgs, arg_aggregator: &'a ArgumentAggregator) -> Self {
        Self {
            args,
            arg_aggregator,
        }
    }

    /// Create an AFL runner
    ///
    /// # Errors
    /// * If any of the provided target binaries are invalid
    ///
    /// # Panics
    /// If the main target binary is empty
    pub fn create_afl_runner(
        gen_args: &GenArgs,
        raw_afl_flags: Option<&String>,
        is_ramdisk: bool,
    ) -> Result<AFLCmdGenerator> {
        let harness = Harness::new(
            gen_args.target.clone().unwrap(),
            gen_args.target_args.clone(),
        )?
        .with_sanitizer(gen_args.san_target.clone())?
        .with_cmplog(gen_args.cmpl_target.clone())?
        .with_cmpcov(gen_args.cmpc_target.clone())?
        .with_coverage(gen_args.san_target.clone())?;

        let seed = if gen_args.use_seed_afl {
            gen_args.seed
        } else {
            None
        };

        let afl_meta = Bcfg::new(
            gen_args
                .input_dir
                .clone()
                .unwrap_or_else(|| Path::new(crate::cli::AFL_CORPUS).to_path_buf()),
            gen_args
                .output_dir
                .clone()
                .unwrap_or_else(|| Path::new("/tmp/afl_output").to_path_buf()),
        )
        .with_dictionary(gen_args.dictionary.clone())
        .with_raw_afl_flags(raw_afl_flags)
        .with_afl_binary(gen_args.afl_binary.clone())
        .with_ramdisk(is_ramdisk);

        Ok(AFLCmdGenerator::new(
            harness,
            gen_args.runners.unwrap_or(1),
            &afl_meta,
            gen_args.mode,
            seed,
        ))
    }
}

impl Command for GenCommand<'_> {
    fn execute(&self) -> Result<()> {
        let (merged_args, raw_afl_flags) = self.arg_aggregator.merge_gen_args(self.args)?;
        let afl_generator = Self::create_afl_runner(&merged_args, raw_afl_flags.as_ref(), false)
            .context("Failed to create AFL runner")?;
        afl_generator
            .run()
            .context("Failed to run AFL generator")?
            .print();
        Ok(())
    }
}
