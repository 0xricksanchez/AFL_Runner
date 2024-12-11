use crate::{
    cli::CovArgs, commands::Command, config_manager::ConfigManager, coverage::CoverageCollector,
};
use anyhow::Result;

pub struct CovCommand<'a> {
    args: &'a CovArgs,
    config_manager: &'a ConfigManager,
}

impl<'a> CovCommand<'a> {
    pub fn new(args: &'a CovArgs, config_manager: &'a ConfigManager) -> Self {
        Self {
            args,
            config_manager,
        }
    }
}

impl Command for CovCommand<'_> {
    fn execute(&self) -> Result<()> {
        let merged_args = self.config_manager.merge_cov_args(self.args)?;
        let mut cov_collector =
            CoverageCollector::new(merged_args.target.unwrap(), merged_args.output_dir.unwrap())?;

        if let Some(target_args) = &merged_args.target_args {
            cov_collector.with_target_args(target_args.clone());
        }

        if merged_args.split_report {
            cov_collector.with_split_report(true);
        }

        if merged_args.show_args.is_some() {
            cov_collector.with_misc_show_args(merged_args.show_args.clone().unwrap());
        }

        if merged_args.report_args.is_some() {
            cov_collector.with_misc_report_args(merged_args.report_args.clone().unwrap());
        }

        if merged_args.text_report {
            cov_collector.with_html(false);
        }

        cov_collector.collect()
    }
}
