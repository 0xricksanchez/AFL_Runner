use clap::{Parser, Subcommand};
use serde::Deserialize;

mod afl;
pub mod constants;
mod cov;
mod coverage;
mod gen;
mod kill;
mod misc;
mod run;
pub mod session;
mod target;
mod tui;
mod utils;

pub use afl::AflArgs;
pub use cov::CovArgs;
pub use coverage::CoverageArgs;
pub use gen::GenArgs;
pub use kill::KillArgs;
pub use misc::MiscArgs;
pub use run::RunArgs;
pub use session::SessionArgs;
pub use session::SessionRunner;
pub use target::TargetArgs;
pub use tui::TuiArgs;

pub use constants::{AFL_CORPUS, AFL_OUTPUT};

/// Command-line interface for the Parallelized `AFLPlusPlus` Campaign Runner
#[derive(Parser, Debug, Clone)]
#[command(name = "Parallelized AFLPlusPlus Campaign Runner")]
#[command(author = "C.K. <admin@0x434b.dev>")]
#[command(version = env!("CARGO_PKG_VERSION"))]
pub struct Cli {
    /// Subcommand to execute
    #[command(subcommand)]
    pub cmd: Commands,
}

/// Available subcommands
#[derive(Subcommand, Clone, Debug)]
pub enum Commands {
    /// Only generate commands for fuzzing campaign, don't run them
    Gen(GenArgs),
    /// Generate fuzzing campaign and run it
    Run(RunArgs),
    /// Collect and visualize fuzzing coverage
    Cov(CovArgs),
    /// Show stats TUI for a running campaign
    Tui(TuiArgs),
    /// Kills a running session and all spawned processes inside
    Kill(KillArgs),
}

#[derive(Deserialize, Default, Debug, Clone)]
pub struct Config {
    /// Target configuration
    pub target: TargetArgs,
    /// Coverage configuration
    pub coverage: CoverageArgs,
    /// AFL++ configuration
    pub afl_cfg: AflArgs,
    /// Session configuration
    pub session: SessionArgs,
    /// Miscellaneous configuration
    pub misc: MiscArgs,
}

pub trait ConfigMerge<T> {
    fn merge_with_config(&self, config: &Config) -> T;
}

impl ConfigMerge<Self> for crate::cli::GenArgs {
    fn merge_with_config(&self, config: &Config) -> Self {
        let merge_path = |opt: Option<std::path::PathBuf>, cfg_str: Option<String>| {
            opt.or_else(|| {
                cfg_str
                    .filter(|p| !p.is_empty())
                    .map(std::path::PathBuf::from)
            })
        };

        Self {
            target: merge_path(self.target.clone(), config.target.path.clone()),
            san_target: merge_path(self.san_target.clone(), config.target.san_path.clone()),
            cmpl_target: merge_path(self.cmpl_target.clone(), config.target.cmpl_path.clone()),
            cmpc_target: merge_path(self.cmpc_target.clone(), config.target.cmpc_path.clone()),
            target_args: self
                .target_args
                .clone()
                .or_else(|| config.target.args.clone().filter(|args| !args.is_empty())),
            runners: Some(self.runners.or(config.afl_cfg.runners).unwrap_or(1)),
            input_dir: merge_path(self.input_dir.clone(), config.afl_cfg.seed_dir.clone())
                .or_else(|| Some(std::path::PathBuf::from(crate::cli::constants::AFL_CORPUS))),
            output_dir: merge_path(self.output_dir.clone(), config.afl_cfg.solution_dir.clone())
                .or_else(|| Some(std::path::PathBuf::from(crate::cli::constants::AFL_OUTPUT))),
            dictionary: merge_path(self.dictionary.clone(), config.afl_cfg.dictionary.clone()),
            afl_binary: self
                .afl_binary
                .clone()
                .or_else(|| config.afl_cfg.afl_binary.clone().filter(|b| !b.is_empty())),
            mode: config.afl_cfg.mode.unwrap_or(self.mode),
            seed: self.seed.or(config.misc.seed),
            use_seed_afl: config.misc.use_seed_afl.unwrap_or(self.use_seed_afl),
            config: self.config.clone(),
        }
    }
}

impl ConfigMerge<Self> for crate::cli::RunArgs {
    fn merge_with_config(&self, config: &Config) -> Self {
        let gen_args = self.gen_args.merge_with_config(config);
        let session_runner = config
            .session
            .runner
            .as_deref()
            .map_or_else(|| self.session_runner.clone(), SessionRunner::from);

        Self {
            gen_args,
            dry_run: self.dry_run || config.session.dry_run.unwrap_or(false),
            session_runner,
            session_name: self
                .session_name
                .clone()
                .or_else(|| config.session.name.clone().filter(|s| !s.is_empty())),
            tui: if self.dry_run {
                false
            } else {
                self.tui || config.misc.tui.unwrap_or(false)
            },
            detached: if self.dry_run {
                false
            } else {
                self.detached || config.misc.detached.unwrap_or(false)
            },
            is_ramdisk: if self.is_ramdisk {
                false
            } else {
                self.is_ramdisk || config.misc.is_ramdisk.unwrap_or(false)
            },
        }
    }
}

impl ConfigMerge<Self> for crate::cli::CovArgs {
    fn merge_with_config(&self, config: &Config) -> Self {
        let merge_path = |opt: Option<std::path::PathBuf>, cfg_str: Option<String>| {
            opt.or_else(|| {
                cfg_str
                    .filter(|p| !p.is_empty())
                    .map(std::path::PathBuf::from)
            })
        };

        Self {
            target: merge_path(self.target.clone(), config.target.cov_path.clone()),
            target_args: self
                .target_args
                .clone()
                .or_else(|| config.target.args.clone().filter(|args| !args.is_empty())),
            output_dir: merge_path(self.output_dir.clone(), config.afl_cfg.solution_dir.clone())
                .or_else(|| Some(std::path::PathBuf::from(crate::cli::constants::AFL_OUTPUT))),
            split_report: config.coverage.split_report.unwrap_or(self.split_report),
            text_report: match config.coverage.report_type.as_deref() {
                Some("HTML" | "html") => false,
                Some("TEXT" | "text") => true,
                Some(unknown) => {
                    eprintln!(
                        "Warning: Unknown report type '{}', defaulting to {}",
                        unknown,
                        if self.text_report { "text" } else { "html" }
                    );
                    self.text_report
                }
                None => self.text_report,
            },
            show_args: self.show_args.clone().or_else(|| {
                config
                    .coverage
                    .misc_show_args
                    .clone()
                    .filter(|args| !args.is_empty())
            }),
            report_args: self.report_args.clone().or_else(|| {
                config
                    .coverage
                    .misc_report_args
                    .clone()
                    .filter(|args| !args.is_empty())
            }),
            config: self.config.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{GenArgs, RunArgs};
    use std::path::PathBuf;

    #[test]
    fn test_gen_args_merge() {
        let args = GenArgs {
            target: Some(PathBuf::from("/custom/path")),
            runners: Some(4),
            ..GenArgs::default()
        };

        let config = Config {
            target: TargetArgs {
                path: Some("/default/path".into()),
                ..TargetArgs::default()
            },
            afl_cfg: AflArgs {
                runners: Some(2),
                ..AflArgs::default()
            },
            ..Config::default()
        };

        let merged = args.merge_with_config(&config);
        assert_eq!(merged.target.unwrap(), PathBuf::from("/custom/path"));
        assert_eq!(merged.runners, Some(4));
    }

    #[test]
    fn test_run_args_merge() {
        let gen_args = GenArgs::default();
        let args = RunArgs {
            gen_args,
            dry_run: true,
            session_runner: crate::cli::session::SessionRunner::Tmux,
            ..RunArgs::default()
        };

        let config = Config {
            session: SessionArgs {
                runner: Some("screen".into()),
                ..SessionArgs::default()
            },
            ..Config::default()
        };

        let merged = args.merge_with_config(&config);
        assert!(merged.dry_run);
        assert!(matches!(
            merged.session_runner,
            crate::cli::session::SessionRunner::Screen
        ));
    }
}
