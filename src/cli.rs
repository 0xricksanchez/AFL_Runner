use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use serde::Deserialize;
use std::path::PathBuf;

use crate::afl::mode::Mode;

/// Default corpus directory
pub const AFL_CORPUS: &str = "/tmp/afl_input";
/// Default output directory
const AFL_OUTPUT: &str = "/tmp/afl_output";

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

// Common trait for config merging behavior
pub trait ConfigMerge<T> {
    fn merge_with_config(&self, config: &Config) -> T;
}

/// Arguments for the `cov` subcommand
#[derive(Args, Clone, Debug, Default)]
pub struct CovArgs {
    /// Target binary instrumented for coverage collection
    #[arg(
        short,
        long,
        help = "Instrumented target binary for coverage collection"
    )]
    pub target: Option<PathBuf>,
    /// Target binary arguments
    #[arg(help = "Target binary arguments, including @@ if needed", raw = true)]
    pub target_args: Option<Vec<String>>,
    /// Output directory
    #[arg(short = 'i', long, help = "Top-level AFL++ output directory")]
    pub output_dir: Option<PathBuf>,
    /// Do *NOT* merge all coverage files into a single report
    #[arg(long, help = "Do *not* merge all coverage files into a single report", action = ArgAction::SetTrue)]
    pub split_report: bool,
    /// Force text-based coverage report
    #[arg(long, help = "Force text-based coverage report", action = ArgAction::SetTrue)]
    pub text_report: bool,
    /// Misc llvm-cov show arguments
    #[arg(short = 'a', long, help = "Miscellaneous llvm-cov show arguments")]
    pub show_args: Option<Vec<String>>,
    /// Misc llvm-cov report arguments
    #[arg(short = 'r', long, help = "Miscellaneous llvm-cov report arguments")]
    pub report_args: Option<Vec<String>>,
    /// Path to a TOML config file
    #[arg(long, help = "Path to TOML config file")]
    pub config: Option<PathBuf>,
}

impl ConfigMerge<Self> for CovArgs {
    fn merge_with_config(&self, config: &Config) -> Self {
        let merge_path = |opt: Option<PathBuf>, cfg_str: Option<String>| {
            opt.or_else(|| cfg_str.filter(|p| !p.is_empty()).map(PathBuf::from))
        };

        Self {
            target: merge_path(self.target.clone(), config.target.cov_path.clone()),
            target_args: self
                .target_args
                .clone()
                .or_else(|| config.target.args.clone().filter(|args| !args.is_empty())),
            output_dir: merge_path(self.output_dir.clone(), config.afl_cfg.solution_dir.clone())
                .or_else(|| Some(PathBuf::from(AFL_OUTPUT))),
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

/// Arguments for the `tui` subcommand
#[derive(Args, Clone, Debug, Default)]
pub struct TuiArgs {
    /// Path to a `AFLPlusPlus` campaign directory, e.g. `afl_output`
    #[arg(
        help = "Path to a AFLPlusPlus campaign directory, e.g. `afl_output`",
        required = true
    )]
    pub afl_output: PathBuf,
}

/// Arguments for the `gen` subcommand
#[derive(Args, Clone, Debug, Default)]
pub struct GenArgs {
    /// Target binary to fuzz
    #[arg(short, long, help = "Instrumented target binary to fuzz")]
    pub target: Option<PathBuf>,
    /// Sanitizer binary to use
    #[arg(short = 's', long, help = "Instrumented with *SAN binary to use")]
    pub san_target: Option<PathBuf>,
    /// CMPLOG binary to use
    #[arg(short = 'c', long, help = "Instrumented with CMPLOG binary to use")]
    pub cmpl_target: Option<PathBuf>,
    /// Laf-Intel/CMPCOV binary to use
    #[arg(
        short = 'l',
        long,
        help = "Instrumented with Laf-intel/CMPCOV binary to use"
    )]
    pub cmpc_target: Option<PathBuf>,
    /// Target binary arguments
    #[arg(help = "Target binary arguments, including @@ if needed", raw = true)]
    pub target_args: Option<Vec<String>>,
    /// Amount of processes to spin up
    #[arg(
        short = 'n',
        long,
        value_name = "NUM_PROCS",
        help = "Amount of processes to spin up"
    )]
    pub runners: Option<u32>,
    /// Corpus directory
    #[arg(short = 'i', long, help = "Seed corpus directory")]
    pub input_dir: Option<PathBuf>,
    /// Output directory
    #[arg(short = 'o', long, help = "Solution/Crash output directory")]
    pub output_dir: Option<PathBuf>,
    /// Path to dictionary
    #[arg(
        short = 'x',
        long,
        value_name = "DICT_FILE",
        help = "Token dictionary to use"
    )]
    pub dictionary: Option<PathBuf>,
    /// AFL-Fuzz binary
    #[arg(short = 'b', long, help = "Custom path to 'afl-fuzz' binary")]
    pub afl_binary: Option<String>,
    /// Path to a TOML config file
    #[arg(long, help = "Path to TOML config file")]
    pub config: Option<PathBuf>,
    /// Select the mode that is used for command generation
    #[arg(
        value_enum,
        short = 'm',
        long,
        help = "Select ",
        default_value = "multiple-cores"
    )]
    pub mode: Mode,
    /// Seed to seed `AFL_Runners` internal PRNG
    #[arg(
        long,
        help = "Seed for AFL_Runners PRNG for deterministic command generation",
        value_name = "AFLR_SEED"
    )]
    pub seed: Option<u64>,
    /// Toggle to relay the seed to AFL++ as well
    #[arg(long, help = "Forward AFLR seed to AFL++", action = ArgAction::SetTrue, requires="seed")]
    pub use_seed_afl: bool,
}

impl ConfigMerge<Self> for GenArgs {
    fn merge_with_config(&self, config: &Config) -> Self {
        let merge_path = |opt: Option<PathBuf>, cfg_str: Option<String>| {
            opt.or_else(|| cfg_str.filter(|p| !p.is_empty()).map(PathBuf::from))
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
                .or_else(|| Some(PathBuf::from(AFL_CORPUS))),
            output_dir: merge_path(self.output_dir.clone(), config.afl_cfg.solution_dir.clone())
                .or_else(|| Some(PathBuf::from(AFL_OUTPUT))),
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

/// Session runner types
#[derive(ValueEnum, Clone, Debug, Default)]
pub enum SessionRunner {
    /// Use tmux as the session runner
    #[default]
    Tmux,
    /// Use screen as the session runner
    Screen,
}

impl From<&str> for SessionRunner {
    fn from(s: &str) -> Self {
        match s {
            "screen" => Self::Screen,
            _ => Self::Tmux,
        }
    }
}

/// Arguments for the `run` subcommand
#[derive(Args, Clone, Debug, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct RunArgs {
    /// Arguments for generating the commands
    #[command(flatten)]
    pub gen_args: GenArgs,
    /// Only show the generated commands, don't run them
    #[arg(long, help = "Output commands without executing")]
    pub dry_run: bool,
    /// Runner backend to use
    #[clap(value_enum)]
    #[arg(long = "session-runner", help = "Session runner to use", default_value_t = SessionRunner::Tmux)]
    pub session_runner: SessionRunner,
    /// Custom tmux session name
    #[arg(long = "session-name", help = "Custom runner session name")]
    pub session_name: Option<String>,
    /// Enable tui mode
    #[arg(long, help = "Enable TUI mode")]
    pub tui: bool,
    /// Start detached from any session (not compatible with TUI)
    #[arg(long, help = "Start detached from session")]
    pub detached: bool,
    /// Use `RAMDisk` for AFL++
    #[arg(long, help = "Use RAMDisk for AFL++")]
    pub is_ramdisk: bool,
}

impl ConfigMerge<Self> for RunArgs {
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

/// Configuration for the Parallelized `AFLPlusPlus` Campaign Runner
#[derive(Deserialize, Default, Debug, Clone)]
pub struct Config {
    /// Target configuration
    pub target: TargetConfig,
    /// Coverage configuration
    pub coverage: CoverageConfig,
    /// AFL configuration
    pub afl_cfg: AflConfig,
    /// Session configuration
    pub session: SessionConfig,
    /// Miscellaneous configuration
    pub misc: MiscConfig,
}

/// Configuration for the target binary
#[derive(Deserialize, Default, Debug, Clone)]
pub struct TargetConfig {
    /// Path to the target binary
    pub path: Option<String>,
    /// Path to the sanitizer binary
    pub san_path: Option<String>,
    /// Path to the CMPLOG binary
    pub cmpl_path: Option<String>,
    /// Path to the CMPCOV binary
    pub cmpc_path: Option<String>,
    /// Path to the Coverage binary
    pub cov_path: Option<String>,
    /// Arguments for the target binary
    pub args: Option<Vec<String>>,
}

/// Configuration for the target binary
#[derive(Deserialize, Default, Debug, Clone)]
pub struct CoverageConfig {
    /// HTML- or Text-based coverage report
    pub report_type: Option<String>,
    /// Split coverage report
    pub split_report: Option<bool>,
    /// Misc llvm-cov show arguments
    pub misc_show_args: Option<Vec<String>>,
    /// Misc llvm-cov report arguments
    pub misc_report_args: Option<Vec<String>>,
}

/// Configuration for AFL
#[derive(Deserialize, Default, Debug, Clone)]
pub struct AflConfig {
    /// Number of AFL runners
    pub runners: Option<u32>,
    /// Path to the AFL binary
    pub afl_binary: Option<String>,
    /// Path to the seed directory
    pub seed_dir: Option<String>,
    /// Path to the solution directory
    pub solution_dir: Option<String>,
    /// Path to the dictionary
    pub dictionary: Option<String>,
    /// Additional AFL flags
    pub afl_flags: Option<String>,
    /// Mode to generate commands
    pub mode: Option<Mode>,
}

/// Configuration for tmux/screen sessions
#[derive(Deserialize, Default, Debug, Clone)]
pub struct SessionConfig {
    /// Dry run mode
    pub dry_run: Option<bool>,
    /// Session name
    pub name: Option<String>,
    /// Session runner
    pub runner: Option<String>,
}

/// Miscellaneous configuration options
#[derive(Deserialize, Default, Debug, Clone)]
pub struct MiscConfig {
    /// Enable TUI mode
    pub tui: Option<bool>,
    /// Enabled detached mode
    pub detached: Option<bool>,
    /// Use a Ramdisk for AFL++ to store `.cur_input`
    pub is_ramdisk: Option<bool>,
    /// Seed for ALFR internal PRNG
    pub seed: Option<u64>,
    /// Use seed for AFL++ as well
    pub use_seed_afl: Option<bool>,
}

/// Arguments for the `kill` subcommand
#[derive(Args, Clone, Debug, Default)]
pub struct KillArgs {
    /// Session name to kill
    pub session_name: Option<String>,
}

// Add tests module
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_runner_from_str() {
        assert!(matches!(SessionRunner::from("tmux"), SessionRunner::Tmux));
        assert!(matches!(
            SessionRunner::from("screen"),
            SessionRunner::Screen
        ));
        assert!(matches!(
            SessionRunner::from("invalid"),
            SessionRunner::Tmux
        ));
    }

    #[test]
    fn test_gen_args_merge() {
        let args = GenArgs {
            target: Some(PathBuf::from("/custom/path")),
            runners: Some(4),
            ..GenArgs::default()
        };

        let config = Config {
            target: TargetConfig {
                path: Some("/default/path".into()),
                ..TargetConfig::default()
            },
            afl_cfg: AflConfig {
                runners: Some(2),
                ..AflConfig::default()
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
            session_runner: SessionRunner::Tmux,
            ..RunArgs::default()
        };

        let config = Config {
            session: SessionConfig {
                runner: Some("screen".into()),
                ..SessionConfig::default()
            },
            ..Config::default()
        };

        let merged = args.merge_with_config(&config);
        assert!(merged.dry_run);
        assert!(matches!(merged.session_runner, SessionRunner::Screen));
    }
}
