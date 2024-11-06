use serde::Deserialize;

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use std::{collections::HashMap, path::PathBuf};

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
    /// Only generate the commands, don't run them
    Gen(GenArgs),
    /// Generate commands and run them
    Run(RunArgs),
    /// Show stats TUI for a running campaign
    Tui(TuiArgs),
    /// Kills a running session and all spawned processes inside
    Kill(KillArgs),
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
#[derive(Args, Clone, Debug)]
pub struct GenArgs {
    /// Target binary to fuzz
    #[arg(short, long, help = "Instrumented target binary to fuzz")]
    pub target: Option<PathBuf>,
    /// Sanitizer binary to use
    #[arg(
        short = 's',
        long,
        help = "Instrumented with *SAN binary to use",
        required = false
    )]
    pub san_target: Option<PathBuf>,
    /// CMPLOG binary to use
    #[arg(
        short = 'c',
        long,
        help = "Instrumented with CMPLOG binary to use",
        required = false
    )]
    pub cmpl_target: Option<PathBuf>,
    /// Laf-Intel/CMPCOV binary to use
    #[arg(
        short = 'l',
        long,
        help = "Instrumented with Laf-intel/CMPCOV binary to use",
        required = false
    )]
    pub cmpc_target: Option<PathBuf>,
    /// Target binary arguments
    #[arg(
        help = "Target binary arguments, including @@ if needed. Example: `<...> -- -foo --bar baz @@`",
        raw = true,
        required = false
    )]
    pub target_args: Option<Vec<String>>,
    /// Amount of processes to spin up
    #[arg(
        short = 'n',
        long,
        default_value = None,
        value_name = "NUM_PROCS",
        help = "Amount of processes to spin up"
    )]
    pub runners: Option<u32>,
    /// Corpus directory
    #[arg(
        short = 'i',
        long,
        default_value = None,
        help = "Seed corpus directory",
        required = false
    )]
    pub input_dir: Option<PathBuf>,
    /// Output directory
    #[arg(
        short = 'o',
        long,
        default_value = None,
        help = "Solution/Crash output directory",
        required = false
    )]
    pub output_dir: Option<PathBuf>,
    /// Path to dictionary
    #[arg(
        short = 'x',
        long,
        default_value = None,
        value_name = "DICT_FILE",
        help = "Token dictionary to use",
        required = false
    )]
    pub dictionary: Option<PathBuf>,
    /// AFL-Fuzz binary
    #[arg(
        short = 'b',
        long,
        default_value = None,
        help = "Custom path to 'afl-fuzz' binary. If not specified and 'afl-fuzz' is not in $PATH, the program will try to use $AFL_PATH",
        required = false
    )]
    pub afl_binary: Option<String>,
    /// Path to a TOML config file
    #[arg(
        long,
        help = "Spin up a custom tmux session with the fuzzers",
        required = false
    )]
    pub config: Option<PathBuf>,
    /// Use AFL-Fuzz defaults
    #[arg(
        short = 'd',
        long,
        help = "Use afl-fuzz defaults power schedules, queue and mutation strategies",
        required = false,
        action = ArgAction::SetTrue
    )]
    pub use_afl_defaults: bool,
}

impl GenArgs {
    /// Merge the command-line arguments with the configuration
    pub fn merge(&self, config: &Config) -> Self {
        Self {
            target: self.target.clone().or_else(|| {
                config
                    .target
                    .path
                    .clone()
                    .filter(|p| !p.is_empty())
                    .map(PathBuf::from)
            }),
            san_target: self.san_target.clone().or_else(|| {
                config
                    .target
                    .san_path
                    .clone()
                    .filter(|p| !p.is_empty())
                    .map(PathBuf::from)
            }),
            cmpl_target: self.cmpl_target.clone().or_else(|| {
                config
                    .target
                    .cmpl_path
                    .clone()
                    .filter(|p| !p.is_empty())
                    .map(PathBuf::from)
            }),
            cmpc_target: self.cmpc_target.clone().or_else(|| {
                config
                    .target
                    .cmpc_path
                    .clone()
                    .filter(|p| !p.is_empty())
                    .map(PathBuf::from)
            }),
            target_args: self
                .target_args
                .clone()
                .or_else(|| config.target.args.clone().filter(|args| !args.is_empty())),
            runners: Some(self.runners.or(config.afl_cfg.runners).unwrap_or(1)),
            input_dir: self
                .input_dir
                .clone()
                .or_else(|| {
                    config
                        .afl_cfg
                        .seed_dir
                        .clone()
                        .filter(|d| !d.is_empty())
                        .map(PathBuf::from)
                })
                .or_else(|| {
                    // Provide a default path here
                    Some(PathBuf::from(AFL_CORPUS))
                }),
            output_dir: self
                .output_dir
                .clone()
                .or_else(|| {
                    config
                        .afl_cfg
                        .solution_dir
                        .clone()
                        .filter(|d| !d.is_empty())
                        .map(PathBuf::from)
                })
                .or_else(|| {
                    // Provide a default path here
                    Some(PathBuf::from(AFL_OUTPUT))
                }),
            dictionary: self.dictionary.clone().or_else(|| {
                config
                    .afl_cfg
                    .dictionary
                    .clone()
                    .filter(|d| !d.is_empty())
                    .map(PathBuf::from)
            }),
            afl_binary: self
                .afl_binary
                .clone()
                .or_else(|| config.afl_cfg.afl_binary.clone().filter(|b| !b.is_empty())),
            use_afl_defaults: config.afl_cfg.use_afl_defaults.unwrap_or(self.use_afl_defaults),
            config: self.config.clone(),
        }
    }
}

#[derive(ValueEnum, Clone, Debug)]
pub enum SessionRunner {
    Tmux,
    Screen,
}

/// Arguments for the `run` subcommand
#[derive(Args, Clone, Debug)]
pub struct RunArgs {
    /// Arguments for generating the commands
    #[command(flatten)]
    pub gen_args: GenArgs,
    /// Only show the generated commands, don't run them
    #[arg(
        long,
        help = "Output the generated commands w/o executing them",
        required = false
    )]
    pub dry_run: bool,
    /// Runner backend to use
    #[clap(value_enum)]
    #[arg(long = "session-runner", help = "Session runner to use", required = false, default_value_t = SessionRunner::Tmux)]
    pub session_runner: SessionRunner,
    /// Custom tmux session name
    #[arg(
        long = "session-name",
        help = "Custom runner session name",
        required = false
    )]
    pub session_name: Option<String>,
    /// Enable tui mode
    #[arg(long, help = "Enable TUI mode", required = false)]
    pub tui: bool,
    /// Start detached from any session (not compatible with TUI)
    #[arg(
        long,
        help = "Started detached from TMUX/screen session",
        required = false
    )]
    pub detached: bool,
    #[arg(
        long,
        help = "Use a RAMDisk for AFL++. Needs elevated prvileges.",
        required = false
    )]
    pub is_ramdisk: bool,
}

impl RunArgs {
    /// Merge the command-line arguments with the configuration
    pub fn merge(&self, config: &Config) -> Self {
        let gen_args = self.gen_args.merge(config);
        let session_runner = config
            .session
            .runner
            .as_ref()
            .and_then(|s| match s.as_str() {
                "tmux" => Some(SessionRunner::Tmux),
                "screen" => Some(SessionRunner::Screen),
                _ => None,
            })
            .unwrap_or_else(|| self.session_runner.clone());
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
    /// Arguments for the target binary
    pub args: Option<Vec<String>>,
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
    /// Use AFL defaults
    pub use_afl_defaults: Option<bool>,
    /// Partial AFL flags
    pub flags_partial: AflFlagsPartial,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct AflFlagsPartial {
    #[serde(flatten)]
    pub global_flags: FlagGroup,
    pub groups: Vec<FlagGroup>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct FlagGroup {
    pub probability: Option<f32>,
    pub count: Option<u32>,
    #[serde(flatten)]
    pub flags: HashMap<String, toml::Value>,
}

impl FlagGroup {
    pub const fn is_valid(&self) -> bool {
        !(self.probability.is_some() && self.count.is_some())
    }
}

/// Configuration for tmux
#[derive(Deserialize, Default, Debug, Clone)]
pub struct SessionConfig {
    /// Dry run mode
    pub dry_run: Option<bool>,
    /// session name
    pub name: Option<String>,
    /// session runner
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
}

/// Arguments for the `kill` subcommand
#[derive(Args, Clone, Debug, Default)]
pub struct KillArgs {
    /// Session name to kill
    pub session_name: Option<String>,
}
