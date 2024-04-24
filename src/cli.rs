use serde::Deserialize;

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

/// Default corpus directory
pub const AFL_CORPUS: &str = "/tmp/afl_input";
/// Default output directory
const AFL_OUTPUT: &str = "/tmp/afl_output";

#[derive(Parser, Debug, Clone)]
#[command(name = "Parallelized AFLPlusPlus Campaign Runner")]
#[command(author = "C.K. <admin@0x434b.dev>")]
#[command(version = "0.3.0")]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Commands,
}

#[derive(Subcommand, Clone, Debug)]
pub enum Commands {
    /// Only generate the commands, don't run them
    Gen(GenArgs),
    /// Generate commands and run them
    Run(RunArgs),
    /// Show stats TUI for a running campaign
    Tui(TuiArgs),
}

#[derive(Args, Clone, Debug, Default)]
pub struct TuiArgs {
    /// Path to a AFLPlusPlus campaign directory, e.g. `afl_output`
    #[arg(
        help = "Path to a AFLPlusPlus campaign directory, e.g. `afl_output`",
        required = true
    )]
    pub afl_output: PathBuf,
}

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
}

impl GenArgs {
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
            runners: Some(self.runners.clone().or(config.afl_cfg.runners).unwrap_or(1)),
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
            config: self.config.clone(),
        }
    }
}

#[derive(Args, Clone, Debug)]
pub struct RunArgs {
    #[command(flatten)]
    pub gen_args: GenArgs,
    /// Only show the generated commands, don't run them
    #[arg(
        long,
        help = "Output the generated commands w/o executing them",
        required = false
    )]
    pub dry_run: bool,
    /// Custom tmux session name
    #[arg(short = 'm', long, help = "Custom tmux session name", required = false)]
    pub tmux_session_name: Option<String>,
    /// Enable tui mode
    #[arg(long, help = "Enable TUI mode", required = false)]
    pub tui: bool,
}

impl RunArgs {
    pub fn merge(&self, config: &Config) -> Self {
        let gen_args = self.gen_args.merge(config);
        Self {
            gen_args,
            dry_run: self.dry_run.clone() || config.tmux.dry_run.unwrap_or(false),
            tmux_session_name: self
                .tmux_session_name
                .clone()
                .or_else(|| config.tmux.session_name.clone().filter(|s| !s.is_empty())),
            tui: if self.dry_run.clone() {
                false
            } else {
                self.tui.clone() || config.misc.tui.unwrap_or(false)
            },
        }
    }
}

#[derive(Deserialize, Default, Debug, Clone)]
pub struct Config {
    pub target: TargetConfig,
    pub afl_cfg: AflConfig,
    pub tmux: TmuxConfig,
    pub misc: MiscConfig,
}

#[derive(Deserialize, Default, Debug, Clone)]
pub struct TargetConfig {
    pub path: Option<String>,
    pub san_path: Option<String>,
    pub cmpl_path: Option<String>,
    pub cmpc_path: Option<String>,
    pub args: Option<Vec<String>>,
}

#[derive(Deserialize, Default, Debug, Clone)]
pub struct AflConfig {
    pub runners: Option<u32>,
    pub afl_binary: Option<String>,
    pub seed_dir: Option<String>,
    pub solution_dir: Option<String>,
    pub dictionary: Option<String>,
    pub afl_flags: Option<String>,
}

#[derive(Deserialize, Default, Debug, Clone)]
pub struct TmuxConfig {
    pub dry_run: Option<bool>,
    pub session_name: Option<String>,
}

#[derive(Deserialize, Default, Debug, Clone)]
pub struct MiscConfig {
    pub tui: Option<bool>,
}
