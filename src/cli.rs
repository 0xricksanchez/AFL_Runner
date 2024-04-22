use serde::Deserialize;

use clap::Parser;
use std::path::PathBuf;

/// Default corpus directory
pub const AFL_CORPUS: &str = "/tmp/afl_input";
/// Default output directory
const AFL_OUTPUT: &str = "/tmp/afl_output";

#[derive(Parser, Debug, Default, Clone)]
#[command(name = "Parallelized AFLPlusPlus Campaign Runner")]
#[command(author = "C.K. <admin@0x434b.dev>")]
#[command(version = "0.2.0")]
pub struct CliArgs {
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
    #[arg(
        long,
        help = "Spin up a custom tmux session with the fuzzers",
        required = false
    )]
    /// Only show the generated commands, don't run them
    pub dry_run: bool,
    #[arg(short = 'm', long, help = "Custom tmux session name", required = false)]
    /// Custom tmux session name
    pub tmux_session_name: Option<String>,
    #[arg(
        long,
        help = "Provide a TOML config for the configation",
        required = false
    )]
    /// Path to a TOML config file
    pub config: Option<PathBuf>,
    /// Enable tui mode
    #[arg(long, help = "Enable TUI mode", required = false)]
    pub tui: bool,
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

pub fn merge_args(cli_args: CliArgs, config_args: Config) -> CliArgs {
    let dry_run = cli_args.dry_run || config_args.tmux.dry_run.unwrap_or(false);
    let tui = if dry_run {
        false
    } else {
        cli_args.tui || config_args.misc.tui.unwrap_or(false)
    };
    CliArgs {
        target: cli_args.target.or_else(|| {
            config_args
                .target
                .path
                .filter(|p| !p.is_empty())
                .map(PathBuf::from)
        }),
        san_target: cli_args.san_target.or_else(|| {
            config_args
                .target
                .san_path
                .filter(|p| !p.is_empty())
                .map(PathBuf::from)
        }),
        cmpl_target: cli_args.cmpl_target.or_else(|| {
            config_args
                .target
                .cmpl_path
                .filter(|p| !p.is_empty())
                .map(PathBuf::from)
        }),
        cmpc_target: cli_args.cmpc_target.or_else(|| {
            config_args
                .target
                .cmpc_path
                .filter(|p| !p.is_empty())
                .map(PathBuf::from)
        }),
        target_args: cli_args
            .target_args
            .or_else(|| config_args.target.args.filter(|args| !args.is_empty())),
        runners: Some(
            cli_args
                .runners
                .or(config_args.afl_cfg.runners)
                .unwrap_or(1),
        ),
        input_dir: cli_args
            .input_dir
            .or_else(|| {
                config_args
                    .afl_cfg
                    .seed_dir
                    .filter(|d| !d.is_empty())
                    .map(PathBuf::from)
            })
            .or_else(|| {
                // Provide a default path here
                Some(PathBuf::from(AFL_CORPUS))
            }),
        output_dir: cli_args
            .output_dir
            .or_else(|| {
                config_args
                    .afl_cfg
                    .solution_dir
                    .filter(|d| !d.is_empty())
                    .map(PathBuf::from)
            })
            .or_else(|| {
                // Provide a default path here
                Some(PathBuf::from(AFL_OUTPUT))
            }),
        dictionary: cli_args.dictionary.or_else(|| {
            config_args
                .afl_cfg
                .dictionary
                .filter(|d| !d.is_empty())
                .map(PathBuf::from)
        }),
        afl_binary: cli_args
            .afl_binary
            .or_else(|| config_args.afl_cfg.afl_binary.filter(|b| !b.is_empty())),
        dry_run,
        tmux_session_name: cli_args
            .tmux_session_name
            .or_else(|| config_args.tmux.session_name.filter(|s| !s.is_empty())),
        config: cli_args.config,
        tui,
    }
}
