use clap::{Parser, Subcommand};

pub mod args;
pub mod config;
mod constants;

pub use args::{CovArgs, GenArgs, KillArgs, RunArgs, TuiArgs};
pub use config::{
    AflConfig, Config, ConfigMerge, CoverageConfig, MiscConfig, SessionConfig, TargetConfig,
};
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
