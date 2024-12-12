use clap::{ArgAction, Args};
use std::path::PathBuf;

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
