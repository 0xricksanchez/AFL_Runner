use clap::Args;
use std::path::PathBuf;

#[derive(Args, Clone, Debug, Default)]
pub struct TuiArgs {
    /// Path to a `AFLPlusPlus` campaign directory, e.g. `afl_output`
    #[arg(
        help = "Path to a AFLPlusPlus campaign directory, e.g. `afl_output`",
        required = true
    )]
    pub afl_output: PathBuf,
}
