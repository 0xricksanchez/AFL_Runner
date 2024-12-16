use clap::Args;
use std::path::PathBuf;

#[derive(Args, Clone, Debug, Default)]
pub struct AddSeedArgs {
    /// Target binary to fuzz
    #[arg(short, long, help = "Instrumented target binary to fuzz")]
    pub target: Option<PathBuf>,
    /// Target binary arguments
    #[arg(help = "Target binary arguments, including @@ if needed", raw = true)]
    pub target_args: Option<Vec<String>>,
    /// Output directory
    #[arg(
        short = 'o',
        long,
        help = "Solution/Crash output directory of the running campaign"
    )]
    pub output_dir: Option<PathBuf>,
    /// Path to a TOML config file
    #[arg(long, help = "Path to TOML config file")]
    pub config: Option<PathBuf>,
    /// Seed(s) to add to the corpus
    #[arg(long, help = "Seed(s) to add to the corpus", value_name = "SEED(S)")]
    pub seed: PathBuf,
}
