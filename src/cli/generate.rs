use clap::{ArgAction, Args};
use std::path::PathBuf;

use crate::afl::mode::Mode;

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

    /// Nyx mode toggle
    #[arg(long, help = "Use AFL++'s Nyx mode", action = ArgAction::SetTrue)]
    pub nyx_mode: bool,

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
        help = "Select fuzzing mode",
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_gen_args_default() {
        let args = GenArgs::default();
        assert!(args.target.is_none());
        assert!(args.runners.is_none());
        assert!(!args.use_seed_afl);
    }

    #[test]
    fn test_gen_args_with_values() {
        let args = GenArgs {
            target: Some(PathBuf::from("/path/to/target")),
            runners: Some(4),
            use_seed_afl: true,
            ..GenArgs::default()
        };

        assert_eq!(args.target.unwrap(), PathBuf::from("/path/to/target"));
        assert_eq!(args.runners.unwrap(), 4);
        assert!(args.use_seed_afl);
    }
}
