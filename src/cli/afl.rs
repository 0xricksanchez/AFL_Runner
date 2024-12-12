use crate::afl::mode::Mode;
use serde::Deserialize;

#[derive(Deserialize, Default, Debug, Clone)]
pub struct AflArgs {
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
