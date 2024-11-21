use clap::ValueEnum;
use serde::Deserialize;

/// Represents the AFL strategy mode
/// This affects the parameters that are being applied
#[derive(Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    Default,
    #[default]
    MultipleCores,
    CIFuzzing,
}
