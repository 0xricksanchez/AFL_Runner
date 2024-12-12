use serde::Deserialize;

#[derive(Deserialize, Default, Debug, Clone)]
pub struct MiscArgs {
    /// Enable TUI mode
    pub tui: Option<bool>,
    /// Enabled detached mode
    pub detached: Option<bool>,
    /// Use a Ramdisk for AFL++ to store `.cur_input`
    pub is_ramdisk: Option<bool>,
    /// Seed for ALFR internal PRNG
    pub seed: Option<u64>,
    /// Use seed for AFL++ as well
    pub use_seed_afl: Option<bool>,
}
