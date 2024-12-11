use clap::{Args, ValueHint};

#[derive(Args, Clone, Debug)]
pub struct KillArgs {
    /// Session name to kill
    #[arg(
        value_parser = super::utils::possible_values_session_names,
        required = true,
        value_hint = ValueHint::Other
    )]
    pub session_name: String,
}
