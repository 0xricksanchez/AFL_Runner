use clap::ValueEnum;
use serde::Deserialize;

#[derive(Deserialize, Default, Debug, Clone)]
pub struct SessionArgs {
    /// Dry run mode
    pub dry_run: Option<bool>,
    /// Session name
    pub name: Option<String>,
    /// Session runner
    pub runner: Option<String>,
}

#[derive(ValueEnum, Clone, Debug, Default)]
pub enum SessionRunner {
    /// Use tmux as the session runner
    #[default]
    Tmux,
    /// Use screen as the session runner
    Screen,
}

impl From<&str> for SessionRunner {
    fn from(s: &str) -> Self {
        match s {
            "screen" => Self::Screen,
            _ => Self::Tmux,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_runner_from_str() {
        assert!(matches!(SessionRunner::from("tmux"), SessionRunner::Tmux));
        assert!(matches!(
            SessionRunner::from("screen"),
            SessionRunner::Screen
        ));
        assert!(matches!(
            SessionRunner::from("invalid"),
            SessionRunner::Tmux
        ));
    }
}
