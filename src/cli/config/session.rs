use serde::Deserialize;

#[derive(Deserialize, Default, Debug, Clone)]
pub struct SessionConfig {
    /// Dry run mode
    pub dry_run: Option<bool>,
    /// Session name
    pub name: Option<String>,
    /// Session runner
    pub runner: Option<String>,
}
