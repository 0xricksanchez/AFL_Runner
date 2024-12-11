use crate::cli::{Config, ConfigMerge, CovArgs, GenArgs, RunArgs};
use anyhow::{bail, Context, Result};
use std::{env, fs, path::PathBuf};

pub static DEFAULT_AFL_CONFIG: &str = "aflr_cfg.toml";

#[derive(Debug)]
pub struct ConfigManager {
    config: Option<Config>,
    default_config_path: PathBuf,
}

impl Default for ConfigManager {
    fn default() -> Self {
        let default_path = env::current_dir()
            .unwrap_or_default()
            .join(DEFAULT_AFL_CONFIG);
        Self {
            config: None,
            default_config_path: default_path,
        }
    }
}

impl ConfigManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load(&mut self, config_path: Option<&PathBuf>) -> Result<()> {
        let path = config_path.unwrap_or(&self.default_config_path);
        if path.exists() {
            let content = fs::read_to_string(path)
                .with_context(|| format!("Failed to read config file: {}", path.display()))?;
            self.config = Some(
                toml::from_str(&content)
                    .with_context(|| format!("Failed to parse config file: {}", path.display()))?,
            );
        } else if config_path.is_some() {
            bail!("Config file not found: {}", path.display());
        }
        Ok(())
    }

    pub fn merge_gen_args(&self, args: &GenArgs) -> Result<(GenArgs, Option<String>)> {
        let merged = self
            .config
            .as_ref()
            .map_or_else(|| args.clone(), |config| args.merge_with_config(config));

        let raw_afl_flags = self
            .config
            .as_ref()
            .and_then(|c| c.afl_cfg.afl_flags.clone());

        Ok((merged, raw_afl_flags))
    }

    pub fn merge_run_args(&self, args: &RunArgs) -> Result<(RunArgs, Option<String>)> {
        let merged = self
            .config
            .as_ref()
            .map_or_else(|| args.clone(), |config| args.merge_with_config(config));

        let raw_afl_flags = self
            .config
            .as_ref()
            .and_then(|c| c.afl_cfg.afl_flags.clone());

        Ok((merged, raw_afl_flags))
    }

    pub fn merge_cov_args(&self, args: &CovArgs) -> Result<CovArgs> {
        Ok(self
            .config
            .as_ref()
            .map_or_else(|| args.clone(), |config| args.merge_with_config(config)))
    }
}
