use std::hash::{DefaultHasher, Hasher};
use std::io::{stdin, Read};
use std::path::Path;
use std::path::PathBuf;
use std::{char, env};
use std::{fs, time::Duration};
use sysinfo::{Pid, System};

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;

use crate::cli::Config;
use crate::cli::GenArgs;
use crate::cli::RunArgs;
use crate::cli::AFL_CORPUS;
use crate::harness::Harness;

pub static DEFAULT_AFL_CONFIG: &str = "aflr_cfg.toml";

/// Creates a new `Harness` instance based on the provided `GenArgs`.
///
/// # Errors
///
/// Returns an error if the target binary is not specified.
pub fn create_harness(args: &GenArgs) -> Result<Harness> {
    if args.target.is_none() {
        bail!("Target binary is required");
    }
    Ok(Harness::new(
        args.target.clone().unwrap(),
        args.san_target.clone(),
        args.cmpl_target.clone(),
        args.cmpc_target.clone(),
        args.target_args.clone().map(|args| args.join(" ")),
    ))
}

/// Generates a unique session name based on the provided `RunArgs` and `target_args`.
///
/// If the `session_name` is not specified in `RunArgs`, the function generates a unique name
/// by combining the target binary name, input directory name, and a hash of the `target_args`.
pub fn generate_session_name(args: &RunArgs, target_args: &str) -> String {
    args.session_name.as_ref().map_or_else(
        || {
            let target = args
                .gen_args
                .target
                .as_ref()
                .expect("Target binary is required")
                .file_name()
                .unwrap_or_default()
                .to_string_lossy();
            let to_hash = format!(
                "{}_{}_{}",
                target,
                args.gen_args.input_dir.as_ref().map_or_else(
                    || AFL_CORPUS.into(),
                    |dir| dir.file_name().unwrap_or_default().to_string_lossy()
                ),
                target_args,
            );
            let mut hasher = DefaultHasher::new();
            hasher.write(to_hash.as_bytes());
            let hash = hasher.finish() % 1_000_000;
            format!("{target}_{hash}")
        },
        std::clone::Clone::clone,
    )
}

/// Loads the configuration from the specified `config_path` or the default configuration file.
///
/// If `config_path` is `None`, the function looks for a default configuration file named `aflr_cfg.toml`
/// in the current working directory. If the default configuration file is not found, an empty `Config`
/// instance is returned.
///
/// # Errors
///
/// Returns an error if the configuration file cannot be read or parsed.
pub fn load_config(config_path: Option<&PathBuf>) -> Result<Config> {
    if let Some(path) = config_path {
        let config_content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;
        let config: Config = toml::from_str(&config_content)
            .with_context(|| format!("Failed to parse TOML from config file: {}", path.display()))?;
        validate_config(&config)?;
        Ok(config)
    } else {
        let cwd = env::current_dir().context("Failed to get current directory")?;
        let default_config_path = cwd.join(DEFAULT_AFL_CONFIG);
        if default_config_path.exists() {
            let config_content = fs::read_to_string(&default_config_path).with_context(|| {
                format!(
                    "Failed to read default config file: {}",
                    default_config_path.display()
                )
            })?;
            let config: Config = toml::from_str(&config_content).with_context(|| {
                format!(
                    "Failed to parse default config file: {}",
                    default_config_path.display()
                )
            })?;
            validate_config(&config)?;
            Ok(config)
        } else {
            bail!("No config file provided and no default configuration file in CWD found")
        }
    }
}

fn validate_config(config: &Config) -> Result<()> {
    for (i, group) in config.afl_cfg.flags_partial.iter().enumerate() {
        if !group.is_valid() {
            return Err(anyhow::anyhow!(
                "Error: Group {} has both `probability` and `count`, which are mutually exclusive",
                i + 1
            ));
        }
    }

    Ok(())
}

/// Prints the generated commands to the console.
pub fn print_generated_commands(cmds: &[String]) {
    println!("Generated commands:");
    for (i, cmd) in cmds.iter().enumerate() {
        println!("  {i:3}. {cmd}");
    }
}

/// Gets user input from stdin
pub fn get_user_input() -> char {
    std::io::stdin()
        .bytes()
        .next()
        .and_then(std::result::Result::ok)
        .map_or('y', |byte| {
            let b = byte as char;
            if b.is_ascii_alphabetic() {
                b.to_lowercase().next().unwrap()
            } else if b == '\n' {
                'y'
            } else {
                b
            }
        })
}

/// Helper function for creating directories
pub fn mkdir_helper(dir: &Path, check_empty: bool) -> Result<()> {
    if dir.is_file() {
        bail!("{} is a file", dir.display());
    }
    if check_empty {
        let is_empty = dir.read_dir().map_or(true, |mut i| i.next().is_none());
        if !is_empty {
            println!("Directory {} is not empty. Clean it [Y/n]? ", dir.display());
            let mut input = String::new();
            stdin().read_line(&mut input)?;
            match input.trim().to_lowercase().chars().next().unwrap_or('y') {
                'y' | '\n' => fs::remove_dir_all(dir)?,
                _ => (),
            }
        }
    }
    if !dir.exists() {
        fs::create_dir_all(dir)?;
    }
    Ok(())
}

/// Count the number of alive procsses based on a list of PIDs
pub fn count_alive_fuzzers(fuzzer_pids: &[u32]) -> Vec<usize> {
    let s = System::new_all();
    fuzzer_pids
        .iter()
        .filter(|&pid| *pid != 0)
        .filter(|&pid| s.process(Pid::from(*pid as usize)).is_some())
        .map(|&pid| pid as usize)
        .collect()
}

/// Formats a duration into a string based on days, hours, minutes, and seconds
pub fn format_duration(duration: &Duration) -> String {
    let mut secs = duration.as_secs();
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    secs %= 60;
    if days > 0 {
        format!("{days} days, {hours:02}:{mins:02}:{secs:02}")
    } else if days == 0 && hours > 0 {
        format!("{hours:02}:{mins:02}:{secs:02}")
    } else if days == 0 && hours == 0 && mins > 0 {
        format!("{mins:02}:{secs:02}")
    } else {
        format!("{secs:02}s")
    }
}
