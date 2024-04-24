use std::env;
use std::fs;
use std::hash::{DefaultHasher, Hasher};
use std::path::PathBuf;

use anyhow::bail;
use anyhow::Result;

use crate::afl_cmd_gen::AFLCmdGenerator;
use crate::cli::Config;
use crate::cli::GenArgs;
use crate::cli::RunArgs;
use crate::cli::AFL_CORPUS;
use crate::harness::Harness;

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

pub fn create_afl_runner(
    args: &GenArgs,
    harness: Harness,
    raw_afl_flags: Option<String>,
) -> AFLCmdGenerator {
    AFLCmdGenerator::new(
        harness,
        args.runners.unwrap_or(1),
        args.afl_binary.clone(),
        args.input_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from(AFL_CORPUS)),
        args.output_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("/tmp/afl_output")),
        args.dictionary.clone(),
        raw_afl_flags,
    )
}

pub fn generate_tmux_name(args: &RunArgs, target_args: &str) -> String {
    args.tmux_session_name.as_ref().map_or_else(
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

pub fn load_config(config_path: Option<&PathBuf>) -> Config {
    config_path.map_or_else(
        || {
            let cwd = env::current_dir().unwrap();
            let default_config_path = cwd.join("aflr_cfg.toml");
            if default_config_path.exists() {
                let config_content = fs::read_to_string(&default_config_path).unwrap();
                toml::from_str(&config_content).unwrap()
            } else {
                Config::default()
            }
        },
        |config_path| {
            // TODO: Add error handling for when config_path does not exist
            let config_content = fs::read_to_string(config_path).unwrap();
            toml::from_str(&config_content).unwrap()
        },
    )
}

pub fn print_generated_commands(cmds: &[String]) {
    println!("Generated commands:");
    for (i, cmd) in cmds.iter().enumerate() {
        println!("  {i:3}. {cmd}");
    }
}
