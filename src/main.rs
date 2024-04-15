use clap::Parser;
use cli::{merge_args, CliArgs, Config};
use std::env;
use std::hash::{DefaultHasher, Hasher};
use std::path::PathBuf;

mod afl_cmd_gen;
mod afl_env;
mod cli;
mod harness;
mod tmux;
use afl_cmd_gen::AFLCmdGenerator;
use harness::Harness;
use tmux::Session;

use crate::cli::AFL_CORPUS;

fn main() {
    let cli_args = CliArgs::parse();
    let config_args: Config = cli_args.config.as_deref().map_or_else(
        || {
            let cwd = env::current_dir().unwrap();
            let default_config_path = cwd.join("aflr_cfg.toml");
            if default_config_path.exists() {
                let config_content = std::fs::read_to_string(&default_config_path).unwrap();
                toml::from_str(&config_content).unwrap()
            } else {
                Config::default()
            }
        },
        |config_path| {
            let config_content = std::fs::read_to_string(config_path).unwrap();
            toml::from_str(&config_content).unwrap()
        },
    );
    let raw_afl_flags = config_args.afl_cfg.afl_flags.clone();
    let args = merge_args(cli_args, config_args);

    let target_args = args.target_args.clone().unwrap_or_default().join(" ");
    let harness = create_harness(&args);
    let afl_runner = create_afl_runner(&args, harness, raw_afl_flags);
    let cmds = afl_runner.generate_afl_commands();

    if args.dry_run {
        print_generated_commands(&cmds);
    } else {
        let tmux_name = generate_tmux_name(&args, &target_args);
        run_tmux_session(&tmux_name, &cmds);
    }
}

fn create_harness(args: &CliArgs) -> Harness {
    Harness::new(
        args.target.clone().unwrap(),
        args.san_target.clone(),
        args.cmpl_target.clone(),
        args.cmpc_target.clone(),
        args.target_args.clone().map(|args| args.join(" ")),
    )
}

fn create_afl_runner(
    args: &CliArgs,
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

fn print_generated_commands(cmds: &[String]) {
    println!("Generated commands:");
    for (i, cmd) in cmds.iter().enumerate() {
        println!("  {i:3}. {cmd}");
    }
}

fn generate_tmux_name(args: &CliArgs, target_args: &str) -> String {
    args.tmux_session_name.as_ref().map_or_else(
        || {
            let target = args
                .target
                .as_ref()
                .expect("Target binary is required")
                .file_name()
                .unwrap_or_default()
                .to_string_lossy();
            let to_hash = format!(
                "{}_{}_{}",
                target,
                args.input_dir.as_ref().map_or_else(
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

fn run_tmux_session(tmux_name: &str, cmds: &[String]) {
    let tmux = Session::new(tmux_name, cmds);
    if let Err(e) = tmux.run() {
        eprintln!("Error running tmux session: {e}");
        let _ = tmux.kill_session();
    } else {
        tmux.attach().unwrap();
    }
}

