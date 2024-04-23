use anyhow::Result;
use clap::Parser;
use cli::{merge_args, CliArgs, Config};
use std::env;
use std::fs;
use std::hash::{DefaultHasher, Hasher};
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;

mod afl_cmd_gen;
mod afl_env;
mod cli;
mod harness;
mod tmux;
use afl_cmd_gen::AFLCmdGenerator;
use harness::Harness;
use tmux::Session;
mod data_collection;
mod session;
mod tui;

use crate::cli::AFL_CORPUS;

fn main() {
    let cli_args = CliArgs::parse();
    let config_args: Config = load_config(&cli_args);

    let raw_afl_flags = config_args.afl_cfg.afl_flags.clone();
    let args = merge_args(cli_args, config_args);

    let target_args = args.target_args.clone().unwrap_or_default().join(" ");
    let harness = create_harness(&args);
    let afl_runner = create_afl_runner(&args, harness, raw_afl_flags);
    let cmds = afl_runner.generate_afl_commands();

    if args.dry_run {
        print_generated_commands(&cmds);
        return;
    }

    let tmux_name = generate_tmux_name(&args, &target_args);
    if args.tui {
        run_tmux_session_with_tui(&tmux_name, &cmds, &args);
    } else {
        run_tmux_session(&tmux_name, &cmds);
    }
}

fn load_config(cli_args: &CliArgs) -> Config {
    cli_args.config.as_deref().map_or_else(
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
            let config_content = fs::read_to_string(config_path).unwrap();
            toml::from_str(&config_content).unwrap()
        },
    )
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
        let _ = tmux.kill_session();
        eprintln!("Error running tmux session: {e}");
    } else {
        tmux.attach().unwrap();
    }
}

fn run_tmux_session_with_tui(tmux_name: &str, cmds: &[String], args: &CliArgs) {
    if let Err(e) = run_tmux_session_detached(tmux_name, cmds) {
        eprintln!("Error running TUI: {e}");
        return;
    }
    let (session_data_tx, session_data_rx) = mpsc::channel();
    let output_dir = args.output_dir.clone().unwrap();

    thread::spawn(move || loop {
        let session_data = data_collection::collect_session_data(&output_dir);
        if let Err(e) = session_data_tx.send(session_data) {
            eprintln!("Error sending session data: {e}");
            break;
        }
        thread::sleep(std::time::Duration::from_secs(1));
    });

    if let Err(e) = tui::run(&session_data_rx) {
        eprintln!("Error running TUI: {e}");
    }
}

fn run_tmux_session_detached(tmux_name: &str, cmds: &[String]) -> Result<()> {
    let tmux = Session::new(tmux_name, cmds);
    if let Err(e) = tmux.run() {
        let _ = tmux.kill_session();
        return Err(e);
    }
    println!("Session {tmux_name} started in detached mode");
    Ok(())
}
