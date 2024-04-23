use anyhow::bail;
use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands, Config, GenArgs, RunArgs, TuiArgs};
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
    let cli_args = Cli::parse();
    match cli_args.cmd {
        Commands::Gen(gen_args) => {
            let config_args: Config = load_config(gen_args.config.as_ref());
            let raw_afl_flags = config_args.afl_cfg.afl_flags.clone();
            let merged_args = gen_args.merge(&config_args);
            let harness = create_harness(&merged_args)
                .map_err(|e| {
                    eprintln!("Error creating harness: {e}");
                    std::process::exit(1);
                })
                .unwrap();
            let afl_runner = create_afl_runner(&merged_args, harness, raw_afl_flags);
            let cmds = afl_runner.generate_afl_commands();
            print_generated_commands(&cmds);
        }
        Commands::Run(run_args) => {
            let config_args: Config = load_config(run_args.gen_args.config.as_ref());
            let raw_afl_flags = config_args.afl_cfg.afl_flags.clone();
            let merged_args = run_args.merge(&config_args);
            let harness = create_harness(&merged_args.gen_args)
                .map_err(|e| {
                    eprintln!("Error creating harness: {e}");
                    std::process::exit(1);
                })
                .unwrap();
            let afl_runner = create_afl_runner(&merged_args.gen_args, harness, raw_afl_flags);
            let cmds = afl_runner.generate_afl_commands();
            let target_args = merged_args
                .gen_args
                .target_args
                .clone()
                .unwrap_or_default()
                .join(" ");
            let tmux_name = generate_tmux_name(&merged_args, &target_args);
            if merged_args.tui {
                run_tmux_session_with_tui(&tmux_name, &cmds, &merged_args);
            } else {
                run_tmux_session(&tmux_name, &cmds);
            }
        }
        Commands::Tui(tui_args) => {
            todo!("TBD")
        }
    }
}

fn load_config(config_path: Option<&PathBuf>) -> Config {
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

fn create_harness(args: &GenArgs) -> Result<Harness> {
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

fn create_afl_runner(
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

fn print_generated_commands(cmds: &[String]) {
    println!("Generated commands:");
    for (i, cmd) in cmds.iter().enumerate() {
        println!("  {i:3}. {cmd}");
    }
}

fn generate_tmux_name(args: &RunArgs, target_args: &str) -> String {
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

fn run_tmux_session(tmux_name: &str, cmds: &[String]) {
    let tmux = Session::new(tmux_name, cmds);
    if let Err(e) = tmux.run() {
        let _ = tmux.kill_session();
        eprintln!("Error running tmux session: {e}");
    } else {
        tmux.attach().unwrap();
    }
}

fn run_tmux_session_with_tui(tmux_name: &str, cmds: &[String], args: &RunArgs) {
    if let Err(e) = run_tmux_session_detached(tmux_name, cmds) {
        eprintln!("Error running TUI: {e}");
        return;
    }
    let (session_data_tx, session_data_rx) = mpsc::channel();
    let output_dir = args.gen_args.output_dir.clone().unwrap();

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
