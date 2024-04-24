use std::path::Path;

use clap::Parser;
use cli::{Cli, Commands};

mod afl_cmd_gen;
mod afl_env;
mod cli;
mod data_collection;
mod harness;
mod session;
mod tmux;
mod tui;
mod utils;

use utils::{create_afl_runner, create_harness, generate_tmux_name, load_config};

fn main() {
    let cli_args = Cli::parse();
    match cli_args.cmd {
        Commands::Gen(gen_args) => handle_gen_command(&gen_args),
        Commands::Run(run_args) => handle_run_command(&run_args),
        Commands::Tui(tui_args) => handle_tui_command(&tui_args),
    }
}

fn handle_gen_command(gen_args: &cli::GenArgs) {
    let config_args = load_config(gen_args.config.as_ref());
    let raw_afl_flags = config_args.afl_cfg.afl_flags.clone();
    let merged_args = gen_args.merge(&config_args);
    let harness = create_harness(&merged_args).unwrap_or_else(|e| {
        eprintln!("Error creating harness: {e}");
        std::process::exit(1);
    });
    let afl_runner = create_afl_runner(&merged_args, harness, raw_afl_flags);
    let cmds = afl_runner.generate_afl_commands();
    utils::print_generated_commands(&cmds);
}

fn handle_run_command(run_args: &cli::RunArgs) {
    let config_args = load_config(run_args.gen_args.config.as_ref());
    let raw_afl_flags = config_args.afl_cfg.afl_flags.clone();
    let merged_args = run_args.merge(&config_args);
    let harness = create_harness(&merged_args.gen_args).unwrap_or_else(|e| {
        eprintln!("Error creating harness: {e}");
        std::process::exit(1);
    });
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
        tmux::run_tmux_session_with_tui(&tmux_name, &cmds, &merged_args.gen_args);
    } else {
        tmux::run_tmux_session(&tmux_name, &cmds);
    }
}

fn handle_tui_command(tui_args: &cli::TuiArgs) {
    if !tui_args.afl_output.exists() {
        eprintln!("Output directory is required for TUI mode");
        std::process::exit(1);
    }
    validate_tui_output_dir(&tui_args.afl_output);
    tui::run_tui_standalone(&tui_args.afl_output);
}

fn validate_tui_output_dir(output_dir: &Path) {
    output_dir.read_dir().unwrap().for_each(|entry| {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            let fuzzer_stats = path.join("fuzzer_stats");
            if !fuzzer_stats.exists() {
                eprintln!(
                    "Invalid output directory: {} is missing 'fuzzer_stats' file",
                    path.display()
                );
                std::process::exit(1);
            }
        }
    });
}
