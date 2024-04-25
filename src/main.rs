use anyhow::{bail, Result};
use std::path::Path;
use tui::Tui;

use clap::Parser;
use cli::{Cli, Commands, SessionRunner};

mod afl_cmd_gen;
mod afl_env;
mod cli;
mod data_collection;
mod harness;
mod runners;
mod session;
use crate::runners::runner::Runner;
use crate::runners::screen::Screen;
use crate::runners::tmux::Tmux;
mod tui;
mod utils;

use utils::{create_afl_runner, create_harness, generate_session_name, load_config};

fn main() -> Result<()> {
    let cli_args = Cli::parse();
    match cli_args.cmd {
        Commands::Gen(gen_args) => handle_gen_command(&gen_args)?,
        Commands::Run(run_args) => handle_run_command(&run_args)?,
        Commands::Tui(tui_args) => handle_tui_command(&tui_args)?,
    }
    Ok(())
}

fn handle_gen_command(gen_args: &cli::GenArgs) -> Result<()> {
    let config_args = load_config(gen_args.config.as_ref())?;
    let raw_afl_flags = config_args.afl_cfg.afl_flags.clone();
    let merged_args = gen_args.merge(&config_args);
    let harness = create_harness(&merged_args)?;
    let afl_runner = create_afl_runner(&merged_args, harness, raw_afl_flags);
    let cmds = afl_runner.generate_afl_commands()?;
    utils::print_generated_commands(&cmds);
    Ok(())
}

fn handle_run_command(run_args: &cli::RunArgs) -> Result<()> {
    let config_args = load_config(run_args.gen_args.config.as_ref())?;
    let raw_afl_flags = config_args.afl_cfg.afl_flags.clone();
    let merged_args = run_args.merge(&config_args);
    let harness = create_harness(&merged_args.gen_args)?;
    let afl_runner = create_afl_runner(&merged_args.gen_args, harness, raw_afl_flags);
    let afl_cmds = afl_runner.generate_afl_commands()?;
    let target_args = merged_args
        .gen_args
        .target_args
        .clone()
        .unwrap_or_default()
        .join(" ");

    let sname = generate_session_name(&merged_args, &target_args);
    let srunner: Box<dyn Runner> = match &merged_args.session_runner {
        SessionRunner::Screen => Box::new(Screen::new(&sname, &afl_cmds)),
        SessionRunner::Tmux => Box::new(Tmux::new(&sname, &afl_cmds)),
    };

    if merged_args.tui {
        srunner.run_with_tui(&merged_args.gen_args.output_dir.unwrap())?;
    } else {
        srunner.run()?;
        srunner.attach()?;
    }

    Ok(())
}

fn handle_tui_command(tui_args: &cli::TuiArgs) -> Result<()> {
    if !tui_args.afl_output.exists() {
        bail!("Output directory is required for TUI mode");
    }
    validate_tui_output_dir(&tui_args.afl_output)?;
    Tui::run(&tui_args.afl_output);
    Ok(())
}

fn validate_tui_output_dir(output_dir: &Path) -> Result<()> {
    for entry in output_dir.read_dir()? {
        let path = entry?.path();
        if path.is_dir() {
            let fuzzer_stats = path.join("fuzzer_stats");
            if !fuzzer_stats.exists() {
                bail!(
                    "Invalid output directory: {} is missing 'fuzzer_stats' file",
                    path.display()
                );
            }
        }
    }
    Ok(())
}
