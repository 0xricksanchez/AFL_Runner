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
use crate::runners::tmux::Tmux;
use crate::{afl_cmd_gen::AFLCmdGenerator, runners::runner::Runner};
use crate::{cli::AFL_CORPUS, runners::screen::Screen};
mod tui;
mod utils;

use utils::{create_harness, generate_session_name, load_config};

fn main() -> Result<()> {
    let cli_args = Cli::parse();
    match cli_args.cmd {
        Commands::Gen(gen_args) => handle_gen_command(&gen_args)?,
        Commands::Run(run_args) => handle_run_command(&run_args)?,
        Commands::Tui(tui_args) => handle_tui_command(&tui_args)?,
        Commands::Kill(kill_args) => handle_kill_command(&kill_args)?,
    }
    Ok(())
}

fn load_merged_gen_args_and_flags(
    gen_args: &cli::GenArgs,
) -> Result<(cli::GenArgs, Option<String>)> {
    if gen_args.config.is_some() {
        let config_args = load_config(gen_args.config.as_ref())?;
        let raw_afl_flags = config_args.afl_cfg.afl_flags.clone();
        Ok((gen_args.merge(&config_args), raw_afl_flags))
    } else {
        Ok((gen_args.clone(), None))
    }
}

fn load_merged_run_args_and_flags(
    run_args: &cli::RunArgs,
) -> Result<(cli::RunArgs, Option<String>)> {
    if run_args.gen_args.config.is_some() {
        let config_args = load_config(run_args.gen_args.config.as_ref())?;
        let raw_afl_flags = config_args.afl_cfg.afl_flags.clone();
        Ok((run_args.merge(&config_args), raw_afl_flags))
    } else {
        Ok((run_args.clone(), None))
    }
}

fn create_afl_runner(
    gen_args: &cli::GenArgs,
    raw_afl_flags: Option<String>,
) -> Result<AFLCmdGenerator> {
    let harness = create_harness(gen_args)?;
    Ok(AFLCmdGenerator::new(
        harness,
        gen_args.runners.unwrap_or(1),
        gen_args
            .input_dir
            .clone()
            .unwrap_or_else(|| Path::new(AFL_CORPUS).to_path_buf()),
        gen_args
            .output_dir
            .clone()
            .unwrap_or_else(|| Path::new("/tmp/afl_output").to_path_buf()),
        gen_args.dictionary.clone(),
        raw_afl_flags,
        gen_args.afl_binary.clone(),
    ))
}

fn handle_gen_command(gen_args: &cli::GenArgs) -> Result<()> {
    let (merged_args, raw_afl_flags) = load_merged_gen_args_and_flags(gen_args)?;
    let mut afl_runner = create_afl_runner(&merged_args, raw_afl_flags)?;
    let cmds = afl_runner.generate_afl_commands()?;
    utils::print_generated_commands(&cmds);
    Ok(())
}

fn handle_run_command(run_args: &cli::RunArgs) -> Result<()> {
    let (merged_args, raw_afl_flags) = load_merged_run_args_and_flags(run_args)?;
    if merged_args.tui && merged_args.detached {
        bail!("TUI and detached mode cannot be used together");
    }
    let mut afl_runner = create_afl_runner(&merged_args.gen_args, raw_afl_flags)?;
    let afl_cmds = afl_runner.generate_afl_commands()?;
    if merged_args.dry_run {
        utils::print_generated_commands(&afl_cmds);
        return Ok(());
    }
    let target_args = merged_args
        .gen_args
        .target_args
        .clone()
        .unwrap_or_default()
        .join(" ");

    let sname = generate_session_name(&merged_args, &target_args);
    let pid_fn = format!("/tmp/.{}_{}.pids", &sname, std::process::id());
    let pid_fn_path = Path::new(&pid_fn);
    let srunner: Box<dyn Runner> = match &merged_args.session_runner {
        SessionRunner::Screen => Box::new(Screen::new(&sname, &afl_cmds, pid_fn_path)),
        SessionRunner::Tmux => Box::new(Tmux::new(&sname, &afl_cmds, pid_fn_path)),
    };

    if merged_args.tui {
        srunner.run_with_tui(&merged_args.gen_args.output_dir.unwrap())?;
    } else {
        srunner.run()?;
        if !merged_args.detached {
            srunner.attach()?;
        }
    }

    Ok(())
}

fn handle_tui_command(tui_args: &cli::TuiArgs) -> Result<()> {
    if !tui_args.afl_output.exists() {
        bail!("Output directory is required for TUI mode");
    }
    validate_tui_output_dir(&tui_args.afl_output)?;
    Tui::run(&tui_args.afl_output, None)?;
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

fn handle_kill_command(kill_args: &cli::KillArgs) -> Result<()> {
    // TODO: Add means to kill the session based on --config or AFLR_DEFAULT_CONFIG
    if kill_args.session_name.is_none() {
        bail!("Session name is required for kill command");
    } else if kill_args.session_name.is_some() {
        let mut is_term = false;
        let tmux = Tmux::new(
            kill_args.session_name.as_ref().unwrap(),
            &[],
            Path::new("/tmp/aflr_foobar_1337"),
        );
        if tmux.is_present() {
            println!(
                "[+] Found TMUX session: {}. Terminating it...",
                kill_args.session_name.as_ref().unwrap()
            );
            tmux.kill_session()?;
            is_term |= true;
        }
        let screen = Screen::new(
            kill_args.session_name.as_ref().unwrap(),
            &[],
            Path::new("/tmp/aflr_foobar_1337"),
        );
        if screen.is_present() {
            println!(
                "[+] Found SCREEN session: {}. Terminating it...",
                kill_args.session_name.as_ref().unwrap()
            );
            screen.kill_session()?;
            is_term |= true;
        }
        if !is_term {
            println!(
                "[-] No session found with the name: {}",
                kill_args.session_name.as_ref().unwrap()
            );
        }
    }

    Ok(())
}
