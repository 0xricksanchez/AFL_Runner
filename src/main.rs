use anyhow::{bail, Context, Result};
use std::{
    env, fs,
    hash::{DefaultHasher, Hasher},
    path::{Path, PathBuf},
};
use tui::Tui;

use clap::Parser;
use cli::{Cli, Commands, SessionRunner};

mod afl_cmd;
mod afl_cmd_gen;
mod afl_env;
mod afl_strategies;
mod cli;
mod data_collection;
mod harness;
mod runners;
mod session;
use crate::{
    afl_cmd::{Printable, ToStringVec},
    afl_cmd_gen::AFLCmdGenerator,
    cli::{Config, RunArgs},
    harness::Harness,
    runners::runner::Runner,
};
use crate::{cli::AFL_CORPUS, runners::screen::Screen};
use crate::{runners::tmux::Tmux, session::CampaignData};
mod log_buffer;
mod seed;
mod system_utils;
mod tui;

pub static DEFAULT_AFL_CONFIG: &str = "aflr_cfg.toml";

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
        toml::from_str(&config_content)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))
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
            toml::from_str(&config_content).with_context(|| {
                format!(
                    "Failed to parse default config file: {}",
                    default_config_path.display()
                )
            })
        } else {
            bail!("No config file provided and no default configuration file in CWD found")
        }
    }
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
    is_ramdisk: bool,
) -> Result<AFLCmdGenerator> {
    // TODO: Implement coverage target in gen_args
    let harness = Harness::new(
        gen_args.target.clone().unwrap(),
        gen_args.target_args.clone(),
    )?
    .with_sanitizer(gen_args.san_target.clone())?
    .with_cmplog(gen_args.cmpl_target.clone())?
    .with_cmpcov(gen_args.cmpc_target.clone())?
    .with_coverage(gen_args.san_target.clone())?;

    let seed = if gen_args.use_seed_afl {
        gen_args.seed
    } else {
        None
    };
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
        is_ramdisk,
        gen_args.use_afl_defaults,
        seed,
    ))
}

fn handle_gen_command(gen_args: &cli::GenArgs) -> Result<()> {
    let (merged_args, raw_afl_flags) = load_merged_gen_args_and_flags(gen_args)?;
    let afl_runner = create_afl_runner(&merged_args, raw_afl_flags, false)?;
    let cmds = afl_runner.run()?;
    cmds.print();
    Ok(())
}

fn handle_run_command(run_args: &cli::RunArgs) -> Result<()> {
    let (merged_args, raw_afl_flags) = load_merged_run_args_and_flags(run_args)?;
    if merged_args.tui && merged_args.detached {
        bail!("TUI and detached mode cannot be used together");
    }
    let afl_runner =
        create_afl_runner(&merged_args.gen_args, raw_afl_flags, merged_args.is_ramdisk)?;
    let afl_cmds = afl_runner.run()?;
    if merged_args.dry_run {
        afl_cmds.print();
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
        SessionRunner::Screen => {
            Box::new(Screen::new(&sname, &afl_cmds.to_string_vec(), pid_fn_path))
        }
        SessionRunner::Tmux => Box::new(Tmux::new(&sname, &afl_cmds.to_string_vec(), pid_fn_path)),
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
    let mut cdata = CampaignData::default();
    Tui::run(&tui_args.afl_output, None, &mut cdata)?;
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
