use anyhow::{bail, Context, Result};
use std::{
    env, fs,
    hash::{DefaultHasher, Hasher},
    path::{Path, PathBuf},
};

use clap::Parser;

mod afl;
mod cli;
mod coverage;
mod data_collection;
mod harness;
mod log_buffer;
mod runners;
mod seed;
mod session;
mod system_utils;
mod tui;
use crate::{
    afl::base_cfg::Bcfg,
    afl::cmd::{Printable, ToStringVec},
    afl::cmd_gen::AFLCmdGenerator,
    cli::{
        Cli, Commands, Config, ConfigMerge, CovArgs, GenArgs, KillArgs, RunArgs, SessionRunner,
        TuiArgs, AFL_CORPUS,
    },
    harness::Harness,
    runners::{
        runner::{Session, SessionManager},
        screen::ScreenSession,
        tmux::TmuxSession,
    },
};
use crate::{coverage::CoverageCollector, session::CampaignData};
use tui::Tui;

pub static DEFAULT_AFL_CONFIG: &str = "aflr_cfg.toml";

fn create_afl_runner(
    gen_args: &cli::GenArgs,
    raw_afl_flags: Option<&String>,
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

    let afl_meta = Bcfg::new(
        gen_args
            .input_dir
            .clone()
            .unwrap_or_else(|| Path::new(AFL_CORPUS).to_path_buf()),
        gen_args
            .output_dir
            .clone()
            .unwrap_or_else(|| Path::new("/tmp/afl_output").to_path_buf()),
    )
    .with_dictionary(gen_args.dictionary.clone())
    .with_raw_afl_flags(raw_afl_flags)
    .with_afl_binary(gen_args.afl_binary.clone())
    .with_ramdisk(is_ramdisk);

    Ok(AFLCmdGenerator::new(
        harness,
        gen_args.runners.unwrap_or(1),
        &afl_meta,
        gen_args.mode,
        seed,
    ))
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
///
/// # Panics
/// If the target binary is not provided in `RunArgs`.
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

fn execute_tui_command(args: &TuiArgs) -> Result<()> {
    if !args.afl_output.exists() {
        bail!("Output directory is required for TUI mode");
    }

    validate_tui_output_dir(&args.afl_output)?;

    let mut cdata = CampaignData::default();
    Tui::run(&args.afl_output, None, &mut cdata).context("Failed to run TUI")
}

fn execute_kill_command(args: &KillArgs) -> Result<()> {
    let session_name = args
        .session_name
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Session name is required for kill command"))?;

    let mut terminated = false;

    // Try Tmux session
    if let Ok(tmux) = TmuxSession::new(session_name, &[], Path::new("/tmp/aflr_foobar_1337")) {
        if tmux.is_present() {
            println!("[+] Found TMUX session: {session_name}. Terminating it...");
            tmux.kill_session().context("Failed to kill TMUX session")?;
            terminated = true;
        }
    }

    // Try Screen session
    if let Ok(screen) = ScreenSession::new(session_name, &[], Path::new("/tmp/aflr_foobar_1337")) {
        if screen.is_present() {
            println!("[+] Found SCREEN session: {session_name}. Terminating it...",);
            screen
                .kill_session()
                .context("Failed to kill SCREEN session")?;
            terminated = true;
        }
    }

    if !terminated {
        println!("[-] No session found with the name: {session_name}");
    }

    Ok(())
}

/// Central configuration manager
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

    /// Loads the configuration from the provided path.
    ///
    /// # Errors
    /// Returns an error if the configuration file is not found or the configuration is invalid.
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

    /// Merges the provided `GenArgs` with the loaded configuration if available.
    ///
    /// # Errors
    /// Returns an error if the configuration is not loaded or the merge fails.
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

    /// Merges the `RunArgs` with the loaded configuration from file (if any).
    ///
    /// # Errors
    /// Returns an error if the configuration file is not found or the configuration is invalid.
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

    /// Merges the `CoverageArgs` with the loaded configuration from file (if any).
    ///
    /// # Errors
    /// Returns an error if the configuration file is not found or the configuration is invalid.
    pub fn merge_cov_args(&self, args: &cli::CovArgs) -> Result<CovArgs> {
        Ok(self
            .config
            .as_ref()
            .map_or_else(|| args.clone(), |config| args.merge_with_config(config)))
    }
}

/// Command executor trait for better abstraction
pub trait CommandExecutor {
    /// Executes the command
    ///
    /// # Errors
    /// Returns an error if the command execution fails
    fn execute(&self) -> Result<()>;
}

/// Coverage command executor
pub struct CovCommandExecutor<'a> {
    args: &'a cli::CovArgs,
    config_manager: &'a ConfigManager,
}

impl<'a> CovCommandExecutor<'a> {
    pub fn new(args: &'a CovArgs, config_manager: &'a ConfigManager) -> Self {
        Self {
            args,
            config_manager,
        }
    }
}

impl CommandExecutor for CovCommandExecutor<'_> {
    fn execute(&self) -> Result<()> {
        let merged_args = self.config_manager.merge_cov_args(self.args)?;
        let mut cov_collector =
            CoverageCollector::new(merged_args.target.unwrap(), merged_args.output_dir.unwrap());

        if let Some(target_args) = &merged_args.target_args {
            cov_collector.with_target_args(target_args.clone());
        }

        if merged_args.split_report {
            cov_collector.with_split_report(true);
        }

        if merged_args.show_args.is_some() {
            cov_collector.with_misc_show_args(merged_args.show_args.clone().unwrap());
        }

        if merged_args.report_args.is_some() {
            cov_collector.with_misc_report_args(merged_args.report_args.clone().unwrap());
        }

        if merged_args.text_report {
            cov_collector.with_html(false);
        }

        cov_collector.collect()?;
        Ok(())
    }
}

/// Generator command executor
pub struct GenCommandExecutor<'a> {
    args: &'a GenArgs,
    config_manager: &'a ConfigManager,
}

impl<'a> GenCommandExecutor<'a> {
    pub fn new(args: &'a GenArgs, config_manager: &'a ConfigManager) -> Self {
        Self {
            args,
            config_manager,
        }
    }
}

impl CommandExecutor for GenCommandExecutor<'_> {
    fn execute(&self) -> Result<()> {
        let (merged_args, raw_afl_flags) = self.config_manager.merge_gen_args(self.args)?;
        let afl_generator = create_afl_runner(&merged_args, raw_afl_flags.as_ref(), false)
            .context("Failed to create AFL runner")?;
        afl_generator
            .run()
            .context("Failed to run AFL generator: {}")?
            .print();
        Ok(())
    }
}

/// Run command executor
pub struct RunCommandExecutor<'a> {
    args: &'a RunArgs,
    config_manager: &'a ConfigManager,
}

impl<'a> RunCommandExecutor<'a> {
    pub fn new(args: &'a RunArgs, config_manager: &'a ConfigManager) -> Self {
        Self {
            args,
            config_manager,
        }
    }
}

impl CommandExecutor for RunCommandExecutor<'_> {
    fn execute(&self) -> Result<()> {
        let (merged_args, raw_afl_flags) = self.config_manager.merge_run_args(self.args)?;

        if merged_args.tui && merged_args.detached {
            bail!("TUI and detached mode cannot be used together");
        }

        let afl_generator = create_afl_runner(
            &merged_args.gen_args,
            raw_afl_flags.as_ref(),
            merged_args.is_ramdisk,
        )
        .context("Failed to create AFL runner")?;

        let afl_commands = afl_generator.run().context("Failed to run AFL generator")?;

        if merged_args.dry_run {
            println!("{afl_commands:?}");
            return Ok(());
        }

        Self::execute_session(&merged_args, &afl_commands.to_string_vec())
    }
}

impl RunCommandExecutor<'_> {
    fn execute_session(merged_args: &RunArgs, afl_commands: &[String]) -> Result<()> {
        let target_args = merged_args
            .gen_args
            .target_args
            .clone()
            .unwrap_or_default()
            .join(" ");

        let sname = generate_session_name(merged_args, &target_args);
        let pid_fn = format!("/tmp/.{}_{}.pids", &sname, std::process::id());
        let pid_fn_path = Path::new(&pid_fn);

        match &merged_args.session_runner {
            SessionRunner::Screen => {
                let screen = ScreenSession::new(&sname, afl_commands, pid_fn_path)
                    .context("Failed to create Screen session")?;
                Self::run_session(&screen, merged_args, "Screen")
            }
            SessionRunner::Tmux => {
                let tmux = TmuxSession::new(&sname, afl_commands, pid_fn_path)
                    .context("Failed to create Tmux session")?;
                Self::run_session(&tmux, merged_args, "Tmux")
            }
        }
    }

    fn run_session<T: SessionManager>(
        session: &Session<T>,
        args: &RunArgs,
        session_type: &str,
    ) -> Result<()> {
        if args.tui {
            session
                .run_with_tui(&args.gen_args.output_dir.clone().unwrap())
                .with_context(|| format!("Failed to run TUI {session_type} session"))?;
        } else {
            session
                .run()
                .with_context(|| format!("Failed to run {session_type} session"))?;
            if !args.detached {
                session
                    .attach()
                    .with_context(|| format!("Failed to attach to {session_type} session"))?;
            }
        }
        Ok(())
    }
}

fn main() -> Result<()> {
    let cli_args = Cli::parse();
    let mut config_manager = ConfigManager::new();

    // Load config based on command
    match &cli_args.cmd {
        Commands::Gen(args) => config_manager.load(args.config.as_ref()),
        Commands::Run(args) => config_manager.load(args.gen_args.config.as_ref()),
        Commands::Cov(args) => config_manager.load(args.config.as_ref()),
        _ => Ok(()),
    }?;

    // Execute command
    match &cli_args.cmd {
        Commands::Gen(args) => GenCommandExecutor::new(args, &config_manager).execute(),
        Commands::Run(args) => RunCommandExecutor::new(args, &config_manager).execute(),
        Commands::Cov(args) => CovCommandExecutor::new(args, &config_manager).execute(),
        Commands::Tui(args) => execute_tui_command(args),
        Commands::Kill(args) => execute_kill_command(args),
    }
}
