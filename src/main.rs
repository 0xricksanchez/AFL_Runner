use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};
use commands::{
    cov::CovCommand, gen::GenCommand, kill::KillCommand, render_tui::RenderCommand,
    run::RunCommand, Command,
};
use config_manager::ConfigManager;

pub mod afl;
pub mod cli;
pub mod commands;
pub mod config_manager;
pub mod coverage;
pub mod data_collection;
pub mod harness;
pub mod log_buffer;
pub mod runners;
pub mod seed;
pub mod session;
pub mod system_utils;
pub mod tui;

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
        Commands::Gen(args) => GenCommand::new(args, &config_manager).execute(),
        Commands::Run(args) => RunCommand::new(args, &config_manager).execute(),
        Commands::Cov(args) => CovCommand::new(args, &config_manager).execute(),
        Commands::Tui(args) => RenderCommand::new(args).execute(),
        Commands::Kill(args) => KillCommand::new(args).execute(),
    }
}
