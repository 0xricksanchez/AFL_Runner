use anyhow::Result;
use argument_aggregator::ArgumentAggregator;
use clap::Parser;
use cli::{Cli, Commands};
use commands::{
    cov::CovCommand, gen::GenCommand, kill::KillCommand, render_tui::RenderCommand,
    run::RunCommand, Command,
};

pub mod afl;
pub mod argument_aggregator;
pub mod cli;
pub mod commands;
pub mod runners;
pub mod tui;
pub mod utils;

fn main() -> Result<()> {
    let cli_args = Cli::parse();
    let mut arg_aggregator = ArgumentAggregator::new();

    // Load config based on command
    match &cli_args.cmd {
        Commands::Gen(args) => arg_aggregator.load(args.config.as_ref()),
        Commands::Run(args) => arg_aggregator.load(args.gen_args.config.as_ref()),
        Commands::Cov(args) => arg_aggregator.load(args.config.as_ref()),
        _ => Ok(()),
    }?;

    // Execute command
    match &cli_args.cmd {
        Commands::Gen(args) => GenCommand::new(args, &arg_aggregator).execute(),
        Commands::Run(args) => RunCommand::new(args, &arg_aggregator).execute(),
        Commands::Cov(args) => CovCommand::new(args, &arg_aggregator).execute(),
        Commands::Tui(args) => RenderCommand::new(args).execute(),
        Commands::Kill(args) => KillCommand::new(args).execute(),
    }
}
