use anyhow::Result;
use clap::Parser;

pub mod afl;
pub mod argument_aggregator;
pub mod cli;
pub mod commands;
pub mod runners;
pub mod tui;
pub mod utils;

use argument_aggregator::ArgumentAggregator;
use cli::{Cli, Commands};
use commands::{
    Command, add_seed::AddSeedCommand, cov::CovCommand, generate::GenCommand, kill::KillCommand,
    render_tui::RenderCommand, run::RunCommand,
};

fn main() -> Result<()> {
    let cli_args = Cli::parse();
    let mut arg_aggregator = ArgumentAggregator::new();

    // Load config based on command
    match &cli_args.cmd {
        Commands::Gen(args) => arg_aggregator.load(args.config.as_ref()),
        Commands::Run(args) => arg_aggregator.load(args.gen_args.config.as_ref()),
        Commands::Cov(args) => arg_aggregator.load(args.config.as_ref()),
        Commands::AddSeed(args) => arg_aggregator.load(args.config.as_ref()),
        _ => Ok(()),
    }?;

    // Execute command
    let result = match &cli_args.cmd {
        Commands::Gen(args) => GenCommand::new(args, &arg_aggregator).execute(),
        Commands::Run(args) => RunCommand::new(args, &arg_aggregator).execute(),
        Commands::Cov(args) => CovCommand::new(args, &arg_aggregator).execute(),
        Commands::Tui(args) => RenderCommand::new(args).execute(),
        Commands::Kill(args) => KillCommand::new(args).execute(),
        Commands::AddSeed(args) => AddSeedCommand::new(args, &arg_aggregator).execute(),
    };

    if let Err(e) = result {
        eprintln!("{e}");
        std::process::exit(1);
    }

    Ok(())
}
