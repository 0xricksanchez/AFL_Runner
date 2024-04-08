use clap::Parser;
use std::path::Path;

use std::hash::{DefaultHasher, Hasher};

mod afl_env;
mod harness;
use harness::Harness;
mod afl_cmd_gen;
use afl_cmd_gen::AFLCmdGenerator;
mod tmux;
use tmux::Session;

/// Default corpus directory
const AFL_CORPUS: &str = "/tmp/afl_input";
/// Default output directory
const AFL_OUTPUT: &str = "/tmp/afl_output";

#[derive(Parser, Debug)]
#[command(name = "Parallelized AFLPlusPlus Campaign Runner")]
#[command(author = "C.K. <admin@0x434b.dev>")]
#[command(version = "0.1.6")]
pub struct Args {
    /// Target binary to fuzz
    #[arg(short, long, help = "Instrumented target binary to fuzz")]
    target: String,
    /// Sanitizer binary to use
    #[arg(
        short = 's',
        long,
        help = "Instrumented with *SAN binary to use",
        required = false
    )]
    san_target: Option<String>,
    /// CMPLOG binary to use
    #[arg(
        short = 'c',
        long,
        help = "Instrumented with CMPLOG binary to use",
        required = false
    )]
    cmpl_target: Option<String>,
    /// Target binary arguments
    #[arg(
        help = "Target binary arguments, including @@ if needed. Example: `<...> -- @@`",
        raw = true,
        required = false
    )]
    target_args: Option<Vec<String>>,
    /// Amount of processes to spin up
    #[arg(
        short = 'n',
        long,
        default_value = "1",
        value_name = "NUM_PROCS",
        help = "Amount of processes to spin up"
    )]
    runners: u32,
    /// Corpus directory
    #[arg(
        short = 'i',
        long,
        default_value = AFL_CORPUS,
        help = "Corpus directory",
        required = false
    )]
    input_dir: Option<String>,
    /// Output directory
    #[arg(
        short = 'o',
        long,
        default_value = AFL_OUTPUT,
        help = "Output directory",
        required = false
    )]
    output_dir: Option<String>,
    /// Path to dictionary
    #[arg(
        short = 'x',
        long,
        default_value = None,
        value_name = "DICT_FILE",
        help = "Dictionary to use",
        required = false
    )]
    dictionary: Option<String>,
    /// AFL-Fuzz binary
    #[arg(
        short = 'b',
        long,
        default_value = None,
        help = "Custom path to 'afl-fuzz' binary. If not specified and 'afl-fuzz' is not in $PATH, the program will try to use $AFL_PATH",
        required = false
    )]
    afl_binary: Option<String>,
    #[arg(
        long,
        help = "Spin up a custom tmux session with the fuzzers",
        required = false
    )]
    /// Only show the generated commands, don't run them
    dry_run: bool,
    #[arg(short = 'm', long, help = "Custom tmux session name", required = false)]
    tmux_session_name: Option<String>,
}

fn main() {
    let cli_args = Args::parse();
    let target_args = Some(cli_args.target_args.clone().unwrap_or_default().join(" "));
    let harness = create_harness(&cli_args, target_args.clone());
    let afl_runner = create_afl_runner(&cli_args, harness);
    let cmds = afl_runner.generate_afl_commands();

    if cli_args.dry_run {
        print_generated_commands(&cmds);
    } else {
        let tmux_name = generate_tmux_name(&cli_args, &target_args);
        run_tmux_session(&tmux_name, &cmds);
    }
}

fn create_harness(cli_args: &Args, target_args: Option<String>) -> Harness {
    Harness::new(
        cli_args.target.clone(),
        cli_args.san_target.clone(),
        cli_args.cmpl_target.clone(),
        target_args,
    )
}

fn create_afl_runner(cli_args: &Args, harness: Harness) -> AFLCmdGenerator {
    AFLCmdGenerator::new(
        harness,
        cli_args.runners,
        cli_args.afl_binary.as_deref(),
        cli_args.input_dir.as_deref().unwrap(),
        cli_args.output_dir.as_deref().unwrap(),
        cli_args.dictionary.as_deref(),
    )
}

fn print_generated_commands(cmds: &[String]) {
    println!("Generated commands:");
    for (i, cmd) in cmds.iter().enumerate() {
        println!("  {i:3}. {cmd}");
    }
}

fn generate_tmux_name(cli_args: &Args, target_args: &Option<String>) -> String {
    if let Some(name) = &cli_args.tmux_session_name {
        name.clone()
    } else {
        let to_hash = format!(
            "{}_{}_{}",
            Path::new(&cli_args.target)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy(),
            Path::new(cli_args.input_dir.as_deref().unwrap_or(AFL_CORPUS))
                .file_name()
                .unwrap_or_default()
                .to_string_lossy(),
            target_args.as_deref().unwrap_or_default(),
        );
        let mut hasher = DefaultHasher::new();
        hasher.write(to_hash.as_bytes());
        let hash = hasher.finish() % 1_000_000;
        format!(
            "{}_{}",
            Path::new(&cli_args.target)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy(),
            hash
        )
    }
}

fn run_tmux_session(tmux_name: &str, cmds: &[String]) {
    let tmux = Session::new(tmux_name, cmds);
    if let Err(e) = tmux.run() {
        eprintln!("Error running tmux session: {e}");
        let _ = tmux.kill_session();
    } else {
        tmux.attach().unwrap();
    }
}
