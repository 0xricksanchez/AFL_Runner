use clap::Parser;

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
#[command(version = "1.0")]
pub struct Args {
    /// Target binary to fuzz
    #[arg(short, long, help = "Instrumented target binary to fuzz")]
    target: String,
    /// Sanitizer binary to use
    #[arg(
        short,
        long,
        help = "Instrumented with *SAN binary to use",
        required = false
    )]
    san_target: Option<String>,
    /// CMPLOG binary to use
    #[arg(
        short,
        long,
        help = "Instrumented with CMPLOG binary to use",
        required = false
    )]
    cmpl_target: Option<String>,
    /// Target binary arguments
    #[arg(
        short = 'a',
        long,
        help = "Target binary arguments, including @@ if needed",
        required = false
    )]
    target_args: Option<String>,
    /// Amount of processes to spin up
    #[arg(
        short,
        long,
        default_value = "1",
        value_name = "NUM_PROCS",
        help = "Amount of processes to spin up"
    )]
    runners: u32,
    /// Corpus directory
    #[arg(
        short,
        long,
        default_value = AFL_CORPUS,
        help = "Corpus directory",
        required = false
    )]
    input_dir: Option<String>,
    /// Output directory
    #[arg(
        short,
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
    /// When used all generated commands will be put into a tmux session
    use_tmux: bool,
}

fn main() {
    let cli_args = Args::parse();
    let harness = Harness::new(
        cli_args.target,
        cli_args.san_target,
        cli_args.cmpl_target,
        cli_args.target_args,
    );
    let afl_runner = AFLCmdGenerator::new(
        harness,
        cli_args.runners,
        cli_args.afl_binary.as_ref(),
        &cli_args.input_dir.unwrap(),
        &cli_args.output_dir.unwrap(),
        cli_args.dictionary.as_ref(),
    );
    let cmds = afl_runner.generate_afl_commands();

    if cli_args.use_tmux {
        let tmux = Session::new("afl_runner", &cmds);
        if let Err(e) = tmux.run() {
            println!("Error running tmux session: {e}");
            let _ = tmux.kill_session();
            return;
        }
        tmux.attach().unwrap();
    } else {
        for cmd in cmds {
            println!("{cmd}");
        }
    }
}
