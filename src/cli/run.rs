use clap::Args;

use super::GenArgs;
use crate::cli::SessionRunner;

#[derive(Args, Clone, Debug, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct RunArgs {
    /// Arguments for generating the commands
    #[command(flatten)]
    pub gen_args: GenArgs,

    /// Only show the generated commands, don't run them
    #[arg(long, help = "Output commands without executing")]
    pub dry_run: bool,

    /// Runner backend to use
    #[clap(value_enum)]
    #[arg(long = "session-runner", help = "Session runner to use", default_value_t = SessionRunner::Tmux)]
    pub session_runner: SessionRunner,

    /// Custom tmux session name
    #[arg(long = "session-name", help = "Custom runner session name")]
    pub session_name: Option<String>,

    /// Enable tui mode
    #[arg(long, help = "Enable TUI mode")]
    pub tui: bool,

    /// Start detached from any session (not compatible with TUI)
    #[arg(long, help = "Start detached from session")]
    pub detached: bool,

    /// Use `RAMDisk` for AFL++
    #[arg(long, help = "Use RAMDisk for AFL++")]
    pub is_ramdisk: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_args_default() {
        let args = RunArgs::default();
        assert!(!args.dry_run);
        assert!(!args.tui);
        assert!(!args.detached);
        assert!(!args.is_ramdisk);
    }

    #[test]
    fn test_run_args_with_values() {
        let gen_args = GenArgs::default();
        let args = RunArgs {
            gen_args,
            dry_run: true,
            tui: true,
            ..RunArgs::default()
        };

        assert!(args.dry_run);
        assert!(args.tui);
        assert!(!args.detached);
    }
}
