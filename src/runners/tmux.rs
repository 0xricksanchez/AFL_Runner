use anyhow::{Context, Result};
use std::process::Command;

use crate::runners::runner::{Session, SessionManager, templates};

/// Tmux session manager implementation
pub struct Tmux;

impl SessionManager for Tmux {
    fn manager_name() -> &'static str {
        "tmux"
    }

    fn template() -> &'static str {
        templates::TMUX
    }

    fn version_flag() -> &'static str {
        "-V"
    }

    fn build_session_check_command(session_name: &str) -> Command {
        let mut cmd = Command::new(Self::manager_name());
        cmd.args(["has-session", "-t", session_name]);
        cmd
    }

    fn build_kill_command(session_name: &str) -> Command {
        let mut cmd = Command::new(Self::manager_name());
        cmd.args(["kill-session", "-t", session_name]);
        cmd
    }

    fn build_attach_command(session_name: &str) -> Command {
        let mut cmd = Command::new(Self::manager_name());
        cmd.args(["attach-session", "-t", session_name]);
        cmd
    }

    fn post_attach_setup(session_name: &str) -> Result<()> {
        let output = Command::new(Self::manager_name())
            .args(["list-windows", "-t", session_name])
            .output()?;

        if !output.status.success() {
            anyhow::bail!("Failed to list tmux windows");
        }

        let output_str = String::from_utf8(output.stdout)?;
        let first_window = output_str.chars().next().context("No windows found")?;

        if first_window != '0' && first_window != '1' {
            anyhow::bail!("Invalid window ID: {}", first_window);
        }

        Ok(())
    }
}

/// Type alias for a Tmux session
pub type TmuxSession = Session<Tmux>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tmux_commands() {
        let session_name = "test_session";

        let check_cmd = Tmux::build_session_check_command(session_name);
        assert_eq!(check_cmd.get_program(), "tmux");
        assert_eq!(
            check_cmd.get_args().collect::<Vec<_>>(),
            vec!["has-session", "-t", "test_session"]
        );

        let kill_cmd = Tmux::build_kill_command(session_name);
        assert_eq!(
            kill_cmd.get_args().collect::<Vec<_>>(),
            vec!["kill-session", "-t", "test_session"]
        );
    }
}
