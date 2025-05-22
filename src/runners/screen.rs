use std::process::Command;

use crate::runners::runner::{Session, SessionManager, templates};

/// Screen session manager implementation
pub struct Screen;

impl SessionManager for Screen {
    fn manager_name() -> &'static str {
        "screen"
    }

    fn template() -> &'static str {
        templates::SCREEN
    }

    fn version_flag() -> &'static str {
        "-v"
    }

    fn build_session_check_command(session_name: &str) -> Command {
        let mut cmd = Command::new(Self::manager_name());
        cmd.args(["-list", session_name]);
        cmd
    }

    fn build_kill_command(session_name: &str) -> Command {
        let mut cmd = Command::new(Self::manager_name());
        cmd.args(["-S", session_name, "-X", "kill"]);
        cmd
    }

    fn build_attach_command(session_name: &str) -> Command {
        let mut cmd = Command::new(Self::manager_name());
        cmd.args(["-r", session_name]);
        cmd
    }
}

/// Type alias for a Screen session
pub type ScreenSession = Session<Screen>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_screen_commands() {
        let session_name = "test_session";

        let check_cmd = Screen::build_session_check_command(session_name);
        assert_eq!(check_cmd.get_program(), "screen");
        assert_eq!(
            check_cmd.get_args().collect::<Vec<_>>(),
            vec!["-list", "test_session"]
        );

        let kill_cmd = Screen::build_kill_command(session_name);
        assert_eq!(
            kill_cmd.get_args().collect::<Vec<_>>(),
            vec!["-S", "test_session", "-X", "kill"]
        );
    }
}
