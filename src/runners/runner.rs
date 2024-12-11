use anyhow::{Context, Result};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

use crate::session::CampaignData;
use crate::system_utils::{get_user_input, mkdir_helper};
use crate::tui::Tui;

/// Template files for different session managers
pub mod templates {
    pub const TMUX: &str = include_str!("../templates/tmux.txt");
    pub const SCREEN: &str = include_str!("../templates/screen.txt");
}

/// Represents a command to be executed in a session
#[derive(Debug, Clone)]
pub struct SessionCommand {
    raw: String,
    input_dir: PathBuf,
    output_dir: PathBuf,
}

impl SessionCommand {
    /// Parse a command string into a `SessionCommand`
    ///
    /// # Errors
    /// * If the input or output directories could not be found
    pub fn new(cmd: &str) -> Result<Self> {
        let parts: Vec<_> = cmd.split_whitespace().collect();
        let input_dir = parts
            .iter()
            .position(|&x| x == "-i")
            .and_then(|i| parts.get(i + 1))
            .map(PathBuf::from)
            .context("Failed to find input directory in command")?;

        let output_dir = parts
            .iter()
            .position(|&x| x == "-o")
            .and_then(|i| parts.get(i + 1))
            .map(PathBuf::from)
            .context("Failed to find output directory in command")?;

        Ok(Self {
            raw: cmd.to_string(),
            input_dir,
            output_dir,
        })
    }
}

/// Common functionality for session management
pub trait SessionManager: Sized {
    /// Name of the session manager (e.g., "tmux" or "screen")
    fn manager_name() -> &'static str;

    /// Template to use for creating the session
    fn template() -> &'static str;

    /// Version flag for checking installation
    fn version_flag() -> &'static str;

    /// Command to check if a session exists
    fn build_session_check_command(session_name: &str) -> Command;

    /// Command to kill a session
    fn build_kill_command(session_name: &str) -> Command;

    /// Command to attach to a session
    fn build_attach_command(session_name: &str) -> Command;

    /// Optional post-attachment setup (e.g., finding window ID in tmux)
    ///
    /// # Errors
    /// * If the implementation specific setup fails
    fn post_attach_setup(_session_name: &str) -> Result<()> {
        Ok(())
    }
}

/// Base session implementation
#[derive(Debug)]
pub struct Session<T: SessionManager> {
    name: String,
    commands: Vec<SessionCommand>,
    log_file: PathBuf,
    pid_file: PathBuf,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: SessionManager> Session<T> {
    /// Create a new session
    ///
    /// # Errors
    /// * If any session command could not be parsed
    pub fn new(session_name: &str, commands: &[String], pid_file: &Path) -> Result<Self> {
        let commands = commands
            .iter()
            .map(|c| SessionCommand::new(&c.replace('"', "\\\"")))
            .collect::<Result<Vec<_>>>()?;

        let log_file = PathBuf::from(format!("/tmp/{}_{}.log", T::manager_name(), session_name));
        if log_file.exists() {
            fs::remove_file(&log_file)?;
        }

        Ok(Self {
            name: session_name.to_string(),
            commands,
            log_file,
            pid_file: pid_file.to_path_buf(),
            _phantom: std::marker::PhantomData,
        })
    }

    pub fn is_present(&self) -> bool {
        T::build_session_check_command(&self.name)
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Kill the session
    ///
    /// # Errors
    /// If `run_command` fails
    pub fn kill_session(&self) -> Result<()> {
        Self::run_command(T::build_kill_command(&self.name))
    }

    /// Attach to the session
    ///
    /// # Errors
    /// * If the session could not be attached
    pub fn attach(&self) -> Result<()> {
        T::post_attach_setup(&self.name)?;
        Self::run_command(T::build_attach_command(&self.name))
    }

    /// Create a bash script to run the session
    ///
    /// # Errors
    /// * If the template could not be loaded
    /// * If the template could not be rendered
    ///
    /// # Panics
    /// * If the log file or pid file paths are not valid UTF-8
    pub fn create_bash_script(&self) -> Result<String> {
        let mut engine = upon::Engine::new();
        engine.add_template("session", T::template())?;

        engine
            .template("session")
            .render(upon::value! {
                session_name: self.name.clone(),
                commands: self.commands.iter().map(|c| c.raw.clone()).collect::<Vec<_>>(),
                log_file: self.log_file.to_str().unwrap().to_string(),
                pid_file: self.pid_file.to_str().unwrap().to_string(),
            })
            .to_string()
            .context("Failed to create bash script")
    }

    fn run_command(mut cmd: Command) -> Result<()> {
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        let mut child = cmd.spawn()?;
        let _ = child.wait()?;
        Ok(())
    }

    /// Run the session
    ///
    /// # Errors
    /// * If the session script could not be created
    /// * If the session could not be started
    pub fn run(&self) -> Result<()> {
        self.setup_directories()?;
        self.confirm_start()?;
        Self::check_manager_installation()?;
        self.execute_session_script()
    }

    fn setup_directories(&self) -> Result<()> {
        // NOTE: We only need to look at the first command since all commands
        // will use the same directories
        let first_cmd = &self.commands[0];

        mkdir_helper(&first_cmd.input_dir, false)?;
        if first_cmd.input_dir.read_dir()?.next().is_none() {
            fs::write(first_cmd.input_dir.join("1"), "fuzz")?;
        }
        mkdir_helper(&first_cmd.output_dir, true)?;

        Ok(())
    }

    fn confirm_start(&self) -> Result<()> {
        println!(
            "Generated {} session '{}' for {} commands. Continue [Y/n]?",
            T::manager_name(),
            self.name,
            self.commands.len()
        );
        std::io::stdout().flush()?;

        if get_user_input() != 'y' {
            anyhow::bail!("Aborting");
        }
        println!("Starting session...");
        Ok(())
    }

    fn check_manager_installation() -> Result<()> {
        let status = Command::new(T::manager_name())
            .arg(T::version_flag())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;

        if !status.success() {
            anyhow::bail!("Error: {} not found or not executable", T::manager_name());
        }
        Ok(())
    }

    fn execute_session_script(&self) -> Result<()> {
        let script_content = self.create_bash_script()?;
        let mut temp_script = NamedTempFile::new()?;

        temp_script.write_all(script_content.as_bytes())?;
        let mut perms = temp_script.as_file().metadata()?.permissions();
        perms.set_mode(perms.mode() | 0o111);
        temp_script.as_file().set_permissions(perms)?;

        let output = Command::new("bash")
            .arg(temp_script.path())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8(output.stderr)
                .unwrap_or_else(|e| format!("Failed to parse stderr: {e}"));
            let path = temp_script.into_temp_path().keep()?;
            anyhow::bail!(
                "Error executing runner script {}: exit code {}, stderr: '{}'",
                path.display(),
                output.status,
                stderr
            );
        }

        Ok(())
    }

    /// Run the session with a TUI
    ///
    /// # Errors
    /// * If the session could not be started
    pub fn run_with_tui(&self, out_dir: &Path) -> Result<()> {
        let mut cdata = CampaignData::new();
        self.run()?;

        thread::sleep(Duration::from_secs(1));
        Tui::run(out_dir, Some(&self.pid_file), &mut cdata)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_command_parsing() {
        let cmd = "afl-fuzz -i /tmp/input -o /tmp/output @@";
        let parsed = SessionCommand::new(cmd).unwrap();
        assert_eq!(parsed.input_dir, PathBuf::from("/tmp/input"));
        assert_eq!(parsed.output_dir, PathBuf::from("/tmp/output"));
    }
}
