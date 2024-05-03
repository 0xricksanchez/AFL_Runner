use crate::runners::runner::{Runner, Session};
use anyhow::Result;
use std::{
    path::Path,
    process::{Command, Stdio},
};

pub const TMUX_TEMPLATE: &str = include_str!("../templates/tmux.txt");

pub struct Tmux {
    inner: Session,
}

impl Runner for Tmux {
    fn new(session_name: &str, commands: &[String], pid_file: &Path) -> Self {
        Self {
            inner: Session::new(session_name, commands, "tmux", pid_file),
        }
    }

    fn create_bash_script(&self) -> Result<String> {
        self.inner.create_bash_script(TMUX_TEMPLATE)
    }

    fn is_present(&self) -> bool {
        let output = Command::new("tmux")
            .args(["has-session", "-t", &self.inner.name])
            .output()
            .unwrap();
        output.status.success()
    }

    fn kill_session(&self) -> Result<()> {
        let mut cmd = Command::new("tmux");
        cmd.arg("kill-session")
            .arg("-t")
            .arg(&self.inner.name)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        Session::run_command(cmd)
    }

    fn attach(&self) -> Result<()> {
        let get_first_window_id = self.find_first_window_id()?;
        let target = format!("{}:{}", &self.inner.name, get_first_window_id);
        let mut cmd = Command::new("tmux");
        cmd.args(["attach-session", "-t", &target])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        Session::run_command(cmd)
    }

    fn run(&self) -> Result<()> {
        self.inner.run()
    }

    fn run_with_tui(&self, out_dir: &Path) -> Result<()> {
        if let Err(e) = self.inner.run_with_tui(out_dir) {
            let _ = self.kill_session();
            return Err(e);
        }
        Ok(())
    }
}

impl Tmux {
    fn find_first_window_id(&self) -> Result<String> {
        let output = Command::new("tmux")
            .args(["list-windows", "-t", &self.inner.name])
            .output()?;

        if !output.status.success() {
            anyhow::bail!("Failed to list tmux windows");
        }

        let output_str = String::from_utf8(output.stdout)?;
        let first_window = output_str.chars().next().unwrap();
        if first_window == '0' || first_window == '1' {
            Ok(first_window.to_string())
        } else {
            self.kill_session()?;
            anyhow::bail!("Failed to find first window id");
        }
    }
}
