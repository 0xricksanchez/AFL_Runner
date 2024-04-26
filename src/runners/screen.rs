use crate::runners::runner::{Runner, Session};
use anyhow::Result;
use std::{
    path::Path,
    process::{Command, Stdio},
};

pub const SCREEN_TEMPLATE: &str = include_str!("../templates/screen.txt");

pub struct Screen {
    inner: Session,
}

impl Runner for Screen {
    fn new(session_name: &str, commands: &[String], pid_file: &Path) -> Self {
        Self {
            inner: Session::new(session_name, commands, "screen", pid_file),
        }
    }

    fn create_bash_script(&self) -> Result<String> {
        self.inner.create_bash_script(SCREEN_TEMPLATE)
    }

    fn kill_session(&self) -> Result<()> {
        let mut cmd = Command::new("screen");
        cmd.arg("-S")
            .arg(&self.inner.name)
            .arg("-X")
            .arg("quit")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        Session::run_command(cmd)
    }

    fn attach(&self) -> Result<()> {
        let mut cmd = Command::new("screen");
        cmd.arg("-r")
            .arg(&self.inner.name)
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
