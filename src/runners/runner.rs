use anyhow::Result;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use crate::runners::screen::SCREEN_TEMPLATE;
use crate::runners::tmux::TMUX_TEMPLATE;
use crate::tui::Tui;
use crate::utils::{get_user_input, mkdir_helper};

#[allow(dead_code)]
pub trait Runner {
    fn new(session_name: &str, commands: &[String]) -> Self
    where
        Self: Sized;
    fn create_bash_script(&self) -> Result<String, anyhow::Error>;
    fn kill_session(&self) -> Result<(), anyhow::Error>;
    fn attach(&self) -> Result<(), anyhow::Error>;
    fn run(&self) -> Result<(), anyhow::Error>;
    fn run_with_tui(&self, out_dir: &Path) -> Result<()>;
}

pub struct Session {
    pub name: String,
    pub commands: Vec<String>,
    pub log_file: PathBuf,
    pub runner_name: &'static str,
}

impl Session {
    pub fn new(session_name: &str, commands: &[String], runner_name: &'static str) -> Self {
        let commands = commands
            .iter()
            .map(|c| c.replace('"', "\\\""))
            .collect::<Vec<String>>();
        let log_file = PathBuf::from(format!("/tmp/{runner_name}_{session_name}.log"));
        if log_file.exists() {
            std::fs::remove_file(&log_file).unwrap();
        }
        Self {
            name: session_name.to_string(),
            commands,
            log_file,
            runner_name,
        }
    }

    pub fn create_bash_script(&self, template: &str) -> Result<String> {
        let mut engine = upon::Engine::new();
        engine.add_template("afl_fuzz", template)?;
        engine
            .template("afl_fuzz")
            .render(upon::value! {
                session_name :self.name.clone(),
                commands : self.commands.clone(),
                log_file : self.log_file.to_str().unwrap().to_string(),
            })
            .to_string()
            .map_err(|e| anyhow::anyhow!("Error creating bash script: {}", e))
    }

    pub fn run_command(mut cmd: Command) -> Result<()> {
        let mut child = cmd.spawn()?;
        let _ = child.wait()?;
        Ok(())
    }

    pub fn run(&self) -> Result<()> {
        let indir = PathBuf::from(
            self.commands[0]
                .split_whitespace()
                .skip_while(|&x| x != "-i")
                .nth(1)
                .unwrap(),
        );
        let outdir = PathBuf::from(
            self.commands[0]
                .split_whitespace()
                .skip_while(|&x| x != "-o")
                .nth(1)
                .unwrap(),
        );

        mkdir_helper(&indir, false)?;
        if indir.read_dir()?.next().is_none() {
            fs::write(indir.join("1"), "fuzz")?;
        }
        mkdir_helper(&outdir, true)?;

        println!(
            "Starting {} session '{}' for {} generated commands...",
            self.runner_name,
            self.name,
            self.commands.len()
        );

        print!("Continue [Y/n]? ");
        std::io::stdout().flush()?;
        let user_input = get_user_input();
        if user_input != "y" {
            anyhow::bail!("Aborting");
        }

        let template = match self.runner_name {
            "tmux" => TMUX_TEMPLATE,
            "screen" => SCREEN_TEMPLATE,
            _ => unreachable!(),
        };

        if let Ok(templ) = self.create_bash_script(template) {
            let mut cmd = Command::new("bash");
            cmd.arg("-c")
                .arg(templ)
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());
            Self::run_command(cmd)?;
        } else {
            return Err(anyhow::anyhow!("Error creating bash script"));
        }
        Ok(())
    }

    pub fn run_with_tui(&self, out_dir: &Path) -> Result<()> {
        if let Err(e) = self.run_detached() {
            eprintln!("Error running TUI: {e}");
            return Err(e);
        }

        thread::sleep(Duration::from_secs(1));

        Tui::run(out_dir);

        Ok(())
    }

    pub fn run_detached(&self) -> Result<()> {
        self.run()?;
        println!("Session {} started in detached mode", self.name);
        Ok(())
    }
}
