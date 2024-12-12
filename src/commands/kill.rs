use anyhow::{Context, Result};
use std::path::Path;

use crate::{
    cli::KillArgs,
    commands::Command,
    runners::{screen::ScreenSession, tmux::TmuxSession},
};

pub struct KillCommand<'a> {
    args: &'a KillArgs,
}

impl<'a> KillCommand<'a> {
    pub fn new(args: &'a KillArgs) -> Self {
        Self { args }
    }
}

impl Command for KillCommand<'_> {
    fn execute(&self) -> Result<()> {
        let session_name = &self.args.session_name;
        let mut terminated = false;

        // Try Tmux session
        if let Ok(tmux) = TmuxSession::new(session_name, &[], Path::new("/tmp/aflr_foobar_1337")) {
            if tmux.is_present() {
                println!("[+] Found TMUX session: {session_name}. Terminating it...");
                tmux.kill_session().context("Failed to kill TMUX session")?;
                terminated = true;
            }
        }

        // Try Screen session
        if let Ok(screen) =
            ScreenSession::new(session_name, &[], Path::new("/tmp/aflr_foobar_1337"))
        {
            if screen.is_present() {
                println!("[+] Found SCREEN session: {session_name}. Terminating it...",);
                screen
                    .kill_session()
                    .context("Failed to kill SCREEN session")?;
                terminated = true;
            }
        }

        if !terminated {
            println!("[-] No session found with the name: {session_name}");
        }

        Ok(())
    }
}
