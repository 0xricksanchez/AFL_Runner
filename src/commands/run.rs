use crate::{
    afl::cmd::ToStringVec,
    cli::{args::SessionRunner, RunArgs},
    commands::{gen::GenCommand, Command},
    config_manager::ConfigManager,
    runners::{
        runner::{Session, SessionManager},
        screen::ScreenSession,
        tmux::TmuxSession,
    },
};
use anyhow::{bail, Context, Result};
use std::{
    hash::{DefaultHasher, Hasher},
    path::Path,
};

pub struct RunCommand<'a> {
    args: &'a RunArgs,
    config_manager: &'a ConfigManager,
}

impl<'a> RunCommand<'a> {
    pub fn new(args: &'a RunArgs, config_manager: &'a ConfigManager) -> Self {
        Self {
            args,
            config_manager,
        }
    }

    fn generate_session_name(args: &RunArgs, target_args: &str) -> String {
        args.session_name.as_ref().map_or_else(
            || {
                let target = args
                    .gen_args
                    .target
                    .as_ref()
                    .expect("Target binary is required")
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy();
                let to_hash = format!(
                    "{}_{}_{}",
                    target,
                    args.gen_args.input_dir.as_ref().map_or_else(
                        || crate::cli::AFL_CORPUS.into(),
                        |dir| dir.file_name().unwrap_or_default().to_string_lossy()
                    ),
                    target_args,
                );
                let mut hasher = DefaultHasher::new();
                hasher.write(to_hash.as_bytes());
                let hash = hasher.finish() % 1_000_000;
                format!("{target}_{hash}")
            },
            std::clone::Clone::clone,
        )
    }

    fn execute_session<T: SessionManager>(
        session: &Session<T>,
        args: &RunArgs,
        session_type: &str,
    ) -> Result<()> {
        if args.tui {
            session
                .run_with_tui(&args.gen_args.output_dir.clone().unwrap())
                .with_context(|| format!("Failed to run TUI {session_type} session"))?;
        } else {
            session
                .run()
                .with_context(|| format!("Failed to run {session_type} session"))?;
            if !args.detached {
                session
                    .attach()
                    .with_context(|| format!("Failed to attach to {session_type} session"))?;
            }
        }
        Ok(())
    }
}

impl Command for RunCommand<'_> {
    fn execute(&self) -> Result<()> {
        let (merged_args, raw_afl_flags) = self.config_manager.merge_run_args(self.args)?;

        if merged_args.tui && merged_args.detached {
            bail!("TUI and detached mode cannot be used together");
        }

        let afl_generator = GenCommand::create_afl_runner(
            &merged_args.gen_args,
            raw_afl_flags.as_ref(),
            merged_args.is_ramdisk,
        )
        .context("Failed to create AFL runner")?;

        let afl_commands = afl_generator.run().context("Failed to run AFL generator")?;

        if merged_args.dry_run {
            println!("{afl_commands:?}");
            return Ok(());
        }

        let target_args = merged_args
            .gen_args
            .target_args
            .clone()
            .unwrap_or_default()
            .join(" ");

        let sname = Self::generate_session_name(&merged_args, &target_args);
        let pid_fn = format!("/tmp/.{}_{}.pids", &sname, std::process::id());
        let pid_fn_path = Path::new(&pid_fn);

        match &merged_args.session_runner {
            SessionRunner::Screen => {
                let screen = ScreenSession::new(&sname, &afl_commands.to_string_vec(), pid_fn_path)
                    .context("Failed to create Screen session")?;
                Self::execute_session(&screen, &merged_args, "Screen")
            }
            SessionRunner::Tmux => {
                let tmux = TmuxSession::new(&sname, &afl_commands.to_string_vec(), pid_fn_path)
                    .context("Failed to create Tmux session")?;
                Self::execute_session(&tmux, &merged_args, "Tmux")
            }
        }
    }
}