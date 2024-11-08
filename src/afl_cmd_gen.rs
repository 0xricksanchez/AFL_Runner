use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::{fs, process::Command};
use uuid::Uuid;

use crate::afl_env::{AFLEnv, AFLFlag};
use crate::cli::FlagGroup;
use crate::harness::Harness;
use anyhow::{Context, Result};
use rand::seq::SliceRandom;
use rand::Rng;
use sysinfo::System;

/// Represents an AFL command
#[derive(Debug)]
pub struct AflCmd {
    /// Path to the AFL binary
    afl_binary: PathBuf,
    /// Environment variables for the AFL command
    env: Vec<String>,
    /// Input directory for AFL
    input_dir: PathBuf,
    /// Output directory for AFL
    output_dir: PathBuf,
    /// Miscellaneous AFL flags
    misc_afl_flags: Vec<String>,
    /// Path to the target binary
    target_binary: PathBuf,
    /// Arguments for the target binary
    target_args: Option<String>,
}

impl AflCmd {
    /// Creates a new `AflCmd` instance
    pub fn new(afl_binary: PathBuf, target_binary: PathBuf) -> Self {
        Self {
            afl_binary,
            env: Vec::new(),
            input_dir: PathBuf::new(),
            output_dir: PathBuf::new(),
            misc_afl_flags: Vec::new(),
            target_binary,
            target_args: None,
        }
    }

    /// Sets the environment variables for the AFL command
    pub fn extend_env(&mut self, env: Vec<String>, is_prepend: bool) {
        if is_prepend {
            env.iter().for_each(|e| self.env.insert(0, e.clone()));
        } else {
            self.env.extend(env);
        }
    }

    /// Sets the input directory for AFL
    pub fn set_input_dir(&mut self, input_dir: PathBuf) {
        self.input_dir = input_dir;
    }

    /// Sets the output directory for AFL
    pub fn set_output_dir(&mut self, output_dir: PathBuf) {
        self.output_dir = output_dir;
    }

    /// Sets the miscellaneous AFL flags
    pub fn set_misc_afl_flags(&mut self, misc_afl_flags: Vec<String>) {
        self.misc_afl_flags = misc_afl_flags;
    }

    /// Sets the arguments for the target binary
    pub fn set_target_args(&mut self, target_args: Option<String>) {
        self.target_args = target_args;
    }

    /// Assembles the AFL command into a string
    pub fn assemble(&self) -> String {
        let mut cmd_parts = Vec::new();

        cmd_parts.extend(self.env.iter().cloned());
        cmd_parts.push(self.afl_binary.display().to_string());
        cmd_parts.push(format!("-i {}", self.input_dir.display()));
        cmd_parts.push(format!("-o {}", self.output_dir.display()));
        cmd_parts.extend(self.misc_afl_flags.iter().cloned());
        cmd_parts.push(format!("-- {}", self.target_binary.display()));

        if let Some(target_args) = &self.target_args {
            cmd_parts.push(target_args.clone());
        }

        cmd_parts.join(" ").trim().replace("  ", " ")
    }
}

/// Retrieves the amount of free memory in the system in MB
/// This function is used to determine the `AFL_TESTCACHE_SIZE` value
///
/// NOTE: This function will likely break on Windows
fn get_free_mem_in_mb() -> u64 {
    let s = System::new_all();
    s.free_memory() / 1024 / 1024
}

/// Applies a flag to a percentage of AFL configurations
fn apply_flags(configs: &mut [AFLEnv], flag: &AFLFlag, percentage: f64, rng: &mut impl Rng) {
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_sign_loss)]
    #[allow(clippy::cast_precision_loss)]
    let count = (configs.len() as f64 * percentage) as usize;
    let mut indices = HashSet::new();
    while indices.len() < count {
        indices.insert(rng.gen_range(0..configs.len()));
    }

    for index in indices {
        configs[index].enable_flag(flag.clone());
    }
}

/// Applies constrained arguments to a percentage of AFL commands
fn apply_constrained_args(cmds: &mut [AflCmd], args: &[(&str, f64)], rng: &mut impl Rng) {
    let n = cmds.len();
    for &(arg, percentage) in args {
        #[allow(clippy::cast_possible_truncation)]
        #[allow(clippy::cast_sign_loss)]
        #[allow(clippy::cast_precision_loss)]
        let count = (n as f64 * percentage) as usize;
        let mut available_indices: Vec<usize> = (0..n)
            .filter(|i| !cmds[*i].misc_afl_flags.iter().any(|f| f.contains(arg)))
            .collect();
        available_indices.shuffle(rng);

        for &index in available_indices.iter().take(count) {
            cmds[index].misc_afl_flags.push(arg.to_string());
        }
    }
}

/// Applies an argument to a percentage of AFL commands
fn apply_args(cmds: &mut [AflCmd], arg: &str, percentage: f64, rng: &mut impl Rng) {
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_sign_loss)]
    #[allow(clippy::cast_precision_loss)]
    let count = (cmds.len() as f64 * percentage) as usize;
    let mut indices = HashSet::new();
    while indices.len() < count {
        indices.insert(rng.gen_range(0..cmds.len()));
    }

    for index in indices {
        cmds[index].misc_afl_flags.push(arg.to_string());
    }
}

/// Applies a list of arguments to a percentage or specific count of AFL commands
fn apply_args_list(cmds: &mut [AflCmd], args: &[&str], percentage: Option<f64>, count: Option<usize>, rng: &mut impl Rng) {
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_sign_loss)]
    #[allow(clippy::cast_precision_loss)]
    let count = percentage.map_or_else(|| count.unwrap_or(0), |percentage| (cmds.len() as f64 * percentage) as usize);

    let mut indices = HashSet::new();
    while indices.len() < count {
        indices.insert(rng.gen_range(0..cmds.len()));
    }

    for index in indices {
        for &arg in args {
            cmds[index].misc_afl_flags.push(arg.to_string());
        }
    }
}

/// Applies a list of env variables to a percentage or specific count of AFL command environments
fn apply_env_vars(cmds: &mut [AflCmd], envs: &[&str], percentage: Option<f64>, count: Option<usize>, rng: &mut impl Rng) {
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_sign_loss)]
    #[allow(clippy::cast_precision_loss)]
    let count = percentage.map_or_else(|| count.unwrap_or(0), |percentage| (cmds.len() as f64 * percentage) as usize);

    let mut indices = HashSet::new();
    while indices.len() < count {
        indices.insert(rng.gen_range(0..cmds.len()));
    }

    for index in indices {
        for &env in envs {
            cmds[index].env.push(env.to_string());
        }
    }
}

/// Generates AFL commands based on the provided configuration
pub struct AFLCmdGenerator {
    /// The harness configuration
    pub harness: Harness,
    /// Input directory for AFL
    pub input_dir: PathBuf,
    /// Output directory for AFL
    pub output_dir: PathBuf,
    /// Number of AFL runners
    pub runners: u32,
    /// Path to the dictionary file/directory
    pub dictionary: Option<String>,
    /// Raw AFL flags
    pub raw_afl_flags: Option<String>,
    /// Path to the AFL binary
    pub afl_binary: Option<String>,
    /// If we have a CMPCOV binary, this will contain the indices of the AFL commands that should
    /// use the CMPCOV binary
    cmpcov_idxs: Vec<usize>,
    pub ramdisk: Option<String>,
    // Use AFL defaults (do not variate mutator, power scheduler, trimming, ...)
    pub use_afl_defaults: bool,
    // AFL additional 
    pub additional_flags: Option<Vec<FlagGroup>>,
}

impl AFLCmdGenerator {
    /// Creates a new `AFLCmdGenerator` instance
    pub fn new(
        harness: Harness,
        runners: u32,
        input_dir: PathBuf,
        output_dir: PathBuf,
        dictionary: Option<PathBuf>,
        raw_afl_flags: Option<String>,
        afl_binary: Option<String>,
        is_ramdisk: bool,
        use_afl_defaults: bool,
        additional_flags: Option<Vec<FlagGroup>>
    ) -> Self {
        let dict = dictionary.and_then(|d| {
            if d.exists() {
                d.to_str().map(String::from)
            } else {
                None
            }
        });
        let rdisk = if is_ramdisk {
            println!("[*] Attempting to create RAMDisk. Needing elevated privileges.");
            let r = Self::create_ramdisk();
            if let Ok(tmpfs) = r {
                println!("[+] Using RAMDisk: {tmpfs}");
                Some(tmpfs)
            } else {
                println!("[!] Failed to create RAMDisk: {}...", r.err().unwrap());
                None
            }
        } else {
            None
        };

        Self {
            harness,
            input_dir,
            output_dir,
            runners,
            dictionary: dict,
            raw_afl_flags,
            afl_binary,
            cmpcov_idxs: Vec::new(),
            ramdisk: rdisk,
            use_afl_defaults,
            additional_flags,
        }
    }

    fn create_ramdisk() -> Result<String> {
        let uuid = Uuid::new_v4().to_string();
        let folder = format!("/tmp/tmpfs/{uuid}");
        fs::create_dir_all(&folder)?;
        let _ = Command::new("sudo")
            .arg("mount")
            .arg("-o")
            .arg("size=4G")
            .arg("-t")
            .arg("tmpfs")
            .arg("none")
            .arg(&folder)
            .output()?;
        Ok(folder)
    }

    /// Retrieves AFL environment variables
    fn get_afl_env_vars() -> Vec<String> {
        std::env::vars()
            .filter(|(k, _)| k.starts_with("AFL_"))
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<String>>()
    }

    /// Retrieves the path to the AFL binary
    fn get_afl_fuzz(&self) -> Result<PathBuf> {
        self.afl_binary
            .as_ref()
            .map(PathBuf::from)
            .or_else(|| std::env::var("AFL_PATH").map(PathBuf::from).ok())
            .or_else(|| {
                let output = Command::new("which")
                    .arg("afl-fuzz")
                    .output()
                    .context("Failed to execute 'which'")
                    .ok()?;
                if output.status.success() {
                    let afl_path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if afl_path.is_empty() {
                        None
                    } else {
                        Some(PathBuf::from(afl_path))
                    }
                } else {
                    None
                }
            })
            .and_then(|path| {
                if path.exists() && path.is_file() && path.ends_with("afl-fuzz") {
                    Some(path)
                } else {
                    None
                }
            })
            .context("Could not find afl-fuzz binary")
    }

    /// Generates AFL commands based on the configuration
    pub fn generate_afl_commands(&mut self) -> Result<Vec<String>> {
        let mut rng = rand::thread_rng();
        let configs = self.initialize_configs(&mut rng);
        let mut cmds = self.create_initial_cmds(&configs)?;

        let afl_env_vars: Vec<String> = Self::get_afl_env_vars();
        let is_using_custom_mutator = afl_env_vars
            .iter()
            .any(|e| e.starts_with("AFL_CUSTOM_MUTATOR_LIBRARY"));
        if !self.use_afl_defaults {
            Self::apply_mutation_strategies(&mut cmds, &mut rng, is_using_custom_mutator);
            Self::apply_queue_selection(&mut cmds, &mut rng);
            Self::apply_power_schedules(&mut cmds);
        }
        self.apply_directory(&mut cmds);
        self.apply_dictionary(&mut cmds)?;
        self.apply_sanitizer_or_target_binary(&mut cmds);
        self.apply_cmplog(&mut cmds, &mut rng);
        self.apply_target_args(&mut cmds);
        self.apply_cmpcov(&mut cmds, &mut rng);

        if let Some(additional_flags) = &self.additional_flags {
            for flag_group in additional_flags {
                let (dash_flags, env_flags): (Vec<_>, Vec<_>) = flag_group
                    .flags
                    .iter()
                    .partition(|flag| flag.0.starts_with('-'));

                let dash_flags: Vec<String> = dash_flags
                    .iter()
                    .map(|flag| format!("{} {}", flag.0, flag.1))
                    .collect();

                let env_flags: Vec<String> = env_flags
                    .iter()
                    .map(|flag| format!("{}={}", flag.0, flag.1))
                    .collect();

                apply_args_list(&mut cmds, &dash_flags.iter().map(String::as_str).collect::<Vec<&str>>(), flag_group.probability.map(f64::from), flag_group.count.map(|c| c as usize), &mut rng);
                apply_env_vars(&mut cmds, &env_flags.iter().map(String::as_str).collect::<Vec<&str>>(), flag_group.probability.map(f64::from), flag_group.count.map(|c| c as usize), &mut rng);
            }
        }

        // NOTE: Needs to called last as it relies on cmpcov/cmplog being already set
        self.apply_fuzzer_roles(&mut cmds);

        // Inherit global AFL environment variables that are not already set
        for cmd in &mut cmds {
            let to_apply = afl_env_vars
                .iter()
                .filter(|env| {
                    !cmd.env
                        .iter()
                        .any(|e| e.split('=').next().unwrap() == env.split('=').next().unwrap())
                })
                .cloned()
                .collect::<Vec<String>>();
            cmd.extend_env(to_apply, true);
        }

        let cmd_strings = cmds.into_iter().map(|cmd| cmd.assemble()).collect();
        Ok(cmd_strings)
    }

    /// Initializes AFL configurations
    fn initialize_configs(&self, rng: &mut impl Rng) -> Vec<AFLEnv> {
        let mut configs = vec![AFLEnv::new(); self.runners as usize];

        // Enable FinalSync for the last configuration
        configs.last_mut().unwrap().enable_flag(AFLFlag::FinalSync);

        if !self.use_afl_defaults {
            apply_flags(&mut configs, &AFLFlag::DisableTrim, 0.65, rng);
            apply_flags(&mut configs, &AFLFlag::KeepTimeouts, 0.5, rng);
            apply_flags(&mut configs, &AFLFlag::ExpandHavocNow, 0.4, rng);
        }
        let free_mb = get_free_mem_in_mb();
        for c in &mut configs {
            match free_mb {
                x if x > (self.runners * 500 + 4096).into() => c.testcache_size = 500,
                x if x > (self.runners * 250 + 4096).into() => c.testcache_size = 250,
                _ => {}
            }
        }

        configs
    }

    /// Creates initial AFL commands
    fn create_initial_cmds(&self, configs: &[AFLEnv]) -> Result<Vec<AflCmd>> {
        let afl_binary = self.get_afl_fuzz()?;
        let target_binary = self.harness.target_binary.clone();

        let cmds = configs
            .iter()
            .map(|config| {
                let mut cmd = AflCmd::new(afl_binary.clone(), target_binary.clone());
                cmd.extend_env(config.generate_afl_env_cmd(self.ramdisk.clone()), false);
                if let Some(raw_afl_flags) = &self.raw_afl_flags {
                    cmd.set_misc_afl_flags(
                        raw_afl_flags
                            .split_whitespace()
                            .map(str::to_string)
                            .collect(),
                    );
                }
                cmd
            })
            .collect();

        Ok(cmds)
    }

    /// Applies mutation strategies to AFL commands
    fn apply_mutation_strategies(
        cmds: &mut [AflCmd],
        rng: &mut impl Rng,
        is_using_custom_mutator: bool,
    ) {
        let mode_args: [(&str, f64); 2] = [("-P explore", 0.4), ("-P exploit", 0.2)];
        apply_constrained_args(cmds, &mode_args, rng);
        let format_args = [("-a binary", 0.3), ("-a text", 0.3)];
        apply_constrained_args(cmds, &format_args, rng);
        if !is_using_custom_mutator {
            apply_args(cmds, "-L 0", 0.1, rng);
        }
    }

    /// Applies queue selection to AFL commands
    fn apply_queue_selection(cmds: &mut [AflCmd], rng: &mut impl Rng) {
        apply_args(cmds, "-Z", 0.2, rng);
    }

    /// Applies power schedules to AFL commands
    fn apply_power_schedules(cmds: &mut [AflCmd]) {
        let pscheds = ["fast", "explore", "coe", "lin", "quad", "exploit", "rare"];
        cmds.iter_mut().enumerate().for_each(|(i, cmd)| {
            cmd.misc_afl_flags
                .push(format!("-p {}", pscheds[i % pscheds.len()]));
        });
    }

    /// Applies input and output directories to AFL commands
    fn apply_directory(&self, cmds: &mut [AflCmd]) {
        for cmd in cmds {
            cmd.set_input_dir(self.input_dir.clone());
            cmd.set_output_dir(self.output_dir.clone());
        }
    }

    /// Applies fuzzer roles to AFL commands
    fn apply_fuzzer_roles(&self, cmds: &mut [AflCmd]) {
        let target_fname = self
            .harness
            .target_binary
            .file_stem()
            .unwrap()
            .to_str()
            .unwrap()
            .replace('.', "_");

        cmds[0]
            .misc_afl_flags
            .push(format!("-M main_{target_fname}"));

        let cmpcov_binary = self.harness.cmpcov_binary.as_ref();

        for (i, cmd) in cmds[1..].iter_mut().enumerate() {
            let suffix = if cmd.misc_afl_flags.iter().any(|f| f.contains("-c")) {
                format!("_{target_fname}_cl")
            } else {
                format!("_{target_fname}")
            };

            let s_flag = if self.cmpcov_idxs.contains(&(i + 1)) {
                let cmpcov_fname = cmpcov_binary
                    .unwrap()
                    .file_stem()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .replace('.', "_");
                format!("-S s_{i}_{cmpcov_fname}")
            } else {
                format!("-S s_{i}{suffix}")
            };

            cmd.misc_afl_flags.push(s_flag);
        }
    }

    /// Applies dictionary to AFL commands
    fn apply_dictionary(&self, cmds: &mut [AflCmd]) -> Result<()> {
        if let Some(dict) = self.dictionary.as_ref() {
            let dict_path = fs::canonicalize(dict).context("Failed to resolve dictionary path")?;
            for cmd in cmds {
                cmd.misc_afl_flags
                    .push(format!("-x {}", dict_path.display()));
            }
        }
        Ok(())
    }

    /// Applies sanitizer or target binary to AFL commands
    fn apply_sanitizer_or_target_binary(&self, cmds: &mut [AflCmd]) {
        let binary = self
            .harness
            .sanitizer_binary
            .as_ref()
            .unwrap_or(&self.harness.target_binary);
        cmds[0].target_binary.clone_from(binary);
    }

    /// Applies CMPLOG instrumentation to AFL commands
    fn apply_cmplog(&self, cmds: &mut [AflCmd], rng: &mut impl Rng) {
        if let Some(cmplog_binary) = self.harness.cmplog_binary.as_ref() {
            #[allow(clippy::cast_possible_truncation)]
            #[allow(clippy::cast_sign_loss)]
            #[allow(clippy::cast_precision_loss)]
            let num_cmplog_cfgs = (f64::from(self.runners) * 0.3) as usize;
            match num_cmplog_cfgs {
                0 => {}
                1 => {
                    cmds[1]
                        .misc_afl_flags
                        .push(format!("-l 2 -c {}", cmplog_binary.display()));
                }
                2 => {
                    cmds[1]
                        .misc_afl_flags
                        .push(format!("-l 2 -c {}", cmplog_binary.display()));
                    cmds[2]
                        .misc_afl_flags
                        .push(format!("-l 2AT -c {}", cmplog_binary.display()));
                }
                3 => {
                    cmds[1]
                        .misc_afl_flags
                        .push(format!("-l 2 -c {}", cmplog_binary.display()));
                    cmds[2]
                        .misc_afl_flags
                        .push(format!("-l 2AT -c {}", cmplog_binary.display()));
                    cmds[3]
                        .misc_afl_flags
                        .push(format!("-l 3 -c {}", cmplog_binary.display()));
                }
                _ => Self::apply_cmplog_instrumentation_many(
                    cmds,
                    num_cmplog_cfgs,
                    cmplog_binary,
                    rng,
                ),
            }
        }
    }

    /// Applies CMPLOG instrumentation to >4 AFL commands
    fn apply_cmplog_instrumentation_many(
        cmds: &mut [AflCmd],
        num_cmplog_cfgs: usize,
        cmplog_binary: &Path,
        rng: &mut impl Rng,
    ) {
        let cmplog_args = [("-l 2", 0.7), ("-l 3", 0.1), ("-l 2AT", 0.2)];
        apply_constrained_args(&mut cmds[1..=num_cmplog_cfgs], &cmplog_args, rng);
        for cmd in &mut cmds[1..=num_cmplog_cfgs] {
            cmd.misc_afl_flags
                .push(format!("-c {}", cmplog_binary.display()));
        }
    }

    /// Applies target arguments to AFL commands
    fn apply_target_args(&self, cmds: &mut [AflCmd]) {
        if let Some(target_args) = self.harness.target_args.as_ref() {
            for cmd in cmds {
                cmd.set_target_args(Some(target_args.clone()));
            }
        }
    }

    /// Applies CMPCOV instrumentation to AFL commands
    fn apply_cmpcov(&mut self, cmds: &mut [AflCmd], rng: &mut impl Rng) {
        if let Some(cmpcov_binary) = self.harness.cmpcov_binary.as_ref() {
            let max_cmpcov_instances = match self.runners {
                0..=2 => 0,
                3..=7 => 1,
                8..=15 => 2,
                _ => 3,
            };

            let mut cmpcov_indices = (1..cmds.len())
                .filter(|i| !cmds[*i].misc_afl_flags.iter().any(|f| f.contains("-c")))
                .collect::<Vec<_>>();
            cmpcov_indices.shuffle(rng);

            for i in cmpcov_indices.into_iter().take(max_cmpcov_instances) {
                self.cmpcov_idxs.push(i);
                cmds[i].target_binary.clone_from(cmpcov_binary);
            }
        }
    }
}
