use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::afl_cmd::AflCmd;
use crate::harness::Harness;
use crate::seed::Xorshift64;
use crate::{
    afl_env::{AFLEnv, AFLFlag},
    system_utils,
};
use anyhow::{Context, Result};
use rand::{rngs::StdRng, Rng};
use rand::{seq::SliceRandom, SeedableRng};

use system_utils::{create_ramdisk, find_binary_in_path, get_free_mem_in_mb};

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

/// Applies constrained arguments to a percentage of AFL commands, flags are mutually exclusive
fn apply_constrained_args_excl(cmds: &mut [AflCmd], args: &[(&str, f64)], rng: &mut impl Rng) {
    let n = cmds.len();

    // First, identify commands that don't have any of these args yet
    let mut available_indices: Vec<usize> = (0..n)
        .filter(|i| {
            !cmds[*i]
                .misc_afl_flags
                .iter()
                .any(|f| args.iter().any(|(arg, _)| f.contains(arg)))
        })
        .collect();
    available_indices.shuffle(rng);

    // Calculate how many commands should get each arg
    let mut current_idx = 0;
    for &(arg, percentage) in args {
        #[allow(clippy::cast_possible_truncation)]
        #[allow(clippy::cast_sign_loss)]
        #[allow(clippy::cast_precision_loss)]
        let count = (n as f64 * percentage) as usize;

        // Only take as many indices as we have available
        let end_idx = (current_idx + count).min(available_indices.len());
        for &index in &available_indices[current_idx..end_idx] {
            cmds[index].misc_afl_flags.push(arg.to_string());
        }
        current_idx = end_idx;
    }
}

/// Applies arguments independently to a percentage of AFL commands
/// Each command can receive multiple different flags, but never the same flag twice
fn apply_constrained_args(cmds: &mut [AflCmd], args: &[(&str, f64)], rng: &mut impl Rng) {
    let n = cmds.len();

    for &(arg, percentage) in args {
        #[allow(clippy::cast_possible_truncation)]
        #[allow(clippy::cast_sign_loss)]
        #[allow(clippy::cast_precision_loss)]
        let count = (n as f64 * percentage) as usize;

        // Only consider indices where this specific argument isn't already present
        let mut available_indices: Vec<usize> = (0..n)
            .filter(|i| !cmds[*i].misc_afl_flags.iter().any(|f| f == arg))
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
    if count == 0 && percentage > 0.0 && cmds.len() > 3 {
        // Ensure at least one command gets the flag
        cmds[rng.gen_range(0..cmds.len())]
            .misc_afl_flags
            .push(arg.to_string());
    } else {
        let mut indices = HashSet::new();
        while indices.len() < count {
            indices.insert(rng.gen_range(0..cmds.len()));
        }

        for index in indices {
            cmds[index].misc_afl_flags.push(arg.to_string());
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
    /// Path to the RAMDisk
    pub ramdisk: Option<String>,
    /// If we should use AFL defaults
    pub use_afl_defaults: bool,
    /// Seed for AFL++
    pub seed: Option<u64>,
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
        seed: Option<u64>,
    ) -> Self {
        if runners > 32 {
            println!("[!] Warning: Performance degradation may occur with more than 32 runners. Observe campaign results carefully.");
        }
        let dict = dictionary.and_then(|d| {
            if d.exists() {
                d.to_str().map(String::from)
            } else {
                None
            }
        });
        let rdisk = if is_ramdisk {
            let r = create_ramdisk();
            if let Ok(tmpfs) = r {
                println!("[+] Using RAMDisk: {}", tmpfs);
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
            seed,
        }
    }

    /// Retrieves AFL environment variables
    fn get_afl_env_vars() -> Vec<String> {
        std::env::vars()
            .filter(|(k, _)| k.starts_with("AFL_"))
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<String>>()
    }

    /// Generates AFL commands based on the configuration
    pub fn generate_afl_commands(&mut self) -> Result<Vec<String>> {
        let mangled_seed = Xorshift64::new(self.seed.unwrap_or(0)).next();
        let mut rng = <StdRng as SeedableRng>::seed_from_u64(mangled_seed as u64);
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
            cmd.with_env(to_apply, true);
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
            apply_flags(&mut configs, &AFLFlag::DisableTrim, 0.60, rng);
            if self.runners < 8 {
                // NOTE: With many runners and/or many seeds this can delay the startup significantly
                apply_flags(&mut configs, &AFLFlag::ImportFirst, 1.0, rng);
            }
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
        let afl_binary = find_binary_in_path(self.afl_binary.clone())?;
        let target_binary = self.harness.target_bin.clone();

        let cmds = configs
            .iter()
            .map(|config| {
                let mut cmd = AflCmd::new(afl_binary.clone(), target_binary.clone());
                cmd.with_env(config.generate_afl_env_cmd(self.ramdisk.clone()), false);
                if let Some(raw_afl_flags) = &self.raw_afl_flags {
                    cmd.with_misc_flags(
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
        apply_constrained_args_excl(cmds, &mode_args, rng);
        let format_args = [("-a binary", 0.3), ("-a text", 0.3)];
        apply_constrained_args_excl(cmds, &format_args, rng);
        if !is_using_custom_mutator {
            apply_args(cmds, "-L 0", 0.1, rng);
        }
    }

    /// Applies queue selection to AFL commands
    fn apply_queue_selection(cmds: &mut [AflCmd], rng: &mut impl Rng) {
        apply_args(cmds, "-Z", 0.1, rng);
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
            cmd.with_input_dir(self.input_dir.clone())
                .with_output_dir(self.output_dir.clone());
        }
    }

    /// Applies fuzzer roles to AFL commands
    fn apply_fuzzer_roles(&self, cmds: &mut [AflCmd]) {
        let target_fname = self
            .harness
            .target_bin
            .file_stem()
            .unwrap()
            .to_str()
            .unwrap()
            .replace('.', "_");

        cmds[0].misc_afl_flags.push(format!("-M m_{target_fname}"));

        let cmpcov_binary = self.harness.cmpcov_bin.as_ref();

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
                format!("-S s{i}_{cmpcov_fname}")
            } else {
                format!("-S s{i}{suffix}")
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
            .sanitizer_bin
            .as_ref()
            .unwrap_or(&self.harness.target_bin);
        cmds[0].target_binary.clone_from(binary);
    }

    /// Applies CMPLOG instrumentation to AFL commands
    fn apply_cmplog(&self, cmds: &mut [AflCmd], rng: &mut impl Rng) {
        if let Some(cmplog_binary) = self.harness.cmplog_bin.as_ref() {
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

    /// Applies CMPLOG instrumentation to >= 4 AFL commands
    fn apply_cmplog_instrumentation_many(
        cmds: &mut [AflCmd],
        num_cmplog_cfgs: usize,
        cmplog_binary: &Path,
        rng: &mut impl Rng,
    ) {
        let cmplog_args = [("-l 2", 0.7), ("-l 3", 0.1), ("-l 2AT", 0.2)];
        apply_constrained_args_excl(&mut cmds[1..=num_cmplog_cfgs], &cmplog_args, rng);
        for cmd in &mut cmds[1..=num_cmplog_cfgs] {
            cmd.misc_afl_flags
                .push(format!("-c {}", cmplog_binary.display()));
        }
    }

    /// Applies target arguments to AFL commands
    fn apply_target_args(&self, cmds: &mut [AflCmd]) {
        if let Some(target_args) = self.harness.target_args.as_ref() {
            for cmd in cmds {
                cmd.with_target_args(Some(target_args.clone()));
            }
        }
    }

    /// Applies CMPCOV instrumentation to AFL commands
    fn apply_cmpcov(&mut self, cmds: &mut [AflCmd], rng: &mut impl Rng) {
        if let Some(cmpcov_binary) = self.harness.cmpcov_bin.as_ref() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    /// Helper struct to hold test configuration and results
    struct TestCase {
        cmds: Vec<AflCmd>,
        explore_count: usize,
        exploit_count: usize,
        both_flags_count: usize,
    }

    impl TestCase {
        fn new() -> Self {
            let mut cmds = Vec::new();
            for i in 1..100 {
                cmds.push(AflCmd::new(
                    PathBuf::from("/tmp/afl-fuzz"),
                    PathBuf::from(format!("/tmp/target{}", i)),
                ));
            }
            Self {
                cmds,
                explore_count: 0,
                exploit_count: 0,
                both_flags_count: 0,
            }
        }

        fn analyze(&mut self) {
            self.explore_count = self
                .cmds
                .iter()
                .filter(|cmd| cmd.misc_afl_flags.iter().any(|f| f.contains("-P explore")))
                .count();

            self.exploit_count = self
                .cmds
                .iter()
                .filter(|cmd| cmd.misc_afl_flags.iter().any(|f| f.contains("-P exploit")))
                .count();

            self.both_flags_count = self
                .cmds
                .iter()
                .filter(|cmd| {
                    cmd.misc_afl_flags.iter().any(|f| f.contains("-P explore"))
                        && cmd.misc_afl_flags.iter().any(|f| f.contains("-P exploit"))
                })
                .count();
        }

        fn verify_no_duplicates(&self) {
            for cmd in &self.cmds {
                let explore_count = cmd
                    .misc_afl_flags
                    .iter()
                    .filter(|f| f.contains("-P explore"))
                    .count();
                let exploit_count = cmd
                    .misc_afl_flags
                    .iter()
                    .filter(|f| f.contains("-P exploit"))
                    .count();

                assert!(
                    explore_count <= 1,
                    "Command should not have duplicate explore flags: {:?}",
                    cmd.misc_afl_flags
                );
                assert!(
                    exploit_count <= 1,
                    "Command should not have duplicate exploit flags: {:?}",
                    cmd.misc_afl_flags
                );
            }
        }

        fn verify_distribution(&self) {
            assert!(
                self.explore_count > 30 && self.explore_count < 50,
                "Explore count should be around 40%, got {}%",
                (self.explore_count as f64 / self.cmds.len() as f64) * 100.0
            );
            assert!(
                self.exploit_count > 15 && self.exploit_count < 25,
                "Exploit count should be around 20%, got {}%",
                (self.exploit_count as f64 / self.cmds.len() as f64) * 100.0
            );
        }

        fn verify_exclusivity(&self) {
            assert_eq!(
                self.both_flags_count, 0,
                "Commands should not have both explore and exploit flags"
            );
        }

        fn verify_some_overlap(&self) {
            assert!(
                self.both_flags_count > 0,
                "Some commands should have both flags, got {} commands with both",
                self.both_flags_count
            );
        }
    }

    #[test]
    fn test_constrained_args_exclusive() {
        let mut test = TestCase::new();
        let args = [("-P explore", 0.4), ("-P exploit", 0.2)];
        let mut rng = StdRng::seed_from_u64(12345);

        apply_constrained_args_excl(&mut test.cmds, &args, &mut rng);

        test.analyze();
        test.verify_no_duplicates();
        test.verify_distribution();
        test.verify_exclusivity();
    }

    #[test]
    fn test_constrained_args_independent() {
        let mut test = TestCase::new();
        let args = [("-P explore", 0.4), ("-P exploit", 0.2)];
        let mut rng = StdRng::seed_from_u64(12345);

        apply_constrained_args(&mut test.cmds, &args, &mut rng);

        test.analyze();
        test.verify_no_duplicates();
        test.verify_distribution();
        test.verify_some_overlap();
    }
}
