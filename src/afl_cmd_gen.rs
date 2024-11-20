use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use crate::afl_cmd::AflCmd;
use crate::afl_strategies::{AflStrategy, CmpcovConfig, CmplogConfig};
use crate::harness::Harness;
use crate::seed::Xorshift64;
use crate::{afl_env::AFLEnv, system_utils};
use anyhow::{Context, Result};
use rand::SeedableRng;
use rand::{rngs::StdRng, Rng};

use system_utils::{create_ramdisk, find_binary_in_path};

const RUNNER_THRESH: u32 = 32;

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
    /// Path to the `RAMDisk`
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
        if runners > RUNNER_THRESH {
            println!("[!] Warning: Performance degradation may occur with more than 32 runners. Observe campaign results carefully.");
        }

        let dict = dictionary.and_then(|d| d.exists().then(|| d.to_string_lossy().into_owned()));

        let rdisk = is_ramdisk
            .then(|| create_ramdisk().map_err(|e| println!("[!] Failed to create RAMDisk: {e}")))
            .transpose()
            .ok()
            .flatten();

        if let Some(ref disk) = rdisk {
            println!("[+] Using RAMDisk: {disk}");
        }

        Self {
            harness,
            input_dir,
            output_dir,
            runners,
            dictionary: dict,
            raw_afl_flags,
            afl_binary,
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
    pub fn run(&self) -> Result<Vec<AflCmd>> {
        let seed = Xorshift64::new(self.seed.unwrap_or(0)).next();
        let mut rng = StdRng::seed_from_u64(seed);

        let afl_envs = AFLEnv::new(self.runners as usize, self.use_afl_defaults, &mut rng);
        let mut cmds = self.create_initial_cmds(&afl_envs)?;
        let mut cmpcov_idxs = HashSet::new();

        let afl_env_vars: Vec<String> = Self::get_afl_env_vars();
        let is_using_custom_mutator = afl_env_vars
            .iter()
            .any(|e| e.starts_with("AFL_CUSTOM_MUTATOR_LIBRARY"));

        if !self.use_afl_defaults {
            Self::apply_strategies(&mut cmds, &mut rng, is_using_custom_mutator);
        }

        if self.seed.is_some() {
            self.apply_afl_seed(&mut cmds, seed);
        }

        self.apply_directory(&mut cmds);
        self.apply_dictionary(&mut cmds)?;
        self.apply_sanitizer_or_target_binary(&mut cmds);

        // Apply CMPLOG if configured
        if let Some(ref cmplog_bin) = self.harness.cmplog_bin {
            AflStrategy::new()
                .with_cmplog(CmplogConfig::new(cmplog_bin.clone()))
                .build()
                .apply_cmplog(&mut cmds, &mut rng);
        }

        self.apply_target_args(&mut cmds);

        if let Some(ref cmpcov_binary) = self.harness.cmpcov_bin {
            let mut strategy = AflStrategy::new()
                .with_cmpcov(CmpcovConfig::new(cmpcov_binary.clone()))
                .build();
            strategy.apply_cmpcov(&mut cmds, &mut rng);
            cmpcov_idxs.clone_from(strategy.get_cmpcov_indices());
        }

        // NOTE: Needs to called last as it relies on cmpcov/cmplog being already set
        self.apply_fuzzer_roles(&mut cmds, &cmpcov_idxs);
        Self::apply_global_env_vars(&mut cmds, &afl_env_vars);

        Ok(cmds)
        //Ok(cmds.into_iter().map(|cmd| cmd.as_string()).collect())
    }

    // Inherit global AFL environment variables that are not already set
    fn apply_global_env_vars(cmds: &mut [AflCmd], afl_env_vars: &[String]) {
        for cmd in cmds {
            let to_apply: Vec<_> = afl_env_vars
                .iter()
                .filter(|env| {
                    let key = env.split('=').next().unwrap();
                    !cmd.env.iter().any(|e| e.split('=').next().unwrap() == key)
                })
                .cloned()
                .collect();
            cmd.with_env(to_apply, true);
        }
    }

    /// Creates initial AFL commands
    fn create_initial_cmds(&self, configs: &[AFLEnv]) -> Result<Vec<AflCmd>> {
        let afl_binary = find_binary_in_path(self.afl_binary.clone())?;
        let target_binary = &self.harness.target_bin;

        Ok(configs
            .iter()
            .map(|config| {
                let mut cmd = AflCmd::new(afl_binary.clone(), target_binary.clone());
                cmd.with_env(config.generate(self.ramdisk.clone()), false);

                if let Some(flags) = &self.raw_afl_flags {
                    cmd.with_misc_flags(flags.split_whitespace().map(String::from).collect());
                }

                cmd
            })
            .collect())
    }

    fn apply_strategies(cmds: &mut [AflCmd], rng: &mut impl Rng, is_using_custom_mutator: bool) {
        let strategy = AflStrategy::new()
            .with_mutation_modes()
            .with_test_case_format()
            .with_power_schedules()
            .with_deterministic_fuzzing()
            .with_seq_queue_cycling()
            .build();

        strategy.apply(cmds, rng, is_using_custom_mutator);
    }

    /// Applies input and output directories to AFL commands
    fn apply_directory(&self, cmds: &mut [AflCmd]) {
        for cmd in cmds {
            cmd.with_input_dir(self.input_dir.clone())
                .with_output_dir(self.output_dir.clone());
        }
    }

    /// Applies fuzzer roles to AFL commands
    fn apply_fuzzer_roles(&self, cmds: &mut [AflCmd], cmpcov_idxs: &HashSet<usize>) {
        let get_file_stem = |path: &PathBuf| -> String {
            path.file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.replace('.', "_"))
                .unwrap_or_default()
        };

        let target_fname = get_file_stem(&self.harness.target_bin);

        if let Some(cmd) = cmds.first_mut() {
            cmd.add_flag(format!("-M m_{target_fname}"));
        }

        for (i, cmd) in cmds.iter_mut().skip(1).enumerate() {
            let suffix = if cmd.misc_afl_flags.iter().any(|f| f.contains("-c")) {
                format!("_{target_fname}_cl")
            } else {
                format!("_{target_fname}")
            };

            let s_flag = if cmpcov_idxs.contains(&(i + 1)) {
                let cmpcov_fname = self
                    .harness
                    .cmpcov_bin
                    .as_ref()
                    .map(get_file_stem)
                    .unwrap_or_default();
                format!("-S s{i}_{cmpcov_fname}")
            } else {
                format!("-S s{i}{suffix}")
            };

            cmd.add_flag(s_flag);
        }
    }

    /// Applies dictionary to AFL commands
    fn apply_dictionary(&self, cmds: &mut [AflCmd]) -> Result<()> {
        if let Some(dict) = &self.dictionary {
            let dict_path = fs::canonicalize(dict).context("Failed to resolve dictionary path")?;
            for cmd in cmds {
                cmd.add_flag(format!("-x {}", dict_path.display()));
            }
        }
        Ok(())
    }

    /// Applies sanitizer or target binary to AFL commands
    fn apply_sanitizer_or_target_binary(&self, cmds: &mut [AflCmd]) {
        if let Some(cmd) = cmds.first_mut() {
            let binary = self
                .harness
                .sanitizer_bin
                .as_ref()
                .unwrap_or(&self.harness.target_bin);
            cmd.target_binary.clone_from(binary);
        }
    }

    /// Applies target arguments to AFL commands
    fn apply_target_args(&self, cmds: &mut [AflCmd]) {
        if let Some(args) = &self.harness.target_args {
            for cmd in cmds {
                cmd.with_target_args(Some(args.clone()));
            }
        }
    }

    fn apply_afl_seed(&self, cmds: &mut [AflCmd], seed: u64) {
        for cmd in cmds {
            cmd.add_flag(format!("-s {seed}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_harness() -> Harness {
        Harness {
            target_bin: PathBuf::from("/bin/test-target"),
            sanitizer_bin: None,
            cmplog_bin: None,
            cmpcov_bin: None,
            target_args: None,
            cov_bin: None,
        }
    }

    fn setup_test_generator() -> (TempDir, AFLCmdGenerator) {
        let temp_dir = TempDir::new().unwrap();
        let input_dir = temp_dir.path().join("input");
        let output_dir = temp_dir.path().join("output");
        fs::create_dir(&input_dir).unwrap();
        fs::create_dir(&output_dir).unwrap();

        let generator = AFLCmdGenerator::new(
            create_test_harness(),
            2,
            input_dir,
            output_dir,
            None,
            None,
            None,
            false,
            false,
            Some(42),
        );

        (temp_dir, generator)
    }

    #[test]
    fn test_generator_initialization() {
        let (_temp, generator) = setup_test_generator();
        assert_eq!(generator.runners, 2);
        assert!(!generator.use_afl_defaults);
        assert_eq!(generator.seed, Some(42));
        assert!(generator.dictionary.is_none());
        assert!(generator.ramdisk.is_none());
    }

    #[test]
    fn test_generator_with_too_many_runners() {
        let generator = AFLCmdGenerator::new(
            create_test_harness(),
            RUNNER_THRESH + 1,
            PathBuf::from("/input"),
            PathBuf::from("/output"),
            None,
            None,
            None,
            false,
            false,
            None,
        );
        assert_eq!(generator.runners, RUNNER_THRESH + 1);
    }

    #[test]
    fn test_generator_with_dictionary() {
        let temp_dir = TempDir::new().unwrap();
        let dict_path = temp_dir.path().join("dict.txt");
        fs::write(&dict_path, "test:test").unwrap();

        let generator = AFLCmdGenerator::new(
            create_test_harness(),
            2,
            PathBuf::from("/input"),
            PathBuf::from("/output"),
            Some(dict_path),
            None,
            None,
            false,
            false,
            None,
        );

        assert!(generator.dictionary.is_some());

        let cmds = generator.run().unwrap();
        assert!(cmds.iter().all(|cmd| cmd.to_string().contains("-x")));
    }

    #[test]
    fn test_generator_with_raw_flags() {
        let (_temp, generator) = setup_test_generator();

        let result = generator.create_initial_cmds(&[AFLEnv::default()]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_fuzzer_roles() {
        let (_temp, generator) = setup_test_generator();
        let mut cmds = vec![
            AflCmd::new(PathBuf::from("afl-fuzz"), PathBuf::from("/bin/test-target")),
            AflCmd::new(PathBuf::from("afl-fuzz"), PathBuf::from("/bin/test-target")),
        ];

        generator.apply_fuzzer_roles(&mut cmds, &HashSet::new());

        // Check master
        assert!(cmds[0].misc_afl_flags.iter().any(|f| f.starts_with("-M")));
        assert!(cmds[0].misc_afl_flags[0].contains("test-target"));

        // Check secondary
        assert!(cmds[1].misc_afl_flags.iter().any(|f| f.starts_with("-S")));
        assert!(cmds[1].misc_afl_flags[0].contains("test-target"));
    }

    #[test]
    fn test_sanitizer_binary() {
        let mut harness = create_test_harness();
        harness.sanitizer_bin = Some(PathBuf::from("/bin/sanitizer"));

        let generator = AFLCmdGenerator::new(
            harness,
            2,
            PathBuf::from("/input"),
            PathBuf::from("/output"),
            None,
            None,
            None,
            false,
            false,
            Some(42),
        );

        let mut cmds = vec![AflCmd::new(
            PathBuf::from("afl-fuzz"),
            PathBuf::from("/bin/test-target"),
        )];

        generator.apply_sanitizer_or_target_binary(&mut cmds);
        assert_eq!(cmds[0].target_binary, PathBuf::from("/bin/sanitizer"));
    }

    #[test]
    fn test_cmpcov_integration() {
        let mut harness = create_test_harness();
        harness.cmpcov_bin = Some(PathBuf::from("/bin/cmpcov-binary"));

        let generator = AFLCmdGenerator::new(
            harness,
            4,
            PathBuf::from("/input"),
            PathBuf::from("/output"),
            None,
            None,
            None,
            false,
            false,
            Some(42),
        );

        let result = generator.run();
        assert!(result.is_ok());

        let cmds = result.unwrap();
        assert!(!cmds.is_empty());
        assert!(cmds
            .iter()
            .any(|cmd| cmd.to_string().contains("cmpcov-binary")));
    }

    #[test]
    fn test_cmplog_integration() {
        let mut harness = create_test_harness();
        harness.cmplog_bin = Some(PathBuf::from("/bin/cmplog-binary"));

        let generator = AFLCmdGenerator::new(
            harness,
            4,
            PathBuf::from("/input"),
            PathBuf::from("/output"),
            None,
            None,
            None,
            false,
            false,
            Some(42),
        );

        let result = generator.run();
        assert!(result.is_ok());

        let cmds = result.unwrap();
        assert!(!cmds.is_empty());
        assert!(cmds.iter().any(|cmd| cmd.to_string().contains("-c")));
    }

    #[test]
    fn test_target_args_handling() {
        let mut harness = create_test_harness();
        harness.target_args = Some("--test argument".to_string());

        let generator = AFLCmdGenerator::new(
            harness,
            2,
            PathBuf::from("/input"),
            PathBuf::from("/output"),
            None,
            None,
            None,
            false,
            false,
            Some(42),
        );

        let mut cmds = vec![AflCmd::new(
            PathBuf::from("afl-fuzz"),
            PathBuf::from("/bin/test-target"),
        )];

        generator.apply_target_args(&mut cmds);
        assert!(cmds[0].target_args.is_some());
        assert_eq!(
            cmds[0].target_args.as_ref().unwrap(),
            "--test argument".to_string().as_str()
        );
    }

    #[test]
    fn test_environment_variables() {
        std::env::set_var("AFL_TEST_VAR", "test_value");
        let env_vars = AFLCmdGenerator::get_afl_env_vars();
        assert!(env_vars.iter().any(|v| v == "AFL_TEST_VAR=test_value"));
        std::env::remove_var("AFL_TEST_VAR");
    }

    #[test]
    fn test_complete_generation() {
        let (_temp, generator) = setup_test_generator();
        let result = generator.run();
        assert!(result.is_ok());

        let cmds = result.unwrap();
        assert_eq!(cmds.len(), 2); // Should match number of runners

        // Verify master and secondary setup
        assert!(cmds[0].to_string().contains("-M"));
        assert!(cmds[1].to_string().contains("-S"));

        // Verify input/output directories
        for cmd in &cmds {
            assert!(cmd.to_string().contains("-i"));
            assert!(cmd.to_string().contains("-o"));
        }
    }

    #[test]
    fn test_afl_defaults() {
        let (_temp_dir, generator) = setup_test_generator();
        let cmds_no_defaults = generator.run().unwrap();

        let generator_with_defaults = AFLCmdGenerator::new(
            create_test_harness(),
            2,
            generator.input_dir.clone(),
            generator.output_dir.clone(),
            None,
            None,
            None,
            false,
            true,
            None,
        );

        let cmds_with_defaults = generator_with_defaults.run().unwrap();

        // Commands with defaults should be simpler
        assert!(cmds_with_defaults[0].to_string().len() < cmds_no_defaults[0].to_string().len());
    }

    #[test]
    fn test_afl_relay_seed() {
        let (_temp_dir, generator) = setup_test_generator();
        let cmds = generator.run().unwrap();
        let expected_seed = Xorshift64::new(generator.seed.unwrap()).next();

        assert!(cmds[0].to_string().contains("-s"));
        assert!(cmds[0].to_string().contains(&format!("{}", expected_seed)));
    }
}
