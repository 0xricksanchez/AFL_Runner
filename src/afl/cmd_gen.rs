use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use crate::afl::env::AFLEnv;
use crate::afl::harness::Harness;
use crate::afl::mode::Mode;
use crate::afl::strategies::{AFLStrategy, CmpcovConfig, CmplogConfig};
use crate::afl::{base_cfg::Bcfg, cmd::AFLCmd};
use crate::utils::seed::Xorshift64;
use crate::utils::system::find_binary_in_path;
use anyhow::{Context, Result};
use rand::rngs::StdRng;
use rand::SeedableRng;

const RUNNER_THRESH: u32 = 32;

/// Generates AFL commands based on the provided configuration
pub struct AFLCmdGenerator {
    /// The harness configuration
    pub harness: Harness,
    /// AFL++ base configuration
    pub base_cfg: Bcfg,
    /// Number of AFL runners
    pub runners: u32,
    /// The mode that determines the amount of parameters applied to the generated commands
    pub mode: Mode,
    /// Seed for AFL++
    pub seed: Option<u64>,
}

impl AFLCmdGenerator {
    /// Creates a new `AFLCmdGenerator` instance
    pub fn new(harness: Harness, runners: u32, meta: &Bcfg, mode: Mode, seed: Option<u64>) -> Self {
        if runners > RUNNER_THRESH {
            println!("[!] Warning: Performance degradation may occur with more than 32 runners. Observe campaign results carefully.");
        }

        Self {
            harness,
            base_cfg: meta.clone(),
            runners,
            mode,
            seed,
        }
    }

    /// Retrieves AFL environment variables
    fn get_afl_env_vars() -> Vec<String> {
        let gl_afl_env = std::env::vars()
            .filter(|(k, _)| k.starts_with("AFL_"))
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<String>>();
        if !gl_afl_env.is_empty() {
            println!("[!] Warning: Exported AFL environment variables found... Check generated commands!");
        }
        gl_afl_env
    }

    /// Generates AFL commands based on the configuration
    ///
    /// # Errors
    /// * If the set of intial commands cannot be constructed
    /// * If dictionary path cannot be resolved
    pub fn run(&self) -> Result<Vec<AFLCmd>> {
        let seed = Xorshift64::new(self.seed.unwrap_or(0)).rand();
        let mut rng = StdRng::seed_from_u64(seed);

        let afl_envs = AFLEnv::new(
            self.mode,
            self.runners,
            self.base_cfg.ramdisk.as_ref(),
            &mut rng,
        );

        let mut cmds = self.create_initial_cmds(&afl_envs)?;

        let afl_env_vars: Vec<String> = Self::get_afl_env_vars();
        let is_using_custom_mutator = afl_env_vars
            .iter()
            .any(|e| e.starts_with("AFL_CUSTOM_MUTATOR_LIBRARY"));

        let mut afl_strategy_builder = AFLStrategy::builder(self.mode);

        // Enable CMPLOG if requested
        if let Some(ref cmplog_bin) = self.harness.cmplog_bin {
            afl_strategy_builder.with_cmplog(CmplogConfig::new(cmplog_bin.clone()));
        }

        // Enable CMPCOV if requested
        if let Some(ref cmpcov_bin) = self.harness.cmpcov_bin {
            afl_strategy_builder.with_cmpcov(CmpcovConfig::new(cmpcov_bin.clone()));
        }

        // Properly initialize the set of cmds
        let afl_strategy =
            afl_strategy_builder
                .build()
                .apply(&mut cmds, &mut rng, is_using_custom_mutator);

        // Apply -s
        if self.seed.is_some() {
            Self::apply_afl_seed(&mut cmds, seed);
        }

        // Apply -i and -o
        self.apply_directory(&mut cmds);
        // Apply -x
        self.apply_dictionary(&mut cmds)?;
        // Apply sanitizer binary to first command if present
        self.apply_sanitizer_or_target_binary(&mut cmds);

        // Apply harness arguments
        self.apply_target_args(&mut cmds);

        // Apply -S/-M
        // NOTE: Needs to called last as it relies on cmpcov/cmplog being already set
        self.apply_fuzzer_roles(&mut cmds, afl_strategy.get_cmpcov_indices(), self.mode);

        // Apply global environment variables that are not yet part of the commands
        Self::apply_global_env_vars(&mut cmds, &afl_env_vars);

        Ok(cmds)
    }

    // Inherit global AFL environment variables that are not already set
    fn apply_global_env_vars(cmds: &mut [AFLCmd], afl_env_vars: &[String]) {
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
    fn create_initial_cmds(&self, afl_envs: &[AFLEnv]) -> Result<Vec<AFLCmd>> {
        let afl_binary = find_binary_in_path(self.base_cfg.afl_binary.clone())?;
        let target_binary = &self.harness.target_bin;
        Ok(afl_envs
            .iter()
            .map(|afl_env_cfg| {
                let mut cmd = AFLCmd::new(afl_binary.clone(), target_binary.clone());
                cmd.with_env(afl_env_cfg.generate(), false);
                if let Some(flags) = &self.base_cfg.raw_afl_flags {
                    cmd.with_misc_flags(flags.split_whitespace().map(String::from).collect());
                }

                cmd
            })
            .collect())
    }

    /// Applies input and output directories to AFL commands
    fn apply_directory(&self, cmds: &mut [AFLCmd]) {
        for cmd in cmds {
            cmd.with_input_dir(self.base_cfg.input_dir.clone())
                .with_output_dir(self.base_cfg.output_dir.clone());
        }
    }

    /// Applies fuzzer roles to AFL commands
    fn apply_fuzzer_roles(&self, cmds: &mut [AFLCmd], cmpcov_idxs: &HashSet<usize>, mode: Mode) {
        let get_file_stem = |path: &PathBuf| -> String {
            path.file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.replace('.', "_"))
                .unwrap_or_default()
        };

        let target_fname = get_file_stem(&self.harness.target_bin);

        if let Some(cmd) = cmds.first_mut() {
            match mode {
                Mode::CIFuzzing => {
                    cmd.add_flag(format!("-S s_{target_fname}"));
                }
                _ => {
                    cmd.add_flag(format!("-M m_{target_fname}"));
                }
            }
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
    fn apply_dictionary(&self, cmds: &mut [AFLCmd]) -> Result<()> {
        if let Some(dict) = &self.base_cfg.dictionary {
            let dict_path = fs::canonicalize(dict).context("Failed to resolve dictionary path")?;
            for cmd in cmds {
                cmd.add_flag(format!("-x {}", dict_path.display()));
            }
        }
        Ok(())
    }

    /// Applies sanitizer or target binary to AFL commands
    fn apply_sanitizer_or_target_binary(&self, cmds: &mut [AFLCmd]) {
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
    fn apply_target_args(&self, cmds: &mut [AFLCmd]) {
        if let Some(args) = &self.harness.target_args {
            for cmd in cmds {
                cmd.with_target_args(Some(args.clone()));
            }
        }
    }

    fn apply_afl_seed(cmds: &mut [AFLCmd], seed: u64) {
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

    fn create_afl_base_cfg() -> Bcfg {
        Bcfg::new(PathBuf::from("/input"), PathBuf::from("/output"))
    }

    fn setup_test_generator() -> (TempDir, AFLCmdGenerator) {
        let temp_dir = TempDir::new().unwrap();
        let input_dir = temp_dir.path().join("input");
        let output_dir = temp_dir.path().join("output");
        fs::create_dir(&input_dir).unwrap();
        fs::create_dir(&output_dir).unwrap();

        let afl_base = Bcfg::new(input_dir.clone(), output_dir.clone());

        let generator = AFLCmdGenerator::new(
            create_test_harness(),
            2,
            &afl_base,
            Mode::MultipleCores,
            Some(42),
        );

        (temp_dir, generator)
    }

    #[test]
    fn test_generator_initialization() {
        let (_temp, generator) = setup_test_generator();
        assert_eq!(generator.runners, 2);
        assert_eq!(generator.seed, Some(42));
        assert!(generator.base_cfg.dictionary.is_none());
        assert!(generator.base_cfg.ramdisk.is_none());
    }

    #[test]
    fn test_generator_with_too_many_runners() {
        let harness = create_test_harness();
        let afl_base = create_afl_base_cfg();
        let generator = AFLCmdGenerator::new(
            harness,
            RUNNER_THRESH + 1,
            &afl_base,
            Mode::MultipleCores,
            None,
        );
        assert_eq!(generator.runners, RUNNER_THRESH + 1);
    }

    #[test]
    fn test_generator_with_dictionary() {
        let temp_dir = TempDir::new().unwrap();
        let dict_path = temp_dir.path().join("dict.txt");
        fs::write(&dict_path, "test:test").unwrap();

        let afl_base = create_afl_base_cfg().with_dictionary(Some(dict_path));

        let generator = AFLCmdGenerator::new(
            create_test_harness(),
            2,
            &afl_base,
            Mode::MultipleCores,
            None,
        );

        assert!(generator.base_cfg.dictionary.is_some());

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
            AFLCmd::new(PathBuf::from("afl-fuzz"), PathBuf::from("/bin/test-target")),
            AFLCmd::new(PathBuf::from("afl-fuzz"), PathBuf::from("/bin/test-target")),
        ];

        generator.apply_fuzzer_roles(&mut cmds, &HashSet::new(), Mode::MultipleCores);

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

        let afl_base = create_afl_base_cfg();

        let generator = AFLCmdGenerator::new(harness, 2, &afl_base, Mode::MultipleCores, Some(42));

        let mut cmds = vec![AFLCmd::new(
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

        let afl_base = Bcfg::new(PathBuf::from("/input"), PathBuf::from("/output"));

        let generator = AFLCmdGenerator::new(harness, 4, &afl_base, Mode::MultipleCores, Some(42));

        let result = generator.run();
        assert!(result.is_ok());

        let cmds = result.unwrap();
        assert!(!cmds.is_empty());

        println!("{:?}", cmds);
        assert!(cmds
            .iter()
            .any(|cmd| cmd.to_string().contains("cmpcov-binary")));
    }

    #[test]
    fn test_cmplog_integration() {
        let mut harness = create_test_harness();
        harness.cmplog_bin = Some(PathBuf::from("/bin/cmplog-binary"));

        let afl_base = create_afl_base_cfg();

        let generator = AFLCmdGenerator::new(harness, 4, &afl_base, Mode::MultipleCores, Some(42));

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

        let afl_base = create_afl_base_cfg();

        let generator = AFLCmdGenerator::new(harness, 2, &afl_base, Mode::MultipleCores, Some(42));

        let mut cmds = vec![AFLCmd::new(
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
            &generator.base_cfg.clone(),
            Mode::MultipleCores,
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
        let expected_seed = Xorshift64::new(generator.seed.unwrap()).rand();

        assert!(cmds[0].to_string().contains("-s"));
        assert!(cmds[0].to_string().contains(&format!("{}", expected_seed)));
    }
}
