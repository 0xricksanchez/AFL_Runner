// -----------------------------------------
// AFLPlusPlus flags
// Based on: https://aflplus.plus/docs/env_variables/
// -----------------------------------------
use std::{collections::HashSet, str::FromStr};

use system_utils::get_free_mem_in_mb;

use rand::Rng;

use crate::system_utils;

/// Enum representing the different AFL environment flags
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AFLFlag {
    /// `AFL_AUTORESUME` will resume a fuzz run (same as providing -i -) for an existing out folder, even if a different -i was provided.
    /// Without this setting, afl-fuzz will refuse execution for a long-fuzzed out dir.
    AutoResume,
    /// `AFL_FINAL_SYNC` will cause the fuzzer to perform a final import of test cases when terminating.
    /// This is beneficial for -M main fuzzers to ensure it has all unique test cases and hence you only need to afl-cmin this single queue.
    FinalSync,
    /// Setting `AFL_DISABLE_TRIM` tells afl-fuzz not to trim test cases.
    DisableTrim,
    /// Setting `AFL_KEEP_TIMEOUTS` will keep longer running inputs if they reach new coverage.
    KeepTimeouts,
    /// Setting `AFL_EXPAND_HAVOC_NOW` will start in the extended havoc mode that includes costly mutations.
    /// afl-fuzz automatically enables this mode when deemed useful otherwise.
    ExpandHavocNow,
    /// `AFL_IGNORE_SEED_PROBLEMS` will skip over crashes and timeouts in the seeds instead of exiting.
    IgnoreSeedProblems,
    /// When setting `AFL_IMPORT_FIRST`, test cases from other fuzzers in the campaign are loaded first.
    /// Note: This can slow down the start of the first fuzz by quite a lot if you have many fuzzers and/or many seeds.
    ImportFirst,
}

impl AFLFlag {
    /// Get the environment variable name for this flag
    const fn as_str(&self) -> &'static str {
        match self {
            Self::AutoResume => "AFL_AUTORESUME",
            Self::FinalSync => "AFL_FINAL_SYNC",
            Self::DisableTrim => "AFL_DISABLE_TRIM",
            Self::KeepTimeouts => "AFL_KEEP_TIMEOUTS",
            Self::ExpandHavocNow => "AFL_EXPAND_HAVOC_NOW",
            Self::IgnoreSeedProblems => "AFL_IGNORE_SEED_PROBLEMS",
            Self::ImportFirst => "AFL_IMPORT_FIRST",
        }
    }
}

impl std::fmt::Display for AFLFlag {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AFLFlag {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "AFL_AUTORESUME" => Ok(Self::AutoResume),
            "AFL_FINAL_SYNC" => Ok(Self::FinalSync),
            "AFL_DISABLE_TRIM" => Ok(Self::DisableTrim),
            "AFL_KEEP_TIMEOUTS" => Ok(Self::KeepTimeouts),
            "AFL_EXPAND_HAVOC_NOW" => Ok(Self::ExpandHavocNow),
            "AFL_IGNORE_SEED_PROBLEMS" => Ok(Self::IgnoreSeedProblems),
            "AFL_IMPORT_FIRST" => Ok(Self::ImportFirst),
            _ => Err(format!("Unknown AFL flag: {s}")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AFLEnv {
    flags: HashSet<AFLFlag>,
    pub testcache_size: u32,
}

impl Default for AFLEnv {
    fn default() -> Self {
        Self {
            flags: HashSet::new(),
            testcache_size: 50,
        }
    }
}

impl AFLEnv {
    /// Creates a new vector of `AFLEnv` instances
    #[inline]
    pub fn new(runners: usize, use_afl_defaults: bool, rng: &mut impl Rng) -> Vec<Self> {
        let mut envs = vec![Self::default(); runners];

        // Enable FinalSync for the last configuration
        envs.last_mut().unwrap().enable_flag(AFLFlag::FinalSync);

        if !use_afl_defaults {
            Self::apply_flags(&mut envs, &AFLFlag::DisableTrim, 0.60, rng);
            if runners < 8 {
                // NOTE: With many runners and/or many seeds this can delay the startup significantly
                Self::apply_flags(&mut envs, &AFLFlag::ImportFirst, 1.0, rng);
            }
        }

        // Set testcache size based on available memory
        let free_mb = get_free_mem_in_mb();
        for env in &mut envs {
            match free_mb {
                x if x > (runners * 500 + 4096) as u64 => env.set_testcache_size(500),
                x if x > (runners * 250 + 4096) as u64 => env.set_testcache_size(250),
                _ => {}
            }
        }

        envs
    }

    /// Enables the specified AFL flag
    #[inline]
    pub fn enable_flag(&mut self, flag: AFLFlag) -> &mut Self {
        self.flags.insert(flag);
        self
    }

    /// Sets the testcache size in MB
    #[inline]
    pub fn set_testcache_size(&mut self, size: u32) {
        self.testcache_size = size;
    }

    /// Generates an `AFLPlusPlus` environment variable string for the current settings
    pub fn generate(&self, ramdisk: Option<String>) -> Vec<String> {
        let mut command = Vec::with_capacity(self.flags.len() + 2);

        // If this env has FinalSync flag, add it first
        if self.flags.contains(&AFLFlag::FinalSync) {
            command.push("AFL_FINAL_SYNC=1".to_string());
        }

        // Add ramdisk if present
        if let Some(ramdisk) = ramdisk {
            command.push(format!("AFL_TMPDIR={ramdisk}"));
        }

        // Add remaining flags in a deterministic order
        let mut sorted_flags: Vec<_> = self
            .flags
            .iter()
            .filter(|&flag| *flag != AFLFlag::FinalSync) // Skip FinalSync as it's already added
            .collect();
        sorted_flags.sort_by_key(|flag| flag.as_str());

        command.extend(
            sorted_flags
                .iter()
                .map(|flag| format!("{}=1", flag.as_str())),
        );

        // Add testcache size last
        command.push(format!("AFL_TESTCACHE_SIZE={} ", self.testcache_size));

        command
    }

    /// Applies a flag to a percentage of AFL configurations
    fn apply_flags(configs: &mut [Self], flag: &AFLFlag, percentage: f64, rng: &mut impl Rng) {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    // Helper function to create a deterministic RNG for testing
    fn get_test_rng() -> impl Rng {
        rand::rngs::StdRng::seed_from_u64(42)
    }

    #[test]
    fn test_flag_parsing() {
        assert_eq!(
            "AFL_AUTORESUME".parse::<AFLFlag>().unwrap(),
            AFLFlag::AutoResume
        );
        assert_eq!(
            "AFL_FINAL_SYNC".parse::<AFLFlag>().unwrap(),
            AFLFlag::FinalSync
        );
        assert_eq!(
            "AFL_DISABLE_TRIM".parse::<AFLFlag>().unwrap(),
            AFLFlag::DisableTrim
        );
        assert_eq!(
            "AFL_KEEP_TIMEOUTS".parse::<AFLFlag>().unwrap(),
            AFLFlag::KeepTimeouts
        );
        assert_eq!(
            "AFL_EXPAND_HAVOC_NOW".parse::<AFLFlag>().unwrap(),
            AFLFlag::ExpandHavocNow
        );
        assert_eq!(
            "AFL_IGNORE_SEED_PROBLEMS".parse::<AFLFlag>().unwrap(),
            AFLFlag::IgnoreSeedProblems
        );
        assert_eq!(
            "AFL_IMPORT_FIRST".parse::<AFLFlag>().unwrap(),
            AFLFlag::ImportFirst
        );
        assert!("INVALID_FLAG".parse::<AFLFlag>().is_err());
    }

    #[test]
    fn test_flag_display() {
        assert_eq!(AFLFlag::AutoResume.to_string(), "AFL_AUTORESUME");
        assert_eq!(AFLFlag::FinalSync.to_string(), "AFL_FINAL_SYNC");
        assert_eq!(AFLFlag::DisableTrim.to_string(), "AFL_DISABLE_TRIM");
        assert_eq!(AFLFlag::KeepTimeouts.to_string(), "AFL_KEEP_TIMEOUTS");
        assert_eq!(AFLFlag::ExpandHavocNow.to_string(), "AFL_EXPAND_HAVOC_NOW");
        assert_eq!(
            AFLFlag::IgnoreSeedProblems.to_string(),
            "AFL_IGNORE_SEED_PROBLEMS"
        );
        assert_eq!(AFLFlag::ImportFirst.to_string(), "AFL_IMPORT_FIRST");
    }

    #[test]
    fn test_default_env() {
        let env = AFLEnv::default();
        assert_eq!(env.testcache_size, 50);
        assert!(env.flags.is_empty());
    }

    #[test]
    fn test_enable_flag() {
        let mut env = AFLEnv::default();
        env.enable_flag(AFLFlag::AutoResume);
        assert!(env.flags.contains(&AFLFlag::AutoResume));
        assert!(!env.flags.contains(&AFLFlag::FinalSync));
    }

    #[test]
    fn test_set_testcache_size() {
        let mut env = AFLEnv::default();
        env.set_testcache_size(100);
        assert_eq!(env.testcache_size, 100);
    }

    #[test]
    fn test_env_generation() {
        let mut env = AFLEnv::default();
        env.enable_flag(AFLFlag::AutoResume)
            .enable_flag(AFLFlag::FinalSync)
            .enable_flag(AFLFlag::DisableTrim)
            .set_testcache_size(100);

        let cmd = env.generate(Some("ramdisk".to_string()));

        // Check ordering
        assert_eq!(cmd[0], "AFL_FINAL_SYNC=1");
        assert_eq!(cmd[1], "AFL_TMPDIR=ramdisk");
        assert_eq!(cmd[2], "AFL_AUTORESUME=1");
        assert_eq!(cmd[3], "AFL_DISABLE_TRIM=1");
        assert_eq!(cmd[4], "AFL_TESTCACHE_SIZE=100 ");

        // Check without ramdisk
        let cmd_no_ramdisk = env.generate(None);
        assert_eq!(cmd_no_ramdisk[0], "AFL_FINAL_SYNC=1");
        assert_eq!(cmd_no_ramdisk[1], "AFL_AUTORESUME=1");
        assert_eq!(cmd_no_ramdisk[2], "AFL_DISABLE_TRIM=1");
        assert_eq!(cmd_no_ramdisk[3], "AFL_TESTCACHE_SIZE=100 ");
    }

    #[test]
    fn test_new_multiple_environments() {
        let mut rng = get_test_rng();
        let envs = AFLEnv::new(4, false, &mut rng);

        // Test number of environments
        assert_eq!(envs.len(), 4);

        // Test FinalSync on last environment
        assert!(!envs[0].flags.contains(&AFLFlag::FinalSync));
        assert!(!envs[1].flags.contains(&AFLFlag::FinalSync));
        assert!(!envs[2].flags.contains(&AFLFlag::FinalSync));
        assert!(envs[3].flags.contains(&AFLFlag::FinalSync));

        // Test DisableTrim distribution (with fixed RNG seed)
        let disable_trim_count = envs
            .iter()
            .filter(|env| env.flags.contains(&AFLFlag::DisableTrim))
            .count();
        assert_eq!(disable_trim_count, 2); // 60% of 4 rounded down = 2

        // Test ImportFirst (should be applied to all since runners < 8)
        assert!(envs
            .iter()
            .all(|env| env.flags.contains(&AFLFlag::ImportFirst)));
    }

    #[test]
    fn test_new_with_afl_defaults() {
        let mut rng = get_test_rng();
        let envs = AFLEnv::new(4, true, &mut rng);

        // Only FinalSync should be set when using AFL defaults
        assert!(envs.iter().take(3).all(|env| env.flags.len() == 0));
        assert_eq!(envs.last().unwrap().flags.len(), 1);
        assert!(envs.last().unwrap().flags.contains(&AFLFlag::FinalSync));
    }

    #[test]
    fn test_new_with_many_runners() {
        let mut rng = get_test_rng();
        let envs = AFLEnv::new(10, false, &mut rng);

        // Test that ImportFirst is not applied when runners >= 8
        assert!(!envs
            .iter()
            .any(|env| env.flags.contains(&AFLFlag::ImportFirst)));
    }

    #[test]
    fn test_apply_flags() {
        let mut rng = get_test_rng();
        let mut envs = vec![AFLEnv::default(); 10];

        AFLEnv::apply_flags(&mut envs, &AFLFlag::DisableTrim, 0.6, &mut rng);

        let count = envs
            .iter()
            .filter(|env| env.flags.contains(&AFLFlag::DisableTrim))
            .count();
        assert_eq!(count, 6); // 60% of 10 = 6
    }
}
