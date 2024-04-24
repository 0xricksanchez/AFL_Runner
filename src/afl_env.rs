// -----------------------------------------
// AFLPlusPlus flags
// Based on: https://aflplus.plus/docs/env_variables/
// -----------------------------------------
#[derive(Debug, Clone)]
pub struct AFLEnv {
    /// `AFL_AUTORESUME` will resume a fuzz run (same as providing -i -) for an existing out folder, even if a different -i was provided.
    /// Without this setting, afl-fuzz will refuse execution for a long-fuzzed out dir
    pub autoresume: bool,
    /// `AFL_FINAL_SYNC` will cause the fuzzer to perform a final import of test cases when terminating.
    /// This is beneficial for -M main fuzzers to ensure it has all unique test cases and hence you only need to afl-cmin this single queue.
    pub final_sync: bool,
    /// Setting `AFL_DISABLE_TRIM` tells afl-fuzz not to trim test cases.
    pub disable_trim: bool,

    /// Setting `AFL_EXPAND_HAVOC_NOW` will start in the extended havoc mode that includes costly mutations.
    /// afl-fuzz automatically enables this mode when deemed useful otherwise.
    pub keep_timeouts: bool,

    ///  Setting `AFL_KEEP_TIMEOUTS` will keep longer running inputs if they reach new coverage
    pub expand_havoc_now: bool,

    /// `AFL_IGNORE_SEED_PROBLEMS` will skip over crashes and timeouts in the seeds instead of exiting.
    pub ignore_seed_problems: bool,

    /// When setting `AFL_IMPORT_FIRST` tests cases from other fuzzers in the campaign are loaded first.
    /// Note: This can slow down the start of the first fuzz
    /// by quite a lot of you have many fuzzers and/or many seeds.
    pub import_first: bool,

    /// `AFL_TESTCACHE_SIZE` sets caching of test cases in MB (default: 50).
    /// If enough RAM is available it is recommended to target values between 50-500MB.
    pub testcache_size: u32,
}

impl Default for AFLEnv {
    fn default() -> Self {
        Self {
            autoresume: true,
            final_sync: false,
            disable_trim: false,
            keep_timeouts: false,
            expand_havoc_now: false,
            ignore_seed_problems: false,
            import_first: false,
            testcache_size: 50,
        }
    }
}

impl AFLEnv {
    pub fn new() -> Self {
        Self::default()
    }

    // Generates a AFLPlusPlus environment variable string for the current settings
    pub fn generate_afl_env_cmd(&self) -> Vec<String> {
        let mut command = Vec::new();

        command.push(format!("AFL_AUTORESUME={} ", u8::from(self.autoresume)));
        command.push(format!("AFL_FINAL_SYNC={} ", u8::from(self.final_sync)));
        command.push(format!("AFL_DISABLE_TRIM={} ", u8::from(self.disable_trim)));
        command.push(format!(
            "AFL_KEEP_TIMEOUTS={} ",
            u8::from(self.keep_timeouts)
        ));
        command.push(format!(
            "AFL_EXPAND_HAVOC_NOW={} ",
            u8::from(self.expand_havoc_now)
        ));
        command.push(format!(
            "AFL_IGNORE_SEED_PROBLEMS={} ",
            u8::from(self.ignore_seed_problems)
        ));
        command.push(format!("AFL_IMPORT_FIRST={} ", u8::from(self.import_first)));
        command.push(format!("AFL_TESTCACHE_SIZE={} ", self.testcache_size));

        command
    }
}
