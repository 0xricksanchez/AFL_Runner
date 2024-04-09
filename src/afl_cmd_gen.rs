use std::collections::HashSet;
use std::ffi::OsStr;
use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::{fs, process::Command};

use crate::afl_env::AFLEnv;
use crate::harness::Harness;
use rand::seq::SliceRandom;
use rand::Rng;
use sysinfo::System;

fn get_free_mem() -> u64 {
    let s = System::new_all();
    s.free_memory()
}

fn apply_flags<F>(configs: &mut [AFLEnv], flag_accessor: F, percentage: f64, rng: &mut impl Rng)
where
    F: Fn(&mut AFLEnv) -> &mut bool,
{
    let count = (configs.len() as f64 * percentage) as usize;
    let mut indices = HashSet::new();
    while indices.len() < count {
        indices.insert(rng.gen_range(0..configs.len()));
    }

    for index in indices {
        *flag_accessor(&mut configs[index]) = true;
    }
}

fn apply_constrained_args(strings: &mut [String], args: &[(&str, f64)], rng: &mut impl Rng) {
    let n = strings.len();
    for &(arg, percentage) in args {
        let count = (n as f64 * percentage) as usize;
        let mut available_indices: Vec<usize> = (0..n)
            .filter(|i| !strings[*i].contains(arg.split_whitespace().next().unwrap()))
            .collect();
        available_indices.shuffle(rng);

        for &index in available_indices.iter().take(count) {
            strings[index].push_str(&format!(" {arg}"));
        }
    }
}

fn apply_args(strings: &mut [String], arg: &str, percentage: f64, rng: &mut impl Rng) {
    let count = (strings.len() as f64 * percentage) as usize;
    let mut indices = HashSet::new();
    while indices.len() < count {
        indices.insert(rng.gen_range(0..strings.len()));
    }

    for index in indices {
        strings[index].push_str(&format!(" {arg}"));
    }
}

pub struct AFLCmdGenerator {
    /// Path to afl-fuzz
    pub afl_binary: PathBuf,
    /// Harness holding the binaries and arguments
    pub harness: Harness,
    /// Corpus directory
    pub input_dir: PathBuf,
    /// Output directory
    pub output_dir: PathBuf,
    /// Amount of runners
    pub runners: u32,
    /// Dictionary
    pub dictionary: Option<String>,
}

impl Default for AFLCmdGenerator {
    fn default() -> Self {
        Self {
            afl_binary: PathBuf::new(),
            harness: Harness::new(String::new(), None, None, None, None),
            input_dir: PathBuf::new(),
            output_dir: PathBuf::new(),
            runners: 1,
            dictionary: None,
        }
    }
}

impl AFLCmdGenerator {
    pub fn new<P: Into<PathBuf> + AsRef<OsStr> + Copy + Display>(
        harness: Harness,
        runners: u32,
        afl_binary: Option<P>,
        input_dir: P,
        output_dir: P,
        dictionary: Option<P>,
    ) -> Self {
        let afl_binary = Self::get_afl_fuzz(afl_binary).expect("Could not find afl-fuzz binary");

        Self::mkdir_helper(&input_dir, false);
        fs::write(format!("{input_dir}/1"), "fuzz").expect("Failed to write to file");

        Self::mkdir_helper(&output_dir, true);

        let dict = dictionary.and_then(|d| {
            let dict_path = d.into();
            if dict_path.exists() && dict_path.is_file() {
                dict_path.to_str().map(String::from)
            } else {
                None
            }
        });

        Self {
            afl_binary,
            harness,
            input_dir: input_dir.into(),
            output_dir: output_dir.into(),
            runners,
            dictionary: dict,
        }
    }

    fn mkdir_helper<P: Into<PathBuf> + AsRef<OsStr> + Copy>(dir: &P, check_empty: bool) {
        let dir: PathBuf = dir.into();
        assert!(!dir.is_file(), "{} is a file", dir.display());
        if check_empty {
            let is_empty = dir.read_dir().map_or(true, |mut i| i.next().is_none());
            assert!(is_empty, "{} exists and is not empty", dir.display());
        }
        if !dir.exists() {
            fs::create_dir(&dir).expect("Failed to create directory");
        }
    }
    fn get_afl_fuzz<P: Into<PathBuf> + AsRef<OsStr>>(afl_fuzz: Option<P>) -> Option<PathBuf> {
        afl_fuzz
            .map(Into::into)
            .or_else(Self::get_afl_fuzz_from_path)
            .or_else(Self::get_afl_fuzz_from_env)
            .and_then(|path| {
                if path.exists() && path.is_file() && path.ends_with("afl-fuzz") {
                    Some(path)
                } else {
                    None
                }
            })
    }

    fn get_afl_fuzz_from_env() -> Option<PathBuf> {
        std::env::var("AFL_PATH").ok().and_then(|path| {
            let afl_path = PathBuf::from(path);
            if afl_path.exists() && afl_path.is_file() && afl_path.ends_with("afl-fuzz") {
                Some(afl_path)
            } else {
                None
            }
        })
    }

    fn get_afl_fuzz_from_path() -> Option<PathBuf> {
        let output = Command::new("which")
            .arg("afl-fuzz")
            .output()
            .expect("Failed to execute 'which'");
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
    }

    pub fn generate_afl_commands(&self) -> Vec<String> {
        let mut rng = rand::thread_rng();
        let configs = self.initialize_configs(&mut rng);
        let mut strings = self.create_initial_strings(&configs);

        Self::apply_mutation_strategies(&mut strings, &mut rng);
        Self::apply_queue_selection(&mut strings, &mut rng);
        Self::apply_power_schedules(&mut strings);
        self.apply_directory(&mut strings);
        self.apply_fuzzer_roles(&mut strings);
        self.apply_dictionary(&mut strings);
        self.apply_sanitizer_or_target_binary(&mut strings);
        self.apply_cmplog(&mut strings, &mut rng);
        self.apply_target_args(&mut strings);
        self.apply_cmpcov(&mut strings, &mut rng);

        strings
    }

    fn initialize_configs(&self, rng: &mut impl Rng) -> Vec<AFLEnv> {
        let mut configs = vec![AFLEnv::new(); self.runners as usize];
        configs.last_mut().unwrap().final_sync = true;

        apply_flags(&mut configs, |c| &mut c.disable_trim, 0.65, rng);
        apply_flags(&mut configs, |c| &mut c.keep_timeouts, 0.5, rng);
        apply_flags(&mut configs, |c| &mut c.expand_havoc_now, 0.4, rng);

        let free_mem = get_free_mem();
        for c in &mut configs {
            if ((self.runners * 500 + 4096) as u64) < free_mem {
                c.testcache_size = 500;
            }
            if ((self.runners * 250 + 4096) as u64) < free_mem {
                c.testcache_size = 250;
            }
        }

        configs
    }

    fn create_initial_strings(&self, configs: &[AFLEnv]) -> Vec<String> {
        configs
            .iter()
            .map(|config| {
                format!(
                    "{} {}",
                    config.generate_afl_env_cmd(),
                    self.afl_binary.display()
                )
            })
            .collect()
    }

    fn apply_mutation_strategies(strings: &mut [String], rng: &mut impl Rng) {
        // Apply different mutation strategies to a percentage of the configs
        let mode_args = [("-P explore", 0.4), ("-P exploit", 0.2)];
        apply_constrained_args(strings, &mode_args, rng);
        let format_args = [("-a binary", 0.3), ("-a text", 0.3)];
        apply_constrained_args(strings, &format_args, rng);
        apply_args(strings, "-L 0", 0.1, rng);
    }

    fn apply_queue_selection(strings: &mut [String], rng: &mut impl Rng) {
        // Apply sequential queue selection to 20% of the configs
        apply_args(strings, "-Z", 0.2, rng);
    }

    fn apply_power_schedules(strings: &mut [String]) {
        // Cycle through the different power schedules for the available runners
        let pscheds = ["fast", "explore", "coe", "lin", "quad", "exploit", "rare"];
        strings.iter_mut().enumerate().for_each(|(i, s)| {
            s.push_str(&format!(" -p {}", pscheds[i % pscheds.len()]));
        });
    }

    fn apply_directory(&self, strings: &mut Vec<String>) {
        for s in strings {
            s.push_str(&format!(
                " -i {} -o {}",
                self.input_dir.display(),
                self.output_dir.display()
            ));
        }
    }

    fn apply_fuzzer_roles(&self, strings: &mut [String]) {
        let target_fname = self
            .harness
            .target_binary
            .file_name()
            .unwrap()
            .to_str()
            .unwrap();
        // Set one main fuzzer
        strings[0].push_str(&format!(" -M main_{target_fname}"));
        // Set the rest to be slaves
        for (i, s) in strings[1..].iter_mut().enumerate() {
            s.push_str(&format!(" -S slave_{i}_{target_fname}"));
        }
    }

    fn apply_dictionary(&self, strings: &mut Vec<String>) {
        // If a dictionary is provided, set it for all configs
        if let Some(dict) = self.dictionary.as_ref() {
            let dict_path = fs::canonicalize(dict).expect("Failed to resolve dictionary path");
            for s in strings {
                s.push_str(&format!(" -x {}", dict_path.display()));
            }
        }
    }

    fn apply_sanitizer_or_target_binary(&self, strings: &mut [String]) {
        // Set the first one to be a sanitizer_binary if available, otherwise the target_binary
        let binary = self
            .harness
            .sanitizer_binary
            .as_ref()
            .unwrap_or(&self.harness.target_binary);
        strings[0].push_str(&format!(" -- {}", binary.display()));
    }

    fn apply_cmplog(&self, strings: &mut [String], rng: &mut impl Rng) {
        if let Some(cmplog_binary) = self.harness.cmplog_binary.as_ref() {
            let num_cmplog_cfgs = (f64::from(self.runners) * 0.3) as usize;
            match num_cmplog_cfgs {
                0 => {
                    // We have a cmplog binary but not enough config slots to use it
                }
                1 => {
                    // We have exactly one runner available for cmplog so we use `-l 2`
                    strings[1].push_str(
                        format!(
                            " -l 2 -c {} -- {}",
                            cmplog_binary.display(),
                            self.harness.target_binary.display()
                        )
                        .as_str(),
                    );
                }
                2 => {
                    // We have exactly two runners available for cmplog so we use `-l 2` and `-l 2AT`
                    strings[1].push_str(
                        format!(
                            " -l 2 -c {} -- {}",
                            cmplog_binary.display(),
                            self.harness.target_binary.display()
                        )
                        .as_str(),
                    );
                    strings[2].push_str(
                        format!(
                            " -l 2AT -c {} -- {}",
                            cmplog_binary.display(),
                            self.harness.target_binary.display()
                        )
                        .as_str(),
                    );
                }
                3 => {
                    // We can now use all three modes
                    strings[1].push_str(
                        format!(
                            " -l 2 -c {} -- {}",
                            cmplog_binary.display(),
                            self.harness.target_binary.display()
                        )
                        .as_str(),
                    );
                    strings[2].push_str(
                        format!(
                            " -l 2AT -c {} -- {}",
                            cmplog_binary.display(),
                            self.harness.target_binary.display()
                        )
                        .as_str(),
                    );
                    strings[3].push_str(
                        format!(
                            " -l 3 -c {} -- {}",
                            cmplog_binary.display(),
                            self.harness.target_binary.display()
                        )
                        .as_str(),
                    );
                }
                _ => {
                    // We have more than 3 runners available for cmplog so we use all three modes with
                    // the following distribution:
                    // - 70% for -l 2
                    // - 10% for -l 3
                    // - 20% for -l 2AT.
                    self.apply_cmplog_instrumentation(strings, num_cmplog_cfgs, cmplog_binary, rng);
                }
            }
            self.apply_normal_instrumentation(strings, num_cmplog_cfgs);
        } else {
            self.apply_normal_instrumentation(strings, 0);
        }
    }

    fn apply_cmplog_instrumentation(
        &self,
        strings: &mut [String],
        num_cmplog_cfgs: usize,
        cmplog_binary: &Path,
        rng: &mut impl Rng,
    ) {
        let cmplog_args = [("-l 2 ", 0.7), ("-l 3", 0.1), ("-l 2AT", 0.2)];
        apply_constrained_args(&mut strings[1..=num_cmplog_cfgs], &cmplog_args, rng);
        for s in &mut strings[1..=num_cmplog_cfgs] {
            s.push_str(
                format!(
                    " -c {} -- {}",
                    cmplog_binary.display(),
                    self.harness.target_binary.display()
                )
                .as_str(),
            );
        }
    }

    fn apply_normal_instrumentation(&self, strings: &mut [String], start_index: usize) {
        for s in &mut strings[start_index + 1..] {
            s.push_str(format!(" -- {}", self.harness.target_binary.display()).as_str());
        }
    }

    fn apply_target_args(&self, strings: &mut [String]) {
        // Appends target arguments to the command string
        if let Some(target_args) = self.harness.target_args.as_ref() {
            for s in strings {
                s.push_str(format!(" {target_args}").as_str());
            }
        }
    }

    fn apply_cmpcov(&self, strings: &mut [String], rng: &mut impl Rng) {
        // Use 1-3 CMPCOV instances if available.
        // We want the following distribution:
        // - 1 instance when >= 3 && < 8 runners
        // - 2 instances when >= 8 && < 16 runners
        // - 3 instances when >= 16 runners
        // Unlike CMPLOG we need to replace the target binary with the cmpcov binary
        // We never want to replace instace[0] as that one houses a SAN binary
        // It is unclear if we want to pair CMPLOG with CMPCOV but let's attempt to avoid it
        if self.harness.cmpcov_binary.as_ref().is_some() {
            let max_cmpcov_instances = if self.runners >= 16 {
                3
            } else if self.runners >= 8 {
                2
            } else if self.runners >= 3 {
                1
            } else {
                0
            };
            // Find instances that don't have CMPLOG (-c) and replace the target binary with CMPLOG)
            // Also skip instance[0] as that one houses a SAN binary
            let mut cmpcov_indices = (1..strings.len())
                .filter(|i| !strings[*i].contains("-c"))
                .collect::<Vec<_>>();
            // Shuffle the indices so we don't always replace the same instances
            // Stylepoints only
            cmpcov_indices.shuffle(rng);
            // Find and replace the target binary string after the -- with the cmpcov binary
            for i in cmpcov_indices.iter().take(max_cmpcov_instances) {
                let target_binary = self.harness.target_binary.display().to_string();
                let cmpcov_binary = self
                    .harness
                    .cmpcov_binary
                    .as_ref()
                    .unwrap()
                    .display()
                    .to_string();
                if let Some(pos) = strings[*i].find(&target_binary) {
                    strings[*i].replace_range(pos..pos + target_binary.len(), &cmpcov_binary);
                }
            }
        }
    }
}
