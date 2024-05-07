use std::{
    process::{Command, Stdio},
    time::Instant,
};

use crate::{
    session::{CampaignData, CrashInfoDetails},
    utils::count_alive_fuzzers,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Data fetcher that collects session data based on the `AFLPlusPlus` `fuzzer_stats` file
#[derive(Debug, Clone)]
pub struct DataFetcher {
    /// Output directory of the `AFLPlusPlus` fuzzing run
    pub output_dir: PathBuf,
    /// Campaign data collected from the output directory
    pub campaign_data: CampaignData,
    pub update_once: bool,
    pub update_never: bool,
}

impl DataFetcher {
    /// Create a new `DataFetcher` instance
    pub fn new(
        output_dir: &Path,
        pid_file: Option<&Path>,
        campaign_data: &mut CampaignData,
    ) -> Self {
        let (fuzzer_pids, fuzzer_pids_dead) = pid_file.map_or_else(
            || {
                let mut pids_alive = Vec::new();
                let mut pids_dead = Vec::new();
                fs::read_dir(output_dir)
                    .unwrap()
                    .flatten()
                    .for_each(|entry| {
                        let path = entry.path();
                        if path.is_dir() {
                            let fuzzer_stats_path = path.join("fuzzer_stats");
                            if fuzzer_stats_path.exists() {
                                if let Ok(content) = fs::read_to_string(fuzzer_stats_path) {
                                    if let Some(pid) = Self::fetch_pid_from_fuzzer_stats(&content) {
                                        pids_alive.push(pid);
                                    } else {
                                        pids_dead.push(path);
                                    }
                                }
                            }
                        }
                    });
                (pids_alive, pids_dead)
            },
            |pid_file| {
                let pids_alive = fs::read_to_string(pid_file)
                    .unwrap_or_default()
                    .split(':')
                    .filter_map(|pid| pid.trim().parse::<u32>().ok())
                    .filter(|&pid| pid != 0)
                    .collect::<Vec<u32>>();
                (pids_alive, Vec::new())
            },
        );
        if pid_file.is_none() {
            campaign_data.append_log("Attempted to fetch PIDs from fuzzer_stats files");
        } else {
            campaign_data.append_log("PIDs fetched from the PID file");
        }
        let fuzzers_alive = count_alive_fuzzers(&fuzzer_pids);
        campaign_data.append_log("Fuzzers alive count fetched");
        let fuzzers_started = fuzzers_alive.len() + fuzzer_pids_dead.len();

        campaign_data.fuzzers_alive = fuzzers_alive;
        campaign_data.fuzzers_started = fuzzers_started;
        campaign_data.fuzzer_pids = fuzzer_pids;

        Self {
            output_dir: output_dir.to_path_buf(),
            campaign_data: campaign_data.clone(),
            update_once: true,
            update_never: false,
        }
    }

    fn fetch_pid_from_fuzzer_stats(content: &str) -> Option<u32> {
        let pgrep_available = Command::new("which")
            .arg("pgrep")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok();
        if pgrep_available {
            content
                .lines()
                .find(|line| line.starts_with("command_line"))
                .and_then(|command_line| {
                    let value = command_line.split(':').last().unwrap_or("").trim();
                    let output = Command::new("pgrep")
                        .arg("-f")
                        .arg(value)
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped())
                        .output()
                        .expect("Failed to execute pgrep command");
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let pids: Vec<&str> = stdout.split_whitespace().collect();
                    if pids.is_empty() {
                        None
                    } else {
                        pids[0].parse::<u32>().ok()
                    }
                })
        } else {
            None
        }
    }

    /// Collects session data from the specified output directory and returns the `CampaignData`.
    /// Only 'alive' fuzzers are considered for data collection.
    pub fn collect_session_data(&mut self) -> &CampaignData {
        self.campaign_data.fuzzers_alive = count_alive_fuzzers(&self.campaign_data.fuzzer_pids);
        if self.campaign_data.fuzzers_alive.is_empty() {
            return &self.campaign_data;
        }
        self.campaign_data.clear();

        fs::read_dir(&self.output_dir)
            .unwrap()
            .flatten()
            .for_each(|entry| {
                let path = entry.path();
                if path.is_dir() {
                    let fuzzer_stats_path = path.join("fuzzer_stats");
                    if fuzzer_stats_path.exists() {
                        if let Ok(content) = fs::read_to_string(&fuzzer_stats_path) {
                            let pid = Self::fetch_pid_from_fuzzer_stats(&content);
                            if let Some(pid) = pid {
                                if self.campaign_data.fuzzers_alive.contains(&(pid as usize)) {
                                    self.process_fuzzer_stats(&content);
                                }
                            } else {
                                self.campaign_data.append_log(&format!(
                                    "Failed to fetch PID from fuzzer_stats: {}",
                                    fuzzer_stats_path.clone().display()
                                ));
                            }
                        }
                    }
                }
            });

        self.update_once = true;
        self.calculate_averages();

        let (last_crashes, last_hangs) = self.collect_session_crashes_hangs(10);
        self.campaign_data.last_crashes = last_crashes;
        self.campaign_data.last_hangs = last_hangs;

        //self.campaign_data.append_log("Session data collected");
        &self.campaign_data
    }

    fn process_fuzzer_stats(&mut self, content: &str) {
        let mut is_alive = false;

        for line in content.lines() {
            let parts: Vec<&str> = line.split(':').map(str::trim).collect();

            if parts.len() == 2 {
                let key = parts[0];
                let value = parts[1];

                if key == "fuzzer_pid" {
                    let pid = value.parse::<usize>().unwrap_or(0);
                    if self.campaign_data.fuzzers_alive.contains(&pid) {
                        is_alive = true;
                    }
                }
            }
        }

        if !is_alive {
            return;
        }

        if self.update_once {
            self.update_run_time();
        }

        for line in content.lines() {
            let parts: Vec<&str> = line.split(':').map(str::trim).collect();

            if parts.len() == 2 {
                let key = parts[0];
                let value = parts[1];

                match key {
                    "run_time" => {
                        if self.update_once {
                            self.process_run_time(value)
                        }
                    }
                    "time_wo_finds" => self.process_time_wo_finds(value),
                    "execs_per_sec" => self.process_execs_per_sec(value),
                    "execs_done" => self.process_execs_done(value),
                    "pending_favs" => self.process_pending_favs(value),
                    "pending_total" => self.process_pending_total(value),
                    "stability" => self.process_stability(value),
                    "corpus_count" => self.process_corpus_count(value),
                    "bitmap_cvg" => self.process_bitmap_cvg(value),
                    "max_depth" => self.process_max_depth(value),
                    "saved_crashes" => self.process_saved_crashes(value),
                    "saved_hangs" => self.process_saved_hangs(value),
                    "afl_banner" => {
                        if !self.update_never {
                            self.campaign_data.misc.afl_banner = value.to_string()
                        }
                    }
                    "afl_version" => {
                        if !self.update_never {
                            self.campaign_data.misc.afl_version = value.to_string()
                        }
                    }
                    "cycles_done" => self.process_cycles_done(value),
                    "cycles_wo_finds" => self.process_cycles_wo_finds(value),
                    _ => {}
                }
            }
        }
        self.update_once = false;
        self.update_never = true;
    }

    fn process_time_wo_finds(&mut self, value: &str) {
        let twof = value.parse::<usize>().unwrap_or(0);
        self.campaign_data.time_without_finds.max =
            self.campaign_data.time_without_finds.max.max(twof);

        if self.campaign_data.time_without_finds.min == 0 {
            self.campaign_data.time_without_finds.min = twof;
        } else {
            self.campaign_data.time_without_finds.min =
                self.campaign_data.time_without_finds.min.min(twof);
        }
    }

    fn update_run_time(&mut self) {
        if let Some(start_time) = self.campaign_data.start_time {
            self.campaign_data.total_run_time = start_time.elapsed();
        }
    }

    fn process_run_time(&mut self, value: &str) {
        let run_time = value.parse::<u64>().unwrap_or(0);

        if run_time > 0 {
            // If run_time is greater than 0, set start_time and total_run_time based on the run_time value
            if self.campaign_data.start_time.is_none() {
                // BUG: We add 75 seconds as we don't know when the `fuzzer_stats` file was last
                // written, it's written roughly every minute
                // https://github.com/AFLplusplus/AFLplusplus/blob/ad0d0c77fb313e6edfee111fecf2bcd16d8f915e/src/afl-fuzz-stats.c#L745
                let duration = Duration::from_secs(run_time + 75);
                let start_time = Instant::now().checked_sub(duration).unwrap();
                self.campaign_data.start_time = Some(start_time);
                self.campaign_data.total_run_time = duration;
            }
        } else {
            // If run_time is 0, start the internal counter if not already started
            if self.campaign_data.start_time.is_none() {
                // BUG: This will still cause issues if we start a fuzzing run detached and attach
                // separately if `run_time` has not yet been written to `fuzzer_stats`
                self.campaign_data.start_time = Some(Instant::now());
                self.campaign_data.total_run_time = Duration::from_secs(0);
            }
        }
    }

    fn process_execs_per_sec(&mut self, value: &str) {
        let exec_ps = value.parse::<f64>().unwrap_or(0.0);

        self.campaign_data.executions.ps_max = self.campaign_data.executions.ps_max.max(exec_ps);

        if self.campaign_data.executions.ps_min == 0.0 {
            self.campaign_data.executions.ps_min = exec_ps;
        } else {
            self.campaign_data.executions.ps_min =
                self.campaign_data.executions.ps_min.min(exec_ps);
        }

        self.campaign_data.executions.ps_cum += exec_ps;
    }

    fn process_execs_done(&mut self, value: &str) {
        let execs_done = value.parse::<usize>().unwrap_or(0);
        self.campaign_data.executions.max = self.campaign_data.executions.max.max(execs_done);
        if self.campaign_data.executions.min == 0 {
            self.campaign_data.executions.min = execs_done;
        } else {
            self.campaign_data.executions.min = self.campaign_data.executions.min.min(execs_done);
        }
        self.campaign_data.executions.cum += execs_done;
    }

    fn process_pending_favs(&mut self, value: &str) {
        let pending_favs = value.parse::<usize>().unwrap_or(0);
        self.campaign_data.pending.favorites_max =
            self.campaign_data.pending.favorites_max.max(pending_favs);
        if self.campaign_data.pending.favorites_min == 0 {
            self.campaign_data.pending.favorites_min = pending_favs;
        } else {
            self.campaign_data.pending.favorites_min =
                self.campaign_data.pending.favorites_min.min(pending_favs);
        }
        self.campaign_data.pending.favorites_cum += pending_favs;
    }

    fn process_pending_total(&mut self, value: &str) {
        let pending_total = value.parse::<usize>().unwrap_or(0);
        self.campaign_data.pending.total_max =
            self.campaign_data.pending.total_max.max(pending_total);
        if self.campaign_data.pending.total_min == 0 {
            self.campaign_data.pending.total_min = pending_total;
        } else {
            self.campaign_data.pending.total_min =
                self.campaign_data.pending.total_min.min(pending_total);
        }
        self.campaign_data.pending.total_cum += pending_total;
    }

    fn process_stability(&mut self, value: &str) {
        let stability = value.trim_end_matches('%').parse::<f64>().unwrap_or(0.0);
        self.campaign_data.stability.max = self.campaign_data.stability.max.max(stability);
        if self.campaign_data.stability.min == 0.0 {
            self.campaign_data.stability.min = stability;
        } else {
            self.campaign_data.stability.min = self.campaign_data.stability.min.min(stability);
        }
    }

    fn process_corpus_count(&mut self, value: &str) {
        let corpus_count = value.parse::<usize>().unwrap_or(0);
        self.campaign_data.corpus.max = self.campaign_data.corpus.max.max(corpus_count);
        if self.campaign_data.corpus.min == 0 {
            self.campaign_data.corpus.min = corpus_count;
        } else {
            self.campaign_data.corpus.min = self.campaign_data.corpus.min.min(corpus_count);
        }
        self.campaign_data.corpus.cum += corpus_count;
    }

    fn process_max_depth(&mut self, value: &str) {
        let levels = value.parse::<usize>().unwrap_or(0);
        self.campaign_data.levels.max = self.campaign_data.levels.max.max(levels);
        if self.campaign_data.levels.min == 0 {
            self.campaign_data.levels.min = levels;
        } else {
            self.campaign_data.levels.min = self.campaign_data.levels.min.min(levels);
        }
    }

    fn process_bitmap_cvg(&mut self, value: &str) {
        let cvg = value.trim_end_matches('%').parse::<f64>().unwrap_or(0.0);
        if self.campaign_data.coverage.min == 0.0 {
            self.campaign_data.coverage.min = cvg;
        } else {
            self.campaign_data.coverage.min = self.campaign_data.coverage.min.min(cvg);
        }
        self.campaign_data.coverage.max = self.campaign_data.coverage.max.max(cvg);
    }

    fn process_saved_crashes(&mut self, value: &str) {
        let saved_crashes = value.parse::<usize>().unwrap_or(0);
        self.campaign_data.crashes.max = self.campaign_data.crashes.max.max(saved_crashes);
        if self.campaign_data.crashes.min == 0 {
            self.campaign_data.crashes.min = saved_crashes;
        } else {
            self.campaign_data.crashes.min = self.campaign_data.crashes.min.min(saved_crashes);
        }
        self.campaign_data.crashes.cum += saved_crashes;
    }

    fn process_saved_hangs(&mut self, value: &str) {
        let saved_hangs = value.parse::<usize>().unwrap_or(0);
        self.campaign_data.hangs.max = self.campaign_data.hangs.max.max(saved_hangs);
        if self.campaign_data.hangs.min == 0 {
            self.campaign_data.hangs.min = saved_hangs;
        } else {
            self.campaign_data.hangs.min = self.campaign_data.hangs.min.min(saved_hangs);
        }
        self.campaign_data.hangs.cum += saved_hangs;
    }

    fn process_cycles_done(&mut self, value: &str) {
        let cycles_done = value.parse::<usize>().unwrap_or(0);
        self.campaign_data.cycles.done_max = self.campaign_data.cycles.done_max.max(cycles_done);
        self.campaign_data.cycles.done_min =
            self.campaign_data.cycles.done_min.min(cycles_done).max(0);
    }

    fn process_cycles_wo_finds(&mut self, value: &str) {
        let cycles_wo_finds = value.parse::<usize>().unwrap_or(0);
        self.campaign_data.cycles.wo_finds_max =
            self.campaign_data.cycles.wo_finds_max.max(cycles_wo_finds);
        self.campaign_data.cycles.wo_finds_min = self
            .campaign_data
            .cycles
            .wo_finds_min
            .min(cycles_wo_finds)
            .max(0);
    }

    fn calculate_averages(&mut self) {
        let is_fuzzers_alive = !self.campaign_data.fuzzers_alive.is_empty();

        // FIXME: Change once https://github.com/rust-lang/rust/issues/15701 is resolved
        #[allow(clippy::cast_possible_truncation)]
        #[allow(clippy::cast_sign_loss)]
        #[allow(clippy::cast_precision_loss)]
        let fuzzers_alive_f64 = self.campaign_data.fuzzers_alive.len() as f64;
        self.campaign_data.executions.ps_avg = if is_fuzzers_alive {
            self.campaign_data.executions.ps_cum / fuzzers_alive_f64
        } else {
            0.0
        };

        let cumulative_avg = |cum: usize| {
            if is_fuzzers_alive {
                cum / self.campaign_data.fuzzers_alive.len()
            } else {
                0
            }
        };

        self.campaign_data.executions.avg = cumulative_avg(self.campaign_data.executions.cum);
        self.campaign_data.pending.favorites_avg =
            cumulative_avg(self.campaign_data.pending.favorites_cum);
        self.campaign_data.pending.total_avg = cumulative_avg(self.campaign_data.pending.total_cum);
        self.campaign_data.corpus.avg = cumulative_avg(self.campaign_data.corpus.cum);
        self.campaign_data.crashes.avg = cumulative_avg(self.campaign_data.crashes.cum);
        self.campaign_data.hangs.avg = cumulative_avg(self.campaign_data.hangs.cum);

        self.campaign_data.coverage.avg =
            (self.campaign_data.coverage.min + self.campaign_data.coverage.max) / 2.0;
        self.campaign_data.stability.avg =
            (self.campaign_data.stability.min + self.campaign_data.stability.max) / 2.0;
        self.campaign_data.cycles.done_avg =
            (self.campaign_data.cycles.done_min + self.campaign_data.cycles.done_max) / 2;
        self.campaign_data.cycles.wo_finds_avg =
            (self.campaign_data.cycles.wo_finds_min + self.campaign_data.cycles.wo_finds_max) / 2;
        self.campaign_data.levels.avg =
            (self.campaign_data.levels.min + self.campaign_data.levels.max) / 2;

        self.campaign_data.time_without_finds.avg = (self.campaign_data.time_without_finds.min
            + self.campaign_data.time_without_finds.max)
            / 2;
    }

    /// Collects information about the latest crashes and hangs from the output directory
    fn collect_session_crashes_hangs(
        &self,
        num_latest: usize,
    ) -> (Vec<CrashInfoDetails>, Vec<CrashInfoDetails>) {
        let out_dir_str = self
            .output_dir
            .clone()
            .into_os_string()
            .into_string()
            .unwrap();
        let mut crashes = Vec::new();
        let mut hangs = Vec::new();

        for entry in fs::read_dir(out_dir_str).unwrap() {
            let entry = entry.unwrap();
            let subdir = entry.path();

            if subdir.is_dir() {
                let fuzzer_name = subdir.file_name().unwrap().to_str().unwrap().to_string();

                let crashes_dir = subdir.join("crashes");
                if crashes_dir.is_dir() {
                    Self::process_files(&crashes_dir, &fuzzer_name, &mut crashes);
                }

                let hangs_dir = subdir.join("hangs");
                if hangs_dir.is_dir() {
                    Self::process_files(&hangs_dir, &fuzzer_name, &mut hangs);
                }
            }
        }

        crashes.sort_by(|a, b| b.time.cmp(&a.time));
        hangs.sort_by(|a, b| b.time.cmp(&a.time));

        (
            crashes.into_iter().take(num_latest).collect(),
            hangs.into_iter().take(num_latest).collect(),
        )
    }

    /// Processes files in a directory and extracts crash/hang information
    fn process_files(dir: &PathBuf, fuzzer_name: &str, file_infos: &mut Vec<CrashInfoDetails>) {
        fs::read_dir(dir).unwrap().flatten().for_each(|file_entry| {
            let file = file_entry.path();
            if file.is_file() {
                let filename = file.file_name().unwrap().to_str().unwrap();
                if let Some(mut file_info) = Self::parse_filename(filename) {
                    file_info.fuzzer_name = fuzzer_name.to_string();
                    file_info.file_path = file;
                    file_infos.push(file_info);
                }
            }
        });
    }

    /// Parses a filename and extracts crash/hang information
    fn parse_filename(filename: &str) -> Option<CrashInfoDetails> {
        let parts: Vec<&str> = filename.split(',').collect();
        if parts.len() == 6 || parts.len() == 7 {
            let id = parts[0].split(':').nth(1)?.to_string();
            let sig = if parts.len() == 7 {
                Some(parts[1].split(':').nth(1)?.to_string())
            } else {
                None
            };
            let src_index = if sig.is_some() { 2 } else { 1 };
            let src = parts[src_index].split(':').nth(1)?.to_string();
            let time = parts[src_index + 1].split(':').nth(1)?.parse().ok()?;
            let execs = parts[src_index + 2].split(':').nth(1)?.parse().ok()?;
            let op = parts[src_index + 3].split(':').nth(1)?.to_string();
            let rep = parts[src_index + 4].split(':').nth(1)?.parse().ok()?;
            Some(CrashInfoDetails {
                fuzzer_name: String::new(),
                file_path: PathBuf::new(),
                id,
                sig,
                src,
                time,
                execs,
                op,
                rep,
            })
        } else {
            None
        }
    }
}
