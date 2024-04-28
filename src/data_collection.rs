use crate::{
    session::{CampaignData, CrashInfoDetails},
    utils::count_alive_fuzzers,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Data fetcher that collects session data based on the `AFLPlusPlus` `fuzzer_stats` file
#[derive(Debug, Clone)]
pub struct DataFetcher {
    /// Output directory of the `AFLPlusPlus` fuzzing run
    pub output_dir: PathBuf,
    pub campaign_data: CampaignData,
}

impl DataFetcher {
    /// Create a new `DataFetcher` instance
    pub fn new(output_dir: &Path, pid_file: Option<&Path>) -> Self {
        let fuzzer_pids = match pid_file {
            Some(pid_file) => {
                let content = fs::read_to_string(pid_file).unwrap_or_default();
                content
                    .split(':')
                    .filter_map(|pid| pid.trim().parse::<u32>().ok())
                    .filter(|&pid| pid != 0)
                    .collect::<Vec<u32>>()
            }
            None => Vec::new(),
        };

        let fuzzers_alive = count_alive_fuzzers(&fuzzer_pids);

        let campaign_data = CampaignData {
            fuzzers_alive,
            fuzzers_started: fuzzer_pids.len(),
            fuzzer_pids,
            ..CampaignData::default()
        };
        Self {
            output_dir: output_dir.to_path_buf(),
            campaign_data,
        }
    }

    /// Collects session data from the specified output directory
    pub fn collect_session_data(&mut self) -> &CampaignData {
        self.campaign_data.fuzzers_alive = count_alive_fuzzers(&self.campaign_data.fuzzer_pids);

        fs::read_dir(&self.output_dir)
            .unwrap()
            .flatten()
            .for_each(|entry| {
                let path = entry.path();
                if path.is_dir() {
                    let fuzzer_stats_path = path.join("fuzzer_stats");
                    if fuzzer_stats_path.exists() {
                        if let Ok(content) = fs::read_to_string(fuzzer_stats_path) {
                            self.process_fuzzer_stats(&content);
                        }
                    }
                }
            });

        self.calculate_averages();

        let (last_crashes, last_hangs) = self.collect_session_crashes_hangs(10);
        self.campaign_data.last_crashes = last_crashes;
        self.campaign_data.last_hangs = last_hangs;

        &self.campaign_data
    }

    fn process_fuzzer_stats(&mut self, content: &str) {
        let lines: Vec<&str> = content.lines().collect();

        for line in lines {
            let parts: Vec<&str> = line.split(':').map(str::trim).collect();

            if parts.len() == 2 {
                let key = parts[0];
                let value = parts[1];

                match key {
                    "start_time" => self.process_start_time(value),
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
                    "last_find" => self.process_last_find(value),
                    "afl_banner" => self.campaign_data.misc.afl_banner = value.to_string(),
                    "afl_version" => self.campaign_data.misc.afl_version = value.to_string(),
                    "cycles_done" => self.process_cycles_done(value),
                    "cycles_wo_finds" => self.process_cycles_wo_finds(value),
                    _ => {}
                }
            }
        }
    }

    fn process_start_time(&mut self, value: &str) {
        let start_time = UNIX_EPOCH + Duration::from_secs(value.parse::<u64>().unwrap_or(0));
        let current_time = SystemTime::now();
        let duration = current_time.duration_since(start_time).unwrap();
        self.campaign_data.total_run_time = duration;
    }

    fn process_execs_per_sec(&mut self, value: &str) {
        let exec_ps = value.parse::<f64>().unwrap_or(0.0);
        if exec_ps > self.campaign_data.executions.ps_max {
            self.campaign_data.executions.ps_max = exec_ps;
        } else if exec_ps < self.campaign_data.executions.ps_min
            || self.campaign_data.executions.ps_min == 0.0
        {
            self.campaign_data.executions.ps_min = exec_ps;
        }
        self.campaign_data.executions.ps_cum += exec_ps;
    }

    fn process_execs_done(&mut self, value: &str) {
        let execs_done = value.parse::<usize>().unwrap_or(0);
        if execs_done > self.campaign_data.executions.max {
            self.campaign_data.executions.max = execs_done;
        } else if execs_done < self.campaign_data.executions.min
            || self.campaign_data.executions.min == 0
        {
            self.campaign_data.executions.min = execs_done;
        }
        self.campaign_data.executions.cum += execs_done;
    }

    fn process_pending_favs(&mut self, value: &str) {
        let pending_favs = value.parse::<usize>().unwrap_or(0);
        if pending_favs > self.campaign_data.pending.favorites_max {
            self.campaign_data.pending.favorites_max = pending_favs;
        } else if pending_favs < self.campaign_data.pending.favorites_min
            || self.campaign_data.pending.favorites_min == 0
        {
            self.campaign_data.pending.favorites_min = pending_favs;
        }
        self.campaign_data.pending.favorites_cum += pending_favs;
    }

    fn process_pending_total(&mut self, value: &str) {
        let pending_total = value.parse::<usize>().unwrap_or(0);
        if pending_total > self.campaign_data.pending.total_max {
            self.campaign_data.pending.total_max = pending_total;
        } else if pending_total < self.campaign_data.pending.total_min
            || self.campaign_data.pending.total_min == 0
        {
            self.campaign_data.pending.total_min = pending_total;
        }
        self.campaign_data.pending.total_cum += pending_total;
    }

    fn process_stability(&mut self, value: &str) {
        let stability = value.trim_end_matches('%').parse::<f64>().unwrap_or(0.0);
        if stability > self.campaign_data.stability.max {
            self.campaign_data.stability.max = stability;
        } else if stability < self.campaign_data.stability.min
            || self.campaign_data.stability.min == 0.0
        {
            self.campaign_data.stability.min = stability;
        }
    }

    fn process_corpus_count(&mut self, value: &str) {
        let corpus_count = value.parse::<usize>().unwrap_or(0);
        if corpus_count > self.campaign_data.corpus.max {
            self.campaign_data.corpus.max = corpus_count;
        } else if corpus_count < self.campaign_data.corpus.min || self.campaign_data.corpus.min == 0
        {
            self.campaign_data.corpus.min = corpus_count;
        }
        self.campaign_data.corpus.cum += corpus_count;
    }

    fn process_bitmap_cvg(&mut self, value: &str) {
        let cvg = value.trim_end_matches('%').parse::<f64>().unwrap_or(0.0);
        if cvg < self.campaign_data.coverage.min || self.campaign_data.coverage.min == 0.0 {
            self.campaign_data.coverage.min = cvg;
        } else if cvg > self.campaign_data.coverage.max {
            self.campaign_data.coverage.max = cvg;
        }
    }

    fn process_max_depth(&mut self, value: &str) {
        let levels = value.parse::<usize>().unwrap_or(0);
        if levels > self.campaign_data.levels.max {
            self.campaign_data.levels.max = levels;
        } else if levels < self.campaign_data.levels.min || self.campaign_data.levels.min == 0 {
            self.campaign_data.levels.min = levels;
        }
    }

    fn process_saved_crashes(&mut self, value: &str) {
        let saved_crashes = value.parse::<usize>().unwrap_or(0);
        if saved_crashes > self.campaign_data.crashes.max {
            self.campaign_data.crashes.max = saved_crashes;
        } else if saved_crashes < self.campaign_data.crashes.min
            || self.campaign_data.crashes.min == 0
        {
            self.campaign_data.crashes.min = saved_crashes;
        }
        self.campaign_data.crashes.cum += saved_crashes;
    }

    fn process_saved_hangs(&mut self, value: &str) {
        let saved_hangs = value.parse::<usize>().unwrap_or(0);
        if saved_hangs > self.campaign_data.hangs.max {
            self.campaign_data.hangs.max = saved_hangs;
        } else if saved_hangs < self.campaign_data.hangs.min || self.campaign_data.hangs.min == 0 {
            self.campaign_data.hangs.min = saved_hangs;
        }
        self.campaign_data.hangs.cum += saved_hangs;
    }

    fn process_last_find(&mut self, value: &str) {
        let last_find = value.parse::<u64>().unwrap_or(0);
        let last_find = UNIX_EPOCH + Duration::from_secs(last_find);
        let current_time = SystemTime::now();
        let duration = current_time.duration_since(last_find).unwrap();
        if duration > self.campaign_data.time_without_finds {
            self.campaign_data.time_without_finds = duration;
        }
    }

    fn process_cycles_done(&mut self, value: &str) {
        let cycles_done = value.parse::<usize>().unwrap_or(0);
        if cycles_done > self.campaign_data.cycles.done_max {
            self.campaign_data.cycles.done_max = cycles_done;
        } else if cycles_done < self.campaign_data.cycles.done_min
            || self.campaign_data.cycles.done_min == 0
        {
            self.campaign_data.cycles.done_min = cycles_done;
        }
    }

    fn process_cycles_wo_finds(&mut self, value: &str) {
        let cycles_wo_finds = value.parse::<usize>().unwrap_or(0);
        if cycles_wo_finds > self.campaign_data.cycles.wo_finds_max {
            self.campaign_data.cycles.wo_finds_max = cycles_wo_finds;
        } else if cycles_wo_finds < self.campaign_data.cycles.wo_finds_min
            || self.campaign_data.cycles.wo_finds_min == 0
        {
            self.campaign_data.cycles.wo_finds_min = cycles_wo_finds;
        }
    }

    fn calculate_averages(&mut self) {
        let is_fuzzers_alive = self.campaign_data.fuzzers_alive > 0;

        self.campaign_data.executions.ps_avg = if is_fuzzers_alive {
            self.campaign_data.executions.ps_cum / self.campaign_data.fuzzers_alive as f64
        } else {
            0.0
        };

        let cumulative_avg = |cum: usize| {
            if is_fuzzers_alive {
                cum / self.campaign_data.fuzzers_alive
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
