use crate::session::{CampaignData, CrashInfoDetails};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Data fetcher that collects session data based on the `AFLPlusPlus` `fuzzer_stats` file
#[derive(Debug, Clone)]
pub struct DataFetcher {
    /// Output directory of the `AFLPlusPlus` fuzzing run
    pub output_dir: PathBuf,
}

impl DataFetcher {
    /// Create a new `DataFetcher` instance
    pub fn new(output_dir: &Path) -> Self {
        Self {
            output_dir: output_dir.to_path_buf(),
        }
    }

    /// Collects session data from the specified output directory
    pub fn collect_session_data(&self) -> CampaignData {
        let mut session_data = CampaignData::new();
        let mut fuzzers_alive = 0;

        fs::read_dir(&self.output_dir)
            .unwrap()
            .flatten()
            .for_each(|entry| {
                let path = entry.path();
                if path.is_dir() {
                    let fuzzer_stats_path = path.join("fuzzer_stats");
                    if fuzzer_stats_path.exists() {
                        if let Ok(content) = fs::read_to_string(fuzzer_stats_path) {
                            Self::process_fuzzer_stats(&content, &mut session_data);
                            fuzzers_alive += 1;
                        }
                    }
                }
            });

        session_data.fuzzers_alive = fuzzers_alive;
        Self::calculate_averages(&mut session_data, fuzzers_alive);

        let (last_crashes, last_hangs) = self.collect_session_crashes_hangs(10);
        session_data.last_crashes = last_crashes;
        session_data.last_hangs = last_hangs;

        session_data
    }

    fn process_fuzzer_stats(content: &str, session_data: &mut CampaignData) {
        let lines: Vec<&str> = content.lines().collect();

        for line in lines {
            let parts: Vec<&str> = line.split(':').map(str::trim).collect();

            if parts.len() == 2 {
                let key = parts[0];
                let value = parts[1];

                match key {
                    "start_time" => Self::process_start_time(value, session_data),
                    "execs_per_sec" => Self::process_execs_per_sec(value, session_data),
                    "execs_done" => Self::process_execs_done(value, session_data),
                    "pending_favs" => Self::process_pending_favs(value, session_data),
                    "pending_total" => Self::process_pending_total(value, session_data),
                    "stability" => Self::process_stability(value, session_data),
                    "corpus_count" => Self::process_corpus_count(value, session_data),
                    "bitmap_cvg" => Self::process_bitmap_cvg(value, session_data),
                    "max_depth" => Self::process_max_depth(value, session_data),
                    "saved_crashes" => Self::process_saved_crashes(value, session_data),
                    "saved_hangs" => Self::process_saved_hangs(value, session_data),
                    "last_find" => Self::process_last_find(value, session_data),
                    "afl_banner" => session_data.misc.afl_banner = value.to_string(),
                    "afl_version" => session_data.misc.afl_version = value.to_string(),
                    "cycles_done" => Self::process_cycles_done(value, session_data),
                    "cycles_wo_finds" => Self::process_cycles_wo_finds(value, session_data),
                    _ => {}
                }
            }
        }
    }

    fn process_start_time(value: &str, session_data: &mut CampaignData) {
        let start_time = UNIX_EPOCH + Duration::from_secs(value.parse::<u64>().unwrap_or(0));
        let current_time = SystemTime::now();
        let duration = current_time.duration_since(start_time).unwrap();
        session_data.total_run_time = duration;
    }

    fn process_execs_per_sec(value: &str, session_data: &mut CampaignData) {
        let exec_ps = value.parse::<f64>().unwrap_or(0.0);
        if exec_ps > session_data.executions.ps_max {
            session_data.executions.ps_max = exec_ps;
        } else if exec_ps < session_data.executions.ps_min || session_data.executions.ps_min == 0.0
        {
            session_data.executions.ps_min = exec_ps;
        }
        session_data.executions.ps_cum += exec_ps;
    }

    fn process_execs_done(value: &str, session_data: &mut CampaignData) {
        let execs_done = value.parse::<usize>().unwrap_or(0);
        if execs_done > session_data.executions.max {
            session_data.executions.max = execs_done;
        } else if execs_done < session_data.executions.min || session_data.executions.min == 0 {
            session_data.executions.min = execs_done;
        }
        session_data.executions.cum += execs_done;
    }

    fn process_pending_favs(value: &str, session_data: &mut CampaignData) {
        let pending_favs = value.parse::<usize>().unwrap_or(0);
        if pending_favs > session_data.pending.favorites_max {
            session_data.pending.favorites_max = pending_favs;
        } else if pending_favs < session_data.pending.favorites_min
            || session_data.pending.favorites_min == 0
        {
            session_data.pending.favorites_min = pending_favs;
        }
        session_data.pending.favorites_cum += pending_favs;
    }

    fn process_pending_total(value: &str, session_data: &mut CampaignData) {
        let pending_total = value.parse::<usize>().unwrap_or(0);
        if pending_total > session_data.pending.total_max {
            session_data.pending.total_max = pending_total;
        } else if pending_total < session_data.pending.total_min
            || session_data.pending.total_min == 0
        {
            session_data.pending.total_min = pending_total;
        }
        session_data.pending.total_cum += pending_total;
    }

    fn process_stability(value: &str, session_data: &mut CampaignData) {
        let stability = value.trim_end_matches('%').parse::<f64>().unwrap_or(0.0);
        if stability > session_data.stability.max {
            session_data.stability.max = stability;
        } else if stability < session_data.stability.min || session_data.stability.min == 0.0 {
            session_data.stability.min = stability;
        }
    }

    fn process_corpus_count(value: &str, session_data: &mut CampaignData) {
        let corpus_count = value.parse::<usize>().unwrap_or(0);
        if corpus_count > session_data.corpus.count_max {
            session_data.corpus.count_max = corpus_count;
        } else if corpus_count < session_data.corpus.count_min || session_data.corpus.count_min == 0
        {
            session_data.corpus.count_min = corpus_count;
        }
        session_data.corpus.count_cum += corpus_count;
    }

    fn process_bitmap_cvg(value: &str, session_data: &mut CampaignData) {
        let cvg = value.trim_end_matches('%').parse::<f64>().unwrap_or(0.0);
        if cvg < session_data.coverage.bitmap_min || session_data.coverage.bitmap_min == 0.0 {
            session_data.coverage.bitmap_min = cvg;
        } else if cvg > session_data.coverage.bitmap_max {
            session_data.coverage.bitmap_max = cvg;
        }
    }

    fn process_max_depth(value: &str, session_data: &mut CampaignData) {
        let levels = value.parse::<usize>().unwrap_or(0);
        if levels > session_data.levels.max {
            session_data.levels.max = levels;
        } else if levels < session_data.levels.min || session_data.levels.min == 0 {
            session_data.levels.min = levels;
        }
    }

    fn process_saved_crashes(value: &str, session_data: &mut CampaignData) {
        let saved_crashes = value.parse::<usize>().unwrap_or(0);
        if saved_crashes > session_data.crashes.saved_max {
            session_data.crashes.saved_max = saved_crashes;
        } else if saved_crashes < session_data.crashes.saved_min
            || session_data.crashes.saved_min == 0
        {
            session_data.crashes.saved_min = saved_crashes;
        }
        session_data.crashes.saved_cum += saved_crashes;
    }

    fn process_saved_hangs(value: &str, session_data: &mut CampaignData) {
        let saved_hangs = value.parse::<usize>().unwrap_or(0);
        if saved_hangs > session_data.hangs.saved_max {
            session_data.hangs.saved_max = saved_hangs;
        } else if saved_hangs < session_data.hangs.saved_min || session_data.hangs.saved_min == 0 {
            session_data.hangs.saved_min = saved_hangs;
        }
        session_data.hangs.saved_cum += saved_hangs;
    }

    fn process_last_find(value: &str, session_data: &mut CampaignData) {
        let last_find = value.parse::<u64>().unwrap_or(0);
        let last_find = UNIX_EPOCH + Duration::from_secs(last_find);
        let current_time = SystemTime::now();
        let duration = current_time.duration_since(last_find).unwrap();
        if duration > session_data.time_without_finds {
            session_data.time_without_finds = duration;
        }
    }

    fn process_cycles_done(value: &str, session_data: &mut CampaignData) {
        let cycles_done = value.parse::<usize>().unwrap_or(0);
        if cycles_done > session_data.cycles.done_max {
            session_data.cycles.done_max = cycles_done;
        } else if cycles_done < session_data.cycles.done_min || session_data.cycles.done_min == 0 {
            session_data.cycles.done_min = cycles_done;
        }
    }

    fn process_cycles_wo_finds(value: &str, session_data: &mut CampaignData) {
        let cycles_wo_finds = value.parse::<usize>().unwrap_or(0);
        if cycles_wo_finds > session_data.cycles.wo_finds_max {
            session_data.cycles.wo_finds_max = cycles_wo_finds;
        } else if cycles_wo_finds < session_data.cycles.wo_finds_min
            || session_data.cycles.wo_finds_min == 0
        {
            session_data.cycles.wo_finds_min = cycles_wo_finds;
        }
    }

    fn calculate_averages(session_data: &mut CampaignData, fuzzers_alive: usize) {
        session_data.executions.ps_avg = if fuzzers_alive > 0 {
            session_data.executions.ps_cum / fuzzers_alive as f64
        } else {
            0.0
        };
        session_data.executions.avg = if fuzzers_alive > 0 {
            session_data.executions.cum / fuzzers_alive
        } else {
            0
        };
        session_data.pending.favorites_avg = if fuzzers_alive > 0 {
            session_data.pending.favorites_cum / fuzzers_alive
        } else {
            0
        };
        session_data.pending.total_avg = if fuzzers_alive > 0 {
            session_data.pending.total_cum / fuzzers_alive
        } else {
            0
        };
        session_data.corpus.count_avg = if fuzzers_alive > 0 {
            session_data.corpus.count_cum / fuzzers_alive
        } else {
            0
        };
        session_data.crashes.saved_avg = if fuzzers_alive > 0 {
            session_data.crashes.saved_cum / fuzzers_alive
        } else {
            0
        };
        session_data.hangs.saved_avg = if fuzzers_alive > 0 {
            session_data.hangs.saved_cum / fuzzers_alive
        } else {
            0
        };
        session_data.coverage.bitmap_avg =
            (session_data.coverage.bitmap_min + session_data.coverage.bitmap_max) / 2.0;
        session_data.stability.avg =
            (session_data.stability.min + session_data.stability.max) / 2.0;
        session_data.cycles.done_avg =
            (session_data.cycles.done_min + session_data.cycles.done_max) / 2;
        session_data.cycles.wo_finds_avg =
            (session_data.cycles.wo_finds_min + session_data.cycles.wo_finds_max) / 2;
        session_data.levels.avg = (session_data.levels.min + session_data.levels.max) / 2;
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
