use std::{
    collections::HashMap,
    fs,
    ops::Add,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use sysinfo::{Pid, System};

use crate::session::{CampaignData, CrashInfoDetails};

macro_rules! update_stat {
    // Special case for floating point numbers
    ($field:expr, $metrics:expr, $key:expr, f64) => {
        if let Some(value) = $metrics.get::<f64>($key) {
            $field.max = $field.max.max(value);
            if $field.min == 0.0 {
                $field.min = value;
            } else {
                $field.min = $field.min.min(value);
            }
            $field.cum += value;
        }
    };
    // Case for integer types (usize)
    ($field:expr, $metrics:expr, $key:expr, usize) => {
        if let Some(value) = $metrics.get::<usize>($key) {
            $field.max = $field.max.max(value);
            if $field.min == 0 {
                $field.min = value;
            } else {
                $field.min = $field.min.min(value);
            }
            $field.cum += value;
        }
    };
}

macro_rules! calculate_average {
    // Case for integer averages from cum/count
    ($field:expr, $fuzzer_count:expr) => {
        $field.avg = $field.cum / $fuzzer_count;
    };
    // Case for floating point averages from cum/count
    ($field:expr, $fuzzer_count:expr, f64) => {
        #[allow(clippy::cast_precision_loss)]
        {
            $field.avg = $field.cum / ($fuzzer_count as f64);
        }
    };
}

// Separate macro for min-max calculations
macro_rules! calculate_minmax_average {
    // Case for floating point min-max
    ($field:expr) => {
        if $field.max != 0.0 || $field.min != 0.0 {
            $field.avg = ($field.min + $field.max) / 2.0;
        }
    };
    // Case for integer min-max
    ($field:expr, integer) => {
        if $field.max != 0 || $field.min != 0 {
            $field.avg = ($field.min + $field.max) / 2;
        }
    };
}

#[derive(Debug)]
struct FuzzerMetrics {
    pid: Option<u32>,
    metrics: HashMap<String, String>,
}

impl FuzzerMetrics {
    fn parse(content: &str) -> Self {
        let mut metrics = HashMap::with_capacity(20);
        let mut pid = None;

        for line in content.lines() {
            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim();
                let value = value.trim();

                if key == "fuzzer_pid" {
                    pid = value.parse().ok();
                }
                metrics.insert(key.to_string(), value.to_string());
            }
        }

        Self { pid, metrics }
    }

    fn get<T: std::str::FromStr>(&self, key: &str) -> Option<T> {
        self.metrics
            .get(key)
            .and_then(|v| v.trim_end_matches('%').parse().ok())
    }
}

#[derive(Debug)]
pub struct DataFetcher {
    output_dir: PathBuf,
    pub campaign_data: CampaignData,
    system: System,
    first_update: bool,
}

impl DataFetcher {
    pub fn new(
        output_dir: &Path,
        pid_file: Option<&Path>,
        campaign_data: &mut CampaignData,
    ) -> Self {
        let mut system = System::new_all();
        system.refresh_all();

        let (fuzzer_pids, dead_count) = Self::collect_pids(output_dir, pid_file, &system);

        campaign_data.log(if pid_file.is_some() {
            "PIDs fetched from the PID file. OK..."
        } else {
            "Attempted to fetch PIDs from fuzzer_stats files"
        });

        let fuzzers_alive = Self::get_alive_fuzzers(&fuzzer_pids, &system);
        campaign_data.log(if fuzzers_alive.is_empty() {
            "No fuzzers alive"
        } else {
            "Fuzzers alive count fetched. OK..."
        });

        campaign_data.fuzzers_started = fuzzers_alive.len() + dead_count;
        campaign_data.fuzzers_alive = fuzzers_alive;
        campaign_data.fuzzer_pids = fuzzer_pids;

        Self {
            output_dir: output_dir.to_path_buf(),
            campaign_data: campaign_data.clone(),
            system,
            first_update: true,
        }
    }

    fn collect_pids(
        output_dir: &Path,
        pid_file: Option<&Path>,
        system: &System,
    ) -> (Vec<u32>, usize) {
        pid_file.map_or_else(
            || {
                let mut alive_pids = Vec::new();
                let mut dead_count = 0;

                if let Ok(entries) = fs::read_dir(output_dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if !path.is_dir() {
                            continue;
                        }

                        let stats_path = path.join("fuzzer_stats");
                        if !stats_path.exists() {
                            continue;
                        }

                        if let Ok(content) = fs::read_to_string(&stats_path) {
                            let metrics = FuzzerMetrics::parse(&content);
                            if let Some(pid) = metrics.pid {
                                if system.process(Pid::from(pid as usize)).is_some() {
                                    alive_pids.push(pid);
                                } else {
                                    dead_count += 1;
                                }
                            }
                        }
                    }
                }

                (alive_pids, dead_count)
            },
            |pid_file| {
                let pids = fs::read_to_string(pid_file)
                    .unwrap_or_default()
                    .split(':')
                    .filter_map(|pid| pid.trim().parse::<u32>().ok())
                    .filter(|&pid| pid != 0)
                    .collect();
                (pids, 0)
            },
        )
    }

    fn get_alive_fuzzers(pids: &[u32], system: &System) -> Vec<usize> {
        pids.iter()
            .filter(|&&pid| pid != 0 && system.process(Pid::from(pid as usize)).is_some())
            .map(|&pid| pid as usize)
            .collect()
    }

    pub fn collect_session_data(&mut self) -> &CampaignData {
        self.system.refresh_all();
        self.campaign_data.fuzzers_alive =
            Self::get_alive_fuzzers(&self.campaign_data.fuzzer_pids, &self.system);

        if self.campaign_data.fuzzers_alive.is_empty() {
            self.campaign_data
                .log("No fuzzers alive. Skipping data collection");
            return &self.campaign_data;
        }

        self.campaign_data.clear();
        self.process_fuzzer_directories();
        self.update_run_time();
        self.calculate_averages();

        let (crashes, hangs) = self.collect_crashes_and_hangs(10);
        self.campaign_data.last_crashes = crashes;
        self.campaign_data.last_hangs = hangs;

        &self.campaign_data
    }

    fn process_fuzzer_directories(&mut self) {
        if let Ok(entries) = fs::read_dir(&self.output_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }

                let stats_path = path.join("fuzzer_stats");
                if !stats_path.exists() {
                    continue;
                }

                if let Ok(content) = fs::read_to_string(&stats_path) {
                    let metrics = FuzzerMetrics::parse(&content);
                    if let Some(pid) = metrics.pid {
                        if self.campaign_data.fuzzers_alive.contains(&(pid as usize)) {
                            self.process_metrics(&metrics);
                        }
                    }
                }
            }
        }
    }

    fn process_metrics(&mut self, metrics: &FuzzerMetrics) {
        if self.first_update {
            if let Some(run_time) = metrics.get::<u64>("run_time") {
                self.update_start_time(run_time);
            }
        }

        self.update_stats(metrics);
        self.update_misc_info(metrics);

        self.first_update = false;
    }

    fn update_stats(&mut self, metrics: &FuzzerMetrics) {
        if self.first_update {
            if let Some(run_time) = metrics.get::<u64>("run_time") {
                self.update_start_time(run_time);
            }
        }

        // Update integer statistics
        update_stat!(
            self.campaign_data.time_without_finds,
            metrics,
            "time_wo_finds",
            usize
        );
        update_stat!(
            self.campaign_data.executions.count,
            metrics,
            "execs_done",
            usize
        );
        update_stat!(
            self.campaign_data.pending.favorites,
            metrics,
            "pending_favs",
            usize
        );
        update_stat!(
            self.campaign_data.pending.total,
            metrics,
            "pending_total",
            usize
        );
        update_stat!(self.campaign_data.corpus, metrics, "corpus_count", usize);
        update_stat!(self.campaign_data.crashes, metrics, "saved_crashes", usize);
        update_stat!(self.campaign_data.hangs, metrics, "saved_hangs", usize);
        update_stat!(self.campaign_data.levels, metrics, "max_depth", usize);
        update_stat!(
            self.campaign_data.cycles.wo_finds,
            metrics,
            "cycles_wo_finds",
            usize
        );

        // Update floating point statistics
        update_stat!(
            self.campaign_data.executions.per_sec,
            metrics,
            "execs_per_sec",
            f64
        );

        self.update_stability_and_coverage(metrics);
        self.update_misc_info(metrics);
        self.first_update = false;
    }

    fn update_stability_and_coverage(&mut self, metrics: &FuzzerMetrics) {
        // Handle stability
        if let Some(stability) = metrics.get::<f64>("stability") {
            self.campaign_data.stability.max = self.campaign_data.stability.max.max(stability);
            if self.campaign_data.stability.min == 0.0
                || stability < self.campaign_data.stability.min
            {
                self.campaign_data.stability.min = stability;
            }
        }

        // Handle coverage
        if let Some(coverage) = metrics.get::<f64>("bitmap_cvg") {
            self.campaign_data.coverage.max = self.campaign_data.coverage.max.max(coverage);
            if self.campaign_data.coverage.min == 0.0 || coverage < self.campaign_data.coverage.min
            {
                self.campaign_data.coverage.min = coverage;
            }
        }
    }

    fn update_misc_info(&mut self, metrics: &FuzzerMetrics) {
        if self.first_update {
            if let Some(banner) = metrics.metrics.get("afl_banner") {
                self.campaign_data.misc.afl_banner.clone_from(banner);
            }
            if let Some(version) = metrics.metrics.get("afl_version") {
                self.campaign_data.misc.afl_version.clone_from(version);
            }
        }
    }

    fn update_start_time(&mut self, run_time: u64) {
        if self.campaign_data.start_time.is_none() {
            // Add 75 seconds buffer as per AFL++ stats file update frequency
            let duration = Duration::from_secs(run_time + 75);
            let start_time = Instant::now()
                .checked_sub(duration)
                .unwrap_or_else(Instant::now);
            self.campaign_data.start_time = Some(start_time);
            self.campaign_data.total_run_time = duration;
        }
    }

    fn update_run_time(&mut self) {
        if let Some(start_time) = self.campaign_data.start_time {
            // Add 5 second buffer to avoid future-dated crashes
            self.campaign_data.total_run_time = start_time.elapsed().add(Duration::from_secs(5));
        }
    }

    fn calculate_averages(&mut self) {
        let fuzzer_count = self.campaign_data.fuzzers_alive.len();
        if fuzzer_count == 0 {
            return;
        }

        // Calculate cumulative averages (using fuzzer count)
        calculate_average!(self.campaign_data.executions.count, fuzzer_count);
        calculate_average!(self.campaign_data.executions.per_sec, fuzzer_count, f64);
        calculate_average!(self.campaign_data.pending.favorites, fuzzer_count);
        calculate_average!(self.campaign_data.pending.total, fuzzer_count);
        calculate_average!(self.campaign_data.corpus, fuzzer_count);
        calculate_average!(self.campaign_data.crashes, fuzzer_count);
        calculate_average!(self.campaign_data.hangs, fuzzer_count);

        // Calculate min-max based averages
        calculate_minmax_average!(self.campaign_data.coverage);
        calculate_minmax_average!(self.campaign_data.stability);
        calculate_minmax_average!(self.campaign_data.cycles.done, integer);
        calculate_minmax_average!(self.campaign_data.cycles.wo_finds, integer);
        calculate_minmax_average!(self.campaign_data.levels, integer);
        calculate_minmax_average!(self.campaign_data.time_without_finds, integer);
    }

    fn collect_crashes_and_hangs(
        &self,
        num_latest: usize,
    ) -> (Vec<CrashInfoDetails>, Vec<CrashInfoDetails>) {
        // Pre-allocate vectors with expected capacity
        let mut crashes = Vec::with_capacity(num_latest);
        let mut hangs = Vec::with_capacity(num_latest);

        if let Ok(entries) = fs::read_dir(&self.output_dir) {
            for entry in entries.flatten() {
                let subdir = entry.path();
                if !subdir.is_dir() {
                    continue;
                }

                let fuzzer_name = subdir
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(String::from)
                    .unwrap_or_default();

                Self::collect_solution_files(&subdir, &fuzzer_name, "crashes", &mut crashes);
                Self::collect_solution_files(&subdir, &fuzzer_name, "hangs", &mut hangs);
            }
        }

        // Sort by time and take latest n items
        crashes.sort_unstable_by(|a, b| b.time.cmp(&a.time));
        hangs.sort_unstable_by(|a, b| b.time.cmp(&a.time));

        (
            crashes.into_iter().take(num_latest).collect(),
            hangs.into_iter().take(num_latest).collect(),
        )
    }

    fn collect_solution_files(
        subdir: &Path,
        fuzzer_name: &str,
        dir_name: &str,
        solutions: &mut Vec<CrashInfoDetails>,
    ) {
        let dir = subdir.join(dir_name);
        if !dir.is_dir() {
            return;
        }

        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }

                if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                    if let Some(mut info) = Self::parse_solution_filename(filename) {
                        info.fuzzer_name = fuzzer_name.to_string();
                        info.file_path = path;
                        solutions.push(info);
                    }
                }
            }
        }
    }

    fn parse_solution_filename(filename: &str) -> Option<CrashInfoDetails> {
        let parts: Vec<&str> = filename.split(',').collect();
        if parts.len() != 6 && parts.len() != 7 {
            return None;
        }

        let mut details = CrashInfoDetails {
            fuzzer_name: String::new(),
            file_path: PathBuf::new(),
            id: String::new(),
            sig: None,
            src: String::new(),
            time: 0,
            execs: 0,
            op: String::new(),
            rep: 0,
        };

        let mut current_part = 0;

        // Parse ID
        if let Some(id) = parts[current_part].split(':').nth(1) {
            details.id = id.to_string();
            current_part += 1;
        } else {
            return None;
        }

        // Check for signature (optional)
        if parts.len() == 7 {
            if let Some(sig) = parts[current_part].split(':').nth(1) {
                details.sig = Some(sig.to_string());
                current_part += 1;
            }
        }

        // Get value after colon and ensure it's not empty
        let get_value = |part: &str| -> Option<String> {
            part.split(':')
                .nth(1)
                .filter(|value| !value.is_empty())
                .map(std::string::ToString::to_string)
        };

        // Source
        details.src = get_value(parts[current_part])?;
        current_part += 1;

        // Time
        details.time = get_value(parts[current_part])?.parse().ok()?;
        current_part += 1;

        // Executions
        details.execs = get_value(parts[current_part])?.parse().ok()?;
        current_part += 1;

        // Operation
        details.op = get_value(parts[current_part])?;
        current_part += 1;

        // Repetition
        details.rep = get_value(parts[current_part])?.parse().ok()?;

        Some(details)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

    const MOCK_STATS_CONTENT: &str = r#"
        fuzzer_pid : 1234
        execs_done : 1000000
        execs_per_sec : 277.77
        pending_favs : 100
        pending_total : 500
        stability : 100.00%
        bitmap_cvg : 45.5%
        afl_banner : test_fuzzer
        afl_version : 4.05c
    "#;

    #[test]
    fn test_fuzzer_metrics_parsing() {
        let metrics = FuzzerMetrics::parse(MOCK_STATS_CONTENT);

        assert_eq!(metrics.pid, Some(1234));
        assert_eq!(metrics.get::<usize>("execs_done"), Some(1000000));
        assert_eq!(metrics.get::<f64>("execs_per_sec"), Some(277.77));
        assert_eq!(metrics.get::<usize>("pending_favs"), Some(100));
        assert_eq!(metrics.get::<f64>("stability"), Some(100.00));
        assert_eq!(metrics.get::<f64>("bitmap_cvg"), Some(45.5));
        assert_eq!(
            metrics.metrics.get("afl_banner").map(String::as_str),
            Some("test_fuzzer")
        );

        assert_eq!(metrics.get::<usize>("nonexistent"), None);

        let invalid_content = "fuzzer_pid : invalid";
        let invalid_metrics = FuzzerMetrics::parse(invalid_content);
        assert_eq!(invalid_metrics.pid, None);
    }

    #[test]
    fn test_parse_solution_filename() {
        let test_cases = vec![
            // (filename, expected_result)
            (
                "id:000000,sig:06,src:000000,time:1234,execs:5678,op:havoc,rep:2",
                Some(CrashInfoDetails {
                    fuzzer_name: String::new(),
                    file_path: PathBuf::new(),
                    id: "000000".to_string(),
                    sig: Some("06".to_string()),
                    src: "000000".to_string(),
                    time: 1234,
                    execs: 5678,
                    op: "havoc".to_string(),
                    rep: 2,
                }),
            ),
            (
                "id:000001,src:000000,time:1234,execs:5678,op:havoc,rep:2",
                Some(CrashInfoDetails {
                    fuzzer_name: String::new(),
                    file_path: PathBuf::new(),
                    id: "000001".to_string(),
                    sig: None,
                    src: "000000".to_string(),
                    time: 1234,
                    execs: 5678,
                    op: "havoc".to_string(),
                    rep: 2,
                }),
            ),
            ("invalid", None),
            ("id:123", None),
            ("id:123,sig:06,src:000", None),
        ];

        for (filename, expected) in test_cases {
            let result = DataFetcher::parse_solution_filename(filename);
            assert_eq!(result.is_some(), expected.is_some());
            if let Some(expected) = expected {
                let result = result.unwrap();
                assert_eq!(result.id, expected.id);
                assert_eq!(result.sig, expected.sig);
                assert_eq!(result.src, expected.src);
                assert_eq!(result.time, expected.time);
                assert_eq!(result.execs, expected.execs);
                assert_eq!(result.op, expected.op);
                assert_eq!(result.rep, expected.rep);
            }
        }
    }

    #[test]
    fn test_stats_calculation_and_stability() {
        let temp_dir = TempDir::new().unwrap();
        let mut campaign_data = CampaignData::new();

        let fuzzer_stats = vec![
            ("fuzzer01", "100.00"),
            ("fuzzer02", "98.50"),
            ("fuzzer03", "99.75"),
        ];

        for (fuzzer_name, stability) in &fuzzer_stats {
            let stats_dir = temp_dir.path().join(fuzzer_name);
            fs::create_dir(&stats_dir).unwrap();
            let stats_content = format!(
                r#"
                fuzzer_pid : 1234
                execs_done : 1000000
                execs_per_sec : 277.77
                pending_favs : 100
                pending_total : 500
                stability : {}%
                bitmap_cvg : 45.5%
                "#,
                stability
            );
            let stats_file = stats_dir.join("fuzzer_stats");
            File::create(&stats_file)
                .unwrap()
                .write_all(stats_content.as_bytes())
                .unwrap();
        }

        let mut fetcher = DataFetcher::new(temp_dir.path(), None, &mut campaign_data);
        fetcher.campaign_data.fuzzers_alive = vec![1234];
        fetcher.process_fuzzer_directories();
        fetcher.calculate_averages();

        assert_eq!(fetcher.campaign_data.executions.count.cum, 3000000);
        assert!((fetcher.campaign_data.executions.per_sec.cum - 833.31).abs() < 0.01);

        assert!((fetcher.campaign_data.stability.max - 100.0).abs() < f64::EPSILON);
        assert!((fetcher.campaign_data.stability.min - 98.50).abs() < f64::EPSILON);
        assert!((fetcher.campaign_data.stability.avg - 99.25).abs() < 0.01);
    }

    #[test]
    fn test_campaign_data_lifecycle() {
        let temp_dir = TempDir::new().unwrap();
        let mut campaign_data = CampaignData::new();

        let stats_content = r#"
            fuzzer_pid : 1234
            execs_done : 1000000
            execs_per_sec : 277.77
            pending_favs : 100
            pending_total : 500
            stability : 100.00%
            bitmap_cvg : 45.5%
            afl_banner : test_fuzzer
            afl_version : 4.05c
            run_time : 3600
        "#;

        let stats_dir = temp_dir.path().join("fuzzer01");
        fs::create_dir(&stats_dir).unwrap();
        File::create(stats_dir.join("fuzzer_stats"))
            .unwrap()
            .write_all(stats_content.as_bytes())
            .unwrap();

        let mut fetcher = DataFetcher::new(temp_dir.path(), None, &mut campaign_data);

        assert!(fetcher.campaign_data.start_time.is_none());
        assert!(fetcher.campaign_data.total_run_time < Duration::from_secs(5));

        fetcher.campaign_data.fuzzers_alive = vec![1234];
        fetcher.process_fuzzer_directories();

        assert!(fetcher.campaign_data.start_time.is_some());

        fetcher.campaign_data.clear();
        assert_eq!(fetcher.campaign_data.executions.count.cum, 0);
        assert_eq!(fetcher.campaign_data.executions.per_sec.cum, 0.0);
        assert_eq!(fetcher.campaign_data.crashes.cum, 0);
    }

    #[test]
    fn test_time_without_finds_direct_usage() {
        let temp_dir = TempDir::new().unwrap();
        let mut campaign_data = CampaignData::new();

        let stats_content = r#"
        fuzzer_pid : 1234
        time_wo_finds : 341
        last_find : 1730983297
    "#;

        let stats_dir = temp_dir.path().join("fuzzer01");
        fs::create_dir(&stats_dir).unwrap();
        File::create(stats_dir.join("fuzzer_stats"))
            .unwrap()
            .write_all(stats_content.as_bytes())
            .unwrap();

        let mut fetcher = DataFetcher::new(temp_dir.path(), None, &mut campaign_data);
        fetcher.campaign_data.fuzzers_alive = vec![1234];
        fetcher.process_fuzzer_directories();

        assert_eq!(fetcher.campaign_data.time_without_finds.max, 341);
        assert_eq!(fetcher.campaign_data.time_without_finds.min, 341);
    }

    #[test]
    fn test_average_calculations() {
        let temp_dir = TempDir::new().unwrap();
        let mut campaign_data = CampaignData::new();

        // Test data with varying values to exercise both types of averages
        let fuzzer_stats = vec![
            ("fuzzer01", "100.00", "1000000", "250.0", "45.5"),
            ("fuzzer02", "98.50", "1200000", "275.0", "47.2"),
            ("fuzzer03", "99.75", "1100000", "260.0", "46.3"),
        ];

        for (fuzzer_name, stability, execs, execs_per_sec, coverage) in &fuzzer_stats {
            let stats_dir = temp_dir.path().join(fuzzer_name);
            fs::create_dir(&stats_dir).unwrap();
            let stats_content = format!(
                r#"
                fuzzer_pid : 1234
                execs_done : {}
                execs_per_sec : {}
                pending_favs : 100
                pending_total : 500
                stability : {}%
                bitmap_cvg : {}%
                "#,
                execs, execs_per_sec, stability, coverage
            );
            let stats_file = stats_dir.join("fuzzer_stats");
            File::create(&stats_file)
                .unwrap()
                .write_all(stats_content.as_bytes())
                .unwrap();
        }

        let mut fetcher = DataFetcher::new(temp_dir.path(), None, &mut campaign_data);
        fetcher.campaign_data.fuzzers_alive = vec![1234];
        fetcher.process_fuzzer_directories();
        fetcher.calculate_averages();

        // Test cumulative averages
        assert_eq!(fetcher.campaign_data.executions.count.cum, 3300000);
        assert_eq!(fetcher.campaign_data.executions.count.avg, 3300000); // Only one fuzzer alive
        assert!((fetcher.campaign_data.executions.per_sec.cum - 785.0).abs() < 0.01);

        // Test min-max based averages
        assert!((fetcher.campaign_data.stability.max - 100.0).abs() < f64::EPSILON);
        assert!((fetcher.campaign_data.stability.min - 98.50).abs() < f64::EPSILON);
        assert!((fetcher.campaign_data.stability.avg - 99.25).abs() < 0.01);

        assert!((fetcher.campaign_data.coverage.max - 47.2).abs() < f64::EPSILON);
        assert!((fetcher.campaign_data.coverage.min - 45.5).abs() < f64::EPSILON);
        assert!((fetcher.campaign_data.coverage.avg - 46.35).abs() < 0.01);
    }

    #[test]
    fn test_zero_value_handling() {
        let temp_dir = TempDir::new().unwrap();
        let mut campaign_data = CampaignData::new();

        let stats_content = r#"
            fuzzer_pid : 1234
            execs_done : 0
            execs_per_sec : 0.0
            pending_favs : 0
            pending_total : 0
            stability : 0.00%
            bitmap_cvg : 0.0%
        "#;

        let stats_dir = temp_dir.path().join("fuzzer01");
        fs::create_dir(&stats_dir).unwrap();
        File::create(stats_dir.join("fuzzer_stats"))
            .unwrap()
            .write_all(stats_content.as_bytes())
            .unwrap();

        let mut fetcher = DataFetcher::new(temp_dir.path(), None, &mut campaign_data);
        fetcher.campaign_data.fuzzers_alive = vec![1234];
        fetcher.process_fuzzer_directories();
        fetcher.calculate_averages();

        // Test that zero values are handled correctly
        assert_eq!(fetcher.campaign_data.executions.count.avg, 0);
        assert_eq!(fetcher.campaign_data.executions.per_sec.avg, 0.0);
        assert_eq!(fetcher.campaign_data.stability.avg, 0.0);
        assert_eq!(fetcher.campaign_data.coverage.avg, 0.0);
    }
}
