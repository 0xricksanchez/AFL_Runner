use chrono::{DateTime, Local};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

use crate::utils::log_buffer::LogRingBuffer;

#[derive(Default, Debug, Clone)]
pub struct Stats<T> {
    pub avg: T,
    pub min: T,
    pub max: T,
    pub cum: T,
}

impl<T: Default> Stats<T> {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Default, Debug, Clone)]
pub struct ExtendedStats {
    pub favorites: Stats<usize>,
    pub total: Stats<usize>,
}

#[derive(Default, Debug, Clone)]
pub struct CycleStats {
    pub done: Stats<usize>,
    pub wo_finds: Stats<usize>,
}

#[derive(Default, Debug, Clone)]
pub struct ExecutionStats {
    pub count: Stats<usize>,
    pub per_sec: Stats<f64>,
}

#[allow(dead_code)]
#[derive(Default, Debug, Clone)]
pub struct CrashInfoDetails {
    pub fuzzer_name: String,
    pub file_path: PathBuf,
    pub id: String,
    pub sig: Option<String>,
    pub src: String,
    pub time: u64,
    pub execs: u64,
    pub op: String,
    pub rep: u64,
}

#[derive(Default, Debug, Clone)]
pub struct Misc {
    pub afl_version: String,
    pub afl_banner: String,
}

#[derive(Debug, Clone)]
pub struct CampaignData {
    pub fuzzers_alive: Vec<usize>,
    pub fuzzers_started: usize,
    pub fuzzer_pids: Vec<u32>,
    pub total_run_time: Duration,
    pub executions: ExecutionStats,
    pub pending: ExtendedStats,
    pub corpus: Stats<usize>,
    pub coverage: Stats<f64>,
    pub cycles: CycleStats,
    pub stability: Stats<f64>,
    pub crashes: Stats<usize>,
    pub hangs: Stats<usize>,
    pub levels: Stats<usize>,
    pub time_without_finds: Stats<usize>,
    pub last_crashes: Vec<CrashInfoDetails>,
    pub last_hangs: Vec<CrashInfoDetails>,
    pub misc: Misc,
    pub start_time: Option<Instant>,
    pub logs: LogRingBuffer<String>,
}

impl Default for CampaignData {
    fn default() -> Self {
        Self {
            fuzzers_alive: Vec::new(),
            fuzzers_started: 0,
            fuzzer_pids: Vec::new(),
            total_run_time: Duration::from_secs(0),
            executions: ExecutionStats::default(),
            pending: ExtendedStats::default(),
            corpus: Stats::new(),
            coverage: Stats::new(),
            cycles: CycleStats::default(),
            stability: Stats::new(),
            crashes: Stats::new(),
            hangs: Stats::new(),
            levels: Stats::new(),
            time_without_finds: Stats::new(),
            last_crashes: Vec::with_capacity(10),
            last_hangs: Vec::with_capacity(10),
            misc: Misc::default(),
            start_time: None,
            logs: LogRingBuffer::new(10),
        }
    }
}

impl CampaignData {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clear(&mut self) {
        let pids = self.fuzzer_pids.clone();
        let fuzzers_alive = self.fuzzers_alive.clone();
        let fuzzers_started = self.fuzzers_started;
        let total_runtime = self.total_run_time;
        let misc = self.misc.clone();
        let start_time = self.start_time;
        let logs = self.logs.clone();
        *self = Self::new();
        self.fuzzer_pids = pids;
        self.fuzzers_alive = fuzzers_alive;
        self.fuzzers_started = fuzzers_started;
        self.total_run_time = total_runtime;
        self.misc = misc;
        self.start_time = start_time;
        self.logs = logs;
    }

    pub fn log<T: AsRef<str>>(&mut self, message: T) {
        let now: DateTime<Local> = SystemTime::now().into();
        let timestamp = now.format("%Y-%m-%d %H:%M:%S");
        self.logs
            .push(format!("[{timestamp}] - {}", message.as_ref()));
    }
}
