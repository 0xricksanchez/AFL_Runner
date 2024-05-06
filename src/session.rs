use std::time::Duration;
use std::{path::PathBuf, time::Instant};

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

#[derive(Debug, Clone)]
pub struct CampaignData {
    pub fuzzers_alive: Vec<usize>,
    pub fuzzers_started: usize,
    pub fuzzer_pids: Vec<u32>,
    pub total_run_time: Duration,
    pub executions: ExecutionsInfo,
    pub pending: PendingInfo,
    pub corpus: CorpusInfo,
    pub coverage: CoverageInfo,
    pub cycles: Cycles,
    pub stability: StabilityInfo,
    pub crashes: Solutions,
    pub hangs: Solutions,
    pub levels: Levels,
    pub time_without_finds: Duration,
    pub last_crashes: Vec<CrashInfoDetails>,
    pub last_hangs: Vec<CrashInfoDetails>,
    pub misc: Misc,
    pub start_time: Option<Instant>,
}

impl Default for CampaignData {
    fn default() -> Self {
        Self {
            fuzzers_alive: Vec::new(),
            fuzzers_started: 0,
            fuzzer_pids: Vec::new(),
            total_run_time: Duration::from_secs(0),
            executions: ExecutionsInfo::default(),
            pending: PendingInfo::default(),
            corpus: CorpusInfo::default(),
            coverage: CoverageInfo::default(),
            cycles: Cycles::default(),
            stability: StabilityInfo::default(),
            crashes: Solutions::default(),
            hangs: Solutions::default(),
            levels: Levels::default(),
            time_without_finds: Duration::from_secs(0),
            last_crashes: Vec::with_capacity(10),
            last_hangs: Vec::with_capacity(10),
            misc: Misc::default(),
            start_time: None,
        }
    }
}

impl CampaignData {
    pub fn clear(&mut self) {
        self.executions = ExecutionsInfo::default();
        self.pending = PendingInfo::default();
        self.corpus = CorpusInfo::default();
        self.coverage = CoverageInfo::default();
        self.cycles = Cycles::default();
        self.stability = StabilityInfo::default();
        self.crashes = Solutions::default();
        self.hangs = Solutions::default();
        self.levels = Levels::default();
        self.time_without_finds = Duration::from_secs(0);
        self.last_crashes.clear();
        self.last_hangs.clear();
    }
}

#[derive(Default, Debug, Clone)]
pub struct Levels {
    pub avg: usize,
    pub min: usize,
    pub max: usize,
}

#[derive(Default, Debug, Clone)]
pub struct Solutions {
    pub cum: usize,
    pub avg: usize,
    pub min: usize,
    pub max: usize,
}

#[derive(Default, Debug, Clone)]
pub struct StabilityInfo {
    pub avg: f64,
    pub min: f64,
    pub max: f64,
}

#[derive(Default, Debug, Clone)]
pub struct Cycles {
    pub done_avg: usize,
    pub done_min: usize,
    pub done_max: usize,
    pub wo_finds_avg: usize,
    pub wo_finds_min: usize,
    pub wo_finds_max: usize,
}

#[derive(Default, Debug, Clone)]
pub struct ExecutionsInfo {
    pub avg: usize,
    pub min: usize,
    pub max: usize,
    pub cum: usize,
    pub ps_avg: f64,
    pub ps_min: f64,
    pub ps_max: f64,
    pub ps_cum: f64,
}

#[derive(Default, Debug, Clone)]
pub struct CoverageInfo {
    pub avg: f64,
    pub min: f64,
    pub max: f64,
}

#[derive(Default, Debug, Clone)]
pub struct PendingInfo {
    pub favorites_avg: usize,
    pub favorites_cum: usize,
    pub favorites_max: usize,
    pub favorites_min: usize,
    pub total_avg: usize,
    pub total_cum: usize,
    pub total_min: usize,
    pub total_max: usize,
}

#[derive(Default, Debug, Clone)]
pub struct CorpusInfo {
    pub avg: usize,
    pub cum: usize,
    pub min: usize,
    pub max: usize,
}

#[derive(Default, Debug, Clone)]
pub struct Misc {
    pub afl_version: String,
    pub afl_banner: String,
}
