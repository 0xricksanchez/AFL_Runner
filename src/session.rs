use std::path::PathBuf;
use std::time::Duration;

#[derive(Default, Debug)]
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

#[derive(Debug)]
pub struct SessionData {
    pub fuzzers_alive: usize,
    pub total_run_time: Duration,
    pub executions: ExecutionsInfo,
    pub pending: PendingInfo,
    pub corpus: CorpusInfo,
    pub coverage: CoverageInfo,
    pub cycles: Cycles,
    pub stability: StabilityInfo,
    pub crashes: CrashInfo,
    pub hangs: CrashInfo,
    pub levels: Levels,
    pub time_without_finds: Duration,
    pub last_crashes: Vec<CrashInfoDetails>,
    pub last_hangs: Vec<CrashInfoDetails>,
    pub misc: Misc,
}

impl Default for SessionData {
    fn default() -> Self {
        Self {
            fuzzers_alive: 0,
            total_run_time: Duration::from_secs(0),
            executions: ExecutionsInfo::default(),
            pending: PendingInfo::default(),
            corpus: CorpusInfo::default(),
            coverage: CoverageInfo::default(),
            cycles: Cycles::default(),
            stability: StabilityInfo::default(),
            crashes: CrashInfo::default(),
            hangs: CrashInfo::default(),
            levels: Levels::default(),
            time_without_finds: Duration::from_secs(0),
            last_crashes: Vec::with_capacity(10),
            last_hangs: Vec::with_capacity(10),
            misc: Misc::default(),
        }
    }
}

impl SessionData {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Default, Debug)]
pub struct Levels {
    pub avg: usize,
    pub min: usize,
    pub max: usize,
}

#[derive(Default, Debug)]
pub struct CrashInfo {
    pub saved_cum: usize,
    pub saved_avg: usize,
    pub saved_min: usize,
    pub saved_max: usize,
}

#[derive(Default, Debug)]
pub struct StabilityInfo {
    pub avg: f64,
    pub min: f64,
    pub max: f64,
}

#[derive(Default, Debug)]
pub struct Cycles {
    pub done_avg: usize,
    pub done_min: usize,
    pub done_max: usize,
    pub wo_finds_avg: usize,
    pub wo_finds_min: usize,
    pub wo_finds_max: usize,
}

#[derive(Default, Debug)]
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

#[derive(Default, Debug)]
pub struct CoverageInfo {
    pub bitmap_avg: f64,
    pub bitmap_min: f64,
    pub bitmap_max: f64,
}

#[derive(Default, Debug)]
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

#[derive(Default, Debug)]
pub struct CorpusInfo {
    pub count_avg: usize,
    pub count_cum: usize,
    pub count_min: usize,
    pub count_max: usize,
}

#[derive(Default, Debug)]
pub struct Misc {
    pub afl_version: String,
    pub afl_banner: String,
}
