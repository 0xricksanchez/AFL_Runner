use crate::session::{CrashInfoDetails, SessionData};
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn collect_session_data(output_dir: &PathBuf) -> SessionData {
    let mut session_data = SessionData::new();

    let mut fuzzers_alive = 0;

    for entry in fs::read_dir(output_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();

        if path.is_dir() {
            let fuzzer_stats_path = path.join("fuzzer_stats");

            if fuzzer_stats_path.exists() {
                let content = fs::read_to_string(fuzzer_stats_path).unwrap();
                let lines: Vec<&str> = content.lines().collect();

                for line in lines {
                    let parts: Vec<&str> = line.split(':').map(str::trim).collect();

                    if parts.len() == 2 {
                        let key = parts[0];
                        let value = parts[1];

                        match key {
                            "start_time" => {
                                let start_time = UNIX_EPOCH
                                    + Duration::from_secs(value.parse::<u64>().unwrap_or(0));
                                let current_time = SystemTime::now();
                                let duration = current_time.duration_since(start_time).unwrap();
                                session_data.total_run_time = duration;
                            }
                            "execs_per_sec" => {
                                let exec_ps = value.parse::<f64>().unwrap_or(0.0);
                                if exec_ps > session_data.executions.ps_max {
                                    session_data.executions.ps_max = exec_ps;
                                } else if exec_ps < session_data.executions.ps_min
                                    || session_data.executions.ps_min == 0.0
                                {
                                    session_data.executions.ps_min = exec_ps;
                                }
                                session_data.executions.ps_cum += exec_ps;
                            }
                            "execs_done" => {
                                let execs_done = value.parse::<usize>().unwrap_or(0);
                                if execs_done > session_data.executions.max {
                                    session_data.executions.max = execs_done;
                                } else if execs_done < session_data.executions.min
                                    || session_data.executions.min == 0
                                {
                                    session_data.executions.min = execs_done;
                                }
                                session_data.executions.cum += execs_done;
                            }
                            "pending_favs" => {
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
                            "pending_total" => {
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
                            "stability" => {
                                let stability =
                                    value.trim_end_matches('%').parse::<f64>().unwrap_or(0.0);
                                if stability > session_data.stability.max {
                                    session_data.stability.max = stability;
                                } else if stability < session_data.stability.min
                                    || session_data.stability.min == 0.0
                                {
                                    session_data.stability.min = stability;
                                }
                            }
                            "corpus_count" => {
                                let corpus_count = value.parse::<usize>().unwrap_or(0);
                                if corpus_count > session_data.corpus.count_max {
                                    session_data.corpus.count_max = corpus_count;
                                } else if corpus_count < session_data.corpus.count_min
                                    || session_data.corpus.count_min == 0
                                {
                                    session_data.corpus.count_min = corpus_count;
                                }
                                session_data.corpus.count_cum += corpus_count;
                            }
                            "bitmap_cvg" => {
                                let cvg = value.trim_end_matches('%').parse::<f64>().unwrap_or(0.0);
                                if cvg < session_data.coverage.bitmap_min
                                    || session_data.coverage.bitmap_min == 0.0
                                {
                                    session_data.coverage.bitmap_min = cvg;
                                } else if cvg > session_data.coverage.bitmap_max {
                                    session_data.coverage.bitmap_max = cvg;
                                }
                            }
                            "max_depth" => {
                                let levels = value.parse::<usize>().unwrap_or(0);
                                if levels > session_data.levels.max {
                                    session_data.levels.max = levels;
                                } else if levels < session_data.levels.min
                                    || session_data.levels.min == 0
                                {
                                    session_data.levels.min = levels;
                                }
                            }
                            "saved_crashes" => {
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
                            "saved_hangs" => {
                                let saved_hangs = value.parse::<usize>().unwrap_or(0);
                                if saved_hangs > session_data.hangs.saved_max {
                                    session_data.hangs.saved_max = saved_hangs;
                                } else if saved_hangs < session_data.hangs.saved_min
                                    || session_data.hangs.saved_min == 0
                                {
                                    session_data.hangs.saved_min = saved_hangs;
                                }
                                session_data.hangs.saved_cum += saved_hangs;
                            }
                            "last_find" => {
                                let last_find = value.parse::<u64>().unwrap_or(0);
                                let last_find = UNIX_EPOCH + Duration::from_secs(last_find);
                                let current_time = SystemTime::now();
                                let duration = current_time.duration_since(last_find).unwrap();
                                if duration > session_data.time_without_finds {
                                    session_data.time_without_finds = duration;
                                }
                            }
                            "afl_banner" => {
                                session_data.misc.afl_banner = value.to_string();
                            }
                            "afl_version" => {
                                session_data.misc.afl_version = value.to_string();
                            }
                            "cycles_done" => {
                                let cycles_done = value.parse::<usize>().unwrap_or(0);
                                if cycles_done > session_data.cycles.done_max {
                                    session_data.cycles.done_max = cycles_done;
                                } else if cycles_done < session_data.cycles.done_min
                                    || session_data.cycles.done_min == 0
                                {
                                    session_data.cycles.done_min = cycles_done;
                                }
                            }
                            "cycles_wo_finds" => {
                                let cycles_wo_finds = value.parse::<usize>().unwrap_or(0);
                                if cycles_wo_finds > session_data.cycles.wo_finds_max {
                                    session_data.cycles.wo_finds_max = cycles_wo_finds;
                                } else if cycles_wo_finds < session_data.cycles.wo_finds_min
                                    || session_data.cycles.wo_finds_min == 0
                                {
                                    session_data.cycles.wo_finds_min = cycles_wo_finds;
                                }
                            }
                            _ => {}
                        }
                    }
                }

                fuzzers_alive += 1;
            }
        }
    }
    session_data.fuzzers_alive = fuzzers_alive;

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
    session_data.stability.avg = (session_data.stability.min + session_data.stability.max) / 2.0;
    session_data.cycles.done_avg =
        (session_data.cycles.done_min + session_data.cycles.done_max) / 2;
    session_data.cycles.wo_finds_avg =
        (session_data.cycles.wo_finds_min + session_data.cycles.wo_finds_max) / 2;
    session_data.levels.avg = (session_data.levels.min + session_data.levels.max) / 2;

    let output_dir = output_dir.clone().into_os_string().into_string().unwrap();
    let (last_crashes, last_hangs) = collect_session_crashes_hangs(&output_dir, 10);
    session_data.last_crashes = last_crashes;
    session_data.last_hangs = last_hangs;

    session_data
}

fn collect_session_crashes_hangs(
    output_dir: &str,
    num_latest: usize,
) -> (Vec<CrashInfoDetails>, Vec<CrashInfoDetails>) {
    let mut crashes = Vec::new();
    let mut hangs = Vec::new();

    for entry in fs::read_dir(output_dir).unwrap() {
        let entry = entry.unwrap();
        let subdir = entry.path();

        if subdir.is_dir() {
            let fuzzer_name = subdir.file_name().unwrap().to_str().unwrap().to_string();

            let crashes_dir = subdir.join("crashes");
            if crashes_dir.is_dir() {
                process_files(&crashes_dir, &fuzzer_name, &mut crashes);
            }

            let hangs_dir = subdir.join("hangs");
            if hangs_dir.is_dir() {
                process_files(&hangs_dir, &fuzzer_name, &mut hangs);
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

fn process_files(dir: &PathBuf, fuzzer_name: &str, file_infos: &mut Vec<CrashInfoDetails>) {
    fs::read_dir(dir).unwrap().flatten().for_each(|file_entry| {
        let file = file_entry.path();
        if file.is_file() {
            let filename = file.file_name().unwrap().to_str().unwrap();
            if let Some(file_info) = parse_filename(filename) {
                let file_info = CrashInfoDetails {
                    fuzzer_name: fuzzer_name.to_string(),
                    file_path: file,
                    id: file_info.0,
                    sig: file_info.1,
                    src: file_info.2,
                    time: file_info.3,
                    execs: file_info.4,
                    op: file_info.5,
                    rep: file_info.6,
                };
                file_infos.push(file_info);
            }
        }
    });
}

fn parse_filename(
    filename: &str,
) -> Option<(String, Option<String>, String, u64, u64, String, u64)> {
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
        Some((id, sig, src, time, execs, op, rep))
    } else {
        None
    }
}
