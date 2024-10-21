use anyhow::Result;
use std::io;
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::session::{CampaignData, CrashInfoDetails};
use crate::{data_collection::DataFetcher, utils::format_duration};
use anyhow::bail;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    prelude::*,
    style::{Color, Style},
    text::Span,
    widgets::{Block, Borders, Paragraph, Wrap},
    Terminal,
};

static SLOW_EXEC_PS_THRESHOLD: f64 = 250.0;
static CAUTION_STABILITY: f64 = 90.0;
static WARN_STABILITY: f64 = 75.0;
static ERROR_STABILITY: f64 = 60.0;

/// Represents the TUI (Text User Interface)
pub struct Tui {
    /// The terminal instance
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
}

impl Tui {
    /// Creates a new `Tui` instance
    pub fn new() -> io::Result<Self> {
        let stdout = io::stdout();
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;
        Ok(Self { terminal })
    }

    /// Runs the TUI standalone with the specified output directory
    pub fn run(output_dir: &Path, pid_file: Option<&Path>, cdata: &mut CampaignData) -> Result<()> {
        let output_dir = output_dir.to_path_buf();
        cdata.log("Initialized TUI");
        let mut dfetcher = DataFetcher::new(&output_dir, pid_file, cdata);
        let (session_data_tx, session_data_rx) = mpsc::channel();
        thread::spawn(move || loop {
            let session_data = dfetcher.collect_session_data().clone();
            if let Err(e) = session_data_tx.send(session_data) {
                eprintln!("Error sending session data: {e}");
                break;
            }
            thread::sleep(Duration::from_secs(1));
        });

        if let Err(e) = Self::new().and_then(|mut tui| tui.run_internal(&session_data_rx)) {
            bail!("Error running TUI: {e}");
        }
        //println!("Campaign data: {:?}", session_data_rx.recv().unwrap());
        Ok(())
    }

    /// Runs the TUI with the specified session data receiver
    fn run_internal(&mut self, session_data_rx: &mpsc::Receiver<CampaignData>) -> io::Result<()> {
        self.terminal.clear()?;
        enable_raw_mode()?;
        crossterm::execute!(self.terminal.backend_mut(), EnterAlternateScreen)?;

        loop {
            if let Ok(session_data) = session_data_rx.recv_timeout(Duration::from_millis(500)) {
                self.draw(&session_data)?;
            }

            if crossterm::event::poll(Duration::from_millis(200))? {
                if let crossterm::event::Event::Key(key_event) = crossterm::event::read()? {
                    if key_event.code == crossterm::event::KeyCode::Char('q') {
                        break;
                    }
                }
            }
        }

        disable_raw_mode()?;
        crossterm::execute!(self.terminal.backend_mut(), LeaveAlternateScreen)?;
        self.terminal.clear()?;
        self.terminal.show_cursor()?;

        Ok(())
    }

    /// Creates the layout for the TUI
    fn create_layout(size: Rect, show_crashes: bool, show_hangs: bool) -> Vec<Rect> {
        let main_layout = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([Constraint::Length(1), Constraint::Min(0)].as_ref())
            .split(size);

        let mut constraints = vec![
            Constraint::Length(7), // Process timings and Overall results
            Constraint::Length(6), // Stage progress and Nerd stats
        ];

        if show_crashes {
            constraints.push(Constraint::Length(14)); // Latest crashes
        }
        if show_hangs {
            constraints.push(Constraint::Length(14)); // Latest hangs
        }

        constraints.push(Constraint::Min(10)); // Logs (at least 10 lines)

        let inner_layout = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints(&constraints)
            .split(main_layout[1]);

        let mut chunks = vec![main_layout[0]];
        chunks.extend_from_slice(&inner_layout);

        chunks
    }

    /// Draws the TUI with the specified session data
    fn draw(&mut self, session_data: &CampaignData) -> io::Result<()> {
        self.terminal.draw(|f| {
            let show_crashes = f.area().height >= 16;
            let show_hangs = f.area().height >= 30;

            let chunks = Self::create_layout(f.area(), show_crashes, show_hangs);

            Self::render_title(f, session_data, chunks[0]);

            let process_overall_layout = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)])
                .split(chunks[1]);
            Self::render_process_timings(f, session_data, process_overall_layout[0]);
            Self::render_overall_results(f, session_data, process_overall_layout[1]);

            let stage_nerd_layout = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)])
                .split(chunks[2]);
            Self::render_stage_progress(f, session_data, stage_nerd_layout[0]);
            Self::render_nerd_stats(f, session_data, stage_nerd_layout[1]);

            let mut idx = 3;

            if show_crashes {
                Self::render_crash_solutions(f, session_data, chunks[idx]);
                idx += 1;
            }
            if show_hangs {
                Self::render_hang_solutions(f, session_data, chunks[idx]);
                idx += 1;
            }

            Self::render_logs(f, session_data, chunks[idx]);
        })?;
        Ok(())
    }

    /// Renders the overall results section of the TUI
    fn render_overall_results(f: &mut Frame, session_data: &CampaignData, area: Rect) {
        let p_overall_res = Self::create_overall_results_paragraph(session_data);
        f.render_widget(p_overall_res, area);
    }

    /// Renders the process timings section of the TUI
    fn render_process_timings(f: &mut Frame, session_data: &CampaignData, area: Rect) {
        let p_proc_timings = Self::create_process_timings_paragraph(session_data);
        f.render_widget(p_proc_timings, area);
    }

    /// Renders the stage progress section of the TUI
    fn render_stage_progress(f: &mut Frame, session_data: &CampaignData, area: Rect) {
        let p_stage_prog = Self::create_stage_progress_paragraph(session_data);
        f.render_widget(p_stage_prog, area);
    }

    /// Renders the nerd stats section of the TUI
    fn render_nerd_stats(f: &mut Frame, session_data: &CampaignData, area: Rect) {
        let p_nerd_stats = Self::create_nerd_stats_paragraph(session_data);
        f.render_widget(p_nerd_stats, area);
    }

    /// Renders the title section of the TUI
    fn render_title(f: &mut Frame, session_data: &CampaignData, area: Rect) {
        let title = Paragraph::new(format!(
            "AFL {} - {} - Fuzzing campaign runner by @0xricksanchez",
            session_data.misc.afl_version, session_data.misc.afl_banner
        ))
        .alignment(Alignment::Center)
        .style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );

        f.render_widget(title, area);
    }

    /// Renders the crash solutions section of the TUI
    fn render_crash_solutions(f: &mut Frame, session_data: &CampaignData, area: Rect) {
        let p_crash_solutions = Paragraph::new(Self::format_solutions(
            &session_data.total_run_time,
            &session_data.last_crashes,
        ))
        .block(
            Block::default()
                .title("Latest Crashes")
                .borders(Borders::ALL)
                .border_style(Style::default().add_modifier(Modifier::BOLD))
                .title_style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .style(Style::default());

        f.render_widget(p_crash_solutions, area);
    }

    /// Renders the hang solutions section of the TUI
    fn render_hang_solutions(f: &mut Frame, session_data: &CampaignData, area: Rect) {
        let p_hang_solutions = Paragraph::new(Self::format_solutions(
            &session_data.total_run_time,
            &session_data.last_hangs,
        ))
        .block(
            Block::default()
                .title("Latest Hangs")
                .borders(Borders::ALL)
                .border_style(Style::default().add_modifier(Modifier::BOLD))
                .title_style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .style(Style::default());

        f.render_widget(p_hang_solutions, area);
    }

    /// Creates the process timings paragraph
    fn create_process_timings_paragraph(session_data: &CampaignData) -> Paragraph {
        let last_seen_crash =
            Self::format_last_event(&session_data.last_crashes, &session_data.total_run_time);
        let last_seen_hang =
            Self::format_last_event(&session_data.last_hangs, &session_data.total_run_time);

        let fuzzers_alive_style = if session_data.fuzzers_alive.len() < session_data.fuzzers_started
        {
            Style::default().fg(Color::Red)
        } else {
            Style::default()
        };

        let text = vec![
            Line::from(vec![
                Span::raw("Fuzzers alive: "),
                Span::styled(
                    format!(
                        "{}/{}",
                        session_data.fuzzers_alive.len(),
                        session_data.fuzzers_started
                    ),
                    fuzzers_alive_style,
                ),
            ]),
            Line::from(format!(
                "Total run time: {}",
                format_duration(&session_data.total_run_time)
            )),
            Line::from(format!(
                "Time without finds: {}s ({}s/{}s)",
                session_data.time_without_finds.avg,
                session_data.time_without_finds.min,
                session_data.time_without_finds.max,
            )),
            Line::from(format!("Last saved crash: {last_seen_crash}")),
            Line::from(format!("Last saved hang: {last_seen_hang}")),
        ];

        let block = Block::default()
            .title(Span::styled(
                "Process timing",
                Style::default().add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().add_modifier(Modifier::BOLD));

        Paragraph::new(text).block(block).wrap(Wrap { trim: true })
    }

    /// Creates the overall results paragraph
    fn create_overall_results_paragraph(session_data: &CampaignData) -> Paragraph {
        let stability_style = if session_data.stability.avg >= CAUTION_STABILITY {
            Style::default()
        } else if session_data.stability.avg >= WARN_STABILITY {
            Style::default().fg(Color::Yellow)
        } else if session_data.stability.avg >= ERROR_STABILITY {
            Style::default().fg(Color::Rgb(255, 165, 0)) // Orange color
        } else {
            Style::default().fg(Color::Red)
        };

        let content = vec![
            Line::from(format!(
                "Cycles done: {} ({}/{})",
                session_data.cycles.done_avg,
                session_data.cycles.done_min,
                session_data.cycles.done_max,
            )),
            Line::from(format!(
                "Crashes saved: {} ({}->{}->{})",
                session_data.crashes.cum,
                session_data.crashes.min,
                session_data.crashes.avg,
                session_data.crashes.max,
            )),
            Line::from(format!(
                "Hangs saved: {} ({}->{}->{})",
                session_data.hangs.cum,
                session_data.hangs.min,
                session_data.hangs.avg,
                session_data.hangs.max,
            )),
            Line::from(format!(
                "Corpus count: {} ({}->{}->{})",
                Self::format_int_to_hint(session_data.corpus.cum),
                Self::format_int_to_hint(session_data.corpus.min),
                Self::format_int_to_hint(session_data.corpus.avg),
                Self::format_int_to_hint(session_data.corpus.max),
            )),
            Line::from(vec![
                Span::raw("Stability: "),
                Span::styled(
                    format!(
                        "{}% ({}%/{}%)",
                        session_data.stability.avg,
                        session_data.stability.min,
                        session_data.stability.max,
                    ),
                    stability_style,
                ),
            ]),
        ];

        Paragraph::new(content)
            .block(
                Block::default()
                    .title("Overall results")
                    .borders(Borders::ALL)
                    .border_style(Style::default().add_modifier(Modifier::BOLD))
                    .title_style(Style::default().add_modifier(Modifier::BOLD)),
            )
            .wrap(Wrap { trim: true })
    }

    /// Creates the stage progress paragraph
    fn create_stage_progress_paragraph(session_data: &CampaignData) -> Paragraph {
        let ps_cum_style = if session_data.executions.ps_cum < SLOW_EXEC_PS_THRESHOLD {
            Style::default().fg(Color::Red)
        } else {
            Style::default()
        };

        let ps_min_style = if session_data.executions.ps_min < SLOW_EXEC_PS_THRESHOLD {
            Style::default().fg(Color::Red)
        } else {
            Style::default()
        };

        let ps_avg_style = if session_data.executions.ps_avg < SLOW_EXEC_PS_THRESHOLD {
            Style::default().fg(Color::Red)
        } else {
            Style::default()
        };

        let ps_max_style = if session_data.executions.ps_max < SLOW_EXEC_PS_THRESHOLD {
            Style::default().fg(Color::Red)
        } else {
            Style::default()
        };

        let text = vec![
            Line::from(format!(
                "Execs: {} ({}->{}<-{})",
                Self::format_int_to_hint(session_data.executions.cum),
                Self::format_int_to_hint(session_data.executions.min),
                Self::format_int_to_hint(session_data.executions.avg),
                Self::format_int_to_hint(session_data.executions.max),
            )),
            Line::from(vec![
                Span::raw("Execs/s: "),
                Span::styled(
                    Self::format_float_to_hfloat(session_data.executions.ps_cum),
                    ps_cum_style,
                ),
                Span::raw(" ("),
                Span::styled(
                    Self::format_float_to_hfloat(session_data.executions.ps_min),
                    ps_min_style,
                ),
                Span::raw("->"),
                Span::styled(
                    Self::format_float_to_hfloat(session_data.executions.ps_avg),
                    ps_avg_style,
                ),
                Span::raw("<-"),
                Span::styled(
                    Self::format_float_to_hfloat(session_data.executions.ps_max),
                    ps_max_style,
                ),
                Span::raw(")"),
            ]),
            Line::from(format!(
                "Coverage: {:.2}% ({:.2}%/{:.2}%)",
                session_data.coverage.avg, session_data.coverage.min, session_data.coverage.max,
            )),
        ];

        let block = Block::default()
            .title(Span::styled(
                "Stage Progress",
                Style::default().add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().add_modifier(Modifier::BOLD));

        Paragraph::new(text).block(block).wrap(Wrap { trim: true })
    }

    /// Creates the nerd stats paragraph
    fn create_nerd_stats_paragraph(session_data: &CampaignData) -> Paragraph {
        let content = format!(
            "Levels: {} ({}/{})
Pending favorites: {} ({}->{}<-{})
Pending total: {} ({}->{}<-{}),
Cycles without finds: {} ({}/{})",
            session_data.levels.avg,
            session_data.levels.min,
            session_data.levels.max,
            Self::format_int_to_hint(session_data.pending.favorites_cum),
            Self::format_int_to_hint(session_data.pending.favorites_min),
            Self::format_int_to_hint(session_data.pending.favorites_avg),
            Self::format_int_to_hint(session_data.pending.favorites_max),
            Self::format_int_to_hint(session_data.pending.total_cum),
            Self::format_int_to_hint(session_data.pending.total_min),
            Self::format_int_to_hint(session_data.pending.total_avg),
            Self::format_int_to_hint(session_data.pending.total_max),
            session_data.cycles.wo_finds_avg,
            session_data.cycles.wo_finds_min,
            session_data.cycles.wo_finds_max
        );

        Paragraph::new(content)
            .block(
                Block::default()
                    .title("Nerd Stats")
                    .borders(Borders::ALL)
                    .border_style(Style::default().add_modifier(Modifier::BOLD))
                    .title_style(Style::default().add_modifier(Modifier::BOLD)),
            )
            .style(Style::default())
    }

    /// Renders the logs section of the TUI
    fn render_logs(f: &mut Frame, session_data: &CampaignData, area: Rect) {
        let content = session_data.logs.join("\n", true);
        let paragraph = Paragraph::new(content)
            .block(
                Block::default()
                    .title("Logs")
                    .borders(Borders::ALL)
                    .border_style(Style::default().add_modifier(Modifier::BOLD))
                    .title_style(Style::default().add_modifier(Modifier::BOLD)),
            )
            .style(Style::default())
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, area);
    }

    /// Format a floating-point number in a more human readable representation
    fn format_float_to_hfloat(float_num: f64) -> String {
        if float_num < 1000.0 {
            format!("{float_num:.2}")
        } else if float_num < 1_000_000.0 {
            format!("{:.2}K", float_num / 1000.0)
        } else if float_num < 1_000_000_000.0 {
            format!("{:.2}M", float_num / 1_000_000.0)
        } else if float_num < 1_000_000_000_000.0 {
            format!("{:.2}B", float_num / 1_000_000_000.0)
        } else {
            format!("{:.2}T", float_num / 1_000_000_000_000.0)
        }
    }

    /// Format a integer in a more human readable representation
    // TODO: Merge with format_float_to_hfloat
    // TODO: Fix the clippy warnings regarding f64 conversion
    fn format_int_to_hint(int_num: usize) -> String {
        if int_num < 1000 {
            format!("{int_num}")
        } else if int_num < 1_000_000 {
            format!("{:.2}K", int_num as f64 / 1000.0)
        } else if int_num < 1_000_000_000 {
            format!("{:.2}M", int_num as f64 / 1_000_000.0)
        } else if int_num < 1_000_000_000_000 {
            format!("{:.2}B", int_num as f64 / 1_000_000_000.0)
        } else {
            format!("{:.2}T", int_num as f64 / 1_000_000_000_000.0)
        }
    }

    /// Formats the last event duration
    fn format_last_event(events: &[CrashInfoDetails], total_run_time: &Duration) -> String {
        events.first().map_or_else(
            || "N/A".to_string(),
            |event| {
                let event_time = (*total_run_time).checked_sub(Duration::from_millis(event.time));
                event_time.map_or_else(
                    || "N/A".to_string(),
                    |duration: std::time::Duration| format_duration(&duration),
                )
            },
        )
    }

    /// Format the solution time to a human readable representation
    fn format_solution_time(total_runtime: &Duration, solution_time: u64) -> String {
        let solution_duration = Duration::from_millis(solution_time);
        let time_ago = total_runtime.checked_sub(solution_duration);

        time_ago.map_or_else(
            || String::from("Solution found in the future"),
            |duration| {
                let seconds = duration.as_secs();
                let minutes = seconds / 60;
                let hours = minutes / 60;

                if hours > 0 {
                    if minutes % 60 > 0 {
                        format!("{hours} hour(s) {} minute(s) ago", minutes % 60)
                    } else {
                        format!("{hours} hour(s) ago")
                    }
                } else if minutes > 0 {
                    format!("{minutes} minute(s) ago")
                } else {
                    format!("{seconds} second(s) ago")
                }
            },
        )
    }

    /// Formats the solutions into a string
    fn format_solutions(total_run_time: &Duration, solutions: &[CrashInfoDetails]) -> String {
        let max_fuzzer_name_length = solutions
            .iter()
            .map(|s| s.fuzzer_name.len())
            .max()
            .map_or(0, |len| std::cmp::min(len, 25));

        let header = format!(
            "{:<width$} | {:<5} | {:<25} | {:<10} | {:<15} | {:<12} | {:<10}",
            "Fuzzer Name",
            "SIG",
            "TIME",
            "EXEC",
            "SRC",
            "OP",
            "REP",
            width = max_fuzzer_name_length
        );

        let separator = "-".repeat(header.len());

        let rows = solutions
            .iter()
            .map(|s| {
                let fuzzer_name = if s.fuzzer_name.len() > 25 {
                    format!("{}...", &s.fuzzer_name[..22])
                } else {
                    s.fuzzer_name.clone()
                };

                let src = if s.src.len() > 15 {
                    format!("{}...", &s.src[..12])
                } else {
                    s.src.clone()
                };

                format!(
                    "{:<width$} | {:<5} | {:<25} | {:<10} | {:<15} | {:<12} | {:<10}",
                    fuzzer_name,
                    s.sig.clone().unwrap_or_else(|| "-".to_string()),
                    Self::format_solution_time(total_run_time, s.time),
                    Self::format_int_to_hint(usize::try_from(s.execs).unwrap_or(0)),
                    src,
                    s.op,
                    s.rep,
                    width = max_fuzzer_name_length
                )
            })
            .collect::<Vec<String>>()
            .join("\n");

        format!("{header}\n{separator}\n{rows}")
    }
}
