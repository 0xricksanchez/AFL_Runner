pub mod data_collection;
pub mod session;

use anyhow::Result;
use std::io;
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::tui::data_collection::DataFetcher;
use crate::tui::session::{CampaignData, CrashInfoDetails};
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

// Constants moved to a dedicated section for better visibility
const SLOW_EXEC_PS_THRESHOLD: f64 = 250.0;
const CAUTION_STABILITY: f64 = 90.0;
const WARN_STABILITY: f64 = 75.0;
const ERROR_STABILITY: f64 = 60.0;
const KILO: f64 = 1_000.0;
const MEGA: f64 = KILO * KILO;
const GIGA: f64 = MEGA * KILO;
const TERA: f64 = GIGA * KILO;

/// Threshold markers for number formatting
#[derive(Debug)]
enum NumberScale {
    Base(f64),
    Kilo(f64),
    Mega(f64),
    Giga(f64),
    Tera(f64),
}

impl NumberScale {
    fn from_f64(num: f64) -> Self {
        match num {
            n if n < KILO => Self::Base(n),
            n if n < MEGA => Self::Kilo(n / KILO),
            n if n < GIGA => Self::Mega(n / MEGA),
            n if n < TERA => Self::Giga(n / GIGA),
            n => Self::Tera(n / TERA),
        }
    }

    fn format(&self) -> String {
        match self {
            Self::Base(n) => format!("{n:.2}"),
            Self::Kilo(n) => format!("{n:.2}K"),
            Self::Mega(n) => format!("{n:.2}M"),
            Self::Giga(n) => format!("{n:.2}B"),
            Self::Tera(n) => format!("{n:.2}T"),
        }
    }
}

/// Represents the TUI (Text User Interface)
pub struct Tui {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
}

impl Tui {
    /// Creates a new `Tui` instance
    ///
    /// # Errors
    /// Returns an error if the terminal backend cannot be created
    pub fn new() -> io::Result<Self> {
        let backend = CrosstermBackend::new(io::stdout());
        let terminal = Terminal::new(backend)?;
        Ok(Self { terminal })
    }

    /// Formats a duration into a string based on days, hours, minutes, and seconds
    pub fn format_duration(duration: &Duration) -> String {
        let total_secs = duration.as_secs();
        let (days, hours, mins, secs) = (
            total_secs / 86400,
            (total_secs % 86400) / 3600,
            (total_secs % 3600) / 60,
            total_secs % 60,
        );

        match (days, hours, mins) {
            (d, _, _) if d > 0 => format!("{d} days, {hours:02}:{mins:02}:{secs:02}"),
            (0, h, _) if h > 0 => format!("{h:02}:{mins:02}:{secs:02}"),
            (0, 0, m) if m > 0 => format!("{m:02}:{secs:02}"),
            _ => format!("{secs:02}s"),
        }
    }

    /// Runs the TUI standalone with the specified output directory
    ///
    /// # Errors
    /// Returns an error if the TUI fails to run
    pub fn run(output_dir: &Path, pid_file: Option<&Path>, cdata: &mut CampaignData) -> Result<()> {
        let output_dir = output_dir.to_path_buf();
        cdata.log("Initialized TUI");
        let mut dfetcher = DataFetcher::new(&output_dir, pid_file, cdata);

        let (tx, rx) = mpsc::channel();

        thread::spawn(move || loop {
            let session_data = dfetcher.collect_session_data().clone();
            if tx.send(session_data).is_err() {
                break;
            }
            thread::sleep(Duration::from_secs(1));
        });

        Self::new()
            .and_then(|mut tui| tui.run_internal(&rx))
            .map_err(|e| anyhow::anyhow!("Error running TUI: {e}"))
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
                Self::format_duration(&session_data.total_run_time)
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
                session_data.cycles.done.avg,
                session_data.cycles.done.min,
                session_data.cycles.done.max,
            )),
            Line::from(format!(
                "Crashes saved: {} ({}->{}<-{})",
                session_data.crashes.cum,
                session_data.crashes.min,
                session_data.crashes.avg,
                session_data.crashes.max,
            )),
            Line::from(format!(
                "Hangs saved: {} ({}->{}<-{})",
                session_data.hangs.cum,
                session_data.hangs.min,
                session_data.hangs.avg,
                session_data.hangs.max,
            )),
            Line::from(format!(
                "Corpus count: {} ({}->{}<-{})",
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
        let ps_cum_style = if session_data.executions.per_sec.cum < SLOW_EXEC_PS_THRESHOLD {
            Style::default().fg(Color::Red)
        } else {
            Style::default()
        };

        let ps_min_style = if session_data.executions.per_sec.min < SLOW_EXEC_PS_THRESHOLD {
            Style::default().fg(Color::Red)
        } else {
            Style::default()
        };

        let ps_avg_style = if session_data.executions.per_sec.avg < SLOW_EXEC_PS_THRESHOLD {
            Style::default().fg(Color::Red)
        } else {
            Style::default()
        };

        let ps_max_style = if session_data.executions.per_sec.max < SLOW_EXEC_PS_THRESHOLD {
            Style::default().fg(Color::Red)
        } else {
            Style::default()
        };

        let text = vec![
            Line::from(format!(
                "Execs: {} ({}->{}<-{})",
                Self::format_int_to_hint(session_data.executions.count.cum),
                Self::format_int_to_hint(session_data.executions.count.min),
                Self::format_int_to_hint(session_data.executions.count.avg),
                Self::format_int_to_hint(session_data.executions.count.max),
            )),
            Line::from(vec![
                Span::raw("Execs/s: "),
                Span::styled(
                    Self::format_float_to_hfloat(session_data.executions.per_sec.cum),
                    ps_cum_style,
                ),
                Span::raw(" ("),
                Span::styled(
                    Self::format_float_to_hfloat(session_data.executions.per_sec.min),
                    ps_min_style,
                ),
                Span::raw("->"),
                Span::styled(
                    Self::format_float_to_hfloat(session_data.executions.per_sec.avg),
                    ps_avg_style,
                ),
                Span::raw("<-"),
                Span::styled(
                    Self::format_float_to_hfloat(session_data.executions.per_sec.max),
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
            Self::format_int_to_hint(session_data.pending.favorites.cum),
            Self::format_int_to_hint(session_data.pending.favorites.min),
            Self::format_int_to_hint(session_data.pending.favorites.avg),
            Self::format_int_to_hint(session_data.pending.favorites.max),
            Self::format_int_to_hint(session_data.pending.total.cum),
            Self::format_int_to_hint(session_data.pending.total.min),
            Self::format_int_to_hint(session_data.pending.total.avg),
            Self::format_int_to_hint(session_data.pending.total.max),
            session_data.cycles.wo_finds.avg,
            session_data.cycles.wo_finds.min,
            session_data.cycles.wo_finds.max
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
        NumberScale::from_f64(float_num).format()
    }

    /// Format an integer in a more human readable representation
    fn format_int_to_hint(int_num: usize) -> String {
        #[allow(clippy::cast_precision_loss)]
        NumberScale::from_f64(int_num as f64).format()
    }

    /// Formats the last event duration
    fn format_last_event(events: &[CrashInfoDetails], total_run_time: &Duration) -> String {
        events
            .first()
            .and_then(|event| total_run_time.checked_sub(Duration::from_millis(event.time)))
            .map_or_else(
                || "N/A".to_string(),
                |duration| Self::format_duration(&duration),
            )
    }

    /// Format the solution time to a human readable representation
    fn format_solution_time(total_runtime: &Duration, solution_time: u64) -> String {
        let solution_duration = Duration::from_millis(solution_time);
        total_runtime.checked_sub(solution_duration).map_or_else(
            || String::from("Solution found in the future"),
            |duration| {
                let secs = duration.as_secs();
                let mins = secs / 60;
                let hours = mins / 60;

                match (hours, mins % 60) {
                    (h, m) if h > 0 && m > 0 => format!("{h} hour(s) {m} minute(s) ago"),
                    (h, 0) if h > 0 => format!("{h} hour(s) ago"),
                    (0, m) if m > 0 => format!("{m} minute(s) ago"),
                    _ => format!("{secs} second(s) ago"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{path::PathBuf, time::Duration};

    // Helper function to create a sample CrashInfoDetails
    fn create_crash_info(time: u64, fuzzer_name: &str) -> CrashInfoDetails {
        CrashInfoDetails {
            fuzzer_name: fuzzer_name.to_string(),
            file_path: PathBuf::from("crash1"),
            id: "id1".to_string(),
            time,
            sig: Some("SIGSEGV".to_string()),
            execs: 1000,
            src: "src/main.rs".to_string(),
            op: "havoc".to_string(),
            rep: 2,
        }
    }

    #[test]
    fn test_number_scale_classification() {
        assert!(matches!(NumberScale::from_f64(100.0), NumberScale::Base(_)));
        assert!(matches!(
            NumberScale::from_f64(1500.0),
            NumberScale::Kilo(_)
        ));
        assert!(matches!(
            NumberScale::from_f64(1_500_000.0),
            NumberScale::Mega(_)
        ));
        assert!(matches!(
            NumberScale::from_f64(1_500_000_000.0),
            NumberScale::Giga(_)
        ));
        assert!(matches!(
            NumberScale::from_f64(1_500_000_000_000.0),
            NumberScale::Tera(_)
        ));
    }

    #[test]
    fn test_number_scale_formatting() {
        let cases = vec![
            (100.0, "100.00"),
            (1500.0, "1.50K"),
            (1_500_000.0, "1.50M"),
            (1_500_000_000.0, "1.50B"),
            (1_500_000_000_000.0, "1.50T"),
        ];

        for (input, expected) in cases {
            assert_eq!(NumberScale::from_f64(input).format(), expected);
        }
    }

    #[test]
    fn test_format_float_to_hfloat() {
        let test_cases = vec![
            (0.0, "0.00"),
            (999.99, "999.99"),
            (1000.0, "1.00K"),
            (1234.5678, "1.23K"),
            (1_000_000.0, "1.00M"),
            (1_234_567.89, "1.23M"),
            (1_000_000_000.0, "1.00B"),
            (1_234_567_890.12, "1.23B"),
            (1_000_000_000_000.0, "1.00T"),
        ];

        for (input, expected) in test_cases {
            assert_eq!(Tui::format_float_to_hfloat(input), expected);
        }
    }

    #[test]
    fn test_format_int_to_hint() {
        let test_cases = vec![
            (0, "0.00"),
            (999, "999.00"),
            (1000, "1.00K"),
            (1234, "1.23K"),
            (1_000_000, "1.00M"),
            (1_234_567, "1.23M"),
            (1_000_000_000, "1.00B"),
            (1_234_567_890, "1.23B"),
            (1_000_000_000_000, "1.00T"),
        ];

        for (input, expected) in test_cases {
            assert_eq!(Tui::format_int_to_hint(input), expected);
        }
    }

    #[test]
    fn test_format_duration() {
        let test_cases = vec![
            (30, "30s"),
            (60, "01:00"),
            (90, "01:30"),
            (3600, "01:00:00"),
            (3661, "01:01:01"),
            (86400, "1 days, 00:00:00"),
            (90061, "1 days, 01:01:01"),
        ];

        for (seconds, expected) in test_cases {
            let duration = Duration::from_secs(seconds);
            assert_eq!(Tui::format_duration(&duration), expected);
        }
    }

    #[test]
    fn test_format_last_event() {
        let total_runtime = Duration::from_secs(3600); // 1 hour

        // Test with empty events
        let empty_events: Vec<CrashInfoDetails> = vec![];
        assert_eq!(Tui::format_last_event(&empty_events, &total_runtime), "N/A");

        // Test with recent event (3500 seconds = 58:20 remaining)
        let recent_events = vec![create_crash_info(3500000, "fuzzer1")]; // 3500 seconds
        assert_eq!(
            Tui::format_last_event(&recent_events, &total_runtime),
            "01:40"
        );

        // Test with future event (should return N/A)
        let future_events = vec![create_crash_info(4000000, "fuzzer1")]; // 4000 seconds
        assert_eq!(
            Tui::format_last_event(&future_events, &total_runtime),
            "N/A"
        );
    }

    #[test]
    fn test_format_solution_time() {
        let total_runtime = Duration::from_secs(7200); // 2 hours

        let test_cases = vec![
            // 7200 - 7000 = 200 seconds = ~3.33 minutes ago
            (7000000, "3 minute(s) ago"),
            // 7200 - 3600 = 3600 seconds = 1 hour ago
            (3600000, "1 hour(s) ago"),
            // 7200 - 5400 = 1800 seconds = 30 minutes ago
            (5400000, "30 minute(s) ago"),
            // Current time
            (7200000, "0 second(s) ago"),
            // Future time
            (7300000, "Solution found in the future"),
        ];

        for (solution_time, expected) in test_cases {
            assert_eq!(
                Tui::format_solution_time(&total_runtime, solution_time),
                expected,
                "Failed for solution_time: {}",
                solution_time
            );
        }
    }

    // Batch testing for number formatting consistency
    #[test]
    fn test_number_formatting_consistency() {
        // Test that integer and float formatting are consistent
        let test_cases = vec![
            (1000, 1000.0),
            (1_000_000, 1_000_000.0),
            (1_000_000_000, 1_000_000_000.0),
        ];

        for (int_val, float_val) in test_cases {
            assert_eq!(
                Tui::format_int_to_hint(int_val),
                Tui::format_float_to_hfloat(float_val),
                "Mismatch between int and float formatting for value: {}",
                int_val
            );
        }
    }
}
