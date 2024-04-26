use anyhow::Result;
use std::io;
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::data_collection::DataFetcher;
use crate::session::{CampaignData, CrashInfoDetails};
use anyhow::bail;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    prelude::*,
    style::{Color, Style},
    widgets::{Block, Borders, Paragraph},
    Terminal,
};

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
    pub fn run(output_dir: &Path, pid_file: Option<&Path>) -> Result<()> {
        let output_dir = output_dir.to_path_buf();
        let mut dfetcher = DataFetcher::new(&output_dir, pid_file);
        let (session_data_tx, session_data_rx) = mpsc::channel();
        thread::spawn(move || loop {
            let session_data = dfetcher.collect_session_data().clone();
            if let Err(e) = session_data_tx.send(session_data) {
                eprintln!("Error sending session data: {e}");
                break;
            }
            thread::sleep(Duration::from_millis(500));
        });

        if let Err(e) = Self::new().and_then(|mut tui| tui.run_internal(&session_data_rx)) {
            bail!("Error running TUI: {e}");
        }
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
                if let crossterm::event::Event::Key(_) = crossterm::event::read()? {
                    break;
                }
            }
        }

        disable_raw_mode()?;
        crossterm::execute!(self.terminal.backend_mut(), LeaveAlternateScreen)?;
        self.terminal.clear()?;
        self.terminal.show_cursor()?;

        Ok(())
    }

    /// Draws the TUI with the specified session data
    fn draw(&mut self, session_data: &CampaignData) -> io::Result<()> {
        self.terminal.draw(|f| {
            let chunks = Self::create_layout(f.size());
            Self::render_title(f, session_data, chunks[0]);
            Self::render_process_timings_and_overall_results(f, session_data, chunks[1]);
            Self::render_stage_progress_and_nerd_stats(f, session_data, chunks[2]);
            Self::render_crash_solutions(f, session_data, chunks[3]);
            Self::render_hang_solutions(f, session_data, chunks[4]);
        })?;
        Ok(())
    }

    /// Creates the layout for the TUI
    fn create_layout(size: Rect) -> Vec<Rect> {
        let main_layout = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([Constraint::Length(1), Constraint::Min(0)].as_ref())
            .split(size);

        let inner_layout = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints(
                [
                    Constraint::Percentage(15),
                    Constraint::Percentage(10),
                    Constraint::Percentage(30),
                    Constraint::Percentage(30),
                ]
                .as_ref(),
            )
            .split(main_layout[1]);

        [
            main_layout[0],
            inner_layout[0],
            inner_layout[1],
            inner_layout[2],
            inner_layout[3],
        ]
        .to_vec()
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

    /// Renders the process timings and overall results section of the TUI
    fn render_process_timings_and_overall_results(
        f: &mut Frame,
        session_data: &CampaignData,
        area: Rect,
    ) {
        let hor_layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)])
            .split(area);

        let p_proc_timings = Self::create_process_timings_paragraph(session_data);
        let p_overall_res = Self::create_overall_results_paragraph(session_data);

        f.render_widget(p_proc_timings, hor_layout[0]);
        f.render_widget(p_overall_res, hor_layout[1]);
    }

    /// Renders the stage progress and nerd stats section of the TUI
    fn render_stage_progress_and_nerd_stats(
        f: &mut Frame,
        session_data: &CampaignData,
        area: Rect,
    ) {
        let hor_layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)])
            .split(area);

        let p_stage_prog = Self::create_stage_progress_paragraph(session_data);
        let p_nerd_stats = Self::create_nerd_stats_paragraph(session_data);

        f.render_widget(p_stage_prog, hor_layout[0]);
        f.render_widget(p_nerd_stats, hor_layout[1]);
    }

    /// Renders the crash solutions section of the TUI
    fn render_crash_solutions(f: &mut Frame, session_data: &CampaignData, area: Rect) {
        let p_crash_solutions = Paragraph::new(Self::format_solutions(&session_data.last_crashes))
            .block(
                Block::default()
                    .title("10 Latest Crashes")
                    .borders(Borders::ALL)
                    .border_style(Style::default()),
            )
            .style(Style::default());

        f.render_widget(p_crash_solutions, area);
    }

    /// Renders the hang solutions section of the TUI
    fn render_hang_solutions(f: &mut Frame, session_data: &CampaignData, area: Rect) {
        let p_hang_solutions = Paragraph::new(Self::format_solutions(&session_data.last_hangs))
            .block(
                Block::default()
                    .title("10 Latest Hangs")
                    .borders(Borders::ALL)
                    .border_style(Style::default()),
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

        // TODO: Check if fuzzers are actually alive and report back when >1 was lost (warning)
        // TODO: If all fuzzers are dead display an error and stop `total_run_time`

        let content = format!(
            "Fuzzers alive: {}/{}
Total run time: {}
Time without finds: {}
Last saved crash: {}
Last saved hang: {}",
            session_data.fuzzers_alive,
            session_data.fuzzers_started,
            Self::format_duration(session_data.total_run_time),
            Self::format_duration(session_data.time_without_finds),
            last_seen_crash,
            last_seen_hang
        );

        Paragraph::new(content)
            .block(
                Block::default()
                    .title("Process timing")
                    .borders(Borders::ALL)
                    .add_modifier(Modifier::BOLD),
            )
            .style(Style::default())
    }

    /// Creates the overall results paragraph
    fn create_overall_results_paragraph(session_data: &CampaignData) -> Paragraph {
        let content = format!(
            "Cycles done: {} ({}/{})
Crashes saved: {} ({}->{}<-{})
Hangs saved: {} ({}->{}<-{})
Corpus count: {} ({}->{}<-{})",
            session_data.cycles.done_avg,
            session_data.cycles.done_min,
            session_data.cycles.done_max,
            session_data.crashes.cum,
            session_data.crashes.min,
            session_data.crashes.avg,
            session_data.crashes.max,
            session_data.hangs.cum,
            session_data.hangs.min,
            session_data.hangs.avg,
            session_data.hangs.max,
            session_data.corpus.cum,
            session_data.corpus.min,
            session_data.corpus.avg,
            session_data.corpus.max
        );

        Paragraph::new(content)
            .block(
                Block::default()
                    .title("Overall results")
                    .borders(Borders::ALL)
                    .add_modifier(Modifier::BOLD),
            )
            .style(Style::default())
    }

    /// Creates the stage progress paragraph
    fn create_stage_progress_paragraph(session_data: &CampaignData) -> Paragraph {
        let content = format!(
            "Execs: {} ({}->{}<-{})
Execs/s: {:.2} ({:.2}->{:.2}<-{:.2}),
Coverage: {:.2}% ({:.2}%/{:.2}%)",
            session_data.executions.cum,
            session_data.executions.min,
            session_data.executions.avg,
            session_data.executions.max,
            session_data.executions.ps_cum,
            session_data.executions.ps_min,
            session_data.executions.ps_avg,
            session_data.executions.ps_max,
            session_data.coverage.avg,
            session_data.coverage.min,
            session_data.coverage.max,
        );

        Paragraph::new(content)
            .block(
                Block::default()
                    .title("Stage Progress")
                    .borders(Borders::ALL)
                    .add_modifier(Modifier::BOLD),
            )
            .style(Style::default())
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
            session_data.pending.favorites_cum,
            session_data.pending.favorites_min,
            session_data.pending.favorites_avg,
            session_data.pending.favorites_max,
            session_data.pending.total_cum,
            session_data.pending.total_min,
            session_data.pending.total_avg,
            session_data.pending.total_max,
            session_data.cycles.wo_finds_avg,
            session_data.cycles.wo_finds_min,
            session_data.cycles.wo_finds_max
        );

        Paragraph::new(content)
            .block(Block::default().title("Nerd Stats").borders(Borders::ALL))
            .style(Style::default())
    }

    /// Formats the last event duration
    fn format_last_event(events: &[CrashInfoDetails], total_run_time: &Duration) -> String {
        if events.is_empty() {
            "N/A".to_string()
        } else {
            let event_time = *total_run_time - Duration::from_millis(events[0].time);
            Self::format_duration(event_time)
        }
    }

    /// Formats the solutions into a string
    fn format_solutions(solutions: &[CrashInfoDetails]) -> String {
        solutions
            .iter()
            .map(|s| {
                format!(
                    "{} | SIG: {} | TIME: {} | EXEC: {} | SRC: {} | OP: {} | REP: {}",
                    s.fuzzer_name,
                    s.sig.clone().unwrap_or_else(|| "-".to_string()),
                    s.time,
                    s.execs,
                    s.src,
                    s.op,
                    s.rep
                )
            })
            .collect::<Vec<String>>()
            .join("\n")
    }

    /// Formats a duration into a string
    fn format_duration(duration: Duration) -> String {
        let mut secs = duration.as_secs();
        let days = secs / 86400;
        let hours = (secs % 86400) / 3600;
        let mins = (secs % 3600) / 60;
        secs %= 60;

        format!("{days} days, {hours:02}:{mins:02}:{secs:02}")
    }
}
