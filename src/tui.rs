use std::io;
use std::sync::mpsc;
use std::time::Duration;

use crate::session::{CrashInfoDetails, SessionData};
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

pub fn run_tui(session_data_rx: mpsc::Receiver<SessionData>) -> io::Result<()> {
    let stdout = io::stdout();
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    terminal.clear()?;
    enable_raw_mode()?;
    crossterm::execute!(terminal.backend_mut(), EnterAlternateScreen)?;

    loop {
        if let Ok(session_data) = session_data_rx.recv_timeout(Duration::from_millis(500)) {
            terminal.draw(|f| {
                let title = create_title(&session_data);
                let main_chunks = create_main_layout(f.size());
                f.render_widget(title, main_chunks[0]);

                let inner_chunks = create_inner_layout(main_chunks[1]);
                render_process_timings_and_overall_results(f, &session_data, inner_chunks[0]);
                render_stage_progress_and_nerd_stats(f, &session_data, inner_chunks[1]);
                render_crash_solutions(f, &session_data, inner_chunks[2]);
                render_hang_solutions(f, &session_data, inner_chunks[3]);
            })?;
        }

        if crossterm::event::poll(Duration::from_millis(200))? {
            if let crossterm::event::Event::Key(_) = crossterm::event::read()? {
                break;
            }
        }
    }

    disable_raw_mode()?;
    crossterm::execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.clear()?;
    terminal.show_cursor()?;

    Ok(())
}

fn create_title(session_data: &SessionData) -> Paragraph {
    Paragraph::new(format!(
        "AFL {} - {} - Fuzzing campaign runner by @0xricksanchez",
        session_data.misc.afl_version, session_data.misc.afl_banner
    ))
    .alignment(Alignment::Center)
    .style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )
}

fn create_main_layout(size: Rect) -> Vec<Rect> {
    Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([Constraint::Length(1), Constraint::Min(0)].as_ref())
        .split(size)
        .to_vec()
}

fn create_inner_layout(area: Rect) -> Vec<Rect> {
    Layout::default()
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
        .split(area)
        .to_vec()
}

fn render_process_timings_and_overall_results(
    f: &mut Frame,
    session_data: &SessionData,
    area: Rect,
) {
    let hor_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)])
        .split(area);

    let p_proc_timings = create_process_timings_paragraph(session_data);
    let p_overall_res = create_overall_results_paragraph(session_data);

    f.render_widget(p_proc_timings, hor_layout[0]);
    f.render_widget(p_overall_res, hor_layout[1]);
}

fn render_stage_progress_and_nerd_stats(f: &mut Frame, session_data: &SessionData, area: Rect) {
    let hor_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)])
        .split(area);

    let p_stage_prog = create_stage_progress_paragraph(session_data);
    let p_nerd_stats = create_nerd_stats_paragraph(session_data);

    f.render_widget(p_stage_prog, hor_layout[0]);
    f.render_widget(p_nerd_stats, hor_layout[1]);
}

fn render_crash_solutions(f: &mut Frame, session_data: &SessionData, area: Rect) {
    let p_crash_solutions = Paragraph::new(format_solutions(&session_data.last_crashes))
        .block(
            Block::default()
                .title("10 Latest Crashes")
                .borders(Borders::ALL)
                .border_style(Style::default()),
        )
        .style(Style::default());

    f.render_widget(p_crash_solutions, area);
}

fn render_hang_solutions(f: &mut Frame, session_data: &SessionData, area: Rect) {
    let p_hang_solutions = Paragraph::new(format_solutions(&session_data.last_hangs))
        .block(
            Block::default()
                .title("10 Latest Hangs")
                .borders(Borders::ALL)
                .border_style(Style::default()),
        )
        .style(Style::default());

    f.render_widget(p_hang_solutions, area);
}

fn create_process_timings_paragraph(session_data: &SessionData) -> Paragraph {
    let last_seen_crash =
        format_last_event(&session_data.last_crashes, &session_data.total_run_time);
    let last_seen_hang = format_last_event(&session_data.last_hangs, &session_data.total_run_time);

    let content = format!(
        "Fuzzers alive: {}
Total run time: {}
Time without finds: {}
Last saved crash: {}
Last saved hang: {}",
        session_data.fuzzers_alive,
        format_duration(session_data.total_run_time),
        format_duration(session_data.time_without_finds),
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

fn create_overall_results_paragraph(session_data: &SessionData) -> Paragraph {
    let content = format!(
        "Cycles done: {} ({}/{})
Crashes saved: {} ({}->{}<-{})
Hangs saved: {} ({}->{}<-{})
Corpus count: {} ({}->{}<-{})",
        session_data.cycles.done_avg,
        session_data.cycles.done_min,
        session_data.cycles.done_max,
        session_data.crashes.saved_cum,
        session_data.crashes.saved_min,
        session_data.crashes.saved_avg,
        session_data.crashes.saved_max,
        session_data.hangs.saved_cum,
        session_data.hangs.saved_min,
        session_data.hangs.saved_avg,
        session_data.hangs.saved_max,
        session_data.corpus.count_cum,
        session_data.corpus.count_min,
        session_data.corpus.count_avg,
        session_data.corpus.count_max
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

fn create_stage_progress_paragraph(session_data: &SessionData) -> Paragraph {
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
        session_data.coverage.bitmap_avg,
        session_data.coverage.bitmap_min,
        session_data.coverage.bitmap_max,
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

fn create_nerd_stats_paragraph(session_data: &SessionData) -> Paragraph {
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

fn format_last_event(events: &[CrashInfoDetails], total_run_time: &Duration) -> String {
    if !events.is_empty() {
        let event_time = *total_run_time - Duration::from_millis(events[0].time);
        format_duration(event_time)
    } else {
        "N/A".to_string()
    }
}

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

fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs();
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    let secs = secs % 60;

    format!("{} days, {:02}:{:02}:{:02}", days, hours, mins, secs)
}
