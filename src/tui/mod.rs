use crate::cli::WatchOptions;
use crate::config::Config;
use crate::modules::{
    file_integrity::FileIntegrityScanner, log_analyzer::LogAnalyzer,
    network_hunter::NetworkHunter, process_scanner::ProcessScanner, ScanResult, Severity,
};
use anyhow::Result;
use chrono::Utc;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Line, Span},
    widgets::{
        Block, Borders, Cell, Clear, Gauge, List, ListItem, ListState, Paragraph, Row,
        Scrollbar, ScrollbarOrientation, ScrollbarState, Table, TableState, Tabs, Wrap,
    },
    Frame, Terminal,
};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
// tokio interval not used; we use std::time::Instant for auto-scan tracking

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TabIndex {
    Dashboard = 0,
    Processes = 1,
    Files = 2,
    Logs = 3,
    Network = 4,
    Findings = 5,
}

pub struct AppState {
    pub tab: TabIndex,
    pub findings: Vec<ScanResult>,
    pub scan_in_progress: bool,
    pub last_scan: Option<chrono::DateTime<Utc>>,
    pub scan_progress: u16,
    pub table_state: TableState,
    pub list_state: ListState,
    pub scroll_offset: u16,
    pub selected_finding: Option<usize>,
    pub show_detail: bool,
    pub threat_counts: [u32; 5], // Critical, High, Medium, Low, Info
    pub system_info: SystemInfo,
    pub should_quit: bool,
    pub status_message: String,
    pub filter_severity: Option<Severity>,
}

#[derive(Debug, Clone, Default)]
pub struct SystemInfo {
    pub hostname: String,
    pub kernel: String,
    pub uptime: String,
    pub cpu_count: usize,
}

impl Default for AppState {
    fn default() -> Self {
        let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap_or_default()
            .trim()
            .to_string();
        let kernel = std::fs::read_to_string("/proc/version")
            .unwrap_or_default()
            .split_whitespace()
            .take(3)
            .collect::<Vec<_>>()
            .join(" ");
        let uptime_secs: f64 = std::fs::read_to_string("/proc/uptime")
            .unwrap_or_default()
            .split_whitespace()
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0.0);
        let hours = (uptime_secs / 3600.0) as u64;
        let mins = ((uptime_secs % 3600.0) / 60.0) as u64;

        let cpu_count = std::fs::read_to_string("/proc/cpuinfo")
            .unwrap_or_default()
            .lines()
            .filter(|l| l.starts_with("processor"))
            .count();

        Self {
            tab: TabIndex::Dashboard,
            findings: Vec::new(),
            scan_in_progress: false,
            last_scan: None,
            scan_progress: 0,
            table_state: TableState::default(),
            list_state: ListState::default(),
            scroll_offset: 0,
            selected_finding: None,
            show_detail: false,
            threat_counts: [0u32; 5],
            system_info: SystemInfo {
                hostname,
                kernel,
                uptime: format!("{}h {}m", hours, mins),
                cpu_count,
            },
            should_quit: false,
            status_message: "Press 's' to start scan | 'q' to quit | Tab to switch views".into(),
            filter_severity: None,
        }
    }
}

impl AppState {
    pub fn update_threat_counts(&mut self) {
        self.threat_counts = [0u32; 5];
        for f in &self.findings {
            match f.severity {
                Severity::Critical => self.threat_counts[0] += 1,
                Severity::High => self.threat_counts[1] += 1,
                Severity::Medium => self.threat_counts[2] += 1,
                Severity::Low => self.threat_counts[3] += 1,
                Severity::Info => self.threat_counts[4] += 1,
            }
        }
    }

    pub fn visible_findings(&self) -> Vec<&ScanResult> {
        self.findings
            .iter()
            .filter(|f| {
                if let Some(ref sev) = self.filter_severity {
                    &f.severity == sev
                } else {
                    !matches!(f.severity, Severity::Info)
                }
            })
            .collect()
    }

    pub fn next_row(&mut self) {
        let len = self.visible_findings().len();
        if len == 0 {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) => (i + 1) % len,
            None => 0,
        };
        self.table_state.select(Some(i));
        self.selected_finding = Some(i);
    }

    pub fn prev_row(&mut self) {
        let len = self.visible_findings().len();
        if len == 0 {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) => if i == 0 { len - 1 } else { i - 1 },
            None => 0,
        };
        self.table_state.select(Some(i));
        self.selected_finding = Some(i);
    }
}

pub async fn run_tui(opts: &WatchOptions, cfg: &Config) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let state = Arc::new(Mutex::new(AppState::default()));
    let tick_rate = Duration::from_millis(250);
    let auto_scan_secs = Duration::from_secs(opts.interval);
    // Trigger first scan immediately on startup
    let mut last_auto_scan = Instant::now()
        .checked_sub(auto_scan_secs)
        .unwrap_or_else(Instant::now);

    loop {
        // Render frame
        {
            let mut s = state.lock().unwrap();
            terminal.draw(|f| render_frame(f, &mut s))?;
        }

        // Poll keyboard events with short timeout to stay responsive
        let timeout = tick_rate;
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                let mut s = state.lock().unwrap();
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => {
                        if s.show_detail {
                            s.show_detail = false;
                        } else {
                            s.should_quit = true;
                        }
                    }
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        s.should_quit = true;
                    }
                    KeyCode::Tab => {
                        s.tab = match s.tab {
                            TabIndex::Dashboard => TabIndex::Processes,
                            TabIndex::Processes => TabIndex::Files,
                            TabIndex::Files => TabIndex::Logs,
                            TabIndex::Logs => TabIndex::Network,
                            TabIndex::Network => TabIndex::Findings,
                            TabIndex::Findings => TabIndex::Dashboard,
                        };
                    }
                    KeyCode::Char('1') => s.tab = TabIndex::Dashboard,
                    KeyCode::Char('2') => s.tab = TabIndex::Processes,
                    KeyCode::Char('3') => s.tab = TabIndex::Files,
                    KeyCode::Char('4') => s.tab = TabIndex::Logs,
                    KeyCode::Char('5') => s.tab = TabIndex::Network,
                    KeyCode::Char('6') => s.tab = TabIndex::Findings,
                    KeyCode::Down | KeyCode::Char('j') => s.next_row(),
                    KeyCode::Up | KeyCode::Char('k') => s.prev_row(),
                    KeyCode::Enter => {
                        if s.selected_finding.is_some() {
                            s.show_detail = !s.show_detail;
                        }
                    }
                    KeyCode::Char('s') => {
                        if !s.scan_in_progress {
                            s.scan_in_progress = true;
                            s.scan_progress = 0;
                            s.status_message = "Scanning...".into();
                            drop(s);
                            let state_clone = Arc::clone(&state);
                            let cfg_clone = cfg.clone();
                            tokio::spawn(async move {
                                do_scan(state_clone, cfg_clone).await;
                            });
                        }
                    }
                    KeyCode::Char('f') => {
                        let mut s = state.lock().unwrap();
                        s.filter_severity = match s.filter_severity {
                            None => Some(Severity::Critical),
                            Some(Severity::Critical) => Some(Severity::High),
                            Some(Severity::High) => Some(Severity::Medium),
                            Some(Severity::Medium) => Some(Severity::Low),
                            Some(Severity::Low) | Some(Severity::Info) => None,
                        };
                    }
                    _ => {}
                }
            }
        }

        // Check quit flag
        if state.lock().unwrap().should_quit {
            break;
        }

        // Auto-scan on configurable interval using Instant tracking (no tokio::interval needed)
        if last_auto_scan.elapsed() >= auto_scan_secs {
            last_auto_scan = Instant::now();
            let s = state.lock().unwrap();
            if !s.scan_in_progress {
                drop(s);
                let state_clone = Arc::clone(&state);
                let cfg_clone = cfg.clone();
                tokio::spawn(async move {
                    do_scan(state_clone, cfg_clone).await;
                });
            }
        }
    }

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    Ok(())
}

async fn do_scan(state: Arc<Mutex<AppState>>, cfg: Config) {
    let mut all_findings = Vec::new();

    {
        let mut s = state.lock().unwrap();
        s.scan_progress = 10;
    }

    if let Ok(f) = ProcessScanner::new(cfg.clone()).scan().await {
        all_findings.extend(f);
    }

    {
        let mut s = state.lock().unwrap();
        s.scan_progress = 35;
    }

    if let Ok(f) = FileIntegrityScanner::new(cfg.clone()).scan().await {
        all_findings.extend(f);
    }

    {
        let mut s = state.lock().unwrap();
        s.scan_progress = 60;
    }

    if let Ok(f) = LogAnalyzer::new(cfg.clone()).scan().await {
        all_findings.extend(f);
    }

    {
        let mut s = state.lock().unwrap();
        s.scan_progress = 85;
    }

    if let Ok(f) = NetworkHunter::new(cfg.clone()).scan().await {
        all_findings.extend(f);
    }

    let mut s = state.lock().unwrap();
    s.findings = all_findings;
    s.update_threat_counts();
    s.scan_in_progress = false;
    s.scan_progress = 100;
    s.last_scan = Some(Utc::now());
    s.status_message = format!(
        "Scan complete: {} findings | Press 'j/k' to navigate | 'Enter' for detail | 'f' to filter",
        s.findings.len()
    );
}

fn render_frame(f: &mut Frame, state: &mut AppState) {
    let area = f.size();

    // Main layout
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header
            Constraint::Length(3),  // Tabs
            Constraint::Min(0),     // Content
            Constraint::Length(3),  // Status bar
        ])
        .split(area);

    render_header(f, chunks[0], state);
    render_tabs(f, chunks[1], state);

    match state.tab {
        TabIndex::Dashboard => render_dashboard(f, chunks[2], state),
        TabIndex::Processes => render_findings_table(f, chunks[2], state, "Process"),
        TabIndex::Files => render_findings_table(f, chunks[2], state, "FileIntegrity"),
        TabIndex::Logs => render_findings_table(f, chunks[2], state, "LogAnalyzer"),
        TabIndex::Network => render_findings_table(f, chunks[2], state, "Network"),
        TabIndex::Findings => render_all_findings(f, chunks[2], state),
    }

    render_status_bar(f, chunks[3], state);

    if state.show_detail {
        if let Some(idx) = state.selected_finding {
            let findings = state.visible_findings();
            if let Some(finding) = findings.get(idx) {
                render_detail_popup(f, area, finding);
            }
        }
    }

    if state.scan_in_progress {
        render_scan_progress(f, area, state.scan_progress);
    }
}

fn render_header(f: &mut Frame, area: Rect, state: &AppState) {
    let title = format!(
        " ⚡ LTHF — Linux Threat Hunter  │  Host: {}  │  Kernel: {}  │  {}",
        state.system_info.hostname,
        state.system_info.kernel.chars().take(30).collect::<String>(),
        state.last_scan.map(|t| format!("Last scan: {}", t.format("%H:%M:%S"))).unwrap_or_else(|| "Not scanned yet".into())
    );

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(Span::styled(
            " Linux Threat Hunting Framework v1.0 ",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ));

    let paragraph = Paragraph::new(title)
        .block(block)
        .style(Style::default().fg(Color::White));
    f.render_widget(paragraph, area);
}

fn render_tabs(f: &mut Frame, area: Rect, state: &AppState) {
    let titles = vec![
        " Dashboard [1]",
        " Processes [2]",
        " Files [3]",
        " Logs [4]",
        " Network [5]",
        " All Findings [6]",
    ];

    let selected = state.tab as usize;
    let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Blue)))
        .style(Style::default().fg(Color::Gray))
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
                .bg(Color::DarkGray),
        )
        .select(selected)
        .divider(symbols::line::VERTICAL);

    f.render_widget(tabs, area);
}

fn render_dashboard(f: &mut Frame, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(9),
            Constraint::Min(0),
        ])
        .split(area);

    // Threat summary row
    let summary_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
        ])
        .split(chunks[0]);

    let severities = [
        ("CRITICAL", state.threat_counts[0], Color::Red),
        ("HIGH", state.threat_counts[1], Color::LightRed),
        ("MEDIUM", state.threat_counts[2], Color::Yellow),
        ("LOW", state.threat_counts[3], Color::Blue),
        ("INFO", state.threat_counts[4], Color::Gray),
    ];

    for (i, (label, count, color)) in severities.iter().enumerate() {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(*color))
            .title(Span::styled(
                format!(" {} ", label),
                Style::default().fg(*color).add_modifier(Modifier::BOLD),
            ));

        let text = Paragraph::new(count.to_string())
            .block(block)
            .style(Style::default().fg(*color).add_modifier(Modifier::BOLD))
            .alignment(Alignment::Center);
        f.render_widget(text, summary_chunks[i]);
    }

    // Recent findings list
    let visible = state.visible_findings();
    let items: Vec<ListItem> = visible
        .iter()
        .take(20)
        .map(|f| {
            let (sev_str, color) = match f.severity {
                Severity::Critical => ("CRIT", Color::Red),
                Severity::High => ("HIGH", Color::LightRed),
                Severity::Medium => ("MED ", Color::Yellow),
                Severity::Low => ("LOW ", Color::Blue),
                Severity::Info => ("INFO", Color::Gray),
            };
            let line = Line::from(vec![
                Span::styled(
                    format!("[{}] ", sev_str),
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("[{}] ", f.category),
                    Style::default().fg(Color::Cyan),
                ),
                Span::raw(if f.title.len() > 80 {
                    format!("{}…", &f.title[..79])
                } else {
                    f.title.clone()
                }),
            ]);
            ListItem::new(line)
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Blue))
                .title(Span::styled(
                    " Recent Findings (press '6' for full list) ",
                    Style::default().fg(Color::White),
                )),
        )
        .highlight_style(Style::default().bg(Color::DarkGray));

    f.render_widget(list, chunks[1]);
}

fn render_findings_table(f: &mut Frame, area: Rect, state: &mut AppState, category: &str) {
    let visible: Vec<&ScanResult> = state.findings
        .iter()
        .filter(|f| f.category == category)
        .collect();

    let header_cells = ["Score", "Severity", "Title", "MITRE ATT&CK"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).height(1).bottom_margin(1);

    let rows: Vec<Row> = visible.iter().map(|f| {
        let color = match f.severity {
            Severity::Critical => Color::Red,
            Severity::High => Color::LightRed,
            Severity::Medium => Color::Yellow,
            Severity::Low => Color::Blue,
            Severity::Info => Color::Gray,
        };

        let title = if f.title.len() > 70 { format!("{}…", &f.title[..69]) } else { f.title.clone() };

        Row::new(vec![
            Cell::from(f.threat_score.to_string()).style(Style::default().fg(color).add_modifier(Modifier::BOLD)),
            Cell::from(format!("{}", f.severity)).style(Style::default().fg(color)),
            Cell::from(title),
            Cell::from(f.mitre_technique.as_deref().unwrap_or("-")).style(Style::default().fg(Color::DarkGray)),
        ])
    }).collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(6),
            Constraint::Length(10),
            Constraint::Min(40),
            Constraint::Length(35),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Blue))
            .title(Span::styled(
                format!(" {} Findings ({}) — ↑↓ navigate, Enter for detail ", category, visible.len()),
                Style::default().fg(Color::White),
            )),
    )
    .highlight_style(Style::default().bg(Color::DarkGray));

    f.render_stateful_widget(table, area, &mut state.table_state);
}

fn render_all_findings(f: &mut Frame, area: Rect, state: &mut AppState) {
    let visible = state.visible_findings();

    let filter_label = state.filter_severity.as_ref()
        .map(|s| format!(" [Filter: {}]", s))
        .unwrap_or_default();

    let header_cells = ["Score", "Sev", "Category", "Title"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).height(1).bottom_margin(1);

    let rows: Vec<Row> = visible.iter().map(|f| {
        let color = match f.severity {
            Severity::Critical => Color::Red,
            Severity::High => Color::LightRed,
            Severity::Medium => Color::Yellow,
            Severity::Low => Color::Blue,
            Severity::Info => Color::Gray,
        };
        let title = if f.title.len() > 70 { format!("{}…", &f.title[..69]) } else { f.title.clone() };
        Row::new(vec![
            Cell::from(f.threat_score.to_string()).style(Style::default().fg(color).add_modifier(Modifier::BOLD)),
            Cell::from(format!("{}", f.severity)).style(Style::default().fg(color)),
            Cell::from(f.category.as_str()),
            Cell::from(title),
        ])
    }).collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(6),
            Constraint::Length(10),
            Constraint::Length(14),
            Constraint::Min(40),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Blue))
            .title(Span::styled(
                format!(" All Findings ({}){} — 'f' to filter severity ", visible.len(), filter_label),
                Style::default().fg(Color::White),
            )),
    )
    .highlight_style(Style::default().bg(Color::DarkGray));

    f.render_stateful_widget(table, area, &mut state.table_state);
}

fn render_detail_popup(f: &mut Frame, area: Rect, finding: &ScanResult) {
    let popup_area = Rect {
        x: area.x + area.width / 8,
        y: area.y + area.height / 8,
        width: area.width * 3 / 4,
        height: area.height * 3 / 4,
    };

    f.render_widget(Clear, popup_area);

    let color = match finding.severity {
        Severity::Critical => Color::Red,
        Severity::High => Color::LightRed,
        Severity::Medium => Color::Yellow,
        Severity::Low => Color::Blue,
        Severity::Info => Color::Gray,
    };

    let mut text_lines = vec![
        Line::from(vec![
            Span::styled("ID: ", Style::default().fg(Color::Gray)),
            Span::raw(&finding.id),
        ]),
        Line::from(vec![
            Span::styled("Severity: ", Style::default().fg(Color::Gray)),
            Span::styled(format!("{}", finding.severity), Style::default().fg(color).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("Score: ", Style::default().fg(Color::Gray)),
            Span::styled(finding.threat_score.to_string(), Style::default().fg(color)),
        ]),
        Line::from(vec![
            Span::styled("Category: ", Style::default().fg(Color::Gray)),
            Span::raw(&finding.category),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Description:", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(finding.description.as_str()),
        Line::from(""),
    ];

    if !finding.artifacts.is_empty() {
        text_lines.push(Line::from(vec![
            Span::styled("Artifacts:", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        ]));
        for a in &finding.artifacts {
            text_lines.push(Line::from(format!("  • {}", a)));
        }
        text_lines.push(Line::from(""));
    }

    if let Some(ref mitre) = finding.mitre_technique {
        text_lines.push(Line::from(vec![
            Span::styled("MITRE ATT&CK: ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(mitre, Style::default().fg(Color::Cyan)),
        ]));
        text_lines.push(Line::from(""));
    }

    if !finding.recommendations.is_empty() {
        text_lines.push(Line::from(vec![
            Span::styled("Recommendations:", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        ]));
        for r in &finding.recommendations {
            text_lines.push(Line::from(format!("  ✓ {}", r)));
        }
    }

    let paragraph = Paragraph::new(text_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(color))
                .title(Span::styled(
                    format!(" {} — Press Esc/Enter to close ", finding.title.chars().take(50).collect::<String>()),
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                )),
        )
        .wrap(Wrap { trim: true });

    f.render_widget(paragraph, popup_area);
}

fn render_scan_progress(f: &mut Frame, area: Rect, progress: u16) {
    let popup = Rect {
        x: area.width / 4,
        y: area.height / 2 - 2,
        width: area.width / 2,
        height: 5,
    };
    f.render_widget(Clear, popup);

    let gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow))
                .title(" Scanning system... "),
        )
        .gauge_style(Style::default().fg(Color::Green).bg(Color::DarkGray))
        .ratio(progress as f64 / 100.0)
        .label(format!("{}%", progress));
    f.render_widget(gauge, popup);
}

fn render_status_bar(f: &mut Frame, area: Rect, state: &AppState) {
    let status = Paragraph::new(state.status_message.as_str())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .style(Style::default().fg(Color::White));
    f.render_widget(status, area);
}
