use std::sync::Arc;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::Frame;

use crate::panic::PanicHandler;
use crate::session::SessionManager;
use crate::types::{ChatMessage, PeerId, FLAG_SYSTEM_INFO, FLAG_SYSTEM_JOIN, FLAG_SYSTEM_LEAVE, FLAG_REAL};

const MAX_MESSAGES: usize = 500;

pub struct TuiState {
    pub messages: Vec<(PeerId, String, u8)>,
    pub input: String,
    pub my_id: PeerId,
    pub session_mgr: Arc<SessionManager>,
    pub panic_handler: Arc<std::sync::Mutex<PanicHandler>>,
    pub quit: bool,
}

impl TuiState {
    pub fn new(
        my_id: PeerId,
        session_mgr: Arc<SessionManager>,
        panic_handler: Arc<std::sync::Mutex<PanicHandler>>,
    ) -> Self {
        Self {
            messages: Vec::new(),
            input: String::new(),
            my_id,
            session_mgr,
            panic_handler,
            quit: false,
        }
    }

    pub fn add_message(&mut self, peer_id: PeerId, text: String, flags: u8) {
        self.messages.push((peer_id, text, flags));
        while self.messages.len() > MAX_MESSAGES {
            self.messages.remove(0);
        }
    }

    pub fn clear_messages(&mut self) {
        self.messages.clear();
        self.input.clear();
    }

    pub fn handle_event(&mut self, event: Event) {
        match event {
            Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                KeyCode::Enter => {
                    let text = std::mem::take(&mut self.input);
                    if !text.is_empty() {
                        let msg = ChatMessage {
                            peer_id: self.my_id,
                            text: text.clone(),
                            timestamp: 0,
                            flags: FLAG_REAL,
                        };
                        if let Ok(data) = serde_json::to_vec(&msg) {
                            self.session_mgr.broadcast(&data);
                        }
                        self.add_message(self.my_id, text, FLAG_REAL);
                    }
                }
                KeyCode::Char(c) => {
                    if key.modifiers == KeyModifiers::NONE || key.modifiers == KeyModifiers::SHIFT {
                        self.input.push(c);
                    }
                }
                KeyCode::Backspace => {
                    self.input.pop();
                }
                KeyCode::Esc => {
                    self.quit = true;
                }
                KeyCode::F(12) => {
                    self.quit = true;
                }
                _ => {}
            },
            _ => {}
        }
    }

    pub fn render(&self, frame: &mut Frame) {
        let panic_mode = self.panic_handler.lock().expect("panic_handler poisoned").is_decoy;

        let main_chunks = Layout::horizontal([
            Constraint::Ratio(3, 4),
            Constraint::Ratio(1, 4),
        ])
        .split(frame.area());

        let right_chunks = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(1),
        ])
        .split(main_chunks[1]);

        let left_chunks = Layout::vertical([
            Constraint::Min(1),
            Constraint::Length(3),
        ])
        .split(main_chunks[0]);

        self.render_chat(frame, left_chunks[0], panic_mode);
        self.render_input(frame, left_chunks[1]);
        self.render_mode_indicator(frame, right_chunks[0], panic_mode);
        self.render_peer_list(frame, right_chunks[1]);
    }

    fn render_chat(&self, frame: &mut Frame, area: Rect, panic_mode: bool) {
        let peer_count = self.session_mgr.peer_count();

        let items: Vec<ListItem> = self
            .messages
            .iter()
            .map(|(peer_id, text, flags)| {
                let (prefix, style) = match *flags {
                    FLAG_SYSTEM_JOIN | FLAG_SYSTEM_LEAVE => (
                        format!(" ◆ "),
                        Style::default().fg(Color::Gray).add_modifier(Modifier::ITALIC),
                    ),
                    FLAG_SYSTEM_INFO => (
                        format!(" ! "),
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ),
                    _ if *peer_id == self.my_id => (
                        " you ".to_string(),
                        Style::default().fg(Color::Cyan),
                    ),
                    _ => {
                        let short = peer_id.to_string();
                        (format!(" {short} "), Style::default().fg(Color::Green))
                    }
                };
                ListItem::new(format!("[{prefix}] {text}")).style(style)
            })
            .collect();

        let mode_indicator = if panic_mode { " [PANIC]" } else { "" };
        let title = format!(" Chat — {peer_count} peers{mode_indicator} ");
        let chat = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(title))
            .style(Style::default());
        frame.render_widget(chat, area);
    }

    fn render_input(&self, frame: &mut Frame, area: Rect) {
        let input = Paragraph::new(self.input.as_str())
            .block(Block::default().borders(Borders::ALL).title(" Message "))
            .style(Style::default());
        frame.render_widget(input, area);
        frame.set_cursor_position((area.x + 1 + self.input.len() as u16, area.y + 1));
    }

    fn render_mode_indicator(&self, frame: &mut Frame, area: Rect, panic_mode: bool) {
        let label = if panic_mode {
            " PANIC MODE "
        } else {
            " REAL MODE "
        };
        let color = if panic_mode {
            Color::Red
        } else {
            Color::Green
        };
        let block = Paragraph::new(label)
            .block(Block::default().borders(Borders::ALL))
            .style(Style::default().fg(color).add_modifier(Modifier::BOLD));
        frame.render_widget(block, area);
    }

    fn render_peer_list(&self, frame: &mut Frame, area: Rect) {
        let sessions = self.session_mgr.list_sessions();
        let items: Vec<ListItem> = sessions
            .iter()
            .map(|info| {
                let short = info.peer_id.to_string();
                let addr = &info.peer_addr;
                ListItem::new(format!("{short}\n{}:{}", addr.ip, addr.port))
                    .style(Style::default().fg(Color::Yellow))
            })
            .collect();

        let max = self.session_mgr.max_sessions;
        let title = format!(" Peers {}/{} ", sessions.len(), max);
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(title));
        frame.render_widget(list, area);
    }
}

pub fn spawn_event_reader() -> tokio::sync::mpsc::UnboundedReceiver<Event> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

    tokio::task::spawn_blocking(move || {
        loop {
            if event::poll(Duration::from_millis(100)).unwrap_or(false) {
                if let Ok(event) = event::read() {
                    if tx.send(event).is_err() {
                        break;
                    }
                }
            }
        }
    });

    rx
}

pub fn setup_terminal(
) -> std::io::Result<ratatui::Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>> {
    use crossterm::terminal::{enable_raw_mode, EnterAlternateScreen};
    use crossterm::ExecutableCommand;
    use ratatui::backend::CrosstermBackend;
    use ratatui::Terminal;

    enable_raw_mode()?;
    std::io::stdout().execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(std::io::stdout());
    Terminal::new(backend)
}

pub fn restore_terminal() -> std::io::Result<()> {
    use crossterm::terminal::{disable_raw_mode, LeaveAlternateScreen};
    use crossterm::ExecutableCommand;

    disable_raw_mode()?;
    std::io::stdout().execute(LeaveAlternateScreen)?;
    Ok(())
}
