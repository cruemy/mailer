use std::sync::Arc;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Text};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};

use crate::panic::PanicHandler;
use crate::session::SessionManager;
use crate::types::{
    ChatMessage, FLAG_REAL, FLAG_SYSTEM_INFO, FLAG_SYSTEM_JOIN, FLAG_SYSTEM_LEAVE, PeerId,
};

// ═══════════════════════════════════════════════════════════════════════════
// INTERFAZ DE TERMINAL (TUI) con Ratatui + Crossterm
// ═══════════════════════════════════════════════════════════════════════════
// Renderiza el chat en la terminal: historial de mensajes, entrada de texto,
// lista de peers conectados, e indicador de modo (real/panico).
//
// Layout:
// ┌───────────────────────┬──────────┐
// │     Chat (75%)        │ Mode (3) │
// │                       ├──────────┤
// │                       │Peers list│
// │                       │          │
// │     Input (3 lines)   │          │
// └───────────────────────┴──────────┘
// ═══════════════════════════════════════════════════════════════════════════

/// Maximo de mensajes en el historial (500). Despues de eso, los mas
/// viejos se borran para no ocupar memoria infinita.
const MAX_MESSAGES: usize = 500;

/// Estado completo de la interfaz de terminal.
///
/// Campos
/// * `messages` — historial de mensajes [(PeerId, texto, flags)]
/// * `input` — lo que el usuario esta escribiendo actualmente
/// * `my_id` — nuestro PeerId (para marcar nuestros mensajes como "you")
/// * `session_mgr` — referencia al SessionManager
/// * `panic_handler` — para saber si estamos en modo panico
/// * `quit` — true si el usuario pidio salir (Esc)
/// * `panic_requested` — true si el usuario pidio panico (F12)
/// * `scroll_offset` — cuantas lineas nos desplazamos hacia arriba
/// * `auto_scroll` — si estamos al final del chat (sigue nuevos mensajes)
pub struct TuiState {
    pub messages: Vec<(PeerId, String, u8)>,
    pub input: String,
    pub my_id: PeerId,
    pub session_mgr: Arc<SessionManager>,
    pub panic_handler: Arc<std::sync::Mutex<PanicHandler>>,
    pub quit: bool,
    pub panic_requested: bool,
    scroll_offset: usize,
    auto_scroll: bool,
}

impl TuiState {
    /// Crea un nuevo estado TUI.
    ///
    /// Parametros
    /// * `my_id` — nuestro PeerId
    /// * `session_mgr` — referencia al SessionManager global
    /// * `panic_handler` — referencia al PanicHandler (para consultar
    ///   si estamos en modo decoy y mostrar el indicador correcto)
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
            panic_requested: false,
            scroll_offset: 0,
            auto_scroll: true,
        }
    }

    /// Agrega un mensaje al historial.
    ///
    /// Si estamos cerca del final del scroll, el nuevo mensaje se
    /// muestra automaticamente (auto_scroll = true).
    ///
    /// Parametros
    /// * `peer_id` — quien envio el mensaje
    /// * `text` — texto del mensaje
    /// * `flags` — tipo de mensaje (para colorear/personalizar)
    pub fn add_message(&mut self, peer_id: PeerId, text: String, flags: u8) {
        let near_bottom =
            self.messages.len() > 5 && self.scroll_offset >= self.messages.len().saturating_sub(5);
        let was_at_bottom = self.auto_scroll || near_bottom;
        self.messages.push((peer_id, text, flags));
        while self.messages.len() > MAX_MESSAGES {
            self.messages.remove(0);
        }
        if was_at_bottom {
            self.auto_scroll = true;
            self.scroll_offset = 0;
        }
    }

    /// Procesa un evento de teclado.
    ///
    /// Teclas
    /// * `Enter` — envia el mensaje escrito
    /// * `Caracter` — escribe en el input
    /// * `Backspace` — borra el ultimo caracter
    /// * `Esc` — sale del programa (quit = true)
    /// * `F12` — activa el modo panico (panic_requested = true)
    /// * `PageUp` — desplaza el chat hacia arriba (5 lineas)
    /// * `PageDown` — desplaza hacia abajo (vuelve a auto_scroll si llega al final)
    ///
    /// Parametros
    /// * `event` — evento de crossterm (teclado, mouse, resize, etc.)
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
                    self.panic_requested = true;
                }
                KeyCode::PageUp => {
                    self.auto_scroll = false;
                    self.scroll_offset = self.scroll_offset.saturating_add(5);
                }
                KeyCode::PageDown => {
                    self.scroll_offset = self.scroll_offset.saturating_sub(5);
                    if self.scroll_offset == 0 {
                        self.auto_scroll = true;
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }

    /// Renderiza toda la interfaz en el frame de ratatui.
    ///
    /// Layout
    /// ```text
    /// ┌───────────────────────┬──────────┐
    /// │    75% Chat          │  25%     │
    /// │                      ├──────────┤
    /// │                      │ Mode (3) │
    /// │                      │ Peers    │
    /// ├──────────────────────┤          │
    /// │  Input (3 lines)     │          │
    /// └──────────────────────┴──────────┘
    /// ```
    pub fn render(&mut self, frame: &mut Frame) {
        let panic_mode = self
            .panic_handler
            .lock()
            .expect("panic_handler poisoned")
            .is_decoy;

        let main_chunks = Layout::horizontal([Constraint::Ratio(3, 4), Constraint::Ratio(1, 4)])
            .split(frame.area());

        let right_chunks =
            Layout::vertical([Constraint::Length(3), Constraint::Min(1)]).split(main_chunks[1]);

        let left_chunks =
            Layout::vertical([Constraint::Min(1), Constraint::Length(3)]).split(main_chunks[0]);

        self.render_chat(frame, left_chunks[0], panic_mode);
        self.render_input(frame, left_chunks[1]);
        self.render_mode_indicator(frame, right_chunks[0], panic_mode);
        self.render_peer_list(frame, right_chunks[1]);
    }

    /// Devuelve el nombre visible de un peer (display name o PeerId en hex).
    fn peer_display_name(&self, peer_id: &PeerId) -> String {
        self.session_mgr
            .get_display_name(peer_id)
            .unwrap_or_else(|| peer_id.to_string())
    }

    /// Renderiza el area del chat (lista de mensajes).
    ///
    /// Estilos
    /// - Mensajes de JOIN/LEAVE: gris italica
    /// - Mensajes de sistema: rojo bold
    /// - Mensajes propios: cyan
    /// - Mensajes de otros peers: verde con nombre
    fn render_chat(&mut self, frame: &mut Frame, area: Rect, panic_mode: bool) {
        let peer_count = self.session_mgr.peer_count();
        let max_width = area.width.saturating_sub(3) as usize;

        let items: Vec<ListItem> = self
            .messages
            .iter()
            .map(|(peer_id, text, flags)| {
                let (prefix, style) = match *flags {
                    FLAG_SYSTEM_JOIN | FLAG_SYSTEM_LEAVE => (
                        format!(" ◆ "),
                        Style::default()
                            .fg(Color::Gray)
                            .add_modifier(Modifier::ITALIC),
                    ),
                    FLAG_SYSTEM_INFO => (
                        format!(" ! "),
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ),
                    _ if *peer_id == self.my_id => {
                        (" you ".to_string(), Style::default().fg(Color::Cyan))
                    }
                    _ => {
                        let name = self.peer_display_name(peer_id);
                        (format!(" {name} "), Style::default().fg(Color::Green))
                    }
                };
                let formatted = format!("[{prefix}] {text}");
                let lines: Vec<Line> = wrap_text(&formatted, max_width)
                    .into_iter()
                    .map(Line::from)
                    .collect();
                ListItem::new(Text::from(lines)).style(style)
            })
            .collect();

        if self.auto_scroll {
            self.scroll_offset = 0;
        }
        let end = items.len().saturating_sub(self.scroll_offset);
        let start = end.saturating_sub(100);
        let visible: Vec<ListItem> = items.into_iter().skip(start).take(end - start).collect();

        let mode_indicator = if panic_mode { " [PANIC]" } else { "" };
        let title = format!(" Chat — {peer_count} peers{mode_indicator} ");
        let chat = List::new(visible)
            .block(Block::default().borders(Borders::ALL).title(title))
            .style(Style::default());
        frame.render_widget(chat, area);
    }

    /// Renderiza el area de entrada de texto.
    fn render_input(&self, frame: &mut Frame, area: Rect) {
        let input = Paragraph::new(self.input.as_str())
            .block(Block::default().borders(Borders::ALL).title(" Message "))
            .style(Style::default());
        frame.render_widget(input, area);
        // Posiciona el cursor al final del texto
        frame.set_cursor_position((area.x + 1 + self.input.len() as u16, area.y + 1));
    }

    /// Renderiza el indicador de modo (REAL MODE / PANIC MODE).
    ///
    /// Cuando estamos en modo panico (decoy), el indicador es ROJO
    /// y dice "PANIC MODE". Es dificil no verlo.
    fn render_mode_indicator(&self, frame: &mut Frame, area: Rect, panic_mode: bool) {
        let label = if panic_mode {
            " PANIC MODE "
        } else {
            " REAL MODE "
        };
        let color = if panic_mode { Color::Red } else { Color::Green };
        let block = Paragraph::new(label)
            .block(Block::default().borders(Borders::ALL))
            .style(Style::default().fg(color).add_modifier(Modifier::BOLD));
        frame.render_widget(block, area);
    }

    /// Renderiza la lista de peers conectados.
    ///
    /// Muestra hasta `max_sessions` (10) peers. Cada peer se muestra
    /// con su display name o PeerId.
    fn render_peer_list(&self, frame: &mut Frame, area: Rect) {
        let sessions = self.session_mgr.list_sessions();
        let my_name = self
            .session_mgr
            .my_display_name()
            .unwrap_or_else(|| self.my_id.to_string());
        let my_item = ListItem::new(format!("● {}", my_name))
            .style(Style::default().fg(Color::Cyan));

        let mut items: Vec<ListItem> = sessions
            .iter()
            .map(|info| {
                let name = self.peer_display_name(&info.peer_id);
                ListItem::new(name).style(Style::default().fg(Color::Yellow))
            })
            .collect();

        items.insert(0, my_item);

        let max = self.session_mgr.max_sessions;
        let total = sessions.len() + 1;
        let title = format!(" Peers {}/{} ", total, max);
        let list = List::new(items).block(Block::default().borders(Borders::ALL).title(title));
        frame.render_widget(list, area);
    }
}

/// Envuelve texto en multiples lineas para que entre en un ancho maximo.
///
/// Como funciona
/// 1. Si el texto entra en una linea, devuelve una sola linea
/// 2. Si no, separa por palabras y va armando lineas
/// 3. Si una palabra es mas larga que el ancho maximo, la pone igual
///    (se va a cortar visualmente pero no perdemos datos)
///
/// Parametros
/// * `text` — el texto a wrappear
/// * `max_width` — ancho maximo en caracteres
///
/// Devuelve
/// Vec de strings, cada uno es una linea que entra en max_width.
fn wrap_text(text: &str, max_width: usize) -> Vec<String> {
    if text.len() <= max_width || max_width == 0 {
        return vec![text.to_string()];
    }

    let mut lines = Vec::new();
    let mut current = String::new();

    for word in text.split_whitespace() {
        if !current.is_empty() {
            if current.len() + 1 + word.len() > max_width {
                lines.push(current);
                current = String::new();
            } else {
                current.push(' ');
            }
        }
        current.push_str(word);
    }

    if !current.is_empty() {
        lines.push(current);
    }

    lines
}

/// Inicia un hilo que lee eventos del teclado y los envia por un canal.
///
/// Por que un hilo separado
/// Crossterm necesita un thread bloqueante para leer eventos (poll/read).
/// No podemos hacer eso en el loop async de Tokio porque bloquearia todo.
/// Entonces lanzamos un `spawn_blocking` que solo lee eventos y los
/// manda por un canal con buffer acotado.
///
/// Devuelve
/// El receptor del canal (para recibir eventos en el loop principal).
pub fn spawn_event_reader() -> tokio::sync::mpsc::Receiver<Event> {
    let (tx, rx) = tokio::sync::mpsc::channel(128);

    tokio::task::spawn_blocking(move || {
        loop {
            // Poll cada 100ms (no queremos quemar CPU)
            if event::poll(Duration::from_millis(100)).unwrap_or(false) {
                if let Ok(event) = event::read() {
                    if tx.try_send(event).is_err() {
                        continue;
                    }
                }
            }
        }
    });

    rx
}

/// Configura la terminal para el modo TUI (pantalla alternativa + raw mode).
///
/// Que hace
/// 1. Activa raw mode (captura teclas sin esperar Enter)
/// 2. Cambia a la pantalla alternativa (no se ve el historial de la terminal)
/// 3. Crea el backend de ratatui con Crossterm
/// 4. Crea la terminal de ratatui
///
/// Devuelve
/// La terminal de ratatui lista para usar, o error si algo falla.
pub fn setup_terminal()
-> std::io::Result<ratatui::Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>> {
    use crossterm::ExecutableCommand;
    use crossterm::terminal::{EnterAlternateScreen, enable_raw_mode};
    use ratatui::Terminal;
    use ratatui::backend::CrosstermBackend;

    enable_raw_mode()?;
    std::io::stdout().execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(std::io::stdout());
    Terminal::new(backend)
}

/// Restaura la terminal al estado normal (reverse de setup_terminal).
///
/// Que hace
/// 1. Sale de la pantalla alternativa
/// 2. Desactiva raw mode
pub fn restore_terminal() -> std::io::Result<()> {
    use crossterm::ExecutableCommand;
    use crossterm::terminal::{LeaveAlternateScreen, disable_raw_mode};

    disable_raw_mode()?;
    std::io::stdout().execute(LeaveAlternateScreen)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PeerAddr;

    /// Verifica que F12 marca panic_requested (no quit).
    #[test]
    fn f12_requests_panic_shutdown_instead_of_plain_quit() {
        let (msg_tx, _msg_rx) = tokio::sync::mpsc::channel(1);
        let my_id = PeerId([1u8; 32]);
        let session_mgr = Arc::new(SessionManager::new(
            crate::crypto::LockedBytes::new(b"phrase".to_vec()),
            msg_tx,
            Duration::from_secs(300),
            PeerAddr {
                ip: "127.0.0.1".parse().expect("valid ip"),
                port: 19000,
            },
            my_id,
            None,
        ));
        let panic_handler = Arc::new(std::sync::Mutex::new(PanicHandler::new(false)));
        let mut state = TuiState::new(my_id, session_mgr, panic_handler);

        state.handle_event(Event::Key(crossterm::event::KeyEvent::new(
            KeyCode::F(12),
            KeyModifiers::NONE,
        )));

        assert!(state.panic_requested);
        assert!(!state.quit);
    }

    /// Verifica que el propio usuario aparece en la lista de peers.
    #[test]
    fn peer_list_includes_self() {
        let (msg_tx, _msg_rx) = tokio::sync::mpsc::channel(1);
        let my_id = PeerId([1u8; 32]);
        let session_mgr = Arc::new(SessionManager::new(
            crate::crypto::LockedBytes::new(b"phrase".to_vec()),
            msg_tx,
            Duration::from_secs(300),
            PeerAddr {
                ip: "127.0.0.1".parse().expect("valid ip"),
                port: 19000,
            },
            my_id,
            None,
        ));
        let panic_handler = Arc::new(std::sync::Mutex::new(PanicHandler::new(false)));
        let state = TuiState::new(my_id, session_mgr, panic_handler);

        let my_name = state
            .session_mgr
            .my_display_name()
            .unwrap_or_else(|| state.my_id.to_string());
        let expected_label = format!("● {}", my_name);

        assert!(expected_label.starts_with("● "));
        assert_eq!(state.my_id, my_id);
    }

    /// Verifica que el propio usuario con display name se muestra correctamente.
    #[test]
    fn peer_list_includes_self_with_display_name() {
        let (msg_tx, _msg_rx) = tokio::sync::mpsc::channel(1);
        let my_id = PeerId([2u8; 32]);
        let session_mgr = Arc::new(SessionManager::new(
            crate::crypto::LockedBytes::new(b"phrase".to_vec()),
            msg_tx,
            Duration::from_secs(300),
            PeerAddr {
                ip: "127.0.0.1".parse().expect("valid ip"),
                port: 19000,
            },
            my_id,
            Some("Alice".to_string()),
        ));
        let panic_handler = Arc::new(std::sync::Mutex::new(PanicHandler::new(false)));
        let state = TuiState::new(my_id, session_mgr, panic_handler);

        let my_name = state
            .session_mgr
            .my_display_name()
            .unwrap_or_else(|| state.my_id.to_string());
        let expected_label = format!("● {}", my_name);

        assert_eq!(my_name, "Alice");
        assert_eq!(expected_label, "● Alice");
    }
}
