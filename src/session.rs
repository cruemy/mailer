use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, watch, Notify};

use crate::crypto::LockedBytes;
use crate::types::{ChatMessage, PeerAddr, PeerId, SessionInfo, FLAG_SYSTEM_ALONE, FLAG_SYSTEM_INFO};

// ═══════════════════════════════════════════════════════════════════════════
// GESTION DE SESIONES ENTRE PEERS
// ═══════════════════════════════════════════════════════════════════════════
// SessionManager es el cerebro del programa: mantiene la lista de peers
// conectados, sus nombres, las direcciones conocidas, y coordina el
// envio de mensajes entre ellos.
//
// Cada peer conectado tiene un SessionHandle que incluye un canal de
// comunicacion (mpsc::Sender) para enviarle mensajes.
// ═══════════════════════════════════════════════════════════════════════════

/// Maneja la comunicacion con un peer especifico.
///
/// Se crea cuando un peer completa el handshake y se registra en
/// SessionManager. Cada SessionHandle tiene su propio canal de
/// envio (sender) para que el sistema pueda enviarle mensajes sin
/// tener que pasar por el loop principal del peer.
///
/// Campos
/// * `peer_id` — identificador unico del peer
/// * `peer_addr` — direccion IP:puerto (la direccion de escucha, no
///   la efimera de la conexion)
/// * `sender` — canal para enviar mensajes a este peer (se recibe en
///   el loop de `run_peer_session` en peer.rs)
/// * `connected_since` — cuando se establecio la conexion
/// * `last_message` — cuando fue el ultimo mensaje (para timeout)
/// * `cancel_notify` — notificador para cortar la sesion forzadamente
pub struct SessionHandle {
    pub peer_id: PeerId,
    pub peer_addr: PeerAddr,
    pub sender: mpsc::Sender<Vec<u8>>,
    pub connected_since: Instant,
    pub last_message: Instant,
    pub cancel_notify: Arc<Notify>,
}

/// Administrador central de todas las sesiones activas.
///
/// Responsabilidades
/// 1. Registrar y remover sesiones de peers
/// 2. Mantener la lista de peers conocidos (known_peers) para reconexion
/// 3. Hacer broadcast de mensajes a todos (o todos excepto uno)
/// 4. Nombrar peers con display names
/// 5. Detectar peers inactivos y cerrar sus sesiones (timeout)
/// 6. Coordinar el shutdown por panico (identity rotation)
/// 7. Proveer la frase de paso a los handshakes
///
/// Thread safety
/// Todo el estado interno esta protegido por `Mutex`. Aunque no es
/// tan performante como un lock-free approach, es suficiente para
/// un chat P2P con pocos peers (decenas, no miles).
///
/// Por que Mutex y no RwLock
/// La mayoria de las operaciones son writes (registrar, remover,
/// broadcast). Con RwLock, los writes tienen que esperar a que todos
/// los readers terminen. Con Mutex es mas simple y predecible.
pub struct SessionManager {
    sessions: Mutex<HashMap<PeerId, SessionHandle>>,
    phrase: LockedBytes,
    pub max_sessions: usize,
    pub same_ip_limit: usize,
    pub message_tx: mpsc::Sender<(PeerId, ChatMessage)>,
    pub inactivity_timeout: Duration,
    known_peers: Mutex<HashMap<PeerId, PeerAddr>>,
    pub my_listen_addr: PeerAddr,
    my_peer_id: Mutex<PeerId>,
    discovery_tx: Mutex<Option<mpsc::Sender<PeerAddr>>>,
    cancel_tx: watch::Sender<bool>,
    display_names: Mutex<HashMap<PeerId, String>>,
    my_display_name: Mutex<Option<String>>,
}

impl SessionManager {
    /// Crea un nuevo SessionManager.
    ///
    /// Parametros
    /// * `phrase` — la frase de paso (LockedBytes con mlock + zeroize)
    /// * `message_tx` — canal para enviar mensajes a la TUI (se recibe
    ///   en el loop principal de main.rs)
    /// * `inactivity_timeout` — tiempo sin mensajes antes de cerrar sesion
    /// * `my_listen_addr` — nuestra direccion de escucha (para que los
    ///   peers sepan a donde reconectarnos)
    /// * `my_peer_id` — nuestro PeerId
    /// * `my_display_name` — nuestro nombre visible (opcional)
    pub fn new(
        phrase: LockedBytes,
        message_tx: mpsc::Sender<(PeerId, ChatMessage)>,
        inactivity_timeout: Duration,
        my_listen_addr: PeerAddr,
        my_peer_id: PeerId,
        my_display_name: Option<String>,
    ) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            phrase,
            max_sessions: 10,
            same_ip_limit: 1,
            message_tx,
            inactivity_timeout,
            known_peers: Mutex::new(HashMap::new()),
            my_listen_addr,
            my_peer_id: Mutex::new(my_peer_id),
            discovery_tx: Mutex::new(None),
            cancel_tx: watch::channel(false).0,
            display_names: Mutex::new(HashMap::new()),
            my_display_name: Mutex::new(my_display_name),
        }
    }

    /// Obtiene un receptor de la senal de cancelacion global.
    ///
    /// Cuando se llama a `panic_shutdown()`, se envia `true` por este
    /// canal y todas las tareas de peer que esten escuchando deben
    /// terminar.
    pub fn cancel_rx(&self) -> watch::Receiver<bool> {
        self.cancel_tx.subscribe()
    }

    /// Devuelve nuestro PeerId actual.
    pub fn my_peer_id(&self) -> PeerId {
        *self.my_peer_id.lock().expect("my_peer_id poisoned")
    }

    /// Cambia nuestro PeerId (se usa despues de panic/identity rotation).
    pub fn set_my_peer_id(&self, peer_id: PeerId) {
        *self.my_peer_id.lock().expect("my_peer_id poisoned") = peer_id;
    }

    /// Devuelve nuestro display name (si tenemos uno).
    pub fn my_display_name(&self) -> Option<String> {
        self.my_display_name.lock().expect("my_display_name poisoned").clone()
    }

    /// Guarda el display name de un peer (para mostrarlo en la UI en vez del PeerId).
    pub fn set_display_name(&self, peer_id: PeerId, name: String) {
        self.display_names.lock().expect("display_names poisoned").insert(peer_id, name);
    }

    /// Obtiene el display name de un peer, si lo tiene.
    pub fn get_display_name(&self, peer_id: &PeerId) -> Option<String> {
        self.display_names.lock().expect("display_names poisoned").get(peer_id).cloned()
    }

    /// Registra una nueva sesion de peer.
    ///
    /// Validaciones: 1) no conectarse a uno mismo, 2) no sesiones
    /// duplicadas (mismo PeerId), 3) no superar max_sessions = 10,
    /// 4) no mas de 1 conexion por misma IP (same_ip_limit).
    ///
    /// Por que limitar por IP
    /// Para evitar que un mismo peer (detras de NAT) se conecte
    /// multiple veces y agote las sesiones. En un mesh P2P tipico
    /// solo necesitas una conexion por peer.
    ///
    /// Parametros
    /// * `handle` — el SessionHandle del peer a registrar
    ///
    /// Devuelve
    /// `Ok(())` si se registro, o `Err(mensaje)` si alguna validacion falla.
    pub fn register_session(&self, handle: SessionHandle) -> Result<(), &'static str> {
        if handle.peer_id == self.my_peer_id() {
            return Err("cannot connect to self");
        }

        let mut sessions = self.sessions.lock().expect("sessions poisoned");

        if sessions.contains_key(&handle.peer_id) {
            return Err("duplicate session");
        }

        if sessions.len() >= self.max_sessions {
            return Err("max sessions reached");
        }

        let ip_count = sessions
            .values()
            .filter(|s| s.peer_addr.ip == handle.peer_addr.ip)
            .count();
        if ip_count >= self.same_ip_limit {
            return Err("same-ip limit reached");
        }

        sessions.insert(handle.peer_id, handle);
        Ok(())
    }

    /// Remueve una sesion (desconexion FORZADA, no limpia).
    ///
    /// Que hace
    /// 1. Saca el SessionHandle del mapa
    /// 2. Notifica al loop del peer que debe terminar (cancel_notify)
    /// 3. Guarda la direccion en known_peers (para reconexion futura)
    /// 4. Envia un mensaje INFO a la TUI diciendo "connection lost"
    ///
    /// Diferencia con disconnect_peer
    /// `remove_session` guarda en known_peers (para reconectar).
    /// `disconnect_peer` saca de known_peers (no reconectar).
    pub fn remove_session(&self, peer_id: &PeerId) {
        let removed = {
            let mut sessions = self.sessions.lock().expect("sessions poisoned");
            sessions.remove(peer_id)
        };
        if let Some(handle) = removed {
            handle.cancel_notify.notify_one();
            let addr = handle.peer_addr;
            self.known_peers.lock().expect("known_peers poisoned").insert(*peer_id, addr);
            let msg = ChatMessage {
                peer_id: *peer_id,
                text: format!("connection lost, reconnecting to {peer_id}..."),
                timestamp: 0,
                flags: FLAG_SYSTEM_INFO,
            };
            let _ = self.message_tx.try_send((*peer_id, msg));
        }
    }

    /// Desconecta un peer DEFINITIVAMENTE (no reconectar).
    ///
    /// Diferencia con remove_session: disconnect_peer NO guarda en
    /// known_peers. Se usa cuando recibimos un GOODBYE (cierre limpio):
    /// el peer se fue voluntariamente, no hay que reconectar.
    pub fn disconnect_peer(&self, peer_id: &PeerId) {
        let removed = {
            let mut sessions = self.sessions.lock().expect("sessions poisoned");
            sessions.remove(peer_id)
        };
        if let Some(handle) = removed {
            handle.cancel_notify.notify_one();
            self.known_peers.lock().expect("known_peers poisoned").remove(peer_id);
        }
    }

    /// Limpia TODAS las sesiones y known_peers.
    ///
    /// Se usa despues de panic/identity rotation. Todos los peers
    /// quedan desconectados y no se reconecta a nadie (se limpia
    /// known_peers tambien).
    ///
    /// Si habia sesiones activas, envia FLAG_SYSTEM_ALONE al
    /// loop de mensajes para que regeneremos identidad TLS.
    pub fn clear_sessions(&self) {
        let mut handles: Vec<SessionHandle> = {
            let mut sessions = self.sessions.lock().expect("sessions poisoned");
            sessions.drain().map(|(_, h)| h).collect()
        };
        let had_sessions = !handles.is_empty();
        for h in &handles {
            h.cancel_notify.notify_one();
        }
        handles.clear();
        self.known_peers.lock().expect("known_peers poisoned").clear();
        if had_sessions {
            let msg = ChatMessage {
                peer_id: self.my_peer_id(),
                text: String::new(),
                timestamp: 0,
                flags: FLAG_SYSTEM_ALONE,
            };
            let _ = self.message_tx.try_send((self.my_peer_id(), msg));
        }
    }

    /// Apagon de emergencia (F12). Envia senal de cancelacion a
    /// TODOS los loops de peer y limpia todo.
    pub fn panic_shutdown(&self) {
        let _ = self.cancel_tx.send(true);
        let handles: Vec<SessionHandle> = {
            let mut sessions = self.sessions.lock().expect("sessions poisoned");
            sessions.drain().map(|(_, h)| h).collect()
        };
        for h in &handles {
            h.cancel_notify.notify_one();
        }
        drop(handles);
        self.known_peers.lock().expect("known_peers poisoned").clear();
    }

    /// Obtiene el canal de envio de un peer especifico.
    ///
    /// Se usa para enviar mensajes DIRECTOS a un peer (ej: display name).
    #[allow(dead_code)]
    pub fn get_sender(&self, peer_id: &PeerId) -> Option<mpsc::Sender<Vec<u8>>> {
        self.sessions
            .lock()
            .expect("sessions poisoned")
            .get(peer_id)
            .map(|s| s.sender.clone())
    }

    /// Envia un mensaje a TODOS los peers conectados.
    ///
    /// Usa `try_send` porque los canales tienen buffer (256) y si
    /// estan llenos, el peer esta desconectado o muy lento. No
    /// queremos bloquear el broadcast por un peer lento.
    pub fn broadcast(&self, data: &[u8]) {
        let sessions = self.sessions.lock().expect("sessions poisoned");
        for handle in sessions.values() {
            let _ = handle.sender.try_send(data.to_vec());
        }
    }

    /// Envia un mensaje a TODOS EXCEPTO un peer especifico.
    ///
    /// Se usa para SYSTEM_JOIN/SYSTEM_LEAVE: no tiene sentido
    /// notificar al peer que se acaba de conectar que el mismo
    /// se conecto.
    pub fn broadcast_except(&self, data: &[u8], exclude: &PeerId) {
        let sessions = self.sessions.lock().expect("sessions poisoned");
        for handle in sessions.values() {
            if handle.peer_id != *exclude {
                let _ = handle.sender.try_send(data.to_vec());
            }
        }
    }

    /// Obtiene informacion resumida de una sesion especifica.
    #[allow(dead_code)]
    pub fn get_session_info(&self, peer_id: &PeerId) -> Option<SessionInfo> {
        let sessions = self.sessions.lock().expect("sessions poisoned");
        sessions.get(peer_id).map(|s| SessionInfo {
            peer_id: s.peer_id,
            peer_addr: s.peer_addr.clone(),
            connected_since: s.connected_since,
            last_message: s.last_message,
        })
    }

    /// Lista todas las sesiones activas (para mostrar en la UI).
    pub fn list_sessions(&self) -> Vec<SessionInfo> {
        let sessions = self.sessions.lock().expect("sessions poisoned");
        sessions
            .values()
            .map(|s| SessionInfo {
                peer_id: s.peer_id,
                peer_addr: s.peer_addr.clone(),
                connected_since: s.connected_since,
                last_message: s.last_message,
            })
            .collect()
    }

    /// Lista las direcciones de peers conectados (excepto uno).
    ///
    /// Se usa para responder a FLAG_PEER_LIST_REQ: "decime que
    /// peers conoces (excepto vos mismo)".
    pub fn list_peer_addresses(&self, exclude: &PeerId) -> Vec<PeerAddr> {
        let sessions = self.sessions.lock().expect("sessions poisoned");
        sessions
            .values()
            .filter(|s| s.peer_id != *exclude)
            .map(|s| s.peer_addr.clone())
            .collect()
    }

    /// Verifica si ya hay una conexion a una direccion especifica.
    pub fn is_connected_to_addr(&self, addr: &PeerAddr) -> bool {
        let sessions = self.sessions.lock().expect("sessions poisoned");
        sessions.values().any(|s| s.peer_addr == *addr)
    }

    /// Cantidad de peers conectados actualmente.
    pub fn peer_count(&self) -> usize {
        self.sessions.lock().expect("sessions poisoned").len()
    }

    /// Devuelve la frase de paso (para los handshakes).
    pub fn phrase(&self) -> &[u8] {
        self.phrase.as_bytes()
    }

    /// Lista todas las direcciones de peers conocidos (para reconexion).
    pub fn known_peers_list(&self) -> Vec<PeerAddr> {
        self.known_peers
            .lock()
            .expect("known_peers poisoned")
            .values()
            .cloned()
            .collect()
    }

    /// Limpia la lista de peers conocidos.
    pub fn clear_known_peers(&self) {
        self.known_peers.lock().expect("known_peers poisoned").clear();
    }

    /// Configura el canal de descubrimiento de peers.
    ///
    /// Cuando recibimos una respuesta PEER_LIST_RES con direcciones
    /// de peers que no conocemos, las enviamos por este canal para
    /// que el loop principal intente conectarse.
    pub fn set_discovery_tx(&self, tx: mpsc::Sender<PeerAddr>) {
        *self.discovery_tx.lock().expect("discovery_tx poisoned") = Some(tx);
    }

    /// Envia una direccion descubierta al canal de discovery.
    pub fn send_discovered(&self, addr: &PeerAddr) {
        if let Some(ref tx) = *self.discovery_tx.lock().expect("discovery_tx poisoned") {
            let _ = tx.try_send(addr.clone());
        }
    }

    /// Envia un mensaje de sistema a la TUI.
    ///
    /// Se usa para mostrar informacion como "connected, connection lost, error, etc."
    /// El peer_id del mensaje se setea a [0u8; 32] para identificarlo
    /// como mensaje del sistema (no de un peer real).
    pub fn system_msg(&self, text: &str) {
        let msg = ChatMessage {
            peer_id: PeerId([0u8; 32]),
            text: text.to_string(),
            timestamp: 0,
            flags: FLAG_SYSTEM_INFO,
        };
        let _ = self.message_tx.try_send((PeerId([0u8; 32]), msg));
    }

    /// Inicia una tarea async que verifica periodicamente si hay
    /// peers inactivos y los desconecta.
    ///
    /// Como funciona: 1) cada 30 segundos revisa todos los peers
    /// (last_message), 2) si now - last_message > inactivity_timeout,
    /// llama a remove_session (que guarda en known_peers).
    ///
    /// Por que 30 segundos de intervalo
    /// Es un balance entre: detectar inactividad rapidamente (si
    /// el timeout es 5 minutos, en 30 segundos maximo de delay
    /// es aceptable) vs no estar lockeando el Mutex constantemente.
    pub fn spawn_timeout_checker(self: &Arc<Self>) {
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                let now = Instant::now();
                let stale: Vec<PeerId> = {
                    let sessions = this.sessions.lock().expect("sessions poisoned");
                    sessions
                        .iter()
                        .filter(|(_, h)| now.duration_since(h.last_message) > this.inactivity_timeout)
                        .map(|(id, _)| *id)
                        .collect()
                };
                for id in stale {
                    this.remove_session(&id);
                }
            }
        });
    }

    /// Actualiza el timestamp de ultimo mensaje de un peer.
    ///
    /// Se llama cada vez que recibimos un mensaje valido de ese peer
    /// para evitar que el timeout checker lo desconecte.
    pub fn update_last_message(&self, peer_id: &PeerId) {
        if let Some(handle) = self.sessions.lock().expect("sessions poisoned").get_mut(peer_id) {
            handle.last_message = Instant::now();
        }
    }
}
