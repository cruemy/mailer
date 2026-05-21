use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, watch, Notify};

use crate::crypto::LockedBytes;
use crate::types::{ChatMessage, PeerAddr, PeerId, SessionInfo, FLAG_SYSTEM_ALONE, FLAG_SYSTEM_INFO};

pub struct SessionHandle {
    pub peer_id: PeerId,
    pub peer_addr: PeerAddr,
    pub sender: mpsc::Sender<Vec<u8>>,
    pub connected_since: Instant,
    pub last_message: Instant,
    pub cancel_notify: Arc<Notify>,
}

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
}

impl SessionManager {
    pub fn new(
        phrase: LockedBytes,
        message_tx: mpsc::Sender<(PeerId, ChatMessage)>,
        inactivity_timeout: Duration,
        my_listen_addr: PeerAddr,
        my_peer_id: PeerId,
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
        }
    }

    pub fn cancel_rx(&self) -> watch::Receiver<bool> {
        self.cancel_tx.subscribe()
    }

    pub fn my_peer_id(&self) -> PeerId {
        *self.my_peer_id.lock().expect("my_peer_id poisoned")
    }

    pub fn set_my_peer_id(&self, peer_id: PeerId) {
        *self.my_peer_id.lock().expect("my_peer_id poisoned") = peer_id;
    }

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

    #[allow(dead_code)]
    pub fn get_sender(&self, peer_id: &PeerId) -> Option<mpsc::Sender<Vec<u8>>> {
        self.sessions
            .lock()
            .expect("sessions poisoned")
            .get(peer_id)
            .map(|s| s.sender.clone())
    }

    pub fn broadcast(&self, data: &[u8]) {
        let sessions = self.sessions.lock().expect("sessions poisoned");
        for handle in sessions.values() {
            let _ = handle.sender.try_send(data.to_vec());
        }
    }

    pub fn broadcast_except(&self, data: &[u8], exclude: &PeerId) {
        let sessions = self.sessions.lock().expect("sessions poisoned");
        for handle in sessions.values() {
            if handle.peer_id != *exclude {
                let _ = handle.sender.try_send(data.to_vec());
            }
        }
    }

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

    pub fn list_peer_addresses(&self, exclude: &PeerId) -> Vec<PeerAddr> {
        let sessions = self.sessions.lock().expect("sessions poisoned");
        sessions
            .values()
            .filter(|s| s.peer_id != *exclude)
            .map(|s| s.peer_addr.clone())
            .collect()
    }

    pub fn is_connected_to_addr(&self, addr: &PeerAddr) -> bool {
        let sessions = self.sessions.lock().expect("sessions poisoned");
        sessions.values().any(|s| s.peer_addr == *addr)
    }

    pub fn peer_count(&self) -> usize {
        self.sessions.lock().expect("sessions poisoned").len()
    }

    pub fn phrase(&self) -> &[u8] {
        self.phrase.as_bytes()
    }

    pub fn known_peers_list(&self) -> Vec<PeerAddr> {
        self.known_peers
            .lock()
            .expect("known_peers poisoned")
            .values()
            .cloned()
            .collect()
    }

    pub fn clear_known_peers(&self) {
        self.known_peers.lock().expect("known_peers poisoned").clear();
    }

    pub fn set_discovery_tx(&self, tx: mpsc::Sender<PeerAddr>) {
        *self.discovery_tx.lock().expect("discovery_tx poisoned") = Some(tx);
    }

    pub fn send_discovered(&self, addr: &PeerAddr) {
        if let Some(ref tx) = *self.discovery_tx.lock().expect("discovery_tx poisoned") {
            let _ = tx.try_send(addr.clone());
        }
    }

    pub fn system_msg(&self, text: &str) {
        let msg = ChatMessage {
            peer_id: PeerId([0u8; 32]),
            text: text.to_string(),
            timestamp: 0,
            flags: FLAG_SYSTEM_INFO,
        };
        let _ = self.message_tx.try_send((PeerId([0u8; 32]), msg));
    }

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

    pub fn update_last_message(&self, peer_id: &PeerId) {
        if let Some(handle) = self.sessions.lock().expect("sessions poisoned").get_mut(peer_id) {
            handle.last_message = Instant::now();
        }
    }
}
