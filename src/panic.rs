use std::sync::Arc;

use crate::session::SessionManager;
use crate::types::PeerAddr;

pub struct PanicHandler {
    pub session_mgr: Arc<SessionManager>,
    pub real_phrase: String,
    pub decoy_phrase: String,
    pub peers: Vec<PeerAddr>,
    pub is_decoy: bool,
}

impl PanicHandler {
    pub fn new(
        session_mgr: Arc<SessionManager>,
        real_phrase: String,
        decoy_phrase: String,
        peers: Vec<PeerAddr>,
        start_decoy: bool,
    ) -> Self {
        Self {
            session_mgr,
            real_phrase,
            decoy_phrase,
            peers,
            is_decoy: start_decoy,
        }
    }

    pub fn current_phrase(&self) -> &str {
        if self.is_decoy {
            &self.decoy_phrase
        } else {
            &self.real_phrase
        }
    }

    pub fn toggle_mode(&mut self) {
        self.session_mgr.clear_sessions();
        self.is_decoy = !self.is_decoy;
        let new = self.current_phrase();
        self.session_mgr.switch_phrase(new);
    }
}
