use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Instant;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ChatMessage {
    pub peer_id: PeerId,
    pub text: String,
    pub timestamp: u64,
    pub flags: u8,
}

pub const FLAG_REAL: u8 = 0;
pub const FLAG_DUMMY: u8 = 1;
pub const FLAG_PEER_LIST_REQ: u8 = 2;
pub const FLAG_PEER_LIST_RES: u8 = 3;
pub const FLAG_SYSTEM_JOIN: u8 = 4;
pub const FLAG_SYSTEM_LEAVE: u8 = 5;
pub const FLAG_SYSTEM_ALONE: u8 = 6;
pub const FLAG_SYSTEM_INFO: u8 = 7;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
pub struct PeerId(pub [u8; 32]);

impl PeerId {
    pub fn from_cert_der(der: &[u8]) -> Self {
        let hash = Sha256::digest(der);
        Self(hash.into())
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0[..8] {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PeerAddr {
    pub ip: std::net::IpAddr,
    pub port: u16,
}

impl std::str::FromStr for PeerAddr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ip, port) = s.split_once(':').ok_or("missing port in peer address")?;
        let port: u16 = port.parse().map_err(|_| "invalid port".to_string())?;
        let ip: std::net::IpAddr = ip.parse().map_err(|_| "invalid IP address".to_string())?;
        Ok(Self { ip, port })
    }
}

impl std::fmt::Display for PeerAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.ip, self.port)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[allow(dead_code)]
pub enum SessionState {
    Handshaking,
    Connected,
    Disconnected,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[allow(dead_code)]
pub enum PanicMode {
    Real,
    Decoy,
}

impl PanicMode {
    #[allow(dead_code)]
    pub fn toggle(&self) -> Self {
        match self {
            PanicMode::Real => PanicMode::Decoy,
            PanicMode::Decoy => PanicMode::Real,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SessionInfo {
    pub peer_id: PeerId,
    pub peer_addr: PeerAddr,
    #[allow(dead_code)]
    pub connected_since: Instant,
    #[allow(dead_code)]
    pub last_message: Instant,
}
