use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sesame_cli::crypto::LockedBytes;
use sesame_cli::session::SessionManager;
use sesame_cli::types::{ChatMessage, FLAG_PEER_LIST_REQ, PeerAddr, PeerId};
use sesame_cli::{config, peer, tls};
use tokio::net::TcpListener;
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const TEST_TIMEOUT: Duration = Duration::from_secs(15);

struct TestPeer {
    addr: PeerAddr,
    peer_id: PeerId,
    session_mgr: Arc<SessionManager>,
    connector: TlsConnector,
    listener_task: JoinHandle<()>,
    message_task: JoinHandle<()>,
}

impl TestPeer {
    async fn new(phrase: &[u8]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind random localhost port");
        let local_addr = listener.local_addr().expect("listener local addr");
        let addr = PeerAddr {
            ip: local_addr.ip(),
            port: local_addr.port(),
        };

        let (certs, key) = tls::generate_cert().expect("generate TLS cert");
        let peer_id = PeerId::from_cert_der(certs[0].as_ref());
        let key_clone = key.clone_key();
        let server_config = tls::make_server_config(certs.clone(), key).expect("server TLS config");
        let client_config = tls::make_client_config(certs, key_clone).expect("client TLS config");
        let acceptor = TlsAcceptor::from(server_config);
        let connector = TlsConnector::from(client_config);

        let (message_tx, mut message_rx) = mpsc::channel::<(PeerId, ChatMessage)>(1024);
        let message_task = tokio::spawn(async move { while message_rx.recv().await.is_some() {} });
        let mut manager = SessionManager::new(
            LockedBytes::new(phrase.to_vec()),
            message_tx,
            Duration::from_secs(30),
            addr.clone(),
            peer_id,
            None,
        );
        manager.same_ip_limit = 10;
        let session_mgr = Arc::new(manager);

        let listener_mgr = session_mgr.clone();
        let listener_task = tokio::spawn(async move {
            loop {
                let (stream, socket_addr) = match listener.accept().await {
                    Ok(accepted) => accepted,
                    Err(_) => break,
                };
                let acceptor = acceptor.clone();
                let session_mgr = listener_mgr.clone();
                tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            let peer_addr = PeerAddr {
                                ip: socket_addr.ip(),
                                port: socket_addr.port(),
                            };
                            peer::handle_incoming(tls_stream, peer_addr, session_mgr).await;
                        }
                        Err(_) => {}
                    }
                });
            }
        });

        Self {
            addr,
            peer_id,
            session_mgr,
            connector,
            listener_task,
            message_task,
        }
    }

    fn shutdown(&self) {
        self.session_mgr.panic_shutdown();
        self.listener_task.abort();
        self.message_task.abort();
    }
}

impl Drop for TestPeer {
    fn drop(&mut self) {
        self.session_mgr.panic_shutdown();
        self.listener_task.abort();
        self.message_task.abort();
    }
}

fn connect(from: &TestPeer, to: &TestPeer) -> JoinHandle<()> {
    let addr = to.addr.clone();
    let session_mgr = from.session_mgr.clone();
    let connector = from.connector.clone();
    tokio::spawn(async move {
        peer::connect_peer(addr, session_mgr, connector).await;
    })
}

async fn integration_lock() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<AsyncMutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| AsyncMutex::new(())).lock().await
}

async fn wait_for_peer_count(peer: &TestPeer, expected: usize) {
    timeout(TEST_TIMEOUT, async {
        loop {
            if peer.session_mgr.peer_count() == expected {
                return;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "peer {} reached count {expected}; actual {}",
            peer.addr,
            peer.session_mgr.peer_count()
        )
    });
}

async fn connect_and_wait(a: &TestPeer, b: &TestPeer) -> JoinHandle<()> {
    let expected_a = a.session_mgr.peer_count() + 1;
    let expected_b = b.session_mgr.peer_count() + 1;
    let task = connect(a, b);
    wait_for_peer_count(a, expected_a).await;
    wait_for_peer_count(b, expected_b).await;
    task
}

#[tokio::test]
async fn test_two_peers_connect() {
    let _guard = integration_lock().await;
    let a = TestPeer::new(b"shared test phrase").await;
    let b = TestPeer::new(b"shared test phrase").await;

    let _connection = connect_and_wait(&a, &b).await;

    assert_eq!(a.session_mgr.peer_count(), 1);
    assert_eq!(b.session_mgr.peer_count(), 1);

    a.shutdown();
    b.shutdown();
}

#[tokio::test]
async fn test_wrong_phrase_rejected() {
    let _guard = integration_lock().await;
    let a = TestPeer::new(b"correct horse battery staple").await;
    let b = TestPeer::new(b"different passphrase").await;

    let _ = timeout(
        TEST_TIMEOUT,
        peer::connect_peer(b.addr.clone(), a.session_mgr.clone(), a.connector.clone()),
    )
    .await;

    sleep(Duration::from_millis(100)).await;
    assert_eq!(a.session_mgr.peer_count(), 0);
    assert_eq!(b.session_mgr.peer_count(), 0);

    a.shutdown();
    b.shutdown();
}

#[tokio::test]
async fn test_peer_list_propagation() {
    let _guard = integration_lock().await;
    let a = TestPeer::new(b"mesh phrase").await;
    let b = TestPeer::new(b"mesh phrase").await;
    let c = TestPeer::new(b"mesh phrase").await;

    let (discovery_tx, mut discovery_rx) = mpsc::channel::<PeerAddr>(8);
    a.session_mgr.set_discovery_tx(discovery_tx);

    let _ab = connect_and_wait(&a, &b).await;
    let _bc = connect_and_wait(&b, &c).await;

    let req = ChatMessage {
        peer_id: a.peer_id,
        text: String::new(),
        timestamp: 0,
        flags: FLAG_PEER_LIST_REQ,
    };
    let data = serde_json::to_vec(&req).expect("serialize peer-list request");
    a.session_mgr.broadcast(&data);

    let discovered = timeout(TEST_TIMEOUT, discovery_rx.recv())
        .await
        .expect("receive discovered peer before timeout")
        .expect("discovery channel open");
    assert_eq!(discovered, c.addr);

    b.session_mgr.disconnect_peer(&c.peer_id);
    c.session_mgr.disconnect_peer(&b.peer_id);
    wait_for_peer_count(&b, 1).await;
    wait_for_peer_count(&c, 0).await;
    sleep(Duration::from_millis(100)).await;

    let _ac = connect(&a, &c);
    wait_for_peer_count(&a, 2).await;
    wait_for_peer_count(&c, 1).await;

    a.shutdown();
    b.shutdown();
    c.shutdown();
}

#[tokio::test]
async fn test_panic_shutdown() {
    let _guard = integration_lock().await;
    let a = TestPeer::new(b"panic phrase").await;
    let b = TestPeer::new(b"panic phrase").await;
    let mut cancel_rx = a.session_mgr.cancel_rx();

    let _connection = connect_and_wait(&a, &b).await;
    a.session_mgr.panic_shutdown();

    timeout(TEST_TIMEOUT, cancel_rx.changed())
        .await
        .expect("cancel signal before timeout")
        .expect("cancel sender alive");
    assert!(*cancel_rx.borrow());

    b.shutdown();
}

#[tokio::test]
async fn test_display_name_persistence() {
    let _guard = integration_lock().await;
    let original_xdg = std::env::var_os("XDG_CONFIG_HOME");
    let temp_config_dir = unique_temp_config_dir();
    std::fs::create_dir_all(&temp_config_dir).expect("create temp config dir");

    unsafe {
        std::env::set_var("XDG_CONFIG_HOME", &temp_config_dir);
    }

    let saved = config::set_display_name("Sesame Tester").expect("save display name");
    let loaded = config::load_config();

    match original_xdg {
        Some(value) => unsafe {
            std::env::set_var("XDG_CONFIG_HOME", value);
        },
        None => unsafe {
            std::env::remove_var("XDG_CONFIG_HOME");
        },
    }
    std::fs::remove_dir_all(&temp_config_dir).expect("remove temp config dir");

    assert_eq!(saved.display_name.as_deref(), Some("Sesame Tester"));
    assert_eq!(loaded.display_name.as_deref(), Some("Sesame Tester"));
}

fn unique_temp_config_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("sesame-config-test-{}-{nanos}", std::process::id()))
}
