use std::collections::HashMap;

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroize;

use crate::crypto::hkdf_derive;

const DH_RATCHET_INTERVAL: u32 = 3;

pub struct DoubleRatchet {
    root_chain: [u8; 32],
    send_chain: [u8; 32],
    recv_chain: [u8; 32],
    our_secret: Option<EphemeralSecret>,
    our_public: PublicKey,
    their_public: Option<PublicKey>,
    dh_counter: u32,
    msg_number_send: u64,
    msg_number_recv: u64,
    max_skip: usize,
    skipped_keys: HashMap<(u64, [u8; 32]), [u8; 32]>,
}

pub struct EncryptedFrame {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub tag: [u8; 16],
    pub dh_public_key: Option<PublicKey>,
}

pub struct ReceivedFrame {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub tag: [u8; 16],
    pub dh_public_key: Option<PublicKey>,
}

impl DoubleRatchet {
    pub fn new(
        root_key: &[u8; 32],
        our_secret: EphemeralSecret,
        our_public: PublicKey,
        their_public: Option<PublicKey>,
        initiator: bool,
        max_skip: usize,
    ) -> Self {
        let (send_chain, recv_chain) = if initiator {
            (hkdf_derive(root_key, b"sesame-send"), hkdf_derive(root_key, b"sesame-recv"))
        } else {
            (hkdf_derive(root_key, b"sesame-recv"), hkdf_derive(root_key, b"sesame-send"))
        };

        Self {
            root_chain: *root_key,
            send_chain,
            recv_chain,
            our_secret: Some(our_secret),
            our_public,
            their_public,
            dh_counter: 0,
            msg_number_send: 0,
            msg_number_recv: 0,
            max_skip,
            skipped_keys: HashMap::new(),
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> EncryptedFrame {
        let dh_public_key = if self.dh_counter % DH_RATCHET_INTERVAL == 0 {
            if let Some(their_pub) = self.their_public {
                let new_pub = self.dh_ratchet_send(their_pub);
                Some(new_pub)
            } else {
                None
            }
        } else {
            None
        };

        let msg_key = hkdf_derive(&self.send_chain, b"sesame-msg");
        self.send_chain = Sha256::digest(&self.send_chain).into();
        self.msg_number_send += 1;
        self.dh_counter += 1;

        let nonce = crate::crypto::generate_random_bytes::<12>();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&msg_key));

        let mut ciphertext = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(&Nonce::from_slice(&nonce), b"", &mut ciphertext)
            .expect("ChaCha20Poly1305 encryption failed");

        EncryptedFrame {
            nonce,
            ciphertext,
            tag: tag.into(),
            dh_public_key,
        }
    }

    pub fn decrypt(&mut self, frame: &ReceivedFrame) -> Result<Vec<u8>, &'static str> {
        if let Some(new_pub) = &frame.dh_public_key {
            self.dh_ratchet_recv(*new_pub);
        }

        let msg_key = hkdf_derive(&self.recv_chain, b"sesame-msg");
        self.recv_chain = Sha256::digest(&self.recv_chain).into();
        self.msg_number_recv += 1;

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&msg_key));
        let mut plaintext = frame.ciphertext.clone();
        cipher
            .decrypt_in_place_detached(
                &Nonce::from_slice(&frame.nonce),
                b"",
                &mut plaintext,
                &frame.tag.into(),
            )
            .map_err(|_| "decryption failed")?;

        Ok(plaintext)
    }

    fn dh_ratchet_send(&mut self, their_public: PublicKey) -> PublicKey {
        let old_secret = self.our_secret.take().expect("no DH secret available");
        let shared = old_secret.diffie_hellman(&their_public);
        let shared_bytes = shared.as_bytes();

        let mut new_root = [0u8; 32];
        crate::crypto::hkdf_expand_with_salt(
            &self.root_chain,
            shared_bytes,
            b"sesame-dh-ratchet",
            &mut new_root,
        );

        self.send_chain = hkdf_derive(&new_root, b"sesame-send");
        self.recv_chain = hkdf_derive(&new_root, b"sesame-recv");
        self.root_chain = new_root;

        let new_secret = EphemeralSecret::random_from_rng(&mut rand::rngs::OsRng);
        let new_public = PublicKey::from(&new_secret);
        self.our_secret = Some(new_secret);

        new_public
    }

    fn dh_ratchet_recv(&mut self, their_new_public: PublicKey) {
        let old_secret = self.our_secret.take().expect("no DH secret available");
        let shared = old_secret.diffie_hellman(&their_new_public);
        let shared_bytes = shared.as_bytes();

        let mut new_root = [0u8; 32];
        crate::crypto::hkdf_expand_with_salt(
            &self.root_chain,
            shared_bytes,
            b"sesame-dh-ratchet",
            &mut new_root,
        );

        self.send_chain = hkdf_derive(&new_root, b"sesame-send");
        self.recv_chain = hkdf_derive(&new_root, b"sesame-recv");
        self.root_chain = new_root;
        self.their_public = Some(their_new_public);
        self.dh_counter = 0;

        let new_secret = EphemeralSecret::random_from_rng(&mut rand::rngs::OsRng);
        let new_public = PublicKey::from(&new_secret);
        self.our_secret = Some(new_secret);
        self.our_public = new_public;
    }
}

impl Drop for DoubleRatchet {
    fn drop(&mut self) {
        self.root_chain.zeroize();
        self.send_chain.zeroize();
        self.recv_chain.zeroize();
        for (_, key) in self.skipped_keys.iter_mut() {
            key.zeroize();
        }
    }
}
