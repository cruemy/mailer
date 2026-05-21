use std::collections::{HashMap, HashSet};

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use sha2::{Digest, Sha256};
use x25519_dalek::PublicKey;
use zeroize::Zeroize;

use crate::crypto::{hkdf_derive, LockedDhSecret, LockedKey};

const DH_RATCHET_INTERVAL: u32 = 3;

pub struct DoubleRatchet {
    root_chain: LockedKey,
    send_chain: LockedKey,
    recv_chain: LockedKey,
    our_secret: Option<LockedDhSecret>,
    our_public: PublicKey,
    their_public: Option<PublicKey>,
    dh_counter: u32,
    msg_number_send: u64,
    msg_number_recv: u64,
    dh_epoch: u64,
    #[allow(dead_code)]
    max_skip: usize,
    skipped_keys: HashMap<(u64, [u8; 32]), [u8; 32]>,
    seen_messages: HashSet<(u64, u64)>,
}

pub struct EncryptedFrame {
    pub nonce: [u8; 12],
    pub msg_number: u64,
    pub dh_epoch: u64,
    pub ciphertext: Vec<u8>,
    pub tag: [u8; 16],
    pub dh_public_key: Option<PublicKey>,
}

pub struct ReceivedFrame {
    pub nonce: [u8; 12],
    pub msg_number: u64,
    pub dh_epoch: u64,
    pub ciphertext: Vec<u8>,
    pub tag: [u8; 16],
    pub dh_public_key: Option<PublicKey>,
}

impl DoubleRatchet {
    pub fn new(
        root_key: &[u8; 32],
        our_secret: LockedDhSecret,
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
            root_chain: LockedKey::new(*root_key),
            send_chain: LockedKey::new(send_chain),
            recv_chain: LockedKey::new(recv_chain),
            our_secret: Some(our_secret),
            our_public,
            their_public,
            dh_counter: 0,
            msg_number_send: 0,
            msg_number_recv: 0,
            dh_epoch: 0,
            max_skip,
            skipped_keys: HashMap::new(),
            seen_messages: HashSet::new(),
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8], aad_prefix: &[u8]) -> EncryptedFrame {
        let msg_number = self.msg_number_send;
        let dh_epoch = self.dh_epoch;
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

        let msg_key = hkdf_derive(self.send_chain.as_bytes(), b"sesame-msg");
        self.send_chain.replace(Sha256::digest(self.send_chain.as_bytes()).into());
        self.msg_number_send += 1;
        self.dh_counter += 1;

        let nonce = crate::crypto::generate_random_bytes::<12>();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&msg_key));
        let aad = frame_aad(aad_prefix, msg_number, dh_epoch, dh_public_key.is_some());

        let mut ciphertext = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(&Nonce::from_slice(&nonce), &aad, &mut ciphertext)
            .expect("ChaCha20Poly1305 encryption failed");

        EncryptedFrame {
            nonce,
            msg_number,
            dh_epoch,
            ciphertext,
            tag: tag.into(),
            dh_public_key,
        }
    }

    pub fn decrypt(&mut self, frame: &ReceivedFrame, aad_prefix: &[u8]) -> Result<Vec<u8>, &'static str> {
        if frame.dh_epoch < self.dh_epoch || self.seen_messages.contains(&(frame.dh_epoch, frame.msg_number)) {
            return Err("replay or stale message");
        }
        if frame.dh_epoch > self.dh_epoch + 1 || frame.msg_number > self.msg_number_recv + self.max_skip as u64 {
            return Err("message too far in the future");
        }

        if let Some(new_pub) = &frame.dh_public_key {
            self.dh_ratchet_recv(*new_pub);
        }

        let msg_key = hkdf_derive(self.recv_chain.as_bytes(), b"sesame-msg");
        self.recv_chain.replace(Sha256::digest(self.recv_chain.as_bytes()).into());
        self.msg_number_recv += 1;

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&msg_key));
        let mut plaintext = frame.ciphertext.clone();
        let aad = frame_aad(aad_prefix, frame.msg_number, frame.dh_epoch, frame.dh_public_key.is_some());
        cipher
            .decrypt_in_place_detached(
                &Nonce::from_slice(&frame.nonce),
                &aad,
                &mut plaintext,
                &frame.tag.into(),
            )
            .map_err(|_| "decryption failed")?;

        self.seen_messages.insert((frame.dh_epoch, frame.msg_number));

        Ok(plaintext)
    }

    fn dh_ratchet_send(&mut self, their_public: PublicKey) -> PublicKey {
        let new_secret = LockedDhSecret::generate();
        let new_public = new_secret.public_key();
        let shared = new_secret.diffie_hellman(&their_public);
        let shared_bytes = shared.as_bytes();

        let mut new_root = [0u8; 32];
        crate::crypto::hkdf_expand_with_salt(
            self.root_chain.as_bytes(),
            shared_bytes,
            b"sesame-dh-ratchet",
            &mut new_root,
        );

        let new_send = hkdf_derive(&new_root, b"sesame-recv");
        let new_recv = hkdf_derive(&new_root, b"sesame-send");
        self.send_chain.replace(new_send);
        self.recv_chain.replace(new_recv);
        self.root_chain.replace(new_root);
        new_root.zeroize();
        self.dh_epoch += 1;

        self.our_secret = Some(new_secret);

        new_public
    }

    fn dh_ratchet_recv(&mut self, their_new_public: PublicKey) {
        let old_secret = self.our_secret.take().expect("no DH secret available");
        let shared = old_secret.diffie_hellman(&their_new_public);
        let shared_bytes = shared.as_bytes();

        let mut new_root = [0u8; 32];
        crate::crypto::hkdf_expand_with_salt(
            self.root_chain.as_bytes(),
            shared_bytes,
            b"sesame-dh-ratchet",
            &mut new_root,
        );

        let new_send = hkdf_derive(&new_root, b"sesame-send");
        let new_recv = hkdf_derive(&new_root, b"sesame-recv");
        self.send_chain.replace(new_send);
        self.recv_chain.replace(new_recv);
        self.root_chain.replace(new_root);
        new_root.zeroize();
        self.their_public = Some(their_new_public);
        self.dh_counter = 0;
        self.dh_epoch += 1;

        let new_secret = LockedDhSecret::generate();
        let new_public = new_secret.public_key();
        self.our_secret = Some(new_secret);
        self.our_public = new_public;
    }
}

impl Drop for DoubleRatchet {
    fn drop(&mut self) {
        for (_, key) in self.skipped_keys.iter_mut() {
            key.zeroize();
        }
    }
}

fn frame_aad(prefix: &[u8], msg_number: u64, dh_epoch: u64, has_dh_pub: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(prefix.len() + 17);
    aad.extend_from_slice(prefix);
    aad.extend_from_slice(&msg_number.to_be_bytes());
    aad.extend_from_slice(&dh_epoch.to_be_bytes());
    aad.push(u8::from(has_dh_pub));
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ratchet_pair() -> (DoubleRatchet, DoubleRatchet) {
        let root = [7u8; 32];
        let a_secret = LockedDhSecret::generate();
        let a_public = a_secret.public_key();
        let b_secret = LockedDhSecret::generate();
        let b_public = b_secret.public_key();
        (
            DoubleRatchet::new(&root, a_secret, a_public, Some(b_public), true, 100),
            DoubleRatchet::new(&root, b_secret, b_public, Some(a_public), false, 100),
        )
    }

    #[test]
    fn decrypt_rejects_wrong_aad() {
        let (mut sender, mut receiver) = ratchet_pair();
        let frame = sender.encrypt(b"hello", b"aad-a");

        assert!(receiver.decrypt(&ReceivedFrame {
            nonce: frame.nonce,
            msg_number: frame.msg_number,
            dh_epoch: frame.dh_epoch,
            ciphertext: frame.ciphertext,
            tag: frame.tag,
            dh_public_key: frame.dh_public_key,
        }, b"aad-b").is_err());
    }

    #[test]
    fn decrypt_rejects_replay() {
        let (mut sender, mut receiver) = ratchet_pair();
        let frame = sender.encrypt(b"hello", b"aad");
        let received = ReceivedFrame {
            nonce: frame.nonce,
            msg_number: frame.msg_number,
            dh_epoch: frame.dh_epoch,
            ciphertext: frame.ciphertext.clone(),
            tag: frame.tag,
            dh_public_key: frame.dh_public_key,
        };

        assert_eq!(receiver.decrypt(&received, b"aad").unwrap(), b"hello");
        assert!(receiver.decrypt(&received, b"aad").is_err());
    }
}
