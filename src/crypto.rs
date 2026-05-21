use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use sha2::Digest;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

pub struct LockedBytes {
    bytes: Box<[u8]>,
}

impl LockedBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        let locked = Self {
            bytes: bytes.into_boxed_slice(),
        };
        try_mlock(locked.as_bytes());
        locked
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for LockedBytes {
    fn drop(&mut self) {
        self.bytes.zeroize();
        try_munlock(self.as_bytes());
    }
}

pub struct LockedKey {
    bytes: Box<[u8; 32]>,
}

impl LockedKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        let key = Self {
            bytes: Box::new(bytes),
        };
        try_mlock(key.as_bytes());
        key
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    pub fn replace(&mut self, bytes: [u8; 32]) {
        self.bytes.zeroize();
        self.bytes.copy_from_slice(&bytes);
        let mut new_bytes = bytes;
        new_bytes.zeroize();
        try_mlock(self.as_bytes());
    }
}

impl Drop for LockedKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
        try_munlock(self.as_bytes());
    }
}

pub struct LockedDhSecret {
    bytes: LockedKey,
}

impl LockedDhSecret {
    pub fn generate() -> Self {
        Self {
            bytes: LockedKey::new(generate_random_bytes::<32>()),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        let secret = StaticSecret::from(*self.bytes.as_bytes());
        PublicKey::from(&secret)
    }

    pub fn diffie_hellman(&self, peer: &PublicKey) -> LockedKey {
        let secret = StaticSecret::from(*self.bytes.as_bytes());
        LockedKey::new(secret.diffie_hellman(peer).to_bytes())
    }
}

pub fn derive_key(phrase: &[u8], salt_a: &[u8; 32], salt_b: &[u8; 32]) -> Result<LockedKey, String> {
    let combined_salt = {
        let mut s = [0u8; 64];
        if salt_a < salt_b {
            s[..32].copy_from_slice(salt_a);
            s[32..].copy_from_slice(salt_b);
        } else {
            s[..32].copy_from_slice(salt_b);
            s[32..].copy_from_slice(salt_a);
        }
        s
    };

    let params = Params::new(65536, 3, 4, Some(32)).map_err(|e| e.to_string())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = [0u8; 32];
    argon2
        .hash_password_into(phrase, &combined_salt, &mut output)
        .map_err(|e| e.to_string())?;

    Ok(LockedKey::new(output))
}

pub fn hkdf_derive(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).expect("HKDF expand failed");
    okm
}

pub fn hkdf_expand_with_salt(salt: &[u8], ikm: &[u8], info: &[u8], output: &mut [u8]) {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    hk.expand(info, output).expect("HKDF expand failed");
}

pub fn sha256_many(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

pub fn generate_random_bytes<const N: usize>() -> [u8; N] {
    use rand::RngCore;
    let mut bytes = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}

pub fn try_mlock(data: &[u8]) -> bool {
    let ptr = data.as_ptr() as *const std::ffi::c_void;
    match unsafe { os_memlock::mlock(ptr, data.len()) } {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
            false
        }
        Err(e) => {
            eprintln!("[sesame] mlock failed: {e}");
            false
        }
    }
}

pub fn try_munlock(data: &[u8]) {
    let ptr = data.as_ptr() as *const std::ffi::c_void;
    let _ = unsafe { os_memlock::munlock(ptr, data.len()) };
}
