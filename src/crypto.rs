use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub fn derive_key(phrase: &str, salt_a: &[u8; 32], salt_b: &[u8; 32]) -> Result<[u8; 32], String> {
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
        .hash_password_into(phrase.as_bytes(), &combined_salt, &mut output)
        .map_err(|e| e.to_string())?;

    try_mlock(&output);

    Ok(output)
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

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn sha256_two(data1: &[u8], data2: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data1);
    hasher.update(data2);
    hasher.finalize().into()
}

pub fn zeroize_key_material(keys: &mut [&mut [u8]]) {
    for key in keys {
        key.zeroize();
    }
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
