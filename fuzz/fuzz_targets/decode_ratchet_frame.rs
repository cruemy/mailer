#![no_main]
#![allow(dead_code)]

use libfuzzer_sys::fuzz_target;

mod auth {
    include!("../../src/auth.rs");
}
mod config {
    include!("../../src/config.rs");
}
mod crypto {
    include!("../../src/crypto.rs");
}
mod obfuscate {
    include!("../../src/obfuscate.rs");
}
mod os_hardening {
    include!("../../src/os_hardening.rs");
}
mod panic {
    include!("../../src/panic.rs");
}
mod protocol {
    include!("../../src/protocol.rs");
}
mod ratchet {
    include!("../../src/ratchet.rs");
}
mod session {
    include!("../../src/session.rs");
}
mod tls {
    include!("../../src/tls.rs");
}
mod tui {
    include!("../../src/tui.rs");
}
mod types {
    include!("../../src/types.rs");
}

mod peer_harness {
    include!("../../src/peer.rs");

    pub fn decode(data: &[u8]) {
        let _ = decode_ratchet_frame(data);
    }
}

fuzz_target!(|data: &[u8]| {
    peer_harness::decode(data);
});
