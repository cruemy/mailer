#![no_main]
#![allow(dead_code)]

use libfuzzer_sys::fuzz_target;

#[path = "../../src/protocol.rs"]
mod protocol;

fuzz_target!(|data: &[u8]| {
    let _ = protocol::remove_padding(data);
});
