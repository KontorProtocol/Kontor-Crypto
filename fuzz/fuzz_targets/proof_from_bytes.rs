#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = kontor_crypto::api::Proof::from_bytes(data);
});
