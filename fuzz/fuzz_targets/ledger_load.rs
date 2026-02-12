#![no_main]

use libfuzzer_sys::fuzz_target;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

fuzz_target!(|data: &[u8]| {
    let capped = &data[..data.len().min(64 * 1024)];

    let mut hasher = DefaultHasher::new();
    capped.hash(&mut hasher);
    let digest = hasher.finish();

    let path = std::env::temp_dir().join(format!(
        "kontor_ledger_fuzz_{}_{}.bin",
        std::process::id(),
        digest
    ));

    let _ = std::fs::write(&path, capped);
    let _ = kontor_crypto::FileLedger::load(&path);
    let _ = std::fs::remove_file(path);
});
