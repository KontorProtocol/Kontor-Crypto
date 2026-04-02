#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let root = kontor_crypto::api::FieldElement::from(
        data.iter()
            .fold(0u64, |acc, b| acc.wrapping_mul(167).wrapping_add(*b as u64)),
    );

    let file_id = format!("file_{:x}", data.iter().fold(0u64, |acc, b| acc ^ (*b as u64)));
    let object_id = format!("obj_{:x}", data.len());
    let filename = format!("f_{}.dat", data.len());
    let nonce = data[..data.len().min(64)].to_vec();

    let depth = (data.get(0).copied().unwrap_or(0) % 10) as usize + 1;
    let padded_len = 1usize << depth;
    let original_size = usize::from(data.get(1).copied().unwrap_or(0)) + 1;

    let metadata = kontor_crypto::api::FileMetadata {
        root,
        object_id,
        file_id,
        nonce,
        padded_len,
        original_size,
        filename,
    };

    let seed = kontor_crypto::api::FieldElement::from(
        data.iter().rev().fold(0u64, |acc, b| acc.wrapping_add(*b as u64)),
    );
    let prover_id = format!("prover_{}", data.get(2).copied().unwrap_or(0));
    let num_challenges = (data.get(3).copied().unwrap_or(0) % 16) as usize + 1;

    let challenge = kontor_crypto::api::Challenge::new(metadata, 1000, num_challenges, seed, prover_id);

    let _ = challenge.validate();
    let id1 = challenge.id();
    let id2 = challenge.id();
    assert_eq!(id1, id2);
});
