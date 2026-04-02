#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let num_codewords = (data[0] as usize % 4) + 1;
    let expected_symbols = num_codewords * kontor_crypto::config::TOTAL_SYMBOLS_PER_CODEWORD;

    let mut symbols: Vec<Option<Vec<u8>>> = Vec::with_capacity(expected_symbols);
    let mut cursor = 1usize;

    for _ in 0..expected_symbols {
        let tag = data.get(cursor).copied().unwrap_or(0);
        cursor = cursor.saturating_add(1);

        if tag % 4 == 0 {
            symbols.push(None);
            continue;
        }

        let sym_len = match tag % 3 {
            0 => kontor_crypto::config::CHUNK_SIZE_BYTES,
            1 => kontor_crypto::config::CHUNK_SIZE_BYTES.saturating_sub(1),
            _ => kontor_crypto::config::CHUNK_SIZE_BYTES + 1,
        };

        let mut sym = vec![0u8; sym_len];
        for byte in &mut sym {
            *byte = data.get(cursor).copied().unwrap_or(0);
            cursor = cursor.saturating_add(1);
        }
        symbols.push(Some(sym));
    }

    let original_size = if data.len() >= 9 {
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&data[1..9]);
        usize::try_from(u64::from_le_bytes(arr)).unwrap_or(usize::MAX)
    } else {
        0
    };

    let _ = kontor_crypto::erasure::decode_file_symbols(&mut symbols, num_codewords, original_size);
});
