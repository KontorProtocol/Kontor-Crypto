//! End-to-end test for large file handling

use kontor_crypto::api::{self, Challenge, FieldElement, PorSystem};
use std::collections::BTreeMap;
use std::time::Instant;

#[test]
fn test_50mb_file_preparation_and_proof() {
    println!("Testing 50 MB file preparation and proof generation...");

    // Create 50 MB of test data
    const FILE_SIZE: usize = 50 * 1024 * 1024; // 50 MB
    let test_data = vec![0x42u8; FILE_SIZE];

    // Use a simple erasure config

    // Prepare the file
    println!("  Preparing {} MB file...", FILE_SIZE / (1024 * 1024));
    let start = Instant::now();
    let (prepared, metadata) =
        api::prepare_file(&test_data, "large_test.dat", b"").expect("Failed to prepare 50 MB file");
    let prep_duration = start.elapsed();

    // Verify metadata makes sense
    assert_eq!(
        metadata.original_size, FILE_SIZE,
        "Original size should match input"
    );
    assert!(metadata.total_symbols() > 0, "Should have encoded symbols");
    assert!(
        metadata.padded_len >= metadata.total_symbols(),
        "Padded length should be >= total symbols"
    );
    println!("  ✓ File prepared successfully in {:.2?}", prep_duration);
    println!("    Original size: {} bytes", metadata.original_size);
    println!("    Total symbols: {}", metadata.total_symbols());
    println!("    Padded length: {}", metadata.padded_len);
    println!(
        "    Tree depth: {}",
        api::tree_depth_from_metadata(&metadata)
    );

    // Create a simple challenge
    let challenge = Challenge::new_test(metadata.clone(), 1000, 1, FieldElement::from(42u64));

    // Create file map
    let mut files = BTreeMap::new();
    files.insert(metadata.file_id.clone(), &prepared);

    // Create ledger
    let mut ledger = kontor_crypto::FileLedger::new();
    ledger
        .add_file(&metadata)
        .expect("Failed to add file to ledger");

    // Generate proof
    println!("  Generating proof...");
    let system = PorSystem::new(&ledger);
    let files_vec: Vec<&_> = files.values().copied().collect();
    let start = Instant::now();
    let proof = system
        .prove(files_vec, std::slice::from_ref(&challenge))
        .expect("Failed to generate proof for 50 MB file");
    let prove_duration = start.elapsed();
    println!("  ✓ Proof generated successfully in {:.2?}", prove_duration);

    // Verify proof
    println!("  Verifying proof...");
    let start = Instant::now();
    let is_valid = system
        .verify(&proof, &[challenge])
        .expect("Failed to verify proof");
    let verify_duration = start.elapsed();
    assert!(is_valid, "Proof should verify successfully");
    println!("  ✓ Proof verified successfully in {:.2?}", verify_duration);

    let total_duration = prep_duration + prove_duration + verify_duration;
    println!("✓ 50 MB file end-to-end test passed");
    println!("  Total time: {:.2?}", total_duration);
}
