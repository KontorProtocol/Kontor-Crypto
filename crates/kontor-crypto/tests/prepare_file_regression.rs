//! Golden-value regression for prepare_file output.
//!
//! These expected values were generated with the current implementation
//! and guard against silent changes in the prepare_file pipeline
//! (Reed-Solomon encoding, Poseidon Merkle tree, ID generation).

use kontor_crypto::api::prepare_file;
use kontor_crypto::utils::field_to_hex;

#[test]
fn prepare_file_hello_deterministic() {
    let data = b"hello";
    let filename = "test.txt";
    let nonce: &[u8] = b"";
    let (prepared, metadata) = prepare_file(data, filename, nonce).unwrap();

    assert_eq!(
        metadata.object_id,
        "obj_2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
    assert_eq!(
        metadata.file_id,
        "file_78f9691e17c086afe6b54bfbf3dc845f8f169dd61b9e1b3d5774eef89c651d42"
    );
    assert_eq!(metadata.original_size, 5);
    assert_eq!(metadata.filename, "test.txt");
    assert_eq!(metadata.padded_len, 256);
    assert!(metadata.padded_len.is_power_of_two());

    assert_eq!(
        field_to_hex(&metadata.root),
        "f38690053b5a535fdbba69f3aa2f24d0f5c3134019e6d26d1121f64bb3413507"
    );

    assert_eq!(prepared.root, metadata.root);
    assert_eq!(prepared.file_id, metadata.file_id);
}

#[test]
fn prepare_file_with_nonce_changes_file_id() {
    let data = b"hello";
    let filename = "test.txt";

    let (_, meta1) = prepare_file(data, filename, b"").unwrap();
    let (_, meta2) = prepare_file(data, filename, b"nonce1").unwrap();
    assert_eq!(meta1.object_id, meta2.object_id);
    assert_ne!(meta1.file_id, meta2.file_id);
    assert_eq!(
        meta2.file_id,
        "file_44f87b13abd124de5bcc42913647a61bbfe212135401f9fefb1d566ad1a87b43"
    );
    assert_eq!(meta1.root, meta2.root);
}
