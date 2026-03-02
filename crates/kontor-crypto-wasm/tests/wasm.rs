use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
fn prepare_file_returns_metadata_and_prepared_file() {
    let file = b"hello".to_vec().into_boxed_slice();
    let nonce = b"".to_vec().into_boxed_slice();
    let result = kontor_crypto_wasm::prepare_file_wasm(file, "test.txt", nonce)
        .expect("prepare_file_wasm should succeed");

    let metadata = js_sys::Reflect::get(&result, &"metadata".into()).unwrap();
    assert!(!metadata.is_undefined(), "result must contain metadata");

    let root = js_sys::Reflect::get(&metadata, &"root".into())
        .unwrap()
        .as_string()
        .expect("root should be a string");
    assert!(root.len() >= 32, "root should be hex-encoded field element");

    let object_id = js_sys::Reflect::get(&metadata, &"objectId".into())
        .unwrap()
        .as_string()
        .unwrap();
    assert!(object_id.starts_with("obj_"));

    let file_id = js_sys::Reflect::get(&metadata, &"fileId".into())
        .unwrap()
        .as_string()
        .unwrap();
    assert!(file_id.starts_with("file_"));

    let original_size = js_sys::Reflect::get(&metadata, &"originalSize".into())
        .unwrap()
        .as_f64()
        .unwrap();
    assert_eq!(original_size, 5.0);

    let prepared_file = js_sys::Reflect::get(&result, &"preparedFile".into()).unwrap();
    assert!(
        !prepared_file.is_undefined(),
        "result must contain preparedFile"
    );

    let descriptor = js_sys::Reflect::get(&result, &"descriptor".into()).unwrap();
    assert!(!descriptor.is_undefined(), "result must contain descriptor");
}

#[wasm_bindgen_test]
fn prepare_file_empty_input_returns_error() {
    let file = b"".to_vec().into_boxed_slice();
    let nonce = b"".to_vec().into_boxed_slice();
    let result = kontor_crypto_wasm::prepare_file_wasm(file, "empty.txt", nonce);
    assert!(result.is_err(), "empty input must fail");
}

#[wasm_bindgen_test]
fn prepare_leaves_returns_leaf_bytes() {
    let file = b"hello".to_vec().into_boxed_slice();
    let nonce = b"nonce".to_vec().into_boxed_slice();
    let result =
        kontor_crypto_wasm::prepare_leaves(file, "test.txt", nonce).expect("should succeed");

    let leaf_bytes = js_sys::Reflect::get(&result, &"leafBytes".into()).unwrap();
    let arr: js_sys::Uint8Array = leaf_bytes
        .dyn_into()
        .expect("leafBytes should be Uint8Array");
    assert!(arr.length() > 0, "leafBytes should not be empty");
    assert_eq!(
        arr.length() % 32,
        0,
        "leafBytes length must be a multiple of 32"
    );

    let object_id = js_sys::Reflect::get(&result, &"objectId".into())
        .unwrap()
        .as_string()
        .unwrap();
    assert!(object_id.starts_with("obj_"));
}

#[wasm_bindgen_test]
fn prepare_leaves_empty_input_returns_error() {
    let file = b"".to_vec().into_boxed_slice();
    let nonce = b"".to_vec().into_boxed_slice();
    let result = kontor_crypto_wasm::prepare_leaves(file, "empty.txt", nonce);
    assert!(result.is_err(), "empty input must fail");
}

#[wasm_bindgen_test]
fn build_merkle_root_rejects_non_multiple_of_32() {
    let result = kontor_crypto_wasm::build_merkle_root(&[0u8; 33]);
    assert!(result.is_err(), "non-multiple of 32 must fail");
}

#[wasm_bindgen_test]
fn hash_nodes_rejects_wrong_size() {
    let left = vec![0u8; 31].into_boxed_slice();
    let right = vec![0u8; 32].into_boxed_slice();
    let result = kontor_crypto_wasm::hash_nodes(left, right);
    assert!(result.is_err(), "wrong size must fail");
}

#[wasm_bindgen_test]
fn parallel_pipeline_prepare_then_build_root() {
    let file = b"hello".to_vec().into_boxed_slice();
    let nonce = b"".to_vec().into_boxed_slice();
    let leaves_result =
        kontor_crypto_wasm::prepare_leaves(file, "test.txt", nonce).expect("prepare_leaves ok");

    let leaf_bytes_js = js_sys::Reflect::get(&leaves_result, &"leafBytes".into()).unwrap();
    let leaf_arr: js_sys::Uint8Array = leaf_bytes_js.dyn_into().unwrap();
    let leaf_bytes = leaf_arr.to_vec();

    let root = kontor_crypto_wasm::build_merkle_root(&leaf_bytes).expect("build_merkle_root ok");
    assert_eq!(root.len(), 32, "root must be 32 bytes");
}

#[wasm_bindgen_test]
fn nonce_changes_file_id_but_not_root() {
    let file1 = b"data".to_vec().into_boxed_slice();
    let nonce1 = b"".to_vec().into_boxed_slice();
    let r1 = kontor_crypto_wasm::prepare_file_wasm(file1, "f.bin", nonce1).unwrap();

    let file2 = b"data".to_vec().into_boxed_slice();
    let nonce2 = b"nonce".to_vec().into_boxed_slice();
    let r2 = kontor_crypto_wasm::prepare_file_wasm(file2, "f.bin", nonce2).unwrap();

    let m1 = js_sys::Reflect::get(&r1, &"metadata".into()).unwrap();
    let m2 = js_sys::Reflect::get(&r2, &"metadata".into()).unwrap();

    let oid1 = js_sys::Reflect::get(&m1, &"objectId".into())
        .unwrap()
        .as_string()
        .unwrap();
    let oid2 = js_sys::Reflect::get(&m2, &"objectId".into())
        .unwrap()
        .as_string()
        .unwrap();
    assert_eq!(oid1, oid2, "same content, same objectId");

    let fid1 = js_sys::Reflect::get(&m1, &"fileId".into())
        .unwrap()
        .as_string()
        .unwrap();
    let fid2 = js_sys::Reflect::get(&m2, &"fileId".into())
        .unwrap()
        .as_string()
        .unwrap();
    assert_ne!(fid1, fid2, "different nonce, different fileId");

    let root1 = js_sys::Reflect::get(&m1, &"root".into())
        .unwrap()
        .as_string()
        .unwrap();
    let root2 = js_sys::Reflect::get(&m2, &"root".into())
        .unwrap()
        .as_string()
        .unwrap();
    assert_eq!(root1, root2, "nonce must not affect Merkle root");
}
