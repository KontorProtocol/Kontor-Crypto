//! WASM bindings for Kontor `prepare_file`: browser-callable API returning metadata and prepared file.

#![deny(unsafe_code)]

use ff::PrimeField;
use kontor_crypto_core::utils::field_to_hex;
use kontor_crypto_core::{prepare_file, FileMetadata, PreparedFile};
use serde::Serialize;
use wasm_bindgen::prelude::*;

/// Metadata returned to JS (root as hex, objectId, fileId, etc.).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetadataOut {
    pub root: String,
    pub object_id: String,
    pub file_id: String,
    pub nonce: Vec<u8>,
    pub padded_len: usize,
    pub original_size: usize,
    pub filename: String,
}

/// Prepared file data for the prover (root, fileId, tree leaves as hex).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedFileOut {
    pub root: String,
    pub file_id: String,
    pub tree_leaves_hex: Vec<String>,
}

/// Result of prepareFile: metadata + prepared file.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareResult {
    pub metadata: MetadataOut,
    pub prepared_file: PreparedFileOut,
    /// Descriptor ready for filestorage `create_agreement`.
    /// Shape mirrors `RawFileDescriptor` from `kontor:built-in/file-registry`.
    pub descriptor: RawFileDescriptorOut,
}

/// File descriptor payload expected by filestorage `create_agreement`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RawFileDescriptorOut {
    pub file_id: String,
    pub object_id: String,
    pub nonce: Vec<u8>,
    /// Canonical field bytes (`to_repr`) expected by host `from_raw` (exactly 32 bytes).
    pub root: Vec<u8>,
    pub padded_len: u64,
    pub original_size: u64,
    pub filename: String,
}

fn metadata_to_out(m: &FileMetadata) -> MetadataOut {
    MetadataOut {
        root: field_to_hex(&m.root),
        object_id: m.object_id.clone(),
        file_id: m.file_id.clone(),
        nonce: m.nonce.clone(),
        padded_len: m.padded_len,
        original_size: m.original_size,
        filename: m.filename.clone(),
    }
}

fn prepared_file_to_out(p: &PreparedFile) -> PreparedFileOut {
    let leaves = p
        .tree
        .layers
        .first()
        .map(|layer| layer.iter().map(field_to_hex).collect())
        .unwrap_or_default();
    PreparedFileOut {
        root: field_to_hex(&p.root),
        file_id: p.file_id.clone(),
        tree_leaves_hex: leaves,
    }
}

fn metadata_to_descriptor_out(m: &FileMetadata) -> RawFileDescriptorOut {
    RawFileDescriptorOut {
        file_id: m.file_id.clone(),
        object_id: m.object_id.clone(),
        nonce: m.nonce.clone(),
        root: m.root.to_repr().as_ref().to_vec(),
        padded_len: m.padded_len as u64,
        original_size: m.original_size as u64,
        filename: m.filename.clone(),
    }
}

/// Prepares file data for PoR: takes raw file bytes, filename, and nonce; returns metadata and prepared file.
///
/// # Arguments
/// - `file`: raw file content (Uint8Array)
/// - `filename`: file name (string)
/// - `nonce`: nonce bytes (Uint8Array)
///
/// # Returns
/// JS object:
/// `{ metadata, preparedFile, descriptor }`
///
/// `descriptor` is directly usable for filestorage `create_agreement`:
/// `{ fileId, objectId, nonce, root, paddedLen, originalSize, filename }`
/// where `root` is a 32-byte array (not hex).
///
/// # Errors
/// Returns a JS Error if input is empty or encoding fails.
#[wasm_bindgen(js_name = prepareFile)]
pub fn prepare_file_wasm(
    file: Box<[u8]>,
    filename: &str,
    nonce: Box<[u8]>,
) -> Result<JsValue, JsValue> {
    let (prepared, metadata) = prepare_file(file.as_ref(), filename, nonce.as_ref())
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let result = PrepareResult {
        metadata: metadata_to_out(&metadata),
        prepared_file: prepared_file_to_out(&prepared),
        descriptor: metadata_to_descriptor_out(&metadata),
    };
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Prepares leaf data for parallel Merkle tree computation.
///
/// Does everything EXCEPT building the Merkle tree: SHA256 for IDs,
/// RS-encode, pad to power of two, convert each chunk to a 32-byte
/// field element representation.
///
/// Returns a JS object:
/// `{ leafBytes: Uint8Array, objectId, fileId, paddedLen, originalSize, filename, nonce }`
#[wasm_bindgen(js_name = prepareLeaves)]
pub fn prepare_leaves(
    file: Box<[u8]>,
    filename: &str,
    nonce: Box<[u8]>,
) -> Result<JsValue, JsValue> {
    use kontor_crypto_core::config;
    use kontor_crypto_core::erasure::encode_file_symbols;
    use kontor_crypto_core::merkle::get_leaf_hash;
    use sha2::{Digest, Sha256};

    if file.is_empty() {
        return Err(JsValue::from_str("empty file"));
    }

    let mut object_hasher = Sha256::new();
    object_hasher.update(file.as_ref());
    let object_id = format!("obj_{:x}", object_hasher.finalize());

    let mut file_hasher = Sha256::new();
    file_hasher.update(b"kontor.file_id.v1");
    file_hasher.update((file.len() as u64).to_le_bytes());
    file_hasher.update(file.as_ref());
    file_hasher.update((nonce.len() as u64).to_le_bytes());
    file_hasher.update(nonce.as_ref());
    let file_id = format!("file_{:x}", file_hasher.finalize());

    let all_symbols =
        encode_file_symbols(file.as_ref()).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let padded_len = all_symbols.len().next_power_of_two();
    let mut padded_symbols = all_symbols;
    padded_symbols.resize(padded_len, vec![0; config::CHUNK_SIZE_BYTES]);

    let mut leaf_bytes = Vec::with_capacity(padded_len * 32);
    for chunk in &padded_symbols {
        let fe = get_leaf_hash(chunk).map_err(|e| JsValue::from_str(&e.to_string()))?;
        leaf_bytes.extend_from_slice(fe.to_repr().as_ref());
    }

    let result = js_sys::Object::new();
    let leaf_arr = js_sys::Uint8Array::from(leaf_bytes.as_slice());
    js_sys::Reflect::set(&result, &"leafBytes".into(), &leaf_arr)?;
    js_sys::Reflect::set(&result, &"objectId".into(), &JsValue::from_str(&object_id))?;
    js_sys::Reflect::set(&result, &"fileId".into(), &JsValue::from_str(&file_id))?;
    js_sys::Reflect::set(
        &result,
        &"paddedLen".into(),
        &JsValue::from_f64(padded_len as f64),
    )?;
    js_sys::Reflect::set(
        &result,
        &"originalSize".into(),
        &JsValue::from_f64(file.len() as f64),
    )?;
    js_sys::Reflect::set(&result, &"filename".into(), &JsValue::from_str(filename))?;
    let nonce_arr = js_sys::Uint8Array::from(nonce.as_ref());
    js_sys::Reflect::set(&result, &"nonce".into(), &nonce_arr)?;

    Ok(result.into())
}

/// Builds a Merkle tree from a flat `Uint8Array` of 32-byte field element
/// representations and returns the 32-byte root.
///
/// Designed to run inside a Web Worker on a subset of leaves for parallel
/// tree construction.
#[wasm_bindgen(js_name = buildMerkleRoot)]
pub fn build_merkle_root(leaf_bytes: &[u8]) -> Result<Box<[u8]>, JsValue> {
    use kontor_crypto_core::merkle::build_tree_from_leaves;
    use kontor_crypto_core::poseidon::FieldElement;

    if !leaf_bytes.len().is_multiple_of(32) {
        return Err(JsValue::from_str(
            "leafBytes length must be a multiple of 32",
        ));
    }

    let leaves: Vec<FieldElement> = leaf_bytes
        .chunks(32)
        .map(|chunk| {
            let mut repr = <FieldElement as PrimeField>::Repr::default();
            repr.as_mut().copy_from_slice(chunk);
            let opt: Option<FieldElement> = FieldElement::from_repr(repr).into();
            opt.ok_or_else(|| JsValue::from_str("invalid field element in leafBytes"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let tree = build_tree_from_leaves(&leaves).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let root = tree.root();
    Ok(root.to_repr().as_ref().to_vec().into_boxed_slice())
}

/// Hashes two 32-byte field elements using the Merkle internal-node hash
/// (Poseidon, domain-tagged). Used to combine sub-roots from parallel workers.
#[wasm_bindgen(js_name = hashNodes)]
pub fn hash_nodes(left_bytes: Box<[u8]>, right_bytes: Box<[u8]>) -> Result<Box<[u8]>, JsValue> {
    use kontor_crypto_core::merkle::hash_node;
    use kontor_crypto_core::poseidon::FieldElement;

    if left_bytes.len() != 32 || right_bytes.len() != 32 {
        return Err(JsValue::from_str("each input must be exactly 32 bytes"));
    }

    let mut left_repr = <FieldElement as PrimeField>::Repr::default();
    left_repr.as_mut().copy_from_slice(&left_bytes);
    let left: Option<FieldElement> = FieldElement::from_repr(left_repr).into();
    let left = left.ok_or_else(|| JsValue::from_str("invalid left field element"))?;

    let mut right_repr = <FieldElement as PrimeField>::Repr::default();
    right_repr.as_mut().copy_from_slice(&right_bytes);
    let right: Option<FieldElement> = FieldElement::from_repr(right_repr).into();
    let right = right.ok_or_else(|| JsValue::from_str("invalid right field element"))?;

    let result = hash_node(left, right);
    Ok(result.to_repr().as_ref().to_vec().into_boxed_slice())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kontor_crypto_core::prepare_file;
    use kontor_crypto_core::utils::field_to_hex;

    #[test]
    fn prepare_file_metadata_consistency() {
        let file = b"hello";
        let filename = "test.txt";
        let nonce: &[u8] = b"";
        let (prepared, metadata) = prepare_file(file, filename, nonce).unwrap();
        let meta_out = metadata_to_out(&metadata);
        let prep_out = prepared_file_to_out(&prepared);

        assert!(
            meta_out.root.len() >= 32,
            "root should be hex-encoded field element"
        );
        assert!(meta_out.object_id.starts_with("obj_"), "objectId format");
        assert!(meta_out.file_id.starts_with("file_"), "fileId format");
        assert_eq!(meta_out.original_size, 5);
        assert_eq!(meta_out.filename, "test.txt");
        assert_eq!(meta_out.root, prep_out.root);
        assert_eq!(meta_out.file_id, prep_out.file_id);
        assert!(
            !prep_out.tree_leaves_hex.is_empty(),
            "tree should have leaves"
        );

        let desc = metadata_to_descriptor_out(&metadata);
        assert_eq!(desc.file_id, meta_out.file_id);
        assert_eq!(desc.object_id, meta_out.object_id);
        assert_eq!(desc.nonce, meta_out.nonce);
        assert_eq!(desc.padded_len, meta_out.padded_len as u64);
        assert_eq!(desc.original_size, meta_out.original_size as u64);
        assert_eq!(desc.filename, meta_out.filename);
        assert_eq!(desc.root.len(), 32, "descriptor.root must be 32 bytes");
    }

    #[test]
    fn prepare_file_empty_input_returns_error() {
        let result = prepare_file(b"", "empty.txt", b"");
        assert!(result.is_err(), "empty input must fail");
    }

    #[test]
    fn descriptor_root_matches_metadata_field_repr() {
        let (_, metadata) = prepare_file(b"hello", "test.txt", b"").unwrap();
        let desc = metadata_to_descriptor_out(&metadata);
        let meta_out = metadata_to_out(&metadata);

        let root_hex_from_bytes: String =
            desc.root
                .iter()
                .fold(String::with_capacity(64), |mut s, b| {
                    use std::fmt::Write;
                    let _ = write!(s, "{:02x}", b);
                    s
                });
        assert_eq!(
            root_hex_from_bytes, meta_out.root,
            "descriptor.root bytes must match metadata.root hex"
        );

        assert_eq!(
            root_hex_from_bytes,
            field_to_hex(&metadata.root),
            "descriptor.root must be canonical to_repr of the field element"
        );
    }

    #[test]
    fn prepare_file_multi_codeword() {
        let data = vec![42u8; 15_000];
        let (prepared, metadata) = prepare_file(&data, "big.bin", b"nonce").unwrap();
        let meta_out = metadata_to_out(&metadata);
        let prep_out = prepared_file_to_out(&prepared);

        assert!(
            meta_out.padded_len >= 765,
            "15 KB needs 3 codewords (765 symbols), padded to next power of two"
        );
        assert!(
            (meta_out.padded_len as u64).is_power_of_two(),
            "padded_len must be power of two"
        );
        assert_eq!(meta_out.original_size, 15_000);
        assert_eq!(
            prep_out.tree_leaves_hex.len(),
            meta_out.padded_len,
            "tree leaves count must equal padded_len"
        );
        assert_eq!(meta_out.root, prep_out.root);

        let desc = metadata_to_descriptor_out(&metadata);
        assert_eq!(desc.original_size, 15_000);
        assert_eq!(desc.padded_len, meta_out.padded_len as u64);
    }

    #[test]
    fn prepare_file_nonce_changes_file_id_not_root() {
        let (_, m1) = prepare_file(b"data", "f.bin", b"").unwrap();
        let (_, m2) = prepare_file(b"data", "f.bin", b"nonce").unwrap();
        assert_eq!(m1.object_id, m2.object_id, "same content, same object_id");
        assert_ne!(m1.file_id, m2.file_id, "different nonce, different file_id");
        assert_eq!(m1.root, m2.root, "nonce must not affect Merkle root");
    }

    #[test]
    fn parallel_root_matches_sequential() {
        use kontor_crypto_core::config;
        use kontor_crypto_core::erasure::encode_file_symbols;
        use kontor_crypto_core::merkle::{build_tree_from_leaves, get_leaf_hash, hash_node};
        use kontor_crypto_core::poseidon::FieldElement;

        let data = vec![42u8; 15_000];
        let (_, metadata) = prepare_file(&data, "test.bin", b"nonce").unwrap();
        let sequential_root = metadata.root;

        let all_symbols = encode_file_symbols(&data).unwrap();
        let padded_len = all_symbols.len().next_power_of_two();
        let mut padded_symbols = all_symbols;
        padded_symbols.resize(padded_len, vec![0; config::CHUNK_SIZE_BYTES]);

        let leaves: Vec<FieldElement> = padded_symbols
            .iter()
            .map(|chunk| get_leaf_hash(chunk).unwrap())
            .collect();

        let num_workers = 4usize;
        let chunk_size = leaves.len() / num_workers;
        let mut sub_roots = Vec::new();
        for i in 0..num_workers {
            let start = i * chunk_size;
            let end = (i + 1) * chunk_size;
            let sub_tree = build_tree_from_leaves(&leaves[start..end]).unwrap();
            sub_roots.push(sub_tree.root());
        }

        while sub_roots.len() > 1 {
            let mut next = Vec::new();
            for pair in sub_roots.chunks(2) {
                next.push(hash_node(pair[0], pair[1]));
            }
            sub_roots = next;
        }
        let parallel_root = sub_roots[0];

        assert_eq!(
            sequential_root, parallel_root,
            "parallel root must match sequential root"
        );
    }
}
