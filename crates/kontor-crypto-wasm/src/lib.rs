//! WASM bindings for Kontor `prepare_file`: browser-callable API returning metadata and prepared file.

use kontor_crypto_core::{prepare_file, FileMetadata, PreparedFile};
use kontor_crypto_core::poseidon::FieldElement;
use ff::PrimeField;
use serde::Serialize;
use wasm_bindgen::prelude::*;

/// Converts a field element to its canonical hex string (lowercase).
fn field_to_hex(f: &FieldElement) -> String {
    use std::fmt::Write;
    let repr = f.to_repr();
    repr.as_ref()
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{:02x}", b);
            s
        })
}

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

/// Prepares file data for PoR: takes raw file bytes, filename, and nonce; returns metadata and prepared file.
///
/// # Arguments
/// - `file`: raw file content (Uint8Array)
/// - `filename`: file name (string)
/// - `nonce`: nonce bytes (Uint8Array)
///
/// # Returns
/// JS object: `{ metadata: { root, objectId, fileId, nonce, paddedLen, originalSize, filename }, preparedFile: { root, fileId, treeLeavesHex } }`
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
    };
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kontor_crypto_core::prepare_file;

    /// Same input as Node example: ensures metadata shape and that core output matches expected.
    #[test]
    fn prepare_file_metadata_consistency() {
        let file = b"hello";
        let filename = "test.txt";
        let nonce: &[u8] = b"";
        let (prepared, metadata) = prepare_file(file, filename, nonce).unwrap();
        let meta_out = metadata_to_out(&metadata);
        let prep_out = prepared_file_to_out(&prepared);

        assert!(meta_out.root.len() >= 32, "root should be hex-encoded field element");
        assert!(meta_out.object_id.starts_with("obj_"), "objectId format");
        assert!(meta_out.file_id.starts_with("file_"), "fileId format");
        assert_eq!(meta_out.original_size, 5);
        assert_eq!(meta_out.filename, "test.txt");
        assert_eq!(meta_out.root, prep_out.root);
        assert_eq!(meta_out.file_id, prep_out.file_id);
        assert!(!prep_out.tree_leaves_hex.is_empty(), "tree should have leaves");
    }
}
