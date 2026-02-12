# Kontor-Crypto Security Audit - Technical Report

Date: 2026-02-12
Scope: protocol/API/circuit boundary review, malformed-input resilience, proof binding, replay/substitution resistance, ledger serialization integrity.

## Methodology
- Static review of security-critical modules:
  - `src/api/{mod,types,prove,verify,system,plan}.rs`
  - `src/{erasure,ledger,config}.rs`
  - `src/circuit/synth.rs`
- Adversarial regression additions and updates.
- Targeted security suite execution.

## Confirmed findings and remediation

### FND-001: Potential panic and malformed-input handling gap in symbol decoding
- Severity: High
- Affected area: `src/erasure.rs`
- Description:
  - `decode_file_symbols` previously trusted `num_codewords` and symbol-vector shape, allowing malformed combinations to hit invalid slicing behavior.
- Remediation:
  - Added strict pre-validation:
    - `num_codewords > 0`
    - exact expected symbol count
    - per-symbol byte-length checks (`31` bytes)
    - encoded-capacity overflow and bounds checks
  - Decoder now returns structured `InvalidInput` errors for malformed input.
- Evidence:
  - Added tests in `tests/validation.rs`:
    - `test_reconstruct_rejects_symbol_count_mismatch_without_panic`
    - `test_reconstruct_rejects_invalid_symbol_length`

### FND-002: Missing metadata invariant enforcement at API boundaries
- Severity: High
- Affected area: `src/api/types.rs`, `src/api/{mod,prove,verify,plan,system}.rs`
- Description:
  - Proof and verification flows accepted logically inconsistent metadata fields.
- Remediation:
  - Added `FileMetadata::validate()` with checks for:
    - power-of-two/non-zero `padded_len`
    - bounded sizes/lengths
    - derived symbol-count consistency
    - `padded_len` consistency with `original_size`
  - Added `Challenge::validate()` and enforced in prove/verify paths.
- Evidence:
  - Updated regression behavior:
    - `tests/verifier_edge_cases.rs`
    - `tests/circuit_uniformity_regression.rs`

### FND-003: Duplicate challenge acceptance (resource abuse / statement ambiguity)
- Severity: Medium
- Affected area: `src/api/{prove,verify,system}.rs`
- Description:
  - Duplicate challenge sets were previously accepted in proving flow.
- Remediation:
  - Added duplicate detection by `ChallengeID` using `HashSet` in prove/verify entry points.
- Evidence:
  - Updated test:
    - `tests/verifier_edge_cases.rs::test_duplicate_file_challenges_fail_verification`

### FND-004: Ambiguous challenge-ID encoding / incomplete metadata binding
- Severity: Medium
- Affected area: `src/api/types.rs`
- Description:
  - Challenge IDs used concatenation of variable-length fields without explicit delimiting.
  - ID binding omitted some metadata fields and used depth from `trailing_zeros(padded_len)`.
- Remediation:
  - Challenge ID derivation now uses canonical length-delimited encoding for variable-length fields.
  - Includes `padded_len`, `original_size`, and `nonce` in binding.
  - Uses raw `padded_len` instead of inferred depth.
- Evidence:
  - Added test:
    - `tests/api_functionality.rs::test_challenge_id_uses_canonical_length_delimited_encoding`

### FND-005: Missing public input guardrails for API abuse resistance
- Severity: Medium
- Affected area: `src/config.rs`, `src/api/mod.rs`, `src/api/types.rs`
- Description:
  - Unbounded filename/nonce/input size handling increased DoS exposure.
- Remediation:
  - Added max bounds:
    - `MAX_FILE_SIZE_BYTES`
    - `MAX_FILENAME_LEN_BYTES`
    - `MAX_IDENTIFIER_LEN_BYTES`
    - `MAX_NONCE_LEN_BYTES`
  - Enforced in `prepare_file` and metadata/challenge validation.

## Validation executed
- `cargo test --test api_functionality -- --nocapture`
- `cargo test --test validation -- --nocapture`
- `cargo test --test verifier_edge_cases -- --nocapture`
- `cargo test --test circuit_uniformity_regression -- --nocapture`
- `cargo test --test security_constraint_regressions -- --nocapture`
- `cargo test --test security_replay_attack -- --nocapture`
- `cargo test --test security_malicious_prover -- --nocapture`
- `cargo test --test security_ledger -- --nocapture`
- `cargo test --test api_consistency -- --nocapture`
- `cargo test --test security_negative_cases -- --nocapture`
- `cargo test --test security_medium_priority -- --nocapture`
- `cargo test --test regression -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --all-targets -- -D warnings`

Note: `cargo clippy --all-targets --all-features -- -D warnings` could not be run in this environment due network-restricted dependency fetch for optional feature crates.

## Open items (non-blocking)
1. Implement real fuzz targets (current `tests/fuzzing_targets.rs` is scaffolding).
2. Define and enforce operational policy for historical-root retention horizon.
3. Add CI job for parser/reconstruction fuzzing corpus regression.
