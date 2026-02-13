# Kontor-Crypto Security Audit - Technical Report

Date: 2026-02-13
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

### FND-006: Non-circuit challenge fields were not cryptographically bound at verification
- Severity: High
- Affected area: `src/api/{plan,prove,verify}.rs`, `src/config.rs`
- Description:
  - Verification checked `proof.challenge_ids`, but that vector is prover-controlled and not part of the SNARK statement.
  - An attacker could rewrite `proof.challenge_ids` and rebind non-circuit fields (e.g., `block_height`, `prover_id`) without changing the compressed proof.
- Remediation:
  - Added deterministic challenge-set binding into the recursive statement:
    - derive `initial_state` from ordered challenge IDs
    - thread this value through `z0_primary[1]` and witness state evolution
  - Prove/verify now require the same challenge-set-derived initial state, making rebinding fail cryptographically.
- Evidence:
  - Added test:
    - `tests/security_replay_attack.rs::test_verify_raw_rejects_rebinding_even_with_rewritten_proof_challenge_ids`

### FND-007: Plan ledger-membership derivation accepted rc-only collisions
- Severity: Medium
- Affected area: `src/api/plan.rs`
- Description:
  - Plan derivation resolved ledger membership by root-commitment (`rc`) lookup only.
  - This allowed ambiguous/non-member `file_id` challenges to map to some other ledger entry with matching `(root, depth)`.
- Remediation:
  - Switched plan derivation to exact `file_id` membership (`ledger.lookup(file_id)`).
  - Added explicit consistency check that the ledger entry `rc` matches challenge metadata `(root, depth)`.
- Evidence:
  - Added test:
    - `tests/security_replay_attack.rs::test_verify_raw_rejects_non_member_file_id_even_with_matching_root`

### FND-008: Parameter-cache mutex poisoning could trigger panic-based DoS
- Severity: Low
- Affected area: `src/params.rs`
- Description:
  - Parameter-cache access used `Mutex::lock().expect(...)`.
  - If any thread panicked while holding the lock, subsequent calls would panic and deny service.
- Remediation:
  - Added centralized lock helper that recovers poisoned state via `into_inner()`.
  - Emits warning telemetry and continues operation with the recovered cache.

### FND-009: CI workflows referenced unpinned GitHub Actions (supply-chain hardening)
- Severity: Low
- Affected area: `.github/workflows/*.yml`
- Description:
  - Some workflows referenced GitHub Actions by moving tags (e.g. `@v4`, `@stable`), which widens the supply-chain trust boundary.
- Remediation:
  - Pinned `actions/checkout` and Rust toolchain setup to immutable SHAs.
  - Standardized caching on `Swatinem/rust-cache` (already pinned) to reduce bespoke caching logic.

### FND-010: Inactive-slot public inputs were not explicitly forced to canonical zeros
- Severity: Low
- Affected area: `src/circuit/synth.rs`, `tests/security_padding_slot_canonicalization.rs`
- Description:
  - The circuit has fixed arity and includes per-slot public inputs even when a slot is inactive (`public_depth == 0`).
  - Enforcing canonical zeros for inactive-slot per-slot fields removes ambiguity and prevents future misuse where callers treat those fields as meaningful statement components.
- Remediation:
  - Added explicit constraints for inactive slots:
    - `inactive * ledger_index_public == 0`
    - `inactive * seed_public == 0`
    - `inactive * expected_rc_public == 0`
    - `inactive * leaf_input == 0`
  - Added a constraint-system regression test asserting non-zero values make the circuit unsatisfied.

### FND-011: Active-flag Merkle depth gating allowed non-prefix patterns
- Severity: Medium
- Affected area: `src/circuit/synth.rs`, `src/circuit/gadgets/merkle.rs`
- Description:
  - File-tree Merkle verification uses per-level boolean `active_flags` to gate hashing for a variable effective depth.
  - Constraining only `sum(active_flags) == public_depth` is insufficient; it allows non-prefix patterns (e.g. `1,0,1,0,...`) that do not correspond to a well-formed depth truncation.
- Remediation:
  - Enforced a prefix-ones pattern via constraints: for each level `i > 0`, `active[i] => active[i-1]`.
  - Added a regression test that asserts the prefix constraints are present in the synthesized constraint system.

## Validation executed
- `cargo test --test api_functionality -- --nocapture`
- `cargo test --test validation -- --nocapture`
- `cargo test --test verifier_edge_cases -- --nocapture`
- `cargo test --test circuit_uniformity_regression -- --nocapture`
- `cargo test --test security_constraint_regressions -- --nocapture`
- `cargo test --test security_padding_slot_canonicalization -- --nocapture`
- `cargo test --test security_active_flags_prefix_regression -- --nocapture`
- `cargo test --test security_replay_attack -- --nocapture`
- `cargo test --test security_malicious_prover -- --nocapture`
- `cargo test --test security_ledger -- --nocapture`
- `cargo test --test api_consistency -- --nocapture`
- `cargo test --test security_negative_cases -- --nocapture`
- `cargo test --test security_medium_priority -- --nocapture`
- `cargo test --test regression -- --nocapture`
- `cargo test --workspace`
- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features -- -D warnings`

## Residual status update
All previously tracked low-priority residuals have been closed:
1. Real fuzz targets implemented under `fuzz/`.
2. Historical root retention policy codified and tested.
3. CI fuzz corpus regression and bounded fuzz campaigns added via `security-fuzz.yml`.
