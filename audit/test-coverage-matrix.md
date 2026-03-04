# Test Coverage Matrix

Date: 2026-02-13

## Summary
- Enumerated tests (`cargo test --workspace -- --list`): **282**
- Integration test files under `tests/`: **38**
- Fuzz targets under `fuzz/fuzz_targets/`: **4**

## Security-critical module coverage map

| Module / Surface | Primary tests | Property style | Fuzz | Notes |
|---|---|---|---|---|
| `src/api/types.rs` (challenge IDs, serialization, metadata validation) | `api_functionality.rs`, `validation.rs`, `verifier_edge_cases.rs` | deterministic/collision-style checks | `proof_from_bytes`, `challenge_id` | Canonical ID encoding and bounds guarded |
| `src/api/prove.rs` / `src/api/verify.rs` | `api_consistency.rs`, `security_replay_attack.rs`, `security_negative_cases.rs`, `security_malicious_prover.rs` | scenario properties | indirect via parser fuzz targets | Duplicate challenge rejection + binding validated |
| `src/circuit/synth.rs` | `circuit_unit_tests.rs`, `circuit_wiring.rs`, `circuit_uniformity*.rs`, `security_constraint_regressions.rs` | shape/wiring invariants | N/A | Constraint regression locks in place |
| `src/circuit/synth.rs` (inactive-slot canonicalization) | `security_padding_slot_canonicalization.rs` | adversarial mutation | N/A | Ensures padding-slot public inputs are forced to canonical zeros |
| `src/circuit/synth.rs` (active-flag prefix constraints) | `security_active_flags_prefix_regression.rs` | constraint presence regression | N/A | Ensures active_flags prefix-ones constraints exist |
| `src/ledger.rs` | `security_ledger.rs`, `ledger_batch_add.rs`, `ledger_state_changes.rs`, `security_ledger_policy.rs` | lifecycle/state properties | `ledger_load` | Retention policy now explicitly tested |
| `src/erasure.rs` | `validation.rs`, unit tests in `erasure.rs` | boundary scenario checks | `decode_file_symbols` | Panic-resistant decode path fuzzed |
| `src/merkle.rs` / `src/utils.rs` | `primitives_merkle.rs`, `public_leaf_exposure.rs`, `security_challenge_distribution.rs` | statistical/challenge distribution checks | future extension | Core path and helper behavior covered |

## Design findings addressed in this pass
1. Replaced placeholder fuzzing design with real fuzz harness + corpus.
2. Added dedicated ledger policy test file for retention/pruning behavior.
3. Consolidated synthetic metadata test helper in `tests/common/fixtures.rs` to reduce duplication.
4. Updated `tests/README.md` to remove stale entries and reflect actual suite structure.

## Remaining improvement opportunities
1. Add structured mutation testing around verification preconditions.
2. Expand nightly fuzz corpora from CI artifacts and production malformed samples.
3. Introduce explicit per-module coverage thresholds once `llvm-cov` policy is finalized in CI.
4. Review mutation-test defaults once `cargo mutants` results stabilize for this crate and CI runtime budgets are known.
