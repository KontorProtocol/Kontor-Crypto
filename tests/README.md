# Test Suite Overview

This suite validates protocol soundness, boundary hardening, and regression safety for Kontor PoR.

## Current inventory
- Integration/unit-style test files under `tests/`: 38
- Executed test cases (`cargo test --workspace -- --list`): 275
- Fuzzing: real targets under `fuzz/` (not `tests/`)

## Structure by responsibility

### API and boundary validation
- `api_functionality.rs`
- `api_consistency.rs`
- `validation.rs`
- `verifier_edge_cases.rs`

Focus:
- proof serialization/deserialization bounds
- metadata/challenge validation contracts
- prove/verify API consistency and misuse resistance

### Circuit and proof semantics
- `circuit_unit_tests.rs`
- `circuit_wiring.rs`
- `circuit_uniformity.rs`
- `circuit_uniformity_regression.rs`
- `security_constraint_regressions.rs`
- `depth_zero_cheat_regression.rs`
- `padding_slot_zero_regression.rs`

Focus:
- constraint completeness
- wiring consistency (on/off-circuit)
- shape uniformity and depth gating invariants

### Security behavior
- `security.rs`
- `security_comprehensive.rs`
- `security_negative_cases.rs`
- `security_replay_attack.rs`
- `security_malicious_prover.rs`
- `security_medium_priority.rs`
- `security_challenge_distribution.rs`

Focus:
- anti-replay and substitution resistance
- malicious input/adversarial prover behavior
- domain separation and challenge derivation properties

### Ledger security and lifecycle
- `security_ledger.rs`
- `security_ledger_policy.rs`
- `security_ledger_range_check.rs`
- `security_ledger_root_pinning.rs`
- `ledger_batch_add.rs`
- `ledger_state_changes.rs`

Focus:
- historical root validation and retention policy
- index/range constraints
- persistence and tamper handling
- state evolution correctness

### End-to-end and integration behavior
- `e2e_single_file.rs`
- `e2e_circuit_uniformity.rs`
- `e2e_variable_depth.rs`
- `e2e_large_file.rs`
- `complex_aggregation.rs`

### Primitive and support coverage
- `primitives_merkle.rs`
- `public_leaf_exposure.rs`
- `shape_derivation.rs`
- `single_file_depth_mismatch.rs`
- `documentation_consistency.rs`
- `regression.rs`

## Shared test utilities
- `tests/common/fixtures.rs`
- `tests/common/assertions.rs`
- `tests/common/mod.rs`

## Fuzzing
Fuzzing targets are implemented in:
- `fuzz/fuzz_targets/proof_from_bytes.rs`
- `fuzz/fuzz_targets/ledger_load.rs`
- `fuzz/fuzz_targets/decode_file_symbols.rs`
- `fuzz/fuzz_targets/challenge_id.rs`

Seed corpora are in `fuzz/corpus/<target>/`.

## Running tests

### Full suite
```bash
cargo test --workspace
```

### Targeted security suites
```bash
cargo test --test security_ledger -- --nocapture
cargo test --test security_replay_attack -- --nocapture
cargo test --test security_constraint_regressions -- --nocapture
```

### Formatting and lint checks
```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
```

### Fuzz smoke locally
```bash
cargo install cargo-fuzz --locked
cargo fuzz run proof_from_bytes fuzz/corpus/proof_from_bytes -- -runs=256 -max_total_time=20
```

## Conventions
- Prefer deterministic fixtures and explicit seeds.
- Keep tests assertion-first; avoid verbose logging in stable tests.
- Any security bug fix must include at least one regression test.
