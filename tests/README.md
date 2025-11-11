# Test Suite Organization

This directory contains comprehensive tests for the Kontor PoR system, organized by category and purpose.

## Test Categories

### Unit Tests (`src/lib.rs`)
Core library unit tests embedded in source files:
- **commitment::tests**: Domain separation verification
- **erasure::tests**: Reed-Solomon encoding/decoding
- **circuit_safety::tests**: Witness validation
- **params::tests**: Parameter cache key generation

### API Tests
**`api_consistency.rs`**: Cross-function consistency checks
- State evolution matches between API and circuit
- Ledger requirements enforced correctly
- Single vs multi-file behavior

**`api_functionality.rs`**: Core API functionality
- `prepare_file()` / `PorSystem` equivalence
- Challenge ID determinism and collision resistance
- Proof serialization/deserialization
- Multi-seed batch validation

### Circuit Tests
**`circuit_unit_tests.rs`**: Low-level circuit behavior
- Basic constraint satisfaction
- Accumulator updates
- Invalid input rejection
- Conditional selection gadget

**`circuit_wiring.rs`**: Circuit-to-API consistency
- Poseidon hash gadget matches off-circuit implementation
- Challenge index derivation consistency
- State chaining correctness
- Arecibo first-step no-op invariant

**`circuit_uniformity.rs`**: Constraint count uniformity
- Circuit structure consistency across depths
- Setup vs proving shape matching

**`circuit_uniformity_regression.rs`**: Historical uniformity bugs
- Parameter generation vs proving shape matching
- Witness depth validation
- Malformed metadata rejection

### End-to-End Tests
**`e2e_single_file.rs`**: Complete single-file workflows
- Basic proof generation and verification
- Multiple challenges
- Different file sizes and erasure configs
- Deterministic behavior

**`e2e_circuit_uniformity.rs`**: Multi-depth consistency
- Same parameters work across different depths
- Deterministic behavior across depths
- Depth 0-3 compatibility

**`e2e_erasure_coding.rs`**: Erasure coding integration
- Different erasure configurations
- Reconstruction workflows
- Mixed configurations

**`e2e_variable_depth.rs`**: Variable depth multi-file
- Files with different depths in same proof
- Large depth differences

### Security Tests
**`security.rs`**: Core security properties
- Valid proofs accepted
- Tampered proofs rejected
- Deterministic challenge calculation
- File integrity through hashing
- Erasure coding security

**`security_comprehensive.rs`**: Domain separation enforcement
- Commitment calculations use correct tags
- Challenge derivation uses domain separation
- Merkle operations use correct tags

**`security_ledger.rs`**: Ledger-specific security
- Duplicate file rejection
- Tamper detection on load
- Ordering consistency
- Proof invalidation after updates

**`security_ledger_root_pinning.rs`**: Root substitution prevention
- Wrong aggregated root fails verification

**`security_ledger_range_check.rs`**: Index validation
- Verifier responsibility for range checking
- Bit-masking attack prevention

**`security_malicious_prover.rs`**: Adversarial scenarios
- Depth spoofing attacks
- Incorrect ledger indices
- Metadata root mismatches
- Index ordering constraints

**`security_medium_priority.rs`**: Additional security checks
- Gating uniformity
- Meta commitment binding
- Multi-file challenge separation
- Single vs multi-file equivalence

**`security_negative_cases.rs`**: Expected failures
- Empty data rejection
- Wrong (root, depth) pairs
- Different num_challenges rejection
- Different seeds (now allowed for multi-batch)

**`security_replay_attack.rs`**: Replay protection
- Wrong seed rejection
- Wrong step count rejection

**`security_challenge_distribution.rs`**: Challenge distribution properties
- Uniform distribution (slow, usually ignored)
- Unbiased index derivation

### Regression Tests
**`regression.rs`**: Previously fixed bugs
- Depth-zero special case (InvalidSumcheckProof)
- Circuit uniformity across depths
- Parameter generation consistency
- Deterministic BTreeMap ordering
- Erasure coding edge cases

**`depth_zero_cheat_regression.rs`**: Depth spoofing prevention
- Active flags enforce correct depth
- Depth-zero cheat attempts blocked

**`padding_slot_zero_regression.rs`**: Padding slot security
- Padding slots don't diverge state
- Gating logic correctness

**`circuit_uniformity_regression.rs`**: Shape matching
- Parameter generation matches proving
- Witness depth validation
- Malformed metadata rejection

### Validation Tests
**`validation.rs`**: Input validation
- Empty/zero size handling
- Challenge count validation
- File size extremes
- Chunk size boundaries
- Metadata consistency
- Different erasure configs
- Mismatched challenge parameters
- Reconstruction failure modes

**`verifier_edge_cases.rs`**: Verifier edge cases
- Inconsistent metadata
- Malformed metadata
- Duplicate file challenges

### Integration Tests
**`complex_aggregation.rs`**: Complex multi-file scenarios
- Highly heterogeneous depths
- Maximum file aggregation
- Awkward file count padding
- Single file with various depths

**`ledger_state_changes.rs`**: Ledger evolution
- Proof invalidation after file updates
- Ledger reorganization effects
- File removal invalidation

### Supporting Tests
**`shape_derivation.rs`**: Circuit shape calculation
- Basic shape derivation
- Power-of-two handling
- Edge cases
- Parameter cache consistency

**`single_file_depth_mismatch.rs`**: Single-file depth handling
- Depth mismatch rejection
- Zero depth acceptance

**`public_leaf_exposure.rs`**: Public leaf binding
- Leaf values exposed correctly
- Multi-file leaf exposure
- Bytes31 field helpers

**`primitives_merkle.rs`**: Merkle tree primitives
- Tree building
- Proof generation
- Verification
- Adversarial attacks
- Hashing properties

**`documentation_consistency.rs`**: Documentation vs implementation
- Circuit arity matches constants
- Chunk size constant validity
- Domain tag uniqueness
- Challenge derivation method
- Proof format version awareness

**`fuzzing_targets.rs`**: Fuzzing support (no tests, infrastructure only)

## Running Tests

### All tests with nextest (recommended):
```bash
cargo nextest run --release
```

### Specific category:
```bash
cargo nextest run --release --test security
cargo nextest run --release --test e2e_single_file
```

### Specific test:
```bash
cargo nextest run --release test_name
```

### Legacy cargo test:
```bash
cargo test --release
```

## Test Markers

### Ignored Tests
Some tests are marked `#[ignore]` for performance reasons:
- `test_proof_determinism`: Determinism check (slow)
- `test_challenge_distribution_is_uniform`: Statistical test (very slow)
- `test_unbiased_index_derivation_non_power_of_two`: Statistical test (very slow)

Run ignored tests with:
```bash
cargo nextest run --release -- --ignored
```

### Slow Tests
Tests that take >60s are marked SLOW by nextest:
- `test_challenge_id_collision_resistance`: ~91s (cryptographic collision test)
- `test_chunk_size_boundary_conditions`: ~55s (multiple complete workflows)

These are kept running by default as they test important properties.

## Test Conventions

### Naming
- `test_*`: Standard test
- `regression_*`: Prevents reintroduction of a specific bug
- `test_*_fails_*`: Expected failure scenario

### Output
Tests use `println!()` for informative output showing what's being tested and results.
Use `cargo nextest run` for clean, organized output.

## Common Test Helpers

Located in `tests/common/`:
- **fixtures.rs**: Test scenario setup, FileSpec, TestConfig
- **assertions.rs**: Reusable assertion helpers
- **helpers.rs**: Ledger creation, challenge building

### Creating Test Scenarios
```rust
use common::fixtures::{setup_test_scenario, TestConfig, FileSpec};

// Simple single-file test
let setup = setup_test_scenario(&TestConfig::default()).unwrap();

// Multi-file test
let setup = setup_test_scenario(&TestConfig::multi_file(3)).unwrap();

// Custom configuration
let setup = setup_test_scenario(&TestConfig {
    file_specs: vec![FileSpec::from_size(1024), FileSpec::from_size(2048)],
    challenges_per_file: 5,
    seed: 12345,
}).unwrap();
```

### Common Assertions
```rust
use common::assertions::{assert_prove_and_verify_succeeds, assert_prove_fails};

assert_prove_and_verify_succeeds(setup);
assert_prove_fails(setup, "expected error substring");
```

## Performance Notes

- Tests run with optimizations by default
- Use `nextest` for parallel execution and better output
- Some tests generate cryptographic parameters (slow first run, then cached)
- File sizes in tests are kept small (typically 100B-64KB) for speed

