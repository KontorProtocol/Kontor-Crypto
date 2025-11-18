# Overview

Kontor-Crypto implements Proof-of-Retrievability using recursive SNARKs. Storage nodes generate proofs (~10KB, ~30ms to verify) demonstrating possession of challenged file sectors without revealing data. Challenges are derived deterministically from public randomness. The system must prevent proof forgery, replay attacks, ledger substitution, metadata tampering, and DoS.

# Critical Code Paths

### 1. Circuit Constraint Logic (`src/circuit/synth.rs`)

`synthesize_por_circuit()` defines R1CS constraints enforcing proof validity. Verify: constraint completeness, gating logic for padding slots, uniformity (fixed constraint count), public input binding of security-critical values.

### 2. Challenge Generation (`src/utils.rs`, `src/commitment.rs`)

`derive_index_unbiased()` and `poseidon_hash_tagged()` determine audited data. Challenges must be unpredictable, uniformly distributed, domain-separated, deterministic, and unbiased.

### 3. Public Input Construction (`src/api/plan.rs`, `src/api/prove.rs`, `src/api/verify.rs`)

`Plan::make_plan()` and `build_z0_primary()` bind proofs to specific files and ledger state. Public I/O layout in `src/config.rs::PublicIOLayout` (lines 46-181). Verify prover/verifier construct identical inputs, aggregated root derived from verifier's ledger only, canonical ordering, no prover-controlled values.

### 4. Ledger Root Pinning (`src/api/plan.rs` lines 46-52)

Single-file proofs use file root from metadata; multi-file uses `ledger.tree.root()` from verifier's ledger. Prover cannot influence which root is used.

### 5. Proof Verification (`src/api/verify.rs`)

`verify()` performs validation before SNARK verification. Check error vs invalid proof distinction (`Ok(false)` vs `Err`), no panics on malformed input, challenge ID binding.

### 6. Serialization (`src/api/types.rs`)

`Proof::from_bytes()` / `to_bytes()` handle network boundary. Verify buffer overflow protection, version validation, trailing data rejection, fixed encoding.

### 7. Nova Recursive SNARK Semantics (`src/api/prove.rs` lines 268-278, 282-376)

Arecibo's `prove_step` has deliberate first-call no-op: `RecursiveSNARK::new()` synthesizes step 0, first `prove_step()` bumps counter only. Must call `prove_step()` exactly N times for N challenges, verify with `num_steps = N`. Check loop counts, off-by-one errors, state updates during no-op, proving/verification step count match.

### 8. Gating Logic (`src/circuit/synth.rs` lines 280-296, 442-462)

`depth_is_positive` (OR of public depth bits) gates processing to slots with `public_depth > 0`. State updates (442-448), leaf outputs (450-462), root verification (404-418) all gated. Padding slots (depth=0) cannot forge proofs.

### 9. State Chain (`src/commitment.rs`, `src/circuit/synth.rs`)

`state_new = H(TAG_STATE_UPDATE, state_old, leaf)` cryptographically links sequential steps, preventing reordering and ensuring all challenges are covered. Verify TAG_STATE_UPDATE = 7, proper state threading, no step skipping.

### 10. Fixed-Size Symbol Storage (`src/api/mod.rs`)

Files are chunked into fixed 31-byte symbols (max field element size for Pallas curve). Multi-codeword Reed-Solomon encoding (231 data + 24 parity symbols per codeword, ~10% overhead). Each 31-byte symbol = one Merkle leaf. This ensures provers must store actual data (not just hashes), preventing hash-only attacks. Verify fixed symbol size enforcement, power-of-2 tree padding, symbol-level RS encoding.

## Cryptographic Assumptions

**Poseidon Hash** (`neptune`): collision resistance, preimage resistance, random oracle in domain-separated contexts.

**Nova SNARKs** (`nova-snark` v0.41.0): soundness, completeness, knowledge soundness.

**Pallas/Vesta Curves** (`pasta_curves`): discrete log hardness, cycle properties.

**Reed-Solomon** (`reed-solomon-erasure` v6.0.0): reconstruction guarantees.

Verify version pinning, security advisories, no known vulnerabilities, component compatibility.

# Input Validation

| Function | Inputs | DoS Risk | Handled |
|----------|--------|----------|---------|
| `prepare_file()` | data size, filename | Large files | ✅ |
| `Challenge::new()` | num_challenges, prover_id | Extreme values | ✅ |
| `prove()` | challenges.len(), num_challenges | Resource exhaustion | ✅ |
| `verify()` | proof bytes, challenges | Malformed data | ✅ |
| `reconstruct_file()` | sector count, metadata | Invalid combinations | ✅ |
| `FileLedger::load()` | file size, contents | Large/malformed files | ✅ |

**Boundary conditions:** empty inputs, maximum sizes (file/challenge/ledger count), zero values (depth, size, count), type boundaries (usize::MAX, u64::MAX).

## Security Properties

### Soundness
Prover cannot generate valid proof without data. Check circuit constraints (`synth.rs`), Merkle path validation, state chaining (prevents step skipping), no freely-chosen witness values. Tests: `security_malicious_prover.rs` (9).

### Completeness
Honest prover always succeeds. Review error paths in `prove()`, witness generation for valid cases, no false rejections. Tests: all e2e.

### Binding
Proof bound to specific challenges and ledger. Public inputs include aggregated_root (from ledger), challenge IDs derived deterministically (includes prover_id), verified before SNARK check, state chain creates temporal binding. Tests: `security_replay_attack.rs`, `security_ledger_root_pinning.rs`.

### Determinism
Same inputs → same outputs. No randomness, canonical ordering (BTreeMap), fixed serialization. Tests: `regression.rs`, `api_consistency.rs`.

## Attack Vectors

### Malformed Proof Bytes (`Proof::from_bytes()`)
Parser vulnerabilities, buffer overflows. Mitigations: magic byte validation, length checks, trailing data rejection, version validation.

### Resource Exhaustion (`prove()`, parameter generation)
Memory exhaustion, DoS. Limits: MAX_NUM_CHALLENGES (10,000), PRACTICAL_MAX_FILES (1,024), parameter cache (50), no unbounded loops.

### Integer Overflow (sector calculations, index arithmetic)
Checked arithmetic, documented type conversions, bounds enforced before casts.

### Depth/Metadata Tampering (challenge construction, verification)
Root commitment binds (root, depth): `rc = H(TAG_RC, root, depth)`. Public depth in circuit, ledger lookup uses rc, gating prevents depth=0 abuse.

### Ledger Substitution (multi-file verification)
Verifier derives aggregated root from its own ledger, not prover-supplied, cryptographically bound via public inputs.

### State Chain Manipulation (recursive proving)
State evolution one-way: `state_new = H(TAG_STATE_UPDATE, state_old, leaf)`. Circuit enforces state threading, no skipping/reordering.

## Test Coverage

| Property | Test File | Count |
|----------|-----------|-------|
| Malicious prover rejection | `security_malicious_prover.rs` | 9 |
| Replay attack prevention | `security_replay_attack.rs` | 2 |
| Input validation | `validation.rs` | 19 |
| Cryptographic properties | `security_comprehensive.rs` | 4 |
| Ledger security | `security_ledger*.rs` | 10 |
| Circuit uniformity | `circuit_uniformity*.rs` | 8 |
| Negative cases | `security_negative_cases.rs` | 5 |
| **Total** | | **57** |

**Gaps:** fuzzing (infrastructure exists), concurrency, timing analysis, malformed serialization fuzzing.

## Parameter Generation

**Files:** `src/params.rs`, `src/api/prove.rs`, `src/api/verify.rs`

Parameters generated on-demand, deterministically:

1. **Shape derivation** (`src/api/plan.rs`): `files_per_step` = next power of 2 ≥ num_files, `file_tree_depth` = max depth across challenged files, `aggregated_tree_depth` = ledger depth (0 for single-file).

2. **Circuit witness** (`src/params.rs::generate_params_for_shape()`): dummy challenges/ledger matching shape, `generate_circuit_witness()`, no real file data.

3. **Nova setup** (lines 132-137): `PublicParams::setup()` with IPA commitment (`ipa_pc`), Pallas/Vesta cycle, floor keys from `nova-snark`.

4. **Key generation** (lines 139-142): `CompressedSNARK::setup(&pp)` produces `(ProverKey, VerifierKey)`.

5. **Cache**: bundle as `PorParams`, store for reuse.

**Determinism:** No randomness, shape from validated challenges only, fixed algorithm/constants. All nodes generate bit-identical parameters for same shape. No trusted setup, parameters regenerated independently. Test: `regression.rs::regression_parameter_generation_consistency()` (136-165).

### Caching

Cache key: `(files_per_step, file_tree_depth, aggregated_tree_depth)`. FIFO eviction at MAX_CACHE_SIZE (50). Mutex-protected, process-local, in-memory only. Generated lazily: `prove()` → `setup_proving_environment()` → `load_or_generate_params()` (132-136), `verify()` → `load_or_generate_params()` (71-75). Not bundled or downloaded.

Verifier generates parameters from challenge shape independently. If prover used different parameters, `CompressedSNARK::verify()` fails. Proof tied to circuit structure; mismatch produces invalid proof.

**Security:** Parameters uniquely determined by shape, cache process-local, keys from validated metadata, bounded size (50), mutex-protected.

**Audit:** Verify deterministic shape derivation (`src/api/plan.rs`, `src/config.rs`), no randomness (`src/params.rs`), identical circuit construction, cache key includes all shape parameters (33-37), verifier independence (71-75 in `verify.rs`), mismatch causes failure.

## Dependencies

| Dependency | Version | Role | Audit Status |
|------------|---------|------|--------------|
| `nova-snark` | 0.41.0 | Nova SNARK | Microsoft Research |
| `neptune` | 13.0.0 | Poseidon hash | ? |
| `reed-solomon-erasure` | 6.0.0 | Erasure coding | ? |
| `pasta_curves` | 0.5.1 | Elliptic curves | ? |
| `ff` | 0.13.1 | Finite field arithmetic | ? |
| `bellpepper-core` | 0.4.0 | R1CS constraints | ? |

# Pre-Audit Checklist

**Code:** Features complete, tests passing, no TODO/FIXME in critical paths, review done.

**Documentation:** README accurate, public APIs documented, security properties documented, limitations listed.

**Testing:** `cargo nextest run` clean, 57+ security tests, edge cases, regressions, circuit uniformity.

**Dependencies:** `cargo audit` clean, versions pinned, licenses compatible, critical deps audited.
