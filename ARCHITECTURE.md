# Technical Implementation

This section provides a technical overview of the cryptographic implementation for contributors.

## Core Architecture

The system processes data through a pipeline of erasure coding, chunking, and Merkle tree construction before entering the recursive proving loop.

```mermaid
graph TD
    A[Original Data] --> B{1. Partition into 31-byte symbols};
    B --> C[Data Symbols];
    C --> D{2. Multi-Codeword RS Encode};
    D --> E[All Symbols: Data + Parity];
    E --> F{3. Build Merkle Tree};
    F --> G[Merkle Root];

    subgraph Prover Loop per symbol challenge
        direction LR
        H(state_in) --> I{4. Derive Symbol Index};
        J(random_seed) --> I;
        I -- symbol_index --> K{5. Prove Inclusion};
        L(symbol & Merkle path) --> K;
        G --> K;
        K --> M{6. Update State};
        L -- symbol_value --> M;
        H --> M;
        M --> N(state_out);
    end

    K -- SNARK per step --> O[7. Compress via Spartan];
    O --> P[Constant-size Proof ~10kB];

    subgraph Verifier
        P --> Q{8. Verify};
        G --> Q;
        J --> Q;
    end

    subgraph Reconstruction
        R[Available Symbols ≥90% per codeword] --> S{9. RS Decode};
        S --> A;
    end
```

**Core Components:**

-   **`src/main.rs`**: Production storage node simulator with realistic multi-file proof aggregation, heterogeneous file sizes, and economic analysis.
-   **`src/api/`**: High-level unified API via `PorSystem` struct providing `prepare_file()`, `prove()`, and `verify()` methods.
  -   **`system.rs`**: `PorSystem` - unified API entry point
  -   **`plan.rs`**: Preprocessing logic shared between prove and verify
  -   **`prove.rs`**: Proof generation with automatic shape derivation
  -   **`verify.rs`**: Verification with secure ledger root pinning
  -   **`witness.rs`**: Circuit witness generation with guaranteed padding
  -   **`types.rs`**: Core data types (Challenge, Proof, FileMetadata, etc.)
-   **`src/circuit/`**: The unified Nova `StepCircuit` for PoR verification.
  -   **`synth.rs`**: Main circuit synthesis logic
  -   **`witness.rs`**: Witness data structures
  -   **`gadgets/`**: Low-level circuit components (Merkle, Poseidon, selection)
  -   **`debug.rs`**: Circuit uniformity fingerprinting (debug builds)
-   **`src/erasure.rs`**: Multi-codeword Reed-Solomon (GF(2^8), 231+24 symbols per codeword).
-   **`src/merkle.rs`**: Poseidon Merkle trees with domain separation.
-   **`src/ledger.rs`**: File ledger with aggregated Merkle tree of root commitments (rc values).
-   **`src/params.rs`**: Dynamic parameter generation with in-memory caching for different circuit shapes.
-   **`src/metrics.rs`**: Performance metrics and structured output for benchmarking.
-   **`src/config.rs`**: Centralized configuration, economic constants, and public I/O layout.
-   **`src/poseidon.rs`**: Domain-separated Poseidon hashing with cached constants.
-   **`benches/`**: Divan benchmark suite (`bench_main.rs`) for regression tracking (primitives, file prep, proving, verification, e2e).

## Data Encoding and Merkle Tree Construction

1.  **Symbol Partitioning**: Raw data is partitioned into fixed 31-byte symbols. The 31-byte size is the maximum that fits in a Pallas field element (255 bits), enabling symbols to encode directly as Merkle leaves.
2.  **Multi-Codeword Reed-Solomon**: Symbols are grouped into codewords of 231 data symbols. Reed-Solomon encoding over GF(2^8) generates 24 parity symbols per codeword (255 total). Files larger than 231 symbols use multiple independent codewords.
3.  **Merkle Tree Construction**: Each symbol encodes directly as a Pallas field element (little-endian byte order) to become a leaf. Internal nodes use Poseidon: `H(TAG_NODE, left, right)`. Tree is padded to next power of two.
4.  **Proof-of-Retrievability**: Verifying a Merkle proof proves possession of the field element. Because the encoding is reversible, this proves possession of the symbol's 31 bytes of file data.
5.  **Domain Separation**: All Poseidon operations use distinct tags to prevent cross-context collisions.

## Circuit Design

The `PorCircuit` implements Nova's `StepCircuit` trait. For each step, it proves:
1.  Correct calculation of the challenged leaf index via domain-separated hashing.
2.  Knowledge of a valid Merkle path from the leaf to the file root.
3.  File root commitment membership in the aggregated ledger (multi-file only).
4.  Correct evolution of the state via a hash chain: `state_out = H(TAG_STATE, state_in, leaf_value)`.

**Public I/O Vector Layout (Primary):**

The vector length is `2 + 4 * files_per_step` with the following sections:

1.  **Fixed (2):** `aggregated_root`, `state_in`.
2.  **Ledger indices (F):** `ledger_index_0 ... ledger_index_{F-1}` (canonical positions in ledger).
3.  **Depths (F):** `actual_depth_0 ... actual_depth_{F-1}` (for depth binding).
4.  **Seeds (F):** `seed_0 ... seed_{F-1}` (enables multi-batch aggregation with different block hashes).
5.  **Leaves (F):** `leaf_0 ... leaf_{F-1}` (challenged symbols, initially zero).

Notes:
-   The leaves section is initialized to zero in `z0_primary` and filled by the circuit; it is carried forward step-to-step by Nova.
-   Different seeds per file enable aggregating challenges from different block heights (different Bitcoin block hashes).

**Security Properties:**

-   **Public Depth Binding:** Each slot's computed depth is enforced to equal its public depth input via constraint.
-   **Ledger Binding:** Public ledger indices and the aggregated root cryptographically prove that each file's `rc = H(TAG_RC, root, depth)` commitment exists in the canonical `FileLedger`.
-   **Gating Logic:** Circuit slots are only processed if their public depth is greater than zero, allowing padding slots to be skipped without changing circuit structure.
-   **Root Commitment (rc):** Binds file root and depth to prevent depth-spoofing attacks.

## Parameter Caching and Shape Derivation

**Dynamic Circuit Shapes:**

The system supports dynamic circuit parameters based on the actual files being proven:
-   **Shape key**: `(files_per_step, file_tree_depth, aggregated_tree_depth)`
-   **files_per_step**: `next_power_of_two(num_files)` - ensures uniform structure
-   **file_tree_depth**: `max(file_depths)` - handles heterogeneous file sizes
-   **aggregated_tree_depth**: `ledger.depth()` for multi-file, 0 for single-file

**In-Memory Caching** (`src/params.rs`):
-   Parameters are expensive to generate (2-5 seconds)
-   Cached by shape key with LRU eviction (max 50 entries)
-   Subsequent proofs with the same shape use cached parameters instantly
-   Simulator displays "Parameter Load (cached)" when cache is hit

## Benchmarking and Testing

**Benchmark Suite** (`benches/bench_main.rs`):
-   Uses **Divan** for statistical benchmarking
-   Regression tracking for critical paths
-   Run with: `cargo bench`

**Production Simulator** (`src/main.rs`):
-   Realistic storage node operation
-   Heterogeneous file sizes and staggered challenges
-   Run with: `cargo run --release`

**Test Suite** (`tests/`):
-   Circuit uniformity regression tests
-   Security tests (ledger binding, depth spoofing, replay attacks)
-   E2E tests with variable file sizes and depths
-   Run with: `cargo test`
