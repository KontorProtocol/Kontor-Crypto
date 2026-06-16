# Protocol Specification

This document describes the network-level protocol for decentralized storage auditing.

## Glossary

-   **Storage Node (Prover):** A network participant that commits to storing data and must generate proofs to demonstrate ongoing possession.
-   **Indexer (Verifier):** A network participant that validates proofs submitted by Storage Nodes and tracks the state of challenges.
-   **Symbol:** A 31-byte unit of data or parity. The 31-byte size is the maximum that fits in a Pallas field element (255 bits), enabling symbols to encode directly as Merkle leaves. Verifying a Merkle proof proves possession of the field element, and because the encoding is reversible, this proves possession of the symbol's 31 bytes of file data.
-   **Codeword:** A Reed-Solomon encoding unit over GF(2^8) containing 231 data symbols + 24 parity symbols (255 total). Files larger than 231 symbols use multiple independent codewords.
-   **Leaf:** A Merkle tree leaf is a symbol encoded as a Pallas field element via little-endian byte order.
-   **FileLedger:** An aggregated Merkle tree over root commitments of all files being tracked by the system.
-   **Root Commitment (rc):** A Poseidon hash binding a file's Merkle `root` and `depth`, preventing depth-spoofing attacks.
-   **State:** A value in a recursive hash chain (`state_out = H(state_in, leaf_value)`) that links sequential proof steps, preventing replay attacks.

## Oracle and Challenge Generation

-   The network uses a shared oracle (e.g., a Bitcoin block hash) to derive challenges deterministically at regular intervals.
-   For each interval and for each relevant file–prover pair, a `Challenge` is deterministically constructed from the `block_height`, `file_metadata`, a per-challenge `seed` derived from the oracle, and a `prover_id`.
-   Each `Challenge` has a deterministic `challenge_id` that uniquely identifies it on the network.

## Challenge Lifecycle

Challenges are created deterministically by all verifiers and transition through a simple lifecycle:

```mermaid
stateDiagram-v2
    [*] --> Open: New block interval creates challenge
    Open --> Resolved: Valid proof is accepted
    Open --> Expired: TTL (e.g., K blocks) elapses
    Resolved --> [*]
    Expired --> [*]
```

-   When a valid proof is broadcast, all `Open` challenges it covers are marked `Resolved`.
-   If a challenge is not resolved within its TTL, it becomes `Expired`, and the associated Storage Node is penalized according to metaprotocol rules.

## Protocol Flow

```mermaid
sequenceDiagram
    participant Oracle as Oracle (e.g., Bitcoin)
    participant Verifier as Verifiers (Indexers)
    participant Prover as Storage Node

    Oracle-->>Verifier: New block (height, hash)
    Verifier->>Verifier: Deterministically derive Challenges for (file, prover_id) pairs
    Note over Verifier: Record new challenges as Open with TTL K blocks

    Prover->>Prover: Select a set of Open Challenges to answer
    Prover->>Prover: Fetch corresponding PreparedFiles
    Prover->>Prover: PorSystem.prove(files, challenges) → Proof
    Note over Prover: Proof object carries compressed SNARK + ledger_root + aggregated_tree_depth

    Prover-->>Verifier: Broadcast Proof to the network
    Verifier->>Verifier: On receiving Proof, look up the claimed Challenge set out-of-band
    Verifier->>Verifier: PorSystem.verify(proof, challenges) → bool
    alt is valid
        Verifier->>Verifier: Mark covered Open challenges as Resolved
    else is not valid
        Verifier->>Verifier: Reject proof, challenges remain Open
    end
```

## Ledger & Aggregation

-   A `FileLedger` binds the set of files via an aggregated Merkle tree built over root commitments `rc = H(TAG_RC, root, depth)`.
-   Files are committed at explicit stable append-only ledger indices. The `files` map is key-sorted for lookup, but the aggregated tree is built by `ledger_index`, not lexicographic `file_id` order.
-   Multi-file proofs pin the ledger root as the aggregated root; single-file proofs pin the file root.
-   The verifier re-derives public ledger indices from its own ledger state and rejects statements whose derived indices do not fit the claimed aggregated tree depth.
-   **Stateless verification.** A verifier needs only two facts about "the ledger" — the stable slot + `rc` of each challenged file, and whether the proof's `ledger_root` is accepted — so it does not need a live `FileLedger`. `verify_stateless` takes those facts as plain data (a `StatelessLedger`: a `file_id → (slot, rc)` registry snapshot plus the set of valid roots), letting a host keep the file registry in contract storage instead of an in-memory accumulator. `aggregate_root`/`aggregate_root_from_files` recompute a root from `(rc, slot)` (resp. `(root, depth, slot)`) pairs, byte-identical to `FileLedger::root`, so the registry holder can derive the current valid root itself.

## Determinism & Canonical Ordering

-   Challenge sets are ordered canonically by `(file_id, challenge_id)` when a proof statement is built.
-   Ledger reconstruction is deterministic only when explicit stable indices are preserved.
-   The map from `file_id` → `PreparedFile` is derived internally from `Vec<PreparedFile>` to avoid user ordering mistakes.
-   Seeds differ per file; domain separation prevents cross-file bias (multi-batch aggregation supported).

## Data Types

```rust
// Public commitment to a file
pub struct FileMetadata {
    pub root: FieldElement,
    pub object_id: String,          // obj_<SHA256(data)>
    pub file_id: String,            // file_<SHA256(domain || len(data) || data || len(nonce) || nonce)>
    pub nonce: Vec<u8>,             // upload-specific nonce used in file_id derivation
    pub padded_len: usize,          // Total Merkle leaves (power of 2)
    pub original_size: usize,       // Original file size in bytes
    pub filename: String,
}

// Derived values (computed from original_size and protocol constants):
impl FileMetadata {
    pub fn num_data_symbols(&self) -> usize;   // ceil(original_size / 31)
    pub fn num_codewords(&self) -> usize;      // ceil(num_data_symbols / 231)
    pub fn total_symbols(&self) -> usize;      // num_codewords × 255
}

/// The prover's representation of a file, containing the full Merkle tree.
pub struct PreparedFile { /* contains the full MerkleTree */ }

// A verifier's challenge for a single file-prover pair at a specific block height.
pub struct Challenge {
    pub file_metadata: FileMetadata,
    pub block_height: u64,
    pub seed: FieldElement,         // Per-file seed (enables multi-batch aggregation)
    pub num_challenges: usize,      // Recursive steps to prove for this file
    pub prover_id: String           // Identifier of the Storage Node being challenged
}

// Deterministic identity for a Challenge.
pub struct ChallengeID([u8; 32]);

// Final succinct proof with constant-size metadata.
pub struct Proof {
    // existing CompressedSNARK payload
    pub ledger_root: FieldElement,
    pub aggregated_tree_depth: usize,
}

// Derivation for ChallengeID (using stable, cryptographic fields only)
challenge_id =
    H(TAG_CHALLENGE_ID
      || encode(block_height)
      || encode(seed)
      || len(file_id) || file_id
      || len(nonce) || nonce
      || encode(padded_len)
      || encode(original_size)
      || encode(root)
      || encode(num_challenges)
      || len(prover_id) || prover_id)
```

## Proof Serialization

The system provides stable helpers to serialize and deserialize proofs for network transport.

```rust
let bytes = proof.to_bytes()?;
let parsed = Proof::from_bytes(&bytes)?;
```

The format is versioned, rejects trailing data, and no longer serializes dynamic `challenge_ids` or `ledger_indices` vectors.

### Encoding Notes

- Use a network-canonical encoding with explicit versioning and magic bytes.
- Fixed-width, little-endian encodings for integers (e.g., `block_height: u64`).
- Field elements are encoded in a canonical 32-byte form.
- Challenge coverage is supplied out-of-band to the verifier and rebound through verifier-constructed public inputs.
