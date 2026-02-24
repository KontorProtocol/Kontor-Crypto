# Proposal: Cargo Workspace for Browser-Compatible `prepare_file()`

## Goal

Expose `prepare_file()` as a TypeScript library callable from the browser, without duplicating cryptographic code or pulling in the Nova proving system.

## Problem

`prepare_file()` depends on shared primitives (Poseidon hash, Merkle tree, Reed-Solomon, field arithmetic) that are currently entangled with the full Nova circuit/proving stack. Extracting them into a separate repo would create code duplication and risk silent cryptographic divergence.

## Proposed Architecture

Restructure the repo into a Cargo workspace with three crates:

```
Kontor-Crypto/
├── Cargo.toml                       # workspace root
├── crates/
│   ├── kontor-crypto-core/          # shared cryptographic primitives
│   ├── kontor-crypto/               # circuit + proving (current crate)
│   └── kontor-crypto-wasm/          # browser bindings via WebAssembly
├── tests/
└── ...
```

### `kontor-crypto-core` — Shared Primitives

Contains all code needed by both the prover and the browser client:

| Module | Purpose |
|--------|---------|
| `poseidon.rs` | Poseidon hash (Pallas field, arity-2, domain-separated) |
| `merkle.rs` | Merkle tree construction and proof generation |
| `erasure.rs` | Reed-Solomon GF(2^8) encoding/decoding |
| `utils.rs` | Field element conversions |
| `config.rs` | Shared constants (chunk size, RS parameters) |
| `error.rs` | Error types |

Key dependency change: the current Poseidon hash is imported from `nova-snark::frontend::gadgets::poseidon`, which pulls in the entire Nova proving stack. Since we can't import it in isolation, `kontor-crypto-core` needs its own standalone Poseidon implementation using the same constants (round constants, MDS matrix, S-box). Field arithmetic uses `pasta_curves` directly.

```toml
[dependencies]
ff = "0.13"
pasta_curves = "0.5"
sha2 = "0.10.6"
reed-solomon-erasure = "6.0"
serde = { version = "1.0", features = ["derive"] }
thiserror = "1.0"
```

**No dependency on `nova-snark`.** WASM-compatible out of the box.

### `kontor-crypto` — Circuit & Proving (Existing Crate)

Everything that requires Nova: circuit synthesis, proving, verification, witness generation, ledger, parameters.

```toml
[dependencies]
kontor-crypto-core = { path = "../kontor-crypto-core" }
nova-snark = { version = "0.41.0", default-features = false }
# ... remaining deps unchanged
```

No breaking changes to the public API — `kontor-crypto` re-exports `kontor-crypto-core` types.

### `kontor-crypto-wasm` — Browser Bindings

Thin WASM layer that exposes `prepare_file()` to JavaScript/TypeScript.

```toml
[dependencies]
kontor-crypto-core = { path = "../kontor-crypto-core" }
wasm-bindgen = "0.2"
serde-wasm-bindgen = "0.6"
```

Published as an npm package. Expected WASM binary size: **~500 KB** (vs. 5+ MB if we compiled all of `nova-snark`).

TypeScript API:

```typescript
import { prepareFile } from '@kontor/crypto';

const file: Uint8Array = /* from FileReader */;
const nonce: Uint8Array = /* unique per upload */;

const { preparedFile, metadata } = await prepareFile(file, "document.pdf", nonce);
// metadata.root      → hex string (Merkle root)
// metadata.objectId  → "obj_<sha256>"
// metadata.fileId    → "file_<sha256(data||nonce)>"
```

## Compatibility Guarantee

`prepare_file()` lives in `kontor-crypto-core` (it only uses core primitives) and is re-exported by `kontor-crypto`. The critical compatibility point is the standalone Poseidon implementation in `kontor-crypto-core` vs. the one in `nova-snark`. A simple regression test locks this down:

```rust
#[test]
fn standalone_poseidon_matches_nova() {
    let x = PallasScalar::from(42u64);
    let y = PallasScalar::from(123u64);
    let tag = PallasScalar::from(2u64); // NODE domain tag

    let hash_core = kontor_crypto_core::poseidon_hash_tagged(tag, x, y);
    let hash_nova = nova_poseidon_hash_tagged(tag, x, y); // via nova-snark sponge

    assert_eq!(hash_core, hash_nova);
}
```

## Risks

1. **Poseidon constant extraction** — The round constants and MDS matrix must be dumped from `nova-snark`'s `PoseidonConstants` and hardcoded in `kontor-crypto-core`. Mitigation: automated extraction script + regression test vectors.
2. **`pasta_curves` WASM support** — Requires pure-Rust fallback (no `asm` feature). Known to work with `wasm32-unknown-unknown` target when compiled without default features.
3. **Large file performance in browser** — A 10 MB file produces ~330k symbols → ~500k Poseidon hashes for the Merkle tree. WASM field arithmetic should handle this in seconds, but worth benchmarking early.
