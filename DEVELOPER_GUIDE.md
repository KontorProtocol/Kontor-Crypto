# Developer Guide

## CLI Usage

A CLI is provided for large-scale proving and verification runs, as well as API demonstrations.

**Examples:**
```bash
# Run with small, approachable defaults (3 files, challenge 2, 3 steps each)
cargo run --release

# Run large-scale benchmark
cargo run --release -- \
  --total-files 1000 \
  --challenged-files 100 \
  --num-challenges 100
```

**Flags:**

-   `--total-files <N>`: Total files to prepare and add to the ledger (default: 3).
-   `--challenged-files <K>`: Subset of files to prove (default: 2).
-   `--num-challenges <C>`: Recursive steps to prove for *each* challenged file (default: 3).
-   `--file-size <bytes>`: Size of synthetic data for each file.
-   `--no-verify`: Skip the verification phase.
-   `-v`/`-vv`: Increase logging verbosity to DEBUG/TRACE.

## Test Suite

The project includes extensive unit and integration tests. Run all tests with:
```bash
cargo install cargo-nextest
cargo nextest run
```

## Running Benchmarks

Microbenchmarks and a small end-to-end flow are available via the `bench` binary:
```bash
cargo run --release --bin bench
```

## Performance Characteristics

-   Proof Size: ~10 kB (constant across challenge count and file set within a shape).
-   Verification Time: ~30 ms for compressed SNARK verification.
-   Proving Time: Approximately linear in the number of recursive steps.

## Errors and Failure Modes

Key error variants surfaced at API boundaries (see `KontorPoRError`):

-   `InvalidInput`, `InvalidChallengeCount`, `ChallengeMismatch` (e.g., non-uniform `num_challenges` across the batch).
-   `FileNotFound`, `FileNotInLedger`, `MetadataMismatch`.
-   `MerkleTree`, `Circuit`, `Snark`.
-   `Serialization`, `IO`.

## Enabling Git Hooks

This project includes a pre-push hook to run tests and a security audit. Enable it with:
```bash
git config core.hooksPath .githooks
```
