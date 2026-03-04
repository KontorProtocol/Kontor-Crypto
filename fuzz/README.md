# Fuzzing (cargo-fuzz)

This repository includes a small set of security-focused `cargo-fuzz` targets under `fuzz/fuzz_targets/`.

## Prerequisites
- Rust nightly (cargo-fuzz uses `-Zsanitizer`):
  - `rustup toolchain install nightly`
- cargo-fuzz:
  - `cargo install cargo-fuzz --locked`

## List targets
```bash
cargo +nightly fuzz list
```

## Run a bounded campaign locally
```bash
# 60s local smoke
cargo +nightly fuzz run proof_from_bytes -- -max_total_time=60
```

## Corpus and artifacts
- Seed corpora live under `fuzz/corpus/<target>/`.
- Crashes and other artifacts are written to `fuzz/artifacts/<target>/`.

## CI
CI runs bounded fuzzing on pull requests via `.github/workflows/security-fuzz.yml`.

