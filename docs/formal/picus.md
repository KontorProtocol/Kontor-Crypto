# Picus Runbook (Comprehensive)

## Files
- Exporter: `src/bin/picus_export.rs`
- Verifier: `src/bin/picus_verify.rs`
- Core export logic: `src/formal/mod.rs`
- Contracts: `tools/picus/components/contracts.json`
- Component manifests:
  - `tools/picus/components/manifest.json` (blocking fast profile)
  - `tools/picus/components/manifest-full.json` (exhaustive profile)
- Monolithic manifest:
  - `tools/picus/manifest-broad.json` (blocking broad profile)

## Export
```bash
# Component export
cargo run --release --bin picus_export -- \
  --all \
  --manifest tools/picus/components/manifest.json \
  --fixtures-dir tools/picus/components/fixtures \
  --scope leafpath \
  --simplify safe

# Monolithic export
cargo run --release --bin picus_export -- \
  --all \
  --manifest tools/picus/manifest-broad.json \
  --fixtures-dir tools/picus/fixtures \
  --scope leafpath \
  --simplify safe
```

## Verify
```bash
# Component blocking profile
cargo run --release --bin picus_verify -- \
  --all \
  --manifest tools/picus/components/manifest.json \
  --fixtures-dir tools/picus/components/fixtures \
  --scope leafpath \
  --simplify safe \
  --solver cvc5 \
  --picus-log-level PROGRESS \
  --artifacts-dir artifacts/picus-components

# Component exhaustive profile (includes heavier mutants)
cargo run --release --bin picus_verify -- \
  --all \
  --manifest tools/picus/components/manifest-full.json \
  --fixtures-dir tools/picus/components/fixtures \
  --scope leafpath \
  --simplify safe \
  --solver cvc5 \
  --picus-log-level PROGRESS \
  --artifacts-dir artifacts/picus-components-full \
  --allow-inconclusive

# Monolithic broad blocking profile
cargo run --release --bin picus_verify -- \
  --all \
  --manifest tools/picus/manifest-broad.json \
  --fixtures-dir tools/picus/fixtures \
  --scope leafpath \
  --simplify safe \
  --solver cvc5 \
  --picus-log-level PROGRESS \
  --artifacts-dir artifacts/picus-monolithic
```

## Dockerized Picus
```bash
tools/picus/check-docker.sh

PICUS_SOURCE_DIR=/path/to/Picus \
tools/picus/run.sh --all --scope leafpath --simplify safe
```

## Notes
- Use Veridise Picus `run-picus` (not PyPI `picus==0.0.5`).
- For cvc5, CoCoA-enabled builds are recommended (`cvc5 --show-config | rg cocoa`).
- `z3` should be available on PATH for fallback solver policy.
- `leafpath` is strict by default. To allow fallback to input-only scope for debugging, set `KONTOR_PICUS_STRICT_SCOPE=0`.
- Fixture `expected_result` is enforced for all profiles.
- Per-fixture `verification` policy overrides CLI defaults unless `--ignore-fixture-policy` is set.
