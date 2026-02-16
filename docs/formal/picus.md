# Picus Runbook (Component-First)

## Files
- Exporter: `src/bin/picus_export.rs`
- Verifier: `src/bin/picus_verify.rs`
- Core export logic: `src/formal/mod.rs`
- Contracts: `tools/picus/components/contracts.json`
- Fixture manifest (CI): `tools/picus/components/manifest.json`
- Fixture manifest (exhaustive): `tools/picus/components/manifest-full.json`
- Fixtures: `tools/picus/components/fixtures/*.json`

## Export
```bash
cargo run --release --bin picus_export -- \
  --all \
  --scope leafpath \
  --simplify safe
```

## Verify
```bash
cargo run --release --bin picus_verify -- \
  --all \
  --scope leafpath \
  --simplify safe \
  --solver cvc5 \
  --picus-log-level PROGRESS

# Exhaustive profile (includes heavier mutants)
cargo run --release --bin picus_verify -- \
  --all \
  --manifest tools/picus/components/manifest-full.json \
  --scope leafpath \
  --simplify safe \
  --solver cvc5 \
  --picus-log-level PROGRESS \
  --allow-inconclusive
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
- `z3` should be available on PATH for mutant retries (`expected_result = unsafe`).
- `leafpath` is strict by default. To allow fallback to input-only scope for debugging, set `KONTOR_PICUS_STRICT_SCOPE=0`.
- Fixture `expected_result` is enforced: normal fixtures must classify `safe`, mutant fixtures must classify `unsafe`.
