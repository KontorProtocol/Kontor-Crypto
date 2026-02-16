# Picus Runbook (Component-First)

## Files
- Exporter: `src/bin/picus_export.rs`
- Verifier: `src/bin/picus_verify.rs`
- Core export logic: `src/formal/mod.rs`
- Contracts: `tools/picus/components/contracts.json`
- Fixture manifest: `tools/picus/components/manifest.json`
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
