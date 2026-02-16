# Picus Runbook (Docker-First)

This repo exports deterministic Picus `.r1cs` inputs directly from Nova `ShapeCS` synthesis and runs Veridise Picus to check uniqueness/determinism for selected outputs.

## Components
- Exporter: `src/bin/picus_export.rs`
- Verifier wrapper: `src/bin/picus_verify.rs`
- Fixture schema + R1CS encoder + preconditions: `src/formal/mod.rs`
- Fixture matrix: `tools/picus/manifest.json`
- Fixtures: `tools/picus/fixtures/*.json`
- Docker wrapper for Picus: `tools/picus/run-picus-docker.sh`

## Quick Start
Sanity-check Docker Picus:
```bash
tools/picus/check-docker.sh
```

Run the full fixture matrix using the intended determinism scope:
```bash
tools/picus/run.sh --all \
  --output-prefix-len 2 \
  --picus-leafpath-precondition \
  --timeout-secs 1200 \
  --hard-timeout-grace-secs 120 \
  --picus-log-level PROGRESS
```

Artifacts land in:
- `artifacts/picus/<fixture-id>/...` (exports, Picus JSON, preconditions)
- `artifacts/picus/summary.json` and `artifacts/picus/summary.md` (run summary)

## Pinned Picus (Recommended For CI / Repro)
`tools/picus/run-picus-docker.sh` can mount a specific Picus checkout into the container:
```bash
PICUS_SOURCE_DIR=/path/to/Picus tools/picus/run.sh --all ...
```
When set, the wrapper runs `/Picus/run-picus` inside the pinned container image.

## Using Multiple Cores (Local)
Picus itself often drives the SMT solver in a way that looks single-core. The easiest way to utilize many cores is to run multiple *independent* proofs concurrently:
```bash
tools/picus/run-matrix-safe.sh \
  --picus-bin tools/picus/run-picus-docker.sh \
  --all \
  --prefix-lens 1,2 \
  --stages leafpath \
  --timeout-leafpath-secs 1200 \
  --jobs 8
```

Status helpers:
```bash
tools/picus/status.sh --watch --interval-secs 30
tools/picus/proc-status.sh --watch --interval-secs 5
```

## Troubleshooting
- If you accidentally installed the unrelated PyPI package `picus==0.0.5`, `picus_verify` will classify it as an error. You need Veridise Picus `run-picus` from the Picus repo.
- `petite` / `invalid memory reference`: typical of running the Racket runtime under emulation. Prefer Docker `linux/amd64` on a native amd64 host/VM, or mount and run a pinned amd64 build.

## Dev-Only Circuits
Some toy/lite circuits exist for convergence experiments. They are gated behind the Cargo feature `formal-dev`:
```bash
cargo run --features formal-dev --release --bin picus_export -- --fixture <dev-fixture>
```

Dev fixtures live under `tools/picus/fixtures/dev/` and can be used by overriding the fixture dir:
```bash
cargo run --features formal-dev --release --bin picus_verify -- \
  --fixtures-dir tools/picus/fixtures/dev \
  --fixture <dev-fixture> \
  --picus-bin tools/picus/run-picus-docker.sh
```
