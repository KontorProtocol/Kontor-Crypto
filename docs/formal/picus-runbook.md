# Picus Runbook

## Current Status (February 12, 2026)
- Deterministic fixture export is implemented and emits Picus-ready `circuit.r1cs` directly from `ShapeCS`.
- `picus_verify` supports bounded execution with:
  - `--timeout-secs` (forwarded to Picus in ms),
  - `--hard-timeout-grace-secs` (host-side kill timeout),
  - `--solver`,
  - `--picus-log-level`,
  - stale solver cleanup between runs/fixtures.
- Formal conclusion is not complete yet: current runs are primarily `inconclusive` (timeouts), so determinism is not yet proven.

## Big-Picture Goal
Prove the `PorCircuit` one-step relation is deterministically constrained for fixed public inputs and fixed shape. See `docs/formal/determinism-spec.md`.

## Fixture Matrix Scope
1. `single-file-minimal`: shape `(1, 8, 0)`, baseline single-file constraints.
2. `single-file-depth10`: shape `(1, 10, 0)`, deeper single-file tree.
3. `multi-file-minimal`: shape `(2, 8, 1)`, multi-file aggregation baseline.
4. `multi-file-mixed-depth`: shape `(2, 10, 1)`, mixed depth behavior.
5. `multi-file-padding`: shape `(4, 8, 2)`, slot-padding and larger aggregate depth.

## Prerequisites
1. Rust toolchain for this repository.
2. Veridise Picus CLI (`run-picus`) installed from `https://github.com/Veridise/Picus`.
3. Optional converter only for legacy/custom environments.

Example Picus install (from Veridise README):
```bash
git clone https://github.com/Veridise/Picus.git
cd Picus
raco pkg install --auto
./run-picus --help
```

Notes:
- This repository now exports deterministic Nova artifacts and a Picus-ready `circuit.r1cs` directly.
- Do not use the unrelated PyPI package `picus==0.0.5`; it is a different tool.
- Converter can still be provided via `--converter-bin` or `PICUS_R1CS_CONVERTER_BIN` as a fallback.

## Dockerized Picus (amd64-safe)
Use this on Apple Silicon or any environment where native `run-picus` setup is difficult.

Sanity check prebuilt image:
```bash
tools/picus/check-docker.sh
```

If your image does not expose `run-picus` on `PATH`, mount a local Picus checkout:
```bash
PICUS_SOURCE_DIR=/path/to/Picus tools/picus/check-docker.sh
```

Run verification with Dockerized Picus:
```bash
tools/picus/run-docker.sh --all --timeout-secs 600 --allow-inconclusive
```

Equivalent manual command:
```bash
cargo run --bin picus_verify -- --all \
  --picus-bin tools/picus/run-picus-docker.sh \
  --timeout-secs 600 \
  --allow-inconclusive
```

Environment overrides:
- `PICUS_DOCKER_IMAGE` (default: `veridise/picus:base`)
- `PICUS_DOCKER_PLATFORM` (default: `linux/amd64`)
- `PICUS_DOCKER_MEMORY` (default: `10g`)
- `PICUS_SOURCE_DIR` (optional mount as `/Picus`; wrapper auto-selects `/Picus/run-picus`)
- `PICUS_DOCKER_CMD` (manual command override if needed)

### Build Local Picus Image (from a Picus clone)
If you want your own local image tag (e.g. `picus:v0`) from a checked-out Picus repository:

```bash
tools/picus/build-local-image.sh /path/to/Picus
```

Then run with it:
```bash
PICUS_DOCKER_IMAGE=picus:v0 tools/picus/run-docker.sh --all --timeout-secs 600 --allow-inconclusive
```

## Troubleshooting
1. `exec: "run-picus": executable file not found in $PATH`
- Use a local Picus checkout mount and command override:
```bash
PICUS_SOURCE_DIR=/path/to/Picus tools/picus/check-docker.sh
```
2. `petite` / `invalid memory reference` / `Aborted`
- This is a Racket runtime crash under emulation. Typical fixes:
  - run on a native amd64 Linux machine/VM,
  - enable Docker Desktop x86 emulation support and retry,
  - or use a host-native Picus install instead of Docker emulation.

## Fixture Files
- Manifest: `tools/picus/manifest.json`
- Fixture definitions: `tools/picus/fixtures/*.json`

## Export Only
```bash
cargo run --bin picus_export -- --all
```

## Run Verification
```bash
cargo run --bin picus_verify -- --all --timeout-secs 600
```

Recommended local command (incremental + bounded):
```bash
cargo run --bin picus_verify -- --all \
  --picus-bin /path/to/run-picus \
  --solver cvc5 \
  --picus-log-level INFO \
  --timeout-secs 120 \
  --hard-timeout-grace-secs 30 \
  --allow-inconclusive
```

Single-fixture iteration:
```bash
cargo run --bin picus_verify -- --fixture single-file-minimal \
  --picus-bin /path/to/run-picus \
  --solver cvc5 \
  --picus-log-level INFO \
  --timeout-secs 120 \
  --hard-timeout-grace-secs 30 \
  --allow-inconclusive
```

If `run-picus` is not on PATH:
```bash
cargo run --bin picus_verify -- --all \
  --picus-bin /path/to/run-picus \
  --timeout-secs 600
```

Converter fallback:
```bash
export PICUS_R1CS_CONVERTER_BIN=/path/to/nova-to-r1cs
cargo run --bin picus_verify -- --all
```

## Output Artifacts
Per fixture:
- `artifacts/picus/<fixture>/shape.bin`
- `artifacts/picus/<fixture>/circuit.r1cs`
- `artifacts/picus/<fixture>/instance.bin`
- `artifacts/picus/<fixture>/witness.bin`
- `artifacts/picus/<fixture>/commitment_key.bin`
- `artifacts/picus/<fixture>/export-metadata.json`
- `artifacts/picus/<fixture>/picus-result.json` (after Picus run)

Aggregate:
- `artifacts/picus/summary.json`
- `artifacts/picus/summary.md`

## Status Mapping
1. `pass`: Picus output classified as safe.
2. `violation`: Picus output classified as unsafe/under-constrained.
3. `inconclusive`: timeout, unknown, or missing Picus-ready input.
4. `error`: command/parsing failure without a classifiable result.

## Incremental Plan
1. Single fixture convergence:
- Run one fixture at higher timeout with explicit solver/model to find first `pass` or `violation`.
2. Shape coverage:
- Repeat convergence run across all five fixtures.
3. Determinism claim gate:
- Require all fixtures to classify `pass` before claiming determinism for current fixture matrix.
4. Expand assurance:
- Add more fixtures for boundary conditions and known risk regions if all five pass.

## CI Use
- Smoke mode should run a small fixture subset in PRs.
- Full matrix should run nightly or on manual workflow dispatch.
