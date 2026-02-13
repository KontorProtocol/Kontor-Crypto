# Picus Runbook

## Current Status (February 13, 2026)
- Deterministic fixture export is implemented and emits Picus-ready `circuit.r1cs` directly from `ShapeCS`.
- `picus_verify` supports bounded execution with:
  - `--timeout-secs` (forwarded to Picus in ms),
  - `--hard-timeout-grace-secs` (host-side kill timeout),
  - `--solver`,
  - `--picus-log-level`,
  - stale solver cleanup between runs/fixtures.
- Toolchain is now producing conclusive results on small scopes when using a correct finite-field solver setup:
  - `single-file-tiny-depth1` with `--output-prefix-len 1` can reach `pass` using `cvc5` (CoCoA-enabled).
- Formal conclusion for the main fixture matrix (`tools/picus/manifest.json`) is not complete yet.

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
3. A `cvc5` binary with finite-field (`QF_FF`) support enabled (CoCoA).
4. Optional converter only for legacy/custom environments.

### Finite-Field Solver Requirement (cvc5 + CoCoA)
Picus uses a finite-field (`QF_FF`) encoding when `--solver cvc5` is selected. Many packaged `cvc5` builds are compiled without CoCoA support and will not solve `QF_FF`, leading to Picus reporting `unknown` with `[solver] skipped`.

Verify your `cvc5` supports CoCoA:
```bash
cvc5 --show-config | rg 'cocoa'
# expect: cocoa         : yes
```

If you have a custom `cvc5`, point Picus at it via `SOLVER_PATH`:
```bash
export SOLVER_PATH=/path/to/cvc5
```

### Optional: Use More CPU (cvc5 Portfolio Mode)
By default, `cvc5` will often use a single core per solve. To parallelize within a single Picus run, you can use `cvc5` portfolio mode via a wrapper:

```bash
export CVC5_BIN=/path/to/cvc5
export CVC5_PORTFOLIO_JOBS=16
export SOLVER_PATH=tools/picus/cvc5-portfolio-wrapper.sh
```

Notes:
- Portfolio mode increases CPU usage but can also increase memory usage.
- Override jobs via `CVC5_PORTFOLIO_JOBS`; the wrapper otherwise auto-picks a conservative default.

You can build a CoCoA-enabled cvc5 locally (GPL build) using `tools/picus/build-cvc5-cocoa.sh`.

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

## Overnight Run Plan
For a practical overnight run plan (mixed "conclusive with precondition" and "best-effort without precondition"), use:
```bash
tools/picus/run-overnight.sh /path/to/run-picus
```

## CI Smoke Workflow
A deterministic Picus smoke test workflow is available at:
- `.github/workflows/formal-picus-smoke.yml`

It runs Picus via Docker with a pinned image digest and verifies a small-scope fixture (`single-file-tiny-depth1`) using `--output-prefix-len 1` and `--picus-witness-precondition`.

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

### Convergence Aid: Witness-Guided Precondition (Use With Care)
`picus_verify` supports `--picus-witness-precondition`, which emits a Picus precondition that fixes all non-output wires to values from a known satisfying assignment.

This is useful to get *conclusive* `pass`/`violation` results for small scopes without spending time on "solve from scratch", but it can hide determinism violations that require changing internal wires. Do not treat a `pass` under witness precondition as sufficient evidence for the full determinism claim in `docs/formal/determinism-spec.md`.

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
