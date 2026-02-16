# Determinism Verification: Big Picture

This document is a high-level narrative of the determinism / underconstraint verification work
for `PorCircuit` using Veridise Picus, written for readers who are not deeply familiar with
R1CS, Nova, or SMT-based circuit analysis.

## What We’re Trying to Prove (And Why)

In this repository, the production circuit is the one-step Nova primary step circuit
implemented in `src/circuit/synth.rs` (referred to as `PorCircuit`).

A ZK “circuit” is a set of algebraic constraints (R1CS). A proof establishes:

> There exists a private witness such that, together with the public inputs, all constraints
> are satisfied.

If the constraints are missing something, the circuit can be **underconstrained**: there can
be multiple different satisfying assignments that produce different “outputs” while still
passing all checks. Underconstraints are a common class of real-world ZK bugs.

The goal of this project is to use Picus to detect (and later prevent regressions of) those
underconstraints for our step circuit.

## The Key Subtlety: `PorCircuit` Is a Relation, Not a Function of Public Inputs

It is tempting to ask for “determinism from public inputs alone”:

> Fix public `z`. Are the step outputs uniquely determined?

For the production `PorCircuit`, that is generally the wrong statement. The circuit contains
a witness-private value (`leaf`) that participates directly in the transition:

`state_out = Poseidon(state_in, leaf)`.

So, unless you additionally assume something like “the public inputs + constraints force a
unique leaf”, you should not expect the step outputs to be a pure function of public `z`
alone. In other words: the production circuit is inherently a **relation**.

As a result, a good practical underconstraint check is scoped as:

> For fixed public inputs, and fixed witness material that defines the transition (e.g. leaf
> and the Merkle siblings used in membership checks), are the step outputs uniquely forced by
> the constraints?

This scope is implemented via a Picus precondition (see below).

## What Picus “Safe/Unsafe” Means

Picus is a uniqueness / determinism checker for R1CS-style circuits. Conceptually it:

1. Duplicates the circuit into two copies (`x*` wires and `y*` wires).
2. Forces the chosen “known” signals to be equal across the two copies.
3. Asks an SMT solver whether a chosen “target” signal can differ (e.g. `x_out != y_out`)
   while both copies still satisfy the constraints and preconditions.

Outcomes:

- `safe` (exit code `8`): no counterexample exists for the chosen targets under the chosen
  scope; targets are uniquely determined.
- `unsafe` (exit code `9`): Picus found two satisfying assignments that agree on the known
  part but differ on a target; the circuit is underconstrained for that scope.
- `unknown` (exit code `0`): timeout / solver couldn’t conclude.

Important: Picus is only as meaningful as the *scope* you give it (which outputs are targets,
and which inputs/witness signals are fixed).

## How This Repo Integrates Picus

### Export: Nova ShapeCS -> Picus `.r1cs`

The Nova step circuit is synthesized into a `ShapeCS` constraint system, then exported into
a Picus-readable `.r1cs` and accompanying `.sym`.

Implementation:

- Exporter / schema / encoding: `src/formal/mod.rs`
- CLI: `src/bin/picus_export.rs`

### Verification Driver

We run Picus with bounded timeouts and capture logs/results into `artifacts/`.

Implementation:

- CLI wrapper: `src/bin/picus_verify.rs`
- Shell runners for parallelizing independent proofs: `tools/picus/run-matrix-safe.sh`

### Determinism Scopes (Preconditions)

We support multiple precondition “levels”:

1. `InputsOnly`: fix public inputs (`z`) to a fixture instance.
2. `WitnessExceptOutputs`: fix essentially all internal witness wires (debugging / upper bound).
3. `InputsPlusLeafPathOnly` (“leaf+path”): fix public inputs plus only witness material intended
   to define the transition (leaf and Merkle siblings), and for convergence also pin the
   derived selector/gating bits.

To make `InputsPlusLeafPathOnly` possible, we added witness tracing in circuit synthesis to
recover the relevant aux indices:

- Trace type and synthesis hook: `src/circuit/synth.rs` (`PorWitnessTrace`,
  `synthesize_por_circuit_with_trace`)
- Precondition writer: `src/formal/mod.rs`

## What We Proved / What We Didn’t

### What We Proved

- The Picus toolchain runs end-to-end on exported artifacts.
- We can get conclusive Picus results (`exit=8`) on a realistic fixture matrix under
  the “leaf+path” precondition, for a limited output prefix (e.g. `[root_out, state_out]`).
- The “circuit ladder” (stripped rungs) demonstrates the solver can handle Poseidon,
  bit-decomposition, and small Merkle gadgets when witness freedom is appropriately scoped.

### What We Did Not Prove

- We did **not** prove “determinism from public inputs alone” for the production circuit
  (and we do not expect it to hold, since the circuit is a relation).
- We did **not** prove any cryptographic assumptions such as hash injectivity or unique
  Merkle preimages.
- We did **not** prove full Nova recursion correctness; scope is the one-step relation.
- We did **not** prove uniqueness for the entire output vector in all runs; we often use
  an output prefix for tractability.

### Output Threading: Now Explicitly Constrained

While validating results, we found that some “carry-forward” outputs were allocated as fresh
variables at the end of `PorCircuit` synthesis without tying them back to their intended
values via equality constraints (e.g. `root_out` should equal the public root input).

This was fixed by adding explicit equality constraints for:

- `root_out`
- `ledger_index_out_*`
- `depth_out_*`
- `seed_out_*`

After this fix, a root-only Picus run (`--output-prefix-len 1`) under the leaf+path scope is
fast and conclusive across the fixture matrix.

## Where to Look Next

- Intended spec: `docs/formal/determinism-spec.md`
- How to run Picus here: `docs/formal/picus-runbook.md`
- Current results and fixture coverage: `docs/formal/determinism-report.md`
