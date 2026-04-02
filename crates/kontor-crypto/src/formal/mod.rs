//! Formal verification tooling support for deterministic/uniqueness checks.
//!
//! This module provides deterministic fixture handling and export of Nova R1CS
//! artifacts for external analyzers such as Picus.

pub mod components;
pub mod roles;

use crate::api::{prepare_file, tree_depth_from_metadata, Challenge, FieldElement, PreparedFile};
use crate::circuit::formal_components::{
    synthesize_aggregation_merkle_component, synthesize_carry_forward_component,
    synthesize_challenge_component, synthesize_file_merkle_component,
    synthesize_full_carry_forward_mutant, synthesize_state_update_component,
    AggregationMerkleComponentCircuit, AggregationMerkleMutantComponentCircuit,
    CarryForwardComponentCircuit, CarryForwardMutantComponentCircuit,
    ChallengeDerivationComponentCircuit, ChallengeDerivationMutantComponentCircuit,
    ComponentWitnessTrace, FileMerkleComponentCircuit, FileMerkleMutantComponentCircuit,
    StateUpdateComponentCircuit, StateUpdateMutantComponentCircuit,
};
#[cfg(feature = "formal-dev")]
use crate::circuit::lite::{
    PorCircuitLiteLinear, PorCircuitLiteMerklePoseidonChallengeBits,
    PorCircuitLiteMerklePoseidonDet, PorCircuitLiteMul, PorCircuitLitePoseidonBits,
    PorCircuitLitePoseidonStateOnly,
};
use crate::circuit::synth::{synthesize_por_circuit_with_trace, PorWitnessTrace};
use crate::circuit::PorCircuit;
use crate::config::{self, PublicIOLayout};
use crate::ledger::FileLedger;
use crate::poseidon::calculate_root_commitment;
use crate::{KontorPoRError, Result};
use bincode::Options;
use ff::{Field, PrimeField};
use nova_snark::frontend::{
    gadgets::num::AllocatedNum,
    r1cs::{NovaShape, NovaWitness},
    shape_cs::ShapeCS,
    solver::SatisfyingAssignment,
    ConstraintSystem, Index, SynthesisError,
};
use nova_snark::provider::PallasEngine;
use nova_snark::traits::{circuit::StepCircuit, snark::default_ck_hint, Engine};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// Manifest listing all formal fixtures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureManifest {
    pub version: u32,
    pub fixtures: Vec<String>,
}

/// Scenario kind used for reporting and filtering.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioKind {
    SingleFile,
    MultiFile,
    MixedDepth,
    Padding,
    /// Toy fixture: build a tiny Merkle tree directly (bypasses RS expansion) for convergence testing.
    TinyMerkle,
}

/// Which circuit implementation to synthesize for a fixture export.
///
/// `full` is the production `PorCircuit`. Other kinds are stripped-down variants used to get
/// conclusive Picus results and to isolate solver bottlenecks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum CircuitKind {
    #[default]
    Full,
    FullCarryForwardMutant,
    ComponentChallengeDerivation,
    ComponentChallengeDerivationMutant,
    ComponentFileMerkle,
    ComponentFileMerkleMutant,
    ComponentAggregationMerkle,
    ComponentAggregationMerkleMutant,
    ComponentStateUpdate,
    ComponentStateUpdateMutant,
    ComponentCarryForward,
    ComponentCarryForwardMutant,
    LiteLinear,
    LiteMul,
    LitePoseidonStateOnly,
    LiteMerklePoseidonDet,
    LitePoseidonBits,
    LiteMerklePoseidonChallengeBits,
}

impl CircuitKind {
    pub fn is_component(&self) -> bool {
        matches!(
            self,
            Self::ComponentChallengeDerivation
                | Self::ComponentChallengeDerivationMutant
                | Self::ComponentFileMerkle
                | Self::ComponentFileMerkleMutant
                | Self::ComponentAggregationMerkle
                | Self::ComponentAggregationMerkleMutant
                | Self::ComponentStateUpdate
                | Self::ComponentStateUpdateMutant
                | Self::ComponentCarryForward
                | Self::ComponentCarryForwardMutant
        )
    }

    pub fn is_mutant(&self) -> bool {
        matches!(
            self,
            Self::FullCarryForwardMutant
                | Self::ComponentChallengeDerivationMutant
                | Self::ComponentFileMerkleMutant
                | Self::ComponentAggregationMerkleMutant
                | Self::ComponentStateUpdateMutant
                | Self::ComponentCarryForwardMutant
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedPicusResult {
    #[default]
    Safe,
    Unsafe,
}

/// Verification scope used by fixture-level policy overrides.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum VerificationScope {
    #[default]
    Leafpath,
    PublicZ,
}

/// Solver selection policy for one fixture.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SolverPolicy {
    pub primary: String,
    #[serde(default)]
    pub fallbacks: Vec<String>,
}

impl Default for SolverPolicy {
    fn default() -> Self {
        Self {
            primary: "cvc5".to_string(),
            fallbacks: Vec::new(),
        }
    }
}

/// Optional fixture-level verification policy.
///
/// Any field left as `None` inherits the corresponding CLI/default value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct FormalVerificationPolicy {
    #[serde(default)]
    pub scope: Option<VerificationScope>,
    #[serde(default)]
    pub output_prefix_len: Option<usize>,
    #[serde(default)]
    pub solver_policy: Option<SolverPolicy>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    #[serde(default)]
    pub hard_timeout_grace_secs: Option<u64>,
}

/// Expected circuit shape metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExpectedShape {
    pub files_per_step: usize,
    pub file_tree_depth: usize,
    pub aggregated_tree_depth: usize,
}

/// File generation spec for a formal fixture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormalFileSpec {
    pub size: usize,
    pub seed: Option<u64>,
    /// Toy fixture only: exact padded leaf count for the Merkle tree (must be power-of-two).
    #[serde(default)]
    pub toy_padded_len: Option<usize>,
}

/// Formal fixture definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormalFixture {
    pub fixture_id: String,
    pub description: String,
    pub scenario_kind: ScenarioKind,
    #[serde(default)]
    pub circuit_kind: CircuitKind,
    pub challenge_count: usize,
    pub seed: u64,
    pub block_height: u64,
    pub prover_id: String,
    #[serde(default = "default_distinct_seeds")]
    pub distinct_seeds: bool,
    pub file_specs: Vec<FormalFileSpec>,
    #[serde(default)]
    pub expected_shape: Option<ExpectedShape>,
    #[serde(default)]
    pub expected_num_constraints: Option<usize>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub expected_result: ExpectedPicusResult,
    #[serde(default)]
    pub verification: FormalVerificationPolicy,
}

/// Serializable metadata describing one export run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportMetadata {
    pub fixture_id: String,
    pub description: String,
    pub scenario_kind: ScenarioKind,
    pub file_count: usize,
    pub challenge_count: usize,
    pub derived_shape: ExpectedShape,
    pub expected_shape: Option<ExpectedShape>,
    #[serde(default)]
    pub expected_num_constraints: Option<usize>,
    pub shape_match: bool,
    pub sorted_file_ids: Vec<String>,
    pub z0_primary_hex: Vec<String>,
    pub num_constraints: usize,
    pub num_inputs: usize,
    pub num_aux: usize,
    pub checksums: ArtifactChecksums,
    pub picus_input_ready: bool,
    #[serde(default)]
    pub picus_output_prefix_len: Option<usize>,
    pub note: String,
}

/// Checksums for exported artifacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactChecksums {
    pub shape_bin_sha256: String,
    pub instance_bin_sha256: String,
    pub witness_bin_sha256: String,
    pub commitment_key_bin_sha256: String,
}

/// Output paths and summary for one export.
#[derive(Debug, Clone)]
pub struct ExportOutput {
    pub fixture_id: String,
    pub artifact_dir: PathBuf,
    pub shape_path: PathBuf,
    pub instance_path: PathBuf,
    pub witness_path: PathBuf,
    pub commitment_key_path: PathBuf,
    pub metadata_path: PathBuf,
    pub picus_input_path: PathBuf,
    pub picus_precondition_path: Option<PathBuf>,
    pub metadata: ExportMetadata,
}

#[derive(Debug, Clone)]
struct DerivedPlan {
    files_per_step: usize,
    file_tree_depth: usize,
    aggregated_tree_depth: usize,
    aggregated_root: FieldElement,
    initial_state: FieldElement,
    sorted_challenges: Vec<Challenge>,
    ledger_indices: Vec<usize>,
    depths: Vec<usize>,
    seeds: Vec<FieldElement>,
    expected_rcs: Vec<FieldElement>,
    public_io_layout: PublicIOLayout,
}

#[derive(Debug)]
struct FixtureScenario {
    files: BTreeMap<String, PreparedFile>,
    challenges: Vec<Challenge>,
    ledger: FileLedger,
}

type E1 = PallasEngine;
type F1 = <E1 as Engine>::Scalar;

fn default_distinct_seeds() -> bool {
    true
}

/// Load fixture manifest from disk.
pub fn load_manifest(path: &Path) -> Result<FixtureManifest> {
    let data = fs::read_to_string(path)
        .map_err(|e| io_err(format!("Failed to read manifest {}", path.display()), e))?;

    serde_json::from_str(&data).map_err(|e| {
        KontorPoRError::Serialization(format!(
            "Failed to parse manifest {}: {}",
            path.display(),
            e
        ))
    })
}

/// Load one formal fixture by id.
pub fn load_fixture(fixtures_dir: &Path, fixture_id: &str) -> Result<FormalFixture> {
    let fixture_path = fixtures_dir.join(format!("{fixture_id}.json"));
    let data = fs::read_to_string(&fixture_path).map_err(|e| {
        io_err(
            format!("Failed to read fixture {}", fixture_path.display()),
            e,
        )
    })?;

    let fixture: FormalFixture = serde_json::from_str(&data).map_err(|e| {
        KontorPoRError::Serialization(format!(
            "Failed to parse fixture {}: {}",
            fixture_path.display(),
            e
        ))
    })?;

    if fixture.fixture_id != fixture_id {
        return Err(KontorPoRError::InvalidInput(format!(
            "Fixture file {} has mismatched fixture_id {}",
            fixture_path.display(),
            fixture.fixture_id
        )));
    }

    validate_fixture(&fixture)?;

    Ok(fixture)
}

/// Load all fixtures listed in the manifest.
pub fn load_manifest_fixtures(
    manifest_path: &Path,
    fixtures_dir: &Path,
) -> Result<Vec<FormalFixture>> {
    let manifest = load_manifest(manifest_path)?;
    let mut fixtures = Vec::with_capacity(manifest.fixtures.len());

    for fixture_id in manifest.fixtures {
        fixtures.push(load_fixture(fixtures_dir, &fixture_id)?);
    }

    Ok(fixtures)
}

/// Export one fixture to deterministic Nova artifacts.
pub fn export_fixture(fixture: &FormalFixture, artifacts_root: &Path) -> Result<ExportOutput> {
    export_fixture_impl(fixture, artifacts_root, None, PicusPreconditionKind::None)
}

/// Export one fixture but write a Picus .r1cs variant where only the first `prefix_len`
/// circuit outputs are treated as Picus "public outputs" (targets).
///
/// This is intended for incremental convergence experiments (e.g. root-only, root+state).
pub fn export_fixture_with_picus_output_prefix(
    fixture: &FormalFixture,
    artifacts_root: &Path,
    prefix_len: usize,
) -> Result<ExportOutput> {
    if prefix_len == 0 {
        return export_fixture(fixture, artifacts_root);
    }
    export_fixture_impl(
        fixture,
        artifacts_root,
        Some(prefix_len),
        PicusPreconditionKind::None,
    )
}

/// Which Picus precondition (if any) to emit alongside an exported Picus-ready R1CS.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PicusPreconditionKind {
    None,
    /// Fix all non-output wires to a known satisfying assignment.
    WitnessExceptOutputs,
    /// Fix only public inputs (and the constant-one wire) to the fixture's `z` instance values.
    InputsOnly,
    /// Fix public inputs plus the witness leaf + Merkle sibling values (and nothing else).
    ///
    /// This is intended to make the production circuit behave "functionally" for the
    /// witness material that actually defines the transition, while still allowing Picus
    /// to explore intermediate wires.
    ///
    /// Note: for convergence, this also pins the derived Merkle path selector bits and
    /// the `active_flags` gating bits used in the production Merkle gadget.
    InputsPlusLeafPathOnly,
}

/// Export one fixture for Picus verification and optionally emit a Picus precondition.
pub fn export_fixture_for_picus_verify(
    fixture: &FormalFixture,
    artifacts_root: &Path,
    picus_output_prefix_len: Option<usize>,
    picus_precondition: PicusPreconditionKind,
) -> Result<ExportOutput> {
    export_fixture_impl(
        fixture,
        artifacts_root,
        picus_output_prefix_len,
        picus_precondition,
    )
}

fn export_fixture_impl(
    fixture: &FormalFixture,
    artifacts_root: &Path,
    picus_output_prefix_len: Option<usize>,
    picus_precondition: PicusPreconditionKind,
) -> Result<ExportOutput> {
    validate_fixture(fixture)?;

    let scenario = build_fixture_scenario(fixture)?;
    let plan = derive_plan(&scenario.challenges, &scenario.ledger)?;

    if let Some(expected) = &fixture.expected_shape {
        let derived = ExpectedShape {
            files_per_step: plan.files_per_step,
            file_tree_depth: plan.file_tree_depth,
            aggregated_tree_depth: plan.aggregated_tree_depth,
        };

        if &derived != expected {
            return Err(KontorPoRError::InvalidInput(format!(
                "Fixture {} expected shape {:?}, got {:?}",
                fixture.fixture_id, expected, derived
            )));
        }
    }

    let sorted_challenge_refs: Vec<&Challenge> = plan.sorted_challenges.iter().collect();
    let file_refs: BTreeMap<String, &PreparedFile> =
        scenario.files.iter().map(|(k, v)| (k.clone(), v)).collect();

    let (circuit_witness, _) = crate::api::generate_circuit_witness(
        &sorted_challenge_refs,
        Some(&file_refs),
        &scenario.ledger,
        plan.file_tree_depth,
        plan.file_tree_depth,
        plan.initial_state,
        plan.aggregated_tree_depth,
        0,
        &plan.ledger_indices,
    )?;

    let witnesses_vec = circuit_witness.witnesses().to_vec();

    let z0_primary = plan.public_io_layout.build_z0_primary(
        plan.aggregated_root,
        plan.initial_state,
        &plan.ledger_indices,
        &plan.depths,
        &plan.seeds,
        &plan.expected_rcs,
    );

    let mut shape_cs: ShapeCS<E1> = ShapeCS::new();
    let z_shape = alloc_z_inputs(&mut shape_cs, &z0_primary).map_err(circuit_err)?;
    let z_next_shape = {
        #[cfg(feature = "formal-dev")]
        {
            match fixture.circuit_kind {
                CircuitKind::Full | CircuitKind::FullCarryForwardMutant => {
                    let circuit = PorCircuit::<FieldElement>::new(
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                        Some(witnesses_vec.clone()),
                    );
                    if fixture.circuit_kind == CircuitKind::FullCarryForwardMutant {
                        synthesize_full_carry_forward_mutant(
                            &mut shape_cs,
                            &z_shape,
                            plan.files_per_step,
                        )
                        .map_err(circuit_err)?
                    } else {
                        circuit
                            .synthesize(&mut shape_cs, &z_shape)
                            .map_err(circuit_err)?
                    }
                }
                CircuitKind::ComponentChallengeDerivation => {
                    let circuit = ChallengeDerivationComponentCircuit::<FieldElement>::new(
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                    );
                    circuit
                        .synthesize(&mut shape_cs, &z_shape)
                        .map_err(circuit_err)?
                }
                CircuitKind::ComponentChallengeDerivationMutant => {
                    let circuit = ChallengeDerivationMutantComponentCircuit::<FieldElement>::new(
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                    );
                    circuit
                        .synthesize(&mut shape_cs, &z_shape)
                        .map_err(circuit_err)?
                }
                CircuitKind::ComponentFileMerkle => {
                    let circuit = FileMerkleComponentCircuit::<FieldElement>::new(
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                        Some(circuit_witness.clone()),
                    );
                    circuit
                        .synthesize(&mut shape_cs, &z_shape)
                        .map_err(circuit_err)?
                }
                CircuitKind::ComponentFileMerkleMutant => {
                    let circuit = FileMerkleMutantComponentCircuit::<FieldElement>::new(
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                        Some(circuit_witness.clone()),
                    );
                    circuit
                        .synthesize(&mut shape_cs, &z_shape)
                        .map_err(circuit_err)?
                }
                CircuitKind::ComponentAggregationMerkle => {
                    let circuit = AggregationMerkleComponentCircuit::<FieldElement>::new(
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                        Some(circuit_witness.clone()),
                    );
                    circuit
                        .synthesize(&mut shape_cs, &z_shape)
                        .map_err(circuit_err)?
                }
                CircuitKind::ComponentAggregationMerkleMutant => {
                    let circuit = AggregationMerkleMutantComponentCircuit::<FieldElement>::new(
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                        Some(circuit_witness.clone()),
                    );
                    circuit
                        .synthesize(&mut shape_cs, &z_shape)
                        .map_err(circuit_err)?
                }
                CircuitKind::ComponentStateUpdate => {
                    let circuit = StateUpdateComponentCircuit::<FieldElement>::new(
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                        Some(circuit_witness.clone()),
                    );
                    circuit
                        .synthesize(&mut shape_cs, &z_shape)
                        .map_err(circuit_err)?
                }
                CircuitKind::ComponentStateUpdateMutant => {
                    let circuit = StateUpdateMutantComponentCircuit::<FieldElement>::new(
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                        Some(circuit_witness.clone()),
                    );
                    circuit
                        .synthesize(&mut shape_cs, &z_shape)
                        .map_err(circuit_err)?
                }
                CircuitKind::ComponentCarryForward => {
                    let circuit =
                        CarryForwardComponentCircuit::<FieldElement>::new(plan.files_per_step);
                    circuit
                        .synthesize(&mut shape_cs, &z_shape)
                        .map_err(circuit_err)?
                }
                CircuitKind::ComponentCarryForwardMutant => {
                    let circuit = CarryForwardMutantComponentCircuit::<FieldElement>::new(
                        plan.files_per_step,
                    );
                    circuit
                        .synthesize(&mut shape_cs, &z_shape)
                        .map_err(circuit_err)?
                }
                CircuitKind::LiteLinear => {
                    let circuit = PorCircuitLiteLinear::<FieldElement>::new(
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                    );
                    circuit
                        .synthesize(&mut shape_cs, &z_shape)
                        .map_err(circuit_err)?
                }
                CircuitKind::LiteMul => {
                    let circuit = PorCircuitLiteMul::<FieldElement>::new(
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                    );
                    circuit
                        .synthesize(&mut shape_cs, &z_shape)
                        .map_err(circuit_err)?
                }
                CircuitKind::LitePoseidonStateOnly => {
                    let circuit = PorCircuitLitePoseidonStateOnly::<FieldElement>::new(
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                    );
                    circuit
                        .synthesize(&mut shape_cs, &z_shape)
                        .map_err(circuit_err)?
                }
                CircuitKind::LiteMerklePoseidonDet => {
                    let circuit = PorCircuitLiteMerklePoseidonDet::<FieldElement>::new(
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                    );
                    circuit
                        .synthesize(&mut shape_cs, &z_shape)
                        .map_err(circuit_err)?
                }
                CircuitKind::LitePoseidonBits => {
                    let circuit = PorCircuitLitePoseidonBits::<FieldElement>::new(
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                    );
                    circuit
                        .synthesize(&mut shape_cs, &z_shape)
                        .map_err(circuit_err)?
                }
                CircuitKind::LiteMerklePoseidonChallengeBits => {
                    let circuit = PorCircuitLiteMerklePoseidonChallengeBits::<FieldElement>::new(
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                    );
                    circuit
                        .synthesize(&mut shape_cs, &z_shape)
                        .map_err(circuit_err)?
                }
            }
        }
        #[cfg(not(feature = "formal-dev"))]
        {
            match &fixture.circuit_kind {
                CircuitKind::Full | CircuitKind::FullCarryForwardMutant => {
                    let circuit = PorCircuit::<FieldElement>::new(
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                        Some(witnesses_vec.clone()),
                    );
                    if fixture.circuit_kind == CircuitKind::FullCarryForwardMutant {
                        synthesize_full_carry_forward_mutant(
                            &mut shape_cs,
                            &z_shape,
                            plan.files_per_step,
                        )
                        .map_err(circuit_err)?
                    } else {
                        circuit
                            .synthesize(&mut shape_cs, &z_shape)
                            .map_err(circuit_err)?
                    }
                }
                CircuitKind::ComponentChallengeDerivation => {
                    let circuit = ChallengeDerivationComponentCircuit::<FieldElement>::new(
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                    );
                    circuit
                        .synthesize(&mut shape_cs, &z_shape)
                        .map_err(circuit_err)?
                }
                CircuitKind::ComponentChallengeDerivationMutant => {
                    let circuit = ChallengeDerivationMutantComponentCircuit::<FieldElement>::new(
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                    );
                    circuit
                        .synthesize(&mut shape_cs, &z_shape)
                        .map_err(circuit_err)?
                }
                CircuitKind::ComponentFileMerkle => {
                    let circuit = FileMerkleComponentCircuit::<FieldElement>::new(
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                        Some(circuit_witness.clone()),
                    );
                    circuit
                        .synthesize(&mut shape_cs, &z_shape)
                        .map_err(circuit_err)?
                }
                CircuitKind::ComponentFileMerkleMutant => {
                    let circuit = FileMerkleMutantComponentCircuit::<FieldElement>::new(
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                        Some(circuit_witness.clone()),
                    );
                    circuit
                        .synthesize(&mut shape_cs, &z_shape)
                        .map_err(circuit_err)?
                }
                CircuitKind::ComponentAggregationMerkle => {
                    let circuit = AggregationMerkleComponentCircuit::<FieldElement>::new(
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                        Some(circuit_witness.clone()),
                    );
                    circuit
                        .synthesize(&mut shape_cs, &z_shape)
                        .map_err(circuit_err)?
                }
                CircuitKind::ComponentAggregationMerkleMutant => {
                    let circuit = AggregationMerkleMutantComponentCircuit::<FieldElement>::new(
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                        Some(circuit_witness.clone()),
                    );
                    circuit
                        .synthesize(&mut shape_cs, &z_shape)
                        .map_err(circuit_err)?
                }
                CircuitKind::ComponentStateUpdate => {
                    let circuit = StateUpdateComponentCircuit::<FieldElement>::new(
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                        Some(circuit_witness.clone()),
                    );
                    circuit
                        .synthesize(&mut shape_cs, &z_shape)
                        .map_err(circuit_err)?
                }
                CircuitKind::ComponentStateUpdateMutant => {
                    let circuit = StateUpdateMutantComponentCircuit::<FieldElement>::new(
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                        Some(circuit_witness.clone()),
                    );
                    circuit
                        .synthesize(&mut shape_cs, &z_shape)
                        .map_err(circuit_err)?
                }
                CircuitKind::ComponentCarryForward => {
                    let circuit =
                        CarryForwardComponentCircuit::<FieldElement>::new(plan.files_per_step);
                    circuit
                        .synthesize(&mut shape_cs, &z_shape)
                        .map_err(circuit_err)?
                }
                CircuitKind::ComponentCarryForwardMutant => {
                    let circuit = CarryForwardMutantComponentCircuit::<FieldElement>::new(
                        plan.files_per_step,
                    );
                    circuit
                        .synthesize(&mut shape_cs, &z_shape)
                        .map_err(circuit_err)?
                }
                other => {
                    return Err(KontorPoRError::InvalidInput(format!(
                        "Circuit kind {:?} requires cargo feature `formal-dev`",
                        other
                    )));
                }
            }
        }
    };

    let num_constraints = shape_cs.num_constraints();
    let num_inputs = shape_cs.num_inputs();
    let num_aux = shape_cs.num_aux();
    if let Some(expected_num_constraints) = fixture.expected_num_constraints {
        if num_constraints != expected_num_constraints {
            return Err(KontorPoRError::InvalidInput(format!(
                "Fixture {} expected {} constraints, got {}",
                fixture.fixture_id, expected_num_constraints, num_constraints
            )));
        }
    }

    let (shape, ck) = shape_cs.r1cs_shape(&*default_ck_hint());

    let mut sat_cs = SatisfyingAssignment::<E1>::new();
    let z_sat = alloc_z_inputs(&mut sat_cs, &z0_primary).map_err(circuit_err)?;
    let mut por_trace: Option<PorWitnessTrace> = None;
    let mut component_trace: Option<ComponentWitnessTrace> = None;
    {
        #[cfg(feature = "formal-dev")]
        match fixture.circuit_kind {
            CircuitKind::Full | CircuitKind::FullCarryForwardMutant => {
                let circuit = PorCircuit::<FieldElement>::new(
                    plan.files_per_step,
                    plan.file_tree_depth,
                    plan.aggregated_tree_depth,
                    Some(witnesses_vec),
                );
                if picus_precondition == PicusPreconditionKind::InputsPlusLeafPathOnly {
                    let mut trace = PorWitnessTrace::default();
                    if fixture.circuit_kind == CircuitKind::FullCarryForwardMutant {
                        let _ = synthesize_full_carry_forward_mutant(
                            &mut sat_cs,
                            &z_sat,
                            plan.files_per_step,
                        )
                        .map_err(circuit_err)?;
                    } else {
                        let _ = synthesize_por_circuit_with_trace(
                            &mut sat_cs,
                            &z_sat,
                            plan.files_per_step,
                            plan.file_tree_depth,
                            plan.aggregated_tree_depth,
                            circuit.witness.as_ref(),
                            Some(&mut trace),
                        )
                        .map_err(circuit_err)?;
                    }
                    por_trace = Some(trace);
                } else if fixture.circuit_kind == CircuitKind::FullCarryForwardMutant {
                    let _ = synthesize_full_carry_forward_mutant(
                        &mut sat_cs,
                        &z_sat,
                        plan.files_per_step,
                    )
                    .map_err(circuit_err)?;
                } else {
                    let _ = circuit
                        .synthesize(&mut sat_cs, &z_sat)
                        .map_err(circuit_err)?;
                }
            }
            CircuitKind::ComponentChallengeDerivation
            | CircuitKind::ComponentChallengeDerivationMutant => {
                if picus_precondition == PicusPreconditionKind::InputsPlusLeafPathOnly {
                    component_trace = Some(ComponentWitnessTrace::default());
                }
                let mutant =
                    fixture.circuit_kind == CircuitKind::ComponentChallengeDerivationMutant;
                let _ = synthesize_challenge_component(
                    &mut sat_cs,
                    &z_sat,
                    plan.files_per_step,
                    plan.aggregated_tree_depth,
                    mutant,
                )
                .map_err(circuit_err)?;
            }
            CircuitKind::ComponentFileMerkle | CircuitKind::ComponentFileMerkleMutant => {
                let mutant = fixture.circuit_kind == CircuitKind::ComponentFileMerkleMutant;
                if picus_precondition == PicusPreconditionKind::InputsPlusLeafPathOnly {
                    let mut trace = ComponentWitnessTrace::default();
                    let _ = synthesize_file_merkle_component(
                        &mut sat_cs,
                        &z_sat,
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                        Some(&circuit_witness),
                        Some(&mut trace),
                        mutant,
                    )
                    .map_err(circuit_err)?;
                    component_trace = Some(trace);
                } else {
                    let _ = synthesize_file_merkle_component(
                        &mut sat_cs,
                        &z_sat,
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                        Some(&circuit_witness),
                        None,
                        mutant,
                    )
                    .map_err(circuit_err)?;
                }
            }
            CircuitKind::ComponentAggregationMerkle
            | CircuitKind::ComponentAggregationMerkleMutant => {
                let mutant = fixture.circuit_kind == CircuitKind::ComponentAggregationMerkleMutant;
                if picus_precondition == PicusPreconditionKind::InputsPlusLeafPathOnly {
                    let mut trace = ComponentWitnessTrace::default();
                    let _ = synthesize_aggregation_merkle_component(
                        &mut sat_cs,
                        &z_sat,
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                        Some(&circuit_witness),
                        Some(&mut trace),
                        mutant,
                    )
                    .map_err(circuit_err)?;
                    component_trace = Some(trace);
                } else {
                    let _ = synthesize_aggregation_merkle_component(
                        &mut sat_cs,
                        &z_sat,
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                        Some(&circuit_witness),
                        None,
                        mutant,
                    )
                    .map_err(circuit_err)?;
                }
            }
            CircuitKind::ComponentStateUpdate | CircuitKind::ComponentStateUpdateMutant => {
                let mutant = fixture.circuit_kind == CircuitKind::ComponentStateUpdateMutant;
                if picus_precondition == PicusPreconditionKind::InputsPlusLeafPathOnly {
                    let mut trace = ComponentWitnessTrace::default();
                    let _ = synthesize_state_update_component(
                        &mut sat_cs,
                        &z_sat,
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                        Some(&circuit_witness),
                        Some(&mut trace),
                        mutant,
                    )
                    .map_err(circuit_err)?;
                    component_trace = Some(trace);
                } else {
                    let _ = synthesize_state_update_component(
                        &mut sat_cs,
                        &z_sat,
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                        Some(&circuit_witness),
                        None,
                        mutant,
                    )
                    .map_err(circuit_err)?;
                }
            }
            CircuitKind::ComponentCarryForward | CircuitKind::ComponentCarryForwardMutant => {
                if picus_precondition == PicusPreconditionKind::InputsPlusLeafPathOnly {
                    component_trace = Some(ComponentWitnessTrace::default());
                }
                let mutant = fixture.circuit_kind == CircuitKind::ComponentCarryForwardMutant;
                let _ = synthesize_carry_forward_component(&mut sat_cs, &z_sat, mutant)
                    .map_err(circuit_err)?;
            }
            CircuitKind::LiteLinear => {
                let circuit = PorCircuitLiteLinear::<FieldElement>::new(
                    plan.files_per_step,
                    plan.file_tree_depth,
                    plan.aggregated_tree_depth,
                );
                let _ = circuit
                    .synthesize(&mut sat_cs, &z_sat)
                    .map_err(circuit_err)?;
            }
            CircuitKind::LiteMul => {
                let circuit = PorCircuitLiteMul::<FieldElement>::new(
                    plan.files_per_step,
                    plan.file_tree_depth,
                    plan.aggregated_tree_depth,
                );
                let _ = circuit
                    .synthesize(&mut sat_cs, &z_sat)
                    .map_err(circuit_err)?;
            }
            CircuitKind::LitePoseidonStateOnly => {
                let circuit = PorCircuitLitePoseidonStateOnly::<FieldElement>::new(
                    plan.files_per_step,
                    plan.file_tree_depth,
                    plan.aggregated_tree_depth,
                );
                let _ = circuit
                    .synthesize(&mut sat_cs, &z_sat)
                    .map_err(circuit_err)?;
            }
            CircuitKind::LiteMerklePoseidonDet => {
                let circuit = PorCircuitLiteMerklePoseidonDet::<FieldElement>::new(
                    plan.files_per_step,
                    plan.file_tree_depth,
                    plan.aggregated_tree_depth,
                );
                let _ = circuit
                    .synthesize(&mut sat_cs, &z_sat)
                    .map_err(circuit_err)?;
            }
            CircuitKind::LitePoseidonBits => {
                let circuit = PorCircuitLitePoseidonBits::<FieldElement>::new(
                    plan.files_per_step,
                    plan.file_tree_depth,
                    plan.aggregated_tree_depth,
                );
                let _ = circuit
                    .synthesize(&mut sat_cs, &z_sat)
                    .map_err(circuit_err)?;
            }
            CircuitKind::LiteMerklePoseidonChallengeBits => {
                let circuit = PorCircuitLiteMerklePoseidonChallengeBits::<FieldElement>::new(
                    plan.files_per_step,
                    plan.file_tree_depth,
                    plan.aggregated_tree_depth,
                );
                let _ = circuit
                    .synthesize(&mut sat_cs, &z_sat)
                    .map_err(circuit_err)?;
            }
        };

        #[cfg(not(feature = "formal-dev"))]
        match &fixture.circuit_kind {
            CircuitKind::Full | CircuitKind::FullCarryForwardMutant => {
                let circuit = PorCircuit::<FieldElement>::new(
                    plan.files_per_step,
                    plan.file_tree_depth,
                    plan.aggregated_tree_depth,
                    Some(witnesses_vec),
                );
                if picus_precondition == PicusPreconditionKind::InputsPlusLeafPathOnly {
                    let mut trace = PorWitnessTrace::default();
                    if fixture.circuit_kind == CircuitKind::FullCarryForwardMutant {
                        let _ = synthesize_full_carry_forward_mutant(
                            &mut sat_cs,
                            &z_sat,
                            plan.files_per_step,
                        )
                        .map_err(circuit_err)?;
                    } else {
                        let _ = synthesize_por_circuit_with_trace(
                            &mut sat_cs,
                            &z_sat,
                            plan.files_per_step,
                            plan.file_tree_depth,
                            plan.aggregated_tree_depth,
                            circuit.witness.as_ref(),
                            Some(&mut trace),
                        )
                        .map_err(circuit_err)?;
                    }
                    por_trace = Some(trace);
                } else if fixture.circuit_kind == CircuitKind::FullCarryForwardMutant {
                    let _ = synthesize_full_carry_forward_mutant(
                        &mut sat_cs,
                        &z_sat,
                        plan.files_per_step,
                    )
                    .map_err(circuit_err)?;
                } else {
                    let _ = circuit
                        .synthesize(&mut sat_cs, &z_sat)
                        .map_err(circuit_err)?;
                }
            }
            CircuitKind::ComponentChallengeDerivation
            | CircuitKind::ComponentChallengeDerivationMutant => {
                if picus_precondition == PicusPreconditionKind::InputsPlusLeafPathOnly {
                    component_trace = Some(ComponentWitnessTrace::default());
                }
                let mutant =
                    fixture.circuit_kind == CircuitKind::ComponentChallengeDerivationMutant;
                let _ = synthesize_challenge_component(
                    &mut sat_cs,
                    &z_sat,
                    plan.files_per_step,
                    plan.aggregated_tree_depth,
                    mutant,
                )
                .map_err(circuit_err)?;
            }
            CircuitKind::ComponentFileMerkle | CircuitKind::ComponentFileMerkleMutant => {
                let mutant = fixture.circuit_kind == CircuitKind::ComponentFileMerkleMutant;
                if picus_precondition == PicusPreconditionKind::InputsPlusLeafPathOnly {
                    let mut trace = ComponentWitnessTrace::default();
                    let _ = synthesize_file_merkle_component(
                        &mut sat_cs,
                        &z_sat,
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                        Some(&circuit_witness),
                        Some(&mut trace),
                        mutant,
                    )
                    .map_err(circuit_err)?;
                    component_trace = Some(trace);
                } else {
                    let _ = synthesize_file_merkle_component(
                        &mut sat_cs,
                        &z_sat,
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                        Some(&circuit_witness),
                        None,
                        mutant,
                    )
                    .map_err(circuit_err)?;
                }
            }
            CircuitKind::ComponentAggregationMerkle
            | CircuitKind::ComponentAggregationMerkleMutant => {
                let mutant = fixture.circuit_kind == CircuitKind::ComponentAggregationMerkleMutant;
                if picus_precondition == PicusPreconditionKind::InputsPlusLeafPathOnly {
                    let mut trace = ComponentWitnessTrace::default();
                    let _ = synthesize_aggregation_merkle_component(
                        &mut sat_cs,
                        &z_sat,
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                        Some(&circuit_witness),
                        Some(&mut trace),
                        mutant,
                    )
                    .map_err(circuit_err)?;
                    component_trace = Some(trace);
                } else {
                    let _ = synthesize_aggregation_merkle_component(
                        &mut sat_cs,
                        &z_sat,
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                        Some(&circuit_witness),
                        None,
                        mutant,
                    )
                    .map_err(circuit_err)?;
                }
            }
            CircuitKind::ComponentStateUpdate | CircuitKind::ComponentStateUpdateMutant => {
                let mutant = fixture.circuit_kind == CircuitKind::ComponentStateUpdateMutant;
                if picus_precondition == PicusPreconditionKind::InputsPlusLeafPathOnly {
                    let mut trace = ComponentWitnessTrace::default();
                    let _ = synthesize_state_update_component(
                        &mut sat_cs,
                        &z_sat,
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                        Some(&circuit_witness),
                        Some(&mut trace),
                        mutant,
                    )
                    .map_err(circuit_err)?;
                    component_trace = Some(trace);
                } else {
                    let _ = synthesize_state_update_component(
                        &mut sat_cs,
                        &z_sat,
                        plan.files_per_step,
                        plan.file_tree_depth,
                        plan.aggregated_tree_depth,
                        Some(&circuit_witness),
                        None,
                        mutant,
                    )
                    .map_err(circuit_err)?;
                }
            }
            CircuitKind::ComponentCarryForward | CircuitKind::ComponentCarryForwardMutant => {
                if picus_precondition == PicusPreconditionKind::InputsPlusLeafPathOnly {
                    component_trace = Some(ComponentWitnessTrace::default());
                }
                let mutant = fixture.circuit_kind == CircuitKind::ComponentCarryForwardMutant;
                let _ = synthesize_carry_forward_component(&mut sat_cs, &z_sat, mutant)
                    .map_err(circuit_err)?;
            }
            other => {
                return Err(KontorPoRError::InvalidInput(format!(
                    "Circuit kind {:?} requires cargo feature `formal-dev`",
                    other
                )));
            }
        };
    }
    let (instance, witness) = sat_cs
        .r1cs_instance_and_witness(&shape, &ck)
        .map_err(snark_err)?;

    shape.is_sat(&ck, &instance, &witness).map_err(snark_err)?;

    let artifact_dir = artifacts_root.join(&fixture.fixture_id);
    fs::create_dir_all(&artifact_dir).map_err(|e| {
        io_err(
            format!("Failed to create artifact dir {}", artifact_dir.display()),
            e,
        )
    })?;

    let shape_path = artifact_dir.join("shape.bin");
    let instance_path = artifact_dir.join("instance.bin");
    let witness_path = artifact_dir.join("witness.bin");
    let commitment_key_path = artifact_dir.join("commitment_key.bin");
    let metadata_path = artifact_dir.join("export-metadata.json");
    let picus_input_path = match picus_output_prefix_len {
        Some(n) => artifact_dir.join(format!("circuit.prefix{n}.r1cs")),
        None => artifact_dir.join("circuit.r1cs"),
    };

    write_bincode_file(&shape_path, &shape)?;
    write_bincode_file(&instance_path, &instance)?;
    write_bincode_file(&witness_path, &witness)?;
    write_bincode_file(&commitment_key_path, &ck)?;
    // Always write the full-output Picus artifact for reference and future full-scope checks.
    let picus_full_path = artifact_dir.join("circuit.r1cs");
    let _ = write_picus_r1cs_file(&shape_cs, &z_next_shape, &picus_full_path)?;

    // Optional reduced-scope Picus artifact for convergence experiments.
    let (picus_selected_wiring, _picus_selected_outputs_len) =
        if let Some(prefix_len) = picus_output_prefix_len {
            let prefix_len = prefix_len.min(z_next_shape.len());
            let wiring =
                write_picus_r1cs_file(&shape_cs, &z_next_shape[..prefix_len], &picus_input_path)?;
            (Some(wiring), Some(prefix_len))
        } else {
            let wiring = write_picus_r1cs_file(&shape_cs, &z_next_shape, &picus_input_path)?;
            (Some(wiring), None)
        };

    let picus_precondition_path = match picus_precondition {
        PicusPreconditionKind::None => None,
        PicusPreconditionKind::WitnessExceptOutputs
        | PicusPreconditionKind::InputsOnly
        | PicusPreconditionKind::InputsPlusLeafPathOnly => {
            let path = artifact_dir.join("picus-precondition.json");
            if let Some(wiring) = &picus_selected_wiring {
                match picus_precondition {
                    PicusPreconditionKind::WitnessExceptOutputs => {
                        write_picus_precondition_fix_witness_except_outputs(&sat_cs, wiring, &path)?
                    }
                    PicusPreconditionKind::InputsOnly => {
                        write_picus_precondition_fix_inputs_only(&sat_cs, wiring, &path)?
                    }
                    PicusPreconditionKind::InputsPlusLeafPathOnly => {
                        let leafpath_aux_indices = por_trace
                            .as_ref()
                            .map(collect_por_leafpath_aux_indices)
                            .or_else(|| {
                                component_trace
                                    .as_ref()
                                    .map(ComponentWitnessTrace::leafpath_aux_indices)
                            });

                        if let Some(aux_indices) = leafpath_aux_indices {
                            write_picus_precondition_fix_inputs_plus_leafpath_only(
                                &sat_cs,
                                wiring,
                                &aux_indices,
                                &path,
                            )?
                        } else if leafpath_scope_strict() {
                            return Err(KontorPoRError::InvalidInput(format!(
                                "Leafpath scope requested but no witness trace was captured for fixture {} (set KONTOR_PICUS_STRICT_SCOPE=0 to allow fallback)",
                                fixture.fixture_id
                            )));
                        } else {
                            write_picus_precondition_fix_inputs_only(&sat_cs, wiring, &path)?
                        }
                    }
                    PicusPreconditionKind::None => {}
                }
                Some(path)
            } else {
                None
            }
        }
    };

    let checksums = ArtifactChecksums {
        shape_bin_sha256: sha256_file(&shape_path)?,
        instance_bin_sha256: sha256_file(&instance_path)?,
        witness_bin_sha256: sha256_file(&witness_path)?,
        commitment_key_bin_sha256: sha256_file(&commitment_key_path)?,
    };

    let derived_shape = ExpectedShape {
        files_per_step: plan.files_per_step,
        file_tree_depth: plan.file_tree_depth,
        aggregated_tree_depth: plan.aggregated_tree_depth,
    };

    let shape_match = fixture
        .expected_shape
        .as_ref()
        .map(|expected| expected == &derived_shape)
        .unwrap_or(true);

    let metadata = ExportMetadata {
        fixture_id: fixture.fixture_id.clone(),
        description: fixture.description.clone(),
        scenario_kind: fixture.scenario_kind.clone(),
        file_count: scenario.files.len(),
        challenge_count: fixture.challenge_count,
        derived_shape,
        expected_shape: fixture.expected_shape.clone(),
        expected_num_constraints: fixture.expected_num_constraints,
        shape_match,
        sorted_file_ids: plan
            .sorted_challenges
            .iter()
            .map(|c| c.file_metadata.file_id.clone())
            .collect(),
        z0_primary_hex: z0_primary.iter().map(field_to_hex).collect(),
        num_constraints,
        num_inputs,
        num_aux,
        checksums,
        picus_input_ready: picus_full_path.exists(),
        picus_output_prefix_len,
        note: String::from(
            "Picus .r1cs input exported directly from ShapeCS constraints (deterministic encoding).",
        ),
    };

    write_json_file(&metadata_path, &metadata)?;

    Ok(ExportOutput {
        fixture_id: fixture.fixture_id.clone(),
        artifact_dir,
        shape_path,
        instance_path,
        witness_path,
        commitment_key_path,
        metadata_path,
        picus_input_path,
        picus_precondition_path,
        metadata,
    })
}

#[derive(Debug, Clone)]
struct PicusTerm {
    wire: u32,
    coeff: FieldElement,
}

#[derive(Debug, Clone)]
struct PicusConstraint {
    a: Vec<PicusTerm>,
    b: Vec<PicusTerm>,
    c: Vec<PicusTerm>,
}

#[derive(Debug, Clone)]
struct PicusLayout {
    fs: u32,
    prime_le: Vec<u8>,
    n_wires: u32,
    n_pub_out: u32,
    n_pub_in: u32,
    n_prvt_in: u32,
    n_labels: u64,
    constraints: Vec<PicusConstraint>,
    wire_map: Vec<u64>,
}

#[derive(Debug, Clone)]
struct PicusWiring {
    n_wires: u32,
    output_wires: Vec<u32>,
    input_to_wire: Vec<Option<u32>>,
    aux_to_wire: Vec<Option<u32>>,
}

fn write_picus_r1cs_file(
    shape_cs: &ShapeCS<E1>,
    outputs: &[AllocatedNum<FieldElement>],
    path: &Path,
) -> Result<PicusWiring> {
    let (layout_raw, wiring) = build_picus_layout(shape_cs, outputs)?;
    let layout = if should_simplify_layout() {
        simplify_layout_safe(layout_raw)
    } else {
        layout_raw
    };
    let bytes = encode_picus_r1cs(&layout)?;
    fs::write(path, bytes).map_err(|e| io_err(format!("Failed to write {}", path.display()), e))?;
    write_picus_sym_file(path, wiring.n_wires)?;
    Ok(wiring)
}

fn should_simplify_layout() -> bool {
    match std::env::var("KONTOR_PICUS_SIMPLIFY") {
        Ok(v) => {
            let t = v.trim().to_ascii_lowercase();
            !(t == "off" || t == "0" || t == "false")
        }
        Err(_) => true,
    }
}

fn leafpath_scope_strict() -> bool {
    match std::env::var("KONTOR_PICUS_STRICT_SCOPE") {
        Ok(v) => {
            let t = v.trim().to_ascii_lowercase();
            !(t == "off" || t == "0" || t == "false")
        }
        Err(_) => true,
    }
}

fn collect_por_leafpath_aux_indices(trace: &PorWitnessTrace) -> Vec<usize> {
    let mut aux_indices = Vec::<usize>::new();
    aux_indices.extend(trace.leaf_aux.iter().copied());
    for v in &trace.file_sibling_aux {
        aux_indices.extend(v.iter().copied());
    }
    for v in &trace.agg_sibling_aux {
        aux_indices.extend(v.iter().copied());
    }
    for v in &trace.file_path_bit_aux {
        aux_indices.extend(v.iter().copied());
    }
    for v in &trace.active_flag_aux {
        aux_indices.extend(v.iter().copied());
    }
    aux_indices.sort_unstable();
    aux_indices.dedup();
    aux_indices
}

fn simplify_layout_safe(mut layout: PicusLayout) -> PicusLayout {
    fn normalize_terms(terms: &[PicusTerm]) -> Vec<PicusTerm> {
        let mut by_wire = BTreeMap::<u32, FieldElement>::new();
        for t in terms {
            by_wire
                .entry(t.wire)
                .and_modify(|c| *c += t.coeff)
                .or_insert(t.coeff);
        }
        by_wire
            .into_iter()
            .filter_map(|(wire, coeff)| {
                if coeff == FieldElement::ZERO {
                    None
                } else {
                    Some(PicusTerm { wire, coeff })
                }
            })
            .collect()
    }

    for c in &mut layout.constraints {
        c.a = normalize_terms(&c.a);
        c.b = normalize_terms(&c.b);
        c.c = normalize_terms(&c.c);
    }

    // Remove trivial tautologies where both sides are guaranteed zero:
    // (0 * X = 0) or (X * 0 = 0).
    layout.constraints.retain(|c| {
        let lhs_is_zero = c.a.is_empty() || c.b.is_empty();
        !(lhs_is_zero && c.c.is_empty())
    });

    layout
}

fn write_picus_sym_file(r1cs_path: &Path, n_wires: u32) -> Result<()> {
    // Picus expects a Circom-style .sym CSV file alongside .r1cs; without it, Picus may
    // refuse to conclude and return "Cannot determine ...".
    //
    // The sym file does not include x0 (wire 0), so it must contain (n_wires - 1) rows.
    let mut sym_path = r1cs_path.to_path_buf();
    sym_path.set_extension("sym");

    let mut out = String::new();
    for sid in 1..n_wires {
        // Columns (minimum 4): id, name, order, scope.path
        // Picus uses col[2] (order) and col[3] (scope.path).
        out.push_str(&format!("{sid},x{sid},0,main.x{sid}\n"));
    }

    fs::write(&sym_path, out)
        .map_err(|e| io_err(format!("Failed to write {}", sym_path.display()), e))
}

fn build_picus_layout(
    shape_cs: &ShapeCS<E1>,
    outputs: &[AllocatedNum<FieldElement>],
) -> Result<(PicusLayout, PicusWiring)> {
    let num_inputs = shape_cs.num_inputs();
    if num_inputs == 0 {
        return Err(KontorPoRError::InvalidInput(
            "ShapeCS has zero inputs".to_string(),
        ));
    }

    let num_aux = shape_cs.num_aux();
    let output_aux = collect_output_aux_indices(outputs, num_aux)?;
    let output_set: BTreeSet<usize> = output_aux.iter().copied().collect();

    let mut next_wire: u32 = 1;
    let mut aux_to_wire = BTreeMap::new();
    let mut input_to_wire = BTreeMap::new();

    for aux_idx in &output_aux {
        aux_to_wire.insert(*aux_idx, next_wire);
        next_wire = checked_u32_add(next_wire, 1, "wire index overflow")?;
    }

    for input_idx in 1..num_inputs {
        input_to_wire.insert(input_idx, next_wire);
        next_wire = checked_u32_add(next_wire, 1, "wire index overflow")?;
    }

    let mut private_aux_count: u32 = 0;
    for aux_idx in 0..num_aux {
        if output_set.contains(&aux_idx) {
            continue;
        }
        aux_to_wire.insert(aux_idx, next_wire);
        next_wire = checked_u32_add(next_wire, 1, "wire index overflow")?;
        private_aux_count = checked_u32_add(private_aux_count, 1, "private aux overflow")?;
    }

    let constraints = shape_cs
        .constraints
        .iter()
        .map(|(a, b, c)| {
            Ok(PicusConstraint {
                a: linear_combination_to_terms(a, &input_to_wire, &aux_to_wire)?,
                b: linear_combination_to_terms(b, &input_to_wire, &aux_to_wire)?,
                c: linear_combination_to_terms(c, &input_to_wire, &aux_to_wire)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let fs_usize = FieldElement::ZERO.to_repr().as_ref().len();
    let fs = checked_u32(fs_usize, "field byte length exceeds u32")?;
    let prime_le = modulus_to_le_bytes(FieldElement::MODULUS, fs_usize)?;
    let n_wires = next_wire;
    let n_pub_out = checked_u32(output_aux.len(), "public output count exceeds u32")?;
    let n_pub_in = checked_u32(num_inputs - 1, "public input count exceeds u32")?;
    let n_labels = u64::from(n_wires);
    let wire_map = (0..n_wires).map(u64::from).collect();

    let mut aux_to_wire_vec = vec![None; num_aux];
    for (aux_idx, wire) in &aux_to_wire {
        aux_to_wire_vec[*aux_idx] = Some(*wire);
    }

    let mut input_to_wire_vec = vec![None; num_inputs];
    input_to_wire_vec[0] = Some(0);
    for (input_idx, wire) in &input_to_wire {
        if *input_idx < input_to_wire_vec.len() {
            input_to_wire_vec[*input_idx] = Some(*wire);
        }
    }

    let output_wires = output_aux
        .iter()
        .filter_map(|aux_idx| aux_to_wire_vec.get(*aux_idx).copied().flatten())
        .collect::<Vec<_>>();

    let layout = PicusLayout {
        fs,
        prime_le,
        n_wires,
        n_pub_out,
        n_pub_in,
        n_prvt_in: private_aux_count,
        n_labels,
        constraints,
        wire_map,
    };

    let wiring = PicusWiring {
        n_wires,
        output_wires,
        input_to_wire: input_to_wire_vec,
        aux_to_wire: aux_to_wire_vec,
    };

    Ok((layout, wiring))
}

// (tests live at end of file)

fn field_to_dec(value: &FieldElement) -> String {
    use num_bigint::{BigInt, Sign};
    BigInt::from_bytes_le(Sign::Plus, value.to_repr().as_ref()).to_string()
}

fn write_picus_precondition_fix_witness_except_outputs(
    sat_cs: &SatisfyingAssignment<E1>,
    wiring: &PicusWiring,
    path: &Path,
) -> Result<()> {
    use std::fmt::Write as _;

    let inputs = sat_cs.input_assignment();
    let aux = sat_cs.aux_assignment();

    let mut is_output_wire = vec![false; wiring.n_wires as usize];
    for w in &wiring.output_wires {
        if let Some(slot) = is_output_wire.get_mut(*w as usize) {
            *slot = true;
        }
    }

    // Build a JSON array of [tag, expr] pairs. We hand-roll numbers because serde_json
    // cannot represent field-sized integers as JSON numbers.
    let mut out = String::new();
    out.push('[');
    let mut first = true;

    // Fix constant wire 0 to 1 (Picus expects x0 to behave as constant one).
    {
        if !first {
            out.push(',');
        }
        first = false;
        let _ = write!(
            &mut out,
            "[\"wire_0_one\",[\"rassert\",[\"req\",[\"rvar\",0],[\"rint\",1]]]]"
        );
    }

    // Fix all non-output input wires.
    for (idx, wire_opt) in wiring.input_to_wire.iter().enumerate() {
        if idx == 0 {
            continue;
        }
        let Some(wire) = *wire_opt else {
            continue;
        };
        if wire as usize >= is_output_wire.len() || is_output_wire[wire as usize] {
            continue;
        }
        let Some(val) = inputs.get(idx) else {
            continue;
        };
        if !first {
            out.push(',');
        }
        first = false;
        let _ = write!(
            &mut out,
            "[\"wire_{wire}_input_{idx}\",[\"rassert\",[\"req\",[\"rvar\",{wire}],[\"rint\",{}]]]]",
            field_to_dec(val)
        );
    }

    // Fix all non-output aux wires.
    for (aux_idx, wire_opt) in wiring.aux_to_wire.iter().enumerate() {
        let Some(wire) = *wire_opt else {
            continue;
        };
        if wire as usize >= is_output_wire.len() || is_output_wire[wire as usize] {
            continue;
        }
        let Some(val) = aux.get(aux_idx) else {
            continue;
        };
        if !first {
            out.push(',');
        }
        first = false;
        let _ = write!(
            &mut out,
            "[\"wire_{wire}_aux_{aux_idx}\",[\"rassert\",[\"req\",[\"rvar\",{wire}],[\"rint\",{}]]]]",
            field_to_dec(val)
        );
    }

    out.push(']');
    fs::write(path, out).map_err(|e| io_err(format!("Failed to write {}", path.display()), e))
}

fn write_picus_precondition_fix_inputs_only(
    sat_cs: &SatisfyingAssignment<E1>,
    wiring: &PicusWiring,
    path: &Path,
) -> Result<()> {
    use std::fmt::Write as _;

    let inputs = sat_cs.input_assignment();

    let mut is_output_wire = vec![false; wiring.n_wires as usize];
    for w in &wiring.output_wires {
        if let Some(slot) = is_output_wire.get_mut(*w as usize) {
            *slot = true;
        }
    }

    let mut out = String::new();
    out.push('[');

    // Fix constant wire 0 to 1 (Picus expects x0 to behave as constant one).
    {
        let _ = write!(
            &mut out,
            "[\"wire_0_one\",[\"rassert\",[\"req\",[\"rvar\",0],[\"rint\",1]]]]"
        );
    }

    // Fix all non-output input wires (i.e., fix z to this fixture's instance).
    for (idx, wire_opt) in wiring.input_to_wire.iter().enumerate() {
        if idx == 0 {
            continue;
        }
        let Some(wire) = *wire_opt else {
            continue;
        };
        if wire as usize >= is_output_wire.len() || is_output_wire[wire as usize] {
            continue;
        }
        let Some(val) = inputs.get(idx) else {
            continue;
        };

        out.push(',');
        let _ = write!(
            &mut out,
            "[\"wire_{wire}_input_{idx}\",[\"rassert\",[\"req\",[\"rvar\",{wire}],[\"rint\",{}]]]]",
            field_to_dec(val)
        );
    }

    out.push(']');
    fs::write(path, out).map_err(|e| io_err(format!("Failed to write {}", path.display()), e))
}

fn write_picus_precondition_fix_inputs_plus_leafpath_only(
    sat_cs: &SatisfyingAssignment<E1>,
    wiring: &PicusWiring,
    aux_indices: &[usize],
    path: &Path,
) -> Result<()> {
    use std::fmt::Write as _;

    let inputs = sat_cs.input_assignment();
    let aux = sat_cs.aux_assignment();

    let mut is_output_wire = vec![false; wiring.n_wires as usize];
    for w in &wiring.output_wires {
        if let Some(slot) = is_output_wire.get_mut(*w as usize) {
            *slot = true;
        }
    }

    let mut fixed_wires = BTreeSet::<u32>::new();

    let mut out = String::new();
    out.push('[');
    let mut first = true;

    let mut push_wire_assert = |tag: &str, wire: u32, val_dec: String| {
        if wire as usize >= is_output_wire.len() || is_output_wire[wire as usize] {
            return;
        }
        if !fixed_wires.insert(wire) {
            return;
        }
        if !first {
            out.push(',');
        }
        first = false;
        let _ = write!(
            &mut out,
            "[\"{tag}\",[\"rassert\",[\"req\",[\"rvar\",{wire}],[\"rint\",{val_dec}]]]]"
        );
    };

    // Fix constant wire 0 to 1 (Picus expects x0 to behave as constant one).
    push_wire_assert("wire_0_one", 0, "1".to_string());

    // Fix all non-output input wires (i.e., fix z to this fixture's instance).
    for (idx, wire_opt) in wiring.input_to_wire.iter().enumerate() {
        if idx == 0 {
            continue;
        }
        let Some(wire) = *wire_opt else {
            continue;
        };
        let Some(val) = inputs.get(idx) else {
            continue;
        };
        push_wire_assert(&format!("wire_{wire}_input_{idx}"), wire, field_to_dec(val));
    }

    // Additionally fix the witness material that should define the transition.
    for aux_idx in aux_indices {
        let Some(wire) = wiring.aux_to_wire.get(*aux_idx).copied().flatten() else {
            continue;
        };
        let Some(val) = aux.get(*aux_idx) else {
            continue;
        };
        push_wire_assert(
            &format!("wire_{wire}_aux_{aux_idx}"),
            wire,
            field_to_dec(val),
        );
    }

    out.push(']');
    fs::write(path, out).map_err(|e| io_err(format!("Failed to write {}", path.display()), e))
}

fn collect_output_aux_indices(
    outputs: &[AllocatedNum<FieldElement>],
    num_aux: usize,
) -> Result<Vec<usize>> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();

    for value in outputs {
        match value.get_variable().get_unchecked() {
            Index::Aux(idx) => {
                if idx >= num_aux {
                    return Err(KontorPoRError::InvalidInput(format!(
                        "Output aux index {} out of bounds {}",
                        idx, num_aux
                    )));
                }
                if seen.insert(idx) {
                    out.push(idx);
                }
            }
            Index::Input(idx) => {
                return Err(KontorPoRError::InvalidInput(format!(
                    "Output variable unexpectedly mapped to input index {}",
                    idx
                )));
            }
        }
    }

    Ok(out)
}

fn linear_combination_to_terms(
    lc: &nova_snark::frontend::LinearCombination<FieldElement>,
    input_to_wire: &BTreeMap<usize, u32>,
    aux_to_wire: &BTreeMap<usize, u32>,
) -> Result<Vec<PicusTerm>> {
    let mut out = Vec::with_capacity(lc.len());

    for (input_idx, coeff) in lc.iter_inputs() {
        let wire = if *input_idx == 0 {
            0
        } else {
            input_to_wire.get(input_idx).copied().ok_or_else(|| {
                KontorPoRError::InvalidInput(format!(
                    "Missing wire mapping for input index {}",
                    input_idx
                ))
            })?
        };

        out.push(PicusTerm {
            wire,
            coeff: *coeff,
        });
    }

    for (aux_idx, coeff) in lc.iter_aux() {
        let wire = aux_to_wire.get(aux_idx).copied().ok_or_else(|| {
            KontorPoRError::InvalidInput(format!("Missing wire mapping for aux index {}", aux_idx))
        })?;

        out.push(PicusTerm {
            wire,
            coeff: *coeff,
        });
    }

    Ok(out)
}

fn encode_picus_r1cs(layout: &PicusLayout) -> Result<Vec<u8>> {
    let mut section_header = Vec::new();
    write_u32_le(&mut section_header, layout.fs);
    section_header.extend_from_slice(&layout.prime_le);
    write_u32_le(&mut section_header, layout.n_wires);
    write_u32_le(&mut section_header, layout.n_pub_out);
    write_u32_le(&mut section_header, layout.n_pub_in);
    write_u32_le(&mut section_header, layout.n_prvt_in);
    write_u64_le(&mut section_header, layout.n_labels);
    write_u32_le(
        &mut section_header,
        checked_u32(layout.constraints.len(), "constraint count exceeds u32")?,
    );

    let coeff_le = is_field_repr_little_endian()?;
    let fs_usize = usize::try_from(layout.fs).map_err(|_| {
        KontorPoRError::InvalidInput("field byte length conversion failed".to_string())
    })?;

    let mut section_constraints = Vec::new();
    for constraint in &layout.constraints {
        encode_lc_terms(&mut section_constraints, &constraint.a, fs_usize, coeff_le)?;
        encode_lc_terms(&mut section_constraints, &constraint.b, fs_usize, coeff_le)?;
        encode_lc_terms(&mut section_constraints, &constraint.c, fs_usize, coeff_le)?;
    }

    let mut section_map = Vec::new();
    for label in &layout.wire_map {
        write_u64_le(&mut section_map, *label);
    }

    let mut out = Vec::new();
    out.extend_from_slice(b"r1cs");
    write_u32_le(&mut out, 1);
    write_u32_le(&mut out, 3);

    write_u32_le(&mut out, 1);
    write_u64_le(
        &mut out,
        checked_u64(section_header.len(), "section size exceeds u64")?,
    );
    out.extend_from_slice(&section_header);

    write_u32_le(&mut out, 2);
    write_u64_le(
        &mut out,
        checked_u64(section_constraints.len(), "section size exceeds u64")?,
    );
    out.extend_from_slice(&section_constraints);

    write_u32_le(&mut out, 3);
    write_u64_le(
        &mut out,
        checked_u64(section_map.len(), "section size exceeds u64")?,
    );
    out.extend_from_slice(&section_map);

    Ok(out)
}

fn encode_lc_terms(
    out: &mut Vec<u8>,
    terms: &[PicusTerm],
    fs: usize,
    coeff_repr_le: bool,
) -> Result<()> {
    write_u32_le(
        out,
        checked_u32(terms.len(), "linear combination term count exceeds u32")?,
    );

    for term in terms {
        let mut coeff = term.coeff.to_repr().as_ref().to_vec();
        if coeff.len() != fs {
            return Err(KontorPoRError::Serialization(format!(
                "Field coefficient length mismatch: expected {}, got {}",
                fs,
                coeff.len()
            )));
        }

        if !coeff_repr_le {
            coeff.reverse();
        }

        write_u32_le(out, term.wire);
        out.extend_from_slice(&coeff);
    }

    Ok(())
}

fn is_field_repr_little_endian() -> Result<bool> {
    let one = FieldElement::ONE.to_repr();
    let bytes = one.as_ref();

    if bytes.first().copied() == Some(1) {
        return Ok(true);
    }
    if bytes.last().copied() == Some(1) {
        return Ok(false);
    }

    Err(KontorPoRError::Serialization(
        "Could not infer field representation endianness".to_string(),
    ))
}

fn modulus_to_le_bytes(modulus: &str, target_len: usize) -> Result<Vec<u8>> {
    let text = modulus.trim();
    let mut out = if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        hex_to_le_bytes(hex)?
    } else if text.chars().all(|c| c.is_ascii_digit()) {
        decimal_to_le_bytes(text)?
    } else {
        return Err(KontorPoRError::Serialization(format!(
            "Unsupported PrimeField::MODULUS format: {}",
            text
        )));
    };

    if out.len() > target_len {
        return Err(KontorPoRError::Serialization(format!(
            "Field modulus does not fit in {} bytes",
            target_len
        )));
    }

    out.resize(target_len, 0u8);
    Ok(out)
}

fn hex_to_le_bytes(hex: &str) -> Result<Vec<u8>> {
    let clean = hex.trim_start_matches('0');
    let normalized = if clean.is_empty() {
        String::from("00")
    } else if clean.len().is_multiple_of(2) {
        clean.to_string()
    } else {
        format!("0{}", clean)
    };

    let mut be = Vec::with_capacity(normalized.len() / 2);
    let bytes = normalized.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let chunk = std::str::from_utf8(&bytes[i..i + 2]).map_err(|e| {
            KontorPoRError::Serialization(format!("Invalid hex modulus bytes: {}", e))
        })?;
        let value = u8::from_str_radix(chunk, 16).map_err(|e| {
            KontorPoRError::Serialization(format!("Invalid hex modulus byte '{}': {}", chunk, e))
        })?;
        be.push(value);
    }

    be.reverse();
    Ok(be)
}

fn decimal_to_le_bytes(decimal: &str) -> Result<Vec<u8>> {
    if decimal == "0" {
        return Ok(vec![0u8]);
    }

    let mut digits = decimal
        .bytes()
        .map(|b| b.wrapping_sub(b'0'))
        .collect::<Vec<u8>>();
    let mut out = Vec::new();

    while !(digits.is_empty() || (digits.len() == 1 && digits[0] == 0)) {
        let mut remainder: u16 = 0;
        let mut quotient = Vec::with_capacity(digits.len());

        for digit in &digits {
            if *digit > 9 {
                return Err(KontorPoRError::Serialization(format!(
                    "Invalid decimal modulus digit '{}'",
                    *digit
                )));
            }
            let value = remainder * 10 + u16::from(*digit);
            let q = (value / 256) as u8;
            remainder = value % 256;
            if !quotient.is_empty() || q != 0 {
                quotient.push(q);
            }
        }

        out.push(remainder as u8);
        digits = if quotient.is_empty() {
            vec![0]
        } else {
            quotient
        };
    }

    Ok(out)
}

fn write_u32_le(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u64_le(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn checked_u32(value: usize, context: &str) -> Result<u32> {
    u32::try_from(value)
        .map_err(|_| KontorPoRError::InvalidInput(format!("{}: {}", context, value)))
}

fn checked_u64(value: usize, context: &str) -> Result<u64> {
    u64::try_from(value)
        .map_err(|_| KontorPoRError::InvalidInput(format!("{}: {}", context, value)))
}

fn checked_u32_add(lhs: u32, rhs: u32, context: &str) -> Result<u32> {
    lhs.checked_add(rhs)
        .ok_or_else(|| KontorPoRError::InvalidInput(context.to_string()))
}

fn validate_fixture(fixture: &FormalFixture) -> Result<()> {
    if fixture.fixture_id.trim().is_empty() {
        return Err(KontorPoRError::InvalidInput(
            "fixture_id must not be empty".to_string(),
        ));
    }

    if fixture.challenge_count == 0 {
        return Err(KontorPoRError::InvalidChallengeCount { count: 0 });
    }

    if fixture.file_specs.is_empty() {
        return Err(KontorPoRError::InvalidInput(format!(
            "Fixture {} has no file_specs",
            fixture.fixture_id
        )));
    }

    for (i, spec) in fixture.file_specs.iter().enumerate() {
        if spec.size == 0 {
            return Err(KontorPoRError::InvalidInput(format!(
                "Fixture {} has file_specs[{}].size = 0",
                fixture.fixture_id, i
            )));
        }

        if fixture.scenario_kind == ScenarioKind::TinyMerkle {
            let Some(padded_len) = spec.toy_padded_len else {
                return Err(KontorPoRError::InvalidInput(format!(
                    "Fixture {} (tiny_merkle) missing file_specs[{}].toy_padded_len",
                    fixture.fixture_id, i
                )));
            };
            if !padded_len.is_power_of_two() || padded_len == 0 {
                return Err(KontorPoRError::InvalidInput(format!(
                    "Fixture {} (tiny_merkle) file_specs[{}].toy_padded_len must be a power-of-two > 0, got {}",
                    fixture.fixture_id, i, padded_len
                )));
            }
            // Keep toy fixtures small on purpose.
            if padded_len > 16 {
                return Err(KontorPoRError::InvalidInput(format!(
                    "Fixture {} (tiny_merkle) file_specs[{}].toy_padded_len too large (>{}) for toy mode, got {}",
                    fixture.fixture_id, i, 16, padded_len
                )));
            }
            let expected_size = padded_len
                .checked_mul(crate::config::CHUNK_SIZE_BYTES)
                .ok_or_else(|| {
                    KontorPoRError::InvalidInput("toy file size overflow".to_string())
                })?;
            if spec.size != expected_size {
                return Err(KontorPoRError::InvalidInput(format!(
                    "Fixture {} (tiny_merkle) file_specs[{}].size must equal toy_padded_len*CHUNK_SIZE_BYTES ({}), got {}",
                    fixture.fixture_id, i, expected_size, spec.size
                )));
            }
        }
    }

    Ok(())
}

fn build_fixture_scenario(fixture: &FormalFixture) -> Result<FixtureScenario> {
    let mut files = BTreeMap::new();
    let mut metadatas = Vec::with_capacity(fixture.file_specs.len());
    let mut ledger = FileLedger::new();

    for (idx, spec) in fixture.file_specs.iter().enumerate() {
        let file_seed = spec
            .seed
            .unwrap_or(fixture.seed.wrapping_add((idx as u64).wrapping_mul(9973)));

        let nonce = deterministic_nonce(&fixture.fixture_id, idx, file_seed);
        let filename = format!("{}_file_{}.dat", fixture.fixture_id, idx);

        let (prepared, metadata) = if fixture.scenario_kind == ScenarioKind::TinyMerkle {
            let padded_len = spec.toy_padded_len.unwrap_or(0);
            prepare_toy_file(padded_len, &filename, &nonce, file_seed)?
        } else {
            let mut rng = StdRng::seed_from_u64(file_seed);
            let mut data = vec![0u8; spec.size];
            rng.fill_bytes(&mut data);
            prepare_file(&data, &filename, &nonce)?
        };

        ledger.add_file(&metadata)?;
        files.insert(metadata.file_id.clone(), prepared);
        metadatas.push(metadata);
    }

    let mut challenges = Vec::with_capacity(metadatas.len());
    for (idx, metadata) in metadatas.into_iter().enumerate() {
        let seed_value = if fixture.distinct_seeds {
            fixture.seed.wrapping_add(idx as u64)
        } else {
            fixture.seed
        };

        challenges.push(Challenge::new(
            metadata,
            fixture.block_height,
            fixture.challenge_count,
            FieldElement::from(seed_value),
            fixture.prover_id.clone(),
        ));
    }

    Ok(FixtureScenario {
        files,
        challenges,
        ledger,
    })
}

fn prepare_toy_file(
    padded_len: usize,
    filename: &str,
    nonce: &[u8],
    seed: u64,
) -> Result<(PreparedFile, crate::FileMetadata)> {
    use crate::merkle::build_tree;
    use crate::FileMetadata;

    let mut rng = StdRng::seed_from_u64(seed);

    let mut data_chunks: Vec<Vec<u8>> = Vec::with_capacity(padded_len);
    let mut data = Vec::with_capacity(padded_len * crate::config::CHUNK_SIZE_BYTES);
    for _ in 0..padded_len {
        let mut chunk = vec![0u8; crate::config::CHUNK_SIZE_BYTES];
        rng.fill_bytes(&mut chunk);
        data.extend_from_slice(&chunk);
        data_chunks.push(chunk);
    }

    let mut object_hasher = Sha256::new();
    object_hasher.update(&data);
    let object_id = format!("obj_{:x}", object_hasher.finalize());

    let mut file_hasher = Sha256::new();
    file_hasher.update(&data);
    file_hasher.update(nonce);
    let file_id = format!("file_{:x}", file_hasher.finalize());

    let (tree, root) = build_tree(&data_chunks)?;

    let metadata = FileMetadata {
        root,
        object_id,
        file_id: file_id.clone(),
        nonce: nonce.to_vec(),
        padded_len,
        original_size: data.len(),
        filename: filename.to_string(),
    };

    let prepared_file = PreparedFile {
        tree,
        file_id,
        root,
    };
    Ok((prepared_file, metadata))
}

fn derive_plan(challenges: &[Challenge], ledger: &FileLedger) -> Result<DerivedPlan> {
    if challenges.is_empty() {
        return Err(KontorPoRError::InvalidInput(
            "Cannot derive plan for empty challenge set".to_string(),
        ));
    }

    let aggregated_root = if challenges.len() > 1 {
        ledger.tree.root()
    } else {
        challenges[0].file_metadata.root
    };

    let max_file_depth = challenges
        .iter()
        .map(|c| tree_depth_from_metadata(&c.file_metadata))
        .max()
        .unwrap_or(0);

    let (files_per_step, file_tree_depth) = config::derive_shape(challenges.len(), max_file_depth);
    let aggregated_tree_depth = if files_per_step > 1 {
        ledger.tree.layers.len() - 1
    } else {
        0
    };

    let mut sorted_challenges = challenges.to_vec();
    sorted_challenges.sort_by(|a, b| {
        a.file_metadata
            .file_id
            .cmp(&b.file_metadata.file_id)
            .then_with(|| a.id().0.cmp(&b.id().0))
    });
    let initial_state = derive_initial_state(&sorted_challenges);

    let mut ledger_indices = vec![0usize; files_per_step];
    let mut depths = vec![0usize; files_per_step];
    let mut seeds = vec![FieldElement::ZERO; files_per_step];
    let mut expected_rcs = vec![FieldElement::ZERO; files_per_step];

    for (i, challenge) in sorted_challenges.iter().enumerate() {
        let file_depth = tree_depth_from_metadata(&challenge.file_metadata);
        let rc = calculate_root_commitment(
            challenge.file_metadata.root,
            FieldElement::from(file_depth as u64),
        );
        expected_rcs[i] = rc;

        let ledger_idx = ledger.get_canonical_index_for_rc(rc).ok_or_else(|| {
            KontorPoRError::FileNotInLedger {
                file_id: challenge.file_metadata.file_id.clone(),
            }
        })?;

        ledger_indices[i] = ledger_idx;
        depths[i] = file_depth;
        seeds[i] = challenge.seed;
    }

    let public_io_layout = PublicIOLayout::new(files_per_step);

    Ok(DerivedPlan {
        files_per_step,
        file_tree_depth,
        aggregated_tree_depth,
        aggregated_root,
        initial_state,
        sorted_challenges,
        ledger_indices,
        depths,
        seeds,
        expected_rcs,
        public_io_layout,
    })
}

fn derive_initial_state(sorted_challenges: &[Challenge]) -> FieldElement {
    const DOMAIN_V1: &[u8] = b"kontor.challenge_set.initial_state.v1";
    const DOMAIN_V1_EXPAND: &[u8] = b"kontor.challenge_set.initial_state.v1.expand";

    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_V1);
    let count = u64::try_from(sorted_challenges.len()).unwrap_or(u64::MAX);
    hasher.update(count.to_le_bytes());
    for challenge in sorted_challenges {
        hasher.update(challenge.id().0);
    }
    let digest_a = hasher.finalize();

    let mut expander = Sha256::new();
    expander.update(DOMAIN_V1_EXPAND);
    expander.update(digest_a);
    let digest_b = expander.finalize();

    let mut uniform_bytes = [0u8; 64];
    uniform_bytes[..32].copy_from_slice(&digest_a);
    uniform_bytes[32..].copy_from_slice(&digest_b);

    crate::utils::field_from_uniform_bytes(&uniform_bytes)
}

fn alloc_z_inputs<CS: ConstraintSystem<F1>>(
    cs: &mut CS,
    z: &[FieldElement],
) -> std::result::Result<Vec<AllocatedNum<FieldElement>>, SynthesisError> {
    z.iter()
        .enumerate()
        .map(|(i, value)| {
            AllocatedNum::alloc_input(cs.namespace(|| format!("z_{i}")), || Ok(*value))
        })
        .collect()
}

fn write_bincode_file<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let options = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .reject_trailing_bytes();

    let bytes = options.serialize(value).map_err(|e| {
        KontorPoRError::Serialization(format!("Failed to encode {}: {}", path.display(), e))
    })?;

    fs::write(path, bytes).map_err(|e| io_err(format!("Failed to write {}", path.display()), e))
}

fn write_json_file<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let data = serde_json::to_string_pretty(value).map_err(|e| {
        KontorPoRError::Serialization(format!("Failed to encode {}: {}", path.display(), e))
    })?;

    fs::write(path, data).map_err(|e| io_err(format!("Failed to write {}", path.display()), e))
}

fn sha256_file(path: &Path) -> Result<String> {
    let bytes =
        fs::read(path).map_err(|e| io_err(format!("Failed to read {}", path.display()), e))?;
    let digest = Sha256::digest(&bytes);
    Ok(bytes_to_hex(&digest))
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{:02x}", b);
    }
    out
}

fn field_to_hex(value: &FieldElement) -> String {
    bytes_to_hex(value.to_repr().as_ref())
}

fn deterministic_nonce(fixture_id: &str, index: usize, seed: u64) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(fixture_id.as_bytes());
    hasher.update((index as u64).to_le_bytes());
    hasher.update(seed.to_le_bytes());
    hasher.finalize()[..16].to_vec()
}

fn io_err(context: String, err: std::io::Error) -> KontorPoRError {
    KontorPoRError::IO(format!("{}: {}", context, err))
}

fn circuit_err(err: SynthesisError) -> KontorPoRError {
    KontorPoRError::Circuit(format!("Circuit synthesis failed: {err:?}"))
}

fn snark_err<E: std::fmt::Debug>(err: E) -> KontorPoRError {
    KontorPoRError::Snark(format!("Nova R1CS extraction failed: {err:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn output_wire_is_referenced(layout: &PicusLayout, wire: u32) -> bool {
        for c in &layout.constraints {
            for t in c.a.iter().chain(c.b.iter()).chain(c.c.iter()) {
                if t.wire == wire {
                    return true;
                }
            }
        }
        false
    }

    fn sample_fixture() -> FormalFixture {
        FormalFixture {
            fixture_id: String::from("sample"),
            description: String::from("sample fixture"),
            scenario_kind: ScenarioKind::SingleFile,
            circuit_kind: CircuitKind::Full,
            challenge_count: 1,
            seed: 1,
            block_height: 1,
            prover_id: String::from("p"),
            distinct_seeds: true,
            file_specs: vec![FormalFileSpec {
                size: 64,
                seed: Some(9),
                toy_padded_len: None,
            }],
            expected_shape: None,
            expected_num_constraints: None,
            tags: vec![],
            expected_result: ExpectedPicusResult::Safe,
            verification: FormalVerificationPolicy::default(),
        }
    }

    #[test]
    fn deterministic_nonce_is_stable() {
        let n1 = deterministic_nonce("fixture-a", 0, 123);
        let n2 = deterministic_nonce("fixture-a", 0, 123);
        let n3 = deterministic_nonce("fixture-a", 1, 123);

        assert_eq!(n1, n2);
        assert_ne!(n1, n3);
        assert_eq!(n1.len(), 16);
    }

    #[test]
    fn validate_fixture_rejects_empty_id() {
        let mut fixture = sample_fixture();
        fixture.fixture_id.clear();
        let err = validate_fixture(&fixture).expect_err("fixture should fail");
        assert!(format!("{err}").contains("fixture_id"));
    }

    #[test]
    fn validate_fixture_rejects_zero_file_size() {
        let mut fixture = sample_fixture();
        fixture.file_specs[0].size = 0;
        let err = validate_fixture(&fixture).expect_err("fixture should fail");
        assert!(format!("{err}").contains("size"));
    }

    #[test]
    fn decimal_to_le_bytes_converts_correctly() {
        let bytes = decimal_to_le_bytes("65537").expect("decimal conversion should succeed");
        assert_eq!(bytes, vec![1, 0, 1]);
    }

    #[test]
    fn hex_to_le_bytes_handles_odd_digits() {
        let bytes = hex_to_le_bytes("abc").expect("hex conversion should succeed");
        assert_eq!(bytes, vec![0xbc, 0x0a]);
    }

    #[test]
    fn writer_emits_r1cs_magic_header() {
        let mut cs: ShapeCS<E1> = ShapeCS::new();
        let x = AllocatedNum::alloc_input(cs.namespace(|| "x"), || Ok(FieldElement::from(3u64)))
            .expect("x alloc");
        let y = AllocatedNum::alloc(cs.namespace(|| "y"), || Ok(FieldElement::from(3u64)))
            .expect("y alloc");

        cs.enforce(
            || "y=x",
            |lc| lc + x.get_variable(),
            |lc| lc + ShapeCS::<E1>::one(),
            |lc| lc + y.get_variable(),
        );

        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("picus-r1cs-test-{}.r1cs", stamp));

        write_picus_r1cs_file(&cs, &[y], &path).expect("writer should succeed");
        let bytes = fs::read(&path).expect("read r1cs file");
        let _ = fs::remove_file(&path);

        assert!(bytes.len() > 16);
        assert_eq!(&bytes[..4], b"r1cs");
        assert_eq!(
            u32::from_le_bytes(bytes[4..8].try_into().expect("version")),
            1
        );
        assert_eq!(
            u32::from_le_bytes(bytes[8..12].try_into().expect("sections")),
            3
        );
    }

    #[test]
    fn production_prefix_outputs_are_constrained() {
        // Regression guard: if a step output is allocated as a fresh wire but never tied
        // back to its intended value, it will not appear in any constraint and Picus
        // can (correctly) report an underconstraint.
        // Path from crate dir (crates/kontor-crypto) to workspace root then tools/picus/fixtures
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let fixtures_dir = manifest_dir.join("../../tools/picus/fixtures");
        let fixture = load_fixture(&fixtures_dir, "single-file-minimal").expect("fixture loads");

        let scenario = build_fixture_scenario(&fixture).expect("scenario builds");
        let plan = derive_plan(&scenario.challenges, &scenario.ledger).expect("plan derives");

        let sorted_challenge_refs: Vec<&Challenge> = plan.sorted_challenges.iter().collect();
        let file_refs: BTreeMap<String, &PreparedFile> =
            scenario.files.iter().map(|(k, v)| (k.clone(), v)).collect();

        let (circuit_witness, _) = crate::api::generate_circuit_witness(
            &sorted_challenge_refs,
            Some(&file_refs),
            &scenario.ledger,
            plan.file_tree_depth,
            plan.file_tree_depth,
            plan.initial_state,
            plan.aggregated_tree_depth,
            0,
            &plan.ledger_indices,
        )
        .expect("witness builds");

        let witnesses_vec = circuit_witness.witnesses().to_vec();

        let z0_primary = plan.public_io_layout.build_z0_primary(
            plan.aggregated_root,
            plan.initial_state,
            &plan.ledger_indices,
            &plan.depths,
            &plan.seeds,
            &plan.expected_rcs,
        );

        let mut shape_cs: ShapeCS<E1> = ShapeCS::new();
        let z_shape = alloc_z_inputs(&mut shape_cs, &z0_primary).expect("alloc z");

        let circuit = PorCircuit::<FieldElement>::new(
            plan.files_per_step,
            plan.file_tree_depth,
            plan.aggregated_tree_depth,
            Some(witnesses_vec),
        );

        let z_next_shape = circuit
            .synthesize(&mut shape_cs, &z_shape)
            .expect("synthesize");

        assert!(
            !z_next_shape.is_empty(),
            "PorCircuit produced no outputs; unexpected arity/layout change?"
        );

        // Root-only target: this was previously at risk of being an unconstrained carry-forward.
        let (layout, wiring) =
            build_picus_layout(&shape_cs, &z_next_shape[..1]).expect("picus layout");
        let out_wire = wiring.output_wires[0];
        assert!(
            output_wire_is_referenced(&layout, out_wire),
            "Picus output wire {} is not referenced by any constraint (likely unconstrained output regression)",
            out_wire
        );
    }
}
