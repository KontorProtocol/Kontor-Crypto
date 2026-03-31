use crate::{KontorPoRError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use super::roles::WireRole;
use super::{CircuitKind, ExpectedPicusResult, FormalFixture};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentContractFile {
    pub version: u32,
    pub contracts: Vec<ComponentContract>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentContract {
    pub component: CircuitKind,
    #[serde(default)]
    pub required_input_roles: Vec<WireRole>,
    #[serde(default)]
    pub produced_output_roles: Vec<WireRole>,
    #[serde(default)]
    pub forbidden_output_roles: Vec<WireRole>,
    #[serde(default)]
    pub determinism_targets: Vec<String>,
    #[serde(default)]
    pub consumes_from: Vec<CircuitKind>,
    #[serde(default)]
    pub notes: String,
}

pub fn load_component_contracts(path: &Path) -> Result<ComponentContractFile> {
    let raw = fs::read_to_string(path).map_err(|e| {
        KontorPoRError::IO(format!(
            "Failed to read component contracts {}: {}",
            path.display(),
            e
        ))
    })?;

    serde_json::from_str(&raw).map_err(|e| {
        KontorPoRError::Serialization(format!(
            "Failed to parse component contracts {}: {}",
            path.display(),
            e
        ))
    })
}

pub fn validate_component_contracts(
    fixtures: &[FormalFixture],
    contracts: &ComponentContractFile,
) -> Result<()> {
    let mut by_kind = BTreeMap::<CircuitKind, &ComponentContract>::new();
    for c in &contracts.contracts {
        if !c.component.is_component() {
            return Err(KontorPoRError::InvalidInput(format!(
                "Contract entry {:?} is not a component circuit kind",
                c.component
            )));
        }
        if by_kind.insert(c.component.clone(), c).is_some() {
            return Err(KontorPoRError::InvalidInput(format!(
                "Duplicate contract for component {:?}",
                c.component
            )));
        }

        if c.required_input_roles.is_empty() {
            return Err(KontorPoRError::InvalidInput(format!(
                "Contract for {:?} has empty required_input_roles",
                c.component
            )));
        }
        if c.produced_output_roles.is_empty() {
            return Err(KontorPoRError::InvalidInput(format!(
                "Contract for {:?} has empty produced_output_roles",
                c.component
            )));
        }
        if c.determinism_targets.is_empty() {
            return Err(KontorPoRError::InvalidInput(format!(
                "Contract for {:?} has empty determinism_targets",
                c.component
            )));
        }

        for forbidden in &c.forbidden_output_roles {
            if c.produced_output_roles.contains(forbidden) {
                return Err(KontorPoRError::InvalidInput(format!(
                    "Contract for {:?} both produces and forbids {:?}",
                    c.component, forbidden
                )));
            }
        }
        for dep in &c.consumes_from {
            if !dep.is_component() {
                return Err(KontorPoRError::InvalidInput(format!(
                    "Contract for {:?} has non-component dependency {:?}",
                    c.component, dep
                )));
            }
        }
    }

    let required_components = [
        CircuitKind::ComponentChallengeDerivation,
        CircuitKind::ComponentChallengeDerivationMutant,
        CircuitKind::ComponentFileMerkle,
        CircuitKind::ComponentFileMerkleMutant,
        CircuitKind::ComponentAggregationMerkle,
        CircuitKind::ComponentAggregationMerkleMutant,
        CircuitKind::ComponentStateUpdate,
        CircuitKind::ComponentStateUpdateMutant,
        CircuitKind::ComponentCarryForward,
        CircuitKind::ComponentCarryForwardMutant,
    ];
    for kind in required_components {
        if !by_kind.contains_key(&kind) {
            return Err(KontorPoRError::InvalidInput(format!(
                "Missing component contract for {:?}",
                kind
            )));
        }
    }

    // Validate composition boundaries: every declared dependency edge must share at least one
    // semantic role between producer outputs and consumer required inputs.
    for consumer in &contracts.contracts {
        for producer_kind in &consumer.consumes_from {
            let Some(producer) = by_kind.get(producer_kind) else {
                return Err(KontorPoRError::InvalidInput(format!(
                    "Contract for {:?} depends on missing producer {:?}",
                    consumer.component, producer_kind
                )));
            };
            let shared_roles = consumer
                .required_input_roles
                .iter()
                .copied()
                .filter(|role| producer.produced_output_roles.contains(role))
                .collect::<Vec<_>>();
            if shared_roles.is_empty() {
                return Err(KontorPoRError::InvalidInput(format!(
                    "Contract role mismatch: consumer {:?} depends on {:?} but has no shared roles (consumer required: {:?}, producer outputs: {:?})",
                    consumer.component,
                    producer_kind,
                    consumer.required_input_roles,
                    producer.produced_output_roles
                )));
            }
        }
    }

    for fixture in fixtures {
        if !fixture.circuit_kind.is_component() {
            return Err(KontorPoRError::InvalidInput(format!(
                "Fixture {} has non-component circuit kind {:?}; component manifests must be component-only",
                fixture.fixture_id, fixture.circuit_kind
            )));
        }

        let Some(_contract) = by_kind.get(&fixture.circuit_kind) else {
            return Err(KontorPoRError::InvalidInput(format!(
                "Missing component contract for {:?} (fixture {})",
                fixture.circuit_kind, fixture.fixture_id
            )));
        };

        if fixture.circuit_kind.is_mutant()
            && fixture.expected_result != ExpectedPicusResult::Unsafe
        {
            return Err(KontorPoRError::InvalidInput(format!(
                "Mutant fixture {} must set expected_result=unsafe",
                fixture.fixture_id
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formal::{FormalFileSpec, FormalVerificationPolicy, ScenarioKind};

    fn component_kinds() -> Vec<CircuitKind> {
        vec![
            CircuitKind::ComponentChallengeDerivation,
            CircuitKind::ComponentChallengeDerivationMutant,
            CircuitKind::ComponentFileMerkle,
            CircuitKind::ComponentFileMerkleMutant,
            CircuitKind::ComponentAggregationMerkle,
            CircuitKind::ComponentAggregationMerkleMutant,
            CircuitKind::ComponentStateUpdate,
            CircuitKind::ComponentStateUpdateMutant,
            CircuitKind::ComponentCarryForward,
            CircuitKind::ComponentCarryForwardMutant,
        ]
    }

    fn contract_for(kind: CircuitKind) -> ComponentContract {
        ComponentContract {
            component: kind,
            required_input_roles: vec![WireRole::PublicInput],
            produced_output_roles: vec![WireRole::PublicOutput],
            forbidden_output_roles: vec![WireRole::WitnessLeaf],
            determinism_targets: vec!["out".to_string()],
            consumes_from: vec![],
            notes: String::new(),
        }
    }

    fn full_contracts() -> ComponentContractFile {
        ComponentContractFile {
            version: 1,
            contracts: component_kinds().into_iter().map(contract_for).collect(),
        }
    }

    fn fixture_for(
        id: &str,
        kind: CircuitKind,
        expected_result: ExpectedPicusResult,
    ) -> FormalFixture {
        FormalFixture {
            fixture_id: id.to_string(),
            description: "test".to_string(),
            scenario_kind: ScenarioKind::SingleFile,
            circuit_kind: kind,
            challenge_count: 1,
            seed: 1,
            block_height: 1,
            prover_id: "p".to_string(),
            distinct_seeds: false,
            file_specs: vec![FormalFileSpec {
                size: 31,
                seed: Some(7),
                toy_padded_len: None,
            }],
            expected_shape: None,
            expected_num_constraints: None,
            tags: vec![],
            expected_result,
            verification: FormalVerificationPolicy::default(),
        }
    }

    #[test]
    fn validate_rejects_mutant_fixture_without_unsafe_expectation() {
        let fixtures = vec![fixture_for(
            "bad-mutant",
            CircuitKind::ComponentChallengeDerivationMutant,
            ExpectedPicusResult::Safe,
        )];
        let err = validate_component_contracts(&fixtures, &full_contracts())
            .expect_err("mutant fixture should require expected_result=unsafe");
        assert!(err.to_string().contains("expected_result=unsafe"));
    }

    #[test]
    fn validate_accepts_safe_and_mutant_fixtures_with_complete_contracts() {
        let fixtures = vec![
            fixture_for(
                "good-safe",
                CircuitKind::ComponentChallengeDerivation,
                ExpectedPicusResult::Safe,
            ),
            fixture_for(
                "good-mutant",
                CircuitKind::ComponentCarryForwardMutant,
                ExpectedPicusResult::Unsafe,
            ),
        ];
        validate_component_contracts(&fixtures, &full_contracts())
            .expect("fixtures should validate with complete contracts");
    }

    #[test]
    fn validate_rejects_conflicting_output_roles() {
        let mut contracts = full_contracts();
        contracts.contracts[0]
            .forbidden_output_roles
            .push(WireRole::PublicOutput);
        let fixtures = vec![fixture_for(
            "fixture",
            CircuitKind::ComponentChallengeDerivation,
            ExpectedPicusResult::Safe,
        )];
        let err = validate_component_contracts(&fixtures, &contracts)
            .expect_err("contract should fail when produced and forbidden overlap");
        assert!(err.to_string().contains("both produces and forbids"));
    }

    #[test]
    fn validate_rejects_consumes_from_without_role_overlap() {
        let mut contracts = full_contracts();
        contracts.contracts[1].consumes_from = vec![contracts.contracts[0].component.clone()];
        contracts.contracts[1].required_input_roles = vec![WireRole::WitnessLeaf];

        let fixtures = vec![fixture_for(
            "fixture",
            CircuitKind::ComponentChallengeDerivationMutant,
            ExpectedPicusResult::Unsafe,
        )];
        let err = validate_component_contracts(&fixtures, &contracts)
            .expect_err("contract should fail when dependency roles do not overlap");
        assert!(err.to_string().contains("no shared roles"));
    }
}
