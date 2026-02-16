use crate::{KontorPoRError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use super::roles::WireRole;
use super::{CircuitKind, FormalFixture};

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
    }

    for fixture in fixtures {
        if !fixture.circuit_kind.is_component() {
            return Err(KontorPoRError::InvalidInput(format!(
                "Fixture {} has non-component circuit kind {:?}; component manifests must be component-only",
                fixture.fixture_id, fixture.circuit_kind
            )));
        }

        let Some(contract) = by_kind.get(&fixture.circuit_kind) else {
            return Err(KontorPoRError::InvalidInput(format!(
                "Missing component contract for {:?} (fixture {})",
                fixture.circuit_kind, fixture.fixture_id
            )));
        };

        if contract.required_input_roles.is_empty() {
            return Err(KontorPoRError::InvalidInput(format!(
                "Contract for {:?} has empty required_input_roles",
                fixture.circuit_kind
            )));
        }
        if contract.produced_output_roles.is_empty() {
            return Err(KontorPoRError::InvalidInput(format!(
                "Contract for {:?} has empty produced_output_roles",
                fixture.circuit_kind
            )));
        }
    }

    Ok(())
}
