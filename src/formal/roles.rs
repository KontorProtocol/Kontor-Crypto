use serde::{Deserialize, Serialize};

/// Semantic role for a wire used by component contracts and scoped preconditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireRole {
    PublicInput,
    WitnessLeaf,
    WitnessFileSibling,
    WitnessAggSibling,
    PathBit,
    GateBit,
    Intermediate,
    PublicOutput,
}
