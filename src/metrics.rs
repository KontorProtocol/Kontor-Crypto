//! Performance metrics and structured output for benchmarking and production monitoring.
//!
//! This module provides shared metric types used by both the simulator and benchmark suite,
//! with CLI-friendly display formatters for human-readable output.

use std::time::Duration;

#[cfg(feature = "memory-profiling")]
use peak_alloc::PeakAlloc;

#[cfg(feature = "memory-profiling")]
#[global_allocator]
static PEAK_ALLOC: PeakAlloc = PeakAlloc;

/// Get current peak memory usage in MB (requires memory-profiling feature)
#[cfg(feature = "memory-profiling")]
pub fn get_peak_memory_mb() -> usize {
    PEAK_ALLOC.peak_usage_as_mb() as usize
}

/// Get current peak memory usage in MB (no-op without memory-profiling feature)
#[cfg(not(feature = "memory-profiling"))]
pub fn get_peak_memory_mb() -> usize {
    0
}

/// Reset peak memory tracking (requires memory-profiling feature)
#[cfg(feature = "memory-profiling")]
pub fn reset_peak_memory() {
    PEAK_ALLOC.reset_peak_usage();
}

/// Reset peak memory tracking (no-op without memory-profiling feature)
#[cfg(not(feature = "memory-profiling"))]
pub fn reset_peak_memory() {
    // No-op
}

/// Metrics collected during proof generation
#[derive(Debug, Clone)]
pub struct ProofMetrics {
    pub total_duration: Duration,
    pub param_gen_duration: Duration,
    pub witness_gen_duration: Duration,
    pub proving_duration: Duration,
    pub compression_duration: Duration,
    pub proof_size_bytes: usize,
    pub num_files: usize,
    pub num_challenges_per_file: usize,
    pub total_steps: usize,
    pub aggregated_tree_depth: usize,
    pub max_file_tree_depth: usize,
    pub memory_peak_mb: Option<usize>,
    pub files_per_step: usize,
    pub param_cache_hit: bool,
    pub param_gen_memory_mb: Option<usize>,
    pub proving_memory_mb: Option<usize>,
}

impl ProofMetrics {
    /// Format metrics as a table for CLI output
    pub fn format_table(&self) -> String {
        let mut output = String::new();
        output.push_str("  ┌─────────────────────────────────────────────────────┐\n");
        output.push_str("  │ Component              │ Duration  │ Memory Usage   │\n");
        output.push_str("  ├────────────────────────┼───────────┼────────────────┤\n");
        
        let param_label = if self.param_cache_hit {
            "Parameter Load (cached)"
        } else {
            "Parameter Generation  "
        };
        
        let param_memory = if let Some(mb) = self.param_gen_memory_mb {
            format!("{} MB", mb)
        } else {
            "N/A".to_string()
        };
        
        output.push_str(&format!(
            "  │ {} │ {:>7.1}s │ {:>14} │\n",
            param_label,
            self.param_gen_duration.as_secs_f64(),
            param_memory
        ));
        
        let proving_memory = if let Some(mb) = self.proving_memory_mb {
            format!("{} MB", mb)
        } else {
            "".to_string()
        };
        
        output.push_str(&format!(
            "  │ Proof Generation       │ {:>7.1}s │ {:>14} │\n",
            self.proving_duration.as_secs_f64(),
            proving_memory
        ));
        
        output.push_str("  ├────────────────────────┼───────────┼────────────────┤\n");
        
        let peak_memory = if let Some(mb) = self.memory_peak_mb {
            format!("{} MB", mb)
        } else {
            "N/A".to_string()
        };
        
        output.push_str(&format!(
            "  │ Total                  │ {:>7.1}s │ {:>9} (peak) │\n",
            self.total_duration.as_secs_f64(),
            peak_memory
        ));
        
        output.push_str("  └─────────────────────────────────────────────────────┘\n");
        output
    }

    /// Get proof size in KB
    pub fn proof_size_kb(&self) -> f64 {
        self.proof_size_bytes as f64 / 1024.0
    }
    
    /// Calculate circuit cost (C_IVC = 100 × depth from protocol spec)
    pub fn circuit_cost(&self) -> usize {
        use crate::config::CIRCUIT_COST_PER_DEPTH;
        CIRCUIT_COST_PER_DEPTH * self.max_file_tree_depth
    }
}

/// Metrics collected during verification
#[derive(Debug, Clone)]
pub struct VerificationMetrics {
    pub duration: Duration,
    pub num_files: usize,
    pub num_challenges_per_file: usize,
}

impl VerificationMetrics {
    /// Format as human-readable string
    pub fn format(&self) -> String {
        format!(
            "Verified {} file challenges ({} symbols each) in {:.0}ms",
            self.num_files,
            self.num_challenges_per_file,
            self.duration.as_secs_f64() * 1000.0
        )
    }
}

/// Metrics for analyzing multi-file aggregation benefits
#[derive(Debug, Clone)]
pub struct AggregationMetrics {
    pub single_file_proof_size: usize,
    pub aggregated_proof_size: usize,
    pub aggregation_factor: usize,
    pub savings_bytes: usize,
    pub savings_percent: f64,
}

impl AggregationMetrics {
    /// Calculate metrics from proof sizes
    pub fn new(single_proof_size: usize, aggregated_size: usize, num_files: usize) -> Self {
        let hypothetical_total = single_proof_size * num_files;
        let savings = hypothetical_total.saturating_sub(aggregated_size);
        let savings_percent = if hypothetical_total > 0 {
            (savings as f64 / hypothetical_total as f64) * 100.0
        } else {
            0.0
        };

        Self {
            single_file_proof_size: single_proof_size,
            aggregated_proof_size: aggregated_size,
            aggregation_factor: num_files,
            savings_bytes: savings,
            savings_percent,
        }
    }

    /// Format as human-readable summary
    pub fn format_summary(&self) -> String {
        format!(
            "Batching {} files: {:.1} KB saved ({:.1}%)",
            self.aggregation_factor,
            self.savings_bytes as f64 / 1024.0,
            self.savings_percent
        )
    }
}

/// Economic analysis of proving costs
#[derive(Debug, Clone)]
pub struct EconomicMetrics {
    pub proof_size_kb: f64,
    pub btc_tx_fee_usd: f64,
    pub challenges_batched: usize,
    pub amortized_cost_per_challenge: f64,
}

impl EconomicMetrics {
    /// Create economic metrics from proof and batching info
    pub fn new(proof_size_bytes: usize, btc_fee: f64, num_challenges: usize) -> Self {
        let amortized = if num_challenges > 0 {
            btc_fee / num_challenges as f64
        } else {
            btc_fee
        };

        Self {
            proof_size_kb: proof_size_bytes as f64 / 1024.0,
            btc_tx_fee_usd: btc_fee,
            challenges_batched: num_challenges,
            amortized_cost_per_challenge: amortized,
        }
    }

    /// Format economics summary (simple version)
    pub fn format_simple(&self, num_files: usize) -> String {
        let hypothetical_cost = self.btc_tx_fee_usd * num_files as f64;
        let savings = hypothetical_cost - self.btc_tx_fee_usd;
        let hypothetical_size = self.proof_size_kb * num_files as f64;
        let size_savings = hypothetical_size - self.proof_size_kb;

        format!(
            "Batching {} challenges: ${:.2} saved, {:.1} KB saved",
            num_files, savings, size_savings
        )
    }
}

/// Challenge information for display
#[derive(Debug, Clone)]
pub struct ChallengeInfo {
    pub file_id: String,
    pub block_height: u64,
    pub expiration_block: u64,
    pub seed: String, // Truncated hex for display
}

impl ChallengeInfo {
    /// Format challenge info for display
    pub fn format(&self) -> String {
        format!(
            "{} at block {} (expires: {})",
            &self.file_id[..8], self.block_height, self.expiration_block
        )
    }
}

/// File size category for heterogeneous testing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileSizeCategory {
    /// 10-50 KB files
    Small,
    /// 50-500 KB files
    Medium,
    /// 500 KB - 10 MB files
    Large,
    /// 10-100 MB files
    XLarge,
}

impl FileSizeCategory {
    /// Get a size within this category's range
    pub fn sample_size(&self, rng_seed: u64) -> usize {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hash, Hasher};
        
        let mut hasher = RandomState::new().build_hasher();
        rng_seed.hash(&mut hasher);
        let hash = hasher.finish();
        
        match self {
            FileSizeCategory::Small => 10 * 1024 + (hash % (40 * 1024)) as usize,
            FileSizeCategory::Medium => 50 * 1024 + (hash % (450 * 1024)) as usize,
            FileSizeCategory::Large => 500 * 1024 + (hash % (9500 * 1024)) as usize,
            FileSizeCategory::XLarge => 10 * 1024 * 1024 + (hash % (90 * 1024 * 1024)) as usize,
        }
    }

    /// Get string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            FileSizeCategory::Small => "Small",
            FileSizeCategory::Medium => "Medium",
            FileSizeCategory::Large => "Large",
            FileSizeCategory::XLarge => "XLarge",
        }
    }

    /// Get depth range for this category
    pub fn depth_range(&self) -> (usize, usize) {
        match self {
            FileSizeCategory::Small => (9, 11),
            FileSizeCategory::Medium => (12, 14),
            FileSizeCategory::Large => (16, 18),
            FileSizeCategory::XLarge => (19, 22),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aggregation_metrics() {
        let metrics = AggregationMetrics::new(10240, 10240, 5);
        assert_eq!(metrics.aggregation_factor, 5);
        assert_eq!(metrics.savings_bytes, 40960);
        assert!((metrics.savings_percent - 80.0).abs() < 0.1);
    }

    #[test]
    fn test_economic_metrics() {
        let metrics = EconomicMetrics::new(10240, 0.50, 5);
        assert!((metrics.proof_size_kb - 10.0).abs() < 0.1);
        assert!((metrics.amortized_cost_per_challenge - 0.10).abs() < 0.01);
    }

    #[test]
    fn test_file_size_categories() {
        let small = FileSizeCategory::Small.sample_size(42);
        assert!(small >= 10 * 1024 && small < 50 * 1024);

        let medium = FileSizeCategory::Medium.sample_size(42);
        assert!(medium >= 50 * 1024 && medium < 500 * 1024);
    }
}

