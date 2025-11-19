//! Kontor Storage Node Simulator
//!
//! This binary simulates realistic storage node operation, showcasing:
//! - Heterogeneous file sizes (10KB - 100MB)
//! - Multi-file proof aggregation
//! - Staggered challenge arrival over time
//! - Bitcoin transaction fee economics
//!
//! Run with: cargo run --release
//! For economic analysis: cargo run --release -- --economic-analysis

use clap::{ArgAction, Parser};
use kontor_crypto::{
    api::{self, Challenge, FieldElement, PorSystem},
    config,
    metrics::{EconomicMetrics, FileSizeCategory, ProofMetrics, VerificationMetrics},
    FileLedger,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::time::{Duration, Instant};
use tracing::{error, info, info_span};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Command-line arguments for the storage node simulator
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Total number of files in the network ledger
    #[arg(long, default_value_t = 100)]
    total_files_in_ledger: usize,

    /// Number of files this storage node stores
    #[arg(long, default_value_t = 10)]
    files_stored_by_node: usize,

    /// Number of challenges to simulate receiving
    #[arg(long, default_value_t = 5)]
    challenges_to_simulate: usize,

    /// File size distribution: "uniform", "mixed", "large-heavy"
    #[arg(long, default_value = "mixed")]
    file_size_distribution: String,

    /// Skip verification to focus on proving performance
    #[arg(long, default_value_t = false)]
    no_verify: bool,

    /// Enable memory profiling (requires memory-profiling feature)
    #[arg(long, default_value_t = false)]
    profile_memory: bool,

    /// Increase output verbosity (-v for DEBUG, -vv for TRACE)
    #[arg(short, long, action = ArgAction::Count)]
    verbose: u8,
}

/// Information about a file stored by this node
struct StoredFile {
    prepared: api::PreparedFile,
    metadata: api::FileMetadata,
    #[allow(dead_code)]
    category: FileSizeCategory,
}

fn main() {
    let cli = Cli::parse();

    // Initialize tracing
    init_tracing(cli.verbose);

    // Validate inputs
    if cli.files_stored_by_node > cli.total_files_in_ledger {
        error!("Error: --files-stored-by-node cannot exceed --total-files-in-ledger");
        std::process::exit(1);
    }
    if cli.challenges_to_simulate > cli.files_stored_by_node {
        error!("Error: --challenges-to-simulate cannot exceed --files-stored-by-node");
        std::process::exit(1);
    }

    // Print welcome banner
    info!("");
    info!("╔══════════════════════════════════════════════════════════════╗");
    info!("║   Kontor Storage Node Simulator                              ║");
    info!("║   Realistic Multi-File Proof Aggregation Demo                ║");
    info!("╚══════════════════════════════════════════════════════════════╝");
    info!("");

    // Phase 1: Network Setup
    info!("[1/4] Network Setup");
    let (ledger, node_files) = setup_network(
        cli.total_files_in_ledger,
        cli.files_stored_by_node,
        &cli.file_size_distribution,
    );
    info!("");

    // Phase 2: Challenge Simulation
    info!("[2/4] Challenge Simulation");
    let challenges = simulate_challenges(&node_files, cli.challenges_to_simulate);
    display_challenge_info(&challenges);
    info!("");

    // Phase 3: Proof Generation
    info!("[3/4] Proof Generation");
    info!("");

    let (proof_metrics, proof) =
        generate_proof(&node_files, &challenges, &ledger, cli.profile_memory);

    info!("{}", proof_metrics.format_table());
    info!("");
    info!(
        "  ✓ Generated aggregated proof: {:.1} KB",
        proof_metrics.proof_size_kb()
    );
    info!(
        "  ✓ Covers {} file challenges ({} symbols each, {} total symbols proven)",
        proof_metrics.num_files,
        proof_metrics.num_challenges_per_file,
        proof_metrics.num_files * proof_metrics.num_challenges_per_file
    );
    info!("");

    info!("  Circuit Details:");
    info!(
        "    • File slots: {} ({} used + {} padding)",
        proof_metrics.files_per_step,
        proof_metrics.num_files,
        proof_metrics.files_per_step - proof_metrics.num_files
    );
    info!(
        "    • Max tree depth: {}",
        proof_metrics.max_file_tree_depth
    );
    info!(
        "    • Aggregated tree depth: {}",
        proof_metrics.aggregated_tree_depth
    );
    info!(
        "    • Circuit cost: {} constraints ({} × depth {})",
        proof_metrics.circuit_cost(),
        config::CIRCUIT_COST_PER_DEPTH,
        proof_metrics.max_file_tree_depth
    );
    info!("    • IVC steps: {} per file", proof_metrics.total_steps);
    info!("");

    // Show per-file coverage
    info!("  Per-File Coverage:");
    for challenge in challenges.iter() {
        let total_symbols = challenge.file_metadata.total_symbols();
        let tested_symbols = challenge.num_challenges;
        let coverage_pct = if total_symbols > 0 {
            (tested_symbols as f64 / total_symbols as f64) * 100.0
        } else {
            0.0
        };
        info!(
            "    • File {}: {}/{} symbols tested ({:.1}%)",
            &challenge.file_metadata.file_id[..8],
            tested_symbols,
            total_symbols,
            coverage_pct
        );
    }
    info!("");

    // Phase 4: Verification
    if !cli.no_verify {
        info!("[4/4] Verification");
        let verify_metrics = verify_proof(&proof, &challenges, &ledger);
        info!("  ✓ {}", verify_metrics.format());
        info!("");
    }

    // Proof Economics
    display_economic_analysis(&proof_metrics);
}

/// Setup realistic network with heterogeneous file sizes
fn setup_network(
    total_files: usize,
    files_stored: usize,
    distribution: &str,
) -> (FileLedger, Vec<StoredFile>) {
    let _span = info_span!("network_setup").entered();

    // Determine file size distribution
    let categories = match distribution {
        "uniform" => vec![FileSizeCategory::Medium; total_files],
        "large-heavy" => {
            let mut cats = vec![];
            for i in 0..total_files {
                let cat = if i % 4 == 0 {
                    FileSizeCategory::Large
                } else if i % 4 == 1 {
                    FileSizeCategory::XLarge
                } else {
                    FileSizeCategory::Medium
                };
                cats.push(cat);
            }
            cats
        }
        _ => {
            // "mixed" - default distribution
            let mut cats = vec![];
            for i in 0..total_files {
                let cat = match i % 10 {
                    0..=2 => FileSizeCategory::Small,
                    3..=6 => FileSizeCategory::Medium,
                    7..=8 => FileSizeCategory::Large,
                    _ => FileSizeCategory::XLarge,
                };
                cats.push(cat);
            }
            cats
        }
    };

    // Create files that this node stores (subset of network)
    let mut node_files = Vec::new();
    let mut category_counts = [0usize; 4]; // Small, Medium, Large, XLarge
    let mut rng = StdRng::seed_from_u64(config::TEST_RANDOM_SEED);

    for i in 0..files_stored {
        let category = categories[i];
        let size = category.sample_size(i as u64);

        let mut data = vec![0u8; size];
        rng.fill_bytes(&mut data);

        let (prepared, metadata) =
            api::prepare_file(&data, &format!("node_file_{}.dat", i)).unwrap();

        let idx = match category {
            FileSizeCategory::Small => 0,
            FileSizeCategory::Medium => 1,
            FileSizeCategory::Large => 2,
            FileSizeCategory::XLarge => 3,
        };
        category_counts[idx] += 1;

        node_files.push(StoredFile {
            prepared,
            metadata,
            category,
        });
    }

    // Build ledger with ALL files in network (node files + other files)
    let mut ledger = FileLedger::new();

    // Add node's files first
    for file in &node_files {
        ledger
            .add_file(
                file.metadata.file_id.clone(),
                file.metadata.root,
                api::tree_depth_from_metadata(&file.metadata),
            )
            .unwrap();
    }

    // Add additional files to simulate full network (that this node doesn't store)
    for i in files_stored..total_files {
        let category = categories[i];
        let size = category.sample_size(i as u64);

        let mut data = vec![0u8; size];
        rng.fill_bytes(&mut data);

        let (_, metadata) = api::prepare_file(&data, &format!("network_file_{}.dat", i)).unwrap();
        ledger
            .add_file(
                metadata.file_id.clone(),
                metadata.root,
                api::tree_depth_from_metadata(&metadata),
            )
            .unwrap();
    }

    // Find depth range across all node files
    let depths: Vec<usize> = node_files
        .iter()
        .map(|f| api::tree_depth_from_metadata(&f.metadata))
        .collect();
    let min_depth = depths.iter().min().copied().unwrap_or(0);
    let _max_depth = depths.iter().max().copied().unwrap_or(0);

    info!(
        "  ✓ Created ledger with {} files (depths {}-22)",
        total_files, min_depth
    );
    info!("  ✓ Node stores {} files:", files_stored);

    if category_counts[0] > 0 {
        let (d_min, d_max) = FileSizeCategory::Small.depth_range();
        info!(
            "    - {} {} (10-50KB, depth {}-{})",
            category_counts[0],
            FileSizeCategory::Small.as_str(),
            d_min,
            d_max
        );
    }
    if category_counts[1] > 0 {
        let (d_min, d_max) = FileSizeCategory::Medium.depth_range();
        info!(
            "    - {} {} (50-500KB, depth {}-{})",
            category_counts[1],
            FileSizeCategory::Medium.as_str(),
            d_min,
            d_max
        );
    }
    if category_counts[2] > 0 {
        let (d_min, d_max) = FileSizeCategory::Large.depth_range();
        info!(
            "    - {} {} (500KB-10MB, depth {}-{})",
            category_counts[2],
            FileSizeCategory::Large.as_str(),
            d_min,
            d_max
        );
    }
    if category_counts[3] > 0 {
        let (d_min, d_max) = FileSizeCategory::XLarge.depth_range();
        info!(
            "    - {} {} (10-100MB, depth {}-{})",
            category_counts[3],
            FileSizeCategory::XLarge.as_str(),
            d_min,
            d_max
        );
    }

    (ledger, node_files)
}

/// Simulate challenges arriving over time with staggered block heights
fn simulate_challenges(node_files: &[StoredFile], num_challenges: usize) -> Vec<Challenge> {
    let _span = info_span!("challenge_simulation").entered();

    // Use protocol challenge frequency for realistic spacing
    // 12 challenges/year per file = ~1 every 30 days = ~4,380 blocks
    // For simulation, use shorter spacing
    let spacing = config::CHALLENGE_SPACING_BLOCKS;
    let base_block = 1000u64;

    let mut challenges = Vec::new();
    let mut rng = StdRng::seed_from_u64(config::TEST_RANDOM_SEED);

    for i in 0..num_challenges {
        let file = &node_files[i];
        let block_height = base_block + (i as u64 * spacing);

        // Derive deterministic seed from block hash simulation
        let mut block_hash_seed = [0u8; 32];
        rng.fill_bytes(&mut block_hash_seed);
        let seed = FieldElement::from(u64::from_le_bytes(block_hash_seed[..8].try_into().unwrap()));

        // Protocol default: s_chal = 100 symbols per challenge
        let num_symbols_to_prove = 100;

        let challenge = Challenge::new(
            file.metadata.clone(),
            block_height,
            num_symbols_to_prove,
            seed,
            String::from("node_1"),
        );

        challenges.push(challenge);
    }

    challenges
}

/// Display challenge information showing staggered timing
fn display_challenge_info(challenges: &[Challenge]) {
    if challenges.is_empty() {
        return;
    }

    let first_block = challenges.first().unwrap().block_height;
    let last_block = challenges.last().unwrap().block_height;
    let span_blocks = last_block - first_block;

    // Convert block span to approximate hours (6 blocks/hour)
    let span_hours = span_blocks / config::BLOCKS_PER_HOUR as u64;

    info!(
        "  ✓ Randomly selected {} of the node's stored files to challenge",
        challenges.len()
    );
    info!("  ✓ Received {} challenges:", challenges.len());
    for challenge in challenges {
        let expiration = challenge.block_height + 2016; // W_proof from protocol
                                                        // Show file ID prefix to identify which file is being challenged
        info!(
            "    • File {} at block {} (expires: {})",
            &challenge.file_metadata.file_id[..8],
            challenge.block_height,
            expiration
        );
    }

    info!(
        "  ✓ Challenges span {} blocks (~{} hours) [simulated; protocol: ~4,380 blocks/challenge]",
        span_blocks, span_hours
    );
    info!("  ✓ All within 2016-block proof window → batching opportunity");
}

/// Generate proof with metric collection
fn generate_proof(
    node_files: &[StoredFile],
    challenges: &[Challenge],
    ledger: &FileLedger,
    profile_memory: bool,
) -> (ProofMetrics, api::Proof) {
    let _span = info_span!("proof_generation").entered();

    if profile_memory {
        kontor_crypto::metrics::reset_peak_memory();
    }

    let total_start = Instant::now();

    // Phase 1: Parameter Generation
    let param_start = Instant::now();

    if profile_memory {
        kontor_crypto::metrics::reset_peak_memory();
    }

    let max_file_depth = challenges
        .iter()
        .map(|c| api::tree_depth_from_metadata(&c.file_metadata))
        .max()
        .unwrap_or(1);
    let (files_per_step, file_tree_depth) = config::derive_shape(challenges.len(), max_file_depth);
    let aggregated_tree_depth = if files_per_step > 1 {
        ledger.tree.layers.len() - 1
    } else {
        0
    };

    let cache_size_before = kontor_crypto::params::memory_cache_size();
    let _params = kontor_crypto::params::load_or_generate_params(
        files_per_step,
        file_tree_depth,
        aggregated_tree_depth,
    )
    .unwrap();
    let cache_size_after = kontor_crypto::params::memory_cache_size();
    let param_cache_hit = cache_size_after == cache_size_before;

    let param_duration = param_start.elapsed();
    let param_memory_mb = if profile_memory {
        Some(kontor_crypto::metrics::get_peak_memory_mb())
    } else {
        None
    };

    // Phase 2: Proof Generation (witness generation happens inside)
    if profile_memory {
        kontor_crypto::metrics::reset_peak_memory();
    }

    let proving_start = Instant::now();
    let system = PorSystem::new(ledger);
    let files_vec: Vec<&_> = node_files.iter().map(|f| &f.prepared).collect();
    let proof = system.prove(files_vec, challenges).unwrap();
    let proving_duration = proving_start.elapsed();

    let proving_memory_mb = if profile_memory {
        Some(kontor_crypto::metrics::get_peak_memory_mb())
    } else {
        None
    };

    // Get proof size
    let proof_bytes = bincode::serialize(&proof)
        .map(|bytes| bytes.len())
        .unwrap_or(0);

    let total_duration = total_start.elapsed();

    let total_memory_mb = if profile_memory {
        param_memory_mb.max(proving_memory_mb)
    } else {
        None
    };

    (
        ProofMetrics {
            total_duration,
            param_gen_duration: param_duration,
            witness_gen_duration: Duration::from_secs(0), // Not separately measured
            proving_duration,
            compression_duration: Duration::from_secs(0), // Not separately measured
            proof_size_bytes: proof_bytes,
            num_files: challenges.len(),
            num_challenges_per_file: challenges.first().map(|c| c.num_challenges).unwrap_or(0),
            total_steps: challenges.first().map(|c| c.num_challenges).unwrap_or(0),
            aggregated_tree_depth,
            max_file_tree_depth: file_tree_depth,
            memory_peak_mb: total_memory_mb,
            files_per_step,
            param_cache_hit,
            param_gen_memory_mb: param_memory_mb,
            proving_memory_mb,
        },
        proof,
    )
}

/// Verify proof and collect metrics
fn verify_proof(
    proof: &api::Proof,
    challenges: &[Challenge],
    ledger: &FileLedger,
) -> VerificationMetrics {
    let _span = info_span!("verification").entered();

    let system = PorSystem::new(ledger);

    let start = Instant::now();
    let result = system.verify(proof, challenges).unwrap();
    let duration = start.elapsed();

    if !result {
        error!("  ✗ Verification failed!");
        std::process::exit(1);
    }

    VerificationMetrics {
        duration,
        num_files: challenges.len(),
        num_challenges_per_file: challenges.first().map(|c| c.num_challenges).unwrap_or(0),
    }
}

/// Display proof economics
fn display_economic_analysis(metrics: &ProofMetrics) {
    info!("═══════════════════════════════════════════════════════════════");
    info!("PROOF ECONOMICS");
    info!("═══════════════════════════════════════════════════════════════");
    info!("");

    let econ = EconomicMetrics::new(
        metrics.proof_size_bytes,
        config::BTC_TX_FEE_USD_DEFAULT,
        metrics.num_files,
    );

    info!("Aggregated Proof:");
    info!("  • Proof size: {:.1} KB", econ.proof_size_kb);
    info!(
        "  • Covers {} file challenges ({} symbols each)",
        metrics.num_files, metrics.num_challenges_per_file
    );
    info!("  • Bitcoin transaction fee: ${:.2}", econ.btc_tx_fee_usd);
    info!(
        "  • Cost per file challenge: ${:.2}",
        econ.amortized_cost_per_challenge
    );
    info!("");
    info!("═══════════════════════════════════════════════════════════════");
    info!("");
}

fn init_tracing(verbosity: u8) {
    let level = match verbosity {
        0 => "info,kontor_crypto=info,nova_snark=warn",
        1 => "debug,kontor_crypto=debug,nova_snark=info",
        _ => "kontor_crypto=trace,nova_snark=debug",
    };

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));

    use tracing_tree::HierarchicalLayer;

    tracing_subscriber::registry()
        .with(env_filter)
        .with(
            HierarchicalLayer::new(2)
                .with_targets(false)
                .with_bracketed_fields(true),
        )
        .init();
}
