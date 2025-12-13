use bincode::serialize;
use clap::{ArgAction, Parser};
use kontor_crypto::{
    api::{self, Challenge, FieldElement, PorSystem},
    config, params, FileLedger,
};
use rand::rngs::OsRng;
use rand::RngCore;
use std::time::Instant;
use tracing::{error, info, info_span, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Command-line arguments for the aggregated PoR benchmark.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Total number of files to store in the ledger.
    #[arg(long, default_value_t = 3)]
    total_files: usize,

    /// Number of files to challenge (prove storage for).
    #[arg(long, default_value_t = 2)]
    challenged_files: usize,

    /// Number of challenges (e.g., sectors) to prove for EACH challenged file.
    #[arg(long, default_value_t = 3)]
    num_challenges: usize,

    /// Size (bytes) of each file to simulate.
    #[arg(long, default_value_t = config::DEFAULT_FILE_SIZE)]
    file_size: usize,

    /// If set, skip verification to focus on proving throughput.
    #[arg(long, default_value_t = false)]
    no_verify: bool,

    /// Increase output verbosity (-v for DEBUG, -vv for TRACE)
    #[arg(short, long, action = ArgAction::Count)]
    verbose: u8,
}

fn main() {
    let cli = Cli::parse();

    // Initialize global tracing/logging
    init_tracing(cli.verbose);

    let total_files = cli.total_files;
    let challenged_files = cli.challenged_files;
    let num_challenges = cli.num_challenges;
    let file_size = cli.file_size;
    let no_verify = cli.no_verify;

    // Print welcome message
    info!("");
    info!("╔══════════════════════════════════════════════════════╗");
    info!("║   Kontor Proof of Retrievability (PoR)               ║");
    info!("╚══════════════════════════════════════════════════════╝");
    info!("  Demonstrating cryptographic proof of data possession");

    if challenged_files > total_files {
        error!("Error: --challenged-files cannot exceed --total-files.");
        std::process::exit(1);
    }
    if challenged_files == 0 {
        error!("Error: --challenged-files must be greater than zero.");
        std::process::exit(1);
    }
    if num_challenges == 0 {
        error!("Error: --num-challenges must be greater than zero.");
        std::process::exit(1);
    }

    info!("┌─────────────────────────────────────────────────────────────┐");
    info!("│ Configuration:                                              │");
    info!(
        "│   • Total files in system: {:>8}                         │",
        total_files
    );
    info!(
        "│   • Files to challenge:    {:>8}                         │",
        challenged_files
    );
    info!(
        "│   • Sectors challenged per file:      {:>8}              │",
        num_challenges
    );
    info!(
        "│   • Total sectors proven:  {:>8}                         │",
        challenged_files * num_challenges
    );
    info!(
        "│   • File size:             {:>8} bytes                   │",
        file_size
    );
    info!(
        "│   • Verification:           {}                         │",
        if no_verify { "SKIPPED " } else { "ENABLED" }
    );
    info!("└─────────────────────────────────────────────────────────────┘");

    // Prepare containers and state used across spans
    let mut ledger = FileLedger::new();
    let mut prepared_files = Vec::new();
    let mut metadatas = Vec::new();
    let total_prove_time;
    let proof_bytes;
    let proof;
    let challenges;

    // --- Step 1: Prepare all files and build ledger ---
    {
        let _setup_span = info_span!("setup_phase").entered();
        let start_prepare = Instant::now();

        info!("Setting up: preparing {} files...", total_files);

        // Generate and prepare all files
        for i in 0..total_files {
            // Create random test data
            let mut data = vec![0u8; file_size];
            OsRng.fill_bytes(&mut data);

            let (prepared_file, metadata) = api::prepare_file(&data, &format!("file_{}.dat", i))
                .unwrap_or_else(|e| {
                    error!("Error preparing file {}: {}", i, e);
                    std::process::exit(1);
                });

            // Add to ledger
            ledger.add_file(&metadata).unwrap_or_else(|e| {
                error!("Error adding file {} to ledger: {}", i, e);
                std::process::exit(1);
            });

            prepared_files.push(prepared_file);
            metadatas.push(metadata);

            if i % 10 == 0 || i == total_files - 1 {
                // Log progress periodically
                info!("  Prepared {}/{} files", i + 1, total_files);
            }
        }

        let setup_time = start_prepare.elapsed();
        info!(
            "Setup complete: {} files prepared and added to ledger in {:.2}s",
            total_files,
            setup_time.as_secs_f64()
        );
    }

    // --- Step 2: Verifier challenges random files ---
    // Select which files to challenge
    // For testing: always select files in order [0, 1, 2, ...]
    let challenged_indices: Vec<usize> = (0..challenged_files).collect();

    // --- Step 3: Create PorSystem and generate proof for ALL challenged files ---

    // Create PorSystem with the populated ledger
    let system = PorSystem::new(&ledger);

    {
        let _prove_span = info_span!("prove_phase").entered();
        let start_prove_total = Instant::now();

        info!("Proving: generating parameters...");

        // Build challenges and file map for all challenged files
        let mut challenges_vec = Vec::new();
        let mut files_map = std::collections::BTreeMap::new();

        // Assume all files have same tree depth for now (requirement of current implementation)
        let first_metadata = &metadatas[challenged_indices[0]];
        let actual_tree_depth = first_metadata.padded_len.trailing_zeros() as usize;
        // Use a minimum tree depth of 3 for parameter generation to ensure proper circuit operation
        let _tree_depth = actual_tree_depth.max(config::DEFAULT_TEST_TREE_DEPTH);

        // Suppress this info message during progress bar display

        for &file_idx in &challenged_indices {
            let metadata = &metadatas[file_idx];
            let prepared_file = &prepared_files[file_idx];

            // Verify all files have same tree depth
            if metadata.padded_len.trailing_zeros() as usize != actual_tree_depth {
                error!(
                    "Error: All challenged files must have same tree depth for multi-file proof"
                );
                std::process::exit(1);
            }

            // Create challenge for this file
            let seed = FieldElement::from(config::TEST_RANDOM_SEED);
            let challenge = Challenge::new(
                metadata.clone(),
                1000,
                num_challenges,
                seed,
                String::from("node_1"),
            );

            challenges_vec.push(challenge);
            files_map.insert(metadata.file_id.clone(), prepared_file);
        }

        // Derive the exact circuit shape from challenges
        let max_file_depth = challenges_vec
            .iter()
            .map(|c| api::tree_depth_from_metadata(&c.file_metadata))
            .max()
            .unwrap_or(1);
        let (files_per_step, file_tree_depth) =
            config::derive_shape(challenges_vec.len(), max_file_depth);
        let aggregated_tree_depth = ledger.tree.layers.len() - 1;

        // Generate or load parameters for the exact shape
        let param_start = Instant::now();
        {
            let _param_span = info_span!(
                "load_params",
                files_per_step,
                file_tree_depth,
                aggregated_tree_depth
            )
            .entered();
            match params::load_or_generate_params(
                files_per_step,
                file_tree_depth,
                aggregated_tree_depth,
            ) {
                Ok(params) => params,
                Err(e) => {
                    error!("Failed to load or generate parameters: {:?}", e);
                    std::process::exit(1);
                }
            }
        };
        let param_time = param_start.elapsed();
        challenges = challenges_vec;

        info!(
            "Parameters ready in {:.2}s (shape: {}x{}), executing {} recursive steps...",
            param_time.as_secs_f64(),
            files_per_step,
            file_tree_depth,
            num_challenges.saturating_sub(1)
        );
        info!("Starting recursive proving...");

        // Convert to Vec for PorSystem API
        let files_vec: Vec<&_> = challenged_indices
            .iter()
            .map(|&i| &prepared_files[i])
            .collect();

        proof = {
            let _proof_span = info_span!(
                "PorSystem::prove",
                challenged_files,
                num_challenges,
                total_steps = num_challenges
            )
            .entered();
            system.prove(files_vec, &challenges)
        }
        .unwrap_or_else(|e| {
            error!("Failed to generate multi-file proof: {:?}", e);
            std::process::exit(1);
        });

        info!("Proof generation complete");
        total_prove_time = start_prove_total.elapsed();

        // Track proof size
        proof_bytes = serialize(&proof)
            .map(|bytes| bytes.len())
            .unwrap_or_else(|e| {
                warn!("Failed to serialize proof for size tracking: {:?}", e);
                0
            });
    }

    // --- Step 4: Verification ---
    if !no_verify {
        let _verify_span = info_span!("verify_phase").entered();
        let start_verify = Instant::now();

        info!("Verifying proof...");

        let is_valid = match system.verify(&proof, &challenges) {
            Ok(valid) => valid,
            Err(e) => {
                error!("Verification check failed unexpectedly: {:?}", e);
                std::process::exit(1);
            }
        };

        let verify_time = start_verify.elapsed();
        if is_valid {
            info!(
                "✓ Proof verification: VALID (took {:.2}s)",
                verify_time.as_secs_f64()
            );
        } else {
            error!(
                "✗ Proof verification: INVALID (took {:.2}s)",
                verify_time.as_secs_f64()
            );
        }
    }

    // --- Results Summary ---
    let proof_size_kb = proof_bytes as f64 / 1024.0;

    info!("--- RESULTS ---");
    info!("{:<35} | {:>15}", "Metric", "Value");
    info!("{:-<35}-|-{:-<15}", "", "");
    info!("{:<35} | {:>15}", "Total Files in Ledger", total_files);
    info!("{:<35} | {:>15}", "Files Challenged", challenged_files);
    info!(
        "{:<35} | {:>15}",
        "Sectors Challenged per File", num_challenges
    );
    info!(
        "{:<35} | {:>15.3} s",
        "Total Proof Generation Time",
        total_prove_time.as_secs_f64()
    );
    info!("{:<35} | {:>15.2} KB", "Proof Size", proof_size_kb);

    info!("--- SUCCESS ---");
    info!(
        "Generated a single compact proof covering {} challenged files.",
        challenged_files
    );
    info!("---------------------------\n");
}

fn init_tracing(verbosity: u8) {
    // Default: info, -v: debug, -vv or more: trace
    let level = match verbosity {
        0 => "info,kontor_crypto=info,nova_snark=warn",
        1 => "debug,kontor_crypto=debug,nova_snark=info",
        _ => "kontor_crypto=trace,nova_snark=debug",
    };

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));

    // Use tracing-tree for hierarchical output with timing
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
