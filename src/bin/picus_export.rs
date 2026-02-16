use clap::Parser;
use kontor_crypto::formal;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "picus_export")]
#[command(about = "Export deterministic Nova R1CS artifacts for Picus workflows")]
struct Args {
    /// Export all fixtures listed in manifest
    #[arg(long)]
    all: bool,

    /// Fixture IDs to export (ignored when --all is set)
    #[arg(long = "fixture")]
    fixtures: Vec<String>,

    /// Export a Picus .r1cs variant where only the first N step outputs are treated as "public outputs".
    /// N=0 (default) exports the full output set.
    #[arg(long, default_value_t = 0)]
    output_prefix_len: usize,

    /// Emit a witness-guided Picus precondition (picus-precondition.json) alongside the exported circuit.
    #[arg(long)]
    picus_witness_precondition: bool,

    /// Emit a Picus precondition that fixes only the public inputs (z) to this fixture's instance.
    /// This matches the "fixed public z" scope described in docs/formal/determinism.md and is
    /// typically much easier
    /// than a fully symbolic no-precondition run.
    #[arg(long, conflicts_with = "picus_witness_precondition")]
    picus_input_precondition: bool,

    /// Emit a Picus precondition that fixes the public inputs plus the witness leaf/path values
    /// (leaf + Merkle siblings), without fixing intermediate wires.
    #[arg(long, conflicts_with_all = ["picus_witness_precondition", "picus_input_precondition"])]
    picus_leafpath_precondition: bool,

    /// Path to fixture manifest file
    #[arg(long, default_value = "tools/picus/manifest.json")]
    manifest: PathBuf,

    /// Directory containing per-fixture JSON definitions
    #[arg(long, default_value = "tools/picus/fixtures")]
    fixtures_dir: PathBuf,

    /// Artifact output root
    #[arg(long, default_value = "artifacts/picus")]
    artifacts_dir: PathBuf,
}

fn main() {
    let args = Args::parse();

    if let Err(err) = run(args) {
        eprintln!("picus_export failed: {}", err);
        std::process::exit(1);
    }
}

fn run(args: Args) -> kontor_crypto::Result<()> {
    let fixture_ids = resolve_fixture_ids(&args)?;

    if fixture_ids.is_empty() {
        return Err(kontor_crypto::KontorPoRError::InvalidInput(
            "No fixtures selected. Use --all or --fixture <id>".to_string(),
        ));
    }

    println!("Exporting {} fixture(s)", fixture_ids.len());
    if args.output_prefix_len > 0 {
        println!("- Picus output prefix len: {}", args.output_prefix_len);
    }
    if args.picus_witness_precondition {
        println!("- Picus witness precondition: enabled");
    }
    if args.picus_input_precondition {
        println!("- Picus input-fixed precondition: enabled");
    }
    if args.picus_leafpath_precondition {
        println!("- Picus leaf+path precondition: enabled");
    }

    for fixture_id in fixture_ids {
        let fixture = formal::load_fixture(&args.fixtures_dir, &fixture_id)?;
        let picus_pre = if args.picus_witness_precondition {
            formal::PicusPreconditionKind::WitnessExceptOutputs
        } else if args.picus_input_precondition {
            formal::PicusPreconditionKind::InputsOnly
        } else if args.picus_leafpath_precondition {
            formal::PicusPreconditionKind::InputsPlusLeafPathOnly
        } else {
            formal::PicusPreconditionKind::None
        };

        let output =
            if args.output_prefix_len == 0 && picus_pre == formal::PicusPreconditionKind::None {
                formal::export_fixture(&fixture, &args.artifacts_dir)?
            } else {
                formal::export_fixture_for_picus_verify(
                    &fixture,
                    &args.artifacts_dir,
                    if args.output_prefix_len == 0 {
                        None
                    } else {
                        Some(args.output_prefix_len)
                    },
                    picus_pre,
                )?
            };

        println!("- {}", output.fixture_id);
        println!("  artifact dir: {}", output.artifact_dir.display());
        println!("  shape: {}", output.shape_path.display());
        println!("  circuit.r1cs: {}", output.picus_input_path.display());
        if let Some(pre) = &output.picus_precondition_path {
            println!("  picus-precondition.json: {}", pre.display());
        }
        println!("  instance: {}", output.instance_path.display());
        println!("  witness: {}", output.witness_path.display());
        println!("  metadata: {}", output.metadata_path.display());
        println!("  constraints: {}", output.metadata.num_constraints);
    }

    Ok(())
}

fn resolve_fixture_ids(args: &Args) -> kontor_crypto::Result<Vec<String>> {
    if args.all {
        let manifest = formal::load_manifest(&args.manifest)?;
        return Ok(manifest.fixtures);
    }

    Ok(args.fixtures.clone())
}
