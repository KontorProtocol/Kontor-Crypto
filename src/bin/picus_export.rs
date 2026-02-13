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

    for fixture_id in fixture_ids {
        let fixture = formal::load_fixture(&args.fixtures_dir, &fixture_id)?;
        let output = formal::export_fixture(&fixture, &args.artifacts_dir)?;

        println!("- {}", output.fixture_id);
        println!("  artifact dir: {}", output.artifact_dir.display());
        println!("  shape: {}", output.shape_path.display());
        println!("  circuit.r1cs: {}", output.picus_input_path.display());
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
