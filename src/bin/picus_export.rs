use clap::{Parser, ValueEnum};
use kontor_crypto::formal;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Scope {
    Leafpath,
    PublicZ,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SimplifyMode {
    Safe,
    Off,
}

#[derive(Debug, Parser)]
#[command(name = "picus_export")]
#[command(about = "Export component-first Nova R1CS artifacts for Picus workflows")]
struct Args {
    /// Export all fixtures listed in manifest
    #[arg(long)]
    all: bool,

    /// Fixture IDs to export (ignored when --all is set)
    #[arg(long = "fixture")]
    fixtures: Vec<String>,

    /// Path to component fixture manifest file
    #[arg(long, default_value = "tools/picus/components/manifest.json")]
    manifest: PathBuf,

    /// Directory containing component fixture JSON definitions
    #[arg(long, default_value = "tools/picus/components/fixtures")]
    fixtures_dir: PathBuf,

    /// Path to component contracts file
    #[arg(long, default_value = "tools/picus/components/contracts.json")]
    contracts: PathBuf,

    /// Artifact output root
    #[arg(long, default_value = "artifacts/picus-components")]
    artifacts_dir: PathBuf,

    /// Determinism scope
    #[arg(long, value_enum, default_value_t = Scope::Leafpath)]
    scope: Scope,

    /// Optional output prefix length (0 = full outputs)
    #[arg(long, default_value_t = 0)]
    output_prefix_len: usize,

    /// R1CS simplification mode
    #[arg(long, value_enum, default_value_t = SimplifyMode::Safe)]
    simplify: SimplifyMode,
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

    std::env::set_var(
        "KONTOR_PICUS_SIMPLIFY",
        match args.simplify {
            SimplifyMode::Safe => "safe",
            SimplifyMode::Off => "off",
        },
    );

    let mut fixtures = Vec::with_capacity(fixture_ids.len());
    for fixture_id in fixture_ids {
        fixtures.push(formal::load_fixture(&args.fixtures_dir, &fixture_id)?);
    }

    let contracts = formal::components::load_component_contracts(&args.contracts)?;
    formal::components::validate_component_contracts(&fixtures, &contracts)?;

    let precondition = match args.scope {
        Scope::Leafpath => formal::PicusPreconditionKind::InputsPlusLeafPathOnly,
        Scope::PublicZ => formal::PicusPreconditionKind::InputsOnly,
    };

    println!("Exporting {} component fixture(s)", fixtures.len());
    println!("- Scope: {:?}", args.scope);
    println!("- Simplify: {:?}", args.simplify);
    if args.output_prefix_len > 0 {
        println!("- Output prefix len: {}", args.output_prefix_len);
    } else {
        println!("- Output scope: full");
    }

    for fixture in fixtures {
        let output = formal::export_fixture_for_picus_verify(
            &fixture,
            &args.artifacts_dir,
            if args.output_prefix_len == 0 {
                None
            } else {
                Some(args.output_prefix_len)
            },
            precondition,
        )?;

        println!("- {}", output.fixture_id);
        println!("  artifact dir: {}", output.artifact_dir.display());
        println!("  circuit.r1cs: {}", output.picus_input_path.display());
        if let Some(pre) = &output.picus_precondition_path {
            println!("  picus-precondition.json: {}", pre.display());
        }
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
