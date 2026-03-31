use clap::{ArgAction, Parser, ValueEnum};
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

    /// Path to fixture manifest file
    #[arg(long, default_value = "tools/picus/components/manifest.json")]
    manifest: PathBuf,

    /// Directory containing fixture JSON definitions
    #[arg(long, default_value = "tools/picus/components/fixtures")]
    fixtures_dir: PathBuf,

    /// Path to component contracts file (used when selected fixtures include component circuits)
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

    /// Enforce strict leafpath scope (fail instead of silently falling back to input-only)
    #[arg(long, default_value_t = true, action = ArgAction::Set)]
    strict_scope: bool,

    /// Ignore fixture-level verification policy and use CLI values only
    #[arg(long)]
    ignore_fixture_policy: bool,
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
    std::env::set_var(
        "KONTOR_PICUS_STRICT_SCOPE",
        if args.strict_scope { "true" } else { "false" },
    );

    let mut fixtures = Vec::with_capacity(fixture_ids.len());
    for fixture_id in fixture_ids {
        fixtures.push(formal::load_fixture(&args.fixtures_dir, &fixture_id)?);
    }

    let component_fixtures = fixtures
        .iter()
        .filter(|f| f.circuit_kind.is_component())
        .cloned()
        .collect::<Vec<_>>();
    if !component_fixtures.is_empty() {
        let contracts = formal::components::load_component_contracts(&args.contracts)?;
        formal::components::validate_component_contracts(&component_fixtures, &contracts)?;
    }

    println!("Exporting {} fixture(s)", fixtures.len());
    println!("- Scope: {:?}", args.scope);
    println!("- Simplify: {:?}", args.simplify);
    println!("- Strict scope: {}", args.strict_scope);
    println!("- Ignore fixture policy: {}", args.ignore_fixture_policy);
    if args.output_prefix_len > 0 {
        println!("- Output prefix len: {}", args.output_prefix_len);
    } else {
        println!("- Output scope: full");
    }

    for fixture in fixtures {
        let scope = resolve_fixture_scope(args.scope, args.ignore_fixture_policy, &fixture);
        let output_prefix_len =
            resolve_output_prefix_len(args.output_prefix_len, args.ignore_fixture_policy, &fixture);
        let precondition = match scope {
            Scope::Leafpath => formal::PicusPreconditionKind::InputsPlusLeafPathOnly,
            Scope::PublicZ => formal::PicusPreconditionKind::InputsOnly,
        };
        let output = formal::export_fixture_for_picus_verify(
            &fixture,
            &args.artifacts_dir,
            if output_prefix_len == 0 {
                None
            } else {
                Some(output_prefix_len)
            },
            precondition,
        )?;

        println!("- {}", output.fixture_id);
        println!("  scope: {:?}", scope);
        if output_prefix_len > 0 {
            println!("  output prefix len: {}", output_prefix_len);
        } else {
            println!("  output scope: full");
        }
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

fn resolve_fixture_scope(
    cli_scope: Scope,
    ignore_fixture_policy: bool,
    fixture: &formal::FormalFixture,
) -> Scope {
    if ignore_fixture_policy {
        return cli_scope;
    }

    match fixture.verification.scope {
        Some(formal::VerificationScope::Leafpath) => Scope::Leafpath,
        Some(formal::VerificationScope::PublicZ) => Scope::PublicZ,
        None => cli_scope,
    }
}

fn resolve_output_prefix_len(
    cli_output_prefix_len: usize,
    ignore_fixture_policy: bool,
    fixture: &formal::FormalFixture,
) -> usize {
    if ignore_fixture_policy {
        return cli_output_prefix_len;
    }
    fixture
        .verification
        .output_prefix_len
        .unwrap_or(cli_output_prefix_len)
}
