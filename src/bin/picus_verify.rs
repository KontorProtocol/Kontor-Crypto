use clap::{ArgAction, Parser, ValueEnum};
use kontor_crypto::formal;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::io;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

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
#[command(name = "picus_verify")]
#[command(about = "Run component-first Picus determinism verification")]
struct Args {
    /// Run all fixtures listed in manifest
    #[arg(long)]
    all: bool,

    /// Fixture IDs to run (ignored when --all is set)
    #[arg(long = "fixture")]
    fixtures: Vec<String>,

    /// Path to component fixture manifest
    #[arg(long, default_value = "tools/picus/components/manifest.json")]
    manifest: PathBuf,

    /// Directory containing component fixture json files
    #[arg(long, default_value = "tools/picus/components/fixtures")]
    fixtures_dir: PathBuf,

    /// Path to component contracts file
    #[arg(long, default_value = "tools/picus/components/contracts.json")]
    contracts: PathBuf,

    /// Artifact output root
    #[arg(long, default_value = "artifacts/picus-components")]
    artifacts_dir: PathBuf,

    /// Picus executable name/path
    #[arg(long, default_value = "run-picus")]
    picus_bin: String,

    /// Picus timeout in seconds
    #[arg(long, default_value_t = 1200)]
    timeout_secs: u64,

    /// Extra grace added to timeout-secs before force-killing Picus process
    #[arg(long, default_value_t = 120)]
    hard_timeout_grace_secs: u64,

    /// Optional Picus model override (qf_nra | qf_bv | qf_lia)
    #[arg(long)]
    model: Option<String>,

    /// Optional Picus solver override (cvc4 | cvc5 | z3)
    #[arg(long, default_value = "cvc5")]
    solver: String,

    /// Optional Picus selector override (counter | first)
    #[arg(long)]
    picus_selector: Option<String>,

    /// Disable Picus propagation phase
    #[arg(long)]
    picus_noprop: bool,

    /// Optional Picus log level (PROGRESS | INFO | DEBUG | ...)
    #[arg(long, default_value = "PROGRESS")]
    picus_log_level: String,

    /// Optional output prefix length (0 = full outputs)
    #[arg(long, default_value_t = 0)]
    output_prefix_len: usize,

    /// Determinism scope
    #[arg(long, value_enum, default_value_t = Scope::Leafpath)]
    scope: Scope,

    /// R1CS simplification mode
    #[arg(long, value_enum, default_value_t = SimplifyMode::Safe)]
    simplify: SimplifyMode,

    /// Enforce strict leafpath scope (fail instead of silently falling back to input-only)
    #[arg(long, default_value_t = true, action = ArgAction::Set)]
    strict_scope: bool,

    /// Allow inconclusive fixtures without failing process exit code
    #[arg(long)]
    allow_inconclusive: bool,

    /// Output summary json path
    #[arg(long, default_value = "artifacts/picus-components/summary.json")]
    summary_json: PathBuf,

    /// Output summary markdown path
    #[arg(long, default_value = "artifacts/picus-components/summary.md")]
    summary_md: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum FixtureStatus {
    Pass,
    Violation,
    Inconclusive,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FixtureSummary {
    fixture_id: String,
    circuit_kind: formal::CircuitKind,
    expected_result: formal::ExpectedPicusResult,
    status: FixtureStatus,
    runtime_ms: u128,
    artifact_dir: String,
    picus_input: Option<String>,
    picus_json: Option<String>,
    reason: String,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SummaryReport {
    fixtures_total: usize,
    pass: usize,
    violation: usize,
    inconclusive: usize,
    error: usize,
    results: Vec<FixtureSummary>,
}

fn main() {
    let args = Args::parse();
    if let Err(err) = run(args) {
        eprintln!("picus_verify failed: {}", err);
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

    let contracts = formal::components::load_component_contracts(&args.contracts)?;
    formal::components::validate_component_contracts(&fixtures, &contracts)?;

    if let Some(parent) = args.summary_json.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            kontor_crypto::KontorPoRError::IO(format!(
                "Failed to create summary dir {}: {}",
                parent.display(),
                e
            ))
        })?;
    }
    if let Some(parent) = args.summary_md.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            kontor_crypto::KontorPoRError::IO(format!(
                "Failed to create summary dir {}: {}",
                parent.display(),
                e
            ))
        })?;
    }

    let mut results = Vec::with_capacity(fixtures.len());
    for fixture in &fixtures {
        let start = Instant::now();
        let summary = match run_fixture(&args, fixture, start) {
            Ok(summary) => summary,
            Err(err) => FixtureSummary {
                fixture_id: fixture.fixture_id.clone(),
                circuit_kind: fixture.circuit_kind.clone(),
                expected_result: fixture.expected_result.clone(),
                status: FixtureStatus::Error,
                runtime_ms: start.elapsed().as_millis(),
                artifact_dir: String::new(),
                picus_input: None,
                picus_json: None,
                reason: err.to_string(),
                stdout: String::new(),
                stderr: String::new(),
            },
        };
        println!(
            "{} ({:?}) => {:?}",
            summary.fixture_id, summary.circuit_kind, summary.status
        );
        results.push(summary);
    }

    let report = build_report(results);
    write_json(&args.summary_json, &report)?;
    write_markdown(&args.summary_md, &report)?;

    println!("Summary json: {}", args.summary_json.display());
    println!("Summary md: {}", args.summary_md.display());

    if report.error > 0 || (report.inconclusive > 0 && !args.allow_inconclusive) {
        return Err(kontor_crypto::KontorPoRError::InvalidInput(
            "Formal verification did not pass for all fixtures".to_string(),
        ));
    }

    Ok(())
}

fn run_fixture(
    args: &Args,
    fixture: &formal::FormalFixture,
    start: Instant,
) -> kontor_crypto::Result<FixtureSummary> {
    let pre = match args.scope {
        Scope::Leafpath => formal::PicusPreconditionKind::InputsPlusLeafPathOnly,
        Scope::PublicZ => formal::PicusPreconditionKind::InputsOnly,
    };

    let exported = formal::export_fixture_for_picus_verify(
        fixture,
        &args.artifacts_dir,
        if args.output_prefix_len == 0 {
            None
        } else {
            Some(args.output_prefix_len)
        },
        pre,
    )?;

    let picus_json_path = exported.artifact_dir.join("picus-result.json");
    let picus_input_path = exported.picus_input_path.clone();
    if !picus_input_path.exists() {
        return Ok(FixtureSummary {
            fixture_id: fixture.fixture_id.clone(),
            circuit_kind: fixture.circuit_kind.clone(),
            expected_result: fixture.expected_result.clone(),
            status: FixtureStatus::Error,
            runtime_ms: start.elapsed().as_millis(),
            artifact_dir: exported.artifact_dir.display().to_string(),
            picus_input: None,
            picus_json: None,
            reason: "Missing exported Picus input".to_string(),
            stdout: String::new(),
            stderr: String::new(),
        });
    }

    let mut run = run_picus_once(
        args,
        &exported,
        &picus_input_path,
        &picus_json_path,
        &args.solver,
    )?;

    // cvc5 often struggles to produce concrete counterexamples for deliberately
    // underconstrained mutants. Retry expected-unsafe fixtures with z3 for robust
    // mutation checking without changing the default solver for normal fixtures.
    if fixture.expected_result == formal::ExpectedPicusResult::Unsafe
        && run.status != FixtureStatus::Violation
        && !args.solver.eq_ignore_ascii_case("z3")
    {
        let z3_json_path = exported.artifact_dir.join("picus-result-z3.json");
        let z3_run = run_picus_once(args, &exported, &picus_input_path, &z3_json_path, "z3")?;
        if z3_run.status == FixtureStatus::Violation {
            run = z3_run;
        } else {
            run.reason = format!("{}; z3 retry: {}", run.reason, z3_run.reason);
            if !z3_run.stdout.is_empty() {
                run.stdout = format!("{}\n\n[z3 retry]\n{}", run.stdout, z3_run.stdout);
            }
            if !z3_run.stderr.is_empty() {
                run.stderr = format!("{}\n\n[z3 retry]\n{}", run.stderr, z3_run.stderr);
            }
        }
    }

    let runtime_ms = start.elapsed().as_millis();
    let (status, reason) = enforce_expected_result(fixture, run.status, run.reason);

    Ok(FixtureSummary {
        fixture_id: fixture.fixture_id.clone(),
        circuit_kind: fixture.circuit_kind.clone(),
        expected_result: fixture.expected_result.clone(),
        status,
        runtime_ms,
        artifact_dir: exported.artifact_dir.display().to_string(),
        picus_input: Some(picus_input_path.display().to_string()),
        picus_json: if run.json_path.exists() {
            Some(run.json_path.display().to_string())
        } else {
            None
        },
        reason,
        stdout: truncate_text(&run.stdout, 6000),
        stderr: truncate_text(&run.stderr, 6000),
    })
}

struct PicusRunOutcome {
    status: FixtureStatus,
    reason: String,
    stdout: String,
    stderr: String,
    json_path: PathBuf,
}

fn run_picus_once(
    args: &Args,
    exported: &formal::ExportOutput,
    picus_input_path: &Path,
    picus_json_path: &Path,
    solver: &str,
) -> kontor_crypto::Result<PicusRunOutcome> {
    let mut cmd = Command::new(&args.picus_bin);
    cmd.arg("--json")
        .arg(picus_json_path)
        .arg("--timeout")
        .arg((args.timeout_secs.saturating_mul(1000)).to_string())
        .arg("--solver")
        .arg(solver)
        .arg("--log-level")
        .arg(&args.picus_log_level);

    if let Some(selector) = &args.picus_selector {
        cmd.arg("--selector").arg(selector);
    }
    if args.picus_noprop {
        cmd.arg("--noprop");
    }
    if let Some(model) = &args.model {
        cmd.arg("--model").arg(model);
    }
    if let Some(pre_path) = &exported.picus_precondition_path {
        cmd.arg("--precondition").arg(pre_path);
    }
    cmd.arg(picus_input_path);

    let hard_timeout = Duration::from_secs(
        args.timeout_secs
            .saturating_add(args.hard_timeout_grace_secs),
    );
    let process_result = run_with_hard_timeout(cmd, hard_timeout)?;
    let (stdout, stderr, status, reason) = match process_result {
        ProcessRunResult::Completed(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let (status, reason) =
                classify_picus_result(output.status.code(), picus_json_path, &stdout, &stderr)?;
            (stdout, stderr, status, reason)
        }
        ProcessRunResult::TimedOut => (
            String::new(),
            String::new(),
            FixtureStatus::Inconclusive,
            format!(
                "Picus hard timeout exceeded ({}s + {}s grace) using solver {}",
                args.timeout_secs, args.hard_timeout_grace_secs, solver
            ),
        ),
    };

    Ok(PicusRunOutcome {
        status,
        reason: format!("{reason} [solver={solver}]"),
        stdout,
        stderr,
        json_path: picus_json_path.to_path_buf(),
    })
}

fn expected_fixture_status(expected: &formal::ExpectedPicusResult) -> FixtureStatus {
    match expected {
        formal::ExpectedPicusResult::Safe => FixtureStatus::Pass,
        formal::ExpectedPicusResult::Unsafe => FixtureStatus::Violation,
    }
}

fn enforce_expected_result(
    fixture: &formal::FormalFixture,
    observed_status: FixtureStatus,
    observed_reason: String,
) -> (FixtureStatus, String) {
    let expected_status = expected_fixture_status(&fixture.expected_result);
    if observed_status == expected_status {
        return (observed_status, observed_reason);
    }

    (
        FixtureStatus::Error,
        format!(
            "Expected {:?} for fixture {}, got {:?} ({})",
            expected_status, fixture.fixture_id, observed_status, observed_reason
        ),
    )
}

fn classify_picus_result(
    exit_code: Option<i32>,
    picus_json_path: &Path,
    stdout: &str,
    stderr: &str,
) -> kontor_crypto::Result<(FixtureStatus, String)> {
    if picus_json_path.exists() {
        let raw = fs::read_to_string(picus_json_path).map_err(|e| {
            kontor_crypto::KontorPoRError::IO(format!(
                "Failed to read {}: {}",
                picus_json_path.display(),
                e
            ))
        })?;

        if let Ok(value) = serde_json::from_str::<Value>(&raw) {
            let res = value
                .get("result")
                .or_else(|| value.get("status"))
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_ascii_lowercase();

            if res.contains("safe") {
                return Ok((
                    FixtureStatus::Pass,
                    format!("Classified from {}", picus_json_path.display()),
                ));
            }
            if res.contains("unsafe") {
                return Ok((
                    FixtureStatus::Violation,
                    format!("Classified from {}", picus_json_path.display()),
                ));
            }
            if res.contains("unknown") {
                return Ok((
                    FixtureStatus::Inconclusive,
                    format!("Classified from {}", picus_json_path.display()),
                ));
            }
        }

        // Picus often emits NDJSON logs where result is encoded in `msg`.
        let mut merged_msgs = String::new();
        for line in raw.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<Value>(line) {
                if let Some(msg) = v.get("msg").and_then(|m| m.as_str()) {
                    merged_msgs.push_str(msg);
                    merged_msgs.push('\n');
                }
            }
        }
        let msgs = merged_msgs.to_ascii_lowercase();
        if msgs.contains("properly constrained") || msgs.contains("exiting picus with the code 8") {
            return Ok((
                FixtureStatus::Pass,
                format!("Classified from NDJSON {}", picus_json_path.display()),
            ));
        }
        if msgs.contains("not properly constrained")
            || msgs.contains("underconstrained")
            || msgs.contains("exiting picus with the code 9")
        {
            return Ok((
                FixtureStatus::Violation,
                format!("Classified from NDJSON {}", picus_json_path.display()),
            ));
        }
        if msgs.contains("cannot determine")
            || msgs.contains("unknown")
            || msgs.contains("timeout")
            || msgs.contains("exiting picus with the code 0")
        {
            return Ok((
                FixtureStatus::Inconclusive,
                format!("Classified from NDJSON {}", picus_json_path.display()),
            ));
        }
    }

    let merged = format!("{stdout}\n{stderr}").to_ascii_lowercase();
    if merged.contains("safe") {
        return Ok((
            FixtureStatus::Pass,
            "Classified from process output".to_string(),
        ));
    }
    if merged.contains("unsafe") {
        return Ok((
            FixtureStatus::Violation,
            "Classified from process output".to_string(),
        ));
    }
    if merged.contains("unknown") || merged.contains("timeout") {
        return Ok((
            FixtureStatus::Inconclusive,
            "Classified from process output".to_string(),
        ));
    }

    match exit_code {
        Some(8) => Ok((
            FixtureStatus::Pass,
            "Classified from Picus exit code 8".to_string(),
        )),
        Some(9) => Ok((
            FixtureStatus::Violation,
            "Classified from Picus exit code 9".to_string(),
        )),
        Some(0) => Ok((
            FixtureStatus::Inconclusive,
            "Classified from Picus exit code 0".to_string(),
        )),
        Some(code) => Ok((
            FixtureStatus::Error,
            format!("Picus exited with unexpected status {code}"),
        )),
        None => Ok((
            FixtureStatus::Error,
            "Picus terminated without a status code".to_string(),
        )),
    }
}

#[derive(Debug)]
enum ProcessRunResult {
    Completed(Output),
    TimedOut,
}

fn run_with_hard_timeout(
    mut cmd: Command,
    hard_timeout: Duration,
) -> kontor_crypto::Result<ProcessRunResult> {
    #[cfg(unix)]
    unsafe {
        cmd.pre_exec(|| {
            if libc::setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        });
    }

    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| kontor_crypto::KontorPoRError::IO(format!("Failed to spawn Picus: {e}")))?;

    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                let output = child.wait_with_output().map_err(|e| {
                    kontor_crypto::KontorPoRError::IO(format!(
                        "Failed to collect Picus output: {e}"
                    ))
                })?;
                return Ok(ProcessRunResult::Completed(output));
            }
            Ok(None) => {
                if started.elapsed() >= hard_timeout {
                    #[cfg(unix)]
                    {
                        let pgid = child.id() as i32;
                        let _ = unsafe { libc::kill(-pgid, libc::SIGKILL) };
                    }
                    let _ = child.kill();
                    let _ = child.wait();
                    return Ok(ProcessRunResult::TimedOut);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                return Err(kontor_crypto::KontorPoRError::IO(format!(
                    "Failed while waiting for Picus process: {e}"
                )));
            }
        }
    }
}

fn resolve_fixture_ids(args: &Args) -> kontor_crypto::Result<Vec<String>> {
    if args.all {
        let manifest = formal::load_manifest(&args.manifest)?;
        return Ok(manifest.fixtures);
    }
    Ok(args.fixtures.clone())
}

fn build_report(results: Vec<FixtureSummary>) -> SummaryReport {
    let mut report = SummaryReport {
        fixtures_total: results.len(),
        pass: 0,
        violation: 0,
        inconclusive: 0,
        error: 0,
        results,
    };

    for result in &report.results {
        match result.status {
            FixtureStatus::Pass => report.pass += 1,
            FixtureStatus::Violation => report.violation += 1,
            FixtureStatus::Inconclusive => report.inconclusive += 1,
            FixtureStatus::Error => report.error += 1,
        }
    }
    report
}

fn write_json(path: &Path, report: &SummaryReport) -> kontor_crypto::Result<()> {
    let data = serde_json::to_string_pretty(report).map_err(|e| {
        kontor_crypto::KontorPoRError::Serialization(format!(
            "Failed to encode {}: {}",
            path.display(),
            e
        ))
    })?;
    fs::write(path, data).map_err(|e| {
        kontor_crypto::KontorPoRError::IO(format!("Failed to write {}: {}", path.display(), e))
    })
}

fn write_markdown(path: &Path, report: &SummaryReport) -> kontor_crypto::Result<()> {
    let mut out = String::new();
    out.push_str("# Picus Component Determinism Summary\n\n");
    out.push_str(&format!("- Fixtures: {}\n", report.fixtures_total));
    out.push_str(&format!("- Pass: {}\n", report.pass));
    out.push_str(&format!("- Violation: {}\n", report.violation));
    out.push_str(&format!("- Inconclusive: {}\n", report.inconclusive));
    out.push_str(&format!("- Error: {}\n\n", report.error));

    out.push_str("| Fixture | Circuit Kind | Expected | Status | Runtime (ms) | Reason |\n");
    out.push_str("|---|---|---|---|---:|---|\n");
    for result in &report.results {
        out.push_str(&format!(
            "| {} | {:?} | {:?} | {:?} | {} | {} |\n",
            result.fixture_id,
            result.circuit_kind,
            result.expected_result,
            result.status,
            result.runtime_ms,
            result.reason.replace('|', "\\|")
        ));
    }

    fs::write(path, out).map_err(|e| {
        kontor_crypto::KontorPoRError::IO(format!("Failed to write {}: {}", path.display(), e))
    })
}

fn truncate_text(input: &str, max_len: usize) -> String {
    if input.len() <= max_len {
        return input.to_string();
    }
    let mut end = max_len.min(input.len());
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    if end == 0 {
        return "...".to_string();
    }
    format!("{}...", &input[..end])
}
