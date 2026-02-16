use clap::{ArgAction, Parser, ValueEnum};
use kontor_crypto::formal;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::io::{self, Read};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread::{self, JoinHandle};
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
#[command(about = "Run Picus determinism verification over formal fixtures")]
struct Args {
    /// Run all fixtures listed in manifest
    #[arg(long)]
    all: bool,

    /// Fixture IDs to run (ignored when --all is set)
    #[arg(long = "fixture")]
    fixtures: Vec<String>,

    /// Path to fixture manifest
    #[arg(long, default_value = "tools/picus/components/manifest.json")]
    manifest: PathBuf,

    /// Directory containing fixture json files
    #[arg(long, default_value = "tools/picus/components/fixtures")]
    fixtures_dir: PathBuf,

    /// Path to component contracts file (used when selected fixtures include component circuits)
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

    /// Ignore fixture-level verification policy and use CLI values only
    #[arg(long)]
    ignore_fixture_policy: bool,

    /// Allow inconclusive fixtures without failing process exit code
    #[arg(long)]
    allow_inconclusive: bool,

    /// Output summary json path
    #[arg(long)]
    summary_json: Option<PathBuf>,

    /// Output summary markdown path
    #[arg(long)]
    summary_md: Option<PathBuf>,
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
    solver_trace: Vec<String>,
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
    let summary_json = args
        .summary_json
        .clone()
        .unwrap_or_else(|| args.artifacts_dir.join("summary.json"));
    let summary_md = args
        .summary_md
        .clone()
        .unwrap_or_else(|| args.artifacts_dir.join("summary.md"));

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

    if let Some(parent) = summary_json.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            kontor_crypto::KontorPoRError::IO(format!(
                "Failed to create summary dir {}: {}",
                parent.display(),
                e
            ))
        })?;
    }
    if let Some(parent) = summary_md.parent() {
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
                solver_trace: Vec::new(),
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
    write_json(&summary_json, &report)?;
    write_markdown(&summary_md, &report)?;

    println!("Summary json: {}", summary_json.display());
    println!("Summary md: {}", summary_md.display());

    if report.error > 0 || (report.inconclusive > 0 && !args.allow_inconclusive) {
        return Err(kontor_crypto::KontorPoRError::InvalidInput(
            "Formal verification did not pass for all fixtures".to_string(),
        ));
    }

    Ok(())
}

#[derive(Debug, Clone)]
struct ResolvedFixturePolicy {
    scope: Scope,
    output_prefix_len: usize,
    timeout_secs: u64,
    hard_timeout_grace_secs: u64,
    solver_chain: Vec<String>,
}

fn resolve_fixture_policy(args: &Args, fixture: &formal::FormalFixture) -> ResolvedFixturePolicy {
    let scope = if args.ignore_fixture_policy {
        args.scope
    } else {
        match fixture.verification.scope {
            Some(formal::VerificationScope::Leafpath) => Scope::Leafpath,
            Some(formal::VerificationScope::PublicZ) => Scope::PublicZ,
            None => args.scope,
        }
    };

    let output_prefix_len = if args.ignore_fixture_policy {
        args.output_prefix_len
    } else {
        fixture
            .verification
            .output_prefix_len
            .unwrap_or(args.output_prefix_len)
    };

    let timeout_secs = if args.ignore_fixture_policy {
        args.timeout_secs
    } else {
        fixture
            .verification
            .timeout_secs
            .unwrap_or(args.timeout_secs)
    };
    let hard_timeout_grace_secs = if args.ignore_fixture_policy {
        args.hard_timeout_grace_secs
    } else {
        fixture
            .verification
            .hard_timeout_grace_secs
            .unwrap_or(args.hard_timeout_grace_secs)
    };

    let mut solver_chain = Vec::<String>::new();
    if args.ignore_fixture_policy {
        solver_chain.push(args.solver.clone());
    } else if let Some(policy) = fixture.verification.solver_policy.as_ref() {
        solver_chain.push(policy.primary.clone());
        solver_chain.extend(policy.fallbacks.iter().cloned());
    } else {
        solver_chain.push(args.solver.clone());
    }
    if fixture.expected_result == formal::ExpectedPicusResult::Unsafe
        && !solver_chain.iter().any(|s| s.eq_ignore_ascii_case("z3"))
    {
        solver_chain.push("z3".to_string());
    }
    let mut unique_chain = Vec::<String>::new();
    for solver in solver_chain {
        if !unique_chain
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(&solver))
        {
            unique_chain.push(solver);
        }
    }

    ResolvedFixturePolicy {
        scope,
        output_prefix_len,
        timeout_secs,
        hard_timeout_grace_secs,
        solver_chain: unique_chain,
    }
}

fn run_fixture(
    args: &Args,
    fixture: &formal::FormalFixture,
    start: Instant,
) -> kontor_crypto::Result<FixtureSummary> {
    let policy = resolve_fixture_policy(args, fixture);

    let pre = match policy.scope {
        Scope::Leafpath => formal::PicusPreconditionKind::InputsPlusLeafPathOnly,
        Scope::PublicZ => formal::PicusPreconditionKind::InputsOnly,
    };

    let exported = formal::export_fixture_for_picus_verify(
        fixture,
        &args.artifacts_dir,
        if policy.output_prefix_len == 0 {
            None
        } else {
            Some(policy.output_prefix_len)
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
            solver_trace: policy.solver_chain,
            artifact_dir: exported.artifact_dir.display().to_string(),
            picus_input: None,
            picus_json: None,
            reason: "Missing exported Picus input".to_string(),
            stdout: String::new(),
            stderr: String::new(),
        });
    }

    let mut runs = Vec::<PicusRunOutcome>::new();
    for (idx, solver) in policy.solver_chain.iter().enumerate() {
        let solver_json_path = if idx == 0 {
            picus_json_path.clone()
        } else {
            exported
                .artifact_dir
                .join(format!("picus-result-{}.json", solver.to_ascii_lowercase()))
        };
        let run = run_picus_once(
            args,
            &exported,
            &picus_input_path,
            &solver_json_path,
            solver,
            policy.timeout_secs,
            policy.hard_timeout_grace_secs,
        )?;
        let stop = match fixture.expected_result {
            formal::ExpectedPicusResult::Safe => {
                run.status == FixtureStatus::Pass || run.status == FixtureStatus::Violation
            }
            formal::ExpectedPicusResult::Unsafe => run.status == FixtureStatus::Violation,
        };
        runs.push(run);
        if stop {
            break;
        }
    }
    let run = select_final_run(fixture, &runs).ok_or_else(|| {
        kontor_crypto::KontorPoRError::InvalidInput(format!(
            "No Picus runs recorded for fixture {}",
            fixture.fixture_id
        ))
    })?;

    let runtime_ms = start.elapsed().as_millis();
    let solver_trace = runs
        .iter()
        .map(|r| format!("{}={:?}", r.solver, r.status))
        .collect::<Vec<_>>();
    let (status, reason) = enforce_expected_result(
        fixture,
        run.status.clone(),
        run.reason.clone(),
        args.allow_inconclusive,
    );

    Ok(FixtureSummary {
        fixture_id: fixture.fixture_id.clone(),
        circuit_kind: fixture.circuit_kind.clone(),
        expected_result: fixture.expected_result.clone(),
        status,
        runtime_ms,
        solver_trace,
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

#[derive(Debug, Clone)]
struct PicusRunOutcome {
    solver: String,
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
    timeout_secs: u64,
    hard_timeout_grace_secs: u64,
) -> kontor_crypto::Result<PicusRunOutcome> {
    let mut cmd = Command::new(&args.picus_bin);
    cmd.arg("--json")
        .arg(picus_json_path)
        .arg("--timeout")
        .arg((timeout_secs.saturating_mul(1000)).to_string())
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

    let hard_timeout = Duration::from_secs(timeout_secs.saturating_add(hard_timeout_grace_secs));
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
                timeout_secs, hard_timeout_grace_secs, solver
            ),
        ),
    };

    Ok(PicusRunOutcome {
        solver: solver.to_string(),
        status,
        reason: format!("{reason} [solver={solver}]"),
        stdout,
        stderr,
        json_path: picus_json_path.to_path_buf(),
    })
}

fn select_final_run(
    fixture: &formal::FormalFixture,
    runs: &[PicusRunOutcome],
) -> Option<PicusRunOutcome> {
    if runs.is_empty() {
        return None;
    }

    let expected = expected_fixture_status(&fixture.expected_result);
    if let Some(r) = runs.iter().find(|r| r.status == expected) {
        return Some(r.clone());
    }
    if let Some(r) = runs.iter().find(|r| r.status == FixtureStatus::Violation) {
        return Some(r.clone());
    }
    if let Some(r) = runs.iter().find(|r| r.status == FixtureStatus::Pass) {
        return Some(r.clone());
    }
    if let Some(r) = runs.iter().find(|r| r.status == FixtureStatus::Error) {
        return Some(r.clone());
    }
    runs.last().cloned()
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
    allow_inconclusive: bool,
) -> (FixtureStatus, String) {
    if observed_status == FixtureStatus::Inconclusive && allow_inconclusive {
        return (observed_status, observed_reason);
    }
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

            if res.contains("unsafe") {
                return Ok((
                    FixtureStatus::Violation,
                    format!("Classified from {}", picus_json_path.display()),
                ));
            }
            if res.contains("safe") {
                return Ok((
                    FixtureStatus::Pass,
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
        if msgs.contains("not properly constrained")
            || msgs.contains("underconstrained")
            || msgs.contains("exiting picus with the code 9")
        {
            return Ok((
                FixtureStatus::Violation,
                format!("Classified from NDJSON {}", picus_json_path.display()),
            ));
        }
        if msgs.contains("properly constrained") || msgs.contains("exiting picus with the code 8") {
            return Ok((
                FixtureStatus::Pass,
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
    if merged.contains("unsafe") {
        return Ok((
            FixtureStatus::Violation,
            "Classified from process output".to_string(),
        ));
    }
    if merged.contains("safe") {
        return Ok((
            FixtureStatus::Pass,
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

fn spawn_pipe_drain_thread<R: Read + Send + 'static>(
    mut reader: R,
) -> JoinHandle<io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        Ok(buf)
    })
}

fn join_pipe_drain_thread(
    handle: JoinHandle<io::Result<Vec<u8>>>,
    stream_name: &str,
) -> kontor_crypto::Result<Vec<u8>> {
    let joined = handle.join().map_err(|_| {
        kontor_crypto::KontorPoRError::IO(format!("Picus {stream_name} drain thread panicked"))
    })?;
    joined.map_err(|e| {
        kontor_crypto::KontorPoRError::IO(format!("Failed to drain Picus {stream_name}: {e}"))
    })
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

    let stdout_reader = child.stdout.take().ok_or_else(|| {
        kontor_crypto::KontorPoRError::IO("Failed to capture Picus stdout".to_string())
    })?;
    let stderr_reader = child.stderr.take().ok_or_else(|| {
        kontor_crypto::KontorPoRError::IO("Failed to capture Picus stderr".to_string())
    })?;
    let mut stdout_handle = Some(spawn_pipe_drain_thread(stdout_reader));
    let mut stderr_handle = Some(spawn_pipe_drain_thread(stderr_reader));

    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = join_pipe_drain_thread(
                    stdout_handle
                        .take()
                        .expect("stdout drain handle must be present"),
                    "stdout",
                )?;
                let stderr = join_pipe_drain_thread(
                    stderr_handle
                        .take()
                        .expect("stderr drain handle must be present"),
                    "stderr",
                )?;
                let output = Output {
                    status,
                    stdout,
                    stderr,
                };
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
                    if let Some(handle) = stdout_handle.take() {
                        let _ = join_pipe_drain_thread(handle, "stdout");
                    }
                    if let Some(handle) = stderr_handle.take() {
                        let _ = join_pipe_drain_thread(handle, "stderr");
                    }
                    return Ok(ProcessRunResult::TimedOut);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                if let Some(handle) = stdout_handle.take() {
                    let _ = join_pipe_drain_thread(handle, "stdout");
                }
                if let Some(handle) = stderr_handle.take() {
                    let _ = join_pipe_drain_thread(handle, "stderr");
                }
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
    out.push_str("# Picus Determinism Summary\n\n");
    out.push_str(&format!("- Fixtures: {}\n", report.fixtures_total));
    out.push_str(&format!("- Pass: {}\n", report.pass));
    out.push_str(&format!("- Violation: {}\n", report.violation));
    out.push_str(&format!("- Inconclusive: {}\n", report.inconclusive));
    out.push_str(&format!("- Error: {}\n\n", report.error));

    out.push_str(
        "| Fixture | Circuit Kind | Expected | Status | Runtime (ms) | Solvers | Reason |\n",
    );
    out.push_str("|---|---|---|---|---:|---|---|\n");
    for result in &report.results {
        out.push_str(&format!(
            "| {} | {:?} | {:?} | {:?} | {} | {} | {} |\n",
            result.fixture_id,
            result.circuit_kind,
            result.expected_result,
            result.status,
            result.runtime_ms,
            result.solver_trace.join(", ").replace('|', "\\|"),
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

#[cfg(test)]
mod tests {
    use super::{classify_picus_result, FixtureStatus};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_json_path(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("picus-verify-{name}-{stamp}.json"))
    }

    #[test]
    fn classify_json_unsafe_not_misread_as_safe() {
        let path = temp_json_path("unsafe");
        fs::write(&path, r#"{"result":"unsafe"}"#).expect("write test json");
        let (status, _) = classify_picus_result(Some(9), &path, "", "").expect("classify");
        let _ = fs::remove_file(&path);
        assert_eq!(status, FixtureStatus::Violation);
    }

    #[test]
    fn classify_ndjson_not_properly_constrained_as_violation() {
        let path = temp_json_path("ndjson");
        fs::write(
            &path,
            r#"{"msg":"The circuit is not properly constrained"}"#,
        )
        .expect("write test ndjson");
        let (status, _) = classify_picus_result(Some(9), &path, "", "").expect("classify");
        let _ = fs::remove_file(&path);
        assert_eq!(status, FixtureStatus::Violation);
    }
}
