use clap::Parser;
use kontor_crypto::formal;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};
#[cfg(unix)]
use std::os::unix::process::CommandExt;

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
    #[arg(long, default_value = "tools/picus/manifest.json")]
    manifest: PathBuf,

    /// Directory containing fixture json files
    #[arg(long, default_value = "tools/picus/fixtures")]
    fixtures_dir: PathBuf,

    /// Artifact output root
    #[arg(long, default_value = "artifacts/picus")]
    artifacts_dir: PathBuf,

    /// Picus executable name/path
    #[arg(long, default_value = "run-picus")]
    picus_bin: String,

    /// Optional converter executable converting Nova shape.bin to Picus .r1cs
    /// The command is invoked as: <converter-bin> <shape.bin> <circuit.r1cs>
    #[arg(long)]
    converter_bin: Option<String>,

    /// Picus timeout in seconds
    #[arg(long, default_value_t = 600)]
    timeout_secs: u64,

    /// Extra grace added to timeout-secs before force-killing Picus process
    #[arg(long, default_value_t = 90)]
    hard_timeout_grace_secs: u64,

    /// Optional Picus model override (qf_nra | qf_bv | qf_lia)
    #[arg(long)]
    model: Option<String>,

    /// Optional Picus solver override (cvc4 | cvc5 | z3)
    #[arg(long)]
    solver: Option<String>,

    /// Optional Picus log level (DEBUG | ACCOUNTING | PROGRESS | INFO | WARNING | ERROR | CRITICAL)
    #[arg(long)]
    picus_log_level: Option<String>,

    /// Allow inconclusive fixtures without failing the process exit code
    #[arg(long)]
    allow_inconclusive: bool,

    /// Output summary json path
    #[arg(long, default_value = "artifacts/picus/summary.json")]
    summary_json: PathBuf,

    /// Output summary markdown path
    #[arg(long, default_value = "artifacts/picus/summary.md")]
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
    status: FixtureStatus,
    runtime_ms: u128,
    artifact_dir: String,
    picus_input: Option<String>,
    picus_json: Option<String>,
    converter_used: bool,
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
    // Best-effort drain of stale solver workers from interrupted prior runs.
    cleanup_picus_solver_processes();

    let fixture_ids = resolve_fixture_ids(&args)?;
    if fixture_ids.is_empty() {
        return Err(kontor_crypto::KontorPoRError::InvalidInput(
            "No fixtures selected. Use --all or --fixture <id>".to_string(),
        ));
    }

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

    let converter_bin = args
        .converter_bin
        .clone()
        .or_else(|| std::env::var("PICUS_R1CS_CONVERTER_BIN").ok());

    let mut results = Vec::with_capacity(fixture_ids.len());

    for fixture_id in fixture_ids {
        let start = std::time::Instant::now();

        let summary = match run_fixture(&args, &fixture_id, converter_bin.as_deref(), start) {
            Ok(summary) => summary,
            Err(err) => FixtureSummary {
                fixture_id,
                status: FixtureStatus::Error,
                runtime_ms: start.elapsed().as_millis(),
                artifact_dir: String::new(),
                picus_input: None,
                picus_json: None,
                converter_used: false,
                reason: err.to_string(),
                stdout: String::new(),
                stderr: String::new(),
            },
        };

        println!("{} => {:?}", summary.fixture_id, summary.status);
        results.push(summary);
    }

    let report = build_report(results);
    write_json(&args.summary_json, &report)?;
    write_markdown(&args.summary_md, &report)?;

    println!("Summary json: {}", args.summary_json.display());
    println!("Summary md: {}", args.summary_md.display());

    let has_violation = report.violation > 0;
    let has_error = report.error > 0;
    let has_inconclusive = report.inconclusive > 0;

    if has_violation || has_error || (has_inconclusive && !args.allow_inconclusive) {
        return Err(kontor_crypto::KontorPoRError::InvalidInput(
            "Formal verification did not pass for all fixtures".to_string(),
        ));
    }

    Ok(())
}

fn run_fixture(
    args: &Args,
    fixture_id: &str,
    converter_bin: Option<&str>,
    start: std::time::Instant,
) -> kontor_crypto::Result<FixtureSummary> {
    // Keep fixture runs isolated by clearing stale SMT workers between fixtures.
    cleanup_picus_solver_processes();

    let fixture = formal::load_fixture(&args.fixtures_dir, fixture_id)?;
    let exported = formal::export_fixture(&fixture, &args.artifacts_dir)?;

    let picus_json_path = exported.artifact_dir.join("picus-result.json");
    let mut converter_used = false;

    let picus_input_path = if exported.picus_input_path.exists() {
        Some(exported.picus_input_path.clone())
    } else if let Some(converter) = converter_bin {
        converter_used = true;
        run_converter(converter, &exported.shape_path, &exported.picus_input_path)?;
        if exported.picus_input_path.exists() {
            Some(exported.picus_input_path.clone())
        } else {
            None
        }
    } else {
        None
    };

    let Some(picus_input_path) = picus_input_path else {
        return Ok(FixtureSummary {
            fixture_id: fixture_id.to_string(),
            status: FixtureStatus::Inconclusive,
            runtime_ms: start.elapsed().as_millis(),
            artifact_dir: exported.artifact_dir.display().to_string(),
            picus_input: None,
            picus_json: None,
            converter_used,
            reason: String::from(
                "No Picus-ready .r1cs input found. Provide --converter-bin (or PICUS_R1CS_CONVERTER_BIN) to convert shape.bin into circuit.r1cs.",
            ),
            stdout: String::new(),
            stderr: String::new(),
        });
    };

    let mut cmd = Command::new(&args.picus_bin);
    cmd.arg("--json")
        .arg(&picus_json_path)
        .arg("--timeout")
        .arg((args.timeout_secs.saturating_mul(1000)).to_string());

    if let Some(solver) = &args.solver {
        cmd.arg("--solver").arg(solver);
    }

    if let Some(model) = &args.model {
        cmd.arg("--model").arg(model);
    }

    if let Some(log_level) = &args.picus_log_level {
        cmd.arg("--log-level").arg(log_level);
    }

    // Picus expects options first and source path as the final positional argument.
    cmd.arg(&picus_input_path);

    let hard_timeout = Duration::from_secs(
        args.timeout_secs
            .saturating_add(args.hard_timeout_grace_secs),
    );

    let process_result = match run_with_hard_timeout(cmd, hard_timeout) {
        Ok(output) => output,
        Err(err) => {
            return Ok(FixtureSummary {
                fixture_id: fixture_id.to_string(),
                status: FixtureStatus::Inconclusive,
                runtime_ms: start.elapsed().as_millis(),
                artifact_dir: exported.artifact_dir.display().to_string(),
                picus_input: Some(picus_input_path.display().to_string()),
                picus_json: None,
                converter_used,
                reason: format!("Failed to execute {}: {}", args.picus_bin, err),
                stdout: String::new(),
                stderr: String::new(),
            });
        }
    };

    if matches!(process_result, ProcessRunResult::TimedOut) {
        cleanup_picus_processes_for_fixture(&picus_input_path, &picus_json_path);
        cleanup_picus_solver_processes();
        return Ok(FixtureSummary {
            fixture_id: fixture_id.to_string(),
            status: FixtureStatus::Inconclusive,
            runtime_ms: start.elapsed().as_millis(),
            artifact_dir: exported.artifact_dir.display().to_string(),
            picus_input: Some(picus_input_path.display().to_string()),
            picus_json: if picus_json_path.exists() {
                Some(picus_json_path.display().to_string())
            } else {
                None
            },
            converter_used,
            reason: format!(
                "Picus hard timeout exceeded ({}s + {}s grace); process was terminated",
                args.timeout_secs, args.hard_timeout_grace_secs
            ),
            stdout: String::new(),
            stderr: String::new(),
        });
    }

    let output = match process_result {
        ProcessRunResult::Completed(output) => output,
        ProcessRunResult::TimedOut => unreachable!("timed-out case is handled above"),
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    let (status, reason) =
        classify_picus_result(output.status.success(), &picus_json_path, &stdout, &stderr)?;

    Ok(FixtureSummary {
        fixture_id: fixture_id.to_string(),
        status,
        runtime_ms: start.elapsed().as_millis(),
        artifact_dir: exported.artifact_dir.display().to_string(),
        picus_input: Some(picus_input_path.display().to_string()),
        picus_json: Some(picus_json_path.display().to_string()),
        converter_used,
        reason,
        stdout: truncate_text(&stdout, 2000),
        stderr: truncate_text(&stderr, 2000),
    })
}

fn classify_picus_result(
    command_success: bool,
    picus_json_path: &Path,
    stdout: &str,
    stderr: &str,
) -> kontor_crypto::Result<(FixtureStatus, String)> {
    if picus_json_path.exists() {
        let raw = fs::read_to_string(picus_json_path).map_err(|e| {
            kontor_crypto::KontorPoRError::IO(format!(
                "Failed to read Picus json {}: {}",
                picus_json_path.display(),
                e
            ))
        })?;

        if let Ok(value) = serde_json::from_str::<Value>(&raw) {
            if let Some(status) = infer_status_from_json(&value) {
                let reason = format!("Classified from {}", picus_json_path.display());
                return Ok((status, reason));
            }
        }
    }

    let merged = format!("{}\n{}", stdout.to_lowercase(), stderr.to_lowercase());

    if merged.contains("input annotation file")
        || merged.contains("variant")
        || merged.contains("evidences")
        || merged.contains("picus.picus")
        || merged.contains(".cache/picus/data")
    {
        return Ok((
            FixtureStatus::Error,
            String::from(
                "Detected unrelated PyPI 'picus' package CLI. Use Veridise Picus `run-picus` from https://github.com/Veridise/Picus.",
            ),
        ));
    }

    if merged.contains("petite")
        && (merged.contains("invalid memory reference") || merged.contains("aborted"))
    {
        return Ok((
            FixtureStatus::Error,
            String::from(
                "Picus Racket runtime crashed (`petite`). This is typically an amd64 emulation/runtime issue; run Picus on a native amd64 host or adjust Docker Desktop x86 emulation settings.",
            ),
        ));
    }

    if merged.contains("unsafe") || merged.contains("under-constrained") {
        return Ok((
            FixtureStatus::Violation,
            String::from("Classified from Picus stdout/stderr"),
        ));
    }

    if merged.contains("underconstrained") {
        return Ok((
            FixtureStatus::Violation,
            String::from("Classified from Picus stdout/stderr"),
        ));
    }

    if merged.contains("safe") {
        return Ok((
            FixtureStatus::Pass,
            String::from("Classified from Picus stdout/stderr"),
        ));
    }

    if merged.contains("properly constrained") && !merged.contains("cannot determine") {
        return Ok((
            FixtureStatus::Pass,
            String::from("Classified from Picus stdout/stderr"),
        ));
    }

    if merged.contains("cannot determine")
        || merged.contains("unknown")
        || merged.contains("timeout")
    {
        return Ok((
            FixtureStatus::Inconclusive,
            String::from("Picus returned unknown/timeout"),
        ));
    }

    if !command_success {
        return Ok((
            FixtureStatus::Error,
            String::from("Picus command failed without parseable result"),
        ));
    }

    Ok((
        FixtureStatus::Error,
        String::from("Could not classify Picus result"),
    ))
}

fn infer_status_from_json(value: &Value) -> Option<FixtureStatus> {
    let mut words = Vec::new();
    collect_words(value, &mut words);

    let has_unsafe = words.iter().any(|w| w == "unsafe");
    let has_safe = words.iter().any(|w| w == "safe");
    let has_unknown = words.iter().any(|w| w == "unknown");

    if has_unsafe {
        return Some(FixtureStatus::Violation);
    }
    if has_safe {
        return Some(FixtureStatus::Pass);
    }
    if has_unknown {
        return Some(FixtureStatus::Inconclusive);
    }

    None
}

fn collect_words(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) => {
            let lower = s.to_lowercase();
            for token in lower.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
                if !token.is_empty() {
                    out.push(token.to_string());
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_words(item, out);
            }
        }
        Value::Object(map) => {
            for (k, v) in map {
                out.push(k.to_lowercase());
                collect_words(v, out);
            }
        }
        _ => {}
    }
}

fn run_converter(
    converter_bin: &str,
    shape_path: &Path,
    output_r1cs: &Path,
) -> kontor_crypto::Result<()> {
    let output = Command::new(converter_bin)
        .arg(shape_path)
        .arg(output_r1cs)
        .output()
        .map_err(|e| {
            kontor_crypto::KontorPoRError::IO(format!(
                "Failed to execute converter {}: {}",
                converter_bin, e
            ))
        })?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(kontor_crypto::KontorPoRError::InvalidInput(format!(
        "Converter {} failed: {}",
        converter_bin, stderr
    )))
}

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
        // Isolate Picus into its own process group so timeout can terminate
        // wrapper + racket + solver descendants in one signal.
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
        .map_err(|e| {
            kontor_crypto::KontorPoRError::IO(format!("Failed to spawn Picus process: {}", e))
        })?;

    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => {
                let output = child.wait_with_output().map_err(|e| {
                    kontor_crypto::KontorPoRError::IO(format!(
                        "Failed to collect Picus output: {}",
                        e
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
                std::thread::sleep(Duration::from_millis(250));
            }
            Err(e) => {
                return Err(kontor_crypto::KontorPoRError::IO(format!(
                    "Failed while waiting for Picus process: {}",
                    e
                )));
            }
        }
    }
}

fn cleanup_picus_processes_for_fixture(picus_input_path: &Path, picus_json_path: &Path) {
    // Best-effort cleanup in case a wrapper script leaves solver descendants behind.
    let patterns = [
        picus_input_path.display().to_string(),
        picus_json_path.display().to_string(),
    ];

    for pattern in patterns {
        let _ = Command::new("pkill")
            .arg("-f")
            .arg(&pattern)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn cleanup_picus_solver_processes() {
    // Picus can leave solver subprocesses detached from wrapper process groups.
    // Reap only temporary solver invocations that include Picus-generated .smt2 paths.
    let patterns = [
        "cvc5 .*picus.*\\.smt2",
        "cvc4 .*picus.*\\.smt2",
        "z3 .*picus.*\\.smt2",
    ];

    for pattern in patterns {
        let _ = Command::new("pkill")
            .arg("-f")
            .arg(pattern)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
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

    out.push_str("| Fixture | Status | Runtime (ms) | Reason |\n");
    out.push_str("|---|---|---:|---|\n");
    for result in &report.results {
        out.push_str(&format!(
            "| {} | {:?} | {} | {} |\n",
            result.fixture_id,
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

    format!("{}...", &input[..max_len])
}
