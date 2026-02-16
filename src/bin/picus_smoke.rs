use clap::Parser;
use kontor_crypto::formal;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};
use std::{fs, io};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

#[derive(Debug, Parser)]
#[command(name = "picus_smoke")]
#[command(about = "Smoke-test Picus with a tiny intentionally underconstrained circuit")]
struct Args {
    /// Artifact output root
    #[arg(long, default_value = "artifacts/picus-smoke")]
    artifacts_dir: PathBuf,

    /// Picus executable name/path
    #[arg(long, default_value = "run-picus")]
    picus_bin: String,

    /// Picus solver override (cvc4 | cvc5 | z3)
    #[arg(long, default_value = "cvc5")]
    solver: String,

    /// Picus timeout in milliseconds (default: 5000ms)
    #[arg(long, default_value_t = 5000)]
    timeout_ms: u64,

    /// Extra grace added before force-killing Picus process
    #[arg(long, default_value_t = 3000)]
    hard_timeout_grace_ms: u64,

    /// Picus log level (INFO | PROGRESS | DEBUG | ...)
    #[arg(long, default_value = "INFO")]
    log_level: String,

    /// Keep Picus temporary files (helps debugging; will write a lot)
    #[arg(long)]
    noclean: bool,
}

fn main() {
    let args = Args::parse();
    if let Err(err) = run(args) {
        eprintln!("picus_smoke failed: {err}");
        std::process::exit(1);
    }
}

fn run(args: Args) -> kontor_crypto::Result<()> {
    fs::create_dir_all(&args.artifacts_dir).map_err(|e| {
        kontor_crypto::KontorPoRError::IO(format!(
            "Failed to create artifacts dir {}: {e}",
            args.artifacts_dir.display()
        ))
    })?;

    let r1cs_path = formal::export_picus_smoke_underconstrained(&args.artifacts_dir)?;
    let artifact_dir = r1cs_path
        .parent()
        .map(PathBuf::from)
        .ok_or_else(|| kontor_crypto::KontorPoRError::InvalidInput("bad r1cs path".to_string()))?;
    let json_path = artifact_dir.join("picus-result.json");

    println!("Smoke artifacts:");
    println!("- r1cs: {}", r1cs_path.display());
    println!("- sym:  {}", r1cs_path.with_extension("sym").display());

    let mut cmd = Command::new(&args.picus_bin);
    cmd.arg("--json")
        .arg(&json_path)
        .arg("--timeout")
        .arg(args.timeout_ms.to_string())
        .arg("--solver")
        .arg(&args.solver)
        .arg("--log-level")
        .arg(&args.log_level);

    if args.noclean {
        cmd.arg("--noclean");
    }

    // Positional arg must be last.
    cmd.arg(&r1cs_path);

    let hard_timeout =
        Duration::from_millis(args.timeout_ms.saturating_add(args.hard_timeout_grace_ms));
    let started = Instant::now();

    let process_result = run_with_hard_timeout(cmd, hard_timeout)?;
    match process_result {
        ProcessRunResult::TimedOut => Err(kontor_crypto::KontorPoRError::InvalidInput(format!(
            "Picus hard timeout exceeded ({}ms + {}ms grace)",
            args.timeout_ms, args.hard_timeout_grace_ms
        ))),
        ProcessRunResult::Completed(output) => {
            println!("Picus exit: {}", output.status);
            println!("Picus json: {}", json_path.display());
            println!("Runtime: {}ms", started.elapsed().as_millis());

            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stdout.trim().is_empty() {
                println!("--- stdout (truncated) ---");
                println!("{}", truncate(&stdout, 2000));
            }
            if !stderr.trim().is_empty() {
                println!("--- stderr (truncated) ---");
                println!("{}", truncate(&stderr, 2000));
            }

            Ok(())
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }

    let mut end = max.min(s.len());
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }

    if end == 0 {
        return "...\n(truncated)\n".to_string();
    }

    format!("{}...\n(truncated)\n", &s[..end])
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
