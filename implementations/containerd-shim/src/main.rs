// SPDX-License-Identifier: MIT OR Apache-2.0
// containerd-shim-verified-container-v1
//
// Containerd shim for verified-container-spec .ctp bundles
// Implements: https://github.com/hyperpolymath/verified-container-spec/blob/main/spec/runtime-integration.adoc

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use tracing::{info, error, warn};

mod bundle;
mod verify;

use bundle::CtpBundle;
use verify::{VerificationMode, verify_bundle};

/// Exit codes as defined in runtime-integration.adoc Section 8.1
const EXIT_SUCCESS: u8 = 0;  // Verification passed
const EXIT_VERIFY_FAILED: u8 = 1;  // Verification failed (REJECT)
const EXIT_MALFORMED: u8 = 2;  // Bundle malformed
const EXIT_NETWORK_ERROR: u8 = 3;  // Network error (log unavailable)

#[tokio::main]
async fn main() -> ExitCode {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    match run().await {
        Ok(()) => {
            info!("Container started successfully");
            ExitCode::from(EXIT_SUCCESS)
        }
        Err(e) => {
            error!("Shim error: {:#}", e);
            // Determine exit code based on error type
            let code = if e.to_string().contains("malformed") {
                EXIT_MALFORMED
            } else if e.to_string().contains("network") {
                EXIT_NETWORK_ERROR
            } else {
                EXIT_VERIFY_FAILED
            };
            ExitCode::from(code)
        }
    }
}

async fn run() -> Result<()> {
    // 1. Parse command-line arguments
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        bail!("Usage: containerd-shim-verified-container-v1 <bundle-path> [--verify-mode=MODE]");
    }

    let bundle_path = PathBuf::from(&args[1]);
    let verify_mode = parse_verify_mode(&args)?;

    info!("Processing .ctp bundle: {:?}", bundle_path);
    info!("Verification mode: {:?}", verify_mode);

    // 2. Load and parse .ctp bundle
    let ctp_bundle = CtpBundle::load(&bundle_path)
        .context("Failed to load .ctp bundle - malformed bundle")?;

    info!("Bundle loaded: {} (version {})",
        ctp_bundle.manifest.name,
        ctp_bundle.manifest.version
    );

    // 3. Verify attestations (implements verification-protocol.adoc)
    match verify_bundle(&ctp_bundle, verify_mode).await {
        Ok(()) => {
            info!("Verification PASSED");
        }
        Err(e) => {
            error!("Verification FAILED: {:#}", e);

            match verify_mode {
                VerificationMode::Strict => {
                    bail!("Verification failed in strict mode: {}", e);
                }
                VerificationMode::Permissive => {
                    warn!("Verification failed in permissive mode, continuing anyway");
                }
                VerificationMode::Audit => {
                    info!("Verification failed in audit mode, logged only");
                }
            }
        }
    }

    // 4. Extract OCI image to temporary location
    let oci_dir = ctp_bundle.extract_oci_layout()
        .context("Failed to extract OCI layout")?;

    info!("OCI layout extracted to: {:?}", oci_dir);

    // 5. Delegate to runc/crun
    delegate_to_runtime(&oci_dir)?;

    Ok(())
}

fn parse_verify_mode(args: &[String]) -> Result<VerificationMode> {
    for arg in args {
        if let Some(mode_str) = arg.strip_prefix("--verify-mode=") {
            return match mode_str {
                "strict" => Ok(VerificationMode::Strict),
                "permissive" => Ok(VerificationMode::Permissive),
                "audit" => Ok(VerificationMode::Audit),
                _ => bail!("Invalid verification mode: {}", mode_str),
            };
        }
    }

    // Default to strict for .ctp bundles (per spec Section 6.3)
    Ok(VerificationMode::Strict)
}

fn delegate_to_runtime(oci_dir: &Path) -> Result<()> {
    // Determine which OCI runtime to use (runc or crun)
    let runtime = std::env::var("OCI_RUNTIME").unwrap_or_else(|_| "runc".to_string());

    info!("Delegating to OCI runtime: {}", runtime);

    let status = Command::new(&runtime)
        .arg("run")
        .arg(oci_dir)
        .status()
        .context(format!("Failed to execute {}", runtime))?;

    if !status.success() {
        bail!("OCI runtime exited with status: {}", status);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_verify_mode() {
        let args = vec!["shim".to_string(), "--verify-mode=strict".to_string()];
        assert!(matches!(parse_verify_mode(&args).unwrap(), VerificationMode::Strict));

        let args = vec!["shim".to_string(), "--verify-mode=permissive".to_string()];
        assert!(matches!(parse_verify_mode(&args).unwrap(), VerificationMode::Permissive));
    }

    #[test]
    fn test_default_mode_is_strict() {
        let args = vec!["shim".to_string()];
        assert!(matches!(parse_verify_mode(&args).unwrap(), VerificationMode::Strict));
    }
}
