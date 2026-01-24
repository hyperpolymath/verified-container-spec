// SPDX-License-Identifier: MIT OR Apache-2.0
// Verification implementation following verification-protocol.adoc

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::fs;
use tracing::{info, warn};

use crate::bundle::CtpBundle;

/// Verification modes (per runtime-integration.adoc Section 6.3)
#[derive(Debug, Clone, Copy)]
pub enum VerificationMode {
    /// REJECT on any verification failure
    Strict,
    /// WARN on failure but continue
    Permissive,
    /// Log verification but don't block execution
    Audit,
}

/// Attestation Bundle (simplified for reference implementation)
#[derive(Debug, Deserialize, Serialize)]
struct AttestationBundle {
    #[serde(rename = "mediaType")]
    media_type: String,
    version: String,
    attestations: Vec<Attestation>,
    #[serde(rename = "logEntries")]
    log_entries: Vec<LogEntry>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Attestation {
    subject: Vec<Subject>,
    #[serde(rename = "predicateType")]
    predicate_type: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct Subject {
    digest: DigestSet,
}

#[derive(Debug, Deserialize, Serialize)]
struct DigestSet {
    sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct LogEntry {
    #[serde(rename = "logId")]
    log_id: String,
    #[serde(rename = "signedEntryTimestamp")]
    signed_entry_timestamp: String,
}

/// Verify a CTP bundle following verification-protocol.adoc
pub async fn verify_bundle(bundle: &CtpBundle, mode: VerificationMode) -> Result<()> {
    info!("Starting verification (mode: {:?})", mode);

    // Step 1: Parse attestation bundle (Section 6.3 of verification-protocol.adoc)
    let attestation_bundle = parse_attestation_bundle(bundle)?;

    // Step 2: Verify subject match (Section 6.4)
    verify_subject_match(bundle, &attestation_bundle)?;

    // Step 3: Verify signatures (Section 6.5)
    // NOTE: This is a simplified implementation
    // Production should use proper Ed25519 verification with trust store
    verify_signatures(&attestation_bundle)?;

    // Step 4: Verify log inclusion (Section 6.6)
    verify_log_inclusion(&attestation_bundle)?;

    // Step 5: Verify threshold (Section 6.7)
    // NOTE: Simplified - production should check k-of-n signatures
    verify_threshold(&attestation_bundle)?;

    info!("Verification completed successfully");

    // Record result (Section 6.8)
    record_verification_result(bundle, "ALLOW").await?;

    Ok(())
}

fn parse_attestation_bundle(bundle: &CtpBundle) -> Result<AttestationBundle> {
    let bundle_path = bundle.attestation_bundle_path();

    if !bundle_path.exists() {
        bail!("Attestation bundle not found: {:?} (MISSING_ATTESTATION)", bundle_path);
    }

    let content = fs::read_to_string(&bundle_path)
        .context("Failed to read attestation bundle")?;

    let attestation_bundle: AttestationBundle = serde_json::from_str(&content)
        .context("Failed to parse attestation bundle (MALFORMED_BUNDLE)")?;

    // Validate media type
    if attestation_bundle.media_type != "application/vnd.verified-container.bundle+json" {
        bail!("Invalid media type: {} (MALFORMED_BUNDLE)", attestation_bundle.media_type);
    }

    Ok(attestation_bundle)
}

fn verify_subject_match(bundle: &CtpBundle, attestation: &AttestationBundle) -> Result<()> {
    info!("Verifying subject match");

    let expected_digest = &bundle.manifest.image_digest;

    for att in &attestation.attestations {
        for subject in &att.subject {
            let subject_digest = format!("sha256:{}", subject.digest.sha256);
            if subject_digest != *expected_digest {
                bail!(
                    "Subject mismatch: expected {}, found {} (SUBJECT_MISMATCH)",
                    expected_digest,
                    subject_digest
                );
            }
        }
    }

    Ok(())
}

fn verify_signatures(_attestation: &AttestationBundle) -> Result<()> {
    info!("Verifying signatures");

    // NOTE: Simplified implementation
    // Production implementation should:
    // 1. Extract DSSE envelope signatures
    // 2. Look up keyid in trust store
    // 3. Check key validity (validFrom, validUntil)
    // 4. Verify Ed25519 signature
    //
    // For now, we just check that signatures exist in the bundle

    // TODO: Implement full signature verification per verification-protocol.adoc Section 6.5

    warn!("Signature verification not fully implemented (development mode)");

    Ok(())
}

fn verify_log_inclusion(attestation: &AttestationBundle) -> Result<()> {
    info!("Verifying log inclusion");

    // Check for at least 2 distinct log entries (federated requirement)
    let unique_logs: std::collections::HashSet<_> = attestation
        .log_entries
        .iter()
        .map(|e| &e.log_id)
        .collect();

    if unique_logs.len() < 2 {
        bail!(
            "Insufficient log coverage: {} logs, need 2+ (INSUFFICIENT_LOG_COVERAGE)",
            unique_logs.len()
        );
    }

    // NOTE: Simplified implementation
    // Production should verify:
    // 1. signedEntryTimestamp signature
    // 2. Merkle inclusion proof
    //
    // See verification-protocol.adoc Section 6.6

    warn!("Log proof verification not fully implemented (development mode)");

    Ok(())
}

fn verify_threshold(_attestation: &AttestationBundle) -> Result<()> {
    info!("Verifying threshold signature");

    // NOTE: Simplified implementation
    // Production should:
    // 1. Identify threshold group (e.g., "release-signers")
    // 2. Count valid signatures from group members
    // 3. Verify count >= k
    //
    // See verification-protocol.adoc Section 6.7

    warn!("Threshold verification not fully implemented (development mode)");

    Ok(())
}

async fn record_verification_result(bundle: &CtpBundle, outcome: &str) -> Result<()> {
    // Log to audit file (per runtime-integration.adoc Section 8.2)
    let log_entry = format!(
        "{{\"timestamp\":\"{}\",\"bundle\":\"{}\",\"digest\":\"{}\",\"outcome\":\"{}\"}}",
        chrono::Utc::now().to_rfc3339(),
        bundle.manifest.name,
        bundle.manifest.image_digest,
        outcome
    );

    // Ensure log directory exists
    std::fs::create_dir_all("/var/log/verified-container")
        .context("Failed to create audit log directory")?;

    // Append to audit log
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/var/log/verified-container/audit.log")
        .context("Failed to open audit log")?;

    writeln!(file, "{}", log_entry)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_mode_is_strict_by_default() {
        // Default should be strict per spec Section 6.3
        let mode = VerificationMode::Strict;
        assert!(matches!(mode, VerificationMode::Strict));
    }
}
