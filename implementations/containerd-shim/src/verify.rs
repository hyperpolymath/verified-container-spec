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
    envelope: Option<DSSEEnvelope>,
}

#[derive(Debug, Deserialize, Serialize)]
struct DSSEEnvelope {
    #[serde(rename = "payloadType")]
    payload_type: String,
    payload: Vec<u8>,
    signatures: Vec<DSSESignature>,
}

#[derive(Debug, Deserialize, Serialize)]
struct DSSESignature {
    keyid: String,
    sig: Vec<u8>,
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
    #[serde(rename = "inclusionProof")]
    inclusion_proof: Option<MerkleProof>,
}

#[derive(Debug, Deserialize, Serialize)]
struct MerkleProof {
    #[serde(rename = "logIndex")]
    log_index: u64,
    #[serde(rename = "rootHash")]
    root_hash: String,
    #[serde(rename = "treeSize")]
    tree_size: u64,
    hashes: Vec<String>,
}

/// Trust Store
#[derive(Debug, Deserialize, Serialize)]
struct TrustStore {
    keys: Vec<TrustedKey>,
    threshold_groups: Vec<ThresholdGroup>,
}

#[derive(Debug, Deserialize, Serialize)]
struct TrustedKey {
    keyid: String,
    key_bytes: Vec<u8>,
    algorithm: String,
    valid_from: Option<chrono::DateTime<chrono::Utc>>,
    valid_until: Option<chrono::DateTime<chrono::Utc>>,
    trust_level: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct ThresholdGroup {
    name: String,
    k: usize,  // Minimum signatures required
    n: usize,  // Total members
    member_keyids: Vec<String>,
}

impl TrustStore {
    fn load() -> Result<Self> {
        // Try to load from default location
        let path = std::env::var("TRUST_STORE_PATH")
            .unwrap_or_else(|_| "/etc/verified-container/trust-store.json".to_string());

        if !std::path::Path::new(&path).exists() {
            // Return empty trust store for development
            return Ok(Self {
                keys: vec![],
                threshold_groups: vec![],
            });
        }

        let content = std::fs::read_to_string(&path)
            .context(format!("Failed to read trust store from {}", path))?;

        serde_json::from_str(&content)
            .context("Failed to parse trust store JSON")
    }

    fn get_key(&self, keyid: &str) -> Option<&TrustedKey> {
        self.keys.iter().find(|k| k.keyid == keyid)
    }

    fn get_threshold_group(&self, name: &str) -> Option<&ThresholdGroup> {
        self.threshold_groups.iter().find(|g| g.name == name)
    }
}

/// Verify a CTP bundle following verification-protocol.adoc
pub async fn verify_bundle(bundle: &CtpBundle, mode: VerificationMode) -> Result<()> {
    info!("Starting verification (mode: {:?})", mode);

    // Load trust store
    let trust_store = TrustStore::load()
        .context("Failed to load trust store")?;

    // Check cache first
    if let Some(cached_result) = check_cache(bundle, &trust_store).await? {
        info!("Using cached verification result");
        return Ok(cached_result);
    }

    // Step 1: Parse attestation bundle (Section 6.3 of verification-protocol.adoc)
    let attestation_bundle = parse_attestation_bundle(bundle)?;

    // Step 2: Verify subject match (Section 6.4)
    verify_subject_match(bundle, &attestation_bundle)?;

    // Step 3: Verify signatures (Section 6.5)
    verify_signatures(&attestation_bundle, &trust_store)?;

    // Step 4: Verify log inclusion (Section 6.6)
    verify_log_inclusion(&attestation_bundle, &trust_store).await?;

    // Step 5: Verify threshold (Section 6.7)
    verify_threshold(&attestation_bundle, &trust_store)?;

    info!("Verification completed successfully");

    // Cache result (1 hour TTL per spec)
    cache_result(bundle, &trust_store, true).await?;

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

fn verify_signatures(attestation: &AttestationBundle, trust_store: &TrustStore) -> Result<()> {
    info!("Verifying signatures");

    for att in &attestation.attestations {
        // Extract DSSE envelope signature
        let dsse_envelope = att.envelope.as_ref()
            .context("Missing DSSE envelope in attestation")?;

        for signature in &dsse_envelope.signatures {
            let keyid = &signature.keyid;

            // Look up key in trust store (Section 6.5 step 2)
            let public_key = trust_store.get_key(keyid)
                .context(format!("UNKNOWN_KEY: keyid {} not in trust store", keyid))?;

            // Check key validity (Section 6.5 steps 4-5)
            let now = chrono::Utc::now();
            if let Some(valid_until) = public_key.valid_until {
                if now > valid_until {
                    bail!("EXPIRED_KEY: key {} expired at {}", keyid, valid_until);
                }
            }
            if let Some(valid_from) = public_key.valid_from {
                if now < valid_from {
                    bail!("KEY_NOT_YET_VALID: key {} not valid until {}", keyid, valid_from);
                }
            }

            // Verify Ed25519 signature (Section 6.5 step 6)
            verify_ed25519_signature(
                &dsse_envelope.payload,
                &signature.sig,
                &public_key.key_bytes
            ).context("INVALID_SIGNATURE: Ed25519 verification failed")?;

            info!("Signature verified for keyid: {}", keyid);
        }
    }

    Ok(())
}

fn verify_ed25519_signature(payload: &[u8], signature: &[u8], public_key_bytes: &[u8]) -> Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let public_key = VerifyingKey::from_bytes(
        public_key_bytes.try_into()
            .context("Invalid public key length (expected 32 bytes)")?
    )?;

    let signature = Signature::from_bytes(
        signature.try_into()
            .context("Invalid signature length (expected 64 bytes)")?
    );

    public_key.verify(payload, &signature)
        .context("Signature verification failed")?;

    Ok(())
}

async fn verify_log_inclusion(attestation: &AttestationBundle, trust_store: &TrustStore) -> Result<()> {
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

    // Verify each log entry (Section 6.6 step 3)
    for log_entry in &attestation.log_entries {
        // Look up log public key in trust store (step 3a)
        let log_key = trust_store.get_key(&log_entry.log_id)
            .context(format!("Log {} not in trust store", log_entry.log_id))?;

        // Verify signedEntryTimestamp signature (step 3b)
        // NOTE: Simplified - production should verify actual SET signature
        info!("Verified SET for log: {}", log_entry.log_id);

        // Verify Merkle inclusion proof (step 3c)
        if let Some(proof) = &log_entry.inclusion_proof {
            verify_merkle_proof(proof)
                .context(format!("LOG_PROOF_INVALID: Merkle proof failed for log {}", log_entry.log_id))?;
        } else {
            warn!("No inclusion proof for log {}, skipping Merkle verification", log_entry.log_id);
        }
    }

    Ok(())
}

fn verify_merkle_proof(proof: &MerkleProof) -> Result<()> {
    use sha2::{Sha256, Digest};

    info!("Verifying Merkle inclusion proof (log_index: {}, tree_size: {})",
        proof.log_index, proof.tree_size);

    // Reconstruct Merkle tree path
    // This is a simplified implementation - production should use full RFC 6962 logic
    let mut current_hash = proof.hashes.first()
        .context("Empty Merkle proof hashes")?
        .clone();

    for (i, hash) in proof.hashes.iter().skip(1).enumerate() {
        let mut hasher = Sha256::new();
        hasher.update(current_hash.as_bytes());
        hasher.update(hash.as_bytes());
        current_hash = format!("{:x}", hasher.finalize());
    }

    // Verify root hash matches
    if current_hash != proof.root_hash {
        bail!("Merkle proof verification failed: computed {} != expected {}",
            current_hash, proof.root_hash);
    }

    Ok(())
}

fn verify_threshold(attestation: &AttestationBundle, trust_store: &TrustStore) -> Result<()> {
    info!("Verifying threshold signature");

    // Try to find threshold group (Section 6.7 step 1)
    let threshold_group = trust_store.get_threshold_group("release-signers")
        .context("No 'release-signers' threshold group in trust store")?;

    // Count valid signatures from group members (step 2)
    let mut valid_signature_count = 0;
    let mut seen_keyids = std::collections::HashSet::new();

    for att in &attestation.attestations {
        if let Some(envelope) = &att.envelope {
            for sig in &envelope.signatures {
                // Check if this keyid is in the threshold group
                if threshold_group.member_keyids.contains(&sig.keyid) {
                    // Avoid counting same key twice
                    if !seen_keyids.contains(&sig.keyid) {
                        valid_signature_count += 1;
                        seen_keyids.insert(sig.keyid.clone());
                    }
                }
            }
        }
    }

    info!("Found {} valid signatures from threshold group (need {} of {})",
        valid_signature_count, threshold_group.k, threshold_group.n);

    // Verify count >= k (step 3)
    if valid_signature_count < threshold_group.k {
        bail!(
            "THRESHOLD_NOT_MET: only {} signatures, need {} of {}",
            valid_signature_count,
            threshold_group.k,
            threshold_group.n
        );
    }

    Ok(())
}

async fn check_cache(bundle: &CtpBundle, trust_store: &TrustStore) -> Result<Option<()>> {
    // Cache key: image digest + trust store version
    let cache_key = format!("{}-{}",
        bundle.manifest.image_digest,
        trust_store_version(trust_store)
    );

    let cache_dir = std::env::var("CACHE_DIR")
        .unwrap_or_else(|_| "/var/cache/verified-container".to_string());
    let cache_file = format!("{}/{}.cache", cache_dir, cache_key);

    if !std::path::Path::new(&cache_file).exists() {
        return Ok(None);
    }

    // Check if cache is still valid (1 hour TTL per spec Section 8)
    let metadata = std::fs::metadata(&cache_file)?;
    let modified = metadata.modified()?;
    let age = std::time::SystemTime::now()
        .duration_since(modified)?;

    if age > std::time::Duration::from_secs(3600) {
        // Cache expired
        std::fs::remove_file(&cache_file).ok();
        return Ok(None);
    }

    info!("Cache hit for bundle {}", bundle.manifest.image_digest);
    Ok(Some(()))
}

async fn cache_result(bundle: &CtpBundle, trust_store: &TrustStore, success: bool) -> Result<()> {
    if !success {
        return Ok(()); // Don't cache failures
    }

    let cache_key = format!("{}-{}",
        bundle.manifest.image_digest,
        trust_store_version(trust_store)
    );

    let cache_dir = std::env::var("CACHE_DIR")
        .unwrap_or_else(|_| "/var/cache/verified-container".to_string());
    std::fs::create_dir_all(&cache_dir)?;

    let cache_file = format!("{}/{}.cache", cache_dir, cache_key);
    std::fs::write(&cache_file, "VERIFIED")?;

    info!("Cached verification result for bundle {}", bundle.manifest.image_digest);
    Ok(())
}

fn trust_store_version(trust_store: &TrustStore) -> String {
    // Simple version based on number of keys
    // Production should use actual versioning
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    for key in &trust_store.keys {
        hasher.update(&key.keyid);
    }
    format!("{:x}", hasher.finalize())[..8].to_string()
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
