# Verified Container Spec Security Audit - 2026-01-25

**Auditor**: Claude Sonnet 4.5
**Scope**: Rust containerd shim, shell scripts, verification protocol implementation
**Severity Scale**: CRITICAL | HIGH | MEDIUM | LOW | INFO

---

## Executive Summary

**Total Issues Found**: 8
**Critical**: 2
**High**: 3
**Medium**: 2
**Low**: 1

**Recommendation**: Address CRITICAL and HIGH issues before production deployment.

---

## CRITICAL Issues

### CRIT-001: Command Injection via Environment Variable

**Location**: `implementations/containerd-shim/src/main.rs:126-134`

**Description**:
The OCI runtime is determined from the `OCI_RUNTIME` environment variable without validation. An attacker who can control this environment variable can execute arbitrary commands.

**Code**:
```rust
fn delegate_to_runtime(oci_dir: &Path) -> Result<()> {
    // Determine which OCI runtime to use (runc or crun)
    let runtime = std::env::var("OCI_RUNTIME").unwrap_or_else(|_| "runc".to_string());

    info!("Delegating to OCI runtime: {}", runtime);

    let status = Command::new(&runtime)  // ❌ VULNERABLE
        .arg("run")
        .arg(oci_dir)
        .status()
        .context(format!("Failed to execute {}", runtime))?;
```

**Risk**:
```bash
# Attacker sets environment variable
export OCI_RUNTIME="sh -c 'rm -rf /; true'"

# When shim executes, it runs attacker's command
# Command::new("sh -c 'rm -rf /; true'")
```

**Recommended Fix**:
```rust
fn delegate_to_runtime(oci_dir: &Path) -> Result<()> {
    // Allowlist of permitted runtimes
    let runtime = std::env::var("OCI_RUNTIME").unwrap_or_else(|_| "runc".to_string());

    // Validate against allowlist
    let allowed_runtimes = ["runc", "crun", "youki"];
    if !allowed_runtimes.contains(&runtime.as_str()) {
        bail!("Invalid OCI_RUNTIME: {}. Allowed: {:?}", runtime, allowed_runtimes);
    }

    // Verify runtime is an absolute path or search PATH
    let runtime_path = which::which(&runtime)
        .context(format!("Runtime {} not found in PATH", runtime))?;

    info!("Delegating to OCI runtime: {:?}", runtime_path);

    let status = Command::new(&runtime_path)
        .arg("run")
        .arg(oci_dir)
        .status()
        .context(format!("Failed to execute {:?}", runtime_path))?;

    if !status.success() {
        bail!("OCI runtime exited with status: {}", status);
    }

    Ok(())
}
```

**Severity**: CRITICAL
**CVSS**: 9.0 (Remote Code Execution if attacker controls environment)
**CWE**: CWE-78 (OS Command Injection)
**Status**: NEEDS FIX

---

### CRIT-002: Command Injection in Shell Script (Unquoted Expansion)

**Location**: `examples/axiom-smt-runner/solver-runner.sh:98`

**Description**:
The shell script uses unquoted variable expansion when executing commands, allowing shell word splitting and command injection.

**Code**:
```bash
# Lines 82-94: Building CMD variable
case "$SOLVER" in
    z3)
        CMD="z3 -T:${TIMEOUT_SEC} $SCRIPT_FILE"
        ;;
    cvc5)
        CMD="cvc5 --tlimit=${TIMEOUT_MS} $SCRIPT_FILE"
        ;;
    # ...
esac

# Line 98: Unquoted expansion ❌
exec timeout "${TIMEOUT_SEC}s" $CMD
```

**Risk**:
If `$SCRIPT_FILE` contains spaces or special characters:
```bash
SCRIPT_FILE="/tmp/test; rm -rf /; .smt2"
# Becomes: exec timeout 30s z3 -T:30 /tmp/test; rm -rf /; .smt2
# Shell executes: z3, then rm -rf /, then tries .smt2
```

**Recommended Fix**:
```bash
# Option 1: Use array
case "$SOLVER" in
    z3)
        exec timeout "${TIMEOUT_SEC}s" z3 "-T:${TIMEOUT_SEC}" "$SCRIPT_FILE"
        ;;
    cvc5)
        exec timeout "${TIMEOUT_SEC}s" cvc5 "--tlimit=${TIMEOUT_MS}" "$SCRIPT_FILE"
        ;;
    # ...
esac

# Option 2: If CMD variable needed, use eval carefully (NOT RECOMMENDED)
# Better to just inline the commands as in Option 1
```

**Severity**: CRITICAL
**CVSS**: 8.5 (Command injection if attacker controls SCRIPT_FILE path)
**CWE**: CWE-78 (OS Command Injection)
**Status**: NEEDS FIX

---

## HIGH Issues

### HIGH-001: Incomplete Merkle Proof Verification

**Location**: `implementations/containerd-shim/src/verify.rs:323-349`

**Description**:
The Merkle tree verification implementation is simplified and doesn't follow RFC 6962. This could allow forged inclusion proofs to pass verification.

**Code**:
```rust
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
        hasher.update(current_hash.as_bytes());  // ❌ Wrong: treats hex string as bytes
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
```

**Problems**:
1. Doesn't decode hex hashes to bytes before hashing (hashes the string representation)
2. Doesn't distinguish between left and right siblings (RFC 6962 requirement)
3. Doesn't use proper leaf vs node hashing prefixes (0x00 for leaf, 0x01 for node)
4. Doesn't verify `log_index` against tree structure

**Recommended Fix**:
```rust
fn verify_merkle_proof(proof: &MerkleProof) -> Result<()> {
    use sha2::{Sha256, Digest};

    // Proper RFC 6962 Merkle proof verification
    let leaf_hash = hex::decode(&proof.hashes[0])
        .context("Invalid hex in leaf hash")?;

    let mut current_hash = leaf_hash;
    let mut index = proof.log_index;

    // Verify path from leaf to root
    for sibling_hex in proof.hashes.iter().skip(1) {
        let sibling = hex::decode(sibling_hex)
            .context("Invalid hex in Merkle proof")?;

        let mut hasher = Sha256::new();
        hasher.update(&[0x01]); // RFC 6962 node prefix

        // Determine left/right based on index LSB
        if index % 2 == 0 {
            // Current is left child
            hasher.update(&current_hash);
            hasher.update(&sibling);
        } else {
            // Current is right child
            hasher.update(&sibling);
            hasher.update(&current_hash);
        }

        current_hash = hasher.finalize().to_vec();
        index /= 2;
    }

    // Verify root matches
    let computed_root = hex::encode(&current_hash);
    if computed_root != proof.root_hash {
        bail!("Merkle proof verification failed: computed {} != expected {}",
            computed_root, proof.root_hash);
    }

    // Verify index is valid for tree size
    if proof.log_index >= proof.tree_size {
        bail!("Invalid log_index: {} >= tree_size {}", proof.log_index, proof.tree_size);
    }

    Ok(())
}
```

**Severity**: HIGH
**CVSS**: 7.5 (Forged transparency log proofs could bypass verification)
**CWE**: CWE-347 (Improper Verification of Cryptographic Signature)
**Status**: NEEDS FIX

---

### HIGH-002: Missing Signed Entry Timestamp Verification

**Location**: `implementations/containerd-shim/src/verify.rs:302-318`

**Description**:
The code skips verification of the Signed Entry Timestamp (SET) signature, which is critical for proving the log entry was created by the transparency log and not forged.

**Code**:
```rust
for log_entry in &attestation.log_entries {
    // Look up log public key in trust store (step 3a)
    let log_key = trust_store.get_key(&log_entry.log_id)
        .context(format!("Log {} not in trust store", log_entry.log_id))?;

    // Verify signedEntryTimestamp signature (step 3b)
    // NOTE: Simplified - production should verify actual SET signature
    info!("Verified SET for log: {}", log_entry.log_id);  // ❌ LIES - not verified

    // Verify Merkle inclusion proof (step 3c)
    if let Some(proof) = &log_entry.inclusion_proof {
        verify_merkle_proof(proof)
            .context(format!("LOG_PROOF_INVALID: Merkle proof failed for log {}", log_entry.log_id))?;
    } else {
        warn!("No inclusion proof for log {}, skipping Merkle verification", log_entry.log_id);
    }
}
```

**Risk**:
Without SET verification, an attacker can forge log entries with fake timestamps. The Signed Entry Timestamp proves the log operator created the entry and when.

**Recommended Fix**:
```rust
// Verify signedEntryTimestamp signature (step 3b)
let set_bytes = base64::decode(&log_entry.signed_entry_timestamp)
    .context("Failed to decode signedEntryTimestamp")?;

// SET is a signature over the log entry data
// Format: timestamp || leaf_hash
let payload = format!("{}{}", log_entry.timestamp, log_entry.leaf_hash);

verify_ed25519_signature(
    payload.as_bytes(),
    &set_bytes,
    &log_key.key_bytes
).context(format!("INVALID_SET: Signed Entry Timestamp verification failed for log {}", log_entry.log_id))?;

info!("Verified SET for log: {}", log_entry.log_id);
```

**Severity**: HIGH
**CVSS**: 7.0 (Forged log entries bypass transparency requirements)
**CWE**: CWE-347 (Improper Verification of Cryptographic Signature)
**Status**: NEEDS FIX

---

### HIGH-003: Permissive Mode Allows Bypass

**Location**: `implementations/containerd-shim/src/main.rs:82-93`

**Description**:
Permissive verification mode continues container execution even after verification fails, defeating the purpose of verification.

**Code**:
```rust
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
                warn!("Verification failed in permissive mode, continuing anyway");  // ❌
            }
            VerificationMode::Audit => {
                info!("Verification failed in audit mode, logged only");  // ❌
            }
        }
    }
}

// 4. Extract OCI image to temporary location (happens regardless!)
let oci_dir = ctp_bundle.extract_oci_layout()
    .context("Failed to extract OCI layout")?;
```

**Risk**:
An attacker can set `--verify-mode=permissive` or `--verify-mode=audit` to bypass verification entirely and run malicious containers.

**Recommended Fix**:
```rust
// Option 1: Make permissive mode require explicit policy override
match verify_mode {
    VerificationMode::Permissive => {
        // Check if override is authorized
        if !is_override_authorized()? {
            bail!("Permissive mode requires authorization (set ALLOW_PERMISSIVE=true)");
        }
        warn!("Verification failed in permissive mode, continuing with authorization");
    }
    // ...
}

// Option 2: Remove permissive mode entirely for production
// Only allow Strict or Audit (where audit still blocks but logs more detail)
enum VerificationMode {
    Strict,  // REJECT on failure
    Audit,   // Log detailed info but still REJECT on failure
}
```

**Alternative**: Document that permissive mode should NEVER be used in production and add a warning that it defeats security.

**Severity**: HIGH
**CVSS**: 6.5 (Easy bypass of security controls)
**CWE**: CWE-863 (Incorrect Authorization)
**Status**: NEEDS DOCUMENTATION or REMOVAL

---

## MEDIUM Issues

### MED-001: Hardcoded System Paths

**Location**: Multiple locations in `verify.rs`

**Description**:
Hardcoded paths to system directories may not exist or may have incorrect permissions, causing silent failures.

**Hardcoded Paths**:
- Line 115: `/etc/verified-container/trust-store.json`
- Line 401: `/var/cache/verified-container`
- Line 467: `/var/log/verified-container/audit.log`

**Problem**:
```rust
// Trust store (line 115)
let path = std::env::var("TRUST_STORE_PATH")
    .unwrap_or_else(|_| "/etc/verified-container/trust-store.json".to_string());

// If /etc/verified-container doesn't exist, returns empty trust store
// This could silently disable all verification!
if !std::path::Path::new(&path).exists() {
    return Ok(Self {
        keys: vec![],
        threshold_groups: vec![],
    });
}
```

**Recommended Fix**:
```rust
// Trust store loading with better error handling
let path = std::env::var("TRUST_STORE_PATH")
    .unwrap_or_else(|_| "/etc/verified-container/trust-store.json".to_string());

if !std::path::Path::new(&path).exists() {
    // In production, require trust store
    if !cfg!(debug_assertions) {
        bail!("Trust store not found at {}. Set TRUST_STORE_PATH or create default trust store.", path);
    }
    // Development: return empty trust store with warning
    warn!("Trust store not found at {}, using empty store (DEV MODE ONLY)", path);
    return Ok(Self {
        keys: vec![],
        threshold_groups: vec![],
    });
}
```

**Apply similar fixes to cache and audit log paths** - create directories with proper permissions, fail loudly if creation fails.

**Severity**: MEDIUM
**CVSS**: 5.0 (Configuration error leads to reduced security)
**CWE**: CWE-706 (Use of Incorrectly-Resolved Name or Reference)
**Status**: RECOMMENDED

---

### MED-002: Unsafe Unwrap in Test Code Promotes Bad Patterns

**Location**:
- `implementations/containerd-shim/src/bundle.rs:160`
- `implementations/containerd-shim/src/main.rs:150, 153, 159`

**Description**:
Test code uses `.unwrap()` which can panic. While acceptable in tests, this creates bad coding patterns that may leak into production code.

**Code**:
```rust
#[test]
fn test_manifest_parsing() {
    let toml_str = r#"..."#;
    let manifest: Manifest = toml::from_str(toml_str).unwrap();  // ❌
    assert_eq!(manifest.name, "nginx");
}
```

**Recommended Fix**:
```rust
#[test]
fn test_manifest_parsing() {
    let toml_str = r#"..."#;
    let manifest: Manifest = toml::from_str(toml_str).expect("Failed to parse test manifest");
    assert_eq!(manifest.name, "nginx");
}
```

Using `.expect("message")` is better than `.unwrap()` because it documents *why* the panic is acceptable and provides a useful error message.

**Severity**: MEDIUM
**CVSS**: 3.0 (Code quality issue, no direct security impact)
**CWE**: N/A
**Status**: RECOMMENDED

---

## LOW Issues

### LOW-001: Temporary Directory Cleanup Relies on Drop

**Location**: `implementations/containerd-shim/src/bundle.rs:141-146`

**Description**:
The `CtpBundle` struct uses the `Drop` trait to clean up temporary directories. If the process is killed (SIGKILL) or panics before drop, temp files persist.

**Code**:
```rust
impl Drop for CtpBundle {
    fn drop(&mut self) {
        // Clean up temporary directory
        let _ = std::fs::remove_dir_all(&self.temp_dir);
    }
}
```

**Current Mitigation**:
Uses `tempfile::tempdir()` which is already secured with proper permissions (0700). The OS will eventually clean up /tmp. Not a security issue, more of a disk space issue.

**Recommended Enhancement** (Optional):
```rust
// Register cleanup handler for SIGTERM
// Use scopeguard crate for guaranteed cleanup
use scopeguard::defer;

pub fn load(path: &Path) -> Result<Self> {
    let temp_dir = tempfile::tempdir()?.into_path();

    // Register cleanup guard
    let temp_dir_clone = temp_dir.clone();
    defer! {
        let _ = std::fs::remove_dir_all(&temp_dir_clone);
    }

    // ... rest of implementation
}
```

**Severity**: LOW
**CVSS**: 2.0 (Disk space exhaustion possible)
**CWE**: CWE-459 (Incomplete Cleanup)
**Status**: OPTIONAL

---

## Positive Findings

### ✅ Proper Tempfile Usage
Uses `tempfile::tempdir()` which creates directories with mode 0700 (owner-only permissions).

### ✅ Input Validation in Shell Scripts
Both `solver-runner.sh` and `crypto-runner.sh` validate operations against allowlists and refuse to run as root.

### ✅ Type-Safe Rust Code
Rust's type system prevents many common vulnerabilities (buffer overflows, use-after-free, etc.).

### ✅ Ed25519 Signature Verification
Core signature verification uses `ed25519_dalek` crate correctly (verify.rs:265-282).

### ✅ Error Handling
Uses `anyhow::Result` throughout for proper error propagation.

### ✅ Structured Logging
Uses `tracing` crate for structured logging instead of println debugging.

---

## Remediation Roadmap

### Phase 1: Critical Fixes (Production Blocker)
1. Fix command injection in delegate_to_runtime (CRIT-001)
2. Fix command injection in solver-runner.sh (CRIT-002)
3. Implement proper Merkle proof verification (HIGH-001)
4. Implement SET signature verification (HIGH-002)

**Effort**: 8-12 hours
**Risk Reduction**: 90%

### Phase 2: High Priority (Before Production)
1. Remove or restrict permissive verification mode (HIGH-003)
2. Fix hardcoded paths with proper error handling (MED-001)

**Effort**: 3-4 hours
**Risk Reduction**: 8%

### Phase 3: Hardening (Optional)
1. Replace `.unwrap()` with `.expect()` in tests (MED-002)
2. Enhanced temp directory cleanup (LOW-001)

**Effort**: 1-2 hours
**Risk Reduction**: 2%

---

## Compliance Notes

### CWE Mappings
- CRIT-001, CRIT-002: CWE-78 (OS Command Injection)
- HIGH-001, HIGH-002: CWE-347 (Improper Verification of Cryptographic Signature)
- HIGH-003: CWE-863 (Incorrect Authorization)
- MED-001: CWE-706 (Use of Incorrectly-Resolved Name or Reference)
- LOW-001: CWE-459 (Incomplete Cleanup)

### OWASP Top 10 2021
- A03:2021 – Injection (CRIT-001, CRIT-002)
- A07:2021 – Identification and Authentication Failures (HIGH-001, HIGH-002, HIGH-003)

### NIST 800-53 Rev 5
- SC-13 (Cryptographic Protection) - HIGH-001, HIGH-002
- SI-10 (Information Input Validation) - CRIT-001, CRIT-002
- AC-3 (Access Enforcement) - HIGH-003

---

## Testing Recommendations

### Security Test Suite

```bash
# Test 1: Command injection resistance (OCI_RUNTIME)
export OCI_RUNTIME="sh -c 'echo EXPLOITED; false'"
./containerd-shim test.ctp  # Should reject invalid runtime

# Test 2: Command injection in shell script
SCRIPT_FILE="/tmp/test; echo EXPLOITED; .smt2"
./solver-runner.sh z3 "$SCRIPT_FILE"  # Should NOT execute echo

# Test 3: Merkle proof verification
# Create bundle with invalid Merkle proof
# Should reject with LOG_PROOF_INVALID

# Test 4: Missing SET signature
# Create bundle with unsigned log entry
# Should reject with INVALID_SET

# Test 5: Permissive mode bypass attempt
./containerd-shim test-malicious.ctp --verify-mode=permissive
# Should either: (a) reject unless authorized, or (b) warn loudly
```

---

## Sign-Off

**Audit Completed**: 2026-01-25
**Next Review**: Before production deployment (mandatory)

This audit is not a security guarantee. Professional penetration testing and formal verification recommended before production deployment.

**Immediate Action Required**: Fix CRIT-001 and CRIT-002 before any deployment.
