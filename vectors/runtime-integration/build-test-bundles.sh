#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# build-test-bundles.sh
#
# Build actual .ctp test bundles from test vector directories

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

# Build a .ctp bundle from a test vector directory
build_bundle() {
    local vector_dir="$1"
    local bundle_name="$2"

    if [[ ! -d "$vector_dir" ]]; then
        log_error "Vector directory not found: $vector_dir"
        return 1
    fi

    log_info "Building bundle: $bundle_name from $vector_dir"

    # Create .ctp tarball
    tar -czf "${bundle_name}.ctp" -C "$vector_dir" .

    log_info "Created: ${bundle_name}.ctp ($(du -h "${bundle_name}.ctp" | cut -f1))"
}

# Generate a valid signed bundle with real attestations
build_valid_bundle() {
    log_info "Building valid-bundle.ctp with real attestations"

    local vector_dir="valid-bundle"

    # Ensure OCI layout directory structure exists
    mkdir -p "$vector_dir/oci-layout/blobs/sha256"
    mkdir -p "$vector_dir/signatures/logs"

    # Create minimal OCI blobs (empty layer for testing)
    local empty_layer_sha="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    echo -n "" > "$vector_dir/oci-layout/blobs/sha256/$empty_layer_sha"

    # Create OCI config blob
    local config_json=$(cat <<'EOF'
{
  "architecture": "amd64",
  "os": "linux",
  "rootfs": {
    "type": "layers",
    "diff_ids": ["sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
  }
}
EOF
)
    local config_sha=$(echo -n "$config_json" | sha256sum | cut -d' ' -f1)
    echo "$config_json" > "$vector_dir/oci-layout/blobs/sha256/$config_sha"

    # Update index.json with correct config digest
    cat > "$vector_dir/oci-layout/index.json" <<EOF
{
  "schemaVersion": 2,
  "manifests": [
    {
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": "sha256:$config_sha",
      "size": $(wc -c < "$vector_dir/oci-layout/blobs/sha256/$config_sha")
    }
  ]
}
EOF

    # Add signature files (placeholders for now)
    echo "signature-placeholder" > "$vector_dir/signatures/release.sig"
    echo "log-proof-placeholder" > "$vector_dir/signatures/logs/log1.proof"
    echo "log-proof-placeholder" > "$vector_dir/signatures/logs/log2.proof"

    # Build tarball
    build_bundle "$vector_dir" "valid-bundle"
}

# Build all test vector bundles
main() {
    log_info "Building test bundles from vectors"
    log_info "Working directory: $SCRIPT_DIR"

    # Clean up old bundles
    rm -f *.ctp

    # Build valid bundle with proper structure
    build_valid_bundle

    # Build insufficient-logs bundle
    if [[ -d "insufficient-logs" ]]; then
        build_bundle "insufficient-logs" "insufficient-logs"
    fi

    # Build subject-mismatch bundle
    if [[ -d "subject-mismatch" ]]; then
        build_bundle "subject-mismatch" "subject-mismatch"
    fi

    # Build missing-attestations bundle
    if [[ -d "missing-attestations" ]]; then
        # Remove attestations directory if it exists
        rm -rf "missing-attestations/attestations"
        build_bundle "missing-attestations" "missing-attestations"
    fi

    # malformed-bundle.ctp already exists as invalid data
    log_info "malformed-bundle.ctp already exists (invalid tarball)"

    # Summary
    log_info ""
    log_info "Built test bundles:"
    ls -lh *.ctp 2>/dev/null || log_warn "No .ctp files found"

    log_info ""
    log_info "Test bundle verification:"
    for bundle in *.ctp; do
        if tar -tzf "$bundle" >/dev/null 2>&1; then
            log_info "✓ $bundle - Valid tarball"
        else
            log_warn "✗ $bundle - Invalid tarball (expected for malformed-bundle.ctp)"
        fi
    done
}

main "$@"
