# SPDX-License-Identifier: AGPL-3.0-or-later
# Justfile - hyperpolymath standard task runner

default:
    @just --list

# Build the project
build:
    @echo "Building..."

# Run all tests
test: vectors-validate schema-validate examples-validate
    @echo "All tests passed."

# Run lints
lint: spec-style-lint
    @echo "Linting complete."

# Clean build artifacts
clean:
    @echo "Cleaning..."
    rm -rf conformance/results/*

# Format code
fmt:
    @echo "Formatting..."

# Run all checks
check: lint test

# Prepare a release
release VERSION:
    @echo "Releasing {{VERSION}}..."
    @echo "1. Update version in all spec files"
    @echo "2. Update CHANGELOG entries"
    @echo "3. Run: git tag v{{VERSION}}"
    @echo "4. Run: git push origin v{{VERSION}}"

# ============================================
# Schema Validation
# ============================================

# Validate JSON schemas are well-formed
schema-validate:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Validating JSON schemas..."

    if ! command -v ajv &> /dev/null; then
        echo "Installing ajv-cli..."
        npm install -g ajv-cli ajv-formats
    fi

    for schema in schema/*.schema.json; do
        echo "  Checking $schema..."
        ajv compile -s "$schema" --spec=draft2020 -c ajv-formats
    done

    echo "Schema validation complete."

# Validate documents against schemas
schema-validate-docs:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Validating documents against schemas..."

    # Validate trust store vectors
    for vector in vectors/valid/trust-store/*.json; do
        echo "  Validating $vector..."
        jq '.input' "$vector" | ajv validate -s schema/trust-store.schema.json --spec=draft2020 -c ajv-formats -d /dev/stdin
    done

    # Validate attestation bundle vectors
    for vector in vectors/valid/attestation-bundle/*.json; do
        echo "  Validating $vector..."
        jq '.input' "$vector" | ajv validate -s schema/attestation-bundle.schema.json --spec=draft2020 -c ajv-formats -d /dev/stdin
    done

    echo "Document validation complete."

# ============================================
# Test Vector Validation
# ============================================

# Validate all test vectors
vectors-validate:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Validating test vectors..."

    error_count=0

    for vector in vectors/**/*.json; do
        if ! jq -e '.id and .description and .category and .expected' "$vector" > /dev/null 2>&1; then
            echo "  ERROR: $vector missing required fields"
            ((error_count++))
        fi
    done

    # Check for duplicate IDs
    ids=$(find vectors -name "*.json" -exec jq -r '.id' {} \; 2>/dev/null | sort)
    duplicates=$(echo "$ids" | uniq -d)
    if [ -n "$duplicates" ]; then
        echo "  ERROR: Duplicate vector IDs: $duplicates"
        ((error_count++))
    fi

    if [ $error_count -gt 0 ]; then
        echo "Vector validation failed with $error_count errors."
        exit 1
    fi

    echo "Vector validation complete."

# Validate vectors by category
vectors-validate-category CATEGORY:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Validating {{CATEGORY}} vectors..."

    for vector in vectors/{{CATEGORY}}/**/*.json; do
        if [ -f "$vector" ]; then
            echo "  Checking $vector..."
            jq -e '.id and .description and .expected' "$vector" > /dev/null
        fi
    done

    echo "Done."

# ============================================
# Examples Validation
# ============================================

# Validate examples
examples-validate:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Validating examples..."

    for example in examples/**/*.json; do
        if [ -f "$example" ]; then
            echo "  Checking $example..."
            jq -e '.id and .description and .flow' "$example" > /dev/null
        fi
    done

    echo "Examples validation complete."

# ============================================
# Specification Linting
# ============================================

# Lint specification documents
spec-style-lint:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Linting specification documents..."

    required_sections=("Scope" "Terminology" "Security Considerations" "Changelog")
    warnings=0

    for spec in spec/*.adoc; do
        echo "  Checking $spec..."

        for section in "${required_sections[@]}"; do
            if ! grep -qi "== .*$section" "$spec"; then
                echo "    WARNING: May be missing section: $section"
                ((warnings++))
            fi
        done

        # Check RFC 2119 reference if normative language is used
        if grep -q "MUST\|SHALL\|SHOULD\|MAY" "$spec"; then
            if ! grep -qi "RFC.2119\|rfc2119" "$spec"; then
                echo "    WARNING: Uses normative language but may not reference RFC 2119"
                ((warnings++))
            fi
        fi
    done

    if [ $warnings -gt 0 ]; then
        echo "Spec linting completed with $warnings warnings."
    else
        echo "Spec linting complete."
    fi

# ============================================
# Conformance Testing
# ============================================

# Run conformance tests
conformance-run PROFILE IMPL:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Running {{PROFILE}} conformance tests with {{IMPL}}..."

    profile="conformance/profiles/{{PROFILE}}.json"
    if [ ! -f "$profile" ]; then
        echo "ERROR: Profile not found: $profile"
        exit 1
    fi

    if [ ! -x "{{IMPL}}" ]; then
        echo "ERROR: Implementation not executable: {{IMPL}}"
        exit 1
    fi

    echo "Profile: $profile"
    echo "Implementation: {{IMPL}}"
    echo ""
    echo "Note: Full conformance runner not yet implemented."
    echo "See conformance/runner/cli-contract.json for the expected CLI interface."

# Self-test conformance infrastructure
conformance-selftest:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Running conformance self-tests..."

    for profile in conformance/profiles/*.json; do
        echo "  Validating $profile..."
        jq -e '.id and .name and .version and .levels' "$profile" > /dev/null
    done

    echo "  Validating CLI contract..."
    jq -e '.commands | keys | length > 0' conformance/runner/cli-contract.json > /dev/null

    echo "Conformance self-test complete."

# ============================================
# Interoperability Matrix
# ============================================

# Generate interop matrix (placeholder)
interop-matrix-generate:
    @echo "Generating interoperability matrix..."
    @echo "Note: No implementations have run conformance tests yet."
    @echo "See docs/interop-matrix.adoc for current status."

# ============================================
# Documentation
# ============================================

# Check documentation links
docs-check-links:
    @echo "Checking documentation links..."
    @echo "Note: Link checker not yet configured."

# Generate documentation index
docs-index:
    @echo "Documentation Index"
    @echo "==================="
    @echo ""
    @echo "Specifications:"
    @ls -1 spec/*.adoc 2>/dev/null || echo "  (none)"
    @echo ""
    @echo "Schemas:"
    @ls -1 schema/*.json 2>/dev/null || echo "  (none)"
    @echo ""
    @echo "Documentation:"
    @ls -1 docs/*.adoc 2>/dev/null || echo "  (none)"
    @echo ""
    @echo "Test Vectors:"
    @find vectors -name "*.json" 2>/dev/null | wc -l | xargs echo "  Count:"
    @echo ""
    @echo "Examples:"
    @find examples -name "*.json" 2>/dev/null | wc -l | xargs echo "  Count:"
