#!/bin/sh
# SPDX-License-Identifier: PMPL-1.0-or-later
# Nix fallback for packages unavailable in Guix
#
# Usage: nix-fallback <package-name>

set -euo pipefail

PACKAGE="$1"

echo "Attempting Nix fallback for package: $PACKAGE" >&2

# Check if Nix is installed
if ! command -v nix >/dev/null 2>&1; then
    echo "ERROR: Nix not installed, cannot use fallback" >&2
    exit 1
fi

# Install package via Nix
nix-env -iA "nixpkgs.$PACKAGE" || {
    echo "ERROR: Failed to install $PACKAGE via Nix" >&2
    exit 1
}

echo "Successfully installed $PACKAGE via Nix fallback" >&2
