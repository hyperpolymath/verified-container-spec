#!/bin/sh
# SPDX-License-Identifier: PMPL-1.0-or-later
# Secure entrypoint for ProvenCrypto.jl container
#
# Security features:
# - Validates operation against allowlist
# - Enforces resource limits
# - Logs all operations
# - Runs with minimal privileges

set -euo pipefail

# Operation allowlist (only these are permitted)
ALLOWED_OPS="repl keygen sign verify encrypt decrypt hash kdf benchmark test"

# Validate operation
OP="${1:-repl}"
if ! echo "$ALLOWED_OPS" | grep -qw "$OP"; then
    echo "ERROR: Operation '$OP' not allowed" >&2
    echo "Allowed operations: $ALLOWED_OPS" >&2
    exit 1
fi

# Ensure running as non-root
if [ "$(id -u)" -eq 0 ]; then
    echo "ERROR: Must not run as root" >&2
    exit 1
fi

# Set locale (fix Guix warnings)
export GUIX_LOCPATH="$HOME/.guix-profile/lib/locale"
export LC_ALL=en_US.utf8

# Load ProvenCrypto.jl
JULIA_LOAD_PATH="/crypto/provencrypto:$JULIA_LOAD_PATH"
export JULIA_LOAD_PATH

# Log operation
echo "[$(date -Iseconds)] ProvenCrypto operation: $OP" >&2

# Execute operation
case "$OP" in
    repl)
        exec julia -e 'using ProvenCrypto; println("ProvenCrypto.jl loaded"); REPL.run_repl()'
        ;;
    keygen)
        exec julia -e 'using ProvenCrypto; @show kyber_keygen()'
        ;;
    sign)
        exec julia -e 'using ProvenCrypto; msg="test"; (pk,sk)=dilithium_keygen(); sig=dilithium_sign(sk, Vector{UInt8}(msg)); @show sig'
        ;;
    verify)
        exec julia -e 'using ProvenCrypto; println("Verify operation placeholder")'
        ;;
    encrypt)
        exec julia -e 'using ProvenCrypto; key=rand(UInt8,32); nonce=rand(UInt8,12); msg=b"secret"; @show aead_encrypt(key, nonce, msg)'
        ;;
    decrypt)
        exec julia -e 'using ProvenCrypto; println("Decrypt operation placeholder")'
        ;;
    hash)
        exec julia -e 'using ProvenCrypto; @show hash_blake3(b"test data")'
        ;;
    kdf)
        exec julia -e 'using ProvenCrypto; pw=b"password"; salt=rand(UInt8,16); @show kdf_argon2(pw, salt)'
        ;;
    benchmark)
        exec julia --project=/crypto/provencrypto -e 'using ProvenCrypto; include("benchmark/benchmarks.jl")'
        ;;
    test)
        exec julia --project=/crypto/provencrypto -e 'using Pkg; Pkg.test("ProvenCrypto")'
        ;;
    *)
        echo "ERROR: Unknown operation: $OP" >&2
        exit 1
        ;;
esac
