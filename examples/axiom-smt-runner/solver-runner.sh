#!/bin/sh
# Axiom SMT Solver Runner
#
# Securely executes SMT solvers with resource limits and timeout.
# Called by Axiom.jl Rust FFI via container runtime.

set -euo pipefail

# Show usage
show_usage() {
    cat <<EOF
Axiom SMT Solver Runner

Usage: solver-runner <solver> <script-file> <timeout-ms>

Solvers:
  z3       - Z3 Theorem Prover
  cvc5     - CVC5 SMT Solver
  yices    - Yices SMT Solver
  mathsat  - MathSAT SMT Solver

Security:
  - Process runs as non-root user (axiom-solver)
  - Resource limits enforced via cgroups
  - Timeout enforced via timeout(1)
  - Read-only root filesystem
  - No network access

Examples:
  solver-runner z3 /tmp/query.smt2 30000
  solver-runner cvc5 /tmp/query.smt2 5000
EOF
}

# Validate arguments
if [ $# -ne 3 ]; then
    show_usage
    exit 1
fi

SOLVER="$1"
SCRIPT_FILE="$2"
TIMEOUT_MS="$3"

# Convert timeout from milliseconds to seconds
TIMEOUT_SEC=$((TIMEOUT_MS / 1000))
if [ "$TIMEOUT_SEC" -lt 1 ]; then
    TIMEOUT_SEC=1
fi

# Validate solver is on allow-list
case "$SOLVER" in
    z3|cvc5|yices|mathsat)
        ;;
    *)
        echo "Error: Solver '$SOLVER' not on allow-list" >&2
        echo "Allowed: z3, cvc5, yices, mathsat" >&2
        exit 1
        ;;
esac

# Validate script file exists and is readable
if [ ! -f "$SCRIPT_FILE" ]; then
    echo "Error: Script file not found: $SCRIPT_FILE" >&2
    exit 1
fi

if [ ! -r "$SCRIPT_FILE" ]; then
    echo "Error: Script file not readable: $SCRIPT_FILE" >&2
    exit 1
fi

# Security check: Ensure we're running as non-root
if [ "$(id -u)" -eq 0 ]; then
    echo "Error: Refusing to run as root" >&2
    exit 1
fi

# Execute solver with timeout
# SECURITY: Use explicit command execution to prevent shell injection
# All variables are quoted to prevent word splitting
case "$SOLVER" in
    z3)
        exec timeout "${TIMEOUT_SEC}s" z3 "-T:${TIMEOUT_SEC}" "$SCRIPT_FILE"
        ;;
    cvc5)
        exec timeout "${TIMEOUT_SEC}s" cvc5 "--tlimit=${TIMEOUT_MS}" "$SCRIPT_FILE"
        ;;
    yices)
        exec timeout "${TIMEOUT_SEC}s" yices "--timeout=${TIMEOUT_SEC}" "$SCRIPT_FILE"
        ;;
    mathsat)
        # MathSAT doesn't have built-in timeout, use timeout(1)
        exec timeout "${TIMEOUT_SEC}s" mathsat "$SCRIPT_FILE"
        ;;
esac
