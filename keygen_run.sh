#!/usr/bin/env bash
# keygen.sh - Wrapper for pqsig_keygen tool

# Force our custom OpenSSL 3.5 (same as client/server)
export PATH="/usr/local/openssl-3.5/bin:$PATH"
export LD_LIBRARY_PATH="/usr/local/openssl-3.5/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export OPENSSL_CONF="/usr/local/openssl-3.5/ssl/openssl.cnf"  # optional but good for consistency

echo "Using OpenSSL: $(openssl version)"
echo "lib path: $LD_LIBRARY_PATH"

# Run the keygen binary with all arguments passed through
exec ./keygen "$@"