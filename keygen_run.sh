#!/usr/bin/env bash

# Wrapper for bin/user_keygen keygenerator to run with openssl 3.5 non default

. bash/shared/default.sh # source bash colors / defaults.

# Force our custom OpenSSL 3.5 (same as client/server)
export PATH="/usr/local/openssl-3.5/bin:$PATH"
export LD_LIBRARY_PATH="/usr/local/openssl-3.5/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export OPENSSL_CONF="/usr/local/openssl-3.5/ssl/openssl.cnf"  # optional but good for consistency

print_openssl_info() {
	print_status "Using OpenSSL: $(openssl version)"
	printf '\n'
	print_status "lib path: $LD_LIBRARY_PATH"
	printf '\n'
}

print_openssl_info

exec bin/user_keygen "$@"