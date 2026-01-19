#!/usr/bin/env bash

# Wrapper for bin/server keygenerator to run with openssl 3.5 non default

. bash/shared/default.sh # source bash colors / defaults.

export PATH="/usr/local/openssl-3.5/bin:$PATH"
export LD_LIBRARY_PATH="/usr/local/openssl-3.5/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export OPENSSL_CONF="/usr/local/openssl-3.5/ssl/openssl.cnf"

print_openssl_info() {
	print_status "Using OpenSSL: $(openssl version)"
	printf '\n'
	print_status "lib path: $LD_LIBRARY_PATH"
	printf '\n'
}

print_openssl_info
exec bin/server "1566"