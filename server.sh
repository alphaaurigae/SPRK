#!/usr/bin/env bash
# server.sh

export PATH="/usr/local/openssl-3.5/bin:$PATH"
export LD_LIBRARY_PATH="/usr/local/openssl-3.5/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"  # note lib64
export OPENSSL_CONF="/usr/local/openssl-3.5/ssl/openssl.cnf"  # ← critical line!

exec bin/server "1566"