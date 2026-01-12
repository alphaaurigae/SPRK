#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
#  Post-quantum certificate generator – native OpenSSL 3.5.0
# =============================================================================

# IMPORTANT: your build installed libs into lib64, not lib!
export LD_PRELOAD="/usr/local/openssl-3.5/lib64/libssl.so.3 /usr/local/openssl-3.5/lib64/libcrypto.so.3${LD_PRELOAD:+:$LD_PRELOAD}"
export PATH="/usr/local/openssl-3.5/bin:$PATH"

# Debug output – helps diagnose
echo "LD_PRELOAD set to: $LD_PRELOAD"
echo "PATH set to: $PATH"

# Verify correct OpenSSL version
OPENSSL_VERSION=$(openssl version 2>/dev/null || echo "failed")
if ! echo "$OPENSSL_VERSION" | grep -q "OpenSSL 3.5"; then
    echo "ERROR: Wrong OpenSSL version loaded!"
    echo "Expected: OpenSSL 3.5.x"
    echo "Got:      $OPENSSL_VERSION"
    echo "(run 'ldd /usr/local/openssl-3.5/bin/openssl' to see loaded libraries)"
    exit 1
fi

echo "Success: Using correct OpenSSL version: $OPENSSL_VERSION"

# ────────────────────────────────────────────────────────────────────────────────
# Rest of your script (unchanged)
# ────────────────────────────────────────────────────────────────────────────────

CLIENTS=("ron" "bob" "beth")
CERT_DIR="sample/sample_test_cert"

# Backup old certs if they exist
if ls "$CERT_DIR"/*.{crt,key,csr,srl} &>/dev/null; then
    BACKUP_DIR="${CERT_DIR}.old.$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    cp -r "$CERT_DIR"/* "$BACKUP_DIR/" 2>/dev/null || true
    echo "Old certificates backed up to $BACKUP_DIR"
fi

# Clean old files
rm -f "$CERT_DIR"/*.{crt,key,csr,srl}

mkdir -p "$CERT_DIR"

ensure_entropy() {
    local current=$(cat /proc/sys/kernel/random/entropy_avail 2>/dev/null || echo 0)
    if (( current < 2000 )); then
        echo "Low entropy detected — waiting a few seconds..."
        sleep 6
    fi
}

write_extensions() {
    cat > "$CERT_DIR/openssl_ext.cnf" <<'EOF'
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign,digitalSignature

[v3_server]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth

[v3_client]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
EOF
}

generate_ca() {
    echo "→ Generating CA key & certificate (ML-DSA-87)..."
    openssl genpkey -algorithm mldsa87 -out "$CERT_DIR/ca.key"
    openssl req -new -key "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.csr" -subj "/CN=SPRK CA"
    openssl x509 -req -in "$CERT_DIR/ca.csr" -signkey "$CERT_DIR/ca.key" \
        -out "$CERT_DIR/ca.crt" -days 3650 \
        -extfile "$CERT_DIR/openssl_ext.cnf" -extensions v3_ca
    rm -f "$CERT_DIR/ca.csr"
}

generate_server() {
    echo "→ Generating server certificate (ML-DSA-87)..."
    openssl genpkey -algorithm mldsa87 -out "$CERT_DIR/server.key"
    openssl req -new -key "$CERT_DIR/server.key" -out "$CERT_DIR/server.csr" -subj "/CN=SPRK Server"
    openssl x509 -req -in "$CERT_DIR/server.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
        -CAcreateserial -out "$CERT_DIR/server.crt" -days 365 \
        -extfile "$CERT_DIR/openssl_ext.cnf" -extensions v3_server
    rm -f "$CERT_DIR/server.csr"
}

generate_clients() {
    for client in "${CLIENTS[@]}"; do
        echo "→ Generating $client client certificate..."
        openssl genpkey -algorithm mldsa87 -out "$CERT_DIR/${client}_tls.key"
        openssl req -new -key "$CERT_DIR/${client}_tls.key" -out "$CERT_DIR/${client}.csr" -subj "/CN=$client"
        openssl x509 -req -in "$CERT_DIR/${client}.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
            -CAcreateserial -out "$CERT_DIR/${client}.crt" -days 365 \
            -extfile "$CERT_DIR/openssl_ext.cnf" -extensions v3_client
        rm -f "$CERT_DIR/${client}.csr"
    done
}

# ────────────────────────────────────────────────────────────────────────────────
# Main execution
# ────────────────────────────────────────────────────────────────────────────────

ensure_entropy
write_extensions

generate_ca
generate_server
generate_clients

rm -f "$CERT_DIR/openssl_ext.cnf"

echo ""
echo "All certificates generated successfully using native OpenSSL 3.5.0 + ML-DSA-87"
echo "KEM recommendation: x25519_mlkem512 (hybrid post-quantum)"
echo ""
echo "Next step: rebuild & run the server"

ls -la "$CERT_DIR"

#openssl rsa -in sample/sample_test_cert/

head -n 5 sample/sample_test_cert/ca.key
tail -n 5 sample/sample_test_cert/ca.key

#openssl rsa -in sample/sample_test_cert/server.key -check -noout

lsb_release -a

openssl version -a
openssl --help
openssl list -providers

openssl list -kem-algorithms | grep mlkem51

openssl list -signature-algorithms | grep mldsa87

# After version check
if ! openssl list -signature-algorithms | grep -q mldsa87; then
    echo "ERROR: mldsa87 algorithm not available!"
    exit 1
fi
echo "ML-DSA-87 support confirmed"
