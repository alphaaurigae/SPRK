#!/usr/bin/env bash
set -euo pipefail

OPENSSL_BIN="${OPENSSL_BIN:-openssl}"

OPENSSL_VERSION=$("$OPENSSL_BIN" version 2>/dev/null || echo "failed")
if ! echo "$OPENSSL_VERSION" | grep -qE "OpenSSL 3\.(5|[6-9]|[1-9][0-9])"; then
    echo "ERROR: OpenSSL 3.5+ required (native ML-KEM/ML-DSA support)."
    echo "Found: $OPENSSL_VERSION"
    exit 1
fi
echo "Using: $OPENSSL_VERSION"

if ! "$OPENSSL_BIN" list -signature-algorithms | grep -qi mldsa87; then
    echo "ERROR: ML-DSA-87 not available in this OpenSSL build."; exit 1
fi
if ! "$OPENSSL_BIN" list -kem-algorithms | grep -qi "ml-kem-768"; then
    echo "ERROR: ML-KEM-768 not available in this OpenSSL build."; exit 1
fi
echo "ML-DSA-87 / ML-KEM-768 confirmed available."

CLIENTS=("ron" "bob" "beth")
CERT_DIR="sample/sample_test_cert"

if [[ -d "$CERT_DIR" ]] && compgen -G "$CERT_DIR/*.key" > /dev/null; then
    BACKUP_DIR="${CERT_DIR}.old.$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    cp -r "$CERT_DIR"/* "$BACKUP_DIR/" 2>/dev/null || true
    echo "Old certificates backed up to $BACKUP_DIR -- treat as compromised, regenerate everything."
fi

rm -f "$CERT_DIR"/*.crt "$CERT_DIR"/*.key "$CERT_DIR"/*.csr "$CERT_DIR"/*.srl
mkdir -p "$CERT_DIR"

cat > "$CERT_DIR/openssl_ext.cnf" <<'EXT'
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
EXT

echo "-> Generating CA (ML-DSA-87)..."
"$OPENSSL_BIN" genpkey -algorithm mldsa87 -out "$CERT_DIR/ca.key"
"$OPENSSL_BIN" req -new -key "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.csr" -subj "/CN=SPRK CA"
"$OPENSSL_BIN" x509 -req -in "$CERT_DIR/ca.csr" -signkey "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.crt" -days 3650 -extfile "$CERT_DIR/openssl_ext.cnf" -extensions v3_ca

echo "-> Generating server cert..."
"$OPENSSL_BIN" genpkey -algorithm mldsa87 -out "$CERT_DIR/server.key"
"$OPENSSL_BIN" req -new -key "$CERT_DIR/server.key" -out "$CERT_DIR/server.csr" -subj "/CN=SPRK Server"
"$OPENSSL_BIN" x509 -req -in "$CERT_DIR/server.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial -out "$CERT_DIR/server.crt" -days 365 -extfile "$CERT_DIR/openssl_ext.cnf" -extensions v3_server

for client in "${CLIENTS[@]}"; do
  echo "-> Generating $client TLS client cert..."
  "$OPENSSL_BIN" genpkey -algorithm mldsa87 -out "$CERT_DIR/${client}_tls.key"
  "$OPENSSL_BIN" req -new -key "$CERT_DIR/${client}_tls.key" -out "$CERT_DIR/${client}.csr" -subj "/CN=$client"
  "$OPENSSL_BIN" x509 -req -in "$CERT_DIR/${client}.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial -out "$CERT_DIR/${client}.crt" -days 365 -extfile "$CERT_DIR/openssl_ext.cnf" -extensions v3_client
done

rm -f "$CERT_DIR"/*.csr "$CERT_DIR/openssl_ext.cnf"
echo "All TLS certificates generated (ML-DSA-87, native OpenSSL 3.5+)."
echo "Next: ./keygen_run.sh <username> --out-dir sample for each user, then ./build_cmake.sh"
ls -la "$CERT_DIR"
