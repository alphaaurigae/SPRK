#!/usr/bin/env bash
# client.sh - Flexible wrapper for PQ chat client

# Force custom OpenSSL 3.5
export PATH="/usr/local/openssl-3.5/bin:$PATH"
export LD_LIBRARY_PATH="/usr/local/openssl-3.5/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export OPENSSL_CONF="/usr/local/openssl-3.5/ssl/openssl.cnf"

echo "OpenSSL: $(openssl version)"
echo "lib path: $LD_LIBRARY_PATH"

# Defaults
DEFAULT_USER="ron"
SK_PATH="${IDENTITY_SK:-sample/${USER:-$DEFAULT_USER}.sk.pem}"
CERT_PATH="${CLIENT_CERT:-sample/${USER:-$DEFAULT_USER}.crt}"

# Collect positional and extra args
POSITIONAL=()
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
    case $1 in
        --sessionid|-sessionid)
            shift
            if [[ $# -gt 0 ]]; then
                EXTRA_ARGS+=("--sessionid" "$1")  # Force double dash + value
                shift
            else
                echo "Error: --sessionid requires a value"
                exit 1
            fi
            ;;
        -*|--*)
            EXTRA_ARGS+=("$1")
            shift
            ;;
        *)
            POSITIONAL+=("$1")
            shift
            ;;
    esac
done

# Assign positional args
if [[ ${#POSITIONAL[@]} -ge 1 ]]; then USER="${POSITIONAL[0]}"; fi
if [[ ${#POSITIONAL[@]} -ge 2 ]]; then SK_PATH="${POSITIONAL[1]}"; fi
if [[ ${#POSITIONAL[@]} -ge 3 ]]; then CERT_PATH="${POSITIONAL[2]}"; fi

echo "Using:"
echo "  Username: $USER"
echo "  Identity key: $SK_PATH"
echo "  Client cert:  $CERT_PATH"
echo ""

# Build command
CMD=(bin/client 127.0.0.1 1566 "$USER" "$SK_PATH" "$CERT_PATH")

# Append extra args (including --sessionid value)
CMD+=("${EXTRA_ARGS[@]}")

echo "Executing: ${CMD[*]}"
echo ""

exec "${CMD[@]}"