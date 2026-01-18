#!/usr/bin/env bash
# client.sh - Flexible wrapper for PQ chat client

export PATH="/usr/local/openssl-3.5/bin:$PATH"
export LD_LIBRARY_PATH="/usr/local/openssl-3.5/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export OPENSSL_CONF="/usr/local/openssl-3.5/ssl/openssl.cnf"

echo "OpenSSL: $(openssl version)"
echo "lib path: $LD_LIBRARY_PATH"

DEFAULT_USER="ron"
DEFAULT_IP="127.0.0.1"
DEFAULT_PORT="1566"

IP="$DEFAULT_IP"
PORT="$DEFAULT_PORT"
SK_PATH=""
CERT_PATH=""

POSITIONAL=()
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
    case $1 in
        --sessionid|-sessionid)
            shift
            [[ $# -gt 0 ]] || exit 1
            EXTRA_ARGS+=("--sessionid" "$1")
            shift
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

if [[ ${#POSITIONAL[@]} -ge 1 ]]; then IP="${POSITIONAL[0]}"; fi
if [[ ${#POSITIONAL[@]} -ge 2 ]]; then PORT="${POSITIONAL[1]}"; fi
if [[ ${#POSITIONAL[@]} -ge 3 ]]; then USER="${POSITIONAL[2]}"; else USER="$DEFAULT_USER"; fi
if [[ ${#POSITIONAL[@]} -ge 4 ]]; then SK_PATH="${POSITIONAL[3]}"; else SK_PATH="${IDENTITY_SK:-sample/${USER}.sk.pem}"; fi
if [[ ${#POSITIONAL[@]} -ge 5 ]]; then CERT_PATH="${POSITIONAL[4]}"; else CERT_PATH="${CLIENT_CERT:-sample/${USER}.crt}"; fi

echo "Using:"
echo "  IP:           $IP"
echo "  Port:         $PORT"
echo "  Username:     $USER"
echo "  Identity key: $SK_PATH"
echo "  Client cert:  $CERT_PATH"
echo ""

CMD=(bin/client "$IP" "$PORT" "$USER" "$SK_PATH" "$CERT_PATH")
CMD+=("${EXTRA_ARGS[@]}")

echo "Executing: ${CMD[*]}"
echo ""

exec "${CMD[@]}"
