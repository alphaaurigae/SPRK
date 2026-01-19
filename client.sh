#!/usr/bin/env bash
set -euo pipefail

. bash/shared/default.sh

export PATH="/usr/local/openssl-3.5/bin:$PATH"
export LD_LIBRARY_PATH="/usr/local/openssl-3.5/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export OPENSSL_CONF="/usr/local/openssl-3.5/ssl/openssl.cnf"

POSITIONAL=()
EXTRA_ARGS=()

print_openssl_info() {
	print_status "Using OpenSSL: $(openssl version)"
	printf '\n'
	print_status "lib path: $LD_LIBRARY_PATH"
	printf '\n'
}

passthrough() {
	exec bin/client "$@"
}

parse_args() {
	while [[ $# -gt 0 ]]; do
		case $1 in
			-h|--help|help)
				passthrough "$@"
				;;
			--sessionid|-sessionid)
				shift
				[[ $# -gt 0 ]] || passthrough
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
}

main() {
	print_openssl_info
	parse_args "$@"

	if [[ ${#POSITIONAL[@]} -lt 3 ]]; then
		passthrough "$@"
	fi

	IP="${POSITIONAL[0]}"
	PORT="${POSITIONAL[1]}"
	USER="${POSITIONAL[2]}"
	SK_PATH="${POSITIONAL[3]:-${IDENTITY_SK:-sample/${USER}.sk.pem}}"
	CERT_PATH="${POSITIONAL[4]:-${CLIENT_CERT:-sample/${USER}.crt}}"

	print_highlight "Using:"
	print_status "IP:           $IP"
	print_status "Port:         $PORT"
	print_status "Username:     $USER"
	print_status "Identity key: $SK_PATH"
	print_status "Client cert:  $CERT_PATH"
	printf '\n'

	CMD=(bin/client "$IP" "$PORT" "$USER" "$SK_PATH" "$CERT_PATH")
	CMD+=("${EXTRA_ARGS[@]}")

	print_status "Executing: ${CMD[*]}"
	exec "${CMD[@]}"
}

main "$@"
