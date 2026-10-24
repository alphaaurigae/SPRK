#!/usr/bin/env bash
set -euo pipefail
. bash/shared/default.sh

POSITIONAL=()
EXTRA_ARGS=()

passthrough() { exec bin/client "$@"; }

parse_args() {
	while [[ $# -gt 0 ]]; do
		case $1 in
			-h|--help|help) passthrough "$@" ;;
			--sessionid|-sessionid)
				shift
				[[ $# -gt 0 ]] || passthrough
				EXTRA_ARGS+=("--sessionid" "$1")
				shift ;;
			-*|--*) EXTRA_ARGS+=("$1"); shift ;;
			*) POSITIONAL+=("$1"); shift ;;
		esac
	done
}

main() {
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

	CMD=(bin/client "$IP" "$PORT" "$USER" "$SK_PATH" "$CERT_PATH")
	CMD+=("${EXTRA_ARGS[@]}")
	print_status "Executing: ${CMD[*]}"
	exec "${CMD[@]}"
}

main "$@"
