#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

WORKDIR_NAME="SPRK" # Verify repository root (check_workdir in bash/shared/default.sh), make sure we only run in WORKLDIR_NAME.

# SERVER IP/DOMAIN:PORT FOR TESTING
SERVER_IPV4="127.0.0.1"
SERVER_PORTV4="1566"

#BINS FOR TESTING
SERVER_BIN="$ROOT_DIR/server.sh"
CLIENT_BIN="$ROOT_DIR/client.sh"

# SESSION ID FOR TESTING
SESSION_ID_001="nHkrMugYTkqiQzZxUDq6wzb5NMXPbRv7gBjHmaUCyLFR21onNu9KWwL3CYMK"


# KEY / CERT FOR TESTING
KEY_RON_PEM="$ROOT_DIR/sample/ron.sk.pem"
CERT_RON="$ROOT_DIR/sample/ron.crt"

KEY_BETH_PEM="$ROOT_DIR/sample/beth.sk.pem"
CERT_BETH="$ROOT_DIR/sample/beth.crt"

KEY_BOB_PEM="$ROOT_DIR/sample/bob.sk.pem"
CERT_BOB="$ROOT_DIR/sample/bob.crt"


TIMESTAMP=$(date +%Y%m%d_%H%M%S) # timestamp.

################################
# COLOR
BOLD=$(tput bold)
RESET=$(tput sgr0)
# Regular colors
BLACK=$(tput setaf 0)
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
BLUE=$(tput setaf 4)
MAGENTA=$(tput setaf 5)
CYAN=$(tput setaf 6)
WHITE=$(tput setaf 7)

# Bright colors
BRIGHT_BLACK=$(tput setaf 8)
BRIGHT_RED=$(tput setaf 9)
BRIGHT_GREEN=$(tput setaf 10)
BRIGHT_YELLOW=$(tput setaf 11)
BRIGHT_BLUE=$(tput setaf 12)
BRIGHT_MAGENTA=$(tput setaf 13)
BRIGHT_CYAN=$(tput setaf 14)
BRIGHT_WHITE=$(tput setaf 15)

print_status()   { printf "%s%s%s\n" "$BOLD$WHITE" "$1" "$RESET"; }
print_success()  { printf "%s%s%s\n" "$BOLD$GREEN" "$1" "$RESET"; }
print_error()    { printf "%s%s%s\n" "$BOLD$RED" "$1" "$RESET"; }
print_warning()  { printf "%s%s%s\n" "$BOLD$MAGENTA" "$1" "$RESET"; }
print_highlight(){ printf "%s%s%s\n" "$BOLD$CYAN" "$1" "$RESET"; }

# Verify repository root, make sure we only run in WORKDIR_NAME.
check_workdir() {
	if [[ "${PWD##*/}" != "$WORKDIR_NAME" ]]; then
		print_error "Error: script must be run from repository root directory named $WORKDIR_NAME"
		exit 1
	fi
}