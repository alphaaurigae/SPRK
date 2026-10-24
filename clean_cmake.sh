#!/usr/bin/env bash
set -euo pipefail
. bash/shared/default.sh
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${script_dir}/build"
BIN_DIR="${script_dir}/bin"

ls_all() {
	print_status "Listing current state:"
	[ -d "$BUILD_DIR" ] && ls -la "$BUILD_DIR" || true
	[ -d "$BIN_DIR" ] && ls -la "$BIN_DIR" || true
}

clean_all() {
	print_status "Cleaning build and bin directories"
	rm -rf "${BUILD_DIR}" "${BIN_DIR}"
	print_status "Cleaning done"
}

main() {
	check_workdir
	ls_all
	clean_all
	ls_all
}

main
