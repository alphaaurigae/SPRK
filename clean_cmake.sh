#!/usr/bin/env bash
set -euo pipefail

. bash/shared/default.sh # source bash colors / defaults.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BUILD_DIR="${script_dir}/build"
BIN_DIR="${script_dir}/bin"
CLANG_TIDY="${script_dir}/clang_tidy_output"
CACHE_DIR="$HOME/.cache"

ls_all() {
	print_status "Listing current state:"
	[ -d "$BUILD_DIR" ] && ls -la "$BUILD_DIR" || true
	[ -d "$BIN_DIR" ] && ls -la "$BIN_DIR" || true
	[ -d "$CLANG_TIDY" ] && ls -la "$CLANG_TIDY" || true
	ls -la "$CACHE_DIR"
}

clean_all() {
	print_status "Cleaning build and bin directories:"
	printf '%s\n' "${BUILD_DIR}"
	printf '%s\n' "${BIN_DIR}"
	printf '%s\n' "${CLANG_TIDY}"
	printf '%s\n' "${CACHE_DIR}/*"
	printf '\n'
	printf '%s\n' "Processing ..."
	rm -rf ${BUILD_DIR} ${BIN_DIR} ${CLANG_TIDY}
	rm -rf "${CACHE_DIR:?}/"* && mkdir -p ${CACHE_DIR}
	rm -rf src_old*
	print_status "Cleaning done"
}


main() {
	check_workdir # verify the workdir by bash/shared/default.sh check_workdir as defined by WORKDIR_NAME=
	ls_all
	clean_all
	ls_all
}

main