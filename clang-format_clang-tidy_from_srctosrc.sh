#!/usr/bin/env bash

# CLANG-FORMAT ; CLANG-TIDY integration script to build flow.
#############################################################
# PREQUISITES
# Adjust: SRC_DIR if source file dir differs.
# Adjust: CHECKS=' ; CLANG_FORMAT_STYLE="{
# ADJUST: WORKLDIR_NAME
#############################
# FLOW
# 1. Copy src/ to src_old_[timestamp]; verify copy successful.
# 2. Run CLANG-FORMAT ; CLANG-TIDY depending on switch for the files in src/
# Add src_old* to .gitignore ...
#############################################################

set -euo pipefail

. bash/shared/default.sh # source bash colors / defaults.

SRC_OLD="$PWD/src_old_$TIMESTAMP" # backup di-
SRC_DIR="$PWD/src" # base dir
BUILD_DIR="$PWD/build" # build dir for clang-tidy input.

# switch for clang-format and clang-tidy false / true.
DO_CLANG_FORMAT="true"
DO_CLANG_TIDY="true"

# Clang-tidy check rules
CHECKS='
clang-analyzer-*,
bugprone-*,
performance-*,
portability-*,
modernize-*,
cppcoreguidelines-*,
readability-*,
-hicpp-*,
-llvmlibc-*,
-altera-*,
-google-*,
-modernize-use-trailing-return-type,
-cppcoreguidelines-avoid-magic-numbers,
-readability-magic-numbers,
-readability-identifier-length,
-readability-braces-around-statements,
-misc-include-cleaner,
-llvm-header-guard
'

# Clang-format style
CLANG_FORMAT_STYLE="{
BasedOnStyle: LLVM,
IndentWidth: 4,
TabWidth: 4,
UseTab: Never,
Language: Cpp,
BreakBeforeBraces: Allman,
AlignConsecutiveAssignments: true,
AlignConsecutiveDeclarations: true
}"

# BAckup src/
backup_src() {
	if [[ ! -d "$SRC_OLD" ]]; then
		cp -r "$SRC_DIR" "$SRC_OLD"
		print_status "Backup of src/ created at $SRC_OLD"

		print_status "Verifying backup integrity..."
		while IFS= read -r f; do
		REL_PATH="${f#$SRC_OLD/}"
		SRC_FILE="$SRC_DIR/$REL_PATH"

		if [[ ! -f "$SRC_FILE" ]]; then
			print_error "Error: backup file $REL_PATH does not exist in source!"
			exit 1
		fi

		if ! cmp -s "$SRC_FILE" "$f"; then
			print_error "Error: checksum mismatch for $REL_PATH"
			exit 1
		fi
		done < <(find "$SRC_OLD" -type f)
		print_success "Backup verification passed."
	fi
}

collect_files() {
	local target_dir="$1"
	FILES=()
	while IFS= read -r f; do
	case "$f" in
		*.cpp|*.hpp|*.h) FILES+=("$f") ;;
	esac
	done < <(find "$target_dir" -type f \( -name "*.cpp" -o -name "*.hpp" -o -name "*.h" \) -print)

	if [[ ${#FILES[@]} -eq 0 ]]; then
		print_warning "Error: no valid C++ files found in $target_dir"
		exit 1
	fi
}

# Clang-format on SRC_DIR
run_clang_format() {
	print_status "Running clang-format on files in $SRC_DIR ..."
	for f in "${FILES[@]}"; do
		TMPFILE="$(mktemp)"
		clang-format -style="$CLANG_FORMAT_STYLE" "$f" > "$TMPFILE"
		mv "$TMPFILE" "$f"
	done
	print_status "Clang-format completed on ${#FILES[@]} files."
}

# Clang-tidy on SRC_DIR
run_clang_tidy() {
	print_status "Running clang-tidy on files in $SRC_DIR ..."

	if [[ ! -f "$BUILD_DIR/compile_commands.json" ]]; then
        	print_error "Error: compile_commands.json not found in $BUILD_DIR"
        	print_highlight "Please rebuild your project with CMake."
		exit 1
	fi

	CPP_FILES=()
	while IFS= read -r f; do
	[[ "$f" == *.cpp ]] && CPP_FILES+=("$f")
	done < <(find "$SRC_DIR" -type f -name "*.cpp")

	if [[ ${#CPP_FILES[@]} -eq 0 ]]; then
		print_warning "No .cpp files found – skipping clang-tidy."
		return
	fi

	for f in "${CPP_FILES[@]}"; do
		print_status "Running clang-tidy on: $f"
		clang-tidy \
		-checks="$CHECKS" \
		-p "$BUILD_DIR" \
		-header-filter=.* \
		"$f" -- \
		-std=gnu++23 \
		-I"$SRC_DIR" \
		|| print_warning "clang-tidy reported issues in $f (continuing)"
	done
}

main() {
	check_workdir # verify the workdir by bash/shared/default.sh check_workdir as defined by WORKDIR_NAME=
	backup_src
	collect_files "$SRC_DIR"

	# Check switch and run if.
	$DO_CLANG_FORMAT && run_clang_format
	$DO_CLANG_TIDY && run_clang_tidy

	print_success "All tasks completed."
}

main
