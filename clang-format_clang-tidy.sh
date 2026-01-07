#!/usr/bin/env bash

set -e

OUTPUT_ROOT="$(pwd)/clang_tidy_output"

show_help() {
    cat << EOF
Usage:
  $0 [options] <file|dir> [file|dir ...]

Description:
  Formats C++ files with clang-format and runs clang-tidy on the original sources.

Options:
  -h, --help      Show this help message and exit

Notes:
  - Original files are never modified
  - Formatted copies are in: $OUTPUT_ROOT
EOF
}

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

if [[ $# -eq 0 || "$1" == "-h" || "$1" == "--help" ]]; then
    show_help
    exit 0
fi

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

FILES=()
for target in "$@"; do
    if [[ -f "$target" ]]; then
        case "$target" in
            *.cpp|*.hpp|*.h) FILES+=("$target") ;;
        esac
    elif [[ -d "$target" ]]; then
        while IFS= read -r f; do
            FILES+=("$f")
        done < <(find "$target" -type f \( -name "*.cpp" -o -name "*.hpp" -o -name "*.h" \))
    else
        echo "Error: invalid target '$target'"
        exit 1
    fi
done

if [[ ${#FILES[@]} -eq 0 ]]; then
    echo "Error: no valid C++ files found"
    exit 1
fi

mkdir -p "$OUTPUT_ROOT"
echo "Formatting files into $OUTPUT_ROOT ..."
for f in "${FILES[@]}"; do
    RELATIVE_PATH=$(realpath --relative-to="$PWD" "$f")
    OUTFILE="$OUTPUT_ROOT/$RELATIVE_PATH"
    mkdir -p "$(dirname "$OUTFILE")"
    clang-format -style="$CLANG_FORMAT_STYLE" "$f" > "$OUTFILE"
done


echo "Running clang-tidy on original .cpp files..."

BUILD_DIR="$PWD/build"
if [[ ! -f "$BUILD_DIR/compile_commands.json" ]]; then
    echo "Error: compile_commands.json not found in $BUILD_DIR"
    echo "    Please rebuild your project with CMake."
    exit 1
fi

CPP_FILES=()
for target in "$@"; do
    if [[ -d "$target" ]]; then
        while IFS= read -r f; do
            [[ "$f" == *.cpp ]] && CPP_FILES+=("$f")
        done < <(find "$target" -type f -name "*.cpp")
    elif [[ -f "$target" && "$target" == *.cpp ]]; then
        CPP_FILES+=("$target")
    fi
done

if [[ ${#CPP_FILES[@]} -eq 0 ]]; then
    echo "No .cpp files found – skipping clang-tidy."
else
    for f in "${CPP_FILES[@]}"; do
        echo "Running clang-tidy on: $f"
        clang-tidy \
            -checks="$CHECKS" \
            -p "$BUILD_DIR" \
            -header-filter=.* \
            "$f" -- \
            -std=gnu++23 \
            -I"$PWD/src" \
            -I"$PWD/src/shared" \
            -I"$PWD/src/client" \
            -I"$PWD/src/server" \
            || echo "clang-tidy reported issues in $f (continuing)"
    done
fi

echo "Done."
echo "Formatted copies are in: $OUTPUT_ROOT"