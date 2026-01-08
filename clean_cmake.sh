#!/bin/bash


BOLD='\033[1m'
BRIGHT_WHITE='\033[1;37m'
RESET='\033[0m' 

BUILD_DIR="build"
BIN_DIR="bin"

CLANG_TIDY="clang_tidy_output"
clean() {
    echo -e "${BOLD}${BRIGHT_WHITE}Cleaning build and bin directories...${RESET}"
    rm -rf ${BUILD_DIR} ${BIN_DIR} ${CLANG_TIDY}
}


clean