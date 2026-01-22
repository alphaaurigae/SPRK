#!/bin/bash

. bash/shared/default.sh # source bash colors / defaults.

BUILD_DIR="build"
BIN_DIR='bin'
BIN1_NAME='server / server.sh'
BIN2_NAME='client / client.sh'

configure() {
	print_status "Create build directories and config cmake"
	mkdir -p ${BUILD_DIR}
	cmake -S . -B ${BUILD_DIR} --fresh -DCMAKE_VERBOSE_MAKEFILE=ON -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
}

build() {
	print_status "Building project..."
	cmake --build ${BUILD_DIR} --clean-first --target all -- -j$(nproc) --debug
}

print_info() {
	print_status "INFO:"
	printf '\n'
	print_status "${BIN_DIR}/${BIN1_NAME} bin/server \"1566\" or ./server.sh"
	print_status "${BIN_DIR}/${BIN2_NAME} bin/client or ./server.sh 127.0.0.1 1566 ron sample/ron.sk.pem sample/ron.crt --sessionid bY5aaFZFaTXxktTSStJW99cQb73KZeRtrMnbvB7gprzecTcatZwqMmYu2tWz"
	printf '\n'
	print_status "Run CLANG-FORMAT & CLANG-TIDY on src/ with ./clang-format_clang-tidy_from_srctosrc.sh from reporoot"
	#./clang-format_clang-tidy_from_srctosrc.sh
	printf '\n'
	print_status "Run a simple unittest for server & client with ./unit.sh from reporoot"
	# echo -e "${BOLD}${BRIGHT_WHITE}Unit test shunit2 (unit/shunit2test.sh)${RESET}"
	# ./unit.sh
	printf '\n'
	print_status "Generate certificates by executing ./generate_pq_certs.sh from reporoot"
	print_status "Generate keys by executing ./keygen_run.sh from reporoot"
	printf '\n'
}

main() {
	check_workdir # verify the workdir by bash/shared/default.sh check_workdir as defined by WORKDIR_NAME=

	./clean_cmake.sh

	configure
	build
}

main
