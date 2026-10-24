#!/bin/bash
. bash/shared/default.sh
BUILD_DIR="build"
BIN_DIR='bin'

configure() {
	print_status "Create build directories and config cmake"
	mkdir -p ${BUILD_DIR}
	cmake -S . -B ${BUILD_DIR} --fresh -DCMAKE_VERBOSE_MAKEFILE=ON -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
}

build() {
	print_status "Building project..."
	cmake --build ${BUILD_DIR} --clean-first --target all -- -j$(nproc)
}

print_info() {
	print_status "INFO:"
	print_status "bin/server \"1566\" or ./server.sh"
	print_status "bin/client or ./client.sh 127.0.0.1 1566 ron sample/ron.sk.pem sample/ron.crt --sessionid <id>"
	print_status "Run integration test with ./unit.sh"
	print_status "Generate certificates: ./generate_pq_certs.sh"
	print_status "Generate per-user identity keys: ./keygen_run.sh <username> --out-dir sample"
}

main() {
	check_workdir
	./clean_cmake.sh
	configure
	build
	print_info
}

main
