#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

DEBUG=0

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

openssl_branch="${OPENSSL_BRANCH:-}"
openssl_tag="${OPENSSL_TAG:-openssl-3.5}"
liboqs_branch="${LIBOQS_BRANCH:-0.15.0}"
liboqs_tag="${LIBOQS_TAG:-}"
oqs_provider_branch="${OQS_PROVIDER_BRANCH:-}"
oqs_provider_tag="${OQS_PROVIDER_TAG:-0.11.0}"

log() {
	if [[ ${DEBUG:-0} -ne 0 ]]; then
		printf '%s\n' "$*"
	else
		printf '%s\n' "$*"
	fi
}

ensure_ubuntu_24() {
	if ! command -v lsb_release >/dev/null 2>&1; then
		sudo apt-get update
		sudo apt-get install -y lsb-release
	fi
	local ver="$(lsb_release -rs || true)"
	case "$ver" in
	24.*) return 0 ;;
	*) printf 'ERROR: This script expects Ubuntu 24 (detected: %s)\n' "$ver" >&2; exit 2 ;;
	esac
}

cleanup_openssl3_5() {
	sudo ldconfig || true
	sudo rm -rf /usr/local/openssl-3.5 || true
	if [[ -L /usr/local/bin/openssl ]]; then
		local target="$(readlink -f /usr/local/bin/openssl || true)"
	if [[ -z "$target" || "$target" == /usr/local/openssl-3.5/* ]]; then
		sudo rm -f /usr/local/bin/openssl || true
	fi
	fi
	sudo rm -f /usr/local/openssl-3.5/ssl/oqs-provider.conf || true
	sudo rm -f /usr/local/openssl-3.5/ssl/openssl.cnf.bak.* || true
	sudo ldconfig || true
}

cleanup_oqs_main() {
	sudo rm -f /usr/local/lib/liboqs.* || true
	sudo rm -f /usr/local/lib64/liboqs.* || true
	sudo rm -f /usr/local/lib/pkgconfig/liboqs.pc || true
	sudo rm -rf /usr/local/lib/cmake/liboqs || true
	sudo rm -rf /usr/local/include/oqs || true
	sudo rm -rf /usr/local/share/doc/liboqs || true
	sudo rm -rf /usr/local/share/man/man*/*oqs* || true
	sudo rm -rf /usr/local/openssl-3.5/lib*/liboqs* || true
	sudo rm -rf /usr/local/openssl-3.5/include/oqs || true
	sudo ldconfig || true
	find /usr/local -name "*oqs*" 2>/dev/null || true
	find /usr -name "*oqs*" 2>/dev/null || true
}

cleanup_oqs_provider() {
	sudo rm -rf /usr/local/include/oqs-provider || true
	sudo rm -f /usr/local/openssl-3.5/lib64/ossl-modules/oqsprovider.so || true
	sudo rm -f /usr/local/openssl-3.5/lib/ossl-modules/oqsprovider.so || true
	sudo rm -f /usr/local/lib/ossl-modules/oqsprovider.so || true
	sudo rm -f /usr/local/lib64/ossl-modules/oqsprovider.so || true
	sudo rm -f /usr/lib64/ossl-modules/oqsprovider.so || true
	sudo rm -f /usr/lib/x86_64-linux-gnu/ossl-modules/oqsprovider.so || true
	sudo rm -f /usr/lib/ossl-modules/oqsprovider.so || true
	sudo rm -f /usr/local/lib/liboqsprovider.* || true
	sudo rm -f /usr/local/lib/pkgconfig/oqsprovider.pc || true
	sudo rm -rf /usr/local/lib/cmake/oqs-provider* || true
	sudo rm -f /usr/local/openssl-3.5/ssl/oqs-provider.conf || true
	sudo ldconfig || true
	find /usr/local -name "*oqsprovider*" 2>/dev/null || true
	find /usr -name "*oqsprovider*" 2>/dev/null || true
	if command -v openssl >/dev/null 2>&1; then
		openssl list -providers || true
	fi
}

verify_git_branch() {
	local repo_dir=$1
	local expected=$2
	cd "$repo_dir"
	local current=$(git describe --tags --exact-match HEAD 2>/dev/null || git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "UNKNOWN")
	if [[ "$current" != "$expected" ]]; then
		echo "WARNING: $repo_dir checked out to '$current', expected '$expected'"
	else
		echo "Verified $repo_dir branch/tag: $current"
	fi
}

setup_openssl3_5() {
	cd "$SCRIPT_DIR"

	local ref_to_use=""
	[[ -n "$openssl_branch" ]] && ref_to_use="$openssl_branch" || ref_to_use="$openssl_tag"

	if [[ -d openssl/.git ]]; then
		cd openssl || exit 1
		echo "Updating clone"
		git remote update --prune 2>/dev/null || git fetch --all --prune --tags || true
		git fetch --tags origin || true
		git checkout --detach 2>/dev/null || true
		git reset --hard HEAD || true
		git clean -fdx || true
		git checkout -q "$ref_to_use" || { echo "Checkout $ref_to_use failed"; exit 1; }
		[[ -n "$openssl_branch" ]] && git reset --hard "origin/$openssl_branch" 2>/dev/null || git reset --hard "$ref_to_use" 2>/dev/null || true
		git clean -fdx || true
		openssl_ref=$(git describe --tags --exact-match HEAD 2>/dev/null || git rev-parse --abbrev-ref HEAD 2>/dev/null || git describe --tags --always)
		echo "Checked out OpenSSL: $openssl_ref"
		echo "Current HEAD commit: $(git rev-parse --short HEAD)"
		git describe --tags --always --abbrev=7 || echo "(describe failed)"
	else
		echo "Fresh clone"
		if [[ -n "$openssl_branch" ]]; then
			git clone --quiet --depth 1 --branch "$openssl_branch" --single-branch https://github.com/openssl/openssl.git || {
				echo "Clone failed!"
				exit 1
			}
		else
			git clone --quiet --depth 1 --branch "$openssl_tag" --single-branch https://github.com/openssl/openssl.git || {
				echo "Clone failed!"
				exit 1
			}
		fi
		cd openssl || exit 1
		git remote update --prune 2>/dev/null || git fetch --all --prune --tags || true
		git fetch --tags origin || true
		git checkout -q "$ref_to_use" || { echo "Checkout $ref_to_use failed"; exit 1; }
		[[ -n "$openssl_branch" ]] && git reset --hard "origin/$openssl_branch" 2>/dev/null || git reset --hard "$ref_to_use" 2>/dev/null || true
		git clean -fdx || true
		openssl_ref=$(git describe --tags --exact-match HEAD 2>/dev/null || git rev-parse --abbrev-ref HEAD 2>/dev/null || git describe --tags --always)
		echo "Checked out OpenSSL: $openssl_ref"
		echo "Current HEAD commit: $(git rev-parse --short HEAD)"
		git describe --tags --always --abbrev=7 || echo "(describe failed)"
	fi

	make clean >/dev/null 2>&1 || true
	rm -f configdata.pm Makefile Makefile.in include/openssl/configuration.h

	./config --prefix=/usr/local/openssl-3.5 --openssldir=/usr/local/openssl-3.5/ssl enable-fips enable-ml-dsa -Wl,-rpath,/usr/local/openssl-3.5/lib64

	make -j"$(nproc)" >/dev/null
	sudo make install_sw install_ssldirs install_fips

	sudo mkdir -p /usr/local/openssl-3.5/ssl

	if [[ -f /usr/local/openssl-3.5/ssl/openssl.cnf ]]; then
		sudo cp /usr/local/openssl-3.5/ssl/openssl.cnf /usr/local/openssl-3.5/ssl/openssl.cnf.bak.$(date +%Y%m%d_%H%M%S) || true
	fi

	if [[ -f "${HOME}/Desktop/openssl/apps/openssl.cnf" ]]; then
		sudo cp "${HOME}/Desktop/openssl/apps/openssl.cnf" /usr/local/openssl-3.5/ssl/openssl.cnf
	fi
	if [[ -f "${HOME}/Desktop/openssl/apps/ct_log_list.cnf" ]]; then
		sudo cp "${HOME}/Desktop/openssl/apps/ct_log_list.cnf" /usr/local/openssl-3.5/ssl/ct_log_list.cnf
	fi

	sudo ln -sf /usr/local/openssl-3.5/bin/openssl /usr/local/bin/openssl || true
	sudo ldconfig || true
}

configure_openssl_cnf_isolated() {
	local module_path=""
	if [[ -f /usr/local/openssl-3.5/lib64/ossl-modules/oqsprovider.so ]]; then
		module_path="/usr/local/openssl-3.5/lib64/ossl-modules/oqsprovider.so"
	elif [[ -f /usr/local/openssl-3.5/lib/ossl-modules/oqsprovider.so ]]; then
		module_path="/usr/local/openssl-3.5/lib/ossl-modules/oqsprovider.so"
	elif [[ -f /usr/local/lib/ossl-modules/oqsprovider.so ]]; then
		module_path="/usr/local/lib/ossl-modules/oqsprovider.so"
	elif [[ -f /usr/lib/x86_64-linux-gnu/ossl-modules/oqsprovider.so ]]; then
		module_path="/usr/lib/x86_64-linux-gnu/ossl-modules/oqsprovider.so"
	fi
	if [[ -z "$module_path" ]]; then
		echo "Warning: oqsprovider.so not found → skipping config" >&2
		return 0
	fi

	local cnf_dir="/usr/local/openssl-3.5/ssl"
	local cnf="${cnf_dir}/openssl.cnf"
	local oqs_conf="${cnf_dir}/oqs-provider.conf"

	sudo mkdir -p "$cnf_dir"

  cat > /tmp/oqs-provider.tmp <<EOF
[evp_properties]
default_properties = provider=default,provider=oqsprovider

[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[oqsprovider_sect]
module = ${module_path}
activate = 1

[default_sect]
activate = 1
EOF

	sudo mv /tmp/oqs-provider.tmp "$oqs_conf"
	sudo chown root:root "$oqs_conf"
	sudo chmod 644 "$oqs_conf"

	if [[ ! -f "$cnf" ]]; then
		echo "Warning: $cnf not found" >&2
		return 1
	fi

	sudo cp "$cnf" "${cnf}.bak.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true

	if ! grep -qE '^[[:space:]]*openssl_conf[[:space:]]*=' "$cnf"; then
		sudo sed -i '1i openssl_conf = openssl_init\n' "$cnf"
	fi

	if ! grep -qE '^\[openssl_init\]' "$cnf"; then
sudo tee -a "$cnf" >/dev/null <<'EOF'

[openssl_init]
providers = provider_sect
alg_section = evp_properties
EOF
	elif ! grep -qE 'providers[[:space:]]*=' "$cnf"; then
		sudo sed -i '/^\[openssl_init\]/a providers = provider_sect\nalg_section = evp_properties' "$cnf"
	fi

	local include_line=".include ${oqs_conf}"
	if ! grep -qF "${include_line}" "$cnf"; then
		echo "" | sudo tee -a "$cnf" >/dev/null
		echo "# OQS provider configuration" | sudo tee -a "$cnf" >/dev/null
		echo "${include_line}" | sudo tee -a "$cnf" >/dev/null
	fi

	echo "Updated $cnf to include OQS provider"
}

setup_liboqs_main() {
	cd "$SCRIPT_DIR"

	local ref_to_use=""
	[[ -n "$liboqs_branch" ]] && ref_to_use="$liboqs_branch" || ref_to_use="$liboqs_tag"

	if [[ -d liboqs/.git ]]; then
		cd liboqs || exit 1
		echo "Resetting existing liboqs clone"
		git remote update --prune 2>/dev/null || git fetch --all --prune --tags || true
		git fetch --tags origin || true
		git checkout --detach 2>/dev/null || true
		git reset --hard HEAD || true
		git clean -fdx || true
		git checkout -q "$ref_to_use" || { echo "Checkout $ref_to_use failed"; exit 1; }
		[[ -n "$liboqs_branch" ]] && git reset --hard "origin/$liboqs_branch" 2>/dev/null || git reset --hard "$ref_to_use" 2>/dev/null || true
		git clean -fdx || true
		liboqs_ref=$(git describe --tags --exact-match HEAD 2>/dev/null || git rev-parse --abbrev-ref HEAD 2>/dev/null || git describe --tags --always)
		echo "Checked out liboqs: $liboqs_ref"
		echo "Current HEAD commit: $(git rev-parse --short HEAD)"
		git describe --tags --always --abbrev=7 || echo "(describe failed)"
	else
		echo "Fresh clone of liboqs"
		if [[ -n "$liboqs_branch" ]]; then
			git clone --depth 1 --branch "$liboqs_branch" https://github.com/open-quantum-safe/liboqs.git || {
				echo "Clone failed!"
				exit 1
			}
		else
			git clone --depth 1 --branch "$liboqs_tag" https://github.com/open-quantum-safe/liboqs.git || {
				echo "Clone failed!"
				exit 1
			}
		fi
		cd liboqs || exit 1
		git remote update --prune 2>/dev/null || git fetch --all --prune --tags || true
		git fetch --tags origin || true
		git checkout -q "$ref_to_use" || { echo "Checkout $ref_to_use failed"; exit 1; }
		[[ -n "$liboqs_branch" ]] && git reset --hard "origin/$liboqs_branch" 2>/dev/null || git reset --hard "$ref_to_use" 2>/dev/null || true
		git clean -fdx || true
		liboqs_ref=$(git describe --tags --exact-match HEAD 2>/dev/null || git rev-parse --abbrev-ref HEAD 2>/dev/null || git describe --tags --always)
		echo "Checked out liboqs: $liboqs_ref"
		echo "Current HEAD commit: $(git rev-parse --short HEAD)"
		git describe --tags --always --abbrev=7 || echo "(describe failed)"
	fi

	rm -rf build
	mkdir -p build && cd build
	cmake -GNinja -DCMAKE_BUILD_TYPE=Release -DOQS_USE_OPENSSL=ON -DOPENSSL_ROOT_DIR=/usr/local/openssl-3.5 -DCMAKE_INSTALL_PREFIX=/usr/local/openssl-3.5 ..
	ninja -j"$(nproc)" >/tmp/ninja.log || { cat /tmp/ninja.log; exit 1; }

	sudo ninja install
	sudo ldconfig || true
	ls -la /usr/local/openssl-3.5/lib*/liboqs* 2>/dev/null || true
	ls -la /usr/local/openssl-3.5/include/oqs 2>/dev/null || true
}

setup_oqs_provider() {
	cd "$SCRIPT_DIR"

	local ref_to_use=""
	[[ -n "$oqs_provider_branch" ]] && ref_to_use="$oqs_provider_branch" || ref_to_use="$oqs_provider_tag"

	if [[ -d oqs-provider/.git ]]; then
		cd oqs-provider || exit 1
		echo "Updating oqs-provider clone"
		git remote update --prune 2>/dev/null || git fetch --all --prune --tags || true
		git fetch --tags origin || true
		git checkout --detach 2>/dev/null || true
		git reset --hard HEAD || true
		git clean -fdx || true
		git checkout -q "$ref_to_use" || { echo "Checkout $ref_to_use failed"; exit 1; }
		[[ -n "$oqs_provider_branch" ]] && git reset --hard "origin/$oqs_provider_branch" 2>/dev/null || git reset --hard "$ref_to_use" 2>/dev/null || true
		git clean -fdx || true
		oqs_provider_ref=$(git describe --tags --exact-match HEAD 2>/dev/null || git rev-parse --abbrev-ref HEAD 2>/dev/null || git describe --tags --always)
		echo "Checked out oqs-provider: $oqs_provider_ref"
		echo "Current HEAD commit: $(git rev-parse --short HEAD)"
		git describe --tags --always --abbrev=7 || echo "(describe failed)"
	else
		echo "Fresh clone of oqs-provider"
		if [[ -n "$oqs_provider_branch" ]]; then
			git clone --depth 1 --branch "$oqs_provider_branch" https://github.com/open-quantum-safe/oqs-provider.git oqs-provider || {
				echo "Clone failed!"
				exit 1
			}
		else
			git clone --depth 1 --branch "$oqs_provider_tag" https://github.com/open-quantum-safe/oqs-provider.git oqs-provider || {
				echo "Clone failed!"
				exit 1
			}
		fi
		cd oqs-provider || exit 1
		git remote update --prune 2>/dev/null || git fetch --all --prune --tags || true
		git fetch --tags origin || true
		git checkout -q "$ref_to_use" || { echo "Checkout $ref_to_use failed"; exit 1; }
		[[ -n "$oqs_provider_branch" ]] && git reset --hard "origin/$oqs_provider_branch" 2>/dev/null || git reset --hard "$ref_to_use" 2>/dev/null || true
		git clean -fdx || true
		oqs_provider_ref=$(git describe --tags --exact-match HEAD 2>/dev/null || git rev-parse --abbrev-ref HEAD 2>/dev/null || git describe --tags --always)
		echo "Checked out oqs-provider: $oqs_provider_ref"
		echo "Current HEAD commit: $(git rev-parse --short HEAD)"
		git describe --tags --always --abbrev=7 || echo "(describe failed)"
	fi

	rm -rf _build
	mkdir -p _build && cd _build
	cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local/openssl-3.5 -DOPENSSL_ROOT_DIR=/usr/local/openssl-3.5 ..
	ninja -j"$(nproc)" >/tmp/ninja.log || { cat /tmp/ninja.log; exit 1; }

	sudo ninja install
	sudo ldconfig || true
	ls -la /usr/local/openssl-3.5/lib64/ossl-modules/oqsprovider.so 2>/dev/null || ls -la /usr/local/openssl-3.5/lib/ossl-modules/oqsprovider.so 2>/dev/null || true
}

verify_cleanup() {
	set +e
	local missing_ok=0
	local results=()
	test -d /usr/local/openssl-3.5 && results+=("/usr/local/openssl-3.5 exists")
	ls /usr/local/lib 2>/dev/null | grep -E 'liboqs' >/dev/null 2>&1 && results+=("liboqs found in /usr/local/lib")
	ls /usr/local/lib/ossl-modules 2>/dev/null | grep -E 'oqsprovider' >/dev/null 2>&1 && results+=("oqsprovider found in /usr/local/lib/ossl-modules")
	ls /usr/lib/x86_64-linux-gnu/ossl-modules 2>/dev/null | grep -E 'oqsprovider' >/dev/null 2>&1 && results+=("oqsprovider found in system openssl modules path")
	test "${#results[@]}" -eq 0 && missing_ok=1
	if [[ $missing_ok -eq 1 ]]; then
		printf 'CLEANUP OK\n'
		set -e
		return 0
	else
		printf 'CLEANUP LEFTOVERS FOUND:\n'
		for r in "${results[@]}"; do
		printf ' - %s\n' "$r"
		done
	fi
	return 0
}

verify_setup_final() {
	set +e
	local pass_count=0
	local i
	local local_ok
	local ver

	for i in 1 2; do
	local_ok=0

	if [[ -x /usr/local/openssl-3.5/bin/openssl ]]; then
		ver=$(/usr/local/openssl-3.5/bin/openssl version 2>/dev/null || true)
		printf 'OpenSSL binary: %s\n' "${ver:-MISSING}"
		[[ "$ver" == *"3.5."* ]] && local_ok=$((local_ok+1))
	fi

	if /usr/local/openssl-3.5/bin/openssl list -providers 2>/dev/null | grep -i oqs >/dev/null 2>&1; then
		printf 'oqsprovider registered in providers list\n'
		local_ok=$((local_ok+1))
		else
		printf 'oqsprovider NOT found in providers list\n' >&2
	fi

	if ls /usr/local/openssl-3.5/lib*/liboqs* 1>/dev/null 2>&1; then
		printf 'liboqs installed in prefix lib\n'
		local_ok=$((local_ok+1))
		else
		printf 'liboqs NOT found in prefix lib\n' >&2
	fi

	[[ $local_ok -ge 3 ]] && pass_count=$((pass_count+1))
	sleep 2
	done

	if [[ $pass_count -eq 2 ]]; then
		printf 'VERIFY OK (passed twice)\n'
		else
		printf 'VERIFY FAILED (did not pass twice)\n'
	fi
}

verify_additional_debug() {
	cd "$SCRIPT_DIR"
	echo "=== OpenSSL version & info ==="
	/usr/local/openssl-3.5/bin/openssl version -a
	echo ""
	echo "=== Loaded providers ==="
	/usr/local/openssl-3.5/bin/openssl list -providers -verbose
	echo ""
	echo "=== Files check ==="
	ls -la /usr/local/openssl-3.5/lib*/ossl-modules/oqsprovider.so 2>/dev/null || echo "oqsprovider.so missing"
	ls -la /usr/local/openssl-3.5/lib*/liboqs* 2>/dev/null || echo "liboqs missing"
	echo ""

	echo "=== Testing p521_mldsa87 hybrid keypair generation ==="
	if /usr/local/openssl-3.5/bin/openssl list -signature-algorithms | grep -qi 'p521_mldsa87'; then
		if /usr/local/openssl-3.5/bin/openssl genpkey -algorithm p521_mldsa87 -out /tmp/p521_mldsa87_test.pem 2>/dev/null; then
			/usr/local/openssl-3.5/bin/openssl pkey -in /tmp/p521_mldsa87_test.pem -text -noout
			rm -f /tmp/p521_mldsa87_test.pem
			echo "SUCCESS: p521_mldsa87 hybrid works (algorithm available)"
		else
			echo "FAILED: p521_mldsa87 hybrid listed but key generation failed"
		fi
			else
		echo "SKIPPED: p521_mldsa87 hybrid not available in this build"
	fi
	echo ""

	echo "=== Testing pure mldsa87 keypair generation ==="
	if /usr/local/openssl-3.5/bin/openssl list -signature-algorithms | grep -qi 'MLDSA87'; then
		if /usr/local/openssl-3.5/bin/openssl genpkey -algorithm mldsa87 -out /tmp/mldsa87_test.pem 2>/dev/null; then
			/usr/local/openssl-3.5/bin/openssl pkey -in /tmp/mldsa87_test.pem -text -noout
			rm -f /tmp/mldsa87_test.pem
			echo "SUCCESS: Pure mldsa87 works (algorithm available)"
		else
			echo "FAILED: Pure mldsa87 listed but key generation failed"
		fi
		else
		echo "SKIPPED: Pure mldsa87 not available in this build"
	fi
	echo ""
	echo "=== Signature algorithms ==="
	/usr/local/openssl-3.5/bin/openssl list -signature-algorithms | grep -iE 'mldsa|falcon|sphincs|mayo|cross|snova' || echo "No PQ signatures found"
	echo ""
	echo "=== KEM algorithms ==="
	/usr/local/openssl-3.5/bin/openssl list -kem-algorithms | grep -iE 'kem|kyber|ml-kem|mlkem' || echo "No PQ KEMs found"
	echo ""
	cd "$SCRIPT_DIR"
	cd openssl
	echo "verify openssl branch"
	verify_git_branch "." "$openssl_ref"
	cd "$SCRIPT_DIR"
	cd liboqs
	echo "verify liboqs branch"
	verify_git_branch "." "$liboqs_ref"
	cd "$SCRIPT_DIR"
	cd oqs-provider
	echo "verify oqs_provider branch"
	verify_git_branch "." "$oqs_provider_ref"
# You should see this file exists:
echo "ls /usr/local/openssl-3.5/lib64/pkgconfig/liboqs.pc "
ls /usr/local/openssl-3.5/lib64/pkgconfig/liboqs.pc
echo "ls /usr/local/openssl-3.5/lib*/pkgconfig/liboqs.pc "
ls /usr/local/openssl-3.5/lib*/pkgconfig/liboqs.pc
echo "ls /usr/local/openssl-3.5/lib*/liboqs.so* "
ls /usr/local/openssl-3.5/lib*/liboqs.so*
echo "/usr/local/openssl-3.5/bin/openssl list -providers -verbose"
/usr/local/openssl-3.5/bin/openssl list -providers -verbose
}

lsb_release -a 2>/dev/null || true
ensure_ubuntu_24

cleanup_oqs_provider
cleanup_oqs_main
cleanup_openssl3_5

verify_cleanup

setup_openssl3_5
setup_liboqs_main
setup_oqs_provider

configure_openssl_cnf_isolated

verify_setup_final
verify_additional_debug

echo "Updated script uses stable tags by default. Override with environment variables:"
echo "For branches: OPENSSL_BRANCH=openssl-3.5 LIBOQS_BRANCH=main OQS_PROVIDER_BRANCH=main ./script.sh"
echo "For tags: OPENSSL_TAG=openssl-3.5.1 LIBOQS_TAG=0.15.0 OQS_PROVIDER_TAG=0.11.0 ./script.sh"
echo "Branch takes precedence over tag if both are set"