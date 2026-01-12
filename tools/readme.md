# Tools
################
# RUN FIRST
sudo apt update
sudo apt install build-essential git cmake ninja-build libssl-dev

# Get OpenSSL 3.5.x (use latest tag or master)
git clone https://github.com/openssl/openssl.git -b openssl-3.5.0  # or just 'git clone' for master
cd openssl
make clean
./config --prefix=/usr/local/openssl-3.5 --openssldir=/usr/local/openssl-3.5/ssl \
    enable-fips \
    -Wl,-rpath,/usr/local/openssl-3.5/lib
make -j$(nproc)
sudo make install_sw install_ssldirs install_fips
sudo mkdir -p /usr/local/openssl-3.5/ssl
sudo cp /home/mmmm/Desktop/openssl/apps/openssl.cnf /usr/local/openssl-3.5/ssl/openssl.cnf
sudo cp /home/mmmm/Desktop/openssl/apps/ct_log_list.cnf /usr/local/openssl-3.5/ssl/ct_log_list.cnf

# Now compile your server against this new OpenSSL
# Update your Makefile/CMakeLists.txt:
#   -I/usr/local/openssl-3.5/include
#   -L/usr/local/openssl-3.5/lib

###################################

# liboqs
- Sample Ubuntu LTS
```
git clone --branch 0.15.0 https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DOQS_USE_OPENSSL=ON \
  -DCMAKE_INSTALL_PREFIX=/usr/local \
  ..
ninja
sudo ninja install
sudo ldconfig
```
# above was the previous setup with defaul openssl 3.0
# lets clean up for reinstall for openssl 3.5
 # 1. Remove shared/static libs & pkg-config files
sudo rm -f /usr/local/lib/liboqs.*
sudo rm -f /usr/local/lib/pkgconfig/liboqs.pc

# 2. Remove headers (the entire oqs dir)
sudo rm -rf /usr/local/include/oqs

# 3. Remove any documentation/man pages if present
sudo rm -rf /usr/local/share/doc/liboqs
sudo rm -rf /usr/local/share/man/man*/*oqs*

# 4. Update linker cache
sudo ldconfig

# 5. Optional: Check for any leftovers (should return almost nothing)
find /usr/local -name "*oqs*" 2>/dev/null
find /usr -name "*oqs*" 2>/dev/null   # just in case something went to /usr/lib

# Remove leftover CMake configs for liboqs (safe, they are just metadata)
sudo rm -rf /usr/local/lib/cmake/liboqs

# Remove the stray oqs-provider header dir (likely from old oqs-provider install)
sudo rm -rf /usr/local/include/oqs-provider

# Remove the old oqsprovider.so from system OpenSSL modules path
sudo rm -f /usr/lib/x86_64-linux-gnu/ossl-modules/oqsprovider.so

# Update linker cache one more time
sudo ldconfig

# Final verification (should now show almost nothing related to oqs/liboqs)
find /usr/local -name "*oqs*" 2>/dev/null
find /usr -name "*oqs*" 2>/dev/null


# ... oqs-provider for TLS (pending integration)
```
git clone https://github.com/open-quantum-safe/oqs-provider.git --branch 0.11.0
cd oqs-provider
mkdir _build && cd _build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DOPENSSL_ROOT_DIR=/usr ..
ninja
sudo ninja install
sudo ldconfig
```








- then edit `/etc/ssl/openssl.cnf` like this
```
[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[oqsprovider_sect]
module = /usr/lib/x86_64-linux-gnu/ossl-modules/oqsprovider.so
activate = 1

```
- VS initial
```
[provider_sect]
default = default_sect
```

- so you end up like this:
```
✔ ~/Desktop/SPRK/tools [main|✚ 1…1] 
19:04 $ openssl list -providers
Providers:
  default
    name: OpenSSL Default Provider
    version: 3.0.13
    status: active
✔ ~/Desktop/SPRK/tools [main|✚ 1…1] 
19:04 $ openssl list -kem-algorithms | grep mlkem512
✘-1 ~/Desktop/SPRK/tools [main|✚ 1…1] 
19:04 $ openssl list -signature-algorithms | grep mldsa87
✘-1 ~/Desktop/SPRK/tools [main|✚ 1…1] 
19:04 $ openssl list -providers
Providers:
  oqsprovider
    name: OpenSSL OQS Provider
    version: 0.11.0
    status: active
✔ ~/Desktop/SPRK/tools [main|✚ 1…1] 
19:10 $ openssl list -kem-algorithms | grep mlkem512
  mlkem512 @ oqsprovider
  p256_mlkem512 @ oqsprovider
  x25519_mlkem512 @ oqsprovider
  bp256_mlkem512 @ oqsprovider
✔ ~/Desktop/SPRK/tools [main|✚ 1…1] 
19:10 $ openssl list -signature-algorithms | grep mldsa87
  mldsa87 @ oqsprovider
  p521_mldsa87 @ oqsprovider
✔ ~/Desktop/SPRK/tools [main|✚ 1…1] 
19:10 $ 

```







cleanup for new openssl 3.5 setup
# 1. Remove the provider module from common/old locations
sudo rm -f /usr/local/lib/ossl-modules/oqsprovider.so
sudo rm -f /usr/local/lib64/ossl-modules/oqsprovider.so           # common on some systems
sudo rm -f /usr/local/lib/liboqsprovider.*                        # any symlinks/variants

# 2. Clean any stray pkg-config or cmake files (rare but possible)
sudo rm -f /usr/local/lib/pkgconfig/oqsprovider.pc
sudo rm -rf /usr/local/lib/cmake/oqs-provider*                    # if any

# 3. If you have leftovers from system-wide attempts
sudo rm -f /usr/lib/ossl-modules/oqsprovider.so
sudo rm -f /usr/lib64/ossl-modules/oqsprovider.so

# 4. Revert your old /etc/ssl/openssl.cnf edit (optional but recommended to avoid confusion)
# Edit /etc/ssl/openssl.cnf and remove the oqsprovider lines, leaving just:
# [provider_sect]
# default = default_sect

# 5. Update cache
sudo ldconfig

# Final check: should show almost nothing now
find /usr/local -name "*oqsprovider*" 2>/dev/null
find /usr -name "*oqsprovider*" 2>/dev/null

sudo cp /etc/ssl/openssl.cnf /etc/ssl/openssl.cnf.bak-$(date +%Y%m%d_%H%M%S)

Open the file:

sudo mousepad /etc/ssl/openssl.cnf

Change this section:

[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[oqsprovider_sect]
module = /usr/lib/x86_64-linux-gnu/ossl-modules/oqsprovider.so
activate = 1

back to:
[provider_sect]
default = default_sect

# after change
✔ ~/Desktop/liboqs [0.15.0|✔] 
16:29 $ openssl list -providers
Providers:
  default
    name: OpenSSL Default Provider
    version: 3.0.13
    status: active
✔ ~/Desktop/liboqs [0.15.0|✔] 
16:32 $ 

# Perfect — the system config cleanup is done correctly:

## Backup created (/etc/ssl/openssl.cnf.bak-20260110_162838)
## oqsprovider lines removed → system OpenSSL 3.0.13 is back to default (only default provider active)
## No more stray oqsprovider files visible in common paths (find returned nothing)


#ä new setup for openssl 3.5
# Build & install liboqs (first!)

```
cd SPRK/
git clone --branch 0.15.0 https://github.com/open-quantum-safe/liboqs.git
cd liboqs

# Clean any old build if exists
rm -rf build

mkdir build && cd build

cmake -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DOQS_USE_OPENSSL=ON \
  -DOPENSSL_ROOT_DIR=/usr/local/openssl-3.5 \
  -DCMAKE_INSTALL_PREFIX=/usr/local/openssl-3.5 \
  ..

ninja
sudo ninja install
sudo ldconfig
# Important changes compared to your old command:
# -DOPENSSL_ROOT_DIR=/usr/local/openssl-3.5 → tells liboqs to link against your custom OpenSSL 3.5
# -DCMAKE_INSTALL_PREFIX=/usr/local/openssl-3.5 → installs everything into your custom prefix (not polluting /usr/local)

ls -la /usr/local/openssl-3.5/lib*/liboqs*     # should show liboqs.so and/or liboqs.a
ls -la /usr/local/openssl-3.5/include/oqs      # should show many .h files
```
cd ../..
```
git clone https://github.com/open-quantum-safe/oqs-provider.git --branch 0.11.0
cd oqs-provider

# Clean any old build
rm -rf _build

mkdir _build && cd _build

cmake -GNinja \
  -DCMAKE_INSTALL_PREFIX=/usr/local/openssl-3.5 \
  -DOPENSSL_ROOT_DIR=/usr/local/openssl-3.5 \
  ..

ninja
sudo ninja install
sudo ldconfig

ls -la /usr/local/openssl-3.5/lib64/ossl-modules/oqsprovider.so  2>/dev/null || \
ls -la /usr/local/openssl-3.5/lib/ossl-modules/oqsprovider.so     2>/dev/null

```

sudo mousepad /usr/local/openssl-3.5/ssl/openssl.cnf
Make sure it contains (add or fix):

[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[oqsprovider_sect]
module = /usr/local/openssl-3.5/lib64/ossl-modules/oqsprovider.so   # ← change to lib/ if the file is there
activate = 1

VS default
# List of providers to load
[provider_sect]
default = default_sect

4. Verify everything works (new terminal)
# Run this test block (copy-paste):
```
export PATH="/usr/local/openssl-3.5/bin:$PATH"
export LD_LIBRARY_PATH="/usr/local/openssl-3.5/lib64:$LD_LIBRARY_PATH"   # or lib/ if needed
export OPENSSL_CONF="/usr/local/openssl-3.5/ssl/openssl.cnf"

openssl version
openssl list -providers             # must show oqsprovider active
openssl list -kem-algorithms | grep -i mlkem
openssl list -signature-algorithms | grep -i mldsa
```







#rebuild openssl

make clean
./config --prefix=/usr/local/openssl-3.5 --openssldir=/usr/local/openssl-3.5/ssl \
  enable-fips enable-ml-dsa -Wl,-rpath,/usr/local/openssl-3.5/lib64
make -j$(nproc)
sudo make install_sw install_ssldirs install_fips


sudo cp /home/mmmm/Desktop/openssl/apps/openssl.cnf /usr/local/openssl-3.5/ssl/openssl.cnf
sudo cp /home/mmmm/Desktop/openssl/apps/ct_log_list.cnf /usr/local/openssl-3.5/ssl/ct_log_list.cnf




cat /usr/local/openssl-3.5/ssl/openssl.cnf

edit again
[openssl_init]
providers = provider_sect
alg_section = evp_properties

[evp_properties]
default_properties = ?provider=oqsprovider

[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[oqsprovider_sect]
module = /usr/local/openssl-3.5/lib64/ossl-modules/oqsprovider.so
activate = 1


cat /usr/local/openssl-3.5/ssl/openssl.cnf





now we need to gen certs 

Why Certificates Are Required (Even for Plain TLS)In plain (non-PQ) TLS with OpenSSL:You can run a server without any certificate if you accept the default self-signed one that OpenSSL generates on-the-fly (very insecure, but it works for testing).
Most real-world examples skip cert generation because people use pre-existing or CA-signed certs, or they accept browser warnings.

But in your PQ-TLS setup with OQS Provider:OpenSSL does not auto-generate post-quantum certificates (ML-DSA-87/mldsa87) on the fly.
The OQS Provider adds PQ algorithms, but it does not provide a built-in "default PQ self-signed cert" — you must explicitly generate one using the PQ algorithm.
Without a server cert/key, SSL_CTX_use_certificate_file and SSL_CTX_use_PrivateKey_file will fail → TLS handshake fails.
For mutual TLS (max security, client must present cert), you also need client certs signed by the same CA (server in this case).

So: Manual generation is required for PQ signatures.
This is not a bug — it's because PQ certs are not yet standardized for auto-generation in OpenSSL/OQS (as of Jan 2026).Why We Generate Them (Security & Practical Reasons)
Self-signed server cert: Quick for testing. Clients can trust it explicitly (or disable verify for dev).
Client certs signed by server: Enables mutual TLS — server verifies clients are who they claim (e.g., ron has a cert signed by the server CA). 
This prevents unauthorized clients from connecting.
Reusable: Once generated, you can commit .crt files (public) to repo; keep .key files private (.gitignore them).
PQ-specific: We use mldsa87 to match your app-layer ML-DSA-87 usage — consistency across layers.

Why We Generate Them (Security & Practical Reasons)Self-signed server cert: Quick for testing. Clients can trust it explicitly (or disable verify for dev).
Client certs signed by server: Enables mutual TLS — server verifies clients are who they claim (e.g., ron has a cert signed by the server CA). This prevents unauthorized clients from connecting.
Reusable: Once generated, you can commit .crt files (public) to repo; keep .key files private (.gitignore them).
PQ-specific: We use mldsa87 to match your app-layer ML-DSA-87 usage — consistency across layers.

Lets go:

```
#!/usr/bin/env bash
set -euo pipefail

# Directory for certificates
CERT_DIR="sample/sample_test_cert"

# Create directory if it doesn't exist
mkdir -p "$CERT_DIR"

echo "Generating PQ certificates using mldsa87 (ML-DSA-87) via OQS Provider..."

# === 1. Server self-signed certificate ===
echo "→ Server certificate..."
openssl genpkey -provider oqsprovider -algorithm mldsa87 -out "$CERT_DIR/server.key"
openssl req -provider oqsprovider -new -key "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.csr" -subj "/CN=SPRK Server"
openssl x509 -provider oqsprovider -req -in "$CERT_DIR/server.csr" \
    -signkey "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" -days 365

# Cleanup temp CSR
rm -f "$CERT_DIR/server.csr"

# === 2. Client certificates (signed by server CA) ===
CLIENTS=("ron" "bob" "beth")

for client in "${CLIENTS[@]}"; do
    echo "→ Client certificate for $client..."
    openssl genpkey -provider oqsprovider -algorithm mldsa87 \
        -out "$CERT_DIR/${client}_tls.key"
    openssl req -provider oqsprovider -new -key "$CERT_DIR/${client}_tls.key" \
        -out "$CERT_DIR/${client}.csr" -subj "/CN=$client"
    openssl x509 -provider oqsprovider -req -in "$CERT_DIR/${client}.csr" \
        -CA "$CERT_DIR/server.crt" -CAkey "$CERT_DIR/server.key" \
        -out "$CERT_DIR/${client}.crt" -days 365 -CAcreateserial

    # Cleanup temp CSR
    rm -f "$CERT_DIR/${client}.csr"
done

echo ""
echo "All certificates generated successfully!"
echo ""
echo "Files created in $CERT_DIR:"
ls -l "$CERT_DIR"
echo ""
echo "Verify server certificate signature algorithm:"
openssl x509 -in "$CERT_DIR/server.crt" -text -noout | grep "Signature Algorithm"
echo ""
echo "Done. You can now proceed to TLS code integration."
echo "Remember: Add *.key files to .gitignore!"

```
# Should show mldsa87 or similar`

## Keygen
```
g++ -std=c++23 -DUSE_LIBOQS -O2 -Wall -Wextra \
$(pkg-config --cflags liboqs) \
pqsig_keygen.cpp -o pqsig_keygen \
$(pkg-config --libs liboqs) \
-lssl -lcrypto
```

`Usage: pqsig_keygen <output.sk>`





