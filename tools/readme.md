# Tools

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

# List algo
`g++ -std=gnu++23 -I/usr/local/include list_algos.cpp /usr/local/lib/liboqs.a -lcrypto -pthread -o list_algos`

## Keygen
```
g++ -std=c++23 -DUSE_LIBOQS -O2 -Wall -Wextra \
$(pkg-config --cflags liboqs) \
pqsig_keygen.cpp -o pqsig_keygen \
$(pkg-config --libs liboqs) \
-lssl -lcrypto
```

`Usage: pqsig_keygen <output.sk>`