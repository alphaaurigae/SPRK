
#  list algo
g++ -std=gnu++23 -I/usr/local/include list_algos.cpp /usr/local/lib/liboqs.a -lcrypto -pthread -o list_algos


# build liboqs
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



# build keygen

g++ -std=c++23 -DUSE_LIBOQS -O2 -Wall -Wextra -o pqsig_keygen pqsig_keygen.cpp \
    $(pkg-config --cflags --libs liboqs) -lssl -lcrypto