#include <oqs/oqs.h>
#include <iostream>

int main() {
    int n = OQS_SIG_algs_length;
    for(int i = 0; i < n; i++) {
        std::cout << OQS_SIG_alg_identifier(i) << std::endl;
    }
}