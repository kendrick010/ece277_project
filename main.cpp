#include <iostream>

#include "rsa.hpp"
#include "utils.hpp"

int main() {
    // -------------------- Encoding --------------------
    const char* message{"hello"};
    unsigned int long long encodedMessage{0};
    Utils::base26_encode(message, encodedMessage);

    std::cout << "Original Message: "<< message << "\n";
    std::cout << "Encoded Message: "<< encodedMessage << "\n\n";

    // -------------------- Encryption --------------------
    size_t p{7919};     // DO NOT SHARE
    size_t q{571};      // DO NOT SHARE
    size_t e{7};        // DO NOT SHARE

    RSA::RSA rsa(p,q,e);
    rsa.encrypt(encodedMessage);

    // -------------------- Decryption --------------------
    auto decryptedMessage = rsa.decrypt(904131);

    // -------------------- Decoding --------------------
    const size_t messageSize = std::strlen(message);
    char* recoveredMessage = new char[messageSize + 1];

    Utils::base26_decode(decryptedMessage, recoveredMessage);

    std::cout << "Recovered Message: "<< recoveredMessage << "\n";

    delete[] recoveredMessage;

    return 0;
}
