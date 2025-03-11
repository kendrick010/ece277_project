#include <iostream>

#include "rsa/cpu_rsa_break.hpp"
#include "utils.hpp"

using ULL = unsigned long long;

int main() {
    // ---------------------------------------- Encoding ----------------------------------------
    const char* message{"hello"};
    ULL encodedMessage{0};
    Utils::base26_encode(message, encodedMessage);

    std::cout << "Original Message: "<< message << "\n";
    std::cout << "Encoded Message: "<< encodedMessage << "\n\n";

    // ---------------------------------------- Encryption ----------------------------------------
    ULL p{7919};        // DO NOT SHARE
    ULL q{571};         // DO NOT SHARE
    ULL d{7};           // DO NOT SHARE

    RSA::RSA rsa(p, q, d);
    auto encryptedMessage = rsa.encrypt(encodedMessage);

    std::cout << "Encrypted Message: "<< encryptedMessage << "\n";

    // ---------------------------------------- Decryption ----------------------------------------
    auto decryptedMessage = rsa.decrypt(encryptedMessage);

    // ---------------------------------------- Decoding ----------------------------------------
    const size_t messageSize = std::strlen(message);
    char* recoveredMessage = new char[messageSize + 1];

    Utils::base26_decode(decryptedMessage, recoveredMessage);

    std::cout << "Deciphered Recovered Message: "<< recoveredMessage << "\n\n";

    // ---------------------------------------- CPU Break ----------------------------------------
    auto publicKeys{rsa.getPublicKeys()};
    auto interceptedMessage{CPU_RSA_Break::rsa_break(encryptedMessage, publicKeys)};

    Utils::base26_decode(interceptedMessage, recoveredMessage);

    std::cout << "Deciphered Encoded Message w/ CPU Break: "<< interceptedMessage << "\n";
    std::cout << "Deciphered Recovered Message w/ CPU Break: "<< recoveredMessage << "\n";

    delete[] recoveredMessage;

    return 0;
}
