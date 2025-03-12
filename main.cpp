#include <iostream>

#include "RSA/cpu_rsa_break.hpp"
#include "Timer.hpp"
#include "utils.hpp"

int main() {
    // ---------------------------------------- Encoding ----------------------------------------
    const char* message{"hello"};
    uint64_t encodedMessage{0};
    Utils::base26_encode(message, encodedMessage);

    std::cout << "Original Message: "<< message << "\n";
    std::cout << "Encoded Message: "<< encodedMessage << "\n\n";

    // ---------------------------------------- Encryption ----------------------------------------

    // DO NOT SHARE KEYS
    uint64_t p{7919};
    uint64_t q{7907};
    uint64_t d{65537};

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
    Timer::Timer timer;
    auto publicKeys{rsa.getPublicKeys()};

    timer.start();
    auto interceptedMessage{CPU_RSA_Break::rsa_break(encryptedMessage, publicKeys)};
    timer.stop();

    Utils::base26_decode(interceptedMessage, recoveredMessage);

    std::cout << "Deciphered Encoded Message w/ CPU Break: "<< interceptedMessage << "\n";
    std::cout << "Deciphered Recovered Message w/ CPU Break: "<< recoveredMessage << "\n";
    std::cout << "CPU Break Elapsed Time: "<< timer.elapsed() << " seconds" << "\n";

    delete[] recoveredMessage;

    return 0;
}

// p: 61
// q: 53
// d: 17

// p: 7919
// q: 7907
// d: 65537