#include <iostream>
#include <string>
#include <gmp.h>

#include "RSA/cpu_rsa_break.hpp"
#include "Timer.hpp"
#include "utils.hpp"

int main() {
    // ---------------------------------------- Encoding ----------------------------------------
    const std::string message{"bootycheeksful"};
    mpz_class encodedMessage{0};

    Utils::base26_encode(message, encodedMessage);

    std::cout << "Original Message: " << message << "\n";
    gmp_printf("Encoded Message: %Zd\n\n", encodedMessage.get_mpz_t());

    // ---------------------------------------- Encryption ----------------------------------------

    // DO NOT SHARE KEYS
    mpz_class encryptedMessage;
    mpz_class p{718064159};
    mpz_class q{7069067389};
    mpz_class d{65537};

    RSA::RSA rsa(p, q, d);
    rsa.encrypt(encryptedMessage, encodedMessage);
    auto publicKeys{rsa.getPublicKeys()};

    gmp_printf("Public Keys: (n:%Zd, e:%Zd)\n", publicKeys.N_KEY.get_mpz_t(), publicKeys.E_KEY.get_mpz_t());
    gmp_printf("Encrypted Message: %Zd\n", encryptedMessage.get_mpz_t());

    // ---------------------------------------- Decryption ----------------------------------------
    mpz_class decryptedMessage;
    rsa.decrypt(decryptedMessage, encryptedMessage);

    // ---------------------------------------- Decoding ----------------------------------------
    std::string recoveredMessage;
    Utils::base26_decode(decryptedMessage, recoveredMessage);

    std::cout << "Deciphered Recovered Message: "<< recoveredMessage << "\n\n";

    // ---------------------------------------- CPU Break ----------------------------------------
    Timer::Timer timer;

    timer.start();
    auto interceptedMessage{CPU_RSA_Break::rsa_break(encryptedMessage, publicKeys)};
    timer.stop();

    Utils::base26_decode(interceptedMessage, recoveredMessage);

    gmp_printf("Deciphered Encoded Message w/ CPU Break: %Zd\n", interceptedMessage.get_mpz_t());
    std::cout << "Deciphered Recovered Message w/ CPU Break: "<< recoveredMessage << "\n";
    std::cout << "CPU Break Elapsed Time: "<< timer.elapsed() << " seconds" << "\n";

    return 0;
}

// p: 61
// q: 53
// d: 17

// p: 7919
// q: 7907
// d: 65537

// p: 718064159
// q: 7069067389
// d: 65537