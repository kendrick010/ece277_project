//
// Created by Kendrick Nguyen on 3/11/25.
//

#ifndef BREAKING_RSA_CPU_RSA_BREAK_HPP
#define BREAKING_RSA_CPU_RSA_BREAK_HPP

#include <stdexcept>
#include <cmath>

#include "rsa.hpp"

namespace CPU_RSA_Break {

    ULL findFactor(const ULL num) {
        const auto half{static_cast<ULL>(sqrt(num))};

        for (ULL i{2}; i <= half; i++) {
            if (num % i == 0) return i;
        }

        // Failed to factor (n is prime)
        return static_cast<ULL>(0);
    }

    ULL rsa_break(ULL encryptedMessage, RSA::PublicKeys publicKeys) {
        const ULL p{findFactor(publicKeys.N_KEY)};
        if (!p) {
            throw std::invalid_argument("Failed to factorize n.");
        }

        // Found p, get q and phi
        const auto q{publicKeys.N_KEY / p};
        const auto phi{(p - 1) * (q - 1)};

        // Calculate d, e≡d^−1 (mod phi(n))
        auto d{RSA::RSA::modInverse(publicKeys.E_KEY, phi)};

        // Decrypt
        return RSA::RSA::modExponentiation(encryptedMessage, d, publicKeys.N_KEY);
    }

}

#endif //BREAKING_RSA_CPU_RSA_BREAK_HPP
