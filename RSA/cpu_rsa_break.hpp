//
// Created by Kendrick Nguyen on 3/11/25.
//

#ifndef BREAKING_RSA_CPU_RSA_BREAK_HPP
#define BREAKING_RSA_CPU_RSA_BREAK_HPP

#include <stdexcept>
#include <cmath>

#include "RSA.hpp"

namespace CPU_RSA_Break {

    __uint128_t findFactor(const __uint128_t num) {
        const auto half{static_cast<__uint128_t>(sqrt(num))};

        for (__uint128_t i{2}; i <= half; i++) {
            if (num % i == 0) return i;
        }

        // Failed to factor (n is prime)
        return static_cast<__uint128_t>(0);
    }

    __uint128_t rsa_break(__uint128_t encryptedMessage, RSA::PublicKeys publicKeys) {
        const __uint128_t p{findFactor(publicKeys.N_KEY)};
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
