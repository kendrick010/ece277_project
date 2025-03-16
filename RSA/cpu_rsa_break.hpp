//
// Created by Kendrick Nguyen on 3/11/25.
//

#ifndef BREAKING_RSA_CPU_RSA_BREAK_HPP
#define BREAKING_RSA_CPU_RSA_BREAK_HPP

#include <stdexcept>
#include <cmath>
#include <utility>

#include "RSA.hpp"

namespace CPU_RSA_Break {

    bool isWholeNumber(double num) {
        return num == std::floor(num);
    }

    std::pair<int64_t, int64_t> solveQuadratic(const int64_t a, const int64_t b, const int64_t c) {
        const int64_t discriminant{b * b - 4 * a * c};

        // Ignore no solutions and complex solutions
        if ((discriminant < 0) || (discriminant == 0))
            return {0 ,0};

        const auto double_a{static_cast<double>(a)};
        const auto double_b{static_cast<double>(b)};

        const auto x1 = (-double_b + sqrt(discriminant)) / (2 * double_a);
        const auto x2 = (-double_b - sqrt(discriminant)) / (2 * double_a);

        if (x1 < 0 && !isWholeNumber(x1) && x2 < 0 && !isWholeNumber(x2))
            return {0 ,0};

        const auto whole_x1{static_cast<int64_t>(x1)};
        const auto whole_x2{static_cast<int64_t>(x2)};

        return {whole_x1, whole_x2};
    }

    uint64_t find_phi(const uint64_t n) {
        const auto max_phi{static_cast<int64_t>(n)};
        const uint64_t a{1};

        for (int64_t phi{0}; phi < max_phi; ++phi) {
            const int64_t b{-(max_phi + 1 - phi)};
            const auto roots{solveQuadratic(a, b, max_phi)};

            const int64_t p{roots.first};
            const int64_t q{roots.second};

            if (phi && (p * q == max_phi) && (max_phi % p == 0) && (max_phi % q == 0)) {
                return phi;
            }
        }

        return 0;
    }

    uint64_t rsa_break(uint64_t encryptedMessage, RSA::PublicKeys publicKeys) {
        const auto phi{find_phi(publicKeys.N_KEY)};

        if (!phi)
            throw std::invalid_argument("Failed to factorize phi.");

        auto d{RSA::RSA::modInverse(publicKeys.E_KEY, phi)};

        // Decrypt
        return RSA::RSA::modExponentiation(encryptedMessage, d, publicKeys.N_KEY);
    }

}

#endif //BREAKING_RSA_CPU_RSA_BREAK_HPP
