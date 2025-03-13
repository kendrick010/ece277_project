//
// Created by Kendrick Nguyen on 3/11/25.
//

#ifndef BREAKING_RSA_CPU_RSA_BREAK_HPP
#define BREAKING_RSA_CPU_RSA_BREAK_HPP

#include <gmpxx.h>
#include <stdexcept>
#include <cmath>
#include "RSA.hpp"

namespace CPU_RSA_Break {

    // Function to find a factor of num (assumes num is a semi-prime)
    mpz_class findFactor(const mpz_class& num) {
        mpz_class half;
        mpz_sqrt(half.get_mpz_t(), num.get_mpz_t());

        for (mpz_class i = 2; i <= half; i++) {
            if (num % i == 0) return i;
        }

        // Failed to factor (num is prime)
        return 0;
    }

    mpz_class rsa_break(const mpz_class& encryptedMessage, const RSA::PublicKeys& publicKeys) {
        // Factorize N_KEY to find p
        mpz_class p = findFactor(publicKeys.N_KEY);
        if (p == 0) {
            throw std::invalid_argument("Failed to factorize N.");
        }

        // Compute q and φ(n)
        mpz_class q = publicKeys.N_KEY / p;
        mpz_class phi = (p - 1) * (q - 1);

        // Compute d (modular inverse of e mod φ(n))
        mpz_class d;
        if (!mpz_invert(d.get_mpz_t(), publicKeys.E_KEY.get_mpz_t(), phi.get_mpz_t())) {
            throw std::invalid_argument("Failed to compute modular inverse.");
        }

        // Decrypt the message using modular exponentiation
        mpz_class decryptedMessage;
        mpz_powm(decryptedMessage.get_mpz_t(), encryptedMessage.get_mpz_t(), d.get_mpz_t(), publicKeys.N_KEY.get_mpz_t());

        return decryptedMessage;
    }

}

#endif //BREAKING_RSA_CPU_RSA_BREAK_HPP
